import { Pool, PoolClient, PoolConfig } from 'pg';
import { createHash } from 'crypto';
import { AttestationArtifacts, CustodyEntry, EvidenceEnvelope } from '@tzun/engine';
import type { AttestationStatusOf, RetryObtainableComponent } from '@tzun/engine';
import { FailureRecord } from '@tzun/engine';
import { ListOptions } from '@tzun/engine';
import { TamperIncident, TamperIncidentStatus } from '@tzun/engine';
import { ChainIdentity, AnnotationRecord, RelinkRecord, ForkRecord } from '@tzun/engine';
import {
  ModelDescriptor,
  ModelDescriptorRow,
  ModelDescriptorAnnotationRow,
} from '@tzun/engine';
import { canonicalSerializeDescriptor } from '@tzun/engine';
import { buildEnrichedView } from '../models/enriched-view';
import {
  CustodyAppendOptions,
  EnvelopeRevision,
  IdempotencyOutcome,
  IdempotencyReceipt,
  IdempotentStoreOptions,
  RelinkCustodyAppend,
  RevisionCause,
  StorageAdapter,
  StoreOptions,
  StoredCustodyEntry,
} from '@tzun/engine';
import {
  canonicalCustodyMetadata,
  computeCustodyEntryHash,
  mirrorCustodyEntry,
  normaliseCustodyMetadata,
} from '@tzun/engine';
import { DEFAULT_CHAIN_ID, resolveActiveChainId } from '@tzun/engine';
import {
  CHAIN_STATE_LOGGED_TAG,
  assertChainHead,
  assertChainNotSealed,
  translateChainStateError,
} from './chain-head-guard';
import {
  assertUniqueExtensionNames,
  installExtensionMethods,
  mergeExtensionMethods,
  type StorageExtension,
  type StoreWrite,
} from './extensions';
import { DEFAULT_STORAGE_EXTENSIONS } from './extensions-registry';
import type { FinalizedHeader } from '../anchoring/header-follower';
import { fillAbsentArtifacts, statusAfterFill } from './attestation-fill';
import { AsyncCredentialStore } from '../attestation/credential-store';
import {
  CREDENTIAL_SCHEMA_POSTGRES,
  CREDENTIAL_TRIGGERS_POSTGRES,
  CredentialStoreProvider,
  PostgresCredentialStore,
} from './credential-stores';
import {
  assertArmed,
  DEMO_SENTINEL_OWNER,
  DemoTamperStoreView,
  DemoTamperTarget,
  tryArmDemoTamperHooks,
} from './demo-tamper-guard';
import { assertDescriptorIntegrityInvariants } from '../models/descriptor-invariants';
import { DuplicateRecordError, postgresBackdatedIdGuard, translateConstraintError } from './append-only';
import { assertNonNegativeInteger } from './pagination-guard';
import { assertRetryObtainableComponents } from './missing-obtainable';
import {
  CAPTURE_REVISION_NO,
  REVISION_ACTOR_ATTESTATION,
  REVISION_ACTOR_RECOVERY,
  captureRevisionActor,
  nextRevisionNo,
} from './revision-log';
import {
  AnchorStore,
  AnchorStoreProvider,
  LogSchemaOptions,
  LogStore,
  LogStoreProvider,
  PostgresLogStore,
  ENVELOPES_POSITION_INDEX,
  assertEvidenceLogChainId,
  migratePostgresLogSchema,
  translateEvidenceLogError,
} from './log-store';

/**
 * PostgreSQL storage adapter for persistent storage.
 *
 * Stores evidence envelopes as JSONB in a PostgreSQL database.
 * Indexed columns enable efficient querying by evidenceId, capturedAt, and aiSystemId.
 *
 * Append-only is enforced at two levels: the application never overwrites a
 * stored evidenceId, and the append-only triggers installed by
 * `ensureTables()` refuse UPDATE of the immutable fields, DELETE, and
 * TRUNCATE. The triggers are defence in depth against a least-privileged DML
 * role — see the append-only enforcement comment in `ensureTables()` for who
 * they do and do not stop. The adapter itself does issue UPDATE on the
 * mutable fields (relink chain-link, custody appends, attestation retry).
 *
 * Connection is configured via a standard PostgreSQL connection string (DATABASE_URL).
 */
/** The `envelope` column, whether pg handed it back parsed (JSONB) or as text. */
function parseEnvelopeColumn(raw: string | EvidenceEnvelope): EvidenceEnvelope {
  return typeof raw === 'string' ? (JSON.parse(raw) as EvidenceEnvelope) : raw;
}

/** custody_entries row → StoredCustodyEntry. */
/** envelope_revisions row → EnvelopeRevision. */
function revisionRowFromPg(row: Record<string, unknown>): EnvelopeRevision {
  return {
    evidenceId: row.evidence_id as string,
    revisionNo: Number(row.revision_no),
    canonicalDigest: row.canonical_digest as string,
    chainLink: (row.chain_link as string | null) ?? null,
    recordedAt: row.recorded_at as string,
    cause: row.cause as RevisionCause,
    actor: row.actor as string,
  };
}

function custodyRowFromPg(row: Record<string, unknown>): StoredCustodyEntry {
  const metadata = row.metadata;
  return {
    id: Number(row.id),
    evidenceId: row.evidence_id as string,
    chainId: (row.chain_id as string | null) ?? null,
    canonicalDigest: row.canonical_digest as string,
    action: row.action as StoredCustodyEntry['action'],
    actor: row.actor as string,
    timestamp: row.ts as string,
    systemId: row.system_id as string,
    metadata:
      metadata == null
        ? null
        : typeof metadata === 'string'
          ? (JSON.parse(metadata) as Record<string, unknown>)
          : (metadata as Record<string, unknown>),
    prevEntryHash: (row.prev_entry_hash as string | null) ?? null,
    entryHash: row.entry_hash as string,
    recoveryId: (row.recovery_id as string | null) ?? null,
  };
}

/**
 * chain_forks row → ForkRecord.
 *
 * `sealedOldChainHead` is optional on ForkRecord and the column is nullable,
 * so a fork can be stored without one. The KEY'S PRESENCE is the
 * discriminator, not its value: when the column is NULL the key is omitted
 * rather than carried as null, because chainUpperBound() branches on
 * `typeof fork.sealedOldChainHead === 'number'` — a recorded head bounds the
 * sequence walk directly, and no head sends it down the recomputation path.
 * Carrying an explicit null would make "no head recorded" arrive as a
 * value and collapse that branch.
 */
function forkFromRow(row: Record<string, unknown>): ForkRecord {
  const fork: ForkRecord = {
    id: row.id as string,
    incidentId: row.incident_id as string,
    forkedAt: row.forked_at instanceof Date ? (row.forked_at as Date).toISOString() : row.forked_at as string,
    forkedBy: row.forked_by as string,
    reason: row.reason as string,
    oldChainId: row.old_chain_id as string,
    newChainId: row.new_chain_id as string,
    forkAfterSequence: row.fork_after_sequence as number,
    sealedOldChainLength: row.sealed_old_chain_length as number,
  };
  if (row.sealed_old_chain_head !== null && row.sealed_old_chain_head !== undefined) {
    fork.sealedOldChainHead = row.sealed_old_chain_head as number;
  }
  return fork;
}

/**
 * `listByMissingObtainable()`: the SQL test that a record lacks each
 * component's artifact. Absent, JSON null or an empty string, the absence
 * `updateAttestation()` fills (`isAbsent`); `->>` reads the first two as SQL
 * NULL.
 */
const POSTGRES_MISSING_COMPONENT: Record<RetryObtainableComponent, string> = {
  timestamp:
    "(envelope->'nonRepudiation'->>'rfc3161Token' IS NULL" +
    " OR envelope->'nonRepudiation'->>'rfc3161Token' = '')",
};

/** Options of {@link PostgresStorageAdapter}. */
export interface PostgresAdapterOptions extends LogSchemaOptions {
  /**
   * The storage extensions this adapter installs (`extensions.ts`): their
   * tables (created by `ensureTables()`), their `store()` hooks and the
   * optional adapter methods they provide. Default:
   * `DEFAULT_STORAGE_EXTENSIONS`.
   */
  extensions?: readonly StorageExtension[];
}

export class PostgresStorageAdapter
  implements StorageAdapter, CredentialStoreProvider, LogStoreProvider, AnchorStoreProvider
{
  private pool: Pool;

  /** The storage extensions this adapter installed, in order. */
  private readonly extensions: readonly StorageExtension[];

  // The optional methods a storage extension provides (extensions.ts),
  // installed at construction: present exactly when an installed extension
  // provides them.
  declare putAgentDescriptor?: StorageAdapter['putAgentDescriptor'];
  declare getAgentDescriptor?: StorageAdapter['getAgentDescriptor'];
  declare listAgentDescriptors?: StorageAdapter['listAgentDescriptors'];
  declare getMandate?: StorageAdapter['getMandate'];
  declare getMandateTotals?: StorageAdapter['getMandateTotals'];
  declare listMandateEvents?: StorageAdapter['listMandateEvents'];
  declare expireMandate?: StorageAdapter['expireMandate'];
  declare listMandates?: StorageAdapter['listMandates'];
  declare getDeciderOpening?: StorageAdapter['getDeciderOpening'];
  declare getDeciderCommitmentSecret?: StorageAdapter['getDeciderCommitmentSecret'];
  declare listLinksTo?: StorageAdapter['listLinksTo'];

  /** What `ensureTables()` passes to the evidence-log migration. */
  private readonly logOptions: LogSchemaOptions;

  // Demo-tamper hooks state.
  private demoHooksArmed = false;

  // Where this adapter's data lives, for the arming guard's locality check.
  // Captured at construction: the pool's effective connection settings are
  // decided here and nowhere else.
  private readonly demoTamperTarget: DemoTamperTarget;

  /**
   * @param connectionString - The database URL.
   * @param poolConfig - Overrides for the `pg` pool.
   * @param options - `logNamespace`: the namespace a new store's identity is
   *   minted with by `ensureTables()`; on a store that has one, a different
   *   value is refused (`LogNamespaceMismatchError`).
   */
  constructor(connectionString: string, poolConfig?: Partial<PoolConfig>, options: PostgresAdapterOptions = {}) {
    this.logOptions = options;
    this.extensions = options.extensions ?? DEFAULT_STORAGE_EXTENSIONS;
    assertUniqueExtensionNames(this.extensions);
    this.pool = new Pool({
      // Default to a 5s connection timeout. Without this, `pg`'s Pool waits
      // forever on a half-open TCP connection (e.g. macOS + Docker Desktop's
      // IPv6 `localhost` binding is flaky and silently stalls). A bounded
      // timeout turns "hang indefinitely" into "fail fast with a clear
      // error" so operators can see what went wrong. Override via poolConfig
      // if a specific deployment needs longer timeouts.
      connectionTimeoutMillis: 5000,
      connectionString,
      ...poolConfig,
    });

    // The arming guard refuses the empty-store path unless the target is
    // demonstrably loopback, so the adapter has to report which connection
    // string the pool above will actually use. `poolConfig` is spread last, so
    // a `connectionString` in it wins over the positional argument. A `host`
    // (or `hostname`) beside a connection string is ambiguous — `pg` resolves
    // exactly one of them and guessing is how a remote store gets called local
    // — so that case reports `unknown` and the guard refuses.
    const overrides = (poolConfig ?? {}) as Partial<PoolConfig> & { hostname?: string };
    this.demoTamperTarget =
      overrides.host !== undefined || overrides.hostname !== undefined
        ? { kind: 'unknown', why: 'pool config overrides the host' }
        : { kind: 'url', url: overrides.connectionString ?? connectionString };

    const extensionDb = { pool: this.pool, inTransaction: <T>(work: (client: PoolClient) => Promise<T>) => this.inTransaction(work) };
    installExtensionMethods(
      this,
      mergeExtensionMethods(this.extensions.map((ext) => ({ name: ext.name, methods: ext.postgres?.methods?.(extensionDb) }))),
    );
  }

  /**
   * Create the required tables and indexes if they do not exist.
   * Must be called after construction before any other operations.
   *
   * Concurrency: this method is safe to call from any number of concurrent
   * processes against the same Postgres. We hold a session-level advisory
   * lock around the full DDL block — including the `CREATE OR REPLACE
   * FUNCTION` + `DROP TRIGGER IF EXISTS` + `CREATE TRIGGER` block at the
   * bottom — because without it concurrent callers race on `pg_proc` /
   * `pg_trigger` catalog rows, which Postgres surfaces as
   * `tuple concurrently updated` errors. The lock is acquired and released
   * on the same dedicated client connection (taken from the pool, returned
   * in finally) so it doesn't leak past this call.
   *
   * The advisory key (2026052501) is an arbitrary int64 reserved for
   * `ensureTables`. Any other process using `pg_advisory_lock` should pick a
   * different key.
   */
  async ensureTables(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('SELECT pg_advisory_lock(2026052501)');
      // Replace a pre-per-chain `chain_state` before the CREATE below, which
      // would otherwise skip the table and leave every append failing on a
      // column that is not there. One evolving pre-release
      // schema, no migration files: the evolution is here. Each chain's row is
      // seeded from its highest sequence number and the digest of the record
      // holding it — exact for a store nothing has deleted from, and short by
      // exactly what was deleted on one that is already missing a tail, which
      // is the one thing no recomputation can recover.
      await client.query(`
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = 'chain_state' AND column_name = 'id'
          ) THEN
            DROP TABLE chain_state;
            CREATE TABLE chain_state (
              chain_id TEXT PRIMARY KEY,
              last_digest TEXT NOT NULL,
              last_sequence INTEGER NOT NULL DEFAULT 0,
              updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            INSERT INTO chain_state (chain_id, last_digest, last_sequence)
            SELECT e.chain_id,
                   (SELECT t.digest FROM envelopes t
                     WHERE t.chain_id = e.chain_id
                     ORDER BY (t.envelope->'payload'->>'sequenceNumber')::int DESC
                     LIMIT 1),
                   MAX((e.envelope->'payload'->>'sequenceNumber')::int)
              FROM envelopes e
             GROUP BY e.chain_id;
          END IF;
        END $$;
      `);
      await client.query(`
      CREATE TABLE IF NOT EXISTS envelopes (
        evidence_id TEXT PRIMARY KEY,
        envelope JSONB NOT NULL,
        captured_at TIMESTAMPTZ NOT NULL,
        ai_system_id TEXT NOT NULL,
        digest TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        -- The chain this record belongs to. Every chain-scoped read goes
        -- through it: list({chainId}) and listBySequence() filter on it,
        -- getChainForRecord() returns it, and getActiveChainId() resolves the
        -- store's active chain from SELECT DISTINCT chain_id. NOT NULL with
        -- a default, so a store that never forks is one chain named
        -- 'default'. Immutable, enforced by the append-only trigger below.
        chain_id TEXT NOT NULL DEFAULT 'default'
      );

      CREATE INDEX IF NOT EXISTS idx_envelopes_captured_at ON envelopes(captured_at);
      CREATE INDEX IF NOT EXISTS idx_envelopes_ai_system_id ON envelopes(ai_system_id);
      -- The store's first and newest record by insertion time, in the order
      -- head() and readEnvelopeAtEnd() sort by. Tzun.init() reads the 0.7.0
      -- store check through readEnvelopeAtEnd() on every open, before this
      -- DDL runs, so only the first open of a store written before the index
      -- sorts the whole table.
      CREATE INDEX IF NOT EXISTS idx_envelopes_created_at ON envelopes(created_at, evidence_id);
      -- getActiveChainId() reads SELECT DISTINCT chain_id on every
      -- resolution: a full scan of this covering index rather
      -- than of the table.
      --
      -- Deliberately not CONCURRENTLY, and this is a path already measured
      -- and rejected: a concurrent build waits for every backend holding an
      -- older snapshot, and a process blocked on the advisory lock this DDL
      -- runs under holds one, so under the lock it is a lock cycle (eight
      -- parallel first inits: four deadlock-detected aborts), and outside the
      -- lock it deadlocks against the CREATE TRIGGER every other concurrent
      -- ensureTables() runs on this table. Either way the aborted build
      -- leaves an INVALID index that IF NOT EXISTS then skips forever.
      CREATE INDEX IF NOT EXISTS idx_envelopes_chain_id ON envelopes(chain_id);
      -- The attestation-status reads:
      -- listByAttestationStatus() and listByMissingObtainable() seek one status
      -- and read it oldest first, so the status leads and the order key follows
      -- it in the index.
      CREATE INDEX IF NOT EXISTS idx_envelopes_attestation_status
        ON envelopes((envelope->>'attestationStatus'), captured_at);

      CREATE TABLE IF NOT EXISTS failures (
        id SERIAL PRIMARY KEY,
        failure_type TEXT NOT NULL,
        evidence_id TEXT,
        diagnostic_metadata JSONB NOT NULL,
        captured_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      -- One head per chain. This was a single row
      -- (id INTEGER PRIMARY KEY CHECK (id = 1)) shared by every chain, so a
      -- second chain's first record took the first chain's next sequence
      -- number and linked from its head: born unverifiable, and a fork of one
      -- chain wiped every other chain's high-water mark. The platform has
      -- keyed its own heads per (chain_id, account_id, env) all along.
      --
      -- last_sequence is a HIGH-WATER MARK, not a count. It does not fall when
      -- a record is deleted, which is the only thing that makes a deleted tail
      -- — or a chain whose every record is gone — detectable: with no survivor
      -- after the missing records there is nothing else to compare against.
      -- Deriving the head from the envelopes table instead (as the Python
      -- adapters do) would remove a source of truth and that detection with it.
      CREATE TABLE IF NOT EXISTS chain_state (
        chain_id TEXT PRIMARY KEY,
        last_digest TEXT NOT NULL,
        last_sequence INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS tamper_incidents (
        id TEXT PRIMARY KEY,
        detected_at TIMESTAMPTZ NOT NULL,
        severity TEXT NOT NULL,
        type TEXT NOT NULL,
        affected_records JSONB NOT NULL,
        affected_sequence_range JSONB,
        details TEXT NOT NULL,
        status TEXT NOT NULL,
        -- When a scan last observed this incident's finding. See
        -- TamperIncident.lastObservedAt: it is what tells a reviewed finding
        -- that is still there from one a later pass no longer sees.
        last_observed_at TIMESTAMPTZ,
        resolved_at TIMESTAMPTZ,
        resolved_by TEXT,
        resolution_notes TEXT
      );

      -- Added to a store written by an earlier build (0.4.6). CREATE TABLE IF
      -- NOT EXISTS above skips an existing table, so without this the column is
      -- absent and every storeIncident() fails on it. Nullable with nothing to
      -- backfill: a pass before the upgrade recorded no observation, and
      -- inventing one would claim a scan saw a finding when none was looking.
      ALTER TABLE tamper_incidents ADD COLUMN IF NOT EXISTS last_observed_at TIMESTAMPTZ;

      CREATE INDEX IF NOT EXISTS idx_tamper_incidents_status ON tamper_incidents(status);
      CREATE INDEX IF NOT EXISTS idx_tamper_incidents_severity ON tamper_incidents(severity);

      CREATE TABLE IF NOT EXISTS chains (
        chain_id TEXT PRIMARY KEY,
        parent_chain_id TEXT,
        fork_point INTEGER,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TIMESTAMPTZ NOT NULL,
        sealed_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS chain_annotations (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        affected_records JSONB NOT NULL,
        annotated_at TIMESTAMPTZ NOT NULL,
        annotated_by TEXT NOT NULL,
        notes TEXT NOT NULL,
        original_digests JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_chain_annotations_incident ON chain_annotations(incident_id);

      CREATE TABLE IF NOT EXISTS chain_relinks (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        relinked_at TIMESTAMPTZ NOT NULL,
        relinked_by TEXT NOT NULL,
        from_sequence INTEGER NOT NULL,
        to_sequence INTEGER NOT NULL,
        modified_links JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_chain_relinks_incident ON chain_relinks(incident_id);

      CREATE TABLE IF NOT EXISTS chain_forks (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        forked_at TIMESTAMPTZ NOT NULL,
        forked_by TEXT NOT NULL,
        reason TEXT NOT NULL,
        old_chain_id TEXT NOT NULL,
        new_chain_id TEXT NOT NULL,
        fork_after_sequence INTEGER NOT NULL,
        sealed_old_chain_length INTEGER NOT NULL,
        sealed_old_chain_head INTEGER,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_chain_forks_incident ON chain_forks(incident_id);
      CREATE INDEX IF NOT EXISTS idx_chain_forks_old_chain ON chain_forks(old_chain_id);
      CREATE INDEX IF NOT EXISTS idx_chain_forks_new_chain ON chain_forks(new_chain_id);

      -- AI-BOM catalog tables. TIMESTAMPTZ for time columns
      -- but we still hand pg ISO strings on insert — pg coerces. On read we
      -- get Date objects back and convert to ISO with .toISOString() so the
      -- observable type matches the memory/SQLite backends.
      CREATE TABLE IF NOT EXISTS model_descriptors (
        model_descriptor_digest TEXT PRIMARY KEY,
        canonical_bytes TEXT NOT NULL,
        vendor TEXT NOT NULL,
        model_name TEXT NOT NULL,
        model_version TEXT NOT NULL,
        parent_model_descriptor_digest TEXT,
        source TEXT NOT NULL,
        first_registered_at TIMESTAMPTZ NOT NULL,
        first_registered_by TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_md_vmv ON model_descriptors(vendor, model_name, model_version);
      CREATE INDEX IF NOT EXISTS idx_md_parent ON model_descriptors(parent_model_descriptor_digest);

      CREATE TABLE IF NOT EXISTS model_descriptor_annotations (
        annotation_id TEXT PRIMARY KEY,
        model_descriptor_digest TEXT NOT NULL REFERENCES model_descriptors(model_descriptor_digest),
        annotated_at TIMESTAMPTZ NOT NULL,
        annotated_by TEXT NOT NULL,
        annotation_type TEXT NOT NULL,
        value_json TEXT NOT NULL,
        retracts_annotation_id TEXT,
        signature TEXT,
        note TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_mda_digest ON model_descriptor_annotations(model_descriptor_digest);
      CREATE INDEX IF NOT EXISTS idx_mda_ts ON model_descriptor_annotations(annotated_at);

      CREATE TABLE IF NOT EXISTS model_descriptor_aliases (
        slug TEXT NOT NULL,
        set_at TIMESTAMPTZ NOT NULL,
        model_descriptor_digest TEXT NOT NULL,
        set_by TEXT NOT NULL,
        PRIMARY KEY (slug, set_at)
      );
      CREATE INDEX IF NOT EXISTS idx_mda_slug ON model_descriptor_aliases(slug);

      -- Demo/test-only sentinel: one row signals this is an armed demo store.
      CREATE TABLE IF NOT EXISTS demo_tamper_sentinel (
        owner TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      -- Idempotency keys: one row per key a capture claimed,
      -- written in the same transaction as the record it names, holding the
      -- fingerprint of the caller input it was claimed with and the receipt a
      -- replay returns. Kept for the life of the store, as the platform keeps
      -- its idempotency_keys: there is no expiry.
      CREATE TABLE IF NOT EXISTS idempotency_keys (
        idempotency_key     TEXT PRIMARY KEY,
        request_fingerprint TEXT NOT NULL,
        evidence_id         TEXT NOT NULL,
        chain_id            TEXT NOT NULL,
        sequence_number     INTEGER NOT NULL,
        canonical_digest    TEXT NOT NULL,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // ── Append-only enforcement ─────────────────────
    //
    // WHO THIS DEFENDS AGAINST. A least-privileged DML role — one granted
    // INSERT/SELECT and the UPDATE needed for attestation retry, custody
    // appends and recovery relink, and nothing else. A table owner or
    // superuser — which is what a hosted database's default URL often
    // carries — can `ALTER TABLE envelopes DISABLE TRIGGER ALL`, or set
    // `session_replication_role = 'replica'` (this file does exactly that in
    // `deleteEnvelopeForDemo`), and walk straight past everything below. These
    // triggers are defence in depth, not a boundary against the DB owner. The
    // boundary against the DB owner is the chain digest and the external
    // attestation, which is why tampering here is detectable even when it is
    // not preventable.
    //
    // NAME RESOLUTION. A trigger function runs with the
    // search_path of the session whose statement fired it, so a table it names
    // bare is whatever that session resolves the name to: a temporary table
    // of the same name, or one in a schema the session puts first. Every
    // function this adapter and the log schema create is created with
    // `SET search_path = pg_catalog, pg_temp`, and names every table it reads
    // or writes, and every function of the store's it calls, through the
    // schema of the table its trigger is on (`TG_TABLE_SCHEMA`; the trigger's
    // own table also by `TG_TABLE_NAME`), in a statement it runs with
    // EXECUTE format('%I.…'). What a deployment still has to do is in
    // docs/integration/postgres-store.md: the inserting role holds no
    // TEMPORARY on the database and no CREATE on a schema in its search_path.
    //
    // What is enforced on `envelopes`:
    //
    //   - payload (all fields, schemaVersion included)  — immutable
    //   - integrity.canonicalDigest                      — immutable
    //   - integrity.chainLink                            — mutable (recovery relink writes this)
    //   - custodyChain                                   — APPEND-ONLY: stays an array,
    //                                                      never shrinks, and its existing
    //                                                      entries are compared EXACTLY at
    //                                                      their index (not by containment,
    //                                                      which let an entry gain keys in
    //                                                      place). An appended entry that
    //                                                      carries an entryHash must be a
    //                                                      custody_entries row for this record.
    //   - nonRepudiation, attestationStatus              — mutable. Attestation retry
    //                                                      legitimately REPLACES a failed
    //                                                      artifact, so containment cannot be
    //                                                      required here. A forged
    //                                                      attestationStatus is caught at
    //                                                      verification time instead: the
    //                                                      scanner verifies the artifacts
    //                                                      rather than checking that a
    //                                                      non-empty string is present.
    //   - evidence_id, digest columns                   — immutable
    //   - chain_id, ai_system_id columns                — immutable. Rewriting chain_id
    //                                                      moves a record out of every
    //                                                      chain-scoped read
    //                                                      (list({chainId}), listBySequence,
    //                                                      getChainForRecord →
    //                                                      resolvePredecessorDigest) without
    //                                                      touching a hashed byte.
    //   - DELETE                                        — blocked outright
    //   - TRUNCATE                                      — blocked. Row-level DELETE triggers
    //                                                      do NOT fire on TRUNCATE; only a
    //                                                      BEFORE TRUNCATE ... FOR EACH
    //                                                      STATEMENT trigger does. Without
    //                                                      one, the entire evidence table
    //                                                      could be emptied in one statement
    //                                                      with every DELETE trigger silent.
    //
    // And on `model_descriptors` — the AI-BOM rows the evidence points at:
    //
    //   - model_descriptor_digest, canonical_bytes      — immutable (rewriting
    //                                                      canonical_bytes retroactively
    //                                                      edits the model an evidence
    //                                                      record attests to)
    //   - DELETE, TRUNCATE                              — blocked
    //
    // Written idempotently via CREATE OR REPLACE so re-running
    // ensureTables on an existing DB is safe.
    await client.query(`
      CREATE OR REPLACE FUNCTION envelopes_enforce_immutable()
      RETURNS TRIGGER AS $$
      DECLARE
        v_old_custody JSONB := COALESCE(OLD.envelope->'custodyChain', '[]'::jsonb);
        v_new_custody JSONB := COALESCE(NEW.envelope->'custodyChain', '[]'::jsonb);
        v_old_len     INTEGER;
        v_hash        TEXT;
        v_held        BOOLEAN;
      BEGIN
        IF OLD.evidence_id IS DISTINCT FROM NEW.evidence_id THEN
          RAISE EXCEPTION 'envelopes.evidence_id is immutable';
        END IF;
        IF OLD.digest IS DISTINCT FROM NEW.digest THEN
          RAISE EXCEPTION 'envelopes.digest is immutable';
        END IF;
        IF OLD.captured_at IS DISTINCT FROM NEW.captured_at THEN
          RAISE EXCEPTION 'envelopes.captured_at is immutable';
        END IF;
        IF OLD.envelope->'payload' IS DISTINCT FROM NEW.envelope->'payload' THEN
          RAISE EXCEPTION 'envelopes.envelope.payload is immutable (append-only evidence)';
        END IF;
        IF OLD.envelope->'integrity'->>'canonicalDigest' IS DISTINCT FROM NEW.envelope->'integrity'->>'canonicalDigest' THEN
          RAISE EXCEPTION 'envelopes.envelope.integrity.canonicalDigest is immutable';
        END IF;
        IF OLD.chain_id IS DISTINCT FROM NEW.chain_id THEN
          RAISE EXCEPTION 'envelopes.chain_id is immutable';
        END IF;
        IF OLD.ai_system_id IS DISTINCT FROM NEW.ai_system_id THEN
          RAISE EXCEPTION 'envelopes.ai_system_id is immutable';
        END IF;
        IF v_new_custody IS DISTINCT FROM v_old_custody THEN
          IF jsonb_typeof(v_old_custody) <> 'array' OR jsonb_typeof(v_new_custody) <> 'array' THEN
            RAISE EXCEPTION 'envelopes.envelope.custodyChain is append-only (it must stay an array)';
          END IF;
          v_old_len := jsonb_array_length(v_old_custody);
          IF jsonb_array_length(v_new_custody) < v_old_len
             OR COALESCE(
                  (SELECT jsonb_agg(e ORDER BY i)
                     FROM jsonb_array_elements(v_new_custody) WITH ORDINALITY AS t(e, i)
                    WHERE i <= v_old_len),
                  '[]'::jsonb) IS DISTINCT FROM v_old_custody THEN
            RAISE EXCEPTION 'envelopes.envelope.custodyChain is append-only';
          END IF;
          -- An appended entry that carries an entryHash claims to be the
          -- mirror of a custody_entries row; it must be one, for this record.
          -- Unhashed appends stay permitted: they are the
          -- client-attested form, and verifiers report them as unhashed.
          FOR v_hash IN
            SELECT e ->> 'entryHash'
              FROM jsonb_array_elements(v_new_custody) WITH ORDINALITY AS t(e, i)
             WHERE i > v_old_len
               AND jsonb_typeof(e) = 'object'
               AND e ? 'entryHash'
          LOOP
            EXECUTE format(
              'SELECT EXISTS (SELECT 1 FROM %I.custody_entries WHERE evidence_id = $1 AND entry_hash = $2)',
              TG_TABLE_SCHEMA)
              INTO v_held USING OLD.evidence_id, v_hash;
            IF NOT v_held THEN
              RAISE EXCEPTION 'envelopes.envelope.custodyChain entry claims an entryHash with no custody_entries row (%)',
                OLD.evidence_id;
            END IF;
          END LOOP;
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS envelopes_enforce_immutable_trigger ON envelopes;
      CREATE TRIGGER envelopes_enforce_immutable_trigger
        BEFORE UPDATE ON envelopes
        FOR EACH ROW EXECUTE FUNCTION envelopes_enforce_immutable();

      CREATE OR REPLACE FUNCTION envelopes_block_delete()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'envelopes rows cannot be deleted (append-only evidence)';
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS envelopes_block_delete_trigger ON envelopes;
      CREATE TRIGGER envelopes_block_delete_trigger
        BEFORE DELETE ON envelopes
        FOR EACH ROW EXECUTE FUNCTION envelopes_block_delete();

      -- TRUNCATE does not fire ON DELETE triggers. Without this statement-level
      -- trigger the whole evidence table can be emptied in one statement with
      -- envelopes_block_delete_trigger never running.
      CREATE OR REPLACE FUNCTION envelopes_block_truncate()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'envelopes cannot be truncated (append-only evidence)';
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS envelopes_block_truncate_trigger ON envelopes;
      CREATE TRIGGER envelopes_block_truncate_trigger
        BEFORE TRUNCATE ON envelopes
        FOR EACH STATEMENT EXECUTE FUNCTION envelopes_block_truncate();

      -- model_descriptors: the AI-BOM rows evidence points at. Rewriting
      -- canonical_bytes in place retroactively edits the model a record
      -- attests to; the digest mismatch makes it detectable, nothing made it
      -- preventable.
      CREATE OR REPLACE FUNCTION model_descriptors_enforce_immutable()
      RETURNS TRIGGER AS $$
      BEGIN
        IF OLD.model_descriptor_digest IS DISTINCT FROM NEW.model_descriptor_digest THEN
          RAISE EXCEPTION 'model_descriptors.model_descriptor_digest is immutable';
        END IF;
        IF OLD.canonical_bytes IS DISTINCT FROM NEW.canonical_bytes THEN
          RAISE EXCEPTION 'model_descriptors.canonical_bytes is immutable';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS model_descriptors_enforce_immutable_trigger ON model_descriptors;
      CREATE TRIGGER model_descriptors_enforce_immutable_trigger
        BEFORE UPDATE ON model_descriptors
        FOR EACH ROW EXECUTE FUNCTION model_descriptors_enforce_immutable();

      CREATE OR REPLACE FUNCTION model_descriptors_block_removal()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'model_descriptors rows cannot be deleted or truncated (evidence references them)';
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS model_descriptors_block_delete_trigger ON model_descriptors;
      CREATE TRIGGER model_descriptors_block_delete_trigger
        BEFORE DELETE ON model_descriptors
        FOR EACH ROW EXECUTE FUNCTION model_descriptors_block_removal();

      DROP TRIGGER IF EXISTS model_descriptors_block_truncate_trigger ON model_descriptors;
      CREATE TRIGGER model_descriptors_block_truncate_trigger
        BEFORE TRUNCATE ON model_descriptors
        FOR EACH STATEMENT EXECUTE FUNCTION model_descriptors_block_removal();
    `);

    // ── Sealed chains and the sealed head ──────────────────
    //
    // A sealed chain is the read-only remainder of a fork, protected by two
    // columns. `chains.status` is what every append reads to refuse a sealed
    // chain; `chain_forks.sealed_old_chain_head` is the sealed chain's
    // high-water mark, the bound chainUpperBound() hands every verifier so a
    // deleted tail stays a reported gap. Both are guarded where they live:
    //
    //   chains      — identity columns (chain_id, parent_chain_id, fork_point,
    //                 created_at) immutable; a seal is never lifted or
    //                 re-dated; DELETE and TRUNCATE refused (a chain with no
    //                 row is open, so deleting the row would reopen it).
    //                 Sealing an active chain is the one transition allowed.
    //   chain_forks — append-only: UPDATE, DELETE and TRUNCATE refused.
    //   chain_annotations, chain_relinks — the recovery records, append-only
    //                 the same way, as the platform's `recoveries` table is
    //                 (which freezes every column but an undo latch these
    //                 tables do not have).
    //
    // Same scope as the append-only block above: defence in depth against a
    // least-privileged DML role, not a boundary against the table owner.
    await client.query(`
      CREATE OR REPLACE FUNCTION chains_enforce_immutable()
      RETURNS TRIGGER AS $$
      BEGIN
        IF OLD.chain_id IS DISTINCT FROM NEW.chain_id
           OR OLD.parent_chain_id IS DISTINCT FROM NEW.parent_chain_id
           OR OLD.fork_point IS DISTINCT FROM NEW.fork_point
           OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
          RAISE EXCEPTION 'chains identity columns are immutable (chain %)', OLD.chain_id;
        END IF;
        IF OLD.status = 'sealed' AND (
             NEW.status IS DISTINCT FROM OLD.status
             OR NEW.sealed_at IS DISTINCT FROM OLD.sealed_at) THEN
          RAISE EXCEPTION 'chain % is sealed: a seal cannot be lifted or re-dated', OLD.chain_id;
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS chains_enforce_immutable_trigger ON chains;
      CREATE TRIGGER chains_enforce_immutable_trigger
        BEFORE UPDATE ON chains
        FOR EACH ROW EXECUTE FUNCTION chains_enforce_immutable();

      CREATE OR REPLACE FUNCTION chains_block_removal()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'chains rows cannot be deleted or truncated (% refused)', TG_OP;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS chains_block_delete_trigger ON chains;
      CREATE TRIGGER chains_block_delete_trigger
        BEFORE DELETE ON chains
        FOR EACH ROW EXECUTE FUNCTION chains_block_removal();

      DROP TRIGGER IF EXISTS chains_block_truncate_trigger ON chains;
      CREATE TRIGGER chains_block_truncate_trigger
        BEFORE TRUNCATE ON chains
        FOR EACH STATEMENT EXECUTE FUNCTION chains_block_removal();

      CREATE OR REPLACE FUNCTION chain_forks_block_mutation()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'chain_forks rows are append-only (% refused)', TG_OP;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS chain_forks_block_mutation_trigger ON chain_forks;
      CREATE TRIGGER chain_forks_block_mutation_trigger
        BEFORE UPDATE OR DELETE ON chain_forks
        FOR EACH ROW EXECUTE FUNCTION chain_forks_block_mutation();

      DROP TRIGGER IF EXISTS chain_forks_block_truncate_trigger ON chain_forks;
      CREATE TRIGGER chain_forks_block_truncate_trigger
        BEFORE TRUNCATE ON chain_forks
        FOR EACH STATEMENT EXECUTE FUNCTION chain_forks_block_mutation();

      CREATE OR REPLACE FUNCTION chain_annotations_block_mutation()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'chain_annotations rows are append-only (% refused)', TG_OP;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS chain_annotations_block_mutation_trigger ON chain_annotations;
      CREATE TRIGGER chain_annotations_block_mutation_trigger
        BEFORE UPDATE OR DELETE ON chain_annotations
        FOR EACH ROW EXECUTE FUNCTION chain_annotations_block_mutation();

      DROP TRIGGER IF EXISTS chain_annotations_block_truncate_trigger ON chain_annotations;
      CREATE TRIGGER chain_annotations_block_truncate_trigger
        BEFORE TRUNCATE ON chain_annotations
        FOR EACH STATEMENT EXECUTE FUNCTION chain_annotations_block_mutation();

      CREATE OR REPLACE FUNCTION chain_relinks_block_mutation()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'chain_relinks rows are append-only (% refused)', TG_OP;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS chain_relinks_block_mutation_trigger ON chain_relinks;
      CREATE TRIGGER chain_relinks_block_mutation_trigger
        BEFORE UPDATE OR DELETE ON chain_relinks
        FOR EACH ROW EXECUTE FUNCTION chain_relinks_block_mutation();

      DROP TRIGGER IF EXISTS chain_relinks_block_truncate_trigger ON chain_relinks;
      CREATE TRIGGER chain_relinks_block_truncate_trigger
        BEFORE TRUNCATE ON chain_relinks
        FOR EACH STATEMENT EXECUTE FUNCTION chain_relinks_block_mutation();
    `);

    // ── The custody ledger ──
    //
    // One row per relink / fork / review custody action. `entry_hash` is the
    // engine's computeCustodyEntryHash over prev_entry_hash, evidence_id,
    // canonical_digest, action, actor, ts, system_id and metadata_canonical
    // (the engine-canonical bytes of `metadata` — the column that is hashed;
    // `metadata` is the same value as JSONB for readers), and is mirrored
    // into envelope->'custodyChain'[i].entryHash. `prev_entry_hash` chains
    // the rows of ONE record.
    //
    // Every INSERT is checked and recomputed, as the
    // platform's INSERT trigger does: the record exists, canonical_digest is
    // the digest it carries now, metadata and metadata_canonical are the same
    // value, prev_entry_hash is the record's current tail, and entry_hash is
    // sha256 over the length-prefixed preimage — the SQL twin of the engine's
    // computeCustodyEntryHash (Postgres length(text) counts code points, as
    // the engine's lengthPrefix does). A row that disagrees is refused, so an
    // inserted row cannot carry a hash its writer chose. Appends to one
    // record are serialised by a transaction advisory lock on (2026091801,
    // hashtext(evidence_id)) — the adapter already holds the record's row
    // lock; the advisory lock covers a direct INSERT racing it. The verifier
    // reads `envelopes` and the ledger's tail, and calls the hash function,
    // through the ledger's own schema (NAME RESOLUTION above), so a table or
    // function of the inserting session's does not stand in for the record,
    // the tail or the hash.
    //
    // Append-only with no exemption: UPDATE and DELETE are refused row by
    // row, TRUNCATE by statement (row-level DELETE triggers do not fire on
    // TRUNCATE). The same caveat as the append-only block above applies —
    // the table owner can disable the triggers; that is what the hash chain
    // is for.
    //
    // Added on an existing database by the same CREATE TABLE IF NOT EXISTS /
    // CREATE OR REPLACE / DROP TRIGGER IF EXISTS idiom as everything above,
    // so ensureTables() on a store written by an earlier build gains the
    // ledger on its next boot. Trigger and function names are deliberately
    // distinct from the platform's (`custody_entries_append_only` /
    // `tzun_custody_entries_*`) so the two schemas cannot silently replace
    // each other's guards should they ever share a database.
    await client.query(`
      CREATE TABLE IF NOT EXISTS custody_entries (
        id BIGSERIAL PRIMARY KEY,
        evidence_id TEXT NOT NULL,
        chain_id TEXT,
        canonical_digest TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL,
        ts TEXT NOT NULL,
        system_id TEXT NOT NULL,
        metadata JSONB,
        metadata_canonical TEXT,
        prev_entry_hash TEXT,
        entry_hash TEXT NOT NULL UNIQUE,
        recovery_id TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_custody_entries_record ON custody_entries(evidence_id, id);

      CREATE OR REPLACE FUNCTION custody_entries_block_mutation()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'custody_entries rows are append-only (% refused)', TG_OP;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS custody_entries_block_mutation_trigger ON custody_entries;
      CREATE TRIGGER custody_entries_block_mutation_trigger
        BEFORE UPDATE OR DELETE ON custody_entries
        FOR EACH ROW EXECUTE FUNCTION custody_entries_block_mutation();

      DROP TRIGGER IF EXISTS custody_entries_block_truncate_trigger ON custody_entries;
      CREATE TRIGGER custody_entries_block_truncate_trigger
        BEFORE TRUNCATE ON custody_entries
        FOR EACH STATEMENT EXECUTE FUNCTION custody_entries_block_mutation();

      -- Each field length-prefixed as the engine's lengthPrefix does ('-:' for
      -- NULL, otherwise its length in code points, ':', the value), the eight
      -- concatenated in the engine's order.
      CREATE OR REPLACE FUNCTION custody_entries_compute_hash(
        p_prev TEXT, p_evidence_id TEXT, p_canonical_digest TEXT, p_action TEXT,
        p_actor TEXT, p_ts TEXT, p_system_id TEXT, p_metadata_canonical TEXT)
      RETURNS TEXT
      LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
        SELECT encode(sha256(convert_to(
            string_agg(CASE WHEN f.v IS NULL THEN '-:' ELSE length(f.v)::text || ':' || f.v END, '' ORDER BY f.i)
          , 'UTF8')), 'hex')
          FROM unnest(ARRAY[p_prev, p_evidence_id, p_canonical_digest, p_action,
                            p_actor, p_ts, p_system_id, p_metadata_canonical]) WITH ORDINALITY AS f(v, i)
      $$;
      DROP FUNCTION IF EXISTS custody_entries_length_prefix(TEXT);

      CREATE OR REPLACE FUNCTION custody_entries_verify_insert()
      RETURNS TRIGGER AS $$
      DECLARE
        v_found  BOOLEAN;
        v_digest TEXT;
        v_prev   TEXT;
        v_hash   TEXT;
      BEGIN
        PERFORM pg_advisory_xact_lock(2026091801, hashtext(NEW.evidence_id));

        EXECUTE format(
          'SELECT true, envelope->''integrity''->>''canonicalDigest'' FROM %I.envelopes WHERE evidence_id = $1',
          TG_TABLE_SCHEMA)
          INTO v_found, v_digest USING NEW.evidence_id;
        IF v_found IS NULL THEN
          RAISE EXCEPTION 'custody_entries: no evidence record % to bind the entry to', NEW.evidence_id;
        END IF;
        IF NEW.canonical_digest IS DISTINCT FROM v_digest THEN
          RAISE EXCEPTION 'custody_entries: canonical_digest does not match the record (%)', NEW.evidence_id;
        END IF;

        IF (NEW.metadata IS NULL) <> (NEW.metadata_canonical IS NULL)
           OR (NEW.metadata IS NOT NULL AND NEW.metadata_canonical::jsonb IS DISTINCT FROM NEW.metadata) THEN
          RAISE EXCEPTION 'custody_entries: metadata and metadata_canonical disagree (%)', NEW.evidence_id;
        END IF;

        EXECUTE format(
          'SELECT entry_hash FROM %I.%I WHERE evidence_id = $1 ORDER BY id DESC LIMIT 1',
          TG_TABLE_SCHEMA, TG_TABLE_NAME)
          INTO v_prev USING NEW.evidence_id;
        IF NEW.prev_entry_hash IS DISTINCT FROM v_prev THEN
          RAISE EXCEPTION 'custody_entries: prev_entry_hash is not the record''s current tail (%)', NEW.evidence_id;
        END IF;

        EXECUTE format('SELECT %I.custody_entries_compute_hash($1, $2, $3, $4, $5, $6, $7, $8)', TG_TABLE_SCHEMA)
          INTO v_hash
          USING v_prev, NEW.evidence_id, NEW.canonical_digest, NEW.action,
                NEW.actor, NEW.ts, NEW.system_id, NEW.metadata_canonical;
        IF NEW.entry_hash IS DISTINCT FROM v_hash THEN
          RAISE EXCEPTION 'custody_entries: entry_hash does not recompute (%)', NEW.evidence_id;
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS custody_entries_verify_insert_trigger ON custody_entries;
      CREATE TRIGGER custody_entries_verify_insert_trigger
        BEFORE INSERT ON custody_entries
        FOR EACH ROW EXECUTE FUNCTION custody_entries_verify_insert();

      -- No entry written ahead of the entries it follows. The
      -- ledger is read in id order and verify_insert takes the tail as the
      -- highest id, so a row that extends the tail but is written at an
      -- explicit id below it would verify and then read first. The guard
      -- refuses an id the sequence did not hand the insert, or one below an
      -- id already committed, and gives the row an id drawn as it is written
      -- (postgresBackdatedIdGuard); the adapter's own appends name no id. Its
      -- trigger sorts before verify_insert's, so it runs first.
      ${postgresBackdatedIdGuard('custody_entries_block_backdated_id', 'custody_entries', 'id')}

      DROP TRIGGER IF EXISTS custody_entries_block_backdated_id_trigger ON custody_entries;
      CREATE TRIGGER custody_entries_block_backdated_id_trigger
        BEFORE INSERT ON custody_entries
        FOR EACH ROW EXECUTE FUNCTION custody_entries_block_backdated_id();
    `);

    // Registered WebAuthn credentials, append-only, with the same trigger
    // discipline as custody_entries above. Inside the same advisory lock: the
    // CREATE OR REPLACE FUNCTION / CREATE TRIGGER pair races on the pg_proc
    // and pg_trigger catalog rows exactly as the ones above it do, and two
    // processes calling ensureTables() concurrently would surface it as
    // `tuple concurrently updated`.
    await client.query(CREDENTIAL_SCHEMA_POSTGRES);
    await client.query(CREDENTIAL_TRIGGERS_POSTGRES);
    // ── The append-only revision log ──────────────────────
    //
    // One row per legitimate write to a record's integrity block: revision 0
    // from store(), then one per relink or attestation retry. It is the only
    // thing in the store that remembers what a record USED TO hash to, and
    // without that memory the rewrite-and-reseat attack is indistinguishable
    // from an honest single-link corruption — the attacker rewrites the
    // payload, recomputes canonicalDigest, repairs the record's own chainLink
    // onto its (untouched) predecessor, and leaves exactly one inconsistent
    // link, on the SUCCESSOR. relink() would repair it, report
    // chainVerified: true, and sign operator custody entries vouching for
    // the laundered record. See EnvelopeRevision in the engine's
    // storage-interface.ts for the full account.
    //
    // recorded_at is TEXT, not TIMESTAMPTZ, for the same reason custody
    // entries' `ts` is: the value is mirrored and compared across adapters,
    // and a driver that hands back a Date on one backend and a string on
    // another is a divergence waiting to be asserted around.
    //
    // Added to an existing database by the same CREATE TABLE IF NOT EXISTS /
    // CREATE OR REPLACE / DROP TRIGGER IF EXISTS idiom as custody_entries and
    // sealed_old_chain_head, so a store written by an earlier build gains the
    // log on its next boot — WITHOUT backfilling revision 0 for the records
    // already in it. A backfill would write today's digest as "the digest
    // this was captured with", which for a record that had already been
    // rewritten is the laundering this whole feature exists to refuse.
    await client.query(`
      CREATE TABLE IF NOT EXISTS envelope_revisions (
        evidence_id      TEXT NOT NULL,
        revision_no      INTEGER NOT NULL,
        canonical_digest TEXT NOT NULL,
        chain_link       TEXT,
        recorded_at      TEXT NOT NULL,
        cause            TEXT NOT NULL,
        actor            TEXT NOT NULL,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (evidence_id, revision_no)
      );
      -- The O(1) capture probe. getCaptureDigests() asks one question per
      -- record — "what did this hash to at capture" — and this partial,
      -- COVERING index answers it index-only: an equality seek on
      -- evidence_id inside the revision_no = 0 slice, with canonical_digest
      -- read straight out of the index. The primary key would serve the seek
      -- but not the read, and the probe runs once per record per chain walk.
      CREATE INDEX IF NOT EXISTS idx_envelope_revisions_capture
        ON envelope_revisions(evidence_id, canonical_digest) WHERE revision_no = 0;

      CREATE OR REPLACE FUNCTION envelope_revisions_block_mutation()
      RETURNS TRIGGER AS $$
      BEGIN
        RAISE EXCEPTION 'envelope_revisions rows are append-only (% refused)', TG_OP;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS envelope_revisions_block_mutation_trigger ON envelope_revisions;
      CREATE TRIGGER envelope_revisions_block_mutation_trigger
        BEFORE UPDATE OR DELETE ON envelope_revisions
        FOR EACH ROW EXECUTE FUNCTION envelope_revisions_block_mutation();

      DROP TRIGGER IF EXISTS envelope_revisions_block_truncate_trigger ON envelope_revisions;
      CREATE TRIGGER envelope_revisions_block_truncate_trigger
        BEFORE TRUNCATE ON envelope_revisions
        FOR EACH STATEMENT EXECUTE FUNCTION envelope_revisions_block_mutation();
    `);

    // One record per chain position: store() reports the refusal as
    // position_taken. The sequence number is compared as text, the canonical
    // form evidence_log_append() already requires. A store holding two rows
    // at one position fails to create the index.
    //
    // A chain whose evidence log holds leaves keeps its sequence state: its
    // chain_state row cannot be deleted, and its last_sequence cannot be
    // lowered. The trigger reads the evidence-log tables when it fires, so it
    // is created before they exist.
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS ${ENVELOPES_POSITION_INDEX}
        ON envelopes (chain_id, (envelope->'payload'->>'sequenceNumber'));
      CREATE INDEX IF NOT EXISTS idx_envelopes_digest ON envelopes(digest);

      CREATE OR REPLACE FUNCTION chain_state_keep_logged() RETURNS TRIGGER AS $$
      DECLARE
        v_logged BOOLEAN;
      BEGIN
        IF TG_OP = 'UPDATE' AND NEW.last_sequence >= OLD.last_sequence THEN
          RETURN NEW;
        END IF;
        EXECUTE format(
          'SELECT EXISTS (SELECT 1 FROM %1$I.logs l JOIN %1$I.log_leaves lv ON lv.log_id = l.log_id WHERE l.kind = ''evidence'' AND l.chain_id = $1)',
          TG_TABLE_SCHEMA)
          INTO v_logged USING OLD.chain_id;
        IF v_logged THEN
          RAISE EXCEPTION '${CHAIN_STATE_LOGGED_TAG} chain_state: the sequence state of a chain whose evidence log holds leaves cannot be cleared or lowered';
        END IF;
        IF TG_OP = 'DELETE' THEN
          RETURN OLD;
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

      DROP TRIGGER IF EXISTS chain_state_keep_logged_trigger ON chain_state;
      CREATE TRIGGER chain_state_keep_logged_trigger
        BEFORE UPDATE OR DELETE ON chain_state
        FOR EACH ROW EXECUTE FUNCTION chain_state_keep_logged();
    `);

    // ── The evidence logs (Tree §5.2) ─────────────────────────────
    //
    // The store identity, the log tables, the backfill of a store that
    // already has records, and the trigger on envelopes that writes each
    // record's leaf, in ONE transaction that locks envelopes while it
    // backfills (log-store.ts). Still under the advisory lock above, so two
    // processes opening one store migrate it once. A store already through
    // it gets its functions replaced, like everything above, and no lock.
    await migratePostgresLogSchema(client, this.logOptions);

    await client.query(`
      -- The finalized block of the anchoring chain, as the anchor scheduler's
      -- header follower last read it: how a capturing process that does not
      -- read the chain itself fills a decider's freshness (Record §6.6).
      -- Written by the role that owns the store only (the anchoring tables'
      -- owner gate), so a capture role cannot plant a reference.
      CREATE TABLE IF NOT EXISTS anchor_freshness (
        chain TEXT PRIMARY KEY,
        block_number BIGINT NOT NULL CHECK (block_number >= 0),
        block_hash TEXT NOT NULL CHECK (block_hash ~ '^0x[0-9a-f]{64}$'),
        block_time TIMESTAMPTZ NOT NULL,
        written_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'anchor_freshness'::regclass AND tgname = 'tzun_anchor_freshness_require_owner') THEN
          CREATE TRIGGER tzun_anchor_freshness_require_owner BEFORE INSERT OR UPDATE OR DELETE ON anchor_freshness
            FOR EACH ROW EXECUTE FUNCTION anchoring_require_owner();
        END IF;
      END $$;
    `);

    for (const ext of this.extensions) await ext.postgres?.migrate(client);
    } finally {
      // Always try to release the advisory lock and the client, even if the
      // DDL above threw. Swallow unlock errors — at worst the lock persists
      // until the connection closes naturally, which is acceptable.
      try {
        await client.query('SELECT pg_advisory_unlock(2026052501)');
      } catch {
        // ignore
      }
      client.release();
    }
  }

  /**
   * Transaction-scoped advisory lock serialising appends to ONE chain.
   *
   * A chain's `chain_state` row may not exist yet, so `SELECT ... FOR UPDATE`
   * has nothing to lock on a chain nothing has written to. An advisory lock has
   * no such gap: it serialises the whole read-head / insert / write-head
   * sequence and is released on COMMIT or ROLLBACK.
   *
   * Taken as the two-key form, `(CHAIN_APPEND_LOCK, hashtext(chainId))`, so it
   * is per chain. The single-key form would serialise every append in
   * the DATABASE, across every chain and every store sharing it: two tenants
   * writing to two chains would queue behind each other for no reason, and a
   * per-chain head would buy correctness and no concurrency. Appends to
   * one chain still serialise, which is what a hash chain requires.
   *
   * `hashtext` collides, as any 32-bit hash does. A collision costs two
   * unrelated chains a shared queue, and cannot let two appends to one chain
   * overlap, because equal ids always hash equally. The key (2026090201) is
   * reserved for this; `ensureTables` uses a different one.
   */
  private static readonly CHAIN_APPEND_LOCK = 2026090201;

  /** Take the append lock for one chain, inside the caller's transaction. */
  private static async lockChain(client: PoolClient, chainId: string): Promise<void> {
    await client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [
      PostgresStorageAdapter.CHAIN_APPEND_LOCK,
      chainId,
    ]);
  }

  /**
   * Store an envelope.
   *
   * When `options.expectChainHead` is supplied this is a conditional append:
   * the head is re-read under the chain advisory lock and the write is refused
   * unless it still matches. Before this, `store()` inserted the row and ran
   * `ON CONFLICT (id) DO UPDATE SET last_digest = $1, last_sequence =
   * GREATEST(...)` with no check that `$2` was `last_sequence + 1` and no check
   * that the envelope's chain link had been computed from `last_digest` — so
   * two concurrent captures (one process with no mutex, or two replicas on one
   * DATABASE_URL) each wrote a record at the same sequence, linked to the same
   * predecessor, and the later `last_digest` write silently orphaned the other.
   * Both callers were told `stored: true`.
   */
  async store(
    envelope: EvidenceEnvelope,
    chainId?: string,
    options?: StoreOptions,
  ): Promise<void> {
    // A chain id that names no evidence log is refused before any query:
    // node-pg would send U+FFFD for a lone surrogate, which is another chain
    // id's bytes, and Postgres text cannot hold U+0000.
    assertEvidenceLogChainId(chainId ?? DEFAULT_CHAIN_ID, envelope.payload?.sequenceNumber);
    const client = await this.pool.connect();

    try {
      await client.query('BEGIN');
      await this.lockExtensionRows(client, { envelope, chainId: chainId ?? DEFAULT_CHAIN_ID, options: options ?? {} });
      await PostgresStorageAdapter.lockChain(client, chainId ?? DEFAULT_CHAIN_ID);
      await this.storeWith(client, envelope, chainId, options);
      await client.query('COMMIT');
    } catch (err) {
      // Every refusal (a duplicate id, a sealed chain, a ChainConflictError
      // from the head check) rolls back here, so the advisory lock is
      // released and nothing is left half written.
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * `store()` under an idempotency key, in ONE transaction
   * holding the target chain's append lock: the key lookup, the write and the
   * claim. Two connections — or two processes — appending to one chain under
   * one key queue on that lock, so they cannot both find the key free. A key is
   * store-wide while the lock is per chain, so two calls under one key aimed at
   * DIFFERENT chains are serialised instead by the primary key on
   * `idempotency_keys`: the second waits on the unique index, then reads the row
   * the first wrote. (Its fingerprint covers the chain, so that second call is a
   * conflict, which is the honest answer — one key names one record.) A
   * `store()` refusal rolls the whole transaction back and leaves the key
   * unclaimed. Keys are never expired, as on the platform.
   */
  async storeIdempotent(
    envelope: EvidenceEnvelope,
    chainId: string | undefined,
    options: IdempotentStoreOptions,
  ): Promise<IdempotencyOutcome> {
    assertEvidenceLogChainId(chainId ?? DEFAULT_CHAIN_ID, envelope.payload?.sequenceNumber);
    const { key, fingerprint } = options.idempotency;
    return this.inTransaction(async (client): Promise<IdempotencyOutcome> => {
      // The extensions' row locks (a mandate row) before the chain's append
      // lock, as in store(): every path that takes both takes them in this
      // order. A lock refuses nothing, so a replay below is still a replay.
      await this.lockExtensionRows(client, { envelope, chainId: chainId ?? DEFAULT_CHAIN_ID, options });
      await PostgresStorageAdapter.lockChain(client, chainId ?? DEFAULT_CHAIN_ID);
      const held = await client.query<{
        request_fingerprint: string;
        evidence_id: string;
        chain_id: string;
        sequence_number: number;
        canonical_digest: string;
      }>(
        `SELECT request_fingerprint, evidence_id, chain_id, sequence_number, canonical_digest
           FROM idempotency_keys WHERE idempotency_key = $1`,
        [key],
      );
      const row = held.rows[0];
      if (row) {
        if (row.request_fingerprint !== fingerprint) return { kind: 'conflict' };
        return {
          kind: 'replay',
          receipt: {
            evidenceId: row.evidence_id,
            chainId: row.chain_id,
            sequenceNumber: Number(row.sequence_number),
            canonicalDigest: row.canonical_digest,
          },
        };
      }
      await this.storeWith(client, envelope, chainId, options);
      const receipt: IdempotencyReceipt = {
        evidenceId: envelope.payload.evidenceId,
        chainId: chainId ?? 'default',
        sequenceNumber: envelope.payload.sequenceNumber,
        canonicalDigest: envelope.integrity.canonicalDigest,
      };
      await client.query(
        `INSERT INTO idempotency_keys
           (idempotency_key, request_fingerprint, evidence_id, chain_id, sequence_number, canonical_digest)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [key, fingerprint, receipt.evidenceId, receipt.chainId, receipt.sequenceNumber, receipt.canonicalDigest],
      );
      return { kind: 'claimed', receipt };
    });
  }

  /** The storage extensions' `lock` hooks: right after BEGIN, before the chain's append lock. */
  private async lockExtensionRows(client: PoolClient, write: StoreWrite): Promise<void> {
    for (const ext of this.extensions) await ext.postgres?.lock?.(client, write);
  }

  /**
   * The body of `store()`, for a caller inside a transaction that already
   * holds the chain append lock. Throws on every refusal; the caller rolls
   * back.
   */
  private async storeWith(
    client: PoolClient,
    envelope: EvidenceEnvelope,
    chainId?: string,
    options?: StoreOptions,
  ): Promise<void> {
    const id = envelope.payload.evidenceId;
    const existing = await client.query(
      'SELECT evidence_id FROM envelopes WHERE evidence_id = $1',
      [id]
    );

    if (existing.rows.length > 0) {
      throw new DuplicateRecordError('Evidence record', id);
    }

    // Sealed-chain guard, inside the transaction holding the append lock so
    // a seal landing mid-write cannot be stepped over.
    const targetChainId = chainId ?? 'default';
    const chainStatus = await client.query<{ status: string; sealed_at: Date | string | null }>(
      'SELECT status, sealed_at FROM chains WHERE chain_id = $1',
      [targetChainId],
    );
    const sealedAt = chainStatus.rows[0]?.sealed_at ?? null;
    assertChainNotSealed(
      targetChainId,
      chainStatus.rows[0]?.status,
      sealedAt instanceof Date ? sealedAt.toISOString() : sealedAt,
    );

    // The TARGET chain's head, not the store's: an append to one chain is
    // never refused because another chain moved.
    const headResult = await client.query<{ last_digest: string; last_sequence: number }>(
      'SELECT last_digest, last_sequence FROM chain_state WHERE chain_id = $1 FOR UPDATE',
      [targetChainId],
    );
    const head = headResult.rows[0];
    assertChainHead(options?.expectChainHead, {
      sequence: head ? Number(head.last_sequence) : 0,
      digest: head ? head.last_digest : null,
    });

    // The storage extensions' checks and claims (a mandate slot), in this
    // transaction: a refusal rolls back everything written below.
    const write: StoreWrite = { envelope, chainId: targetChainId, options: options ?? {} };
    for (const ext of this.extensions) await ext.postgres?.beforeInsert?.(client, write);

    // The trigger on envelopes writes the record's evidence-log leaf in this
    // statement; a refusal (a gap, a malformed position) fails it, and the
    // caller rolls the transaction back.
    try {
      await client.query(
        `INSERT INTO envelopes (evidence_id, envelope, captured_at, ai_system_id, digest, chain_id)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          id,
          JSON.stringify(envelope),
          envelope.payload.capturedAt,
          envelope.payload.aiSystemId,
          envelope.integrity.canonicalDigest,
          targetChainId,
        ]
      );
    } catch (err) {
      throw translateEvidenceLogError(err, targetChainId, envelope.payload.sequenceNumber);
    }

    await client.query(
      `INSERT INTO chain_state (chain_id, last_digest, last_sequence, updated_at) VALUES ($1, $2, $3, NOW())
       ON CONFLICT (chain_id) DO UPDATE SET last_digest = $2, last_sequence = GREATEST(chain_state.last_sequence, $3), updated_at = NOW()`,
      [targetChainId, envelope.integrity.canonicalDigest, envelope.payload.sequenceNumber]
    );

    // The capture revision, in the SAME transaction as the
    // row it describes. Separate writes would leave a window in which a
    // record exists with no record of what it hashed to — and that window
    // is the whole attack, because a rewritten record with no capture
    // revision is indistinguishable from a legacy one, which every verifier
    // must treat as unprovable rather than tampered.
    await client.query(
      // ON CONFLICT DO NOTHING, not a plain INSERT: a record that was
      // deleted and re-stored under the same id keeps the capture revision
      // it already has. See CAPTURE_REVISION_NO for why overwriting it
      // would launder the demo's own rewrite pattern.
      `INSERT INTO envelope_revisions
         (evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (evidence_id, revision_no) DO NOTHING`,
      [
        id,
        CAPTURE_REVISION_NO,
        envelope.integrity.canonicalDigest,
        envelope.integrity.chainLink,
        new Date().toISOString(),
        'capture',
        captureRevisionActor(envelope),
      ]
    );

    // The extensions' rows written with the record (a decider opening, the
    // link index), in this transaction.
    for (const ext of this.extensions) await ext.postgres?.afterInsert?.(client, write);
  }

  async retrieve(evidenceId: string): Promise<EvidenceEnvelope | null> {
    const result = await this.pool.query(
      'SELECT envelope FROM envelopes WHERE evidence_id = $1',
      [evidenceId]
    );

    if (result.rows.length === 0) return null;

    const envelope = result.rows[0].envelope;
    return typeof envelope === 'string'
      ? JSON.parse(envelope) as EvidenceEnvelope
      : envelope as EvidenceEnvelope;
  }

  async list(options?: ListOptions): Promise<EvidenceEnvelope[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    if (options?.aiSystemId) {
      conditions.push(`ai_system_id = $${paramIndex++}`);
      params.push(options.aiSystemId);
    }

    if (options?.chainId) {
      conditions.push(`chain_id = $${paramIndex++}`);
      params.push(options.chainId);
    }

    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const order = options?.order === 'asc' ? 'ASC' : 'DESC';

    // Validated as SQLite always did: pg bound the raw value, so a
    // negative limit surfaced as a DatabaseError and a forwarded
    // `req.query.limit` string was silently coerced.
    let limitClause = '';
    if (options?.limit != null) {
      limitClause = ` LIMIT $${paramIndex++}`;
      params.push(assertNonNegativeInteger(options.limit, 'limit'));
    }

    let offsetClause = '';
    if (options?.offset != null) {
      offsetClause = ` OFFSET $${paramIndex++}`;
      params.push(assertNonNegativeInteger(options.offset, 'offset'));
    }

    // Ordering contract (src/storage/list-order.ts): the instant at
    // MILLISECOND precision — truncated, matching Date.parse on the local
    // backends — then sequenceNumber, then evidenceId, all in one direction.
    // Postgres keeps microseconds; comparing them would order two records
    // 500µs apart by instant here and by sequence on memory/SQLite.
    const orderBy =
      `ORDER BY date_trunc('milliseconds', captured_at) ${order}, ` +
      `(envelope->'payload'->>'sequenceNumber')::int ${order}, ` +
      `evidence_id ${order}`;
    const sql = `SELECT envelope FROM envelopes ${where} ${orderBy}${limitClause}${offsetClause}`;
    const result = await this.pool.query(sql, params);

    return result.rows.map((row: { envelope: string | EvidenceEnvelope }) => {
      const envelope = row.envelope;
      return typeof envelope === 'string'
        ? JSON.parse(envelope) as EvidenceEnvelope
        : envelope as EvidenceEnvelope;
    });
  }

  async storeFailure(failure: FailureRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO failures (failure_type, evidence_id, diagnostic_metadata, captured_at)
       VALUES ($1, $2, $3, $4)`,
      [
        failure.failureType,
        failure.evidenceId ?? null,
        JSON.stringify(failure.diagnosticMetadata),
        failure.capturedAt,
      ]
    );
  }

  async getLastDigest(chainId: string = DEFAULT_CHAIN_ID): Promise<string | null> {
    const result = await this.pool.query(
      'SELECT last_digest FROM chain_state WHERE chain_id = $1',
      [chainId],
    );

    if (result.rows.length === 0) return null;
    return result.rows[0].last_digest;
  }

  async getLastSequence(chainId: string = DEFAULT_CHAIN_ID): Promise<number> {
    const result = await this.pool.query(
      'SELECT last_sequence FROM chain_state WHERE chain_id = $1',
      [chainId],
    );

    if (result.rows.length === 0) return 0;
    return Number(result.rows[0].last_sequence);
  }

  async listBySequence(fromSequence?: number, toSequence?: number, chainId?: string): Promise<EvidenceEnvelope[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    const from = fromSequence ?? 1;
    conditions.push(`(envelope->'payload'->>'sequenceNumber')::int >= $${paramIndex++}`);
    params.push(from);

    if (toSequence != null) {
      conditions.push(`(envelope->'payload'->>'sequenceNumber')::int <= $${paramIndex++}`);
      params.push(toSequence);
    }

    if (chainId) {
      conditions.push(`chain_id = $${paramIndex++}`);
      params.push(chainId);
    }

    const where = 'WHERE ' + conditions.join(' AND ');
    const sql = `SELECT envelope FROM envelopes ${where} ORDER BY (envelope->'payload'->>'sequenceNumber')::int ASC`;
    const result = await this.pool.query(sql, params);

    return result.rows.map((row: { envelope: string | EvidenceEnvelope }) => {
      const envelope = row.envelope;
      return typeof envelope === 'string'
        ? JSON.parse(envelope) as EvidenceEnvelope
        : envelope as EvidenceEnvelope;
    });
  }

  // This is the THIRD whole-blob rewriter, alongside updateEnvelopeChainLink
  // and appendCustodyEntry below, and it takes the same row lock they do.
  // Were its SELECT and its UPDATE two autocommit pool queries, a recovery
  // write committed in between — relink's chain-link repair, or
  // fork/annotate's custody append — would leave this UPDATE blocked on the
  // row lock and then writing back the blob it had read BEFORE that commit:
  // the healed chainLink silently reverted to the broken value, or the custody
  // entry gone. A deployment running retryPendingAttestations() on a timer
  // while an operator relinks would never converge — the relink audit row says
  // the chain was repaired, the next scan raises chain_break again, and the
  // operator relinks again.
  async updateAttestation(
    evidenceId: string,
    artifacts: AttestationArtifacts,
    newStatus: EvidenceEnvelope['attestationStatus'] | AttestationStatusOf
  ): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await client.query(
        'SELECT envelope FROM envelopes WHERE evidence_id = $1 FOR UPDATE',
        [evidenceId]
      );

      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        throw new Error(
          `Evidence record "${evidenceId}" not found. Cannot update attestation.`
        );
      }

      const raw = result.rows[0].envelope;
      const envelope: EvidenceEnvelope = typeof raw === 'string'
        ? JSON.parse(raw)
        : raw;

      // Fill only what the record does not have yet, under the row lock taken
      // above, so a second pass cannot replace a token that has already
      // landed. A pass that fills nothing writes nothing.
      const { merged, filled } = fillAbsentArtifacts(envelope.nonRepudiation, artifacts);
      const status = statusAfterFill(envelope, merged, newStatus);
      if (!filled && status === envelope.attestationStatus) {
        await client.query('COMMIT');
        return;
      }
      envelope.nonRepudiation = merged;
      envelope.attestationStatus = status;

      await client.query(
        'UPDATE envelopes SET envelope = $1 WHERE evidence_id = $2',
        [JSON.stringify(envelope), evidenceId]
      );
      // An attestation retry is a legitimate envelope write, so it leaves a
      // revision row. It carries the digest UNCHANGED — this
      // is the one permitted mutation and it touches neither the payload nor
      // integrity — which is exactly what makes the row prove the retry did
      // not supersede anything.
      await this.appendRevisionWith(
        client,
        evidenceId,
        envelope.integrity.canonicalDigest,
        envelope.integrity.chainLink,
        'attestation_retry',
        REVISION_ACTOR_ATTESTATION,
      );
      await client.query('COMMIT');
    } catch (err) {
      if (!(err as Error).message.includes('not found')) {
        await client.query('ROLLBACK').catch(() => {});
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async listByAttestationStatus(
    status: EvidenceEnvelope['attestationStatus'],
    limit?: number,
  ): Promise<EvidenceEnvelope[]> {
    // Oldest first, bounded: a caller reads a backlog a batch at a time
    // rather than every record in the status. The ORDER BY is list()'s
    // ascending contract, and idx_envelopes_attestation_status is
    // what keeps the seek off a sequential scan.
    const bound = limit != null ? assertNonNegativeInteger(limit, 'limit') : null;
    const result = await this.pool.query(
      `SELECT envelope FROM envelopes
        WHERE envelope->>'attestationStatus' = $1
        ORDER BY date_trunc('milliseconds', captured_at) ASC,
                 (envelope->'payload'->>'sequenceNumber')::int ASC,
                 evidence_id ASC
        LIMIT $2`,
      [status, bound]
    );

    return result.rows.map((row: { envelope: string | EvidenceEnvelope }) => {
      const envelope = row.envelope;
      return typeof envelope === 'string'
        ? JSON.parse(envelope) as EvidenceEnvelope
        : envelope as EvidenceEnvelope;
    });
  }

  async listByMissingObtainable(
    components: readonly RetryObtainableComponent[],
    limit?: number,
  ): Promise<EvidenceEnvelope[]> {
    // The retry pass's queue: 'pending' records missing a component it can
    // obtain, oldest first. The status seek uses
    // idx_envelopes_attestation_status like listByAttestationStatus; the
    // missing-component test filters within it.
    const wanted = assertRetryObtainableComponents(components);
    const bound = limit != null ? assertNonNegativeInteger(limit, 'limit') : null;
    if (wanted.length === 0) return [];
    const missing = wanted.map((c) => POSTGRES_MISSING_COMPONENT[c]).join(' OR ');
    const result = await this.pool.query(
      `SELECT envelope FROM envelopes
        WHERE envelope->>'attestationStatus' = 'pending'
          AND (${missing})
        ORDER BY date_trunc('milliseconds', captured_at) ASC,
                 (envelope->'payload'->>'sequenceNumber')::int ASC,
                 evidence_id ASC
        LIMIT $1`,
      [bound]
    );

    return result.rows.map((row: { envelope: string | EvidenceEnvelope }) => {
      const envelope = row.envelope;
      return typeof envelope === 'string'
        ? JSON.parse(envelope) as EvidenceEnvelope
        : envelope as EvidenceEnvelope;
    });
  }

  private rowToIncident(row: Record<string, unknown>): TamperIncident {
    const affectedRecords = typeof row.affected_records === 'string'
      ? JSON.parse(row.affected_records) as string[]
      : row.affected_records as string[];

    let affectedSequenceRange: { from: number; to: number } | undefined;
    if (row.affected_sequence_range != null) {
      affectedSequenceRange = typeof row.affected_sequence_range === 'string'
        ? JSON.parse(row.affected_sequence_range) as { from: number; to: number }
        : row.affected_sequence_range as { from: number; to: number };
    }

    return {
      id: row.id as string,
      detectedAt: row.detected_at instanceof Date
        ? (row.detected_at as Date).toISOString()
        : row.detected_at as string,
      severity: row.severity as TamperIncident['severity'],
      type: row.type as TamperIncident['type'],
      affectedRecords,
      affectedSequenceRange,
      details: row.details as string,
      status: row.status as TamperIncident['status'],
      lastObservedAt: row.last_observed_at != null
        ? (row.last_observed_at instanceof Date
            ? (row.last_observed_at as Date).toISOString()
            : row.last_observed_at as string)
        : undefined,
      resolvedAt: row.resolved_at != null
        ? (row.resolved_at instanceof Date ? (row.resolved_at as Date).toISOString() : row.resolved_at as string)
        : undefined,
      resolvedBy: (row.resolved_by as string) ?? undefined,
      resolutionNotes: (row.resolution_notes as string) ?? undefined,
    };
  }

  async storeIncident(incident: TamperIncident): Promise<void> {
    const existing = await this.pool.query(
      'SELECT id FROM tamper_incidents WHERE id = $1',
      [incident.id]
    );

    if (existing.rows.length > 0) {
      throw new DuplicateRecordError('Tamper incident', incident.id);
    }

    await this.pool.query(
      `INSERT INTO tamper_incidents (id, detected_at, severity, type, affected_records, affected_sequence_range, details, status, last_observed_at, resolved_at, resolved_by, resolution_notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        incident.id,
        incident.detectedAt,
        incident.severity,
        incident.type,
        JSON.stringify(incident.affectedRecords),
        incident.affectedSequenceRange ? JSON.stringify(incident.affectedSequenceRange) : null,
        incident.details,
        incident.status,
        incident.lastObservedAt ?? null,
        incident.resolvedAt ?? null,
        incident.resolvedBy ?? null,
        incident.resolutionNotes ?? null,
      ]
    );
  }

  async getIncident(id: string): Promise<TamperIncident | null> {
    const result = await this.pool.query(
      'SELECT * FROM tamper_incidents WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) return null;
    return this.rowToIncident(result.rows[0]);
  }

  async listIncidents(filter?: { status?: TamperIncidentStatus; severity?: string }): Promise<TamperIncident[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;

    if (filter?.status) {
      conditions.push(`status = $${paramIndex++}`);
      params.push(filter.status);
    }
    if (filter?.severity) {
      conditions.push(`severity = $${paramIndex++}`);
      params.push(filter.severity);
    }

    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const sql = `SELECT * FROM tamper_incidents ${where} ORDER BY detected_at DESC, id DESC`;
    const result = await this.pool.query(sql, params);

    return result.rows.map((row: Record<string, unknown>) => this.rowToIncident(row));
  }

  async recordIncidentObservation(id: string, observedAt: string): Promise<void> {
    // `observedAt` is a parameter, NOT `now()`: it is compared against
    // ScanSummary.startedAt, which the scanner stamps from the process clock,
    // and taking this one from the database clock would make the comparison
    // wrong by the skew between them. Only this column moves — the status and
    // resolution the operator left are not this call's business.
    const result = await this.pool.query(
      'UPDATE tamper_incidents SET last_observed_at = $2 WHERE id = $1',
      [id, observedAt]
    );
    if ((result.rowCount ?? 0) === 0) {
      throw new Error(
        `Tamper incident "${id}" not found. Cannot record an observation.`
      );
    }
  }

  async updateIncidentStatus(
    id: string,
    status: TamperIncidentStatus,
    metadata?: { resolvedBy?: string; resolutionNotes?: string }
  ): Promise<void> {
    const existing = await this.pool.query(
      'SELECT id FROM tamper_incidents WHERE id = $1',
      [id]
    );

    if (existing.rows.length === 0) {
      throw new Error(
        `Tamper incident "${id}" not found. Cannot update status.`
      );
    }

    if (status === 'resolved') {
      // COALESCE, not overwrite — see the SQLite twin. resolved_at is
      // the first transition into 'resolved'; resolved_by / resolution_notes
      // are replaced only when the caller supplies a new value, so a
      // metadata-less re-resolve keeps the auditor's sign-off.
      await this.pool.query(
        `UPDATE tamper_incidents
            SET status = $1,
                resolved_at = COALESCE(resolved_at, $2::timestamptz),
                resolved_by = COALESCE($3, resolved_by),
                resolution_notes = COALESCE($4, resolution_notes)
          WHERE id = $5`,
        [
          status,
          new Date().toISOString(),
          metadata?.resolvedBy ?? null,
          metadata?.resolutionNotes ?? null,
          id,
        ]
      );
    } else {
      await this.pool.query(
        'UPDATE tamper_incidents SET status = $1 WHERE id = $2',
        [status, id]
      );
    }
  }

  async getChainForRecord(evidenceId: string): Promise<string | null> {
    const result = await this.pool.query(
      'SELECT chain_id FROM envelopes WHERE evidence_id = $1',
      [evidenceId]
    );
    if (result.rows.length === 0) return null;
    return result.rows[0].chain_id;
  }

  // The append-only ledger tables below are a bare INSERT against a primary
  // key (and, for descriptor annotations, a foreign key). pg's DatabaseError
  // (SQLSTATE 23505 / 23503) is translated into the SDK's own
  // DuplicateRecordError / MissingReferenceError so a caller's `catch` means
  // the same thing on every backend; anything else is rethrown untouched.

  async storeChain(chain: ChainIdentity): Promise<void> {
    try {
      await this.pool.query(
        `INSERT INTO chains (chain_id, parent_chain_id, fork_point, status, created_at, sealed_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          chain.chainId,
          chain.parentChainId ?? null,
          chain.forkPoint ?? null,
          chain.status,
          chain.createdAt,
          chain.sealedAt ?? null,
        ]
      );
    } catch (err) {
      throw translateConstraintError(err, { recordType: 'Chain', recordId: chain.chainId });
    }
  }

  async getChain(chainId: string): Promise<ChainIdentity | null> {
    const result = await this.pool.query(
      'SELECT chain_id, parent_chain_id, fork_point, status, created_at, sealed_at FROM chains WHERE chain_id = $1',
      [chainId]
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    const chain: ChainIdentity = {
      chainId: row.chain_id,
      status: row.status,
      createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    };
    if (row.parent_chain_id) chain.parentChainId = row.parent_chain_id;
    if (row.fork_point !== null) chain.forkPoint = row.fork_point;
    if (row.sealed_at) chain.sealedAt = row.sealed_at instanceof Date ? row.sealed_at.toISOString() : row.sealed_at;
    return chain;
  }

  async listChains(): Promise<ChainIdentity[]> {
    return this.readChains(this.pool);
  }

  /** `listChains()` on a given connection, so a caller can pair it with another read in one snapshot. */
  private async readChains(via: Pick<PoolClient, 'query'>): Promise<ChainIdentity[]> {
    const result = await via.query(
      'SELECT chain_id, parent_chain_id, fork_point, status, created_at, sealed_at FROM chains ORDER BY created_at ASC, chain_id ASC'
    );
    return result.rows.map((row: Record<string, unknown>) => {
      const chain: ChainIdentity = {
        chainId: row.chain_id as string,
        status: row.status as 'active' | 'sealed',
        createdAt: row.created_at instanceof Date ? (row.created_at as Date).toISOString() : row.created_at as string,
      };
      if (row.parent_chain_id) chain.parentChainId = row.parent_chain_id as string;
      if (row.fork_point !== null && row.fork_point !== undefined) chain.forkPoint = row.fork_point as number;
      if (row.sealed_at) chain.sealedAt = row.sealed_at instanceof Date ? (row.sealed_at as Date).toISOString() : row.sealed_at as string;
      return chain;
    });
  }

  /**
   * Seal a chain. A seal is final: sealing a sealed chain changes nothing and
   * keeps its first `sealed_at`, which is also all `chains_enforce_immutable`
   * allows. One statement, so "found" and "sealed" are answered from the same
   * snapshot.
   */
  async sealChain(chainId: string, sealedAt: string): Promise<void> {
    const result = await this.pool.query<{ found: boolean }>(
      `WITH sealed AS (
         UPDATE chains SET status = 'sealed', sealed_at = $1
          WHERE chain_id = $2 AND status <> 'sealed'
         RETURNING chain_id
       )
       SELECT EXISTS (SELECT 1 FROM sealed)
           OR EXISTS (SELECT 1 FROM chains WHERE chain_id = $2) AS found`,
      [sealedAt, chainId]
    );
    if (!result.rows[0]?.found) {
      throw new Error(`Chain "${chainId}" not found.`);
    }
  }

  /**
   * Both reads the rule runs over come from ONE snapshot.
   *
   * As two pool queries they could land on two connections with nothing
   * holding the store still between them, and a fork another process commits
   * in that gap — chains read before it, records read after — gave the rule
   * chains=[] and records=['default', <new>]: two implicit chains, an
   * `ambiguous_active_chain` refusal on a store that at no instant had more
   * than one open chain (the reverse order gives a false `no_active_chain`).
   * One client, one REPEATABLE READ transaction: the snapshot is taken at the
   * first SELECT and the second reads the same store. READ ONLY because it
   * is, and so the transaction can never be the writer another process
   * waits on. Pinned by the "ONE snapshot" case in
   * `tests/ts/active-chain-resolution-postgres.test.ts`.
   *
   * What this does not cover: a fork is several statements (`sealChain()`,
   * then `storeChain()` for the new row), so a snapshot taken between those
   * two sees every row sealed and answers `no_active_chain` truthfully for
   * that instant. Making the fork atomic is the fork's job, not this read's.
   */
  async getActiveChainId(): Promise<string> {
    const client = await this.pool.connect();
    let chains: ChainIdentity[];
    let recordChainIds: string[];
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      chains = await this.readChains(client);
      recordChainIds = await this.readRecordChainIds(client);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
    return resolveActiveChainId(chains, recordChainIds);
  }

  async listRecordChainIds(): Promise<string[]> {
    return this.readRecordChainIds(this.pool);
  }

  private async readRecordChainIds(via: Pick<PoolClient, 'query'>): Promise<string[]> {
    const result = await via.query(
      'SELECT DISTINCT chain_id FROM envelopes ORDER BY chain_id ASC'
    );
    return result.rows.map((row: { chain_id: string }) => row.chain_id);
  }

  async storeAnnotation(annotation: AnnotationRecord): Promise<void> {
    try {
      await this.pool.query(
        `INSERT INTO chain_annotations (id, incident_id, affected_records, annotated_at, annotated_by, notes, original_digests)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          annotation.id,
          annotation.incidentId,
          JSON.stringify(annotation.affectedRecords),
          annotation.annotatedAt,
          annotation.annotatedBy,
          annotation.notes,
          JSON.stringify(annotation.originalDigests),
        ]
      );
    } catch (err) {
      throw translateConstraintError(err, { recordType: 'Annotation', recordId: annotation.id });
    }
  }

  async getAnnotation(id: string): Promise<AnnotationRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM chain_annotations WHERE id = $1',
      [id]
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    return {
      id: row.id,
      incidentId: row.incident_id,
      affectedRecords: typeof row.affected_records === 'string' ? JSON.parse(row.affected_records) : row.affected_records,
      annotatedAt: row.annotated_at instanceof Date ? row.annotated_at.toISOString() : row.annotated_at,
      annotatedBy: row.annotated_by,
      notes: row.notes,
      originalDigests: typeof row.original_digests === 'string' ? JSON.parse(row.original_digests) : row.original_digests,
    };
  }

  async listAnnotations(incidentId: string): Promise<AnnotationRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM chain_annotations WHERE incident_id = $1 ORDER BY annotated_at ASC, id ASC',
      [incidentId]
    );
    return result.rows.map((row: Record<string, unknown>) => ({
      id: row.id as string,
      incidentId: row.incident_id as string,
      affectedRecords: typeof row.affected_records === 'string' ? JSON.parse(row.affected_records as string) : row.affected_records as string[],
      annotatedAt: row.annotated_at instanceof Date ? (row.annotated_at as Date).toISOString() : row.annotated_at as string,
      annotatedBy: row.annotated_by as string,
      notes: row.notes as string,
      originalDigests: typeof row.original_digests === 'string' ? JSON.parse(row.original_digests as string) : row.original_digests as Record<string, string>,
    }));
  }

  async listAnnotationsForRecord(evidenceId: string): Promise<AnnotationRecord[]> {
    const result = await this.pool.query(
      `SELECT * FROM chain_annotations WHERE affected_records @> $1::jsonb ORDER BY annotated_at ASC, id ASC`,
      [JSON.stringify([evidenceId])]
    );
    return result.rows.map((row: Record<string, unknown>) => ({
      id: row.id as string,
      incidentId: row.incident_id as string,
      affectedRecords: typeof row.affected_records === 'string' ? JSON.parse(row.affected_records as string) : row.affected_records as string[],
      annotatedAt: row.annotated_at instanceof Date ? (row.annotated_at as Date).toISOString() : row.annotated_at as string,
      annotatedBy: row.annotated_by as string,
      notes: row.notes as string,
      originalDigests: typeof row.original_digests === 'string' ? JSON.parse(row.original_digests as string) : row.original_digests as Record<string, string>,
    }));
  }

  async storeRelink(relink: RelinkRecord): Promise<void> {
    await this.insertRelinkWith(this.pool, relink);
  }

  private async insertRelinkWith(db: Pick<Pool | PoolClient, 'query'>, relink: RelinkRecord): Promise<void> {
    try {
      await db.query(
        `INSERT INTO chain_relinks (id, incident_id, relinked_at, relinked_by, from_sequence, to_sequence, modified_links)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          relink.id,
          relink.incidentId,
          relink.relinkedAt,
          relink.relinkedBy,
          relink.fromSequence,
          relink.toSequence,
          JSON.stringify(relink.modifiedLinks),
        ]
      );
    } catch (err) {
      throw translateConstraintError(err, { recordType: 'Relink', recordId: relink.id });
    }
  }

  async getRelink(id: string): Promise<RelinkRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM chain_relinks WHERE id = $1',
      [id]
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    return {
      id: row.id,
      incidentId: row.incident_id,
      relinkedAt: row.relinked_at instanceof Date ? row.relinked_at.toISOString() : row.relinked_at,
      relinkedBy: row.relinked_by,
      fromSequence: row.from_sequence,
      toSequence: row.to_sequence,
      modifiedLinks: typeof row.modified_links === 'string' ? JSON.parse(row.modified_links) : row.modified_links,
    };
  }

  async listRelinks(incidentId: string): Promise<RelinkRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM chain_relinks WHERE incident_id = $1 ORDER BY relinked_at ASC, id ASC',
      [incidentId]
    );
    return result.rows.map((row: Record<string, unknown>) => ({
      id: row.id as string,
      incidentId: row.incident_id as string,
      relinkedAt: row.relinked_at instanceof Date ? (row.relinked_at as Date).toISOString() : row.relinked_at as string,
      relinkedBy: row.relinked_by as string,
      fromSequence: row.from_sequence as number,
      toSequence: row.to_sequence as number,
      modifiedLinks: typeof row.modified_links === 'string' ? JSON.parse(row.modified_links as string) : row.modified_links,
    }));
  }

  async storeFork(fork: ForkRecord): Promise<void> {
    try {
      await this.pool.query(
        `INSERT INTO chain_forks (id, incident_id, forked_at, forked_by, reason, old_chain_id, new_chain_id, fork_after_sequence, sealed_old_chain_length, sealed_old_chain_head)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          fork.id,
          fork.incidentId,
          fork.forkedAt,
          fork.forkedBy,
          fork.reason,
          fork.oldChainId,
          fork.newChainId,
          fork.forkAfterSequence,
          fork.sealedOldChainLength,
          fork.sealedOldChainHead ?? null,
        ]
      );
    } catch (err) {
      throw translateConstraintError(err, { recordType: 'Fork', recordId: fork.id });
    }
  }

  async getFork(id: string): Promise<ForkRecord | null> {
    const result = await this.pool.query(
      'SELECT * FROM chain_forks WHERE id = $1',
      [id]
    );
    if (result.rows.length === 0) return null;
    return forkFromRow(result.rows[0]);
  }

  async listForks(incidentId: string): Promise<ForkRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM chain_forks WHERE incident_id = $1 ORDER BY forked_at ASC, id ASC',
      [incidentId]
    );
    return result.rows.map(forkFromRow);
  }

  async listForksForChain(chainId: string): Promise<ForkRecord[]> {
    const result = await this.pool.query(
      'SELECT * FROM chain_forks WHERE old_chain_id = $1 OR new_chain_id = $1 ORDER BY forked_at ASC, id ASC',
      [chainId]
    );
    return result.rows.map(forkFromRow);
  }

  // Both methods below rewrite the entire envelope JSONB blob after a
  // SELECT. Without a row lock, concurrent calls
  // race: A's SELECT, B's SELECT, A's UPDATE, B's UPDATE clobbers A. Even when
  // each call mutates a *different* field (chainLink vs custodyChain) the loser
  // overwrites the winner because the whole blob is rewritten. Locking only one
  // side does nothing — both methods must take the same row lock so they
  // serialize against each other. We use a dedicated pooled client with
  // BEGIN / SELECT ... FOR UPDATE / UPDATE / COMMIT.
  async updateEnvelopeChainLink(evidenceId: string, newChainLink: string | null): Promise<void> {
    await this.inTransaction((client) =>
      this.updateChainLinkWith(client, evidenceId, newChainLink, REVISION_ACTOR_RECOVERY),
    );
  }

  /**
   * Run `work` on one pooled client inside BEGIN / COMMIT, rolling back on
   * any throw and always releasing the client. Every recovery write below
   * goes through this so "one transaction" is a property of the helper, not
   * a discipline each method has to remember.
   */
  private async inTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  private async updateChainLinkWith(
    client: PoolClient,
    evidenceId: string,
    newChainLink: string | null,
    actor: string,
  ): Promise<void> {
    const result = await client.query(
      'SELECT envelope FROM envelopes WHERE evidence_id = $1 FOR UPDATE',
      [evidenceId]
    );
    if (result.rows.length === 0) {
      throw new Error(`Evidence record "${evidenceId}" not found.`);
    }
    const envelope = parseEnvelopeColumn(result.rows[0].envelope);
    envelope.integrity.chainLink = newChainLink;
    await client.query(
      'UPDATE envelopes SET envelope = $1 WHERE evidence_id = $2',
      [JSON.stringify(envelope), evidenceId]
    );
    // The repair, recorded: the digest carried forward
    // unchanged and the NEW link written down, so the log shows a chain link
    // moving while the digest stands still — the shape of an honest repair,
    // and the shape a laundering attempt cannot produce, because its
    // revision 0 already disagrees with the record's current digest.
    await this.appendRevisionWith(
      client,
      evidenceId,
      envelope.integrity.canonicalDigest,
      newChainLink,
      'relink',
      actor,
    );
  }

  /**
   * Append one non-capture revision row, for a caller already inside a
   * transaction.
   *
   * The revision number comes from the record's own highest, never a global
   * counter, and a record with NO rows starts at 1 — see `nextRevisionNo` for
   * why backfilling revision 0 would launder exactly the records this log
   * exists to protect.
   */
  private async appendRevisionWith(
    client: PoolClient,
    evidenceId: string,
    canonicalDigest: string,
    chainLink: string | null,
    cause: RevisionCause,
    actor: string,
  ): Promise<void> {
    const head = await client.query<{ highest: number | null }>(
      'SELECT MAX(revision_no) AS highest FROM envelope_revisions WHERE evidence_id = $1',
      [evidenceId]
    );
    const highest = head.rows[0]?.highest;
    await client.query(
      `INSERT INTO envelope_revisions
         (evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        evidenceId,
        nextRevisionNo(highest == null ? null : Number(highest)),
        canonicalDigest,
        chainLink,
        new Date().toISOString(),
        cause,
        actor,
      ]
    );
  }

  async listEnvelopeRevisions(evidenceId: string): Promise<EnvelopeRevision[]> {
    const result = await this.pool.query(
      `SELECT evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor
         FROM envelope_revisions WHERE evidence_id = $1 ORDER BY revision_no ASC`,
      [evidenceId]
    );
    return result.rows.map(revisionRowFromPg);
  }

  async getCaptureDigests(evidenceIds: string[]): Promise<Record<string, string>> {
    if (evidenceIds.length === 0) return {};
    // ONE round trip for the whole walk: `= ANY($1)` inside the
    // revision_no = 0 slice is an index-only scan of the partial covering
    // index, not a probe per record over the network. A per-record query
    // would be O(n) round trips against a remote Postgres, which is the
    // cost that would have made the check something a caller switches off.
    const result = await this.pool.query<{ evidence_id: string; canonical_digest: string }>(
      `SELECT evidence_id, canonical_digest FROM envelope_revisions
        WHERE revision_no = $1 AND evidence_id = ANY($2::text[])`,
      [CAPTURE_REVISION_NO, evidenceIds]
    );
    const out: Record<string, string> = {};
    // Absent stays absent: a record with no capture revision is one this
    // store cannot speak for, not one it is vouching for.
    for (const row of result.rows) out[row.evidence_id] = row.canonical_digest;
    return out;
  }

  /**
   * Hashed, chained append: the `custody_entries` row and the
   * envelope mirror in one transaction under the record's row lock. Before
   * this the entry went into the JSONB blob as plain JSON — nothing bound it
   * to the record, to its neighbours or to anything outside the blob, so
   * deleting the `relinked` entry was a one-statement edit that left the
   * record presenting as never repaired.
   */
  async confirmRecord(
    evidenceId: string,
    confirmation: NonNullable<AttestationArtifacts['confirmation']>,
    custodyEntry: CustodyEntry,
  ): Promise<{ filled: boolean }> {
    // One transaction under the record's row lock: the fill-only
    // confirmation, its revision row and the custody entry commit together or
    // not at all, and a second confirmation waits on the lock, then finds the
    // record filled.
    return this.inTransaction(async (client) => {
      const result = await client.query<{ envelope: string | EvidenceEnvelope }>(
        'SELECT envelope FROM envelopes WHERE evidence_id = $1 FOR UPDATE',
        [evidenceId]
      );
      if (result.rows.length === 0) {
        throw new Error(`Evidence record "${evidenceId}" not found. Cannot confirm it.`);
      }
      const envelope = parseEnvelopeColumn(result.rows[0].envelope);
      const merged = fillAbsentArtifacts(envelope.nonRepudiation, { confirmation });
      if (!merged.filled) return { filled: false };
      envelope.nonRepudiation = merged.merged;
      envelope.attestationStatus = statusAfterFill(envelope, merged.merged, (stored) => stored.attestationStatus);
      await client.query(
        'UPDATE envelopes SET envelope = $1 WHERE evidence_id = $2',
        [JSON.stringify(envelope), evidenceId]
      );
      await this.appendRevisionWith(
        client,
        evidenceId,
        envelope.integrity.canonicalDigest,
        envelope.integrity.chainLink,
        'attestation_retry',
        REVISION_ACTOR_ATTESTATION,
      );
      await this.appendCustodyEntryWith(client, evidenceId, custodyEntry, null);
      return { filled: true };
    });
  }

  async appendCustodyEntry(
    evidenceId: string,
    entry: CustodyEntry,
    options?: CustodyAppendOptions,
  ): Promise<void> {
    await this.inTransaction((client) =>
      this.appendCustodyEntryWith(client, evidenceId, entry, options?.recoveryId ?? null),
    );
  }

  /**
   * The append itself, for callers already inside a transaction. Locks the
   * record, reads its current digest and chain and the previous row's hash
   * for THIS record, mints the entry hash with the engine's one rule, inserts
   * the row and mirrors the hashed entry into the envelope.
   */
  private async appendCustodyEntryWith(
    client: PoolClient,
    evidenceId: string,
    entry: CustodyEntry,
    recoveryId: string | null,
  ): Promise<void> {
    const result = await client.query<{ envelope: string | EvidenceEnvelope; chain_id: string | null }>(
      'SELECT envelope, chain_id FROM envelopes WHERE evidence_id = $1 FOR UPDATE',
      [evidenceId]
    );
    if (result.rows.length === 0) {
      throw new Error(`Evidence record "${evidenceId}" not found.`);
    }
    const envelope = parseEnvelopeColumn(result.rows[0].envelope);
    const tail = await client.query<{ entry_hash: string }>(
      'SELECT entry_hash FROM custody_entries WHERE evidence_id = $1 ORDER BY id DESC LIMIT 1',
      [evidenceId]
    );
    const prevEntryHash = tail.rows[0]?.entry_hash ?? null;
    const canonicalDigest = envelope.integrity.canonicalDigest;
    const metadata = normaliseCustodyMetadata(entry.metadata);
    const entryHash = computeCustodyEntryHash({
      prevEntryHash,
      evidenceId,
      canonicalDigest,
      action: entry.action,
      actor: entry.actor,
      timestamp: entry.timestamp,
      systemId: entry.systemId,
      metadata,
    });
    await client.query(
      `INSERT INTO custody_entries
         (evidence_id, chain_id, canonical_digest, action, actor, ts, system_id,
          metadata, metadata_canonical, prev_entry_hash, entry_hash, recovery_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        evidenceId,
        result.rows[0].chain_id ?? null,
        canonicalDigest,
        entry.action,
        entry.actor,
        entry.timestamp,
        entry.systemId,
        metadata === null ? null : JSON.stringify(metadata),
        canonicalCustodyMetadata(metadata),
        prevEntryHash,
        entryHash,
        recoveryId,
      ]
    );
    envelope.custodyChain.push(mirrorCustodyEntry(entry, entryHash, prevEntryHash));
    await client.query(
      'UPDATE envelopes SET envelope = $1 WHERE evidence_id = $2',
      [JSON.stringify(envelope), evidenceId]
    );
  }

  /**
   * One client, one transaction: the links, the relink record
   * and the hashed custody entries commit together or not at all. A throw at
   * any point — an unknown record, a duplicate relink id, a crash injected
   * after the link update — rolls every statement back.
   */
  async applyRelink(relink: RelinkRecord, custodyEntries: RelinkCustodyAppend[]): Promise<void> {
    await this.inTransaction(async (client) => {
      for (const link of relink.modifiedLinks) {
        await this.updateChainLinkWith(client, link.evidenceId, link.newChainLink, relink.relinkedBy);
      }
      await this.insertRelinkWith(client, relink);
      for (const { evidenceId, entry } of custodyEntries) {
        await this.appendCustodyEntryWith(client, evidenceId, entry, relink.id);
      }
    });
  }

  async listCustodyEntries(evidenceId: string): Promise<StoredCustodyEntry[]> {
    const result = await this.pool.query(
      `SELECT id::text AS id, evidence_id, chain_id, canonical_digest, action, actor, ts, system_id,
              metadata, prev_entry_hash, entry_hash, recovery_id
         FROM custody_entries WHERE evidence_id = $1 ORDER BY id ASC`,
      [evidenceId]
    );
    return result.rows.map(custodyRowFromPg);
  }

  async getBySequenceRange(fromSequence: number, toSequence: number, chainId?: string): Promise<EvidenceEnvelope[]> {
    const result = await this.pool.query(
      chainId
        ? 'SELECT envelope FROM envelopes WHERE chain_id = $1'
        : 'SELECT envelope FROM envelopes',
      chainId ? [chainId] : []
    );
    return result.rows
      .map((row: { envelope: string | EvidenceEnvelope }) => {
        const envelope = typeof row.envelope === 'string'
          ? JSON.parse(row.envelope) as EvidenceEnvelope
          : row.envelope as EvidenceEnvelope;
        return envelope;
      })
      .filter((e: EvidenceEnvelope) => e.payload.sequenceNumber >= fromSequence && e.payload.sequenceNumber <= toSequence)
      .sort((a: EvidenceEnvelope, b: EvidenceEnvelope) => a.payload.sequenceNumber - b.payload.sequenceNumber);
  }

  /**
   * Clear one chain's state. Refused with `ChainStateResetRefusedError` when
   * the chain's evidence log holds leaves (the `chain_state` trigger).
   */
  async resetChainState(chainId: string = DEFAULT_CHAIN_ID): Promise<void> {
    try {
      await this.pool.query('DELETE FROM chain_state WHERE chain_id = $1', [chainId]);
    } catch (err) {
      throw translateChainStateError(err, chainId);
    }
  }

  /**
   * Share the header follower's finalized block (`anchor_freshness`). The row
   * moves forward only: a block below the one it holds is not written.
   */
  async writeAnchorFreshness(header: FinalizedHeader): Promise<void> {
    await this.pool.query(
      `INSERT INTO anchor_freshness (chain, block_number, block_hash, block_time, written_at)
       VALUES ($1, $2, $3, to_timestamp($4::double precision / 1000), NOW())
       ON CONFLICT (chain) DO UPDATE
         SET block_number = EXCLUDED.block_number, block_hash = EXCLUDED.block_hash,
             block_time = EXCLUDED.block_time, written_at = NOW()
       WHERE anchor_freshness.block_number <= EXCLUDED.block_number`,
      [header.chain, header.number, header.hash, header.timeMs],
    );
  }

  /** The finalized block another process shared for `chain`, or `null`. */
  async readAnchorFreshness(chain: string): Promise<FinalizedHeader | null> {
    const result = await this.pool.query<{ block_number: string | number; block_hash: string; block_ms: string | number }>(
      `SELECT block_number, block_hash, (EXTRACT(EPOCH FROM block_time) * 1000)::bigint AS block_ms
         FROM anchor_freshness WHERE chain = $1`,
      [chain],
    );
    const row = result.rows[0];
    if (!row) return null;
    return { chain, number: Number(row.block_number), hash: row.block_hash, timeMs: Number(row.block_ms) };
  }

  /** The record whose stored canonical digest is `digest`, or `null`; the oldest when several share it. */
  async retrieveByDigest(digest: string): Promise<EvidenceEnvelope | null> {
    const result = await this.pool.query<{ envelope: string | EvidenceEnvelope }>(
      'SELECT envelope FROM envelopes WHERE digest = $1 ORDER BY created_at, evidence_id LIMIT 1',
      [digest],
    );
    const row = result.rows[0];
    return row ? parseEnvelopeColumn(row.envelope) : null;
  }

  async getChainLength(chainId?: string): Promise<number> {
    const result = chainId
      ? await this.pool.query('SELECT COUNT(*) as count FROM envelopes WHERE chain_id = $1', [chainId])
      : await this.pool.query('SELECT COUNT(*) as count FROM envelopes');
    return parseInt(result.rows[0].count, 10);
  }

  // ── AI-BOM model-descriptor catalog ────────────────────────────────

  // pg returns TIMESTAMPTZ values as JS Date objects by default. The
  // memory + SQLite backends return ISO strings, so we normalize here on
  // read. `toIsoIfDate` accepts either, since some code paths (or future
  // pg type-parser overrides) might pass strings through unchanged.
  private toIsoIfDate(v: unknown): string {
    if (v instanceof Date) return v.toISOString();
    return v as string;
  }

  private rowToModelDescriptorRow(row: {
    model_descriptor_digest: string;
    canonical_bytes: string;
    vendor: string;
    model_name: string;
    model_version: string;
    parent_model_descriptor_digest: string | null;
    source: string;
    first_registered_at: string | Date;
    first_registered_by: string;
  }): ModelDescriptorRow {
    return {
      modelDescriptorDigest: row.model_descriptor_digest,
      canonicalBytes: row.canonical_bytes,
      descriptor: JSON.parse(row.canonical_bytes) as ModelDescriptor,
      vendor: row.vendor,
      modelName: row.model_name,
      modelVersion: row.model_version,
      parentModelDescriptorDigest: row.parent_model_descriptor_digest,
      source: row.source as ModelDescriptorRow['source'],
      firstRegisteredAt: this.toIsoIfDate(row.first_registered_at),
      firstRegisteredBy: row.first_registered_by,
    };
  }

  private rowToAnnotationRow(row: {
    annotation_id: string;
    model_descriptor_digest: string;
    annotated_at: string | Date;
    annotated_by: string;
    annotation_type: string;
    value_json: string;
    retracts_annotation_id: string | null;
    signature: string | null;
    note: string | null;
  }): ModelDescriptorAnnotationRow {
    return {
      annotationId: row.annotation_id,
      modelDescriptorDigest: row.model_descriptor_digest,
      annotatedAt: this.toIsoIfDate(row.annotated_at),
      annotatedBy: row.annotated_by,
      annotationType: row.annotation_type,
      valueJson: row.value_json,
      retractsAnnotationId: row.retracts_annotation_id,
      signature: row.signature,
      note: row.note,
    };
  }

  async registerModelDescriptor(
    descriptor: ModelDescriptor,
    source: ModelDescriptorRow['source'],
    registeredBy: string,
  ): Promise<{ digest: string; alreadyExisted: boolean }> {
    // The catalog write is the choke point: the connector path
    // (wrappers.ts) and the inline-AI-BOM capture path (sdk/index.ts) both
    // land here WITHOUT passing through register.ts's `mvdFrom`, so this is
    // the only place that sees every descriptor before it is stored.
    assertDescriptorIntegrityInvariants(descriptor, 'registerModelDescriptor');
    const canonicalBytes = canonicalSerializeDescriptor(descriptor);
    const digest = 'sha256:' + createHash('sha256').update(canonicalBytes).digest('hex');
    // Simpler than ON CONFLICT + RETURNING: SELECT-then-INSERT. Identical
    // canonical bytes produce identical digests, so the worst case under a
    // race is two writers both attempting the INSERT — one wins, the other
    // hits the PK uniqueness violation. We catch '23505' (unique_violation)
    // and report alreadyExisted=true. This is race-safe and matches the
    // memory + SQLite semantics.
    const existing = await this.pool.query(
      'SELECT 1 FROM model_descriptors WHERE model_descriptor_digest = $1',
      [digest],
    );
    if (existing.rows.length > 0) {
      return { digest, alreadyExisted: true };
    }
    try {
      await this.pool.query(
        `INSERT INTO model_descriptors (
          model_descriptor_digest, canonical_bytes, vendor, model_name, model_version,
          parent_model_descriptor_digest, source, first_registered_at, first_registered_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          digest,
          canonicalBytes,
          descriptor.vendor,
          descriptor.modelName,
          descriptor.modelVersion,
          descriptor.parentModelDescriptorDigest,
          source,
          new Date().toISOString(),
          registeredBy,
        ],
      );
      return { digest, alreadyExisted: false };
    } catch (err) {
      // Race: another writer inserted the same digest between our SELECT
      // and INSERT. Treat as a successful idempotent registration.
      if ((err as { code?: string }).code === '23505') {
        return { digest, alreadyExisted: true };
      }
      throw err;
    }
  }

  async getModelDescriptor(digest: string): Promise<ModelDescriptorRow | null> {
    const result = await this.pool.query(
      'SELECT * FROM model_descriptors WHERE model_descriptor_digest = $1',
      [digest],
    );
    if (result.rows.length === 0) return null;
    return this.rowToModelDescriptorRow(result.rows[0]);
  }

  async getEnrichedModelDescriptor(digest: string): Promise<ModelDescriptor | null> {
    const row = await this.getModelDescriptor(digest);
    if (!row) return null;
    const annotations = await this.listModelDescriptorAnnotations(digest);
    return buildEnrichedView(row.descriptor, annotations);
  }

  async listModelDescriptors(filter: {
    vendor?: string;
    modelName?: string;
    modelVersion?: string;
    integrityTier?: 'weight-attested' | 'vendor-asserted';
    hasRegulatoryMarking?: boolean;
    limit?: number;
    offset?: number;
  } = {}): Promise<ModelDescriptorRow[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIndex = 1;
    if (filter.vendor !== undefined) {
      conditions.push(`vendor = $${paramIndex++}`);
      params.push(filter.vendor);
    }
    if (filter.modelName !== undefined) {
      conditions.push(`model_name = $${paramIndex++}`);
      params.push(filter.modelName);
    }
    if (filter.modelVersion !== undefined) {
      conditions.push(`model_version = $${paramIndex++}`);
      params.push(filter.modelVersion);
    }
    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

    // For integrityTier and hasRegulatoryMarking we post-filter in JS because
    // those fields are not denormalized columns — they live inside the
    // canonical JSON. Pagination is applied AFTER post-filtering so the
    // result count matches the memory backend's slice semantics.
    const needsPostFilter =
      filter.integrityTier !== undefined || filter.hasRegulatoryMarking !== undefined;

    let sql = `SELECT * FROM model_descriptors ${where}`;
    if (!needsPostFilter) {
      if (filter.limit !== undefined) {
        sql += ` LIMIT $${paramIndex++}`;
        params.push(assertNonNegativeInteger(filter.limit, 'limit'));
      }
      if (filter.offset !== undefined) {
        sql += ` OFFSET $${paramIndex++}`;
        params.push(assertNonNegativeInteger(filter.offset, 'offset'));
      }
    }

    const result = await this.pool.query(sql, params);
    let rows = result.rows.map((r: Record<string, unknown>) =>
      this.rowToModelDescriptorRow(r as Parameters<PostgresStorageAdapter['rowToModelDescriptorRow']>[0]),
    );

    if (filter.integrityTier !== undefined) {
      rows = rows.filter((r) => r.descriptor.integrityTier === filter.integrityTier);
    }
    if (filter.hasRegulatoryMarking === true) {
      rows = rows.filter((r) => r.descriptor.regulatoryMarkings.length > 0);
    } else if (filter.hasRegulatoryMarking === false) {
      rows = rows.filter((r) => r.descriptor.regulatoryMarkings.length === 0);
    }

    if (needsPostFilter) {
      const offset = filter.offset !== undefined ? assertNonNegativeInteger(filter.offset, 'offset') : 0;
      const end = filter.limit !== undefined ? offset + assertNonNegativeInteger(filter.limit, 'limit') : undefined;
      rows = rows.slice(offset, end);
    }

    return rows;
  }

  async listDescendantDescriptors(parentDigest: string): Promise<ModelDescriptorRow[]> {
    const result = await this.pool.query(
      'SELECT * FROM model_descriptors WHERE parent_model_descriptor_digest = $1',
      [parentDigest],
    );
    return result.rows.map((r: Record<string, unknown>) =>
      this.rowToModelDescriptorRow(r as Parameters<PostgresStorageAdapter['rowToModelDescriptorRow']>[0]),
    );
  }

  async appendModelDescriptorAnnotation(annotation: ModelDescriptorAnnotationRow): Promise<void> {
    try {
      await this.pool.query(
        `INSERT INTO model_descriptor_annotations (
          annotation_id, model_descriptor_digest, annotated_at, annotated_by,
          annotation_type, value_json, retracts_annotation_id, signature, note
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          annotation.annotationId,
          annotation.modelDescriptorDigest,
          annotation.annotatedAt,
          annotation.annotatedBy,
          annotation.annotationType,
          annotation.valueJson,
          annotation.retractsAnnotationId,
          annotation.signature,
          annotation.note,
        ],
      );
    } catch (err) {
      throw translateConstraintError(err, {
        recordType: 'Model descriptor annotation',
        recordId: annotation.annotationId,
        reference: { type: 'model descriptor', id: annotation.modelDescriptorDigest },
      });
    }
  }

  async listModelDescriptorAnnotations(digest: string): Promise<ModelDescriptorAnnotationRow[]> {
    const result = await this.pool.query(
      `SELECT * FROM model_descriptor_annotations
       WHERE model_descriptor_digest = $1
       ORDER BY annotated_at ASC, annotation_id ASC`,
      [digest],
    );
    return result.rows.map((r: Record<string, unknown>) =>
      this.rowToAnnotationRow(r as Parameters<PostgresStorageAdapter['rowToAnnotationRow']>[0]),
    );
  }

  async setModelDescriptorAlias(slug: string, digest: string, setBy: string): Promise<void> {
    // PRIMARY KEY (slug, set_at): a rebind in the same millisecond replaces
    // that instant's row — last writer wins, on every adapter.
    await this.pool.query(
      `INSERT INTO model_descriptor_aliases (slug, set_at, model_descriptor_digest, set_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (slug, set_at) DO UPDATE SET
         model_descriptor_digest = EXCLUDED.model_descriptor_digest,
         set_by = EXCLUDED.set_by`,
      [slug, new Date().toISOString(), digest, setBy],
    );
  }

  async resolveModelDescriptorAlias(slug: string): Promise<string | null> {
    const result = await this.pool.query(
      `SELECT model_descriptor_digest FROM model_descriptor_aliases
       WHERE slug = $1 ORDER BY set_at DESC LIMIT 1`,
      [slug],
    );
    if (result.rows.length === 0) return null;
    return result.rows[0].model_descriptor_digest;
  }

  /**
   * Test-only helper: clears all three catalog tables so each test runs in
   * isolation. Not part of the public StorageAdapter interface. The chain of
   * TRUNCATE ... CASCADE handles the FK from annotations → descriptors.
   *
   * @internal
   */
  async truncateCatalogForTests(): Promise<void> {
    // model_descriptors carries a BEFORE TRUNCATE blocker, so this has to
    // step around it explicitly. `session_replication_role = 'replica'`
    // is scoped to the transaction and is a privileged GUC, so it does not
    // widen what a least-privileged DML role can do — it just makes the
    // test-only bypass visible instead of accidental.
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL session_replication_role = 'replica'");
      await client.query(
        'TRUNCATE TABLE model_descriptor_annotations, model_descriptor_aliases, model_descriptors RESTART IDENTITY CASCADE',
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => { /* ignore */ });
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * The store's first or newest record by `created_at` (it defaults to the
   * insertion time, and a writer with INSERT on the table can set it; ties by
   * `evidence_id`), as stored, or null. Only reads: on a schema with no
   * `envelopes` table yet it answers null and creates nothing, so
   * `Tzun.init()` runs the 0.7.0 store check with it before `ensureTables()`.
   * It reads through `idx_envelopes_created_at`, which `ensureTables()`
   * creates, so only the first open of a store written before that index
   * reads the whole table.
   */
  async readEnvelopeAtEnd(end: 'first' | 'newest'): Promise<unknown> {
    const present = await this.pool.query(`SELECT to_regclass('envelopes') IS NOT NULL AS present`);
    if (present.rows[0]?.present !== true) return null;
    const order = end === 'first' ? 'ASC' : 'DESC';
    const result = await this.pool.query(
      `SELECT envelope FROM envelopes ORDER BY created_at ${order}, evidence_id ${order} LIMIT 1`
    );
    return result.rows[0]?.envelope ?? null;
  }

  async head(): Promise<EvidenceEnvelope | null> {
    const result = await this.pool.query(
      `SELECT envelope FROM envelopes ORDER BY created_at DESC, evidence_id DESC LIMIT 1`
    );
    if (result.rows.length === 0) return null;
    return result.rows[0].envelope as EvidenceEnvelope;
  }

  // ── Demo-tamper hooks ──────────────────────────────

  private demoTamperView(): DemoTamperStoreView {
    return {
      hasSentinel: async () => {
        const result = await this.pool.query(
          'SELECT 1 FROM demo_tamper_sentinel LIMIT 1'
        );
        return result.rows.length > 0;
      },
      writeSentinel: async () => {
        await this.pool.query(
          'INSERT INTO demo_tamper_sentinel (owner, created_at) VALUES ($1, NOW())',
          [DEMO_SENTINEL_OWNER],
        );
      },
      envelopeCount: async () => {
        const result = await this.pool.query('SELECT COUNT(*) AS count FROM envelopes');
        return parseInt(result.rows[0].count, 10);
      },
      target: () => this.demoTamperTarget,
    };
  }

  async armDemoTamperHooks(): Promise<void> {
    this.demoHooksArmed = await tryArmDemoTamperHooks(this.demoTamperView(), 'postgres');
  }

  async deleteEnvelopeForDemo(evidenceId: string): Promise<void> {
    assertArmed(this.demoHooksArmed);
    // Bypass the append-only trigger by using session_replication_role.
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL session_replication_role = 'replica'");
      await client.query('DELETE FROM envelopes WHERE evidence_id = $1', [evidenceId]);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => { /* ignore */ });
      throw err;
    } finally {
      client.release();
    }
  }

  async overwriteModelDescriptorBytesForDemo(digest: string, canonicalBytes: string): Promise<string> {
    assertArmed(this.demoHooksArmed);
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // The demo's whole point is to make a descriptor row disagree with its
      // digest. model_descriptors.canonical_bytes is immutable under the
      // append-only triggers, so the demo has to opt out of the trigger the
      // same way deleteEnvelopeForDemo does — explicitly, inside one
      // transaction, and only after assertArmed().
      await client.query("SET LOCAL session_replication_role = 'replica'");
      const sel = await client.query(
        'SELECT canonical_bytes FROM model_descriptors WHERE model_descriptor_digest = $1',
        [digest],
      );
      if (sel.rows.length === 0) {
        await client.query('ROLLBACK');
        throw new Error(`No model descriptor row for digest ${digest}`);
      }
      const previous: string = sel.rows[0].canonical_bytes;
      await client.query(
        'UPDATE model_descriptors SET canonical_bytes = $1 WHERE model_descriptor_digest = $2',
        [canonicalBytes, digest],
      );
      await client.query('COMMIT');
      return previous;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => { /* ignore */ });
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * The durable credential directory held in this database.
   *
   * Shares this adapter's pool, so it participates in the same connection
   * budget and the same lifetime — `close()` ends both.
   */
  credentialStore(): AsyncCredentialStore {
    return new PostgresCredentialStore(this.pool);
  }

  /** The store's identity and evidence logs, on this adapter's pool (Anchor §3, §4.3.2). */
  logStore(): LogStore {
    return new PostgresLogStore(this.pool);
  }

  /** The anchoring tables the anchor scheduler writes, on this adapter's pool. */
  anchorStore(): AnchorStore {
    return new PostgresLogStore(this.pool);
  }

  /**
   * Close the connection pool.
   * Must be called when the adapter is no longer needed.
   */
  async close(): Promise<void> {
    await this.pool.end();
  }
}
