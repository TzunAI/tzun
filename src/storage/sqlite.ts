import Database from 'better-sqlite3';
import { chmodSync } from 'fs';
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
import { fillAbsentArtifacts, statusAfterFill } from './attestation-fill';
import { assertNonNegativeInteger } from './pagination-guard';
import { assertRetryObtainableComponents } from './missing-obtainable';
import { AsyncCredentialStore } from '../attestation/credential-store';
import {
  CREDENTIAL_SCHEMA_SQLITE,
  CredentialStoreProvider,
  SqliteCredentialStore,
} from './credential-stores';
import {
  assertArmed,
  DEMO_SENTINEL_OWNER,
  DemoTamperStoreView,
  tryArmDemoTamperHooks,
} from './demo-tamper-guard';
import { assertDescriptorIntegrityInvariants } from '../models/descriptor-invariants';
import { DuplicateRecordError, EXISTING_ROW_TAG, translateConstraintError } from './append-only';
import {
  CAPTURE_REVISION_NO,
  REVISION_ACTOR_ATTESTATION,
  REVISION_ACTOR_RECOVERY,
  captureRevisionActor,
  nextRevisionNo,
} from './revision-log';
import { capturedAtInstantMs } from './list-order';
import {
  AnchorStore,
  AnchorStoreProvider,
  LogSchemaOptions,
  LogStore,
  LogStoreProvider,
  SqliteLogStore,
  ENVELOPES_POSITION_INDEX,
  assertEvidenceLogChainId,
  assertSqliteUtf8,
  migrateSqliteLogSchema,
  translateEvidenceLogError,
} from './log-store';

/**
 * True when `dbPath` names a real file SQLite will create on disk.
 *
 * `:memory:` and the empty string (SQLite's private temporary database) have no
 * file to chmod, and attempting to narrow the umask around them would be a
 * pointless global side effect.
 */
function isOnDiskPath(dbPath: string): boolean {
  return dbPath !== ':memory:' && dbPath !== '';
}

/**
 * The DELETE guard on `envelopes`, as one statement because two places install
 * it: `createTables()`, and `deleteEnvelopeForDemo()`, which lifts it for the
 * demo hook's one DELETE and puts it back inside the same transaction.
 */
const ENVELOPES_BLOCK_DELETE_TRIGGER = `
  CREATE TRIGGER IF NOT EXISTS envelopes_block_delete
    BEFORE DELETE ON envelopes
    BEGIN SELECT RAISE(ABORT, 'envelopes rows cannot be deleted (append-only evidence)'); END;
`;

/** custody_entries row → StoredCustodyEntry. */
function custodyRowFromSqlite(row: Record<string, unknown>): StoredCustodyEntry {
  return {
    id: row.id as number,
    evidenceId: row.evidence_id as string,
    chainId: (row.chain_id as string | null) ?? null,
    canonicalDigest: row.canonical_digest as string,
    action: row.action as StoredCustodyEntry['action'],
    actor: row.actor as string,
    timestamp: row.ts as string,
    systemId: row.system_id as string,
    metadata: row.metadata == null ? null : (JSON.parse(row.metadata as string) as Record<string, unknown>),
    prevEntryHash: (row.prev_entry_hash as string | null) ?? null,
    entryHash: row.entry_hash as string,
    recoveryId: (row.recovery_id as string | null) ?? null,
  };
}

/** envelope_revisions row → EnvelopeRevision. */
function revisionRowFromSqlite(row: Record<string, unknown>): EnvelopeRevision {
  return {
    evidenceId: row.evidence_id as string,
    revisionNo: row.revision_no as number,
    canonicalDigest: row.canonical_digest as string,
    chainLink: (row.chain_link as string | null) ?? null,
    recordedAt: row.recorded_at as string,
    cause: row.cause as RevisionCause,
    actor: row.actor as string,
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
    forkedAt: row.forked_at as string,
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
 * `updateAttestation()` fills (`isAbsent`); `json_extract` reads the first two
 * as SQL NULL.
 */
const SQLITE_MISSING_COMPONENT: Record<RetryObtainableComponent, string> = {
  timestamp:
    "(json_extract(envelope, '$.nonRepudiation.rfc3161Token') IS NULL" +
    " OR json_extract(envelope, '$.nonRepudiation.rfc3161Token') = '')",
};

/**
 * SQLite storage adapter for local mode.
 *
 * Stores evidence envelopes as JSON blobs in a SQLite database.
 * Indexed columns enable efficient querying by evidenceId, capturedAt, and aiSystemId.
 *
 * APPEND-ONLY, ENFORCED IN THE DATABASE. `store()` refuses to overwrite an
 * existing evidenceId, and the triggers `createTables()` installs refuse the
 * rest, whoever issues the statement — this adapter, a migration script, or
 * someone at a `sqlite3` prompt:
 *
 *   - `envelopes`: the payload (every field, `schemaVersion` included),
 *     `integrity.canonicalDigest`, and the evidence_id, digest, captured_at,
 *     captured_at_ms, chain_id and ai_system_id columns never change;
 *     `custodyChain` only grows, its existing entries never change, and an
 *     appended entry that carries an `entryHash` must have a `custody_entries`
 *     row; rows are never deleted. The writes this adapter makes are the ones
 *     the triggers leave open: `integrity.chainLink` (relink's repair),
 *     `nonRepudiation` and `attestationStatus` (attestation retry), and custody
 *     appends.
 *   - `custody_entries`: append-only, and every inserted row is bound to its
 *     record and recomputed from its fields.
 *   - `envelope_revisions`, `chain_forks`, `chain_annotations`,
 *     `chain_relinks`: append-only.
 *   - `chains`: identity columns fixed, a seal final, rows never deleted.
 *   - the seven tables above (`envelopes`, `chains`, `custody_entries`,
 *     `envelope_revisions`, `chain_forks`, `chain_annotations`,
 *     `chain_relinks`): no insert over an existing row, whatever its conflict
 *     clause, and no row at a negative rowid; on `envelopes` and `chains`,
 *     whose UPDATE triggers let some updates through, a rowid never changes;
 *     on `envelopes` a rowid written explicitly is not below the first row's
 *     (the 0.7.0 store check reads the lowest rowid as the store's first
 *     record); on `custody_entries` an id written explicitly is above every
 *     existing one. SQLite's REPLACE deletes the row an INSERT OR REPLACE or an
 *     UPDATE OR REPLACE conflicts with without firing a DELETE or UPDATE
 *     trigger, so the rules above would not hold on these tables without
 *     this.
 *   - the evidence logs (log-store.ts): `store_identity` immutable; `logs`
 *     and `log_leaves` insert-only, a leaf written once, only after its
 *     predecessor, and never repeating a record or digest of its log;
 *     `log_checkpoints` insert-only but for appended signatures;
 *     `anchor_publications` never deleted, its state moving forward only.
 *     The trigger on `envelopes` writes each record's leaf inside the
 *     transaction that stores it, and calls no function this adapter
 *     registers, so any connection's insert gets its leaf.
 *   - the evidence-log and anchoring tables, and `credential_events`
 *     (credential-stores.ts): no insert over an existing row, whatever its
 *     conflict clause, and no row at a negative rowid; where an UPDATE
 *     trigger lets some updates through, a rowid never changes, and a
 *     publication never takes a sender and nonce another holds; on `logs`,
 *     `anchor_publications` and `credential_events`, which are read in id
 *     order, an id written explicitly is above every existing one.
 *     `anchor_lease` is mutable, and taken through an upsert.
 *
 * What the triggers do not stop: SQLite has no privilege model, so anyone who
 * can write the file can DROP TRIGGER. That is a schema change rather than a
 * row edit, and it is the only way past. Against a writer who makes it, the
 * guarantee is detection — the chain digest, external attestation, revision 0
 * of the revision log, and `verify()` / `ScheduledScanner`. The one path in
 * this file that lifts a trigger is the demo delete hook, and only after the
 * arming guard has passed, for its one statement, inside one transaction.
 */
/** Options of {@link SqliteStorageAdapter}. */
export interface SqliteAdapterOptions extends LogSchemaOptions {
  /**
   * The storage extensions this adapter installs (`extensions.ts`): their
   * tables, their `store()` hooks and the optional adapter methods they
   * provide. Default: `DEFAULT_STORAGE_EXTENSIONS`.
   */
  extensions?: readonly StorageExtension[];
}

export class SqliteStorageAdapter
  implements StorageAdapter, CredentialStoreProvider, LogStoreProvider, AnchorStoreProvider
{
  private db: Database.Database;

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

  // Demo-tamper hooks state.
  private demoHooksArmed = false;

  /**
   * Absolute-or-relative path this adapter opened, or null for in-memory /
   * anonymous databases. Kept so the WAL and SHM sidecars can be re-hardened
   * after they are (re)created lazily by SQLite.
   */
  private readonly dbPath: string | null;

  /**
   * @param dbPath - The database file, or `:memory:`.
   * @param options - `logNamespace`: the namespace a new store's identity is
   *   minted with; on a store that has one, a different value is refused
   *   (`LogNamespaceMismatchError`).
   * @throws {SqliteEncodingError} when the file's text encoding is not UTF-8.
   */
  constructor(dbPath: string, options: SqliteAdapterOptions = {}) {
    this.extensions = options.extensions ?? DEFAULT_STORAGE_EXTENSIONS;
    assertUniqueExtensionNames(this.extensions);
    // Evidence at rest is confidential: envelopes carry aiOutput, reason,
    // WebAuthn assertions and custody actors. Under the usual 022/002 process
    // umask the database file would be born mode 0644, and every other local
    // account on a shared build box, CI runner or container volume could read
    // the entire decision history out of ./tzun.db. Narrow the umask around the
    // open so the file, and the -wal/-shm sidecars that `journal_mode = WAL`
    // creates, are born 0600 rather than being widened for the instant between
    // creation and a follow-up chmod.
    this.dbPath = isOnDiskPath(dbPath) ? dbPath : null;
    const previousUmask = this.dbPath !== null ? process.umask(0o077) : null;
    let db: Database.Database | undefined;
    try {
      db = new Database(dbPath);
      this.db = db;
      // Before any DDL: the evidence-log origins are computed in SQL from the
      // chain id's bytes in the database's text encoding, which must be UTF-8.
      assertSqliteUtf8(db);
      this.db.pragma('journal_mode = WAL');
      this.db.pragma('foreign_keys = ON');
      this.registerCustodyFunctions();
      this.createTables(options);
      for (const ext of this.extensions) ext.sqlite?.migrate(this.db);
      installExtensionMethods(
        this,
        mergeExtensionMethods(this.extensions.map((ext) => ({ name: ext.name, methods: ext.sqlite?.methods?.(this.db) }))),
      );
    } catch (err) {
      db?.close();
      throw err;
    } finally {
      if (previousUmask !== null) process.umask(previousUmask);
    }
    // Belt and braces: an existing database created by an older SDK build (or
    // by a wider umask) is narrowed on open too, and the sidecars are chmod'd
    // in case SQLite created them before the umask was in force.
    this.hardenFilePermissions();
  }

  /**
   * Restrict the database file and its WAL/SHM sidecars to owner-only (0600).
   *
   * Best-effort: a missing sidecar (ENOENT — WAL not yet materialised), a
   * filesystem without POSIX modes, or a non-owner process must not turn a
   * successful open into a thrown constructor. The umask narrowing in the
   * constructor is the primary mechanism; this is the repair path for files
   * that already existed.
   */
  private hardenFilePermissions(): void {
    if (this.dbPath === null) return;
    for (const p of [this.dbPath, `${this.dbPath}-wal`, `${this.dbPath}-shm`]) {
      try {
        chmodSync(p, 0o600);
      } catch {
        // Sidecar absent or mode unsupported — nothing to harden.
      }
    }
  }

  /**
   * The SQL functions the `custody_entries` INSERT trigger calls.
   * Both are the engine's one hash rule, reached from SQL:
   *
   *   - `custody_entries_canonical_metadata(metadata)` — the engine-canonical
   *     bytes of the metadata JSON, which the trigger requires
   *     `metadata_canonical` to equal.
   *   - `custody_entries_entry_hash(prev, evidence_id, canonical_digest,
   *     action, actor, ts, system_id, metadata)` — `computeCustodyEntryHash`
   *     over the row. Hashing the metadata JSON rather than
   *     `metadata_canonical` is the same hash, because the trigger has
   *     already required the two to agree.
   *
   * A value of the wrong type, or metadata that is not a JSON object, throws,
   * and the INSERT fails with it: nothing is coerced into a hash.
   */
  private registerCustodyFunctions(): void {
    const text = (value: unknown, column: string): string | null => {
      if (value === null || typeof value === 'string') return value;
      throw new TypeError(`custody_entries.${column} must be text`);
    };
    const metadataOf = (value: unknown): Record<string, unknown> | null => {
      const raw = text(value, 'metadata');
      if (raw === null) return null;
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new TypeError('custody_entries.metadata must be a JSON object');
      }
      return parsed as Record<string, unknown>;
    };
    this.db.function(
      'custody_entries_canonical_metadata',
      { deterministic: true },
      (metadata: unknown) => canonicalCustodyMetadata(metadataOf(metadata)),
    );
    this.db.function(
      'custody_entries_entry_hash',
      { deterministic: true },
      (
        prevEntryHash: unknown,
        evidenceId: unknown,
        canonicalDigest: unknown,
        action: unknown,
        actor: unknown,
        ts: unknown,
        systemId: unknown,
        metadata: unknown,
      ) =>
        computeCustodyEntryHash({
          prevEntryHash: text(prevEntryHash, 'prev_entry_hash'),
          evidenceId: text(evidenceId, 'evidence_id') as string,
          canonicalDigest: text(canonicalDigest, 'canonical_digest') as string,
          action: text(action, 'action') as string,
          actor: text(actor, 'actor') as string,
          timestamp: text(ts, 'ts') as string,
          systemId: text(systemId, 'system_id') as string,
          metadata: metadataOf(metadata),
        }),
    );
  }

  /**
   * Replace a pre-per-chain `chain_state` with the per-chain table, seeding one
   * row per chain from the records themselves.
   *
   * `CREATE TABLE IF NOT EXISTS` skips a table that already exists, so a store
   * written by an earlier build keeps the single `id = 1` row and every append
   * then fails on a column that is not there. The schema in this repo is one
   * evolving pre-release schema with no migration files, so the evolution
   * happens here: the old table goes, the new one is created by
   * `createTables()`, and each chain's row is seeded from its highest sequence
   * number and the digest of the record holding it.
   *
   * That seed is exact for a store nothing has deleted from, which is every
   * store at upgrade time. On a store already missing a chain's tail the
   * high-water mark comes back short by exactly what was deleted — the one
   * thing no recomputation can recover, because the counter that remembered it
   * is the thing being replaced.
   *
   * A no-op on a store that has the per-chain table, and on a store that has no
   * `chain_state` at all.
   */
  private evolveLegacyChainState(): void {
    const columns = this.db.prepare("PRAGMA table_info('chain_state')").all() as Array<{ name: string }>;
    if (columns.length === 0 || columns.some((c) => c.name === 'chain_id')) return;
    this.db.transaction(() => {
      this.db.exec('DROP TABLE chain_state');
      this.db.exec(`
        CREATE TABLE chain_state (
          chain_id TEXT PRIMARY KEY,
          last_digest TEXT NOT NULL,
          last_sequence INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
      `);
      this.db.exec(`
        INSERT INTO chain_state (chain_id, last_digest, last_sequence)
        SELECT e.chain_id,
               (SELECT t.digest FROM envelopes t
                 WHERE t.chain_id = e.chain_id
                 ORDER BY json_extract(t.envelope, '$.payload.sequenceNumber') DESC, t.rowid DESC
                 LIMIT 1),
               MAX(json_extract(e.envelope, '$.payload.sequenceNumber'))
          FROM envelopes e
         GROUP BY e.chain_id
      `);
    })();
  }

  /**
   * Add `tamper_incidents.last_observed_at` to a store written by an earlier
   * build (tzun-sdk 0.4.6).
   *
   * `CREATE TABLE IF NOT EXISTS` skips a table that already exists, so without
   * this the column is simply absent and every `storeIncident()` then fails on
   * `no such column` — the same class of hard break `evolveLegacyChainState`
   * exists for, so it gets the same treatment. One evolving pre-release schema,
   * no migration files.
   *
   * Cheaper than that one, though: the column is nullable and there is nothing
   * to backfill. A pass BEFORE the upgrade recorded no observation, and
   * inventing one would claim a scan saw a finding at a time no scan was
   * looking. The rows stay NULL and are counted in neither direction until the
   * next pass observes their finding for real.
   *
   * A no-op on a fresh store (no table yet — `createTables` makes it with the
   * column) and on one already upgraded.
   */
  private addIncidentObservationColumn(): void {
    const columns = this.db
      .prepare("PRAGMA table_info('tamper_incidents')")
      .all() as Array<{ name: string }>;
    if (columns.length === 0 || columns.some((c) => c.name === 'last_observed_at')) return;
    this.db.exec('ALTER TABLE tamper_incidents ADD COLUMN last_observed_at TEXT');
  }

  /** Create or evolve the schema, then run the evidence-log migration. */
  private createTables(options: LogSchemaOptions): void {
    this.evolveLegacyChainState();
    this.addIncidentObservationColumn();
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS envelopes (
        evidence_id TEXT PRIMARY KEY,
        envelope JSON NOT NULL,
        captured_at TEXT NOT NULL,
        -- The UTC instant of captured_at in epoch milliseconds, computed by the
        -- SDK on insert (src/storage/list-order.ts) and the key list() orders
        -- on. captured_at itself is the integrator's string, kept verbatim;
        -- ordering on it was lexicographic and wrong for anything that was not
        -- uniform ms-precision UTC. NULL when the string does not parse.
        captured_at_ms INTEGER,
        ai_system_id TEXT NOT NULL,
        digest TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        -- The chain this record belongs to. Every chain-scoped read goes
        -- through it: list({chainId}) and listBySequence() filter on it,
        -- getChainForRecord() returns it, and getActiveChainId() resolves the
        -- store's active chain from SELECT DISTINCT chain_id. NOT NULL with
        -- a default, so a store that never forks is one chain named
        -- 'default'.
        chain_id TEXT NOT NULL DEFAULT 'default'
      );

      CREATE INDEX IF NOT EXISTS idx_envelopes_captured_at ON envelopes(captured_at);
      CREATE INDEX IF NOT EXISTS idx_envelopes_ai_system_id ON envelopes(ai_system_id);
      -- The key list() orders on.
      CREATE INDEX IF NOT EXISTS idx_envelopes_captured_at_ms ON envelopes(captured_at_ms);
      -- getActiveChainId() reads SELECT DISTINCT chain_id on every
      -- resolution; this covering index is what keeps that off
      -- a table scan.
      CREATE INDEX IF NOT EXISTS idx_envelopes_chain_id ON envelopes(chain_id);
      -- The attestation-status reads:
      -- listByAttestationStatus() and listByMissingObtainable() seek one status
      -- and read it oldest first, so the status leads and the order key follows
      -- it in the index.
      CREATE INDEX IF NOT EXISTS idx_envelopes_attestation_status
        ON envelopes(json_extract(envelope, '$.attestationStatus'), captured_at_ms);
      -- Append-only evidence, frozen where the Postgres
      -- adapter's envelopes_enforce_immutable freezes it. Rewriting chain_id
      -- or ai_system_id moves a record out of every scoped read without
      -- touching a hashed byte, so those columns are frozen with the rest.
      -- json_extract compares the stored JSON text, which is what every
      -- write in this file produces from a parse/stringify round trip, so an
      -- untouched field reads back byte for byte. custodyChain may only grow:
      -- it stays an array, gets no shorter, and every entry it had is still
      -- there, unchanged, at the same index.
      CREATE TRIGGER IF NOT EXISTS envelopes_enforce_immutable
        BEFORE UPDATE ON envelopes
        BEGIN
          SELECT RAISE(ABORT, 'envelopes.evidence_id is immutable')
           WHERE NEW.evidence_id IS NOT OLD.evidence_id;
          SELECT RAISE(ABORT, 'envelopes.digest is immutable')
           WHERE NEW.digest IS NOT OLD.digest;
          SELECT RAISE(ABORT, 'envelopes.captured_at is immutable')
           WHERE NEW.captured_at IS NOT OLD.captured_at
              OR NEW.captured_at_ms IS NOT OLD.captured_at_ms;
          SELECT RAISE(ABORT, 'envelopes.chain_id is immutable')
           WHERE NEW.chain_id IS NOT OLD.chain_id;
          SELECT RAISE(ABORT, 'envelopes.ai_system_id is immutable')
           WHERE NEW.ai_system_id IS NOT OLD.ai_system_id;
          SELECT RAISE(ABORT, 'envelopes.envelope.payload is immutable (append-only evidence)')
           WHERE json_extract(NEW.envelope, '$.payload') IS NOT json_extract(OLD.envelope, '$.payload');
          SELECT RAISE(ABORT, 'envelopes.envelope.integrity.canonicalDigest is immutable')
           WHERE json_extract(NEW.envelope, '$.integrity.canonicalDigest')
              IS NOT json_extract(OLD.envelope, '$.integrity.canonicalDigest');
          SELECT RAISE(ABORT, 'envelopes.envelope.custodyChain is append-only')
           WHERE json_extract(NEW.envelope, '$.custodyChain') IS NOT json_extract(OLD.envelope, '$.custodyChain')
             AND (
               json_type(NEW.envelope, '$.custodyChain') IS NOT 'array'
               OR json_type(COALESCE(json_extract(OLD.envelope, '$.custodyChain'), '[]')) IS NOT 'array'
               OR json_array_length(NEW.envelope, '$.custodyChain')
                    < json_array_length(COALESCE(json_extract(OLD.envelope, '$.custodyChain'), '[]'))
               OR EXISTS (
                 SELECT 1
                   FROM json_each(COALESCE(json_extract(OLD.envelope, '$.custodyChain'), '[]')) AS old_entry
                  WHERE json_type(NEW.envelope, '$.custodyChain[' || old_entry.key || ']') IS NOT old_entry.type
                     OR json_extract(NEW.envelope, '$.custodyChain[' || old_entry.key || ']') IS NOT old_entry.value
               )
             );
          -- An appended entry that carries an entryHash claims to be the
          -- mirror of a custody_entries row; it must be one, for this record.
          -- Unhashed appends stay permitted: they are the
          -- client-attested form, and verifiers report them as unhashed.
          SELECT RAISE(ABORT, 'envelopes.envelope.custodyChain entry claims an entryHash with no custody_entries row')
           WHERE EXISTS (
             SELECT 1
               FROM json_each(NEW.envelope, '$.custodyChain') AS new_entry
              WHERE new_entry.key >= COALESCE(json_array_length(OLD.envelope, '$.custodyChain'), 0)
                AND new_entry.type = 'object'
                AND json_type(new_entry.value, '$.entryHash') IS NOT NULL
                AND NOT EXISTS (
                  SELECT 1 FROM custody_entries
                   WHERE custody_entries.evidence_id = OLD.evidence_id
                     AND custody_entries.entry_hash = json_extract(new_entry.value, '$.entryHash')
                )
           );
        END;
      ${ENVELOPES_BLOCK_DELETE_TRIGGER}
      -- No insert over an existing row. REPLACE conflict
      -- resolution (INSERT OR REPLACE, REPLACE INTO) deletes the row an
      -- insert conflicts with and then inserts; that delete fires no DELETE
      -- trigger unless recursive_triggers is on, and no UPDATE trigger fires
      -- at all, so without this guard REPLACE swaps a row past both triggers
      -- above. A BEFORE INSERT trigger runs before conflict handling, so an
      -- insert naming an evidence_id or a rowid a row already holds is
      -- refused whatever its conflict clause, as log_leaves_verify_insert
      -- refuses an occupied position. An insert that names no rowid reads
      -- NEW.rowid as -1 here; SQLite never assigns a negative rowid itself,
      -- and envelopes_block_negative_rowid refuses one written explicitly, so
      -- no row holds -1. The same guard sits on chains, custody_entries,
      -- envelope_revisions, chain_annotations, chain_relinks and chain_forks
      -- below.
      CREATE TRIGGER IF NOT EXISTS envelopes_block_replace
        BEFORE INSERT ON envelopes
        BEGIN
          SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} envelopes rows are append-only (INSERT over an existing row refused)')
           WHERE EXISTS (SELECT 1 FROM envelopes WHERE evidence_id = NEW.evidence_id)
              OR EXISTS (SELECT 1 FROM envelopes WHERE rowid = NEW.rowid);
        END;
      -- No row at a negative rowid. A row planted at -1 would make every
      -- later insert, which reads NEW.rowid as -1 in envelopes_block_replace,
      -- collide with it. AFTER INSERT, because only there does NEW.rowid tell
      -- a rowid of -1 written explicitly from none. The same guard sits on
      -- every table with a *_block_replace guard.
      CREATE TRIGGER IF NOT EXISTS envelopes_block_negative_rowid
        AFTER INSERT ON envelopes
        BEGIN
          SELECT RAISE(ABORT, 'envelopes: a rowid cannot be negative')
           WHERE NEW.rowid < 0;
        END;
      -- No record written ahead of the first. Tzun.init() reads the lowest
      -- rowid as the store's first record, and the 0.7.0 store check decides
      -- by it whether the store opens, so a row planted at an explicit rowid
      -- below every other would decide that. An insert that names no rowid
      -- reads NEW.rowid as -1 here, and gets the next one; an explicit -1 is
      -- left to envelopes_block_negative_rowid, and an empty table has no
      -- first row.
      CREATE TRIGGER IF NOT EXISTS envelopes_block_low_rowid
        BEFORE INSERT ON envelopes
        BEGIN
          SELECT RAISE(ABORT, 'envelopes: an explicit rowid cannot be below the first row''s')
           WHERE NEW.rowid <> -1
             AND NEW.rowid < (SELECT MIN(rowid) FROM envelopes);
        END;
      -- A record's rowid never changes. UPDATE OR REPLACE ... SET rowid = N
      -- deletes the row that holds N, as INSERT OR REPLACE does, and fires no
      -- DELETE trigger; the record deleted that way could then be inserted
      -- again, rewritten, past envelopes_block_replace. A plain rowid change
      -- reorders head(), which reads the highest rowid. A trigger of its own
      -- rather than a line in envelopes_enforce_immutable, so that a store
      -- written before it gets it: CREATE TRIGGER IF NOT EXISTS leaves an
      -- existing trigger's body as it was.
      CREATE TRIGGER IF NOT EXISTS envelopes_block_rowid_change
        BEFORE UPDATE ON envelopes
        BEGIN
          SELECT RAISE(ABORT, 'envelopes.rowid is immutable')
           WHERE NEW.rowid IS NOT OLD.rowid;
        END;

      CREATE TABLE IF NOT EXISTS failures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        failure_type TEXT NOT NULL,
        evidence_id TEXT,
        diagnostic_metadata JSON NOT NULL,
        captured_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      -- One head per chain. This was a single row
      -- (id INTEGER PRIMARY KEY CHECK (id = 1)) shared by every chain, so a
      -- second chain's first record took the first chain's next sequence
      -- number and linked from its head: born unverifiable, and a fork of one
      -- chain wiped every other chain's high-water mark.
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
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS tamper_incidents (
        id TEXT PRIMARY KEY,
        detected_at TEXT NOT NULL,
        severity TEXT NOT NULL,
        type TEXT NOT NULL,
        affected_records TEXT NOT NULL,
        affected_sequence_range TEXT,
        details TEXT NOT NULL,
        status TEXT NOT NULL,
        -- When a scan last observed this incident's finding. See
        -- TamperIncident.lastObservedAt: it is what tells a reviewed finding
        -- that is still there from one a later pass no longer sees.
        last_observed_at TEXT,
        resolved_at TEXT,
        resolved_by TEXT,
        resolution_notes TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_tamper_incidents_status ON tamper_incidents(status);
      CREATE INDEX IF NOT EXISTS idx_tamper_incidents_severity ON tamper_incidents(severity);

      CREATE TABLE IF NOT EXISTS chains (
        chain_id TEXT PRIMARY KEY,
        parent_chain_id TEXT,
        fork_point INTEGER,
        status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL,
        sealed_at TEXT
      );
      -- Forward-only. status is what every append reads to
      -- refuse a sealed chain, so the column is guarded where it lives: the
      -- identity columns never change, a seal is never lifted or re-dated,
      -- and a row is never deleted (a chain with no row is open). Sealing an
      -- active chain is the one transition the table allows. The same caveat
      -- as custody_entries below: dropping a trigger is a schema change, not
      -- a row edit.
      CREATE TRIGGER IF NOT EXISTS chains_enforce_immutable
        BEFORE UPDATE ON chains
        BEGIN
          SELECT RAISE(ABORT, 'chains identity columns are immutable (chain_id, parent_chain_id, fork_point, created_at)')
           WHERE NEW.chain_id IS NOT OLD.chain_id
              OR NEW.parent_chain_id IS NOT OLD.parent_chain_id
              OR NEW.fork_point IS NOT OLD.fork_point
              OR NEW.created_at IS NOT OLD.created_at;
          SELECT RAISE(ABORT, 'chain is sealed: a seal cannot be lifted or re-dated')
           WHERE OLD.status = 'sealed'
             AND (NEW.status IS NOT OLD.status OR NEW.sealed_at IS NOT OLD.sealed_at);
        END;
      CREATE TRIGGER IF NOT EXISTS chains_block_delete
        BEFORE DELETE ON chains
        BEGIN SELECT RAISE(ABORT, 'chains rows cannot be deleted (DELETE refused)'); END;
      -- No insert over an existing row, no row at a negative rowid, and a
      -- rowid that never changes: see envelopes_block_replace,
      -- envelopes_block_negative_rowid and envelopes_block_rowid_change.
      -- REPLACE would otherwise lift a seal by writing the row again as
      -- active, and UPDATE OR REPLACE ... SET rowid would delete the sealed
      -- row so that it could be.
      CREATE TRIGGER IF NOT EXISTS chains_block_replace
        BEFORE INSERT ON chains
        BEGIN
          SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} chains rows are append-only (INSERT over an existing row refused)')
           WHERE EXISTS (SELECT 1 FROM chains WHERE chain_id = NEW.chain_id)
              OR EXISTS (SELECT 1 FROM chains WHERE rowid = NEW.rowid);
        END;
      CREATE TRIGGER IF NOT EXISTS chains_block_negative_rowid
        AFTER INSERT ON chains
        BEGIN
          SELECT RAISE(ABORT, 'chains: a rowid cannot be negative')
           WHERE NEW.rowid < 0;
        END;
      CREATE TRIGGER IF NOT EXISTS chains_block_rowid_change
        BEFORE UPDATE ON chains
        BEGIN
          SELECT RAISE(ABORT, 'chains.rowid is immutable')
           WHERE NEW.rowid IS NOT OLD.rowid;
        END;

      CREATE TABLE IF NOT EXISTS chain_annotations (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        affected_records JSON NOT NULL,
        annotated_at TEXT NOT NULL,
        annotated_by TEXT NOT NULL,
        notes TEXT NOT NULL,
        original_digests JSON NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_chain_annotations_incident ON chain_annotations(incident_id);
      -- Recovery records are append-only, as the hosted service's recoveries
      -- table is: who annotated or re-linked what, and the digests and links
      -- as they stood, never change once written.
      CREATE TRIGGER IF NOT EXISTS chain_annotations_block_update
        BEFORE UPDATE ON chain_annotations
        BEGIN SELECT RAISE(ABORT, 'chain_annotations rows are append-only (UPDATE refused)'); END;
      CREATE TRIGGER IF NOT EXISTS chain_annotations_block_delete
        BEFORE DELETE ON chain_annotations
        BEGIN SELECT RAISE(ABORT, 'chain_annotations rows are append-only (DELETE refused)'); END;
      -- No insert over an existing row and no row at a negative rowid: see
      -- envelopes_block_replace and envelopes_block_negative_rowid. The
      -- UPDATE trigger above refuses every update, a rowid change included.
      CREATE TRIGGER IF NOT EXISTS chain_annotations_block_replace
        BEFORE INSERT ON chain_annotations
        BEGIN
          SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} chain_annotations rows are append-only (INSERT over an existing row refused)')
           WHERE EXISTS (SELECT 1 FROM chain_annotations WHERE id = NEW.id)
              OR EXISTS (SELECT 1 FROM chain_annotations WHERE rowid = NEW.rowid);
        END;
      CREATE TRIGGER IF NOT EXISTS chain_annotations_block_negative_rowid
        AFTER INSERT ON chain_annotations
        BEGIN
          SELECT RAISE(ABORT, 'chain_annotations: a rowid cannot be negative')
           WHERE NEW.rowid < 0;
        END;

      CREATE TABLE IF NOT EXISTS chain_relinks (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        relinked_at TEXT NOT NULL,
        relinked_by TEXT NOT NULL,
        from_sequence INTEGER NOT NULL,
        to_sequence INTEGER NOT NULL,
        modified_links JSON NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_chain_relinks_incident ON chain_relinks(incident_id);
      CREATE TRIGGER IF NOT EXISTS chain_relinks_block_update
        BEFORE UPDATE ON chain_relinks
        BEGIN SELECT RAISE(ABORT, 'chain_relinks rows are append-only (UPDATE refused)'); END;
      CREATE TRIGGER IF NOT EXISTS chain_relinks_block_delete
        BEFORE DELETE ON chain_relinks
        BEGIN SELECT RAISE(ABORT, 'chain_relinks rows are append-only (DELETE refused)'); END;
      -- No insert over an existing row and no row at a negative rowid: see
      -- envelopes_block_replace and envelopes_block_negative_rowid. The
      -- UPDATE trigger above refuses every update, a rowid change included.
      CREATE TRIGGER IF NOT EXISTS chain_relinks_block_replace
        BEFORE INSERT ON chain_relinks
        BEGIN
          SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} chain_relinks rows are append-only (INSERT over an existing row refused)')
           WHERE EXISTS (SELECT 1 FROM chain_relinks WHERE id = NEW.id)
              OR EXISTS (SELECT 1 FROM chain_relinks WHERE rowid = NEW.rowid);
        END;
      CREATE TRIGGER IF NOT EXISTS chain_relinks_block_negative_rowid
        AFTER INSERT ON chain_relinks
        BEGIN
          SELECT RAISE(ABORT, 'chain_relinks: a rowid cannot be negative')
           WHERE NEW.rowid < 0;
        END;

      CREATE TABLE IF NOT EXISTS chain_forks (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        forked_at TEXT NOT NULL,
        forked_by TEXT NOT NULL,
        reason TEXT NOT NULL,
        old_chain_id TEXT NOT NULL,
        new_chain_id TEXT NOT NULL,
        fork_after_sequence INTEGER NOT NULL,
        sealed_old_chain_length INTEGER NOT NULL,
        sealed_old_chain_head INTEGER,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE INDEX IF NOT EXISTS idx_chain_forks_incident ON chain_forks(incident_id);
      CREATE INDEX IF NOT EXISTS idx_chain_forks_old_chain ON chain_forks(old_chain_id);
      CREATE INDEX IF NOT EXISTS idx_chain_forks_new_chain ON chain_forks(new_chain_id);
      -- Append-only. sealed_old_chain_head is the sealed
      -- chain's high-water mark, the bound chainUpperBound() hands every
      -- verifier; lowering it to match a deleted tail would make the deletion
      -- invisible.
      CREATE TRIGGER IF NOT EXISTS chain_forks_block_update
        BEFORE UPDATE ON chain_forks
        BEGIN SELECT RAISE(ABORT, 'chain_forks rows are append-only (UPDATE refused)'); END;
      CREATE TRIGGER IF NOT EXISTS chain_forks_block_delete
        BEFORE DELETE ON chain_forks
        BEGIN SELECT RAISE(ABORT, 'chain_forks rows are append-only (DELETE refused)'); END;
      -- No insert over an existing row and no row at a negative rowid: see
      -- envelopes_block_replace and envelopes_block_negative_rowid. The
      -- UPDATE trigger above refuses every update, a rowid change included.
      CREATE TRIGGER IF NOT EXISTS chain_forks_block_replace
        BEFORE INSERT ON chain_forks
        BEGIN
          SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} chain_forks rows are append-only (INSERT over an existing row refused)')
           WHERE EXISTS (SELECT 1 FROM chain_forks WHERE id = NEW.id)
              OR EXISTS (SELECT 1 FROM chain_forks WHERE rowid = NEW.rowid);
        END;
      CREATE TRIGGER IF NOT EXISTS chain_forks_block_negative_rowid
        AFTER INSERT ON chain_forks
        BEGIN
          SELECT RAISE(ABORT, 'chain_forks: a rowid cannot be negative')
           WHERE NEW.rowid < 0;
        END;

      -- AI-BOM catalog tables.
      CREATE TABLE IF NOT EXISTS model_descriptors (
        model_descriptor_digest TEXT PRIMARY KEY,
        canonical_bytes TEXT NOT NULL,
        vendor TEXT NOT NULL,
        model_name TEXT NOT NULL,
        model_version TEXT NOT NULL,
        parent_model_descriptor_digest TEXT,
        source TEXT NOT NULL,
        first_registered_at TEXT NOT NULL,
        first_registered_by TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_md_vmv ON model_descriptors(vendor, model_name, model_version);
      CREATE INDEX IF NOT EXISTS idx_md_parent ON model_descriptors(parent_model_descriptor_digest);

      CREATE TABLE IF NOT EXISTS model_descriptor_annotations (
        annotation_id TEXT PRIMARY KEY,
        model_descriptor_digest TEXT NOT NULL,
        annotated_at TEXT NOT NULL,
        annotated_by TEXT NOT NULL,
        annotation_type TEXT NOT NULL,
        value_json TEXT NOT NULL,
        retracts_annotation_id TEXT,
        signature TEXT,
        note TEXT,
        FOREIGN KEY (model_descriptor_digest) REFERENCES model_descriptors(model_descriptor_digest)
      );
      CREATE INDEX IF NOT EXISTS idx_mda_digest ON model_descriptor_annotations(model_descriptor_digest);
      CREATE INDEX IF NOT EXISTS idx_mda_ts ON model_descriptor_annotations(annotated_at);

      CREATE TABLE IF NOT EXISTS model_descriptor_aliases (
        slug TEXT NOT NULL,
        set_at TEXT NOT NULL,
        model_descriptor_digest TEXT NOT NULL,
        set_by TEXT NOT NULL,
        PRIMARY KEY (slug, set_at)
      );
      CREATE INDEX IF NOT EXISTS idx_mda_slug ON model_descriptor_aliases(slug);

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
        created_at          TEXT NOT NULL
      );

      -- Demo/test-only sentinel: one row signals this is an armed demo store.
      CREATE TABLE IF NOT EXISTS demo_tamper_sentinel (
        owner TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );

      -- The custody ledger.
      -- One row per relink / fork / review custody action. entry_hash is the
      -- engine's computeCustodyEntryHash over prev_entry_hash, evidence_id,
      -- canonical_digest, action, actor, ts, system_id and metadata_canonical
      -- (the engine-canonical bytes of metadata — the column that is hashed;
      -- metadata is the same value as JSON text for readers), and is mirrored
      -- into envelope.custodyChain[i].entryHash. prev_entry_hash chains the
      -- rows of ONE record.
      CREATE TABLE IF NOT EXISTS custody_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id TEXT NOT NULL,
        chain_id TEXT,
        canonical_digest TEXT NOT NULL,
        action TEXT NOT NULL,
        actor TEXT NOT NULL,
        ts TEXT NOT NULL,
        system_id TEXT NOT NULL,
        metadata TEXT,
        metadata_canonical TEXT,
        prev_entry_hash TEXT,
        entry_hash TEXT NOT NULL UNIQUE,
        recovery_id TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_custody_entries_record ON custody_entries(evidence_id, id);
      -- Append-only, enforced in the database and not just by the absence of
      -- a delete method: an insider with the file open in sqlite3 gets the
      -- same refusal the adapter would. SQLite has no session-level bypass
      -- like Postgres' replica role; dropping the trigger is the only way
      -- past, and that is a schema change, not a row edit.
      -- Every inserted row is checked against the record and recomputed,
      -- as the platform's INSERT trigger does: the record
      -- exists, canonical_digest is the digest it carries now, metadata and
      -- metadata_canonical are the same value, prev_entry_hash is the
      -- record's current tail, and entry_hash is the engine's hash of the
      -- row. SQLite has no sha256, so the last two checks call functions
      -- this adapter registers on its connection (registerCustodyFunctions).
      -- A connection without them — a sqlite3 prompt — cannot insert a
      -- custody row at all.
      CREATE TRIGGER IF NOT EXISTS custody_entries_verify_insert
        BEFORE INSERT ON custody_entries
        BEGIN
          SELECT RAISE(ABORT, 'custody_entries: no evidence record to bind the entry to')
           WHERE NOT EXISTS (SELECT 1 FROM envelopes WHERE evidence_id = NEW.evidence_id);
          SELECT RAISE(ABORT, 'custody_entries: canonical_digest does not match the record')
           WHERE NEW.canonical_digest IS NOT (
             SELECT json_extract(envelope, '$.integrity.canonicalDigest')
               FROM envelopes WHERE evidence_id = NEW.evidence_id
           );
          SELECT RAISE(ABORT, 'custody_entries: metadata and metadata_canonical disagree')
           WHERE NEW.metadata_canonical IS NOT custody_entries_canonical_metadata(NEW.metadata);
          SELECT RAISE(ABORT, 'custody_entries: prev_entry_hash is not the record''s current tail')
           WHERE NEW.prev_entry_hash IS NOT (
             SELECT entry_hash FROM custody_entries
              WHERE evidence_id = NEW.evidence_id ORDER BY id DESC LIMIT 1
           );
          SELECT RAISE(ABORT, 'custody_entries: entry_hash does not recompute')
           WHERE NEW.entry_hash IS NOT custody_entries_entry_hash(
             NEW.prev_entry_hash, NEW.evidence_id, NEW.canonical_digest, NEW.action,
             NEW.actor, NEW.ts, NEW.system_id, NEW.metadata
           );
        END;
      CREATE TRIGGER IF NOT EXISTS custody_entries_block_update
        BEFORE UPDATE ON custody_entries
        BEGIN SELECT RAISE(ABORT, 'custody_entries rows are append-only (UPDATE refused)'); END;
      CREATE TRIGGER IF NOT EXISTS custody_entries_block_delete
        BEFORE DELETE ON custody_entries
        BEGIN SELECT RAISE(ABORT, 'custody_entries rows are append-only (DELETE refused)'); END;
      -- No insert over an existing row and no row at a negative id: see
      -- envelopes_block_replace and envelopes_block_negative_rowid. The keys
      -- are id (the rowid) and entry_hash. custody_entries_verify_insert
      -- accepts a row that extends the record's tail wherever it is written,
      -- so without this guard REPLACE at an existing id displaces that row
      -- with one that verifies.
      CREATE TRIGGER IF NOT EXISTS custody_entries_block_replace
        BEFORE INSERT ON custody_entries
        BEGIN
          SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} custody_entries rows are append-only (INSERT over an existing row refused)')
           WHERE EXISTS (SELECT 1 FROM custody_entries WHERE id = NEW.id)
              OR EXISTS (SELECT 1 FROM custody_entries WHERE entry_hash = NEW.entry_hash);
        END;
      CREATE TRIGGER IF NOT EXISTS custody_entries_block_negative_rowid
        AFTER INSERT ON custody_entries
        BEGIN
          SELECT RAISE(ABORT, 'custody_entries: a rowid cannot be negative')
           WHERE NEW.id < 0;
        END;
      -- An id written explicitly is above every id the ledger holds. The
      -- ledger is read in id order and verify_insert takes the tail as the
      -- highest id, so a row that extends the tail but is written below it
      -- would verify and then read first, ahead of the entries it follows.
      -- An insert that names no id reads NEW.id as -1 here, and gets the
      -- next id. An id a row already holds is left to
      -- custody_entries_block_replace, which reports it as the duplicate it
      -- is.
      CREATE TRIGGER IF NOT EXISTS custody_entries_block_backdated_id
        BEFORE INSERT ON custody_entries
        BEGIN
          SELECT RAISE(ABORT, 'custody_entries: an explicit id must be above every existing id')
           WHERE NEW.id <> -1
             AND NEW.id < (SELECT MAX(id) FROM custody_entries)
             AND NOT EXISTS (SELECT 1 FROM custody_entries WHERE id = NEW.id);
        END;

      -- The append-only revision log. One row per legitimate
      -- write to a record's integrity block: revision 0 from store(), then
      -- one per relink / attestation retry. It is the ONLY thing in the store
      -- that remembers what a record used to hash to, and without it the
      -- rewrite-and-reseat attack is indistinguishable from an honest
      -- single-link corruption -- see EnvelopeRevision in the engine's
      -- storage-interface.ts.
      CREATE TABLE IF NOT EXISTS envelope_revisions (
        evidence_id      TEXT NOT NULL,
        revision_no      INTEGER NOT NULL,
        canonical_digest TEXT NOT NULL,
        chain_link       TEXT,
        recorded_at      TEXT NOT NULL,
        cause            TEXT NOT NULL,
        actor            TEXT NOT NULL,
        created_at       TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (evidence_id, revision_no)
      );
      -- The O(1) capture probe. getCaptureDigests() asks exactly one
      -- question -- "what did this record hash to when it was captured" --
      -- and this partial, COVERING index answers it without touching the
      -- table: an equality seek on evidence_id inside the revision_no = 0
      -- slice, reading canonical_digest straight out of the index. The
      -- PRIMARY KEY would serve the seek, but not index-only, and the probe
      -- runs once per record in every chain walk.
      CREATE INDEX IF NOT EXISTS idx_envelope_revisions_capture
        ON envelope_revisions(evidence_id, canonical_digest) WHERE revision_no = 0;
      -- Append-only in the database: UPDATE and DELETE are refused, and so is
      -- an insert over an existing row, the way REPLACE would reseat a
      -- record's capture revision (see envelopes_block_replace), and a row
      -- at a negative rowid (see envelopes_block_negative_rowid). Rewriting
      -- a record is itself refused, by the triggers on envelopes; what the
      -- log adds is that a rewrite made after dropping those triggers still
      -- disagrees with revision 0, unless these triggers are dropped too.
      -- SQLite has no privilege model, so anyone who can write the file can
      -- drop them: that is a schema change, not a row edit, and the only way
      -- past. The Python adapter creates these four triggers on the same
      -- table, with the same bodies.
      CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_update
        BEFORE UPDATE ON envelope_revisions
        BEGIN SELECT RAISE(ABORT, 'envelope_revisions rows are append-only (UPDATE refused)'); END;
      CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_delete
        BEFORE DELETE ON envelope_revisions
        BEGIN SELECT RAISE(ABORT, 'envelope_revisions rows are append-only (DELETE refused)'); END;
      CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_replace
        BEFORE INSERT ON envelope_revisions
        BEGIN
          SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} envelope_revisions rows are append-only (INSERT over an existing row refused)')
           WHERE EXISTS (SELECT 1 FROM envelope_revisions WHERE evidence_id = NEW.evidence_id AND revision_no = NEW.revision_no)
              OR EXISTS (SELECT 1 FROM envelope_revisions WHERE rowid = NEW.rowid);
        END;
      CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_negative_rowid
        AFTER INSERT ON envelope_revisions
        BEGIN
          SELECT RAISE(ABORT, 'envelope_revisions: a rowid cannot be negative')
           WHERE NEW.rowid < 0;
        END;
    `);

    // Registered WebAuthn credentials, append-only, same shape and the same
    // trigger discipline as custody_entries above. Kept in this file so the
    // keys and the records they signed are backed up, restored and moved
    // together: keys held only in process memory are gone after a redeploy,
    // leaving a chain full of signatures and nothing that can check one.
    this.db.exec(CREDENTIAL_SCHEMA_SQLITE);

    // One record per chain position. Without it a row inserted at a chain's
    // next position takes that position's leaf, and the genuine record stored
    // there afterwards is written with no leaf. store() reports the refusal as
    // position_taken. A store that already holds two rows at one position fails
    // to create the index and is not opened.
    this.db.exec(`
      CREATE UNIQUE INDEX IF NOT EXISTS ${ENVELOPES_POSITION_INDEX}
        ON envelopes (chain_id, json_extract(envelope, '$.payload.sequenceNumber'));
      -- retrieveByDigest(): a link target is resolved by its digest.
      CREATE INDEX IF NOT EXISTS idx_envelopes_digest ON envelopes(digest);
    `);

    // The evidence logs (Tree §5.2): the store identity, the log tables, the
    // backfill of a store that already has records, and the trigger on
    // envelopes that writes each record's leaf. One IMMEDIATE transaction; a
    // store already through it is only read.
    migrateSqliteLogSchema(this.db, options);

    // A chain whose evidence log holds leaves keeps its sequence state: its
    // chain_state row cannot be deleted, and its last_sequence cannot be
    // lowered. Created after the log tables, which the triggers read.
    this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS chain_state_keep_logged_delete
        BEFORE DELETE ON chain_state
        BEGIN
          SELECT RAISE(ABORT, '${CHAIN_STATE_LOGGED_TAG} chain_state: the state of a chain whose evidence log holds leaves cannot be cleared')
           WHERE EXISTS (
             SELECT 1 FROM logs l JOIN log_leaves lv ON lv.log_id = l.log_id
              WHERE l.kind = 'evidence' AND l.chain_id = OLD.chain_id
           );
        END;
      CREATE TRIGGER IF NOT EXISTS chain_state_keep_logged_lower
        BEFORE UPDATE OF last_sequence ON chain_state
        WHEN NEW.last_sequence < OLD.last_sequence
        BEGIN
          SELECT RAISE(ABORT, '${CHAIN_STATE_LOGGED_TAG} chain_state: the sequence state of a chain whose evidence log holds leaves cannot be lowered')
           WHERE EXISTS (
             SELECT 1 FROM logs l JOIN log_leaves lv ON lv.log_id = l.log_id
              WHERE l.kind = 'evidence' AND l.chain_id = OLD.chain_id
           );
        END;
    `);
  }

  /**
   * Store an envelope.
   *
   * When `options.expectChainHead` is supplied this is a conditional append.
   * The head read, the duplicate-id check, the insert and the head update all
   * run inside one BEGIN IMMEDIATE transaction, so the write lock is taken
   * before the head is read and no other connection can slip an append in
   * between. Before this, `store()` inserted the row and upserted
   * `chain_state` with no check that the incoming sequence was `last + 1`, so
   * two writers on one file each wrote at the same position and the second
   * `last_digest` write simply overwrote the first — orphaning a record that
   * every later verifier reports as a chain break.
   */
  async store(
    envelope: EvidenceEnvelope,
    chainId?: string,
    options?: StoreOptions,
  ): Promise<void> {
    // A chain id that names no evidence log is refused before the transaction:
    // better-sqlite3 would write a lone surrogate's WTF-8 bytes.
    assertEvidenceLogChainId(chainId ?? 'default', envelope.payload?.sequenceNumber);
    // IMMEDIATE: take the write lock up front. A DEFERRED transaction would
    // read the head under a shared lock and only upgrade on the INSERT, which
    // is the classic SQLITE_BUSY / lost-update window between two processes on
    // one file.
    this.db.transaction(() => this.storeInTransaction(envelope, chainId, options)).immediate();
  }

  /**
   * `store()` under an idempotency key, in ONE IMMEDIATE
   * transaction: the key lookup, the write and the claim. The write lock is
   * taken before the lookup, so two connections with one key cannot both
   * find it free, and a `store()` refusal rolls the whole transaction back,
   * leaving the key unclaimed. Keys are never expired, as on the platform.
   */
  async storeIdempotent(
    envelope: EvidenceEnvelope,
    chainId: string | undefined,
    options: IdempotentStoreOptions,
  ): Promise<IdempotencyOutcome> {
    assertEvidenceLogChainId(chainId ?? 'default', envelope.payload?.sequenceNumber);
    const { key, fingerprint } = options.idempotency;
    const txn = this.db.transaction((): IdempotencyOutcome => {
      const held = this.db.prepare(
        `SELECT request_fingerprint, evidence_id, chain_id, sequence_number, canonical_digest
           FROM idempotency_keys WHERE idempotency_key = ?`
      ).get(key) as
        | { request_fingerprint: string; evidence_id: string; chain_id: string; sequence_number: number; canonical_digest: string }
        | undefined;
      if (held) {
        if (held.request_fingerprint !== fingerprint) return { kind: 'conflict' };
        return {
          kind: 'replay',
          receipt: {
            evidenceId: held.evidence_id,
            chainId: held.chain_id,
            sequenceNumber: held.sequence_number,
            canonicalDigest: held.canonical_digest,
          },
        };
      }
      this.storeInTransaction(envelope, chainId, options);
      const receipt: IdempotencyReceipt = {
        evidenceId: envelope.payload.evidenceId,
        chainId: chainId ?? 'default',
        sequenceNumber: envelope.payload.sequenceNumber,
        canonicalDigest: envelope.integrity.canonicalDigest,
      };
      this.db.prepare(
        `INSERT INTO idempotency_keys
           (idempotency_key, request_fingerprint, evidence_id, chain_id, sequence_number, canonical_digest, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(key, fingerprint, receipt.evidenceId, receipt.chainId, receipt.sequenceNumber, receipt.canonicalDigest,
        new Date().toISOString());
      return { kind: 'claimed', receipt };
    });
    return txn.immediate();
  }

  /** The body of `store()`, for a caller already inside an IMMEDIATE transaction. */
  private storeInTransaction(envelope: EvidenceEnvelope, chainId?: string, options?: StoreOptions): void {
    const id = envelope.payload.evidenceId;

    const selectExisting = this.db.prepare(
      'SELECT evidence_id FROM envelopes WHERE evidence_id = ?'
    );

    const selectHead = this.db.prepare(
      'SELECT last_digest, last_sequence FROM chain_state WHERE chain_id = ?'
    );

    const selectChainStatus = this.db.prepare(
      'SELECT status, sealed_at FROM chains WHERE chain_id = ?'
    );

    const insertEnvelope = this.db.prepare(`
      INSERT INTO envelopes (evidence_id, envelope, captured_at, captured_at_ms, ai_system_id, digest, chain_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    const upsertChainState = this.db.prepare(`
      INSERT INTO chain_state (chain_id, last_digest, last_sequence) VALUES (?, ?, ?)
      ON CONFLICT(chain_id) DO UPDATE SET last_digest = excluded.last_digest, last_sequence = MAX(chain_state.last_sequence, excluded.last_sequence), updated_at = datetime('now')
    `);

    // Written only where the record has no capture revision yet: a record
    // that was deleted and re-stored under the same id keeps the one it
    // already has. See CAPTURE_REVISION_NO for why overwriting it would
    // launder the demo's own rewrite pattern. INSERT ... SELECT ... WHERE NOT
    // EXISTS rather than ON CONFLICT DO NOTHING: envelope_revisions_block_replace
    // refuses any insert over an existing row, a skipping conflict clause
    // included, and a SELECT that yields no row inserts nothing to refuse.
    const insertRevision = this.db.prepare(`
      INSERT INTO envelope_revisions
        (evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor)
      SELECT @evidenceId, @revisionNo, @canonicalDigest, @chainLink, @recordedAt, @cause, @actor
       WHERE NOT EXISTS (
         SELECT 1 FROM envelope_revisions WHERE evidence_id = @evidenceId AND revision_no = @revisionNo
       )
    `);

    if (selectExisting.get(id)) {
      throw new DuplicateRecordError('Evidence record', id);
    }

    const targetChainId = chainId ?? 'default';
    const chainRow = selectChainStatus.get(targetChainId) as
      | { status: string; sealed_at: string | null }
      | undefined;
    assertChainNotSealed(targetChainId, chainRow?.status, chainRow?.sealed_at);

    // The TARGET chain's head, not the store's: an append to one chain is
    // never refused because another chain moved.
    const head = selectHead.get(targetChainId) as
      | { last_digest: string; last_sequence: number }
      | undefined;
    assertChainHead(options?.expectChainHead, {
      sequence: head?.last_sequence ?? 0,
      digest: head?.last_digest ?? null,
    });

    // The storage extensions' checks and claims (a mandate slot), in this
    // transaction: a refusal rolls back everything written below.
    const write: StoreWrite = { envelope, chainId: targetChainId, options: options ?? {} };
    for (const ext of this.extensions) ext.sqlite?.beforeInsert?.(this.db, write);

    // The trigger on envelopes writes the record's evidence-log leaf in this
    // statement; a refusal (a gap, a malformed position, a position another
    // record holds) aborts it and rolls the transaction back.
    try {
      insertEnvelope.run(
        id,
        JSON.stringify(envelope),
        envelope.payload.capturedAt,
        capturedAtInstantMs(envelope.payload.capturedAt),
        envelope.payload.aiSystemId,
        envelope.integrity.canonicalDigest,
        targetChainId
      );
    } catch (err) {
      throw translateEvidenceLogError(err, targetChainId, envelope.payload.sequenceNumber);
    }
    upsertChainState.run(
      targetChainId,
      envelope.integrity.canonicalDigest,
      envelope.payload.sequenceNumber,
    );
    // The capture revision, in the SAME transaction as the
    // row it describes. Separate writes would leave a window in which a
    // record exists with no record of what it hashed to — and that window
    // is the whole attack: a rewritten record with no capture revision is
    // indistinguishable from a legacy one, which every verifier must treat
    // as unprovable rather than tampered.
    insertRevision.run({
      evidenceId: id,
      revisionNo: CAPTURE_REVISION_NO,
      canonicalDigest: envelope.integrity.canonicalDigest,
      chainLink: envelope.integrity.chainLink,
      recordedAt: new Date().toISOString(),
      cause: 'capture',
      actor: captureRevisionActor(envelope),
    });
    // The extensions' rows written with the record (a decider opening, the
    // link index), in this transaction.
    for (const ext of this.extensions) ext.sqlite?.afterInsert?.(this.db, write);
  }

  async retrieve(evidenceId: string): Promise<EvidenceEnvelope | null> {
    const row = this.db.prepare(
      'SELECT envelope FROM envelopes WHERE evidence_id = ?'
    ).get(evidenceId) as { envelope: string } | undefined;

    if (!row) return null;
    return JSON.parse(row.envelope) as EvidenceEnvelope;
  }

  async list(options?: ListOptions): Promise<EvidenceEnvelope[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (options?.aiSystemId) {
      conditions.push('ai_system_id = ?');
      params.push(options.aiSystemId);
    }

    if (options?.chainId) {
      conditions.push('chain_id = ?');
      params.push(options.chainId);
    }

    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const order = options?.order === 'asc' ? 'ASC' : 'DESC';

    // BIND these, do not interpolate. `limit`/`offset` are declared `number`
    // on ListOptions, but TypeScript types are not a runtime boundary: a JS
    // integrator forwarding `req.query.limit` straight through handed this a
    // string, and the string was pasted into the SQL text. better-sqlite3
    // refuses multi-statement input, so this was not arbitrary write access,
    // but a single SELECT subquery placed in the LIMIT position DOES execute
    // — enough to read row counts out of tamper_incidents, chain_state or the
    // catalog through the returned row count. Everything else in this file
    // already binds `?`, and the Postgres twin binds `$n` for these same two
    // clauses; list() was the one that did not.
    let limit = '';
    let offset = '';
    if (options?.limit != null) {
      limit = 'LIMIT ?';
      params.push(assertNonNegativeInteger(options.limit, 'limit'));
    }
    if (options?.offset != null) {
      // SQLite rejects OFFSET without LIMIT, so supply the no-op sentinel -1.
      if (limit === '') limit = 'LIMIT -1';
      offset = 'OFFSET ?';
      params.push(assertNonNegativeInteger(options.offset, 'offset'));
    }

    // Ordering contract (src/storage/list-order.ts): instant, sequence,
    // evidenceId, all in the same direction. NULL captured_at_ms sorts first
    // ASC / last DESC, which is where the memory adapter puts an unparseable
    // instant too.
    const orderBy =
      `ORDER BY captured_at_ms ${order}, ` +
      `json_extract(envelope, '$.payload.sequenceNumber') ${order}, ` +
      `evidence_id ${order}`;
    const sql = `SELECT envelope FROM envelopes ${where} ${orderBy} ${limit} ${offset}`;
    const rows = this.db.prepare(sql).all(...params) as { envelope: string }[];

    return rows.map((row) => JSON.parse(row.envelope) as EvidenceEnvelope);
  }

  async storeFailure(failure: FailureRecord): Promise<void> {
    this.db.prepare(`
      INSERT INTO failures (failure_type, evidence_id, diagnostic_metadata, captured_at)
      VALUES (?, ?, ?, ?)
    `).run(
      failure.failureType,
      failure.evidenceId ?? null,
      JSON.stringify(failure.diagnosticMetadata),
      failure.capturedAt
    );
  }

  async getLastDigest(chainId: string = DEFAULT_CHAIN_ID): Promise<string | null> {
    const row = this.db.prepare(
      'SELECT last_digest FROM chain_state WHERE chain_id = ?'
    ).get(chainId) as { last_digest: string } | undefined;

    return row?.last_digest ?? null;
  }

  async getLastSequence(chainId: string = DEFAULT_CHAIN_ID): Promise<number> {
    const row = this.db.prepare(
      'SELECT last_sequence FROM chain_state WHERE chain_id = ?'
    ).get(chainId) as { last_sequence: number } | undefined;

    return row?.last_sequence ?? 0;
  }

  async listBySequence(fromSequence?: number, toSequence?: number, chainId?: string): Promise<EvidenceEnvelope[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    const from = fromSequence ?? 1;
    conditions.push("json_extract(envelope, '$.payload.sequenceNumber') >= ?");
    params.push(from);

    if (toSequence != null) {
      conditions.push("json_extract(envelope, '$.payload.sequenceNumber') <= ?");
      params.push(toSequence);
    }

    if (chainId) {
      conditions.push('chain_id = ?');
      params.push(chainId);
    }

    const where = 'WHERE ' + conditions.join(' AND ');
    const sql = `SELECT envelope FROM envelopes ${where} ORDER BY json_extract(envelope, '$.payload.sequenceNumber') ASC`;
    const rows = this.db.prepare(sql).all(...params) as { envelope: string }[];

    return rows.map((row) => JSON.parse(row.envelope) as EvidenceEnvelope);
  }

  // The third whole-blob rewriter, wrapped like the other two. better-sqlite3
  // is synchronous so in-process interleaving is impossible, but two processes
  // on one file (an ops CLI relinking while a service runs
  // retryPendingAttestations) interleave freely; without the transaction the
  // loser's whole envelope overwrites the winner's, reverting a healed
  // chainLink or dropping a custody entry.
  async updateAttestation(
    evidenceId: string,
    artifacts: AttestationArtifacts,
    newStatus: EvidenceEnvelope['attestationStatus'] | AttestationStatusOf
  ): Promise<void> {
    const txn = this.db.transaction(() => {
      const row = this.db.prepare(
        'SELECT envelope FROM envelopes WHERE evidence_id = ?'
      ).get(evidenceId) as { envelope: string } | undefined;

      if (!row) {
        throw new Error(
          `Evidence record "${evidenceId}" not found. Cannot update attestation.`
        );
      }

      const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
      // Fill only what the record does not have yet, inside this IMMEDIATE
      // transaction, so a second pass cannot replace a token that has already
      // landed. A pass that fills nothing writes nothing.
      const { merged, filled } = fillAbsentArtifacts(envelope.nonRepudiation, artifacts);
      const status = statusAfterFill(envelope, merged, newStatus);
      if (!filled && status === envelope.attestationStatus) return;
      envelope.nonRepudiation = merged;
      envelope.attestationStatus = status;

      this.db.prepare(
        'UPDATE envelopes SET envelope = ? WHERE evidence_id = ?'
      ).run(JSON.stringify(envelope), evidenceId);
      // An attestation retry is a legitimate envelope write, so it leaves a
      // revision row. It carries the digest UNCHANGED — this
      // is the one permitted mutation and it touches neither the payload nor
      // integrity — which is exactly what makes the row prove the retry did
      // not supersede anything.
      this.appendRevisionSync(
        evidenceId,
        envelope.integrity.canonicalDigest,
        envelope.integrity.chainLink,
        'attestation_retry',
        REVISION_ACTOR_ATTESTATION,
      );
    });
    txn();
  }

  async confirmRecord(
    evidenceId: string,
    confirmation: NonNullable<AttestationArtifacts['confirmation']>,
    custodyEntry: CustodyEntry,
  ): Promise<{ filled: boolean }> {
    // One IMMEDIATE transaction: the fill-only confirmation, its revision row
    // and the custody entry commit together or not at all, and a second
    // connection waits for the write lock before it reads the record.
    let filled = false;
    const txn = this.db.transaction(() => {
      const row = this.db.prepare(
        'SELECT envelope FROM envelopes WHERE evidence_id = ?'
      ).get(evidenceId) as { envelope: string } | undefined;
      if (!row) {
        throw new Error(`Evidence record "${evidenceId}" not found. Cannot confirm it.`);
      }
      const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
      const merged = fillAbsentArtifacts(envelope.nonRepudiation, { confirmation });
      if (!merged.filled) return;
      envelope.nonRepudiation = merged.merged;
      envelope.attestationStatus = statusAfterFill(envelope, merged.merged, (stored) => stored.attestationStatus);
      this.db.prepare(
        'UPDATE envelopes SET envelope = ? WHERE evidence_id = ?'
      ).run(JSON.stringify(envelope), evidenceId);
      this.appendRevisionSync(
        evidenceId,
        envelope.integrity.canonicalDigest,
        envelope.integrity.chainLink,
        'attestation_retry',
        REVISION_ACTOR_ATTESTATION,
      );
      this.appendCustodyEntrySync(evidenceId, custodyEntry, null);
      filled = true;
    });
    txn.immediate();
    return { filled };
  }

  async listByAttestationStatus(
    status: EvidenceEnvelope['attestationStatus'],
    limit?: number,
  ): Promise<EvidenceEnvelope[]> {
    // Oldest first, bounded: a caller reads a backlog a batch at a time
    // rather than every record in the status. The ORDER BY is
    // list()'s ascending contract, and idx_envelopes_attestation_status is
    // what keeps the seek off a table scan. LIMIT -1 is SQLite's "no limit".
    const bound = limit != null ? assertNonNegativeInteger(limit, 'limit') : -1;
    const rows = this.db.prepare(
      `SELECT envelope FROM envelopes
        WHERE json_extract(envelope, '$.attestationStatus') = ?
        ORDER BY captured_at_ms ASC, json_extract(envelope, '$.payload.sequenceNumber') ASC, evidence_id ASC
        LIMIT ?`
    ).all(status, bound) as { envelope: string }[];

    return rows.map((row) => JSON.parse(row.envelope) as EvidenceEnvelope);
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
    const bound = limit != null ? assertNonNegativeInteger(limit, 'limit') : -1;
    if (wanted.length === 0) return [];
    const missing = wanted.map((c) => SQLITE_MISSING_COMPONENT[c]).join(' OR ');
    const rows = this.db.prepare(
      `SELECT envelope FROM envelopes
        WHERE json_extract(envelope, '$.attestationStatus') = 'pending'
          AND (${missing})
        ORDER BY captured_at_ms ASC, json_extract(envelope, '$.payload.sequenceNumber') ASC, evidence_id ASC
        LIMIT ?`
    ).all(bound) as { envelope: string }[];

    return rows.map((row) => JSON.parse(row.envelope) as EvidenceEnvelope);
  }

  private rowToIncident(row: Record<string, unknown>): TamperIncident {
    return {
      id: row.id as string,
      detectedAt: row.detected_at as string,
      severity: row.severity as TamperIncident['severity'],
      type: row.type as TamperIncident['type'],
      affectedRecords: JSON.parse(row.affected_records as string) as string[],
      affectedSequenceRange: row.affected_sequence_range
        ? JSON.parse(row.affected_sequence_range as string) as { from: number; to: number }
        : undefined,
      details: row.details as string,
      status: row.status as TamperIncident['status'],
      lastObservedAt: (row.last_observed_at as string) ?? undefined,
      resolvedAt: (row.resolved_at as string) ?? undefined,
      resolvedBy: (row.resolved_by as string) ?? undefined,
      resolutionNotes: (row.resolution_notes as string) ?? undefined,
    };
  }

  async storeIncident(incident: TamperIncident): Promise<void> {
    const existing = this.db.prepare(
      'SELECT id FROM tamper_incidents WHERE id = ?'
    ).get(incident.id);

    if (existing) {
      throw new DuplicateRecordError('Tamper incident', incident.id);
    }

    this.db.prepare(`
      INSERT INTO tamper_incidents (id, detected_at, severity, type, affected_records, affected_sequence_range, details, status, last_observed_at, resolved_at, resolved_by, resolution_notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
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
      incident.resolutionNotes ?? null
    );
  }

  async getIncident(id: string): Promise<TamperIncident | null> {
    const row = this.db.prepare(
      'SELECT * FROM tamper_incidents WHERE id = ?'
    ).get(id) as Record<string, unknown> | undefined;

    if (!row) return null;
    return this.rowToIncident(row);
  }

  async listIncidents(filter?: { status?: TamperIncidentStatus; severity?: string }): Promise<TamperIncident[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filter?.status) {
      conditions.push('status = ?');
      params.push(filter.status);
    }
    if (filter?.severity) {
      conditions.push('severity = ?');
      params.push(filter.severity);
    }

    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const sql = `SELECT * FROM tamper_incidents ${where} ORDER BY detected_at DESC, id DESC`;
    const rows = this.db.prepare(sql).all(...params) as Record<string, unknown>[];

    return rows.map((row) => this.rowToIncident(row));
  }

  async recordIncidentObservation(id: string, observedAt: string): Promise<void> {
    // Only this column moves: the status and the resolution the operator left
    // are not this call's business.
    const changed = this.db.prepare(
      'UPDATE tamper_incidents SET last_observed_at = ? WHERE id = ?'
    ).run(observedAt, id).changes;
    if (changed === 0) {
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
    const existing = this.db.prepare(
      'SELECT id FROM tamper_incidents WHERE id = ?'
    ).get(id);

    if (!existing) {
      throw new Error(
        `Tamper incident "${id}" not found. Cannot update status.`
      );
    }

    if (status === 'resolved') {
      // COALESCE, not overwrite. An unconditional `resolved_by =
      // metadata?.resolvedBy ?? null` would let a metadata-less re-resolve — a
      // retry, a double-click, a replayed webhook — erase the auditor's name
      // and notes from a resolved tamper incident and re-stamp resolved_at to
      // now. resolved_at is the FIRST transition into 'resolved'; a field is
      // replaced only when a new value is supplied, as on the memory and
      // Postgres adapters.
      this.db.prepare(`
        UPDATE tamper_incidents
           SET status = ?,
               resolved_at = COALESCE(resolved_at, ?),
               resolved_by = COALESCE(?, resolved_by),
               resolution_notes = COALESCE(?, resolution_notes)
         WHERE id = ?
      `).run(
        status,
        new Date().toISOString(),
        metadata?.resolvedBy ?? null,
        metadata?.resolutionNotes ?? null,
        id
      );
    } else {
      this.db.prepare(
        'UPDATE tamper_incidents SET status = ? WHERE id = ?'
      ).run(status, id);
    }
  }

  async getChainForRecord(evidenceId: string): Promise<string | null> {
    const row = this.db.prepare(
      'SELECT chain_id FROM envelopes WHERE evidence_id = ?'
    ).get(evidenceId) as { chain_id: string } | undefined;
    return row?.chain_id ?? null;
  }

  // The append-only ledger tables below are a bare INSERT against a primary
  // key (and, for descriptor annotations, a foreign key). The driver's
  // SqliteError is translated into the SDK's own DuplicateRecordError /
  // MissingReferenceError so a caller's `catch` means the same thing on every
  // backend; anything that is not a constraint violation is rethrown
  // untouched. On chains and the three recovery tables a duplicate key is
  // refused by the table's *_block_replace guard before the key's own
  // constraint, and translateConstraintError reads the guard's tag as the
  // same duplicate.

  async storeChain(chain: ChainIdentity): Promise<void> {
    try {
      this.db.prepare(`
        INSERT INTO chains (chain_id, parent_chain_id, fork_point, status, created_at, sealed_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        chain.chainId,
        chain.parentChainId ?? null,
        chain.forkPoint ?? null,
        chain.status,
        chain.createdAt,
        chain.sealedAt ?? null
      );
    } catch (err) {
      throw translateConstraintError(err, { recordType: 'Chain', recordId: chain.chainId });
    }
  }

  async getChain(chainId: string): Promise<ChainIdentity | null> {
    const row = this.db.prepare(
      'SELECT chain_id, parent_chain_id, fork_point, status, created_at, sealed_at FROM chains WHERE chain_id = ?'
    ).get(chainId) as {
      chain_id: string;
      parent_chain_id: string | null;
      fork_point: number | null;
      status: 'active' | 'sealed';
      created_at: string;
      sealed_at: string | null;
    } | undefined;
    if (!row) return null;
    const result: ChainIdentity = {
      chainId: row.chain_id,
      status: row.status,
      createdAt: row.created_at,
    };
    if (row.parent_chain_id) result.parentChainId = row.parent_chain_id;
    if (row.fork_point !== null) result.forkPoint = row.fork_point;
    if (row.sealed_at) result.sealedAt = row.sealed_at;
    return result;
  }

  async listChains(): Promise<ChainIdentity[]> {
    return this.readChains();
  }

  private readChains(): ChainIdentity[] {
    const rows = this.db.prepare(
      'SELECT chain_id, parent_chain_id, fork_point, status, created_at, sealed_at FROM chains ORDER BY created_at ASC, chain_id ASC'
    ).all() as Array<{
      chain_id: string;
      parent_chain_id: string | null;
      fork_point: number | null;
      status: 'active' | 'sealed';
      created_at: string;
      sealed_at: string | null;
    }>;
    return rows.map((row) => {
      const result: ChainIdentity = {
        chainId: row.chain_id,
        status: row.status,
        createdAt: row.created_at,
      };
      if (row.parent_chain_id) result.parentChainId = row.parent_chain_id;
      if (row.fork_point !== null) result.forkPoint = row.fork_point;
      if (row.sealed_at) result.sealedAt = row.sealed_at;
      return result;
    });
  }

  /**
   * Seal a chain. A seal is final: sealing a sealed chain changes nothing and
   * keeps its first `sealed_at`, which is also all the `chains` trigger allows.
   */
  async sealChain(chainId: string, sealedAt: string): Promise<void> {
    const txn = this.db.transaction(() => {
      const exists = this.db.prepare('SELECT 1 FROM chains WHERE chain_id = ?').get(chainId);
      if (!exists) {
        throw new Error(`Chain "${chainId}" not found.`);
      }
      this.db.prepare(
        `UPDATE chains SET status = 'sealed', sealed_at = ? WHERE chain_id = ? AND status <> 'sealed'`
      ).run(sealedAt, chainId);
    });
    txn.immediate();
  }

  /**
   * Both reads the rule runs over come from ONE snapshot.
   *
   * With an `await` between two autocommit reads, a write committed in that
   * gap — another handle's fork, or another in-process operation's
   * continuation — gave the rule the chains of one store and the records of
   * another: chains=[] and records=['default', <new>] is two implicit chains
   * and an `ambiguous_active_chain` refusal on a store that at no instant had
   * more than one open chain. One deferred transaction: WAL fixes the read
   * snapshot at the first SELECT and the second reads the same store, without
   * blocking the writer. Pinned by the "one snapshot" case in
   * `tests/ts/active-chain-resolution.test.ts`.
   */
  async getActiveChainId(): Promise<string> {
    const [chains, recordChainIds] = this.db.transaction(
      (): [ChainIdentity[], string[]] => [this.readChains(), this.readRecordChainIds()],
    )();
    return resolveActiveChainId(chains, recordChainIds);
  }

  async listRecordChainIds(): Promise<string[]> {
    return this.readRecordChainIds();
  }

  private readRecordChainIds(): string[] {
    const rows = this.db.prepare(
      'SELECT DISTINCT chain_id FROM envelopes ORDER BY chain_id ASC'
    ).all() as Array<{ chain_id: string }>;
    return rows.map((row) => row.chain_id);
  }

  async storeAnnotation(annotation: AnnotationRecord): Promise<void> {
    try {
      this.db.prepare(`
        INSERT INTO chain_annotations (id, incident_id, affected_records, annotated_at, annotated_by, notes, original_digests)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        annotation.id,
        annotation.incidentId,
        JSON.stringify(annotation.affectedRecords),
        annotation.annotatedAt,
        annotation.annotatedBy,
        annotation.notes,
        JSON.stringify(annotation.originalDigests)
      );
    } catch (err) {
      throw translateConstraintError(err, { recordType: 'Annotation', recordId: annotation.id });
    }
  }

  async getAnnotation(id: string): Promise<AnnotationRecord | null> {
    const row = this.db.prepare(
      'SELECT * FROM chain_annotations WHERE id = ?'
    ).get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      id: row.id as string,
      incidentId: row.incident_id as string,
      affectedRecords: JSON.parse(row.affected_records as string) as string[],
      annotatedAt: row.annotated_at as string,
      annotatedBy: row.annotated_by as string,
      notes: row.notes as string,
      originalDigests: JSON.parse(row.original_digests as string) as Record<string, string>,
    };
  }

  async listAnnotations(incidentId: string): Promise<AnnotationRecord[]> {
    const rows = this.db.prepare(
      'SELECT * FROM chain_annotations WHERE incident_id = ? ORDER BY annotated_at ASC, id ASC'
    ).all(incidentId) as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      id: row.id as string,
      incidentId: row.incident_id as string,
      affectedRecords: JSON.parse(row.affected_records as string) as string[],
      annotatedAt: row.annotated_at as string,
      annotatedBy: row.annotated_by as string,
      notes: row.notes as string,
      originalDigests: JSON.parse(row.original_digests as string) as Record<string, string>,
    }));
  }

  async listAnnotationsForRecord(evidenceId: string): Promise<AnnotationRecord[]> {
    const rows = this.db.prepare(
      'SELECT * FROM chain_annotations ORDER BY annotated_at ASC, id ASC'
    ).all() as Array<Record<string, unknown>>;
    return rows
      .filter((row) => {
        const affected = JSON.parse(row.affected_records as string) as string[];
        return affected.includes(evidenceId);
      })
      .map((row) => ({
        id: row.id as string,
        incidentId: row.incident_id as string,
        affectedRecords: JSON.parse(row.affected_records as string) as string[],
        annotatedAt: row.annotated_at as string,
        annotatedBy: row.annotated_by as string,
        notes: row.notes as string,
        originalDigests: JSON.parse(row.original_digests as string) as Record<string, string>,
      }));
  }

  async storeRelink(relink: RelinkRecord): Promise<void> {
    this.insertRelinkSync(relink);
  }

  private insertRelinkSync(relink: RelinkRecord): void {
    try {
      this.db.prepare(`
        INSERT INTO chain_relinks (id, incident_id, relinked_at, relinked_by, from_sequence, to_sequence, modified_links)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        relink.id,
        relink.incidentId,
        relink.relinkedAt,
        relink.relinkedBy,
        relink.fromSequence,
        relink.toSequence,
        JSON.stringify(relink.modifiedLinks)
      );
    } catch (err) {
      throw translateConstraintError(err, { recordType: 'Relink', recordId: relink.id });
    }
  }

  async getRelink(id: string): Promise<RelinkRecord | null> {
    const row = this.db.prepare(
      'SELECT * FROM chain_relinks WHERE id = ?'
    ).get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      id: row.id as string,
      incidentId: row.incident_id as string,
      relinkedAt: row.relinked_at as string,
      relinkedBy: row.relinked_by as string,
      fromSequence: row.from_sequence as number,
      toSequence: row.to_sequence as number,
      modifiedLinks: JSON.parse(row.modified_links as string),
    };
  }

  async listRelinks(incidentId: string): Promise<RelinkRecord[]> {
    const rows = this.db.prepare(
      'SELECT * FROM chain_relinks WHERE incident_id = ? ORDER BY relinked_at ASC, id ASC'
    ).all(incidentId) as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      id: row.id as string,
      incidentId: row.incident_id as string,
      relinkedAt: row.relinked_at as string,
      relinkedBy: row.relinked_by as string,
      fromSequence: row.from_sequence as number,
      toSequence: row.to_sequence as number,
      modifiedLinks: JSON.parse(row.modified_links as string),
    }));
  }

  async storeFork(fork: ForkRecord): Promise<void> {
    try {
      this.db.prepare(`
        INSERT INTO chain_forks (id, incident_id, forked_at, forked_by, reason, old_chain_id, new_chain_id, fork_after_sequence, sealed_old_chain_length, sealed_old_chain_head)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
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
      );
    } catch (err) {
      throw translateConstraintError(err, { recordType: 'Fork', recordId: fork.id });
    }
  }

  async getFork(id: string): Promise<ForkRecord | null> {
    const row = this.db.prepare(
      'SELECT * FROM chain_forks WHERE id = ?'
    ).get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return forkFromRow(row);
  }

  async listForks(incidentId: string): Promise<ForkRecord[]> {
    const rows = this.db.prepare(
      'SELECT * FROM chain_forks WHERE incident_id = ? ORDER BY forked_at ASC, id ASC'
    ).all(incidentId) as Array<Record<string, unknown>>;
    return rows.map(forkFromRow);
  }

  async listForksForChain(chainId: string): Promise<ForkRecord[]> {
    const rows = this.db.prepare(
      'SELECT * FROM chain_forks WHERE old_chain_id = ? OR new_chain_id = ? ORDER BY forked_at ASC, id ASC'
    ).all(chainId, chainId) as Array<Record<string, unknown>>;
    return rows.map(forkFromRow);
  }

  // The same row-level serialization as the Postgres adapter. better-sqlite3
  // is synchronous, so there is no real async interleaving, but wrapping each
  // method body in `db.transaction(() => { ... })` is defense-in-depth and
  // matches the Postgres intent. It protects against future code that
  // might insert an `await` between the SELECT and UPDATE.
  async updateEnvelopeChainLink(evidenceId: string, newChainLink: string | null): Promise<void> {
    const txn = this.db.transaction(() => {
      this.updateChainLinkSync(evidenceId, newChainLink, REVISION_ACTOR_RECOVERY);
    });
    txn.immediate();
  }

  private updateChainLinkSync(evidenceId: string, newChainLink: string | null, actor: string): void {
    const row = this.db.prepare(
      'SELECT envelope FROM envelopes WHERE evidence_id = ?'
    ).get(evidenceId) as { envelope: string } | undefined;
    if (!row) {
      throw new Error(`Evidence record "${evidenceId}" not found.`);
    }
    const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
    envelope.integrity.chainLink = newChainLink;
    this.db.prepare(
      'UPDATE envelopes SET envelope = ? WHERE evidence_id = ?'
    ).run(JSON.stringify(envelope), evidenceId);
    // The repair, recorded: the digest is carried forward
    // unchanged and the NEW link is written down, so the log shows a chain
    // link moving while the digest stands still — the shape of an honest
    // repair, and the shape a laundering attempt cannot produce, because its
    // revision 0 already disagrees with the record's current digest.
    this.appendRevisionSync(
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
   * The revision number comes from the record's own highest, never from a
   * global counter, and a record with NO rows starts at 1 — see
   * `nextRevisionNo` for why backfilling revision 0 would launder exactly the
   * records this log exists to protect.
   */
  private appendRevisionSync(
    evidenceId: string,
    canonicalDigest: string,
    chainLink: string | null,
    cause: RevisionCause,
    actor: string,
  ): void {
    const head = this.db.prepare(
      'SELECT MAX(revision_no) AS highest FROM envelope_revisions WHERE evidence_id = ?'
    ).get(evidenceId) as { highest: number | null } | undefined;
    this.db.prepare(`
      INSERT INTO envelope_revisions
        (evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      evidenceId,
      nextRevisionNo(head?.highest ?? null),
      canonicalDigest,
      chainLink,
      new Date().toISOString(),
      cause,
      actor,
    );
  }

  async listEnvelopeRevisions(evidenceId: string): Promise<EnvelopeRevision[]> {
    const rows = this.db.prepare(
      'SELECT * FROM envelope_revisions WHERE evidence_id = ? ORDER BY revision_no ASC'
    ).all(evidenceId) as Array<Record<string, unknown>>;
    return rows.map(revisionRowFromSqlite);
  }

  async getCaptureDigests(evidenceIds: string[]): Promise<Record<string, string>> {
    if (evidenceIds.length === 0) return {};
    const out: Record<string, string> = {};
    // One prepared statement, reused: an equality probe into the partial
    // covering index (evidence_id, canonical_digest) WHERE revision_no = 0.
    // A single IN (...) would need a statement per distinct arity, which
    // better-sqlite3 would re-prepare on every differently sized chain.
    const probe = this.db.prepare(
      'SELECT canonical_digest FROM envelope_revisions WHERE evidence_id = ? AND revision_no = ?'
    );
    for (const evidenceId of evidenceIds) {
      const row = probe.get(evidenceId, CAPTURE_REVISION_NO) as
        | { canonical_digest: string }
        | undefined;
      // Absent stays absent: a record with no capture revision is one this
      // store cannot speak for, not one it is vouching for.
      if (row) out[evidenceId] = row.canonical_digest;
    }
    return out;
  }

  /**
   * Hashed, chained append: the row and the envelope mirror
   * in one BEGIN IMMEDIATE transaction. Before this the entry went into the
   * envelope as plain JSON — nothing bound it to the record, to its
   * neighbours or to anything outside the blob, so deleting the `relinked`
   * entry was a one-statement edit that left the record presenting as never
   * repaired.
   */
  async appendCustodyEntry(
    evidenceId: string,
    entry: CustodyEntry,
    options?: CustodyAppendOptions,
  ): Promise<void> {
    const txn = this.db.transaction(() => {
      this.appendCustodyEntrySync(evidenceId, entry, options?.recoveryId ?? null);
    });
    txn.immediate();
  }

  /**
   * The append itself, for callers already inside a transaction. Reads the
   * record's current digest and chain, the previous row's hash for THIS
   * record, mints the entry hash with the engine's one rule, inserts the row
   * and mirrors the hashed entry into the envelope.
   */
  private appendCustodyEntrySync(evidenceId: string, entry: CustodyEntry, recoveryId: string | null): void {
    const row = this.db.prepare(
      'SELECT envelope, chain_id FROM envelopes WHERE evidence_id = ?'
    ).get(evidenceId) as { envelope: string; chain_id: string | null } | undefined;
    if (!row) {
      throw new Error(`Evidence record "${evidenceId}" not found.`);
    }
    const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
    const tail = this.db.prepare(
      'SELECT entry_hash FROM custody_entries WHERE evidence_id = ? ORDER BY id DESC LIMIT 1'
    ).get(evidenceId) as { entry_hash: string } | undefined;
    const prevEntryHash = tail?.entry_hash ?? null;
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
    this.db.prepare(`
      INSERT INTO custody_entries
        (evidence_id, chain_id, canonical_digest, action, actor, ts, system_id,
         metadata, metadata_canonical, prev_entry_hash, entry_hash, recovery_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      evidenceId,
      row.chain_id ?? null,
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
    );
    envelope.custodyChain.push(mirrorCustodyEntry(entry, entryHash, prevEntryHash));
    this.db.prepare(
      'UPDATE envelopes SET envelope = ? WHERE evidence_id = ?'
    ).run(JSON.stringify(envelope), evidenceId);
  }

  /**
   * One BEGIN IMMEDIATE transaction: the links, the relink
   * record and the hashed custody entries commit together or not at all. A
   * throw at any point — an unknown record, a duplicate relink id, a crash
   * injected after the link update — rolls every statement back.
   */
  async applyRelink(relink: RelinkRecord, custodyEntries: RelinkCustodyAppend[]): Promise<void> {
    const txn = this.db.transaction(() => {
      for (const link of relink.modifiedLinks) {
        this.updateChainLinkSync(link.evidenceId, link.newChainLink, relink.relinkedBy);
      }
      this.insertRelinkSync(relink);
      for (const { evidenceId, entry } of custodyEntries) {
        this.appendCustodyEntrySync(evidenceId, entry, relink.id);
      }
    });
    txn.immediate();
  }

  async listCustodyEntries(evidenceId: string): Promise<StoredCustodyEntry[]> {
    const rows = this.db.prepare(
      'SELECT * FROM custody_entries WHERE evidence_id = ? ORDER BY id ASC'
    ).all(evidenceId) as Array<Record<string, unknown>>;
    return rows.map(custodyRowFromSqlite);
  }

  async getBySequenceRange(fromSequence: number, toSequence: number, chainId?: string): Promise<EvidenceEnvelope[]> {
    let sql = 'SELECT envelope FROM envelopes WHERE 1=1';
    const params: unknown[] = [];
    if (chainId) {
      sql += ' AND chain_id = ?';
      params.push(chainId);
    }
    const rows = this.db.prepare(sql).all(...params) as Array<{ envelope: string }>;
    return rows
      .map((row) => JSON.parse(row.envelope) as EvidenceEnvelope)
      .filter((e) => e.payload.sequenceNumber >= fromSequence && e.payload.sequenceNumber <= toSequence)
      .sort((a, b) => a.payload.sequenceNumber - b.payload.sequenceNumber);
  }

  /**
   * Clear one chain's state. Refused with `ChainStateResetRefusedError` when
   * the chain's evidence log holds leaves (the `chain_state` trigger).
   */
  async resetChainState(chainId: string = DEFAULT_CHAIN_ID): Promise<void> {
    try {
      this.db.prepare('DELETE FROM chain_state WHERE chain_id = ?').run(chainId);
    } catch (err) {
      throw translateChainStateError(err, chainId);
    }
  }

  /** The record whose stored canonical digest is `digest`, or `null`; the oldest when several share it. */
  async retrieveByDigest(digest: string): Promise<EvidenceEnvelope | null> {
    const row = this.db
      .prepare('SELECT envelope FROM envelopes WHERE digest = ? ORDER BY rowid LIMIT 1')
      .get(digest) as { envelope: string } | undefined;
    return row ? (JSON.parse(row.envelope) as EvidenceEnvelope) : null;
  }

  async getChainLength(chainId?: string): Promise<number> {
    if (chainId) {
      const row = this.db.prepare(
        'SELECT COUNT(*) as count FROM envelopes WHERE chain_id = ?'
      ).get(chainId) as { count: number };
      return row.count;
    }
    const row = this.db.prepare(
      'SELECT COUNT(*) as count FROM envelopes'
    ).get() as { count: number };
    return row.count;
  }

  // ── AI-BOM model-descriptor catalog ────────────────────────────────

  private rowToModelDescriptorRow(row: {
    model_descriptor_digest: string;
    canonical_bytes: string;
    vendor: string;
    model_name: string;
    model_version: string;
    parent_model_descriptor_digest: string | null;
    source: string;
    first_registered_at: string;
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
      firstRegisteredAt: row.first_registered_at,
      firstRegisteredBy: row.first_registered_by,
    };
  }

  private rowToAnnotationRow(row: {
    annotation_id: string;
    model_descriptor_digest: string;
    annotated_at: string;
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
      annotatedAt: row.annotated_at,
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
    const existing = this.db.prepare(
      'SELECT 1 FROM model_descriptors WHERE model_descriptor_digest = ?'
    ).get(digest);
    if (existing) {
      return { digest, alreadyExisted: true };
    }
    this.db.prepare(`
      INSERT INTO model_descriptors (
        model_descriptor_digest, canonical_bytes, vendor, model_name, model_version,
        parent_model_descriptor_digest, source, first_registered_at, first_registered_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      digest,
      canonicalBytes,
      descriptor.vendor,
      descriptor.modelName,
      descriptor.modelVersion,
      descriptor.parentModelDescriptorDigest,
      source,
      new Date().toISOString(),
      registeredBy,
    );
    return { digest, alreadyExisted: false };
  }

  async getModelDescriptor(digest: string): Promise<ModelDescriptorRow | null> {
    const row = this.db.prepare(
      'SELECT * FROM model_descriptors WHERE model_descriptor_digest = ?'
    ).get(digest) as Parameters<SqliteStorageAdapter['rowToModelDescriptorRow']>[0] | undefined;
    if (!row) return null;
    return this.rowToModelDescriptorRow(row);
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
    if (filter.vendor !== undefined) {
      conditions.push('vendor = ?');
      params.push(filter.vendor);
    }
    if (filter.modelName !== undefined) {
      conditions.push('model_name = ?');
      params.push(filter.modelName);
    }
    if (filter.modelVersion !== undefined) {
      conditions.push('model_version = ?');
      params.push(filter.modelVersion);
    }
    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

    // For integrityTier and hasRegulatoryMarking we post-filter in JS because
    // those fields are not denormalized columns — they live inside `descriptor`.
    // Pagination (limit/offset) is applied AFTER post-filtering so the result
    // count matches the memory backend's slice semantics.
    const needsPostFilter =
      filter.integrityTier !== undefined || filter.hasRegulatoryMarking !== undefined;

    let sql = `SELECT * FROM model_descriptors ${where}`;
    if (!needsPostFilter) {
      // Bound, not interpolated — same reasoning as list() above. The old
      // `Number()` coercion turned garbage into the literal text `LIMIT NaN`,
      // which SQLite reports as "no such column: NaN" — a confusing 500
      // rather than a clear rejection.
      if (filter.limit !== undefined) {
        sql += ' LIMIT ?';
        params.push(assertNonNegativeInteger(filter.limit, 'limit'));
      }
      if (filter.offset !== undefined) {
        if (filter.limit === undefined) sql += ' LIMIT -1';
        sql += ' OFFSET ?';
        params.push(assertNonNegativeInteger(filter.offset, 'offset'));
      }
    }

    const rawRows = this.db.prepare(sql).all(...params) as Array<
      Parameters<SqliteStorageAdapter['rowToModelDescriptorRow']>[0]
    >;
    let rows = rawRows.map((r) => this.rowToModelDescriptorRow(r));

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
    const rawRows = this.db.prepare(
      'SELECT * FROM model_descriptors WHERE parent_model_descriptor_digest = ?'
    ).all(parentDigest) as Array<
      Parameters<SqliteStorageAdapter['rowToModelDescriptorRow']>[0]
    >;
    return rawRows.map((r) => this.rowToModelDescriptorRow(r));
  }

  async appendModelDescriptorAnnotation(annotation: ModelDescriptorAnnotationRow): Promise<void> {
    try {
      this.db.prepare(`
        INSERT INTO model_descriptor_annotations (
          annotation_id, model_descriptor_digest, annotated_at, annotated_by,
          annotation_type, value_json, retracts_annotation_id, signature, note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        annotation.annotationId,
        annotation.modelDescriptorDigest,
        annotation.annotatedAt,
        annotation.annotatedBy,
        annotation.annotationType,
        annotation.valueJson,
        annotation.retractsAnnotationId,
        annotation.signature,
        annotation.note,
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
    const rawRows = this.db.prepare(
      `SELECT * FROM model_descriptor_annotations
       WHERE model_descriptor_digest = ?
       ORDER BY annotated_at ASC, annotation_id ASC`
    ).all(digest) as Array<Parameters<SqliteStorageAdapter['rowToAnnotationRow']>[0]>;
    return rawRows.map((r) => this.rowToAnnotationRow(r));
  }

  async setModelDescriptorAlias(slug: string, digest: string, setBy: string): Promise<void> {
    // PRIMARY KEY (slug, set_at) at millisecond resolution: a second bind in
    // the same millisecond replaces that instant's row rather than colliding
    // on the key — last writer wins, as on memory and Postgres.
    this.db.prepare(`
      INSERT INTO model_descriptor_aliases (slug, set_at, model_descriptor_digest, set_by)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(slug, set_at) DO UPDATE SET
        model_descriptor_digest = excluded.model_descriptor_digest,
        set_by = excluded.set_by
    `).run(slug, new Date().toISOString(), digest, setBy);
  }

  async resolveModelDescriptorAlias(slug: string): Promise<string | null> {
    const row = this.db.prepare(
      `SELECT model_descriptor_digest FROM model_descriptor_aliases
       WHERE slug = ? ORDER BY set_at DESC LIMIT 1`
    ).get(slug) as { model_descriptor_digest: string } | undefined;
    return row?.model_descriptor_digest ?? null;
  }

  async head(): Promise<EvidenceEnvelope | null> {
    const row = this.db.prepare(
      `SELECT envelope FROM envelopes ORDER BY rowid DESC LIMIT 1`
    ).get() as { envelope: string } | undefined;
    if (!row) return null;
    return JSON.parse(row.envelope) as EvidenceEnvelope;
  }

  // ── Demo-tamper hooks ──────────────────────────────

  private demoTamperView(): DemoTamperStoreView {
    return {
      hasSentinel: async () => {
        const row = this.db.prepare(
          'SELECT 1 FROM demo_tamper_sentinel LIMIT 1'
        ).get();
        return row !== undefined;
      },
      writeSentinel: async () => {
        this.db.prepare(
          'INSERT INTO demo_tamper_sentinel (owner, created_at) VALUES (?, ?)'
        ).run(DEMO_SENTINEL_OWNER, new Date().toISOString());
      },
      envelopeCount: async () => {
        const row = this.db.prepare(
          'SELECT COUNT(*) as count FROM envelopes'
        ).get() as { count: number };
        return row.count;
      },
      // The guard arms an EMPTY store only on a target that shows it is a
      // demo store. An in-memory database (':memory:', or '' — a
      // private temporary one) belongs to this process and dies with it, so
      // it answers `local`. A file does not show that: it is where a
      // production SQLite store lives too, and every production store is
      // empty on day one, so a file-backed store answers `unknown` and an
      // empty one arms only through TZUN_DEMO_TAMPER_BOOTSTRAP — the
      // same rule Postgres gets for a target it cannot show is loopback.
      // After that first arm the sentinel keeps it armed.
      target: () =>
        this.db.memory
          ? { kind: 'local', what: 'sqlite in-memory database' }
          : {
              kind: 'unknown',
              why:
                `sqlite file ${this.dbPath ?? this.db.name}: a file-backed store is local to production ` +
                'deployments too, so locality does not show it is a demo store; arm an empty one with ' +
                'TZUN_DEMO_TAMPER_BOOTSTRAP=true',
            },
    };
  }

  async armDemoTamperHooks(): Promise<void> {
    this.demoHooksArmed = await tryArmDemoTamperHooks(this.demoTamperView(), 'sqlite');
  }

  async deleteEnvelopeForDemo(evidenceId: string): Promise<void> {
    assertArmed(this.demoHooksArmed);
    // The one DELETE the envelopes table lets through, and only past the
    // arming guard above. SQLite's equivalent of the Postgres hook's
    // transaction-scoped `session_replication_role = 'replica'`: the guard is
    // dropped and re-created inside one IMMEDIATE transaction, so no other
    // connection ever sees the table without it, and a failure rolls the
    // drop back with the delete.
    const txn = this.db.transaction(() => {
      this.db.exec('DROP TRIGGER IF EXISTS envelopes_block_delete');
      this.db.prepare('DELETE FROM envelopes WHERE evidence_id = ?').run(evidenceId);
      this.db.exec(ENVELOPES_BLOCK_DELETE_TRIGGER);
    });
    txn.immediate();
  }

  async overwriteModelDescriptorBytesForDemo(digest: string, canonicalBytes: string): Promise<string> {
    assertArmed(this.demoHooksArmed);
    const txn = this.db.transaction(() => {
      const row = this.db.prepare(
        'SELECT canonical_bytes FROM model_descriptors WHERE model_descriptor_digest = ?'
      ).get(digest) as { canonical_bytes: string } | undefined;
      if (!row) {
        throw new Error(`No model descriptor row for digest ${digest}`);
      }
      const previous = row.canonical_bytes;
      this.db.prepare(
        'UPDATE model_descriptors SET canonical_bytes = ? WHERE model_descriptor_digest = ?'
      ).run(canonicalBytes, digest);
      return previous;
    });
    return txn();
  }

  /**
   * The durable credential directory held in this database file.
   *
   * A fresh `SqliteCredentialStore` each call, but every one of them shares
   * this adapter's `Database` handle — so they are the same store, no cache is
   * needed, and no second connection is opened onto the file.
   */
  credentialStore(): AsyncCredentialStore {
    return new SqliteCredentialStore(this.db);
  }

  /** The store's identity and evidence logs, on this adapter's connection (Anchor §3, §4.3.2). */
  logStore(): LogStore {
    return new SqliteLogStore(this.db);
  }

  /** The anchoring tables the anchor scheduler writes, on this adapter's connection. */
  anchorStore(): AnchorStore {
    return new SqliteLogStore(this.db);
  }

  /**
   * Close the database file handle.
   *
   * Matches the optional `StorageAdapter.close()` contract: Promise-returning
   * so `Tzun.close()` can `await` it uniformly across all backends. The
   * underlying `better-sqlite3` close is synchronous.
   */
  async close(): Promise<void> {
    // Harden once more before closing: SQLite recreates -wal/-shm on demand
    // during the adapter's lifetime, and a sidecar created after the
    // constructor's umask window would otherwise keep the process default.
    this.hardenFilePermissions();
    this.db.close();
  }
}
