/**
 * The schema of a local store, as data, and the way back to the schema an SDK
 * 0.5.0 store has (Tree §5.2).
 *
 * The upgrade suites need stores written by 0.5.0. A 0.5.0 store is a store
 * with the evidence-log schema minus that schema (added in 0.6.0): the log
 * tables, the store identity, and the triggers and functions that guard and
 * fill them; on SQLite, also minus the insert guards later SDKs added to
 * 0.5.0 tables. The
 * helpers below remove exactly those objects, put back the Postgres functions
 * later SDKs rewrote as 0.5.0 defined them, and the snapshots in
 * `tests/fixtures/store-schema-0.5.0/` hold what a store written by the
 * 0.5.0 code itself looks like. `log-storage-upgrade.test.ts` asserts that a
 * stripped store equals that snapshot, so the stores it upgrades are 0.5.0
 * stores and not an approximation of one.
 */
import type BetterSqlite3 from 'better-sqlite3';
import type { Client, Pool } from 'pg';

/** One `sqlite_schema` row. */
export interface SqliteSchemaObject {
  type: string;
  name: string;
  tbl_name: string;
  sql: string | null;
}

/** Every schema object of a SQLite store, sorted, SQLite's own `sqlite_*` objects left out. */
export function sqliteSchemaSnapshot(db: BetterSqlite3.Database): SqliteSchemaObject[] {
  return db
    .prepare(
      `SELECT type, name, tbl_name, sql FROM sqlite_schema
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name`,
    )
    .all() as SqliteSchemaObject[];
}

/** What `postgresSchemaSnapshot` reads: columns, constraints, indexes, triggers and functions. */
export interface PostgresSchemaSnapshot {
  columns: Array<{ table: string; column: string; type: string; nullable: string; default: string | null }>;
  constraints: Array<{ table: string; name: string; definition: string }>;
  indexes: Array<{ table: string; name: string; definition: string }>;
  triggers: Array<{ table: string; name: string; definition: string }>;
  functions: Array<{ name: string; arguments: string; bodyMd5: string }>;
}

type Queryable = Pick<Client, 'query'> | Pick<Pool, 'query'>;

/**
 * Every object of one Postgres schema. Definitions are read with the schema's
 * qualification removed — Postgres prints it or not depending on the reading
 * connection's search_path — so snapshots of two differently named test
 * schemas, read from any connection, compare equal.
 */
export async function postgresSchemaSnapshot(db: Queryable, schema: string): Promise<PostgresSchemaSnapshot> {
  const unqualify = (text: string | null): string | null =>
    text === null ? null : text.split(`${schema}.`).join('');
  const columns = await db.query(
    `SELECT table_name, column_name, data_type, is_nullable, column_default
       FROM information_schema.columns
      WHERE table_schema = $1
      ORDER BY table_name, ordinal_position`,
    [schema],
  );
  const constraints = await db.query(
    `SELECT t.relname AS table_name, c.conname, pg_get_constraintdef(c.oid) AS def
       FROM pg_constraint c
       JOIN pg_class t ON t.oid = c.conrelid
       JOIN pg_namespace n ON n.oid = t.relnamespace
      WHERE n.nspname = $1
      ORDER BY t.relname, c.conname`,
    [schema],
  );
  const indexes = await db.query(
    `SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = $1 ORDER BY tablename, indexname`,
    [schema],
  );
  const triggers = await db.query(
    `SELECT c.relname AS table_name, t.tgname, pg_get_triggerdef(t.oid) AS def
       FROM pg_trigger t
       JOIN pg_class c ON c.oid = t.tgrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = $1 AND NOT t.tgisinternal
      ORDER BY c.relname, t.tgname`,
    [schema],
  );
  const functions = await db.query(
    `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args, md5(p.prosrc) AS body_md5
       FROM pg_proc p
       JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = $1
      ORDER BY p.proname, args`,
    [schema],
  );
  return {
    columns: columns.rows.map((r) => ({
      table: r.table_name,
      column: r.column_name,
      type: r.data_type,
      nullable: r.is_nullable,
      default: unqualify(r.column_default),
    })),
    constraints: constraints.rows.map((r) => ({ table: r.table_name, name: r.conname, definition: unqualify(r.def)! })),
    indexes: indexes.rows.map((r) => ({ table: r.tablename, name: r.indexname, definition: unqualify(r.indexdef)! })),
    triggers: triggers.rows.map((r) => ({ table: r.table_name, name: r.tgname, definition: unqualify(r.def)! })),
    functions: functions.rows.map((r) => ({ name: r.proname, arguments: r.args, bodyMd5: r.body_md5 })),
  };
}

/** The tables of the evidence-log schema (0.6.0), in an order that drops dependents first. */
export const LOG_TABLES = [
  'anchor_wallet_txs',
  'anchor_wallets',
  'anchor_lease',
  'anchor_publications',
  'log_checkpoints',
  'log_leaves',
  'logs',
  'store_identity',
] as const;

/** The evidence-log schema's one trigger on a 0.5.0 table. Everything else in it sits on its own tables. */
export const LOG_TRIGGER_ON_ENVELOPES = {
  sqlite: 'envelopes_evidence_log_append',
  postgres: 'evidence_log_append_trigger',
} as const;

/**
 * The guards later SDKs added to 0.5.0 SQLite tables: no insert over an
 * existing row, no row at a negative rowid, a rowid that never changes on
 * `envelopes` and `chains`, no record written ahead of the first, and no
 * custody row written below the ledger's last id (0.7.0); the
 * same on `credential_events`, and no event written below its last seq
 * (0.7.1).
 */
export const LATER_GUARDS_SQLITE = [
  'envelopes_block_replace',
  'chains_block_replace',
  'custody_entries_block_replace',
  'envelope_revisions_block_replace',
  'chain_annotations_block_replace',
  'chain_relinks_block_replace',
  'chain_forks_block_replace',
  'envelopes_block_negative_rowid',
  'chains_block_negative_rowid',
  'custody_entries_block_negative_rowid',
  'envelope_revisions_block_negative_rowid',
  'chain_annotations_block_negative_rowid',
  'chain_relinks_block_negative_rowid',
  'chain_forks_block_negative_rowid',
  'envelopes_block_rowid_change',
  'chains_block_rowid_change',
  'envelopes_block_low_rowid',
  'custody_entries_block_backdated_id',
  'credential_events_block_replace',
  'credential_events_block_negative_rowid',
  'credential_events_block_backdated_seq',
  // 0.8.0: one record per chain position, and the
  // digest index link targets are resolved by.
  'envelopes_position',
  'idx_envelopes_digest',
] as const;

/** The 0.8.0 indexes of `LATER_GUARDS_SQLITE`. */
const LATER_INDEXES_SQLITE = ['envelopes_position', 'idx_envelopes_digest'] as const;

/**
 * What 0.8.0 creates after the evidence-log migration, so a store whose
 * migration failed has none of it: the chain_state guard,
 * which reads the log tables, and the storage extensions' tables.
 */
const AFTER_LOG_TRIGGERS_SQLITE = ['chain_state_keep_logged_delete', 'chain_state_keep_logged_lower'] as const;
const EXTENSION_TABLES_SQLITE = [
  'decider_openings',
  'decider_commitment_secret',
  'agent_descriptors',
  'evidence_links',
  'mandates',
  'mandate_totals',
  'mandate_events',
] as const;

/**
 * Turn a SQLite store with the evidence-log schema back into the store 0.5.0 wrote: drop the
 * trigger on `envelopes`, the log tables (their own triggers go with them) and the guards
 * later SDKs added to 0.5.0 tables. The rows of every 0.5.0 table are left exactly as they are.
 */
export function stripLogSchemaSqlite(db: BetterSqlite3.Database): void {
  db.exec(`DROP TRIGGER IF EXISTS ${LOG_TRIGGER_ON_ENVELOPES.sqlite}`);
  for (const table of LOG_TABLES) db.exec(`DROP TABLE IF EXISTS ${table}`);
  for (const table of EXTENSION_TABLES_SQLITE) db.exec(`DROP TABLE IF EXISTS ${table}`);
  for (const trigger of AFTER_LOG_TRIGGERS_SQLITE) db.exec(`DROP TRIGGER IF EXISTS ${trigger}`);
  for (const index of LATER_INDEXES_SQLITE) db.exec(`DROP INDEX IF EXISTS ${index}`);
  for (const guard of LATER_GUARDS_SQLITE) {
    if ((LATER_INDEXES_SQLITE as readonly string[]).includes(guard)) continue;
    db.exec(`DROP TRIGGER IF EXISTS ${guard}`);
  }
}

/**
 * The indexes later SDKs added to 0.5.0 Postgres tables: the store check's
 * read order (0.7.0); one record per chain position and
 * the digest index link targets are resolved by (0.8.0).
 */
export const LATER_INDEXES_POSTGRES = ['idx_envelopes_created_at', 'envelopes_position', 'idx_envelopes_digest'] as const;

/**
 * The guards a later SDK added to 0.5.0 Postgres tables, each a function and
 * its BEFORE INSERT trigger: no custody entry or credential event written
 * ahead of the rows it follows.
 */
export const LATER_GUARDS_POSTGRES = [
  { table: 'custody_entries', fn: 'custody_entries_block_backdated_id', trigger: 'custody_entries_block_backdated_id_trigger' },
  { table: 'credential_events', fn: 'credential_events_block_backdated_seq', trigger: 'credential_events_block_backdated_seq_trigger' },
  // 0.8.0: a chain whose evidence log holds leaves keeps its sequence state.
  { table: 'chain_state', fn: 'chain_state_keep_logged', trigger: 'chain_state_keep_logged_trigger' },
] as const;

/**
 * What 0.8.0 creates on Postgres after the evidence-log migration, so a store
 * whose migration failed has none of it: the `anchor_freshness` row's table
 * (its owner gate reads the anchoring tables' function) and the storage
 * extensions' tables, with their functions.
 */
const AFTER_LOG_TABLES_POSTGRES = [
  'anchor_freshness',
  'decider_openings',
  'decider_commitment_secret',
  'agent_descriptors',
  'evidence_links',
  'mandates',
  'mandate_totals',
  'mandate_events',
] as const;
const AFTER_LOG_FUNCTIONS_POSTGRES = [
  'decider_openings_block_mutation',
  'agent_descriptors_block_mutation',
  'evidence_links_block_mutation',
  'mandates_guard',
  'mandate_totals_guard',
  'mandate_events_block_mutation',
] as const;

/**
 * The 0.5.0 definitions of the functions a later SDK rewrote or removed, in an
 * order they can be created in. In 0.5.0 the custody ledger's verifier and
 * hash and the guard on `envelopes` UPDATEs read their tables, and called
 * `custody_entries_length_prefix`, through the session's search_path; a later
 * SDK pinned their search_path, rewrote the first three and dropped the
 * fourth. These are the statements 0.5.0 ran, byte for byte: the snapshot
 * compares each body's md5.
 */
export const FUNCTIONS_0_5_0_POSTGRES: ReadonlyArray<{ name: string; sql: string }> = [
  {
    name: 'custody_entries_length_prefix',
    sql: `CREATE OR REPLACE FUNCTION custody_entries_length_prefix(v TEXT)
      RETURNS TEXT
      LANGUAGE sql IMMUTABLE AS $$
        SELECT CASE WHEN v IS NULL THEN '-:' ELSE length(v)::text || ':' || v END
      $$;`,
  },
  {
    name: 'custody_entries_compute_hash',
    sql: `CREATE OR REPLACE FUNCTION custody_entries_compute_hash(
        p_prev TEXT, p_evidence_id TEXT, p_canonical_digest TEXT, p_action TEXT,
        p_actor TEXT, p_ts TEXT, p_system_id TEXT, p_metadata_canonical TEXT)
      RETURNS TEXT
      LANGUAGE sql IMMUTABLE AS $$
        SELECT encode(sha256(convert_to(
            custody_entries_length_prefix(p_prev)
            || custody_entries_length_prefix(p_evidence_id)
            || custody_entries_length_prefix(p_canonical_digest)
            || custody_entries_length_prefix(p_action)
            || custody_entries_length_prefix(p_actor)
            || custody_entries_length_prefix(p_ts)
            || custody_entries_length_prefix(p_system_id)
            || custody_entries_length_prefix(p_metadata_canonical)
          , 'UTF8')), 'hex')
      $$;`,
  },
  {
    name: 'custody_entries_verify_insert',
    sql: `CREATE OR REPLACE FUNCTION custody_entries_verify_insert()
      RETURNS TRIGGER AS $$
      DECLARE
        v_digest TEXT;
        v_prev   TEXT;
      BEGIN
        PERFORM pg_advisory_xact_lock(2026091801, hashtext(NEW.evidence_id));

        SELECT envelope->'integrity'->>'canonicalDigest' INTO v_digest
          FROM envelopes WHERE evidence_id = NEW.evidence_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'custody_entries: no evidence record % to bind the entry to', NEW.evidence_id;
        END IF;
        IF NEW.canonical_digest IS DISTINCT FROM v_digest THEN
          RAISE EXCEPTION 'custody_entries: canonical_digest does not match the record (%)', NEW.evidence_id;
        END IF;

        IF (NEW.metadata IS NULL) <> (NEW.metadata_canonical IS NULL)
           OR (NEW.metadata IS NOT NULL AND NEW.metadata_canonical::jsonb IS DISTINCT FROM NEW.metadata) THEN
          RAISE EXCEPTION 'custody_entries: metadata and metadata_canonical disagree (%)', NEW.evidence_id;
        END IF;

        SELECT entry_hash INTO v_prev FROM custody_entries
         WHERE evidence_id = NEW.evidence_id ORDER BY id DESC LIMIT 1;
        IF NEW.prev_entry_hash IS DISTINCT FROM v_prev THEN
          RAISE EXCEPTION 'custody_entries: prev_entry_hash is not the record''s current tail (%)', NEW.evidence_id;
        END IF;

        IF NEW.entry_hash IS DISTINCT FROM custody_entries_compute_hash(
             v_prev, NEW.evidence_id, NEW.canonical_digest, NEW.action,
             NEW.actor, NEW.ts, NEW.system_id, NEW.metadata_canonical) THEN
          RAISE EXCEPTION 'custody_entries: entry_hash does not recompute (%)', NEW.evidence_id;
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;`,
  },
  {
    name: 'envelopes_enforce_immutable',
    sql: `CREATE OR REPLACE FUNCTION envelopes_enforce_immutable()
      RETURNS TRIGGER AS $$
      DECLARE
        v_old_custody JSONB := COALESCE(OLD.envelope->'custodyChain', '[]'::jsonb);
        v_new_custody JSONB := COALESCE(NEW.envelope->'custodyChain', '[]'::jsonb);
        v_old_len     INTEGER;
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
          IF EXISTS (
               SELECT 1
                 FROM jsonb_array_elements(v_new_custody) WITH ORDINALITY AS t(e, i)
                WHERE i > v_old_len
                  AND jsonb_typeof(e) = 'object'
                  AND e ? 'entryHash'
                  AND NOT EXISTS (
                    SELECT 1 FROM custody_entries ce
                     WHERE ce.evidence_id = OLD.evidence_id
                       AND ce.entry_hash = (e ->> 'entryHash'))) THEN
            RAISE EXCEPTION 'envelopes.envelope.custodyChain entry claims an entryHash with no custody_entries row (%)',
              OLD.evidence_id;
          END IF;
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;`,
  },
];

/** The 0.5.0 functions a later SDK rewrote. */
export const REWRITTEN_FUNCTIONS_POSTGRES = [
  'custody_entries_compute_hash',
  'custody_entries_verify_insert',
  'envelopes_enforce_immutable',
] as const;

/** The 0.5.0 functions a later SDK dropped. */
export const REMOVED_FUNCTIONS_POSTGRES = ['custody_entries_length_prefix'] as const;

/**
 * Put back the functions as 0.5.0 defined them: the definitions in
 * `FUNCTIONS_0_5_0_POSTGRES`, and no function of the schema with a
 * configuration of its own (0.5.0 set none; a later SDK pins every
 * function's search_path).
 */
export async function restore050FunctionsPostgres(db: Queryable): Promise<void> {
  for (const fn of FUNCTIONS_0_5_0_POSTGRES) await db.query(fn.sql);
  const configured = await db.query(
    `SELECT p.oid::regprocedure::text AS signature
       FROM pg_proc p
      WHERE p.pronamespace = current_schema()::regnamespace AND p.proconfig IS NOT NULL`,
  );
  for (const row of configured.rows) await db.query(`ALTER FUNCTION ${row.signature} RESET ALL`);
}

/**
 * The Postgres twin of `stripLogSchemaSqlite`: the trigger on `envelopes`, the
 * log tables, every function of the evidence-log schema, and the indexes and
 * guards later SDKs added to 0.5.0 tables; then the functions later SDKs
 * rewrote or removed, as 0.5.0 defined them.
 */
export async function stripLogSchemaPostgres(db: Queryable): Promise<void> {
  await db.query(`DROP TRIGGER IF EXISTS ${LOG_TRIGGER_ON_ENVELOPES.postgres} ON envelopes`);
  // The anchoring tables' owner gate on a record's anchor (0.8.0).
  await db.query('DROP TRIGGER IF EXISTS tzun_envelopes_anchor_require_owner ON envelopes');
  for (const index of LATER_INDEXES_POSTGRES) await db.query(`DROP INDEX IF EXISTS ${index}`);
  for (const guard of LATER_GUARDS_POSTGRES) {
    await db.query(`DROP TRIGGER IF EXISTS ${guard.trigger} ON ${guard.table}`);
    await db.query(`DROP FUNCTION IF EXISTS ${guard.fn}()`);
  }
  for (const table of AFTER_LOG_TABLES_POSTGRES) await db.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
  for (const fn of AFTER_LOG_FUNCTIONS_POSTGRES) await db.query(`DROP FUNCTION IF EXISTS ${fn}() CASCADE`);
  for (const table of LOG_TABLES) await db.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
  const fns = await db.query(
    `SELECT p.oid::regprocedure::text AS signature
       FROM pg_proc p
      WHERE p.pronamespace = current_schema()::regnamespace
        AND p.proname = ANY($1::text[])`,
    [LOG_FUNCTIONS_POSTGRES],
  );
  for (const row of fns.rows) await db.query(`DROP FUNCTION IF EXISTS ${row.signature}`);
  await restore050FunctionsPostgres(db);
}

/** The Postgres functions of the evidence-log schema (0.6.0). */
export const LOG_FUNCTIONS_POSTGRES = [
  'store_identity_block_mutation',
  'logs_block_backdated_id',
  'logs_verify_insert',
  'logs_block_mutation',
  'log_leaves_verify_insert',
  'log_leaves_block_mutation',
  'evidence_log_append',
  'log_checkpoints_verify_insert',
  'log_checkpoints_guard_update',
  'log_checkpoints_block_removal',
  'anchor_publications_block_backdated_id',
  'anchor_publications_verify_insert',
  'anchor_publications_guard_update',
  'anchor_publications_block_removal',
  'anchor_lease_verify',
  'anchor_wallets_verify_insert',
  'anchor_wallets_guard_update',
  'anchor_wallets_block_removal',
  'anchor_wallet_txs_verify_insert',
  'anchor_wallet_txs_block_mutation',
  // The anchoring trust rules (0.8.0).
  'log_leaves_bind_record',
  'anchoring_require_owner',
  'log_checkpoints_check_digest',
  'anchor_publications_assign_created_at',
  'log_leaves_assign_logged_at',
  'anchor_publications_guard_transitions',
  'anchor_lease_require_protocol',
];
