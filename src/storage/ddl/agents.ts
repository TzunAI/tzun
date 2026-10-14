/**
 * The agent catalog (Record §6.9): the `agent_descriptors` table and the
 * optional adapter methods `putAgentDescriptor`, `getAgentDescriptor` and
 * `listAgentDescriptors`, as a storage extension. The statements and rules
 * are in `../agent-sql.ts`.
 *
 * A store with this extension is a store with the catalog: capture refuses an
 * agent reference the catalog does not hold, and store-level verification
 * resolves each reference and re-hashes its bytes. A store without it accepts
 * references as given and verification reports them `catalog_absent`.
 *
 * The table is keyed by digest. `canonical_bytes` are the exact bytes that
 * were hashed; `name`, `organization` and `parent` are lookup columns that
 * verification never reads; `seq` orders the listing (registration order).
 * Every row is immutable and none is removed: an UPDATE or a DELETE (and on
 * Postgres a TRUNCATE) is refused by trigger. On SQLite an INSERT that names
 * a digest, a `seq` or a rowid a row already holds is refused too, whatever
 * its conflict clause, so REPLACE conflict resolution cannot swap or remove a
 * row past the DELETE trigger. On Postgres a CHECK also
 * refuses a row whose bytes do not hash to its digest, so the table cannot
 * hold a row under a digest it does not answer to. The catalog writes no row
 * with a record, so the extension has no `store()` hooks.
 */
import { EXISTING_ROW_TAG } from '../append-only';
import type { StorageExtension } from '../extensions';
import {
  createMemoryAgentCatalog,
  memoryAgentMethods,
  postgresAgentMethods,
  sqliteAgentMethods,
  type MemoryAgentCatalog,
} from '../agent-sql';

export const SQLITE_AGENTS_DDL = `
  CREATE TABLE IF NOT EXISTS agent_descriptors (
    digest TEXT PRIMARY KEY
      CHECK (length(digest) = 71 AND substr(digest, 1, 7) = 'sha256:' AND substr(digest, 8) NOT GLOB '*[^0-9a-f]*'),
    canonical_bytes TEXT NOT NULL,
    name TEXT NOT NULL,
    organization TEXT NOT NULL,
    parent TEXT,
    registered_at TEXT NOT NULL,
    seq INTEGER NOT NULL UNIQUE
  );
  CREATE INDEX IF NOT EXISTS idx_agent_descriptors_name ON agent_descriptors(name, seq);
  CREATE INDEX IF NOT EXISTS idx_agent_descriptors_organization ON agent_descriptors(organization, seq);
  CREATE TRIGGER IF NOT EXISTS agent_descriptors_block_update
    BEFORE UPDATE ON agent_descriptors
    BEGIN SELECT RAISE(ABORT, 'agent_descriptors rows are immutable (UPDATE refused)'); END;
  CREATE TRIGGER IF NOT EXISTS agent_descriptors_block_delete
    BEFORE DELETE ON agent_descriptors
    BEGIN SELECT RAISE(ABORT, 'agent_descriptors rows are immutable (DELETE refused)'); END;
  -- No insert over an existing row. REPLACE conflict resolution (INSERT OR
  -- REPLACE, REPLACE INTO) deletes the row an insert conflicts with and then
  -- inserts, and that delete fires no DELETE trigger unless
  -- recursive_triggers is on. A BEFORE INSERT trigger runs before conflict
  -- handling, so an insert naming a digest, a seq or a rowid a row holds is
  -- refused whatever its conflict clause. An insert that names no rowid
  -- reads NEW.rowid as -1 here, and agent_descriptors_block_negative_rowid
  -- keeps any row from holding -1.
  CREATE TRIGGER IF NOT EXISTS agent_descriptors_block_replace
    BEFORE INSERT ON agent_descriptors
    BEGIN
      SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} agent_descriptors rows are immutable (INSERT over an existing row refused)')
       WHERE EXISTS (SELECT 1 FROM agent_descriptors WHERE digest = NEW.digest)
          OR EXISTS (SELECT 1 FROM agent_descriptors WHERE seq = NEW.seq)
          OR EXISTS (SELECT 1 FROM agent_descriptors WHERE rowid = NEW.rowid);
    END;
  -- No row at a negative rowid: a row planted at -1 would collide with every
  -- later insert, which reads NEW.rowid as -1 above. AFTER INSERT, because
  -- only there does NEW.rowid tell a rowid of -1 written explicitly from none.
  CREATE TRIGGER IF NOT EXISTS agent_descriptors_block_negative_rowid
    AFTER INSERT ON agent_descriptors
    BEGIN
      SELECT RAISE(ABORT, 'agent_descriptors: a rowid cannot be negative')
       WHERE NEW.rowid < 0;
    END;
`;

export const POSTGRES_AGENTS_DDL = `
  CREATE TABLE IF NOT EXISTS agent_descriptors (
    digest TEXT PRIMARY KEY,
    canonical_bytes TEXT NOT NULL,
    name TEXT NOT NULL,
    organization TEXT NOT NULL,
    parent TEXT,
    registered_at TIMESTAMPTZ NOT NULL,
    seq BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    CONSTRAINT agent_descriptors_digest_hashes_bytes
      CHECK (digest = 'sha256:' || encode(sha256(convert_to(canonical_bytes, 'UTF8')), 'hex'))
  );
  CREATE INDEX IF NOT EXISTS idx_agent_descriptors_name ON agent_descriptors(name, seq);
  CREATE INDEX IF NOT EXISTS idx_agent_descriptors_organization ON agent_descriptors(organization, seq);
  CREATE OR REPLACE FUNCTION agent_descriptors_block_mutation()
  RETURNS TRIGGER AS $$
  BEGIN
    RAISE EXCEPTION 'agent_descriptors rows are immutable (% refused)', TG_OP;
  END;
  $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
  DROP TRIGGER IF EXISTS agent_descriptors_block_mutation_trigger ON agent_descriptors;
  CREATE TRIGGER agent_descriptors_block_mutation_trigger
    BEFORE UPDATE OR DELETE ON agent_descriptors
    FOR EACH ROW EXECUTE FUNCTION agent_descriptors_block_mutation();
  DROP TRIGGER IF EXISTS agent_descriptors_block_truncate_trigger ON agent_descriptors;
  CREATE TRIGGER agent_descriptors_block_truncate_trigger
    BEFORE TRUNCATE ON agent_descriptors
    FOR EACH STATEMENT EXECUTE FUNCTION agent_descriptors_block_mutation();
`;

/** The agent catalog as a storage extension of the SQLite, Postgres and memory adapters. */
export const agentsStorageExtension: StorageExtension = {
  name: 'agents',
  sqlite: {
    migrate(db) {
      db.exec(SQLITE_AGENTS_DDL);
    },
    methods(db) {
      return sqliteAgentMethods(db);
    },
  },
  postgres: {
    async migrate(client) {
      await client.query(POSTGRES_AGENTS_DDL);
    },
    methods(db) {
      return postgresAgentMethods(db);
    },
  },
  memory: {
    createState(): MemoryAgentCatalog {
      return createMemoryAgentCatalog();
    },
    methods(state: MemoryAgentCatalog) {
      return memoryAgentMethods(state);
    },
  },
};
