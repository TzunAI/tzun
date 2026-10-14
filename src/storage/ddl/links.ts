/**
 * The link index as a storage extension: the `evidence_links` table, the
 * rows each stored record contributes, written in the storing transaction,
 * and `listLinksTo`.
 *
 * The table is derived from the stored `links` and is not hashed:
 * verification never reads it. Its rows are never changed or deleted (a
 * record's links never change), and a row is written at most once per
 * (record, link index). When the table is first created on a store that
 * already holds records, every stored record with links is indexed in the
 * same transaction. The index is rebuilt from the envelopes by dropping the
 * table (the triggers refuse UPDATE, DELETE and TRUNCATE, not DROP) and
 * reopening the store. Three indexes serve the three page shapes: by target
 * digest; by target digest and one relation; and the statements of link
 * records by target digest. The memory adapter keeps no table: it scans the
 * records it holds.
 *
 * Statements are in `../links-sql.ts`.
 */
import type { StorageAdapter } from '@tzun/engine';
import type { StorageExtension } from '../extensions';
import {
  checkLinkIndexQuery,
  linkIndexRows,
  memoryLinkIndexPage,
  postgresBackfillLinkIndex,
  postgresInsertLinkRows,
  postgresLinkIndexPage,
  sqliteBackfillLinkIndex,
  sqliteInsertLinkRows,
  sqliteLinkIndexPage,
  type CheckedLinkIndexQuery,
  type LinkIndexPage,
  type LinkIndexQuery,
} from '../links-sql';

export const SQLITE_LINKS_DDL = `
  CREATE TABLE IF NOT EXISTS evidence_links (
    evidence_id TEXT NOT NULL,
    idx INTEGER NOT NULL CHECK (idx >= 0),
    rel TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    subject_digest TEXT,
    PRIMARY KEY (evidence_id, idx)
  );
  CREATE INDEX IF NOT EXISTS idx_evidence_links_target ON evidence_links (target_digest, evidence_id, idx);
  CREATE INDEX IF NOT EXISTS idx_evidence_links_target_rel ON evidence_links (target_digest, rel, evidence_id, idx);
  CREATE INDEX IF NOT EXISTS idx_evidence_links_target_statement ON evidence_links (target_digest, evidence_id, idx) WHERE subject_digest IS NOT NULL;
  CREATE TRIGGER IF NOT EXISTS evidence_links_block_update
    BEFORE UPDATE ON evidence_links
    BEGIN SELECT RAISE(ABORT, 'evidence_links rows are derived from immutable records (UPDATE refused)'); END;
  CREATE TRIGGER IF NOT EXISTS evidence_links_block_delete
    BEFORE DELETE ON evidence_links
    BEGIN SELECT RAISE(ABORT, 'evidence_links rows are derived from immutable records (DELETE refused)'); END;
`;

export const POSTGRES_LINKS_DDL = `
  CREATE TABLE IF NOT EXISTS evidence_links (
    evidence_id TEXT COLLATE "C" NOT NULL,
    idx INTEGER NOT NULL CHECK (idx >= 0),
    rel TEXT NOT NULL,
    target_digest TEXT NOT NULL CHECK (target_digest ~ '^[0-9a-f]{64}$'),
    subject_digest TEXT CHECK (subject_digest IS NULL OR subject_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (evidence_id, idx)
  );
  CREATE INDEX IF NOT EXISTS idx_evidence_links_target ON evidence_links (target_digest, evidence_id, idx);
  CREATE INDEX IF NOT EXISTS idx_evidence_links_target_rel ON evidence_links (target_digest, rel, evidence_id, idx);
  CREATE INDEX IF NOT EXISTS idx_evidence_links_target_statement ON evidence_links (target_digest, evidence_id, idx) WHERE subject_digest IS NOT NULL;
  CREATE OR REPLACE FUNCTION evidence_links_block_mutation()
  RETURNS TRIGGER AS $$
  BEGIN
    RAISE EXCEPTION '% rows are derived from immutable records (% refused)', TG_TABLE_NAME, TG_OP;
  END;
  $$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
  DROP TRIGGER IF EXISTS evidence_links_block_mutation_trigger ON evidence_links;
  CREATE TRIGGER evidence_links_block_mutation_trigger
    BEFORE UPDATE OR DELETE ON evidence_links
    FOR EACH ROW EXECUTE FUNCTION evidence_links_block_mutation();
  DROP TRIGGER IF EXISTS evidence_links_block_truncate_trigger ON evidence_links;
  CREATE TRIGGER evidence_links_block_truncate_trigger
    BEFORE TRUNCATE ON evidence_links
    FOR EACH STATEMENT EXECUTE FUNCTION evidence_links_block_mutation();
`;

type ListLinksTo = NonNullable<StorageAdapter['listLinksTo']>;

/**
 * `listLinksTo` over a page reader. The options are the engine's (`rels`,
 * `limit`, `cursor`) plus `statements: true`, which keeps only the statements
 * of link records; every row carries `subjectDigest`.
 */
function listLinksToOver(page: (query: CheckedLinkIndexQuery) => Promise<LinkIndexPage> | LinkIndexPage): ListLinksTo {
  return async (digest: string, options?: LinkIndexQuery) => page(checkLinkIndexQuery(digest, options));
}

/** The `evidence_links` index and `listLinksTo`, on the SQLite, Postgres and memory adapters. */
export const linksStorageExtension: StorageExtension = {
  name: 'links',
  sqlite: {
    migrate(db) {
      // Checked, created and filled in one IMMEDIATE transaction: a store is
      // never left with the table and only part of its rows, and a second
      // opener waits for the first.
      db.transaction(() => {
        const present = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'evidence_links'").get() !== undefined;
        db.exec(SQLITE_LINKS_DDL);
        if (!present) sqliteBackfillLinkIndex(db);
      }).immediate();
    },
    afterInsert(db, write) {
      sqliteInsertLinkRows(db, linkIndexRows(write.envelope));
    },
    methods(db) {
      return { listLinksTo: listLinksToOver((query) => sqliteLinkIndexPage(db, query)) };
    },
  },
  postgres: {
    async migrate(client) {
      const present = await client.query<{ present: boolean }>("SELECT to_regclass('evidence_links') IS NOT NULL AS present");
      if (present.rows[0]?.present === true) {
        await client.query(POSTGRES_LINKS_DDL);
        return;
      }
      // Created and filled in one transaction: a store is never left with the
      // table and only part of its rows. The caller holds the store's
      // advisory lock, so no second opener runs this at the same time.
      await client.query('BEGIN');
      try {
        await client.query(POSTGRES_LINKS_DDL);
        await postgresBackfillLinkIndex(client);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw error;
      }
    },
    async afterInsert(client, write) {
      await postgresInsertLinkRows(client, linkIndexRows(write.envelope));
    },
    methods({ pool }) {
      return { listLinksTo: listLinksToOver((query) => postgresLinkIndexPage(pool, query)) };
    },
  },
  memory: {
    createState(): null {
      return null;
    },
    methods(_state: null, reads) {
      return { listLinksTo: listLinksToOver((query) => memoryLinkIndexPage(reads.all(), query)) };
    },
  },
};
