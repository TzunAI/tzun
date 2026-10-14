/**
 * Annotation and relink records are append-only in the database, on both SQL
 * adapters.
 *
 * `chain_annotations` and `chain_relinks` are the SDK's recovery records: who
 * annotated or re-linked what, when, and the digests and links as they stood.
 * The hosted service keeps the same facts in `recoveries`, whose trigger refuses
 * DELETE and TRUNCATE and freezes every column except an `undone_at` latch
 * these tables do not have. So here every column is frozen: UPDATE, DELETE
 * and (Postgres) TRUNCATE are refused, and INSERT stays open.
 *
 * Every attack is a raw statement on the adapter's own connection. Legs:
 * sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own,
 * under run-unique ids. A TRUNCATE case whose guard is missing empties only
 * this file's table.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { StorageAdapter } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { makeAnnotation, makeRelink } from './storage-conformance/fixtures';

interface Leg {
  name: 'sqlite' | 'postgres';
  make: () => Promise<{ adapter: StorageAdapter; teardown: () => Promise<void> }>;
  raw: (adapter: StorageAdapter, sql: string, params?: unknown[]) => Promise<void>;
}

const sqliteLeg: Leg = {
  name: 'sqlite',
  make: async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-recovery-records-'));
    const adapter = new SqliteStorageAdapter(path.join(dir, 'recovery.db'));
    return {
      adapter,
      teardown: async () => {
        await adapter.close();
        fs.rmSync(dir, { recursive: true, force: true });
      },
    };
  },
  raw: async (adapter, sql, params = []) => {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    db.prepare(sql).run(...params);
  },
};

const pgSchema = pgSuiteSchema('recovery_append_only');

const postgresLeg: Leg = {
  name: 'postgres',
  make: async () => {
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    return { adapter, teardown: async () => adapter.close() };
  },
  raw: async (adapter, sql, params = []) => {
    const pool = (adapter as unknown as { pool: import('pg').Pool }).pool;
    let n = 0;
    await pool.query(sql.replace(/\?/g, () => `$${++n}`), params);
  },
};

const legs: Leg[] = PG_TESTS_ENABLED ? [sqliteLeg, postgresLeg] : [sqliteLeg];

/** The message a raw statement was refused with (realm-independent; see custody-trail-hashed-and-atomic.test.ts). */
async function refusal(run: () => Promise<void>): Promise<string> {
  try {
    await run();
  } catch (err) {
    const message = (err as { message?: unknown } | null)?.message;
    return typeof message === 'string' ? message : String(err);
  }
  throw new Error('expected the statement to be refused, but it went through');
}

let counter = 0;
const unique = (label: string): string =>
  `${label}-${Date.now().toString(36)}-${(counter += 1)}-${Math.random().toString(36).slice(2, 8)}`;

describe.each(legs)('recovery records are append-only — $name adapter', (leg) => {
  let adapter: StorageAdapter;
  let teardown: () => Promise<void>;

  beforeEach(async () => {
    ({ adapter, teardown } = await leg.make());
  });

  afterEach(async () => {
    await teardown();
  });

  const raw = (sql: string, p?: unknown[]) => leg.raw(adapter, sql, p);

  describe('chain_annotations', () => {
    it('refuses rewriting any column, and deleting the row; the record reads back unchanged', async () => {
      const annotation = makeAnnotation({ id: unique('ann'), incidentId: unique('inc') });
      await adapter.storeAnnotation(annotation);

      const edits: Array<[string, unknown[]]> = [
        ['UPDATE chain_annotations SET notes = ? WHERE id = ?', ['rewritten', annotation.id]],
        ['UPDATE chain_annotations SET annotated_by = ? WHERE id = ?', ['mallory@acme.example', annotation.id]],
        ['UPDATE chain_annotations SET original_digests = ? WHERE id = ?', ['{}', annotation.id]],
        ['UPDATE chain_annotations SET affected_records = ? WHERE id = ?', ['[]', annotation.id]],
        ['UPDATE chain_annotations SET incident_id = ? WHERE id = ?', ['other', annotation.id]],
        ['DELETE FROM chain_annotations WHERE id = ?', [annotation.id]],
      ];
      for (const [sql, params] of edits) {
        expect({ sql, message: await refusal(() => raw(sql, params)) })
          .toEqual({ sql, message: expect.stringMatching(/chain_annotations rows are append-only/) });
      }
      expect(await adapter.getAnnotation(annotation.id)).toEqual(annotation);
    });

    if (leg.name === 'postgres') {
      it('refuses TRUNCATE', async () => {
        await adapter.storeAnnotation(makeAnnotation({ id: unique('ann'), incidentId: unique('inc') }));
        expect(await refusal(() => raw('TRUNCATE chain_annotations'))).toMatch(/chain_annotations rows are append-only/);
      });
    }
  });

  describe('chain_relinks', () => {
    it('refuses rewriting any column, and deleting the row; the record reads back unchanged', async () => {
      const relink = makeRelink({ id: unique('rlk'), incidentId: unique('inc') });
      await adapter.storeRelink(relink);

      const edits: Array<[string, unknown[]]> = [
        ['UPDATE chain_relinks SET modified_links = ? WHERE id = ?', ['[]', relink.id]],
        ['UPDATE chain_relinks SET relinked_by = ? WHERE id = ?', ['mallory@acme.example', relink.id]],
        ['UPDATE chain_relinks SET to_sequence = ? WHERE id = ?', [99, relink.id]],
        ['UPDATE chain_relinks SET from_sequence = ? WHERE id = ?', [0, relink.id]],
        ['DELETE FROM chain_relinks WHERE id = ?', [relink.id]],
      ];
      for (const [sql, params] of edits) {
        expect({ sql, message: await refusal(() => raw(sql, params)) })
          .toEqual({ sql, message: expect.stringMatching(/chain_relinks rows are append-only/) });
      }
      expect(await adapter.getRelink(relink.id)).toEqual(relink);
    });

    if (leg.name === 'postgres') {
      it('refuses TRUNCATE', async () => {
        await adapter.storeRelink(makeRelink({ id: unique('rlk'), incidentId: unique('inc') }));
        expect(await refusal(() => raw('TRUNCATE chain_relinks'))).toMatch(/chain_relinks rows are append-only/);
      });
    }
  });
});
