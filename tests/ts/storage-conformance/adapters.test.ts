/**
 * Storage-adapter conformance suite — the runner.
 *
 * `contract.ts` holds one behavioural spec; this file runs it against every
 * in-tree adapter so the three are asked the SAME questions. Independently
 * written per-adapter suites can all pass while the adapters disagree: an
 * application's tamper flow can work on memory and fabricate its incident on
 * SQLite when nothing asks both adapters the same question.
 *
 * Legs:
 *   - memory   — always.
 *   - sqlite   — always; a fresh temp file per case, with better-sqlite3
 *                raising its errors from another realm (see below).
 *   - postgres — when the Postgres legs run
 *                (tests/ts/helpers/postgres-test-db.ts), in a schema of this
 *                file's own, emptied before each case.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryStorageAdapter } from '../../../src/storage/memory';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';
import { raiseSqliteErrorsFromAnotherRealm } from '../helpers/sqlite-foreign-realm';
import { describeStorageConformance, AdapterUnderTest } from './contract';

// In a full run most files share their jest worker with a file that opened a
// SQLite database first, and there better-sqlite3 raises its errors from that
// file's realm. The SQLite leg runs in that state every time, whichever file
// the worker ran first, so an assertion that holds only in a worker's first
// file fails on every run.
let restoreSqliteErrors: (() => void) | undefined;
beforeAll(() => {
  restoreSqliteErrors = raiseSqliteErrorsFromAnotherRealm();
});
afterAll(() => restoreSqliteErrors?.());

// ── memory ────────────────────────────────────────────────────────────────

describeStorageConformance('memory', async () => {
  const adapter = new MemoryStorageAdapter();
  return { adapter, teardown: async () => adapter.close() };
}, { backend: 'memory' });

// ── sqlite (temp file) ────────────────────────────────────────────────────

describeStorageConformance('sqlite', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tzun-test-conformance-'));
  const adapter = new SqliteStorageAdapter(join(dir, 'conformance.db'));
  return {
    adapter,
    teardown: async () => {
      await adapter.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}, { backend: 'sqlite' });

// ── postgres (integration-gated) ──────────────────────────────────────────

const pgSchema = pgSuiteSchema('conformance');

if (PG_TESTS_ENABLED) {
  // Every table in the schema is emptied — the append-only ones included, past
  // their triggers — so one case's residue cannot leak into the next.
  const factory: AdapterUnderTest['factory'] = async () => {
    await pgSchema.empty();
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    return { adapter, teardown: async () => adapter.close() };
  };

  describeStorageConformance('postgres', factory, { backend: 'postgres' });
} else {
  describe('storage conformance: postgres', () => {
    it.skip('skipped: set RUN_INTEGRATION_TESTS=true and DATABASE_URL to run', () => { /* gated */ });
  });
}
