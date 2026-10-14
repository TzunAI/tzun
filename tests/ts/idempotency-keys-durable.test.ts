/**
 * Idempotency keys outlive the handle that claimed them.
 *
 * The conformance contract pins the replay rule on one adapter instance. A
 * retry after a timeout usually comes from somewhere else: the same process
 * after a restart, or another replica on the same database. So:
 *   - SQLite: a key claimed before the file was closed still replays after it
 *     is reopened.
 *   - Postgres: a key claimed through one adapter (one pool) replays through
 *     another, and two adapters racing one key store one record.
 * Keys are kept for the life of the store, as the platform keeps them: there
 * is no expiry to test beyond "still there".
 *
 * Postgres leg: when the Postgres legs run (tests/ts/helpers/postgres-test-db.ts),
 * in a schema of this file's own, under run-unique ids and keys on a
 * run-unique chain.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { makeEnvelope } from './storage-conformance/fixtures';

let counter = 0;
const unique = (label: string): string =>
  `${label}-${Date.now().toString(36)}-${(counter += 1)}-${Math.random().toString(36).slice(2, 8)}`;

describe('idempotency keys survive a reopen — sqlite', () => {
  it('a key claimed before close replays after the file is reopened', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-'));
    const dbPath = path.join(dir, 'idem.db');
    try {
      const first = new SqliteStorageAdapter(dbPath);
      const claimed = await first.storeIdempotent(makeEnvelope({ evidenceId: 'ev-before' }), undefined, {
        idempotency: { key: 'k-1', fingerprint: 'fp' },
      });
      await first.close();

      const reopened = new SqliteStorageAdapter(dbPath);
      const replay = await reopened.storeIdempotent(makeEnvelope({ evidenceId: 'ev-after', sequenceNumber: 2 }), undefined, {
        idempotency: { key: 'k-1', fingerprint: 'fp' },
      });
      expect(replay).toEqual({ kind: 'replay', receipt: (claimed as { receipt: unknown }).receipt });
      expect(await reopened.getChainLength()).toBe(1);
      await reopened.close();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

const pgSchema = pgSuiteSchema('idem_keys_durable');

(PG_TESTS_ENABLED ? describe : describe.skip)('idempotency keys across adapters — postgres', () => {
  let a: PostgresStorageAdapter;
  let b: PostgresStorageAdapter;

  beforeEach(async () => {
    a = new PostgresStorageAdapter(pgSchema.url);
    b = new PostgresStorageAdapter(pgSchema.url);
    await a.ensureTables();
  });

  afterEach(async () => {
    await Promise.all([a.close(), b.close()]);
  });

  it('a key claimed through one adapter replays through another', async () => {
    const chainId = unique('chain');
    const key = unique('key');
    const claimed = await a.storeIdempotent(makeEnvelope({ evidenceId: unique('ev') }), chainId, {
      idempotency: { key, fingerprint: 'fp' },
    });
    const replay = await b.storeIdempotent(makeEnvelope({ evidenceId: unique('ev'), sequenceNumber: 2 }), chainId, {
      idempotency: { key, fingerprint: 'fp' },
    });
    expect(replay).toEqual({ kind: 'replay', receipt: (claimed as { receipt: unknown }).receipt });
    expect(await b.storeIdempotent(makeEnvelope({ evidenceId: unique('ev'), sequenceNumber: 2 }), chainId, {
      idempotency: { key, fingerprint: 'other' },
    })).toEqual({ kind: 'conflict' });
    expect(await a.getChainLength(chainId)).toBe(1);
  });

  it('two adapters racing one key store one record', async () => {
    const chainId = unique('chain');
    const key = unique('key');
    const outcomes = await Promise.all(
      [a, b, a, b].map((adapter) =>
        adapter.storeIdempotent(makeEnvelope({ evidenceId: unique('ev') }), chainId, {
          idempotency: { key, fingerprint: 'fp' },
        }),
      ),
    );
    expect(outcomes.map((o) => o.kind).sort()).toEqual(['claimed', 'replay', 'replay', 'replay']);
    const receipts = outcomes.map((o) => (o as { receipt: unknown }).receipt);
    for (const r of receipts) expect(r).toEqual(receipts[0]);
    expect(await a.getChainLength(chainId)).toBe(1);
  });
});
