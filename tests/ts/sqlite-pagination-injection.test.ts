/**
 * SQLite list() binds LIMIT/OFFSET as parameters and rejects any bound that
 * is not a non-negative integer, instead of pasting it into the SQL text.
 *
 * `ListOptions.limit` is declared `number`, but a TypeScript type is not a
 * runtime boundary. A JavaScript integrator writing
 * `tzun.list({ limit: req.query.limit })` hands the adapter a string, and a
 * string pasted into the LIMIT position would be SQL, not data.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import request from 'supertest';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { assembleEnvelope, SchemaRegistry, StorageAdapter } from '@tzun/engine';
import { InvalidPaginationError } from '../../src/storage/pagination-guard';
import { createServer } from '../../src/api/server';
import { Tzun } from '../../src/sdk/index';

function tmpDb(name: string): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), `tzun-${name}-`)), 'tzun.db');
}

async function captureN(storage: StorageAdapter, n: number): Promise<void> {
  const registry = new SchemaRegistry();
  let previousDigest: string | undefined;
  for (let i = 1; i <= n; i++) {
    const envelope = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'sys',
        aiOutput: { rec: `r-${i}` },
        action: 'approved',
        reason: `reason-${i}`,
      }, { previousDigest: previousDigest, sequenceNumber: i, signoffExpectation: null });
    await storage.store(envelope);
    previousDigest = envelope.integrity.canonicalDigest;
  }
}

describe('SQLite pagination bounds are bound, not interpolated', () => {
  let store: SqliteStorageAdapter;
  let dbPath: string;

  beforeEach(async () => {
    dbPath = tmpDb('pagination');
    store = new SqliteStorageAdapter(dbPath);
    await captureN(store, 5);
  });

  afterEach(() => {
    store.close();
    try { fs.rmSync(path.dirname(dbPath), { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('legitimate numeric limit/offset still page correctly', async () => {
    // Numeric bounds keep working: a guard that rejected every bound would
    // pass the rejection cases below and break paging.
    expect(await store.list({ limit: 2 })).toHaveLength(2);
    expect(await store.list({ offset: 3 })).toHaveLength(2);
    expect(await store.list({ limit: 2, offset: 4 })).toHaveLength(1);
    expect(await store.list({ limit: 0 })).toHaveLength(0);
  });

  it('a SELECT subquery in the limit position does not reach the database', async () => {
    // The core hazard: interpolated into the SQL, this subquery would execute
    // and return rows — a blind read of another table through the row count.
    const payload = "(SELECT count(*) FROM tamper_incidents)" as unknown as number;
    await expect(store.list({ limit: payload })).rejects.toThrow(InvalidPaginationError);
  });

  it('a subquery cannot be used as a row-count oracle on another table', async () => {
    // The exploit shape: the attacker learns a count from another table by
    // reading how many rows come back. With 5 envelopes stored, an
    // interpolated payload would return exactly 5 rows, confirming the
    // subquery executed. The adapter rejects it outright.
    const oracle = '(SELECT count(*) FROM envelopes)' as unknown as number;
    await expect(store.list({ limit: oracle })).rejects.toThrow(InvalidPaginationError);
  });

  it('a subquery in the offset position does not reach the database', async () => {
    const payload = "(SELECT count(*) FROM chain_state)" as unknown as number;
    await expect(store.list({ offset: payload })).rejects.toThrow(InvalidPaginationError);
  });

  it('a non-numeric limit is rejected rather than becoming LIMIT NaN', async () => {
    // Interpolated, this would surface as SqliteError "no such column: NaN" —
    // a confusing 500.
    await expect(store.list({ limit: 'abc' as unknown as number }))
      .rejects.toThrow(InvalidPaginationError);
  });

  it('numeric-looking strings are rejected too, not silently coerced', async () => {
    await expect(store.list({ limit: '2' as unknown as number }))
      .rejects.toThrow(InvalidPaginationError);
  });

  it('negative and fractional bounds are rejected', async () => {
    await expect(store.list({ limit: -1 })).rejects.toThrow(InvalidPaginationError);
    await expect(store.list({ offset: 1.5 })).rejects.toThrow(InvalidPaginationError);
    await expect(store.list({ limit: NaN })).rejects.toThrow(InvalidPaginationError);
  });

  it('listModelDescriptors rejects the same payloads (sibling path)', async () => {
    await expect(
      store.listModelDescriptors!({ limit: '(SELECT 1)' as unknown as number }),
    ).rejects.toThrow(InvalidPaginationError);
  });
});

describe('memory adapter agrees on legitimate paging (parity)', () => {
  it('paging semantics match the SQLite adapter', async () => {
    const mem = new MemoryStorageAdapter();
    await captureN(mem, 5);
    expect(await mem.list({ limit: 2 })).toHaveLength(2);
    expect(await mem.list({ offset: 3 })).toHaveLength(2);
  });
});

describe('GET /v1/evidence rejects bad pagination with 400, not 500', () => {
  let app: ReturnType<typeof createServer>;

  beforeEach(async () => {
    app = createServer(await Tzun.init(), { allowUnauthenticated: true });
  });

  it('?limit=abc answers 400', async () => {
    // Unvalidated, parseInt('abc') -> NaN -> LIMIT NaN -> SqliteError -> 500.
    const res = await request(app).get('/v1/evidence?limit=abc');
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/limit/);
  });

  it('?limit=(SELECT...) answers 400', async () => {
    const res = await request(app)
      .get('/v1/evidence?limit=' + encodeURIComponent('(SELECT count(*) FROM tamper_incidents)'));
    expect(res.status).toBe(400);
  });

  it('?limit=9 OR 1=1 answers 400 rather than silently paging at 9', async () => {
    // parseInt stops at the first non-digit and returns 9 — a silent
    // truncation that looks like success.
    const res = await request(app).get('/v1/evidence?limit=' + encodeURIComponent('9 OR 1=1'));
    expect(res.status).toBe(400);
  });

  it('?limit=2 still works', async () => {
    const res = await request(app).get('/v1/evidence?limit=2');
    expect(res.status).toBe(200);
  });
});
