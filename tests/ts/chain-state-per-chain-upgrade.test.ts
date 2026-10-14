/**
 * A store written before per-chain heads is evolved in place.
 *
 * In such a store `chain_state` is one row (`id INTEGER PRIMARY KEY CHECK
 * (id = 1)`) shared by every chain. `CREATE TABLE IF NOT EXISTS` skips a table
 * that already exists, so on its own it would keep the single-row table and
 * every append would fail on a column that is not there. This repo has one
 * evolving pre-release schema and no migration files, so `ensureTables()` /
 * `createTables()` does the evolution: the single-row table goes, the
 * per-chain one is created, and each chain's row is seeded from its own
 * highest sequence number and the digest of the record holding it.
 *
 * Legs: sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema created for the case and
 * dropped after it.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { randomBytes } from 'crypto';
import Database from 'better-sqlite3';
import { Client } from 'pg';
import { assembleEnvelope, SchemaRegistry } from '@tzun/engine';
import type { EvidenceEnvelope, StorageAdapter } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgCaseSchema, type PgCaseSchema } from './helpers/postgres-test-db';

const registry = new SchemaRegistry();

function envelope(chainTag: string, seq: number, previousDigest?: string): EvidenceEnvelope {
  return assembleEnvelope({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: `sys-${chainTag}`,
      aiOutput: { n: seq },
      action: 'approved',
      reason: `${chainTag} ${seq}`,
    }, { previousDigest: previousDigest, sequenceNumber: seq });
}

/** Three records on `default`, two on `tenant-b`, each chain linked from its own. */
async function seed(adapter: StorageAdapter): Promise<Record<string, EvidenceEnvelope[]>> {
  const written: Record<string, EvidenceEnvelope[]> = { default: [], 'tenant-b': [] };
  for (const [chainId, count] of [['default', 3], ['tenant-b', 2]] as const) {
    let previousDigest: string | undefined;
    for (let seq = 1; seq <= count; seq++) {
      const e = envelope(chainId, seq, previousDigest);
      await adapter.store(e, chainId);
      previousDigest = e.integrity.canonicalDigest;
      written[chainId]!.push(e);
    }
  }
  return written;
}

/** What the per-chain table must say about a seeded store, however it got there. */
async function expectPerChainHeads(
  adapter: StorageAdapter,
  written: Record<string, EvidenceEnvelope[]>,
): Promise<void> {
  expect(await adapter.getLastSequence('default')).toBe(3);
  expect(await adapter.getLastDigest('default')).toBe(written.default![2]!.integrity.canonicalDigest);
  expect(await adapter.getLastSequence('tenant-b')).toBe(2);
  expect(await adapter.getLastDigest('tenant-b')).toBe(written['tenant-b']![1]!.integrity.canonicalDigest);
  expect(await adapter.getLastSequence('never-written')).toBe(0);

  // And the evolved table backs a conditional append on each chain's own head.
  const next = envelope('tenant-b', 3, written['tenant-b']![1]!.integrity.canonicalDigest);
  await adapter.store(next, 'tenant-b', {
    expectChainHead: { sequence: 2, digest: written['tenant-b']![1]!.integrity.canonicalDigest },
  });
  expect(await adapter.getLastSequence('tenant-b')).toBe(3);
  expect(await adapter.getLastSequence('default')).toBe(3);
}

describe('sqlite: a legacy single-row chain_state is replaced and reseeded per chain', () => {
  let dbPath: string;

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `tzun-test-chain-state-upgrade-${randomBytes(6).toString('hex')}.db`);
  });

  afterEach(() => {
    for (const suffix of ['', '-wal', '-shm']) {
      try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
    }
  });

  it('seeds each chain from its own records and leaves the append CAS working', async () => {
    const first = new SqliteStorageAdapter(dbPath);
    const written = await seed(first);
    await first.close();

    // Put the store back the way an earlier build left it: one row, id = 1,
    // describing whichever chain was written last.
    const raw = new Database(dbPath);
    raw.exec('DROP TABLE chain_state');
    raw.exec(`
      CREATE TABLE chain_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        last_digest TEXT NOT NULL,
        last_sequence INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    raw.prepare('INSERT INTO chain_state (id, last_digest, last_sequence) VALUES (1, ?, ?)')
      .run(written['tenant-b']![1]!.integrity.canonicalDigest, 3);
    raw.close();

    const upgraded = new SqliteStorageAdapter(dbPath);
    try {
      const columns = (upgraded as unknown as { db: Database.Database }).db
        .prepare("PRAGMA table_info('chain_state')").all() as Array<{ name: string }>;
      expect(columns.map((c) => c.name)).toContain('chain_id');
      expect(columns.map((c) => c.name)).not.toContain('id');

      await expectPerChainHeads(upgraded, written);
    } finally {
      await upgraded.close();
    }
  });

  it('is a no-op on a store that already has the per-chain table', async () => {
    const first = new SqliteStorageAdapter(dbPath);
    const written = await seed(first);
    await first.close();

    const reopened = new SqliteStorageAdapter(dbPath);
    try {
      await expectPerChainHeads(reopened, written);
    } finally {
      await reopened.close();
    }
  });
});

const describePg = PG_TESTS_ENABLED ? describe : describe.skip;
describePg('postgres: a legacy single-row chain_state is replaced and reseeded per chain', () => {
  let schema: PgCaseSchema;
  // Connected into the case's schema, so its unqualified DDL lands there.
  let admin: Client;

  beforeEach(async () => {
    schema = await pgCaseSchema('chain_state_upgrade');
    admin = new Client({ connectionString: schema.url });
    await admin.connect();
  });

  afterEach(async () => {
    await admin.end();
    await schema.drop();
  });

  const adapter = (): PostgresStorageAdapter => new PostgresStorageAdapter(schema.url);

  it('seeds each chain from its own records and leaves the append CAS working', async () => {
    const first = adapter();
    await first.ensureTables();
    const written = await seed(first);
    await first.close();

    await admin.query('DROP TABLE chain_state');
    await admin.query(`
      CREATE TABLE chain_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        last_digest TEXT NOT NULL,
        last_sequence INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await admin.query('INSERT INTO chain_state (id, last_digest, last_sequence) VALUES (1, $1, $2)', [
      written['tenant-b']![1]!.integrity.canonicalDigest,
      3,
    ]);

    const upgraded = adapter();
    try {
      await upgraded.ensureTables();
      const columns = await admin.query<{ column_name: string }>(
        `SELECT column_name FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = 'chain_state'`,
        [schema.name],
      );
      const names = columns.rows.map((r) => r.column_name);
      expect(names).toContain('chain_id');
      expect(names).not.toContain('id');

      await expectPerChainHeads(upgraded, written);
    } finally {
      await upgraded.close();
    }
  });

  it('is a no-op on a store that already has the per-chain table', async () => {
    const first = adapter();
    await first.ensureTables();
    const written = await seed(first);
    await first.close();

    const reopened = adapter();
    try {
      await reopened.ensureTables();
      await expectPerChainHeads(reopened, written);
    } finally {
      await reopened.close();
    }
  });
});
