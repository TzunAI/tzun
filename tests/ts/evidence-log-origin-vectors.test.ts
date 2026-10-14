/**
 * Evidence-log origins agree across implementations (Anchor §4.3.2).
 *
 * `vectors/evidence-log-origin-vectors.json` pins the origin of each chain id,
 * the chain ids a store refuses, and the namespaces a store accepts and
 * refuses. This file runs it through the TypeScript functions and the three
 * adapters (memory, SQLite, and Postgres when its legs run), through SQLite's
 * and Postgres's SQL (`lower(hex(...))`, `encode(convert_to(..., 'UTF8'),
 * 'hex')`, the trigger on `envelopes`, the `store_identity.ns` CHECK).
 * `tests/cross-sdk/test_evidence_log_origin_parity.py` runs it through Python.
 *
 * The SQL legs cannot choose a store id — the store mints its own — so they
 * check the origin the trigger wrote against the vector's chain segment under
 * the store's own identity.
 *
 * A refused chain id on Postgres: the adapter refuses it before any query.
 * Raw SQL cannot carry one to the trigger: Postgres refuses U+0000 in text
 * itself, and node-pg sends U+FFFD in place of a lone surrogate, which is a
 * well-formed chain id.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from 'pg';
import type { EvidenceEnvelope } from '@tzun/engine';
import {
  EvidenceLogRefusalError,
  InvalidLogNamespaceError,
  assertLogNamespace,
  chainIdRefusal,
  chainSegment,
  domainPrefix,
  evidenceLogOrigin,
  logStoreFor,
  storeLogOrigin,
} from '../../src/storage/log-store';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { refusal } from './helpers/log-store-backends';

interface OriginVector {
  name: string;
  chainId: string;
  chainSegment: string;
  origin: string;
}

interface Named<T> {
  name: string;
  ns: T;
}

const DOC = JSON.parse(
  readFileSync(join(__dirname, '..', '..', 'vectors', 'evidence-log-origin-vectors.json'), 'utf8'),
) as {
  ns: string;
  storeId: string;
  vectors: OriginVector[];
  storeLogs: Array<{ kind: string; origin: string }>;
  invalidChainIds: Array<{ name: string; chainId: string; reason: 'empty_chain_id' | 'invalid_chain_id' }>;
  namespaces: { valid: Array<Named<string>>; invalid: Array<Named<string>> };
};

/** The name of the error `work` throws, or `'accepted'`. */
function refusedWith(work: () => unknown): string {
  try {
    work();
    return 'accepted';
  } catch (err) {
    return (err as Error).name;
  }
}

/** A store_identity row with `ns`, as raw SQL writes it, bypassing the adapter's own check. */
const IDENTITY_INSERT = 'INSERT INTO store_identity (singleton, store_id, ns, created_at) VALUES (1, ?, ?, ?)';

function envelopeOn(evidenceId: string, sequenceNumber: number): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'origin-vectors',
      aiOutput: { ok: true },
      action: 'approved',
      reason: 'origin vector',
      capturedAt: '2026-09-25T10:00:00.000Z',
      sequenceNumber,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: createHash('sha256').update(evidenceId).digest('hex'), chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

describe('evidence-log origin vectors: TypeScript', () => {
  it.each(DOC.vectors.map((v) => [v.name, v] as const))('%s', (_name, vector) => {
    expect(chainSegment(vector.chainId)).toBe(vector.chainSegment);
    expect(evidenceLogOrigin(DOC.ns, DOC.storeId, vector.chainId)).toBe(vector.origin);
  });

  it('per-store logs', () => {
    for (const entry of DOC.storeLogs) expect(storeLogOrigin(DOC.ns, DOC.storeId, entry.kind)).toBe(entry.origin);
  });

  it.each(DOC.invalidChainIds.map((v) => [v.name, v] as const))('refuses the chain id: %s', (_name, vector) => {
    expect(chainIdRefusal(vector.chainId)).toBe(vector.reason);
    expect(() => chainSegment(vector.chainId)).toThrow(TypeError);
    expect(() => evidenceLogOrigin(DOC.ns, DOC.storeId, vector.chainId)).toThrow(TypeError);
  });

  it('accepts every valid namespace and refuses every invalid one', () => {
    for (const { name, ns } of DOC.namespaces.valid) expect([name, assertLogNamespace(ns)]).toEqual([name, ns]);
    for (const { name, ns } of DOC.namespaces.invalid) {
      expect([name, refusedWith(() => assertLogNamespace(ns))]).toEqual([name, 'InvalidLogNamespaceError']);
      expect(() => domainPrefix(ns, DOC.storeId)).toThrow(InvalidLogNamespaceError);
    }
  });

  it('refuses a store id or kind the rules refuse, as the Python twin does', () => {
    expect(() => domainPrefix('local.invalid', 'NOT-HEX')).toThrow(TypeError);
    expect(() => storeLogOrigin(DOC.ns, DOC.storeId, 'evidence')).toThrow(TypeError);
    expect(chainIdRefusal(42)).toBe('invalid_chain_id');
  });
});

describe('evidence-log origin vectors: the memory adapter', () => {
  it.each(DOC.invalidChainIds.map((v) => [v.name, v] as const))('store() and storeIdempotent() refuse the chain id: %s', async (_name, vector) => {
    const adapter = new MemoryStorageAdapter();
    const attempt = adapter.store(envelopeOn('mem-bad', 1), vector.chainId);
    await expect(attempt).rejects.toBeInstanceOf(EvidenceLogRefusalError);
    await expect(attempt).rejects.toMatchObject({ reason: vector.reason, retryable: false });
    await expect(
      adapter.storeIdempotent(envelopeOn('mem-bad', 1), vector.chainId, { idempotency: { key: 'k', fingerprint: 'f' } }),
    ).rejects.toMatchObject({ reason: vector.reason });
    expect(await adapter.retrieve('mem-bad')).toBeNull();
    expect(await adapter.logStore().listLogs()).toEqual([]);
  });
});

describe('evidence-log origin vectors: SQLite', () => {
  let dir: string;
  let adapter: SqliteStorageAdapter;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-origin-vectors-'));
    adapter = new SqliteStorageAdapter(join(dir, 'origins.db'));
  });

  afterAll(async () => {
    await adapter.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it("SQLite's lower(hex(chain_id)) is the vector's chain segment", () => {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    for (const vector of DOC.vectors) {
      const row = db.prepare('SELECT lower(hex(?)) AS segment').get(vector.chainId) as { segment: string };
      expect(row.segment).toBe(vector.chainSegment);
    }
  });

  it('the trigger names each chain\'s log with the vector\'s origin, under the store\'s identity', async () => {
    const logs = logStoreFor(adapter)!;
    const { ns, storeId } = await logs.getStoreIdentity();
    for (const [i, vector] of DOC.vectors.entries()) {
      await adapter.store(envelopeOn(`sq-${i}`, 1), vector.chainId);
      const log = await logs.getEvidenceLog(vector.chainId);
      expect(log?.origin).toBe(`${ns}/${storeId}/evidence/${vector.chainSegment}`);
      expect(log?.origin).toBe(evidenceLogOrigin(ns, storeId, vector.chainId));
    }
  });

  it('the adapter and the trigger refuse every refused chain id, and write nothing', async () => {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    const logsBefore = (await logStoreFor(adapter)!.listLogs()).length;
    for (const [i, vector] of DOC.invalidChainIds.entries()) {
      const env = envelopeOn(`sq-bad-${i}`, 1);
      await expect(adapter.store(env, vector.chainId)).rejects.toMatchObject({ reason: vector.reason });
      await expect(
        adapter.storeIdempotent(env, vector.chainId, { idempotency: { key: `k-${i}`, fingerprint: 'f' } }),
      ).rejects.toMatchObject({ reason: vector.reason });
      // A writer that is not the SDK reaches the trigger, which refuses the same chain ids.
      await refusal(
        async () =>
          db
            .prepare(
              'INSERT INTO envelopes (evidence_id, envelope, captured_at, captured_at_ms, ai_system_id, digest, chain_id) VALUES (?, ?, ?, 0, ?, ?, ?)',
            )
            .run(env.payload.evidenceId, JSON.stringify(env), env.payload.capturedAt, env.payload.aiSystemId, env.integrity.canonicalDigest, vector.chainId),
        new RegExp(`\\[tzun:${vector.reason}\\]`),
      );
      expect(await adapter.retrieve(env.payload.evidenceId)).toBeNull();
    }
    expect((await logStoreFor(adapter)!.listLogs()).length).toBe(logsBefore);
  });
});

describe('evidence-log origin vectors: the SQLite store_identity.ns CHECK', () => {
  it('accepts every valid namespace and refuses every invalid one', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tzun-test-ns-check-'));
    const adapter = new SqliteStorageAdapter(join(dir, 'ns.db'));
    try {
      const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
      // Step around the immutability guard, as only the file's owner can.
      db.exec('DROP TRIGGER store_identity_block_delete');
      const at = '2026-09-25T10:00:00Z';
      for (const { name, ns } of DOC.namespaces.valid) {
        db.exec('DELETE FROM store_identity');
        expect([name, db.prepare(IDENTITY_INSERT).run(DOC.storeId, ns, at).changes]).toEqual([name, 1]);
      }
      for (const { name, ns } of DOC.namespaces.invalid) {
        db.exec('DELETE FROM store_identity');
        expect([name, await refusal(async () => db.prepare(IDENTITY_INSERT).run(DOC.storeId, ns, at))]).toEqual([
          name,
          expect.stringMatching(/CHECK constraint failed/),
        ]);
      }
    } finally {
      await adapter.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

const pgSchema = pgSuiteSchema('origin_vectors');

(PG_TESTS_ENABLED ? describe : describe.skip)('evidence-log origin vectors: Postgres', () => {
  let adapter: PostgresStorageAdapter;
  let client: Client;

  beforeAll(async () => {
    adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    client = new Client({ connectionString: pgSchema.url });
    await client.connect();
  });

  afterAll(async () => {
    await client?.end();
    await adapter?.close();
  });

  it("Postgres's encode(convert_to(chain_id, 'UTF8'), 'hex') is the vector's chain segment", async () => {
    for (const vector of DOC.vectors) {
      const { rows } = await client.query("SELECT encode(convert_to($1::text, 'UTF8'), 'hex') AS segment", [vector.chainId]);
      expect(rows[0].segment).toBe(vector.chainSegment);
    }
  });

  it('the trigger names each chain\'s log with the vector\'s origin, under the store\'s identity', async () => {
    const logs = logStoreFor(adapter)!;
    const { ns, storeId } = await logs.getStoreIdentity();
    for (const [i, vector] of DOC.vectors.entries()) {
      await adapter.store(envelopeOn(`pg-${i}`, 1), vector.chainId);
      const log = await logs.getEvidenceLog(vector.chainId);
      expect(log?.origin).toBe(`${ns}/${storeId}/evidence/${vector.chainSegment}`);
      expect(log?.origin).toBe(evidenceLogOrigin(ns, storeId, vector.chainId));
    }
  });

  it('the adapter refuses every refused chain id before any query, and the trigger refuses an empty one', async () => {
    const logsBefore = (await logStoreFor(adapter)!.listLogs()).length;
    for (const [i, vector] of DOC.invalidChainIds.entries()) {
      const env = envelopeOn(`pg-bad-${i}`, 1);
      await expect(adapter.store(env, vector.chainId)).rejects.toMatchObject({ reason: vector.reason });
      await expect(
        adapter.storeIdempotent(env, vector.chainId, { idempotency: { key: `k-${i}`, fingerprint: 'f' } }),
      ).rejects.toMatchObject({ reason: vector.reason });
      expect(await adapter.retrieve(env.payload.evidenceId)).toBeNull();
    }
    const env = envelopeOn('pg-raw-empty', 1);
    await refusal(
      client.query(
        'INSERT INTO envelopes (evidence_id, envelope, captured_at, ai_system_id, digest, chain_id) VALUES ($1, $2::jsonb, $3, $4, $5, $6)',
        [env.payload.evidenceId, JSON.stringify(env), env.payload.capturedAt, env.payload.aiSystemId, env.integrity.canonicalDigest, ''],
      ),
      /\[tzun:empty_chain_id\]/,
    );
    expect((await logStoreFor(adapter)!.listLogs()).length).toBe(logsBefore);
  });

  it('the store_identity.ns CHECK accepts every valid namespace and refuses every invalid one', async () => {
    const insert = 'INSERT INTO store_identity (singleton, store_id, ns) VALUES (1, $1, $2)';
    const step = async (work: () => Promise<unknown>): Promise<void> => {
      await client.query('BEGIN');
      try {
        // Triggers off, as only a table owner can; the CHECK still applies.
        await client.query("SET LOCAL session_replication_role = 'replica'");
        await client.query('DELETE FROM store_identity');
        await work();
      } finally {
        await client.query('ROLLBACK');
      }
    };
    for (const { name, ns } of DOC.namespaces.valid) {
      await step(async () => expect([name, (await client.query(insert, [DOC.storeId, ns])).rowCount]).toEqual([name, 1]));
    }
    for (const { name, ns } of DOC.namespaces.invalid) {
      await step(async () =>
        expect([name, await refusal(client.query(insert, [DOC.storeId, ns]))]).toEqual([
          name,
          expect.stringMatching(/check constraint/),
        ]),
      );
    }
  });
});
