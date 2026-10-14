/**
 * The storage extension contract (src/storage/extensions.ts): a feature's
 * tables, its store() hooks inside the storing transaction, and the optional
 * adapter methods it provides, on the memory, SQLite and Postgres adapters.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { EvidenceEnvelope, StorageAdapter } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../../src/storage/memory';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';
import { StorageExtensionConflictError, type StorageExtension, type StoreWrite } from '../../../src/storage/extensions';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import { VerifyingStorageProxy } from '../../../src/monitoring/storage-proxy';
import { SchemaRegistry } from '@tzun/engine';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

function envelope(id: string, sequenceNumber: number, previous: string | null = null): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      evidenceId: id,
      schemaVersion: 'v1.0',
      aiSystemId: 'ext-suite',
      aiOutput: { id },
      action: 'approved',
      reason: 'extension suite',
      capturedAt: '2026-10-01T10:00:00.000Z',
      sequenceNumber,
      decider: { kind: 'human', id: 'acct:u-ext', agent: null, credential: null, freshness: null },
      contributions: null,
      links: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: hex(id), chainLink: previous },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

/** What the test extension saw, per adapter instance. */
interface Seen {
  before: string[];
  after: string[];
}

/**
 * A feature with one table, `ext_marks (evidence_id, mark)`: afterInsert
 * writes a row for every record stored with `idempotencyKey: 'mark'`;
 * beforeInsert refuses a record whose id starts with `refuse-`; afterInsert
 * refuses one whose id starts with `late-`; `getMandateTotals` (an optional
 * method chosen only because the contract lists it) reads the marks.
 */
function testExtension(seen: Seen): StorageExtension {
  const check = (write: StoreWrite, phase: 'before' | 'after'): void => {
    const id = write.envelope.payload.evidenceId;
    seen[phase].push(id);
    if (phase === 'before' && id.startsWith('refuse-')) throw new Error(`refused before insert: ${id}`);
    if (phase === 'after' && id.startsWith('late-')) throw new Error(`refused after insert: ${id}`);
  };
  const marks = new Map<string, string>();
  return {
    name: 'test-marks',
    sqlite: {
      migrate(db) {
        db.exec('CREATE TABLE IF NOT EXISTS ext_marks (evidence_id TEXT PRIMARY KEY, mark TEXT NOT NULL)');
      },
      beforeInsert(_db, write) {
        check(write, 'before');
      },
      afterInsert(db, write) {
        check(write, 'after');
        if (write.options.idempotencyKey === 'mark') {
          db.prepare('INSERT INTO ext_marks (evidence_id, mark) VALUES (?, ?)').run(write.envelope.payload.evidenceId, 'm');
        }
      },
      methods(db) {
        return {
          async getMandateTotals(evidenceId: string) {
            const row = db.prepare('SELECT mark FROM ext_marks WHERE evidence_id = ?').get(evidenceId) as { mark: string } | undefined;
            return row ? { [row.mark]: 1 } : {};
          },
        };
      },
    },
    postgres: {
      async migrate(client) {
        await client.query('CREATE TABLE IF NOT EXISTS ext_marks (evidence_id TEXT PRIMARY KEY, mark TEXT NOT NULL)');
      },
      async beforeInsert(_client, write) {
        check(write, 'before');
      },
      async afterInsert(client, write) {
        check(write, 'after');
        if (write.options.idempotencyKey === 'mark') {
          await client.query('INSERT INTO ext_marks (evidence_id, mark) VALUES ($1, $2)', [write.envelope.payload.evidenceId, 'm']);
        }
      },
      methods({ pool }) {
        return {
          async getMandateTotals(evidenceId: string) {
            const r = await pool.query<{ mark: string }>('SELECT mark FROM ext_marks WHERE evidence_id = $1', [evidenceId]);
            return r.rows[0] ? { [r.rows[0].mark]: 1 } : {};
          },
        };
      },
    },
    memory: {
      createState: () => marks,
      check(_state, write) {
        check(write, 'before');
        const id = write.envelope.payload.evidenceId;
        if (id.startsWith('late-')) throw new Error(`refused after insert: ${id}`);
      },
      apply(state: Map<string, string>, write) {
        seen.after.push(write.envelope.payload.evidenceId);
        if (write.options.idempotencyKey === 'mark') state.set(write.envelope.payload.evidenceId, 'm');
      },
      methods(state: Map<string, string>) {
        return {
          async getMandateTotals(evidenceId: string) {
            const mark = state.get(evidenceId);
            return mark ? { [mark]: 1 } : {};
          },
        };
      },
    },
  };
}

interface Leg {
  name: string;
  open(extensions: StorageExtension[]): Promise<StorageAdapter>;
}

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'tzun-test-ext-'));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

let n = 0;
const pg = pgSuiteSchema('storage_extensions');
const legs: Leg[] = [
  { name: 'memory', open: async (extensions) => new MemoryStorageAdapter({ extensions }) },
  { name: 'sqlite', open: async (extensions) => new SqliteStorageAdapter(join(dir, `ext-${++n}.db`), { extensions }) },
  ...(PG_TESTS_ENABLED
    ? [
        {
          name: 'postgres',
          open: async (extensions: StorageExtension[]) => {
            await pg.reset();
            const adapter = new PostgresStorageAdapter(pg.url, undefined, { extensions });
            await adapter.ensureTables();
            return adapter;
          },
        },
      ]
    : []),
];

describe.each(legs)('storage extensions on $name', (leg) => {
  let adapter: StorageAdapter;
  let seen: Seen;

  beforeEach(async () => {
    seen = { before: [], after: [] };
    adapter = await leg.open([decidersExtension, testExtension(seen)]);
  });
  afterEach(async () => {
    await adapter.close?.();
  });

  it('runs beforeInsert and afterInsert on every store, and installs the methods it provides', async () => {
    await adapter.store(envelope('ok-1', 1), 'default', { idempotencyKey: 'mark' });
    expect(seen.before).toEqual(['ok-1']);
    expect(seen.after).toEqual(['ok-1']);
    expect(typeof adapter.getMandateTotals).toBe('function');
    expect(await adapter.getMandateTotals!('ok-1')).toEqual({ m: 1 });
  });

  it('a refusal in beforeInsert writes nothing: no record, no leaf, no row of the extension', async () => {
    await expect(adapter.store(envelope('refuse-1', 1), 'default', { idempotencyKey: 'mark' })).rejects.toThrow(/refused before insert/);
    expect(await adapter.retrieve('refuse-1')).toBeNull();
    expect(await adapter.getLastSequence()).toBe(0);
    // The position is still free.
    await adapter.store(envelope('ok-1', 1));
    expect(await adapter.getLastSequence()).toBe(1);
  });

  it('a refusal in afterInsert rolls the record back with it', async () => {
    await expect(adapter.store(envelope('late-1', 1), 'default', { idempotencyKey: 'mark' })).rejects.toThrow(/refused after insert/);
    expect(await adapter.retrieve('late-1')).toBeNull();
    expect(await adapter.getMandateTotals!('late-1')).toEqual({});
    expect(await adapter.getLastSequence()).toBe(0);
  });

  it('a keyed replay runs no hook', async () => {
    const claim = { key: 'k-1', fingerprint: 'f' };
    await adapter.storeIdempotent!(envelope('ok-1', 1), 'default', { idempotency: claim });
    const replay = await adapter.storeIdempotent!(envelope('ok-1b', 2), 'default', { idempotency: claim });
    expect(replay.kind).toBe('replay');
    expect(seen.before).toEqual(['ok-1']);
  });

  it('the verifying proxy has the optional methods exactly when the adapter does', async () => {
    const proxy = new VerifyingStorageProxy(adapter, null, new SchemaRegistry());
    expect(typeof (proxy as StorageAdapter).getMandateTotals).toBe('function');
    expect(typeof (proxy as StorageAdapter).getDeciderOpening).toBe('function');
    expect(typeof (proxy as StorageAdapter).getDeciderCommitmentSecret).toBe('function');
    expect(typeof (proxy as StorageAdapter).getMandate).toBe('undefined');
    expect(typeof (proxy as StorageAdapter).retrieveByDigest).toBe('function');
  });
});

describe('storage extensions: the list itself', () => {
  it('two extensions providing one method are refused at construction', () => {
    const rival: StorageExtension = {
      name: 'rival',
      memory: { createState: () => null, methods: () => ({ async getDeciderOpening() { return null; } }) },
    };
    expect(() => new MemoryStorageAdapter({ extensions: [decidersExtension, rival] })).toThrow(StorageExtensionConflictError);
  });

  it('an extension listed twice is refused', () => {
    expect(() => new MemoryStorageAdapter({ extensions: [decidersExtension, decidersExtension] })).toThrow(/listed twice/);
  });

  it('an adapter with no extension has none of their methods', () => {
    const adapter = new MemoryStorageAdapter({ extensions: [] });
    expect(typeof adapter.getDeciderOpening).toBe('undefined');
    expect(typeof adapter.getDeciderCommitmentSecret).toBe('undefined');
  });
});
