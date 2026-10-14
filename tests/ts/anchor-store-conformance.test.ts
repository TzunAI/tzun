/**
 * The anchor-store conformance kit (src/testing/anchor-store-conformance.ts)
 * run against the SDK's own stores: SQLite always, Postgres when its legs run.
 *
 * Both must pass every case, with nothing skipped: they have every hook the
 * kit asks for. That is what shows the kit asks questions the SDK's own rules
 * answer, so a store kept outside the SDK that passes it holds the same
 * rules. The last blocks show the kit fails a store that breaks one, and a
 * harness whose raw() could not have shown a guard at all.
 */
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type BetterSqlite3 from 'better-sqlite3';
import { Client } from 'pg';
import type { EvidenceEnvelope } from '@tzun/engine';
import {
  anchorStoreConformanceCases,
  runAnchorStoreConformance,
  type AnchorStore,
  type AnchorStoreConformanceHarness,
  type AnchorStoreConformanceStore,
} from '../../src/sdk/index';
import { anchorStoreFor, logStoreFor } from '../../src/storage/log-store';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

type Adapter = SqliteStorageAdapter | PostgresStorageAdapter;

function storeOver(
  adapter: Adapter,
  raw: AnchorStoreConformanceStore['raw'],
  close: () => Promise<void>,
  rawNow?: string,
): AnchorStoreConformanceStore {
  return {
    logs: logStoreFor(adapter)!,
    anchors: anchorStoreFor(adapter)!,
    raw,
    ...(rawNow !== undefined && { rawNow }),
    storeRecords: async (chainId: string, envelopes: EvidenceEnvelope[]) => {
      for (const envelope of envelopes) await adapter.store(envelope, chainId);
    },
    readRecord: (evidenceId: string) => adapter.retrieve(evidenceId),
    close,
  };
}

const sqlite: AnchorStoreConformanceHarness = {
  async open() {
    const dir = mkdtempSync(join(tmpdir(), 'tzun-test-anchor-conformance-'));
    const adapter = new SqliteStorageAdapter(join(dir, 'store.db'));
    const db = (adapter as unknown as { db: BetterSqlite3.Database }).db;
    return storeOver(
      adapter,
      async (sql, params) => db.prepare(sql).run(...params),
      async () => {
        await adapter.close();
        rmSync(dir, { recursive: true, force: true });
      },
      // SQLite's anchoring tables take only the statement's own time as an insert time.
      "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
    );
  },
};

const schema = pgSuiteSchema('anchor_conformance');
const postgres: AnchorStoreConformanceHarness = {
  async open() {
    // Every row goes, store_identity included, so each case mints a new store.
    await schema.empty();
    const adapter = new PostgresStorageAdapter(schema.url);
    await adapter.ensureTables();
    const client = new Client({ connectionString: schema.url });
    await client.connect();
    let i = 0;
    return storeOver(
      adapter,
      async (sql, params) => {
        i = 0;
        return client.query(sql.replace(/\?/g, () => `$${++i}`), params);
      },
      async () => {
        await client.end();
        await adapter.close();
      },
    );
  },
};

const harnesses: Array<[string, AnchorStoreConformanceHarness]> = PG_TESTS_ENABLED
  ? [['sqlite', sqlite], ['postgres', postgres]]
  : [['sqlite', sqlite]];

describe.each(harnesses)('the anchor-store conformance kit on %s', (_name, harness) => {
  const cases = anchorStoreConformanceCases(harness);

  it('runs every case: the SDK store has every hook the kit asks for', () => {
    expect(cases.filter((c) => c.skip !== undefined)).toEqual([]);
    expect(new Set(cases.map((c) => c.name)).size).toBe(cases.length);
    expect(cases.length).toBeGreaterThan(40);
  });

  for (const c of cases) {
    it(c.name, () => c.run(), 120_000);
  }
});

/** The cases that run through raw(): those a harness without it skips. */
const RAW_CASES = anchorStoreConformanceCases({ ...sqlite, without: { raw: 'no raw' } })
  .filter((c) => c.skip === 'no raw')
  .map((c) => c.name);
const RAW_CONTROL = RAW_CASES.find((n) => n.startsWith('raw: '))!;
const RAW_ATTACKS = RAW_CASES.filter((n) => n !== RAW_CONTROL);
/** The attacks through raw() that are INSERTs at an explicit id: an INSERT grant is all they need. */
const BACKDATED_LOG = RAW_ATTACKS.find((n) => n.startsWith('logs: none is written at an explicit log_id'))!;
const BACKDATED_PUBLICATION = RAW_ATTACKS.find((n) => n.startsWith('publications: none is written at an explicit id'))!;
/** The attack that writes an evidence leaf no stored record stands behind. */
const UNBOUND_LEAF = RAW_ATTACKS.find((n) => n.startsWith('leaves: an evidence leaf that copies no stored record'))!;
const INSERT_ATTACKS = [BACKDATED_LOG, BACKDATED_PUBLICATION];

/** Each case of `harness` that `names` picks and that fails, with its error. */
async function errors(harness: AnchorStoreConformanceHarness, names: (name: string) => boolean): Promise<Map<string, string>> {
  const failed = new Map<string, string>();
  for (const c of anchorStoreConformanceCases(harness).filter((k) => names(k.name))) {
    // The kit's AssertionError is from another realm than jest's Error: read its message, not instanceof.
    await c.run().catch((err: unknown) => failed.set(c.name, String((err as Error)?.message ?? err)));
  }
  return failed;
}

/** `harness` with its stores' raw() replaced. */
const withRaw = (
  harness: AnchorStoreConformanceHarness,
  replace: (original: NonNullable<AnchorStoreConformanceStore['raw']>, store: AnchorStoreConformanceStore) => Promise<NonNullable<AnchorStoreConformanceStore['raw']>>,
): AnchorStoreConformanceHarness => ({
  ...harness,
  async open() {
    const store = await harness.open();
    const raw = await replace(store.raw!, store);
    return { ...store, raw };
  },
});

describe('the kit fails a store that breaks a rule (sqlite)', () => {
  jest.setTimeout(120_000);

  /** The SQLite harness with one AnchorStore method replaced. */
  const mutant = <K extends keyof AnchorStore>(method: K, replace: (original: AnchorStore[K], anchors: AnchorStore) => AnchorStore[K]): AnchorStoreConformanceHarness => ({
    ...sqlite,
    async open() {
      const store = await sqlite.open();
      const original = (store.anchors[method] as unknown as (...args: unknown[]) => unknown).bind(store.anchors) as AnchorStore[K];
      const anchors = Object.create(store.anchors) as AnchorStore;
      anchors[method] = replace(original, store.anchors);
      return { ...store, anchors };
    },
  });

  async function failures(harness: AnchorStoreConformanceHarness, names: (name: string) => boolean): Promise<string[]> {
    return [...(await errors(harness, names)).keys()];
  }

  it('an epoch guard that throws a plain Error, which the scheduler would count as a failed pass', async () => {
    const harness = mutant('persistEpoch', (original) => async (write) => {
      try {
        return await original(write);
      } catch (err) {
        throw new Error(String((err as Error).message));
      }
    });
    const failed = await failures(harness, (n) => n.startsWith('epochs: the guard refuses'));
    expect(failed.sort()).toEqual(anchorStoreConformanceCases(harness).map((c) => c.name).filter((n) => n.startsWith('epochs: the guard refuses')).sort());
    expect(failed).toHaveLength(3);
  });

  it('a lease that goes to whoever asks', async () => {
    const harness = mutant('acquireAnchorLease', (original, anchors) => async (domain, holder, ttlMs) => {
      const held = await anchors.getAnchorLease(domain);
      if (held) await anchors.releaseAnchorLease(domain, held.holder);
      return original(domain, holder, ttlMs);
    });
    expect(await failures(harness, (n) => n.startsWith('lease: taken when free'))).toHaveLength(1);
  });

  it('a fill that writes over an anchor already in place', async () => {
    const harness = mutant('fillAnchorArtifacts', (original) => async (chunk) => {
      const result = await original(chunk);
      return { ...result, filled: result.filled + result.alreadyAnchored, alreadyAnchored: 0 };
    });
    expect((await failures(harness, (n) => n.startsWith('fill: '))).sort()).toEqual([
      "fill: an anchor that is null or '' is absent, and is filled; any other value, false among them, is kept",
      'fill: fill-only; a record that has an anchor keeps it',
    ]);
  });

  it('a leaf that may be rewritten: its UPDATE trigger dropped', async () => {
    const harness: AnchorStoreConformanceHarness = {
      ...sqlite,
      async open() {
        const store = await sqlite.open();
        await store.logs.getStoreIdentity();
        await store.raw!('DROP TRIGGER log_leaves_block_update', []);
        return store;
      },
    };
    expect(await failures(harness, (n) => RAW_CASES.includes(n))).toEqual(['leaves: a leaf is never updated or deleted']);
  });

  it('a log or publication that may be written at an id below the last: its backdated-id guard dropped', async () => {
    const dropped = (trigger: string): AnchorStoreConformanceHarness => ({
      ...sqlite,
      async open() {
        const store = await sqlite.open();
        await store.logs.getStoreIdentity();
        await store.raw!(`DROP TRIGGER ${trigger}`, []);
        return store;
      },
    });
    expect(await failures(dropped('logs_block_backdated_id'), (n) => RAW_CASES.includes(n))).toEqual([BACKDATED_LOG]);
    expect(await failures(dropped('anchor_publications_block_backdated_id'), (n) => RAW_CASES.includes(n))).toEqual([BACKDATED_PUBLICATION]);
  });

  it('reports every case of a sound store as passed', async () => {
    const report = await runAnchorStoreConformance({ ...sqlite, without: { raw: 'not asked here', records: 'not asked here' } });
    expect(report.failed).toEqual([]);
    expect(report.passed.length).toBeGreaterThan(25);
    expect(report.skipped.map((s) => s.reason)).toEqual(report.skipped.map(() => 'not asked here'));
    expect(report.skipped.length).toBeGreaterThan(5);
  });
});

describe('the kit fails a harness whose raw() cannot show a guard (sqlite)', () => {
  jest.setTimeout(120_000);

  it('has a raw() check and eight attacks through raw(), three of them INSERTs', () => {
    expect(RAW_CONTROL).toBeDefined();
    expect(RAW_ATTACKS).toHaveLength(8);
    expect(UNBOUND_LEAF).toBeDefined();
    expect(INSERT_ATTACKS.every((n) => n !== undefined)).toBe(true);
  });

  it('a raw() that runs nothing: every raw case fails, none passes on the rejection', async () => {
    const harness = withRaw(sqlite, async () => async () => {
      throw new Error('SQLITE_ERROR: no such table: log_leaves');
    });
    const failed = await errors(harness, (n) => RAW_CASES.includes(n));
    expect([...failed.keys()].sort()).toEqual([...RAW_CASES].sort());
    for (const message of failed.values()) expect(message).toMatch(/^raw\(\) cannot write the store's tables/);
  });

  it('a raw() that writes another database: every raw case fails', async () => {
    const harness = withRaw(sqlite, async (_original, store) => {
      const elsewhere = await sqlite.open();
      await elsewhere.logs.getStoreIdentity();
      const close = store.close;
      store.close = async () => {
        await elsewhere.close();
        await close();
      };
      return elsewhere.raw!;
    });
    const failed = await errors(harness, (n) => RAW_CASES.includes(n));
    expect([...failed.keys()].sort()).toEqual([...RAW_CASES].sort());
    for (const message of failed.values()) expect(message).toMatch(/did not reach the store/);
  });

  it('a raw() without the grant to change log_leaves, its guards intact: the leaf attack fails, not passes', async () => {
    const harness = withRaw(sqlite, async (original) => async (sql, params) => {
      if (/\blog_leaves\b/.test(sql)) throw new Error('permission denied for table log_leaves');
      return original(sql, params);
    });
    const failed = await errors(harness, (n) => RAW_CASES.includes(n));
    expect([...failed.keys()]).toEqual(['leaves: a leaf is never updated or deleted', UNBOUND_LEAF]);
    expect(failed.get('leaves: a leaf is never updated or deleted')).toMatch(/^raw\(\) cannot run an UPDATE of a leaf even on no row \(permission denied for table log_leaves\)/);
    expect(failed.get(UNBOUND_LEAF)).toMatch(/^raw\(\) cannot run a leaf naming no stored record even on no row \(permission denied for table log_leaves\)/);
  });

  it('a raw() on tables whose columns are named otherwise: the attack fails, not passes', async () => {
    const harness = withRaw(sqlite, async (original) => async (sql, params) => original(sql.replace(/\bnonce_base\b/g, 'base_nonce'), params));
    const failed = await errors(harness, (n) => RAW_CASES.includes(n));
    expect([...failed.keys()]).toEqual(['wallets: an enrolment is never changed or deleted']);
    expect(failed.get('wallets: an enrolment is never changed or deleted')).toMatch(/no such column: base_nonce/);
  });
});

(PG_TESTS_ENABLED ? describe : describe.skip)('the kit fails a raw() connected as a role without the grants (postgres)', () => {
  jest.setTimeout(120_000);
  // A role that may read and insert every table, draw from its sequences and
  // change only the lease: what an application role has on a role-separated
  // database.
  const role = `anchor_conformance_${randomBytes(5).toString('hex')}`;
  const password = randomBytes(16).toString('hex');
  const admin = async (sql: string): Promise<void> => {
    const client = new Client({ connectionString: schema.url });
    await client.connect();
    try {
      await client.query(sql);
    } finally {
      await client.end();
    }
  };

  beforeAll(() => admin(`CREATE ROLE ${role} LOGIN PASSWORD '${password}'`));
  afterAll(async () => {
    await admin(`DROP OWNED BY ${role}`);
    await admin(`DROP ROLE ${role}`);
  });

  it("every attack fails: the store's owner gate refuses this role even the lease, so raw() cannot show a guard, which the kit does not count as a refusal", async () => {
    const harness = withRaw(postgres, async (_original, store) => {
      await admin(
        `GRANT USAGE ON SCHEMA ${schema.name} TO ${role};
         GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA ${schema.name} TO ${role};
         GRANT USAGE ON ALL SEQUENCES IN SCHEMA ${schema.name} TO ${role};
         GRANT UPDATE, DELETE ON ${schema.name}.anchor_lease TO ${role}`,
      );
      const url = new URL(schema.url);
      url.username = role;
      url.password = password;
      const client = new Client({ connectionString: url.toString() });
      await client.connect();
      const close = store.close;
      store.close = async () => {
        await client.end();
        await close();
      };
      return async (sql, params) => {
        let i = 0;
        return client.query(sql.replace(/\?/g, () => `$${++i}`), params);
      };
    });
    const failed = await errors(harness, (n) => RAW_CASES.includes(n));
    // Every anchoring write needs the store's owner (D2), the lease's
    // included, so the kit's own check that raw() writes the store fails
    // first, for every case: a role that is not the owner shows no guard.
    expect([...failed.keys()].sort()).toEqual([...RAW_CASES].sort());
    for (const message of failed.values()) {
      expect(message).toMatch(/^raw\(\) cannot write the store's tables.*\[tzun:anchoring_owner_required\] anchor_lease: UPDATE/);
    }
    expect(INSERT_ATTACKS.every((n) => failed.has(n))).toBe(true);
  });
});
