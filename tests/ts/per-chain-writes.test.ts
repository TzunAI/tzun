/**
 * Writes are chain-scoped end to end.
 *
 * If the chain head, the append compare-and-swap or the Postgres append lock
 * were store-wide, a second chain's first record would take the first chain's
 * next sequence number and link from its head: born unverifiable, and with
 * monitoring on it would raise a `sequence_gap` incident on a store nobody had
 * touched. The Python SDK takes a `chain_id` and the platform keys heads per
 * `(chain_id, account_id, env)`; this file holds the TypeScript SDK to the
 * same.
 *
 * `Tzun.init({ chainId })` names the chain, every head is per chain, and two
 * instances on ONE store writing to TWO chains interleave correctly — the
 * TypeScript mirror of the same run against the Python SDK:
 *
 *   round 1: acme seq=1 link=None   globex seq=1 link=None
 *   round 2: acme seq=2 link=…      globex seq=2 link=…
 *   round 3: acme seq=3 link=…      globex seq=3 link=…
 *   both chains verify clean
 *
 * Legs: sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own,
 * emptied before each case. A memory adapter is per-instance, so two
 * instances cannot share one.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AmbiguousActiveChainError } from '@tzun/engine';
import type { CaptureInput, TzunConfig } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

// A schema of this file's own, emptied before each Postgres case.
const pgSchema = pgSuiteSchema('per_chain_writes');

interface Leg {
  name: 'sqlite' | 'postgres';
  config: () => Promise<{ config: TzunConfig; teardown: () => Promise<void> }>;
}

const legs: Leg[] = [
  {
    name: 'sqlite',
    config: async () => {
      const dbPath = path.join(
        os.tmpdir(),
        `tzun-test-per-chain-${process.pid}-${Math.random().toString(36).slice(2)}.db`,
      );
      return {
        config: { dbPath },
        teardown: async () => {
          for (const suffix of ['', '-wal', '-shm']) {
            try {
              fs.unlinkSync(dbPath + suffix);
            } catch {
              /* ignore */
            }
          }
        },
      };
    },
  },
];
if (PG_TESTS_ENABLED) {
  legs.push({
    name: 'postgres',
    config: async () => {
      await pgSchema.empty();
      return { config: { dbUrl: pgSchema.url }, teardown: async () => undefined };
    },
  });
}

const decision = (tenant: string, i: number): CaptureInput => ({
  aiSystemId: `underwriter-${tenant}`,
  aiOutput: { round: i },
  action: 'approved',
  reason: `${tenant} round ${i}`,
  decider: { kind: 'human', id: `acct:reviewer-${tenant}`, agent: null, credential: null, freshness: null },
});

describe.each(legs)('per-chain writes on one store — $name', (leg) => {
  let storageConfig: TzunConfig;
  let teardown: () => Promise<void>;
  let open: Tzun[] = [];

  beforeEach(async () => {
    const made = await leg.config();
    storageConfig = made.config;
    teardown = made.teardown;
  });

  afterEach(async () => {
    for (const t of open) await t.close();
    open = [];
    await teardown?.();
  });

  async function instance(extra: TzunConfig = {}): Promise<Tzun> {
    const tzun = await Tzun.init({ ...storageConfig, ...extra });
    open.push(tzun);
    return tzun;
  }

  it('two instances, two chains, one store: both number from 1 and both verify clean', async () => {
    const acme = await instance({ chainId: 'tenant-acme' });
    const globex = await instance({ chainId: 'tenant-globex' });

    const rounds: Array<{ a: number; g: number }> = [];
    for (let i = 1; i <= 3; i++) {
      const a = await acme.capture(decision('acme', i));
      const g = await globex.capture(decision('globex', i));
      expect(a.stored).toBe(true);
      expect(g.stored).toBe(true);
      rounds.push({ a: a.envelope.payload.sequenceNumber, g: g.envelope.payload.sequenceNumber });

      // Each chain links from its OWN predecessor. Round 1 is genesis on both.
      for (const link of [a.envelope.integrity.chainLink, g.envelope.integrity.chainLink]) {
        if (i === 1) expect(link).toBeNull();
        else expect(link).toMatch(/^[0-9a-f]{64}$/);
      }
    }

    expect(rounds).toEqual([{ a: 1, g: 1 }, { a: 2, g: 2 }, { a: 3, g: 3 }]);

    const storage = acme.getStorage();
    expect(await storage.getChainLength('tenant-acme')).toBe(3);
    expect(await storage.getChainLength('tenant-globex')).toBe(3);
    expect(await storage.getChainLength()).toBe(6);

    // Heads are per chain and name that chain's own last record.
    expect(await storage.getLastSequence('tenant-acme')).toBe(3);
    expect(await storage.getLastSequence('tenant-globex')).toBe(3);
    expect(await storage.getLastDigest('tenant-acme')).not.toBe(
      await storage.getLastDigest('tenant-globex'),
    );

    // Both chains walk clean, which a store-wide head could not give: the
    // second chain's first record would carry the first chain's sequence
    // number and chain link.
    for (const chainId of ['tenant-acme', 'tenant-globex']) {
      const walk = await acme.verifyChainCompleteness(chainId);
      expect(walk).toMatchObject({ valid: true, totalRecords: 3, chainId });
      expect(walk.sequenceGaps).toEqual([]);
      expect(walk.brokenLinks).toEqual([]);
    }
    const all = await acme.verifyAllChains();
    expect(all.valid).toBe(true);
    expect(all.chains.reduce((n, c) => n + c.totalRecords, 0)).toBe(6);
  });

  it('the two chains interleave in any order, not just in lockstep', async () => {
    const a = await instance({ chainId: 'chain-a' });
    const b = await instance({ chainId: 'chain-b' });

    // a, a, b, a, b, b — with a shared head, the loser would be refused (or
    // silently renumbered) at every switch.
    await a.capture(decision('a', 1));
    await a.capture(decision('a', 2));
    await b.capture(decision('b', 1));
    const a3 = await a.capture(decision('a', 3));
    const b2 = await b.capture(decision('b', 2));
    const b3 = await b.capture(decision('b', 3));

    expect([a3, b2, b3].every((r) => r.stored)).toBe(true);
    expect(a3.envelope.payload.sequenceNumber).toBe(3);
    expect(b3.envelope.payload.sequenceNumber).toBe(3);
    expect((await a.verifyChainCompleteness('chain-a')).valid).toBe(true);
    expect((await a.verifyChainCompleteness('chain-b')).valid).toBe(true);
  });

  it('concurrent captures on two chains all land, and each chain stays intact', async () => {
    const a = await instance({ chainId: 'race-a' });
    const b = await instance({ chainId: 'race-b' });

    const results = await Promise.all([
      ...[1, 2, 3, 4].map((i) => a.capture(decision('a', i))),
      ...[1, 2, 3, 4].map((i) => b.capture(decision('b', i))),
    ]);
    expect(results.filter((r) => r.stored)).toHaveLength(8);

    const storage = a.getStorage();
    expect(await storage.getChainLength('race-a')).toBe(4);
    expect(await storage.getChainLength('race-b')).toBe(4);
    for (const chainId of ['race-a', 'race-b']) {
      expect(await storage.getLastSequence(chainId)).toBe(4);
      expect((await a.verifyChainCompleteness(chainId)).valid).toBe(true);
    }
  });

  it('a restart resumes the named chain, not whichever chain the store calls active', async () => {
    const first = await instance({ chainId: 'tenant-acme' });
    await first.capture(decision('acme', 1));
    await first.capture(decision('acme', 2));
    const other = await instance({ chainId: 'tenant-globex' });
    await other.capture(decision('globex', 1));
    await first.close();
    await other.close();
    open = [];

    const resumed = await instance({ chainId: 'tenant-acme' });
    const next = await resumed.capture(decision('acme', 3));
    expect(next.stored).toBe(true);
    expect(next.envelope.payload.sequenceNumber).toBe(3);
    expect(await resumed.getActiveChainId()).toBe('tenant-acme');
    expect((await resumed.verifyChainCompleteness('tenant-acme')).valid).toBe(true);
  });

  it('naming a chain is the answer to an ambiguous store, which still refuses without one', async () => {
    const seed = await instance({ chainId: 'tenant-acme' });
    await seed.capture(decision('acme', 1));
    const storage = seed.getStorage();
    await storage.storeChain({
      chainId: 'tenant-globex',
      status: 'active',
      createdAt: new Date().toISOString(),
    });
    await seed.close();
    open = [];

    // Two chains accept appends and nothing says which: refuse rather than
    // guess.
    await expect(Tzun.init({ ...storageConfig })).rejects.toThrow(AmbiguousActiveChainError);
    await expect(Tzun.init({ ...storageConfig })).rejects.toThrow(/Tzun\.init\(\{ chainId \}\)/);

    // Naming one resolves nothing and refuses nothing: the caller chose.
    const named = await instance({ chainId: 'tenant-globex' });
    const stored = await named.capture(decision('globex', 1));
    expect(stored.stored).toBe(true);
    expect(stored.envelope.payload.sequenceNumber).toBe(1);
  });

  it('a chain the store records as sealed is refused at init, not on the first capture', async () => {
    const seed = await instance();
    await seed.capture(decision('acme', 1));
    await seed.getStorage().storeChain({
      chainId: 'retired',
      status: 'sealed',
      createdAt: new Date().toISOString(),
      sealedAt: new Date().toISOString(),
    });
    await seed.close();
    open = [];

    await expect(Tzun.init({ ...storageConfig, chainId: 'retired' })).rejects.toMatchObject({
      code: 'chain_sealed',
      chainId: 'retired',
    });
  });

  it('a chain with no identity row is accepted, as store() accepts it', async () => {
    // Chain identities are created lazily; a caller naming a fresh per-tenant
    // chain is naming one that does not exist yet.
    const fresh = await instance({ chainId: 'tenant-brand-new' });
    const stored = await fresh.capture(decision('new', 1));
    expect(stored.stored).toBe(true);
    expect(stored.envelope.payload.sequenceNumber).toBe(1);
    expect(stored.envelope.integrity.chainLink).toBeNull();
    expect(await fresh.getStorage().getChainForRecord(stored.envelope.payload.evidenceId)).toBe(
      'tenant-brand-new',
    );
  });

  it('no chainId still resolves the chain from the store', async () => {
    const tzun = await instance();
    expect(await tzun.getActiveChainId()).toBe('default');
    const stored = await tzun.capture(decision('default', 1));
    expect(stored.stored).toBe(true);
    expect(await tzun.getStorage().getLastSequence('default')).toBe(1);
  });

  it('an idempotency key is fingerprinted with the chain, so one key cannot span two chains', async () => {
    const a = await instance({ chainId: 'key-a' });
    const b = await instance({ chainId: 'key-b' });
    const input = decision('shared', 1);

    const first = await a.capture(input, { idempotencyKey: 'order-retry' });
    expect(first.stored).toBe(true);

    // Same key, same decision, DIFFERENT chain. A key names one record in the
    // store, and that record is on the other chain, so this is a conflict
    // rather than a replay that would hand back a record from another tenant's
    // chain.
    const crossChain = await b.capture(input, { idempotencyKey: 'order-retry' });
    expect(crossChain.stored).toBe(false);
    expect(crossChain.failure?.failureType).toBe('idempotency_conflict');
    expect(await a.getStorage().getChainLength('key-b')).toBe(0);

    // On its own chain it still replays.
    const replay = await a.capture(input, { idempotencyKey: 'order-retry' });
    expect(replay.replayed).toBe(true);
    expect(replay.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
  });
});

/**
 * The cloud path: `HttpStorageAdapter.store()` puts the chainId named at init
 * on the wire, and the platform keys heads per `(chain_id, account_id, env)`.
 * With no chain named, the body carries no chainId and the server applies its
 * own default.
 */
describe('a configured chain reaches the wire on the cloud transport', () => {
  const API_KEY = 'sk_test_per_chain_writes';

  const input: CaptureInput = {
    aiSystemId: 'underwriter-v2',
    aiOutput: { recommendation: 'approve' },
    action: 'approved',
    reason: 'meets policy',
    decider: { kind: 'human' as const, id: 'acct:reviewer-bank.example', agent: null, credential: null, freshness: null },
  };

  /** Records each POST body and answers with the platform's success shape. */
  function recordingFetch(): { fetchFn: typeof fetch; bodies: Array<Record<string, unknown>> } {
    const bodies: Array<Record<string, unknown>> = [];
    const fetchFn = (async (_url: string, init: { body?: string }) => {
      const body = JSON.parse(String(init.body)) as {
        chainId?: string;
        envelope: { payload: { evidenceId: string; sequenceNumber: number }; integrity: { canonicalDigest: string } };
      };
      bodies.push(body as unknown as Record<string, unknown>);
      return {
        ok: true,
        status: 202,
        headers: new Headers(),
        async json() {
          return {
            ok: true,
            state: 'captured',
            evidenceId: body.envelope.payload.evidenceId,
            chainId: body.chainId ?? 'default',
            sequence: body.envelope.payload.sequenceNumber,
            canonicalDigest: body.envelope.integrity.canonicalDigest,
            headDigest: body.envelope.integrity.canonicalDigest,
          };
        },
      } as unknown as Response;
    }) as unknown as typeof fetch;
    return { fetchFn, bodies };
  }

  async function cloudTzun(fetchFn: typeof fetch, chainId?: string): Promise<Tzun> {
    return Tzun.init({
      mode: 'dev',
      apiKey: API_KEY,
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: fetchFn,
      ...(chainId !== undefined ? { chainId } : {}),
    } as Parameters<typeof Tzun.init>[0]);
  }

  it('sends the configured chainId, and the receipt names it', async () => {
    const { fetchFn, bodies } = recordingFetch();
    const tzun = await cloudTzun(fetchFn, 'tenant-acme');
    try {
      expect(await tzun.getActiveChainId()).toBe('tenant-acme');
      const result = await tzun.capture(input);
      expect(result.stored).toBe(true);
      expect(result.serverReceipt?.chainId).toBe('tenant-acme');
    } finally {
      await tzun.close();
    }
    expect(bodies).toHaveLength(1);
    expect(bodies[0]!.chainId).toBe('tenant-acme');
  });

  it('sends no chainId when none is configured, so the server applies its own default', async () => {
    const { fetchFn, bodies } = recordingFetch();
    const tzun = await cloudTzun(fetchFn);
    try {
      expect(await tzun.getActiveChainId()).toBe('default');
      await tzun.capture(input);
    } finally {
      await tzun.close();
    }
    expect(Object.keys(bodies[0]!)).not.toContain('chainId');
  });
});
