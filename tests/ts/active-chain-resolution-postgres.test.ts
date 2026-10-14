// Active-chain resolution on the Postgres adapter — the twin of
// `active-chain-resolution.test.ts`, which explains both properties. This file
// exists because the chain rows, the record chain ids and the resolution are
// all SQL here (`SELECT DISTINCT chain_id FROM envelopes`, `listChains()`
// under pg's own type mapping, the append-only triggers between the test and
// the row it tampers), and none of that is exercised by the memory or SQLite
// legs.
//
// Runs when the Postgres legs do (tests/ts/helpers/postgres-test-db.ts), in a
// schema of the file's own. Each case starts from that schema EMPTY — the
// helper's `reset()` — so `ensureTables()` builds the store from nothing (which
// is also what proves the unconditional `idx_envelopes_chain_id` lands on a
// table born with the column).
//
// Envelope tampering goes through the shared helper, which uses
// `session_replication_role = 'replica'` to step around the append-only
// triggers — an edit made outside the SDK, which is what tampering is.
// Sealing every row behind the SDK's back is a plain UPDATE: active -> sealed
// is the one transition the `chains` trigger allows. Re-opening a sealed row
// is refused by that trigger, so the repair steps around it the same way, as a
// DB owner would.
import { Pool, PoolClient } from 'pg';
import { Tzun } from '../../src/sdk/index';
import { resolveChainScopes } from '../../src/storage/chain-bounds';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const schema = pgSuiteSchema('active_chain_resolution');
const describeLive = PG_TESTS_ENABLED ? describe : describe.skip;

function boot(): Promise<Tzun> {
  return Tzun.init({ mode: 'dev', dbUrl: schema.url });
}

async function capture(tzun: Tzun, tag: string, i: number): Promise<string> {
  const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { [tag]: i }, action: 'approved', reason: `${tag}-${i}` });
  expect(result.failure).toBeUndefined();
  expect(result.stored).toBe(true);
  return result.envelope.payload.evidenceId;
}

async function chainRows(pool: Pool): Promise<Array<{ chain_id: string; status: string }>> {
  const result = await pool.query('SELECT chain_id, status FROM chains ORDER BY chain_id ASC');
  return result.rows;
}

/**
 * Re-open a sealed chain row. A plain UPDATE is refused by the `chains`
 * trigger; the repair goes through the transaction-scoped
 * `session_replication_role = 'replica'` bypass, which only a DB owner has.
 */
async function reactivate(pool: Pool, chainId: string): Promise<void> {
  const plain = pool.query("UPDATE chains SET status = 'active', sealed_at = NULL WHERE chain_id = $1", [chainId]);
  await expect(plain).rejects.toThrow(/sealed/);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query("UPDATE chains SET status = 'active', sealed_at = NULL WHERE chain_id = $1", [chainId]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

async function envelopeCount(pool: Pool): Promise<number> {
  const result = await pool.query('SELECT COUNT(*)::int AS n FROM envelopes');
  return result.rows[0].n;
}

/** Three captures on the implicit default chain, a fork after 3, one capture on the new chain; closed. */
async function forkedStore(): Promise<{ sealedChainId: string; forkedChainId: string }> {
  const tzun = await boot();
  try {
    for (let i = 1; i <= 3; i++) await capture(tzun, 'old', i);
    const sealedChainId = await tzun.getActiveChainId();
    const fork = await tzun.recovery.fork('inc-active-chain-pg', {
      authorizedBy: 'admin@acme.example',
      reason: 'Signing key compromised; rotating the chain.',
      forkAfterSequence: 3,
    });
    await capture(tzun, 'new', 1);
    return { sealedChainId, forkedChainId: fork.newChain.chainId };
  } finally {
    await tzun.close();
  }
}

/**
 * Run `after` once, right after the next `SELECT … FROM chains` the adapter
 * issues and before its next statement, on whichever pool client carries it.
 * The pool's `connect()` is what gets wrapped, because both shapes of the read
 * pass through it: a bare `pool.query()` is `connect()` + `client.query()`
 * inside pg-pool (callback form), and a checked-out client is `connect()`
 * itself (promise form). So the hook fires whether the adapter reads on two
 * pool queries or on one client inside a transaction — which is the
 * difference under test.
 */
function afterNextChainsRead(adapter: PostgresStorageAdapter, after: () => Promise<void>): void {
  const pool = (adapter as unknown as { pool: Pool }).pool;
  const wrapped = new WeakSet<object>();
  let fired = false;
  const wrapClient = (client: PoolClient): void => {
    if (wrapped.has(client)) return;
    wrapped.add(client);
    const original = client.query.bind(client) as (...args: unknown[]) => unknown;
    (client as unknown as { query: unknown }).query = (...args: unknown[]): unknown => {
      const head = args[0];
      const text = typeof head === 'string' ? head : ((head as { text?: string } | undefined)?.text ?? '');
      const callback =
        typeof args[args.length - 1] === 'function' ? (args.pop() as (err: unknown, res?: unknown) => void) : undefined;
      if (fired || !/\bFROM chains\b/.test(text)) {
        return callback ? original(...args, callback) : original(...args);
      }
      fired = true;
      const result = (original(...args) as Promise<unknown>).then(async (res) => {
        await after();
        return res;
      });
      if (!callback) return result;
      result.then(
        (res) => callback(null, res),
        (err) => callback(err),
      );
      return undefined;
    };
  };
  const originalConnect = pool.connect.bind(pool) as (...args: unknown[]) => unknown;
  (pool as unknown as { connect: unknown }).connect = (cb?: unknown): unknown => {
    if (typeof cb === 'function') {
      return originalConnect((err: unknown, client?: PoolClient, release?: unknown) => {
        if (client) wrapClient(client);
        (cb as (...a: unknown[]) => void)(err, client, release);
      });
    }
    return (originalConnect() as Promise<PoolClient>).then((client) => {
      wrapClient(client);
      return client;
    });
  };
}

/** Boot expecting a refusal; returns the error, or fails naming what init came up with. */
async function bootRefused<T>(): Promise<T> {
  return boot().then(
    async (t) => {
      const id = await t.getActiveChainId();
      await t.close();
      throw new Error(`Tzun.init() came up with activeChainId "${id}" instead of refusing`);
    },
    (e: unknown) => e as T,
  );
}

describeLive('active-chain resolution on Postgres', () => {
  let pool: Pool;

  beforeAll(() => { pool = new Pool({ connectionString: schema.url }); });
  afterAll(async () => { await pool.end(); });
  beforeEach(() => schema.reset());

  it('ensureTables() indexes envelopes.chain_id on a table born with the column', async () => {
    const tzun = await boot();
    await tzun.close();
    const result = await pool.query(
      "SELECT indexname FROM pg_indexes WHERE schemaname = $1 AND tablename = 'envelopes' AND indexname = 'idx_envelopes_chain_id'",
      [schema.name],
    );
    expect(result.rows).toHaveLength(1);
  });

  it('adapter: listRecordChainIds and getActiveChainId follow the shared rule', async () => {
    const tzun = await boot();
    try {
      const storage = tzun.getStorage();
      expect(await storage.listRecordChainIds()).toEqual([]);
      expect(await storage.getActiveChainId()).toBe('default');
      for (let i = 1; i <= 3; i++) await capture(tzun, 'acme', i);
      expect(await storage.listRecordChainIds()).toEqual(['default']);
      expect(await storage.getActiveChainId()).toBe('default');

      await storage.storeChain({ chainId: 'tenant-globex', status: 'active', createdAt: new Date().toISOString() });
      await expect(storage.getActiveChainId()).rejects.toMatchObject({
        code: 'ambiguous_active_chain',
        activeChainIds: ['tenant-globex', 'default'],
        implicitChainIds: ['default'],
      });
    } finally {
      await tzun.close();
    }
  });

  it('(a) fork, close, re-open: the forked-to chain is active and the next capture lands on it', async () => {
    const { forkedChainId } = await forkedStore();
    const second = await boot();
    try {
      expect(await second.getActiveChainId()).toBe(forkedChainId);
      const id = await capture(second, 'after-restart', 1);
      expect(await second.getStorage().getChainForRecord(id)).toBe(forkedChainId);
      expect(await second.getStorage().listRecordChainIds()).toEqual([forkedChainId, 'default'].sort());
    } finally {
      await second.close();
    }
  });

  it('(a) seal every chain, re-open: Tzun.init() refuses with no_active_chain naming both rows; repair, and it boots', async () => {
    const { sealedChainId, forkedChainId } = await forkedStore();
    await pool.query("UPDATE chains SET status = 'sealed', sealed_at = $1 WHERE status = 'active'", [new Date().toISOString()]);
    expect((await chainRows(pool)).map((r) => r.status)).toEqual(['sealed', 'sealed']);

    const err = await bootRefused<{ name: string; code: string; chains: Array<{ chainId: string; status: string }> }>();
    expect(err).toMatchObject({ name: 'NoActiveChainError', code: 'no_active_chain' });
    expect(err.chains.map((c) => `${c.chainId}:${c.status}`).sort()).toEqual(
      [`${sealedChainId}:sealed`, `${forkedChainId}:sealed`].sort(),
    );
    expect(await envelopeCount(pool)).toBe(4);

    await reactivate(pool, forkedChainId);
    const repaired = await boot();
    try {
      expect(await repaired.getActiveChainId()).toBe(forkedChainId);
      const id = await capture(repaired, 'repaired', 1);
      expect(await repaired.getStorage().getChainForRecord(id)).toBe(forkedChainId);
    } finally {
      await repaired.close();
    }
    expect(await envelopeCount(pool)).toBe(5);
  });

  it('across a restart, the implicit default chain plus one active row is refused at init, not adopted', async () => {
    const first = await boot();
    try {
      for (let i = 1; i <= 3; i++) await capture(first, 'acme', i);
      await first.getStorage().storeChain({ chainId: 'tenant-globex', status: 'active', createdAt: new Date().toISOString() });
    } finally {
      await first.close();
    }
    const err = await bootRefused<{ code: string; activeChainIds: string[]; implicitChainIds: string[] }>();
    expect(err.code).toBe('ambiguous_active_chain');
    expect(err.activeChainIds.sort()).toEqual(['default', 'tenant-globex']);
    expect(err.implicitChainIds).toEqual(['default']);
    expect(await envelopeCount(pool)).toBe(3);
  });

  it('getActiveChainId() reads chains and record chain ids from ONE snapshot: a fork landing between them cannot make the answer false', async () => {
    // Two pool queries could run on two connections with no snapshot
    // between them. A fork another process commits in that gap (chains read
    // before it, records read after) would give chains=[] and
    // records=['default', <new>]: two implicit chains, `ambiguous_active_chain`
    // on a store that at no instant had more than one open chain. Reader and
    // writer are two pools here, as two processes would be.
    const reader = new PostgresStorageAdapter(schema.url);
    await reader.ensureTables();
    const writer = await boot();
    try {
      for (let i = 1; i <= 3; i++) await capture(writer, 'acme', i);
      expect(await reader.listChains()).toEqual([]);

      let forkedChainId = '';
      let interleaved = 0;
      afterNextChainsRead(reader, async () => {
        interleaved += 1;
        const fork = await writer.recovery.fork('inc-race', {
          authorizedBy: 'admin@acme.example',
          reason: 'Rotating the chain under a concurrent reader.',
          forkAfterSequence: 3,
        });
        forkedChainId = fork.newChain.chainId;
        await capture(writer, 'new', 1);
      });

      // One snapshot: not AmbiguousActiveChainError over ['default', <new>].
      expect(await reader.getActiveChainId()).toBe('default');
      expect(interleaved).toBe(1);

      // The fork really did land underneath that read; the next one sees it.
      expect(forkedChainId).not.toBe('');
      expect(await reader.getActiveChainId()).toBe(forkedChainId);
      expect(await reader.listRecordChainIds()).toEqual([forkedChainId, 'default'].sort());
    } finally {
      await writer.close();
      await reader.close();
    }
  });

  it('(b) verifyAllChains() keeps the implicit default chain in the walk and reports its tampered link', async () => {
    const tzun = await boot();
    try {
      const ids: string[] = [];
      for (let i = 1; i <= 3; i++) ids.push(await capture(tzun, 'default', i));
      const storage = tzun.getStorage();
      await storage.storeChain({ chainId: 'tenant-b', status: 'active', createdAt: new Date().toISOString() });
      await rewriteStoredEnvelope(storage, ids[2], (e) => { e.integrity.chainLink = 'TAMPERED'; });

      // The precondition — see the SQLite twin for why it is set
      // directly rather than produced by a restart.
      (tzun as unknown as { activeChainId: string }).activeChainId = 'tenant-b';

      const result = await tzun.verifyAllChains();
      expect(result.chains.map((c) => c.chainId).sort()).toEqual(['default', 'tenant-b']);
      const byId = new Map(result.chains.map((c) => [c.chainId, c]));
      expect(byId.get('tenant-b')).toMatchObject({ valid: true, totalRecords: 0 });
      expect(byId.get('default')).toMatchObject({ valid: false, totalRecords: 3 });
      expect(byId.get('default')!.brokenLinks).toContain(ids[2]);
      expect(result.valid).toBe(false);
      const walked = result.chains.reduce((n, c) => n + c.totalRecords, 0);
      expect(walked).toBe((await storage.list({})).length);
      expect(walked).toBe(3);

      const scopes = await resolveChainScopes(storage);
      expect(scopes.map((s) => s.chainId).sort()).toEqual(['default', 'tenant-b']);
    } finally {
      await tzun.close();
    }
  });

  it('(b) default + one forked chain: a tampered default-chain record is reported and named', async () => {
    const tzun = await boot();
    try {
      const ids: string[] = [];
      for (let i = 1; i <= 3; i++) ids.push(await capture(tzun, 'old', i));
      const fork = await tzun.recovery.fork('inc-active-chain-pg-b', {
        authorizedBy: 'admin@acme.example',
        reason: 'Rotating the chain.',
        forkAfterSequence: 3,
      });
      for (let i = 1; i <= 2; i++) await capture(tzun, 'new', i);
      await rewriteStoredEnvelope(tzun.getStorage(), ids[1], (e) => { e.payload.reason = 'rewritten after the seal'; });

      const result = await tzun.verifyAllChains();
      expect(result.valid).toBe(false);
      const byId = new Map(result.chains.map((c) => [c.chainId, c]));
      expect(byId.get('default')).toMatchObject({ valid: false, totalRecords: 3 });
      expect(byId.get('default')!.digestMismatches).toEqual([ids[1]]);
      expect(byId.get(fork.newChain.chainId)).toMatchObject({ valid: true, totalRecords: 2 });
      expect(result.chains.reduce((n, c) => n + c.totalRecords, 0)).toBe(5);
    } finally {
      await tzun.close();
    }
  });
});
