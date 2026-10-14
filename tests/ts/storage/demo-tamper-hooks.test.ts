// tests/ts/storage/demo-tamper-hooks.test.ts — the demo-tamper hooks and their arming guard.
import { Tzun } from '../../../src/sdk/index';
import { MemoryStorageAdapter } from '../../../src/storage/memory';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { assertArmed, classifyDemoTamperTarget, DemoTamperGuardError } from '../../../src/storage/demo-tamper-guard';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const sqlitePath = () => join(mkdtempSync(join(tmpdir(), 'tzun-test-hooks-')), 'demo.db');

describe('demo-tamper hooks guard matrix', () => {
  afterEach(() => { delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP; });

  it('no flag → every hook call throws DemoTamperGuardError', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();
    await expect(storage.deleteEnvelopeForDemo!('x')).rejects.toThrow(DemoTamperGuardError);
    await expect(storage.overwriteModelDescriptorBytesForDemo!('d', '{}')).rejects.toThrow(DemoTamperGuardError);
  });

  it('flag + empty throwaway store → arms; sentinel written; hooks work (memory + in-memory sqlite)', async () => {
    for (const config of [
      { demoTamperHooks: true },
      { demoTamperHooks: true, dbPath: ':memory:' },
    ] as const) {
      const tzun = await Tzun.init(config as never);
      const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'a', reason: 'r' });
      await tzun.getStorage().deleteEnvelopeForDemo!(r.envelope.payload.evidenceId);
      expect(await tzun.getStorage().retrieve(r.envelope.payload.evidenceId)).toBeNull();
    }
  });

  // A file-backed SQLite store is local to every deployment, demo or
  // production, so an empty one proves nothing about whose store it is — the
  // same day-one hole the loopback-target check closes for Postgres. It arms
  // only through the bootstrap valve, and after that the sentinel keeps it armed.
  it('flag + empty FILE-backed sqlite store → refuses, writes no sentinel, and stays refused on the next start', async () => {
    const dbPath = sqlitePath();
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      for (let start = 0; start < 2; start++) {
        const tzun = await Tzun.init({ demoTamperHooks: true, dbPath } as never);
        await expect(tzun.getStorage().deleteEnvelopeForDemo!('x')).rejects.toThrow(DemoTamperGuardError);
        await tzun.close();
      }
      const refusals = errSpy.mock.calls.map((c) => String(c[0])).filter((l) => l.includes('demo_tamper_guard_refused'));
      expect(refusals).toHaveLength(2);
      for (const line of refusals) {
        expect(JSON.parse(line)).toMatchObject({ reason: 'empty-store-not-loopback', backend: 'sqlite' });
      }
    } finally {
      errSpy.mockRestore();
    }
  });

  it('flag + empty FILE-backed sqlite store + TZUN_DEMO_TAMPER_BOOTSTRAP → arms, and the sentinel keeps it armed', async () => {
    const dbPath = sqlitePath();
    process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
    const first = await Tzun.init({ demoTamperHooks: true, dbPath } as never);
    expect(process.env.TZUN_DEMO_TAMPER_BOOTSTRAP).toBeUndefined(); // the valve is spent
    const r1 = await first.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'a', reason: 'r' });
    await first.getStorage().deleteEnvelopeForDemo!(r1.envelope.payload.evidenceId);
    await first.close();

    const second = await Tzun.init({ demoTamperHooks: true, dbPath } as never); // no valve: the sentinel arms it
    const r2 = await second.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 2 }, action: 'a', reason: 'r' });
    await second.getStorage().deleteEnvelopeForDemo!(r2.envelope.payload.evidenceId);
    expect(await second.getStorage().retrieve(r2.envelope.payload.evidenceId)).toBeNull();
    await second.close();
  });

  it('flag + non-empty unsentineled store → refuses for process lifetime + structured error', async () => {
    const dbPath = sqlitePath();
    const seed = await Tzun.init({ dbPath } as never); // no flag — no sentinel
    await seed.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'a', reason: 'r' });
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const t2 = await Tzun.init({ demoTamperHooks: true, dbPath } as never);
    await expect(t2.getStorage().deleteEnvelopeForDemo!('x')).rejects.toThrow(DemoTamperGuardError);
    const line = errSpy.mock.calls.map((c) => JSON.stringify(c[0])).find((l) =>
      l.includes('demo_tamper_guard_refused'));
    expect(line).toContain('unsentineled-non-empty-store');
    errSpy.mockRestore();
  });

  it('TZUN_DEMO_TAMPER_BOOTSTRAP=true arms a non-empty store once (migration valve)', async () => {
    const dbPath = sqlitePath();
    const seed = await Tzun.init({ dbPath } as never);
    await seed.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'a', reason: 'r' });
    process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
    const t2 = await Tzun.init({ demoTamperHooks: true, dbPath } as never);
    const head = await t2.getStorage().head!();
    await t2.getStorage().deleteEnvelopeForDemo!(head!.payload.evidenceId); // armed
    delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
    const t3 = await Tzun.init({ demoTamperHooks: true, dbPath } as never);
    const r3 = await t3.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 2 }, action: 'a', reason: 'r' });
    await t3.getStorage().deleteEnvelopeForDemo!(r3.envelope.payload.evidenceId); // sentinel persists
  });
});

describe('descriptor overwrite + restore', () => {
  it('overwrites canonicalBytes WITHOUT recomputing the digest; returns previous bytes', async () => {
    const tzun = await Tzun.init({ demoTamperHooks: true } as never);
    const { digest } = await tzun.models.register({ vendor: 'v', modelName: 'm', modelVersion: '1' });
    const row = await tzun.getStorage().getModelDescriptor!(digest);
    const mutated = row!.canonicalBytes.replace('"m"', '"m (retroactively edited)"');
    const previous = await tzun.getStorage().overwriteModelDescriptorBytesForDemo!(digest, mutated);
    expect(previous).toBe(row!.canonicalBytes);
    const after = await tzun.getStorage().getModelDescriptor!(digest);
    expect(after!.canonicalBytes).toBe(mutated); // digest key unchanged — mismatch is detectable
    await tzun.getStorage().overwriteModelDescriptorBytesForDemo!(digest, previous); // restore path
    expect((await tzun.getStorage().getModelDescriptor!(digest))!.canonicalBytes).toBe(row!.canonicalBytes);
  });
});

describe('proxy forwarding', () => {
  it('VerifyingStorageProxy forwards both hooks when the inner adapter has them', async () => {
    const tzun = await Tzun.init({ demoTamperHooks: true, monitoring: { enabled: true, proxy: true } } as never);
    const storage = tzun.getStorage(); // the proxy
    expect(typeof storage.deleteEnvelopeForDemo).toBe('function');
    expect(typeof storage.overwriteModelDescriptorBytesForDemo).toBe('function');
    const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'a', reason: 'r' });
    await storage.deleteEnvelopeForDemo!(r.envelope.payload.evidenceId);
    expect(await storage.retrieve(r.envelope.payload.evidenceId)).toBeNull();
  });
});

// Postgres parity. Runs when the Postgres legs do
// (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own: an
// empty store, which the guard arms without the bootstrap variable. The guard
// also arms only a store it can PROVE is loopback, and it does not
// resolve names, so a DATABASE_URL naming any host but a loopback literal or
// `localhost` — `host.docker.internal` from a dev container, say — can never
// arm. That case is skipped with the guard's own reason rather than failed.
const pgSchema = pgSuiteSchema('demo_tamper');
const pgTarget = PG_TESTS_ENABLED ? classifyDemoTamperTarget({ kind: 'url', url: pgSchema.url }) : undefined;

describe('demo-tamper hooks Postgres parity (integration)', () => {
  if (!PG_TESTS_ENABLED || pgTarget === undefined) {
    it.skip('skipped: set RUN_INTEGRATION_TESTS=true and DATABASE_URL to run', () => {});
    return;
  }
  if (!pgTarget.loopback) {
    it.skip(
      `arms on empty PG store — skipped: DATABASE_URL names ${pgTarget.detail}, which the arming guard cannot prove is loopback`,
      () => {},
    );
    return;
  }

  it('arms on empty PG store, deletes, and overwrites canonicalBytes', async () => {
    const tzun = await Tzun.init({ dbUrl: pgSchema.url, demoTamperHooks: true } as never);
    const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { pg: 1 }, action: 'a', reason: 'r' });
    await tzun.getStorage().deleteEnvelopeForDemo!(r.envelope.payload.evidenceId);
    expect(await tzun.getStorage().retrieve(r.envelope.payload.evidenceId)).toBeNull();

    const { digest } = await tzun.models.register({ vendor: 'pg', modelName: 'm', modelVersion: '1' });
    const row = await tzun.getStorage().getModelDescriptor!(digest);
    const mutated = row!.canonicalBytes.replace('"m"', '"m-pg-tamper"');
    const previous = await tzun.getStorage().overwriteModelDescriptorBytesForDemo!(digest, mutated);
    expect(previous).toBe(row!.canonicalBytes);
    const after = await tzun.getStorage().getModelDescriptor!(digest);
    expect(after!.canonicalBytes).toBe(mutated);

    await tzun.getStorage().close?.();
  });
});

/**
 * The guard's observability and its one-shot bootstrap valve.
 *
 * (1) Every arm logs a `demo_tamper_guard_armed` line naming its reason, as
 *     every refusal logs a `demo_tamper_guard_refused` line. An arm is
 *     permanent — the sentinel persists — so an arm that logged nothing would
 *     leave no record, months later when a stray `deleteEnvelopeForDemo`
 *     deletes evidence, that the store had been armed at first boot.
 *
 * (2) The arm that spends TZUN_DEMO_TAMPER_BOOTSTRAP removes it from the
 *     environment itself. A one-shot property that rested on an operator
 *     remembering to unset the variable would let a lingering variable arm any
 *     store the process was later pointed at.
 */
import {
  DemoTamperStoreView,
  DemoTamperTarget,
  tryArmDemoTamperHooks,
} from '../../../src/storage/demo-tamper-guard';

/**
 * `target` is deliberately opt-in here, mirroring the interface: a fake that
 * does not pass one produces a view with NO `target` method at all — the
 * out-of-tree-adapter case that must fail closed.
 */
function fakeStore(opts: {
  sentinel?: boolean;
  count?: number;
  target?: DemoTamperTarget;
  targetThrows?: boolean;
}) {
  const state = { sentinel: opts.sentinel ?? false };
  const view: DemoTamperStoreView = {
    hasSentinel: async () => state.sentinel,
    writeSentinel: async () => { state.sentinel = true; },
    envelopeCount: async () => opts.count ?? 0,
  };
  if (opts.targetThrows) {
    view.target = () => { throw new Error('cannot determine target'); };
  } else if (opts.target !== undefined) {
    const t = opts.target;
    view.target = () => t;
  }
  return { view, state };
}

const LOCAL: DemoTamperTarget = { kind: 'local', what: 'test fake' };

describe('demo-tamper guard observability and the one-shot valve', () => {
  let lines: string[];
  let spy: jest.SpyInstance;
  const savedEnv = process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;

  beforeEach(() => {
    lines = [];
    spy = jest.spyOn(console, 'error').mockImplementation((m?: unknown) => {
      lines.push(String(m));
    });
    delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
  });

  afterEach(() => {
    spy.mockRestore();
    if (savedEnv === undefined) delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
    else process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = savedEnv;
  });

  const armedLines = () =>
    lines.map((l) => JSON.parse(l)).filter((o) => o.type === 'demo_tamper_guard_armed');

  /**
   * An empty store proves nothing about WHOSE store it is — every production
   * database is empty on day one — and this fake offers no `target`, which is
   * the adapter that cannot say where it points. The guard refuses it, leaves
   * no sentinel, logs no arm, and logs the refusal with its reason.
   */
  it('REFUSES an empty store whose adapter offers no target — the production-day-one case', async () => {
    const { view, state } = fakeStore({ count: 0 });
    expect(await tryArmDemoTamperHooks(view, 'postgres')).toBe(false);
    expect(state.sentinel).toBe(false); // and leaves no sentinel to arm on next boot
    expect(armedLines()).toEqual([]);
    expect(lines.map((l) => JSON.parse(l))).toEqual([
      {
        type: 'demo_tamper_guard_refused',
        reason: 'empty-store-not-loopback',
        backend: 'postgres',
        target: 'adapter offers no target descriptor',
      },
    ]);
  });

  it('logs when it arms an empty store the adapter shows is local', async () => {
    const { view } = fakeStore({ count: 0, target: LOCAL });
    expect(await tryArmDemoTamperHooks(view, 'sqlite')).toBe(true);
    expect(armedLines()).toEqual([
      { type: 'demo_tamper_guard_armed', reason: 'empty-store', backend: 'sqlite' },
    ]);
  });

  it('logs when it arms via an existing sentinel', async () => {
    const { view } = fakeStore({ sentinel: true, count: 42 });
    expect(await tryArmDemoTamperHooks(view, 'sqlite')).toBe(true);
    expect(armedLines()).toEqual([
      { type: 'demo_tamper_guard_armed', reason: 'sentinel', backend: 'sqlite' },
    ]);
  });

  it('consumes the bootstrap valve on the arm that spends it', async () => {
    process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
    const { view } = fakeStore({ count: 7 }); // populated: only bootstrap can arm
    expect(await tryArmDemoTamperHooks(view, 'postgres')).toBe(true);
    expect(armedLines()).toEqual([
      { type: 'demo_tamper_guard_armed', reason: 'bootstrap', backend: 'postgres' },
    ]);
    // The valve is spent: the arm removed the variable from the environment.
    expect(process.env.TZUN_DEMO_TAMPER_BOOTSTRAP).toBeUndefined();

    // The outcome that matters: the NEXT populated store this process opens is
    // refused instead of inheriting the arm.
    lines = [];
    const second = fakeStore({ count: 3 });
    expect(await tryArmDemoTamperHooks(second.view, 'postgres')).toBe(false);
    expect(second.state.sentinel).toBe(false);
    expect(lines.map((l) => JSON.parse(l).type)).toEqual(['demo_tamper_guard_refused']);
  });

  it('does NOT spend the valve on an arm that did not need it', async () => {
    // An empty LOCAL store arms on its own. Clearing the variable here would
    // silently disarm a migration the operator has not performed yet.
    //
    // An empty store arms without the valve only when the adapter
    // demonstrates locality, so the fake passes `target: LOCAL`. The property
    // under test is that the valve survives an arm that did not spend it. The
    // remote counterpart is the next case.
    process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
    const { view } = fakeStore({ count: 0, target: LOCAL });
    expect(await tryArmDemoTamperHooks(view, 'memory')).toBe(true);
    expect(armedLines()[0].reason).toBe('empty-store');
    expect(process.env.TZUN_DEMO_TAMPER_BOOTSTRAP).toBe('true');
  });

  it('DOES spend the valve when an empty non-local store could not have armed without it', async () => {
    process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = 'true';
    const { view, state } = fakeStore({
      count: 0,
      target: { kind: 'url', url: 'postgres://u:p@db.prod.example.com:5432/tzun' },
    });
    expect(await tryArmDemoTamperHooks(view, 'postgres')).toBe(true);
    expect(state.sentinel).toBe(true);
    expect(armedLines()[0].reason).toBe('bootstrap'); // not 'empty-store'
    expect(process.env.TZUN_DEMO_TAMPER_BOOTSTRAP).toBeUndefined();
  });

  it('still logs refusal, and labels the backend', async () => {
    const { view } = fakeStore({ count: 5 });
    expect(await tryArmDemoTamperHooks(view, 'postgres')).toBe(false);
    expect(lines.map((l) => JSON.parse(l))).toEqual([
      {
        type: 'demo_tamper_guard_refused',
        reason: 'unsentineled-non-empty-store',
        backend: 'postgres',
      },
    ]);
  });
});

/**
 * The empty-store arm path against a REMOTE store.
 *
 * `demoTamperHooks: true` copied out of the demo's config preset meets an
 * empty store on every production deployment's first day. The arming log makes
 * an arm visible, but visible is not prevented, so the empty path requires the
 * adapter to demonstrate, through `DemoTamperStoreView.target()`, that its
 * target is loopback. An adapter that cannot say where it points is treated as
 * remote, not as local.
 */
describe('empty-store arming requires a demonstrably loopback target', () => {
  let lines: string[];
  let spy: jest.SpyInstance;
  const savedEnv = process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;

  beforeEach(() => {
    lines = [];
    spy = jest.spyOn(console, 'error').mockImplementation((m?: unknown) => { lines.push(String(m)); });
    delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
  });
  afterEach(() => {
    spy.mockRestore();
    if (savedEnv === undefined) delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
    else process.env.TZUN_DEMO_TAMPER_BOOTSTRAP = savedEnv;
  });

  const url = (u: string): DemoTamperTarget => ({ kind: 'url', url: u });

  it('an empty REMOTE store refuses to arm, and writes no sentinel', async () => {
    const { view, state } = fakeStore({
      count: 0,
      target: url('postgres://tzun:s3cret@db.example:5432/evidence'),
    });
    expect(await tryArmDemoTamperHooks(view, 'postgres')).toBe(false);
    // No sentinel: a refusal that armed the store on the next boot anyway would
    // be no refusal at all.
    expect(state.sentinel).toBe(false);
    const refused = lines.map((l) => JSON.parse(l));
    expect(refused).toEqual([{
      type: 'demo_tamper_guard_refused',
      reason: 'empty-store-not-loopback',
      backend: 'postgres',
      target: 'host db.example (name, not resolved)',
    }]);
    // The refusal line is operator-facing output about a connection string.
    expect(JSON.stringify(refused)).not.toContain('s3cret');
  });

  it('an empty LOCAL store still arms', async () => {
    const { view, state } = fakeStore({ count: 0, target: url('postgres://u:p@127.0.0.1:5432/tzun_demo') });
    expect(await tryArmDemoTamperHooks(view, 'postgres')).toBe(true);
    expect(state.sentinel).toBe(true);
    expect(lines.map((l) => JSON.parse(l).reason)).toEqual(['empty-store']);
  });

  it('an unarmed remote store keeps the hooks throwing', async () => {
    const { view } = fakeStore({ count: 0, target: url('postgres://u:p@10.0.0.7:5432/tzun') });
    const armed = await tryArmDemoTamperHooks(view, 'postgres');
    expect(() => assertArmed(armed)).toThrow(DemoTamperGuardError);
  });

  describe('fail closed on unknown', () => {
    const unknowns: Array<[string, Parameters<typeof fakeStore>[0]]> = [
      ['no target method at all (an adapter written before the target check)', { count: 0 }],
      ['an explicit unknown answer', { count: 0, target: { kind: 'unknown', why: 'ambiguous config' } }],
      ['a target() that throws', { count: 0, targetThrows: true }],
      ['a connection string that does not parse', { count: 0, target: url('host=1.2.3.4 port=5432 dbname=x') }],
      ['a multi-host connection string', { count: 0, target: url('postgres://u:p@a.example.com:5432,b.example.com:5432/db') }],
    ];
    it.each(unknowns)('refuses when the adapter gives %s', async (_label, opts) => {
      const { view, state } = fakeStore(opts);
      expect(await tryArmDemoTamperHooks(view, 'postgres')).toBe(false);
      expect(state.sentinel).toBe(false);
      expect(lines.map((l) => JSON.parse(l).reason)).toEqual(['empty-store-not-loopback']);
    });
  });

  describe('what counts as loopback', () => {
    const loopback = [
      'postgres://u:p@localhost:5432/db',
      'postgres://u:p@LOCALHOST:5432/db',
      'postgres://u:p@localhost.:5432/db',      // fully-qualified form
      'postgres://u:p@127.0.0.1:5432/db',
      'postgres://u:p@127.9.9.9:5432/db',       // all of 127.0.0.0/8
      'postgres://u:p@[::1]:5432/db',
      'postgres://u:p@[0:0:0:0:0:0:0:1]:5432/db',
      'postgres://u:p@[::ffff:127.0.0.1]:5432/db', // v4-mapped loopback
      'postgres:///db?host=/var/run/postgresql',   // unix socket
    ];
    it.each(loopback)('%s is loopback', (u) => {
      expect(classifyDemoTamperTarget({ kind: 'url', url: u }).loopback).toBe(true);
    });

    const remote = [
      'postgres://u:p@db.example.com:5432/db',
      'postgres://u:p@10.0.0.5:5432/db',
      'postgres://u:p@192.168.1.10:5432/db',       // a LAN host is not loopback
      'postgres://u:p@126.0.0.1:5432/db',
      'postgres://u:p@128.0.0.1:5432/db',
      'postgres://u:p@0.0.0.0:5432/db',            // unspecified, not loopback
      'postgres://u:p@2130706433:5432/db',         // decimal 127.0.0.1: not a literal we accept
      'postgres://u:p@127.1:5432/db',              // short form: not a literal we accept
      'postgres://u:p@localhost.evil.example:5432/db',
      'postgres://u:p@127.0.0.1.evil.example:5432/db',
      'postgres://u:p@[::ffff:8.8.8.8]:5432/db',
      'postgres://u:p@[2001:db8::1]:5432/db',
      'postgres://u:p@[::]:5432/db',
      'postgres:///db',                             // host comes from $PGHOST
      'postgres://u:p@evil.example:5432/db?host=127.0.0.1', // two hosts named
      'not a url at all',
    ];
    it.each(remote)('%s is NOT loopback', (u) => {
      expect(classifyDemoTamperTarget({ kind: 'url', url: u }).loopback).toBe(false);
    });

    it('never puts the connection string (and its password) in the detail', () => {
      const { detail } = classifyDemoTamperTarget({
        kind: 'url',
        url: 'postgres://tzun:hunter2@db.example.com:5432/evidence',
      });
      expect(detail).not.toContain('hunter2');
      expect(detail).not.toContain('tzun');
    });

    it('a missing descriptor is not local', () => {
      expect(classifyDemoTamperTarget(undefined).loopback).toBe(false);
    });
  });

  describe('the adapters answer for themselves', () => {
    it('memory and in-memory sqlite report local', async () => {
      const mem = new MemoryStorageAdapter();
      expect(await (mem as never as { demoTamperView(): DemoTamperStoreView }).demoTamperView().target!())
        .toEqual({ kind: 'local', what: 'in-process memory' });

      for (const dbPath of [':memory:', '']) {
        const lite = new SqliteStorageAdapter(dbPath);
        const t = await (lite as never as { demoTamperView(): DemoTamperStoreView }).demoTamperView().target!();
        expect(t).toEqual({ kind: 'local', what: 'sqlite in-memory database' });
        expect(classifyDemoTamperTarget(t).loopback).toBe(true);
        await lite.close?.();
      }
    });

    // a file is where a production SQLite store lives too.
    it('a file-backed sqlite store is NOT demonstrably a demo store, and says why, naming its file', async () => {
      const path = sqlitePath();
      const lite = new SqliteStorageAdapter(path);
      const t = await (lite as never as { demoTamperView(): DemoTamperStoreView }).demoTamperView().target!();
      expect(t).toMatchObject({ kind: 'unknown' });
      expect((t as { why: string }).why).toContain(`sqlite file ${path}`);
      expect((t as { why: string }).why).toContain('TZUN_DEMO_TAMPER_BOOTSTRAP');
      expect(classifyDemoTamperTarget(t).loopback).toBe(false);
      await lite.close?.();
    });

    it('postgres reports the connection string the pool will actually use', async () => {
      const { PostgresStorageAdapter } = await import('../../../src/storage/postgres');
      // `pg.Pool` connects lazily, so constructing these opens no socket.
      const plain = new PostgresStorageAdapter('postgres://u:p@db.example.com:5432/x');
      expect(await (plain as never as { demoTamperView(): DemoTamperStoreView }).demoTamperView().target!())
        .toEqual({ kind: 'url', url: 'postgres://u:p@db.example.com:5432/x' });

      // poolConfig is spread last, so ITS connectionString is the effective one.
      const overridden = new PostgresStorageAdapter('postgres://u:p@127.0.0.1:5432/x', {
        connectionString: 'postgres://u:p@db.example.com:5432/x',
      });
      const t = await (overridden as never as { demoTamperView(): DemoTamperStoreView }).demoTamperView().target!();
      expect(classifyDemoTamperTarget(t).loopback).toBe(false);

      // A host beside a connection string is ambiguous — refuse rather than pick.
      const ambiguous = new PostgresStorageAdapter('postgres://u:p@127.0.0.1:5432/x', { host: '127.0.0.1' });
      expect(await (ambiguous as never as { demoTamperView(): DemoTamperStoreView }).demoTamperView().target!())
        .toEqual({ kind: 'unknown', why: 'pool config overrides the host' });

      await Promise.all([plain.close?.(), overridden.close?.(), ambiguous.close?.()]);
    });
  });
});
