// Which chains exist, and which one takes appends.
//
// Two properties of the "which chains are there" resolution:
//
//   1. `StorageAdapter.getActiveChainId()` resolves the chain that takes
//      appends; it does not guess. Exactly one chain accepting appends → that
//      chain; none → typed `no_active_chain`; more than one → typed
//      `ambiguous_active_chain`. A chain accepts appends when its row is
//      active OR when it holds records and has no row at all — the adapters'
//      sealed guard only refuses a chain whose ROW says sealed, so an implicit
//      chain is as open as an active one. A guess such as "the newest active
//      row, else 'default'" would name the SEALED default chain on a forked
//      store whose every chain has been sealed, and on a store with records on
//      the implicit default chain plus one active `tenant-globex` row it would
//      adopt the row silently: a second chain, born with the default chain's
//      next sequence number and a link from the default chain's head.
//
//   2. `Tzun.verifyAllChains()` walks every chain that has records, whatever
//      the SDK was told is active. A walk over the chain rows alone would drop
//      every record on the implicit default chain as soon as one non-default
//      row exists; an empty chain is vacuously valid, so the AND would stay
//      `true` over a tampered record it never read.
//
// ADAPTERS. Everything that does not need a process restart runs on the memory
// adapter AND on SQLite over a temp file, through the same `describe.each`, so
// the two are asked the same question (the memory adapter is not a faithful
// double unless something makes it one). The restart shapes — a
// second `Tzun.init()` on a store that already holds the state — need a store
// that survives `close()`, so they are SQLite-only here; the Postgres twin is
// `active-chain-resolution-postgres.test.ts`.
//
// The on-disk edits (sealing every row, tampering a link) go through a second
// `better-sqlite3` handle or the tamper helper, not the SDK: the states being
// pinned are the ones an operator, another process, or an attacker leaves
// behind, which is what "re-open" has to cope with.
import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Tzun } from '../../src/sdk/index';
import { resolveChainScopes } from '../../src/storage/chain-bounds';
import { deleteStoredEnvelope, rewriteStoredEnvelope } from './helpers/tamper-store';
import type { TamperIncident } from '@tzun/engine';

type Backend = 'memory' | 'sqlite';

function tmpDbPath(label: string): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-active-chain-')), `${label}.db`);
}

function cleanup(dbPath: string): void {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
  }
  try { fs.rmdirSync(path.dirname(dbPath)); } catch { /* ignore */ }
}

/**
 * Open the SDK the way an integrator does — nothing hand-constructed.
 *
 * `mode: 'dev'` on BOTH legs. Storage is chosen by `dbPath` — passing
 * one is what selects SQLite over a temp file, and that is the only reason the
 * sqlite leg passes one — while `mode` chooses ATTESTATION, and a production
 * mode obtains an RFC 3161 timestamp for every record: a live round trip to
 * freetsa.org on every capture(), which the suite-wide guard
 * (tests/ts/setup/no-live-network.ts) refuses, failing the test by name even
 * though capture() swallows the refusal and stores the record 'pending'.
 * Which chain a record lands on is a storage property;
 * the attestation mode does not change it.
 */
function boot(dbPath?: string): Promise<Tzun> {
  return dbPath ? Tzun.init({ mode: 'dev', dbPath }) : Tzun.init({ mode: 'dev' });
}

async function capture(tzun: Tzun, tag: string, i: number): Promise<string> {
  const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { [tag]: i }, action: 'approved', reason: `${tag}-${i}` });
  expect(result.failure).toBeUndefined();
  expect(result.stored).toBe(true);
  return result.envelope.payload.evidenceId;
}

function chainRowsOnDisk(dbPath: string): Array<{ chain_id: string; status: string }> {
  const db = new Database(dbPath, { readonly: true });
  try {
    return db.prepare('SELECT chain_id, status FROM chains ORDER BY created_at ASC, chain_id ASC').all() as Array<{
      chain_id: string;
      status: string;
    }>;
  } finally {
    db.close();
  }
}

function envelopeCountOnDisk(dbPath: string): number {
  const db = new Database(dbPath, { readonly: true });
  try {
    return (db.prepare('SELECT COUNT(*) AS n FROM envelopes').get() as { n: number }).n;
  } finally {
    db.close();
  }
}

/** Seal every chain row behind the SDK's back, as an operator or another process can. */
function sealEveryChainOnDisk(dbPath: string): void {
  const db = new Database(dbPath);
  try {
    db.prepare("UPDATE chains SET status = 'sealed', sealed_at = ? WHERE status = 'active'").run(new Date().toISOString());
  } finally {
    db.close();
  }
}

/**
 * Re-open a sealed chain on disk. The `chains` trigger refuses a plain
 * UPDATE, so this is a schema change: drop the trigger, update, put the
 * trigger back — one transaction, which is what an operator repairing the file
 * by hand has to do.
 */
function reactivateOnDisk(dbPath: string, chainId: string): void {
  const db = new Database(dbPath);
  try {
    const reopen = db.prepare("UPDATE chains SET status = 'active', sealed_at = NULL WHERE chain_id = ?");
    expect(() => reopen.run(chainId)).toThrow(/sealed/);
    db.transaction(() => {
      const trigger = db
        .prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'chains_enforce_immutable'")
        .get() as { sql: string };
      db.exec('DROP TRIGGER chains_enforce_immutable');
      reopen.run(chainId);
      db.exec(trigger.sql);
    })();
  } finally {
    db.close();
  }
}

/** Three captures on the implicit default chain, then a fork after 3, then one capture on the new chain. */
async function forkedStore(tzun: Tzun): Promise<{ sealedChainId: string; forkedChainId: string }> {
  for (let i = 1; i <= 3; i++) await capture(tzun, 'old', i);
  const sealedChainId = await tzun.getActiveChainId();
  const fork = await tzun.recovery.fork('inc-active-chain', {
    authorizedBy: 'admin@acme.example',
    reason: 'Signing key compromised; rotating the chain.',
    forkAfterSequence: 3,
  });
  await capture(tzun, 'new', 1);
  return { sealedChainId, forkedChainId: fork.newChain.chainId };
}

const backends: Backend[] = ['memory', 'sqlite'];

describe.each(backends)('getActiveChainId() on %s — the active chain is resolved, not guessed', (backend) => {
  let dbPath: string | undefined;
  let tzun: Tzun;

  beforeEach(async () => {
    dbPath = backend === 'sqlite' ? tmpDbPath('live') : undefined;
    tzun = await boot(dbPath);
  });

  afterEach(async () => {
    await tzun.close();
    if (dbPath) cleanup(dbPath);
  });

  it('a store whose every chain is sealed has no active chain: typed refusal, and no capture lands anywhere', async () => {
    const { sealedChainId, forkedChainId } = await forkedStore(tzun);
    const storage = tzun.getStorage();
    await storage.sealChain(forkedChainId, new Date().toISOString());

    // Refused, not resolved to 'default' — the chain the fork sealed.
    const err = await storage.getActiveChainId().then(
      (id) => { throw new Error(`resolved to "${id}" instead of refusing`); },
      (e: unknown) => e as { name: string; code: string; chains: Array<{ chainId: string; status: string }> },
    );
    expect(err).toMatchObject({ name: 'NoActiveChainError', code: 'no_active_chain' });
    expect(err.chains.map((c) => `${c.chainId}:${c.status}`).sort()).toEqual(
      [`${sealedChainId}:sealed`, `${forkedChainId}:sealed`].sort(),
    );

    // Nothing can land: this instance still believes the forked chain is
    // live (it resolved that at init), and the adapter's own sealed guard is
    // what refuses the append. The refusal is reported, not swallowed.
    const before = await storage.getChainLength();
    const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { late: 1 }, action: 'approved', reason: 'after the seal' });
    expect(result.stored).toBe(false);
    expect(result.failure?.diagnosticMetadata).toBeDefined();
    expect(await storage.getChainLength()).toBe(before);
    expect(await storage.getChainLength(sealedChainId)).toBe(3);
    expect(await storage.getChainLength(forkedChainId)).toBe(1);
  });

  it("records on the implicit default chain plus one active row is ambiguous — the row is not adopted", async () => {
    for (let i = 1; i <= 3; i++) await capture(tzun, 'acme', i);
    const storage = tzun.getStorage();
    // The only thing the public API lets an integrator do towards per-tenant
    // chains. The row holds nothing and the records are on default, so the
    // store must not answer `tenant-globex` from here on.
    await storage.storeChain({ chainId: 'tenant-globex', status: 'active', createdAt: new Date().toISOString() });

    const err = await storage.getActiveChainId().then(
      (id) => { throw new Error(`resolved to "${id}" instead of refusing`); },
      (e: unknown) => e as { name: string; code: string; activeChainIds: string[]; implicitChainIds: string[]; message: string },
    );
    expect(err).toMatchObject({ name: 'AmbiguousActiveChainError', code: 'ambiguous_active_chain' });
    expect(err.activeChainIds.sort()).toEqual(['default', 'tenant-globex']);
    expect(err.implicitChainIds).toEqual(['default']);
    // The message says which is which, says the SDK will not choose, and names
    // the way to choose.
    expect(err.message).toContain('tenant-globex (row: active)');
    expect(err.message).toContain('default (no identity row, holds records)');
    expect(err.message).toContain('Tzun.init({ chainId })');
  });

  it('two active rows is ambiguous, naming both', async () => {
    const { sealedChainId, forkedChainId } = await forkedStore(tzun);
    const storage = tzun.getStorage();
    await storage.storeChain({ chainId: 'tenant-b', status: 'active', createdAt: new Date().toISOString() });

    const err = await storage.getActiveChainId().then(
      (id) => { throw new Error(`resolved to "${id}" instead of refusing`); },
      (e: unknown) => e as { code: string; activeChainIds: string[]; implicitChainIds: string[]; chains: Array<{ chainId: string }> },
    );
    expect(err.code).toBe('ambiguous_active_chain');
    expect(err.activeChainIds.sort()).toEqual([forkedChainId, 'tenant-b'].sort());
    expect(err.implicitChainIds).toEqual([]);
    expect(err.chains.map((c) => c.chainId).sort()).toEqual([sealedChainId, forkedChainId, 'tenant-b'].sort());
  });

  it('after a fork exactly one chain is active and it is the new one', async () => {
    const { forkedChainId } = await forkedStore(tzun);
    expect(await tzun.getStorage().getActiveChainId()).toBe(forkedChainId);
    expect(await tzun.getActiveChainId()).toBe(forkedChainId);
  });

  it('a store nothing has written to is the implicit default chain; a registered lone active row is that row', async () => {
    const storage = tzun.getStorage();
    expect(await storage.getActiveChainId()).toBe('default');
    await storage.storeChain({ chainId: 'chain-001', status: 'active', createdAt: new Date().toISOString() });
    expect(await storage.getActiveChainId()).toBe('chain-001');
  });

  it('on an ambiguous store, annotate() and relink() work when the operator names the chain, and refuse when they would have to pick it', async () => {
    // The ambiguous store: three records on the implicit default chain, one
    // empty active row. The store cannot say which chain takes appends — and
    // recovery on a chain the operator has NAMED needs no such answer, only
    // a bound, which comes from the records present. Recovery that would
    // have to pick the chain itself gets the store's refusal instead.
    const ids: string[] = [];
    for (let i = 1; i <= 3; i++) ids.push(await capture(tzun, 'acme', i));
    const storage = tzun.getStorage();
    await storage.storeChain({ chainId: 'tenant-globex', status: 'active', createdAt: new Date().toISOString() });
    await expect(storage.getActiveChainId()).rejects.toMatchObject({ code: 'ambiguous_active_chain' });

    // A sequence-shaped incident: a range and no evidence ids, so the chain
    // it is about is the one thing annotate() has to be told.
    await storage.storeIncident({
      id: 'inc-gap',
      detectedAt: new Date().toISOString(),
      severity: 'warning',
      type: 'sequence_gap',
      affectedRecords: [],
      affectedSequenceRange: { from: 2, to: 3 },
      details: 'raised by a scan',
      status: 'open',
    } as TamperIncident);
    await expect(
      tzun.recovery.annotate('inc-gap', { authorizedBy: 'admin@acme.example', notes: 'reviewed the gap' }),
    ).rejects.toThrow(/no single active chain to resolve the range against/);
    const annotated = await tzun.recovery.annotate('inc-gap', {
      authorizedBy: 'admin@acme.example',
      notes: 'reviewed the gap',
      chainId: 'default',
    });
    expect(annotated.annotation.affectedRecords.sort()).toEqual([ids[1], ids[2]].sort());

    // A corrupted link on default's record 2. Without a chain, relink() gets
    // the store's own refusal and rewrites nothing; with one, it repairs the
    // link and its verification walks the named chain to its real head (3),
    // not to a live counter the store could not attribute.
    const goodLink = (await storage.retrieve(ids[1]))!.integrity.chainLink;
    await storage.updateEnvelopeChainLink(ids[1], 'corrupted-link');
    await storage.storeIncident({
      id: 'inc-link',
      detectedAt: new Date().toISOString(),
      severity: 'critical',
      type: 'chain_break',
      affectedRecords: [ids[1]],
      details: 'raised by a scan',
      status: 'open',
    } as TamperIncident);
    await expect(
      tzun.recovery.relink('inc-link', { authorizedBy: 'admin@acme.example', fromSequence: 2 }),
    ).rejects.toMatchObject({ code: 'ambiguous_active_chain' });
    expect((await storage.retrieve(ids[1]))!.integrity.chainLink).toBe('corrupted-link');
    const relinked = await tzun.recovery.relink('inc-link', {
      authorizedBy: 'admin@acme.example',
      fromSequence: 2,
      chainId: 'default',
    });
    expect(relinked.relink.toSequence).toBe(3);
    expect(relinked.relink.modifiedLinks).toHaveLength(1);
    expect(relinked.chainVerified).toBe(true);
    expect((await storage.retrieve(ids[1]))!.integrity.chainLink).toBe(goodLink);

    // Neither operation adopted a chain: the store is as ambiguous as it was,
    // and the empty row is still empty.
    await expect(storage.getActiveChainId()).rejects.toMatchObject({ code: 'ambiguous_active_chain' });
    expect(await storage.getChainLength('tenant-globex')).toBe(0);
    expect(await storage.getChainLength('default')).toBe(3);
  });
});

describe('getActiveChainId() on sqlite — re-opening the store', () => {
  let dbPath: string;

  beforeEach(() => { dbPath = tmpDbPath('restart'); });
  afterEach(() => cleanup(dbPath));

  it('(a) fork, close, re-open: the forked-to chain is active and the next capture lands on it', async () => {
    const first = await boot(dbPath);
    let forkedChainId: string;
    try {
      ({ forkedChainId } = await forkedStore(first));
    } finally {
      await first.close();
    }

    const second = await boot(dbPath);
    try {
      expect(await second.getActiveChainId()).toBe(forkedChainId);
      const id = await capture(second, 'after-restart', 1);
      expect(await second.getStorage().getChainForRecord(id)).toBe(forkedChainId);
      expect(await second.getStorage().getChainLength(forkedChainId)).toBe(2);
    } finally {
      await second.close();
    }
  });

  it('(a) seal every chain, re-open: Tzun.init() refuses with no_active_chain naming both rows, and the file is left free for the repair', async () => {
    const first = await boot(dbPath);
    let sealedChainId: string;
    let forkedChainId: string;
    try {
      ({ sealedChainId, forkedChainId } = await forkedStore(first));
    } finally {
      await first.close();
    }
    sealEveryChainOnDisk(dbPath);
    expect(chainRowsOnDisk(dbPath).map((r) => r.status)).toEqual(['sealed', 'sealed']);

    // Refused at init. Resolving would name 'default' — a sealed chain — and
    // aim the next captures there.
    const err = await boot(dbPath).then(
      async (t) => {
        const id = await t.getActiveChainId();
        await t.close();
        throw new Error(`Tzun.init() came up with activeChainId "${id}" on a store whose every chain is sealed`);
      },
      (e: unknown) => e as { name: string; code: string; chains: Array<{ chainId: string; status: string }> },
    );
    expect(err).toMatchObject({ name: 'NoActiveChainError', code: 'no_active_chain' });
    expect(err.chains.map((c) => `${c.chainId}:${c.status}`).sort()).toEqual(
      [`${sealedChainId}:sealed`, `${forkedChainId}:sealed`].sort(),
    );
    expect(envelopeCountOnDisk(dbPath)).toBe(4);

    // The repair the error describes: leave exactly one chain active. The
    // refused init released its handle, so this does not wait on a lock.
    reactivateOnDisk(dbPath, forkedChainId);
    const repaired = await boot(dbPath);
    try {
      expect(await repaired.getActiveChainId()).toBe(forkedChainId);
      const id = await capture(repaired, 'repaired', 1);
      expect(await repaired.getStorage().getChainForRecord(id)).toBe(forkedChainId);
    } finally {
      await repaired.close();
    }
    expect(envelopeCountOnDisk(dbPath)).toBe(5);
  });

  it('across a restart, the implicit default chain plus one active row is refused at init, not adopted', async () => {
    const first = await boot(dbPath);
    try {
      for (let i = 1; i <= 3; i++) await capture(first, 'acme', i);
      await first.getStorage().storeChain({ chainId: 'tenant-globex', status: 'active', createdAt: new Date().toISOString() });
    } finally {
      await first.close();
    }

    // Adopting `tenant-globex` here would give its first record sequence 4
    // and a link from default's head.
    const err = await boot(dbPath).then(
      async (t) => {
        const id = await t.getActiveChainId();
        await t.close();
        throw new Error(`Tzun.init() adopted "${id}"`);
      },
      (e: unknown) => e as { code: string; activeChainIds: string[]; implicitChainIds: string[] },
    );
    expect(err.code).toBe('ambiguous_active_chain');
    expect(err.activeChainIds.sort()).toEqual(['default', 'tenant-globex']);
    expect(err.implicitChainIds).toEqual(['default']);
    expect(envelopeCountOnDisk(dbPath)).toBe(3);
  });
});

/** The SQLite handle under `storage`, through the verifying proxy if one is on. */
function sqliteHandle(storage: unknown): Database.Database {
  let s = storage;
  while (s && typeof s === 'object' && 'inner' in (s as Record<string, unknown>)) s = (s as { inner: unknown }).inner;
  return (s as { db: Database.Database }).db;
}

/**
 * Run `after` once, right after the next `SELECT … FROM chains` the adapter
 * executes and before its next statement. better-sqlite3 is synchronous, so
 * whatever `after` commits through a second handle is on disk before the
 * adapter's next read runs — the only question is whether that read is in
 * the same snapshot as the first.
 */
function afterNextChainsRead(storage: unknown, after: () => void): void {
  const db = sqliteHandle(storage);
  const originalPrepare = db.prepare.bind(db);
  let fired = false;
  (db as unknown as { prepare: unknown }).prepare = (sql: string) => {
    const statement = originalPrepare(sql);
    if (fired || !/\bFROM chains\b/.test(sql)) return statement;
    const all = statement.all.bind(statement);
    (statement as unknown as { all: unknown }).all = (...args: unknown[]) => {
      const rows = all(...args);
      if (!fired) {
        fired = true;
        after();
      }
      return rows;
    };
    return statement;
  };
}

/**
 * What another process's fork leaves on disk, written through a second
 * handle: the default chain materialised and sealed, a new active row, and
 * one record on the new chain (a copy of default's first record under a new
 * id — `listRecordChainIds()` reads `chain_id` and nothing else).
 */
function forkOnDiskBehindTheReader(dbPath: string, newChainId: string): void {
  const db = new Database(dbPath);
  try {
    const now = new Date().toISOString();
    db.transaction(() => {
      db.prepare("INSERT INTO chains (chain_id, status, created_at, sealed_at) VALUES ('default', 'sealed', ?, ?)").run(now, now);
      db.prepare("INSERT INTO chains (chain_id, parent_chain_id, fork_point, status, created_at) VALUES (?, 'default', 3, 'active', ?)").run(newChainId, now);
      const columns = (db.pragma('table_info(envelopes)') as Array<{ name: string }>).map((c) => c.name);
      const select = columns.map((c) => (c === 'evidence_id' ? "'ev-race'" : c === 'chain_id' ? '?' : c)).join(', ');
      db.prepare(
        `INSERT INTO envelopes (${columns.join(', ')}) SELECT ${select} FROM envelopes WHERE chain_id = 'default' ORDER BY created_at ASC LIMIT 1`,
      ).run(newChainId);
    })();
  } finally {
    db.close();
  }
}

describe('getActiveChainId() on sqlite — both reads come from one snapshot', () => {
  let dbPath: string;

  beforeEach(() => { dbPath = tmpDbPath('snapshot'); });
  afterEach(() => cleanup(dbPath));

  it('a fork committed by another handle between the chains read and the records read cannot make the answer false', async () => {
    // Without a transaction around the two reads, the chains read would see
    // no rows and the records read would see the new chain's record: two
    // implicit chains, `ambiguous_active_chain` on a store that at no instant had
    // more than one open chain. The Postgres twin does the same with a fork
    // through the SDK on a second pool.
    const tzun = await boot(dbPath);
    try {
      for (let i = 1; i <= 3; i++) await capture(tzun, 'acme', i);
      const storage = tzun.getStorage();
      expect(await storage.listChains()).toEqual([]);

      let interleaved = 0;
      afterNextChainsRead(storage, () => {
        interleaved += 1;
        forkOnDiskBehindTheReader(dbPath, 'chain-race');
      });

      expect(await storage.getActiveChainId()).toBe('default');
      expect(interleaved).toBe(1);

      // The fork really did land underneath that read; the next one sees it.
      expect(chainRowsOnDisk(dbPath).map((r) => `${r.chain_id}:${r.status}`).sort()).toEqual(['chain-race:active', 'default:sealed']);
      expect(await storage.getActiveChainId()).toBe('chain-race');
      expect(await storage.listRecordChainIds()).toEqual(['chain-race', 'default']);
    } finally {
      await tzun.close();
    }
  });
});

/**
 * The tampered store: three records on the implicit default chain, one
 * empty `tenant-b` identity row, and default's record 3 re-linked to the
 * literal string 'TAMPERED'. Returns the tampered record's id.
 */
async function addendumStore(tzun: Tzun): Promise<string> {
  const ids: string[] = [];
  for (let i = 1; i <= 3; i++) ids.push(await capture(tzun, 'default', i));
  const storage = tzun.getStorage();
  await storage.storeChain({ chainId: 'tenant-b', status: 'active', createdAt: new Date().toISOString() });
  await rewriteStoredEnvelope(storage, ids[2], (e) => { e.integrity.chainLink = 'TAMPERED'; });
  return ids[2];
}

describe.each(backends)('verifyAllChains() on %s — walks every record in the store', (backend) => {
  let dbPath: string | undefined;
  let tzun: Tzun;

  beforeEach(async () => {
    dbPath = backend === 'sqlite' ? tmpDbPath('verify') : undefined;
    tzun = await boot(dbPath);
  });

  afterEach(async () => {
    await tzun.close();
    if (dbPath) cleanup(dbPath);
  });

  it('the implicit default chain stays in the walk once a non-default row exists, and its tampered link is reported', async () => {
    const tamperedId = await addendumStore(tzun);

    // The precondition: the SDK believes `tenant-b` is the active chain while
    // the records sit on the implicit default chain. The SDK's own adapters
    // refuse such a restart as ambiguous — but the walk must be whole-store
    // whatever it was told is active, because a consumer's own StorageAdapter
    // (the platform's resolves chains its own way) can name any chain. So the
    // belief is set directly, and what is asserted is that it changes nothing
    // about coverage.
    (tzun as unknown as { activeChainId: string }).activeChainId = 'tenant-b';

    const result = await tzun.verifyAllChains();

    // Both chains are walked, not only the one the SDK believes is active.
    expect(result.chains.map((c) => c.chainId).sort()).toEqual(['default', 'tenant-b']);
    const byId = new Map(result.chains.map((c) => [c.chainId, c]));
    // `tenant-b` has never held a record, so it has no high-water mark and it is
    // vacuously valid. That is only sound because the bound is attributed PER
    // CHAIN: one counter read for whichever chain the SDK believes is
    // active — this chain, here — would hand the empty chain the DEFAULT
    // chain's bound of 3, and since an empty range with a bound reports its
    // whole range missing, it would read as a chain whose three records had
    // been destroyed.
    expect(await tzun.getStorage().getLastSequence('tenant-b')).toBe(0);
    expect(byId.get('tenant-b')).toMatchObject({ valid: true, totalRecords: 0 });
    expect(byId.get('tenant-b')!.sequenceGaps).toEqual([]);
    expect(byId.get('default')).toMatchObject({ valid: false, totalRecords: 3 });
    expect(byId.get('default')!.brokenLinks).toContain(tamperedId);
    expect(result.valid).toBe(false);
    expect(result.activeChainId).toBe('tenant-b');
    expect(result.active.chainId).toBe('tenant-b');

    // Non-vacuity: every record in the store was walked by exactly one chain
    // result.
    const walked = result.chains.reduce((n, c) => n + c.totalRecords, 0);
    expect(walked).toBe((await tzun.getStorage().list({})).length);
    expect(walked).toBe(3);
  });

  it('a chain whose every record is deleted is NOT the same answer as a chain that was always empty', async () => {
    // The distinction the per-chain bound buys, and the reason an empty range
    // with a bound is still checked: both chains hold zero records at walk
    // time, and only one of them ever did.
    await addendumStore(tzun);
    const storage = tzun.getStorage();
    for (const record of await storage.list({ chainId: 'default' })) {
      await deleteStoredEnvelope(storage, record.payload.evidenceId);
    }
    expect(await storage.getChainLength('default')).toBe(0);
    // The high-water mark does not fall with the rows. That is what remembers.
    expect(await storage.getLastSequence('default')).toBe(3);

    const result = await tzun.verifyAllChains();
    const byId = new Map(result.chains.map((c) => [c.chainId, c]));
    expect(byId.get('default')).toMatchObject({ valid: false, totalRecords: 0 });
    expect(byId.get('default')!.sequenceGaps).toEqual([1, 2, 3]);
    expect(byId.get('tenant-b')).toMatchObject({ valid: true, totalRecords: 0 });
    expect(byId.get('tenant-b')!.sequenceGaps).toEqual([]);
    expect(result.valid).toBe(false);
  });

  it('the scanner resolves the same chain set, so it does not go dark on the implicit chain either', async () => {
    await addendumStore(tzun);
    // Scopes of [tenant-b] alone would leave three records with no scanner
    // over them.
    const scopes = await resolveChainScopes(tzun.getStorage());
    expect(scopes.map((s) => s.chainId).sort()).toEqual(['default', 'tenant-b']);
  });

  it('(b) default + one forked chain: a tampered default-chain record is reported, named as default, and nothing is skipped', async () => {
    // Fork registers both chains, so both are walked. Pinned so a change to
    // chain resolution cannot break the fork path.
    const ids: string[] = [];
    for (let i = 1; i <= 3; i++) ids.push(await capture(tzun, 'old', i));
    const fork = await tzun.recovery.fork('inc-active-chain-b', {
      authorizedBy: 'admin@acme.example',
      reason: 'Rotating the chain.',
      forkAfterSequence: 3,
    });
    for (let i = 1; i <= 2; i++) await capture(tzun, 'new', i);
    await rewriteStoredEnvelope(tzun.getStorage(), ids[1], (e) => { e.payload.reason = 'rewritten after the seal'; });

    const result = await tzun.verifyAllChains();
    expect(result.valid).toBe(false);
    expect(result.chains.map((c) => c.chainId).sort()).toEqual(['default', fork.newChain.chainId].sort());
    const byId = new Map(result.chains.map((c) => [c.chainId, c]));
    expect(byId.get('default')).toMatchObject({ valid: false, totalRecords: 3 });
    expect(byId.get('default')!.digestMismatches).toEqual([ids[1]]);
    expect(byId.get(fork.newChain.chainId)).toMatchObject({ valid: true, totalRecords: 2 });
    expect(result.active.chainId).toBe(fork.newChain.chainId);
    const walked = result.chains.reduce((n, c) => n + c.totalRecords, 0);
    expect(walked).toBe((await tzun.getStorage().list({})).length);
    expect(walked).toBe(5);
  });
});
