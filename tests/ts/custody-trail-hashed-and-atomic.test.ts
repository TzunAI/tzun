/**
 * SDK-local custody entries are hashed, chained, ledgered and written
 * atomically (the writer); verifyEnvelope checks them (the reader).
 *
 * WHY IT MATTERS. `custodyChain` is outside the hashed field set, so without
 * a hash chain nothing would bind a custody entry to the record, to its
 * neighbours, or to the RelinkRecord: an insider who deleted the `relinked`
 * entry would leave a record that presents as never repaired. And if the link
 * update, the recovery record and each custody append were separate writes, a
 * crash between them would leave rewritten links with no trace of who
 * rewrote them. So `RecoveryManager.relink/fork/annotate` append hashed,
 * chained custody entries, ledgered as `custody_entries` rows and written in
 * one transaction with the link update and the recovery record, on the SDK's
 * SQLite, Postgres and memory adapters. The hosted service chains its custody
 * entries by the same rule, byte for byte
 * (vectors/custody-entry-hash-vectors.json).
 *
 * Legs: memory and sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own,
 * emptied before each case.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  assembleEnvelope,
  computeCustodyEntryHash,
  isHashedCustodyEntry,
  SchemaRegistry,
  verifyCustodyTrail,
  verifyEnvelope,
} from '@tzun/engine';
import type {
  EnvelopeInput,
  CustodyEntry,
  EvidenceEnvelope,
  RelinkRecord,
  StorageAdapter,
  TamperIncident,
} from '@tzun/engine';
import { RecoveryManager } from '../../src/monitoring/recovery-manager';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { rewriteStoredEnvelope } from './helpers/tamper-store';

const HEX64 = /^[0-9a-f]{64}$/;
const CHAIN = 'chain-001';
const registry = new SchemaRegistry();

const input: EnvelopeInput = {
  aiSystemId: 'test-system',
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Test',
  decider: { kind: 'human' as const, id: 'acct:tester-acme.com', agent: null, credential: null, freshness: null },
};

function incidentFor(evidenceIds: string[], id = 'inc-001'): TamperIncident {
  return {
    id,
    detectedAt: new Date().toISOString(),
    severity: 'critical',
    type: 'chain_break',
    affectedRecords: evidenceIds,
    details: 'Chain break detected during scan.',
    status: 'open',
  };
}

async function captureSequence(adapter: StorageAdapter, count: number): Promise<EvidenceEnvelope[]> {
  const envelopes: EvidenceEnvelope[] = [];
  let previousDigest: string | undefined;
  for (let i = 1; i <= count; i++) {
    const envelope = assembleEnvelope(input, { previousDigest: previousDigest, sequenceNumber: i });
    previousDigest = envelope.integrity.canonicalDigest;
    await adapter.store(envelope, CHAIN);
    envelopes.push(envelope);
  }
  return envelopes;
}

interface Leg {
  name: 'memory' | 'sqlite' | 'postgres';
  make: () => Promise<{ adapter: StorageAdapter; teardown: () => Promise<void> }>;
  /** Attack the ledger directly, behind the adapter's back. Undefined when the backend has no such path. */
  rawDeleteRow?: (adapter: StorageAdapter, evidenceId: string) => Promise<void>;
  rawUpdateRow?: (adapter: StorageAdapter, evidenceId: string) => Promise<void>;
}

const memoryLeg: Leg = {
  name: 'memory',
  make: async () => {
    const adapter = new MemoryStorageAdapter();
    return { adapter, teardown: async () => adapter.close() };
  },
};

const sqliteLeg: Leg = {
  name: 'sqlite',
  make: async () => {
    const dbPath = path.join(os.tmpdir(), `tzun-test-custody-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    const adapter = new SqliteStorageAdapter(dbPath);
    return {
      adapter,
      teardown: async () => {
        adapter.close();
        for (const suffix of ['', '-wal', '-shm']) {
          try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
        }
      },
    };
  },
  rawDeleteRow: async (adapter, evidenceId) => {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    db.prepare('DELETE FROM custody_entries WHERE evidence_id = ?').run(evidenceId);
  },
  rawUpdateRow: async (adapter, evidenceId) => {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    db.prepare("UPDATE custody_entries SET actor = 'mallory' WHERE evidence_id = ?").run(evidenceId);
  },
};

// A schema of this file's own, emptied before each Postgres case.
const pgSchema = pgSuiteSchema('custody_trail_atomic');

const postgresLeg: Leg = {
  name: 'postgres',
  make: async () => {
    await pgSchema.empty();
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    return { adapter, teardown: async () => adapter.close() };
  },
  rawDeleteRow: async (adapter, evidenceId) => {
    const pool = (adapter as unknown as { pool: import('pg').Pool }).pool;
    await pool.query('DELETE FROM custody_entries WHERE evidence_id = $1', [evidenceId]);
  },
  rawUpdateRow: async (adapter, evidenceId) => {
    const pool = (adapter as unknown as { pool: import('pg').Pool }).pool;
    await pool.query("UPDATE custody_entries SET actor = 'mallory' WHERE evidence_id = $1", [evidenceId]);
  },
};

const legs: Leg[] = PG_TESTS_ENABLED ? [memoryLeg, sqliteLeg, postgresLeg] : [memoryLeg, sqliteLeg];

/**
 * The message the database refused a raw statement with — asserted on the
 * message, deliberately NOT via `rejects.toThrow`.
 *
 * `expect(p).rejects.toThrow()` only inspects a rejection jest recognises as
 * an Error (`@jest/expect-utils` `isError`: `Object.prototype.toString` tag
 * `[object Error]`, else `instanceof Error`). A better-sqlite3 `SqliteError`
 * satisfies neither once another test file has opened a database in the same
 * jest worker: the addon pins its error constructor process-wide the first
 * time any file opens a database (`addon.isInitialized`), so every later file
 * in that worker gets errors built by the FIRST file's `SqliteError` — a
 * function whose prototype chain roots in that file's vm-context `Error`,
 * not this one's — and `SqliteError` is built with `Error.call(this)`, so the
 * object carries no [[ErrorData]] slot and its toString tag is
 * `[object Object]`. `rejects.toThrow` then reports "Received function did
 * not throw" for a DELETE the trigger DID refuse. It passes whenever this
 * file is first in its worker (every `--runInBand` run of the file alone),
 * which makes the failure look like a flake. Reading `.message` off the rejection
 * is realm-independent.
 */
async function refusalMessage(run: () => Promise<void>): Promise<string> {
  try {
    await run();
  } catch (err) {
    const message = (err as { message?: unknown } | null)?.message;
    return typeof message === 'string' ? message : String(err);
  }
  throw new Error('expected the statement to be refused, but it went through');
}

describe.each(legs)('custody trail is hashed, chained, ledgered and atomic — $name adapter', (leg) => {
  let adapter: StorageAdapter;
  let teardown: () => Promise<void>;
  let manager: RecoveryManager;
  let envelopes: EvidenceEnvelope[];
  let target: string;

  beforeEach(async () => {
    ({ adapter, teardown } = await leg.make());
    manager = new RecoveryManager(adapter, registry);
    envelopes = await captureSequence(adapter, 5);
    target = envelopes[2].payload.evidenceId;
    await adapter.storeIncident(incidentFor([target]));
    // The honest break relink() exists to repair: record 3's link corrupted in the store.
    await rewriteStoredEnvelope(adapter, target, (e) => { e.integrity.chainLink = 'tampered-link'; });
  });

  afterEach(async () => {
    await teardown();
  });

  const relink = () => manager.relink('inc-001', { authorizedBy: 'admin@acme.example', chainId: CHAIN, fromSequence: 3 });
  const prevDigestOfTarget = () => envelopes[1].integrity.canonicalDigest;

  it('relink appends a hashed, chained custody entry mirrored from a custody_entries row', async () => {
    const result = await relink();
    expect(result.relink.modifiedLinks.map((l) => l.evidenceId)).toEqual([target]);

    const stored = (await adapter.retrieve(target))!;
    expect(stored.integrity.chainLink).not.toBe('tampered-link');
    const entry = stored.custodyChain[stored.custodyChain.length - 1];
    expect(entry.action).toBe('relinked');
    expect(entry.entryHash).toMatch(HEX64);
    expect(entry.prevEntryHash).toBeNull();
    expect(isHashedCustodyEntry(entry)).toBe(true);
    // The hash recomputes from the entry's own fields, the record's id and its digest — the one engine rule.
    expect(entry.entryHash).toBe(computeCustodyEntryHash({
      prevEntryHash: null,
      evidenceId: target,
      canonicalDigest: stored.integrity.canonicalDigest,
      action: entry.action,
      actor: entry.actor,
      timestamp: entry.timestamp,
      systemId: entry.systemId,
      metadata: entry.metadata,
    }));
    expect((entry.metadata as Record<string, unknown>).relinkId).toBe(result.relink.id);

    // The ledger row behind it.
    const rows = await adapter.listCustodyEntries(target);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      evidenceId: target,
      chainId: CHAIN,
      canonicalDigest: stored.integrity.canonicalDigest,
      action: 'relinked',
      actor: 'admin@acme.example',
      timestamp: entry.timestamp,
      systemId: 'tzun-recovery',
      metadata: entry.metadata,
      prevEntryHash: null,
      entryHash: entry.entryHash,
      recoveryId: result.relink.id,
    });
    expect(await adapter.getRelink(result.relink.id)).toEqual(result.relink);

    // And the offline verifier agrees.
    const v = verifyEnvelope(stored, prevDigestOfTarget(), registry);
    expect(v.verified).toBe(true);
    expect(v.chainLinkValid).toBe(true);
    expect(v.custodyTrailValid).toBe(true);
    expect(v.custodyTrailFailures).toBeUndefined();
  });

  it('annotate after relink chains to the relinked entry; each row names its recovery record', async () => {
    const { relink: rec } = await relink();
    const { annotation } = await manager.annotate('inc-001', { authorizedBy: 'reviewer@acme.example', notes: 'seen' });
    const stored = (await adapter.retrieve(target))!;
    const [, relinked, reviewed] = stored.custodyChain;
    expect(reviewed.action).toBe('reviewed');
    expect(reviewed.prevEntryHash).toBe(relinked.entryHash);
    expect(reviewed.entryHash).toMatch(HEX64);
    const rows = await adapter.listCustodyEntries(target);
    expect(rows.map((r) => [r.action, r.prevEntryHash, r.recoveryId])).toEqual([
      ['relinked', null, rec.id],
      ['reviewed', relinked.entryHash, annotation.id],
    ]);
    expect(rows[1].id).toBeGreaterThan(rows[0].id);
    expect(verifyCustodyTrail(stored)).toEqual({ valid: true, hashedEntries: 2, unhashedEntries: 1, failures: [] });
  });

  it('fork appends hashed chain_forked entries bound to the fork record', async () => {
    // captureSequence stored under CHAIN; fork seals the ACTIVE chain
    // ('default'), and records after the fork point on THAT chain get the
    // entry — so put one there first, before the seal refuses appends.
    //
    // CHAIN is register-then-sealed first. Both CHAIN and 'default' would
    // otherwise be implicit chains HOLDING RECORDS and so both would accept
    // appends, which `getActiveChainId()` refuses as
    // `AmbiguousActiveChainError` rather than silently answering 'default' —
    // and `fork()` refuses rather than seal a chain it had to guess. These two
    // statements are the remedy that error names ("register-
    // then-seal an identity for an implicit chain that is finished"), and they
    // say out loud which chain this test means by "the active chain": the five
    // records of the shared fixture are on a finished chain, the fork is about
    // 'default'. Nothing about the custody append changes.
    await adapter.storeChain({ chainId: CHAIN, status: 'active', createdAt: new Date(0).toISOString() });
    await adapter.sealChain(CHAIN, new Date().toISOString());
    const onDefault = assembleEnvelope(input, { sequenceNumber: 1 });
    await adapter.store(onDefault);
    const { fork } = await manager.fork('inc-001', { authorizedBy: 'admin@acme.example', reason: 'seal it', forkAfterSequence: 0 });
    const stored = (await adapter.retrieve(onDefault.payload.evidenceId))!;
    expect(stored.custodyChain).toHaveLength(2);
    const entry = stored.custodyChain[1];
    expect(entry.action).toBe('chain_forked');
    expect(entry.entryHash).toMatch(HEX64);
    expect(entry.prevEntryHash).toBeNull();
    expect((entry.metadata as Record<string, unknown>).forkId).toBe(fork.id);
    expect((await adapter.listCustodyEntries(onDefault.payload.evidenceId))[0]).toMatchObject({
      action: 'chain_forked', recoveryId: fork.id, entryHash: entry.entryHash, chainId: 'default',
    });
    expect(verifyEnvelope(stored, undefined, registry).custodyTrailValid).toBe(true);
  });

  it('(1) rewriting the entry\'s actor in the envelope makes recomputation fail: custodyTrailValid false', async () => {
    await relink();
    const before = verifyEnvelope((await adapter.retrieve(target))!, prevDigestOfTarget(), registry);
    expect(before.custodyTrailValid).toBe(true);

    await rewriteStoredEnvelope(adapter, target, (e) => {
      e.custodyChain[e.custodyChain.length - 1].actor = 'mallory@acme.example';
    });

    const after = verifyEnvelope((await adapter.retrieve(target))!, prevDigestOfTarget(), registry);
    expect(after.custodyTrailValid).toBe(false);
    expect(after.custodyTrailFailures).toEqual([{ reason: 'entry_hash_mismatch', index: 1 }]);
    // The decision record itself is intact; that is what `verified` still says.
    expect(after.verified).toBe(true);
    // The ledger still names the honest actor — the row is the evidence the mirror was edited.
    expect((await adapter.listCustodyEntries(target))[0].actor).toBe('admin@acme.example');
  });

  it('(1b) deleting the mirrored entry from the envelope leaves a ledger row that names the repair', async () => {
    const { relink: rec } = await relink();
    await rewriteStoredEnvelope(adapter, target, (e) => { e.custodyChain.pop(); });
    const stored = (await adapter.retrieve(target))!;
    // Offline, with the envelope alone, the last entry's removal is invisible
    // by construction (nothing after it names its hash) — the verdict is
    // "unverified", never "valid"; the ledger row is what catches it.
    expect(verifyEnvelope(stored, prevDigestOfTarget(), registry).custodyTrailValid).toBeNull();
    const rows = await adapter.listCustodyEntries(target);
    expect(rows).toHaveLength(1);
    expect(rows[0].recoveryId).toBe(rec.id);
    expect(stored.custodyChain.some((e) => e.entryHash === rows[0].entryHash)).toBe(false);
  });

  it('(2) a custody_entries row cannot be deleted or rewritten', async () => {
    await relink();
    if (leg.rawDeleteRow && leg.rawUpdateRow) {
      const { rawDeleteRow, rawUpdateRow } = leg;
      expect(await refusalMessage(() => rawDeleteRow(adapter, target))).toMatch(/append-only/);
      expect(await refusalMessage(() => rawUpdateRow(adapter, target))).toMatch(/append-only/);
      const rows = await adapter.listCustodyEntries(target);
      expect(rows).toHaveLength(1);
      expect(rows[0].actor).toBe('admin@acme.example');
    } else {
      // Memory: no SQL to attack. Assert there is no delete/rewrite path at
      // all — nothing on the adapter names a custody row for removal or
      // update, and the adapter sources issue no such statement.
      const methods = new Set<string>();
      for (let proto = Object.getPrototypeOf(adapter); proto && proto !== Object.prototype; proto = Object.getPrototypeOf(proto)) {
        for (const name of Object.getOwnPropertyNames(proto)) methods.add(name);
      }
      const suspicious = [...methods].filter((m) => /custody/i.test(m) && /delete|remove|update|rewrite|truncate|clear|reset/i.test(m));
      expect(suspicious).toEqual([]);
      for (const file of ['memory.ts', 'sqlite.ts', 'postgres.ts']) {
        const src = readFileSync(join(__dirname, '..', '..', 'src', 'storage', file), 'utf-8');
        expect({ file, deletes: /DELETE\s+FROM\s+custody_entries/i.test(src) }).toEqual({ file, deletes: false });
        expect({ file, updates: /UPDATE\s+custody_entries\s+SET/i.test(src) }).toEqual({ file, updates: false });
        expect({ file, truncates: /TRUNCATE\s+custody_entries/i.test(src) }).toEqual({ file, truncates: false });
      }
    }
  });

  it('(3) a failure after the link update rolls everything back: no link change, no relink record, no custody row', async () => {
    // Drive the adapter's transaction directly with a custody list whose LAST
    // item names a record that does not exist. The links and the relink
    // record have already been written by the time the append throws, so all
    // three must roll back together or the store keeps a repair nobody is
    // recorded as making.
    const relinkRecord: RelinkRecord = {
      id: 'rlk-crash',
      incidentId: 'inc-001',
      relinkedAt: new Date().toISOString(),
      relinkedBy: 'admin@acme.example',
      fromSequence: 3,
      toSequence: 5,
      modifiedLinks: [{ evidenceId: target, sequenceNumber: 3, previousChainLink: 'tampered-link', newChainLink: 'repaired-link' }],
    };
    const entry: CustodyEntry = { timestamp: relinkRecord.relinkedAt, actor: 'admin@acme.example', action: 'relinked', systemId: 'tzun-recovery' };
    await expect(adapter.applyRelink(relinkRecord, [
      { evidenceId: target, entry },
      { evidenceId: 'ghost', entry },
    ])).rejects.toThrow('Evidence record "ghost" not found.');

    const stored = (await adapter.retrieve(target))!;
    expect(stored.integrity.chainLink).toBe('tampered-link');
    expect(stored.custodyChain).toHaveLength(1);
    expect(await adapter.getRelink('rlk-crash')).toBeNull();
    expect(await adapter.listCustodyEntries(target)).toEqual([]);

    // And a duplicate relink id is refused before anything lands.
    await adapter.storeRelink({ ...relinkRecord, id: 'rlk-dup', modifiedLinks: [] });
    await expect(adapter.applyRelink({ ...relinkRecord, id: 'rlk-dup' }, [{ evidenceId: target, entry }]))
      .rejects.toThrow(/already exists|duplicate/i);
    expect((await adapter.retrieve(target))!.integrity.chainLink).toBe('tampered-link');
    expect(await adapter.listCustodyEntries(target)).toEqual([]);
  });

  it('(4) reordering or deleting a middle entry, or appending an unhashed one after, is caught offline', async () => {
    await relink();
    await manager.annotate('inc-001', { authorizedBy: 'reviewer@acme.example', notes: 'seen' });
    const clean = (await adapter.retrieve(target))!;
    expect(verifyCustodyTrail(clean).valid).toBe(true);

    const swapped = JSON.parse(JSON.stringify(clean)) as EvidenceEnvelope;
    [swapped.custodyChain[1], swapped.custodyChain[2]] = [swapped.custodyChain[2], swapped.custodyChain[1]];
    expect(verifyCustodyTrail(swapped).valid).toBe(false);

    const forged = JSON.parse(JSON.stringify(clean)) as EvidenceEnvelope;
    forged.custodyChain.push({ timestamp: 't', actor: 'mallory', action: 'reviewed', systemId: 'x' });
    expect(verifyCustodyTrail(forged).failures).toEqual([{ reason: 'unhashed_after_hashed', index: 3 }]);
  });

  it('custodyChain stays OUTSIDE the hashed field set: the repair changes no digest', async () => {
    const digestBefore = envelopes[2].integrity.canonicalDigest;
    await relink();
    await manager.annotate('inc-001', { authorizedBy: 'reviewer@acme.example', notes: 'seen' });
    const stored = (await adapter.retrieve(target))!;
    expect(registry.get('v1.0')!.hashedFieldSet).not.toContain('custodyChain');
    const v = verifyEnvelope(stored, prevDigestOfTarget(), registry);
    expect(v.recomputedDigest).toBe(digestBefore);
    expect(v.storedDigest).toBe(digestBefore);
    expect(v.verified).toBe(true);
  });

  it('a record whose trail predates hashing is unverified, never valid', async () => {
    const stored = (await adapter.retrieve(envelopes[0].payload.evidenceId))!;
    expect(verifyEnvelope(stored, undefined, registry).custodyTrailValid).toBeNull();
  });
});

describe('platform parity', () => {
  it('the SDK computes the platform\'s hash for the platform\'s own test fixture', () => {
    // The platform's own test fixture; value computed with the platform's
    // computeCustodyEntryHash.
    expect(computeCustodyEntryHash({
      prevEntryHash: null, evidenceId: 'ev-1', canonicalDigest: 'd'.repeat(64), action: 'relinked',
      actor: 'ünï 😀', timestamp: '2026-09-09T00:00:00.000Z', systemId: 'rec-1', metadata: { newChainId: 'c2' },
    })).toBe('5c7467b1eecfd9f3541d3cf51fa3a68c2eeba4388ccde8b240bf4ed4e882c193');
  });
});

(PG_TESTS_ENABLED ? describe : describe.skip)('postgres: ensureTables adds the ledger to an existing database', () => {
  it('re-creates custody_entries and its guards on a store that predates the ledger', async () => {
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    const pool = (adapter as unknown as { pool: import('pg').Pool }).pool;
    try {
      await pool.query('DROP TABLE IF EXISTS custody_entries CASCADE');
      const gone = await pool.query("SELECT to_regclass('custody_entries') AS t");
      expect(gone.rows[0].t).toBeNull();
      await adapter.ensureTables();
      const back = await pool.query("SELECT to_regclass('custody_entries') AS t");
      expect(back.rows[0].t).toBe('custody_entries');
      const triggers = await pool.query(
        "SELECT tgname FROM pg_trigger WHERE tgrelid = 'custody_entries'::regclass AND NOT tgisinternal ORDER BY tgname",
      );
      expect(triggers.rows.map((r: { tgname: string }) => r.tgname)).toEqual([
        'custody_entries_block_backdated_id_trigger', // no row written ahead of the tail
        'custody_entries_block_mutation_trigger',
        'custody_entries_block_truncate_trigger',
        'custody_entries_verify_insert_trigger', // every inserted row is recomputed
      ]);
      await expect(pool.query('TRUNCATE custody_entries')).rejects.toThrow(/append-only/);
    } finally {
      await adapter.close();
    }
  });
});
