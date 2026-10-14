// The sealed chain's sequence upper bound is a SEQUENCE (the chain's head),
// not a ROW COUNT.
//
// `chainUpperBound()` hands every verifier "the highest sequence this chain
// reached". A row count (`getChainLength()`) agrees with that only while the
// chain has no gaps. On a sealed chain with one gap a row-count bound is short
// by one, so the chain's last record sits outside every sealed-chain range:
// `relink()` reports a range it has not covered, and
// `verifyChainCompleteness()` and the scheduled scanner stop looking one
// record before the tail — which is where tail truncation shows. Delete the
// last record of a gapped sealed chain and nothing would notice.
//
// With a row-count bound, this file's fixture (five captures, record 4
// deleted, fork after 3, record 5 deleted) gives:
//   verifyChainCompleteness(sealed) -> sequenceGaps [4]      (5 never looked at)
//   relink(fromSequence 3)          -> toSequence 4, modifiedLinks []
//
// `fork()` records the sealed chain's HEAD (`sealedOldChainHead`) on the fork
// record and the bound is taken from that; the row count stays on the record
// as `sealedOldChainLength`, a count. `sealedOldChainHead` is optional, so a
// fork row can still reach the store with no head in it; the second half of
// this file drives that fallback on a real file whose chain_forks table cannot
// supply one.
//
// Every case here runs on the SQLite adapter against a temp file, with the
// tampering done to the CLOSED file through better-sqlite3 — an edit made
// outside the SDK, which is what tampering is. The memory adapter keeps fork
// records as objects, with no column to drop, and would not exercise the
// column or the no-head-on-read path at all.
import Database from 'better-sqlite3';
import { withSqliteEnvelopeTriggersLifted } from './helpers/tamper-store';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Tzun } from '../../src/sdk/index';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { chainUpperBound } from '../../src/storage/chain-bounds';
import { ForkRecord, TamperIncident } from '@tzun/engine';

function tmpDbPath(label: string): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-')), `${label}.db`);
}

function cleanup(dbPath: string): void {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
  }
  try { fs.rmdirSync(path.dirname(dbPath)); } catch { /* ignore */ }
}

/** Open the SDK the way an integrator does — nothing hand-constructed. */
function boot(dbPath: string): Promise<Tzun> {
  return Tzun.init({ dbPath });
}

/** Delete one record straight out of the closed database file. */
function deleteOnDisk(dbPath: string, evidenceId: string): void {
  const db = new Database(dbPath);
  try {
    const result = withSqliteEnvelopeTriggersLifted(db, () =>
      db.prepare('DELETE FROM envelopes WHERE evidence_id = ?').run(evidenceId),
    );
    if (result.changes !== 1) throw new Error(`expected to delete 1 row for ${evidenceId}, deleted ${result.changes}`);
  } finally {
    db.close();
  }
}

/**
 * Take the head column off the closed file, so every fork row in it reads back
 * with no head — the state `forkFromRow()` turns into an absent
 * `sealedOldChainHead` key and `chainUpperBound()` recomputes a bound for.
 */
function dropHeadColumnOnDisk(dbPath: string): void {
  const db = new Database(dbPath);
  try {
    db.exec('ALTER TABLE chain_forks DROP COLUMN sealed_old_chain_head');
  } finally {
    db.close();
  }
}

function incidentFor(evidenceIds: string[], id: string): TamperIncident {
  return {
    id,
    detectedAt: new Date().toISOString(),
    severity: 'critical',
    type: 'sequence_gap',
    affectedRecords: evidenceIds,
    details: 'A record was deleted.',
    status: 'open',
  };
}

interface Fixture {
  sealedChainId: string;
  /** sequenceNumber -> evidenceId for the five records as captured. */
  ids: Map<number, string>;
  fork: ForkRecord;
}

/**
 * Five captures; record 4 deleted from the closed file (the gap); fork after 3.
 * The sealed chain then holds sequences 1, 2, 3, 5 — four rows, head 5 — which
 * is exactly the pair of numbers a row-count bound conflates. Record 4 rather than
 * a mid-chain one so the shape matches the demo's phase-4 pin: the orphaned
 * record is the TAIL.
 */
async function gappedThenSealed(dbPath: string, gap = true): Promise<Fixture> {
  let tzun = await boot(dbPath);
  const ids = new Map<number, string>();
  try {
    for (let i = 1; i <= 5; i++) {
      const result = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `record-${i}` });
      expect(result.failure).toBeUndefined();
      expect(result.stored).toBe(true);
      ids.set(result.envelope.payload.sequenceNumber, result.envelope.payload.evidenceId);
    }
  } finally {
    await tzun.close();
  }
  if (gap) deleteOnDisk(dbPath, ids.get(4)!);

  tzun = await boot(dbPath);
  try {
    const sealedChainId = await tzun.getActiveChainId();
    const forked = await tzun.recovery.fork('inc-sealed-bound-fork', {
      authorizedBy: 'admin@acme.example',
      reason: 'A record was deleted; sealing the chain.',
      forkAfterSequence: 3,
    });
    return { sealedChainId, ids, fork: forked.fork };
  } finally {
    await tzun.close();
  }
}

describe('the sealed chain bound is a sequence, not a row count (SQLite)', () => {
  let dbPath: string;
  beforeEach(() => { dbPath = tmpDbPath('sealed-bound'); });
  afterEach(() => cleanup(dbPath));

  it('fork() records the head sequence distinctly from the row count, and the adapter persists it', async () => {
    const { sealedChainId, fork } = await gappedThenSealed(dbPath);

    // Four rows survived, but the chain reached 5. Both numbers are kept, and
    // they are different numbers.
    expect(fork.sealedOldChainLength).toBe(4);
    expect(fork.sealedOldChainHead).toBe(5);

    // Round-trip through the chain_forks table, not just the returned object.
    const adapter = new SqliteStorageAdapter(dbPath);
    try {
      const stored = await adapter.listForksForChain(sealedChainId);
      expect(stored).toHaveLength(1);
      expect(stored[0].sealedOldChainLength).toBe(4);
      expect(stored[0].sealedOldChainHead).toBe(5);
      expect(await adapter.getFork(fork.id)).toEqual(stored[0]);
      expect(await chainUpperBound(adapter, sealedChainId)).toBe(5);
    } finally {
      adapter.close();
    }
  });

  it('verifyChainCompleteness(sealed) reports a deleted TAIL on a sealed chain that has a gap', async () => {
    const { sealedChainId, ids } = await gappedThenSealed(dbPath);
    deleteOnDisk(dbPath, ids.get(5)!);

    const tzun = await boot(dbPath);
    try {
      expect(await tzun.getActiveChainId()).not.toBe(sealedChainId);
      const result = await tzun.verifyChainCompleteness(sealedChainId);
      expect(result.chainId).toBe(sealedChainId);
      expect(result.valid).toBe(false);
      // 4 is the gap; 5 is the deleted tail. A row-count bound (4) would give
      // [4]: sequence 5 would never be expected and its absence never
      // reported.
      expect(result.sequenceGaps).toEqual([4, 5]);
      expect(result.totalRecords).toBe(3);
      expect(result.lastRecord).toBe(3);

      // The all-chains answer carries it too.
      const all = await tzun.verifyAllChains();
      expect(all.valid).toBe(false);
      expect(all.chains.find((c) => c.chainId === sealedChainId)!.sequenceGaps).toEqual([4, 5]);
    } finally {
      await tzun.close();
    }
  });

  it("relink()'s reported range covers the sealed chain's tail, and the orphaned tail is actually re-linked", async () => {
    const { sealedChainId, ids } = await gappedThenSealed(dbPath);

    const tzun = await boot(dbPath);
    try {
      await tzun.getStorage().storeIncident(incidentFor([ids.get(4)!, ids.get(5)!], 'inc-sealed-bound-relink'));
      // From the surviving predecessor of the gap, the way the demo drives it.
      const result = await tzun.recovery.relink('inc-sealed-bound-relink', {
        chainId: sealedChainId,
        fromSequence: 3,
        authorizedBy: 'admin@acme.example',
      });

      // A row-count bound would give toSequence 4 and modifiedLinks [] — the
      // range 3..4 selects record 3 alone, whose link is fine, and the
      // orphaned record 5 is never in the range.
      expect(result.relink.toSequence).toBe(5);
      expect(result.relink.modifiedLinks.map((l) => l.sequenceNumber)).toEqual([5]);
      expect(result.relink.modifiedLinks[0].evidenceId).toBe(ids.get(5));
      expect(result.chainVerified).toBe(true);

      // The tail now links onto record 3, so the sealed chain walks clean
      // apart from the gap it genuinely has.
      const after = await tzun.verifyChainCompleteness(sealedChainId);
      expect(after.brokenLinks).toEqual([]);
      expect(after.sequenceGaps).toEqual([4]);
      expect(after.lastRecord).toBe(5);
    } finally {
      await tzun.close();
    }
  });
});

describe('fork rows with no recorded head (SQLite, recomputed bound)', () => {
  let dbPath: string;
  beforeEach(() => { dbPath = tmpDbPath('headless-fork'); });
  afterEach(() => cleanup(dbPath));

  it('a row with no head reads back with no head, and the bound is recomputed from the records — not the row count', async () => {
    const { sealedChainId, fork } = await gappedThenSealed(dbPath);
    dropHeadColumnOnDisk(dbPath);

    const adapter = new SqliteStorageAdapter(dbPath);
    try {
      const [headless] = await adapter.listForksForChain(sealedChainId);
      expect(headless.id).toBe(fork.id);
      expect(headless.sealedOldChainLength).toBe(4);
      // Absent, not 0 and not null: "no head recorded".
      expect('sealedOldChainHead' in headless).toBe(false);
      expect(await adapter.getFork(fork.id)).toEqual(headless);

      // Sequences 1, 2, 3, 5 are present. The row count says 4; the records
      // say the chain reached 5. Reading the count as the head would leave
      // record 5 outside the range.
      expect(await chainUpperBound(adapter, sealedChainId)).toBe(5);
    } finally {
      adapter.close();
    }

    // And through the SDK: the tail is inside the range.
    const tzun = await boot(dbPath);
    try {
      const result = await tzun.verifyChainCompleteness(sealedChainId);
      expect(result.sequenceGaps).toEqual([4]);
      expect(result.lastRecord).toBe(5);
      expect(result.totalRecords).toBe(4);
    } finally {
      await tzun.close();
    }
  });

  it('a GAPLESS chain with no recorded head still has a deleted tail detected: the row count is kept as a lower bound', async () => {
    // No gap: five rows, head 5, count 5. Where count == head, the count alone
    // is enough to catch a deleted tail. Recomputing purely from surviving
    // records would lose that, so the count stays in as a lower bound on the
    // head — it can never overstate it.
    const { sealedChainId, ids } = await gappedThenSealed(dbPath, false);
    dropHeadColumnOnDisk(dbPath);
    deleteOnDisk(dbPath, ids.get(5)!);

    const tzun = await boot(dbPath);
    try {
      const result = await tzun.verifyChainCompleteness(sealedChainId);
      expect(result.valid).toBe(false);
      expect(result.sequenceGaps).toEqual([5]);
      expect(result.lastRecord).toBe(4);
    } finally {
      await tzun.close();
    }
  });
});
