// `fork()` reads the sealed chain's head AFTER `sealChain()`, so the head on
// the fork record covers every record the chain accepted. Companion to
// `sealed-chain-bound-is-a-sequence.test.ts`.
//
// The fork record carries the sealed chain's head sequence, and every
// sealed-chain verifier is bounded by it. Until the seal, the old chain is
// still the active one and still accepts appends — from any other client on
// the same store, or from a stale one holding the old chain id — so a head
// (and row count) read before the seal can miss a capture that lands at
// head+1 in between. The fork record would then say the chain reached N when
// it reached N+1, and record N+1 would sit outside every range
// `verifyChainCompleteness()`, `relink()` and the scanner walk for that
// chain: exactly one record, at the tail, which is where truncation shows.
//
// `store()` refuses appends to a sealed chain INSIDE its own write transaction
// (`assertChainNotSealed`, applied under SQLite's IMMEDIATE transaction), so a
// head read AFTER the seal is exact: nothing can land between that read and
// the fork record. The SDK's `resetChainState()` only runs after `fork()`
// returns, so the live counter is still the sealed chain's own at that point.
//
// This file drives the window on a real SQLite file with two SDK instances —
// one running the fork, one still capturing — and lets the second one land a
// record while the first is about to seal. With the head read before the
// seal, the fork records `sealedOldChainHead` 5 with six records in the chain,
// and `verifyChainCompleteness(sealed)` after deleting record 6 reports
// `sequenceGaps: []`, `valid: true`.
import Database from 'better-sqlite3';
import { withSqliteEnvelopeTriggersLifted } from './helpers/tamper-store';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Tzun } from '../../src/sdk/index';

function tmpDbPath(label: string): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-race-')), `${label}.db`);
}

function cleanup(dbPath: string): void {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
  }
  try { fs.rmdirSync(path.dirname(dbPath)); } catch { /* ignore */ }
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

describe('sealed-chain bound: fork() reads the sealed chain head AFTER the seal (SQLite)', () => {
  let dbPath: string;
  beforeEach(() => { dbPath = tmpDbPath('head-after-seal'); });
  afterEach(() => cleanup(dbPath));

  it('a capture that lands between the head read and the seal is inside the recorded head, and its deletion is detected', async () => {
    // `admin` runs the fork. `writer` is another client of the same store —
    // a second process, or a stale one — still capturing into the chain the
    // fork is about to seal. Both are opened the way an integrator opens the
    // SDK; nothing is hand-constructed.
    const admin = await Tzun.init({ dbPath });
    const writer = await Tzun.init({ dbPath });
    const ids = new Map<number, string>();
    let sealedChainId: string;
    let forkHead: number | undefined;
    let forkLength: number;
    try {
      for (let i = 1; i <= 5; i++) {
        const result = await writer.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `record-${i}` });
        expect(result.failure).toBeUndefined();
        expect(result.stored).toBe(true);
        ids.set(result.envelope.payload.sequenceNumber, result.envelope.payload.evidenceId);
      }
      sealedChainId = await admin.getActiveChainId();

      // Wrap the seal on the adapter `fork()` actually uses: let one more
      // capture land in the old chain immediately before the seal is written.
      // This is the widest the window can be — the read has happened, the
      // seal has not.
      const storage = admin.getStorage();
      const realSeal = storage.sealChain.bind(storage);
      let landedInWindow = 0;
      storage.sealChain = async (chainId: string, sealedAt: string) => {
        const result = await writer.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i: 6 }, action: 'approved', reason: 'record-6' });
        expect(result.failure).toBeUndefined();
        expect(result.stored).toBe(true);
        expect(result.envelope.payload.sequenceNumber).toBe(6);
        ids.set(6, result.envelope.payload.evidenceId);
        landedInWindow += 1;
        return realSeal(chainId, sealedAt);
      };

      const forked = await admin.recovery.fork('inc-sealed-bound-race', {
        authorizedBy: 'admin@acme.example',
        reason: 'Sealing while another writer is still capturing.',
        forkAfterSequence: 3,
      });
      expect(landedInWindow).toBe(1);
      expect(forked.oldChain.status).toBe('sealed');
      forkHead = forked.fork.sealedOldChainHead;
      forkLength = forked.fork.sealedOldChainLength;

      // The seal is what closes the window: the same writer is refused now.
      // `store()` throws from inside its write transaction and `capture()`
      // reports it as a `chain_sealed` failure record rather than throwing.
      const refused = await writer.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i: 7 }, action: 'approved', reason: 'record-7' });
      expect(refused.stored).toBe(false);
      expect(refused.failure?.failureType).toBe('chain_sealed');
      expect(refused.failure?.diagnosticMetadata?.chainId).toBe(sealedChainId);
      expect(refused.failure?.diagnosticMetadata?.reason).toMatch(/is sealed and cannot accept new records/);
      expect(await storage.getChainLength(sealedChainId)).toBe(6);
    } finally {
      await writer.close();
      await admin.close();
    }

    // Six records reached the sealed chain, so its head is 6. Read before the
    // seal, the head (and the count) would be 5 and 5.
    expect(forkHead).toBe(6);
    expect(forkLength!).toBe(6);

    // The user-observable consequence: delete the record that landed in the
    // window and the sealed chain's verifier must see it go. With a recorded
    // head of 5, sequence 6 would never be expected and its absence never
    // reported — `sequenceGaps: []`, `valid: true`.
    deleteOnDisk(dbPath, ids.get(6)!);
    const reopened = await Tzun.init({ dbPath });
    try {
      expect(await reopened.getActiveChainId()).not.toBe(sealedChainId!);
      const result = await reopened.verifyChainCompleteness(sealedChainId!);
      expect(result.valid).toBe(false);
      expect(result.sequenceGaps).toEqual([6]);
      expect(result.lastRecord).toBe(5);
      expect(result.totalRecords).toBe(5);

      // And the range the new chain's fork record describes is the whole
      // sealed chain, so the chain_forked custody entries reached record 6's
      // neighbours too: records after the fork point are 4, 5 and 6.
      const stored = await reopened.getStorage().listForksForChain(sealedChainId!);
      expect(stored).toHaveLength(1);
      expect(stored[0].sealedOldChainHead).toBe(6);
      expect(stored[0].sealedOldChainLength).toBe(6);
    } finally {
      await reopened.close();
    }
  });
});
