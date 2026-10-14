// The scheduled scanner walks each chain of a forked store separately, in that
// chain's own sequence order.
//
// `recovery.fork()` seals the old chain and restarts the new one at
// sequenceNumber 1, so after a fork both chains hold a record 1 and a
// record 2. A pass that read them as one interleaved sequence would raise
// duplicate_sequence and chain_break incidents on a store nobody touched,
// every one fabricated. That is the alert an operator learns to dismiss, and
// dismissing it is what makes the next real chain_break invisible. These cases
// pin zero incidents on an untampered forked store, and that tampering on
// either chain, and a deleted record on the sealed chain, are still caught.
import { Tzun } from '../../src/sdk/index';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
// These cases tamper by rewriting the stored row itself, through
// `rewriteStoredEnvelope`, which works on every backend. The memory adapter
// clones on read and write, as the SQL adapters do, so mutating an object a
// read returned would change nothing in the store and leave the detection
// under test with nothing to detect.
import { TamperIncident } from '@tzun/engine';

const scannerConfig = {
  batchSize: 100,
  workers: 2,
  mode: 'interval' as const,
  intervalMs: 0,
  verifyAttestation: false,
  verifyChainCompleteness: true,
};

async function forkedStoreWithScanner(): Promise<{
  tzun: Tzun;
  sealedChainId: string;
  activeChainId: string;
}> {
  const tzun = await Tzun.init({
    verifyReads: false,
    monitoring: { enabled: true, scanner: scannerConfig },
  });
  for (let i = 1; i <= 3; i++) {
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { old: i }, action: 'approved', reason: `old-${i}` });
  }
  const sealedChainId = await tzun.getActiveChainId();
  const fork = await tzun.recovery.fork('inc-post-fork', {
    authorizedBy: 'admin@acme.example',
    reason: 'Chain compromised',
    forkAfterSequence: 1,
  });
  for (let i = 1; i <= 2; i++) {
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { fresh: i }, action: 'approved', reason: `new-${i}` });
  }
  return { tzun, sealedChainId, activeChainId: fork.newChain.chainId };
}

describe('scheduled scanner after recovery.fork()', () => {
  it('a full pass over an untampered two-chain store raises ZERO incidents', async () => {
    const { tzun } = await forkedStoreWithScanner();
    try {
      await tzun.runScan();
      const incidents = await tzun.getStorage().listIncidents();
      expect(incidents.map((i: TamperIncident) => i.type)).toEqual([]);
    } finally {
      await tzun.close();
    }
  });

  it('the SEALED chain is still scanned — tampering there is caught, not scoped away', async () => {
    const { tzun, sealedChainId } = await forkedStoreWithScanner();
    try {
      // Rewrite a payload field on a sealed-chain record without touching its
      // stored digest. This is the digest_mismatch shape.
      const storage = tzun.getStorage();
      const sealed = await storage.listBySequence(1, 10, sealedChainId);
      expect(sealed).toHaveLength(3);
      await rewriteStoredEnvelope(storage, sealed[2].payload.evidenceId, (e) => { e.payload.reason = 'rewritten after sealing'; });

      await tzun.runScan();

      const incidents = await tzun.getStorage().listIncidents();
      const mismatches = incidents.filter((i: TamperIncident) => i.type === 'digest_mismatch');
      expect(mismatches).toHaveLength(1);
      expect(mismatches[0].affectedRecords).toEqual([sealed[2].payload.evidenceId]);
    } finally {
      await tzun.close();
    }
  });

  it('a real break on the ACTIVE chain is still caught after a fork', async () => {
    const { tzun, activeChainId } = await forkedStoreWithScanner();
    try {
      const storage = tzun.getStorage();
      const active = await storage.listBySequence(1, 10, activeChainId);
      expect(active).toHaveLength(2);
      await rewriteStoredEnvelope(storage, active[1].payload.evidenceId, (e) => { e.integrity.chainLink = 'a'.repeat(64); });

      await tzun.runScan();

      const incidents = await tzun.getStorage().listIncidents();
      const breaks = incidents.filter((i: TamperIncident) => i.type === 'chain_break');
      expect(breaks).toHaveLength(1);
      expect(breaks[0].affectedRecords).toEqual([active[1].payload.evidenceId]);
      // And nothing else was invented alongside it.
      expect(incidents).toHaveLength(1);
    } finally {
      await tzun.close();
    }
  });

  it('a deleted record on the SEALED chain is still reported as a gap', async () => {
    const { tzun, sealedChainId } = await forkedStoreWithScanner();
    try {
      const storage = tzun.getStorage();
      const sealed = await storage.listBySequence(1, 10, sealedChainId);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const envelopes = (storage as any).envelopes as Map<string, unknown>;
      envelopes.delete(sealed[1].payload.evidenceId);

      await tzun.runScan();

      const incidents = await tzun.getStorage().listIncidents();
      const gaps = incidents.filter((i: TamperIncident) => i.type === 'sequence_gap');
      // Non-vacuity: the sealed chain's upper bound came from the fork record's
      // sealedOldChainLength, not from the live chain_state counter, which was
      // reset to the new chain when the fork happened.
      expect(gaps.length).toBeGreaterThan(0);
    } finally {
      await tzun.close();
    }
  });

  it('a store that never forked scans clean, and a tamper on it raises one digest_mismatch', async () => {
    const tzun = await Tzun.init({
      verifyReads: false,
      monitoring: { enabled: true, scanner: scannerConfig },
    });
    try {
      for (let i = 1; i <= 4; i++) {
        await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `r-${i}` });
      }
      await tzun.runScan();
      expect(await tzun.getStorage().listIncidents()).toEqual([]);

      const records = await tzun.getStorage().listBySequence(1, 10);
      await rewriteStoredEnvelope(tzun.getStorage(), records[2].payload.evidenceId, (e) => { e.payload.reason = 'tampered'; });
      await tzun.runScan();
      const incidents = await tzun.getStorage().listIncidents();
      expect(incidents).toHaveLength(1);
      expect(incidents[0].type).toBe('digest_mismatch');
    } finally {
      await tzun.close();
    }
  });
});
