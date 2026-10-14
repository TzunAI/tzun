// verifyChainCompleteness and verifyRange are chain-scoped, so an untampered
// forked store verifies clean, and tampering on any chain is still reported.
//
// `recovery.fork()` seals the old chain and restarts the new one at
// sequenceNumber 1, so sequence numbers are unique only WITHIN a chain. A walk
// of `listBySequence(1, lastSequence)` with no chain filter would sort the
// union of both chains by sequence number, read the collisions as mid-chain
// insertions and every chain-boundary crossing as a broken link, and call a
// store nobody touched invalid: on the fixture below (three captures, fork
// after 1, two more captures) that is `duplicateSequences: [1, 2]` and three
// broken links.
import request from 'supertest';
import { Tzun } from '../../src/sdk/index';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { createServer } from '../../src/api/server';

async function captureN(tzun: Tzun, n: number, tag: string): Promise<void> {
  for (let i = 1; i <= n; i++) {
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { tag, i },
      action: 'approved',
      reason: `${tag}-${i}`,
    });
  }
}

/** Three records, fork after sequence 1, then two more on the new chain. */
async function forkedStore(): Promise<{ tzun: Tzun; sealedChainId: string; activeChainId: string }> {
  const tzun = await Tzun.init();
  await captureN(tzun, 3, 'old');
  const sealedChainId = await tzun.getActiveChainId();
  const forkResult = await tzun.recovery.fork('inc-chain-scoped', {
    authorizedBy: 'admin@acme.example',
    reason: 'Chain compromised',
    forkAfterSequence: 1,
  });
  await captureN(tzun, 2, 'new');
  return { tzun, sealedChainId, activeChainId: forkResult.newChain.chainId };
}

describe('verifyChainCompleteness is chain-scoped', () => {
  it('an untampered forked store verifies CLEAN: no duplicates, no broken links', async () => {
    const { tzun, activeChainId } = await forkedStore();
    try {
      const result = await tzun.verifyChainCompleteness();

      expect(result.valid).toBe(true);
      expect(result.duplicateSequences).toEqual([]);
      expect(result.brokenLinks).toEqual([]);
      expect(result.sequenceGaps).toEqual([]);
      // Non-vacuity: it really walked the two post-fork records, it did not
      // return the empty-store all-clear.
      expect(result.totalRecords).toBe(2);
      expect(result.firstRecord).toBe(1);
      expect(result.lastRecord).toBe(2);
      // The answer names the chain it is an answer about.
      expect(result.chainId).toBe(activeChainId);
    } finally {
      await tzun.close();
    }
  });

  it('a genuinely broken forked chain still reports INVALID', async () => {
    const { tzun, activeChainId } = await forkedStore();
    try {
      // Tamper the second post-fork record's chain link. chainLink is not part
      // of the hashed field set, so this is exactly the edit an attacker with
      // store-write access can make without touching any digest.
      const storage = tzun.getStorage();
      const records = await storage.listBySequence(1, 10, activeChainId);
      expect(records).toHaveLength(2);
      // Rewrite the stored row; assigning to a detached copy would leave the store as it was.
      await rewriteStoredEnvelope(storage, records[1].payload.evidenceId, (e) => { e.integrity.chainLink = 'f'.repeat(64); });

      const result = await tzun.verifyChainCompleteness();

      expect(result.valid).toBe(false);
      expect(result.brokenLinks).toEqual([records[1].payload.evidenceId]);
      expect(result.chainId).toBe(activeChainId);
    } finally {
      await tzun.close();
    }
  });

  it('detects a deleted TAIL on the forked chain (the upper bound survives the fork)', async () => {
    const { tzun } = await forkedStore();
    try {
      // Delete the post-fork tail record straight out of the store.
      const storage = tzun.getStorage();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const envelopes = (storage as any).envelopes as Map<string, unknown>;
      const active = await tzun.getActiveChainId();
      const records = await storage.listBySequence(1, 10, active);
      envelopes.delete(records[1].payload.evidenceId);

      const result = await tzun.verifyChainCompleteness();
      expect(result.valid).toBe(false);
      expect(result.sequenceGaps).toEqual([2]);
    } finally {
      await tzun.close();
    }
  });

  it('verifyAllChains covers the SEALED chain — tampering there is not scoped away', async () => {
    const { tzun, sealedChainId, activeChainId } = await forkedStore();
    try {
      const clean = await tzun.verifyAllChains();
      expect(clean.valid).toBe(true);
      expect(clean.activeChainId).toBe(activeChainId);
      expect(clean.chains.map((c) => c.chainId).sort()).toEqual(
        [sealedChainId, activeChainId].sort(),
      );
      // Non-vacuity: the sealed chain's three records were actually walked.
      const sealedClean = clean.chains.find((c) => c.chainId === sealedChainId)!;
      expect(sealedClean.totalRecords).toBe(3);

      // Now break a link on the SEALED chain only. The active chain is
      // untouched, so an active-chain-scoped answer would call this store
      // healthy — the reassuring-direction error, which is the worse one.
      const storage = tzun.getStorage();
      const sealed = await storage.listBySequence(1, 10, sealedChainId);
      await rewriteStoredEnvelope(storage, sealed[2].payload.evidenceId, (e) => { e.integrity.chainLink = 'e'.repeat(64); });

      const afterTamper = await tzun.verifyAllChains();
      expect(afterTamper.active.valid).toBe(true);
      expect(afterTamper.valid).toBe(false);
      const sealedResult = afterTamper.chains.find((c) => c.chainId === sealedChainId)!;
      expect(sealedResult.valid).toBe(false);
      expect(sealedResult.brokenLinks).toEqual([sealed[2].payload.evidenceId]);
    } finally {
      await tzun.close();
    }
  });

  // Contract pin. This assertion is deliberately exhaustive — `toEqual` on the
  // whole object — so that any change to the published
  // `ChainCompletenessResult` shape has to come here and be argued for. A new
  // field goes into the expected object rather than the matcher being relaxed
  // to `toMatchObject`: the point of the test is that the field set is pinned,
  // and a looser matcher would delete the only guard that catches a field
  // being REMOVED.
  it('a store that never forked reports the pinned field set: chainId names the default chain, and checks a and h from its evidence log', async () => {
    const tzun = await Tzun.init();
    try {
      await captureN(tzun, 3, 'only');
      const result = await tzun.verifyChainCompleteness();
      expect(result).toEqual({
        valid: true,
        totalRecords: 3,
        sequenceGaps: [],
        duplicateSequences: [],
        brokenLinks: [],
        digestMismatches: [],
        digestSuperseded: [],
        timeRegressions: [],
        custodyTrailInvalid: [],
        digestDiffersFromLoggedLeaf: [],
        anchorStripped: [],
        firstRecord: 1,
        lastRecord: 3,
        chainId: 'default',
      });
    } finally {
      await tzun.close();
    }
  });

  it('verifyRange does not cross the fork boundary', async () => {
    const { tzun } = await forkedStore();
    try {
      const result = await tzun.verifyRange(1);
      // Two post-fork records, both clean. An unscoped range would return four
      // records (both chains' 1 and 2) and flag chain breaks across the boundary.
      expect(result.recordsVerified).toBe(2);
      expect(result.issuesFound).toBe(0);
    } finally {
      await tzun.close();
    }
  });
});

describe('GET /v1/integrity/chain', () => {
  it('reports the active chain clean on a forked store, and lists every chain', async () => {
    const { tzun, sealedChainId, activeChainId } = await forkedStore();
    const app = createServer(tzun, { allowUnauthenticated: true });
    try {
      const res = await request(app).get('/v1/integrity/chain').expect(200);

      // The top-level fields the operator console reads.
      expect(res.body.valid).toBe(true);
      expect(res.body.brokenLinks).toEqual([]);
      expect(res.body.duplicateSequences).toEqual([]);
      expect(res.body.totalRecords).toBe(2);
      // The per-chain fields alongside them.
      expect(res.body.chainId).toBe(activeChainId);
      expect(res.body.activeChainId).toBe(activeChainId);
      expect(res.body.allChainsValid).toBe(true);
      expect(res.body.chains).toHaveLength(2);
      expect(res.body.chains.map((c: { chainId: string }) => c.chainId).sort()).toEqual(
        [sealedChainId, activeChainId].sort(),
      );
    } finally {
      await tzun.close();
    }
  });

  it('?chainId= answers about that chain; an unknown chain is a 404', async () => {
    const { tzun, sealedChainId } = await forkedStore();
    const app = createServer(tzun, { allowUnauthenticated: true });
    try {
      const sealedRes = await request(app)
        .get(`/v1/integrity/chain?chainId=${sealedChainId}`)
        .expect(200);
      expect(sealedRes.body.chainId).toBe(sealedChainId);
      expect(sealedRes.body.totalRecords).toBe(3);
      expect(sealedRes.body.valid).toBe(true);

      await request(app).get('/v1/integrity/chain?chainId=chain-nope').expect(404);
    } finally {
      await tzun.close();
    }
  });

  it('allChainsValid goes false when only the SEALED chain is tampered', async () => {
    const { tzun, sealedChainId } = await forkedStore();
    const app = createServer(tzun, { allowUnauthenticated: true });
    try {
      const sealed = await tzun.getStorage().listBySequence(1, 10, sealedChainId);
      await rewriteStoredEnvelope(tzun.getStorage(), sealed[2].payload.evidenceId, (e) => { e.integrity.chainLink = 'd'.repeat(64); });

      const res = await request(app).get('/v1/integrity/chain').expect(200);
      expect(res.body.valid).toBe(true); // active chain is genuinely fine
      expect(res.body.allChainsValid).toBe(false);
      const sealedEntry = res.body.chains.find(
        (c: { chainId: string }) => c.chainId === sealedChainId,
      );
      expect(sealedEntry.valid).toBe(false);
      expect(sealedEntry.brokenLinks).toHaveLength(1);
    } finally {
      await tzun.close();
    }
  });
});
