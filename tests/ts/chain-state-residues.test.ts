// On a forked store, every reader that needs a chain's extent asks about THAT
// chain.
//
// `recovery.fork()` seals the old chain and starts a new one at sequence 1, and
// `chain_state` is keyed by chain: each chain keeps its own head, sealed or
// live, and there is no store-wide counter. A reader that takes one chain's
// head (typically the active chain's) as a number for the store, or for
// another chain, silently truncates. The places that need the right chain's
// bound, pinned here:
//
//   1. relink()'s default `toSequence` — the one that matters. Bounded by the
//      wrong chain, a recovery tool reports a repair it did not perform.
//   2. relink()'s post-repair `chainVerified`, which covers the chain, not just
//      the range the operator named.
//   3. fork()'s 'chain_forked' custody stamping, which stays on the forked
//      chain.
//   4. computeIntegrityStatus's `totalRecords`, which counts every chain.
//   5. annotate(), which does not assume a sequence-range incident is about the
//      active chain.
//
// The last block checks that chain-scoped verification itself holds on a store
// forked twice: it verifies clean, raises no incident, and still catches a
// tamper on a sealed chain.
import { Tzun } from '../../src/sdk/index';
import { computeIntegrityStatus } from '../../src/api/integrity-status';
import { TamperIncident, CustodyEntry } from '@tzun/engine';

const scannerConfig = {
  batchSize: 100,
  workers: 2,
  mode: 'interval' as const,
  intervalMs: 0,
  verifyAttestation: false,
  verifyChainCompleteness: true,
};

async function capture(tzun: Tzun, tag: string, i: number): Promise<void> {
  await tzun.capture({
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    aiOutput: { [tag]: i },
    action: 'approved',
    reason: `${tag}-${i}`,
  });
}

/**
 * A store whose SEALED chain is longer than its active one.
 *
 * That inequality is the whole point: the active chain's head is a strictly
 * smaller number than the sealed chain's, so anything that reads one chain's
 * counter for another silently truncates.
 */
async function sealedLongerThanActive(
  sealedLength: number,
  activeLength: number,
): Promise<{ tzun: Tzun; sealedChainId: string }> {
  const tzun = await Tzun.init({
    verifyReads: false,
    monitoring: { enabled: true, scanner: scannerConfig },
  });
  for (let i = 1; i <= sealedLength; i++) await capture(tzun, 'old', i);
  const sealedChainId = await tzun.getActiveChainId();
  await tzun.recovery.fork('inc-fork', {
    authorizedBy: 'admin@acme.example',
    reason: 'compromise',
    forkAfterSequence: sealedLength,
  });
  for (let i = 1; i <= activeLength; i++) await capture(tzun, 'new', i);
  return { tzun, sealedChainId };
}

function incident(id: string, over: Partial<TamperIncident> = {}): TamperIncident {
  return {
    id,
    detectedAt: new Date().toISOString(),
    severity: 'critical',
    type: 'chain_break',
    affectedRecords: [],
    details: 'raised by a scan',
    status: 'open',
    ...over,
  } as TamperIncident;
}

describe('relink() reports exactly the repair it performed', () => {
  it('re-links the SEALED chain past the active chain\'s counter, and says so honestly', async () => {
    // Sealed chain: 6 records, link corrupted at sequence 5.
    // Active chain: 4 records. Each chain's own head says so.
    const { tzun, sealedChainId } = await sealedLongerThanActive(6, 4);
    try {
      const storage = tzun.getStorage();
      expect(await storage.getLastSequence(sealedChainId)).toBe(6);
      expect(await storage.getLastSequence(await tzun.getActiveChainId())).toBe(4);

      const sealed = await storage.listBySequence(1, 20, sealedChainId);
      const victim = sealed.find((e) => e.payload.sequenceNumber === 5)!;
      const goodLink = victim.integrity.chainLink;
      await storage.updateEnvelopeChainLink(victim.payload.evidenceId, 'corrupted-link');
      await storage.storeIncident(
        incident('inc-relink', { affectedRecords: [victim.payload.evidenceId] }),
      );

      const before = await tzun.verifyChainCompleteness(sealedChainId);
      expect(before.valid).toBe(false);

      const result = await tzun.recovery.relink('inc-relink', {
        authorizedBy: 'admin@acme.example',
        fromSequence: 5,
        chainId: sealedChainId,
      });

      // The default toSequence is the sealed chain's own head. The ACTIVE
      // chain's counter (4) would give an empty 5..4 range, modifiedLinks 0 and
      // chainVerified TRUE over a repair that never happened.
      expect(result.relink.toSequence).toBe(6);
      expect(result.relink.modifiedLinks).toHaveLength(1);
      expect(result.chainVerified).toBe(true);

      // The claim is not vacuous: the link really was put back.
      const repaired = await storage.retrieve(victim.payload.evidenceId);
      expect(repaired!.integrity.chainLink).toBe(goodLink);
      const after = await tzun.verifyChainCompleteness(sealedChainId);
      expect(after.valid).toBe(true);
    } finally {
      await tzun.close();
    }
  });

  it('refuses an empty range rather than reporting an all-clear over it', async () => {
    const { tzun, sealedChainId } = await sealedLongerThanActive(3, 2);
    try {
      await tzun.getStorage().storeIncident(incident('inc-empty'));
      await expect(
        tzun.recovery.relink('inc-empty', {
          authorizedBy: 'admin@acme.example',
          fromSequence: 4,
          toSequence: 3,
          chainId: sealedChainId,
        }),
      ).rejects.toThrow(/Refusing to re-link an empty range/);
    } finally {
      await tzun.close();
    }
  });
});

describe('chainVerified describes the chain, not the re-linked range', () => {
  it('a break beyond the re-linked range makes chainVerified false', async () => {
    // Single chain, five records. The operator re-links 2..3; the break is at
    // 5. A post-relink walk that stopped at toSequence 3 would never see
    // record 5 and would return chainVerified: true.
    const t = await Tzun.init({});
    try {
      for (let i = 1; i <= 5; i++) await capture(t, 'r', i);
      const st = t.getStorage();
      const chainId = await st.getActiveChainId();
      const all = await st.listBySequence(1, 20, chainId);
      const late = all.find((e) => e.payload.sequenceNumber === 5)!;
      await st.updateEnvelopeChainLink(late.payload.evidenceId, 'still-broken');
      await st.storeIncident(incident('inc-partial'));

      const result = await t.recovery.relink('inc-partial', {
        authorizedBy: 'admin@acme.example',
        fromSequence: 2,
        toSequence: 3,
        chainId,
      });

      expect(result.relink.toSequence).toBe(3);
      expect(result.chainVerified).toBe(false);
    } finally {
      await t.close();
    }
  });
});

describe('fork() stamps custody entries only on the chain it forks', () => {
  it('a second fork does not write chain_forked into the first sealed chain', async () => {
    const tzun = await Tzun.init({
      verifyReads: false,
      monitoring: { enabled: true, scanner: scannerConfig },
    });
    try {
      for (let i = 1; i <= 4; i++) await capture(tzun, 'a', i);
      const chain0 = await tzun.getActiveChainId();
      const fork1 = await tzun.recovery.fork('inc-a', {
        authorizedBy: 'admin@acme.example',
        reason: 'first compromise',
        forkAfterSequence: 2,
      });
      for (let i = 1; i <= 4; i++) await capture(tzun, 'b', i);
      const chain1 = await tzun.getActiveChainId();
      const fork2 = await tzun.recovery.fork('inc-b', {
        authorizedBy: 'admin@acme.example',
        reason: 'second compromise',
        forkAfterSequence: 2,
      });

      const storage = tzun.getStorage();
      const forkEntriesOn = async (chainId: string) => {
        const recs = await storage.listBySequence(1, 20, chainId);
        recs.sort((a, b) => a.payload.sequenceNumber - b.payload.sequenceNumber);
        return recs.map((e) => ({
          seq: e.payload.sequenceNumber,
          forks: (e.custodyChain ?? [])
            .filter((c: CustodyEntry) => c.action === 'chain_forked')
            .map((c: CustodyEntry) => c.metadata!.newChainId as string),
        }));
      };

      // Chain 0's post-fork-point records belong to fork 1 and to nothing else.
      // Fork 2's entry on sequences 3 and 4 of chain 0 would name a fork of a
      // chain they were never part of, written into the custody chain that
      // ships inside the evidence envelope.
      expect(await forkEntriesOn(chain0)).toEqual([
        { seq: 1, forks: [] },
        { seq: 2, forks: [] },
        { seq: 3, forks: [fork1.newChain.chainId] },
        { seq: 4, forks: [fork1.newChain.chainId] },
      ]);
      expect(await forkEntriesOn(chain1)).toEqual([
        { seq: 1, forks: [] },
        { seq: 2, forks: [] },
        { seq: 3, forks: [fork2.newChain.chainId] },
        { seq: 4, forks: [fork2.newChain.chainId] },
      ]);
    } finally {
      await tzun.close();
    }
  });
});

describe('integrity status counts every record of a forked store', () => {
  it('totalRecords counts every chain, not the active chain\'s counter', async () => {
    const { tzun, sealedChainId } = await sealedLongerThanActive(5, 2);
    try {
      const storage = tzun.getStorage();
      const realTotal = (await storage.list({})).length;
      expect(realTotal).toBe(7);
      // The active chain's counter: the number a status that read one chain's
      // head as a store-wide total would publish.
      expect(await storage.getLastSequence(await tzun.getActiveChainId())).toBe(2);
      expect(await storage.getLastSequence(sealedChainId)).toBe(5);

      const status = await computeIntegrityStatus({
        storage,
        scannerState: tzun.getScannerState(),
        activeChainId: await tzun.getActiveChainId(),
        sealedChains: await tzun.getSealedChainCount(),
      });

      expect(status.totalRecords).toBe(7);
      expect(status.sealedChains).toBe(1);
    } finally {
      await tzun.close();
    }
  });
});

describe('annotate() does not guess which chain a sequence range means', () => {
  it('refuses a sequence-shaped incident on a forked store instead of stamping the active chain', async () => {
    const { tzun } = await sealedLongerThanActive(4, 2);
    try {
      // A sequence_gap incident: a range, no evidence ids. The scanner raises
      // these on sealed chains too.
      await tzun.getStorage().storeIncident(
        incident('inc-gap', {
          type: 'sequence_gap',
          severity: 'warning',
          affectedRecords: [],
          affectedSequenceRange: { from: 3, to: 4 },
        }),
      );

      await expect(
        tzun.recovery.annotate('inc-gap', {
          authorizedBy: 'admin@acme.example',
          notes: 'reviewed the gap',
        }),
      ).rejects.toThrow(/names a sequence range but no evidence ids/);
    } finally {
      await tzun.close();
    }
  });

  it('annotates the named chain, and no record of any other chain', async () => {
    const { tzun, sealedChainId } = await sealedLongerThanActive(4, 2);
    try {
      const storage = tzun.getStorage();
      await storage.storeIncident(
        incident('inc-gap', {
          type: 'sequence_gap',
          severity: 'warning',
          affectedRecords: [],
          affectedSequenceRange: { from: 3, to: 4 },
        }),
      );

      const result = await tzun.recovery.annotate('inc-gap', {
        authorizedBy: 'admin@acme.example',
        notes: 'reviewed the gap',
        chainId: sealedChainId,
      });

      const sealed = await storage.listBySequence(3, 4, sealedChainId);
      expect(result.annotation.affectedRecords.sort()).toEqual(
        sealed.map((e) => e.payload.evidenceId).sort(),
      );

      // Nothing on the active chain was touched. Resolving the range against the
      // ACTIVE chain would give its records 3..4 (here: none, and on a longer
      // active chain: the wrong ones) the 'reviewed' entry.
      const active = await storage.listBySequence(1, 20, await tzun.getActiveChainId());
      for (const e of active) {
        expect((e.custodyChain ?? []).filter((c: CustodyEntry) => c.action === 'reviewed')).toEqual([]);
      }

      // Non-vacuity: the sealed records really did get the entry.
      for (const e of await storage.listBySequence(3, 4, sealedChainId)) {
        const stored = await storage.retrieve(e.payload.evidenceId);
        expect(
          (stored!.custodyChain ?? []).filter((c: CustodyEntry) => c.action === 'reviewed'),
        ).toHaveLength(1);
      }
    } finally {
      await tzun.close();
    }
  });

  it('still defaults to the active chain on a store that has never forked', async () => {
    const tzun = await Tzun.init({});
    try {
      for (let i = 1; i <= 3; i++) await capture(tzun, 'z', i);
      const storage = tzun.getStorage();
      await storage.storeIncident(
        incident('inc-single', {
          type: 'sequence_gap',
          severity: 'warning',
          affectedRecords: [],
          affectedSequenceRange: { from: 2, to: 3 },
        }),
      );
      const result = await tzun.recovery.annotate('inc-single', {
        authorizedBy: 'admin@acme.example',
        notes: 'single-chain store, nothing to disambiguate',
      });
      expect(result.annotation.affectedRecords).toHaveLength(2);
    } finally {
      await tzun.close();
    }
  });
});

describe('chain-scoped verification on a store forked twice', () => {
  it('a DOUBLE fork on an untampered store verifies clean and raises no incident', async () => {
    const tzun = await Tzun.init({
      verifyReads: false,
      monitoring: { enabled: true, scanner: scannerConfig },
    });
    try {
      for (let i = 1; i <= 3; i++) await capture(tzun, 'a', i);
      await tzun.recovery.fork('inc-1', {
        authorizedBy: 'admin@acme.example',
        reason: 'r1',
        forkAfterSequence: 1,
      });
      for (let i = 1; i <= 2; i++) await capture(tzun, 'b', i);
      await tzun.recovery.fork('inc-2', {
        authorizedBy: 'admin@acme.example',
        reason: 'r2',
        forkAfterSequence: 1,
      });
      for (let i = 1; i <= 2; i++) await capture(tzun, 'c', i);

      const report = await tzun.verifyAllChains();
      expect(report.chains).toHaveLength(3);
      expect(report.chains.map((c) => c.valid)).toEqual([true, true, true]);
      expect(report.valid).toBe(true);

      await tzun.runScan();
      expect(await tzun.getStorage().listIncidents()).toEqual([]);

      // Non-vacuity: the walk really did cover all seven records.
      const covered = report.chains.reduce((n, c) => n + c.totalRecords, 0);
      expect(covered).toBe(7);

      // And it is not blind — a sealed-chain tamper is still caught.
      const sealedChains = (await tzun.getStorage().listChains()).filter(
        (c) => c.status === 'sealed',
      );
      const victimChain = sealedChains[0]!.chainId;
      const recs = await tzun.getStorage().listBySequence(1, 20, victimChain);
      const target = recs[recs.length - 1]!;
      await tzun.getStorage().updateEnvelopeChainLink(target.payload.evidenceId, 'tampered');
      expect((await tzun.verifyAllChains()).valid).toBe(false);
    } finally {
      await tzun.close();
    }
  });
});
