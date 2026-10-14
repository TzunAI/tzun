import { storeAtTakenPosition } from './helpers/store-owner';
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { verifyChainCompleteness } from '@tzun/engine';
import { EvidenceEnvelope, assembleEnvelope, SchemaRegistry, EvidenceChain } from '@tzun/engine';

const captureInput = (label: string) => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { label },
  action: 'approved',
  reason: `Reason for ${label}`,
});

/** Helper: capture N records and return them in order. */
async function captureRecords(tzun: Tzun, count: number): Promise<EvidenceEnvelope[]> {
  const envelopes: EvidenceEnvelope[] = [];
  for (let i = 1; i <= count; i++) {
    const result = await tzun.capture(captureInput(`record-${i}`));
    expect(result.stored).toBe(true);
    envelopes.push(result.envelope);
  }
  return envelopes;
}

describe('verifyChainCompleteness', () => {
  it('empty chain is valid with totalRecords 0', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();

    const result = await verifyChainCompleteness(storage);

    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(0);
    expect(result.sequenceGaps).toEqual([]);
    expect(result.brokenLinks).toEqual([]);
    expect(result.firstRecord).toBeNull();
    expect(result.lastRecord).toBeNull();
  });

  it('single record (genesis) is valid', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();
    const envelopes = await captureRecords(tzun, 1);

    const result = await verifyChainCompleteness(storage);

    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(1);
    expect(result.sequenceGaps).toEqual([]);
    expect(result.brokenLinks).toEqual([]);
    expect(result.firstRecord).toBe(1);
    expect(result.lastRecord).toBe(1);
    // Genesis record should have null chainLink
    expect(envelopes[0].integrity.chainLink).toBeNull();
  });

  it('clean 5-record chain is valid', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();
    await captureRecords(tzun, 5);

    const result = await verifyChainCompleteness(storage);

    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(5);
    expect(result.sequenceGaps).toEqual([]);
    expect(result.brokenLinks).toEqual([]);
    expect(result.firstRecord).toBe(1);
    expect(result.lastRecord).toBe(5);
  });

  it('detects a deleted record (gap in sequence)', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 5);

    // Delete record 3 by reaching into the internal Map
    const deletedId = envelopes[2].payload.evidenceId;
    (storage as any).envelopes.delete(deletedId);

    const result = await verifyChainCompleteness(storage);

    expect(result.valid).toBe(false);
    expect(result.totalRecords).toBe(4);
    expect(result.sequenceGaps).toEqual([3]);
    // Record 4 will have a broken link because record 3 (its predecessor in
    // storage) is missing, so the verifier compares record 4's chainLink
    // against a link computed from record 2's digest, which won't match.
    expect(result.brokenLinks).toContain(envelopes[3].payload.evidenceId);
    expect(result.firstRecord).toBe(1);
    expect(result.lastRecord).toBe(5);
  });

  it('detects multiple non-adjacent gaps', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 7);

    // Delete records 2 and 5
    (storage as any).envelopes.delete(envelopes[1].payload.evidenceId);
    (storage as any).envelopes.delete(envelopes[4].payload.evidenceId);

    const result = await verifyChainCompleteness(storage);

    expect(result.valid).toBe(false);
    expect(result.totalRecords).toBe(5);
    expect(result.sequenceGaps).toContain(2);
    expect(result.sequenceGaps).toContain(5);
    expect(result.sequenceGaps).toHaveLength(2);
  });

  it('detects a broken chain link', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 5);

    // Tamper with record 3's chain link
    const tamperedId = envelopes[2].payload.evidenceId;
    const tampered = (storage as any).envelopes.get(tamperedId) as EvidenceEnvelope;
    tampered.integrity.chainLink = 'aaaa' + tampered.integrity.chainLink!.slice(4);

    const result = await verifyChainCompleteness(storage);

    expect(result.valid).toBe(false);
    expect(result.totalRecords).toBe(5);
    expect(result.sequenceGaps).toEqual([]);
    expect(result.brokenLinks).toEqual([tamperedId]);
    expect(result.firstRecord).toBe(1);
    expect(result.lastRecord).toBe(5);
  });

  it('detects combined gap and broken link', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 6);

    // Delete record 2 (creates a gap)
    (storage as any).envelopes.delete(envelopes[1].payload.evidenceId);

    // Tamper with record 5's chain link
    const tamperedId = envelopes[4].payload.evidenceId;
    const tampered = (storage as any).envelopes.get(tamperedId) as EvidenceEnvelope;
    tampered.integrity.chainLink = 'bbbb' + tampered.integrity.chainLink!.slice(4);

    const result = await verifyChainCompleteness(storage);

    expect(result.valid).toBe(false);
    expect(result.sequenceGaps).toEqual([2]);
    // Record 3 has a broken link (predecessor record 2 is missing, so verifier
    // computes against record 1's digest), and record 5 was explicitly tampered.
    expect(result.brokenLinks).toContain(envelopes[2].payload.evidenceId);
    expect(result.brokenLinks).toContain(tamperedId);
  });

  it('paginated verification with fromSequence and toSequence', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();
    const envelopes = await captureRecords(tzun, 10);

    const result = await verifyChainCompleteness(storage, undefined, {
      fromSequence: 3,
      toSequence: 7,
    });

    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(5);
    expect(result.sequenceGaps).toEqual([]);
    expect(result.brokenLinks).toEqual([]);
    expect(result.firstRecord).toBe(3);
    expect(result.lastRecord).toBe(7);
  });

  it('genesis link validation works with explicit fromSequence: 1', async () => {
    // An explicit fromSequence: 1 still starts at genesis, so the genesis record
    // (sequenceNumber 1) must be validated — its chainLink must be null. A
    // "starts at genesis" test written as `!options?.fromSequence` is `false`
    // for fromSequence: 1 and would silently skip the genesis check.
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 3);

    // Verify clean chain with explicit fromSequence: 1 — should be valid.
    const cleanResult = await verifyChainCompleteness(storage, undefined, {
      fromSequence: 1,
    });
    expect(cleanResult.valid).toBe(true);
    expect(cleanResult.totalRecords).toBe(3);
    expect(cleanResult.brokenLinks).toEqual([]);

    // Tamper with the genesis record's chainLink — it should not be null anymore.
    const genesisId = envelopes[0].payload.evidenceId;
    const genesis = (storage as any).envelopes.get(genesisId) as EvidenceEnvelope;
    genesis.integrity.chainLink = 'tampered-chain-link-value';

    // With fromSequence: 1, the genesis check must fire and detect the broken link.
    const tamperedResult = await verifyChainCompleteness(storage, undefined, {
      fromSequence: 1,
    });
    expect(tamperedResult.valid).toBe(false);
    expect(tamperedResult.brokenLinks).toContain(genesisId);
  });

  it('genesis link validation is skipped for paginated ranges starting after genesis', async () => {
    // When fromSequence > 1, the first record in the range is not the chain
    // genesis — we cannot validate its chainLink without the preceding record.
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();
    await captureRecords(tzun, 5);

    const result = await verifyChainCompleteness(storage, undefined, {
      fromSequence: 2,
      toSequence: 5,
    });

    expect(result.valid).toBe(true);
    expect(result.totalRecords).toBe(4);
    expect(result.brokenLinks).toEqual([]);
  });
});

describe('verifyChainCompleteness — truncation at the ends of the chain', () => {
  it('detects deletion of the HEAD of the chain (records 1..N)', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 5);

    // Delete records 1 and 2 — the beginning of the chain. These are the records
    // that establish who set the system up and what the earliest decisions were,
    // so they are the highest-value target for an attacker with store access.
    (storage as any).envelopes.delete(envelopes[0].payload.evidenceId);
    (storage as any).envelopes.delete(envelopes[1].payload.evidenceId);

    const result = await verifyChainCompleteness(storage);

    // The gap baseline is genesis, not the first SURVIVING record: measured from
    // the survivor, this store would report valid:true with sequenceGaps:[].
    expect(result.valid).toBe(false);
    expect(result.sequenceGaps).toEqual([1, 2]);
    expect(result.totalRecords).toBe(3);
    expect(result.firstRecord).toBe(3);
  });

  it('detects deletion of the TAIL of the chain via Tzun.verifyChainCompleteness()', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 5);

    // Delete records 4 and 5. chain_state.last_sequence still reports 5, which is
    // what makes the loss detectable — the counter survives row deletion.
    (storage as any).envelopes.delete(envelopes[3].payload.evidenceId);
    (storage as any).envelopes.delete(envelopes[4].payload.evidenceId);

    // Go through the SDK method, which is the path the API and scanner use.
    const result = await tzun.verifyChainCompleteness();

    // The SDK method bounds the walk with the chain's upper bound as toSequence;
    // without that bound trailing gaps are never checked and a truncated tail
    // reports clean.
    expect(result.valid).toBe(false);
    expect(result.sequenceGaps).toEqual([4, 5]);
    expect(result.lastRecord).toBe(3);
  });

  it('an intact chain still verifies clean through the SDK method', async () => {
    const tzun = await Tzun.init();
    await captureRecords(tzun, 5);

    const result = await tzun.verifyChainCompleteness();

    expect(result.valid).toBe(true);
    expect(result.sequenceGaps).toEqual([]);
    expect(result.brokenLinks).toEqual([]);
  });

  it('detects deletion of EVERY record in the range when toSequence is known', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 5);
    for (const e of envelopes) (storage as any).envelopes.delete(e.payload.evidenceId);

    // The bound says the chain reached 5; nothing at all survives below it.
    const result = await verifyChainCompleteness(storage, undefined, { toSequence: 5 });

    expect(result.valid).toBe(false);
    expect(result.sequenceGaps).toEqual([1, 2, 3, 4, 5]);
    expect(result.totalRecords).toBe(0);
    expect(result.firstRecord).toBeNull();
    expect(result.lastRecord).toBeNull();

    // A range that does not start at genesis is missing from where it starts.
    const tail = await verifyChainCompleteness(storage, undefined, { fromSequence: 4, toSequence: 5 });
    expect(tail.valid).toBe(false);
    expect(tail.sequenceGaps).toEqual([4, 5]);
  });

  it('detects deletion of EVERY record via Tzun.verifyChainCompleteness()', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 3);
    for (const e of envelopes) (storage as any).envelopes.delete(e.payload.evidenceId);

    // The API's GET /v1/integrity/chain answers from this method.
    const result = await tzun.verifyChainCompleteness();

    expect(result.valid).toBe(false);
    expect(result.sequenceGaps).toEqual([1, 2, 3]);
  });

  it('a store that has never held a record still verifies clean through the SDK method', async () => {
    const tzun = await Tzun.init();

    const result = await tzun.verifyChainCompleteness();

    expect(result.valid).toBe(true);
    expect(result.sequenceGaps).toEqual([]);
    expect(result.totalRecords).toBe(0);
  });
});

describe('verifyChainCompleteness — mid-chain insertion (duplicate sequence numbers)', () => {
  /**
   * Mint a forged envelope the way a store-write attacker would: a genuine,
   * fully self-consistent record (its canonicalDigest really is the digest of
   * its payload) that claims a sequence number the chain already uses, chained
   * onto whichever honest record it is meant to shadow.
   *
   * The attack needs nothing more than store-write access, because `chainLink`
   * is not part of the hashed field set: no existing record's payload or
   * canonicalDigest changes, so every RFC 3161 token, Merkle anchor and
   * WebAuthn signature on the honest records keeps verifying.
   */
  function forgeEnvelope(
    sequenceNumber: number,
    linkedAfter: EvidenceEnvelope,
    label: string,
  ): EvidenceEnvelope {
    return assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { label },
        action: 'approved',
        reason: `Forged: ${label}`,
      }, { previousDigest: linkedAfter.integrity.canonicalDigest, sequenceNumber: sequenceNumber });
  }

  it('detects a forged record appended under the head sequence number', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 3);

    // The cheapest variant of the attack: reuse the LAST sequence number and
    // link to the honest head. Nothing at all is rewritten, and the chain-state
    // counter is untouched because it only ever takes the maximum.
    const forged = forgeEnvelope(3, envelopes[2], 'inserted-at-head');
    await storeAtTakenPosition(storage, forged);

    expect(await storage.getLastSequence()).toBe(3);

    // Through the SDK method — the path the REST /v1/integrity/chain endpoint
    // and the platform both call.
    const result = await tzun.verifyChainCompleteness();

    // A record sitting AT the baseline is a duplicate and is reported as one. Gap
    // detection only fires for a record AHEAD of the baseline, so on its own it
    // would answer { valid: true, sequenceGaps: [], brokenLinks: [] } here.
    expect(result.valid).toBe(false);
    expect(result.duplicateSequences).toEqual([3]);
    expect(result.totalRecords).toBe(4);
    // The forgery is invisible to every other check, which is the whole point.
    expect(result.sequenceGaps).toEqual([]);
    expect(result.brokenLinks).toEqual([]);
  });

  it('detects a mid-chain insertion that rewrites one neighbour chainLink', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 3);

    // Insert a forged record claiming sequence 2, linked to the honest record 2,
    // then re-point record 3's chainLink at the forgery so the links still walk.
    const forged = forgeEnvelope(2, envelopes[1], 'inserted-mid-chain');
    await storeAtTakenPosition(storage, forged);

    const chain = new EvidenceChain();
    chain.restore(forged.integrity.canonicalDigest);
    const stored3 = (storage as any).envelopes.get(
      envelopes[2].payload.evidenceId,
    ) as EvidenceEnvelope;
    stored3.integrity.chainLink = chain.computeLink(
      envelopes[2].integrity.canonicalDigest,
    );

    const result = await tzun.verifyChainCompleteness();

    expect(result.valid).toBe(false);
    expect(result.duplicateSequences).toEqual([2]);
    // The gap check and the link check both still see a clean chain.
    expect(result.sequenceGaps).toEqual([]);
    expect(result.brokenLinks).toEqual([]);
  });

  it('a duplicate does not fabricate gaps for the records after it', async () => {
    // The baseline must not move backwards onto the duplicate, or every
    // subsequent record looks like it jumped a gap.
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const envelopes = await captureRecords(tzun, 5);

    await storeAtTakenPosition(storage, forgeEnvelope(2, envelopes[1], 'inserted-mid-chain'));

    const result = await tzun.verifyChainCompleteness();

    expect(result.duplicateSequences).toEqual([2]);
    expect(result.sequenceGaps).toEqual([]);
  });

  it('an intact chain reports no duplicates', async () => {
    const tzun = await Tzun.init();
    await captureRecords(tzun, 5);

    const result = await tzun.verifyChainCompleteness();

    expect(result.valid).toBe(true);
    expect(result.duplicateSequences).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The walk against the chain's evidence log.
// ---------------------------------------------------------------------------
describe('verifyChainCompleteness — against the chain\'s evidence log', () => {
  const registry = new SchemaRegistry();

  async function chainOf(storage: MemoryStorageAdapter, n: number): Promise<EvidenceEnvelope[]> {
    const out: EvidenceEnvelope[] = [];
    let previous: string | undefined;
    for (let i = 1; i <= n; i++) {
      const e = assembleEnvelope(captureInput(`logged-${i}`), { previousDigest: previous, sequenceNumber: i });
      await storage.store(e);
      previous = e.integrity.canonicalDigest;
      out.push(e);
    }
    return out;
  }

  /** A log whose leaves are `digests` (leaf i for sequence i + 1), and whose fill is done below `filled`. */
  function log(digests: Array<string | undefined>, filled = 0) {
    const asked: number[] = [];
    return {
      asked,
      evidenceLog: {
        leaves: async (from: number, to: number) =>
          digests
            .map((leafDigest, leafIndex) => ({ leafIndex, leafDigest }))
            .filter((l): l is { leafIndex: number; leafDigest: string } => l.leafDigest !== undefined && l.leafIndex >= from && l.leafIndex < to),
        anchorFillDone: async (leafIndex: number) => {
          asked.push(leafIndex);
          return leafIndex < filled;
        },
      },
    };
  }

  it('reports neither finding when it is not given the log: absent means not checked', async () => {
    const storage = new MemoryStorageAdapter();
    await chainOf(storage, 2);
    const result = await verifyChainCompleteness(storage, registry, { chainId: 'default' });
    expect(result).not.toHaveProperty('digestDiffersFromLoggedLeaf');
    expect(result).not.toHaveProperty('anchorStripped');
  });

  it('names a record whose digest is not its logged leaf, and calls the chain invalid', async () => {
    const storage = new MemoryStorageAdapter();
    const records = await chainOf(storage, 3);
    const digests: Array<string | undefined> = records.map((r) => r.integrity.canonicalDigest);
    digests[1] = 'ab'.repeat(32);
    const result = await verifyChainCompleteness(storage, registry, { chainId: 'default', ...log(digests) });
    expect(result.digestDiffersFromLoggedLeaf).toEqual([records[1].payload.evidenceId]);
    expect(result.anchorStripped).toEqual([]);
    expect(result.valid).toBe(false);
  });

  it('a position the log holds no leaf for is not a finding', async () => {
    const storage = new MemoryStorageAdapter();
    const records = await chainOf(storage, 3);
    const result = await verifyChainCompleteness(storage, registry, {
      chainId: 'default',
      ...log([records[0].integrity.canonicalDigest, undefined, undefined]),
    });
    expect(result.digestDiffersFromLoggedLeaf).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it('names a record with no anchor in a filled epoch, asks only about records without one, and leaves `valid` alone', async () => {
    const storage = new MemoryStorageAdapter();
    const records = await chainOf(storage, 4);
    // Record 1 carries an anchor, so it is never asked about.
    const anchored = (await storage.retrieve(records[0].payload.evidenceId))!;
    (storage as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes.set(anchored.payload.evidenceId, {
      ...anchored,
      nonRepudiation: { anchor: { anchorSpec: 'tzun-anchor/1' } } as unknown as EvidenceEnvelope['nonRepudiation'],
    });
    const { asked, evidenceLog } = log(records.map((r) => r.integrity.canonicalDigest), 3);
    const result = await verifyChainCompleteness(storage, registry, { chainId: 'default', evidenceLog });
    expect(asked).toEqual([1, 2, 3]);
    expect(result.anchorStripped).toEqual([records[1].payload.evidenceId, records[2].payload.evidenceId]);
    expect(result.valid).toBe(true);
  });

  it('reads a record again once its fill is done, and names it only if it still has no anchor: the fill may commit between the two reads', async () => {
    const storage = new MemoryStorageAdapter();
    const records = await chainOf(storage, 2);
    const envelopes = (storage as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes;
    const { evidenceLog } = log(records.map((r) => r.integrity.canonicalDigest), 2);
    // The fill of record 1 commits after the walk read it, before the walk asks whether its epoch is filled.
    const result = await verifyChainCompleteness(storage, registry, {
      chainId: 'default',
      evidenceLog: {
        ...evidenceLog,
        anchorFillDone: async (leafIndex: number) => {
          if (leafIndex === 0) {
            const current = envelopes.get(records[0].payload.evidenceId)!;
            envelopes.set(records[0].payload.evidenceId, {
              ...current,
              nonRepudiation: { anchor: { anchorSpec: 'tzun-anchor/1' } } as unknown as EvidenceEnvelope['nonRepudiation'],
            });
          }
          return evidenceLog.anchorFillDone(leafIndex);
        },
      },
    });
    expect(result.anchorStripped).toEqual([records[1].payload.evidenceId]);
  });

  it('reads the log only with a chain id: a log belongs to one chain', async () => {
    const storage = new MemoryStorageAdapter();
    await chainOf(storage, 1);
    const result = await verifyChainCompleteness(storage, registry, log(['cd'.repeat(32)]));
    expect(result).not.toHaveProperty('digestDiffersFromLoggedLeaf');
  });
});
