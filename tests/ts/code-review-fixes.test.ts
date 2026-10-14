import type { EnvelopeInput } from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { assembleEnvelope } from '@tzun/engine';
import { NotificationRouter } from '../../src/monitoring/notification-router';
import { NotificationChannel, TamperIncident, TamperSeverity } from '@tzun/engine';
import { CaptureInput, EvidenceEnvelope } from '@tzun/engine';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeIncident(overrides: Partial<TamperIncident> = {}): TamperIncident {
  return {
    id: overrides.id ?? 'inc-001',
    detectedAt: overrides.detectedAt ?? '2026-04-04T10:00:00.000Z',
    severity: overrides.severity ?? 'warning',
    type: overrides.type ?? 'sequence_gap',
    affectedRecords: overrides.affectedRecords ?? [],
    affectedSequenceRange: overrides.affectedSequenceRange,
    details: overrides.details ?? 'Sequence gap detected',
    status: overrides.status ?? 'open',
  };
}

function mockChannel(
  name: string,
  severities: TamperSeverity[],
): { registration: { channel: NotificationChannel; severities: TamperSeverity[] }; sent: TamperIncident[] } {
  const sent: TamperIncident[] = [];
  const channel: NotificationChannel = {
    name,
    send: jest.fn(async (incident: TamperIncident) => {
      sent.push(incident);
    }),
    test: jest.fn(async () => {}),
  };
  return { registration: { channel, severities }, sent };
}

async function captureSequence(
  adapter: MemoryStorageAdapter,
  count: number,
  chainId: string = 'default',
): Promise<EvidenceEnvelope[]> {
  const input: EnvelopeInput = {
    aiSystemId: 'test-system',
    aiOutput: { recommendation: 'approve' },
    action: 'approved',
    reason: 'Test',
    decider: { kind: 'human' as const, id: 'acct:tester-acme.com', agent: null, credential: null, freshness: null },
  };
  const envelopes: EvidenceEnvelope[] = [];
  let previousDigest: string | undefined;
  for (let i = 1; i <= count; i++) {
    const envelope = assembleEnvelope(input, { previousDigest: previousDigest, sequenceNumber: i });
    previousDigest = envelope.integrity.canonicalDigest;
    await adapter.store(envelope, chainId);
    envelopes.push(envelope);
  }
  return envelopes;
}

// ---------------------------------------------------------------------------
// Dedup key collision for gap events
// ---------------------------------------------------------------------------

describe('Notification dedup key includes sequence range for gap events', () => {
  it('dispatches two sequence_gap incidents with different sequence ranges (not deduplicated)', async () => {
    const ch = mockChannel('ch', ['warning']);

    const router = new NotificationRouter({
      channels: [ch.registration],
      deduplicationWindowMs: 60_000,
    });

    const gap1 = makeIncident({
      id: 'inc-gap-1',
      type: 'sequence_gap',
      affectedRecords: [],
      affectedSequenceRange: { from: 5, to: 7 },
    });

    const gap2 = makeIncident({
      id: 'inc-gap-2',
      type: 'sequence_gap',
      affectedRecords: [],
      affectedSequenceRange: { from: 12, to: 15 },
    });

    await router.dispatch(gap1);
    await router.dispatch(gap2);

    // Both should be sent since they have different sequence ranges
    expect(ch.sent).toHaveLength(2);
    expect(ch.sent[0]).toBe(gap1);
    expect(ch.sent[1]).toBe(gap2);
  });

  it('deduplicates two sequence_gap incidents with the SAME sequence range', async () => {
    const ch = mockChannel('ch', ['warning']);

    const router = new NotificationRouter({
      channels: [ch.registration],
      deduplicationWindowMs: 60_000,
    });

    const gap1 = makeIncident({
      id: 'inc-gap-1',
      type: 'sequence_gap',
      affectedRecords: [],
      affectedSequenceRange: { from: 5, to: 7 },
    });

    const gap2 = makeIncident({
      id: 'inc-gap-2',
      type: 'sequence_gap',
      affectedRecords: [],
      affectedSequenceRange: { from: 5, to: 7 },
    });

    await router.dispatch(gap1);
    await router.dispatch(gap2);

    // Same range = same dedup key, so only first should be sent
    expect(ch.sent).toHaveLength(1);
    expect(ch.sent[0]).toBe(gap1);
  });

  it('falls back to incident id for events with no affectedRecords and no sequence range', async () => {
    const ch = mockChannel('ch', ['warning']);

    const router = new NotificationRouter({
      channels: [ch.registration],
      deduplicationWindowMs: 60_000,
    });

    const incident1 = makeIncident({
      id: 'inc-missing-1',
      type: 'missing_record',
      affectedRecords: [],
      affectedSequenceRange: undefined,
    });

    const incident2 = makeIncident({
      id: 'inc-missing-2',
      type: 'missing_record',
      affectedRecords: [],
      affectedSequenceRange: undefined,
    });

    await router.dispatch(incident1);
    await router.dispatch(incident2);

    // Different incident IDs = different dedup keys, so both should be sent
    expect(ch.sent).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// The chain a fork creates starts empty — and the chain it sealed
// keeps its head
// ---------------------------------------------------------------------------

describe('a fork leaves the new chain empty and the sealed chain intact', () => {
  it('the new chain has no head and the sealed chain keeps its own', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();

    // Capture 3 records
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { step: 1 }, action: 'approved', reason: 'First' });
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { step: 2 }, action: 'approved', reason: 'Second' });
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { step: 3 }, action: 'approved', reason: 'Third' });

    // Verify chain state is populated before fork
    const digestBefore = await storage.getLastDigest();
    const seqBefore = await storage.getLastSequence();
    expect(digestBefore).not.toBeNull();
    expect(seqBefore).toBe(3);

    // Fork
    const fork = await tzun.recovery.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Chain compromised',
      forkAfterSequence: 1,
    });

    // A store has one head PER CHAIN, not one global head a fork resets, so
    // neither reading is a choice:
    //
    //   - the chain the fork created has no head because nothing has been
    //     written to it, which is what starts it at sequence 1; and
    //   - the chain the fork SEALED keeps its own head for good, which is what
    //     keeps a record deleted from its tail detectable without going through
    //     the fork record for a bound.
    expect(await storage.getLastDigest(fork.newChain.chainId)).toBeNull();
    expect(await storage.getLastSequence(fork.newChain.chainId)).toBe(0);

    const sealedChainId = 'default';
    expect(await storage.getLastSequence(sealedChainId)).toBe(3);
    expect(await storage.getLastDigest(sealedChainId)).toBe(digestBefore);

    // The seal still records the head as well: an export of a sealed chain is
    // checkable offline from the fork record alone.
    const forks = await storage.listForksForChain(sealedChainId);
    expect(forks).toHaveLength(1);
    expect(forks[0].oldChainId).toBe(sealedChainId);
    expect(forks[0].sealedOldChainLength).toBe(3);
    expect(forks[0].sealedOldChainHead).toBe(3);
  });

  it('capture after fork starts with sequence 1 and null chain link', async () => {
    const tzun = await Tzun.init();

    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { step: 1 }, action: 'approved', reason: 'First' });
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { step: 2 }, action: 'approved', reason: 'Second' });
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { step: 3 }, action: 'approved', reason: 'Third' });

    await tzun.recovery.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Chain compromised',
      forkAfterSequence: 1,
    });

    const result = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 4 },
      action: 'approved',
      reason: 'Post-fork',
    });

    expect(result.stored).toBe(true);
    expect(result.envelope.payload.sequenceNumber).toBe(1);
    expect(result.envelope.integrity.chainLink).toBeNull();

    // A sequence-1 record with a null link is shaped exactly
    // like a detached genesis, so on its own it cannot be told apart from a
    // chain someone started from nothing. The disambiguator is not in the
    // envelope — it is the chain the record belongs to, whose identity records
    // the parent and the fork point. Pin that, or the record's provenance
    // rests on a field that carries no information.
    const storage = tzun.getStorage();
    const chainId = await storage.getChainForRecord(result.envelope.payload.evidenceId);
    expect(chainId).not.toBe('default');
    const identity = await storage.getChain(chainId!);
    expect(identity!.parentChainId).toBe('default');
    expect(identity!.forkPoint).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// listBySequence is chain-aware post-fork
// ---------------------------------------------------------------------------

describe('listBySequence is chain-aware post-fork', () => {
  it('listBySequence with chainId filters to only that chain', async () => {
    const adapter = new MemoryStorageAdapter();

    // Capture records on chain A
    const chainAId = 'chain-A';
    await adapter.storeChain({ chainId: chainAId, status: 'active', createdAt: '2026-04-01T00:00:00Z' });
    const chainARecords = await captureSequence(adapter, 3, chainAId);

    // Simulate fork: seal chain A, create chain B with new records starting at seq 1
    await adapter.sealChain(chainAId, '2026-04-02T00:00:00Z');
    await adapter.resetChainState();

    const chainBId = 'chain-B';
    await adapter.storeChain({
      chainId: chainBId,
      status: 'active',
      createdAt: '2026-04-02T00:00:01Z',
      parentChainId: chainAId,
      forkPoint: 2,
    });
    const chainBRecords = await captureSequence(adapter, 2, chainBId);

    // Without chainId this is a RAW STORE SCAN, not a chain walk, and the
    // sequence numbers in it collide: chain A and chain B each have a record 1
    // and a record 2.
    //
    // On its own this assertion would read as "the unscoped call is the
    // correct thing for a verifier to use". It is not. A verifier that walked
    // it unscoped — verifyChainCompleteness, verifyRange, either scanner phase
    // — would report the collisions as mid-chain insertions and every
    // chain-boundary crossing as a broken link, raising incidents on every
    // scan of an untampered forked store. The primitive keeps its documented
    // meaning (it is the only way to sweep a store whose chain identities are
    // unknown), and no verifier calls it this way. Assert BOTH halves so
    // neither can drift without the other noticing.
    const allRecords = await adapter.listBySequence(1, 10);
    expect(allRecords.length).toBe(5); // 3 from A + 2 from B
    // ...and the collision is real, which is what makes an unscoped walk
    // useless for chain verification.
    const seqs = allRecords.map((r) => r.payload.sequenceNumber);
    expect(seqs).toEqual([1, 1, 2, 2, 3]);
    expect(new Set(seqs).size).toBeLessThan(seqs.length);

    // With chainId = chain B: only returns chain B records
    const chainBOnly = await adapter.listBySequence(1, 10, chainBId);
    expect(chainBOnly).toHaveLength(2);
    for (const record of chainBOnly) {
      const chain = await adapter.getChainForRecord(record.payload.evidenceId);
      expect(chain).toBe(chainBId);
    }

    // With chainId = chain A: only returns chain A records
    const chainAOnly = await adapter.listBySequence(1, 10, chainAId);
    expect(chainAOnly).toHaveLength(3);
    for (const record of chainAOnly) {
      const chain = await adapter.getChainForRecord(record.payload.evidenceId);
      expect(chain).toBe(chainAId);
    }
  });

  it('SDK-level: after fork, listBySequence with new chainId only returns new chain records', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();

    // Capture on the default chain
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { a: 1 }, action: 'approved', reason: 'One' });
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { a: 2 }, action: 'approved', reason: 'Two' });
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { a: 3 }, action: 'approved', reason: 'Three' });

    // Fork
    const forkResult = await tzun.recovery.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 1,
    });

    const newChainId = forkResult.newChain.chainId;

    // Capture on new chain
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { b: 1 }, action: 'approved', reason: 'New-1' });
    await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { b: 2 }, action: 'approved', reason: 'New-2' });

    // listBySequence with new chain ID should only return post-fork records
    const newChainRecords = await storage.listBySequence(1, 10, newChainId);
    expect(newChainRecords).toHaveLength(2);
    expect(newChainRecords[0].payload.sequenceNumber).toBe(1);
    expect(newChainRecords[1].payload.sequenceNumber).toBe(2);
  });
});
