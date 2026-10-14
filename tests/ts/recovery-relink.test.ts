import { RecoveryManager, computeRelinkDigest } from '../../src/monitoring/recovery-manager';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { SchemaRegistry } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { EvidenceChain } from '@tzun/engine';
import { canonicalSerialize, computeDigest } from '@tzun/engine';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { MonitoringEvent } from '@tzun/engine';
import { EnvelopeInput, EvidenceEnvelope, TamperIncident } from '@tzun/engine';

/**
 * relink() rewrites evidence chain links, so it requires a real incident
 * and an explicit (or active) chain. These fixtures store records under
 * 'chain-001' without a ChainIdentity, so they pass the chain explicitly.
 */
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

async function captureSequence(
  adapter: MemoryStorageAdapter,
  count: number,
  chainId: string = 'chain-001',
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

describe('RecoveryManager.relink (Tier 2)', () => {
  let adapter: MemoryStorageAdapter;
  let registry: SchemaRegistry;
  let manager: RecoveryManager;
  let envelopes: EvidenceEnvelope[];

  beforeEach(async () => {
    adapter = new MemoryStorageAdapter();
    registry = new SchemaRegistry();
    manager = new RecoveryManager(adapter, registry);
    envelopes = await captureSequence(adapter, 5);
    await adapter.storeIncident(incidentFor([envelopes[2].payload.evidenceId]));
  });

  it('recomputes chain links from the specified sequence forward', async () => {
    // Tamper with record 3's chain link
    await adapter.updateEnvelopeChainLink(
      envelopes[2].payload.evidenceId,
      'tampered-link',
    );

    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 3,
    });

    expect(result.relink.fromSequence).toBe(3);
    expect(result.relink.toSequence).toBe(5);
  });

  it('captures before/after state for every modified link', async () => {
    await adapter.updateEnvelopeChainLink(
      envelopes[2].payload.evidenceId,
      'tampered-link',
    );

    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 3,
    });

    for (const link of result.relink.modifiedLinks) {
      expect(link.evidenceId).toBeDefined();
      expect(link.sequenceNumber).toBeGreaterThanOrEqual(3);
      expect(link.previousChainLink).toBeDefined();
      expect(link.newChainLink).toBeDefined();
      expect(link.previousChainLink).not.toBe(link.newChainLink);
    }
  });

  it('does NOT recompute digests -- only chain links change', async () => {
    const originalDigests = envelopes.map((e) => e.integrity.canonicalDigest);

    await adapter.updateEnvelopeChainLink(
      envelopes[2].payload.evidenceId,
      'tampered-link',
    );

    await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 3,
    });

    // Verify digests are unchanged
    for (let i = 0; i < envelopes.length; i++) {
      const current = await adapter.retrieve(envelopes[i].payload.evidenceId);
      expect(current!.integrity.canonicalDigest).toBe(originalDigests[i]);
    }
  });

  it('chain verifies clean after re-link', async () => {
    await adapter.updateEnvelopeChainLink(
      envelopes[2].payload.evidenceId,
      'tampered-link',
    );

    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 3,
    });

    expect(result.chainVerified).toBe(true);

    // Manually verify the chain links
    for (let i = 1; i < envelopes.length; i++) {
      const current = await adapter.retrieve(envelopes[i].payload.evidenceId);
      const previous = await adapter.retrieve(envelopes[i - 1].payload.evidenceId);
      const chain = new EvidenceChain();
      chain.restore(previous!.integrity.canonicalDigest);
      const expectedLink = chain.computeLink(current!.integrity.canonicalDigest);
      expect(current!.integrity.chainLink).toBe(expectedLink);
    }
  });

  it('appends relinked custody chain entry to affected records', async () => {
    await adapter.updateEnvelopeChainLink(
      envelopes[2].payload.evidenceId,
      'tampered-link',
    );

    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 3,
    });

    for (const link of result.relink.modifiedLinks) {
      const envelope = await adapter.retrieve(link.evidenceId);
      const relinkEntries = envelope!.custodyChain.filter((e) => e.action === 'relinked');
      expect(relinkEntries.length).toBeGreaterThanOrEqual(1);
      const entry = relinkEntries[relinkEntries.length - 1];
      expect(entry.actor).toBe('admin@acme.example');
      expect(entry.metadata!.incidentId).toBe('inc-001');
    }
  });

  it('stores the RelinkRecord in the storage adapter', async () => {
    await adapter.updateEnvelopeChainLink(
      envelopes[2].payload.evidenceId,
      'tampered-link',
    );

    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 3,
    });

    const stored = await adapter.getRelink(result.relink.id);
    expect(stored).toEqual(result.relink);
  });

  it('respects toSequence parameter', async () => {
    await adapter.updateEnvelopeChainLink(
      envelopes[2].payload.evidenceId,
      'tampered-link',
    );

    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 3,
      toSequence: 4,
    });

    expect(result.relink.toSequence).toBe(4);
    // Only records 3 and 4 should have been re-linked
    for (const link of result.relink.modifiedLinks) {
      expect(link.sequenceNumber).toBeGreaterThanOrEqual(3);
      expect(link.sequenceNumber).toBeLessThanOrEqual(4);
    }
  });

  it('refuses to launder a substituted digest (the attacker recomputed it)', async () => {
    // The laundering attack. An attacker with DB write edits a decision AND
    // recomputes integrity.canonicalDigest, so every digest check still passes
    // and the only trace is the chain_break the scanner reports at that record
    // and the next. A relink that computed each new link from the stored
    // digest without comparing links pairwise would rewrite both links to
    // agree with the attacker's digest, report chainVerified: true, append
    // 'relinked' custody entries signed by the operator, and leave a store
    // that scans clean.
    //
    // A chain link is H(digest(N-1) || digest(N)), so corrupting link 3 alone
    // leaves link 4 valid, while substituting digest 3 breaks both. That is the
    // discriminator relink() refuses on.
    // The attacker rewrites the stored ROW; assigning to what retrieve()
    // returns does not reach the store on any backend.
    const hashRegistry = new SchemaRegistry();
    const victim = await rewriteStoredEnvelope(adapter, envelopes[2].payload.evidenceId, (e) => {
      e.payload.reason = 'REJECTED-BY-ATTACKER';
      e.integrity.canonicalDigest = computeDigest(
        canonicalSerialize(
          e.payload as unknown as Record<string, unknown>,
          hashRegistry.get('v1.0')!.hashedFieldSet,
        ),
      );
    });
    // Sanity: the record still hashes to its stored digest, which is why the
    // digest check alone cannot see this.
    expect(
      computeDigest(
        canonicalSerialize(
          victim.payload as unknown as Record<string, unknown>,
          hashRegistry.get('v1.0')!.hashedFieldSet,
        ),
      ),
    ).toBe(victim.integrity.canonicalDigest);

    const linksBefore = await Promise.all(
      envelopes.map(async (e) => (await adapter.retrieve(e.payload.evidenceId))!.integrity.chainLink),
    );

    await expect(
      manager.relink('inc-001', {
        authorizedBy: 'admin@acme.example',
        chainId: 'chain-001',
        fromSequence: 3,
      }),
    ).rejects.toThrow('canonical digest was substituted');

    // Nothing was rewritten, and no custody entry was signed by the operator.
    const linksAfter = await Promise.all(
      envelopes.map(async (e) => (await adapter.retrieve(e.payload.evidenceId))!.integrity.chainLink),
    );
    expect(linksAfter).toEqual(linksBefore);
    for (const e of envelopes) {
      const stored = await adapter.retrieve(e.payload.evidenceId);
      expect(stored!.custodyChain.filter((c) => c.action === 'relinked')).toHaveLength(0);
    }
  });

  it('refuses to re-link over a payload that does not hash to its stored digest', async () => {
    // The sloppier variant: the payload was edited and the digest left alone.
    // relink() refuses a range holding a record that fails digest
    // verification, because re-linking around it would return
    // chainVerified: true, a claim about links that reads as a claim about the
    // evidence.
    await rewriteStoredEnvelope(adapter, envelopes[2].payload.evidenceId, (e) => {
      e.payload.reason = 'REJECTED-BY-ATTACKER';
    });

    await expect(
      manager.relink('inc-001', {
        authorizedBy: 'admin@acme.example',
        chainId: 'chain-001',
        fromSequence: 3,
      }),
    ).rejects.toThrow('does not hash to its stored digest');

    for (const e of envelopes) {
      const stored = await adapter.retrieve(e.payload.evidenceId);
      expect(stored!.custodyChain.filter((c) => c.action === 'relinked')).toHaveLength(0);
    }
  });

  it('refuses correctedPayload instead of silently discarding it', async () => {
    // correctedPayload is not implemented, so relink() refuses it with an
    // error. Accepting and ignoring it would drop the genuine text an operator
    // supplied while the tampered record was re-linked in and reported
    // repaired.
    await expect(
      manager.relink('inc-001', {
        authorizedBy: 'admin@acme.example',
        chainId: 'chain-001',
        fromSequence: 3,
        correctedPayload: { reason: 'The real reason' },
      }),
    ).rejects.toThrow('correctedPayload is not implemented');
  });

  it('refuses an incident id that does not exist', async () => {
    await expect(
      manager.relink('inc-nope', {
        authorizedBy: 'admin@acme.example',
        chainId: 'chain-001',
        fromSequence: 3,
      }),
    ).rejects.toThrow('not found');
  });

  it('re-links only the target chain, leaving a second chain untouched', async () => {
    // Sequence numbers restart at 1 per chain, so a sequence range read
    // without a chain scope pulls in same-numbered records from every chain. A
    // relink meant for one chain would then rewrite links in another (after a
    // fork, in the SEALED parent chain).
    const other = await captureSequence(adapter, 5, 'chain-002');
    const otherLinksBefore = await Promise.all(
      other.map(async (e) => (await adapter.retrieve(e.payload.evidenceId))!.integrity.chainLink),
    );

    await adapter.updateEnvelopeChainLink(envelopes[2].payload.evidenceId, 'tampered-link');
    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 3,
    });

    expect(result.relink.modifiedLinks.map((l) => l.evidenceId)).toEqual([
      envelopes[2].payload.evidenceId,
    ]);

    const otherLinksAfter = await Promise.all(
      other.map(async (e) => (await adapter.retrieve(e.payload.evidenceId))!.integrity.chainLink),
    );
    expect(otherLinksAfter).toEqual(otherLinksBefore);
  });

  it('throws if authorizedBy is empty', async () => {
    await expect(
      manager.relink('inc-001', {
        authorizedBy: '',
        fromSequence: 3,
      }),
    ).rejects.toThrow('authorizedBy is required');
  });

  it('throws if fromSequence is less than 1', async () => {
    await expect(
      manager.relink('inc-001', {
        authorizedBy: 'admin@acme.example',
        chainId: 'chain-001',
        fromSequence: 0,
      }),
    ).rejects.toThrow('fromSequence must be >= 1');
  });
});

describe('RecoveryManager.relink event emission', () => {
  it('emits chain_relinked event through the event bus', async () => {
    const adapter = new MemoryStorageAdapter();
    const registry = new SchemaRegistry();
    const eventBus = new MonitoringEventBus();
    const events: MonitoringEvent[] = [];
    eventBus.subscribe((event) => events.push(event));
    const manager = new RecoveryManager(adapter, registry, eventBus);

    const envelopes = await captureSequence(adapter, 3);
    await adapter.storeIncident(incidentFor([envelopes[1].payload.evidenceId]));
    await adapter.updateEnvelopeChainLink(
      envelopes[1].payload.evidenceId,
      'tampered',
    );

    await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 2,
    });

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('chain_relinked');
    if (events[0].type === 'chain_relinked') {
      expect(events[0].fromSequence).toBe(2);
      expect(events[0].authorizedBy).toBe('admin@acme.example');
    }
  });
});

/**
 * A RelinkRecord is itself evidence: it is the only stored account of which
 * chain links a human authorised rewriting. These two tests pin that the
 * account records a missing prior link truthfully and that every rewritten
 * record is bound to it.
 */
describe('RecoveryManager.relink -- the recovery record must be honest and bound', () => {
  let adapter: MemoryStorageAdapter;
  let manager: RecoveryManager;
  let envelopes: EvidenceEnvelope[];

  beforeEach(async () => {
    adapter = new MemoryStorageAdapter();
    manager = new RecoveryManager(adapter, new SchemaRegistry());
    envelopes = await captureSequence(adapter, 4);
    await adapter.storeIncident(incidentFor([envelopes[1].payload.evidenceId]));
  });

  it('records a missing prior chain link as null, not as the string "null"', async () => {
    // Null record 2's link. Record 3's link still derives from record 2's
    // (untouched) digest, so it stays valid and the digest-substitution guard
    // does not trip -- this is a corrupted link, exactly what relink is for.
    await adapter.updateEnvelopeChainLink(envelopes[1].payload.evidenceId, null);

    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 2,
    });

    const entry = result.relink.modifiedLinks.find(
      (l) => l.sequenceNumber === 2,
    );
    expect(entry).toBeDefined();

    // A real null, not the four-character string 'null'. The string would
    // claim record 2 previously carried a chain link whose value was "null",
    // which is indistinguishable from a real link with that value and is the
    // value an undo would write back into integrity.chainLink.
    expect(entry!.previousChainLink).toBeNull();

    // Non-vacuity: the *new* link is a real link, so this is not passing
    // because relink stopped populating the field at all.
    expect(typeof entry!.newChainLink).toBe('string');
    expect(entry!.newChainLink).not.toBe('null');
    expect(entry!.newChainLink).toBe(
      envelopes[1].integrity.chainLink,
    );
  });

  it('binds each relinked custody entry to a digest of the RelinkRecord', async () => {
    await adapter.updateEnvelopeChainLink(
      envelopes[1].payload.evidenceId,
      'tampered-link',
    );

    const result = await manager.relink('inc-001', {
      authorizedBy: 'admin@acme.example',
      chainId: 'chain-001',
      fromSequence: 2,
    });

    const touched = result.relink.modifiedLinks.map((l) => l.evidenceId);
    expect(touched.length).toBeGreaterThan(0);

    const expectedDigest = computeRelinkDigest(result.relink);

    for (const evidenceId of touched) {
      const stored = await adapter.retrieve(evidenceId);
      const relinked = (stored!.custodyChain ?? []).filter(
        (c) => c.action === 'relinked',
      );
      expect(relinked).toHaveLength(1);
      // The relink id and digest tie the rewritten link to the record that
      // authorises it. With only incidentId and the range, the RelinkRecord
      // could be edited or swapped afterwards and no envelope would disagree.
      expect(relinked[0].metadata?.relinkId).toBe(result.relink.id);
      expect(relinked[0].metadata?.relinkDigest).toBe(expectedDigest);
    }

    // Non-vacuity: the digest must actually cover modifiedLinks, so tampering
    // with the stored relink record has to break the binding.
    const forged = {
      ...result.relink,
      modifiedLinks: [
        ...result.relink.modifiedLinks,
        {
          evidenceId: envelopes[3].payload.evidenceId,
          sequenceNumber: 4,
          previousChainLink: 'a',
          newChainLink: 'b',
        },
      ],
    };
    expect(computeRelinkDigest(forged)).not.toBe(expectedDigest);
  });
});
