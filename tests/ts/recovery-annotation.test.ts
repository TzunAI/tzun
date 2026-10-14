import { RecoveryManager } from '../../src/monitoring/recovery-manager';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SchemaRegistry } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { MonitoringEvent } from '@tzun/engine';
import { EnvelopeInput, EvidenceEnvelope, TamperIncident } from '@tzun/engine';

/**
 * annotate() records a human review of a SPECIFIC incident and refuses an
 * incident id the store does not hold, so every test stores a real incident
 * first.
 */
function incidentFor(evidenceIds: string[], id = 'inc-001'): TamperIncident {
  return {
    id,
    detectedAt: new Date().toISOString(),
    severity: 'critical',
    type: 'digest_mismatch',
    affectedRecords: evidenceIds,
    details: 'Digest mismatch detected during scan.',
    status: 'open',
  };
}

function captureSequence(
  adapter: MemoryStorageAdapter,
  count: number,
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
  const promises = [];
  for (let i = 1; i <= count; i++) {
    const envelope = assembleEnvelope(input, { previousDigest: previousDigest, sequenceNumber: i });
    previousDigest = envelope.integrity.canonicalDigest;
    envelopes.push(envelope);
    promises.push(adapter.store(envelope, 'chain-001'));
  }
  return Promise.all(promises).then(() => envelopes);
}

describe('RecoveryManager.annotate (Tier 1)', () => {
  let adapter: MemoryStorageAdapter;
  let registry: SchemaRegistry;
  let manager: RecoveryManager;
  let envelopes: EvidenceEnvelope[];

  beforeEach(async () => {
    adapter = new MemoryStorageAdapter();
    registry = new SchemaRegistry();
    manager = new RecoveryManager(adapter, registry);
    envelopes = await captureSequence(adapter, 3);
    // The incident touches record 1 only.
    await adapter.storeIncident(incidentFor([envelopes[0].payload.evidenceId]));
  });

  it('creates an AnnotationRecord with correct fields', async () => {
    const result = await manager.annotate(
      'inc-001',
      { authorizedBy: 'admin@acme.example', notes: 'Tampering detected on record ev-001, acknowledged and documented.' },
    );
    expect(result.annotation.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(result.annotation.incidentId).toBe('inc-001');
    expect(result.annotation.annotatedBy).toBe('admin@acme.example');
    expect(result.annotation.notes).toBe('Tampering detected on record ev-001, acknowledged and documented.');
    expect(result.annotation.annotatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('stores the annotation in the storage adapter', async () => {
    const result = await manager.annotate('inc-001', { authorizedBy: 'admin@acme.example', notes: 'Noted' });
    const stored = await adapter.getAnnotation(result.annotation.id);
    expect(stored).toEqual(result.annotation);
  });

  it('captures original digests of affected records', async () => {
    const result = await manager.annotate('inc-001', { authorizedBy: 'admin@acme.example', notes: 'Noted' });
    expect(result.annotation.affectedRecords.length).toBeGreaterThan(0);
    for (const evidenceId of result.annotation.affectedRecords) {
      const digest = result.annotation.originalDigests[evidenceId];
      expect(digest).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it('annotates only the records the incident names, not the whole store', async () => {
    // affectedRecords and the 'reviewed' custody entries cover only the record
    // the incident names. Custody chains ship inside the evidence, so a
    // 'reviewed' entry on any other record would make an export of that
    // unrelated record claim it had been reviewed in connection with a tamper
    // incident it had nothing to do with.
    const result = await manager.annotate('inc-001', {
      authorizedBy: 'admin@acme.example',
      notes: 'Noted',
    });

    expect(result.annotation.affectedRecords).toEqual([envelopes[0].payload.evidenceId]);
    expect(Object.keys(result.annotation.originalDigests)).toEqual([
      envelopes[0].payload.evidenceId,
    ]);

    const reviewedActions = await Promise.all(
      envelopes.map(async (e) => {
        const stored = await adapter.retrieve(e.payload.evidenceId);
        return stored!.custodyChain.filter((c) => c.action === 'reviewed').length;
      }),
    );
    expect(reviewedActions).toEqual([1, 0, 0]);
  });

  it('acknowledges the stored incident, not only the returned status', async () => {
    // The stored incident moves from 'open' to 'acknowledged', matching what
    // the caller is told. If only the returned field changed, the incident
    // would stay 'open' (and /v1/integrity/status 'compromised') while the
    // caller, and any UI that renders this field, showed 'acknowledged'.
    expect((await adapter.getIncident('inc-001'))!.status).toBe('open');

    const result = await manager.annotate('inc-001', {
      authorizedBy: 'admin@acme.example',
      notes: 'Noted',
    });

    expect(result.updatedIncidentStatus).toBe('acknowledged');
    expect((await adapter.getIncident('inc-001'))!.status).toBe('acknowledged');
  });

  it('refuses to annotate an incident that does not exist', async () => {
    await expect(
      manager.annotate('inc-does-not-exist', {
        authorizedBy: 'admin@acme.example',
        notes: 'Noted',
      }),
    ).rejects.toThrow('not found');
  });

  it('appends custody chain entry of type reviewed to affected records', async () => {
    const result = await manager.annotate('inc-001', { authorizedBy: 'admin@acme.example', notes: 'Reviewed and noted' });
    for (const evidenceId of result.annotation.affectedRecords) {
      const envelope = await adapter.retrieve(evidenceId);
      const reviewEntries = envelope!.custodyChain.filter((e) => e.action === 'reviewed');
      expect(reviewEntries.length).toBeGreaterThanOrEqual(1);
      const entry = reviewEntries[reviewEntries.length - 1];
      expect(entry.actor).toBe('admin@acme.example');
      expect(entry.action).toBe('reviewed');
      expect(entry.metadata).toBeDefined();
      expect(entry.metadata!.incidentId).toBe('inc-001');
    }
  });

  it('returns updatedIncidentStatus as acknowledged', async () => {
    const result = await manager.annotate('inc-001', { authorizedBy: 'admin@acme.example', notes: 'Noted' });
    expect(result.updatedIncidentStatus).toBe('acknowledged');
  });

  it('throws if authorizedBy is empty', async () => {
    await expect(
      manager.annotate('inc-001', { authorizedBy: '', notes: 'Notes' }),
    ).rejects.toThrow('authorizedBy is required');
  });

  it('throws if notes is empty', async () => {
    await expect(
      manager.annotate('inc-001', { authorizedBy: 'admin@acme.example', notes: '' }),
    ).rejects.toThrow('notes is required');
  });
});

describe('RecoveryManager.annotate event emission', () => {
  it('emits incident_annotated event through the event bus', async () => {
    const adapter = new MemoryStorageAdapter();
    const registry = new SchemaRegistry();
    const eventBus = new MonitoringEventBus();
    const events: MonitoringEvent[] = [];
    eventBus.subscribe((event) => events.push(event));
    const manager = new RecoveryManager(adapter, registry, eventBus);

    // Store a record so annotate has something to work with
    const input: EnvelopeInput = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'test',
      aiOutput: { text: 'test' },
      action: 'approved',
      reason: 'ok',
    };
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    await adapter.store(envelope);
    await adapter.storeIncident(incidentFor([envelope.payload.evidenceId]));

    await manager.annotate('inc-001', { authorizedBy: 'admin@acme.example', notes: 'Noted' });

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('incident_annotated');
    if (events[0].type === 'incident_annotated') {
      expect(events[0].incidentId).toBe('inc-001');
      expect(events[0].authorizedBy).toBe('admin@acme.example');
    }
  });

  it('does not throw when no event bus is configured', async () => {
    const adapter = new MemoryStorageAdapter();
    const registry = new SchemaRegistry();
    const manager = new RecoveryManager(adapter, registry);

    const input: EnvelopeInput = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'test',
      aiOutput: { text: 'test' },
      action: 'approved',
      reason: 'ok',
    };
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    await adapter.store(envelope);
    await adapter.storeIncident(incidentFor([envelope.payload.evidenceId]));

    await expect(
      manager.annotate('inc-001', { authorizedBy: 'admin@acme.example', notes: 'Noted' }),
    ).resolves.toBeDefined();
  });
});
