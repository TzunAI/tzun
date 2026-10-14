import { MemoryStorageAdapter } from '../../src/storage/memory';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { MonitoringEvent } from '@tzun/engine';
import { SchemaRegistry } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { VerifyingStorageProxy } from '../../src/monitoring/storage-proxy';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
// The tamper cases rewrite the stored row itself with `rewriteStoredEnvelope`,
// which works the same on every backend. The memory adapter clones on read and
// write, so assigning to the object it returned changes nothing in the store;
// a tamper done that way would pass only against an adapter that handed out
// live references into its own storage.
import { EnvelopeInput, EvidenceEnvelope } from '@tzun/engine';
import { FailureRecord } from '@tzun/engine';

function makeCaptureInput(overrides: Partial<EnvelopeInput> & { reviewer?: string } = {}): EnvelopeInput {
  return {
    aiSystemId: overrides.aiSystemId ?? 'test-system',
    aiOutput: overrides.aiOutput ?? { recommendation: 'approve', confidence: 0.95 },
    action: overrides.action ?? 'approved',
    reason: overrides.reason ?? 'Meets all criteria',
    decider: { kind: 'human' as const, id: `acct:${overrides.reviewer ?? 'test-user'}`, agent: null, credential: null, freshness: null },
  };
}

function makeEnvelope(seq: number = 1, registry?: SchemaRegistry): EvidenceEnvelope {
  const reg = registry ?? new SchemaRegistry();
  return assembleEnvelope(makeCaptureInput(), { sequenceNumber: seq });
}

/**
 * The proxy is what `Tzun.getStorage()` returns when monitoring's proxy is on,
 * so every write the SDK makes through it has to arrive whole. A write method
 * the proxy does not forward is invisible to the capture path.
 */
describe('VerifyingStorageProxy forwards the write methods whole', () => {
  let inner: MemoryStorageAdapter;
  let proxy: VerifyingStorageProxy;

  beforeEach(() => {
    inner = new MemoryStorageAdapter();
    proxy = new VerifyingStorageProxy(inner, new MonitoringEventBus(), new SchemaRegistry());
  });

  it('forwards storeIdempotent, so a keyed capture claims and replays through the proxy', async () => {
    const claim = { idempotency: { key: 'k-proxy', fingerprint: 'fp' } };
    const first = await proxy.storeIdempotent!(makeEnvelope(1), 'chain-p', claim);
    expect(first).toMatchObject({ kind: 'claimed', receipt: { chainId: 'chain-p' } });

    const retry = await proxy.storeIdempotent!(makeEnvelope(2), 'chain-p', claim);
    expect(retry).toEqual({ kind: 'replay', receipt: (first as { receipt: unknown }).receipt });
    expect(await inner.getChainLength('chain-p')).toBe(1);
  });

  it('forwards the listByAttestationStatus limit instead of dropping it', async () => {
    for (const seq of [1, 2, 3]) {
      const envelope = makeEnvelope(seq);
      envelope.attestationStatus = 'pending';
      envelope.payload.capturedAt = `2026-03-22T10:00:0${seq}.000Z`;
      await inner.store(envelope);
    }
    expect(await proxy.listByAttestationStatus('pending', 2)).toHaveLength(2);
    expect(await proxy.listByAttestationStatus('pending')).toHaveLength(3);
  });

  it('forwards listByMissingObtainable with its components and limit', async () => {
    for (const seq of [1, 2, 3]) {
      const envelope = makeEnvelope(seq);
      envelope.attestationStatus = 'pending';
      envelope.payload.capturedAt = `2026-03-22T10:00:0${seq}.000Z`;
      await inner.store(envelope);
    }
    const forwarded = jest.spyOn(inner, 'listByMissingObtainable');
    expect(await proxy.listByMissingObtainable(['timestamp'], 2)).toHaveLength(2);
    expect(await proxy.listByMissingObtainable(['timestamp'])).toHaveLength(3);
    expect(forwarded).toHaveBeenNthCalledWith(1, ['timestamp'], 2);
  });
});

describe('VerifyingStorageProxy', () => {
  let inner: MemoryStorageAdapter;
  let eventBus: MonitoringEventBus;
  let registry: SchemaRegistry;
  let proxy: VerifyingStorageProxy;
  let events: MonitoringEvent[];

  beforeEach(() => {
    inner = new MemoryStorageAdapter();
    eventBus = new MonitoringEventBus();
    registry = new SchemaRegistry();
    proxy = new VerifyingStorageProxy(inner, eventBus, registry);
    events = [];
    eventBus.subscribe((event) => events.push(event));
  });

  it('clean record passes without events', async () => {
    const envelope = makeEnvelope(1, registry);
    await inner.store(envelope);

    const result = await proxy.retrieve(envelope.payload.evidenceId);
    expect(result).toEqual(envelope);
    expect(events).toHaveLength(0);
  });

  it('tampered record (modified payload) emits digest_mismatch', async () => {
    const envelope = makeEnvelope(1, registry);
    await inner.store(envelope);

    // Rewrite the stored row (the adapter shares no references with callers)
    await rewriteStoredEnvelope(inner, envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED REASON'; });

    await proxy.retrieve(envelope.payload.evidenceId);

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('digest_mismatch');
    if (events[0].type === 'digest_mismatch') {
      expect(events[0].evidenceId).toBe(envelope.payload.evidenceId);
      expect(events[0].stored).toBe(envelope.integrity.canonicalDigest);
      expect(events[0].recomputed).not.toBe(events[0].stored);
    }
  });

  it('tampered record still returned to caller', async () => {
    const envelope = makeEnvelope(1, registry);
    await inner.store(envelope);

    // Tamper the stored row
    await rewriteStoredEnvelope(inner, envelope.payload.evidenceId, (e) => { e.payload.action = 'TAMPERED'; });

    const result = await proxy.retrieve(envelope.payload.evidenceId);
    expect(result).not.toBeNull();
    expect(result!.payload.action).toBe('TAMPERED');
  });

  it('store delegates correctly', async () => {
    const envelope = makeEnvelope(1, registry);
    await proxy.store(envelope);

    // Verify it's in the inner adapter
    const result = await inner.retrieve(envelope.payload.evidenceId);
    expect(result).toEqual(envelope);
  });

  it('list delegates correctly', async () => {
    const e1 = makeEnvelope(1, registry);
    const e2 = makeEnvelope(2, registry);
    await inner.store(e1);
    await inner.store(e2);

    const results = await proxy.list();
    expect(results).toHaveLength(2);
  });

  it('storeFailure delegates', async () => {
    const failure: FailureRecord = {
      failureType: 'validation_failure',
      evidenceId: 'ev-001',
      diagnosticMetadata: { reason: 'Something went wrong' },
      capturedAt: new Date().toISOString(),
    };
    // Should not throw - delegates to inner
    await expect(proxy.storeFailure(failure)).resolves.not.toThrow();
  });

  it('getLastDigest delegates', async () => {
    const envelope = makeEnvelope(1, registry);
    await inner.store(envelope);

    const digest = await proxy.getLastDigest();
    expect(digest).toBe(envelope.integrity.canonicalDigest);
  });

  it('getLastSequence delegates', async () => {
    for (let seq = 1; seq <= 5; seq++) await inner.store(makeEnvelope(seq, registry));

    const seq = await proxy.getLastSequence();
    expect(seq).toBe(5);
  });

  it('listBySequence delegates', async () => {
    const e1 = makeEnvelope(1, registry);
    const e2 = makeEnvelope(2, registry);
    const e3 = makeEnvelope(3, registry);
    await inner.store(e1);
    await inner.store(e2);
    await inner.store(e3);

    const results = await proxy.listBySequence(2, 3);
    expect(results).toHaveLength(2);
    expect(results[0].payload.sequenceNumber).toBe(2);
    expect(results[1].payload.sequenceNumber).toBe(3);
  });

  it('incident storage methods delegate', async () => {
    const incident = {
      id: 'inc-001',
      detectedAt: '2026-04-04T10:00:00.000Z',
      severity: 'critical' as const,
      type: 'digest_mismatch' as const,
      affectedRecords: ['ev-001'],
      details: 'Test incident',
      status: 'open' as const,
    };

    await proxy.storeIncident(incident);
    const retrieved = await proxy.getIncident('inc-001');
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe('inc-001');

    const listed = await proxy.listIncidents({ status: 'open' });
    expect(listed).toHaveLength(1);

    await proxy.updateIncidentStatus('inc-001', 'acknowledged');
    const updated = await proxy.getIncident('inc-001');
    expect(updated!.status).toBe('acknowledged');
  });

  it('list() verifies each envelope, emits events for tampered ones', async () => {
    const e1 = makeEnvelope(1, registry);
    const e2 = makeEnvelope(2, registry);
    const e3 = makeEnvelope(3, registry);
    await inner.store(e1);
    await inner.store(e2);
    await inner.store(e3);

    // Tamper with two of the three stored rows
    await rewriteStoredEnvelope(inner, e1.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED-1'; });
    await rewriteStoredEnvelope(inner, e3.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED-3'; });

    const results = await proxy.list();
    expect(results).toHaveLength(3);
    expect(events).toHaveLength(2);
    expect(events.every((e) => e.type === 'digest_mismatch')).toBe(true);

    const mismatchIds = events
      .filter((e): e is Extract<MonitoringEvent, { type: 'digest_mismatch' }> =>
        e.type === 'digest_mismatch')
      .map((e) => e.evidenceId);

    expect(mismatchIds).toContain(e1.payload.evidenceId);
    expect(mismatchIds).toContain(e3.payload.evidenceId);
  });

  it('retrieve null for non-existent without emitting', async () => {
    const result = await proxy.retrieve('non-existent-id');
    expect(result).toBeNull();
    expect(events).toHaveLength(0);
  });

  it('emits digest_mismatch when the schemaVersion is not in the registry', async () => {
    // schemaVersion is NOT in v1.0's hashedFieldSet, so an attacker with UPDATE
    // on the evidence table can flip it without disturbing canonicalDigest.
    // An unknown schemaVersion still emits digest_mismatch (with an empty
    // recomputed digest); returning silently would make that one edit the way
    // to buy silence from read-time verification.
    const envelope = makeEnvelope(1, registry);
    await inner.store(envelope);

    await rewriteStoredEnvelope(inner, envelope.payload.evidenceId, (e) => {
      e.payload.reason = 'TAMPERED';
      e.payload.schemaVersion = 'v9.9';
    });

    const result = await proxy.retrieve(envelope.payload.evidenceId);
    expect(result).not.toBeNull();

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('digest_mismatch');
    if (events[0].type === 'digest_mismatch') {
      expect(events[0].evidenceId).toBe(envelope.payload.evidenceId);
      expect(events[0].stored).toBe(envelope.integrity.canonicalDigest);
      expect(events[0].recomputed).toBe('');
    }
  });
});

/**
 * A read whose custody-trail check fails says so on the monitoring bus, not
 * only in the verdict it hands back.
 *
 * `custodyChain` is outside the v1.0 hashed field set: an insider who rewrites,
 * reorders or deletes a custody entry changes no digest and breaks no chain
 * link. The proxy reports it as `custody_trail_invalid` alongside the
 * `digest_mismatch` it raises for a rewritten payload, so a bus subscriber
 * hears about a rewritten custody trail when the record is read. Left to the
 * next scheduled scan, the finding would wait, and on a store with no scanner
 * it would never be raised at all.
 */
describe('VerifyingStorageProxy reports a failed custody trail on the bus', () => {
  let inner: MemoryStorageAdapter;
  let eventBus: MonitoringEventBus;
  let registry: SchemaRegistry;
  let proxy: VerifyingStorageProxy;
  let events: MonitoringEvent[];

  beforeEach(() => {
    inner = new MemoryStorageAdapter();
    eventBus = new MonitoringEventBus();
    registry = new SchemaRegistry();
    proxy = new VerifyingStorageProxy(inner, eventBus, registry);
    events = [];
    eventBus.subscribe((event) => events.push(event));
  });

  /** A stored record with one hashed custody entry, mirrored and in the ledger. */
  async function recordWithCustody(seq: number): Promise<string> {
    const envelope = makeEnvelope(seq, registry);
    await inner.store(envelope);
    const evidenceId = envelope.payload.evidenceId;
    await inner.appendCustodyEntry(evidenceId, {
      timestamp: '2026-09-19T09:00:00.000Z',
      actor: 'auditor@acme.example',
      action: 'reviewed',
      systemId: 'tzun-recovery',
    });
    return evidenceId;
  }

  /** Delete the last mirrored custody entry — the row stays in the ledger. */
  async function dropLastMirrorEntry(evidenceId: string): Promise<void> {
    await rewriteStoredEnvelope(inner, evidenceId, (e) => { e.custodyChain.pop(); });
  }

  const custodyEvents = (): Array<Extract<MonitoringEvent, { type: 'custody_trail_invalid' }>> =>
    events.filter((e): e is Extract<MonitoringEvent, { type: 'custody_trail_invalid' }> =>
      e.type === 'custody_trail_invalid');

  it('emits custody_trail_invalid naming the record and what failed', async () => {
    const evidenceId = await recordWithCustody(1);
    await dropLastMirrorEntry(evidenceId);

    const read = await proxy.retrieveWithVerdict(evidenceId);
    expect(read!.verdict.custodyTrail).toMatchObject({ status: 'invalid', reason: 'mirror_entry_missing' });

    expect(custodyEvents()).toHaveLength(1);
    expect(custodyEvents()[0]!.evidenceId).toBe(evidenceId);
    expect(custodyEvents()[0]!.failures.map((f) => f.reason)).toContain('mirror_entry_missing');
  });

  it('a clean custody trail emits nothing', async () => {
    const evidenceId = await recordWithCustody(1);
    const read = await proxy.retrieveWithVerdict(evidenceId);
    expect(read!.verdict.custodyTrail.status).toBe('valid');
    expect(events).toHaveLength(0);
  });

  it('raises one event per record however many times the record is read', async () => {
    const evidenceId = await recordWithCustody(1);
    await dropLastMirrorEntry(evidenceId);

    for (let i = 0; i < 5; i++) await proxy.retrieveWithVerdict(evidenceId);
    await proxy.listWithVerdicts();
    await proxy.listWithVerdicts();

    expect(custodyEvents()).toHaveLength(1);
  });

  it('raises one event per broken record, not one per read pass', async () => {
    const first = await recordWithCustody(1);
    const second = await recordWithCustody(2);
    await dropLastMirrorEntry(first);
    await dropLastMirrorEntry(second);

    await proxy.listWithVerdicts();
    await proxy.listWithVerdicts();

    expect(custodyEvents().map((e) => e.evidenceId).sort()).toEqual([first, second].sort());
  });

  it('an unmeasured custody trail is not a finding', async () => {
    // No ledger rows and no hashed entries: nothing to measure.
    const envelope = makeEnvelope(1, registry);
    await inner.store(envelope);
    const read = await proxy.retrieveWithVerdict(envelope.payload.evidenceId);
    expect(read!.verdict.custodyTrail).toMatchObject({ status: 'unmeasured', reason: 'nothing_to_measure' });
    expect(events).toHaveLength(0);

    // An unreadable ledger is reported in the verdict with its error, not on the bus.
    inner.listCustodyEntries = async () => { throw new Error('custody_entries is unreadable'); };
    const unreadable = await proxy.retrieveWithVerdict(envelope.payload.evidenceId);
    expect(unreadable!.verdict.custodyTrail).toMatchObject({ status: 'unmeasured', reason: 'custody_ledger_unreadable' });
    expect(events).toHaveLength(0);
  });

  it('a record with both failures reports each on its own event', async () => {
    const evidenceId = await recordWithCustody(1);
    await dropLastMirrorEntry(evidenceId);
    await rewriteStoredEnvelope(inner, evidenceId, (e) => { e.payload.reason = 'rewritten'; });

    await proxy.retrieveWithVerdict(evidenceId);
    expect(events.map((e) => e.type).sort()).toEqual(['custody_trail_invalid', 'digest_mismatch']);
  });

  it('the digest-only read path makes no custody claim', async () => {
    // `retrieve()` does not read the ledger, so it cannot report on custody —
    // and must not report a clean trail either.
    const evidenceId = await recordWithCustody(1);
    await dropLastMirrorEntry(evidenceId);
    await proxy.retrieve(evidenceId);
    expect(events).toHaveLength(0);
  });
});
