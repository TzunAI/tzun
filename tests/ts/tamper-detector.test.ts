import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { TamperDetector, incidentDedupeKey } from '../../src/monitoring/tamper-detector';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { TamperIncident } from '@tzun/engine';

describe('TamperDetector', () => {
  let bus: MonitoringEventBus;
  let storage: MemoryStorageAdapter;
  let detector: TamperDetector;

  beforeEach(() => {
    bus = new MonitoringEventBus();
    storage = new MemoryStorageAdapter();
    detector = new TamperDetector(bus, storage);
  });

  // ---------------------------------------------------------------------------
  // Test 1: digest_mismatch creates critical incident
  // ---------------------------------------------------------------------------
  it('digest_mismatch creates a critical incident', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'digest_mismatch',
      evidenceId: 'ev-001',
      stored: 'aabbcc',
      recomputed: 'ddeeff',
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    expect(incidents[0].type).toBe('digest_mismatch');
    expect(incidents[0].severity).toBe('critical');
    expect(incidents[0].affectedRecords).toEqual(['ev-001']);
    expect(incidents[0].status).toBe('open');
  });

  // ---------------------------------------------------------------------------
  // Test 2: chain_break creates critical incident with correct sequenceRange
  // ---------------------------------------------------------------------------
  it('chain_break creates a critical incident with correct sequenceRange', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'chain_break',
      evidenceId: 'ev-007',
      sequenceNumber: 42,
      expectedPrevDigest: '112233',
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    const incident = incidents[0];
    expect(incident.type).toBe('chain_break');
    expect(incident.severity).toBe('critical');
    expect(incident.affectedRecords).toEqual(['ev-007']);
    expect(incident.affectedSequenceRange).toEqual({ from: 42, to: 42 });
  });

  // ---------------------------------------------------------------------------
  // Test 3: sequence_gap creates warning (range: expectedSequence to foundSequence-1)
  // ---------------------------------------------------------------------------
  it('sequence_gap creates a warning incident with range expectedSequence to foundSequence-1', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'sequence_gap',
      expectedSequence: 5,
      foundSequence: 8,
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    const incident = incidents[0];
    expect(incident.type).toBe('sequence_gap');
    expect(incident.severity).toBe('warning');
    expect(incident.affectedRecords).toEqual([]);
    expect(incident.affectedSequenceRange).toEqual({ from: 5, to: 7 });
  });

  // ---------------------------------------------------------------------------
  // Test 4: missing_record creates warning
  // ---------------------------------------------------------------------------
  it('missing_record creates a warning incident', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'missing_record',
      sequenceNumber: 13,
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    const incident = incidents[0];
    expect(incident.type).toBe('missing_record');
    expect(incident.severity).toBe('warning');
    expect(incident.affectedRecords).toEqual([]);
    expect(incident.affectedSequenceRange).toEqual({ from: 13, to: 13 });
  });

  // ---------------------------------------------------------------------------
  // Test 4b: duplicate_sequence creates a CRITICAL incident
  // ---------------------------------------------------------------------------
  it('duplicate_sequence creates a critical incident', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'duplicate_sequence',
      evidenceId: 'ev-forged',
      sequenceNumber: 3,
      previousSequence: 3,
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    const incident = incidents[0];
    expect(incident.type).toBe('duplicate_sequence');
    // Critical, not warning: a gap can be a benign deletion, but a reused
    // sequence number cannot arise from any capture path — they all assign
    // headSequence + 1 under a lock — so it means a write bypassed the SDK.
    expect(incident.severity).toBe('critical');
    expect(incident.affectedRecords).toEqual(['ev-forged']);
    expect(incident.affectedSequenceRange).toEqual({ from: 3, to: 3 });
  });

  // ---------------------------------------------------------------------------
  // Test 4c: digest_superseded creates a CRITICAL incident naming both digests
  // ---------------------------------------------------------------------------
  it('digest_superseded creates a critical incident naming both digests', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'digest_superseded',
      evidenceId: 'ev-reseated',
      sequenceNumber: 4,
      capturedDigest: 'aa11',
      currentDigest: 'bb22',
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    const incident = incidents[0];
    expect(incident.type).toBe('digest_superseded');
    // Critical: the record was rewritten after capture and its digest
    // recomputed — a deliberate edit, not something ordinary operation does.
    expect(incident.severity).toBe('critical');
    expect(incident.affectedRecords).toEqual(['ev-reseated']);
    expect(incident.affectedSequenceRange).toEqual({ from: 4, to: 4 });
    expect(incident.details).toContain('aa11');
    expect(incident.details).toContain('bb22');
  });

  // ---------------------------------------------------------------------------
  // Test 4d: captured_at_regression is a WARNING that does not assert tampering
  // ---------------------------------------------------------------------------
  it('captured_at_regression creates a warning incident that does not call the record tampered', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'captured_at_regression',
      evidenceId: 'ev-clock',
      sequenceNumber: 9,
      capturedAt: '2026-09-17T09:00:00.000Z',
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    const incident = incidents[0];
    expect(incident.type).toBe('captured_at_regression');
    // Warning, not critical: an NTP correction produces one honestly.
    expect(incident.severity).toBe('warning');
    expect(incident.affectedRecords).toEqual(['ev-clock']);
    expect(incident.affectedSequenceRange).toEqual({ from: 9, to: 9 });
    expect(incident.details).toContain('2026-09-17T09:00:00.000Z');
    expect(incident.details).toMatch(/not proof of tampering/i);
  });

  // ---------------------------------------------------------------------------
  // Test 4e: custody_trail_invalid is CRITICAL and names where the trail broke
  // ---------------------------------------------------------------------------
  it('custody_trail_invalid creates a critical incident naming each failure and where it is', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'custody_trail_invalid',
      evidenceId: 'ev-custody',
      failures: [
        { reason: 'entry_hash_mismatch', index: 2 },
        { reason: 'mirror_fields_mismatch', index: 2, rowId: '7' },
        { reason: 'mirror_entry_missing', rowId: '8' },
      ],
    });
    await detector.settle();

    expect(incidents).toHaveLength(1);
    expect(incidents[0]).toMatchObject({
      type: 'custody_trail_invalid',
      severity: 'critical',
      affectedRecords: ['ev-custody'],
    });
    expect(incidents[0].details).toBe(
      'Custody trail of evidence record "ev-custody" failed verification: ' +
        'entry_hash_mismatch (custodyChain[2]); ' +
        'mirror_fields_mismatch (custodyChain[2], custody_entries row 7); ' +
        'mirror_entry_missing (custody_entries row 8)',
    );
  });

  // ---------------------------------------------------------------------------
  // Test 5: attestation_invalid creates warning
  // ---------------------------------------------------------------------------
  it('attestation_invalid creates a warning incident', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'attestation_invalid',
      evidenceId: 'ev-099',
      component: 'timestamp',
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    const incident = incidents[0];
    expect(incident.type).toBe('attestation_invalid');
    expect(incident.severity).toBe('warning');
    expect(incident.affectedRecords).toEqual(['ev-099']);
  });

  // ---------------------------------------------------------------------------
  // Test 5a: attestation_invalid names the verifier's reason
  // ---------------------------------------------------------------------------
  // The reason is the difference between a clock that drifted and a token
  // stamped over some other record; an incident that says only "failed
  // verification" leaves an operator unable to tell which. One case per reason
  // the scanner passes on for a component that verified false, plus the
  // presence case.
  const attestationReasons: Array<['timestamp' | 'signature' | 'anchor', string]> = [
    ['timestamp', 'unparseable_token'],
    ['timestamp', 'imprint_mismatch'],
    ['timestamp', 'untrusted_chain'],
    ['timestamp', 'missing_dependency'],
    ['timestamp', 'verification_failed'],
    ['timestamp', 'captured_after_timestamp'],
    ['timestamp', 'unparsable_captured_at'],
    ['signature', 'unknown_credential'],
    ['signature', 'revoked_credential'],
    ['signature', 'unverifiable_assertion'],
    ['signature', 'challenge_mismatch'],
    ['signature', 'verification_failed'],
    ['anchor', 'malformed_checkpoint'],
    ['anchor', 'merkle_proof_invalid'],
    ['anchor', 'anchor_not_found_on_chain'],
    ['anchor', 'verification_failed'],
    ['timestamp', 'missing'],
    ['signature', 'missing'],
    ['anchor', 'missing'],
  ];

  it.each(attestationReasons)('attestation_invalid on %s names the reason %s', async (component, reason) => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({ type: 'attestation_invalid', evidenceId: 'ev-why', component, reason });
    await detector.settle();

    expect(incidents).toHaveLength(1);
    expect(incidents[0].details).toBe(
      `Attestation component "${component}" failed verification for evidence record "ev-why": ${reason}`,
    );
  });

  it('attestation_invalid for captured_after_timestamp carries the skew', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'attestation_invalid',
      evidenceId: 'ev-clock',
      component: 'timestamp',
      reason: 'captured_after_timestamp',
      capturedAtSkewMs: -3_600_000,
    });
    await detector.settle();

    expect(incidents).toHaveLength(1);
    expect(incidents[0].details).toBe(
      'Attestation component "timestamp" failed verification for evidence record "ev-clock": ' +
        'captured_after_timestamp — capturedAt is 3600 s later than the genTime of the timestamp ' +
        'token that notarised it (capturedAtSkewMs -3600000)',
    );
  });

  it('attestation_invalid with no reason keeps the plain wording', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({ type: 'attestation_invalid', evidenceId: 'ev-old', component: 'signature' });
    await detector.settle();

    expect(incidents[0].details).toBe(
      'Attestation component "signature" failed verification for evidence record "ev-old"',
    );
  });

  // ---------------------------------------------------------------------------
  // Test 5b: attestation_unverifiable is its OWN incident type
  // ---------------------------------------------------------------------------
  it('attestation_unverifiable is a distinct incident that does not call the record bad', async () => {
    // Same severity as attestation_invalid, deliberately different type. An
    // operator triaging a list must be able to tell "this record's anchor
    // failed verification" from "this build cannot read this record's anchor" —
    // the first is a possible tampering, the second is a software version
    // problem whose remedy is upgrade-or-re-attest. The router also dedups on
    // incident.type, so a distinct type keeps the two from collapsing together.
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({
      type: 'attestation_unverifiable',
      evidenceId: 'ev-100',
      component: 'anchor',
      reason: 'unsupported_merkle_spec',
    });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(1);
    const incident = incidents[0];
    expect(incident.type).toBe('attestation_unverifiable');
    expect(incident.severity).toBe('warning');
    expect(incident.affectedRecords).toEqual(['ev-100']);
    // The wording is the assertion. Nothing may claim the record failed.
    expect(incident.details).toMatch(/could not be verified/i);
    expect(incident.details).toMatch(/unsupported_merkle_spec/);
    expect(incident.details).not.toMatch(/failed verification/i);
  });

  // ---------------------------------------------------------------------------
  // Test 6: record_verified does NOT create incident
  // ---------------------------------------------------------------------------
  it('record_verified does not create an incident', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({ type: 'record_verified', evidenceId: 'ev-001' });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Test 7: scan_completed does NOT create incident
  // ---------------------------------------------------------------------------
  it('scan_completed does not create an incident', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({ type: 'scan_completed', recordsChecked: 100, issuesFound: 0, durationMs: 0, digestMismatches: 0, chainBreaks: 0, sequenceGaps: 0, attestationFailures: 0 });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Test 8: each incident gets a unique id
  // ---------------------------------------------------------------------------
  it('each incident gets a unique id', async () => {
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-001', stored: 'aa', recomputed: 'bb' });
    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-002', stored: 'cc', recomputed: 'dd' });
    bus.emit({ type: 'chain_break', evidenceId: 'ev-003', sequenceNumber: 1, expectedPrevDigest: 'ee' });

    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(incidents).toHaveLength(3);
    const ids = incidents.map((i) => i.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(3);
  });

  // ---------------------------------------------------------------------------
  // Test 9: detectedAt is set to current time
  // ---------------------------------------------------------------------------
  it('detectedAt is set to the current time (within 2 seconds)', async () => {
    const before = Date.now();
    const incidents: TamperIncident[] = [];
    detector.onIncident((i) => incidents.push(i));

    bus.emit({ type: 'missing_record', sequenceNumber: 7 });

    await new Promise((resolve) => setTimeout(resolve, 10));

    const after = Date.now();
    expect(incidents).toHaveLength(1);
    const detectedMs = new Date(incidents[0].detectedAt).getTime();
    expect(detectedMs).toBeGreaterThanOrEqual(before);
    expect(detectedMs).toBeLessThanOrEqual(after + 100);
  });

  // ---------------------------------------------------------------------------
  // Test 10: onIncident callback fires synchronously
  // ---------------------------------------------------------------------------
  it('onIncident callback fires before storage persistence', async () => {
    const callOrder: string[] = [];

    // Track when storage.storeIncident is called by wrapping it
    const originalStore = storage.storeIncident.bind(storage);
    storage.storeIncident = async (incident: TamperIncident) => {
      callOrder.push('storage');
      return originalStore(incident);
    };

    detector.onIncident(() => {
      callOrder.push('callback');
    });

    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-sync', stored: 'aa', recomputed: 'bb' });
    await detector.settle();

    // The callback fires once the detector has decided the incident is new —
    // after the lookup for an open one, before the write that stores it.
    expect(callOrder).toEqual(['callback', 'storage']);
  });
});

// ---------------------------------------------------------------------------
// Deduplication: the platform's key and rule
// ---------------------------------------------------------------------------
describe('TamperDetector does not raise a finding that already has an incident being handled', () => {
  const incident = (over: Partial<TamperIncident>): TamperIncident => ({
    id: 'x',
    detectedAt: '2026-09-19T00:00:00.000Z',
    severity: 'critical',
    type: 'chain_break',
    affectedRecords: [],
    details: '',
    status: 'open',
    ...over,
  });

  it('keys a finding by its type and what it names: records sorted, else the range, else the chain', () => {
    // The hosted service's incident dedupe key, less the account,
    // environment and chain, which a TamperIncident does not carry.
    expect(incidentDedupeKey(incident({ type: 'chain_break', affectedRecords: ['ev-b', 'ev-a'] }))).toBe(
      'chain_break|ev-a,ev-b',
    );
    expect(
      incidentDedupeKey(
        incident({ type: 'sequence_gap', affectedRecords: [], affectedSequenceRange: { from: 3, to: 5 } }),
      ),
    ).toBe('sequence_gap|seq:3-5');
    expect(incidentDedupeKey(incident({ type: 'missing_record', affectedRecords: [] }))).toBe('missing_record|chain');
    // Records win over a range when an incident carries both.
    expect(
      incidentDedupeKey(
        incident({ type: 'chain_break', affectedRecords: ['ev-a'], affectedSequenceRange: { from: 1, to: 1 } }),
      ),
    ).toBe('chain_break|ev-a');
  });

  it('raises a finding reported twice in one burst once', async () => {
    const bus = new MonitoringEventBus();
    const storage = new MemoryStorageAdapter();
    const detector = new TamperDetector(bus, storage);
    const raised: TamperIncident[] = [];
    detector.onIncident((i) => raised.push(i));

    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-1', stored: 'a', recomputed: 'b' });
    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-1', stored: 'a', recomputed: 'b' });
    bus.emit({ type: 'chain_break', evidenceId: 'ev-1', sequenceNumber: 1, expectedPrevDigest: '' });
    await detector.settle();

    expect(raised.map((i) => i.type)).toEqual(['digest_mismatch', 'chain_break']);
    expect(await storage.listIncidents()).toHaveLength(2);
  });

  it('raises every finding when the store cannot list incidents, rather than dropping one', async () => {
    // The platform's chain-scoped scanner view has no listIncidents: it
    // deduplicates in its own incident writer.
    const bus = new MonitoringEventBus();
    const storage = new MemoryStorageAdapter();
    (storage as unknown as { listIncidents: undefined }).listIncidents = undefined;
    const detector = new TamperDetector(bus, storage);
    const raised: TamperIncident[] = [];
    detector.onIncident((i) => raised.push(i));

    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-1', stored: 'a', recomputed: 'b' });
    await detector.settle();
    bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-1', stored: 'a', recomputed: 'b' });
    await detector.settle();

    expect(raised).toHaveLength(2);
  });

  it('raises every finding, and says why once, when listing incidents fails', async () => {
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const bus = new MonitoringEventBus();
      const storage = new MemoryStorageAdapter();
      jest.spyOn(storage, 'listIncidents').mockRejectedValue(new Error('pool is closed'));
      const detector = new TamperDetector(bus, storage);
      const raised: TamperIncident[] = [];
      detector.onIncident((i) => raised.push(i));

      bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-1', stored: 'a', recomputed: 'b' });
      await detector.settle();
      bus.emit({ type: 'digest_mismatch', evidenceId: 'ev-1', stored: 'a', recomputed: 'b' });
      await detector.settle();

      expect(raised).toHaveLength(2);
      const lookupErrors = errorSpy.mock.calls.filter((c) => String(c[0]).includes('could not list'));
      expect(lookupErrors).toHaveLength(1);
    } finally {
      errorSpy.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// Evidence logs and anchoring
// ---------------------------------------------------------------------------
describe('TamperDetector: the evidence-log and anchoring findings', () => {
  const origin = (chain: string) => `test.tzun.dev/${'ab'.repeat(16)}/evidence/${Buffer.from(chain).toString('hex')}`;
  const anchors = `test.tzun.dev/${'ab'.repeat(16)}/anchors`;

  async function raise(...events: Parameters<MonitoringEventBus['emit']>[0][]): Promise<TamperIncident[]> {
    const bus = new MonitoringEventBus();
    const storage = new MemoryStorageAdapter();
    const detector = new TamperDetector(bus, storage);
    const raised: TamperIncident[] = [];
    detector.onIncident((i) => raised.push(i));
    for (const e of events) bus.emit(e);
    await detector.settle();
    return raised;
  }

  it('rates each finding: the rewrites, truncations, split views and foreign nonces critical; a stripped, transplanted or late anchor a warning', async () => {
    const raised = await raise(
      { type: 'digest_differs_from_logged_leaf', evidenceId: 'ev-1', sequenceNumber: 1, origin: origin('a'), loggedDigest: 'aa', currentDigest: 'bb' },
      { type: 'log_rewritten_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, reason: 'leaves_do_not_rebuild_root', authenticated: true, leafRange: { from: 4, to: 8 }, evidenceIds: ['ev-6'] },
      { type: 'log_truncated_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, logSize: 5, lastSequence: 8 },
      { type: 'log_inconsistent_with_anchor', origin: anchors, chainId: null, fromSize: 2, toSize: 3, reason: 'consistency_proof_invalid' },
      { type: 'split_view', origin: anchors, chainId: null, size: 3, roots: ['01', '02'] },
      { type: 'anchor_wallet_nonce_unaccounted', address: '0xaa', chain: 'eip155:1', nonce: 4, nonceBase: 0, epochId: null, publicationId: null },
      { type: 'anchor_stripped', evidenceId: 'ev-2', sequenceNumber: 2, origin: origin('a') },
      { type: 'anchor_transplanted', evidenceId: 'ev-3', sequenceNumber: 3, origin: origin('a'), artifactOrigin: origin('b'), artifactLeafIndex: 2 },
      { type: 'anchor_overdue', origin: origin('a'), chainId: 'a', reason: 'finality_stalled', leafIndex: 9, evidenceId: 'ev-10', loggedAt: '2026-09-25T00:00:00.000Z', maxStalenessMs: 86_400_000 },
    );
    expect(raised.map((i) => [i.type, i.severity, i.affectedRecords, i.affectedSequenceRange ?? null])).toEqual([
      ['digest_differs_from_logged_leaf', 'critical', ['ev-1'], { from: 1, to: 1 }],
      ['log_rewritten_below_anchor', 'critical', ['ev-6'], { from: 5, to: 8 }],
      ['log_truncated_below_anchor', 'critical', [], { from: 6, to: 8 }],
      ['log_inconsistent_with_anchor', 'critical', [], null],
      ['split_view', 'critical', [], null],
      ['anchor_wallet_nonce_unaccounted', 'critical', [], null],
      ['anchor_stripped', 'warning', ['ev-2'], { from: 2, to: 2 }],
      ['anchor_transplanted', 'warning', ['ev-3'], { from: 3, to: 3 }],
      ['anchor_overdue', 'warning', ['ev-10'], { from: 10, to: 10 }],
    ]);
    expect(raised.find((i) => i.type === 'log_rewritten_below_anchor')!.details).toContain('published on chain');
    expect(raised.find((i) => i.type === 'anchor_transplanted')!.details).toBe(
      `Evidence record "ev-3" (sequence 3) carries an anchor made for another record: it names leaf 2 of ${origin('b')}, ` +
        `and the record is leaf 2 of its evidence log ${origin('a')}.`,
    );
  });

  it('raises a transplanted anchor once per record: a second pass, or another artifact on the same record, opens no second incident', async () => {
    const raised = await raise(
      { type: 'anchor_transplanted', evidenceId: 'ev-3', sequenceNumber: 3, origin: origin('a'), artifactOrigin: origin('b'), artifactLeafIndex: 2 },
      { type: 'anchor_transplanted', evidenceId: 'ev-3', sequenceNumber: 3, origin: origin('a'), artifactOrigin: origin('c'), artifactLeafIndex: 7 },
      { type: 'anchor_transplanted', evidenceId: 'ev-4', sequenceNumber: 4, origin: origin('a'), artifactOrigin: origin('b'), artifactLeafIndex: 2 },
    );
    expect(raised.map((i) => [i.type, i.affectedRecords])).toEqual([
      ['anchor_transplanted', ['ev-3']],
      ['anchor_transplanted', ['ev-4']],
    ]);
    expect(incidentDedupeKey(raised[0])).toBe('anchor_transplanted|ev-3');
  });

  it('keys a finding about a log by what identifies the log, so two chains\' findings never merge', async () => {
    const raised = await raise(
      { type: 'log_truncated_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, logSize: 5, lastSequence: 8 },
      { type: 'log_truncated_below_anchor', origin: origin('b'), chainId: 'b', anchoredSize: 8, logSize: 5, lastSequence: 8 },
      { type: 'log_truncated_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, logSize: 5, lastSequence: 8 },
      { type: 'anchor_wallet_nonce_unaccounted', address: '0xaa', chain: 'eip155:1', nonce: 4, nonceBase: 0, epochId: null, publicationId: null },
      { type: 'anchor_wallet_nonce_unaccounted', address: '0xaa', chain: 'eip155:1', nonce: 5, nonceBase: 0, epochId: null, publicationId: null },
      { type: 'anchor_wallet_nonce_unaccounted', address: '0xaa', chain: 'eip155:1', nonce: 4, nonceBase: 0, epochId: null, publicationId: null },
    );
    expect(raised.map((i) => i.type)).toEqual([
      'log_truncated_below_anchor',
      'log_truncated_below_anchor',
      'anchor_wallet_nonce_unaccounted',
      'anchor_wallet_nonce_unaccounted',
    ]);
    expect(incidentDedupeKey(raised[0])).not.toBe(incidentDedupeKey(raised[1]));
    expect(incidentDedupeKey(raised[0])).toBe(`log_truncated_below_anchor|finding:${raised[0].details.split('\n')[0]}`);
  });

  it('keys a finding about a log or a wallet by the first line of its details alone: what changes from pass to pass opens no second incident', async () => {
    const raised = await raise(
      { type: 'log_rewritten_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, reason: 'leaves_do_not_rebuild_root', authenticated: true, leafRange: { from: 4, to: 8 }, evidenceIds: ['ev-6'] },
      // The chain unreachable: the root came from the store, and no record could be named.
      { type: 'log_rewritten_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, reason: 'leaves_do_not_rebuild_root', authenticated: false, leafRange: { from: 4, to: 8 }, evidenceIds: [] },
      { type: 'log_truncated_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, logSize: 5, lastSequence: 8 },
      { type: 'log_truncated_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, logSize: 6, lastSequence: 9 },
      { type: 'split_view', origin: anchors, chainId: null, size: 3, roots: ['01', '02'] },
      { type: 'split_view', origin: anchors, chainId: null, size: 3, roots: ['01', '02', '03'] },
      { type: 'anchor_wallet_nonce_unaccounted', address: '0xaa', chain: 'eip155:1', nonce: 4, nonceBase: 0, epochId: null, publicationId: null },
      { type: 'anchor_wallet_nonce_unaccounted', address: '0xaa', chain: 'eip155:1', nonce: 4, nonceBase: 2, epochId: 3, publicationId: 3 },
      // Another reason at the same size is another finding.
      { type: 'log_rewritten_below_anchor', origin: origin('a'), chainId: 'a', anchoredSize: 8, reason: 'checkpoint_rewritten', authenticated: true, evidenceIds: [] },
    );
    expect(raised.map((i) => i.type)).toEqual([
      'log_rewritten_below_anchor',
      'log_truncated_below_anchor',
      'split_view',
      'anchor_wallet_nonce_unaccounted',
      'log_rewritten_below_anchor',
    ]);
  });
});
