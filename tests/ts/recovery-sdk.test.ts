import { Tzun } from '../../src/sdk/index';

describe('SDK Recovery Integration', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init();
  });

  it('exposes tzun.recovery as a non-null object', () => {
    expect(tzun.recovery).toBeDefined();
    expect(typeof tzun.recovery.annotate).toBe('function');
    expect(typeof tzun.recovery.relink).toBe('function');
    expect(typeof tzun.recovery.fork).toBe('function');
  });

  it('annotate creates an annotation via the SDK', async () => {
    const captured = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { text: 'test' },
      action: 'approved',
      reason: 'Good',
    });
    // annotate() is incident-scoped, so the incident must exist.
    await tzun.getStorage().storeIncident({
      id: 'inc-001',
      detectedAt: new Date().toISOString(),
      severity: 'critical',
      type: 'digest_mismatch',
      affectedRecords: [captured.envelope.payload.evidenceId],
      details: 'Digest mismatch.',
      status: 'open',
    });

    const result = await tzun.recovery.annotate(
      'inc-001',
      { authorizedBy: 'admin@acme.example', notes: 'Incident acknowledged' },
    );

    expect(result.annotation.incidentId).toBe('inc-001');
    expect(result.updatedIncidentStatus).toBe('acknowledged');
  });

  it('relink recomputes chain links via the SDK', async () => {
    // Capture 3 records to build a chain
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 1 },
      action: 'approved',
      reason: 'First',
    });
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 2 },
      action: 'approved',
      reason: 'Second',
    });
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 3 },
      action: 'approved',
      reason: 'Third',
    });

    await tzun.getStorage().storeIncident({
      id: 'inc-relink',
      detectedAt: new Date().toISOString(),
      severity: 'critical',
      type: 'chain_break',
      affectedRecords: [],
      details: 'Chain break.',
      status: 'open',
    });

    const result = await tzun.recovery.relink('inc-relink', {
      authorizedBy: 'admin@acme.example',
      fromSequence: 2,
    });

    expect(result.relink.fromSequence).toBe(2);
    expect(result.chainVerified).toBe(true);
  });

  it('fork creates a new chain via the SDK', async () => {
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 1 },
      action: 'approved',
      reason: 'First',
    });
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 2 },
      action: 'approved',
      reason: 'Second',
    });

    const result = await tzun.recovery.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Chain compromised',
      forkAfterSequence: 1,
    });

    expect(result.fork.forkAfterSequence).toBe(1);
    expect(result.newChain.status).toBe('active');
    expect(result.oldChain.status).toBe('sealed');
  });

  it('capture after fork appends to new chain', async () => {
    // Capture on original chain
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 1 },
      action: 'approved',
      reason: 'First',
    });

    // Fork
    const forkResult = await tzun.recovery.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 0,
    });

    // Capture on new chain — should get sequenceNumber 1 on the new chain
    const r2 = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 2 },
      action: 'approved',
      reason: 'After fork',
    });

    expect(r2.stored).toBe(true);
    expect(r2.envelope.payload.sequenceNumber).toBe(1);
    expect(r2.envelope.integrity.chainLink).toBeNull();

    // Verify the new record is on the new chain
    const chainId = await tzun.getStorage().getChainForRecord(
      r2.envelope.payload.evidenceId,
    );
    expect(chainId).toBe(forkResult.newChain.chainId);
  });

  it('old chain records are still accessible after fork', async () => {
    const r1 = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 1 },
      action: 'approved',
      reason: 'First',
    });

    await tzun.recovery.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 0,
    });

    const retrieved = await tzun.getStorage().retrieve(r1.envelope.payload.evidenceId);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.payload.evidenceId).toBe(r1.envelope.payload.evidenceId);
  });
});
