import { Tzun } from '../../src/sdk/index';

describe('Recovery Lifecycle: end-to-end', () => {
  it('full lifecycle: capture -> annotate -> relink -> verify clean', async () => {
    const tzun = await Tzun.init();

    // Capture 5 records
    const results = [];
    for (let i = 0; i < 5; i++) {
      const r = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { step: i + 1 },
        action: 'approved',
        reason: `Step ${i + 1}`,
      });
      expect(r.stored).toBe(true);
      results.push(r);
    }

    // Annotate an incident. annotate() is scoped to the incident, so the
    // incident has to exist and the annotation covers exactly the record it
    // names, not every record in the store.
    await tzun.getStorage().storeIncident({
      id: 'inc-lifecycle',
      detectedAt: new Date().toISOString(),
      severity: 'critical',
      type: 'digest_mismatch',
      affectedRecords: [results[2].envelope.payload.evidenceId],
      details: 'Digest mismatch on record 3.',
      status: 'open',
    });

    const annResult = await tzun.recovery.annotate(
      'inc-lifecycle',
      { authorizedBy: 'security@acme.example', notes: 'Chain reviewed during audit -- all records verified manually.' },
    );
    expect(annResult.updatedIncidentStatus).toBe('acknowledged');
    expect(annResult.annotation.affectedRecords).toEqual([
      results[2].envelope.payload.evidenceId,
    ]);
    expect((await tzun.getStorage().getIncident('inc-lifecycle'))!.status).toBe('acknowledged');

    // Re-link from record 3 onward
    const relinkResult = await tzun.recovery.relink('inc-lifecycle', {
      authorizedBy: 'admin@acme.example',
      fromSequence: 3,
    });
    expect(relinkResult.chainVerified).toBe(true);

    // Verify all records are still retrievable
    for (const r of results) {
      const envelope = await tzun.getStorage().retrieve(r.envelope.payload.evidenceId);
      expect(envelope).not.toBeNull();
    }
  });

  it('full lifecycle: capture -> fork -> capture on new chain -> verify isolation', async () => {
    const tzun = await Tzun.init();

    // Capture 3 records on original chain
    const originalResults = [];
    for (let i = 0; i < 3; i++) {
      const r = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { step: i + 1 },
        action: 'approved',
        reason: `Original ${i + 1}`,
      });
      originalResults.push(r);
    }

    // Fork after record 2
    const forkResult = await tzun.recovery.fork('inc-fork', {
      authorizedBy: 'admin@acme.example',
      reason: 'Record 3 was compromised',
      forkAfterSequence: 2,
    });

    // Capture 2 records on new chain
    const newResults = [];
    for (let i = 0; i < 2; i++) {
      const r = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { step: i + 1 },
        action: 'approved',
        reason: `New chain ${i + 1}`,
      });
      expect(r.stored).toBe(true);
      newResults.push(r);
    }

    // New chain records start with sequenceNumber 1
    expect(newResults[0].envelope.payload.sequenceNumber).toBe(1);
    expect(newResults[1].envelope.payload.sequenceNumber).toBe(2);

    // First new record has null chainLink (genesis of new chain)
    expect(newResults[0].envelope.integrity.chainLink).toBeNull();

    // Second new record has a valid chainLink
    expect(newResults[1].envelope.integrity.chainLink).toMatch(/^[a-f0-9]{64}$/);

    // New records are on the new chain
    for (const r of newResults) {
      const chainId = await tzun.getStorage().getChainForRecord(
        r.envelope.payload.evidenceId,
      );
      expect(chainId).toBe(forkResult.newChain.chainId);
    }

    // Original records are still accessible
    for (const r of originalResults) {
      const envelope = await tzun.getStorage().retrieve(r.envelope.payload.evidenceId);
      expect(envelope).not.toBeNull();
    }
  });

  it('chain identity: system with no fork has single active chain', async () => {
    const tzun = await Tzun.init();
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { text: 'test' },
      action: 'approved',
      reason: 'Good',
    });

    const activeChainId = await tzun.getStorage().getActiveChainId();
    expect(activeChainId).toBe('default');
  });

  it('chain identity: after fork, old chain sealed and new chain active', async () => {
    const tzun = await Tzun.init();
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { text: 'test' },
      action: 'approved',
      reason: 'Good',
    });

    const forkResult = await tzun.recovery.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Test fork',
      forkAfterSequence: 0,
    });

    const activeChainId = await tzun.getStorage().getActiveChainId();
    expect(activeChainId).toBe(forkResult.newChain.chainId);

    const oldChain = await tzun.getStorage().getChain(forkResult.oldChain.chainId);
    expect(oldChain!.status).toBe('sealed');
  });

  it('multiple forks create chain lineage', async () => {
    const tzun = await Tzun.init();

    // Capture on original chain
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 1 },
      action: 'approved',
      reason: 'First',
    });

    // First fork
    const fork1 = await tzun.recovery.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'First compromise',
      forkAfterSequence: 0,
    });

    // Capture on second chain
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { step: 2 },
      action: 'approved',
      reason: 'Second chain',
    });

    // Second fork
    const fork2 = await tzun.recovery.fork('inc-002', {
      authorizedBy: 'admin@acme.example',
      reason: 'Second compromise',
      forkAfterSequence: 0,
    });

    // Third chain should reference second chain as parent
    expect(fork2.newChain.parentChainId).toBe(fork1.newChain.chainId);

    // All chains queryable
    const chains = await tzun.getStorage().listChains();
    expect(chains.length).toBeGreaterThanOrEqual(2);
    const sealed = chains.filter((c) => c.status === 'sealed');
    expect(sealed.length).toBeGreaterThanOrEqual(2);
  });
});
