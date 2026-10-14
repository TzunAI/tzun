import {
  AnnotationRecord,
  RelinkRecord,
  ForkRecord,
  ChainIdentity,
  AnnotateOptions,
  RelinkOptions,
  ForkOptions,
  AnnotationResult,
  RelinkResult,
  ForkResult,
} from '@tzun/engine';

describe('Recovery Types', () => {
  it('AnnotationRecord has required fields', () => {
    const record: AnnotationRecord = {
      id: 'ann-001',
      incidentId: 'inc-001',
      affectedRecords: ['ev-001', 'ev-002'],
      annotatedAt: '2026-04-04T10:00:00Z',
      annotatedBy: 'admin@acme.example',
      notes: 'Tampering detected and acknowledged',
      originalDigests: {
        'ev-001': 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
        'ev-002': 'efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678',
      },
    };
    expect(record.id).toBe('ann-001');
    expect(record.incidentId).toBe('inc-001');
    expect(record.affectedRecords).toHaveLength(2);
    expect(record.annotatedBy).toBe('admin@acme.example');
    expect(record.originalDigests['ev-001']).toMatch(/^[a-f0-9]{64}$/);
  });

  it('RelinkRecord captures before/after chain link state', () => {
    const record: RelinkRecord = {
      id: 'rlk-001',
      incidentId: 'inc-001',
      relinkedAt: '2026-04-04T10:00:00Z',
      relinkedBy: 'admin@acme.example',
      fromSequence: 5,
      toSequence: 10,
      modifiedLinks: [
        {
          evidenceId: 'ev-005',
          sequenceNumber: 5,
          previousChainLink: 'old-link-5',
          newChainLink: 'new-link-5',
        },
        {
          evidenceId: 'ev-006',
          sequenceNumber: 6,
          previousChainLink: 'old-link-6',
          newChainLink: 'new-link-6',
        },
      ],
    };
    expect(record.modifiedLinks).toHaveLength(2);
    expect(record.fromSequence).toBe(5);
    expect(record.toSequence).toBe(10);
  });

  it('ForkRecord cross-references old and new chains', () => {
    const record: ForkRecord = {
      id: 'frk-001',
      incidentId: 'inc-001',
      forkedAt: '2026-04-04T10:00:00Z',
      forkedBy: 'admin@acme.example',
      reason: 'Chain compromised beyond repair from sequence 50 onward',
      oldChainId: 'chain-001',
      newChainId: 'chain-002',
      forkAfterSequence: 49,
      sealedOldChainLength: 100,
    };
    expect(record.oldChainId).toBe('chain-001');
    expect(record.newChainId).toBe('chain-002');
    expect(record.forkAfterSequence).toBe(49);
  });

  it('ChainIdentity tracks chain lineage', () => {
    const genesis: ChainIdentity = {
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    };
    expect(genesis.parentChainId).toBeUndefined();
    expect(genesis.forkPoint).toBeUndefined();

    const forked: ChainIdentity = {
      chainId: 'chain-002',
      parentChainId: 'chain-001',
      forkPoint: 49,
      status: 'active',
      createdAt: '2026-04-04T11:00:00Z',
    };
    expect(forked.parentChainId).toBe('chain-001');
    expect(forked.forkPoint).toBe(49);
  });

  it('RelinkOptions specifies repair range', () => {
    const opts: RelinkOptions = {
      authorizedBy: 'admin@acme.example',
      fromSequence: 5,
    };
    expect(opts.toSequence).toBeUndefined();
    expect(opts.correctedPayload).toBeUndefined();

    const optsWithPayload: RelinkOptions = {
      authorizedBy: 'admin@acme.example',
      fromSequence: 5,
      toSequence: 10,
      correctedPayload: { evidenceId: 'ev-005', aiOutput: { corrected: true } },
    };
    expect(optsWithPayload.correctedPayload).toBeDefined();
  });

  it('AnnotateOptions requires authorizedBy and notes', () => {
    const opts: AnnotateOptions = {
      authorizedBy: 'admin@acme.example',
      notes: 'Tampering detected and acknowledged',
    };
    expect(opts.authorizedBy).toBe('admin@acme.example');
    expect(opts.notes).toBe('Tampering detected and acknowledged');
  });

  it('ForkOptions requires reason and fork point', () => {
    const opts: ForkOptions = {
      authorizedBy: 'admin@acme.example',
      reason: 'Chain compromised beyond repair',
      forkAfterSequence: 49,
    };
    expect(opts.reason).toBe('Chain compromised beyond repair');
    expect(opts.forkAfterSequence).toBe(49);
  });

  it('AnnotationResult includes the created record', () => {
    const result: AnnotationResult = {
      annotation: {
        id: 'ann-001',
        incidentId: 'inc-001',
        affectedRecords: ['ev-001'],
        annotatedAt: '2026-04-04T10:00:00Z',
        annotatedBy: 'admin@acme.example',
        notes: 'Acknowledged',
        originalDigests: { 'ev-001': 'a'.repeat(64) },
      },
      updatedIncidentStatus: 'acknowledged',
    };
    expect(result.annotation.id).toBe('ann-001');
    expect(result.updatedIncidentStatus).toBe('acknowledged');
  });

  it('RelinkResult includes the created record', () => {
    const result: RelinkResult = {
      relink: {
        id: 'rlk-001',
        incidentId: 'inc-001',
        relinkedAt: '2026-04-04T10:00:00Z',
        relinkedBy: 'admin@acme.example',
        fromSequence: 5,
        toSequence: 10,
        modifiedLinks: [],
      },
      chainVerified: true,
    };
    expect(result.chainVerified).toBe(true);
  });

  it('ForkResult includes both chain identities', () => {
    const result: ForkResult = {
      fork: {
        id: 'frk-001',
        incidentId: 'inc-001',
        forkedAt: '2026-04-04T10:00:00Z',
        forkedBy: 'admin@acme.example',
        reason: 'Compromised',
        oldChainId: 'chain-001',
        newChainId: 'chain-002',
        forkAfterSequence: 49,
        sealedOldChainLength: 100,
      },
      oldChain: {
        chainId: 'chain-001',
        status: 'sealed',
        createdAt: '2026-04-01T00:00:00Z',
        sealedAt: '2026-04-04T10:00:00Z',
      },
      newChain: {
        chainId: 'chain-002',
        parentChainId: 'chain-001',
        forkPoint: 49,
        status: 'active',
        createdAt: '2026-04-04T10:00:00Z',
      },
    };
    expect(result.oldChain.status).toBe('sealed');
    expect(result.newChain.status).toBe('active');
  });
});
