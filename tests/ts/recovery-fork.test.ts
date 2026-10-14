import type { EnvelopeInput } from '@tzun/engine';
import { RecoveryManager } from '../../src/monitoring/recovery-manager';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SchemaRegistry } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { MonitoringEvent } from '@tzun/engine';
import { CaptureInput, EvidenceEnvelope } from '@tzun/engine';

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

describe('RecoveryManager.fork (Tier 3)', () => {
  let adapter: MemoryStorageAdapter;
  let registry: SchemaRegistry;
  let manager: RecoveryManager;
  let envelopes: EvidenceEnvelope[];

  beforeEach(async () => {
    adapter = new MemoryStorageAdapter();
    registry = new SchemaRegistry();
    manager = new RecoveryManager(adapter, registry);

    // Set up initial chain identity
    await adapter.storeChain({
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    });

    envelopes = await captureSequence(adapter, 5);
  });

  it('seals the old chain', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Chain compromised beyond repair from sequence 4',
      forkAfterSequence: 3,
    });

    const oldChain = await adapter.getChain(result.fork.oldChainId);
    expect(oldChain!.status).toBe('sealed');
    expect(oldChain!.sealedAt).toBeDefined();
  });

  it('creates a new chain with a new chainId', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    expect(result.newChain.chainId).toBeDefined();
    expect(result.newChain.chainId).not.toBe('chain-001');
    expect(result.newChain.status).toBe('active');
  });

  it('new chain references old chain and fork point', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    expect(result.newChain.parentChainId).toBe('chain-001');
    expect(result.newChain.forkPoint).toBe(3);
  });

  it('creates a ForkRecord with cross-references', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    expect(result.fork.oldChainId).toBe('chain-001');
    expect(result.fork.newChainId).toBe(result.newChain.chainId);
    expect(result.fork.forkAfterSequence).toBe(3);
    expect(result.fork.sealedOldChainLength).toBe(5);
    // The sealed chain's HEAD, recorded distinctly from the row count.
    // Equal here only because this fixture has no gaps.
    expect(result.fork.sealedOldChainHead).toBe(5);
    expect(result.fork.forkedBy).toBe('admin@acme.example');
    expect(result.fork.reason).toBe('Compromised');
  });

  it('stores the ForkRecord in the storage adapter', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    const stored = await adapter.getFork(result.fork.id);
    expect(stored).toEqual(result.fork);
  });

  it('old chain remains fully queryable after fork', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    // All 5 records still accessible
    for (const envelope of envelopes) {
      const retrieved = await adapter.retrieve(envelope.payload.evidenceId);
      expect(retrieved).not.toBeNull();
    }

    // Old chain records queryable by chainId
    const oldChainRecords = await adapter.list({ chainId: 'chain-001' });
    expect(oldChainRecords).toHaveLength(5);
  });

  it('appends chain_forked custody entry to affected records', async () => {
    await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    // Records after the fork point should get chain_forked custody entries
    for (let i = 3; i < envelopes.length; i++) {
      const envelope = await adapter.retrieve(envelopes[i].payload.evidenceId);
      const forkEntries = envelope!.custodyChain.filter((e) => e.action === 'chain_forked');
      expect(forkEntries.length).toBeGreaterThanOrEqual(1);
    }
  });

  it('throws if authorizedBy is empty', async () => {
    await expect(
      manager.fork('inc-001', {
        authorizedBy: '',
        reason: 'Compromised',
        forkAfterSequence: 3,
      }),
    ).rejects.toThrow('authorizedBy is required');
  });

  it('throws if reason is empty', async () => {
    await expect(
      manager.fork('inc-001', {
        authorizedBy: 'admin@acme.example',
        reason: '',
        forkAfterSequence: 3,
      }),
    ).rejects.toThrow('reason is required');
  });

  it('throws if forkAfterSequence is less than 0', async () => {
    await expect(
      manager.fork('inc-001', {
        authorizedBy: 'admin@acme.example',
        reason: 'Compromised',
        forkAfterSequence: -1,
      }),
    ).rejects.toThrow('forkAfterSequence must be >= 0');
  });
});

describe('RecoveryManager.fork event emission', () => {
  it('emits chain_forked event through the event bus', async () => {
    const adapter = new MemoryStorageAdapter();
    const registry = new SchemaRegistry();
    const eventBus = new MonitoringEventBus();
    const events: MonitoringEvent[] = [];
    eventBus.subscribe((event) => events.push(event));
    const manager = new RecoveryManager(adapter, registry, eventBus);

    await adapter.storeChain({
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    });
    await captureSequence(adapter, 3);

    await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 1,
    });

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('chain_forked');
    if (events[0].type === 'chain_forked') {
      expect(events[0].forkPoint).toBe(1);
      expect(events[0].authorizedBy).toBe('admin@acme.example');
    }
  });
});

// ---------------------------------------------------------------------------
// The shipped path: fork on the default chain
//
// Every test above pre-creates a 'chain-001' identity and stores records under
// it. No SDK deployment does that: `Tzun.capture()` stores under
// `activeChainId`, which is 'default' until something creates a chain, so this
// is the path every real fork takes. fork() must seal 'default', the chain the
// records are tagged with; sealing a freshly minted id instead would seal an
// empty name and leave every captured record on an open chain.
// ---------------------------------------------------------------------------
describe('RecoveryManager.fork on the default chain', () => {
  let adapter: MemoryStorageAdapter;
  let manager: RecoveryManager;
  let defaultEnvelopes: EvidenceEnvelope[];

  beforeEach(async () => {
    adapter = new MemoryStorageAdapter();
    manager = new RecoveryManager(adapter, new SchemaRegistry());
    // No storeChain() call — exactly what an SDK store looks like before its
    // first fork.
    defaultEnvelopes = await captureSequence(adapter, 3, 'default');
  });

  it('seals the chain that actually owns the records', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    // The sealed chain is the one the records are tagged with.
    expect(result.fork.oldChainId).toBe('default');
    for (const envelope of defaultEnvelopes) {
      expect(await adapter.getChainForRecord(envelope.payload.evidenceId)).toBe(
        result.fork.oldChainId,
      );
    }

    // ...and it is therefore non-empty, which is the whole point of sealing it.
    expect(await adapter.getChainLength(result.fork.oldChainId)).toBe(3);
    expect(await adapter.list({ chainId: result.fork.oldChainId })).toHaveLength(3);
    expect(result.fork.sealedOldChainLength).toBe(3);

    const oldChain = await adapter.getChain(result.fork.oldChainId);
    expect(oldChain!.status).toBe('sealed');
  });

  it('refuses further appends to the sealed chain', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    const intruder = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'test-system',
        aiOutput: { recommendation: 'approve' },
        action: 'approved',
        reason: 'appended after the seal',
      }, { sequenceNumber: 4 });

    await expect(adapter.store(intruder, result.fork.oldChainId)).rejects.toThrow(
      /sealed/i,
    );
    // And nothing was written.
    expect(await adapter.getChainLength(result.fork.oldChainId)).toBe(3);
    expect(await adapter.retrieve(intruder.payload.evidenceId)).toBeNull();
  });

  it('still accepts appends to the chain the fork created', async () => {
    const result = await manager.fork('inc-001', {
      authorizedBy: 'admin@acme.example',
      reason: 'Compromised',
      forkAfterSequence: 3,
    });

    const next = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'test-system',
        aiOutput: { recommendation: 'approve' },
        action: 'approved',
        reason: 'first record on the new chain',
      }, { sequenceNumber: 1 });

    await adapter.store(next, result.newChain.chainId);
    expect(await adapter.getChainLength(result.newChain.chainId)).toBe(1);
  });

  it('leaves a store that has never forked writable', async () => {
    // The guard must key on an explicit 'sealed' status, not on the absence of
    // a chain identity — chain identities are created lazily, so every store
    // before its first fork has none.
    const fresh = new MemoryStorageAdapter();
    const envelope = assembleEnvelope({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'test-system',
        aiOutput: { recommendation: 'approve' },
        action: 'approved',
        reason: 'no chain identity exists',
      }, { sequenceNumber: 1 });
    await expect(fresh.store(envelope)).resolves.toBeUndefined();
    await expect(
      fresh.store({ ...envelope, payload: { ...envelope.payload, evidenceId: 'ev-x' } }, 'never-created'),
    ).resolves.toBeUndefined();
  });
});
