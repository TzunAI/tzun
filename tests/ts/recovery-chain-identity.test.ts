import { MemoryStorageAdapter } from '../../src/storage/memory';
import { ChainIdentity } from '@tzun/engine';
import { EvidenceEnvelope } from '@tzun/engine';

function makeEnvelope(overrides: Partial<{
  evidenceId: string;
  aiSystemId: string;
  capturedAt: string;
  digest: string;
  sequenceNumber: number;
  chainId: string;
}> = {}): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: overrides.evidenceId ?? 'ev-001',
      schemaVersion: 'v1.0',
      aiSystemId: overrides.aiSystemId ?? 'openai-gpt4',
      aiOutput: { recommendation: 'approve', confidence: 0.94 },
      action: 'approved',
      reason: 'All criteria met',
      capturedAt: overrides.capturedAt ?? '2026-03-22T10:00:00.000Z',
      sequenceNumber: overrides.sequenceNumber ?? 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: {
      canonicalDigest: overrides.digest ?? 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
      chainLink: null,
    },
    nonRepudiation: {},
    custodyChain: [{
      timestamp: '2026-03-22T10:00:00.000Z',
      actor: 'jane@acme.example',
      action: 'decision_captured',
      systemId: 'openai-gpt4',
    }],
    attestationStatus: 'none',
  };
}

describe('Chain Identity Storage (Memory)', () => {
  let adapter: MemoryStorageAdapter;

  beforeEach(() => {
    adapter = new MemoryStorageAdapter();
  });

  it('creates a genesis chain identity', async () => {
    const chain: ChainIdentity = {
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    };
    await adapter.storeChain(chain);
    const retrieved = await adapter.getChain('chain-001');
    expect(retrieved).toEqual(chain);
  });

  it('returns null for non-existent chain', async () => {
    const result = await adapter.getChain('non-existent');
    expect(result).toBeNull();
  });

  it('lists all chains', async () => {
    await adapter.storeChain({
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    });
    await adapter.storeChain({
      chainId: 'chain-002',
      parentChainId: 'chain-001',
      forkPoint: 49,
      status: 'active',
      createdAt: '2026-04-04T11:00:00Z',
    });
    const chains = await adapter.listChains();
    expect(chains).toHaveLength(2);
  });

  it('updates chain status to sealed', async () => {
    await adapter.storeChain({
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    });
    await adapter.sealChain('chain-001', '2026-04-04T12:00:00Z');
    const chain = await adapter.getChain('chain-001');
    expect(chain!.status).toBe('sealed');
    expect(chain!.sealedAt).toBe('2026-04-04T12:00:00Z');
  });

  it('stores envelope with chainId', async () => {
    const envelope = makeEnvelope({ evidenceId: 'ev-001' });
    await adapter.store(envelope, 'chain-001');
    const retrieved = await adapter.retrieve('ev-001');
    expect(retrieved).toEqual(envelope);
  });

  it('lists envelopes filtered by chainId', async () => {
    await adapter.store(
      makeEnvelope({ evidenceId: 'ev-001', digest: 'a'.repeat(64) }),
      'chain-001',
    );
    await adapter.store(
      makeEnvelope({ evidenceId: 'ev-002', digest: 'b'.repeat(64) }),
      'chain-002',
    );
    const chain1Records = await adapter.list({ chainId: 'chain-001' });
    expect(chain1Records).toHaveLength(1);
    expect(chain1Records[0].payload.evidenceId).toBe('ev-001');
  });

  it('getChainForRecord returns the chainId for a stored record', async () => {
    await adapter.store(
      makeEnvelope({ evidenceId: 'ev-001' }),
      'chain-001',
    );
    const chainId = await adapter.getChainForRecord('ev-001');
    expect(chainId).toBe('chain-001');
  });

  it('getChainForRecord returns null for non-existent record', async () => {
    const chainId = await adapter.getChainForRecord('non-existent');
    expect(chainId).toBeNull();
  });

  it('store without chainId uses default chain', async () => {
    const envelope = makeEnvelope({ evidenceId: 'ev-001' });
    await adapter.store(envelope);
    const chainId = await adapter.getChainForRecord('ev-001');
    expect(chainId).toBe('default');
  });

  it('getActiveChainId returns the active chain', async () => {
    await adapter.storeChain({
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    });
    const activeId = await adapter.getActiveChainId();
    expect(activeId).toBe('chain-001');
  });

  it('getActiveChainId returns the newest active chain after fork', async () => {
    await adapter.storeChain({
      chainId: 'chain-001',
      status: 'sealed',
      createdAt: '2026-04-04T10:00:00Z',
      sealedAt: '2026-04-04T12:00:00Z',
    });
    await adapter.storeChain({
      chainId: 'chain-002',
      parentChainId: 'chain-001',
      forkPoint: 49,
      status: 'active',
      createdAt: '2026-04-04T12:00:00Z',
    });
    const activeId = await adapter.getActiveChainId();
    expect(activeId).toBe('chain-002');
  });
});
