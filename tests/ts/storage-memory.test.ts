import { createHash } from 'crypto';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { EvidenceEnvelope } from '@tzun/engine';
import { FailureRecord } from '@tzun/engine';

/** A 64-hex digest named by `label`: the shape of a real digest and of an evidence-log leaf. */
const d = (label: string): string => createHash('sha256').update(label).digest('hex');

function makeEnvelope(overrides: Partial<{
  evidenceId: string;
  aiSystemId: string;
  capturedAt: string;
  digest: string;
  sequenceNumber: number;
}>= {}): EvidenceEnvelope {
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

/** A 64-hex digest unique to `label`: one per record, as the evidence log requires. */
const dg = (label: string): string => require('crypto').createHash('sha256').update(label).digest('hex');

describe('MemoryStorageAdapter', () => {
  let adapter: MemoryStorageAdapter;

  beforeEach(() => {
    adapter = new MemoryStorageAdapter();
  });

  it('stores and retrieves an envelope', async () => {
    const envelope = makeEnvelope();
    await adapter.store(envelope);
    const retrieved = await adapter.retrieve('ev-001');
    expect(retrieved).toEqual(envelope);
  });

  it('returns null for non-existent evidenceId', async () => {
    const result = await adapter.retrieve('non-existent');
    expect(result).toBeNull();
  });

  it('rejects duplicate evidenceId', async () => {
    const envelope = makeEnvelope();
    await adapter.store(envelope);
    await expect(adapter.store(envelope)).rejects.toThrow('already exists');
  });

  it('lists envelopes in descending order by default', async () => {
    await adapter.store(makeEnvelope({ evidenceId: 'ev-001', capturedAt: '2026-03-22T10:00:00.000Z', sequenceNumber: 1, digest: dg('ev-001') }));
    await adapter.store(makeEnvelope({ evidenceId: 'ev-002', capturedAt: '2026-03-22T11:00:00.000Z', sequenceNumber: 2, digest: dg('ev-002') }));
    await adapter.store(makeEnvelope({ evidenceId: 'ev-003', capturedAt: '2026-03-22T12:00:00.000Z', sequenceNumber: 3, digest: dg('ev-003') }));
    const results = await adapter.list();
    expect(results.map(e => e.payload.evidenceId)).toEqual(['ev-003', 'ev-002', 'ev-001']);
  });

  it('lists with limit and offset', async () => {
    await adapter.store(makeEnvelope({ evidenceId: 'ev-001', capturedAt: '2026-03-22T10:00:00.000Z', sequenceNumber: 1, digest: dg('ev-001') }));
    await adapter.store(makeEnvelope({ evidenceId: 'ev-002', capturedAt: '2026-03-22T11:00:00.000Z', sequenceNumber: 2, digest: dg('ev-002') }));
    await adapter.store(makeEnvelope({ evidenceId: 'ev-003', capturedAt: '2026-03-22T12:00:00.000Z', sequenceNumber: 3, digest: dg('ev-003') }));
    const results = await adapter.list({ limit: 1, offset: 1 });
    expect(results).toHaveLength(1);
    expect(results[0].payload.evidenceId).toBe('ev-002');
  });

  it('filters by aiSystemId', async () => {
    await adapter.store(makeEnvelope({ evidenceId: 'ev-001', aiSystemId: 'openai-gpt4', sequenceNumber: 1, digest: dg('ev-001') }));
    await adapter.store(makeEnvelope({ evidenceId: 'ev-002', aiSystemId: 'anthropic-claude', sequenceNumber: 2, digest: dg('ev-002') }));
    const results = await adapter.list({ aiSystemId: 'anthropic-claude' });
    expect(results).toHaveLength(1);
    expect(results[0].payload.evidenceId).toBe('ev-002');
  });

  it('stores and tracks last digest', async () => {
    expect(await adapter.getLastDigest()).toBeNull();
    const envelope = makeEnvelope({ digest: d('digest-aaa') });
    await adapter.store(envelope);
    expect(await adapter.getLastDigest()).toBe(d('digest-aaa'));
  });

  it('stores and tracks last sequence number', async () => {
    expect(await adapter.getLastSequence()).toBe(0);
    await adapter.store(makeEnvelope({ sequenceNumber: 1 }));
    expect(await adapter.getLastSequence()).toBe(1);
    await adapter.store(makeEnvelope({ evidenceId: 'ev-002', sequenceNumber: 2, digest: d('ev-002') }));
    expect(await adapter.getLastSequence()).toBe(2);
  });

  it('each chain keeps its own high-water mark, and neither falls', async () => {
    // Pre-fork records on the default chain: sequence 1..5
    for (let i = 1; i <= 5; i++) {
      await adapter.store(makeEnvelope({
        evidenceId: `ev-pre-${i}`,
        sequenceNumber: i,
        digest: d(`digest-pre-${i}`),
      }));
    }
    expect(await adapter.getLastSequence()).toBe(5);
    expect(await adapter.getLastSequence('new-chain')).toBe(0);

    // The forked chain restarts at 1 — in its OWN counter, not a store-wide
    // one, so its numbering does not continue from the other chain's head.
    await adapter.store(makeEnvelope({
      evidenceId: 'ev-post-fork-1',
      sequenceNumber: 1,
      digest: d('digest-post-fork-1'),
    }), 'new-chain');
    expect(await adapter.getLastSequence('new-chain')).toBe(1);
    expect(await adapter.getLastDigest('new-chain')).toBe(d('digest-post-fork-1'));
    // The default chain is untouched by a write to another chain.
    expect(await adapter.getLastSequence()).toBe(5);
    expect(await adapter.getLastDigest()).toBe(d('digest-pre-5'));

    // Within a chain the mark only rises, so a record at a lower position
    // cannot lower it.
    for (let i = 2; i <= 6; i++) {
      await adapter.store(makeEnvelope({
        evidenceId: `ev-post-fork-${i}`,
        sequenceNumber: i,
        digest: d(`digest-post-fork-${i}`),
      }), 'new-chain');
    }
    await expect(adapter.store(makeEnvelope({
      evidenceId: 'ev-post-fork-2b',
      sequenceNumber: 2,
      digest: d('digest-post-fork-2b'),
    }), 'new-chain')).rejects.toMatchObject({ reason: 'position_taken' });
    expect(await adapter.getLastSequence('new-chain')).toBe(6);
    expect(await adapter.getLastSequence()).toBe(5);
  });

  it('resetChainState refuses a chain whose evidence log holds leaves, and leaves every chain as it was', async () => {
    await adapter.store(makeEnvelope({ evidenceId: 'ev-a', sequenceNumber: 1, digest: d('digest-a') }));
    await adapter.store(makeEnvelope({ evidenceId: 'ev-b', sequenceNumber: 1, digest: d('digest-b') }), 'chain-b');

    await expect(adapter.resetChainState('chain-b')).rejects.toMatchObject({ code: 'chain_state_reset_refused', chainId: 'chain-b' });

    expect(await adapter.getLastSequence('chain-b')).toBe(1);
    expect(await adapter.getLastDigest('chain-b')).toBe(d('digest-b'));
    expect(await adapter.getLastSequence()).toBe(1);
    expect(await adapter.getLastDigest()).toBe(d('digest-a'));
    // The next record of the chain takes the next position, with a leaf.
    await adapter.store(makeEnvelope({ evidenceId: 'ev-b2', sequenceNumber: 2, digest: d('digest-b2') }), 'chain-b');
    expect(await adapter.getLastSequence('chain-b')).toBe(2);
  });

  it('resetChainState clears a chain whose evidence log holds no leaf', async () => {
    await adapter.resetChainState('never-written');
    expect(await adapter.getLastSequence('never-written')).toBe(0);
    expect(await adapter.getLastDigest('never-written')).toBeNull();
  });

  it('stores failure records', async () => {
    const failure: FailureRecord = {
      failureType: 'validation_failure',
      evidenceId: 'ev-001',
      diagnosticMetadata: { reason: 'missing field' },
      capturedAt: '2026-03-22T10:00:00.000Z',
    };
    await expect(adapter.storeFailure(failure)).resolves.toBeUndefined();
  });
});

describe('updateAttestation', () => {
  let adapter: MemoryStorageAdapter;

  beforeEach(() => {
    adapter = new MemoryStorageAdapter();
  });

  it('updates artifacts and status on an existing envelope', async () => {
    const envelope = makeEnvelope({ evidenceId: 'ev-upd-001' });
    await adapter.store(envelope);

    await adapter.updateAttestation(
      'ev-upd-001',
      { rfc3161Token: 'token-abc' },
      'complete'
    );

    const updated = await adapter.retrieve('ev-upd-001');
    expect(updated?.nonRepudiation.rfc3161Token).toBe('token-abc');
    expect(updated?.attestationStatus).toBe('complete');
  });

  it('merges new artifacts with existing ones without overwriting unrelated fields', async () => {
    const envelope = makeEnvelope({ evidenceId: 'ev-upd-002' });
    envelope.nonRepudiation = {
      webauthnAssertion: {
        signature: 'sig-xyz',
        credentialKeyId: 'key-001',
        algorithm: 'ES256',
      },
    };
    await adapter.store(envelope);

    await adapter.updateAttestation(
      'ev-upd-002',
      { rfc3161Token: 'token-def' },
      'complete'
    );

    const updated = await adapter.retrieve('ev-upd-002');
    expect(updated?.nonRepudiation.webauthnAssertion?.signature).toBe('sig-xyz');
    expect(updated?.nonRepudiation.rfc3161Token).toBe('token-def');
    expect(updated?.attestationStatus).toBe('complete');
  });

  it('throws for a non-existent evidenceId', async () => {
    await expect(
      adapter.updateAttestation('ev-does-not-exist', { rfc3161Token: 'x' }, 'complete')
    ).rejects.toThrow('ev-does-not-exist');
  });

  it('does not change the payload or digest', async () => {
    const envelope = makeEnvelope({ evidenceId: 'ev-upd-003', digest: d('stable-digest') });
    await adapter.store(envelope);

    await adapter.updateAttestation('ev-upd-003', { rfc3161Token: 'token-ghi' }, 'partial');

    const updated = await adapter.retrieve('ev-upd-003');
    expect(updated?.payload).toEqual(envelope.payload);
    expect(updated?.integrity.canonicalDigest).toBe(d('stable-digest'));
  });
});
