import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { EvidenceEnvelope } from '@tzun/engine';
import { FailureRecord } from '@tzun/engine';

function makeEnvelope(overrides: Partial<{
  evidenceId: string;
  aiSystemId: string;
  capturedAt: string;
  digest: string;
  sequenceNumber: number;
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

/** A 64-hex digest unique to `label`: one per record, as the evidence log requires. */
const dg = (label: string): string => require('crypto').createHash('sha256').update(label).digest('hex');

describe('SqliteStorageAdapter', () => {
  let adapter: SqliteStorageAdapter;
  let dbPath: string;

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `tzun-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    adapter = new SqliteStorageAdapter(dbPath);
  });

  afterEach(() => {
    adapter.close();
    try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
    try { fs.unlinkSync(dbPath + '-wal'); } catch { /* ignore */ }
    try { fs.unlinkSync(dbPath + '-shm'); } catch { /* ignore */ }
  });

  it('creates tables on initialization', () => {
    expect(adapter).toBeDefined();
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

  it('stores and tracks last digest via chain_state table', async () => {
    expect(await adapter.getLastDigest()).toBeNull();
    await adapter.store(makeEnvelope({ digest: 'a'.repeat(64) }));
    expect(await adapter.getLastDigest()).toBe('a'.repeat(64));

    // Create a fresh adapter pointing at the same DB to verify persistence
    const adapter2 = new SqliteStorageAdapter(dbPath);
    expect(await adapter2.getLastDigest()).toBe('a'.repeat(64));
    adapter2.close();
  });

  it('stores and tracks last sequence number', async () => {
    expect(await adapter.getLastSequence()).toBe(0);
    await adapter.store(makeEnvelope({ sequenceNumber: 1 }));
    expect(await adapter.getLastSequence()).toBe(1);

    // Verify persistence with a fresh adapter
    const adapter2 = new SqliteStorageAdapter(dbPath);
    expect(await adapter2.getLastSequence()).toBe(1);
    adapter2.close();
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

  // -------------------------------------------------------------------------
  // Sealed chains are read-only
  //
  // `sealChain()` was a label: no adapter consulted chain status on the write
  // path, so the chain an operator had just been told was sealed kept
  // accepting appends.
  // -------------------------------------------------------------------------
  it('refuses to append to a sealed chain', async () => {
    await adapter.storeChain({
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    });
    await adapter.store(makeEnvelope({ evidenceId: 'ev-before' }), 'chain-001');
    await adapter.sealChain('chain-001', '2026-04-04T11:00:00Z');

    await expect(
      adapter.store(makeEnvelope({ evidenceId: 'ev-after', sequenceNumber: 2 }), 'chain-001'),
    ).rejects.toThrow(/sealed/i);

    expect(await adapter.retrieve('ev-after')).toBeNull();
    expect(await adapter.getChainLength('chain-001')).toBe(1);
  });

  it('still accepts appends to an active chain and to a chain with no identity', async () => {
    await adapter.storeChain({
      chainId: 'chain-open',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    });
    await expect(
      adapter.store(makeEnvelope({ evidenceId: 'ev-open' }), 'chain-open'),
    ).resolves.toBeUndefined();
    // No identity row at all — the shipped default path before its first fork.
    await expect(
      adapter.store(makeEnvelope({ evidenceId: 'ev-implicit', sequenceNumber: 1 })),
    ).resolves.toBeUndefined();
  });
});
