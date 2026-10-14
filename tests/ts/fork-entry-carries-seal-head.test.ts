/**
 * A 'chain_forked' custody entry carries the sealed old chain's head.
 *
 * fork() seals the old chain and records its head sequence on the ForkRecord
 * (`sealedOldChainHead`). The custody entry it appends to each record after the
 * fork point also carries that head and the canonical digest of the record at
 * it, so the seal bound sits inside the hashed custody entry and an auditor
 * holding only the exported envelope can check it offline.
 *
 * - `sealedOldChainHead`: the same number as `ForkRecord.sealedOldChainHead`.
 * - `sealedOldChainHeadDigest`: the canonicalDigest of the old-chain record at
 *   that sequence when it is present; otherwise the store's last digest, read
 *   at the same point as the head (it pairs with `getLastSequence()` and is
 *   still the old chain's until the SDK's `resetChainState()`).
 *
 * Legs: memory and sqlite.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { assembleEnvelope, SchemaRegistry, verifyCustodyTrail } from '@tzun/engine';
import type { EnvelopeInput, CustodyEntry, EvidenceEnvelope, StorageAdapter } from '@tzun/engine';
import { RecoveryManager } from '../../src/monitoring/recovery-manager';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { withSqliteEnvelopeTriggersLifted } from './helpers/tamper-store';

const CHAIN = 'chain-001';
const registry = new SchemaRegistry();

const input: EnvelopeInput = {
  aiSystemId: 'test-system',
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Test',
  decider: { kind: 'human' as const, id: 'acct:tester-acme.com', agent: null, credential: null, freshness: null },
};

async function captureSequence(adapter: StorageAdapter, count: number): Promise<EvidenceEnvelope[]> {
  const envelopes: EvidenceEnvelope[] = [];
  let previousDigest: string | undefined;
  for (let i = 1; i <= count; i++) {
    const envelope = assembleEnvelope(input, { previousDigest: previousDigest, sequenceNumber: i });
    previousDigest = envelope.integrity.canonicalDigest;
    await adapter.store(envelope, CHAIN);
    envelopes.push(envelope);
  }
  return envelopes;
}

interface Leg {
  name: 'memory' | 'sqlite';
  make: () => { adapter: StorageAdapter; teardown: () => void };
  /** Remove a stored record behind the adapter's back, as an insider would. */
  deleteRecord: (adapter: StorageAdapter, evidenceId: string) => void;
}

const legs: Leg[] = [
  {
    name: 'memory',
    make: () => {
      const adapter = new MemoryStorageAdapter();
      return { adapter, teardown: () => adapter.close() };
    },
    deleteRecord: (adapter, evidenceId) => {
      const mem = adapter as unknown as {
        envelopes: Map<string, unknown>;
        recordChainMap: Map<string, string>;
        insertionOrder: string[];
      };
      mem.envelopes.delete(evidenceId);
      mem.recordChainMap.delete(evidenceId);
      const idx = mem.insertionOrder.indexOf(evidenceId);
      if (idx !== -1) mem.insertionOrder.splice(idx, 1);
    },
  },
  {
    name: 'sqlite',
    make: () => {
      const dbPath = path.join(
        os.tmpdir(),
        `tzun-test-fork-${Date.now()}-${Math.random().toString(36).slice(2)}.db`,
      );
      const adapter = new SqliteStorageAdapter(dbPath);
      return {
        adapter,
        teardown: () => {
          adapter.close();
          for (const suffix of ['', '-wal', '-shm']) {
            try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
          }
        },
      };
    },
    deleteRecord: (adapter, evidenceId) => {
      const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
      const result = withSqliteEnvelopeTriggersLifted(db, () =>
        db.prepare('DELETE FROM envelopes WHERE evidence_id = ?').run(evidenceId),
      );
      if (result.changes !== 1) throw new Error(`expected to delete 1 row for ${evidenceId}`);
    },
  },
];

describe.each(legs)('fork() chain_forked entry carries the sealed head ($name)', (leg) => {
  let adapter: StorageAdapter;
  let teardown: () => void;
  let manager: RecoveryManager;
  let envelopes: EvidenceEnvelope[];

  beforeEach(async () => {
    ({ adapter, teardown } = leg.make());
    manager = new RecoveryManager(adapter, registry);
    await adapter.storeChain({ chainId: CHAIN, status: 'active', createdAt: '2026-09-19T10:00:00Z' });
    envelopes = await captureSequence(adapter, 4);
  });

  afterEach(() => teardown());

  async function forkedEntries(evidenceId: string): Promise<{ envelope: EvidenceEnvelope; entries: CustodyEntry[] }> {
    const envelope = (await adapter.retrieve(evidenceId))!;
    return { envelope, entries: envelope.custodyChain.filter((e) => e.action === 'chain_forked') };
  }

  it('records 3 and 4 carry sealedOldChainHead 4 and record 4\'s digest, and still verify offline', async () => {
    const result = await manager.fork('inc-seal-head', {
      authorizedBy: 'admin@acme.example',
      reason: 'Chain compromised after sequence 2.',
      forkAfterSequence: 2,
    });
    expect(result.fork.sealedOldChainHead).toBe(4);

    for (const envelope of envelopes.slice(2)) {
      const { envelope: stored, entries } = await forkedEntries(envelope.payload.evidenceId);
      expect(entries).toHaveLength(1);
      expect(entries[0].metadata).toEqual({
        incidentId: 'inc-seal-head',
        forkId: result.fork.id,
        oldChainId: CHAIN,
        newChainId: result.newChain.chainId,
        forkAfterSequence: 2,
        recoveryTier: 'fork',
        sealedOldChainHead: 4,
        sealedOldChainHeadDigest: envelopes[3].integrity.canonicalDigest,
      });
      expect(entries[0].metadata!.sealedOldChainHead).toBe(result.fork.sealedOldChainHead);
      expect(verifyCustodyTrail(stored).valid).toBe(true);
    }

    // Records at or before the fork point get no entry.
    for (const envelope of envelopes.slice(0, 2)) {
      expect((await forkedEntries(envelope.payload.evidenceId)).entries).toHaveLength(0);
    }
  });

  it('keeps the existing metadata keys in order and appends the two seal fields last', async () => {
    await manager.fork('inc-seal-head', {
      authorizedBy: 'admin@acme.example',
      reason: 'Chain compromised after sequence 2.',
      forkAfterSequence: 2,
    });

    const { entries } = await forkedEntries(envelopes[2].payload.evidenceId);
    expect(Object.keys(entries[0].metadata!)).toEqual([
      'incidentId',
      'forkId',
      'oldChainId',
      'newChainId',
      'forkAfterSequence',
      'recoveryTier',
      'sealedOldChainHead',
      'sealedOldChainHeadDigest',
    ]);
  });

  it('uses the store\'s last digest when the old chain\'s tail record was deleted before the fork', async () => {
    leg.deleteRecord(adapter, envelopes[3].payload.evidenceId);
    expect(await adapter.retrieve(envelopes[3].payload.evidenceId)).toBeNull();

    const result = await manager.fork('inc-seal-head', {
      authorizedBy: 'admin@acme.example',
      reason: 'Tail record deleted; sealing the chain.',
      forkAfterSequence: 2,
    });
    // The counter still says 4, so the deleted tail stays inside the bound.
    expect(result.fork.sealedOldChainHead).toBe(4);

    const { envelope: stored, entries } = await forkedEntries(envelopes[2].payload.evidenceId);
    expect(entries).toHaveLength(1);
    expect(entries[0].metadata!.sealedOldChainHead).toBe(4);
    expect(entries[0].metadata!.sealedOldChainHeadDigest).toBe(envelopes[3].integrity.canonicalDigest);
    expect(verifyCustodyTrail(stored).valid).toBe(true);
  });
});
