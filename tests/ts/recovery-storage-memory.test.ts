import { MemoryStorageAdapter } from '../../src/storage/memory';
import { AnnotationRecord, RelinkRecord, ForkRecord } from '@tzun/engine';

describe('Recovery Storage (Memory)', () => {
  let adapter: MemoryStorageAdapter;

  beforeEach(() => {
    adapter = new MemoryStorageAdapter();
  });

  describe('Annotations', () => {
    const annotation: AnnotationRecord = {
      id: 'ann-001',
      incidentId: 'inc-001',
      affectedRecords: ['ev-001', 'ev-002'],
      annotatedAt: '2026-04-04T10:00:00Z',
      annotatedBy: 'admin@acme.example',
      notes: 'Tampering detected and acknowledged',
      originalDigests: {
        'ev-001': 'a'.repeat(64),
        'ev-002': 'b'.repeat(64),
      },
    };

    it('stores and retrieves an annotation', async () => {
      await adapter.storeAnnotation(annotation);
      const retrieved = await adapter.getAnnotation('ann-001');
      expect(retrieved).toEqual(annotation);
    });

    it('returns null for non-existent annotation', async () => {
      const result = await adapter.getAnnotation('non-existent');
      expect(result).toBeNull();
    });

    it('lists annotations for an incident', async () => {
      await adapter.storeAnnotation(annotation);
      await adapter.storeAnnotation({
        ...annotation,
        id: 'ann-002',
        incidentId: 'inc-002',
      });
      const results = await adapter.listAnnotations('inc-001');
      expect(results).toHaveLength(1);
      expect(results[0].id).toBe('ann-001');
    });

    it('lists annotations for affected records', async () => {
      await adapter.storeAnnotation(annotation);
      const results = await adapter.listAnnotationsForRecord('ev-001');
      expect(results).toHaveLength(1);
      expect(results[0].id).toBe('ann-001');
    });

    it('returns empty array when no annotations exist for a record', async () => {
      const results = await adapter.listAnnotationsForRecord('ev-999');
      expect(results).toEqual([]);
    });
  });

  describe('Relinks', () => {
    const relink: RelinkRecord = {
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
          previousChainLink: 'old-5',
          newChainLink: 'new-5',
        },
      ],
    };

    it('stores and retrieves a relink record', async () => {
      await adapter.storeRelink(relink);
      const retrieved = await adapter.getRelink('rlk-001');
      expect(retrieved).toEqual(relink);
    });

    it('returns null for non-existent relink', async () => {
      const result = await adapter.getRelink('non-existent');
      expect(result).toBeNull();
    });

    it('lists relinks for an incident', async () => {
      await adapter.storeRelink(relink);
      const results = await adapter.listRelinks('inc-001');
      expect(results).toHaveLength(1);
      expect(results[0].id).toBe('rlk-001');
    });
  });

  describe('Forks', () => {
    const fork: ForkRecord = {
      id: 'frk-001',
      incidentId: 'inc-001',
      forkedAt: '2026-04-04T10:00:00Z',
      forkedBy: 'admin@acme.example',
      reason: 'Chain compromised beyond repair',
      oldChainId: 'chain-001',
      newChainId: 'chain-002',
      forkAfterSequence: 49,
      sealedOldChainLength: 100,
    };

    it('stores and retrieves a fork record', async () => {
      await adapter.storeFork(fork);
      const retrieved = await adapter.getFork('frk-001');
      expect(retrieved).toEqual(fork);
    });

    it('returns null for non-existent fork', async () => {
      const result = await adapter.getFork('non-existent');
      expect(result).toBeNull();
    });

    it('lists forks for an incident', async () => {
      await adapter.storeFork(fork);
      const results = await adapter.listForks('inc-001');
      expect(results).toHaveLength(1);
      expect(results[0].id).toBe('frk-001');
    });

    it('lists forks by chain ID', async () => {
      await adapter.storeFork(fork);
      const results = await adapter.listForksForChain('chain-001');
      expect(results).toHaveLength(1);
      expect(results[0].oldChainId).toBe('chain-001');
    });
  });
});
