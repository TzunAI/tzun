import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { AnnotationRecord, RelinkRecord, ForkRecord } from '@tzun/engine';

describe('Recovery Storage (SQLite)', () => {
  let adapter: SqliteStorageAdapter;
  let dbPath: string;

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `tzun-test-recovery-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    adapter = new SqliteStorageAdapter(dbPath);
  });

  afterEach(() => {
    adapter.close();
    try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
    try { fs.unlinkSync(dbPath + '-wal'); } catch { /* ignore */ }
    try { fs.unlinkSync(dbPath + '-shm'); } catch { /* ignore */ }
  });

  it('stores and retrieves an annotation', async () => {
    const annotation: AnnotationRecord = {
      id: 'ann-001',
      incidentId: 'inc-001',
      affectedRecords: ['ev-001'],
      annotatedAt: '2026-04-04T10:00:00Z',
      annotatedBy: 'admin@acme.example',
      notes: 'Acknowledged',
      originalDigests: { 'ev-001': 'a'.repeat(64) },
    };
    await adapter.storeAnnotation(annotation);
    const retrieved = await adapter.getAnnotation('ann-001');
    expect(retrieved).toEqual(annotation);
  });

  it('stores and retrieves a relink record', async () => {
    const relink: RelinkRecord = {
      id: 'rlk-001',
      incidentId: 'inc-001',
      relinkedAt: '2026-04-04T10:00:00Z',
      relinkedBy: 'admin@acme.example',
      fromSequence: 5,
      toSequence: 10,
      modifiedLinks: [{
        evidenceId: 'ev-005',
        sequenceNumber: 5,
        previousChainLink: 'old',
        newChainLink: 'new',
      }],
    };
    await adapter.storeRelink(relink);
    const retrieved = await adapter.getRelink('rlk-001');
    expect(retrieved).toEqual(relink);
  });

  it('stores and retrieves a fork record', async () => {
    const fork: ForkRecord = {
      id: 'frk-001',
      incidentId: 'inc-001',
      forkedAt: '2026-04-04T10:00:00Z',
      forkedBy: 'admin@acme.example',
      reason: 'Compromised',
      oldChainId: 'chain-001',
      newChainId: 'chain-002',
      forkAfterSequence: 49,
      sealedOldChainLength: 100,
    };
    await adapter.storeFork(fork);
    const retrieved = await adapter.getFork('frk-001');
    expect(retrieved).toEqual(fork);
  });

  it('persists the sealed chain head distinctly from the row count', async () => {
    const fork: ForkRecord = {
      id: 'frk-seal-head',
      incidentId: 'inc-001',
      forkedAt: '2026-04-04T10:00:00Z',
      forkedBy: 'admin@acme.example',
      reason: 'Compromised',
      oldChainId: 'chain-001',
      newChainId: 'chain-002',
      forkAfterSequence: 49,
      // 100 rows, but the chain reached 103: three gaps.
      sealedOldChainLength: 100,
      sealedOldChainHead: 103,
    };
    await adapter.storeFork(fork);
    expect(await adapter.getFork('frk-seal-head')).toStrictEqual(fork);
    expect(await adapter.listForks('inc-001')).toStrictEqual([fork]);
    expect(await adapter.listForksForChain('chain-002')).toStrictEqual([fork]);
  });

  it('reads a pre-0.3.14 fork row (NULL head) back WITHOUT a sealedOldChainHead key', async () => {
    // A row exactly as 0.3.13 wrote it: no head column value at all.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const db = (adapter as any).db as import('better-sqlite3').Database;
    db.prepare(`
      INSERT INTO chain_forks (id, incident_id, forked_at, forked_by, reason, old_chain_id, new_chain_id, fork_after_sequence, sealed_old_chain_length)
      VALUES ('frk-legacy', 'inc-legacy', '2026-01-01T00:00:00Z', 'admin@acme.example', 'Compromised', 'chain-old', 'chain-new', 2, 4)
    `).run();
    const legacy = (await adapter.getFork('frk-legacy'))!;
    expect(legacy.sealedOldChainLength).toBe(4);
    expect('sealedOldChainHead' in legacy).toBe(false);
    expect(await adapter.listForksForChain('chain-old')).toStrictEqual([legacy]);
  });

  it('stores and retrieves chain identity', async () => {
    await adapter.storeChain({
      chainId: 'chain-001',
      status: 'active',
      createdAt: '2026-04-04T10:00:00Z',
    });
    const chain = await adapter.getChain('chain-001');
    expect(chain!.chainId).toBe('chain-001');
    expect(chain!.status).toBe('active');
  });

  it('seals a chain', async () => {
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

  it('persists recovery data across adapter instances', async () => {
    await adapter.storeAnnotation({
      id: 'ann-001',
      incidentId: 'inc-001',
      affectedRecords: ['ev-001'],
      annotatedAt: '2026-04-04T10:00:00Z',
      annotatedBy: 'admin@acme.example',
      notes: 'Persisted',
      originalDigests: { 'ev-001': 'a'.repeat(64) },
    });
    adapter.close();

    const adapter2 = new SqliteStorageAdapter(dbPath);
    const retrieved = await adapter2.getAnnotation('ann-001');
    expect(retrieved!.notes).toBe('Persisted');
    adapter2.close();

    // Reopen original adapter for afterEach cleanup
    adapter = new SqliteStorageAdapter(dbPath);
  });
});
