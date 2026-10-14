import { MemoryStorageAdapter } from '../../src/storage/memory';
import { TamperIncident, TamperIncidentStatus, TamperSeverity, MonitoringEventType } from '@tzun/engine';

function makeIncident(overrides: Partial<TamperIncident> = {}): TamperIncident {
  return {
    id: overrides.id ?? 'inc-001',
    detectedAt: overrides.detectedAt ?? '2026-04-04T10:00:00.000Z',
    severity: overrides.severity ?? 'critical',
    type: overrides.type ?? 'digest_mismatch',
    affectedRecords: overrides.affectedRecords ?? ['ev-001'],
    affectedSequenceRange: overrides.affectedSequenceRange,
    details: overrides.details ?? 'Digest mismatch detected on ev-001',
    status: overrides.status ?? 'open',
    resolvedAt: overrides.resolvedAt,
    resolvedBy: overrides.resolvedBy,
    resolutionNotes: overrides.resolutionNotes,
  };
}

describe('Incident storage (MemoryStorageAdapter)', () => {
  let adapter: MemoryStorageAdapter;

  beforeEach(() => {
    adapter = new MemoryStorageAdapter();
  });

  it('stores and retrieves incident by id', async () => {
    const incident = makeIncident();
    await adapter.storeIncident(incident);
    const retrieved = await adapter.getIncident('inc-001');
    expect(retrieved).toEqual(incident);
  });

  it('returns null for non-existent incident', async () => {
    const result = await adapter.getIncident('non-existent');
    expect(result).toBeNull();
  });

  it('lists all incidents', async () => {
    await adapter.storeIncident(makeIncident({ id: 'inc-001' }));
    await adapter.storeIncident(makeIncident({ id: 'inc-002' }));
    await adapter.storeIncident(makeIncident({ id: 'inc-003' }));
    const results = await adapter.listIncidents();
    expect(results).toHaveLength(3);
  });

  it('lists filtered by status', async () => {
    await adapter.storeIncident(makeIncident({ id: 'inc-001', status: 'open' }));
    await adapter.storeIncident(makeIncident({ id: 'inc-002', status: 'acknowledged' }));
    await adapter.storeIncident(makeIncident({ id: 'inc-003', status: 'open' }));
    const results = await adapter.listIncidents({ status: 'open' });
    expect(results).toHaveLength(2);
    expect(results.every((i) => i.status === 'open')).toBe(true);
  });

  it('lists filtered by severity', async () => {
    await adapter.storeIncident(makeIncident({ id: 'inc-001', severity: 'critical' }));
    await adapter.storeIncident(makeIncident({ id: 'inc-002', severity: 'warning' }));
    await adapter.storeIncident(makeIncident({ id: 'inc-003', severity: 'info' }));
    const results = await adapter.listIncidents({ severity: 'warning' });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe('inc-002');
  });

  it('updates incident status', async () => {
    await adapter.storeIncident(makeIncident({ id: 'inc-001', status: 'open' }));
    await adapter.updateIncidentStatus('inc-001', 'acknowledged');
    const updated = await adapter.getIncident('inc-001');
    expect(updated?.status).toBe('acknowledged');
  });

  it('updates to resolved with metadata', async () => {
    await adapter.storeIncident(makeIncident({ id: 'inc-001', status: 'open' }));
    await adapter.updateIncidentStatus('inc-001', 'resolved', {
      resolvedBy: 'admin@acme.example',
      resolutionNotes: 'False positive confirmed',
    });
    const updated = await adapter.getIncident('inc-001');
    expect(updated?.status).toBe('resolved');
    expect(updated?.resolvedBy).toBe('admin@acme.example');
    expect(updated?.resolutionNotes).toBe('False positive confirmed');
    expect(updated?.resolvedAt).toBeDefined();
    // resolvedAt should be a valid ISO-8601 timestamp
    expect(new Date(updated!.resolvedAt!).toISOString()).toBe(updated!.resolvedAt);
  });

  it('throws updating non-existent incident', async () => {
    await expect(
      adapter.updateIncidentStatus('non-existent', 'acknowledged')
    ).rejects.toThrow('non-existent');
  });

  it('rejects duplicate incident id', async () => {
    const incident = makeIncident();
    await adapter.storeIncident(incident);
    await expect(adapter.storeIncident(incident)).rejects.toThrow('already exists');
  });
});
