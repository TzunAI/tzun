/**
 * annotate() records a review; it never moves an incident backwards.
 *
 * The rule is the hosted service's: annotate acknowledges an `open`
 * incident and leaves every other status as it is. A resolved incident stays
 * resolved, with its resolution metadata intact, and `annotate()` returns the
 * status it stored. The `reviewed` custody entries are appended whatever the
 * status.
 *
 * The engine's TamperIncidentStatus also carries 'in_progress' — the status the
 * platform moves an acknowledged incident to when a recovery action starts on
 * it. The SDK never writes it and annotate() must not move
 * an incident out of it.
 *
 * Legs: memory and sqlite.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { assembleEnvelope, SchemaRegistry } from '@tzun/engine';
import type {
  EnvelopeInput,
  EvidenceEnvelope,
  StorageAdapter,
  TamperIncident,
  TamperIncidentStatus,
} from '@tzun/engine';
import { RecoveryManager } from '../../src/monitoring/recovery-manager';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';

const CHAIN = 'chain-001';
const INCIDENT = 'inc-annotate';
const registry = new SchemaRegistry();

const input: EnvelopeInput = {
  aiSystemId: 'test-system',
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'Test',
  decider: { kind: 'human' as const, id: 'acct:tester-acme.com', agent: null, credential: null, freshness: null },
};

function incidentFor(evidenceIds: string[]): TamperIncident {
  return {
    id: INCIDENT,
    detectedAt: new Date().toISOString(),
    severity: 'critical',
    type: 'digest_mismatch',
    affectedRecords: evidenceIds,
    details: 'Digest mismatch detected during scan.',
    status: 'open',
  };
}

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
}

const legs: Leg[] = [
  {
    name: 'memory',
    make: () => {
      const adapter = new MemoryStorageAdapter();
      return { adapter, teardown: () => adapter.close() };
    },
  },
  {
    name: 'sqlite',
    make: () => {
      const dbPath = path.join(
        os.tmpdir(),
        `tzun-test-annotate-${Date.now()}-${Math.random().toString(36).slice(2)}.db`,
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
  },
];

describe.each(legs)('RecoveryManager.annotate keeps the incident status it finds ($name)', (leg) => {
  let adapter: StorageAdapter;
  let teardown: () => void;
  let manager: RecoveryManager;
  let affectedId: string;

  beforeEach(async () => {
    ({ adapter, teardown } = leg.make());
    manager = new RecoveryManager(adapter, registry);
    const envelopes = await captureSequence(adapter, 2);
    affectedId = envelopes[0].payload.evidenceId;
    await adapter.storeIncident(incidentFor([affectedId]));
  });

  afterEach(() => teardown());

  async function reviewedEntries(evidenceId: string) {
    const envelope = await adapter.retrieve(evidenceId);
    return (envelope?.custodyChain ?? []).filter(
      (e) => e.action === 'reviewed' && e.metadata?.incidentId === INCIDENT,
    );
  }

  it('acknowledges an open incident and returns acknowledged', async () => {
    const result = await manager.annotate(INCIDENT, { authorizedBy: 'admin@acme.example', notes: 'Reviewed.' });

    expect(result.updatedIncidentStatus).toBe('acknowledged');
    expect((await adapter.getIncident(INCIDENT))?.status).toBe('acknowledged');
    expect(await reviewedEntries(affectedId)).toHaveLength(1);
  });

  it('leaves an acknowledged incident acknowledged and returns acknowledged', async () => {
    await adapter.updateIncidentStatus(INCIDENT, 'acknowledged');

    const result = await manager.annotate(INCIDENT, { authorizedBy: 'admin@acme.example', notes: 'Reviewed again.' });

    expect(result.updatedIncidentStatus).toBe('acknowledged');
    expect((await adapter.getIncident(INCIDENT))?.status).toBe('acknowledged');
    expect(await reviewedEntries(affectedId)).toHaveLength(1);
  });

  it('leaves an in_progress incident in_progress and returns in_progress', async () => {
    // The platform moves an acknowledged incident here when a recovery action
    // starts on it. A review is not the end of that
    // recovery, so annotate() must not pull the incident back to acknowledged.
    await adapter.updateIncidentStatus(INCIDENT, 'in_progress');

    const result = await manager.annotate(INCIDENT, { authorizedBy: 'admin@acme.example', notes: 'Reviewed mid-recovery.' });

    expect(result.updatedIncidentStatus).toBe('in_progress');
    expect((await adapter.getIncident(INCIDENT))?.status).toBe('in_progress');
    expect(await reviewedEntries(affectedId)).toHaveLength(1);
  });

  it('leaves a resolved incident resolved, with its resolution intact, and returns resolved', async () => {
    await adapter.updateIncidentStatus(INCIDENT, 'resolved', {
      resolvedBy: 'auditor@acme.example',
      resolutionNotes: 'Root cause found; record restored from backup.',
    });
    const resolved = await adapter.getIncident(INCIDENT);
    expect(resolved?.status).toBe('resolved');

    const result = await manager.annotate(INCIDENT, {
      authorizedBy: 'admin@acme.example',
      notes: 'Post-resolution review.',
    });

    expect(result.updatedIncidentStatus).toBe('resolved');
    const after = await adapter.getIncident(INCIDENT);
    expect(after?.status).toBe('resolved');
    expect(after?.resolvedAt).toBe(resolved?.resolvedAt);
    expect(after?.resolvedBy).toBe('auditor@acme.example');
    expect(after?.resolutionNotes).toBe('Root cause found; record restored from backup.');

    // The review is still recorded: annotation stored, custody entry appended.
    expect(await adapter.getAnnotation(result.annotation.id)).toEqual(result.annotation);
    const reviewed = await reviewedEntries(affectedId);
    expect(reviewed).toHaveLength(1);
    expect(reviewed[0].actor).toBe('admin@acme.example');
    expect(reviewed[0].metadata).toEqual({
      incidentId: INCIDENT,
      annotationId: result.annotation.id,
      recoveryTier: 'annotation',
    });
  });

  it('does not reopen an incident resolved while the review is being written', async () => {
    // A resolve that lands after annotate() first read the incident, but
    // before it sets the status, is the status annotate() must respect.
    const realAppend = adapter.appendCustodyEntry.bind(adapter);
    let resolvedMidway = false;
    adapter.appendCustodyEntry = async (...args: Parameters<StorageAdapter['appendCustodyEntry']>) => {
      const out = await realAppend(...args);
      if (!resolvedMidway) {
        resolvedMidway = true;
        await adapter.updateIncidentStatus(INCIDENT, 'resolved', { resolvedBy: 'auditor@acme.example' });
      }
      return out;
    };

    const result = await manager.annotate(INCIDENT, { authorizedBy: 'admin@acme.example', notes: 'Reviewed.' });

    expect(resolvedMidway).toBe(true);
    expect(result.updatedIncidentStatus).toBe('resolved');
    expect((await adapter.getIncident(INCIDENT))?.status).toBe('resolved');
  });

  it('fails loudly when the store does not keep the acknowledgement', async () => {
    adapter.updateIncidentStatus = async (_id: string, _status: TamperIncidentStatus) => {
      /* drops the write */
    };

    await expect(
      manager.annotate(INCIDENT, { authorizedBy: 'admin@acme.example', notes: 'Reviewed.' }),
    ).rejects.toThrow(/stored status is "open"/);
  });
});
