import { builtModel } from './helpers/step-model';
/**
 * ScheduledScanner AI-BOM descriptor verification tests.
 *
 * Covers:
 *   - Scanner verifies descriptors for each DEO with `aiBom !== null`.
 *     Behavior toggled by `ScannerConfig.scannerVerifyDescriptors` (default true).
 *   - The 4 descriptor-related tamper-incident types flow through the
 *     existing event bus untouched — the scanner emits them on the same
 *     MonitoringEventBus the rest of the pipeline already subscribes to.
 *
 * The scanner uses the verifier's `options.storage` + `walkLineage` path.
 * When `scannerVerifyDescriptors: false`, the scanner MUST NOT pass `storage` to
 * the verifier so the descriptor path is skipped entirely.
 */
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { ScheduledScanner } from '../../src/monitoring/scheduled-scanner';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
import { SchemaRegistry } from '@tzun/engine';
import { assembleEnvelope } from '@tzun/engine';
import { EvidenceEnvelope } from '@tzun/engine';
import {
  AiBom,
  ModelDescriptor,
  ModelDescriptorRow,
} from '@tzun/engine';
import { MonitoringEvent, ScannerConfig } from '@tzun/engine';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const baseConfig: ScannerConfig = {
  batchSize: 100,
  workers: 2,
  mode: 'interval',
  intervalMs: 0,
  verifyAttestation: false,
  verifyChainCompleteness: true,
};

function descriptorFixture(overrides: Partial<ModelDescriptor> = {}): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor: 'openai',
    modelName: 'scanner-task15',
    modelVersion: 'v1',
    modelType: 'llm',
    integrityTier: 'vendor-asserted',
    modelDigest: null,
    parentModelDescriptorDigest: null,
    derivation: null,
    trainedBy: 'TestCorp',
    license: 'mit',
    modelCardUrl: null,
    training: {
      trainingDataDigest: null,
      trainingDataRef: null,
      lastTrainingDate: null,
      evaluations: [],
    },
    regulatoryMarkings: [],
    externalIdentifiers: [],
    ...overrides,
  };
}

/**
 * Capture N envelopes with the supplied aiBom on each, chained properly.
 * Mirrors the pattern used in `tests/ts/scheduled-scanner.test.ts:captureN`.
 */
async function captureN(
  storage: MemoryStorageAdapter,
  n: number,
  aiBoms: Array<AiBom | null>,
): Promise<EvidenceEnvelope[]> {
  if (aiBoms.length !== n) {
    throw new Error(`captureN: aiBoms.length (${aiBoms.length}) must equal n (${n})`);
  }
  const registry = new SchemaRegistry();
  const envelopes: EvidenceEnvelope[] = [];
  let previousDigest: string | undefined;

  for (let i = 1; i <= n; i++) {
    const record = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'test-system',
      aiOutput: { recommendation: `rec-${i}` },
      action: 'approved',
      reason: `reason-${i}`,
    };
    const aiBom = aiBoms[i - 1];
    const envelope = assembleEnvelope(
      { ...record, contributions: aiBom === null ? null : builtModel(aiBom, record) },
      { previousDigest, sequenceNumber: i },
    );
    await storage.store(envelope);
    previousDigest = envelope.integrity.canonicalDigest;
    envelopes.push(envelope);
  }

  return envelopes;
}

/** Direct access to the in-memory descriptor map for tamper-simulation. */
function modelDescriptorsMap(storage: MemoryStorageAdapter): Map<string, ModelDescriptorRow> {
  return (storage as unknown as { modelDescriptors: Map<string, ModelDescriptorRow> })
    .modelDescriptors;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('scheduled scanner: AI-BOM descriptor verification', () => {
  let bus: MonitoringEventBus;
  let storage: MemoryStorageAdapter;
  let registry: SchemaRegistry;

  beforeEach(() => {
    bus = new MonitoringEventBus();
    storage = new MemoryStorageAdapter();
    registry = new SchemaRegistry();
  });

  it('default (scannerVerifyDescriptors: true) — scanner verifies descriptors and emits descriptor_resolution_failure on miss', async () => {
    // Register a descriptor, capture an envelope referencing it, then mutate
    // storage to remove the descriptor row (simulating cross-environment export
    // or catalog corruption).
    const { digest } = await storage.registerModelDescriptor!(
      descriptorFixture({ modelName: 'missing-after-capture' }),
      'manual',
      'test',
    );
    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    await captureN(storage, 1, [aiBom]);
    modelDescriptorsMap(storage).delete(digest);

    // Default config: scannerVerifyDescriptors absent → treated as true.
    const scanner = new ScheduledScanner(storage, bus, registry, baseConfig);

    const descriptorEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (
        event.type === 'descriptor_resolution_failure' ||
        event.type === 'descriptor_digest_mismatch' ||
        event.type === 'parent_descriptor_resolution_failure' ||
        event.type === 'parent_descriptor_digest_mismatch'
      ) {
        descriptorEvents.push(event);
      }
    });

    await scanner.runFullPass();

    const types = descriptorEvents.map((e) => e.type);
    expect(types).toContain('descriptor_resolution_failure');
  });

  it('scannerVerifyDescriptors: false — scanner skips descriptor verification entirely', async () => {
    const { digest } = await storage.registerModelDescriptor!(
      descriptorFixture({ modelName: 'skipped' }),
      'manual',
      'test',
    );
    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const envelopes = await captureN(storage, 2, [aiBom, aiBom]);

    // Delete the descriptor — would normally trigger descriptor_resolution_failure.
    modelDescriptorsMap(storage).delete(digest);

    // Also tamper chainLink on record 2 so we can prove the standard checks still fire.
    // Rewrite the stored row: retrieve() returns a detached copy, so editing
    // the retrieved envelope would not reach the store.
    await rewriteStoredEnvelope(storage, envelopes[1].payload.evidenceId, (e) => { e.integrity.chainLink = 'deadbeef'; });

    const config: ScannerConfig = { ...baseConfig, scannerVerifyDescriptors: false };
    const scanner = new ScheduledScanner(storage, bus, registry, config);

    const descriptorEvents: MonitoringEvent[] = [];
    const chainBreaks: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (
        event.type === 'descriptor_resolution_failure' ||
        event.type === 'descriptor_digest_mismatch' ||
        event.type === 'parent_descriptor_resolution_failure' ||
        event.type === 'parent_descriptor_digest_mismatch'
      ) {
        descriptorEvents.push(event);
      } else if (event.type === 'chain_break') {
        chainBreaks.push(event);
      }
    });

    await scanner.runFullPass();

    expect(descriptorEvents).toEqual([]);
    expect(chainBreaks).toHaveLength(1);
  });

  it('scannerVerifyDescriptors: true — descriptor_digest_mismatch on tampered canonicalBytes', async () => {
    const { digest } = await storage.registerModelDescriptor!(
      descriptorFixture({ modelName: 'tamper-bytes' }),
      'manual',
      'test',
    );
    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    await captureN(storage, 1, [aiBom]);

    // Mutate canonicalBytes for the row without recomputing the digest.
    const map = modelDescriptorsMap(storage);
    const row = map.get(digest)!;
    map.set(digest, {
      ...row,
      canonicalBytes: row.canonicalBytes.replace(
        /"vendor":"openai"/,
        '"vendor":"tampered-by-test"',
      ),
    });

    const scanner = new ScheduledScanner(storage, bus, registry, baseConfig);

    const events: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (event.type === 'descriptor_digest_mismatch') {
        events.push(event);
      }
    });

    await scanner.runFullPass();

    expect(events).toHaveLength(1);
    if (events[0].type === 'descriptor_digest_mismatch') {
      expect(events[0].claimedDigest).toBe(digest);
      expect(events[0].recomputedDigest).not.toBe(digest);
    }
  });

  it('scannerVerifyDescriptors: true with a parent DAG — walk produces parent_descriptor_resolution_failure when ancestor missing', async () => {
    // Register root → leaf. Capture an envelope referencing leaf, then remove root
    // from the catalog so the lineage walk finds it missing.
    const { digest: rootDigest } = await storage.registerModelDescriptor!(
      descriptorFixture({ modelName: 'parent-walk-root' }),
      'manual',
      'test',
    );
    const { digest: leafDigest } = await storage.registerModelDescriptor!(
      descriptorFixture({
        modelName: 'parent-walk-leaf',
        parentModelDescriptorDigest: rootDigest,
      }),
      'manual',
      'test',
    );

    const aiBom: AiBom = {
      modelDescriptorDigest: leafDigest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    await captureN(storage, 1, [aiBom]);

    // Remove only the ancestor; leaf stays intact.
    modelDescriptorsMap(storage).delete(rootDigest);

    const scanner = new ScheduledScanner(storage, bus, registry, baseConfig);

    const events: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (
        event.type === 'parent_descriptor_resolution_failure' ||
        event.type === 'parent_descriptor_digest_mismatch'
      ) {
        events.push(event);
      }
    });

    await scanner.runFullPass();

    const types = events.map((e) => e.type);
    expect(types).toContain('parent_descriptor_resolution_failure');
  });

  it('scanner does NOT touch envelopes with aiBom: null (no descriptor incidents emitted for them)', async () => {
    // Two clean envelopes, both with aiBom: null.
    await captureN(storage, 2, [null, null]);

    const scanner = new ScheduledScanner(storage, bus, registry, baseConfig);

    const descriptorEvents: MonitoringEvent[] = [];
    bus.subscribe((event) => {
      if (
        event.type === 'descriptor_resolution_failure' ||
        event.type === 'descriptor_digest_mismatch' ||
        event.type === 'parent_descriptor_resolution_failure' ||
        event.type === 'parent_descriptor_digest_mismatch'
      ) {
        descriptorEvents.push(event);
      }
    });

    await scanner.runFullPass();

    expect(descriptorEvents).toEqual([]);

    // Same check with scannerVerifyDescriptors: false — still no descriptor events.
    const bus2 = new MonitoringEventBus();
    const scanner2 = new ScheduledScanner(
      storage,
      bus2,
      registry,
      { ...baseConfig, scannerVerifyDescriptors: false },
    );
    const descriptorEvents2: MonitoringEvent[] = [];
    bus2.subscribe((event) => {
      if (
        event.type === 'descriptor_resolution_failure' ||
        event.type === 'descriptor_digest_mismatch' ||
        event.type === 'parent_descriptor_resolution_failure' ||
        event.type === 'parent_descriptor_digest_mismatch'
      ) {
        descriptorEvents2.push(event);
      }
    });

    await scanner2.runFullPass();
    expect(descriptorEvents2).toEqual([]);
  });
});
