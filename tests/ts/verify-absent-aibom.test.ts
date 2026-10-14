import { singleModel } from '@tzun/engine';
/**
 * Tests for an envelope with NO `aiBom` key.
 *
 * `canonicalSerialize` maps a missing key to `null`, so an envelope that
 * simply lacks `aiBom` has exactly the same canonical digest as one carrying
 * `aiBom: null`, and the sync verifier accepts it. Every consumer must
 * therefore treat an ABSENT key as null. One that discriminated with strict
 * `=== null` / `!== null` would read an absent key as "has an aiBom", run the
 * async descriptor path and dereference `aiBom.modelDescriptorDigest` on
 * `undefined`.
 *
 * Result: an honest record that the sync verifier accepts would make
 * `tzun.verify()` reject with a TypeError, and kill a whole scanner pass.
 */
import { Tzun } from '../../src/sdk/index';
import { verifyEnvelope, SchemaRegistry, EvidenceEnvelope } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { ScheduledScanner } from '../../src/monitoring/scheduled-scanner';
import { MonitoringEvent, ScannerConfig } from '@tzun/engine';

const scannerConfig: ScannerConfig = {
  batchSize: 100,
  workers: 1,
  mode: 'interval',
  intervalMs: 0,
  verifyAttestation: false,
  verifyChainCompleteness: false,
};

/**
 * A "legacy" envelope: captured normally with `aiBom: null`, then the key is
 * deleted outright. This is what a hand-built envelope from a customer, or a
 * row written before aiBom joined the hashed set, actually looks like on disk.
 */
function stripAiBomKey(envelope: EvidenceEnvelope): EvidenceEnvelope {
  const clone = JSON.parse(JSON.stringify(envelope)) as EvidenceEnvelope;
  delete (clone.payload as unknown as Record<string, unknown>).aiBom;
  return clone;
}

describe('absent aiBom key is digest-equivalent to explicit null', () => {
  it('precondition: deleting the key leaves the digest valid (sync verify passes)', () => {
    const registry = new SchemaRegistry();
    const tzunless = stripAiBomKey; // readability
    return Tzun.init().then(async (tzun) => {
      const cap = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiSystemId: 'sys', aiOutput: { t: 1 },
        action: 'approved', reason: 'ok', contributions: null,
      });
      const legacy = tzunless(cap.envelope);
      expect('aiBom' in legacy.payload).toBe(false);
      const sync = verifyEnvelope(legacy, undefined, registry);
      // If this ever fails the whole issue is moot — absent would not be
      // digest-equivalent to null and the record would be genuinely invalid.
      expect(sync.verified).toBe(true);
    });
  });

  it('engine: verifyEnvelope with storage returns a result instead of throwing', async () => {
    const tzun = await Tzun.init();
    const cap = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys', aiOutput: { t: 1 },
      action: 'approved', reason: 'ok', contributions: null,
    });
    const legacy = stripAiBomKey(cap.envelope);

    const result = await verifyEnvelope(legacy, undefined, new SchemaRegistry(), {
      storage: tzun.getStorage(),
      walkLineage: true,
    });
    expect(result.verified).toBe(true);
  });

  it('SDK: tzun.verify() resolves instead of rejecting with TypeError', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const cap = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys', aiOutput: { t: 1 },
      action: 'approved', reason: 'ok', contributions: null,
    });

    // Rewrite the stored row to the legacy shape, bypassing append-only.
    const rows = (storage as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes;
    rows.set(cap.envelope.payload.evidenceId, stripAiBomKey(rows.get(cap.envelope.payload.evidenceId)!));

    const result = await tzun.verify(cap.envelope.payload.evidenceId);
    expect(result.verified).toBe(true);
  });

  it('scanner: a legacy record does not abort the pass', async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const first = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys', aiOutput: { t: 1 },
      action: 'approved', reason: 'ok', contributions: null,
    });
    const second = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys', aiOutput: { t: 2 },
      action: 'approved', reason: 'ok', contributions: null,
    });
    const rows = (storage as unknown as { envelopes: Map<string, EvidenceEnvelope> }).envelopes;
    rows.set(first.envelope.payload.evidenceId, stripAiBomKey(rows.get(first.envelope.payload.evidenceId)!));

    const bus = new MonitoringEventBus();
    const verified: string[] = [];
    bus.subscribe((e: MonitoringEvent) => {
      if (e.type === 'record_verified') verified.push(e.evidenceId);
    });
    const scanner = new ScheduledScanner(storage, bus, new SchemaRegistry(), scannerConfig);

    // Must RESOLVE. Reading the absent key as present rejects with
    // 'TypeError: Cannot read properties of undefined (reading
    // \'modelDescriptorDigest\')' and the pass dies.
    await expect(scanner.runFullPass()).resolves.not.toThrow();
    // Non-vacuity: the record AFTER the legacy one must still have been
    // checked. A pass that aborted on record 1 would never reach record 2.
    expect(verified).toContain(second.envelope.payload.evidenceId);
  });

  it('scanner: a throw from descriptor resolution is contained, not fatal', async () => {
    // This proves the try/catch around verifyDescriptorPath is a LIVE guard,
    // not dead code that only an absent aiBom could reach: here the aiBom IS
    // present and the catalog lookup itself throws.
    const tzun = await Tzun.init();
    const storage = tzun.getStorage() as MemoryStorageAdapter;
    const { digest } = await storage.registerModelDescriptor!(
      {
        descriptorVersion: 'd1', vendor: 'openai', modelName: 'boom',
        modelVersion: 'v1', modelType: 'llm', integrityTier: 'vendor-asserted',
        modelDigest: null, parentModelDescriptorDigest: null, derivation: null,
        trainedBy: 'TestCorp', license: 'mit', modelCardUrl: null,
        training: {
          trainingDataDigest: null, trainingDataRef: null,
          lastTrainingDate: null, evaluations: [],
        },
        regulatoryMarkings: [], externalIdentifiers: [],
      },
      'manual',
      'test',
    );
    await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys', aiOutput: { t: 1 },
      action: 'approved', reason: 'ok',
      contributions: singleModel({
        modelDescriptorDigest: digest, vendorFingerprint: null,
        promptTemplate: null, inferenceParameters: null, infrastructure: null,
      }),
    });
    const second = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiSystemId: 'sys', aiOutput: { t: 2 },
      action: 'approved', reason: 'ok', contributions: null,
    });

    storage.getModelDescriptor = async () => {
      throw new Error('catalog unavailable');
    };

    const bus = new MonitoringEventBus();
    const verified: string[] = [];
    const failures: MonitoringEvent[] = [];
    bus.subscribe((e: MonitoringEvent) => {
      if (e.type === 'record_verified') verified.push(e.evidenceId);
      if (e.type === 'descriptor_resolution_failure') failures.push(e);
    });
    const scanner = new ScheduledScanner(storage, bus, new SchemaRegistry(), scannerConfig);

    await expect(scanner.runFullPass()).resolves.not.toThrow();
    expect(failures.length).toBeGreaterThan(0);
    expect(verified).toContain(second.envelope.payload.evidenceId);
  });
});
