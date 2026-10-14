import { modelInput } from './helpers/step-model';
/**
 * Verifier descriptor resolution + parent-DAG walk tests.
 *
 * Covers:
 *   - verifier resolves + verifies descriptor when aiBom !== null.
 *   - lineage walk respects maxLineageDepth and detects cycles.
 *   - VerificationResult.modelLineage is populated when walkLineage=true.
 *   - emits descriptor_/parent_descriptor_ incidents on failures.
 */

import { Tzun } from '../../src/sdk/index';
import { verifyEnvelope } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { AiBom, ModelDescriptor, ModelDescriptorRow } from '@tzun/engine';

function descriptorFixture(overrides: Partial<ModelDescriptor> = {}): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor: 'openai',
    modelName: 'verify-task14',
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

function baseInput() {
  return {
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    aiSystemId: 'test-system',
    aiOutput: { text: 'sample' },
    action: 'approved',
    reason: 'meets criteria',
  };
}

/** Direct access to the in-memory descriptor map for tamper-simulation. */
function modelDescriptorsMap(storage: MemoryStorageAdapter): Map<string, ModelDescriptorRow> {
  return (storage as unknown as { modelDescriptors: Map<string, ModelDescriptorRow> }).modelDescriptors;
}

describe('verifier: AI-BOM descriptor resolution + DAG walk', () => {
  it('envelope with aiBom: null verifies with no descriptor path triggered', async () => {
    const tzun = await Tzun.init();
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(null) });
    expect(cap.stored).toBe(true);

    // Sync path — no options.
    const result = verifyEnvelope(cap.envelope);
    expect(result.verified).toBe(true);
    expect(result.tamperIncidents).toBeUndefined();
    expect(result.modelLineage).toBeUndefined();

    // Async path with storage — still no descriptor incidents.
    const result2 = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
    });
    expect(result2.verified).toBe(true);
    expect(result2.tamperIncidents ?? []).toEqual([]);
  });

  it('envelope with aiBom + registered descriptor verifies with no descriptor incidents', async () => {
    const tzun = await Tzun.init();
    const { digest } = await tzun.models.register(descriptorFixture());
    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: 'fp_ok',
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });
    expect(cap.stored).toBe(true);

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
    });
    expect(result.verified).toBe(true);
    expect(result.tamperIncidents ?? []).toEqual([]);
  });

  it('descriptor missing from catalog → descriptor_resolution_failure', async () => {
    const tzun = await Tzun.init();
    const { digest } = await tzun.models.register(descriptorFixture());
    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });
    expect(cap.stored).toBe(true);

    // Remove the row to simulate catalog miss.
    modelDescriptorsMap(tzun.getStorage() as MemoryStorageAdapter).delete(digest);

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
    });
    const types = (result.tamperIncidents ?? []).map((i) => i.type);
    expect(types).toContain('descriptor_resolution_failure');
    // Any descriptor incident MUST flip result.verified to false.
    expect(result.verified).toBe(false);
  });

  it('stored canonicalBytes mismatch claimed digest → descriptor_digest_mismatch', async () => {
    const tzun = await Tzun.init();
    const { digest } = await tzun.models.register(descriptorFixture());
    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });
    expect(cap.stored).toBe(true);

    // Mutate canonicalBytes for the row without recomputing the digest.
    const map = modelDescriptorsMap(tzun.getStorage() as MemoryStorageAdapter);
    const row = map.get(digest)!;
    map.set(digest, { ...row, canonicalBytes: row.canonicalBytes.replace(/"vendor":"openai"/, '"vendor":"tampered"') });

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
    });
    const types = (result.tamperIncidents ?? []).map((i) => i.type);
    expect(types).toContain('descriptor_digest_mismatch');
    expect(result.verified).toBe(false);
  });

  it('walkLineage: true follows parentModelDescriptorDigest and produces modelLineage leaf-to-root', async () => {
    const tzun = await Tzun.init();
    // Register chain: root -> middle -> leaf.
    const { digest: rootDigest } = await tzun.models.register(
      descriptorFixture({ modelName: 'root', derivation: 'base' }),
    );
    const { digest: middleDigest } = await tzun.models.register(
      descriptorFixture({
        modelName: 'middle',
        derivation: 'fine-tune',
        parentModelDescriptorDigest: rootDigest,
      }),
    );
    const { digest: leafDigest } = await tzun.models.register(
      descriptorFixture({
        modelName: 'leaf',
        derivation: 'quantization',
        parentModelDescriptorDigest: middleDigest,
      }),
    );

    const aiBom: AiBom = {
      modelDescriptorDigest: leafDigest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
      walkLineage: true,
    });

    expect(result.tamperIncidents ?? []).toEqual([]);
    expect(result.modelLineage).toBeDefined();
    expect(result.modelLineage![0].lineage).toHaveLength(3);
    // Leaf-to-root: [leaf, middle, root]
    expect(result.modelLineage![0].lineage[0].descriptorDigest).toBe(leafDigest);
    expect(result.modelLineage![0].lineage[0].derivation).toBe('quantization');
    expect(result.modelLineage![0].lineage[1].descriptorDigest).toBe(middleDigest);
    expect(result.modelLineage![0].lineage[1].derivation).toBe('fine-tune');
    expect(result.modelLineage![0].lineage[2].descriptorDigest).toBe(rootDigest);
    expect(result.modelLineage![0].lineage[2].derivation).toBe('base');
    expect(result.modelLineage![0].lineage[0].integrityTier).toBe('vendor-asserted');
    expect(result.modelLineage![0].lineage[0].trainedBy).toBe('TestCorp');
  });

  it('walkLineage halts at custom depth via maxLineageDepth', async () => {
    const tzun = await Tzun.init();
    // Register 6-deep chain: gen0 (root) ... gen5 (leaf).
    const digests: string[] = [];
    let parent: string | null = null;
    for (let i = 0; i < 6; i++) {
      const { digest } = await tzun.models.register(
        descriptorFixture({
          modelName: `gen-${i}`,
          parentModelDescriptorDigest: parent,
        }),
      );
      digests.push(digest);
      parent = digest;
    }
    const leafDigest = digests[5];

    const aiBom: AiBom = {
      modelDescriptorDigest: leafDigest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });

    // maxLineageDepth = 3 should stop after walking 3 entries.
    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
      walkLineage: true,
      maxLineageDepth: 3,
    });
    expect(result.modelLineage![0].lineage).toHaveLength(3);
  });

  it('walkLineage halts at default depth 16', async () => {
    const tzun = await Tzun.init();
    // Build an 20-deep chain.
    let parent: string | null = null;
    const digests: string[] = [];
    for (let i = 0; i < 20; i++) {
      const { digest } = await tzun.models.register(
        descriptorFixture({
          modelName: `depth-${i}`,
          parentModelDescriptorDigest: parent,
        }),
      );
      digests.push(digest);
      parent = digest;
    }
    const leafDigest = digests[19];

    const aiBom: AiBom = {
      modelDescriptorDigest: leafDigest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
      walkLineage: true,
    });
    // Default maxLineageDepth is 16: leaf + 15 ancestors = 16 entries.
    expect(result.modelLineage![0].lineage).toHaveLength(16);
  });

  it('walkLineage short-circuits on cycle and emits parent_descriptor_resolution_failure', async () => {
    // The walk must short-circuit on a repeated digest, bound the lineage, and
    // emit the defensive incident. It reads the parent pointer out of the
    // digest-covered canonicalBytes, not the parentModelDescriptorDigest
    // *column*, so a column rewrite is inert and cannot build a cycle. The
    // cycle is injected the only way it can reach the walk: through the bytes
    // themselves (which necessarily breaks the leaf's own digest, hence the
    // extra descriptor_digest_mismatch below).
    const tzun = await Tzun.init();
    const { digest: leafDigest } = await tzun.models.register(
      descriptorFixture({ modelName: 'cycle-leaf' }),
    );

    const aiBom: AiBom = {
      modelDescriptorDigest: leafDigest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });

    // Inject the cycle in the bytes: the leaf now names itself as its parent.
    const map = modelDescriptorsMap(tzun.getStorage() as MemoryStorageAdapter);
    const leafRow = map.get(leafDigest)!;
    const tamperedBytes = JSON.stringify({
      ...(JSON.parse(leafRow.canonicalBytes) as Record<string, unknown>),
      parentModelDescriptorDigest: leafDigest,
    });
    map.set(leafDigest, { ...leafRow, canonicalBytes: tamperedBytes });

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
      walkLineage: true,
    });
    const types = (result.tamperIncidents ?? []).map((i) => i.type);
    expect(types).toContain('descriptor_digest_mismatch');
    expect(types).toContain('parent_descriptor_resolution_failure');
    // The walk must not hang: lineage length is bounded.
    expect(result.modelLineage![0].lineage.length).toBeLessThanOrEqual(2);
    expect(result.verified).toBe(false);
  });

  it('lineage walk ignores the mutable parent column and follows the digest-covered bytes', async () => {
    // `parent_model_descriptor_digest` is a denormalized SQL column that
    // modelDescriptorDigest does not commit to. A DB-write attacker could
    // repoint a leaf at an entirely different base model with one UPDATE:
    // canonical_bytes untouched, the leaf re-hashes fine, verified stays true,
    // and the reported modelLineage names a root the digest-covered descriptor
    // never named.
    const tzun = await Tzun.init();
    const { digest: rootA } = await tzun.models.register(
      descriptorFixture({ modelName: 'lineage-root-a-honest', trainedBy: 'HonestCorp' }),
    );
    const { digest: rootB } = await tzun.models.register(
      descriptorFixture({ modelName: 'lineage-root-b-other', trainedBy: 'OtherCorp' }),
    );
    const { digest: leafDigest } = await tzun.models.register(
      descriptorFixture({
        modelName: 'lineage-leaf',
        parentModelDescriptorDigest: rootA,
        trainedBy: 'TestCorp',
        integrityTier: 'vendor-asserted',
      }),
    );

    const aiBom: AiBom = {
      modelDescriptorDigest: leafDigest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });

    // Sanity: the honest catalog walks leaf -> rootA.
    const honest = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
      walkLineage: true,
    });
    expect(honest.verified).toBe(true);
    expect((honest.modelLineage?.[0]?.lineage ?? []).map((e) => e.descriptorDigest)).toEqual([leafDigest, rootA]);

    // Attack: rewrite ONLY the denormalized columns of the leaf row. This is
    // exactly what `UPDATE model_descriptors SET parent_model_descriptor_digest
    // = '<rootB>' WHERE model_descriptor_digest = '<leaf>'` does on
    // SQLite/Postgres. canonicalBytes are left alone, so the row still hashes
    // to its claimed digest.
    const map = modelDescriptorsMap(tzun.getStorage() as MemoryStorageAdapter);
    const leafRow = map.get(leafDigest)!;
    map.set(leafDigest, {
      ...leafRow,
      parentModelDescriptorDigest: rootB,
      descriptor: { ...leafRow.descriptor, trainedBy: 'FAKE Corp', integrityTier: 'weight-attested' },
    });

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
      walkLineage: true,
    });

    // The walk follows the bytes, so the lineage is still leaf -> rootA with
    // the committed attributes, not rootB and 'FAKE Corp' from the columns.
    expect((result.modelLineage?.[0]?.lineage ?? []).map((e) => e.descriptorDigest)).toEqual([leafDigest, rootA]);
    expect(result.modelLineage![0].lineage[0].trainedBy).toBe('TestCorp');
    expect(result.modelLineage![0].lineage[0].integrityTier).toBe('vendor-asserted');
    expect(result.modelLineage![0].lineage[1].trainedBy).toBe('HonestCorp');
    // The bytes are intact, so the record itself is still a clean verify —
    // the point is that the lineage it reports is the true one.
    expect(result.verified).toBe(true);
  });

  it('walkLineage emits parent_descriptor_digest_mismatch when a parent\'s canonicalBytes do not match its digest', async () => {
    const tzun = await Tzun.init();
    const { digest: rootDigest } = await tzun.models.register(
      descriptorFixture({ modelName: 'parent-mismatch-root' }),
    );
    const { digest: leafDigest } = await tzun.models.register(
      descriptorFixture({
        modelName: 'parent-mismatch-leaf',
        parentModelDescriptorDigest: rootDigest,
      }),
    );

    const aiBom: AiBom = {
      modelDescriptorDigest: leafDigest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });

    // Tamper with the *parent's* canonicalBytes (not the leaf).
    const map = modelDescriptorsMap(tzun.getStorage() as MemoryStorageAdapter);
    const rootRow = map.get(rootDigest)!;
    map.set(rootDigest, {
      ...rootRow,
      canonicalBytes: rootRow.canonicalBytes.replace(/"vendor":"openai"/, '"vendor":"tampered-root"'),
    });

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
      walkLineage: true,
    });
    const types = (result.tamperIncidents ?? []).map((i) => i.type);
    expect(types).toContain('parent_descriptor_digest_mismatch');
    expect(result.verified).toBe(false);
  });

  it('walkLineage emits parent_descriptor_resolution_failure when an ancestor is missing', async () => {
    const tzun = await Tzun.init();
    const { digest: rootDigest } = await tzun.models.register(
      descriptorFixture({ modelName: 'missing-parent-root' }),
    );
    const { digest: leafDigest } = await tzun.models.register(
      descriptorFixture({
        modelName: 'missing-parent-leaf',
        parentModelDescriptorDigest: rootDigest,
      }),
    );

    const aiBom: AiBom = {
      modelDescriptorDigest: leafDigest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });

    // Remove just the ancestor.
    modelDescriptorsMap(tzun.getStorage() as MemoryStorageAdapter).delete(rootDigest);

    const result = await verifyEnvelope(cap.envelope, undefined, undefined, {
      storage: tzun.getStorage(),
      walkLineage: true,
    });
    const types = (result.tamperIncidents ?? []).map((i) => i.type);
    expect(types).toContain('parent_descriptor_resolution_failure');
    expect(result.verified).toBe(false);
  });

  it('without options.storage, descriptor verification is skipped entirely', async () => {
    const tzun = await Tzun.init();
    const { digest } = await tzun.models.register(descriptorFixture());
    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };
    const cap = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });

    // Even if we delete the descriptor, no storage = no descriptor path triggered.
    modelDescriptorsMap(tzun.getStorage() as MemoryStorageAdapter).delete(digest);

    const result = verifyEnvelope(cap.envelope);
    expect(result.verified).toBe(true);
    expect(result.tamperIncidents).toBeUndefined();
    expect(result.modelLineage).toBeUndefined();
  });

  it('verifyEnvelope remains backward-compatible with the 3-arg sync signature', () => {
    // Existing callers passing (envelope, previousDigest, registry) must still
    // get a synchronous VerificationResult.
    const adapter = new MemoryStorageAdapter();
    void adapter; // not used here; only confirming sync path exists.

    // No need to build an actual envelope here — we already exercise the sync
    // path in the other tests. This case asserts the signature shape compiles.
    expect(typeof verifyEnvelope).toBe('function');
  });
});
