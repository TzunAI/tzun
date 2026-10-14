/**
 * A known-models reference entry cannot set integrity fields.
 *
 * `mergeMvdWithEnrichment` copies descriptive fields off a known-models
 * reference entry onto the descriptor, never `integrityTier`, `modelDigest`,
 * `parentModelDescriptorDigest` or `derivation`. The two paths that register
 * descriptors automatically (the connector path in `wrappers.ts` and the
 * inline-AI-BOM capture path in `sdk/index.ts`) call
 * `storage.registerModelDescriptor` directly, never through `register.ts`'s
 * `mvdFrom`. If enrichment could set integrity fields, a poisoned or typo'd
 * reference entry could mint `integrityTier: 'weight-attested'` with
 * `modelDigest: null` — the strongest integrity claim the product makes,
 * bound to nothing, and a pair `register.ts` refuses outright.
 *
 * Two guarantees are pinned here:
 *   1. Enrichment cannot set any integrity field.
 *   2. The tier↔digest invariant is enforced at the catalog write itself, so
 *      every registration path is covered, not just `tzun.models.register`.
 */
import { importFromVendor } from '../../src/models/import-vendor';
import type { KnownModelsReference } from '../../src/models/known-models';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { assertDescriptorIntegrityInvariants } from '../../src/models/descriptor-invariants';
import type { ModelDescriptor } from '@tzun/engine';

const FAKE_DIGEST = 'sha256:' + 'e'.repeat(64);
const FAKE_PARENT = 'sha256:' + 'f'.repeat(64);

function poisonedReference(extra: Partial<ModelDescriptor>): KnownModelsReference {
  return {
    entries: [
      {
        vendor: 'openai',
        modelName: 'gpt-4o',
        modelVersion: '2024-08-06',
        license: 'proprietary',
        ...extra,
      },
    ],
  } as unknown as KnownModelsReference;
}

function vendorAssertedDescriptor(): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor: 'openai',
    modelName: 'gpt-4o',
    modelVersion: '2024-08-06',
    modelType: null,
    integrityTier: 'vendor-asserted',
    modelDigest: null,
    parentModelDescriptorDigest: null,
    derivation: null,
    trainedBy: null,
    license: null,
    modelCardUrl: null,
    training: {
      trainingDataDigest: null,
      trainingDataRef: null,
      lastTrainingDate: null,
      evaluations: [],
    },
    regulatoryMarkings: [],
    externalIdentifiers: [],
  } as unknown as ModelDescriptor;
}

describe('known-models enrichment cannot forge integrity fields', () => {
  it('does not copy integrityTier / modelDigest / parent / derivation from a reference entry', () => {
    const { descriptor, enriched } = importFromVendor({
      vendor: 'openai',
      modelId: 'gpt-4o-2024-08-06',
      knownModels: poisonedReference({
        integrityTier: 'weight-attested',
        modelDigest: FAKE_DIGEST,
        parentModelDescriptorDigest: FAKE_PARENT,
        derivation: 'fine-tune',
      } as Partial<ModelDescriptor>),
    });

    // The entry still matched and descriptive enrichment still applies …
    expect(enriched).toBe(true);
    expect(descriptor.license).toBe('proprietary');

    // … but nothing about integrity came from it.
    expect(descriptor.integrityTier).toBe('vendor-asserted');
    expect(descriptor.modelDigest).toBeNull();
    expect(descriptor.parentModelDescriptorDigest).toBeNull();
    expect(descriptor.derivation).toBeNull();
  });

  it('does not accept a tier-only override (weight-attested with a null digest)', () => {
    const { descriptor } = importFromVendor({
      vendor: 'openai',
      modelId: 'gpt-4o-2024-08-06',
      knownModels: poisonedReference({
        integrityTier: 'weight-attested',
      } as Partial<ModelDescriptor>),
    });
    expect(descriptor.integrityTier).toBe('vendor-asserted');
    expect(descriptor.modelDigest).toBeNull();
  });
});

describe('the catalog write enforces the tier↔digest invariant', () => {
  it('rejects weight-attested with a null modelDigest', async () => {
    const storage = new MemoryStorageAdapter();
    const bad = vendorAssertedDescriptor();
    bad.integrityTier = 'weight-attested';

    await expect(
      storage.registerModelDescriptor(bad, 'connector-auto', 'test'),
    ).rejects.toThrow(/integrityTier "weight-attested" is inconsistent with modelDigest/);
  });

  it('rejects vendor-asserted carrying a modelDigest', async () => {
    const storage = new MemoryStorageAdapter();
    const bad = vendorAssertedDescriptor();
    bad.modelDigest = FAKE_DIGEST;

    await expect(
      storage.registerModelDescriptor(bad, 'manual', 'test'),
    ).rejects.toThrow(/integrityTier "vendor-asserted" is inconsistent with modelDigest/);
  });

  it('rejects a malformed modelDigest', async () => {
    const storage = new MemoryStorageAdapter();
    const bad = vendorAssertedDescriptor();
    bad.integrityTier = 'weight-attested';
    bad.modelDigest = 'sha256:NOTHEX';

    await expect(
      storage.registerModelDescriptor(bad, 'manual', 'test'),
    ).rejects.toThrow(/must match "sha256:<64 hex chars>"/);
  });

  it('still accepts both well-formed shapes', async () => {
    const storage = new MemoryStorageAdapter();
    const ok = vendorAssertedDescriptor();
    await expect(
      storage.registerModelDescriptor(ok, 'connector-auto', 'test'),
    ).resolves.toHaveProperty('digest');

    const attested = vendorAssertedDescriptor();
    attested.integrityTier = 'weight-attested';
    attested.modelDigest = FAKE_DIGEST;
    await expect(
      storage.registerModelDescriptor(attested, 'manual', 'test'),
    ).resolves.toHaveProperty('digest');
  });

  it('assertDescriptorIntegrityInvariants is a pure predicate on the pair', () => {
    expect(() =>
      assertDescriptorIntegrityInvariants({ integrityTier: 'vendor-asserted', modelDigest: null }),
    ).not.toThrow();
    expect(() =>
      assertDescriptorIntegrityInvariants({ integrityTier: 'weight-attested', modelDigest: null }),
    ).toThrow();
  });
});
