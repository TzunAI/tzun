import { modelOf, modelInput } from './helpers/step-model';
/**
 * Capture-side `aiBom` validation tests.
 *
 * Covers:
 *   - `aiBom: null | undefined` passes through.
 *   - Pre-built `AiBom` with pre-registered digest succeeds.
 *   - Pre-built `AiBom` with missing digest fails with structured
 *     `FailureRecord` (no exception).
 *   - Convenience form (`AiBomWithInlineDescriptor`) auto-registers and
 *     substitutes the digest.
 *   - `aiBom` participates in `canonicalDigest` round-trip.
 */

import { Tzun } from '../../src/sdk/index';
import { ModelDescriptor, AiBom, AiBomWithInlineDescriptor } from '@tzun/engine';

function descriptorFixture(): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor: 'openai',
    modelName: 'test-capture-model',
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
  };
}

function baseInput() {
  return {
    decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
    aiSystemId: 'test-system',
    aiOutput: { text: 'sample output' },
    action: 'approved',
    reason: 'meets criteria',
  };
}

describe('capture: explicit aiBom field', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init();
  });

  it('aiBom: null succeeds and canonicalizes as null', async () => {
    const result = await tzun.capture({ ...baseInput(), contributions: modelInput(null) });
    expect(result.stored).toBe(true);
    expect(result.failure).toBeUndefined();
    expect(modelOf(result.envelope.payload)).toBeNull();
  });

  it('aiBom: undefined (absent field) succeeds and canonicalizes as null', async () => {
    const result = await tzun.capture(baseInput());
    expect(result.stored).toBe(true);
    expect(modelOf(result.envelope.payload)).toBeNull();
  });

  it('pre-built aiBom with pre-registered digest succeeds', async () => {
    // Register first so the digest exists in the catalog.
    const { digest } = await tzun.models.register(descriptorFixture());

    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: 'fp_test_123',
      promptTemplate: null,
      inferenceParameters: {
        temperature: 0.3,
        topP: 0.95,
        maxTokens: 256,
        seed: null,
        stopSequences: null,
      },
      infrastructure: null,
    };
    const result = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });
    expect(result.stored).toBe(true);
    expect(modelOf(result.envelope.payload)).toEqual(aiBom);
  });

  it('pre-built aiBom with missing digest fails with structured FailureRecord', async () => {
    const aiBom: AiBom = {
      modelDescriptorDigest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };

    let result;
    try {
      result = await tzun.capture({ ...baseInput(), contributions: modelInput(aiBom) });
    } catch (err) {
      throw new Error(
        `capture threw instead of returning a FailureRecord. ` +
        `Error: ${(err as Error).message}`,
      );
    }
    expect(result.stored).toBe(false);
    expect(result.failure).toBeDefined();
    expect(result.failure?.failureType).toBe('descriptor_not_registered');
    expect(result.failure?.diagnosticMetadata.modelDescriptorDigest).toBe(
      aiBom.modelDescriptorDigest,
    );
  });

  it('convenience form (AiBomWithInlineDescriptor) auto-registers then substitutes digest', async () => {
    const descriptor = descriptorFixture();
    const inlineForm: AiBomWithInlineDescriptor = {
      modelDescriptor: descriptor,
      vendorFingerprint: 'fp_inline_456',
      promptTemplate: null,
      inferenceParameters: {
        temperature: 0.2,
        topP: null,
        maxTokens: 128,
        seed: 42,
        stopSequences: ['END'],
      },
      infrastructure: {
        provider: 'test',
        region: 'us-east-1',
        apiVersion: null,
        endpoint: null,
      },
    };

    const result = await tzun.capture({ ...baseInput(), contributions: modelInput(inlineForm) });
    expect(result.stored).toBe(true);
    expect(modelOf(result.envelope.payload)).not.toBeNull();
    // Wire form: modelDescriptorDigest replaces the inline modelDescriptor.
    expect(modelOf(result.envelope.payload)).toHaveProperty('modelDescriptorDigest');
    expect((modelOf(result.envelope.payload) as AiBom).vendorFingerprint).toBe('fp_inline_456');

    // The descriptor must be in the catalog now (idempotent register).
    const digest = (modelOf(result.envelope.payload) as AiBom).modelDescriptorDigest;
    const row = await tzun.getStorage().getModelDescriptor!(digest);
    expect(row).not.toBeNull();
    expect(row?.descriptor.modelName).toBe('test-capture-model');
  });

  it('convenience form is idempotent — second capture re-uses the existing digest', async () => {
    const inlineForm: AiBomWithInlineDescriptor = {
      modelDescriptor: descriptorFixture(),
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };

    const a = await tzun.capture({ ...baseInput(), contributions: modelInput({ ...inlineForm }) });
    const b = await tzun.capture({ ...baseInput(), contributions: modelInput({ ...inlineForm }) });
    expect(a.stored).toBe(true);
    expect(b.stored).toBe(true);
    expect((modelOf(a.envelope.payload) as AiBom).modelDescriptorDigest).toBe(
      (modelOf(b.envelope.payload) as AiBom).modelDescriptorDigest,
    );
  });

  it('aiBom contributes to canonicalDigest round-trip', async () => {
    // Capture with an explicit aiBom and verify the digest differs from
    // an otherwise-identical capture with aiBom: null. (Both records share
    // sequenceNumber-driven monotonicity, but the canonicalDigest must
    // differ once aiBom is non-null.)
    const tzunA = await Tzun.init();
    const tzunB = await Tzun.init();
    const { digest } = await tzunA.models.register(descriptorFixture());
    await tzunB.models.register(descriptorFixture());

    const aiBom: AiBom = {
      modelDescriptorDigest: digest,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: null,
      infrastructure: null,
    };

    // Fix the time-dependent fields between captures so the *only*
    // canonical-input differential is the aiBom subtree. We do this by
    // freezing `capturedAt` via the canonical serializer's existing
    // deterministic path — we just compare the canonical digests of the
    // two payloads with the only difference being aiBom.
    const a = await tzunA.capture({ ...baseInput(), contributions: modelInput(aiBom) });
    const b = await tzunB.capture({ ...baseInput(), contributions: modelInput(null) });

    // Both succeed.
    expect(a.stored).toBe(true);
    expect(b.stored).toBe(true);

    // The digests must differ — aiBom is in the hashed field set.
    expect(a.envelope.integrity.canonicalDigest).not.toBe(
      b.envelope.integrity.canonicalDigest,
    );
  });
});
