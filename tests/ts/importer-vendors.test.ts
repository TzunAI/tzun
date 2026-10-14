/**
 * Per-vendor importer tests using the known-models reference.
 *
 * Each vendor block exercises:
 *   1. A known model (drawn from `data/known-models.json`) → `enriched: true`,
 *      with the seed entry's enrichment fields (license, modelType, etc.)
 *      surfaced on the descriptor.
 *   2. An unknown model id → `enriched: false`, descriptor is a valid MVD.
 *   3. `source` matches `<vendor>-known-models` per `ModelDescriptorSource`
 *      (note: the `nvidia-nim` vendor maps to `nim-known-models`, the source
 *      string already typed into `src/types/ai-bom.ts`).
 *
 * Plus cross-cutting tests for parseModelId behavior and reference immutability.
 */

import {
  importFromVendor,
  parseModelId,
  SupportedVendor,
} from '../../src/models/import-vendor';
import { loadKnownModels, KnownModelsReference } from '../../src/models/known-models';
import { ModelDescriptor } from '@tzun/engine';

// Helper — assert a descriptor is a valid MVD with the always-present fields
// (every key present; unknown values are explicit null).
function assertMvdShape(d: ModelDescriptor): void {
  expect(d.descriptorVersion).toBe('d1');
  expect(typeof d.vendor).toBe('string');
  expect(typeof d.modelName).toBe('string');
  expect(typeof d.modelVersion).toBe('string');
  expect(['weight-attested', 'vendor-asserted']).toContain(d.integrityTier);
  expect(d.modelDigest).toBeNull();
  expect(d.parentModelDescriptorDigest).toBeNull();
  expect(d.training).toBeDefined();
  expect(d.training.trainingDataDigest).toBeNull();
  expect(d.training.trainingDataRef).toBeNull();
  expect(d.training.lastTrainingDate).toBeNull();
  expect(Array.isArray(d.training.evaluations)).toBe(true);
  expect(Array.isArray(d.regulatoryMarkings)).toBe(true);
  expect(Array.isArray(d.externalIdentifiers)).toBe(true);
}

describe('vendor importer', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  // ── Per-vendor parametrized blocks ───────────────────────────────

  describe('openai', () => {
    it('1. enriches a known model (gpt-4o + date-split modelId)', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'openai',
        modelId: 'gpt-4o-2024-08-06',
        knownModels: known,
      });
      expect(enriched).toBe(true);
      expect(source).toBe('openai-known-models');
      expect(descriptor.vendor).toBe('openai');
      expect(descriptor.modelName).toBe('gpt-4o');
      expect(descriptor.modelVersion).toBe('2024-08-06');
      expect(descriptor.license).toBe('openai-commercial');
      expect(descriptor.modelType).toBe('llm');
      expect(descriptor.trainedBy).toBe('OpenAI');
      expect(descriptor.modelCardUrl).toBe(
        'https://platform.openai.com/docs/models/gpt-4o',
      );
      assertMvdShape(descriptor);
    });

    it('2. falls back to MVD for an unknown openai model', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'openai',
        modelId: 'gpt-not-a-real-model-2099-01-01',
        knownModels: known,
      });
      expect(enriched).toBe(false);
      expect(source).toBe('openai-known-models');
      expect(descriptor.vendor).toBe('openai');
      expect(descriptor.modelName).toBe('gpt-not-a-real-model');
      expect(descriptor.modelVersion).toBe('2099-01-01');
      expect(descriptor.license).toBeNull();
      expect(descriptor.modelType).toBeNull();
      expect(descriptor.trainedBy).toBeNull();
      expect(descriptor.modelCardUrl).toBeNull();
      assertMvdShape(descriptor);
    });
  });

  describe('anthropic', () => {
    it('1. enriches a known model from its real snapshot id (claude-3-5-sonnet-20241022)', () => {
      // A real Anthropic snapshot id, with the undashed `-YYYYMMDD` suffix the
      // API returns. The seed is keyed on what this wire id parses to, so the
      // id a connector actually sees is the one that enriches.
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'anthropic',
        modelId: 'claude-3-5-sonnet-20241022',
        knownModels: known,
      });
      expect(enriched).toBe(true);
      expect(source).toBe('anthropic-known-models');
      expect(descriptor.vendor).toBe('anthropic');
      expect(descriptor.modelName).toBe('claude-3-5-sonnet');
      expect(descriptor.modelVersion).toBe('20241022');
      expect(descriptor.license).toBe('anthropic-commercial');
      expect(descriptor.modelType).toBe('llm');
      expect(descriptor.trainedBy).toBe('Anthropic');
      assertMvdShape(descriptor);
    });

    it('1b. enriches a current-generation model whose id carries no snapshot (claude-opus-4-7)', () => {
      // `claude-opus-4-7` is the whole id — there is no dated form — so the
      // parser yields `modelVersion: 'unknown'` and the seed is keyed on that.
      const { descriptor, enriched } = importFromVendor({
        vendor: 'anthropic',
        modelId: 'claude-opus-4-7',
        knownModels: known,
      });
      expect(enriched).toBe(true);
      expect(descriptor.modelName).toBe('claude-opus-4-7');
      expect(descriptor.modelVersion).toBe('unknown');
      expect(descriptor.license).toBe('anthropic-commercial');
      assertMvdShape(descriptor);
    });

    it('2. falls back to MVD for unknown anthropic model (no date suffix)', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'anthropic',
        modelId: 'claude-nonexistent',
        knownModels: known,
      });
      expect(enriched).toBe(false);
      expect(source).toBe('anthropic-known-models');
      expect(descriptor.vendor).toBe('anthropic');
      expect(descriptor.modelName).toBe('claude-nonexistent');
      expect(descriptor.modelVersion).toBe('unknown');
      expect(descriptor.license).toBeNull();
      assertMvdShape(descriptor);
    });

    /**
     * A dashed date is not an Anthropic snapshot: the id stays whole, nothing
     * in the seed matches it, and the descriptor carries no enrichment. An id
     * the API never returns must not pick up a real model's license.
     */
    it('3. does NOT split or enrich a synthetic dashed-date id', () => {
      const { descriptor, enriched } = importFromVendor({
        vendor: 'anthropic',
        modelId: 'claude-opus-4-7-2026-01-15',
        knownModels: known,
      });
      expect(enriched).toBe(false);
      expect(descriptor.modelName).toBe('claude-opus-4-7-2026-01-15');
      expect(descriptor.modelVersion).toBe('unknown');
      expect(descriptor.license).toBeNull();
    });
  });

  describe('bedrock', () => {
    it('1. enriches a known bedrock model from its real wire modelId', () => {
      // The real wire modelId, with no `apiMetadata`: no connector passes
      // apiMetadata, so the seed is reachable only if the parser splits the
      // `provider.model-date-vN:M` id into name and version on its own.
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'bedrock',
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        knownModels: known,
      });
      expect(enriched).toBe(true);
      expect(source).toBe('bedrock-known-models');
      expect(descriptor.vendor).toBe('bedrock');
      expect(descriptor.modelName).toBe('anthropic.claude-3-5-sonnet');
      expect(descriptor.modelVersion).toBe('20241022-v2:0');
      expect(descriptor.license).toBe('anthropic-commercial');
      expect(descriptor.modelType).toBe('llm');
      expect(descriptor.trainedBy).toBe('Anthropic');
      assertMvdShape(descriptor);
    });

    it('2. falls back to MVD for unknown bedrock model', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'bedrock',
        modelId: 'fakeprovider.imaginary-model',
        knownModels: known,
      });
      expect(enriched).toBe(false);
      expect(source).toBe('bedrock-known-models');
      expect(descriptor.vendor).toBe('bedrock');
      expect(descriptor.modelName).toBe('fakeprovider.imaginary-model');
      expect(descriptor.modelVersion).toBe('unknown');
      expect(descriptor.license).toBeNull();
      assertMvdShape(descriptor);
    });
  });

  describe('vertex', () => {
    it('1. enriches a known vertex model with trailing numeric version', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'vertex',
        modelId: 'gemini-1.5-pro-001',
        knownModels: known,
      });
      expect(enriched).toBe(true);
      expect(source).toBe('vertex-known-models');
      expect(descriptor.vendor).toBe('vertex');
      expect(descriptor.modelName).toBe('gemini-1.5-pro');
      expect(descriptor.modelVersion).toBe('001');
      expect(descriptor.license).toBe('google-commercial');
      expect(descriptor.modelType).toBe('llm');
      expect(descriptor.trainedBy).toBe('Google');
      assertMvdShape(descriptor);
    });

    it('2. falls back to MVD when there is no trailing numeric version', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'vertex',
        modelId: 'gemini-1.5-pro',
        knownModels: known,
      });
      // No known entry exists for `gemini-1.5-pro` + `modelVersion: 'unknown'`.
      expect(enriched).toBe(false);
      expect(source).toBe('vertex-known-models');
      expect(descriptor.modelName).toBe('gemini-1.5-pro');
      expect(descriptor.modelVersion).toBe('unknown');
      assertMvdShape(descriptor);
    });

    it('3. falls back to MVD for unknown vertex model', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'vertex',
        modelId: 'unknown-model-007',
        knownModels: known,
      });
      expect(enriched).toBe(false);
      expect(source).toBe('vertex-known-models');
      expect(descriptor.modelName).toBe('unknown-model');
      expect(descriptor.modelVersion).toBe('007');
      assertMvdShape(descriptor);
    });
  });

  describe('azure-ai', () => {
    it('1. enriches a known azure-ai model (deployment-name surface)', () => {
      // On this surface the whole deployment name is the modelName and
      // nothing encodes a version, so the seed is keyed on
      // `('phi-3-medium-4k-instruct', 'unknown')`, the key the wire id parses
      // to with no apiMetadata.
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'azure-ai',
        modelId: 'phi-3-medium-4k-instruct',
        knownModels: known,
      });
      expect(enriched).toBe(true);
      expect(source).toBe('azure-ai-known-models');
      expect(descriptor.vendor).toBe('azure-ai');
      expect(descriptor.modelName).toBe('phi-3-medium-4k-instruct');
      expect(descriptor.modelVersion).toBe('unknown');
      expect(descriptor.license).toBe('mit');
      expect(descriptor.modelType).toBe('llm');
      expect(descriptor.trainedBy).toBe('Microsoft');
      assertMvdShape(descriptor);
    });

    it('2. falls back to MVD for unknown azure-ai deployment', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'azure-ai',
        modelId: 'custom-internal-deployment',
        knownModels: known,
      });
      expect(enriched).toBe(false);
      expect(source).toBe('azure-ai-known-models');
      expect(descriptor.modelName).toBe('custom-internal-deployment');
      expect(descriptor.modelVersion).toBe('unknown');
      assertMvdShape(descriptor);
    });
  });

  describe('nvidia-nim', () => {
    it('1. enriches a known NIM model with org/model id', () => {
      // `response.model` carries no version (a NIM container version such as
      // '1.0.0' never appears in it), so the seed is keyed on 'unknown' and the
      // bare wire id hits with no apiMetadata.
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'nvidia-nim',
        modelId: 'meta/llama-3.1-70b-instruct',
        knownModels: known,
      });
      expect(enriched).toBe(true);
      // The existing ModelDescriptorSource type uses `nim-known-models`
      // (not `nvidia-nim-known-models`), so the source must match that.
      expect(source).toBe('nim-known-models');
      expect(descriptor.vendor).toBe('nvidia-nim');
      expect(descriptor.modelName).toBe('meta/llama-3.1-70b-instruct');
      expect(descriptor.modelVersion).toBe('unknown');
      expect(descriptor.license).toBe('llama-3.1-community');
      expect(descriptor.modelType).toBe('llm');
      expect(descriptor.trainedBy).toBe('Meta');
      assertMvdShape(descriptor);
    });

    it('2. falls back to MVD for unknown NIM model', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'nvidia-nim',
        modelId: 'unknownorg/no-such-model',
        knownModels: known,
      });
      expect(enriched).toBe(false);
      expect(source).toBe('nim-known-models');
      expect(descriptor.vendor).toBe('nvidia-nim');
      expect(descriptor.modelName).toBe('unknownorg/no-such-model');
      expect(descriptor.modelVersion).toBe('unknown');
      assertMvdShape(descriptor);
    });
  });

  describe('hf-inference', () => {
    it('1. enriches a known hf-inference model with org/repo id', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'hf-inference',
        modelId: 'meta-llama/Llama-3.1-70B-Instruct',
        knownModels: known,
      });
      expect(enriched).toBe(true);
      expect(source).toBe('hf-inference-known-models');
      expect(descriptor.vendor).toBe('hf-inference');
      expect(descriptor.modelName).toBe('meta-llama/Llama-3.1-70B-Instruct');
      expect(descriptor.modelVersion).toBe('main');
      expect(descriptor.license).toBe('llama-3.1-community');
      expect(descriptor.modelType).toBe('llm');
      expect(descriptor.trainedBy).toBe('Meta');
      assertMvdShape(descriptor);
    });

    it('2. falls back to MVD for unknown hf-inference model', () => {
      const { descriptor, source, enriched } = importFromVendor({
        vendor: 'hf-inference',
        modelId: 'fake-org/no-such-model',
        knownModels: known,
      });
      expect(enriched).toBe(false);
      expect(source).toBe('hf-inference-known-models');
      expect(descriptor.vendor).toBe('hf-inference');
      expect(descriptor.modelName).toBe('fake-org/no-such-model');
      // Default for hf-inference is 'main' (HF-style branch convention).
      expect(descriptor.modelVersion).toBe('main');
      assertMvdShape(descriptor);
    });
  });

  // ── Cross-cutting parser tests ──────────────────────────────────

  describe('parseModelId', () => {
    type ParseCase = {
      vendor: SupportedVendor;
      modelId: string;
      expectedName: string;
      expectedVersion: string;
      apiMetadata?: { modelName?: string; modelVersion?: string };
    };

    const dateSplitCases: ParseCase[] = [
      {
        vendor: 'openai',
        modelId: 'gpt-4o-2024-08-06',
        expectedName: 'gpt-4o',
        expectedVersion: '2024-08-06',
      },
      {
        vendor: 'openai',
        modelId: 'gpt-4o-mini-2024-07-18',
        expectedName: 'gpt-4o-mini',
        expectedVersion: '2024-07-18',
      },
      {
        vendor: 'openai',
        modelId: 'gpt-4o',
        expectedName: 'gpt-4o',
        expectedVersion: 'unknown',
      },
      {
        vendor: 'openai',
        modelId: 'gpt-4o',
        expectedName: 'gpt-4o',
        expectedVersion: 'pinned-2024',
        apiMetadata: { modelVersion: 'pinned-2024' },
      },
      {
        // Real Anthropic snapshot ids are undashed `-YYYYMMDD`.
        vendor: 'anthropic',
        modelId: 'claude-3-5-sonnet-20241022',
        expectedName: 'claude-3-5-sonnet',
        expectedVersion: '20241022',
      },
      {
        vendor: 'anthropic',
        modelId: 'claude-opus-4-1-20250805',
        expectedName: 'claude-opus-4-1',
        expectedVersion: '20250805',
      },
      {
        // A dashed date is not an Anthropic id shape: the id stays whole.
        vendor: 'anthropic',
        modelId: 'claude-opus-4-7-2026-01-15',
        expectedName: 'claude-opus-4-7-2026-01-15',
        expectedVersion: 'unknown',
      },
      {
        vendor: 'anthropic',
        modelId: 'claude-haiku-4-5',
        expectedName: 'claude-haiku-4-5',
        expectedVersion: 'unknown',
      },
    ];

    it.each(dateSplitCases)(
      'splits trailing date for $vendor:$modelId',
      ({ vendor, modelId, expectedName, expectedVersion, apiMetadata }) => {
        const parsed = parseModelId(vendor, modelId, apiMetadata);
        expect(parsed.modelName).toBe(expectedName);
        expect(parsed.modelVersion).toBe(expectedVersion);
      },
    );

    it('vertex: extracts trailing numeric version', () => {
      expect(parseModelId('vertex', 'gemini-1.5-pro-002')).toEqual({
        modelName: 'gemini-1.5-pro',
        modelVersion: '002',
      });
      expect(parseModelId('vertex', 'gemini-1.5-flash-001')).toEqual({
        modelName: 'gemini-1.5-flash',
        modelVersion: '001',
      });
    });

    it('vertex: no trailing numeric → modelVersion is unknown (or hint)', () => {
      expect(parseModelId('vertex', 'gemini-1.5-pro')).toEqual({
        modelName: 'gemini-1.5-pro',
        modelVersion: 'unknown',
      });
      expect(
        parseModelId('vertex', 'gemini-1.5-pro', { modelVersion: 'hint-v' }),
      ).toEqual({ modelName: 'gemini-1.5-pro', modelVersion: 'hint-v' });
    });

    it('bedrock: splits the trailing -vN:M version (with its date run) off the provider.model id', () => {
      // The seed's bedrock entries are keyed on the `-vN:M` version, so the
      // parser must split it off for any of them to be reachable.
      expect(
        parseModelId('bedrock', 'anthropic.claude-3-5-sonnet-20241022-v2:0'),
      ).toEqual({
        modelName: 'anthropic.claude-3-5-sonnet',
        modelVersion: '20241022-v2:0',
      });
      expect(parseModelId('bedrock', 'meta.llama3-1-70b-instruct-v1:0')).toEqual({
        modelName: 'meta.llama3-1-70b-instruct',
        modelVersion: 'v1:0',
      });
      // An id with no `-vN:M` still keeps the whole id and defaults to unknown.
      expect(parseModelId('bedrock', 'anthropic.claude-3-5-sonnet')).toEqual({
        modelName: 'anthropic.claude-3-5-sonnet',
        modelVersion: 'unknown',
      });
      // A context-length variant after the `:M` (`:28k`, `:200k` — Bedrock's
      // provisioned-throughput ids) is not a `-vN:M` tail: kept whole,
      // 'unknown'. Documented in the module docstring; no bundled entry is
      // keyed on one.
      expect(parseModelId('bedrock', 'anthropic.claude-3-sonnet-20240229-v1:0:28k')).toEqual({
        modelName: 'anthropic.claude-3-sonnet-20240229-v1:0:28k',
        modelVersion: 'unknown',
      });
    });

    it('hf-inference: default modelVersion is "main"', () => {
      expect(parseModelId('hf-inference', 'org/repo')).toEqual({
        modelName: 'org/repo',
        modelVersion: 'main',
      });
    });

    it('nvidia-nim: keeps full org/model and defaults to unknown', () => {
      expect(
        parseModelId('nvidia-nim', 'meta/llama-3.1-70b-instruct'),
      ).toEqual({
        modelName: 'meta/llama-3.1-70b-instruct',
        modelVersion: 'unknown',
      });
    });
  });

  // ── Cross-cutting immutability test ──────────────────────────────

  it('does not mutate knownModels.entries', () => {
    const before = JSON.parse(JSON.stringify(known.entries));
    // Multiple imports across different vendors.
    importFromVendor({
      vendor: 'openai',
      modelId: 'gpt-4o-2024-08-06',
      knownModels: known,
    });
    importFromVendor({
      vendor: 'anthropic',
      modelId: 'claude-3-5-sonnet-20241022',
      knownModels: known,
    });
    importFromVendor({
      vendor: 'vertex',
      modelId: 'gemini-1.5-pro-001',
      knownModels: known,
    });
    expect(known.entries).toEqual(before);
  });

  it('never overrides parsed (vendor, modelName, modelVersion) from enrichment', () => {
    // Even if a hypothetical enrichment entry had different vendor/name/version
    // fields, the descriptor's identity triple must come from the parsed id.
    const localRef: KnownModelsReference = {
      version: 'test',
      entries: [
        {
          vendor: 'openai',
          modelName: 'gpt-4o',
          modelVersion: '2024-08-06',
          // Hypothetical malformed entry — would NOT survive the merge:
          // these three fields should be sourced from the parsed id.
          license: 'openai-commercial',
          modelType: 'llm',
        },
      ],
    };
    const { descriptor, enriched } = importFromVendor({
      vendor: 'openai',
      modelId: 'gpt-4o-2024-08-06',
      knownModels: localRef,
    });
    expect(enriched).toBe(true);
    expect(descriptor.vendor).toBe('openai');
    expect(descriptor.modelName).toBe('gpt-4o');
    expect(descriptor.modelVersion).toBe('2024-08-06');
    expect(descriptor.license).toBe('openai-commercial');
    expect(descriptor.modelType).toBe('llm');
  });
});
