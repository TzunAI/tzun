/**
 * Connector base + OpenAI / Azure-OpenAI connector tests.
 *
 * The connector is a pure (params, response, knownModels) → AiBomSkeleton
 * transform. Descriptor registration happens in the wrapper layer; these
 * tests exercise only the transform side.
 *
 * Field mapping (OpenAI row):
 *   - params.temperature  → inferenceParameters.temperature
 *   - params.top_p        → inferenceParameters.topP
 *   - params.max_tokens   → inferenceParameters.maxTokens
 *   - params.seed         → inferenceParameters.seed
 *   - params.stop         → inferenceParameters.stopSequences (normalized to string[])
 *   - response.system_fingerprint → vendorFingerprint
 *   - response.model      → drives modelName/modelVersion resolution
 *
 * Azure variant: deployment-name surface; reverse-lookup against
 * known-models entries tagged with an `azure-deployment-name` external
 * identifier resolves the underlying model identity.
 */

import { openAiConnector } from '../../../src/sdk/connectors/openai';
import { AiBomSkeleton } from '../../../src/sdk/connectors/base';
import {
  loadKnownModels,
  KnownModelsReference,
} from '../../../src/models/known-models';
import { ModelDescriptor } from '@tzun/engine';

function assertSkeletonShape(s: AiBomSkeleton): void {
  expect(s.modelDescriptor).toBeDefined();
  expect(s.modelDescriptor.descriptorVersion).toBe('d1');
  expect(typeof s.modelDescriptor.vendor).toBe('string');
  expect(typeof s.modelDescriptor.modelName).toBe('string');
  expect(typeof s.modelDescriptor.modelVersion).toBe('string');
  expect(Array.isArray(s.modelDescriptor.regulatoryMarkings)).toBe(true);
  expect(Array.isArray(s.modelDescriptor.externalIdentifiers)).toBe(true);
}

describe('OpenAI connector', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  // ── Direct OpenAI happy path ─────────────────────────────────────

  it('extracts AiBom skeleton from a direct OpenAI chat-completions call', () => {
    const params = {
      model: 'gpt-4o-2024-08-06',
      temperature: 0.2,
      top_p: 0.9,
      max_tokens: 1024,
      seed: 42,
      stop: ['END'],
      messages: [{ role: 'user', content: 'hi' }],
    };
    const response = {
      id: 'chatcmpl-test',
      object: 'chat.completion',
      model: 'gpt-4o-2024-08-06',
      system_fingerprint: 'fp_abc123',
      choices: [{ index: 0, message: { role: 'assistant', content: 'hi' } }],
    };

    const skel = openAiConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    assertSkeletonShape(s);
    expect(s.modelDescriptor.vendor).toBe('openai');
    expect(s.modelDescriptor.modelName).toBe('gpt-4o');
    expect(s.modelDescriptor.modelVersion).toBe('2024-08-06');
    // Enriched from the seeded known-models entry.
    expect(s.modelDescriptor.license).toBe('openai-commercial');
    expect(s.modelDescriptor.modelType).toBe('llm');
    expect(s.modelDescriptor.trainedBy).toBe('OpenAI');

    expect(s.vendorFingerprint).toBe('fp_abc123');
    expect(s.inferenceParameters).toEqual({
      temperature: 0.2,
      topP: 0.9,
      maxTokens: 1024,
      seed: 42,
      stopSequences: ['END'],
    });
    // Direct OpenAI: no infrastructure block.
    expect(s.infrastructure).toBeNull();
    // No prompt template captured at the connector layer.
    expect(s.promptTemplate).toBeNull();
  });

  it('vendorFingerprint comes from response.system_fingerprint', () => {
    const params = { model: 'gpt-4o-2024-08-06' };
    const response = {
      model: 'gpt-4o-2024-08-06',
      system_fingerprint: 'fp_xyz789',
    };
    const skel = openAiConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    expect((skel as AiBomSkeleton).vendorFingerprint).toBe('fp_xyz789');
  });

  it('vendorFingerprint is null when system_fingerprint is absent', () => {
    const params = { model: 'gpt-4o-2024-08-06' };
    const response = { model: 'gpt-4o-2024-08-06' };
    const skel = openAiConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    expect((skel as AiBomSkeleton).vendorFingerprint).toBeNull();
  });

  // ── stop / stopSequences normalization ───────────────────────────

  it('stopSequences normalizes a single string to a single-element array', () => {
    const params = { model: 'gpt-4o-2024-08-06', stop: 'END' };
    const response = { model: 'gpt-4o-2024-08-06' };
    const skel = openAiConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).inferenceParameters?.stopSequences).toEqual([
      'END',
    ]);
  });

  it('stopSequences preserves a string array', () => {
    const params = {
      model: 'gpt-4o-2024-08-06',
      stop: ['END', 'STOP'],
    };
    const response = { model: 'gpt-4o-2024-08-06' };
    const skel = openAiConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).inferenceParameters?.stopSequences).toEqual([
      'END',
      'STOP',
    ]);
  });

  it('stopSequences is null when stop is absent', () => {
    const params = { model: 'gpt-4o-2024-08-06' };
    const response = { model: 'gpt-4o-2024-08-06' };
    const skel = openAiConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).inferenceParameters?.stopSequences).toBeNull();
  });

  // ── Missing-model / minimal-call behavior ────────────────────────

  it('returns null when response has no model field', () => {
    const params = {
      input: 'hello world',
      model: 'text-embedding-3-small',
    };
    // Embedding-style response — no `model` field on the response object.
    const response = {
      object: 'list',
      data: [{ object: 'embedding', index: 0, embedding: [0.1, 0.2] }],
      usage: { prompt_tokens: 2, total_tokens: 2 },
    };
    const skel = openAiConnector.buildAiBom(params, response, known);
    expect(skel).toBeNull();
  });

  it('handles missing optional params gracefully (all null)', () => {
    const params = { model: 'gpt-4o-2024-08-06' };
    const response = { model: 'gpt-4o-2024-08-06' };
    const skel = openAiConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    expect(s.inferenceParameters).toEqual({
      temperature: null,
      topP: null,
      maxTokens: null,
      seed: null,
      stopSequences: null,
    });
    expect(s.vendorFingerprint).toBeNull();
    expect(s.infrastructure).toBeNull();
    expect(s.promptTemplate).toBeNull();
  });

  // ── Azure OpenAI ─────────────────────────────────────────────────

  it('Azure OpenAI: deployment-name resolved via known-models reverse-lookup', () => {
    // Construct an inline known-models reference with a deployment-name
    // external identifier pointing back to the underlying OpenAI model.
    const localRef: KnownModelsReference = {
      version: 'test-azure',
      entries: [
        {
          vendor: 'openai',
          modelName: 'gpt-4o',
          modelVersion: '2024-08-06',
          modelType: 'llm',
          license: 'openai-commercial',
          trainedBy: 'OpenAI',
          externalIdentifiers: [
            {
              scheme: 'azure-deployment-name',
              value: 'my-prod-gpt4o',
              issuedBy: null,
              issuedAt: null,
              url: null,
            },
          ],
        },
      ],
    };

    const params = {
      model: 'my-prod-gpt4o',
      temperature: 0.1,
      max_tokens: 256,
      __tzunIsAzure: true,
      azure_endpoint: 'https://my-resource.openai.azure.com',
      api_version: '2024-06-01',
      azure_region: 'eastus',
    };
    const response = {
      // Azure surfaces the deployment name in `model`, not the underlying id.
      model: 'my-prod-gpt4o',
    };

    const skel = openAiConnector.buildAiBom(params, response, localRef);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    // Reverse-lookup resolved deployment-name → underlying model identity.
    expect(s.modelDescriptor.vendor).toBe('openai');
    expect(s.modelDescriptor.modelName).toBe('gpt-4o');
    expect(s.modelDescriptor.modelVersion).toBe('2024-08-06');
    expect(s.modelDescriptor.license).toBe('openai-commercial');

    // Azure infrastructure block populated.
    expect(s.infrastructure).toEqual({
      provider: 'azure',
      region: 'eastus',
      apiVersion: '2024-06-01',
      endpoint: 'https://my-resource.openai.azure.com',
    });
    expect(s.inferenceParameters?.temperature).toBe(0.1);
    expect(s.inferenceParameters?.maxTokens).toBe(256);
  });

  it('Azure OpenAI: unresolved deployment-name passes through as modelName', () => {
    const params = {
      model: 'custom-private-deployment',
      __tzunIsAzure: true,
      azure_endpoint: 'https://other.openai.azure.com',
      api_version: '2024-06-01',
    };
    const response = { model: 'custom-private-deployment' };

    const skel = openAiConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    // No matching deployment-name external identifier → pass-through.
    expect(s.modelDescriptor.vendor).toBe('openai');
    expect(s.modelDescriptor.modelName).toBe('custom-private-deployment');
    expect(s.modelDescriptor.integrityTier).toBe('vendor-asserted');
    expect(s.modelDescriptor.license).toBeNull();

    expect(s.infrastructure?.provider).toBe('azure');
    expect(s.infrastructure?.endpoint).toBe('https://other.openai.azure.com');
    expect(s.infrastructure?.apiVersion).toBe('2024-06-01');
  });

  it('Azure OpenAI: detected via azure_endpoint when explicit hint absent', () => {
    // No __tzunIsAzure hint but azure_endpoint set + no system_fingerprint
    // → connector should still classify as Azure.
    const params = {
      model: 'custom-private-deployment',
      azure_endpoint: 'https://other.openai.azure.com',
      api_version: '2024-06-01',
    };
    const response = { model: 'custom-private-deployment' };

    const skel = openAiConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    expect((skel as AiBomSkeleton).infrastructure?.provider).toBe('azure');
  });

  // ── Connector vendor identity ────────────────────────────────────

  it('exposes vendor = "openai"', () => {
    expect(openAiConnector.vendor).toBe('openai');
  });

  // ── Determinism ──────────────────────────────────────────────────

  it('is a pure transform — same input yields equal AiBom skeletons', () => {
    const params = {
      model: 'gpt-4o-2024-08-06',
      temperature: 0.5,
      top_p: 0.95,
      max_tokens: 512,
      seed: 7,
      stop: ['STOP'],
    };
    const response = {
      model: 'gpt-4o-2024-08-06',
      system_fingerprint: 'fp_deterministic',
    };
    const a = openAiConnector.buildAiBom(params, response, known);
    const b = openAiConnector.buildAiBom(params, response, known);
    expect(a).toEqual(b);
  });

  // ── Type integrity ───────────────────────────────────────────────

  it('descriptor passes the MVD shape contract', () => {
    const params = { model: 'gpt-4o-2024-08-06' };
    const response = { model: 'gpt-4o-2024-08-06' };
    const skel = openAiConnector.buildAiBom(params, response, known);
    const d: ModelDescriptor = (skel as AiBomSkeleton).modelDescriptor;
    expect(d.descriptorVersion).toBe('d1');
    expect(d.modelDigest).toBeNull();
    expect(d.parentModelDescriptorDigest).toBeNull();
    expect(d.training).toBeDefined();
    expect(d.training.trainingDataDigest).toBeNull();
    expect(Array.isArray(d.training.evaluations)).toBe(true);
  });
});
