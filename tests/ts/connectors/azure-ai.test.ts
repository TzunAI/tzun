/**
 * Azure AI Foundry connector tests.
 *
 * Field mapping (Azure AI Foundry row):
 *   - params.temperature → inferenceParameters.temperature
 *   - params.top_p       → inferenceParameters.topP
 *   - params.max_tokens  → inferenceParameters.maxTokens
 *   - params.stop        → inferenceParameters.stopSequences (string→[string])
 *   - response.model     → drives modelName/modelVersion (deployment-name
 *                          surface — full id is the modelName, like the
 *                          Azure-OpenAI deployment surface)
 *
 * Azure AI Foundry is the non-OpenAI Azure surface (Phi, Mistral, Cohere,
 * etc.). Distinct from Azure OpenAI which is the OpenAI connector with
 * Azure deployment-name reverse-lookup.
 */

import { azureAiConnector } from '../../../src/sdk/connectors/azure-ai';
import { AiBomSkeleton } from '../../../src/sdk/connectors/base';
import {
  loadKnownModels,
  KnownModelsReference,
} from '../../../src/models/known-models';

describe('Azure AI Foundry connector', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  // ── Happy path ─────────────────────────────────────────────────────

  it('extracts AiBom skeleton from an Azure AI Foundry chat-completions call', () => {
    const params = {
      model: 'mistral-large-2407',
      temperature: 0.2,
      top_p: 0.9,
      max_tokens: 1024,
      stop: ['END'],
      messages: [{ role: 'user', content: 'hi' }],
      azure_endpoint:
        'https://my-foundry.eastus.inference.ai.azure.com',
      api_version: '2024-05-01-preview',
      azure_region: 'eastus',
    };
    const response = {
      id: 'chatcmpl-az-1',
      model: 'mistral-large-2407',
      choices: [{ index: 0, message: { role: 'assistant', content: 'hi' } }],
    };

    const skel = azureAiConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    expect(s.modelDescriptor.vendor).toBe('azure-ai');
    expect(s.modelDescriptor.modelName).toBe('mistral-large-2407');

    expect(s.vendorFingerprint).toBeNull();
    expect(s.inferenceParameters).toEqual({
      temperature: 0.2,
      topP: 0.9,
      maxTokens: 1024,
      seed: null,
      stopSequences: ['END'],
    });

    expect(s.infrastructure).toEqual({
      provider: 'azure-ai',
      region: 'eastus',
      apiVersion: '2024-05-01-preview',
      endpoint: 'https://my-foundry.eastus.inference.ai.azure.com',
    });
    expect(s.promptTemplate).toBeNull();
  });

  // ── Parameter mapping ──────────────────────────────────────────────

  it('stop string normalizes to single-element array', () => {
    const params = { model: 'phi-3-medium-4k-instruct', stop: 'END' };
    const response = { model: 'phi-3-medium-4k-instruct' };
    const skel = azureAiConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).inferenceParameters?.stopSequences).toEqual([
      'END',
    ]);
  });

  it('stopSequences null when stop absent', () => {
    const params = { model: 'phi-3-medium-4k-instruct' };
    const response = { model: 'phi-3-medium-4k-instruct' };
    const skel = azureAiConnector.buildAiBom(params, response, known);
    expect(
      (skel as AiBomSkeleton).inferenceParameters?.stopSequences,
    ).toBeNull();
  });

  it('handles missing optional params gracefully (all null)', () => {
    const params = { model: 'mistral-large-2407' };
    const response = { model: 'mistral-large-2407' };
    const skel = azureAiConnector.buildAiBom(params, response, known);
    const s = skel as AiBomSkeleton;

    expect(s.inferenceParameters).toEqual({
      temperature: null,
      topP: null,
      maxTokens: null,
      seed: null,
      stopSequences: null,
    });
    expect(s.vendorFingerprint).toBeNull();
    expect(s.infrastructure).toEqual({
      provider: 'azure-ai',
      region: null,
      apiVersion: null,
      endpoint: null,
    });
  });

  // ── Missing-model behavior ────────────────────────────────────────

  it('returns null when response has no model field', () => {
    const params = { model: 'mistral-large-2407' };
    const response = { id: 'x', object: 'embedding' };
    const skel = azureAiConnector.buildAiBom(params, response, known);
    expect(skel).toBeNull();
  });

  // ── Connector vendor identity ─────────────────────────────────────

  it('exposes vendor = "azure-ai"', () => {
    expect(azureAiConnector.vendor).toBe('azure-ai');
  });
});
