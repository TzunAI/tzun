/**
 * Hugging Face Inference Endpoints connector tests.
 *
 * Field mapping (HF Inference row):
 *   - params.model (or extracted from endpoint URL) → modelName/modelVersion
 *   - params.parameters.temperature     → inferenceParameters.temperature
 *   - params.parameters.top_p           → inferenceParameters.topP
 *   - params.parameters.max_new_tokens  → inferenceParameters.maxTokens
 *                                          (HF uses `max_new_tokens`)
 *   - params.parameters.stop            → inferenceParameters.stopSequences
 *
 * The endpoint URL form for HF inference is
 *   https://api-inference.huggingface.co/models/<org>/<model>
 * The connector extracts `<org>/<model>` as the modelName when `params.model`
 * is not set explicitly.
 */

import { hfInferenceConnector } from '../../../src/sdk/connectors/hf-inference';
import { AiBomSkeleton } from '../../../src/sdk/connectors/base';
import {
  loadKnownModels,
  KnownModelsReference,
} from '../../../src/models/known-models';

describe('HF Inference connector', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  // ── Happy path ─────────────────────────────────────────────────────

  it('extracts AiBom skeleton from an HF Inference call', () => {
    const params = {
      model: 'meta-llama/Llama-3.1-70B-Instruct',
      parameters: {
        temperature: 0.2,
        top_p: 0.9,
        max_new_tokens: 1024,
        stop: ['END'],
      },
      inputs: 'hi',
      endpoint:
        'https://api-inference.huggingface.co/models/meta-llama/Llama-3.1-70B-Instruct',
    };
    const response = {
      generated_text: 'hi',
    };

    const skel = hfInferenceConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    expect(s.modelDescriptor.vendor).toBe('hf-inference');
    expect(s.modelDescriptor.modelName).toBe(
      'meta-llama/Llama-3.1-70B-Instruct',
    );
    expect(s.modelDescriptor.modelVersion).toBe('main');
    // Enriched from the seeded known-models entry.
    expect(s.modelDescriptor.license).toBe('llama-3.1-community');
    expect(s.modelDescriptor.trainedBy).toBe('Meta');

    expect(s.vendorFingerprint).toBeNull();
    expect(s.inferenceParameters).toEqual({
      temperature: 0.2,
      topP: 0.9,
      maxTokens: 1024,
      seed: null,
      stopSequences: ['END'],
    });
    expect(s.infrastructure).toEqual({
      provider: 'hf-inference',
      region: null,
      apiVersion: null,
      endpoint:
        'https://api-inference.huggingface.co/models/meta-llama/Llama-3.1-70B-Instruct',
    });
  });

  // ── Model id extraction ────────────────────────────────────────────

  it('extracts modelName from endpoint URL when params.model is absent', () => {
    const params = {
      parameters: { temperature: 0.5 },
      inputs: 'hi',
      endpoint:
        'https://api-inference.huggingface.co/models/meta-llama/Llama-3.1-70B-Instruct',
    };
    const response = { generated_text: 'hi' };
    const skel = hfInferenceConnector.buildAiBom(params, response, known);
    const s = skel as AiBomSkeleton;
    expect(s.modelDescriptor.modelName).toBe(
      'meta-llama/Llama-3.1-70B-Instruct',
    );
  });

  it('returns null when neither params.model nor endpoint identify a model', () => {
    const params = {
      parameters: { temperature: 0.5 },
      inputs: 'hi',
    };
    const response = { generated_text: 'hi' };
    const skel = hfInferenceConnector.buildAiBom(params, response, known);
    expect(skel).toBeNull();
  });

  // ── Parameter mapping ──────────────────────────────────────────────

  it('uses max_new_tokens (not max_tokens) for maxTokens mapping', () => {
    const params = {
      model: 'meta-llama/Llama-3.1-70B-Instruct',
      parameters: { max_new_tokens: 512, max_tokens: 9999 },
    };
    const response = { generated_text: 'hi' };
    const skel = hfInferenceConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).inferenceParameters?.maxTokens).toBe(512);
  });

  it('stop string normalizes to single-element array', () => {
    const params = {
      model: 'meta-llama/Llama-3.1-70B-Instruct',
      parameters: { stop: 'END' },
    };
    const response = { generated_text: 'hi' };
    const skel = hfInferenceConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).inferenceParameters?.stopSequences).toEqual([
      'END',
    ]);
  });

  it('handles missing parameters block gracefully', () => {
    const params = { model: 'meta-llama/Llama-3.1-70B-Instruct' };
    const response = { generated_text: 'hi' };
    const skel = hfInferenceConnector.buildAiBom(params, response, known);
    const s = skel as AiBomSkeleton;
    expect(s.inferenceParameters).toEqual({
      temperature: null,
      topP: null,
      maxTokens: null,
      seed: null,
      stopSequences: null,
    });
  });

  // ── Connector vendor identity ─────────────────────────────────────

  it('exposes vendor = "hf-inference"', () => {
    expect(hfInferenceConnector.vendor).toBe('hf-inference');
  });
});

/**
 * The chatCompletion argument shape.
 *
 * `params.parameters.*` is the `textGeneration({ inputs, parameters: {...} })`
 * shape. `attachClient` also intercepts `chatCompletion`, whose parameters are
 * OpenAI-style and top-level — and chatCompletion is the shape
 * the AI-BOM runbook documents
 * (`hf.chatCompletion({ model, messages, max_tokens: 100, tzun_capture })`).
 * The connector reads the top-level parameters when `parameters` is absent.
 * Reading only `params.parameters.*` would make every capture that followed
 * the runbook record null for every inference parameter, on a record that
 * otherwise looked complete: the AI-BOM would assert no inference parameters
 * were set when they demonstrably were.
 */
describe('HF Inference connector — chatCompletion argument shape', () => {
  let known: KnownModelsReference;
  beforeAll(async () => {
    known = await loadKnownModels();
  });

  it('reads top-level OpenAI-style parameters when `parameters` is absent', () => {
    const skeleton = hfInferenceConnector.buildAiBom(
      {
        model: 'meta-llama/Llama-3.1-70B-Instruct',
        messages: [{ role: 'user', content: 'hi' }],
        temperature: 0.2,
        top_p: 0.85,
        max_tokens: 100,
        seed: 7,
        stop: ['STOP'],
      },
      { choices: [{ message: { role: 'assistant', content: 'hi' } }] },
      known,
    );

    expect(skeleton).not.toBeNull();
    expect(skeleton!.inferenceParameters).toEqual({
      temperature: 0.2,
      topP: 0.85,
      maxTokens: 100,
      seed: 7,
      stopSequences: ['STOP'],
    });
  });

  it('a bare string `stop` is normalized on the chatCompletion path too', () => {
    const skeleton = hfInferenceConnector.buildAiBom(
      { model: 'meta-llama/Llama-3.1-70B-Instruct', stop: 'END' },
      {},
      known,
    );
    expect(skeleton).not.toBeNull();
    expect(skeleton!.inferenceParameters!.stopSequences).toEqual(['END']);
  });

  it('the textGeneration shape still wins when `parameters` is present', () => {
    // `parameters` is authoritative: a caller using the textGeneration shape
    // must not have top-level keys read out from under it.
    const skeleton = hfInferenceConnector.buildAiBom(
      {
        model: 'meta-llama/Llama-3.1-70B-Instruct',
        parameters: { temperature: 0.1, max_new_tokens: 64 },
        temperature: 0.9,
        max_tokens: 4096,
      },
      {},
      known,
    );
    expect(skeleton).not.toBeNull();
    expect(skeleton!.inferenceParameters!.temperature).toBe(0.1);
    expect(skeleton!.inferenceParameters!.maxTokens).toBe(64);
  });
});
