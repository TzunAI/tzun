/**
 * NVIDIA NIM connector tests.
 *
 * NIM exposes an OpenAI-compatible API surface. The connector mirrors the
 * OpenAI connector's parameter mapping but emits vendor='nvidia-nim' and
 * populates an infrastructure block with provider='nvidia-nim'.
 *
 * Field mapping (NIM row):
 *   - params.temperature → inferenceParameters.temperature
 *   - params.top_p       → inferenceParameters.topP
 *   - params.max_tokens  → inferenceParameters.maxTokens
 *   - params.seed        → inferenceParameters.seed
 *   - params.stop        → inferenceParameters.stopSequences
 *   - response.model     → drives modelName/modelVersion (form: `org/model`)
 *   - response.system_fingerprint → vendorFingerprint (if present)
 */

import { nimConnector } from '../../../src/sdk/connectors/nim';
import { AiBomSkeleton } from '../../../src/sdk/connectors/base';
import {
  loadKnownModels,
  KnownModelsReference,
} from '../../../src/models/known-models';

describe('NVIDIA NIM connector', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  // ── Happy path ─────────────────────────────────────────────────────

  it('extracts AiBom skeleton from an NIM OpenAI-compatible call', () => {
    const params = {
      model: 'meta/llama-3.1-70b-instruct',
      temperature: 0.2,
      top_p: 0.9,
      max_tokens: 1024,
      seed: 7,
      stop: ['END'],
      messages: [{ role: 'user', content: 'hi' }],
      nim_endpoint: 'https://integrate.api.nvidia.com/v1',
      api_version: '1.0.0',
    };
    const response = {
      id: 'chatcmpl-nim-1',
      model: 'meta/llama-3.1-70b-instruct',
      choices: [{ index: 0, message: { role: 'assistant', content: 'hi' } }],
    };

    const skel = nimConnector.buildAiBom(params, response, known);
    expect(skel).not.toBeNull();
    const s = skel as AiBomSkeleton;

    // NIM emits vendor='nvidia-nim'.
    expect(s.modelDescriptor.vendor).toBe('nvidia-nim');
    expect(s.modelDescriptor.modelName).toBe('meta/llama-3.1-70b-instruct');
    // NIM's OpenAI-compatible response surface carries no version segment
    // in `model`, so the descriptor's modelVersion is 'unknown'.
    expect(s.modelDescriptor.modelVersion).toBe('unknown');
    // The known-models seed is keyed on what the wire id parses to (version
    // 'unknown'), so a bare NIM response still enriches from it. A seed keyed
    // on a version no NIM response carries would never match, and the
    // descriptor would lose its license and trainer.
    expect(s.modelDescriptor.license).toBe('llama-3.1-community');
    expect(s.modelDescriptor.trainedBy).toBe('Meta');

    expect(s.inferenceParameters).toEqual({
      temperature: 0.2,
      topP: 0.9,
      maxTokens: 1024,
      seed: 7,
      stopSequences: ['END'],
    });

    expect(s.infrastructure).toEqual({
      provider: 'nvidia-nim',
      region: null,
      apiVersion: '1.0.0',
      endpoint: 'https://integrate.api.nvidia.com/v1',
    });
    expect(s.vendorFingerprint).toBeNull();
  });

  it('vendorFingerprint comes from response.system_fingerprint when present', () => {
    const params = { model: 'meta/llama-3.1-70b-instruct' };
    const response = {
      model: 'meta/llama-3.1-70b-instruct',
      system_fingerprint: 'fp_nim_xyz',
    };
    const skel = nimConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).vendorFingerprint).toBe('fp_nim_xyz');
  });

  // ── Parameter mapping ──────────────────────────────────────────────

  it('stop string normalizes to single-element array', () => {
    const params = { model: 'meta/llama-3.1-70b-instruct', stop: 'END' };
    const response = { model: 'meta/llama-3.1-70b-instruct' };
    const skel = nimConnector.buildAiBom(params, response, known);
    expect((skel as AiBomSkeleton).inferenceParameters?.stopSequences).toEqual([
      'END',
    ]);
  });

  it('stopSequences null when stop absent', () => {
    const params = { model: 'meta/llama-3.1-70b-instruct' };
    const response = { model: 'meta/llama-3.1-70b-instruct' };
    const skel = nimConnector.buildAiBom(params, response, known);
    expect(
      (skel as AiBomSkeleton).inferenceParameters?.stopSequences,
    ).toBeNull();
  });

  it('handles missing optional params gracefully', () => {
    const params = { model: 'meta/llama-3.1-70b-instruct' };
    const response = { model: 'meta/llama-3.1-70b-instruct' };
    const skel = nimConnector.buildAiBom(params, response, known);
    const s = skel as AiBomSkeleton;

    expect(s.inferenceParameters).toEqual({
      temperature: null,
      topP: null,
      maxTokens: null,
      seed: null,
      stopSequences: null,
    });
    expect(s.vendorFingerprint).toBeNull();
    expect(s.infrastructure?.provider).toBe('nvidia-nim');
  });

  // ── Missing-model behavior ────────────────────────────────────────

  it('returns null when response has no model field', () => {
    const params = { model: 'meta/llama-3.1-70b-instruct' };
    const response = { object: 'embedding' };
    const skel = nimConnector.buildAiBom(params, response, known);
    expect(skel).toBeNull();
  });

  // ── Connector vendor identity ─────────────────────────────────────

  it('exposes vendor = "nvidia-nim"', () => {
    expect(nimConnector.vendor).toBe('nvidia-nim');
  });
});
