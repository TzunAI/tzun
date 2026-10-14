/**
 * AWS Bedrock connector tests.
 *
 * Bedrock has TWO API surfaces; this file exercises both:
 *
 *   1. Converse: params.modelId + params.messages + params.inferenceConfig
 *   2. InvokeModel: params.modelId + params.body (JSON of vendor-native params,
 *      as a string or as UTF-8 bytes in a Uint8Array or Buffer)
 *
 * Dispatch discriminator:
 *   - params.inferenceConfig is a non-array object          → Converse
 *   - otherwise, params.body is a non-empty string, or a
 *     Uint8Array (Buffer included) that decodes to a
 *     non-empty string                                      → InvokeModel
 *   - otherwise                                             → all-null params
 *
 * Field mapping (Bedrock row):
 *   Converse:    inferenceConfig.{temperature, topP, maxTokens, stopSequences}
 *   InvokeModel: body-encoded vendor-native params (Anthropic-on-Bedrock,
 *                Llama-on-Bedrock, etc.)
 */

import { bedrockConnector } from '../../../src/sdk/connectors/bedrock';
import { AiBomSkeleton } from '../../../src/sdk/connectors/base';
import {
  loadKnownModels,
  KnownModelsReference,
} from '../../../src/models/known-models';

describe('Bedrock connector', () => {
  let known: KnownModelsReference;

  beforeAll(async () => {
    known = await loadKnownModels();
  });

  // ── Converse surface ───────────────────────────────────────────────

  describe('Converse surface', () => {
    it('extracts AiBom skeleton from a Bedrock Converse call', () => {
      const params = {
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        messages: [{ role: 'user', content: [{ text: 'hi' }] }],
        inferenceConfig: {
          temperature: 0.2,
          topP: 0.9,
          maxTokens: 1024,
          stopSequences: ['END'],
        },
        region: 'us-east-1',
      };
      const response = {
        output: { message: { role: 'assistant', content: [{ text: 'hi' }] } },
        stopReason: 'end_turn',
        usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
      };

      const skel = bedrockConnector.buildAiBom(params, response, known);
      expect(skel).not.toBeNull();
      const s = skel as AiBomSkeleton;

      expect(s.modelDescriptor.vendor).toBe('bedrock');
      // The date and `-vN:M` version split off the full
      // `provider.model-date-vN:M` id, leaving `provider.model` as the
      // modelName, which is the key the bundled seed uses for this model.
      expect(s.modelDescriptor.modelName).toBe('anthropic.claude-3-5-sonnet');
      expect(s.modelDescriptor.modelVersion).toBe('20241022-v2:0');

      expect(s.inferenceParameters).toEqual({
        temperature: 0.2,
        topP: 0.9,
        maxTokens: 1024,
        seed: null,
        stopSequences: ['END'],
      });

      expect(s.infrastructure).toEqual({
        provider: 'aws-bedrock',
        region: 'us-east-1',
        apiVersion: null,
        endpoint: null,
      });
      expect(s.vendorFingerprint).toBeNull();
    });

    it('Converse: infrastructure.region is null when params.region absent', () => {
      const params = {
        modelId: 'meta.llama-3.1-70b-instruct-v1:0',
        inferenceConfig: { temperature: 0.5 },
      };
      const response = { output: { message: { role: 'assistant' } } };
      const skel = bedrockConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      expect(s.infrastructure?.region).toBeNull();
      expect(s.infrastructure?.provider).toBe('aws-bedrock');
    });

    it('Converse: handles missing optional inference params gracefully', () => {
      const params = {
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        inferenceConfig: {},
      };
      const response = { output: {} };
      const skel = bedrockConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      expect(s.inferenceParameters).toEqual({
        temperature: null,
        topP: null,
        maxTokens: null,
        seed: null,
        stopSequences: null,
      });
    });
  });

  // ── InvokeModel surface ───────────────────────────────────────────

  describe('InvokeModel surface', () => {
    it('extracts AiBom skeleton from InvokeModel with Anthropic-on-Bedrock body', () => {
      const params = {
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        body: JSON.stringify({
          anthropic_version: 'bedrock-2023-05-31',
          messages: [{ role: 'user', content: 'hi' }],
          temperature: 0.3,
          top_p: 0.85,
          max_tokens: 1500,
          stop_sequences: ['STOP'],
        }),
        region: 'us-west-2',
      };
      const response = { body: { /* stream bytes */ } };

      const skel = bedrockConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;

      expect(s.modelDescriptor.vendor).toBe('bedrock');
      // The date and `-vN:M` version split off the full
      // `provider.model-date-vN:M` id, leaving `provider.model` as the
      // modelName, which is the key the bundled seed uses for this model.
      expect(s.modelDescriptor.modelName).toBe('anthropic.claude-3-5-sonnet');
      expect(s.modelDescriptor.modelVersion).toBe('20241022-v2:0');
      expect(s.inferenceParameters).toEqual({
        temperature: 0.3,
        topP: 0.85,
        maxTokens: 1500,
        seed: null,
        stopSequences: ['STOP'],
      });
      expect(s.infrastructure).toEqual({
        provider: 'aws-bedrock',
        region: 'us-west-2',
        apiVersion: null,
        endpoint: null,
      });
    });

    it('extracts AiBom skeleton from InvokeModel with Llama-on-Bedrock body', () => {
      const params = {
        modelId: 'meta.llama-3.1-70b-instruct-v1:0',
        body: JSON.stringify({
          prompt: 'hi',
          temperature: 0.4,
          top_p: 0.7,
          max_gen_len: 512,
        }),
      };
      const response = { body: {} };

      const skel = bedrockConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;

      expect(s.inferenceParameters).toEqual({
        temperature: 0.4,
        topP: 0.7,
        maxTokens: 512,
        seed: null,
        stopSequences: null,
      });
    });

    it('InvokeModel: tolerates unknown body shape — null parameter mapping', () => {
      const params = {
        modelId: 'cohere.command-text-v14',
        body: JSON.stringify({ prompt: 'hi', some_other_param: 5 }),
      };
      const response = { body: {} };

      const skel = bedrockConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      // No recognized fields — all null. Connector still produces a descriptor.
      expect(s.inferenceParameters).toEqual({
        temperature: null,
        topP: null,
        maxTokens: null,
        seed: null,
        stopSequences: null,
      });
    });

    it('InvokeModel: malformed JSON body produces null params, descriptor still built', () => {
      const params = {
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        body: '{not valid json',
      };
      const response = { body: {} };
      const skel = bedrockConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      // The date and `-vN:M` version split off the full
      // `provider.model-date-vN:M` id, leaving `provider.model` as the
      // modelName, which is the key the bundled seed uses for this model.
      expect(s.modelDescriptor.modelName).toBe('anthropic.claude-3-5-sonnet');
      expect(s.modelDescriptor.modelVersion).toBe('20241022-v2:0');
      expect(s.inferenceParameters?.temperature).toBeNull();
    });
  });

  // ── Dispatch discrimination ────────────────────────────────────────

  describe('dispatch', () => {
    it('routes to Converse when params.inferenceConfig is present', () => {
      const params = {
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        // Both shapes attached — inferenceConfig wins per the spec.
        inferenceConfig: { temperature: 0.1 },
        body: JSON.stringify({ temperature: 0.9 }),
      };
      const response = {};
      const skel = bedrockConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      // Converse branch fired → temperature comes from inferenceConfig.
      expect(s.inferenceParameters?.temperature).toBe(0.1);
    });

    it('routes to InvokeModel when params.body (string) is present and inferenceConfig absent', () => {
      const params = {
        modelId: 'anthropic.claude-3-5-sonnet-20241022-v2:0',
        body: JSON.stringify({ temperature: 0.7 }),
      };
      const response = {};
      const skel = bedrockConnector.buildAiBom(params, response, known);
      const s = skel as AiBomSkeleton;
      expect(s.inferenceParameters?.temperature).toBe(0.7);
    });
  });

  // ── Missing-model behavior ────────────────────────────────────────

  it('returns null when params has no modelId', () => {
    const params = { inferenceConfig: { temperature: 0.5 } };
    const response = {};
    const skel = bedrockConnector.buildAiBom(params, response, known);
    expect(skel).toBeNull();
  });

  // ── Connector vendor identity ─────────────────────────────────────

  it('exposes vendor = "bedrock"', () => {
    expect(bedrockConnector.vendor).toBe('bedrock');
  });
});

/**
 * An InvokeModel body that is not a string.
 *
 * `InvokeModelCommandInput.body` is a blob payload — the AWS SDK types it
 * `Uint8Array | string | ...` and its own examples steer TypeScript users to
 * `new TextEncoder().encode(...)` or `Buffer.from(...)` — so the InvokeModel
 * branch reads those bodies as well as a string. Reading only a string would
 * give those callers an AI-BOM asserting
 * `temperature/topP/maxTokens/stopSequences: null` while the modelId still
 * resolved, so the record would look complete and be quietly wrong about how
 * the model was run.
 *
 * This also covers the path the AI-BOM runbook recommends for streaming —
 * decode the response yourself, then
 * `tzun.hook('bedrock', command.input, decoded)`.
 */
describe('Bedrock InvokeModel — non-string body shapes', () => {
  let known: KnownModelsReference;
  beforeAll(async () => {
    known = await loadKnownModels();
  });

  const payload = {
    anthropic_version: 'bedrock-2023-05-31',
    messages: [{ role: 'user', content: 'hi' }],
    temperature: 0.3,
    top_p: 0.85,
    max_tokens: 1500,
    stop_sequences: ['STOP'],
  };
  const expected = {
    temperature: 0.3,
    topP: 0.85,
    maxTokens: 1500,
    seed: null,
    stopSequences: ['STOP'],
  };
  const modelId = 'anthropic.claude-3-5-sonnet-20241022-v2:0';

  it('reads a Uint8Array body (the AWS-typed TextEncoder path)', () => {
    const skel = bedrockConnector.buildAiBom(
      { modelId, body: new TextEncoder().encode(JSON.stringify(payload)), region: 'us-west-2' },
      {},
      known,
    ) as AiBomSkeleton;
    expect(skel).not.toBeNull();
    expect(skel.inferenceParameters).toEqual(expected);
  });

  it('reads a Buffer body', () => {
    const skel = bedrockConnector.buildAiBom(
      { modelId, body: Buffer.from(JSON.stringify(payload), 'utf8'), region: 'us-west-2' },
      {},
      known,
    ) as AiBomSkeleton;
    expect(skel).not.toBeNull();
    expect(skel.inferenceParameters).toEqual(expected);
  });

  it('all three body encodings agree', () => {
    const forBody = (body: unknown) =>
      (bedrockConnector.buildAiBom({ modelId, body }, {}, known) as AiBomSkeleton)
        .inferenceParameters;
    const asStr = forBody(JSON.stringify(payload));
    expect(forBody(new TextEncoder().encode(JSON.stringify(payload)))).toEqual(asStr);
    expect(forBody(Buffer.from(JSON.stringify(payload), 'utf8'))).toEqual(asStr);
  });

  it('an empty or non-blob body still yields empty params, not a crash', () => {
    const empty = bedrockConnector.buildAiBom(
      { modelId, body: new Uint8Array(0) },
      {},
      known,
    ) as AiBomSkeleton;
    expect(empty.inferenceParameters).toEqual({
      temperature: null, topP: null, maxTokens: null, seed: null, stopSequences: null,
    });
    const numeric = bedrockConnector.buildAiBom(
      { modelId, body: 42 },
      {},
      known,
    ) as AiBomSkeleton;
    expect(numeric.inferenceParameters!.temperature).toBeNull();
  });

  it('Converse still wins over InvokeModel when both are present', () => {
    const skel = bedrockConnector.buildAiBom(
      {
        modelId,
        inferenceConfig: { temperature: 0.1, topP: 0.5, maxTokens: 10 },
        body: new TextEncoder().encode(JSON.stringify(payload)),
      },
      {},
      known,
    ) as AiBomSkeleton;
    expect(skel.inferenceParameters!.temperature).toBe(0.1);
    expect(skel.inferenceParameters!.maxTokens).toBe(10);
  });
});
