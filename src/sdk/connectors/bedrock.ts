/**
 * AWS Bedrock connector.
 *
 * Bedrock has TWO API surfaces and the connector dispatches per call:
 *
 *   1. Converse:   params.modelId + params.messages + params.inferenceConfig
 *                  Parameters live in inferenceConfig in Bedrock-canonical form
 *                  (temperature, topP, maxTokens, stopSequences).
 *
 *   2. InvokeModel: params.modelId + params.body
 *                  `body` is a JSON-encoded blob of *vendor-native* params,
 *                  as a string or as UTF-8 bytes in a Uint8Array or Buffer
 *                  (the shape depends on which model family is being invoked
 *                  through Bedrock — Anthropic-on-Bedrock uses Anthropic
 *                  param names, Llama-on-Bedrock uses Llama param names, etc.)
 *
 * Dispatch discriminator:
 *   - params.inferenceConfig is a non-array object      ⇒ Converse
 *   - otherwise, params.body is a non-empty string, or a
 *     Uint8Array (Buffer included) that decodes to a
 *     non-empty string                                  ⇒ InvokeModel
 *   - otherwise                                         ⇒ all-null params
 *
 * Both surfaces share the modelId → descriptor path: importFromVendor with
 * vendor='bedrock' splits a trailing `-vN:M` version:variant, with any
 * date-like run before it, out as the modelVersion
 * (`anthropic.claude-3-5-sonnet-20241022-v2:0` →
 * `anthropic.claude-3-5-sonnet` + `20241022-v2:0`); an id without that tail
 * is the whole modelName, with version 'unknown'.
 *
 * Field mapping (Bedrock surface):
 *   Converse:    inferenceConfig.{temperature, topP, maxTokens, stopSequences}
 *   InvokeModel: see body-shape branches below.
 *
 * Infrastructure block: provider='aws-bedrock'; region from params.region when
 * present (the AWS SDK v3 client typically carries region in client config, not
 * per-call params — the wrapper layer is expected to surface it via params).
 *
 * No blocking external I/O is performed.
 */

import type { Connector, AiBomSkeleton } from './base';
import type { AiBom } from '@tzun/engine';
import { importFromVendor } from '../../models/import-vendor';

function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

function asNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : null;
}

function normalizeStopSequences(v: unknown): string[] | null {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) {
    const xs = v.filter((x): x is string => typeof x === 'string');
    return xs.length > 0 ? xs : null;
  }
  return null;
}

type InferenceParameters = NonNullable<AiBom['inferenceParameters']>;

const EMPTY_PARAMS: InferenceParameters = {
  temperature: null,
  topP: null,
  maxTokens: null,
  seed: null,
  stopSequences: null,
};

/**
 * Converse-surface parameter extractor. Field names match the Bedrock
 * Converse API shape verbatim.
 */
function paramsFromConverse(
  inferenceConfig: Record<string, unknown>,
): InferenceParameters {
  return {
    temperature: asNumber(inferenceConfig.temperature),
    topP: asNumber(inferenceConfig.topP),
    maxTokens: asNumber(inferenceConfig.maxTokens),
    seed: null,
    stopSequences: normalizeStopSequences(inferenceConfig.stopSequences),
  };
}

/**
 * InvokeModel-surface parameter extractor. The body shape depends on the
 * model family; we extract what's safe and leave the rest null.
 *
 * Recognized shapes:
 *   - Anthropic-on-Bedrock: temperature + top_p + max_tokens + stop_sequences
 *   - Llama-on-Bedrock:     temperature + top_p + max_gen_len
 *   - Other:                fall back to null mapping
 *
 * The two recognized shapes share `temperature` and `top_p`; we read those
 * uniformly and then look for the family-specific max-token / stop-sequence
 * fields. For an unknown body shape, whatever of those fields it carries is
 * read and the rest are null.
 */
function paramsFromInvokeModelBody(body: string): InferenceParameters {
  let parsed: Record<string, unknown>;
  try {
    const raw = JSON.parse(body);
    const rec = asRecord(raw);
    if (!rec) return EMPTY_PARAMS;
    parsed = rec;
  } catch {
    // Defensive: malformed body → empty params, but the descriptor still rides
    // on modelId so callers see *something* in the AiBom.
    return EMPTY_PARAMS;
  }

  // `max_tokens` (Anthropic-on-Bedrock) wins when both are present; otherwise
  // `max_gen_len` (Llama-on-Bedrock) covers the Llama family. Neither present
  // → null.
  const maxTokens =
    asNumber(parsed.max_tokens) ?? asNumber(parsed.max_gen_len);

  return {
    temperature: asNumber(parsed.temperature),
    topP: asNumber(parsed.top_p),
    maxTokens,
    seed: null,
    stopSequences: normalizeStopSequences(parsed.stop_sequences),
  };
}

/**
 * Decode an InvokeModel request body to text.
 *
 * `InvokeModelCommandInput.body` is a blob payload: the AWS SDK types it as
 * `Uint8Array | string | ...` and its own examples steer TypeScript users to
 * `new TextEncoder().encode(JSON.stringify(payload))` or `Buffer.from(...)`.
 * A string is taken as it is; a Uint8Array (Buffer is a subclass) is decoded
 * as UTF-8. Anything else, or an empty result, is `null`, and the call gets
 * EMPTY_PARAMS. The Python port (`_params_from_invoke_model_body`) reads
 * `str`, `bytes` and `bytearray` bodies the same way.
 */
function asBodyText(v: unknown): string | null {
  if (typeof v === 'string') return v.length > 0 ? v : null;
  if (v instanceof Uint8Array) {
    const text = new TextDecoder().decode(v);
    return text.length > 0 ? text : null;
  }
  return null;
}

export const bedrockConnector: Connector = {
  vendor: 'bedrock',

  buildAiBom(params, response, knownModels): AiBomSkeleton | null {
    const modelId = asString(params.modelId);
    if (!modelId) {
      return null;
    }

    const { descriptor } = importFromVendor({
      vendor: 'bedrock',
      modelId,
      knownModels,
    });

    // Dispatch — Converse beats InvokeModel when both shapes are present
    // (`inferenceConfig` is the primary discriminator). InvokeModel is the
    // legacy/Llama path; Converse is the unified path.
    const inferenceConfig = asRecord(params.inferenceConfig);
    const body = asBodyText(params.body);

    let inferenceParameters: InferenceParameters;
    if (inferenceConfig) {
      inferenceParameters = paramsFromConverse(inferenceConfig);
    } else if (body) {
      inferenceParameters = paramsFromInvokeModelBody(body);
    } else {
      inferenceParameters = EMPTY_PARAMS;
    }

    return {
      modelDescriptor: descriptor,
      // Bedrock does not expose a system fingerprint on either surface.
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters,
      infrastructure: {
        provider: 'aws-bedrock',
        region: asString(params.region),
        apiVersion: null,
        endpoint: null,
      },
    };
  },
};
