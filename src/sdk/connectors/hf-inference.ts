/**
 * Hugging Face Inference Endpoints connector.
 *
 * Field mapping (HF Inference surface):
 *
 *   params.model OR endpoint URL → drives modelName resolution
 *     (form: `<org>/<model>`, parsed by importFromVendor with vendor
 *     'hf-inference'; modelVersion defaults to 'main' per the HF revision
 *     convention)
 *   params.parameters.temperature     → inferenceParameters.temperature
 *   params.parameters.top_p           → inferenceParameters.topP
 *   params.parameters.max_new_tokens  → inferenceParameters.maxTokens
 *                                        (HF uses `max_new_tokens`, not
 *                                        `max_tokens`)
 *   params.parameters.stop            → inferenceParameters.stopSequences
 *                                        (string normalized to [string])
 *
 * The HF Inference endpoint URL form is
 *   https://api-inference.huggingface.co/models/<org>/<model>
 * The connector extracts the `<org>/<model>` segment when params.model is
 * absent (matching what the HF python/node clients build internally).
 *
 * vendorFingerprint is null — the HF inference surface does not expose one.
 *
 * No blocking external I/O is performed.
 */

import type { Connector, AiBomSkeleton } from './base';
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

function normalizeStop(v: unknown): string[] | null {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) {
    const xs = v.filter((x): x is string => typeof x === 'string');
    return xs.length > 0 ? xs : null;
  }
  return null;
}

const ENDPOINT_MODEL_RE = /\/models\/([^/]+\/[^/?#]+)(?:[/?#]|$)/;

/**
 * Extracts the `<org>/<model>` segment from an HF inference endpoint URL.
 * Returns null if the URL doesn't follow the expected `/models/<org>/<model>`
 * shape.
 */
function modelIdFromEndpoint(endpoint: string): string | null {
  const m = ENDPOINT_MODEL_RE.exec(endpoint);
  return m ? m[1] : null;
}

export const hfInferenceConnector: Connector = {
  vendor: 'hf-inference',

  buildAiBom(params, response, knownModels): AiBomSkeleton | null {
    let modelId: string | null = asString(params.model);
    if (!modelId) {
      const endpoint = asString(params.endpoint);
      if (endpoint) {
        modelId = modelIdFromEndpoint(endpoint);
      }
    }
    if (!modelId) {
      return null;
    }

    const { descriptor } = importFromVendor({
      vendor: 'hf-inference',
      modelId,
      knownModels,
    });

    // Two argument shapes reach this connector, and both are read:
    //
    //   textGeneration({ inputs, parameters: { temperature, max_new_tokens, … } })
    //   chatCompletion({ model, messages, temperature, max_tokens, … })
    //
    // `attachClient` intercepts BOTH and hands them to the same connector, and
    // chatCompletion — the OpenAI-style, top-level-parameter shape — is the one
    // the AI-BOM integration guide (`docs/integration/`) documents. Reading
    // only `params.parameters.*` would record null for every inference
    // parameter of a capture that follows the guide, on a record that
    // otherwise looks complete.
    const parameters = asRecord(params.parameters);
    const inferenceParameters = parameters
      ? {
          temperature: asNumber(parameters.temperature),
          topP: asNumber(parameters.top_p),
          // HF's text-generation surface uses `max_new_tokens`, not `max_tokens`.
          maxTokens: asNumber(parameters.max_new_tokens),
          seed: asNumber(parameters.seed),
          stopSequences: normalizeStop(parameters.stop),
        }
      : {
          temperature: asNumber(params.temperature),
          topP: asNumber(params.top_p),
          maxTokens: asNumber(params.max_tokens),
          seed: asNumber(params.seed),
          stopSequences: normalizeStop(params.stop),
        };

    return {
      modelDescriptor: descriptor,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters,
      infrastructure: {
        provider: 'hf-inference',
        region: null,
        apiVersion: null,
        endpoint: asString(params.endpoint),
      },
    };
  },
};
