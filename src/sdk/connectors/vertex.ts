/**
 * GCP Vertex AI connector.
 *
 * Vertex has TWO API surfaces and the connector dispatches per call:
 *
 *   1. generateContent: params.model + params.contents + params.generationConfig
 *                       (Gemini-family models)
 *
 *   2. predict:         params.endpoint + params.instances + params.parameters
 *                       (PaLM-family + publisher models served via the
 *                       generic prediction endpoint)
 *
 * Dispatch discriminator (per the plan):
 *   - presence of params.generationConfig ⇒ generateContent
 *   - presence of params.instances        ⇒ predict
 *
 * Field mapping (Vertex surface):
 *   generateContent: generationConfig.{temperature, topP, maxOutputTokens,
 *                                       stopSequences}
 *                    (note `maxOutputTokens`, not `max_tokens`)
 *   predict:         parameters.{temperature, topP, maxOutputTokens,
 *                                 stopSequences}
 *
 * Model id resolution:
 *   - generateContent uses `params.model` directly (e.g., `gemini-1.5-pro-001`).
 *   - predict uses `params.endpoint` (a resource path like
 *     `projects/p/locations/l/publishers/google/models/gemini-1.5-pro-001`);
 *     we extract the trailing model id.
 *
 * Infrastructure block uses provider='gcp-vertex'; region from params.location.
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

/**
 * Extracts the trailing model id from a Vertex endpoint resource path.
 * Accepts both fully-qualified
 *   `projects/p/locations/l/publishers/google/models/<model-id>`
 * and short
 *   `publishers/google/models/<model-id>`
 * forms. Returns null if the path doesn't follow the
 * `publishers/<publisher>/models/<id>` shape.
 */
function modelIdFromEndpoint(endpoint: string): string | null {
  const m = /publishers\/[^/]+\/models\/([^/]+)$/.exec(endpoint);
  return m ? m[1] : null;
}

/**
 * Parameter extractor common to both surfaces: the field shapes are the same,
 * just nested under different keys (`generationConfig` vs `parameters`).
 */
function paramsFromVertexConfig(
  config: Record<string, unknown>,
): InferenceParameters {
  return {
    temperature: asNumber(config.temperature),
    topP: asNumber(config.topP),
    maxTokens: asNumber(config.maxOutputTokens),
    seed: null,
    stopSequences: normalizeStopSequences(config.stopSequences),
  };
}

export const vertexConnector: Connector = {
  vendor: 'vertex',

  buildAiBom(params, response, knownModels): AiBomSkeleton | null {
    // Dispatch — generateContent wins when both shapes are present
    // (`generationConfig` is the primary discriminator).
    const generationConfig = asRecord(params.generationConfig);
    const predictParameters = asRecord(params.parameters);
    const hasInstances = Array.isArray(params.instances);

    let modelId: string | null = null;
    let inferenceParameters: InferenceParameters;

    if (generationConfig) {
      // generateContent path: model id comes from params.model.
      modelId = asString(params.model);
      inferenceParameters = paramsFromVertexConfig(generationConfig);
    } else if (hasInstances) {
      // predict path: model id is derived from the endpoint resource path.
      // Falls back to params.model when caller sets it explicitly (some SDK
      // call sites carry both for convenience).
      const endpoint = asString(params.endpoint);
      modelId =
        (endpoint ? modelIdFromEndpoint(endpoint) : null) ??
        asString(params.model);
      inferenceParameters = predictParameters
        ? paramsFromVertexConfig(predictParameters)
        : {
            temperature: null,
            topP: null,
            maxTokens: null,
            seed: null,
            stopSequences: null,
          };
    } else {
      // No dispatch discriminator → fall back to params.model and empty params.
      modelId = asString(params.model);
      inferenceParameters = {
        temperature: null,
        topP: null,
        maxTokens: null,
        seed: null,
        stopSequences: null,
      };
    }

    if (!modelId) {
      return null;
    }

    const { descriptor } = importFromVendor({
      vendor: 'vertex',
      modelId,
      knownModels,
    });

    return {
      modelDescriptor: descriptor,
      // Vertex exposes no system fingerprint on either surface.
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters,
      infrastructure: {
        provider: 'gcp-vertex',
        region: asString(params.location),
        apiVersion: null,
        endpoint: asString(params.endpoint),
      },
    };
  },
};
