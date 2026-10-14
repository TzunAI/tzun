/**
 * Anthropic connector.
 *
 * Field mapping (Anthropic direct surface):
 *
 *   params.temperature      → inferenceParameters.temperature
 *   params.top_p            → inferenceParameters.topP
 *   params.max_tokens       → inferenceParameters.maxTokens
 *   params.stop_sequences   → inferenceParameters.stopSequences
 *                             (Anthropic uses `stop_sequences`, not `stop`)
 *   response.model          → drives modelName/modelVersion resolution
 *
 * Anthropic does not expose `system_fingerprint` or `seed`; both surface as
 * null in the AiBom skeleton. Infrastructure is null — the Anthropic direct
 * surface is a single SaaS endpoint with no per-call region/endpoint metadata.
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

function normalizeStopSequences(v: unknown): string[] | null {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) {
    const xs = v.filter((x): x is string => typeof x === 'string');
    return xs.length > 0 ? xs : null;
  }
  return null;
}

export const anthropicConnector: Connector = {
  vendor: 'anthropic',

  buildAiBom(params, response, knownModels): AiBomSkeleton | null {
    const responseModel = asString(response.model);
    if (!responseModel) {
      return null;
    }

    const { descriptor } = importFromVendor({
      vendor: 'anthropic',
      modelId: responseModel,
      knownModels,
    });

    return {
      modelDescriptor: descriptor,
      vendorFingerprint: null,
      promptTemplate: null,
      inferenceParameters: {
        temperature: asNumber(params.temperature),
        topP: asNumber(params.top_p),
        maxTokens: asNumber(params.max_tokens),
        seed: null,
        stopSequences: normalizeStopSequences(params.stop_sequences),
      },
      infrastructure: null,
    };
  },
};
