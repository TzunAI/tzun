/**
 * NVIDIA NIM connector.
 *
 * NIM exposes an OpenAI-compatible API surface, so parameter mapping mirrors
 * the OpenAI connector. The vendor string is `nvidia-nim` (matching the
 * `SupportedVendor` literal in src/models/import-vendor.ts), and the
 * infrastructure block carries provider='nvidia-nim' with endpoint and
 * apiVersion sourced from per-call wrapper hints.
 *
 * Field mapping (NIM surface):
 *
 *   params.temperature → inferenceParameters.temperature
 *   params.top_p       → inferenceParameters.topP
 *   params.max_tokens  → inferenceParameters.maxTokens
 *   params.seed        → inferenceParameters.seed
 *   params.stop        → inferenceParameters.stopSequences (string→[string])
 *   response.model     → drives modelName/modelVersion (form: `org/model`,
 *                        passed verbatim to importFromVendor as modelName)
 *   response.system_fingerprint → vendorFingerprint (passed through if
 *                                 NIM emits one; null otherwise)
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

function normalizeStop(v: unknown): string[] | null {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) {
    const xs = v.filter((x): x is string => typeof x === 'string');
    return xs.length > 0 ? xs : null;
  }
  return null;
}

export const nimConnector: Connector = {
  vendor: 'nvidia-nim',

  buildAiBom(params, response, knownModels): AiBomSkeleton | null {
    const responseModel = asString(response.model);
    if (!responseModel) {
      return null;
    }

    const { descriptor } = importFromVendor({
      vendor: 'nvidia-nim',
      modelId: responseModel,
      knownModels,
    });

    return {
      modelDescriptor: descriptor,
      vendorFingerprint: asString(response.system_fingerprint),
      promptTemplate: null,
      inferenceParameters: {
        temperature: asNumber(params.temperature),
        topP: asNumber(params.top_p),
        maxTokens: asNumber(params.max_tokens),
        seed: asNumber(params.seed),
        stopSequences: normalizeStop(params.stop),
      },
      infrastructure: {
        provider: 'nvidia-nim',
        region: null,
        apiVersion: asString(params.api_version),
        endpoint: asString(params.nim_endpoint),
      },
    };
  },
};
