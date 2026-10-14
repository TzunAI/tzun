/**
 * Azure AI Foundry connector.
 *
 * This is the non-OpenAI Azure surface — Phi, Mistral, Cohere, etc. served
 * through Azure AI Foundry endpoints. The Azure-OpenAI surface is handled
 * by the OpenAI connector with deployment-name reverse-lookup; this module
 * is its sibling for everything else under Azure.
 *
 * Field mapping (Azure AI Foundry surface):
 *
 *   params.temperature → inferenceParameters.temperature
 *   params.top_p       → inferenceParameters.topP
 *   params.max_tokens  → inferenceParameters.maxTokens
 *   params.stop        → inferenceParameters.stopSequences
 *                        (string normalized to [string])
 *   response.model     → drives modelName/modelVersion (deployment-name
 *                        surface — full id is the modelName)
 *
 * The infrastructure block is populated with provider='azure-ai' plus
 * region / apiVersion / endpoint from the per-call hints set by the
 * Azure AI wrapper layer.
 *
 * vendorFingerprint is null — the Azure AI Foundry surface does not expose
 * one.
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

export const azureAiConnector: Connector = {
  vendor: 'azure-ai',

  buildAiBom(params, response, knownModels): AiBomSkeleton | null {
    const responseModel = asString(response.model);
    if (!responseModel) {
      return null;
    }

    const { descriptor } = importFromVendor({
      vendor: 'azure-ai',
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
        stopSequences: normalizeStop(params.stop),
      },
      infrastructure: {
        provider: 'azure-ai',
        region: asString(params.azure_region),
        apiVersion: asString(params.api_version),
        endpoint: asString(params.azure_endpoint),
      },
    };
  },
};
