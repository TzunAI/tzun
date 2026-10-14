/**
 * OpenAI / Azure OpenAI connector.
 *
 * Field mapping (OpenAI surface):
 *
 *   params.temperature       → inferenceParameters.temperature
 *   params.top_p             → inferenceParameters.topP
 *   params.max_tokens        → inferenceParameters.maxTokens
 *   params.seed              → inferenceParameters.seed
 *   params.stop              → inferenceParameters.stopSequences
 *                              (string is normalized to a single-element array)
 *   response.system_fingerprint → vendorFingerprint
 *   response.model           → drives modelName/modelVersion resolution
 *
 * Azure OpenAI:
 *   The Azure surface exposes deployment names in `response.model`, not the
 *   underlying OpenAI model id. The connector detects Azure via
 *   `params.__tzunIsAzure === true` (an explicit hint that the wrapper layer
 *   sets when it sees an `AzureOpenAI` SDK instance) or by inspecting
 *   `params.azure_endpoint` (URL-shaped hint). When Azure-classified, the
 *   connector reverse-looks-up the deployment name against known-models
 *   entries that carry an `azure-deployment-name` external identifier; on a
 *   match, the descriptor identity is rewritten to the underlying model.
 *   On a miss, the deployment name passes through as the `modelName` and the
 *   descriptor stays vendor-asserted.
 *
 *   The infrastructure block on Azure is populated from `params.azure_endpoint`,
 *   `params.api_version`, and (optionally) `params.azure_region`.
 *
 * No blocking external I/O is performed. Same input → same output.
 */

import type { Connector, AiBomSkeleton } from './base';
import type { ModelDescriptor } from '@tzun/engine';
import type { KnownModelsReference } from '../../models/known-models';
import { importFromVendor } from '../../models/import-vendor';

// ── Field-extraction helpers ──────────────────────────────────────

function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

function asNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function asBoolean(v: unknown): boolean {
  return v === true;
}

/**
 * Normalize the OpenAI `stop` parameter (string or string[]) to a
 * `string[] | null` per the AI-BOM `inferenceParameters.stopSequences` shape.
 * Non-string array elements are filtered out defensively.
 */
function normalizeStop(v: unknown): string[] | null {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) {
    const xs = v.filter((x): x is string => typeof x === 'string');
    return xs.length > 0 ? xs : null;
  }
  return null;
}

// ── Azure detection + deployment reverse-lookup ───────────────────

/**
 * Heuristic Azure-OpenAI detector. The wrapper layer sets an explicit
 * `__tzunIsAzure: true` hint when it observes the `AzureOpenAI` SDK class;
 * we also accept an `azure_endpoint`-shaped URL as a fallback for callers
 * that build params manually. The heuristic intentionally avoids
 * `system_fingerprint` checks — Azure may surface a fingerprint in
 * future API versions, and absence-of-fingerprint is not a reliable
 * positive signal.
 */
function isAzure(params: Record<string, unknown>): boolean {
  if (asBoolean(params.__tzunIsAzure)) return true;
  const endpoint = asString(params.azure_endpoint);
  if (endpoint && /openai\.azure\.com/i.test(endpoint)) return true;
  return false;
}

/**
 * Reverse-lookup a deployment name against the known-models reference.
 * Matches entries with `vendor === 'openai'` that carry an external
 * identifier `{ scheme: 'azure-deployment-name', value: <deployment> }`.
 * Returns the matching entry (a Partial<ModelDescriptor>) or null.
 */
function resolveAzureDeployment(
  deploymentName: string,
  ref: KnownModelsReference,
): Partial<ModelDescriptor> | null {
  for (const entry of ref.entries) {
    if (entry.vendor !== 'openai') continue;
    const ids = entry.externalIdentifiers ?? [];
    if (
      ids.some(
        (i) => i.scheme === 'azure-deployment-name' && i.value === deploymentName,
      )
    ) {
      return entry;
    }
  }
  return null;
}

// ── Descriptor construction ───────────────────────────────────────

/**
 * Build a vendor-asserted MVD with explicit nulls — used as the pass-through
 * fallback for unresolved Azure deployments (the deployment name itself
 * becomes the `modelName`).
 */
function vendorAssertedMvd(modelName: string, modelVersion: string): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor: 'openai',
    modelName,
    modelVersion,
    modelType: null,
    integrityTier: 'vendor-asserted',
    modelDigest: null,
    parentModelDescriptorDigest: null,
    derivation: null,
    trainedBy: null,
    license: null,
    modelCardUrl: null,
    training: {
      trainingDataDigest: null,
      trainingDataRef: null,
      lastTrainingDate: null,
      evaluations: [],
    },
    regulatoryMarkings: [],
    externalIdentifiers: [],
  };
}

// ── Connector implementation ──────────────────────────────────────

export const openAiConnector: Connector = {
  vendor: 'openai',

  buildAiBom(
    params: Record<string, unknown>,
    response: Record<string, unknown>,
    knownModels: KnownModelsReference,
  ): AiBomSkeleton | null {
    // Returning null for a call with no resolvable model identity is the
    // canonical "no AI-BOM" signal. The wire AiBom can't be built without
    // at least a model id.
    const responseModel = asString(response.model);
    if (!responseModel) {
      return null;
    }

    const azure = isAzure(params);

    let modelDescriptor: ModelDescriptor;

    if (azure) {
      // Azure surface: `response.model` is the deployment name. Try
      // reverse-lookup against the known-models reference.
      const resolved = resolveAzureDeployment(responseModel, knownModels);
      if (
        resolved &&
        typeof resolved.modelName === 'string' &&
        typeof resolved.modelVersion === 'string'
      ) {
        // Hand the resolved underlying identity to the vendor importer so
        // enrichment is consistent with the direct-OpenAI path.
        const synthesizedId = `${resolved.modelName}-${resolved.modelVersion}`;
        modelDescriptor = importFromVendor({
          vendor: 'openai',
          modelId: synthesizedId,
          knownModels,
        }).descriptor;
      } else {
        // Pass-through: deployment-name is the modelName; vendor-asserted MVD.
        modelDescriptor = vendorAssertedMvd(responseModel, 'unknown');
      }
    } else {
      // Direct OpenAI: importer parses the date suffix and enriches.
      modelDescriptor = importFromVendor({
        vendor: 'openai',
        modelId: responseModel,
        knownModels,
      }).descriptor;
    }

    // Inference parameters envelope.
    const inferenceParameters = {
      temperature: asNumber(params.temperature),
      topP: asNumber(params.top_p),
      maxTokens: asNumber(params.max_tokens),
      seed: asNumber(params.seed),
      stopSequences: normalizeStop(params.stop),
    };

    // Infrastructure block: null for direct OpenAI; populated for Azure.
    const infrastructure = azure
      ? {
          provider: 'azure',
          region: asString(params.azure_region),
          apiVersion: asString(params.api_version),
          endpoint: asString(params.azure_endpoint),
        }
      : null;

    // Vendor fingerprint: only the direct surface emits it today; defensive
    // null-coalesce keeps the Azure path consistent if it ever lands.
    const vendorFingerprint = asString(response.system_fingerprint);

    return {
      modelDescriptor,
      vendorFingerprint,
      // Prompt template extraction is not part of the OpenAI request/response
      // pair — the wrapper layer injects this from per-call options.
      promptTemplate: null,
      inferenceParameters,
      infrastructure,
    };
  },
};
