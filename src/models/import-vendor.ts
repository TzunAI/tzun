/**
 * Per-vendor importers using the known-models reference.
 *
 * Supports the eight conventional vendor surfaces seeded in
 * `data/known-models.json`:
 *   openai, anthropic, bedrock, vertex, azure-ai, nvidia-nim, hf-inference,
 *   openrouter.
 *
 * Each vendor's `modelId` is parsed per its native id convention. The rule of
 * the table is: the parser splits out exactly the version segment the vendor's
 * own id encodes, verbatim, and `data/known-models.json` is keyed on what the
 * parser yields for the vendor's real wire id — so every bundled entry is
 * reachable from a real `response.model` / `modelId`. Nothing is normalised
 * (no dashes inserted into dates), so `modelName + '-' + modelVersion`
 * reconstructs the wire id for every vendor that encodes a version at all.
 *
 *   - openai: trailing `-YYYY-MM-DD` snapshot date (`gpt-4o-2024-08-06`) is
 *     split out as `modelVersion`; the head becomes `modelName`.
 *   - anthropic: trailing `-YYYYMMDD` snapshot date — an undashed 8-digit
 *     run, which is the only shape Anthropic has ever published
 *     (`claude-3-5-sonnet-20241022`, `claude-sonnet-4-20250514`,
 *     `claude-opus-4-1-20250805`). Ids with no snapshot suffix
 *     (`claude-opus-4-7`, `claude-sonnet-4-6`) keep the full id as
 *     `modelName` with `modelVersion: 'unknown'`; the bundled entries for
 *     those models are keyed on `'unknown'` for that reason. A dashed
 *     `-YYYY-MM-DD` suffix is NOT split for Anthropic: no real id uses it,
 *     and splitting one would register a phantom snapshot that never served
 *     a request.
 *   - bedrock: trailing `-vN:M` version:variant, with the optional date-like
 *     run that precedes it, is split out as `modelVersion`
 *     (`anthropic.claude-3-5-sonnet-20241022-v2:0` →
 *     `('anthropic.claude-3-5-sonnet', '20241022-v2:0')`,
 *     `meta.llama3-1-70b-instruct-v1:0` → `('meta.llama3-1-70b-instruct',
 *     'v1:0')`, `mistral.mistral-large-2402-v1:0` →
 *     `('mistral.mistral-large', '2402-v1:0')`). Ids without the `:M` variant
 *     (`cohere.command-text-v14`, `amazon.titan-text-express-v1`) are kept
 *     whole with `'unknown'`. So are ids with a context-length variant after
 *     the `:M` (`anthropic.claude-3-sonnet-20240229-v1:0:28k`, `:200k` —
 *     Bedrock's provisioned-throughput ids): `:28k` is not a `-vN:M` tail,
 *     the whole id is the `modelName` and the version is `'unknown'`. No
 *     bundled entry is keyed on one; the rule is documented, not extended.
 *   - vertex: trailing `-NNN` numeric segment is split out as `modelVersion`;
 *     otherwise the id is the full `modelName` and version defaults to
 *     `apiMetadata.modelVersion ?? 'unknown'`.
 *   - azure-ai: id is the deployment-name surface; full id is `modelName`.
 *   - nvidia-nim / hf-inference: full `org/model` id is the `modelName`.
 *   - openrouter: the whole served id is the `modelName`, variant suffix
 *     included (`nvidia/nemotron-3-super-120b-a12b:free`), with
 *     `'unknown'` as the version. OpenRouter ids are slugs: no date is split
 *     out, and the dated `canonical_slug` of OpenRouter's model list is not
 *     in the response. OpenRouter is a gateway, so two more rules apply to
 *     this vendor only: `trainedBy` is the author prefix of the served id
 *     (`openRouterAuthor`), the maker as the gateway names it; and a lookup
 *     that misses on an id with a variant suffix retries with the base id
 *     (`openRouterVariantBase`), so a `:free` call enriches from the base
 *     model's entry while keeping its own `modelName`.
 *
 * Every rule is anchored to the whole id and matches ASCII digits only; the
 * Python port (`tzun_sdk.ai_bom.connectors._base.parse_model_id`) uses
 * `re.fullmatch` and `[0-9]` for the same reason. `tests/cross-sdk/
 * test_model_id_parity.py` asserts both parsers agree on every bundled id.
 *
 * After parsing, the importer looks up the entry in the bundled known-models
 * reference. On a match, non-null enrichment fields overlay the always-present
 * MVD shape — but the parsed identity triple `(vendor, modelName, modelVersion)`
 * is always authoritative. On a miss, the descriptor is returned as a
 * vendor-asserted MVD with explicit nulls for every non-required field.
 *
 * Note on the `source` string for NIM: the existing `ModelDescriptorSource`
 * type already encodes `'nim-known-models'` (not `'nvidia-nim-known-models'`),
 * so we map the `nvidia-nim` vendor to that source literal.
 *
 * The two OpenRouter helpers use string operations only, no regular
 * expressions, so the Python port (`openrouter_author`,
 * `openrouter_variant_base`) yields the same strings for every input.
 */

import { ModelDescriptor, ModelDescriptorSource } from '@tzun/engine';
import {
  KnownModelsReference,
  lookupKnownModel,
} from './known-models';

export type SupportedVendor =
  | 'openai'
  | 'anthropic'
  | 'bedrock'
  | 'vertex'
  | 'azure-ai'
  | 'nvidia-nim'
  | 'hf-inference'
  | 'openrouter';

export interface VendorImportInput {
  vendor: SupportedVendor;
  /** Vendor-specific id form. See module docstring for per-vendor parsing rules. */
  modelId: string;
  knownModels: KnownModelsReference;
  /** Optional thin API metadata — used as a fallback for `modelVersion` when the id doesn't encode one. */
  apiMetadata?: { modelName?: string; modelVersion?: string };
}

export interface VendorImportResult {
  descriptor: ModelDescriptor;
  source: ModelDescriptorSource;
  /** False → no known-models match; descriptor is a vendor-asserted MVD. */
  enriched: boolean;
}

interface ParsedId {
  modelName: string;
  modelVersion: string;
}

/**
 * Maps the public `SupportedVendor` literal to the `ModelDescriptorSource`
 * literal typed in `packages/engine/src/types/ai-bom.ts`. The only
 * non-identity mapping is `nvidia-nim -> nim-known-models`.
 */
function sourceFor(vendor: SupportedVendor): ModelDescriptorSource {
  if (vendor === 'nvidia-nim') return 'nim-known-models';
  return `${vendor}-known-models` as ModelDescriptorSource;
}

// Trailing `-YYYY-MM-DD` snapshot date — OpenAI (`gpt-4o-2024-08-06`).
const OPENAI_DATE_SUFFIX_RE = /^(.*)-([0-9]{4}-[0-9]{2}-[0-9]{2})$/;
// Trailing `-YYYYMMDD` snapshot date — Anthropic (`claude-3-5-sonnet-20241022`).
// Anthropic never dashes the date; the dashed OpenAI form is deliberately NOT
// accepted here (see the module docstring).
const ANTHROPIC_SNAPSHOT_SUFFIX_RE = /^(.*)-([0-9]{8})$/;
// Trailing numeric segment (1+ digits) — Vertex (`gemini-1.5-pro-002`).
const VERTEX_NUMERIC_SUFFIX_RE = /^(.*)-([0-9]+)$/;
// Trailing `-vN:M` version:variant, optionally preceded by a 4–8 digit
// date-like run — Bedrock (`anthropic.claude-3-5-sonnet-20241022-v2:0`,
// `mistral.mistral-large-2402-v1:0`, `meta.llama3-1-70b-instruct-v1:0`). The
// head is lazy so the optional date run lands in the version, not the name.
// A context-length variant after the `:M` (`...-v1:0:28k`) does not match:
// such an id is kept whole with 'unknown' (see the module docstring).
const BEDROCK_VERSION_SUFFIX_RE = /^(.+?)-((?:[0-9]{4,8}-)?v[0-9]+:[0-9]+)$/;

/**
 * Parses a vendor-specific model id into `{modelName, modelVersion}` per
 * the conventions documented at the top of this module.
 *
 * Exported for direct testability — the importer composes it internally.
 */
export function parseModelId(
  vendor: SupportedVendor,
  modelId: string,
  apiMetadata?: { modelName?: string; modelVersion?: string },
): ParsedId {
  // The hint is a fallback for ids that encode no version. It must be a
  // string to become part of the identity triple: connectors build
  // `apiMetadata` from JSON, and `??` alone would let a number through.
  const hint =
    typeof apiMetadata?.modelVersion === 'string' ? apiMetadata.modelVersion : undefined;
  switch (vendor) {
    case 'openai': {
      const m = OPENAI_DATE_SUFFIX_RE.exec(modelId);
      if (m) {
        return { modelName: m[1], modelVersion: m[2] };
      }
      return {
        modelName: modelId,
        modelVersion: hint ?? 'unknown',
      };
    }
    case 'anthropic': {
      // Anthropic ids have their own snapshot-suffix rule: OpenAI's
      // dashed-date rule matches no Anthropic id, and under it every
      // Anthropic capture would record `modelVersion: 'unknown'` with the
      // full id as `modelName`, leaving the bundled Anthropic entries
      // unreachable.
      const m = ANTHROPIC_SNAPSHOT_SUFFIX_RE.exec(modelId);
      if (m) {
        return { modelName: m[1], modelVersion: m[2] };
      }
      return {
        modelName: modelId,
        modelVersion: hint ?? 'unknown',
      };
    }
    case 'bedrock': {
      const m = BEDROCK_VERSION_SUFFIX_RE.exec(modelId);
      if (m) {
        return { modelName: m[1], modelVersion: m[2] };
      }
      return {
        modelName: modelId,
        modelVersion: hint ?? 'unknown',
      };
    }
    case 'vertex': {
      const m = VERTEX_NUMERIC_SUFFIX_RE.exec(modelId);
      if (m) {
        return { modelName: m[1], modelVersion: m[2] };
      }
      return {
        modelName: modelId,
        modelVersion: hint ?? 'unknown',
      };
    }
    case 'hf-inference': {
      return {
        modelName: modelId,
        modelVersion: hint ?? 'main',
      };
    }
    case 'azure-ai':
    case 'nvidia-nim':
    case 'openrouter': {
      return {
        modelName: modelId,
        modelVersion: hint ?? 'unknown',
      };
    }
  }
}

/**
 * OpenRouter's author prefix of a served id: the maker as the gateway names it
 * (`openai`, `meta-llama`, `x-ai`, ...), verbatim.
 *
 * One leading `~` is dropped: `~anthropic/claude-opus-latest` is an alias in
 * the maker's own namespace. An id with no `author/` prefix gives `null`, and
 * so does `openrouter/*`: those ids name OpenRouter's routers
 * (`openrouter/auto`), not a model maker.
 */
export function openRouterAuthor(modelId: string): string | null {
  const id = modelId.startsWith('~') ? modelId.slice(1) : modelId;
  const slash = id.indexOf('/');
  if (slash <= 0) return null;
  const author = id.slice(0, slash);
  return author === 'openrouter' ? null : author;
}

/**
 * The base id of an OpenRouter id with a variant suffix
 * (`author/slug:variant` -> `author/slug`), or `null` when the id carries no
 * variant: no `/`, no `:` after the `/`, or nothing after the last `:`.
 */
export function openRouterVariantBase(modelId: string): string | null {
  const slash = modelId.indexOf('/');
  const colon = modelId.lastIndexOf(':');
  if (slash < 0 || colon <= slash || colon === modelId.length - 1) return null;
  return modelId.slice(0, colon);
}

/**
 * Build a fixed-shape MVD with explicit nulls for every not-yet-known field.
 */
function mvdFor(
  vendor: SupportedVendor,
  modelName: string,
  modelVersion: string,
): ModelDescriptor {
  return {
    descriptorVersion: 'd1',
    vendor,
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

/**
 * Overlays non-null enrichment fields on top of an MVD. The identity triple
 * `(vendor, modelName, modelVersion)` — plus `descriptorVersion` — always
 * comes from the parsed id and is never overwritten from enrichment, even if
 * the reference entry contained different values.
 *
 * `training` is merged field-by-field so a partial enrichment doesn't clobber
 * the always-present nested shape; nested arrays from enrichment replace the
 * empty defaults when explicitly present.
 */
function mergeMvdWithEnrichment(
  mvd: ModelDescriptor,
  enrichment: Partial<ModelDescriptor> | null,
): ModelDescriptor {
  if (!enrichment) return mvd;

  const out: ModelDescriptor = { ...mvd };

  // Scalar / nullable-scalar fields. `vendor`, `modelName`, `modelVersion`,
  // and `descriptorVersion` are deliberately excluded — those are
  // authoritative from the parsed id.
  if (enrichment.modelType !== undefined && enrichment.modelType !== null) {
    out.modelType = enrichment.modelType;
  }
  // `integrityTier`, `modelDigest`, `parentModelDescriptorDigest` and
  // `derivation` are deliberately NOT copied from enrichment. Enrichment is
  // descriptive metadata from a reference table (bundled, runtime-fetched, or
  // an `AttachOptions.knownModels` override) — it is not an attestation. A
  // reference entry saying `integrityTier: 'weight-attested'` would otherwise
  // mint exactly that tier on every capture of that model, with `modelDigest: null`
  // and a fabricated parent, straight past the tier↔digest invariant that
  // `register.ts` enforces. A vendor-asserted capture stays vendor-asserted;
  // weight attestation comes only from hashing real weights.
  if (enrichment.trainedBy !== undefined && enrichment.trainedBy !== null) {
    out.trainedBy = enrichment.trainedBy;
  }
  if (enrichment.license !== undefined && enrichment.license !== null) {
    out.license = enrichment.license;
  }
  if (
    enrichment.modelCardUrl !== undefined &&
    enrichment.modelCardUrl !== null
  ) {
    out.modelCardUrl = enrichment.modelCardUrl;
  }

  // Training subtree — merge field-by-field so enrichment doesn't have to
  // restate the full shape. Arrays are replaced as a unit when present.
  if (enrichment.training !== undefined && enrichment.training !== null) {
    const enrTraining = enrichment.training;
    out.training = {
      trainingDataDigest:
        enrTraining.trainingDataDigest ?? out.training.trainingDataDigest,
      trainingDataRef:
        enrTraining.trainingDataRef ?? out.training.trainingDataRef,
      lastTrainingDate:
        enrTraining.lastTrainingDate ?? out.training.lastTrainingDate,
      evaluations: Array.isArray(enrTraining.evaluations)
        ? enrTraining.evaluations
        : out.training.evaluations,
    };
  }

  if (Array.isArray(enrichment.regulatoryMarkings)) {
    out.regulatoryMarkings = enrichment.regulatoryMarkings;
  }
  if (Array.isArray(enrichment.externalIdentifiers)) {
    out.externalIdentifiers = enrichment.externalIdentifiers;
  }

  return out;
}

/**
 * Per-vendor importer. Combines thin API metadata + the known-models
 * reference into a fixed-shape `ModelDescriptor`. Never throws on
 * missing-reference cases — always falls back to an MVD.
 */
export function importFromVendor(
  input: VendorImportInput,
): VendorImportResult {
  const { vendor, modelId, knownModels, apiMetadata } = input;
  const { modelName, modelVersion } = parseModelId(
    vendor,
    modelId,
    apiMetadata,
  );

  let enrichment = lookupKnownModel(
    knownModels,
    vendor,
    modelName,
    modelVersion,
  );

  const mvd = mvdFor(vendor, modelName, modelVersion);
  if (vendor === 'openrouter') {
    // The maker is the author prefix of the served id, as the gateway states
    // it. The bundled OpenRouter entries carry no `trainedBy`, so enrichment
    // never replaces this with a display name for some models and not others.
    mvd.trainedBy = openRouterAuthor(modelName);
    // A variant (`:free`, `:batch`, ...) is the base model offered with its
    // own limits or pricing: enrich from the base entry when the variant has
    // none of its own. The descriptor keeps the variant in `modelName`.
    if (enrichment === null) {
      const base = openRouterVariantBase(modelName);
      if (base !== null) {
        enrichment = lookupKnownModel(knownModels, vendor, base, modelVersion);
      }
    }
  }
  const descriptor = mergeMvdWithEnrichment(mvd, enrichment);

  return {
    descriptor,
    source: sourceFor(vendor),
    enriched: enrichment !== null,
  };
}

// ── CLI-registration enrichment ─────────────────────────

/** Result of `enrichPartialFromKnownModels`. */
export interface PartialEnrichmentResult {
  /** The input with absent descriptive fields filled from the matched entry. */
  descriptor: Partial<ModelDescriptor>;
  /**
   * The reference entry the identity triple matched, or `null` when the
   * triple was incomplete or hit nothing. A non-null entry with an empty
   * `filled` means every descriptive field was already supplied.
   */
  entry: Partial<ModelDescriptor> | null;
  /** Fields that were absent on the input and filled from the entry. */
  filled: string[];
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}

/**
 * Fills the descriptive fields an operator did NOT supply on a partial
 * descriptor from the known-models reference — the enrichment step
 * `tzun models register` performs before `registerModel`.
 *
 * Precedence is the opposite of `mergeMvdWithEnrichment`, deliberately: there
 * the base is a bare connector MVD and the reference is the only source of
 * descriptive fields, so the reference overlays; here the base is what a human
 * typed at a prompt, put in `--from-file`, or passed as a flag, and the CLI's
 * standing rule is that supplied values win (`applyFlagOverrides`). Only
 * `null`/absent scalars, `null` training fields, and empty arrays are filled.
 *
 * The identity triple and `descriptorVersion` are never touched, and — as in
 * `mergeMvdWithEnrichment` — `integrityTier`, `modelDigest`,
 * `parentModelDescriptorDigest` and `derivation` are never copied from a
 * reference entry. A reference is descriptive metadata, not an attestation;
 * `registerModel` derives the tier from the digest it computes or does not.
 */
export function enrichPartialFromKnownModels(
  input: Partial<ModelDescriptor>,
  reference: KnownModelsReference,
): PartialEnrichmentResult {
  if (
    !isNonEmptyString(input.vendor) ||
    !isNonEmptyString(input.modelName) ||
    !isNonEmptyString(input.modelVersion)
  ) {
    return { descriptor: input, entry: null, filled: [] };
  }

  const entry = lookupKnownModel(
    reference,
    input.vendor,
    input.modelName,
    input.modelVersion,
  );
  if (!entry) {
    return { descriptor: input, entry: null, filled: [] };
  }

  const out: Partial<ModelDescriptor> = { ...input };
  const filled: string[] = [];

  const scalars = ['modelType', 'trainedBy', 'license', 'modelCardUrl'] as const;
  for (const key of scalars) {
    if (out[key] == null && entry[key] != null) {
      out[key] = entry[key];
      filled.push(key);
    }
  }

  const entryTraining = entry.training;
  if (entryTraining !== undefined && entryTraining !== null) {
    const base = out.training;
    const training: ModelDescriptor['training'] = {
      trainingDataDigest: base?.trainingDataDigest ?? null,
      trainingDataRef: base?.trainingDataRef ?? null,
      lastTrainingDate: base?.lastTrainingDate ?? null,
      evaluations: Array.isArray(base?.evaluations) ? base.evaluations : [],
    };
    let touched = false;
    const trainingScalars = ['trainingDataDigest', 'trainingDataRef', 'lastTrainingDate'] as const;
    for (const key of trainingScalars) {
      if (training[key] === null && entryTraining[key] != null) {
        training[key] = entryTraining[key];
        filled.push(`training.${key}`);
        touched = true;
      }
    }
    if (
      training.evaluations.length === 0 &&
      Array.isArray(entryTraining.evaluations) &&
      entryTraining.evaluations.length > 0
    ) {
      training.evaluations = entryTraining.evaluations;
      filled.push('training.evaluations');
      touched = true;
    }
    if (touched) out.training = training;
  }

  const arrays = ['regulatoryMarkings', 'externalIdentifiers'] as const;
  for (const key of arrays) {
    const current = out[key];
    const fromEntry = entry[key];
    if (
      (!Array.isArray(current) || current.length === 0) &&
      Array.isArray(fromEntry) &&
      fromEntry.length > 0
    ) {
      // The two arrays have different element types; assign through the
      // widened partial so TypeScript keeps the per-key type.
      (out as Record<string, unknown>)[key] = fromEntry;
      filled.push(key);
    }
  }

  return { descriptor: out, entry, filled };
}
