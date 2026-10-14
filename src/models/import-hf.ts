/**
 * Hugging Face model card importer.
 *
 * The importer takes injected `fetcher` and `cardFetcher` callables so the
 * suite runs offline against canned model-card fixtures. The default
 * implementations hit `https://huggingface.co/api/models/{id}` (HF's public
 * model-metadata endpoint) and the README raw URL for richer card data.
 *
 * Missing fields resolve to explicit `null`; the importer never silently
 * invents data. On fetcher error the importer throws — the caller decides
 * whether to fall back to MVD.
 */
import { ModelDescriptor, Evaluation, ExternalIdentifier } from '@tzun/engine';
import { computeModelDigest } from './compute-model-digest';

// ── Raw HF API shape ───────────────────────────────────────────────
// We only type the fields we map; the rest pass through as `unknown`.

/** One `model-index[].results[]` entry, as the live HF API emits it. */
export interface HfModelIndexResult {
  task?: { name?: string; type?: string };
  dataset?: { name?: string; type?: string; config?: string; split?: string };
  metrics?: Array<{ name?: string; type?: string; value?: number }>;
}

/** One `model-index[]` entry. */
export interface HfModelIndexEntry {
  name?: string;
  results?: HfModelIndexResult[];
}

export interface HfApiResponse {
  modelId?: string;
  id?: string;
  sha?: string;
  license?: string;
  pipeline_tag?: string;
  cardData?: {
    license?: string;
    base_model?: string | string[];
    datasets?: string[] | string;
    pipeline_tag?: string;
    eval_results?: Array<{
      task: { name?: string; type?: string };
      metrics?: Array<{ name?: string; type?: string; value?: number }>;
    }>;
    doi?: string;
    /** Some cards also carry the model-index inside cardData. */
    'model-index'?: HfModelIndexEntry[] | null;
    [k: string]: unknown;
  };
  /**
   * The live API emits evaluation data here, at the TOP LEVEL — not as
   * `cardData.eval_results`, which is a client-side synthesis by the Python
   * `huggingface_hub` library and never appears on the wire.
   */
  'model-index'?: HfModelIndexEntry[] | null;
  [k: string]: unknown;
}

export interface HfImportOptions {
  /** Injected metadata fetcher; defaults to the public HF API endpoint. */
  fetcher?: (modelId: string) => Promise<HfApiResponse>;
  /** Optional richer-card fetcher (README YAML frontmatter). Merged on top of `fetcher` output. */
  cardFetcher?: (modelId: string, revision?: string) => Promise<HfApiResponse>;
  /** When set, computes `modelDigest` via tzun-model-manifest-v1 and upgrades to weight-attested. */
  weightsPath?: string;
  /** Optional pinned revision (sha or branch); used as fallback for `modelVersion`. */
  revision?: string;
  /** Deadline for the default fetcher's HTTP call. Ignored when `fetcher` is injected. */
  fetchTimeoutMs?: number;
}

// pipeline_tag → modelType mapping.
// Keeping this inline (not a separate module) so the importer is self-contained.
const LLM_TAGS = new Set([
  'text-generation',
  'text2text-generation',
  'conversational',
  'question-answering',
]);
const VISION_TAGS = new Set([
  'image-classification',
  'image-segmentation',
  'object-detection',
  'image-to-text',
]);
const EMBEDDING_TAGS = new Set(['sentence-similarity', 'feature-extraction']);

function mapPipelineTag(tag: string | undefined): string | null {
  if (!tag) return null;
  if (LLM_TAGS.has(tag)) return 'llm';
  if (VISION_TAGS.has(tag)) return 'vision';
  if (EMBEDDING_TAGS.has(tag)) return 'embedding';
  return null;
}

/** Default deadline for the built-in fetcher. Bare `fetch` has none at all. */
export const DEFAULT_HF_FETCH_TIMEOUT_MS = 10_000;
/** Hard ceiling on the metadata body we will buffer. */
export const MAX_HF_RESPONSE_BYTES = 5 * 1024 * 1024;

/**
 * Builds the HF metadata URL, percent-encoding each path segment.
 *
 * A repo id is `<org>/<name>`; the separating slashes are structural and stay
 * literal, but everything else is caller-supplied and is encoded. The host is
 * a fixed literal, so an id containing `../` or a `?` can only reshape the
 * path on huggingface.co -- it can never redirect the request elsewhere.
 */
export function buildHfApiUrl(modelId: string): string {
  const encoded = modelId
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
  return `https://huggingface.co/api/models/${encoded}`;
}

async function readBodyCapped(res: Response, cap: number): Promise<string> {
  const declared = res.headers?.get?.('content-length');
  if (declared !== null && declared !== undefined && declared !== '') {
    const n = Number(declared);
    if (Number.isFinite(n) && n > cap) {
      throw new Error(
        `HF API response too large: content-length ${n} exceeds ${cap} bytes`,
      );
    }
  }
  const body = (res as { body?: ReadableStream<Uint8Array> | null }).body;
  if (!body || typeof body.getReader !== 'function') {
    // Fetch mocks and older runtimes may not expose a stream; fall back to
    // buffering, then enforce the same ceiling after the fact.
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > cap) {
      throw new Error(`HF API response too large: exceeds ${cap} bytes`);
    }
    return text;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel();
      throw new Error(`HF API response too large: exceeds ${cap} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

export async function defaultFetcher(
  modelId: string,
  timeoutMs: number = DEFAULT_HF_FETCH_TIMEOUT_MS,
): Promise<HfApiResponse> {
  const url = buildHfApiUrl(modelId);
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    throw new Error(`HF API GET ${url} failed: HTTP ${res.status}`);
  }
  return JSON.parse(
    await readBodyCapped(res, MAX_HF_RESPONSE_BYTES),
  ) as HfApiResponse;
}

/**
 * Imports a Hugging Face model card into a fixed-shape `ModelDescriptor`.
 *
 * Naming decision: `modelName` is set to the full repo id (e.g.
 * `meta-llama/Llama-3.1-70B-Instruct`) — unambiguous and matches what users
 * actually type. The org part is captured separately in `trainedBy`.
 *
 * `derivation` heuristic: presence of `cardData.base_model` implies
 * `'fine-tune'`; absence implies `'base'`. The HF API doesn't distinguish
 * fine-tunes from quantizations/merges/distillations at the metadata layer,
 * so anything more specific would require an annotation to resolve the
 * parent descriptor digest.
 */
export async function importFromHuggingFace(
  modelId: string,
  options: HfImportOptions = {},
): Promise<ModelDescriptor> {
  const fetcher =
    options.fetcher ??
    ((id: string) =>
      defaultFetcher(
        id,
        options.fetchTimeoutMs ?? DEFAULT_HF_FETCH_TIMEOUT_MS,
      ));

  let base: HfApiResponse;
  try {
    base = await fetcher(modelId);
  } catch (err) {
    throw new Error(
      `Hugging Face importer: fetch failed for '${modelId}': ${(err as Error).message}`,
    );
  }

  // Optional richer card data merged on top of `base.cardData`.
  if (options.cardFetcher) {
    try {
      const card = await options.cardFetcher(modelId, options.revision);
      base = {
        ...base,
        ...card,
        cardData: { ...(base.cardData ?? {}), ...(card.cardData ?? {}) },
      };
    } catch (err) {
      throw new Error(
        `Hugging Face importer: card fetch failed for '${modelId}': ${(err as Error).message}`,
      );
    }
  }

  // Canonical repo id. The API 307-redirects case and rename variants and
  // answers with the canonical `id`, so keying the descriptor on the caller's
  // spelling made `Org/Model` and `org/model` two content-addressed
  // descriptors for one model. Prefer what the API says it is.
  const canonicalId =
    (typeof base.id === 'string' && base.id.length > 0 && base.id) ||
    (typeof base.modelId === 'string' &&
      base.modelId.length > 0 &&
      base.modelId) ||
    modelId;

  const card = base.cardData ?? {};
  const sha = base.sha ?? null;

  const modelVersion =
    (typeof sha === 'string' && sha.length > 0 && sha) ||
    options.revision ||
    'main';

  const license = (card.license ?? base.license ?? null) as string | null;
  const pipelineTag =
    (card.pipeline_tag as string | undefined) ?? base.pipeline_tag;
  const modelType = mapPipelineTag(pipelineTag);

  // Org / trainedBy split. Repo ids are `<org>/<name>`; unscoped ids are rare
  // (only legacy HF accounts) — when there's no '/', leave trainedBy null.
  const slashIdx = canonicalId.indexOf('/');
  const trainedBy = slashIdx >= 0 ? canonicalId.slice(0, slashIdx) : null;

  const modelCardUrl = `https://huggingface.co/${canonicalId}`;

  // training.trainingDataRef ← cardData.datasets.
  // datasets can be string[] or single string; flatten to a comma-joined ref.
  const trainingDataRef = (() => {
    const d = card.datasets;
    if (Array.isArray(d) && d.length > 0) return d.join(',');
    if (typeof d === 'string' && d.length > 0) return d;
    return null;
  })();

  // Evaluations. The live API puts these in a TOP-LEVEL `model-index` array
  // (sometimes mirrored under `cardData['model-index']`); `eval_results` is
  // what the Python `huggingface_hub` client synthesises locally and never
  // arrives over the wire. Reading only `eval_results` meant
  // `training.evaluations` was `[]` for every real model. All three sources
  // are read now, so both shapes import.
  const evaluations = buildEvaluations(
    card.eval_results,
    base['model-index'],
    card['model-index'],
  );

  // External identifiers: hf-repo always, hf-revision when sha is known,
  // doi when the card carries one.
  const externalIdentifiers: ExternalIdentifier[] = [
    {
      scheme: 'hf-repo',
      value: canonicalId,
      issuedBy: 'huggingface',
      issuedAt: null,
      url: modelCardUrl,
    },
  ];
  if (sha) {
    externalIdentifiers.push({
      scheme: 'hf-revision',
      value: sha,
      issuedBy: 'huggingface',
      issuedAt: null,
      url: `${modelCardUrl}/commit/${sha}`,
    });
  }
  if (typeof card.doi === 'string' && card.doi.length > 0) {
    externalIdentifiers.push({
      scheme: 'doi',
      value: card.doi,
      issuedBy: 'DataCite',
      issuedAt: null,
      url: `https://doi.org/${card.doi}`,
    });
  }

  // derivation: base_model present → 'fine-tune'; absent → 'base'.
  const baseModel = card.base_model;
  const derivation: ModelDescriptor['derivation'] =
    baseModel !== undefined && baseModel !== null
      ? 'fine-tune'
      : 'base';

  // Weight attestation.
  let modelDigest: string | null = null;
  let integrityTier: ModelDescriptor['integrityTier'] = 'vendor-asserted';
  if (options.weightsPath) {
    const result = await computeModelDigest(options.weightsPath);
    modelDigest = result.modelDigest;
    integrityTier = 'weight-attested';
  }

  const descriptor: ModelDescriptor = {
    descriptorVersion: 'd1',
    vendor: 'huggingface',
    modelName: canonicalId,
    modelVersion,
    modelType,
    integrityTier,
    modelDigest,
    parentModelDescriptorDigest: null, // backfilled by annotation, not auto-resolved here
    derivation,
    trainedBy,
    license,
    modelCardUrl,
    training: {
      trainingDataDigest: null,
      trainingDataRef,
      lastTrainingDate: null,
      evaluations,
    },
    regulatoryMarkings: [], // HF doesn't expose regulatory markings
    externalIdentifiers,
  };

  return descriptor;
}

type HfEvalResult = NonNullable<NonNullable<HfApiResponse['cardData']>['eval_results']>[number];

/**
 * Aggregates evaluations from every shape HF uses.
 *
 * `eval_results` (huggingface_hub's client-side synthesis) and
 * `model-index[].results[]` (what the HTTP API actually returns) carry the
 * same `{ task, metrics }` records, so they normalise to one list.
 */
function buildEvaluations(
  evalResults: HfEvalResult[] | undefined,
  ...modelIndexes: Array<HfModelIndexEntry[] | null | undefined>
): Evaluation[] {
  const results: HfModelIndexResult[] = [];
  if (Array.isArray(evalResults)) results.push(...evalResults);
  for (const index of modelIndexes) {
    if (!Array.isArray(index)) continue;
    for (const entry of index) {
      if (entry && Array.isArray(entry.results)) results.push(...entry.results);
    }
  }
  // Overlap between the sources is expected -- cardData['model-index'] usually
  // restates the top-level one. Aggregation below is an assignment into a
  // per-task map, so restating a metric is idempotent rather than additive.
  if (results.length === 0) return [];

  // Aggregate per task name (preferring task.name, falling back to task.type).
  const byName = new Map<string, Evaluation>();
  for (const r of results) {
    const name =
      (r.task && (r.task.name || r.task.type)) || 'unknown';
    let entry = byName.get(name);
    if (!entry) {
      entry = {
        name,
        testSetDigest: null,
        evaluatedAt: null,
        metrics: {},
      };
      byName.set(name, entry);
    }
    if (Array.isArray(r.metrics)) {
      for (const m of r.metrics) {
        const key = m.name || m.type;
        if (typeof key === 'string' && typeof m.value === 'number') {
          entry.metrics[key] = m.value;
        }
      }
    }
  }
  return Array.from(byName.values());
}
