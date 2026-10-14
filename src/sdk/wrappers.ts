/**
 * SDK wrapper layer — `hook()` core + `attach()` per-call opt-in surface.
 *
 * The wrapper layer's hot-path is `hookCore`: given a vendor connector and
 * a per-Tzun LRU cache, it runs the connector against `(params, response)`
 * to produce an `AiBomSkeleton`, registers the descriptor (cache-short-
 * circuited), and returns a wire `AiBom`. `Tzun#hook` is the public
 * entry point that dispatches by vendor label.
 *
 * `attachClient` (exposed as `Tzun#attach`) is the optional sugar: it
 * duck-types an incoming client against the seven supported vendor
 * shapes and returns a wrapped object whose intercepted methods strip a
 * `tzun_capture` kwarg and, when present, call `hook()` + `tzun.capture()`
 * after forwarding to the underlying client.
 */

import { Tzun } from './index';
import type { AiBom, AiBomWithInlineDescriptor, DeciderInput, LinkInput, StepActorInput } from '@tzun/engine';
import type { CaptureInput } from '@tzun/engine';
import { singleModel } from '@tzun/engine';
import type { CaptureResult, EvidenceEnvelope } from '@tzun/engine';
import { LruCache } from '../models/lru-cache';
import { loadKnownModels, KnownModelsReference } from '../models/known-models';
import { getConnector } from './connectors/index';
import type { Connector, AiBomSkeleton } from './connectors/base';
import { sdkLog } from './log';
import { isModelCatalogUnsupported } from './http-transport';

// ── Supported vendor enumeration ─────────────────────────────────────

/**
 * The seven vendor labels supported by `tzun.hook()` and `tzun.attach()`.
 * Mirrors the registry keys in `src/sdk/connectors/index.ts`.
 */
export const SUPPORTED_VENDORS = [
  'openai',
  'anthropic',
  'bedrock',
  'vertex',
  'azure-ai',
  'nvidia-nim',
  'hf-inference',
] as const;

export type SupportedVendor = (typeof SUPPORTED_VENDORS)[number];

/**
 * Build the standard error thrown when `hook()` or `attach()` receives an
 * unknown vendor label. The message names every supported vendor so the
 * caller can correct the typo without consulting docs.
 */
export function unknownVendorError(vendor: string): Error {
  return new Error(
    `Unknown vendor "${vendor}"; supported vendors: ${SUPPORTED_VENDORS.join(', ')}.`,
  );
}

/**
 * Decision input — the value the caller injects into a wrapped vendor SDK
 * call (via the `tzun_capture` kwarg, or on the command object for the
 * Bedrock shape). The wrapper layer reads this, strips it from the call
 * payload, forwards the rest to the underlying client, then calls
 * `tzun.capture(...)` with the resulting response, the decision, and the
 * model as a contributions list of one (`singleModel`, Record §7.3):
 * one `propose` step whose bill of materials is the (auto-built or
 * caller-supplied) `aiBom` and whose actor is `actor`, or `null` for a model
 * called directly.
 *
 * The optional `aiBom` field lets the caller override the wrapper-built
 * AI-BOM — useful when the call is part of a streaming or multi-call
 * sequence and the caller wants to attach a pre-assembled AI-BOM
 * representing the whole sequence rather than just this call. `null` records
 * no model (`contributions: null`).
 */
export interface DecisionInput {
  /** The decision taken. */
  action: string;
  /** The stated reason. */
  reason: string;
  /** Who decided. */
  decider: DeciderInput;
  aiBom?: AiBom | AiBomWithInlineDescriptor | null;
  /** The agent that called the model, as the model step's actor; omitted for a model called directly. */
  actor?: StepActorInput | null;
  /** The records this decision relates to. */
  links?: LinkInput[] | null;
}

/** The 0.7 names a decision input may still carry: passed on, so `capture()` refuses them (`renamed_field`). */
const RENAMED_DECISION_FIELDS = ['humanAction', 'humanReason', 'reviewer'] as const;

/** Options for `Tzun#attach`. */
export interface AttachOptions {
  /**
   * Explicit vendor override — bypasses duck-type detection. Required to
   * disambiguate NIM from OpenAI (both expose `chat.completions.create`),
   * and useful as an escape hatch when a custom client happens to match
   * multiple shapes.
   */
  vendor?: SupportedVendor;
  /** Default `aiSystemId` to inject into `CaptureInput` when capture fires. */
  aiSystemId?: string;
  /**
   * Capture kill-switch. Default `true`. When `false`, intercepted calls become
   * pure pass-through — `tzun_capture` is still stripped from forwarded params,
   * but **no evidence is captured at all**, not merely no AI-BOM.
   *
   * The name predates the capture path and reads narrower than it is. If you
   * are here because you saw `descriptor_not_registered` and wanted to skip the
   * catalog round-trip, this is not that switch: it drops the whole record. A
   * call that carries `tzun_capture` while this is `false` emits
   * `capture_skipped { vendor, reason: 'emitAiBom:false' }` on the log sink so
   * a kill-switch left on after an incident is visible in your telemetry rather
   * than silently discarding a month of decisions.
   */
  emitAiBom?: boolean;
  /** Override the cache capacity for the per-Tzun hook LRU. Default 256. */
  cacheCapacity?: number;
  /**
   * Override the known-models reference. By default the wrapper loads the
   * bundled reference via `loadKnownModels()` at first call.
   */
  knownModels?: KnownModelsReference;
}


/**
 * Build the hot-path AI-BOM core: given a connector + per-Tzun LRU cache,
 * runs the connector against `(params, response)` and resolves to a wire
 * `AiBom` (or `null` if the connector returned no skeleton).
 *
 * This is the shared kernel behind `Tzun#hook`, and through it `attach()` and
 * the `wrap<Vendor>` helpers. The cache short-circuits the catalog round trip
 * for repeat calls with the same vendor/model.
 */
/** Internal result returned by `hookCoreInternal` — carries telemetry metadata. */
interface HookCoreResult {
  aiBom: AiBom | AiBomWithInlineDescriptor | null;
  /** True iff the descriptor digest was already in the LRU cache. */
  cached: boolean;
  /** Digest of the registered descriptor, or null when no descriptor was registered. */
  digest: string | null;
  /** Model name extracted by the connector, or null when skeleton is null. */
  modelName: string | null;
  /**
   * The connector named a model and the store cannot register its
   * descriptor (an adapter without `registerModelDescriptor`, or the cloud
   * transport against a platform that does not serve `POST /v1/models`), so
   * the model is not recorded.
   */
  notRecordable?: boolean;
}

/** Internal version that also returns telemetry metadata. */
async function hookCoreInternal(
  connector: Connector,
  tzun: Tzun,
  cache: LruCache<string, string>,
  knownModels: KnownModelsReference,
  params: Record<string, unknown>,
  response: Record<string, unknown>,
): Promise<HookCoreResult> {
  const skeleton: AiBomSkeleton | null = connector.buildAiBom(
    params,
    response,
    knownModels,
  );
  if (!skeleton) {
    return { aiBom: null, cached: false, digest: null, modelName: null };
  }

  const modelName = skeleton.modelDescriptor.modelName;
  const cacheKey =
    `${connector.vendor}:${modelName}:` +
    `${skeleton.modelDescriptor.modelVersion}:${knownModels.version}`;

  const existingDigest = cache.get(cacheKey);
  if (existingDigest) {
    return {
      aiBom: {
        modelDescriptorDigest: existingDigest,
        vendorFingerprint: skeleton.vendorFingerprint,
        promptTemplate: skeleton.promptTemplate,
        inferenceParameters: skeleton.inferenceParameters,
        infrastructure: skeleton.infrastructure,
      },
      cached: true,
      digest: existingDigest,
      modelName,
    };
  }

  const storage = tzun.getStorage();
  // A 0.8.0 record names a model only by a catalogued descriptor digest in a
  // contribution step, and `capture()` refuses an inline descriptor a store
  // cannot register. So on a store with no model catalog to register the
  // descriptor in (an adapter without `registerModelDescriptor`, or the cloud
  // transport against a platform that does not serve `POST /v1/models`) no
  // AI-BOM is built: the decision is captured without its model, and
  // `hook()` logs `capture_model_not_recordable`.
  const notRecordable: HookCoreResult = { aiBom: null, cached: false, digest: null, modelName, notRecordable: true };
  if (!storage.registerModelDescriptor) return notRecordable;
  let reg: { digest: string };
  try {
    reg = await storage.registerModelDescriptor(
      skeleton.modelDescriptor,
      'connector-auto',
      `wrapper:${connector.vendor}`,
    );
  } catch (error) {
    if (isModelCatalogUnsupported(error)) return notRecordable;
    throw error;
  }
  const digest = reg.digest;
  cache.set(cacheKey, digest);

  return {
    aiBom: {
      modelDescriptorDigest: digest,
      vendorFingerprint: skeleton.vendorFingerprint,
      promptTemplate: skeleton.promptTemplate,
      inferenceParameters: skeleton.inferenceParameters,
      infrastructure: skeleton.infrastructure,
    },
    cached: false,
    digest,
    modelName,
  };
}

/**
 * Public `hookCore` — stable exported signature for tests that call it
 * directly. Delegates to `hookCoreInternal`.
 */
export async function hookCore(
  connector: Connector,
  tzun: Tzun,
  cache: LruCache<string, string>,
  knownModels: KnownModelsReference,
  params: Record<string, unknown>,
  response: Record<string, unknown>,
): Promise<AiBom | AiBomWithInlineDescriptor | null> {
  const result = await hookCoreInternal(connector, tzun, cache, knownModels, params, response);
  return result.aiBom;
}

/**
 * Module-level known-models loader cache. The known-models reference is
 * deterministic and bundled by default, so a single Promise shared across
 * wrapper instances is safe — no cross-instance state leaks.
 */
let cachedKnownModels: Promise<KnownModelsReference> | null = null;

export function getKnownModels(
  override?: KnownModelsReference,
): Promise<KnownModelsReference> {
  if (override) return Promise.resolve(override);
  if (!cachedKnownModels) {
    cachedKnownModels = loadKnownModels();
  }
  return cachedKnownModels;
}

/**
 * Test-only escape hatch — resets the module-level known-models cache.
 * Exists so tests can swap in a custom reference between cases without
 * needing to instantiate a fresh import graph.
 */
export function __resetKnownModelsCacheForTests(): void {
  cachedKnownModels = null;
}

// ── Per-Tzun hook state ──────────────────────────────────────────────

/**
 * The hook-surface state for a single `Tzun` instance — an LRU cache that
 * deduplicates descriptor registrations across calls, plus an optional
 * known-models override.
 *
 * One state per Tzun instance, lazily constructed on first `hook()` call.
 */
export interface HookState {
  cache: LruCache<string, string>;
  knownModels: Promise<KnownModelsReference>;
  /** Per-vendor call and aiBom production counters. */
  usage: Record<string, { calls: number; aiBomsProduced: number }>;
}

export const hookStateByTzun = new WeakMap<Tzun, HookState>();

/**
 * Default LRU capacity for the per-Tzun hook cache.
 */
const DEFAULT_HOOK_CACHE_CAPACITY = 256;

/**
 * Get-or-create the per-Tzun hook state.
 *
 * `cacheCapacity` and `knownModels` are honored only on first construction —
 * subsequent calls reuse the existing state. Tests that need to inject
 * different overrides on the same Tzun should construct a fresh instance.
 */
export function getOrCreateHookState(
  tzun: Tzun,
  cacheCapacity?: number,
  knownModelsOverride?: KnownModelsReference,
): HookState {
  let state = hookStateByTzun.get(tzun);
  if (!state) {
    state = {
      cache: new LruCache<string, string>(cacheCapacity ?? DEFAULT_HOOK_CACHE_CAPACITY),
      knownModels: getKnownModels(knownModelsOverride),
      usage: {},
    };
    hookStateByTzun.set(tzun, state);
  }
  return state;
}

/**
 * Public `Tzun#hook` implementation. Dispatches to the connector matching
 * `vendor` via the registry; throws `unknownVendorError` on miss; reuses
 * the per-Tzun LRU cache; returns the wire `AiBom` (or `null` when the
 * connector emits no skeleton).
 *
 * This is `Tzun#hook(vendor, request, response)` plumbed through; the
 * method on the Tzun class is a thin one-liner that calls into here.
 */
export async function hook(
  tzun: Tzun,
  vendor: string,
  request: Record<string, unknown>,
  response: Record<string, unknown>,
): Promise<AiBom | AiBomWithInlineDescriptor | null> {
  const connector = getConnector(vendor);
  if (!connector) {
    throw unknownVendorError(vendor);
  }
  const state = getOrCreateHookState(tzun);
  const known = await state.knownModels;
  const result = await hookCoreInternal(connector, tzun, state.cache, known, request, response);

  // ── per-vendor usage counter ───────────────────────────────────────────
  const usageEntry = state.usage[vendor] ?? { calls: 0, aiBomsProduced: 0 };
  usageEntry.calls++;
  if (result.aiBom !== null) usageEntry.aiBomsProduced++;
  state.usage[vendor] = usageEntry;

  // ── structured log ─────────────────────────────────────────────────────
  // Emits connector_auto_registration for both new and cached registrations.
  // `cached: true` means this model/version was already in the LRU and no
  // storage round-trip occurred. Security: no auth material, no payload content.
  if (result.notRecordable === true) {
    // The connector named a model this store cannot record (no model
    // catalog). The decision is still captured, with `contributions: null`;
    // this line is the signal that its model is not.
    sdkLog(tzun.getLogSink(), 'capture_model_not_recordable', {
      vendor,
      modelName: result.modelName,
      reason: 'store_has_no_model_catalog',
    });
  } else if (result.modelName !== null) {
    sdkLog(
      tzun.getLogSink(),
      'connector_auto_registration',
      {
        vendor,
        modelName: result.modelName,
        digest: result.digest,
        cached: result.cached,
      },
    );
  } else {
    // The connector produced no skeleton — the capture will be stored with
    // `aiBom: null`. Without this event that would be indistinguishable from
    // success on the log sink (only the success arm above emits), so a whole
    // deployment could store model-less evidence without a single line anywhere.
    sdkLog(tzun.getLogSink(), 'connector_no_aibom', { vendor });
  }

  return result.aiBom;
}

// ── attach() — duck-type dispatch + per-call opt-in capture ──────────

/**
 * The kwarg name applications inject on a wrapped vendor SDK call to
 * trigger capture. Stripped from the forwarded params before the call
 * reaches the underlying client. Exported for use in docs/type tests.
 */
export const TZUN_CAPTURE_KWARG = 'tzun_capture' as const;

/**
 * Duck-type detect which vendor a client object matches. An explicit
 * `options.vendor` always wins; otherwise the function inspects the
 * client's call surface in a fixed priority order:
 *
 *   1. `client.chat.completions.create` → openai
 *      (NIM shares this shape; callers MUST pass `vendor: 'nvidia-nim'`
 *       to override.)
 *   2. `client.messages.create` → anthropic
 *   3. `client.send` + constructor name matching `/^Bedrock(Runtime)?Client$/`
 *      → bedrock
 *   4. `client.generateContent` or `client.predict` → vertex
 *   5. `client.complete` or `client.getChatCompletions` → azure-ai
 *   6. `client.chatCompletion` or `client.textGeneration` → hf-inference
 *
 * Unrecognized shapes throw with the seven checked shapes named in the
 * error message.
 */
export function detectVendor(
  client: unknown,
  options?: AttachOptions,
): SupportedVendor {
  if (options?.vendor) return options.vendor;
  const c = client as Record<string, unknown> & {
    chat?: { completions?: { create?: unknown } };
    messages?: { create?: unknown };
    send?: unknown;
    generateContent?: unknown;
    predict?: unknown;
    complete?: unknown;
    getChatCompletions?: unknown;
    chatCompletion?: unknown;
    textGeneration?: unknown;
    constructor?: { name?: string };
  };
  if (typeof c?.chat?.completions?.create === 'function') return 'openai';
  if (typeof c?.messages?.create === 'function') return 'anthropic';
  if (
    typeof c?.send === 'function' &&
    /^Bedrock(Runtime)?Client$/.test(c?.constructor?.name ?? '')
  ) {
    return 'bedrock';
  }
  if (
    typeof c?.generateContent === 'function' ||
    typeof c?.predict === 'function'
  ) {
    return 'vertex';
  }
  if (
    typeof c?.complete === 'function' ||
    typeof c?.getChatCompletions === 'function'
  ) {
    return 'azure-ai';
  }
  if (
    typeof c?.chatCompletion === 'function' ||
    typeof c?.textGeneration === 'function'
  ) {
    return 'hf-inference';
  }
  throw new Error(
    `tzun.attach: client shape unrecognized. Checked: ` +
      `openai (chat.completions.create), anthropic (messages.create), ` +
      `bedrock (send + BedrockRuntimeClient), vertex (generateContent or predict), ` +
      `azure-ai (complete or getChatCompletions), nvidia-nim (explicit override), ` +
      `hf-inference (chatCompletion or textGeneration).`,
  );
}

/**
 * Read `tzun_capture` off a call payload. For most vendors the payload is
 * the first positional argument (a kwargs object); for Bedrock the payload
 * is the `command` object passed to `send(command)`.
 *
 * Returns `null` when `tzun_capture` is absent, null, or undefined.
 */
function readDecisionInput(payload: unknown): DecisionInput | null {
  if (payload === null || payload === undefined) return null;
  if (typeof payload !== 'object') return null;
  const cap = (payload as Record<string, unknown>)[TZUN_CAPTURE_KWARG];
  if (cap === null || cap === undefined) return null;
  return cap as DecisionInput;
}

/**
 * Return a shallow copy of `payload` with the `tzun_capture` kwarg
 * removed. Preserves prototype + own properties so the forwarded payload
 * looks structurally identical to one the caller would build by hand.
 */
function stripCapture<T extends object>(payload: T): T {
  const copy = Object.create(Object.getPrototypeOf(payload));
  for (const key of Object.keys(payload)) {
    if (key !== TZUN_CAPTURE_KWARG) {
      (copy as Record<string, unknown>)[key] = (payload as Record<string, unknown>)[key];
    }
  }
  return copy as T;
}

/**
 * For the Bedrock dispatch surface: given the raw command, extract the
 * `params` object the connector expects. Bedrock commands carry their
 * SDK-canonical request shape under `command.input`.
 */
function extractBedrockParams(command: unknown): Record<string, unknown> {
  if (command && typeof command === 'object' && 'input' in command) {
    const input = (command as { input?: unknown }).input;
    if (input && typeof input === 'object') {
      return input as Record<string, unknown>;
    }
  }
  return {};
}

/**
 * Build the connector params for a Vertex call.
 *
 * The `@google-cloud/vertexai` SDK puts the model id and the GCP region on
 * the `GenerativeModel` *instance* (`vertex.getGenerativeModel({ model })`,
 * `new VertexAI({ location })`) and the request object carries only
 * `{ contents, generationConfig, ... }`. Forwarding `args[0]` alone would
 * hand the connector a params object with no `model` and no `location`, so
 * `buildAiBom` would return `null` and every capture through the Vertex
 * recipe of the AI-BOM integration guide (`docs/integration/`) would store
 * `aiBom: null` — no model identity, no inference parameters, no region —
 * silently.
 *
 * Precedence is request-first so an explicit `model` in the payload (the
 * `predict` surface, and callers who pass it for convenience) still wins;
 * the instance and the response's `modelVersion` are fallbacks. `config` is
 * accepted as an alias of `generationConfig` because the newer `@google/genai`
 * SDK renamed that key.
 */
function extractVertexParams(
  payload: unknown,
  thisArg: unknown,
  response: unknown,
): Record<string, unknown> {
  const params: Record<string, unknown> = {
    ...((payload as Record<string, unknown> | undefined) ?? {}),
  };
  const instance = (thisArg ?? {}) as Record<string, unknown>;

  // `config` is @google/genai's spelling of `generationConfig`.
  if (params.generationConfig === undefined && isRecord(params.config)) {
    params.generationConfig = params.config;
  }

  if (asString(params.model) === null) {
    // GenerativeModel stores the id as `model`; some builds also expose
    // `publisherModelEndpoint`. Fall back to the version the response echoes.
    const fromInstance =
      asString(instance.model) ?? asString(instance.publisherModelEndpoint);
    const fromResponse = asString(
      isRecord(response) && isRecord(response.response)
        ? response.response.modelVersion
        : isRecord(response)
          ? response.modelVersion
          : undefined,
    );
    const resolved = fromInstance ?? fromResponse;
    if (resolved !== null) params.model = resolved;
  }

  if (asString(params.location) === null) {
    const fromInstance =
      asString(instance.location) ??
      (isRecord(instance.vertexai) ? asString(instance.vertexai.location) : null);
    if (fromInstance !== null) params.location = fromInstance;
  }

  return params;
}

/** Narrow to a plain object without widening `unknown` at every call site. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Read a own-property string, ignoring empty strings and non-strings. Mirrors
 * the connectors' `asString` helper; duplicated here to avoid importing the
 * connector-internal module into the wrapper layer.
 */
function asString(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Build the intercept function for one vendor method. Captures-on-presence
 * of `tzun_capture`; pass-through otherwise. Honors the `emitAiBom: false`
 * kill-switch.
 *
 * For the Bedrock surface, the call payload is the command object; the
 * connector reads from `command.input`. For every other surface the call
 * payload IS the kwargs object the connector consumes directly.
 *
 * Failure observability (the structured log sink, `sdkLog` / `TzunConfig.onLog`):
 *   - `connector_hook_failure { vendor, errorName }` — the AI-BOM was lost
 *     (connector threw, or descriptor registration failed); the capture
 *     still proceeds with `contributions: null`.
 *   - `capture_model_not_recordable { vendor, modelName, reason }` — the
 *     store has no model catalog (an adapter without one, or the cloud
 *     transport against a platform that does not serve `POST /v1/models`),
 *     so the model is not recorded; the capture still proceeds with
 *     `contributions: null`.
 *   - `capture_skipped { vendor, reason }` — the caller passed `tzun_capture`
 *     but `emitAiBom: false` suppressed the whole capture, so no evidence
 *     exists for this decision either. Emitted only when capture was actually
 *     requested; a plain un-annotated pass-through is silent.
 *   - `capture_failure { vendor, failureType, aiSystemId, evidenceId }` —
 *     `capture()` returned `{ stored: false }`, so NO evidence exists for
 *     this decision. `capture()` never throws, so nothing is thrown and the
 *     vendor response is still returned; the log is the only signal.
 *
 * No event carries payload content. Embedders observe both by
 * registering `TzunConfig.onLog` and filtering on the event name — that is
 * the SDK's caller-facing observability surface; `AttachOptions` carries no
 * callback.
 */
function buildIntercept(
  vendor: SupportedVendor,
  originalMethod: (...args: unknown[]) => Promise<unknown>,
  thisArg: unknown,
  tzun: Tzun,
  options?: AttachOptions,
  /**
   * Facts that live on the CLIENT INSTANCE, not in the call kwargs.
   *
   * The openai package puts the Azure endpoint, deployment and api-version on
   * the AzureOpenAI object (`this.baseURL` / `this.deploymentName` /
   * `this.apiVersion`); none of them ever appear in a
   * `chat.completions.create` payload. buildIntercept forwarded only the call
   * kwargs, so `isAzure(params)` was false for every attach()-ed Azure client
   * and the capture recorded `infrastructure: null` — no region, no endpoint,
   * no API version, the one thing a data-residency auditor asks for.
   */
  clientHints?: Record<string, unknown>,
): (...args: unknown[]) => Promise<unknown> {
  return async function intercepted(...args: unknown[]): Promise<unknown> {
    const payload = args[0];

    // Read tzun_capture (if any) BEFORE stripping, so the kwarg never
    // reaches the underlying client.
    const decisionInput = readDecisionInput(payload);

    // Build the forwarded args: same shape as caller passed, but with
    // tzun_capture removed from the first positional payload.
    const forwardedArgs =
      payload && typeof payload === 'object'
        ? [stripCapture(payload as object), ...args.slice(1)]
        : args;

    // Pass-through path: no capture intent, OR explicit kill-switch.
    if (!decisionInput || options?.emitAiBom === false) {
      // `emitAiBom` reads like "skip the descriptor catalog round-trip", but it
      // is a capture kill-switch: a caller who set it to dodge a
      // `descriptor_not_registered` on the cloud transport silently loses every
      // record. Every other way a capture can be lost is observable on the log
      // sink, and so is this one: fire `capture_skipped`, but only
      // when the caller actually asked for a capture (`tzun_capture` present) —
      // an ordinary un-annotated call is not a skip and must not spam the sink.
      if (decisionInput) {
        sdkLog(tzun.getLogSink(), 'capture_skipped', {
          vendor,
          reason: 'emitAiBom:false',
        });
      }
      return originalMethod.apply(thisArg, forwardedArgs);
    }

    const response = (await originalMethod.apply(
      thisArg,
      forwardedArgs,
    )) as Record<string, unknown>;

    const connectorParams =
      vendor === 'bedrock'
        ? extractBedrockParams(forwardedArgs[0])
        : vendor === 'vertex'
          ? extractVertexParams(forwardedArgs[0], thisArg, response)
          : {
              // Client-instance hints first, so an explicit call kwarg still wins.
              // Vertex is handled above and does not need them: extractVertexParams
              // already takes `thisArg` and reads the instance's model/location
              // itself, which is a superset of what clientHints carries.
              ...(clientHints ?? {}),
              ...((forwardedArgs[0] as Record<string, unknown>) ?? {}),
            };

    let autoAiBom: AiBom | AiBomWithInlineDescriptor | null = null;
    try {
      autoAiBom = await hook(tzun, vendor, connectorParams, response);
    } catch (error) {
      // Connector throws on bad input are surfaced as aiBom: null so the
      // capture proceeds — the caller's decision is more important than a
      // missing AI-BOM.
      //
      // This arm also catches storage faults from `registerModelDescriptor`
      // inside `hookCoreInternal`, so a database blip silently strips the
      // AI-BOM off an otherwise-good record. Emit a log so the loss is
      // observable (the structured log sink; `connector_auto_registration`'s
      // sibling event on the failure side).
      //
      // Security: the error's class name only — never its
      // message, which can echo caller-supplied values.
      autoAiBom = null;
      sdkLog(
        tzun.getLogSink(),
        'connector_hook_failure',
        {
          vendor,
          errorName: error instanceof Error ? error.name : typeof error,
        },
      );
    }

    const modelAiBom = decisionInput.aiBom !== undefined ? decisionInput.aiBom : autoAiBom;
    const legacy: Record<string, unknown> = {};
    for (const name of RENAMED_DECISION_FIELDS) {
      if (Object.prototype.hasOwnProperty.call(decisionInput, name)) legacy[name] = (decisionInput as unknown as Record<string, unknown>)[name];
    }
    const captureInput = {
      ...legacy,
      aiSystemId:
        options?.aiSystemId ??
        (connectorParams.model as string | undefined) ??
        (connectorParams.modelId as string | undefined) ??
        vendor,
      aiOutput: response,
      action: decisionInput.action,
      reason: decisionInput.reason,
      decider: decisionInput.decider,
      contributions:
        modelAiBom === null || modelAiBom === undefined
          ? null
          : singleModel(modelAiBom, decisionInput.actor ? { actor: decisionInput.actor } : {}),
      ...(decisionInput.links !== undefined && { links: decisionInput.links }),
    } as CaptureInput;
    // `capture()` is contracted never to throw, but this is the last line of
    // defence for the vendor response, which has already been paid for and
    // cannot be re-fetched. A bug or an unguarded infrastructure fault inside
    // capture() must not reject the wrapped call and destroy the model output
    // plus the human decision along with the evidence. Degrade to an unstored
    // capture and log it like any other.
    let result: CaptureResult;
    try {
      result = await tzun.capture(captureInput);
    } catch (error) {
      result = {
        envelope: {} as EvidenceEnvelope,
        stored: false,
        failure: {
          failureType: 'capture_threw',
          diagnosticMetadata: {
            errorName: error instanceof Error ? error.name : typeof error,
            errorMessage: error instanceof Error ? error.message : String(error),
          },
          capturedAt: new Date().toISOString(),
        },
      };
    }

    // The contract stays intact: a capture failure never throws and never
    // changes the response surface — the original vendor response is
    // returned either way. What it does NOT license is emitting no signal at
    // all, which would leave every dropped capture (validation_failure,
    // descriptor_not_registered, a missing required attestation, a
    // cloud-mode chain_conflict/401/5xx, or any thrown error converted to
    // serialization_failure) indistinguishable from a stored one. Log it on
    // the structured log sink so the caller can see that no evidence exists
    // for this decision.
    //
    // Security: vendor, failure type and identifiers only. The
    // failure's `diagnosticMetadata` is not logged. Its shape depends on the
    // failure type, and several carry free-form text this sink's contract
    // cannot vouch for: a storage or transport error's message, and on a
    // cloud failure the server's context. A validation failure names the
    // field, the rule it broke and the type it had, never the value.
    if (!result.stored) {
      sdkLog(
        tzun.getLogSink(),
        'capture_failure',
        {
          vendor,
          failureType: result.failure?.failureType ?? 'unknown',
          aiSystemId: captureInput.aiSystemId,
          evidenceId: result.failure?.evidenceId ?? null,
          // The failure's code: a validation rule's code, or a cloud
          // capture's stable wire code, which with the retryable flag tells
          // "rotate the key" from "the backend is down, this will drain on its
          // own". `retryable` is absent (undefined) for non-cloud failures.
          cloudErrorCode: result.failure?.diagnosticMetadata?.code,
          retryable: result.failure?.diagnosticMetadata?.retryable,
        },
      );
    }
    return response;
  };
}

/**
 * Wrap a vendor SDK client so that per-call `tzun_capture` kwargs trigger
 * `tzun.capture()` automatically. Returns a new object that shares the
 * original's prototype + own props; only the vendor-specific call methods
 * are intercepted.
 *
 * Detection is duck-typed via `detectVendor`. Pass `options.vendor` to
 * override (required for NIM, which shares OpenAI's call surface).
 */
/**
 * Copy an object the way `attachClient` copies the root client: a fresh object
 * on the SAME prototype, with own enumerable props assigned over it.
 *
 * Object spread copies own enumerable properties only. Vendor SDKs put their
 * resource methods on the class prototype — openai@4 defines
 * `retrieve/update/list/del` on `Completions.prototype`, Anthropic puts
 * `stream` on `Messages.prototype` — so `{ ...client.chat.completions }`
 * produced a bare object whose prototype was `Object.prototype` and every
 * non-intercepted method was simply gone. `attachClient` already did this
 * correctly for the root object; the nested resources it rebuilds did not.
 */
function copyPreservingPrototype<T extends object>(source: T): T {
  return Object.assign(Object.create(Object.getPrototypeOf(source)), source) as T;
}

/**
 * Read Azure OpenAI facts off the client instance.
 *
 * `AzureOpenAI` from the `openai` package sets `apiVersion` / `deploymentName`
 * on the instance and points `baseURL` at `*.openai.azure.com`. Returns `{}`
 * for a plain OpenAI client, so a direct-OpenAI capture is byte-for-byte what
 * it was.
 */
export function extractAzureClientHints(client: object): Record<string, unknown> {
  const c = client as Record<string, unknown>;
  const ctorName = (client as { constructor?: { name?: string } }).constructor?.name;
  const baseURL = typeof c.baseURL === 'string' ? c.baseURL : undefined;
  const looksAzure =
    ctorName === 'AzureOpenAI' ||
    typeof c.deploymentName === 'string' ||
    (baseURL !== undefined && /openai\.azure\.com/i.test(baseURL));
  if (!looksAzure) return {};

  const hints: Record<string, unknown> = { __tzunIsAzure: true };
  if (baseURL !== undefined) hints.azure_endpoint = baseURL;
  if (typeof c.apiVersion === 'string') hints.api_version = c.apiVersion;
  if (typeof c.deploymentName === 'string') hints.azure_deployment = c.deploymentName;
  return hints;
}

export function attachClient<T extends object>(
  client: T,
  tzun: Tzun,
  options?: AttachOptions,
): T {
  const vendor = detectVendor(client, options);

  // Object.create + Object.assign, so the wrapped client preserves its
  // prototype and own props.
  const wrapped = Object.create(Object.getPrototypeOf(client));
  Object.assign(wrapped, client);

  const c = client as Record<string, unknown> & {
    chat?: { completions?: { create?: (...args: unknown[]) => Promise<unknown> } };
    messages?: { create?: (...args: unknown[]) => Promise<unknown> };
    send?: (...args: unknown[]) => Promise<unknown>;
    generateContent?: (...args: unknown[]) => Promise<unknown>;
    predict?: (...args: unknown[]) => Promise<unknown>;
    complete?: (...args: unknown[]) => Promise<unknown>;
    getChatCompletions?: (...args: unknown[]) => Promise<unknown>;
    chatCompletion?: (...args: unknown[]) => Promise<unknown>;
    textGeneration?: (...args: unknown[]) => Promise<unknown>;
  };

  switch (vendor) {
    case 'openai':
    case 'nvidia-nim': {
      const completions = c.chat!.completions!;
      const originalCreate = completions.create!.bind(completions);
      const completionsCopy = copyPreservingPrototype(completions);
      completionsCopy.create = buildIntercept(
        vendor,
        originalCreate,
        completions,
        tzun,
        options,
        vendor === 'openai' ? extractAzureClientHints(client) : undefined,
      );
      wrapped.chat = copyPreservingPrototype(c.chat!);
      wrapped.chat.completions = completionsCopy;
      break;
    }
    case 'anthropic': {
      const messages = c.messages!;
      const originalCreate = messages.create!.bind(messages);
      const messagesCopy = copyPreservingPrototype(messages);
      messagesCopy.create = buildIntercept(vendor, originalCreate, messages, tzun, options);
      wrapped.messages = messagesCopy;
      break;
    }
    case 'bedrock': {
      const originalSend = c.send!.bind(c);
      wrapped.send = buildIntercept(vendor, originalSend, c, tzun, options);
      break;
    }
    case 'vertex': {
      if (typeof c.generateContent === 'function') {
        const original = c.generateContent.bind(c);
        wrapped.generateContent = buildIntercept(vendor, original, c, tzun, options);
      }
      if (typeof c.predict === 'function') {
        const original = c.predict.bind(c);
        wrapped.predict = buildIntercept(vendor, original, c, tzun, options);
      }
      break;
    }
    case 'azure-ai': {
      if (typeof c.complete === 'function') {
        const original = c.complete.bind(c);
        wrapped.complete = buildIntercept(vendor, original, c, tzun, options);
      }
      if (typeof c.getChatCompletions === 'function') {
        const original = c.getChatCompletions.bind(c);
        wrapped.getChatCompletions = buildIntercept(vendor, original, c, tzun, options);
      }
      break;
    }
    case 'hf-inference': {
      if (typeof c.chatCompletion === 'function') {
        const original = c.chatCompletion.bind(c);
        wrapped.chatCompletion = buildIntercept(vendor, original, c, tzun, options);
      }
      if (typeof c.textGeneration === 'function') {
        const original = c.textGeneration.bind(c);
        wrapped.textGeneration = buildIntercept(vendor, original, c, tzun, options);
      }
      break;
    }
  }

  return wrapped as T;
}

// ── Named per-vendor wrappers ────────────────────────────────────────

/**
 * Build a named vendor-pinned wrapper.
 * The returned function has the same signature as `attachClient` but with the
 * vendor hard-coded and removed from the `options` surface (`Omit<…,'vendor'>`),
 * preventing callers from accidentally overriding the pin.
 */
function makeVendorWrapper(vendor: SupportedVendor) {
  return function wrapVendor<T extends object>(
    client: T,
    tzun: import('./index').Tzun,
    options?: Omit<AttachOptions, 'vendor'>,
  ): T {
    return attachClient(client, tzun, { ...options, vendor });
  };
}

/** Wrap an OpenAI SDK client, pinning the vendor to `openai`. */
export const wrapOpenAI = makeVendorWrapper('openai');
/** Wrap an Anthropic SDK client, pinning the vendor to `anthropic`. */
export const wrapAnthropic = makeVendorWrapper('anthropic');
/** Wrap an AWS Bedrock client, pinning the vendor to `bedrock`. */
export const wrapAwsBedrock = makeVendorWrapper('bedrock');
/** Wrap a GCP Vertex AI client, pinning the vendor to `vertex`. */
export const wrapGcpVertex = makeVendorWrapper('vertex');
/** Wrap an Azure AI Inference client, pinning the vendor to `azure-ai`. */
export const wrapAzureAI = makeVendorWrapper('azure-ai');
/** Wrap an NVIDIA NIM client (OpenAI-compatible), pinning the vendor to `nvidia-nim`. */
export const wrapNvidiaNim = makeVendorWrapper('nvidia-nim');
/** Wrap a Hugging Face Inference client, pinning the vendor to `hf-inference`. */
export const wrapHFInference = makeVendorWrapper('hf-inference');
