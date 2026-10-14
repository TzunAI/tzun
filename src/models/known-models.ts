/**
 * Known-models reference loader.
 *
 * The bundled reference at `data/known-models.json` is authoritative by
 * default. Runtime fetch is opt-in via `enableRuntimeFetch` and reads the
 * HTTPS URL the caller names in `runtimeFetchUrl`; there is no default URL.
 * Without a URL, or on any error (network, parse, schema), the loader falls
 * back to the bundled copy.
 *
 * The fetcher is injectable to keep the loader testable without touching
 * the network.
 */

import knownModelsData from '../../data/known-models.json';
import { ModelDescriptor } from '@tzun/engine';

export interface KnownModelsReference {
  version: string;
  entries: Array<Partial<ModelDescriptor>>;
}

export interface KnownModelsLoaderOptions {
  /** Default false — the bundled reference is authoritative unless opted in. */
  enableRuntimeFetch?: boolean;
  /**
   * The HTTPS URL a runtime fetch reads. There is no default: without it,
   * `enableRuntimeFetch` keeps the bundled reference and reports `no-url`.
   */
  runtimeFetchUrl?: string;
  /**
   * Injectable fetcher used when `enableRuntimeFetch` is true. The default
   * implementation uses Node 22's global `fetch`. Returning a value resolves
   * to the fetched reference; any thrown/rejected error triggers the
   * bundled-fallback path.
   */
  fetcher?: (url: string) => Promise<KnownModelsReference>;
  /**
   * Milliseconds before the default fetcher aborts. Default 5000.
   *
   * Without this the loader inherits `fetch`'s absence of a default timeout, so
   * a black-holed host hangs `tzun models register` forever with no output.
   * Ignored when a custom `fetcher` is supplied — that fetcher owns its own
   * deadline.
   */
  fetchTimeoutMs?: number;
  /**
   * Called once with what the load actually produced. `loadKnownModels` is
   * best-effort by design: it swallows every fetch error and returns the
   * bundled copy, which means an operator who opted into a runtime fetch had
   * no way to tell a successful fetch from a silent fallback. This is that way.
   */
  onOutcome?: (outcome: KnownModelsLoadOutcome) => void;
}

/** What a `loadKnownModels` call actually did. */
export type KnownModelsLoadOutcome =
  | { source: 'bundled'; version: string; reason: 'fetch-not-enabled' }
  | { source: 'bundled'; version: string; reason: 'no-url' }
  | { source: 'bundled'; version: string; reason: 'fetch-failed'; error: string }
  | { source: 'bundled'; version: string; reason: 'url-not-https'; url: string }
  | { source: 'fetched'; version: string; url: string };

const DEFAULT_FETCH_TIMEOUT_MS = 5000;

async function defaultFetcher(url: string, timeoutMs: number): Promise<KnownModelsReference> {
  // Node 22 ships a global `fetch`. Kept inside the default impl so tests
  // that pass a custom `fetcher` never reach this code path.
  //
  // `fetch` has no default timeout. A black-holed known-models host would
  // otherwise hang `tzun models register` indefinitely, with the CLI printing
  // nothing, on a code path whose entire contract is "best-effort".
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) {
    throw new Error(`known-models fetch failed: HTTP ${res.status}`);
  }
  const body = (await res.json()) as KnownModelsReference;
  if (!body || typeof body.version !== 'string' || !Array.isArray(body.entries)) {
    throw new Error('known-models fetch returned an invalid payload');
  }
  return body;
}

/**
 * Returns the bundled known-models reference by default; when
 * `enableRuntimeFetch: true` and a `runtimeFetchUrl` is named, attempts a
 * best-effort fetch via the injected (or default) `fetcher` and falls back to
 * the bundled copy on any error.
 */
export async function loadKnownModels(
  options: KnownModelsLoaderOptions = {},
): Promise<KnownModelsReference> {
  const bundled = knownModelsData as KnownModelsReference;
  const report = (o: KnownModelsLoadOutcome) => options.onOutcome?.(o);

  if (!options.enableRuntimeFetch) {
    report({ source: 'bundled', version: bundled.version, reason: 'fetch-not-enabled' });
    return bundled;
  }

  // A runtime fetch names its URL. With none, the bundled copy stays in use
  // and the outcome says why.
  const url = options.runtimeFetchUrl;
  if (!url) {
    report({ source: 'bundled', version: bundled.version, reason: 'no-url' });
    return bundled;
  }

  // HTTPS-only, enforced HERE and not only in the CLI. The reference feeds
  // descriptor enrichment, so a plaintext source is an attacker-controlled
  // input to evidence content; the CLI checked it (cli.ts) but every library
  // caller of loadKnownModels could pass http:// and bypass the rule.
  if (!url.startsWith('https://')) {
    report({ source: 'bundled', version: bundled.version, reason: 'url-not-https', url });
    return bundled;
  }

  const timeoutMs = options.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const fetcher = options.fetcher ?? ((u: string) => defaultFetcher(u, timeoutMs));

  try {
    const fetched = await fetcher(url);
    report({ source: 'fetched', version: fetched.version, url });
    return fetched;
  } catch (error) {
    // Fall back to the bundled copy on any error — but say so.
    report({
      source: 'bundled',
      version: bundled.version,
      reason: 'fetch-failed',
      // Class name only, never the message: a fetch error can echo a
      // caller-supplied URL with credentials in it.
      error: error instanceof Error ? error.name : typeof error,
    });
    return bundled;
  }
}

/**
 * Exact-match lookup on `(vendor, modelName, modelVersion)`. Case-sensitive
 * (the seed uses conventional lowercase vendor strings, and model names are
 * vendor-published — both sides should treat them as opaque identifiers).
 * Returns `null` when no entry matches.
 */
export function lookupKnownModel(
  reference: KnownModelsReference,
  vendor: string,
  modelName: string,
  modelVersion: string,
): Partial<ModelDescriptor> | null {
  return (
    reference.entries.find(
      (e) =>
        e.vendor === vendor &&
        e.modelName === modelName &&
        e.modelVersion === modelVersion,
    ) ?? null
  );
}
