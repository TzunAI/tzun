/**
 * OpenRouter gateway connector.
 *
 * OpenRouter (https://openrouter.ai) serves models of many makers through one
 * OpenAI-compatible chat-completions API and routes each call to an upstream
 * provider. A record of such a call states four things, each as the gateway
 * reported it, and nothing it did not report:
 *
 *   - who served it: the descriptor's `vendor` is `openrouter`, and
 *     `infrastructure.endpoint` is the gateway URL the client called;
 *   - which model it served: `modelName` is `response.model` verbatim, variant
 *     suffix (`:free`, `:batch`, ...) included, with `modelVersion: 'unknown'`;
 *   - who made it: `trainedBy` is the author prefix of that id (`nvidia`,
 *     `meta-llama`, `x-ai`, ...), or `null` for OpenRouter's own routers
 *     (`openrouter/*`);
 *   - which upstream ran it: `infrastructure.provider` is `response.provider`
 *     verbatim (`"Nvidia"`, `"Google AI Studio"`, ...), OpenRouter's own name
 *     for the provider it routed the call to.
 *
 * The integrity tier is `vendor-asserted`, the asserting vendor being the
 * gateway: nothing here is attested by the maker.
 *
 * Field mapping:
 *
 *   response.model              → modelName (no AI-BOM without it; never
 *                                 `params.model`, which a fallback list or a
 *                                 router may not have served)
 *   response.system_fingerprint → vendorFingerprint (never `response.id`, a
 *                                 per-call generation id)
 *   response.provider           → infrastructure.provider (1..256 UTF-16 code
 *                                 units, else null)
 *   params.openrouter_endpoint  → infrastructure.endpoint (a client hint, set
 *                                 by attach() from the client's base URL or
 *                                 passed to hook(); never assumed)
 *   params.temperature          → inferenceParameters.temperature
 *   params.top_p                → inferenceParameters.topP
 *   params.max_tokens           → inferenceParameters.maxTokens (non-negative
 *                                 safe integer, else null)
 *   params.seed                 → inferenceParameters.seed (safe integer, else
 *                                 null)
 *   params.stop                 → inferenceParameters.stopSequences
 *                                 (string → [string]; null when there are
 *                                 more than 16 or one is over 256 UTF-16
 *                                 code units)
 *
 * `params.provider` (OpenRouter's routing preferences), `models`, `route`,
 * `transforms`, `reasoning` and `usage` are request options, not AI-BOM
 * members, and are not read.
 *
 * The URL helpers below use string operations only: `new URL` and Python's
 * `urllib.parse` disagree on host case, default ports and IDNA, which would
 * make the two SDKs record different strings for one client. The Python port
 * (`tzun_sdk.ai_bom.connectors.openrouter`) follows them step for step.
 * `openRouterEndpoint` lowercases the ASCII letters of the host and drops the
 * scheme's default port, as openai-python's `httpx.URL` base URL already
 * does, so a client configured as `https://OpenRouter.AI:443/api/v1` records
 * the same endpoint through either SDK's `attach()`. httpx also IDNA-encodes
 * a non-ASCII host, percent-encodes some path characters and reads a port
 * written with leading zeros (`:0443`) as a number; such a base URL may still
 * be recorded differently by the two `attach()` paths.
 *
 * No blocking external I/O is performed. Same input → same output.
 */

import { AI_BOM_MAX_STOP_SEQUENCES, AI_BOM_MAX_STRING_LENGTH } from '@tzun/engine';
import type { Connector, AiBomSkeleton } from './base';
import { importFromVendor } from '../../models/import-vendor';

// ── Field-extraction helpers ──────────────────────────────────────

function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

function asFiniteNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/** A safe integer, else null: an AI-BOM `seed` that is anything else fails capture. */
function asSafeInteger(v: unknown): number | null {
  return typeof v === 'number' && Number.isSafeInteger(v) ? v : null;
}

/** A non-negative safe integer, else null (the AI-BOM `maxTokens` rule). */
function asNonNegativeSafeInteger(v: unknown): number | null {
  const n = asSafeInteger(v);
  return n !== null && n >= 0 ? n : null;
}

function normalizeStop(v: unknown): string[] | null {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) {
    const xs = v.filter((x): x is string => typeof x === 'string');
    return xs.length > 0 ? xs : null;
  }
  return null;
}

/**
 * The stop sequences an AI-BOM can carry: at most 16, each at most 256 UTF-16
 * code units. Anything else is null as a whole, never truncated: a partial
 * list would misstate the request, and an over-long one would turn the
 * capture into a validation failure.
 */
function boundedStops(v: unknown): string[] | null {
  const xs = normalizeStop(v);
  if (xs === null || xs.length > AI_BOM_MAX_STOP_SEQUENCES) return null;
  return xs.every((x) => x.length <= AI_BOM_MAX_STRING_LENGTH) ? xs : null;
}

/** A string of 1..256 UTF-16 code units, else null (an `infrastructure` member's limit). */
function boundedString(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 && v.length <= AI_BOM_MAX_STRING_LENGTH
    ? v
    : null;
}

// ── Base-URL handling ─────────────────────────────────────────────

interface HttpUrlParts {
  scheme: 'https://' | 'http://';
  authority: string;
  path: string;
}

/**
 * Splits an `http(s)://` URL into scheme, authority (without userinfo) and
 * path (without query or fragment), by string operations only. `null` for a
 * value that is not a string, has another scheme, or has an empty authority.
 */
function splitHttpUrl(value: unknown): HttpUrlParts | null {
  if (typeof value !== 'string') return null;
  let scheme: HttpUrlParts['scheme'];
  if (value.startsWith('https://')) scheme = 'https://';
  else if (value.startsWith('http://')) scheme = 'http://';
  else return null;
  let rest = value.slice(scheme.length);
  // Drop the query and the fragment: cut at the first `?` or `#`.
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '?' || rest[i] === '#') {
      rest = rest.slice(0, i);
      break;
    }
  }
  const slash = rest.indexOf('/');
  let authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? '' : rest.slice(slash);
  // Drop the userinfo (`user:password@`).
  authority = authority.slice(authority.lastIndexOf('@') + 1);
  if (authority.length === 0) return null;
  return { scheme, authority, path };
}

/** ASCII `A`-`Z` to `a`-`z`, nothing else (JS and Python case-map other characters differently). */
function asciiLower(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += c >= 0x41 && c <= 0x5a ? String.fromCharCode(c + 0x20) : s[i];
  }
  return out;
}

/**
 * The gateway endpoint an `infrastructure` block records for a base URL:
 * scheme, host and path, with userinfo, query, fragment and trailing `/`
 * removed (openai-node's `baseURL` has no trailing `/`, openai-python's
 * `base_url` has one; both record `https://openrouter.ai/api/v1`). The host's
 * ASCII letters are lowercased and the scheme's default port (`:443` for
 * https, `:80` for http) is dropped, as openai-python's `httpx.URL` does, so
 * `https://OpenRouter.AI:443/api/v1/` records `https://openrouter.ai/api/v1`.
 * The path is kept as given. `null` when the value is not an `http(s)://` URL,
 * the host is empty, or the result is longer than 256 UTF-16 code units.
 */
export function openRouterEndpoint(value: unknown): string | null {
  const parts = splitHttpUrl(value);
  if (parts === null) return null;
  let authority = asciiLower(parts.authority);
  const defaultPort = parts.scheme === 'https://' ? ':443' : ':80';
  if (authority.endsWith(defaultPort)) {
    authority = authority.slice(0, -defaultPort.length);
  }
  if (authority.length === 0) return null;
  let path = parts.path;
  while (path.endsWith('/')) path = path.slice(0, -1);
  const out = parts.scheme + authority + path;
  return out.length <= AI_BOM_MAX_STRING_LENGTH ? out : null;
}

/**
 * Whether a client's base URL points at OpenRouter: its host, without the
 * port and compared case-insensitively, is `openrouter.ai`.
 */
export function isOpenRouterBaseUrl(value: unknown): boolean {
  const parts = splitHttpUrl(value);
  if (parts === null) return false;
  const colon = parts.authority.lastIndexOf(':');
  const host = colon < 0 ? parts.authority : parts.authority.slice(0, colon);
  return host.toLowerCase() === 'openrouter.ai';
}

// ── Connector implementation ──────────────────────────────────────

export const openRouterConnector: Connector = {
  vendor: 'openrouter',

  buildAiBom(params, response, knownModels): AiBomSkeleton | null {
    // The served id, as the gateway names it. Never `params.model`: with a
    // `models` fallback list or a router (`openrouter/auto`) the requested id
    // is not necessarily the one that served the call.
    const served = asString(response.model);
    if (!served) {
      return null;
    }

    const { descriptor } = importFromVendor({
      vendor: 'openrouter',
      modelId: served,
      knownModels,
    });

    return {
      modelDescriptor: descriptor,
      vendorFingerprint: asString(response.system_fingerprint),
      promptTemplate: null,
      inferenceParameters: {
        temperature: asFiniteNumber(params.temperature),
        topP: asFiniteNumber(params.top_p),
        maxTokens: asNonNegativeSafeInteger(params.max_tokens),
        seed: asSafeInteger(params.seed),
        stopSequences: boundedStops(params.stop),
      },
      infrastructure: {
        provider: boundedString(response.provider),
        region: null,
        apiVersion: null,
        endpoint: openRouterEndpoint(params.openrouter_endpoint),
      },
    };
  },
};
