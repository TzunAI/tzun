// The TS cloud HTTP transport.
//
// When an API key is configured, captures are POSTed to the backend
// `POST /v1/evidence` endpoint instead of a local store. This file provides
// two layers:
//
//   1. `HttpTransport` — a focused, injectable client that performs the typed
//      POST, applies the bearer header, and maps the wire response (202 →
//      success; stable `error` codes → `TzunCaptureError`). It also performs the
//      four customer READS — retrieve, list, verify and
//      export — against `/v1/app/evidence*`, mapping their wire codes to
//      `TzunReadError`. It is the unit of logic tested in isolation (NO network
//      — `fetchFn` is injectable).
//
//   2. `HttpStorageAdapter` — a thin `StorageAdapter` that the SDK factory
//      selects when `apiKey` is present. Its `store()` delegates to the
//      transport and KEEPS the head the server reports back; the server is
//      authoritative and re-stamps `partial` captures from its own locked chain
//      head, so the adapter's chain-restore reads must echo that head rather
//      than a locally-invented one. Its `retrieveWithVerdict`,
//      `listWithVerdicts`, `verifyRecord` and `exportEvidence` serve the four
//      customer reads from the server; every other read — the ones that would
//      have to walk a whole chain — throws instead of returning empty data.
//      Its model and agent catalog methods (`registerModelDescriptor`,
//      `getModelDescriptor`, `putAgentDescriptor`, `getAgentDescriptor`,
//      `listAgentDescriptors`) call the platform's key-authenticated catalog
//      endpoints (`POST /v1/models`, `GET /v1/models/:digest`, `POST /v1/agents`,
//      `GET /v1/agents/:digest`, `GET /v1/agents`), and answer as a store
//      without the catalog when the platform does not serve them.
//      Local (memory/sqlite/postgres) modes are untouched — this adapter is
//      never constructed unless `apiKey` is set.
//
// SECURITY: the API key is NEVER included in any thrown error
// message, error context, or log line. Only the request `Authorization`
// header carries it.

import {
  DEFAULT_CHAIN_ID,
  InvalidPaginationError,
  MODEL_DESCRIPTOR_DIGEST_RE,
  canonicalSerializeAgentDescriptor,
  canonicalSerializeDescriptor,
} from '@tzun/engine';
import type {
  AgentDescriptor,
  AgentDescriptorRow,
  ModelDescriptor,
  ModelDescriptorRow,
  AttestationArtifacts,
  AttestationStatusOf,
  CustodyEntry,
  CustodyLedgerEntry,
  CustodyLedgerVerdict,
  CustodyTrailVerdict,
  EvidenceEnvelope,
  EvidenceRead,
  ExportedChainPosition,
  FailureRecord,
  ListOptions,
  RecordVerdict,
  StorageAdapter,
  StoreOptions,
  TamperIncident,
  TamperIncidentStatus,
  ChainIdentity,
  AnnotationRecord,
  RelinkRecord,
  ForkRecord,
  RelinkCustodyAppend,
  StoredCustodyEntry,
  EnvelopeRevision,
} from '@tzun/engine';
import { assertDescriptorIntegrityInvariants } from '../models/descriptor-invariants';
import {
  AgentCatalogUnsupportedError,
  agentListRequest,
  checkedAgentDescriptor,
  isAgentDescriptorDigest,
  prefixedSha256,
} from '../storage/agent-sql';

/** Default managed cloud base URL. */
export const DEFAULT_API_URL = 'https://api.tzun.ai';

/** Completeness levels accepted by `POST /v1/evidence`. */
export type Completeness = 'raw' | 'partial' | 'sealed';

/**
 * Injectable fetch signature — a structural subset of the global `fetch`.
 * Tests pass a fake; production defaults to the global `fetch`.
 */
export type FetchFn = (
  url: string,
  init?: RequestInit,
) => Promise<Response>;

/**
 * Default per-request deadline for a capture POST, in milliseconds.
 *
 * `capture()` is awaited inside the vendor intercept before the customer's own
 * handler returns, so this bound is the customer's added latency ceiling when
 * the backend is wedged. Without it the request rides Node/undici defaults
 * (10 s connect, ~300 s headers/body) or a proxy's 100 s origin timeout — i.e.
 * minutes of hang per decision. 10 s is comfortably above p99 for a capture
 * POST and well below any worker-pool exhaustion threshold.
 */
export const DEFAULT_CAPTURE_TIMEOUT_MS = 10_000;

/** Options for constructing an {@link HttpTransport}. */
export interface HttpTransportOptions {
  /** API key sent as `Authorization: Bearer <apiKey>`. */
  apiKey: string;
  /** Base URL; defaults to {@link DEFAULT_API_URL}. */
  apiUrl?: string;
  /** Injectable fetch (for tests). Defaults to the global `fetch`. */
  fetchFn?: FetchFn;
  /**
   * Per-request deadline in ms; defaults to
   * {@link DEFAULT_CAPTURE_TIMEOUT_MS}. `0` or a negative value disables the
   * deadline (NOT recommended — see the constant's doc comment).
   */
  timeoutMs?: number;
}

/** A single capture POST to `/v1/evidence`. */
export interface CaptureRequest {
  /** Defaults to `'partial'`. */
  completeness?: Completeness;
  /** Optional chain selector — passed through verbatim. */
  chainId?: string;
  /** For `partial`/`sealed`: the SDK-built, self-consistent envelope. */
  envelope?: EvidenceEnvelope;
  /** For `raw`: an arbitrary payload object. */
  payload?: Record<string, unknown>;
  /**
   * Optional `Idempotency-Key` header value. The platform fingerprints a keyed
   * capture over what the caller chose (chain, completeness and the decision),
   * not over what the SDK mints per attempt (evidenceId, capturedAt, sequence,
   * chain link, digest, obtained attestations). A retry of one decision under
   * its key is answered 202 with the first capture's receipt; the key under a
   * different decision is `idempotency_conflict`.
   */
  idempotencyKey?: string;
}

/** Typed success result mapped from a 202 response. */
export interface CaptureSuccess {
  evidenceId: string;
  chainId: string;
  sequence: number;
  canonicalDigest: string;
  headDigest: string;
}

/**
 * Stable error codes returned by the backend capture route. `transport_error`
 * is a synthetic code the transport assigns to network failures / unparseable
 * responses (never sent by the server).
 *
 * `rate_limited` (429) is retryable and carries `retryAfterSeconds` in
 * `context` when the server or the `Retry-After` header supplies one.
 * `evidence_id_conflict` (409) means the evidence id already belongs to another
 * record, and `invalid_captured_at` (422) means the server refused the
 * record's `capturedAt` (`context.reason` says why); neither is retryable.
 * `chain_sealed` (409) means the chain is sealed, the read-only remainder of a
 * fork; `context.chainId` and `context.sealedAt` name the chain and when it
 * was sealed. It is not retryable: a seal is never lifted, and new records go
 * to the chain the fork created.
 * `idempotency_conflict` (422) means the `Idempotency-Key` already belongs to a
 * capture of a different decision (`context.reason` names the rarer causes).
 * It is not retryable: the key answers for its first decision only. The same
 * key with the same decision is not an error; the server answers 202 with the
 * first capture's receipt.
 */
export type CaptureErrorCode =
  | 'unauthenticated'
  | 'invalid_request'
  | 'payload_too_large'
  | 'verification_failed'
  | 'idempotency_conflict'
  | 'chain_conflict'
  | 'evidence_id_conflict'
  | 'invalid_captured_at'
  | 'chain_sealed'
  | 'rate_limited'
  | 'store_unavailable'
  | 'internal'
  | 'transport_error';

/**
 * A typed capture failure that CARRIES the stable wire `error` code.
 *
 * The API key is never placed into `message` or `context`.
 */
export class TzunCaptureError extends Error {
  /** Stable wire `error` code. */
  readonly code: CaptureErrorCode;
  /** HTTP status, or 0 for a pre-response network failure. */
  readonly status: number;
  /** Whether the caller may safely retry (network / 429 / 5xx). */
  readonly retryable: boolean;
  /** Extra fields from the error body (e.g. `failedCheck`, `expectedPreviousDigest`). */
  readonly context: Record<string, unknown>;

  constructor(
    code: CaptureErrorCode,
    status: number,
    options: { retryable?: boolean; context?: Record<string, unknown>; message?: string } = {},
  ) {
    super(options.message ?? `Tzun cloud capture failed: ${code} (HTTP ${status})`);
    this.name = 'TzunCaptureError';
    this.code = code;
    this.status = status;
    this.retryable = options.retryable ?? false;
    this.context = options.context ?? {};
    // Restore prototype chain for `instanceof` across the ts-jest/CJS boundary.
    Object.setPrototypeOf(this, TzunCaptureError.prototype);
  }
}

/**
 * HTTP status → whether a same-request retry is safe: a 429 (after the
 * server's wait) and any 5xx.
 */
function isRetryableStatus(status: number): boolean {
  return status === 429 || (status >= 500 && status < 600);
}

/**
 * The code for an error response whose body carries no known code: `internal`
 * for a 5xx, `rate_limited` for a 429 (a proxy in front of the backend answers
 * 429 with its own body), `transport_error` otherwise.
 */
function fallbackCode(status: number): CaptureErrorCode {
  if (status === 429) return 'rate_limited';
  if (status >= 500 && status < 600) return 'internal';
  return 'transport_error';
}

/**
 * Parse a `Retry-After` header — delta-seconds or an HTTP-date — into whole
 * seconds from now. A date in the past gives 0. Returns `undefined` when the
 * header is absent or unparsable.
 */
function parseRetryAfter(res: Response): number | undefined {
  const raw = res.headers?.get?.('Retry-After')?.trim();
  if (!raw) return undefined;
  if (/^\d+$/.test(raw)) return Number(raw);
  const at = Date.parse(raw);
  if (Number.isNaN(at)) return undefined;
  return Math.max(0, Math.ceil((at - Date.now()) / 1000));
}

function isRetryAfterSeconds(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

/** Known stable codes the server may return (mapped 1:1). */
const KNOWN_CODES: ReadonlySet<string> = new Set<CaptureErrorCode>([
  'unauthenticated',
  'invalid_request',
  'payload_too_large',
  'verification_failed',
  'idempotency_conflict',
  'chain_conflict',
  'evidence_id_conflict',
  'invalid_captured_at',
  'chain_sealed',
  'rate_limited',
  'store_unavailable',
  'internal',
]);

/**
 * Focused HTTP transport for the cloud capture path.
 *
 * Decoupled from `StorageAdapter` so it can be unit-tested directly with an
 * injected `fetchFn` and no network.
 */
export class HttpTransport {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchFn: FetchFn;
  private readonly timeoutMs: number;

  constructor(options: HttpTransportOptions) {
    this.apiKey = options.apiKey;
    this.baseUrl = (options.apiUrl ?? DEFAULT_API_URL).replace(/\/+$/, '');
    // Bind to preserve `this` when the global fetch is used.
    this.fetchFn =
      options.fetchFn ??
      ((url, init) => (globalThis.fetch as FetchFn)(url, init));
    this.timeoutMs =
      options.timeoutMs !== undefined && Number.isFinite(options.timeoutMs)
        ? options.timeoutMs
        : DEFAULT_CAPTURE_TIMEOUT_MS;
  }

  /** The resolved `/v1/evidence` URL (no trailing slash on the base). */
  get evidenceUrl(): string {
    return `${this.baseUrl}/v1/evidence`;
  }

  /**
   * POST a capture to `/v1/evidence`.
   *
   * @throws {TzunCaptureError} on any non-2xx response or network failure. The
   *   error carries the stable wire `error` code; the API key is never leaked.
   */
  async capture(req: CaptureRequest): Promise<CaptureSuccess> {
    const completeness: Completeness = req.completeness ?? 'partial';

    const body: Record<string, unknown> = { completeness };
    if (req.chainId !== undefined) body.chainId = req.chainId;
    if (completeness === 'raw') {
      if (req.payload !== undefined) body.payload = req.payload;
    } else if (req.envelope !== undefined) {
      body.envelope = req.envelope;
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json',
    };
    if (req.idempotencyKey !== undefined) {
      headers['Idempotency-Key'] = req.idempotencyKey;
    }

    // A capture POST is awaited inside the vendor intercept, so an unbounded
    // fetch makes the evidence service's availability the customer's
    // availability: a wedged backend stalls their handler for minutes and
    // exhausts their worker pool. Bound the WHOLE exchange — connect, headers
    // AND body read — with one deadline, and refuse redirects so a 3xx cannot
    // silently turn this POST into a GET that drops the envelope on the floor.
    const deadline = this.startDeadline();
    try {
      return await this.exchange(req, body, headers, deadline.controller, deadline.isTimedOut);
    } finally {
      deadline.clear();
    }
  }

  /**
   * One per-request deadline, armed for the whole exchange — connect, headers
   * and body read — so a wedged backend cannot stall a caller past
   * `timeoutMs`. `timeoutMs <= 0` arms nothing.
   */
  private startDeadline(): {
    controller: AbortController | undefined;
    isTimedOut: () => boolean;
    clear: () => void;
  } {
    const controller = this.timeoutMs > 0 ? new AbortController() : undefined;
    let timedOut = false;
    const timer =
      controller !== undefined
        ? setTimeout(() => {
            timedOut = true;
            controller.abort();
          }, this.timeoutMs)
        : undefined;
    // Never hold the process open on the deadline timer.
    (timer as { unref?: () => void } | undefined)?.unref?.();
    return {
      controller,
      isTimedOut: () => timedOut,
      clear: () => {
        if (timer !== undefined) clearTimeout(timer);
      },
    };
  }

  /**
   * The POST itself plus the response mapping, run under the caller's deadline.
   *
   * Split out of `capture()` only so the deadline timer can be cleared in one
   * `finally` that covers the body read as well as the fetch — aborting after
   * headers arrive but before the body does is a real stall shape.
   */
  private async exchange(
    req: CaptureRequest,
    body: Record<string, unknown>,
    headers: Record<string, string>,
    controller: AbortController | undefined,
    isTimedOut: () => boolean,
  ): Promise<CaptureSuccess> {
    let res: Response;
    try {
      res = await this.fetchFn(this.evidenceUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        redirect: 'error',
        ...(controller !== undefined ? { signal: controller.signal } : {}),
      });
    } catch (err) {
      // Network-level failure — retryable. Do NOT propagate the original error
      // (its message could, in theory, echo request details); use a generic
      // message that cannot contain the API key.
      throw this.networkError(err, isTimedOut());
    }

    if (res.status === 202 || res.ok) {
      let json: Partial<CaptureSuccess> | null;
      try {
        json = (await safeJson(res)) as Partial<CaptureSuccess> | null;
      } catch (err) {
        // A body that never arrives is the same outage as headers that never
        // arrive; the deadline covers both.
        throw this.networkError(err, isTimedOut());
      }
      if (!json || typeof json.evidenceId !== 'string') {
        throw new TzunCaptureError('transport_error', res.status, {
          retryable: true,
          message: 'Tzun cloud capture succeeded but returned an unexpected body shape',
        });
      }
      return {
        evidenceId: json.evidenceId,
        chainId: typeof json.chainId === 'string' ? json.chainId : (req.chainId ?? 'default'),
        sequence: typeof json.sequence === 'number' ? json.sequence : 0,
        canonicalDigest: typeof json.canonicalDigest === 'string' ? json.canonicalDigest : '',
        headDigest: typeof json.headDigest === 'string' ? json.headDigest : '',
      };
    }

    // Error path — extract the stable `error` code from the body.
    const errBody = (await safeJson(res)) as Record<string, unknown> | null;
    const wireCode = typeof errBody?.error === 'string' ? errBody.error : undefined;
    const code: CaptureErrorCode =
      wireCode && KNOWN_CODES.has(wireCode)
        ? (wireCode as CaptureErrorCode)
        : fallbackCode(res.status);

    // Carry through extra context fields (failedCheck, expectedPreviousDigest,
    // retryAfterSeconds, …) but NEVER copy anything that could contain the
    // key — the body is server-authored and contains no credentials.
    const context: Record<string, unknown> = {};
    if (errBody) {
      for (const [k, v] of Object.entries(errBody)) {
        if (k !== 'ok' && k !== 'error') context[k] = v;
      }
    }
    // The body's `retryAfterSeconds` wins; the `Retry-After` header fills in
    // when the body has no usable one (e.g. a proxy's 429).
    if (!isRetryAfterSeconds(context.retryAfterSeconds)) {
      const fromHeader = parseRetryAfter(res);
      if (fromHeader !== undefined) context.retryAfterSeconds = fromHeader;
    }

    throw new TzunCaptureError(code, res.status, {
      retryable: isRetryableStatus(res.status),
      context,
    });
  }

  /** Map a pre-response / mid-body failure to a typed, key-free error. */
  private networkError(err: unknown, timedOut: boolean): TzunCaptureError {
    if (timedOut) {
      return new TzunCaptureError('transport_error', 0, {
        retryable: true,
        message: `Tzun cloud capture failed: timed out after ${this.timeoutMs}ms`,
        context: { cause: 'timeout', timeoutMs: this.timeoutMs },
      });
    }
    return new TzunCaptureError('transport_error', 0, {
      retryable: true,
      message: 'Tzun cloud capture failed: network error reaching the backend',
      context: { cause: err instanceof Error ? err.name : 'unknown' },
    });
  }

  // ── Reads ────────────────────────────────────────────
  //
  // The customer read surface, scoped by the backend to the KEY's account and
  // env. Nothing here names a scope: the key does, which is why a request
  // cannot reach across accounts or into the other env.

  /** The resolved `/v1/app/evidence` URL. */
  get evidenceReadUrl(): string {
    return `${this.baseUrl}/v1/app/evidence`;
  }

  /**
   * The URL of one record's resource, or `null` for an id no record can have:
   * `''`, `'.'` and `'..'` survive `encodeURIComponent` and a URL resolver
   * reads them as path segments, so `/evidence/.` would name the list route
   * and `/evidence/..` the parent.
   */
  private recordUrl(evidenceId: string, suffix = ''): string | null {
    if (typeof evidenceId !== 'string' || evidenceId === '' || evidenceId === '.' || evidenceId === '..') return null;
    return `${this.evidenceReadUrl}/${encodeURIComponent(evidenceId)}${suffix}`;
  }

  /**
   * GET `/v1/app/evidence/:id` — one record with the verdict on it.
   *
   * `null` when the key's scope holds no such record, which is the same answer
   * the backend gives for another account's id: it cannot be probed.
   *
   * @throws {TzunReadError} on any other non-2xx response or network failure.
   */
  async retrieve(evidenceId: string): Promise<EvidenceRead | null> {
    const url = this.recordUrl(evidenceId);
    if (url === null) return null;
    const read = await this.read<EvidenceRead>(url, 'retrieve', { notFoundIsNull: true });
    if (read === null) return null;
    if (!read.envelope || !read.verdict) {
      throw this.shapeError('retrieve');
    }
    // Projected, not passed through: an `EvidenceRead` is the record and the
    // verdict, and a field the server adds later must not silently become part
    // of what a local read and a cloud read have in common.
    return { envelope: read.envelope, verdict: read.verdict };
  }

  /**
   * GET `/v1/app/evidence?include=envelope` — a page of whole records, each
   * with the verdict on it, newest first.
   *
   * Only `limit` and `offset` are sent, because they are the only filters the
   * endpoint applies. A `ListOptions` naming anything else — `aiSystemId`,
   * `chainId`, or `order: 'asc'` — is refused rather than answered with a page
   * that quietly ignored it.
   */
  async list(options?: ListOptions): Promise<EvidenceRead[]> {
    const unsupportedFilter = unsupportedListFilter(options);
    if (unsupportedFilter !== null) {
      throw new TzunCloudReadUnsupportedError(`list (${unsupportedFilter})`);
    }
    const url = new URL(this.evidenceReadUrl);
    url.searchParams.set('include', 'envelope');
    if (options?.limit !== undefined) url.searchParams.set('limit', String(options.limit));
    if (options?.offset !== undefined) url.searchParams.set('offset', String(options.offset));

    const body = await this.read<{ evidence?: unknown }>(url.toString(), 'list');
    const page = body?.evidence;
    if (!Array.isArray(page)) throw this.shapeError('list');
    return page.map((item) => {
      const row = item as Partial<EvidenceRead>;
      if (!row.envelope || !row.verdict) throw this.shapeError('list');
      return { envelope: row.envelope, verdict: row.verdict };
    });
  }

  /**
   * GET `/v1/app/evidence/:id/verify` — the same three checks the read carries,
   * with the chain link measured against the record at the previous sequence of
   * the record's chain, plus the `chain` block naming what it was measured
   * against.
   *
   * `null` when the key's scope holds no such record.
   */
  async verify(evidenceId: string): Promise<CloudVerification | null> {
    const url = this.recordUrl(evidenceId, '/verify');
    if (url === null) return null;
    const body = await this.read<CloudVerification>(url, 'verify', { notFoundIsNull: true });
    if (body === null) return null;
    if (!body.verdict || !body.chain) throw this.shapeError('verify');
    return { evidenceId: body.evidenceId, verdict: body.verdict, chain: body.chain };
  }

  /**
   * GET `/v1/app/evidence/:id/export` — the DEO bundle, which is the bundle the
   * portal downloads for the same record.
   *
   * `null` when the key's scope holds no such record.
   */
  async exportEvidence(evidenceId: string): Promise<CloudExportBundle | null> {
    const url = this.recordUrl(evidenceId, '/export');
    if (url === null) return null;
    const body = await this.read<CloudExportBundle>(url, 'export', { notFoundIsNull: true });
    if (body === null) return null;
    if (!body.envelope || !body.verdict || !body.chain || !body.server) {
      throw this.shapeError('export');
    }
    return body;
  }

  // ── Catalog (the model and agent descriptor endpoints) ────────────────────
  //
  // Scoped by the backend to the key's account and env, like the reads above.
  // The wire shapes are fixed in the SDK 0.8.0 cloud catalog contract
  // (`POST /v1/models`, `GET /v1/models/:digest`, `POST /v1/agents`,
  // `GET /v1/agents/:digest`, `GET /v1/agents`).

  /**
   * One authenticated catalog request under the per-request deadline.
   *
   * Answers the 2xx body, or what the platform said instead:
   *   - `not_found` with the body's `error` code for a 404 whose body is a
   *     JSON object carrying one, which the caller reads (a digest the
   *     catalog does not hold, or a route the platform does not serve: its
   *     catch-all answers `not_found`);
   *   - `absent` for a 405 or 501, a route the platform does not serve.
   *
   * @throws {TzunCatalogError} on any other non-2xx response (a 404 without
   *   that body, such as an edge's HTML page during a deploy, is a retryable
   *   `transport_error`), a network failure or timeout, and a 2xx whose body
   *   is not a JSON object.
   */
  async catalog(
    method: 'GET' | 'POST',
    path: string,
    operation: CatalogOperation,
    body?: unknown,
  ): Promise<CatalogAnswer> {
    const deadline = this.startDeadline();
    try {
      let res: Response;
      try {
        const headers: Record<string, string> = {
          Authorization: `Bearer ${this.apiKey}`,
          Accept: 'application/json',
        };
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        res = await this.fetchFn(`${this.baseUrl}${path}`, {
          method,
          headers,
          ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
          redirect: 'error',
          ...(deadline.controller !== undefined ? { signal: deadline.controller.signal } : {}),
        });
      } catch (err) {
        throw catalogNetworkError(operation, err, deadline.isTimedOut(), this.timeoutMs);
      }

      if (res.ok) {
        let json: unknown;
        try {
          json = await safeJson(res);
        } catch (err) {
          throw catalogNetworkError(operation, err, deadline.isTimedOut(), this.timeoutMs);
        }
        if (json === null || typeof json !== 'object' || Array.isArray(json)) {
          throw catalogShapeError(operation, res.status);
        }
        return { kind: 'ok', status: res.status, body: json as Record<string, unknown> };
      }

      const parsed = await safeJson(res);
      const errBody =
        parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
      const wireCode = typeof errBody?.error === 'string' ? errBody.error : undefined;
      if (res.status === 404) {
        if (wireCode !== undefined) return { kind: 'not_found', code: wireCode };
        throw new TzunCatalogError('transport_error', 404, {
          operation,
          retryable: true,
          message: `Tzun cloud ${operation} failed: a 404 that is not the platform's (no JSON error code)`,
          context: { cause: 'unrecognised_not_found' },
        });
      }
      if (res.status === 405 || res.status === 501) return { kind: 'absent' };

      const code: CatalogErrorCode =
        wireCode && KNOWN_CATALOG_CODES.has(wireCode)
          ? (wireCode as CatalogErrorCode)
          : fallbackCatalogCode(res.status);
      // Server-authored context only; the body holds no credentials.
      const context: Record<string, unknown> = {};
      if (errBody) {
        for (const [k, v] of Object.entries(errBody)) {
          if (k !== 'ok' && k !== 'error') context[k] = v;
        }
      }
      if (!isRetryAfterSeconds(context.retryAfterSeconds)) {
        const fromHeader = parseRetryAfter(res);
        if (fromHeader !== undefined) context.retryAfterSeconds = fromHeader;
      }
      throw new TzunCatalogError(code, res.status, {
        operation,
        retryable: isRetryableStatus(res.status),
        context,
      });
    } finally {
      deadline.clear();
    }
  }

  /**
   * One authenticated GET under the per-request deadline, with the wire `error`
   * code carried into a {@link TzunReadError}. Redirects are refused so a 3xx
   * cannot silently point the read at another origin with the key attached.
   */
  private async read<T>(
    url: string,
    operation: string,
    opts: { notFoundIsNull?: boolean } = {},
  ): Promise<T | null> {
    const deadline = this.startDeadline();
    try {
      let res: Response;
      try {
        res = await this.fetchFn(url, {
          method: 'GET',
          headers: { Authorization: `Bearer ${this.apiKey}`, Accept: 'application/json' },
          redirect: 'error',
          ...(deadline.controller !== undefined ? { signal: deadline.controller.signal } : {}),
        });
      } catch (err) {
        throw this.readNetworkError(operation, err, deadline.isTimedOut());
      }

      if (res.ok) {
        let json: unknown;
        try {
          json = await safeJson(res);
        } catch (err) {
          // A body that never arrives is the same outage as headers that never
          // arrive; the deadline covers both.
          throw this.readNetworkError(operation, err, deadline.isTimedOut());
        }
        if (json === null || typeof json !== 'object') throw this.shapeError(operation);
        return json as T;
      }

      if (res.status === 404 && opts.notFoundIsNull === true) return null;

      const errBody = (await safeJson(res)) as Record<string, unknown> | null;
      const wireCode = typeof errBody?.error === 'string' ? errBody.error : undefined;
      const code: ReadErrorCode =
        wireCode && KNOWN_READ_CODES.has(wireCode)
          ? (wireCode as ReadErrorCode)
          : fallbackReadCode(res.status);

      // Carry through the server-authored context fields but never anything that
      // could contain the key — the body holds no credentials.
      const context: Record<string, unknown> = {};
      if (errBody) {
        for (const [k, v] of Object.entries(errBody)) {
          if (k !== 'ok' && k !== 'error') context[k] = v;
        }
      }
      if (!isRetryAfterSeconds(context.retryAfterSeconds)) {
        const fromHeader = parseRetryAfter(res);
        if (fromHeader !== undefined) context.retryAfterSeconds = fromHeader;
      }

      throw new TzunReadError(code, res.status, {
        operation,
        retryable: isRetryableStatus(res.status),
        context,
      });
    } finally {
      deadline.clear();
    }
  }

  /** Map a pre-response / mid-body read failure to a typed, key-free error. */
  private readNetworkError(operation: string, err: unknown, timedOut: boolean): TzunReadError {
    if (timedOut) {
      return new TzunReadError('transport_error', 0, {
        operation,
        retryable: true,
        message: `Tzun cloud ${operation} failed: timed out after ${this.timeoutMs}ms`,
        context: { cause: 'timeout', timeoutMs: this.timeoutMs },
      });
    }
    return new TzunReadError('transport_error', 0, {
      operation,
      retryable: true,
      message: `Tzun cloud ${operation} failed: network error reaching the backend`,
      context: { cause: err instanceof Error ? err.name : 'unknown' },
    });
  }

  /**
   * A 2xx whose body is not the shape the operation returns. Retryable, and
   * NEVER answered with an empty result: `[]` or `null` here would be read
   * upstream as "the server holds nothing and nothing is wrong".
   */
  private shapeError(operation: string): TzunReadError {
    return new TzunReadError('transport_error', 200, {
      operation,
      retryable: true,
      message: `Tzun cloud ${operation} returned an unexpected body shape`,
    });
  }
}

/**
 * Stable error codes a customer read can answer with. `not_found` reaches the
 * caller only where the operation does not map it to `null`; `rate_limited`
 * (429) is retryable and carries `retryAfterSeconds` in `context`, and
 * `context.scope` names which allowance was spent (`api-key` for the per-key
 * read window). `transport_error` is synthetic — a network failure, a timeout,
 * or a 2xx body that is not the shape the operation returns.
 */
export type ReadErrorCode =
  | 'unauthenticated'
  | 'invalid_session'
  | 'session_expired'
  | 'account_not_active'
  | 'not_found'
  | 'invalid_request'
  | 'rate_limited'
  | 'internal_error'
  | 'internal'
  | 'transport_error';

/** The codes the backend's read routes send, mapped 1:1. */
const KNOWN_READ_CODES: ReadonlySet<string> = new Set<ReadErrorCode>([
  'unauthenticated',
  'invalid_session',
  'session_expired',
  'account_not_active',
  'not_found',
  'invalid_request',
  'rate_limited',
  'internal_error',
  'internal',
]);

/** The code for an error response whose body carries no known code. */
function fallbackReadCode(status: number): ReadErrorCode {
  if (status === 401) return 'unauthenticated';
  if (status === 404) return 'not_found';
  if (status === 429) return 'rate_limited';
  if (status >= 500 && status < 600) return 'internal';
  return 'transport_error';
}

/**
 * A typed cloud READ failure that carries the stable wire `error` code, the same
 * way {@link TzunCaptureError} does for a capture.
 *
 * The API key is never placed into `message` or `context`.
 */
export class TzunReadError extends Error {
  /** Stable wire `error` code. */
  readonly code: ReadErrorCode;
  /** HTTP status, or 0 for a pre-response network failure. */
  readonly status: number;
  /** Which read failed: `retrieve`, `list`, `verify` or `export`. */
  readonly operation: string;
  /** Whether the caller may safely retry (network / 429 / 5xx). */
  readonly retryable: boolean;
  /** Extra fields from the error body (e.g. `retryAfterSeconds`, `scope`). */
  readonly context: Record<string, unknown>;

  constructor(
    code: ReadErrorCode,
    status: number,
    options: {
      operation: string;
      retryable?: boolean;
      context?: Record<string, unknown>;
      message?: string;
    },
  ) {
    super(
      options.message ??
        `Tzun cloud ${options.operation} failed: ${code} (HTTP ${status})`,
    );
    this.name = 'TzunReadError';
    this.code = code;
    this.status = status;
    this.operation = options.operation;
    this.retryable = options.retryable ?? false;
    this.context = options.context ?? {};
    // Restore prototype chain for `instanceof` across the ts-jest/CJS boundary.
    Object.setPrototypeOf(this, TzunReadError.prototype);
  }
}

/**
 * The first `ListOptions` field the read endpoint cannot apply, or `null` when
 * every field it carries is one the endpoint honours.
 *
 * The endpoint pages an account's records newest first and filters by nothing
 * else, so a filter it cannot apply must refuse rather than return a page that
 * looks filtered and is not — the same reason the unsupported reads below throw
 * instead of answering `[]`.
 */
function unsupportedListFilter(options?: ListOptions): string | null {
  if (options === undefined) return null;
  if (options.aiSystemId !== undefined) return 'aiSystemId';
  if (options.chainId !== undefined) return 'chainId';
  if (options.order !== undefined && options.order !== 'desc') return `order: '${options.order}'`;
  return null;
}

/** What `GET /v1/app/evidence/:id/verify` answers. */
export interface CloudVerification {
  evidenceId: string;
  verdict: RecordVerdict;
  chain: ExportedChainPosition;
}

/**
 * What `GET /v1/app/evidence/:id/export` answers: the DEO bundle the portal
 * downloads. `verdict` and `chain` are the same blocks, under the same names, as
 * the SDK's own export bundle, and `server.custody` carries the ledger rows in
 * the same field names — so one offline verifier reads either bundle.
 */
export interface CloudExportBundle {
  /** The record, verbatim: its digest must keep verifying byte-for-byte. */
  envelope: EvidenceEnvelope;
  /** The platform's `recordVerdict` on the record, chain link included. */
  verdict: RecordVerdict;
  /** The predecessor, so `integrity.chainLink` can be recomputed offline. */
  chain: ExportedChainPosition;
  /** Receipt metadata the platform attests, beside the record's own claims. */
  server: {
    receivedAt: string | null;
    attestation: {
      state: 'pending' | 'attested' | 'failed';
      status: string;
      claimedStatus: string | null;
      rfc3161Token: string | null;
      artifact: unknown;
    };
    custody: {
      hashPreimage: string;
      /** `null` when the platform could not read the ledger. */
      entries: CustodyLedgerEntry[] | null;
      /** The ledger-against-mirror verdict; `null` when `entries` is. */
      trail: CustodyLedgerVerdict | null;
      /** `verifyCustodyTrail` over the envelope alone. */
      offlineTrail: CustodyTrailVerdict | null;
    };
  };
}

/** Read a JSON body without throwing on empty/invalid payloads. */
async function safeJson(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * A cloud read/catalog/recovery operation this transport-only adapter cannot
 * honour.
 *
 * Thrown INSTEAD of returning an empty list or a null. Returning `[]`/`0`/`null`
 * from a read the adapter never performed is indistinguishable, to every caller
 * upstream, from "the server holds nothing and nothing is wrong" — which is how
 * `verifyChainCompleteness()`, `verifyRange()` and the scheduled scanner came to
 * report a permanent clean bill of health on evidence they had never read.
 */
export class TzunCloudReadUnsupportedError extends Error {
  /** Stable discriminator for callers that branch on the cause. */
  readonly code = 'cloud_read_unsupported' as const;
  /** The `StorageAdapter` method that was called. */
  readonly method: string;

  constructor(method: string) {
    super(
      `HttpStorageAdapter.${method} is not supported in cloud transport mode — ` +
        'this operation requires a server round-trip not implemented in this build. ' +
        'It throws rather than returning empty data, because an empty result would ' +
        'be read upstream as "verified, nothing wrong".',
    );
    this.name = 'TzunCloudReadUnsupportedError';
    this.method = method;
    // Restore prototype chain for `instanceof` across the ts-jest/CJS boundary.
    Object.setPrototypeOf(this, TzunCloudReadUnsupportedError.prototype);
  }
}

/** Which catalog operation a {@link TzunCatalogError} or a {@link CatalogAnswer} is about. */
export type CatalogOperation =
  | 'models.register'
  | 'models.get'
  | 'agents.register'
  | 'agents.get'
  | 'agents.list';

/** What {@link HttpTransport.catalog} answered. */
export type CatalogAnswer =
  | { kind: 'ok'; status: number; body: Record<string, unknown> }
  | { kind: 'not_found'; code: string }
  | { kind: 'absent' };

/**
 * Whether an answer says the platform does not serve the route: a 405, a
 * 501, or the catch-all's JSON `404 { error: 'not_found' }`. A catalog route
 * that is served never answers `not_found` (the contract's "not held" codes
 * are `descriptor_not_registered` and `agent_not_registered`).
 */
function routeNotServed(answer: CatalogAnswer): boolean {
  return answer.kind === 'absent' || (answer.kind === 'not_found' && answer.code === 'not_found');
}

/**
 * A JSON 404 a catalog route answered with a code it does not use for that
 * request. Retryable: the next call asks again, and nothing is concluded
 * about the catalog.
 */
function unexpectedNotFound(operation: CatalogOperation, code: string): TzunCatalogError {
  return new TzunCatalogError('transport_error', 404, {
    operation,
    retryable: true,
    message: `Tzun cloud ${operation} failed: an unexpected 404 (${code})`,
    context: { cause: 'unexpected_not_found', error: code },
  });
}

/**
 * Stable error codes a catalog request can answer with. `digest_mismatch` is
 * the SDK's own: the platform answered a registration with a digest other than
 * the one the SDK computed over the same bytes, or a lookup with a row whose
 * bytes do not hash to the digest asked for, and the SDK never records or
 * returns a digest it did not compute. `transport_error` is synthetic, as for
 * reads.
 */
export type CatalogErrorCode =
  | 'unauthenticated'
  | 'forbidden'
  | 'invalid_request'
  | 'payload_too_large'
  | 'rate_limited'
  | 'store_unavailable'
  | 'internal_error'
  | 'internal'
  | 'digest_mismatch'
  | 'transport_error';

/** The codes the backend's catalog routes send, mapped 1:1. */
const KNOWN_CATALOG_CODES: ReadonlySet<string> = new Set<CatalogErrorCode>([
  'unauthenticated',
  'forbidden',
  'invalid_request',
  'payload_too_large',
  'rate_limited',
  'store_unavailable',
  'internal_error',
  'internal',
]);

/** The code for a catalog error response whose body carries no known code. */
function fallbackCatalogCode(status: number): CatalogErrorCode {
  if (status === 401) return 'unauthenticated';
  if (status === 403) return 'forbidden';
  if (status === 413) return 'payload_too_large';
  if (status === 429) return 'rate_limited';
  if (status >= 500 && status < 600) return 'internal';
  return 'transport_error';
}

/**
 * A typed failure of a catalog request (a descriptor registration or lookup),
 * carrying the stable wire `error` code the way {@link TzunReadError} does for
 * a read. The API key is never placed into `message` or `context`.
 */
export class TzunCatalogError extends Error {
  /** Stable wire `error` code, or the SDK's `digest_mismatch` / `transport_error`. */
  readonly code: CatalogErrorCode;
  /** HTTP status, or 0 for a pre-response network failure. */
  readonly status: number;
  /** Which catalog operation failed. */
  readonly operation: CatalogOperation;
  /** Whether the caller may safely retry (network / 429 / 5xx). */
  readonly retryable: boolean;
  /** Extra fields from the error body (e.g. `reason`, `field`, `retryAfterSeconds`). */
  readonly context: Record<string, unknown>;

  constructor(
    code: CatalogErrorCode,
    status: number,
    options: {
      operation: CatalogOperation;
      retryable?: boolean;
      context?: Record<string, unknown>;
      message?: string;
    },
  ) {
    super(options.message ?? `Tzun cloud ${options.operation} failed: ${code} (HTTP ${status})`);
    this.name = 'TzunCatalogError';
    this.code = code;
    this.status = status;
    this.operation = options.operation;
    this.retryable = options.retryable ?? false;
    this.context = options.context ?? {};
    // Restore prototype chain for `instanceof` across the ts-jest/CJS boundary.
    Object.setPrototypeOf(this, TzunCatalogError.prototype);
  }
}

/** Map a pre-response / mid-body catalog failure to a typed, key-free error. */
function catalogNetworkError(
  operation: CatalogOperation,
  err: unknown,
  timedOut: boolean,
  timeoutMs: number,
): TzunCatalogError {
  if (timedOut) {
    return new TzunCatalogError('transport_error', 0, {
      operation,
      retryable: true,
      message: `Tzun cloud ${operation} failed: timed out after ${timeoutMs}ms`,
      context: { cause: 'timeout', timeoutMs },
    });
  }
  return new TzunCatalogError('transport_error', 0, {
    operation,
    retryable: true,
    message: `Tzun cloud ${operation} failed: network error reaching the backend`,
    context: { cause: err instanceof Error ? err.name : 'unknown' },
  });
}

/**
 * A 2xx catalog answer that is not the shape the operation returns. Retryable,
 * and never read as "not registered": `null` here would turn a broken answer
 * into a refusal of the caller's capture.
 */
function catalogShapeError(operation: CatalogOperation, status: number): TzunCatalogError {
  return new TzunCatalogError('transport_error', status, {
    operation,
    retryable: true,
    message: `Tzun cloud ${operation} returned an unexpected body shape`,
  });
}

/**
 * A platform answer naming, or holding bytes that hash to, a digest other
 * than the one the SDK computed or asked for. Not retryable: the SDK never
 * records or returns a digest it did not compute.
 */
function digestMismatch(
  operation: CatalogOperation,
  status: number,
  expectedDigest: string,
  answeredDigest: string,
): TzunCatalogError {
  return new TzunCatalogError('digest_mismatch', status, {
    operation,
    message:
      operation === 'models.get' || operation === 'agents.get'
        ? `Tzun cloud ${operation} answered a row whose bytes do not hash to the digest asked for`
        : `Tzun cloud ${operation} answered a digest other than the one computed over the descriptor sent`,
    context: { expectedDigest, answeredDigest },
  });
}

/**
 * The platform's refusal of a listing's `limit` or `cursor` (`400
 * invalid_request` naming the field, or reason `invalid_pagination`), as the
 * `InvalidPaginationError` a local store throws; `null` for any other error.
 */
function paginationRefusal(
  error: unknown,
  query: { limit: number; cursor: string | null },
): InvalidPaginationError | null {
  if (!(error instanceof TzunCatalogError) || error.status !== 400 || error.code !== 'invalid_request') return null;
  const { field, reason } = error.context;
  if (field === 'limit') return new InvalidPaginationError('limit', query.limit);
  if (field === 'cursor' || (reason === 'invalid_pagination' && query.cursor !== null)) {
    return new InvalidPaginationError('cursor', query.cursor);
  }
  if (reason === 'invalid_pagination') return new InvalidPaginationError('limit', query.limit);
  return null;
}

/**
 * The store keeps no model catalog: the cloud transport against a platform
 * that does not serve `POST /v1/models`. Thrown by
 * `HttpStorageAdapter.registerModelDescriptor`; the wrappers read it as "the
 * model cannot be recorded" (`capture_model_not_recordable`), and `capture()`
 * refuses an inline step descriptor with `invalid_step_ai_bom`, as on a store
 * whose adapter has no `registerModelDescriptor`.
 */
export class ModelCatalogUnsupportedError extends Error {
  readonly code = 'model_catalog_not_supported_by_store' as const;
  constructor() {
    super('This store keeps no model catalog: the platform does not serve POST /v1/models.');
    this.name = 'ModelCatalogUnsupportedError';
    Object.setPrototypeOf(this, ModelCatalogUnsupportedError.prototype);
  }
}

/** Whether an error is a store's answer that it keeps no model catalog. */
export function isModelCatalogUnsupported(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { code?: unknown }).code === 'model_catalog_not_supported_by_store'
  );
}

/**
 * How long the adapter takes a platform's "route not served" answer as
 * standing before it asks again, in milliseconds. A platform without the
 * catalog endpoints costs one probe per window, not one per wrapped call, and
 * a platform upgraded under a running client is used within one window.
 */
export const CATALOG_REPROBE_MS = 5 * 60_000;

/** Catalog rows each kind keeps in the adapter's cache. Rows are immutable, so a cached row never goes stale. */
const CATALOG_ROW_CACHE_SIZE = 256;

/**
 * Cloud `StorageAdapter`.
 *
 * Slots into the SDK's existing `this.storage` seam: `Tzun.capture()` calls
 * `await this.storage.store(envelope, chainId)` and then re-reads the head.
 *
 * The server is authoritative. It re-stamps `partial` captures onto its own
 * locked chain head (`sequence = headSeq + 1`, digest recomputed because
 * `sequenceNumber` is a hashed field) and rejects any non-null `chainLink` that
 * does not verify against THAT head. So this adapter must track the head the
 * server reports, not a head of its own invention:
 *
 *   - `store()` keeps the `CaptureSuccess` the wire already returns. Without
 *     it, `getLastDigest()`/`getLastSequence()` would return `null`/`0`
 *     forever, `Tzun.capture()` would link from and advance a purely LOCAL
 *     head, and the second capture against any non-virgin server chain would
 *     be rejected with `chain_conflict` — permanently, because the local head
 *     only advances on success. Every decision after the first would be
 *     silently dropped.
 *   - On a `chain_conflict` the server tells us its real head in
 *     `expectedPreviousDigest`. Adopting it makes the next capture link
 *     correctly instead of wedging the chain for the life of the process.
 *   - Read/catalog/recovery methods that require a server round-trip THROW
 *     (see {@link TzunCloudReadUnsupportedError}) rather than returning empty
 *     data that upstream verifiers read as "clean".
 *
 * This adapter is constructed ONLY when `apiKey` is present, so local modes are
 * unaffected.
 */
export class HttpStorageAdapter implements StorageAdapter {
  /**
   * Each chain's head as the SERVER last reported it — not a local invention.
   * An absent entry means "we have not been told yet about THIS chain" (nothing
   * stored to it in this process and no conflict observed on it), which is the
   * only honest genesis default.
   *
   * Keyed by chain id, because the backend's own chain state is:
   * a head belongs to one chain and says nothing about any other. One shared
   * head was invisible while an instance wrote a single chain — the shape
   * `Tzun.init({ chainId })` produces — and wrong as soon as one adapter was
   * handed two, in a way that never surfaced as an error: chain B's append
   * linked from chain A's head, the server refused it with `chain_conflict`,
   * and the head adopted from that refusal then overwrote A's. The two chains
   * took turns invalidating each other, so every capture paid a wasted round
   * trip — and, with a client-side attestation, a wasted TSA round trip.
   */
  private readonly serverHeads = new Map<string, { digest: string; sequence: number }>();

  /**
   * The server's authoritative stamp for the most recent successful `store()`.
   * `Tzun.capture()` surfaces this as `CaptureResult.serverReceipt` so callers
   * can see the sequence/digest actually recorded, which for the first capture
   * of a process against a non-virgin chain is NOT the one in the local
   * envelope they were handed.
   */
  private lastReceipt: CaptureSuccess | null = null;

  /**
   * Until when (epoch ms) each catalog is taken as not served by the platform:
   * `models` (`POST /v1/models`, `GET /v1/models/:digest`), `agents`
   * (`POST /v1/agents`, `GET /v1/agents/:digest`) and `agents.list`
   * (`GET /v1/agents`, which a platform may serve without the list). Set by a
   * "route not served" answer and kept for {@link CATALOG_REPROBE_MS}.
   */
  private readonly catalogAbsentUntil = new Map<'models' | 'agents' | 'agents.list', number>();

  /**
   * Until when (epoch ms) the agent catalog is taken as served, after a 2xx
   * from one of its routes; kept for {@link CATALOG_REPROBE_MS}, so a
   * platform rolled back to a build without the routes is noticed within
   * one window.
   */
  private agentCatalogServedUntil = 0;

  /** Model descriptor rows read from the platform, by digest (immutable, so never stale). */
  private readonly modelRows = new Map<string, ModelDescriptorRow>();

  /** Agent descriptor rows read from the platform, by digest (immutable, so never stale). */
  private readonly agentRows = new Map<string, AgentDescriptorRow>();

  constructor(private readonly transport: HttpTransport) {}

  /**
   * The chain a `chainId` argument names, as the wire resolves it.
   *
   * `store()` omits a falsy id and the literal `'default'` from the request, and
   * the server resolves an omitted id to `'default'` — so all three name one
   * chain and must share one cache entry.
   */
  private static chainKey(chainId?: string): string {
    return chainId || DEFAULT_CHAIN_ID;
  }

  /** POST the envelope to the backend. Server is authoritative. */
  async store(envelope: EvidenceEnvelope, chainId?: string, options?: StoreOptions): Promise<void> {
    const chainKey = HttpStorageAdapter.chainKey(chainId);
    try {
      const ok = await this.transport.capture({
        completeness: 'partial',
        envelope,
        chainId: chainId && chainId !== 'default' ? chainId : undefined,
        ...(options?.idempotencyKey ? { idempotencyKey: options.idempotencyKey } : {}),
      });
      this.lastReceipt = ok;
      // `headDigest` is the just-committed record's canonical digest (the
      // backend sets `headDigest: canonicalDigest`), i.e. exactly what the next
      // capture must link from.
      if (ok.headDigest) {
        this.serverHeads.set(chainKey, { digest: ok.headDigest, sequence: ok.sequence });
      }
      return;
    } catch (err) {
      if (err instanceof TzunCaptureError && err.code === 'chain_conflict') {
        // The 409 body carries the server's real head. Adopt it so the NEXT
        // build links from the truth. Without this a single conflict (a
        // second writer, a replica, an idempotent replay) wedges the chain for
        // the life of the process.
        //
        // The sequence is on the wire only for one refusal, and there it is
        // essential. An un-attested partial is re-stamped by the backend onto
        // its own locked head, so a stale `sequenceNumber` costs nothing and
        // the following success resyncs it. An ATTESTED partial cannot be
        // re-stamped — the token or signature attests one digest, and the
        // sequence number is hashed into it — so the backend refuses with
        // `reason: 'attested_envelope_cannot_be_restamped'` and names the
        // sequence it would have assigned as `expectedSequence`. Adopting
        // only the digest from that body would make the retry rebuild the
        // record at the SAME stale sequence, be refused for the same reason,
        // and so on until `chainConflictMaxAttempts` ran out: ten builds, ten
        // paid TSA round trips, nothing stored, on every capture after any
        // restart on a non-empty chain. Adopting the sequence too lands the
        // next build at exactly the position named.
        const expected = err.context['expectedPreviousDigest'];
        const expectedSequence = err.context['expectedSequence'];
        const sequence =
          typeof expectedSequence === 'number' &&
          Number.isInteger(expectedSequence) &&
          expectedSequence >= 1
            ? expectedSequence - 1
            : (this.serverHeads.get(chainKey)?.sequence ?? 0);
        // Scoped to the chain the refused append named: a 409 describes that
        // chain's head and says nothing about any other chain in the store.
        if (expected === null) {
          this.serverHeads.delete(chainKey);
        } else if (typeof expected === 'string' && expected.length > 0) {
          this.serverHeads.set(chainKey, { digest: expected, sequence });
        }
      }
      throw err;
    }
  }

  // ── Chain-restore reads: the named chain's head, as last reported ─────────
  async getLastDigest(chainId?: string): Promise<string | null> {
    return this.serverHeads.get(HttpStorageAdapter.chainKey(chainId))?.digest ?? null;
  }
  async getLastSequence(chainId?: string): Promise<number> {
    return this.serverHeads.get(HttpStorageAdapter.chainKey(chainId))?.sequence ?? 0;
  }
  /**
   * The constant `'default'`, read nowhere — and deliberately not a resolution.
   *
   * This keeps being re-filed as a stub, so: `getActiveChainId()` is consulted
   * only when the config names no `chainId` (`src/sdk/index.ts`:
   * `config?.chainId ?? await storage.getActiveChainId()`), the server's own
   * default chain is also `'default'`, and the server resolves the chain on its
   * side — the SDK reads no chain rows over HTTP. So this is the same "no chain
   * was named" answer the local adapters give for a store with no identity rows,
   * not a guess at which of several chains is live. The local adapters' rule
   * (`resolveActiveChainId`, and the `NoActiveChainError` /
   * `AmbiguousActiveChainError` it raises) exists because they CAN see several
   * chains and must not pick one silently; this adapter can see none, so there
   * is nothing to pick and nothing to refuse.
   *
   * The per-chain head cache above is unrelated: it records where each chain the
   * caller named actually is, and does not make this adapter able to enumerate
   * the chains the server holds.
   */
  async getActiveChainId(): Promise<string> {
    return DEFAULT_CHAIN_ID;
  }
  async resetChainState(chainId?: string): Promise<void> {
    // The server owns chain state; drop our cached view of THIS chain so its
    // next capture re-links from whatever the server reports. Scoped to one
    // chain, as on the SQL adapters: one chain forking says nothing about the
    // heads of the others.
    const chainKey = HttpStorageAdapter.chainKey(chainId);
    this.serverHeads.delete(chainKey);
    // The receipt is the last successful store, whichever chain that was; it is
    // stale only if it belongs to the chain being reset.
    if (this.lastReceipt && HttpStorageAdapter.chainKey(this.lastReceipt.chainId) === chainKey) {
      this.lastReceipt = null;
    }
  }

  /**
   * The server's stamp for the most recent successful `store()`, or `null` if
   * this adapter has not stored anything yet.
   */
  getLastStoredReceipt(): CaptureSuccess | null {
    return this.lastReceipt;
  }

  // ── Failure capture is best-effort local; nothing to persist remotely here.
  // KNOWN GAP: a dropped cloud capture leaves no
  // FailureRecord anywhere. This must stay a no-op rather than throw —
  // `Tzun.capture()` calls it from its catch block, so throwing would convert
  // `{ stored: false, failure }` into a rejected promise for every caller.
  async storeFailure(_failure: FailureRecord): Promise<void> {
    /* no-op: cloud captures fail via thrown TzunCaptureError, not stored FailureRecords */
  }

  // ── The four customer reads, served by the backend ────
  //
  // Each is scoped by the SERVER to the key's own account and env — the request
  // names no scope — and each carries the platform's `RecordVerdict` on the
  // record, in the engine's shape. A record the key's scope does not hold is
  // `null`, exactly as a record that does not exist is, so an id cannot be
  // probed across accounts or envs.

  /** One record with the server's verdict on it, or `null`. */
  async retrieveWithVerdict(evidenceId: string): Promise<EvidenceRead | null> {
    return this.transport.retrieve(evidenceId);
  }

  /** A page of records, each with the server's verdict on it. */
  async listWithVerdicts(options?: ListOptions): Promise<EvidenceRead[]> {
    return this.transport.list(options);
  }

  /**
   * The verdict with the chain link measured against the record at the previous
   * sequence of its chain, and the `chain` block naming what it was measured
   * against. `null` when the key's scope holds no such record.
   */
  async verifyRecord(evidenceId: string): Promise<CloudVerification | null> {
    return this.transport.verify(evidenceId);
  }

  /**
   * The DEO export bundle the server holds for the record — the same bundle the
   * portal downloads. `null` when the key's scope holds no such record.
   */
  async exportEvidence(evidenceId: string): Promise<CloudExportBundle | null> {
    return this.transport.exportEvidence(evidenceId);
  }

  // ── The model and agent catalogs, served by the backend ──────────────────
  //
  // Each catalog is the key's own account and env. A platform that does not
  // serve a catalog's routes makes this a store without that catalog for
  // CATALOG_REPROBE_MS: model registration throws
  // ModelCatalogUnsupportedError and a model lookup answers `null`; the agent
  // methods throw AgentCatalogUnsupportedError, which `tzun.agents` reports
  // and export reads as `catalog_absent`. Capture reads neither catalog for
  // an agent reference: the platform checks those itself.
  //
  // "Not served" is a 405, a 501, or the catch-all's JSON
  // `404 { error: 'not_found' }` on a write. A 404 without a JSON error code
  // (an edge's page during a deploy) is a retryable `transport_error`, and
  // decides nothing. A JSON 404 on a model lookup is always "not held"
  // (`null`). A 404 on an agent lookup is "not registered" when it carries
  // `agent_not_registered`; a bare `not_found` (which a platform may also
  // answer for an unregistered digest) is "not registered" when the agent
  // catalog has answered a 2xx within the window, and is otherwise settled by
  // asking for one row of the listing.
  //
  // Every row read is re-hashed here: a row whose bytes do not hash to the
  // digest asked for is refused (`TzunCatalogError`, `digest_mismatch`) and
  // never kept.

  private catalogAbsent(kind: 'models' | 'agents' | 'agents.list'): boolean {
    const until = this.catalogAbsentUntil.get(kind);
    if (until === undefined) return false;
    if (Date.now() < until) return true;
    this.catalogAbsentUntil.delete(kind);
    return false;
  }

  private markCatalogAbsent(kind: 'models' | 'agents' | 'agents.list'): void {
    this.catalogAbsentUntil.set(kind, Date.now() + CATALOG_REPROBE_MS);
  }

  private markAgentCatalogServed(): void {
    this.agentCatalogServedUntil = Date.now() + CATALOG_REPROBE_MS;
  }

  /**
   * Whether the platform answered, within the last {@link CATALOG_REPROBE_MS},
   * that it does not serve the model catalog. `capture()` then words a
   * pre-built digest it cannot find as one this store cannot check.
   */
  modelCatalogKnownAbsent(): boolean {
    return this.catalogAbsent('models');
  }

  /**
   * Register a model descriptor in the platform's catalog (`POST /v1/models`),
   * idempotently on identical canonical bytes.
   *
   * The descriptor passes the same integrity invariants every local adapter
   * applies, and its digest is computed here over the engine's canonical
   * bytes: a platform answer naming another digest is refused
   * (`TzunCatalogError`, `digest_mismatch`), so a record never names a digest
   * the SDK did not compute.
   *
   * @throws {ModelCatalogUnsupportedError} when the platform does not serve
   *   the route.
   * @throws {TzunCatalogError} on any other failure.
   */
  async registerModelDescriptor(
    descriptor: ModelDescriptor,
    source: ModelDescriptorRow['source'],
    registeredBy: string,
  ): Promise<{ digest: string; alreadyExisted: boolean }> {
    assertDescriptorIntegrityInvariants(descriptor, 'registerModelDescriptor');
    const digest = prefixedSha256(canonicalSerializeDescriptor(descriptor));
    if (this.catalogAbsent('models')) throw new ModelCatalogUnsupportedError();
    const answer = await this.transport.catalog('POST', '/v1/models', 'models.register', {
      descriptor,
      source,
      registeredBy,
    });
    if (answer.kind !== 'ok') {
      if (answer.kind === 'not_found' && !routeNotServed(answer)) throw unexpectedNotFound('models.register', answer.code);
      this.markCatalogAbsent('models');
      throw new ModelCatalogUnsupportedError();
    }
    const answered = answer.body.digest;
    if (typeof answered !== 'string') throw catalogShapeError('models.register', answer.status);
    if (answered !== digest) throw digestMismatch('models.register', answer.status, digest, answered);
    return { digest, alreadyExisted: answer.body.alreadyExisted === true };
  }

  /**
   * The platform catalog's row for a model descriptor (`GET /v1/models/:digest`),
   * or `null` when the key's scope does not hold it (a JSON 404), the digest
   * is not a descriptor digest, or the platform keeps no model catalog.
   *
   * @throws {TzunCatalogError} `digest_mismatch` for a row whose
   *   `canonicalBytes` do not hash to `digest`, and on a failure that is not
   *   one of those answers.
   */
  async getModelDescriptor(digest: string): Promise<ModelDescriptorRow | null> {
    if (typeof digest !== 'string' || !MODEL_DESCRIPTOR_DIGEST_RE.test(digest)) return null;
    const cached = this.modelRows.get(digest);
    if (cached !== undefined) return structuredClone(cached);
    if (this.catalogAbsent('models')) return null;
    const answer = await this.transport.catalog(
      'GET',
      `/v1/models/${encodeURIComponent(digest)}`,
      'models.get',
    );
    if (answer.kind !== 'ok') return null;
    const row = modelRowFrom(digest, answer.body);
    if (row === null) throw catalogShapeError('models.get', answer.status);
    const hashed = prefixedSha256(row.canonicalBytes);
    if (hashed !== digest) throw digestMismatch('models.get', answer.status, digest, hashed);
    remember(this.modelRows, digest, row);
    return structuredClone(row);
  }

  /**
   * Register an agent descriptor in the platform's catalog (`POST /v1/agents`),
   * idempotently on identical canonical bytes. The descriptor is checked here
   * as every local store checks it (`InvalidAgentDescriptorError`), and a
   * platform answer naming a digest other than the one computed here is
   * refused (`TzunCatalogError`, `digest_mismatch`).
   *
   * @throws {AgentCatalogUnsupportedError} when the platform does not serve the route.
   */
  async putAgentDescriptor(descriptor: AgentDescriptor): Promise<{ digest: string; alreadyExisted: boolean }> {
    const checked = checkedAgentDescriptor(descriptor);
    const digest = prefixedSha256(canonicalSerializeAgentDescriptor(checked));
    if (this.catalogAbsent('agents')) throw new AgentCatalogUnsupportedError();
    const answer = await this.transport.catalog('POST', '/v1/agents', 'agents.register', { descriptor: checked });
    if (answer.kind !== 'ok') {
      if (answer.kind === 'not_found' && !routeNotServed(answer)) throw unexpectedNotFound('agents.register', answer.code);
      this.markCatalogAbsent('agents');
      throw new AgentCatalogUnsupportedError();
    }
    this.markAgentCatalogServed();
    const answered = answer.body.digest;
    if (typeof answered !== 'string') throw catalogShapeError('agents.register', answer.status);
    if (answered !== digest) throw digestMismatch('agents.register', answer.status, digest, answered);
    return { digest, alreadyExisted: answer.body.alreadyExisted === true };
  }

  /**
   * The platform catalog's row for an agent descriptor (`GET /v1/agents/:digest`),
   * or `null` when the key's scope does not hold it or the reference is not a
   * descriptor digest.
   *
   * @throws {AgentCatalogUnsupportedError} when the platform does not serve the
   *   route, which `tzun.agents` reports and export reads as `catalog_absent`.
   * @throws {TzunCatalogError} `digest_mismatch` for a row whose bytes do not
   *   hash to `digest`, and on any other failure.
   */
  async getAgentDescriptor(digest: string): Promise<AgentDescriptorRow | null> {
    if (this.catalogAbsent('agents')) throw new AgentCatalogUnsupportedError();
    if (!isAgentDescriptorDigest(digest)) return null;
    const cached = this.agentRows.get(digest);
    if (cached !== undefined) return { ...cached };
    const answer = await this.transport.catalog(
      'GET',
      `/v1/agents/${encodeURIComponent(digest)}`,
      'agents.get',
    );
    if (answer.kind === 'not_found') {
      if (answer.code === 'agent_not_registered') return null;
      if (answer.code !== 'not_found') throw unexpectedNotFound('agents.get', answer.code);
      if (await this.agentCatalogServed()) return null;
    }
    if (answer.kind !== 'ok') {
      this.markCatalogAbsent('agents');
      throw new AgentCatalogUnsupportedError();
    }
    this.markAgentCatalogServed();
    const row = agentRowFrom(answer.body);
    if (row === null || row.digest !== digest) throw catalogShapeError('agents.get', answer.status);
    const hashed = prefixedSha256(row.canonicalBytes);
    if (hashed !== digest) throw digestMismatch('agents.get', answer.status, digest, hashed);
    remember(this.agentRows, digest, row);
    return { ...row };
  }

  /**
   * Whether the platform serves the agent catalog: known from a 2xx within
   * the last {@link CATALOG_REPROBE_MS}, or asked with one row of the listing
   * (`GET /v1/agents?limit=1`).
   */
  private async agentCatalogServed(): Promise<boolean> {
    if (Date.now() < this.agentCatalogServedUntil) return true;
    const answer = await this.transport.catalog('GET', '/v1/agents?limit=1', 'agents.list');
    if (answer.kind === 'ok') {
      this.markAgentCatalogServed();
      return true;
    }
    if (routeNotServed(answer)) return false;
    throw unexpectedNotFound('agents.list', (answer as { code: string }).code);
  }

  /**
   * A page of the platform's agent catalog (`GET /v1/agents`), in the
   * platform's order. The filter is checked as every store checks it; the
   * cursor is the platform's own, handed back to it unread. A cursor the
   * platform refuses (`400` naming `cursor` or `limit`, or reason
   * `invalid_pagination`) is `InvalidPaginationError`, as on a local store.
   *
   * @throws {AgentCatalogUnsupportedError} when the platform does not serve the
   *   listing (it may serve register and get without it).
   */
  async listAgentDescriptors(filter?: {
    name?: string;
    organization?: string;
    limit?: number;
    cursor?: string;
  }): Promise<{ rows: AgentDescriptorRow[]; cursor: string | null }> {
    const query = agentListRequest(filter);
    if (this.catalogAbsent('agents') || this.catalogAbsent('agents.list')) {
      throw new AgentCatalogUnsupportedError();
    }
    const params = new URLSearchParams();
    if (query.name !== null) params.set('name', query.name);
    if (query.organization !== null) params.set('organization', query.organization);
    params.set('limit', String(query.limit));
    if (query.cursor !== null) params.set('cursor', query.cursor);
    let answer: CatalogAnswer;
    try {
      answer = await this.transport.catalog('GET', `/v1/agents?${params.toString()}`, 'agents.list');
    } catch (error) {
      const refused = paginationRefusal(error, query);
      if (refused !== null) throw refused;
      throw error;
    }
    if (answer.kind !== 'ok') {
      if (answer.kind === 'not_found' && !routeNotServed(answer)) throw unexpectedNotFound('agents.list', answer.code);
      this.markCatalogAbsent('agents.list');
      throw new AgentCatalogUnsupportedError();
    }
    this.markAgentCatalogServed();
    // `rows`/`cursor`, or the `agents`/`nextCursor` spelling of the same page.
    const rows = answer.body.rows ?? answer.body.agents;
    const cursor = answer.body.cursor !== undefined ? answer.body.cursor : (answer.body.nextCursor ?? null);
    if (!Array.isArray(rows) || (cursor !== null && typeof cursor !== 'string')) {
      throw catalogShapeError('agents.list', answer.status);
    }
    const page: AgentDescriptorRow[] = [];
    for (const item of rows) {
      const row = agentRowFrom(item);
      if (row === null) throw catalogShapeError('agents.list', answer.status);
      page.push(row);
    }
    return { rows: page, cursor: cursor as string | null };
  }

  // ── Reads that require a server round-trip. These THROW.
  //
  // Returning `[]` / `0` / `null` instead would not be a safe default for a
  // verifier: `verifyChainCompleteness()` would report
  // `{ valid: true, totalRecords: 0 }`, `ScheduledScanner` would emit
  // `scan_completed` with zero issues on every pass, `verifyRange()` would
  // report `recordsVerified: 0, issuesFound: 0`, and `retrieve()` would report
  // "not found" for evidence the server holds. A cloud customer alerting on
  // `issuesFound > 0` or gating a compliance job on `valid` would get a
  // permanent green light over data nobody had looked at.
  //
  // `retrieve` and `list` throw although the round trip exists above: their
  // `StorageAdapter` contract returns bare envelopes, so answering them would
  // discard the verdict the server computed and leave the caller holding a
  // record whose checks it has no way to report. `retrieveWithVerdict` /
  // `listWithVerdicts` are the same round trips with the verdict kept.
  async retrieve(_evidenceId: string): Promise<EvidenceEnvelope | null> {
    throw unsupported('retrieve');
  }
  async list(_options?: ListOptions): Promise<EvidenceEnvelope[]> {
    throw unsupported('list');
  }
  async listBySequence(): Promise<EvidenceEnvelope[]> {
    throw unsupported('listBySequence');
  }
  async getBySequenceRange(): Promise<EvidenceEnvelope[]> {
    throw unsupported('getBySequenceRange');
  }
  async getChainLength(): Promise<number> {
    throw unsupported('getChainLength');
  }
  async listByAttestationStatus(): Promise<EvidenceEnvelope[]> {
    throw unsupported('listByAttestationStatus');
  }
  async listByMissingObtainable(): Promise<EvidenceEnvelope[]> {
    throw unsupported('listByMissingObtainable');
  }
  async listChains(): Promise<ChainIdentity[]> {
    throw unsupported('listChains');
  }
  async listRecordChainIds(): Promise<string[]> {
    throw unsupported('listRecordChainIds');
  }
  async listIncidents(): Promise<TamperIncident[]> {
    throw unsupported('listIncidents');
  }
  async getChainForRecord(): Promise<string | null> {
    throw unsupported('getChainForRecord');
  }
  async getChain(): Promise<ChainIdentity | null> {
    throw unsupported('getChain');
  }
  async getIncident(): Promise<TamperIncident | null> {
    throw unsupported('getIncident');
  }
  async getAnnotation(): Promise<AnnotationRecord | null> {
    throw unsupported('getAnnotation');
  }
  async listAnnotations(): Promise<AnnotationRecord[]> {
    throw unsupported('listAnnotations');
  }
  async listAnnotationsForRecord(): Promise<AnnotationRecord[]> {
    throw unsupported('listAnnotationsForRecord');
  }
  async getRelink(): Promise<RelinkRecord | null> {
    throw unsupported('getRelink');
  }
  async listRelinks(): Promise<RelinkRecord[]> {
    throw unsupported('listRelinks');
  }
  async getFork(): Promise<ForkRecord | null> {
    throw unsupported('getFork');
  }
  async listForks(): Promise<ForkRecord[]> {
    throw unsupported('listForks');
  }
  async listForksForChain(): Promise<ForkRecord[]> {
    throw unsupported('listForksForChain');
  }

  // ── Mutations not supported by the transport-only cloud adapter. ──
  async updateAttestation(
    _evidenceId: string,
    _artifacts: AttestationArtifacts,
    _newStatus: EvidenceEnvelope['attestationStatus'] | AttestationStatusOf,
  ): Promise<void> {
    throw unsupported('updateAttestation');
  }
  async storeIncident(_incident: TamperIncident): Promise<void> {
    throw unsupported('storeIncident');
  }
  async updateIncidentStatus(
    _id: string,
    _status: TamperIncidentStatus,
  ): Promise<void> {
    throw unsupported('updateIncidentStatus');
  }
  // `recordIncidentObservation` is deliberately ABSENT rather than throwing
  // `unsupported`: it is optional on StorageAdapter, and TamperDetector detects
  // it and skips the observation. A throwing stub would log an error on every
  // re-observed finding of every pass to say what absence says once, quietly.
  // There are no incidents to stamp here anyway — the platform owns the store
  // this transport talks to, and records observations in its own writer.
  async storeChain(_chain: ChainIdentity): Promise<void> {
    throw unsupported('storeChain');
  }
  async sealChain(_chainId: string, _sealedAt: string): Promise<void> {
    throw unsupported('sealChain');
  }
  async storeAnnotation(_annotation: AnnotationRecord): Promise<void> {
    throw unsupported('storeAnnotation');
  }
  async storeRelink(_relink: RelinkRecord): Promise<void> {
    throw unsupported('storeRelink');
  }
  async storeFork(_fork: ForkRecord): Promise<void> {
    throw unsupported('storeFork');
  }
  async updateEnvelopeChainLink(
    _evidenceId: string,
    _newChainLink: string | null,
  ): Promise<void> {
    throw unsupported('updateEnvelopeChainLink');
  }
  async appendCustodyEntry(_evidenceId: string, _entry: CustodyEntry): Promise<void> {
    throw unsupported('appendCustodyEntry');
  }
  async applyRelink(_relink: RelinkRecord, _custodyEntries: RelinkCustodyAppend[]): Promise<void> {
    throw unsupported('applyRelink');
  }
  async listCustodyEntries(_evidenceId: string): Promise<StoredCustodyEntry[]> {
    throw unsupported('listCustodyEntries');
  }

  // The revision log lives on the server side of the cloud
  // transport, like every other chain read. These throw rather than answering
  // `[]` / `{}` for the same reason the reads above do: an empty answer here
  // would tell `verifyChainCompleteness()` that no record in the store was
  // ever superseded, which is the reassuring lie, over evidence the SDK has
  // not looked at. (It never gets that far in practice — `listBySequence`
  // refuses first — but the honest answer must not depend on call order.)
  async listEnvelopeRevisions(_evidenceId: string): Promise<EnvelopeRevision[]> {
    throw unsupported('listEnvelopeRevisions');
  }
  async getCaptureDigests(_evidenceIds: string[]): Promise<Record<string, string>> {
    throw unsupported('getCaptureDigests');
  }

  /** No external resource held locally. */
  async close(): Promise<void> {
    /* no-op */
  }
}

function unsupported(method: string): Error {
  return new TzunCloudReadUnsupportedError(method);
}

/**
 * A model descriptor row from a `GET /v1/models/:digest` body: `canonicalBytes`
 * must be a string that parses as a JSON object, which becomes `descriptor`
 * (the platform's copy of the parsed form is not read). `null` for any other
 * shape.
 */
function modelRowFrom(digest: string, body: Record<string, unknown>): ModelDescriptorRow | null {
  const canonicalBytes = body.canonicalBytes;
  if (typeof canonicalBytes !== 'string') return null;
  let descriptor: unknown;
  try {
    descriptor = JSON.parse(canonicalBytes);
  } catch {
    return null;
  }
  if (descriptor === null || typeof descriptor !== 'object' || Array.isArray(descriptor)) return null;
  const d = descriptor as Partial<ModelDescriptor>;
  const text = (value: unknown): string => (typeof value === 'string' ? value : '');
  return {
    modelDescriptorDigest: digest,
    canonicalBytes,
    descriptor: descriptor as ModelDescriptor,
    vendor: text(d.vendor),
    modelName: text(d.modelName),
    modelVersion: text(d.modelVersion),
    parentModelDescriptorDigest:
      typeof d.parentModelDescriptorDigest === 'string' ? d.parentModelDescriptorDigest : null,
    source: (typeof body.source === 'string' ? body.source : 'manual') as ModelDescriptorRow['source'],
    firstRegisteredAt: text(body.firstRegisteredAt),
    firstRegisteredBy: text(body.firstRegisteredBy),
  };
}

/**
 * An agent descriptor row from a catalog body, or `null` for any other shape.
 *
 * The row's `canonicalBytes` are taken as sent; a body that carries the
 * parsed `descriptor` in their place has them computed from it with the
 * engine's serializer (a value it refuses is not a row). Either way capture
 * and verification re-hash the bytes against the reference, so the platform
 * cannot answer one descriptor for another.
 */
function agentRowFrom(value: unknown): AgentDescriptorRow | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  let canonicalBytes: string;
  if (typeof v.canonicalBytes === 'string') {
    canonicalBytes = v.canonicalBytes;
  } else if (v.descriptor !== null && typeof v.descriptor === 'object' && !Array.isArray(v.descriptor)) {
    try {
      canonicalBytes = canonicalSerializeAgentDescriptor(v.descriptor as AgentDescriptor);
    } catch {
      return null;
    }
  } else {
    return null;
  }
  const parent =
    v.parent !== undefined ? v.parent : ((v.descriptor as { parent?: unknown } | undefined)?.parent ?? null);
  if (
    typeof v.digest !== 'string' ||
    typeof v.name !== 'string' ||
    typeof v.organization !== 'string' ||
    (parent !== null && typeof parent !== 'string') ||
    typeof v.registeredAt !== 'string'
  ) {
    return null;
  }
  return {
    digest: v.digest,
    canonicalBytes,
    name: v.name,
    organization: v.organization,
    parent: parent as string | null,
    registeredAt: v.registeredAt,
  };
}

/** Keep a row in a bounded cache, dropping the oldest entry past {@link CATALOG_ROW_CACHE_SIZE}. */
function remember<T>(cache: Map<string, T>, digest: string, row: T): void {
  cache.set(digest, row);
  if (cache.size > CATALOG_ROW_CACHE_SIZE) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
}
