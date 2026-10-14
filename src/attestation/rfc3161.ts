/**
 * RFC 3161 Timestamp Client
 *
 * Sends a timestamp request to a Timestamp Authority (TSA) and receives
 * a signed timestamp token proving the digest existed at the time of signing.
 *
 * The client fails closed: an HTTP 200 is not on its own a timestamp. The
 * response must parse as a DER TimeStampResp, carry a granted PKIStatus, embed
 * a SHA-256 messageImprint equal to the digest that was requested, and echo the
 * per-request nonce. Anything else throws, so no unparseable or mismatched blob
 * can reach `rfc3161Token` — which every downstream timestamp decision in the
 * SDK and platform treats as presence-equals-attested.
 */

import { DEFAULT_TRUST_ANCHOR_AUTHORITIES, timestampAuthorityUrls } from './tsa-registry';
import { verifyRfc3161Steps } from './rfc3161-token';

/**
 * The authorities a client uses when none is configured, in the order it tries
 * them: FreeTSA, then Sectigo.
 *
 * The URL form of `DEFAULT_TRUST_ANCHOR_AUTHORITIES` in ./tsa-registry, which
 * is also the list the default verifier trusts, so a token an unconfigured
 * client obtains always chains to a root an unconfigured verifier accepts.
 * The default is changed there, not here.
 */
export const DEFAULT_TIMESTAMP_AUTHORITIES: readonly string[] = Object.freeze(
  timestampAuthorityUrls(DEFAULT_TRUST_ANCHOR_AUTHORITIES),
);

export interface RFC3161Config {
  /**
   * URL of the primary Timestamp Authority. When `tsaUrls` is also given this
   * is the head of the list. When neither is given the client uses
   * `DEFAULT_TIMESTAMP_AUTHORITIES`; giving either replaces that list
   * entirely, so `tsaUrl` alone pins the client to one authority.
   */
  tsaUrl?: string;
  /**
   * Additional Timestamp Authorities, tried in order after `tsaUrl`.
   *
   * WHY A SECOND KEY RATHER THAN WIDENING `tsaUrl` TO `string | string[]`:
   * `tsaUrl` is read from `TzunConfig.attestation.timestamp.rfc3161Url`, which
   * integrators set from env vars and JSON config, and platform code reads it
   * back. Widening the type makes every one of those call sites handle two
   * shapes, and a config file that may hold a string or an array is the kind
   * of thing that gets half-migrated.
   *
   * Duplicates are collapsed, preserving first appearance, so an authority is
   * never contacted twice for one digest.
   */
  tsaUrls?: string[];
  /** Per-authority timeout in milliseconds. Defaults to 10000. */
  timeoutMs?: number;
  /**
   * Ceiling on the whole `requestTimestamp()` call, across every authority.
   * Defaults to `timeoutMs * 2`.
   *
   * `capture()` is awaited inside the caller's own request handler, so a list
   * of N authorities must not be able to hold that handler open for
   * N x timeoutMs. Each attempt is granted the smaller of `timeoutMs` and an
   * equal share of the REMAINING budget among the authorities still to try,
   * which means a hanging first authority cannot consume the whole budget and
   * an authority that fails fast hands its unused share to the next one. With
   * a single authority the share is the whole budget, capped at `timeoutMs`.
   *
   * A share covers the whole exchange with that authority: connecting, the
   * response headers and the response body. An authority that sends its
   * headers and then stalls, or a `fetchFn` that ignores the abort signal, is
   * cut off at its share like one that never answers.
   *
   * With the defaults (10000 and 20000) and the default pair, a FreeTSA that
   * hangs is cut off at 10000ms and Sectigo gets the remaining 10000ms.
   */
  totalTimeoutMs?: number;
  /** Per-authority circuit-breaker tuning. */
  breaker?: {
    /** Consecutive failures before an authority is skipped. Default 3. */
    failureThreshold?: number;
    /** How long an authority stays skipped before one probe. Default 60000. */
    coolDownMs?: number;
  };
  /** Injectable fetch function for testing. Defaults to global fetch. */
  fetchFn?: typeof fetch;
}

// SHA-256 OID: 2.16.840.1.101.3.4.2.1
// DER-encoded as: 06 09 60 86 48 01 65 03 04 02 01
const SHA256_OID = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

/**
 * Build a minimal DER-encoded TimeStampReq (RFC 3161, Section 2.4.1).
 *
 * Structure:
 *   TimeStampReq ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     messageImprint MessageImprint,
 *     nonce          INTEGER OPTIONAL,
 *     certReq        BOOLEAN DEFAULT FALSE
 *   }
 *
 *   MessageImprint ::= SEQUENCE {
 *     hashAlgorithm  AlgorithmIdentifier,
 *     hashedMessage  OCTET STRING
 *   }
 *
 * WIRE-FORMAT NOTE: when `nonce` is omitted the output is byte for byte the
 * Python port's golden fixture (`python/tests/attestation/fixtures/tsq_golden.hex`).
 * The nonce is an OPTIONAL field that RFC 3161 places between messageImprint
 * and certReq, and it is only emitted when the caller supplies one.
 *
 * @param digest - 64-character hex SHA-256 digest
 * @param nonce - Optional nonce bytes. Emitted as `nonce INTEGER` so the TSA
 *   must echo it in TSTInfo; the client uses this to reject replayed or cached
 *   TimeStampResp bodies.
 * @returns DER-encoded timestamp request
 */
export function buildTimestampQuery(digest: string, nonce?: Buffer): Buffer {
  assertValidDigest(digest);

  const digestBytes = Buffer.from(digest, 'hex');

  // AlgorithmIdentifier SEQUENCE: SEQUENCE { OID, NULL }
  const algIdNull = Buffer.from([0x05, 0x00]); // NULL
  const algIdContent = Buffer.concat([SHA256_OID, algIdNull]);
  const algIdSeq = wrapDER(0x30, algIdContent); // SEQUENCE

  // hashedMessage OCTET STRING
  const hashedMessage = wrapDER(0x04, digestBytes);

  // MessageImprint SEQUENCE
  const messageImprint = wrapDER(0x30, Buffer.concat([algIdSeq, hashedMessage]));

  // version INTEGER v1(1)
  const version = Buffer.from([0x02, 0x01, 0x01]); // INTEGER, length 1, value 1

  // nonce INTEGER OPTIONAL — RFC 3161 orders it AFTER messageImprint/reqPolicy
  // and BEFORE certReq. Empty when no nonce was requested, which keeps the
  // no-nonce encoding identical to the pre-nonce implementation.
  const nonceDer = nonce ? wrapDER(0x02, toPositiveInteger(nonce)) : Buffer.alloc(0);

  // certReq BOOLEAN TRUE (request the TSA certificate in the response)
  const certReq = Buffer.from([0x01, 0x01, 0xff]); // BOOLEAN, length 1, TRUE

  // TimeStampReq SEQUENCE
  const tsReq = wrapDER(0x30, Buffer.concat([version, messageImprint, nonceDer, certReq]));

  return tsReq;
}

/**
 * Reject a digest that is not a 64-character hex SHA-256.
 *
 * Hoisted out of `buildTimestampQuery` so `requestTimestamp` can run it ONCE,
 * before any authority is contacted. A malformed digest is a caller error, not
 * an outage: it must not be charged against an authority's circuit breaker and
 * it must not be reported as "every timestamp authority failed".
 */
function assertValidDigest(digest: string): void {
  if (!/^[0-9a-f]{64}$/i.test(digest)) {
    throw new Error(
      `Invalid digest: expected 64-character hex string, got "${digest.substring(0, 20)}..."`
    );
  }
}

/**
 * Normalise raw bytes into a DER INTEGER content octet string.
 *
 * DER INTEGERs are signed two's-complement, so a random 64-bit nonce whose top
 * bit is set has to be prefixed with 0x00 or it encodes as a negative number
 * and the TSA echoes back something that does not compare equal.
 */
function toPositiveInteger(raw: Buffer): Buffer {
  let i = 0;
  while (i < raw.length - 1 && raw[i] === 0x00) i++;
  const trimmed = raw.subarray(i);
  return (trimmed[0] & 0x80) !== 0
    ? Buffer.concat([Buffer.from([0x00]), trimmed])
    : Buffer.from(trimmed);
}

/**
 * Wrap content in a DER TLV (Tag-Length-Value) structure.
 */
function wrapDER(tag: number, content: Buffer): Buffer {
  const length = content.length;
  let lengthBytes: Buffer;

  if (length < 0x80) {
    lengthBytes = Buffer.from([length]);
  } else if (length < 0x100) {
    lengthBytes = Buffer.from([0x81, length]);
  } else if (length < 0x10000) {
    lengthBytes = Buffer.from([0x82, (length >> 8) & 0xff, length & 0xff]);
  } else {
    throw new Error(`DER content too long: ${length} bytes`);
  }

  return Buffer.concat([Buffer.from([tag]), lengthBytes, content]);
}

/** What one authority did when it was asked for a token. */
export interface AuthorityAttempt {
  /** The authority's URL. */
  url: string;
  /** `ok` issued a valid token; `failed` was contacted and did not; `skipped` was never contacted. */
  outcome: 'ok' | 'failed' | 'skipped';
  /** Milliseconds this attempt was allowed. Absent when the attempt was skipped. */
  timeoutMs?: number;
  /** Wall-clock milliseconds the attempt actually took. */
  durationMs: number;
  /** Error class name, for alerting that keys on a stable value. */
  errorName?: string;
  /** Operator-facing diagnosis — a typo'd URL must stay distinguishable from an outage. */
  error?: string;
}

/** Which authority issued the token, and what happened on the way there. */
export interface TimestampProvenance {
  /** The authority that issued the token. */
  authorityUrl: string;
  /** Its zero-based position in the configured list. */
  authorityIndex: number;
  /** True when the token came from anything other than the primary. */
  failedOver: boolean;
  /** Every authority considered, in order, including the one that succeeded. */
  attempts: AuthorityAttempt[];
}

/**
 * Whether a token meets tzun-anchor/1 §10.5 steps 1 to 3 over the digest it
 * was requested for: the rules every verifier holds a record's token to (a
 * DER TimeStampResp carrying its signer certificate, a SHA-256 imprint of the
 * digest, the CMS signature, a signingCertificate(V2) naming the signer, and
 * a critical extendedKeyUsage whose only purpose is timestamping). `reason`
 * is the first step that does not hold.
 */
export type TimestampConformance =
  | { holds: true }
  | { holds: false; reason: 'malformed' | 'imprint_mismatch' | 'verification_failed' | 'missing_dependency'; error?: string };

/**
 * Whether `token` (base64 of a TimeStampResp) meets tzun-anchor/1 §10.5 steps 1
 * to 3 over `digest`: what `RFC3161Client` returns as
 * `TimestampResult.conformance` for each token it keeps. It does not throw.
 * The Python SDK's `timestamp_conformance` gives the same answer on the same
 * token (tests/cross-sdk/test_rfc3161_conformance_parity.py).
 */
export function timestampConformance(token: string, digest: string): TimestampConformance {
  const steps = verifyRfc3161Steps(token, digest, []);
  return steps.token === 'held'
    ? { holds: true }
    : { holds: false, reason: steps.token, ...(steps.error !== undefined && { error: steps.error }) };
}

/** Result from a timestamp request, including the opaque token and optional parsed metadata. */
export interface TimestampResult {
  /** Base64-encoded DER TimeStampResp -- the canonical artifact. */
  token: string;
  /** Parsed metadata from the response. Null if parsing fails. */
  metadata: {
    genTime: string;
    tsaName?: string;
    policyOid?: string;
    status: 'granted' | 'grantedWithMods' | 'rejection' | 'waiting';
  } | null;
  /**
   * Which authority issued this token and what the others did.
   *
   * OPERATOR TELEMETRY, NOT AN EVIDENCE ARTIFACT. The orchestrator copies only
   * `token` and `metadata` into `nonRepudiation`, and this field deliberately
   * does not join them. The issuing authority is ALREADY recoverable from the
   * token: every request sets `certReq` TRUE, so the TSA's signing certificate
   * is embedded in the response's CMS SignedData, and `metadata.tsaName` is
   * read out of that certificate's Common Name (`extractRFC3161Metadata`),
   * with `metadata.policyOid` naming the TSA's policy. Those facts are covered
   * by the TSA's own signature. A URL copied alongside them would be an
   * unsigned, freely-editable second opinion on the same question — worse than
   * nothing in an evidence envelope, because a store-write attacker could
   * change it and every verifier would still pass.
   *
   * The one thing the token does NOT carry is which ENDPOINT was contacted,
   * which matters operationally (a relay such as rfc3161.ai.moda forwards to
   * DigiCert, so the token says DigiCert while the outage is the relay's).
   * That is an ops fact, so it goes to the log sink, not into the envelope.
   */
  provenance: TimestampProvenance;
  /**
   * Whether the token meets tzun-anchor/1 §10.5 steps 1 to 3 over the
   * requested digest. OPERATOR TELEMETRY, like `provenance`: the client keeps
   * a token that passes its own checks (a parseable TimeStampResp, granted,
   * the imprint, the nonce) whatever this says, and the orchestrator reports
   * one that does not hold as `attestation_timestamp_nonconformant`. An
   * authority whose tokens every verifier refuses (BER, no
   * signingCertificate(V2), no critical timestamping-only extendedKeyUsage)
   * is then seen at its first capture, not in a later scan. Absent from a
   * client stand-in that does not compute it.
   */
  conformance?: TimestampConformance;
}

import { randomBytes } from 'crypto';
import { CircuitBreaker, CircuitOpenError } from './circuit-breaker';
export { CircuitOpenError };

/**
 * Thrown when no configured authority issued a token.
 *
 * Carries the per-authority attempt log so the orchestrator can report WHICH
 * authorities were tried and WHY each one failed. The message concatenates
 * every authority's own diagnosis, so the existing contract — 'getaddrinfo
 * ENOTFOUND typo-tsa.example' stays visible and distinguishable from an
 * outage — survives having more than one authority.
 */
export class TimestampAuthorityError extends Error {
  readonly attempts: readonly AuthorityAttempt[];

  constructor(attempts: AuthorityAttempt[]) {
    const lines = attempts.map((a) => `  ${a.url} — ${a.error ?? 'unknown failure'}`);
    super(
      `No timestamp authority issued a token (${attempts.length} tried):\n${lines.join('\n')}`
    );
    this.name = 'TimestampAuthorityError';
    this.attempts = attempts;
  }
}

/** A token as it comes off one authority, before provenance is attached. */
type IssuedToken = Pick<TimestampResult, 'token' | 'metadata' | 'conformance'>;

/** Per-authority breaker snapshot, as read by observability endpoints. */
export interface AuthorityBreakerState {
  url: string;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  failures: number;
  openedAt: number | null;
}

export class RFC3161Client {
  private tsaUrlList: string[];
  private timeoutMs: number;
  private totalTimeoutMs: number;
  private fetchFn: typeof fetch;
  private breakers: CircuitBreaker[];

  constructor(config: RFC3161Config = {}) {
    // `tsaUrl` is the head, `tsaUrls` the tail, and either one replaces the
    // default list. Setting only `tsaUrl` pins the client to exactly that
    // authority: an integrator who named one TSA meant that TSA, and would not
    // thank us for quietly sending their digests somewhere else.
    const configured = [...(config.tsaUrl ? [config.tsaUrl] : []), ...(config.tsaUrls ?? [])];
    const resolved = configured.length > 0 ? configured : [...DEFAULT_TIMESTAMP_AUTHORITIES];
    // Contacting the same authority twice for one digest is pure latency.
    this.tsaUrlList = [...new Set(resolved)];

    this.timeoutMs = config.timeoutMs || 10000;
    this.totalTimeoutMs = config.totalTimeoutMs || this.timeoutMs * 2;
    this.fetchFn = config.fetchFn || globalThis.fetch;

    // One breaker PER AUTHORITY. A single shared breaker was worse than
    // useless once there is a list: three failures at a dead primary opened
    // the circuit for the healthy fallbacks too, so an outage at one TSA still
    // stopped every capture — the exact failure failover exists to prevent.
    // Per-authority, a dead TSA is skipped in well under a millisecond on the
    // next capture while its neighbours are untouched, and it gets one probe
    // per cool-down so recovery is automatic.
    this.breakers = this.tsaUrlList.map(
      (url) =>
        new CircuitBreaker({
          name: `rfc3161-tsa:${url}`,
          failureThreshold: config.breaker?.failureThreshold ?? 3,
          coolDownMs: config.breaker?.coolDownMs ?? 60_000,
        })
    );
  }

  /** The authorities this client will try, in order. */
  authorities(): string[] {
    return [...this.tsaUrlList];
  }

  /**
   * Current breaker state — for operators reading /demo/health or
   * similar observability surfaces.
   *
   * The top-level fields answer "can this client get a timestamp right now?",
   * the only question worth alerting on: `state` is the BEST state in the
   * pool, so one dead authority alongside a live one reads CLOSED, and OPEN
   * means every authority is being skipped. With a single authority these
   * three fields describe that authority alone. `authorities`
   * is the per-authority detail, which is what tells an operator that FreeTSA
   * has been down since Tuesday while captures kept working.
   */
  breakerState(): {
    state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
    failures: number;
    openedAt: number | null;
    authorities: AuthorityBreakerState[];
  } {
    const authorities: AuthorityBreakerState[] = this.tsaUrlList.map((url, i) => ({
      url,
      ...this.breakers[i].snapshot(),
    }));

    const state = authorities.some((a) => a.state === 'CLOSED')
      ? 'CLOSED'
      : authorities.some((a) => a.state === 'HALF_OPEN')
        ? 'HALF_OPEN'
        : 'OPEN';

    const openedAts = authorities
      .map((a) => a.openedAt)
      .filter((t): t is number => t !== null);

    return {
      state,
      failures: authorities.reduce((total, a) => total + a.failures, 0),
      openedAt: state === 'OPEN' && openedAts.length > 0 ? Math.min(...openedAts) : null,
      authorities,
    };
  }

  /**
   * Request a timestamp token, trying each configured authority in order.
   *
   * A token from ANY authority satisfies the timestamp component — they are
   * interchangeable for that purpose, because what the component asserts is
   * "an independent third party attested this digest existed at time T", and
   * any one of them is such a party. The first authority to return a token
   * that passes every structural check (parseable TimeStampResp, granted
   * PKIStatus, SHA-256 imprint equal to `digest`, echoed nonce) wins; an
   * authority that returns a token failing any of those is treated as a
   * failure and the next one is tried, so a caching proxy handing back
   * somebody else's valid token cannot short-circuit the list.
   *
   * @param digest - 64-character hex SHA-256 digest to timestamp
   * @returns TimestampResult with base64 token, parsed metadata and provenance
   * @throws Error on an invalid digest (before any authority is contacted).
   * @throws TimestampAuthorityError when no authority issued a token; its
   *   `attempts` and message name every authority and why each one failed.
   */
  async requestTimestamp(digest: string): Promise<TimestampResult> {
    assertValidDigest(digest);

    const budgetStartedAt = Date.now();
    const attempts: AuthorityAttempt[] = [];

    for (let i = 0; i < this.tsaUrlList.length; i++) {
      const url = this.tsaUrlList[i];
      const authoritiesLeft = this.tsaUrlList.length - i;
      const budgetLeft = this.totalTimeoutMs - (Date.now() - budgetStartedAt);

      if (budgetLeft <= 0) {
        attempts.push({
          url,
          outcome: 'skipped',
          durationMs: 0,
          errorName: 'TimestampBudgetExhausted',
          error:
            `skipped: the ${this.totalTimeoutMs}ms timestamp budget was already ` +
            `spent on earlier authorities`,
        });
        continue;
      }

      // An equal share of what is LEFT, capped at the per-authority ceiling.
      // A hanging authority therefore burns its share and no more, and one
      // that fails fast leaves its unspent share to those behind it.
      const slice = Math.max(1, Math.min(this.timeoutMs, Math.floor(budgetLeft / authoritiesLeft)));
      const startedAt = Date.now();

      try {
        const issued = await this.breakers[i].fire(() =>
          this.doRequestTimestamp(digest, url, slice)
        );
        attempts.push({
          url,
          outcome: 'ok',
          timeoutMs: slice,
          durationMs: Date.now() - startedAt,
        });
        return {
          ...issued,
          provenance: {
            authorityUrl: url,
            authorityIndex: i,
            failedOver: i > 0,
            attempts,
          },
        };
      } catch (err) {
        // A CircuitOpenError means `fire()` returned without calling fetch —
        // the authority was skipped, not contacted, and that distinction is
        // what tells an operator "still down" from "failed again just now".
        const skipped = err instanceof CircuitOpenError;
        attempts.push({
          url,
          outcome: skipped ? 'skipped' : 'failed',
          ...(skipped ? {} : { timeoutMs: slice }),
          durationMs: Date.now() - startedAt,
          errorName: err instanceof Error ? err.name : typeof err,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    throw new TimestampAuthorityError(attempts);
  }

  private async doRequestTimestamp(
    digest: string,
    tsaUrl: string,
    timeoutMs: number
  ): Promise<IssuedToken> {
    // A fresh nonce per request. RFC 3161 §2.4.2 requires the TSA to echo it in
    // TSTInfo, so it is what distinguishes a token minted for THIS request from
    // one a cache or proxy is replaying.
    const nonce = randomBytes(8);
    const query = buildTimestampQuery(digest, nonce);

    // One deadline for the whole exchange, enforced here rather than left to
    // `fetchFn`. The abort cancels a real fetch, including a body read still in
    // flight; the rejection settles this attempt at its share even when the
    // transport does not honour the signal, so the next authority always gets
    // the budget that is left.
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        const timeout = new Error(`TSA did not answer within its ${timeoutMs}ms timeout`);
        timeout.name = 'TimeoutError';
        reject(timeout);
        controller.abort();
      }, timeoutMs);
    });

    let buffer: ArrayBuffer;
    try {
      buffer = await Promise.race([
        this.fetchReply(tsaUrl, query, controller.signal),
        deadline,
      ]);
    } finally {
      clearTimeout(timer);
    }
    const token = Buffer.from(buffer).toString('base64');

    // Fail closed. Keeping whatever bytes come back on an HTTP 200 would make
    // an HTML error page, a captive-portal redirect body, or a TimeStampResp
    // minted for somebody else's digest the `rfc3161Token`, and a downstream
    // decision that is a presence check on that field
    // (`!!attestation.rfc3161Token`) would let a garbage body satisfy
    // `require: ['timestamp']`, produce attestationStatus 'partial', and be
    // written to the store as an 'attested' artifact. A token nobody can parse
    // is not evidence of anything, so it is an error rather than a token.
    const {
      parseTimestampResponse,
      extractPKIStatus,
      parsePKIStatus,
      extractTSTInfo,
      extractRFC3161Metadata,
      nonceMatches,
    } = require('./rfc3161-verify');

    let tsResp;
    try {
      tsResp = parseTimestampResponse(token);
    } catch (err) {
      throw new Error(
        `TSA response is not a parseable RFC 3161 TimeStampResp: ` +
          `${err instanceof Error ? err.message : String(err)}`
      );
    }

    const status = parsePKIStatus(extractPKIStatus(tsResp));
    if (status !== 'granted' && status !== 'grantedWithMods') {
      throw new Error(`TSA returned non-success PKIStatus: ${status}`);
    }

    let tstInfo;
    try {
      tstInfo = extractTSTInfo(tsResp);
    } catch (err) {
      throw new Error(
        `TSA response does not contain a readable TSTInfo: ` +
          `${err instanceof Error ? err.message : String(err)}`
      );
    }

    // The imprint binds the token to the digest we asked about. Without this a
    // proxy or cache could hand back a perfectly valid token for an unrelated
    // record and it would be stored as proof for this one.
    if (tstInfo.messageImprint.hashAlgorithm !== 'SHA-256') {
      throw new Error(
        `TSA timestamped with ${tstInfo.messageImprint.hashAlgorithm}, expected SHA-256`
      );
    }
    if (tstInfo.messageImprint.hashedMessage.toLowerCase() !== digest.toLowerCase()) {
      throw new Error(
        `TSA imprint does not match the requested digest ` +
          `(requested ${digest.toLowerCase()}, token carries ` +
          `${tstInfo.messageImprint.hashedMessage.toLowerCase()})`
      );
    }

    // RFC 3161 §2.4.2 makes echoing the nonce mandatory when the request
    // carried one, so a missing or different nonce means this token was not
    // minted for this request — a replay.
    const sentNonce = toPositiveInteger(nonce).toString('hex');
    if (!nonceMatches(tstInfo.nonce, sentNonce)) {
      throw new Error(
        tstInfo.nonce === undefined
          ? 'TSA response omitted the nonce that was sent; cannot prove the token is not a replay'
          : 'TSA response nonce does not match the nonce that was sent (replayed or cached token)'
      );
    }

    // Metadata stays best-effort: it is descriptive (genTime, TSA name, policy
    // OID), not load-bearing, and the checks above have already established
    // that the token is real.
    const metadata: TimestampResult['metadata'] = extractRFC3161Metadata(token);

    // tzun-anchor/1 §10.5 steps 1 to 3, which every verifier holds the
    // record's token to. A token that passes the checks above and not these is
    // kept, and reported (see `TimestampResult.conformance`).
    return { token, metadata, conformance: timestampConformance(token, digest) };
  }

  /**
   * POST the query and read the whole reply body, rejecting a reply that is
   * not a timestamp response before its body is read.
   */
  private async fetchReply(
    tsaUrl: string,
    query: Buffer,
    signal: AbortSignal
  ): Promise<ArrayBuffer> {
    const response = await this.fetchFn(tsaUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/timestamp-query',
      },
      body: query,
      signal,
    });

    if (!response.ok) {
      throw new Error(
        `TSA request failed: HTTP ${response.status} ${response.statusText}`
      );
    }

    // A Content-Type that is clearly not a timestamp reply is the cheapest way
    // to name the real-world misconfiguration (TZUN_TSA_URL pointed at a site
    // root, a captive portal, a CDN error page served with HTTP 200) in the
    // error message. It is NOT the security boundary — the structural checks
    // in doRequestTimestamp are — so it stays permissive: absent header, or the
    // `application/timestamp-response` / `application/octet-stream` spellings
    // some TSAs use, are all accepted.
    const contentType = readContentType(response);
    if (contentType && !ACCEPTED_RESPONSE_TYPES.has(contentType)) {
      throw new Error(
        `TSA returned Content-Type "${contentType}", not an RFC 3161 timestamp reply. ` +
          `Check that the TSA URL points at the timestamping endpoint (e.g. .../tsr).`
      );
    }

    return response.arrayBuffer();
  }
}

/** Response media types accepted as an RFC 3161 reply. */
const ACCEPTED_RESPONSE_TYPES = new Set([
  'application/timestamp-reply',
  'application/timestamp-response',
  'application/octet-stream',
]);

/**
 * Read the lower-cased media type from a fetch Response, tolerating the
 * hand-rolled Response stand-ins used in tests (which may have no headers).
 */
function readContentType(response: Response): string | null {
  const raw = response.headers?.get?.('content-type');
  if (!raw) return null;
  return raw.split(';')[0].trim().toLowerCase();
}

/**
 * Convenience function: request a timestamp using default config.
 */
export async function requestTimestamp(
  digest: string,
  config?: RFC3161Config
): Promise<TimestampResult> {
  const client = new RFC3161Client(config);
  return client.requestTimestamp(digest);
}
