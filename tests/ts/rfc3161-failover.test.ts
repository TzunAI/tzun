/**
 * RFC 3161 timestamp authority failover.
 *
 * With `require: ['timestamp']`, a capture whose only authority is down —
 * somebody else's server, on somebody else's maintenance schedule — returns
 * `{ stored: false, failure: attestation_failure }` and no evidence record;
 * with the timestamp deferrable (the production default) it is stored
 * 'pending' and waits for the retry.
 *
 * These tests pin the failover contract: an ordered list of authorities that
 * defaults to FreeTSA then Sectigo, a token from any one of them satisfying
 * the requirement, a per-authority budget that a first authority which never
 * answers cannot eat entirely, a per-authority circuit breaker so a dead TSA
 * is skipped rather than waited on, a failure report that names every
 * authority and why each one failed, and a default capture list and default
 * trust store that name the same authorities.
 *
 * Every fetch here is a stub. The suite's no-live-network guard
 * (tests/ts/setup/no-live-network.ts) fails any test that reaches a real host.
 */
import { createHash, X509Certificate } from 'crypto';
import {
  RFC3161Client,
  DEFAULT_TIMESTAMP_AUTHORITIES,
  TimestampAuthorityError,
  TimestampResult,
} from '../../src/attestation/rfc3161';
import { resolveTrustAnchors } from '../../src/attestation/rfc3161-verify';
import {
  DEFAULT_TRUST_ANCHOR_AUTHORITIES,
  getTimestampAuthority,
  resolveTimestampAuthorities,
  timestampAuthorityUrls,
} from '../../src/attestation/tsa-registry';
import { Tzun } from '../../src/sdk/index';
import { buildTimestampResponse, parseTimestampQuery, makeResponse } from './helpers/mock-tsa';

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

const PRIMARY = 'https://primary-tsa.example/tsr';
const SECONDARY = 'https://secondary-tsa.example/tsr';
const TERTIARY = 'https://tertiary-tsa.example/tsr';

// The two endpoints an unconfigured client uses, read from the registry rather
// than typed out, so a URL change there cannot leave these tests pointing at a
// stub nobody calls.
const FREETSA = getTimestampAuthority('freetsa')!.url;
const SECTIGO = getTimestampAuthority('sectigo')!.url;

/** SHA-256 fingerprint in the registry's form (`AB:CD:...`). */
function fingerprint(pem: string): string {
  return new X509Certificate(pem).fingerprint256;
}

/** How a stubbed authority behaves for one request. */
type Behaviour =
  /** Mints a structurally valid TimeStampResp echoing the digest and nonce. */
  | { kind: 'ok' }
  /** Connection refused — what undici throws when nothing is listening. */
  | { kind: 'refused' }
  /** HTTP error status. */
  | { kind: 'http'; status: number }
  /** HTTP 200, correct Content-Type, body that is not a DER TimeStampResp. */
  | { kind: 'malformed' }
  /** A genuine, parseable token — minted for somebody else's digest. */
  | { kind: 'wrongDigest' }
  /** Accepts the connection and never answers until the caller aborts. */
  | { kind: 'hang' }
  /** Answers like `ok`, but only after `delayMs`. Aborting first rejects it. */
  | { kind: 'slow'; delayMs: number }
  /**
   * Sends the status line and headers, then never sends the body. Reading the
   * body rejects when the request's signal aborts, which is what undici does.
   */
  | { kind: 'stall' }
  /** Never answers and ignores the abort signal: a fetch that cannot be cancelled. */
  | { kind: 'deaf' };

/** Reject with the error undici raises for an aborted request, once `signal` aborts. */
function rejectOnAbort(signal: AbortSignal | null | undefined, reject: (err: unknown) => void): void {
  const abort = () => reject(new DOMException('The operation was aborted.', 'AbortError'));
  if (signal?.aborted) abort();
  else signal?.addEventListener('abort', abort);
}

/**
 * A `fetch` stand-in that dispatches on URL, so one client can face several
 * authorities with different failure modes. `routes` is mutated in place by
 * the breaker-recovery test to bring a dead authority back.
 */
function routingTsaFetch(routes: Record<string, Behaviour>): jest.Mock {
  return jest.fn(async (url: string, init: RequestInit) => {
    const behaviour = routes[url];
    if (!behaviour) {
      // Not a configured authority. Modelled as a connection failure so a
      // client that ignores the authority list fails loudly rather than
      // silently passing on a stub it was never pointed at.
      throw new TypeError(`fetch failed: nothing is listening on ${url}`);
    }

    switch (behaviour.kind) {
      case 'refused':
        throw new TypeError(`fetch failed: ECONNREFUSED ${url}`);

      case 'http':
        return {
          ok: false,
          status: behaviour.status,
          statusText: behaviour.status === 500 ? 'Internal Server Error' : 'Error',
        };

      case 'malformed':
        return makeResponse(
          Buffer.from('not-der-at-all', 'utf8'),
          'application/timestamp-reply',
        );

      case 'hang':
        return new Promise((_resolve, reject) => rejectOnAbort(init.signal, reject));

      case 'deaf':
        return new Promise(() => {});

      case 'stall':
        return {
          ok: true,
          status: 200,
          statusText: 'OK',
          headers: {
            get: (name: string) =>
              name.toLowerCase() === 'content-type' ? 'application/timestamp-reply' : null,
          },
          arrayBuffer: () => new Promise((_resolve, reject) => rejectOnAbort(init.signal, reject)),
        };

      case 'slow': {
        const { digest, nonce } = parseTimestampQuery(Buffer.from(init.body as any));
        const bytes = Buffer.from(buildTimestampResponse(digest, nonce), 'base64');
        return new Promise((resolve, reject) => {
          const timer = setTimeout(
            () => resolve(makeResponse(bytes, 'application/timestamp-reply')),
            behaviour.delayMs,
          );
          rejectOnAbort(init.signal, (err) => {
            clearTimeout(timer);
            reject(err);
          });
        });
      }

      case 'ok':
      case 'wrongDigest': {
        const { digest, nonce } = parseTimestampQuery(Buffer.from(init.body as any));
        const responseDigest =
          behaviour.kind === 'wrongDigest' ? sha256('a completely different record') : digest;
        const b64 = buildTimestampResponse(responseDigest, nonce);
        return makeResponse(Buffer.from(b64, 'base64'), 'application/timestamp-reply');
      }
    }
  }) as unknown as jest.Mock;
}

/** The URLs a routing stub was asked for, in order. */
function urlsCalled(fetchFn: jest.Mock): string[] {
  return fetchFn.mock.calls.map((call: any[]) => call[0]);
}

function countCalls(fetchFn: jest.Mock, url: string): number {
  return urlsCalled(fetchFn).filter((u) => u === url).length;
}

describe('RFC 3161 timestamp authority failover', () => {
  const digest = sha256('an evidence record that must get a timestamp');

  describe('ordered failover', () => {
    it('falls over to the second authority when the first refuses the connection', async () => {
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'refused' },
        [SECONDARY]: { kind: 'ok' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      const result = await client.requestTimestamp(digest);

      expect(result.metadata?.status).toBe('granted');
      expect(urlsCalled(fetchFn)).toEqual([PRIMARY, SECONDARY]);
    });

    it('falls over when the first authority answers HTTP 500', async () => {
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'http', status: 500 },
        [SECONDARY]: { kind: 'ok' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(digest)).resolves.toHaveProperty('token');
      expect(urlsCalled(fetchFn)).toEqual([PRIMARY, SECONDARY]);
    });

    it('falls over when the first authority returns a malformed token on HTTP 200', async () => {
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'malformed' },
        [SECONDARY]: { kind: 'ok' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      const result = await client.requestTimestamp(digest);

      // The token that comes back is the SECOND authority's, and it is real.
      expect(result.metadata?.status).toBe('granted');
      expect(Buffer.from(result.token, 'base64').length).toBeGreaterThan(32);
      expect(urlsCalled(fetchFn)).toEqual([PRIMARY, SECONDARY]);
    });

    it('falls over rather than accepting a token minted for another digest', async () => {
      // A caching proxy in front of the primary hands back a genuine,
      // fully-parseable token for somebody else's record. Failing over is the
      // only safe move: accepting it would file another record's proof as this
      // one's, and every downstream timestamp check is a presence check on
      // `rfc3161Token`.
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'wrongDigest' },
        [SECONDARY]: { kind: 'ok' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      const result = await client.requestTimestamp(digest);

      const { extractTSTInfo, parseTimestampResponse } = require('../../src/attestation/rfc3161-verify');
      const tstInfo = extractTSTInfo(parseTimestampResponse(result.token));
      expect(tstInfo.messageImprint.hashedMessage.toLowerCase()).toBe(digest);
      expect(urlsCalled(fetchFn)).toEqual([PRIMARY, SECONDARY]);
    });

    it('stops at the first authority that succeeds', async () => {
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'ok' },
        [SECONDARY]: { kind: 'ok' },
        [TERTIARY]: { kind: 'ok' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY, TERTIARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await client.requestTimestamp(digest);

      expect(urlsCalled(fetchFn)).toEqual([PRIMARY]);
    });

    it('reports which authority issued the token without putting it in the artifact', async () => {
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'refused' },
        [SECONDARY]: { kind: 'ok' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      const result = await client.requestTimestamp(digest);

      expect(result.provenance.authorityUrl).toBe(SECONDARY);
      expect(result.provenance.authorityIndex).toBe(1);
      expect(result.provenance.failedOver).toBe(true);
      expect(result.provenance.attempts).toHaveLength(2);
      expect(result.provenance.attempts[0]).toMatchObject({
        url: PRIMARY,
        outcome: 'failed',
      });
      expect(String(result.provenance.attempts[0].error)).toContain('ECONNREFUSED');
      expect(result.provenance.attempts[1]).toMatchObject({ url: SECONDARY, outcome: 'ok' });

      // `provenance` is operator telemetry, NOT an evidence artifact: the
      // orchestrator copies only `token` and `metadata` into
      // `nonRepudiation`. The issuing authority is already recoverable from
      // the token itself — `metadata.tsaName` is read out of the signing
      // certificate embedded in the CMS SignedData (certReq is TRUE on every
      // request), so duplicating it into the envelope would add an unsigned,
      // forgeable copy of a fact the signature already carries.
      expect(result).not.toHaveProperty('authorityUrl');
    });
  });

  describe('configured lists', () => {
    it('a single rfc3161Url still makes exactly one request to exactly that URL', async () => {
      const fetchFn = routingTsaFetch({ [PRIMARY]: { kind: 'ok' } });
      const client = new RFC3161Client({
        tsaUrl: PRIMARY,
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await client.requestTimestamp(digest);

      expect(urlsCalled(fetchFn)).toEqual([PRIMARY]);
      expect(client.authorities()).toEqual([PRIMARY]);
    });

    it('tsaUrl is the primary and tsaUrls are the fallbacks when both are given', async () => {
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'refused' },
        [SECONDARY]: { kind: 'ok' },
      });
      const client = new RFC3161Client({
        tsaUrl: PRIMARY,
        tsaUrls: [SECONDARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await client.requestTimestamp(digest);

      expect(client.authorities()).toEqual([PRIMARY, SECONDARY]);
      expect(urlsCalled(fetchFn)).toEqual([PRIMARY, SECONDARY]);
    });

    it('the same URL given twice is contacted once', async () => {
      const fetchFn = routingTsaFetch({ [PRIMARY]: { kind: 'refused' } });
      const client = new RFC3161Client({
        tsaUrl: PRIMARY,
        tsaUrls: [PRIMARY, PRIMARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(digest)).rejects.toThrow(TimestampAuthorityError);
      expect(client.authorities()).toEqual([PRIMARY]);
      expect(countCalls(fetchFn, PRIMARY)).toBe(1);
    });
  });

  describe('the default authority list', () => {
    it('is FreeTSA, then Sectigo', () => {
      expect([...DEFAULT_TIMESTAMP_AUTHORITIES]).toEqual([
        'https://freetsa.org/tsr',
        'https://timestamp.sectigo.com',
      ]);
      expect(new RFC3161Client().authorities()).toEqual([...DEFAULT_TIMESTAMP_AUTHORITIES]);
    });

    it('is the URL form of the default trust list, so capture and trust name one set', () => {
      expect([...DEFAULT_TIMESTAMP_AUTHORITIES]).toEqual(
        timestampAuthorityUrls(DEFAULT_TRUST_ANCHOR_AUTHORITIES),
      );
    });

    it('an unconfigured client falls over from FreeTSA to Sectigo', async () => {
      const fetchFn = routingTsaFetch({
        [FREETSA]: { kind: 'refused' },
        [SECTIGO]: { kind: 'ok' },
      });
      const client = new RFC3161Client({ fetchFn: fetchFn as unknown as typeof fetch });

      const result = await client.requestTimestamp(digest);

      expect(result.provenance.authorityUrl).toBe(SECTIGO);
      expect(result.provenance.failedOver).toBe(true);
      expect(urlsCalled(fetchFn)).toEqual([FREETSA, SECTIGO]);
    });

    it('an unconfigured client contacts Sectigo only when FreeTSA fails', async () => {
      // Sectigo is sent a digest only on the captures FreeTSA could not serve.
      const fetchFn = routingTsaFetch({
        [FREETSA]: { kind: 'ok' },
        [SECTIGO]: { kind: 'ok' },
      });
      const client = new RFC3161Client({ fetchFn: fetchFn as unknown as typeof fetch });

      const result = await client.requestTimestamp(digest);

      expect(result.provenance.authorityUrl).toBe(FREETSA);
      expect(urlsCalled(fetchFn)).toEqual([FREETSA]);
    });
  });

  describe('capture and verification cannot disagree', () => {
    // resolveTrustAnchors() reads these before falling back to the default.
    const savedAnchors = process.env.TZUN_TSA_TRUST_ANCHORS;
    const savedAuthorities = process.env.TZUN_TSA_AUTHORITIES;
    beforeEach(() => {
      delete process.env.TZUN_TSA_TRUST_ANCHORS;
      delete process.env.TZUN_TSA_AUTHORITIES;
    });
    afterAll(() => {
      if (savedAnchors === undefined) delete process.env.TZUN_TSA_TRUST_ANCHORS;
      else process.env.TZUN_TSA_TRUST_ANCHORS = savedAnchors;
      if (savedAuthorities === undefined) delete process.env.TZUN_TSA_AUTHORITIES;
      else process.env.TZUN_TSA_AUTHORITIES = savedAuthorities;
    });

    it('every default capture authority chains to a default trust anchor', () => {
      // `verifyAttestation` defaults to `timestampVerification: 'trust-chain'`
      // against `resolveTrustAnchors()`. A default capture authority whose root
      // is not in that store captures happily and then reports
      // `timestampValid: false, timestampReason: 'untrusted_chain'` for every
      // record it produced — silent until somebody verifies.
      const trusted = resolveTrustAnchors().map(fingerprint);

      expect(DEFAULT_TIMESTAMP_AUTHORITIES.length).toBeGreaterThan(0);
      for (const url of DEFAULT_TIMESTAMP_AUTHORITIES) {
        const authority = getTimestampAuthority(url);
        expect(authority).toBeDefined();
        expect(trusted).toContain(authority!.anchorFingerprintSha256);
      }
    });

    it('every default trust anchor belongs to a default capture authority', () => {
      // The converse. Every trusted root is a signing hierarchy that can make
      // a token verify, so the default store holds the roots the default
      // capture list needs and no others — not the rest of the bundled set.
      const needed = resolveTimestampAuthorities([...DEFAULT_TIMESTAMP_AUTHORITIES]).map(
        (a) => a.anchorFingerprintSha256,
      );
      const trusted = resolveTrustAnchors().map(fingerprint);

      expect(trusted.length).toBeGreaterThan(0);
      for (const fp of trusted) {
        expect(needed).toContain(fp);
      }
      expect(trusted).toHaveLength(new Set(needed).size);
    });
  });

  describe('budget', () => {
    it('a hanging first authority does not consume the whole budget', async () => {
      // Why the budget is shared: if each authority got the full per-authority
      // timeout, a list of three wedged TSAs would hold `capture()` open for
      // 3 x timeoutMs. The caller awaits capture() inside its own request
      // handler, so that ceiling is the caller's latency, not ours to spend.
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'hang' },
        [SECONDARY]: { kind: 'ok' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        timeoutMs: 1000,
        totalTimeoutMs: 1000,
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      const startedAt = Date.now();
      const result = await client.requestTimestamp(digest);
      const elapsedMs = Date.now() - startedAt;

      expect(result.metadata?.status).toBe('granted');
      // The assertion that matters: the primary's slice was the remaining
      // budget divided by the authorities still to try (1000 / 2), NOT the
      // full 1000ms per-authority ceiling. The lower bound allows for the
      // millisecond or two of wall clock spent entering the loop.
      expect(result.provenance.attempts[0].timeoutMs).toBeLessThanOrEqual(500);
      expect(result.provenance.attempts[0].timeoutMs).toBeGreaterThan(450);
      // Timing sanity check, generously bounded for CI.
      expect(elapsedMs).toBeLessThan(900);
    }, 10_000);

    describe('under the default budget, a FreeTSA that does not answer still leaves Sectigo its turn', () => {
      // An unconfigured client: timeoutMs 10000, totalTimeoutMs 2 x 10000, and
      // the default pair. Sectigo is made to answer as slowly as the slowest
      // live sample recorded in tsa-registry.ts (3401ms), so this is the case
      // the default has to survive, not the best one.
      const DEFAULT_TOTAL_BUDGET_MS = 20_000;
      const SECTIGO_SLOWEST_SAMPLE_MS = 3401;

      beforeEach(() => {
        // Fakes setTimeout AND Date together, so the client's budget
        // arithmetic and its timers run on the same clock.
        jest.useFakeTimers({ doNotFake: ['nextTick', 'queueMicrotask'] });
      });
      afterEach(() => {
        jest.useRealTimers();
      });

      it.each<[string, Behaviour]>([
        ['holds the request open until it is aborted', { kind: 'hang' }],
        ['sends its headers and then never sends the body', { kind: 'stall' }],
        ['ignores the abort signal altogether', { kind: 'deaf' }],
      ])('FreeTSA %s', async (_label, freetsa) => {
        const fetchFn = routingTsaFetch({
          [FREETSA]: freetsa,
          [SECTIGO]: { kind: 'slow', delayMs: SECTIGO_SLOWEST_SAMPLE_MS },
        });
        const client = new RFC3161Client({ fetchFn: fetchFn as unknown as typeof fetch });

        const startedAt = Date.now();
        let settled: { result?: TimestampResult; error?: unknown; at: number } | undefined;
        client.requestTimestamp(digest).then(
          (result) => (settled = { result, at: Date.now() }),
          (error) => (settled = { error, at: Date.now() }),
        );

        await jest.advanceTimersByTimeAsync(DEFAULT_TOTAL_BUDGET_MS);

        // Settled inside the budget, and with Sectigo's token.
        expect(settled).toBeDefined();
        expect(settled!.error).toBeUndefined();
        expect(settled!.at - startedAt).toBeLessThanOrEqual(DEFAULT_TOTAL_BUDGET_MS);
        const { provenance } = settled!.result!;
        expect(provenance.authorityUrl).toBe(SECTIGO);
        expect(provenance.attempts[0]).toMatchObject({ url: FREETSA, outcome: 'failed' });
        // FreeTSA was cut off at its share, and what was left covers Sectigo's
        // slowest measured answer.
        expect(provenance.attempts[0].durationMs).toBeLessThanOrEqual(
          provenance.attempts[0].timeoutMs!,
        );
        expect(provenance.attempts[1].timeoutMs).toBeGreaterThanOrEqual(SECTIGO_SLOWEST_SAMPLE_MS);
        expect(urlsCalled(fetchFn)).toEqual([FREETSA, SECTIGO]);
      });
    });

    it('a single authority still gets the full per-authority timeout', async () => {
      const fetchFn = routingTsaFetch({ [PRIMARY]: { kind: 'ok' } });
      const client = new RFC3161Client({
        tsaUrl: PRIMARY,
        timeoutMs: 250,
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      const result = await client.requestTimestamp(digest);

      expect(result.provenance.attempts[0].timeoutMs).toBe(250);
    });
  });

  describe('circuit breaker', () => {
    it('skips an authority whose breaker has opened instead of paying its timeout again', async () => {
      const routes: Record<string, Behaviour> = {
        [PRIMARY]: { kind: 'refused' },
        [SECONDARY]: { kind: 'ok' },
      };
      const fetchFn = routingTsaFetch(routes);
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        breaker: { failureThreshold: 2, coolDownMs: 60_000 },
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await client.requestTimestamp(digest); // primary failure 1
      await client.requestTimestamp(digest); // primary failure 2 -> OPEN
      expect(countCalls(fetchFn, PRIMARY)).toBe(2);

      const result = await client.requestTimestamp(digest);

      // No third network call to the dead authority.
      expect(countCalls(fetchFn, PRIMARY)).toBe(2);
      expect(result.provenance.attempts[0]).toMatchObject({
        url: PRIMARY,
        outcome: 'skipped',
      });
      expect(result.provenance.authorityUrl).toBe(SECONDARY);

      const state = client.breakerState();
      expect(state.authorities.find((a) => a.url === PRIMARY)!.state).toBe('OPEN');
      expect(state.authorities.find((a) => a.url === SECONDARY)!.state).toBe('CLOSED');
      // A pool with a live authority is not an open circuit, whatever one
      // member is doing — this is what an operator reads off /demo/health.
      expect(state.state).toBe('CLOSED');
    });

    it('probes a skipped authority again after the cool-down and recovers it', async () => {
      const routes: Record<string, Behaviour> = {
        [PRIMARY]: { kind: 'refused' },
        [SECONDARY]: { kind: 'ok' },
      };
      const fetchFn = routingTsaFetch(routes);
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        breaker: { failureThreshold: 2, coolDownMs: 50 },
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await client.requestTimestamp(digest);
      await client.requestTimestamp(digest);
      expect(client.breakerState().authorities[0].state).toBe('OPEN');

      // The outage ends.
      routes[PRIMARY] = { kind: 'ok' };
      await new Promise((resolve) => setTimeout(resolve, 70));

      const result = await client.requestTimestamp(digest);

      expect(countCalls(fetchFn, PRIMARY)).toBe(3);
      expect(result.provenance.authorityUrl).toBe(PRIMARY);
      expect(result.provenance.failedOver).toBe(false);
      expect(client.breakerState().authorities[0].state).toBe('CLOSED');
    }, 10_000);

    it('reports OPEN only when every authority in the pool is open', async () => {
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'refused' },
        [SECONDARY]: { kind: 'refused' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY],
        breaker: { failureThreshold: 1, coolDownMs: 60_000 },
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(digest)).rejects.toThrow(TimestampAuthorityError);

      expect(client.breakerState().state).toBe('OPEN');
      expect(client.breakerState().authorities.map((a) => a.state)).toEqual(['OPEN', 'OPEN']);
    });
  });

  describe('every authority failing', () => {
    it('throws one error naming every authority and why each one failed', async () => {
      const fetchFn = routingTsaFetch({
        [PRIMARY]: { kind: 'refused' },
        [SECONDARY]: { kind: 'http', status: 500 },
        [TERTIARY]: { kind: 'malformed' },
      });
      const client = new RFC3161Client({
        tsaUrls: [PRIMARY, SECONDARY, TERTIARY],
        fetchFn: fetchFn as unknown as typeof fetch,
      });

      const error = await client.requestTimestamp(digest).then(
        () => {
          throw new Error('expected requestTimestamp to reject');
        },
        (err: unknown) => err as TimestampAuthorityError,
      );

      expect(error).toBeInstanceOf(TimestampAuthorityError);
      expect(error.attempts.map((a) => a.url)).toEqual([PRIMARY, SECONDARY, TERTIARY]);
      // Each authority's own diagnosis survives into the aggregate message —
      // a typo'd URL has to stay distinguishable from an outage.
      expect(error.message).toContain(PRIMARY);
      expect(error.message).toContain('ECONNREFUSED');
      expect(error.message).toContain('TSA request failed: HTTP 500');
      expect(error.message).toContain('not a parseable RFC 3161 TimeStampResp');
    });
  });

  describe('through capture()', () => {
    const input = {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { recommendation: 'approve' },
      action: 'approved',
      reason: 'meets policy',
    };

    it('a dead primary does not stop a capture that requires a timestamp', async () => {
      const savedFetch = globalThis.fetch;
      try {
        globalThis.fetch = routingTsaFetch({
          [PRIMARY]: { kind: 'refused' },
          [SECONDARY]: { kind: 'ok' },
        }) as unknown as typeof fetch;

        const tzun = await Tzun.init({
          mode: 'dev',
          attestation: {
            require: ['timestamp'],
            timestamp: { rfc3161Url: PRIMARY, rfc3161Urls: [SECONDARY] },
          },
        });

        const result = await tzun.capture(input);

        expect(result.stored).toBe(true);
        expect(result.failure).toBeUndefined();
        expect(result.envelope.nonRepudiation.rfc3161Token).toBeDefined();
        expect(result.envelope.attestationStatus).toBe('partial');
        await tzun.close();
      } finally {
        globalThis.fetch = savedFetch;
      }
    });

    it('with no authority configured, a FreeTSA outage falls over to Sectigo and the record is stored', async () => {
      const savedFetch = globalThis.fetch;
      try {
        globalThis.fetch = routingTsaFetch({
          [FREETSA]: { kind: 'refused' },
          [SECTIGO]: { kind: 'ok' },
        }) as unknown as typeof fetch;

        const tzun = await Tzun.init({
          mode: 'dev',
          attestation: { require: ['timestamp'] },
        });

        const result = await tzun.capture(input);

        expect(result.stored).toBe(true);
        expect(result.failure).toBeUndefined();
        expect(result.envelope.nonRepudiation.rfc3161Token).toBeDefined();
        expect(urlsCalled(globalThis.fetch as unknown as jest.Mock)).toEqual([FREETSA, SECTIGO]);
        await tzun.close();
      } finally {
        globalThis.fetch = savedFetch;
      }
    });

    it('logs the failover, naming the authority that was skipped and the one that issued', async () => {
      const savedFetch = globalThis.fetch;
      const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
      try {
        globalThis.fetch = routingTsaFetch({
          [PRIMARY]: { kind: 'refused' },
          [SECONDARY]: { kind: 'ok' },
        }) as unknown as typeof fetch;

        const tzun = await Tzun.init({
          mode: 'dev',
          attestation: {
            require: ['timestamp'],
            timestamp: { rfc3161Url: PRIMARY, rfc3161Urls: [SECONDARY] },
          },
          onLog: (event, fields) => events.push({ event, fields }),
        });

        await tzun.capture(input);

        // A successful failover is the event nobody would otherwise see: the
        // capture worked, so nothing else in the system says the primary TSA
        // has been down since Tuesday.
        const failover = events.filter((e) => e.event === 'attestation_timestamp_failover');
        expect(failover).toHaveLength(1);
        expect(failover[0].fields.authorityUrl).toBe(SECONDARY);
        expect(failover[0].fields.authorityIndex).toBe(1);
        const attempts = failover[0].fields.attempts as Array<Record<string, unknown>>;
        expect(attempts.map((a) => a.url)).toEqual([PRIMARY, SECONDARY]);
        expect(String(attempts[0].error)).toContain('ECONNREFUSED');
        await tzun.close();
      } finally {
        globalThis.fetch = savedFetch;
      }
    });

    it('every authority failing still yields the typed attestation_failure, unchanged', async () => {
      const savedFetch = globalThis.fetch;
      const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
      try {
        globalThis.fetch = routingTsaFetch({
          [PRIMARY]: { kind: 'refused' },
          [SECONDARY]: { kind: 'http', status: 503 },
        }) as unknown as typeof fetch;

        const tzun = await Tzun.init({
          mode: 'dev',
          attestation: {
            require: ['timestamp'],
            timestamp: { rfc3161Url: PRIMARY, rfc3161Urls: [SECONDARY] },
          },
          onLog: (event, fields) => events.push({ event, fields }),
        });

        const result = await tzun.capture(input);

        expect(result.stored).toBe(false);
        expect(result.failure!.failureType).toBe('attestation_failure');
        expect(result.failure!.diagnosticMetadata.missingServices).toContain('timestamp');

        // ...and the log names both authorities and both reasons.
        const failed = events.filter((e) => e.event === 'attestation_component_failed');
        expect(failed).toHaveLength(1);
        const attempts = failed[0].fields.attempts as Array<Record<string, unknown>>;
        expect(attempts.map((a) => a.url)).toEqual([PRIMARY, SECONDARY]);
        expect(String(attempts[0].error)).toContain('ECONNREFUSED');
        expect(String(attempts[1].error)).toContain('HTTP 503');
        await tzun.close();
      } finally {
        globalThis.fetch = savedFetch;
      }
    });
  });
});
