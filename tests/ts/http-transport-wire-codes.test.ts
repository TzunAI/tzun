// the three wire codes the platform's capture route sends that
// the transport did not know — `rate_limited` (429), `evidence_id_conflict`
// (409) and `invalid_captured_at` (422) — must reach the caller as themselves,
// and a 429 must be reported retryable with its wait time carried in context.
//
// Wire shapes are the platform's:
//   429 — its quota middleware, `sendRateLimited`:
//         header `Retry-After: <n>`, body
//         `{ ok: false, error: 'rate_limited', retryAfterSeconds: n, scope }`
//   409 — its capture route:
//         `{ ok: false, error: 'evidence_id_conflict', evidenceId }`
//   422 — its capture route:
//         `{ ok: false, error: 'invalid_captured_at', reason }`

import {
  HttpTransport,
  TzunCaptureError,
  type FetchFn,
} from '../../src/sdk/http-transport';
import { Tzun } from '../../src/sdk/index';
import { EvidenceEnvelope } from '@tzun/engine';

const SECRET_KEY = 'sk_test_wire_codes_secret_456';

function makeEnvelope(): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: 'ev-1',
      schemaVersion: 'v1.0',
      aiSystemId: 'default',
      aiOutput: { text: 'do the thing' },
      action: 'approved',
      reason: 'looks good',
      capturedAt: '2026-06-07T00:00:00.000Z',
      sequenceNumber: 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: 'sha256:abc', chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

/**
 * A fetch that answers every request with one fixed response. `body` of
 * `undefined` makes `json()` reject, as a non-JSON body does on a real
 * `Response`. No network.
 */
function fixedFetch(opts: {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}): FetchFn {
  return async () =>
    ({
      ok: opts.status >= 200 && opts.status < 300,
      status: opts.status,
      headers: new Headers(opts.headers ?? {}),
      async json() {
        if (opts.body === undefined) throw new SyntaxError('Unexpected token');
        return opts.body;
      },
    }) as unknown as Response;
}

async function captureError(fetchFn: FetchFn): Promise<TzunCaptureError> {
  const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn });
  const err = await transport.capture({ envelope: makeEnvelope() }).then(
    () => {
      throw new Error('expected capture to reject');
    },
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(TzunCaptureError);
  return err as TzunCaptureError;
}

describe('HttpTransport — platform wire codes reach the caller as themselves', () => {
  it('maps 429 rate_limited to code rate_limited, retryable, with retryAfterSeconds and scope', async () => {
    const e = await captureError(
      fixedFetch({
        status: 429,
        headers: { 'Retry-After': '60' },
        body: { ok: false, error: 'rate_limited', retryAfterSeconds: 60, scope: 'ip' },
      }),
    );

    expect(e.code).toBe('rate_limited');
    expect(e.status).toBe(429);
    expect(e.retryable).toBe(true);
    expect(e.context.retryAfterSeconds).toBe(60);
    expect(e.context.scope).toBe('ip');
  });

  it('maps 409 evidence_id_conflict to code evidence_id_conflict, not retryable', async () => {
    const e = await captureError(
      fixedFetch({
        status: 409,
        body: { ok: false, error: 'evidence_id_conflict', evidenceId: 'ev-1' },
      }),
    );

    expect(e.code).toBe('evidence_id_conflict');
    expect(e.status).toBe(409);
    // The same id will collide on every resubmission.
    expect(e.retryable).toBe(false);
    expect(e.context.evidenceId).toBe('ev-1');
  });

  it('maps 422 invalid_captured_at to code invalid_captured_at, not retryable', async () => {
    const e = await captureError(
      fixedFetch({
        status: 422,
        body: { ok: false, error: 'invalid_captured_at', reason: 'future_dated' },
      }),
    );

    expect(e.code).toBe('invalid_captured_at');
    expect(e.status).toBe(422);
    expect(e.retryable).toBe(false);
    expect(e.context.reason).toBe('future_dated');
  });
});

describe('HttpTransport — a 429 without a platform body', () => {
  // A proxy or load balancer in front of the platform answers 429 with its
  // own body, often not JSON. The status alone says "rate limited".
  it('reports a bare 429 as rate_limited and retryable, with the Retry-After delay', async () => {
    const e = await captureError(
      fixedFetch({ status: 429, headers: { 'Retry-After': '120' } }),
    );

    expect(e.code).toBe('rate_limited');
    expect(e.retryable).toBe(true);
    expect(e.context.retryAfterSeconds).toBe(120);
  });

  it('reads an HTTP-date Retry-After as seconds from now, rounded up', async () => {
    const now = Date.parse('2026-09-18T12:00:00.000Z');
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(now);
    try {
      const e = await captureError(
        fixedFetch({
          status: 429,
          headers: { 'Retry-After': 'Fri, 18 Sep 2026 12:01:30 GMT' },
        }),
      );

      expect(e.code).toBe('rate_limited');
      expect(e.context.retryAfterSeconds).toBe(90);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it('reports an HTTP-date Retry-After already in the past as 0', async () => {
    const now = Date.parse('2026-09-18T12:00:00.000Z');
    const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(now);
    try {
      const e = await captureError(
        fixedFetch({
          status: 429,
          headers: { 'Retry-After': 'Fri, 18 Sep 2026 11:59:00 GMT' },
        }),
      );

      expect(e.context.retryAfterSeconds).toBe(0);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it('leaves retryAfterSeconds out when the header is absent or unparsable', async () => {
    const absent = await captureError(fixedFetch({ status: 429 }));
    expect(absent.code).toBe('rate_limited');
    expect(absent.retryable).toBe(true);
    expect('retryAfterSeconds' in absent.context).toBe(false);

    const garbage = await captureError(
      fixedFetch({ status: 429, headers: { 'Retry-After': 'soon-ish' } }),
    );
    expect('retryAfterSeconds' in garbage.context).toBe(false);
  });

  it("keeps the body's retryAfterSeconds over the header when both are present", async () => {
    const e = await captureError(
      fixedFetch({
        status: 429,
        headers: { 'Retry-After': '999' },
        body: { ok: false, error: 'rate_limited', retryAfterSeconds: 42, scope: 'user' },
      }),
    );

    expect(e.context.retryAfterSeconds).toBe(42);
  });

  it('takes the header when the body carries no usable retryAfterSeconds', async () => {
    const e = await captureError(
      fixedFetch({
        status: 429,
        headers: { 'Retry-After': '30' },
        body: { ok: false, error: 'rate_limited', retryAfterSeconds: 'later' },
      }),
    );

    expect(e.context.retryAfterSeconds).toBe(30);
  });
});

describe('HttpTransport — retryability of the other statuses is unchanged', () => {
  const cases: Array<{ status: number; error: string; retryable: boolean }> = [
    { status: 400, error: 'invalid_request', retryable: false },
    { status: 401, error: 'unauthenticated', retryable: false },
    { status: 409, error: 'chain_conflict', retryable: false },
    { status: 413, error: 'payload_too_large', retryable: false },
    { status: 422, error: 'verification_failed', retryable: false },
    { status: 500, error: 'internal', retryable: true },
    { status: 503, error: 'store_unavailable', retryable: true },
  ];

  for (const c of cases) {
    it(`${c.status} ${c.error} → retryable ${c.retryable}`, async () => {
      const e = await captureError(
        fixedFetch({ status: c.status, body: { ok: false, error: c.error } }),
      );
      expect(e.code).toBe(c.error);
      expect(e.retryable).toBe(c.retryable);
    });
  }

  it('still maps an unknown code on a non-5xx, non-429 status to transport_error', async () => {
    const e = await captureError(
      fixedFetch({ status: 418, body: { ok: false, error: 'teapot' } }),
    );
    expect(e.code).toBe('transport_error');
    expect(e.retryable).toBe(false);
    // The server's own code is not in `context` under `error`; only the extra
    // fields are. This pins that the fallback still drops nothing else.
    expect(e.context).toEqual({});
  });
});

describe('Tzun.capture() surfaces the platform wire codes', () => {
  async function captureAgainst(fetchFn: FetchFn) {
    const tzun = await Tzun.init({
      mode: 'dev',
      apiKey: SECRET_KEY,
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: fetchFn,
    } as Parameters<typeof Tzun.init>[0]);
    try {
      return await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { text: 'do the thing' },
        action: 'approved',
        reason: 'looks good',
      });
    } finally {
      await tzun.close();
    }
  }

  it('reports a 429 as cloud_rate_limited, retryable, with the wait time', async () => {
    const result = await captureAgainst(
      fixedFetch({
        status: 429,
        headers: { 'Retry-After': '60' },
        body: { ok: false, error: 'rate_limited', retryAfterSeconds: 60, scope: 'ip' },
      }),
    );

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('cloud_rate_limited');
    expect(result.failure?.diagnosticMetadata.code).toBe('rate_limited');
    expect(result.failure?.diagnosticMetadata.status).toBe(429);
    expect(result.failure?.diagnosticMetadata.retryable).toBe(true);
    expect(result.failure?.diagnosticMetadata.retryAfterSeconds).toBe(60);
    expect(JSON.stringify(result.failure)).not.toContain(SECRET_KEY);
  });

  it('reports a 409 evidence_id_conflict as cloud_evidence_id_conflict', async () => {
    const result = await captureAgainst(
      fixedFetch({
        status: 409,
        body: { ok: false, error: 'evidence_id_conflict', evidenceId: 'ev-x' },
      }),
    );

    expect(result.failure?.failureType).toBe('cloud_evidence_id_conflict');
    expect(result.failure?.diagnosticMetadata.retryable).toBe(false);
  });

  it('reports a 422 invalid_captured_at as cloud_invalid_captured_at', async () => {
    const result = await captureAgainst(
      fixedFetch({
        status: 422,
        body: { ok: false, error: 'invalid_captured_at', reason: 'unparsable' },
      }),
    );

    expect(result.failure?.failureType).toBe('cloud_invalid_captured_at');
    expect(result.failure?.diagnosticMetadata.retryable).toBe(false);
  });
});
