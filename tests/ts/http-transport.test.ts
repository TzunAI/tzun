import {
  HttpTransport,
  HttpStorageAdapter,
  TzunCaptureError,
  type FetchFn,
} from '../../src/sdk/http-transport';
import { Tzun } from '../../src/sdk/index';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { EvidenceEnvelope } from '@tzun/engine';

const SECRET_KEY = 'sk_test_super_secret_value_123';

/** A minimal self-consistent envelope, like the SDK's normal capture builds. */
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
 * Build a fake fetch that records the last request and returns a configured
 * Response-like object. No network.
 */
function fakeFetch(opts: {
  status: number;
  body: unknown;
}): { fn: FetchFn; calls: Array<{ url: string; init: RequestInit }> } {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fn: FetchFn = async (url, init) => {
    calls.push({ url: String(url), init: init ?? {} });
    return {
      ok: opts.status >= 200 && opts.status < 300,
      status: opts.status,
      async json() {
        return opts.body;
      },
      async text() {
        return JSON.stringify(opts.body);
      },
    } as unknown as Response;
  };
  return { fn, calls };
}

const SUCCESS_BODY = {
  ok: true,
  evidenceId: 'ev-server-1',
  chainId: 'default',
  sequence: 7,
  state: 'captured',
  verification: { digestValid: true, chainLinkValid: true },
  canonicalDigest: 'sha256:server-digest',
  headDigest: 'sha256:server-head',
};

describe('HttpTransport — request shape', () => {
  it('POSTs to <apiUrl>/v1/evidence with Bearer auth and a partial envelope by default', async () => {
    const { fn, calls } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const transport = new HttpTransport({
      apiKey: SECRET_KEY,
      apiUrl: 'https://example.test',
      fetchFn: fn,
    });

    await transport.capture({ envelope: makeEnvelope(), chainId: 'chain-9' });

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call.url).toBe('https://example.test/v1/evidence');
    expect(call.init.method).toBe('POST');

    const headers = call.init.headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Bearer ${SECRET_KEY}`);
    expect(headers['Content-Type']).toBe('application/json');

    const body = JSON.parse(call.init.body as string);
    expect(body.completeness).toBe('partial');
    expect(body.chainId).toBe('chain-9');
    expect(body.envelope).toBeDefined();
    expect(body.envelope.payload.evidenceId).toBe('ev-1');
  });

  it('defaults the base URL to https://api.tzun.ai when apiUrl is omitted', async () => {
    const { fn, calls } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    await transport.capture({ envelope: makeEnvelope() });

    expect(calls[0].url).toBe('https://api.tzun.ai/v1/evidence');
  });

  it('sends an Idempotency-Key header when supplied', async () => {
    const { fn, calls } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    await transport.capture({ envelope: makeEnvelope(), idempotencyKey: 'idem-42' });

    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['Idempotency-Key']).toBe('idem-42');
  });

  it('omits the Idempotency-Key header when not supplied', async () => {
    const { fn, calls } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    await transport.capture({ envelope: makeEnvelope() });

    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['Idempotency-Key']).toBeUndefined();
  });

  it('sends a raw payload (not an envelope) when completeness is raw', async () => {
    const { fn, calls } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    await transport.capture({ completeness: 'raw', payload: { foo: 'bar' } });

    const body = JSON.parse(calls[0].init.body as string);
    expect(body.completeness).toBe('raw');
    expect(body.payload).toEqual({ foo: 'bar' });
    expect(body.envelope).toBeUndefined();
  });
});

describe('HttpTransport — success mapping', () => {
  it('maps 202 to a typed success result with evidenceId and sequence', async () => {
    const { fn } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    const result = await transport.capture({ envelope: makeEnvelope() });

    expect(result).toEqual({
      evidenceId: 'ev-server-1',
      chainId: 'default',
      sequence: 7,
      canonicalDigest: 'sha256:server-digest',
      headDigest: 'sha256:server-head',
    });
  });
});

describe('HttpTransport — error mapping carries stable codes', () => {
  const cases: Array<{ status: number; code: string; extra?: Record<string, unknown> }> = [
    { status: 401, code: 'unauthenticated' },
    { status: 400, code: 'invalid_request' },
    { status: 413, code: 'payload_too_large' },
    { status: 422, code: 'verification_failed', extra: { failedCheck: 'digest' } },
    { status: 422, code: 'idempotency_conflict' },
    { status: 409, code: 'chain_conflict', extra: { expectedPreviousDigest: 'sha256:expected' } },
    { status: 503, code: 'store_unavailable' },
  ];

  for (const c of cases) {
    it(`maps ${c.status} ${c.code} to a TzunCaptureError with .code==='${c.code}'`, async () => {
      const { fn } = fakeFetch({
        status: c.status,
        body: { ok: false, error: c.code, ...(c.extra ?? {}) },
      });
      const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

      await expect(transport.capture({ envelope: makeEnvelope() })).rejects.toThrow(
        TzunCaptureError,
      );
      try {
        await transport.capture({ envelope: makeEnvelope() });
        throw new Error('expected capture to reject');
      } catch (err) {
        expect(err).toBeInstanceOf(TzunCaptureError);
        const e = err as TzunCaptureError;
        expect(e.code).toBe(c.code);
        expect(e.status).toBe(c.status);
        if (c.extra) {
          for (const [k, v] of Object.entries(c.extra)) {
            expect((e.context as Record<string, unknown>)[k]).toEqual(v);
          }
        }
      }
    });
  }

  it('treats 5xx without a known code as a retryable transport error', async () => {
    const { fn } = fakeFetch({ status: 500, body: { ok: false, error: 'internal' } });
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    try {
      await transport.capture({ envelope: makeEnvelope() });
      throw new Error('expected capture to reject');
    } catch (err) {
      const e = err as TzunCaptureError;
      expect(e).toBeInstanceOf(TzunCaptureError);
      expect(e.code).toBe('internal');
      expect(e.retryable).toBe(true);
    }
  });

  it('treats a network/fetch rejection as a retryable transport error', async () => {
    const fn: FetchFn = async () => {
      throw new Error('ECONNREFUSED');
    };
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    try {
      await transport.capture({ envelope: makeEnvelope() });
      throw new Error('expected capture to reject');
    } catch (err) {
      const e = err as TzunCaptureError;
      expect(e).toBeInstanceOf(TzunCaptureError);
      expect(e.retryable).toBe(true);
    }
  });
});

describe('HttpTransport — never leaks the API key', () => {
  it('does not include the API key in a thrown error message', async () => {
    const { fn } = fakeFetch({ status: 401, body: { ok: false, error: 'unauthenticated' } });
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    try {
      await transport.capture({ envelope: makeEnvelope() });
      throw new Error('expected capture to reject');
    } catch (err) {
      const e = err as TzunCaptureError;
      expect(e.message).not.toContain(SECRET_KEY);
      // Full serialized error (message + JSON of own fields) must not leak it.
      const serialized = `${e.message} ${JSON.stringify({ code: e.code, context: e.context })}`;
      expect(serialized).not.toContain(SECRET_KEY);
    }
  });

  it('does not include the API key in a network-error throw', async () => {
    const fn: FetchFn = async () => {
      throw new Error('boom');
    };
    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn });

    try {
      await transport.capture({ envelope: makeEnvelope() });
      throw new Error('expected capture to reject');
    } catch (err) {
      expect((err as Error).message).not.toContain(SECRET_KEY);
    }
  });
});

describe('HttpStorageAdapter — StorageAdapter integration', () => {
  it('store() POSTs the envelope and resolves (server is authoritative)', async () => {
    const { fn, calls } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const adapter = new HttpStorageAdapter(
      new HttpTransport({ apiKey: SECRET_KEY, apiUrl: 'https://example.test', fetchFn: fn }),
    );

    await expect(adapter.store(makeEnvelope(), 'chain-x')).resolves.toBeUndefined();
    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0].init.body as string);
    expect(body.chainId).toBe('chain-x');
    expect(body.completeness).toBe('partial');
  });

  it('returns safe genesis defaults for chain-restore reads', async () => {
    const { fn } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const adapter = new HttpStorageAdapter(
      new HttpTransport({ apiKey: SECRET_KEY, fetchFn: fn }),
    );

    expect(await adapter.getLastDigest()).toBeNull();
    expect(await adapter.getLastSequence()).toBe(0);
    expect(await adapter.getActiveChainId()).toBe('default');
  });
});

describe('SDK factory — selection by apiKey', () => {
  it('selects the cloud HttpStorageAdapter when apiKey is present', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      apiKey: SECRET_KEY,
      attestation: { require: [] },
    });
    expect(tzun.getStorage()).toBeInstanceOf(HttpStorageAdapter);
    await tzun.close();
  });

  it('uses a local (memory) adapter when no apiKey is set — local mode unaffected', async () => {
    const tzun = await Tzun.init({ mode: 'dev' });
    expect(tzun.getStorage()).toBeInstanceOf(MemoryStorageAdapter);
    expect(tzun.getStorage()).not.toBeInstanceOf(HttpStorageAdapter);
    await tzun.close();
  });

  it('a cloud-configured capture routes through the transport (POSTs once)', async () => {
    const { fn, calls } = fakeFetch({ status: 202, body: SUCCESS_BODY });
    const tzun = await Tzun.init({
      mode: 'dev',
      apiKey: SECRET_KEY,
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: fn,
    });

    const result = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { text: 'do the thing' },
      action: 'approved',
      reason: 'looks good',
    });

    expect(result.stored).toBe(true);
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(calls[0].url).toBe('https://example.test/v1/evidence');
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['Authorization']).toBe(`Bearer ${SECRET_KEY}`);
    await tzun.close();
  });
});

// ---------------------------------------------------------------------------
// The capture POST is bounded by a deadline.
//
// `HttpTransport.capture()` passes fetch an AbortSignal that fires at
// `timeoutMs`, and `redirect: 'error'`. `buildIntercept` awaits
// `tzun.capture()` before returning the vendor's response, so without a
// deadline a wedged api.tzun.ai would turn the evidence service's outage into
// an outage of the customer's own product: their handler would hang until
// Node's ~300 s headers timeout (or a proxy's 100 s origin timeout),
// exhausting their worker pool one decision at a time.
// ---------------------------------------------------------------------------
describe('HttpTransport request deadline', () => {
  it('aborts a hung backend and reports a retryable timeout instead of hanging', async () => {
    let abortedWith: string | null = null;

    // A fetch that NEVER resolves on its own — it settles only when the
    // transport's own AbortSignal fires.
    const hungFetch: FetchFn = (_url, init) =>
      new Promise((_resolve, reject) => {
        const signal = init?.signal as AbortSignal | undefined;
        if (!signal) return; // no deadline wired → hangs forever
        signal.addEventListener('abort', () => {
          abortedWith = 'aborted';
          const err = new Error('The operation was aborted.');
          err.name = 'AbortError';
          reject(err);
        });
      });

    const transport = new HttpTransport({
      apiKey: SECRET_KEY,
      fetchFn: hungFetch,
      timeoutMs: 40,
    });

    const started = Date.now();
    // Fail the test loudly rather than hanging the suite if no deadline fires.
    const raced = await Promise.race([
      transport.capture({ envelope: makeEnvelope() }).then(
        () => 'resolved' as const,
        (e: unknown) => e,
      ),
      new Promise((r) => setTimeout(() => r('STILL_PENDING'), 2_000)),
    ]);
    const elapsed = Date.now() - started;

    expect(raced).not.toBe('STILL_PENDING');
    expect(raced).toBeInstanceOf(TzunCaptureError);

    const err = raced as TzunCaptureError;
    expect(err.code).toBe('transport_error');
    expect(err.retryable).toBe(true);
    expect(err.context.cause).toBe('timeout');
    expect(err.context.timeoutMs).toBe(40);
    // The key must never reach the message or context.
    expect(err.message).not.toContain(SECRET_KEY);
    expect(JSON.stringify(err.context)).not.toContain(SECRET_KEY);

    expect(abortedWith).toBe('aborted');
    expect(elapsed).toBeLessThan(1_500);
  });

  it('passes an AbortSignal and refuses redirects on every capture POST', async () => {
    let seenInit: RequestInit | undefined;
    const okFetch: FetchFn = async (_url, init) => {
      seenInit = init;
      return {
        status: 202,
        ok: true,
        json: async () => ({
          evidenceId: 'ev-1',
          chainId: 'default',
          sequence: 1,
          canonicalDigest: 'sha256:abc',
          headDigest: 'sha256:abc',
        }),
      } as unknown as Response;
    };

    const transport = new HttpTransport({ apiKey: SECRET_KEY, fetchFn: okFetch });
    await transport.capture({ envelope: makeEnvelope() });

    expect(seenInit?.signal).toBeInstanceOf(AbortSignal);
    expect((seenInit?.signal as AbortSignal).aborted).toBe(false);
    // A 3xx must not silently turn the POST into a GET that drops the envelope.
    expect(seenInit?.redirect).toBe('error');
  });

  it('clears the deadline once the exchange completes (no lingering abort)', async () => {
    let capturedSignal: AbortSignal | undefined;
    const okFetch: FetchFn = async (_url, init) => {
      capturedSignal = init?.signal as AbortSignal;
      return {
        status: 202,
        ok: true,
        json: async () => ({
          evidenceId: 'ev-1',
          chainId: 'default',
          sequence: 1,
          canonicalDigest: 'sha256:abc',
          headDigest: 'sha256:abc',
        }),
      } as unknown as Response;
    };

    const transport = new HttpTransport({
      apiKey: SECRET_KEY,
      fetchFn: okFetch,
      timeoutMs: 30,
    });
    await transport.capture({ envelope: makeEnvelope() });

    await new Promise((r) => setTimeout(r, 80));
    expect(capturedSignal?.aborted).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tzun.capture() keeps a typed cloud error's code, status and retryability.
//
// HttpTransport.capture() throws TzunCaptureError carrying the backend's
// stable wire code, HTTP status, a `retryable` flag and structured context.
// Tzun.capture() — the only public surface — maps it to a cloud `failureType`
// and carries the code, status and `retryable` in diagnosticMetadata. Flattened
// to `failureType: 'serialization_failure'` and a message string, a revoked API
// key (401), a chain conflict (409), an over-size payload (413), a store
// outage (503) and a DNS failure would be indistinguishable, alerting keyed on
// `failureType` would file every one of them as a payload bug, and a caller
// could not tell which failures are safe to retry.
// ---------------------------------------------------------------------------
describe('Tzun.capture() cloud failure taxonomy', () => {
  async function captureAgainst(status: number, body: unknown) {
    const { fn } = fakeFetch({ status, body });
    const logs: Array<{ event: string; data: Record<string, unknown> }> = [];
    const tzun = await Tzun.init({
      mode: 'dev',
      apiKey: SECRET_KEY,
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: fn,
      onLog: (event: string, data: Record<string, unknown>) => {
        logs.push({ event, data });
      },
    } as Parameters<typeof Tzun.init>[0]);

    const result = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { text: 'do the thing' },
      action: 'approved',
      reason: 'looks good',
    });
    await tzun.close();
    return { result, logs };
  }

  it('maps a 401 to cloud_unauthenticated, not serialization_failure', async () => {
    const { result } = await captureAgainst(401, { ok: false, error: 'unauthenticated' });

    expect(result.stored).toBe(false);
    expect(result.failure?.failureType).toBe('cloud_unauthenticated');
    expect(result.failure?.failureType).not.toBe('serialization_failure');
    expect(result.failure?.diagnosticMetadata.code).toBe('unauthenticated');
    expect(result.failure?.diagnosticMetadata.status).toBe(401);
    // A revoked key is NOT worth retrying — the whole point of the flag.
    expect(result.failure?.diagnosticMetadata.retryable).toBe(false);
    expect(JSON.stringify(result.failure)).not.toContain(SECRET_KEY);
  });

  it('maps a 409 to cloud_chain_conflict and keeps the server context fields', async () => {
    const { result } = await captureAgainst(409, {
      ok: false,
      error: 'chain_conflict',
      expectedPreviousDigest: 'sha256:server-head',
    });

    expect(result.failure?.failureType).toBe('cloud_chain_conflict');
    expect(result.failure?.diagnosticMetadata.retryable).toBe(false);
    expect(result.failure?.diagnosticMetadata.expectedPreviousDigest).toBe(
      'sha256:server-head',
    );
    // This fake 409s forever with a digest and no `expectedSequence`, so the
    // capture loop ran its whole default budget before surfacing the
    // conflict — and the failure record says so. An operator reading
    // `attempts: 10` knows the head was contested ten times in a row, which
    // is a different fact from a single refusal.
    expect(result.failure?.diagnosticMetadata.attempts).toBe(10);
  });

  it('maps a 503 to cloud_store_unavailable and marks it retryable', async () => {
    const { result } = await captureAgainst(503, { ok: false, error: 'store_unavailable' });

    expect(result.failure?.failureType).toBe('cloud_store_unavailable');
    expect(result.failure?.diagnosticMetadata.status).toBe(503);
    // A store outage IS safe to re-submit; a caller must be able to tell.
    expect(result.failure?.diagnosticMetadata.retryable).toBe(true);
  });

  it('attributes the failure to the evidenceId that was being written', async () => {
    const { result } = await captureAgainst(409, { ok: false, error: 'chain_conflict' });

    // The failure record names the evidenceId being written, so a
    // `capture_failure` log ties the failure to that record rather than
    // logging `evidenceId: null`.
    expect(typeof result.failure?.evidenceId).toBe('string');
    expect(result.failure?.evidenceId).not.toBe('');
  });

  it('is exported so callers can catch it by name', () => {
    // An integrator inspecting diagnosticMetadata needs to `instanceof` the
    // typed error, so it is part of the public exports.
    expect(typeof TzunCaptureError).toBe('function');
    const e = new TzunCaptureError('unauthenticated', 401, { retryable: false });
    expect(e).toBeInstanceOf(Error);
    expect(e.code).toBe('unauthenticated');
  });

  it('reports a network throw from fetch as a retryable cloud_transport_error', async () => {
    const boom: FetchFn = async () => {
      throw Object.assign(new Error('kaboom'), { name: 'TypeError' });
    };
    const tzun = await Tzun.init({
      mode: 'dev',
      apiKey: SECRET_KEY,
      apiUrl: 'https://example.test',
      attestation: { require: [] },
      _httpFetchFn: boom,
    } as Parameters<typeof Tzun.init>[0]);

    const result = await tzun.capture({
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      aiOutput: { text: 'x' },
      action: 'approved',
      reason: 'y',
    });
    await tzun.close();

    // A network throw is still a cloud error (the transport types it), but its
    // code must be transport_error and it must be retryable.
    expect(result.failure?.failureType).toBe('cloud_transport_error');
    expect(result.failure?.diagnosticMetadata.retryable).toBe(true);
  });
});
