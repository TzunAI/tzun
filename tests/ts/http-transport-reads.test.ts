// The cloud transport's read paths.
//
// An API key could capture and could not read: the transport threw
// `TzunCloudReadUnsupportedError` for every read, and the platform's reads were
// cookie-gated. The platform now serves four key-authenticated customer reads,
// and this file drives the transport against their wire shapes with no network.
//
// Wire shapes are the platform's (its customer read routes):
//   GET /v1/app/evidence/:id          -> { envelope, verdict }
//   GET /v1/app/evidence?include=envelope
//                                     -> { evidence: [{ …, envelope, verdict }] }
//   GET /v1/app/evidence/:id/verify   -> { evidenceId, verdict, chain }
//   GET /v1/app/evidence/:id/export   -> { envelope, verdict, chain, server }
//   404                               -> { ok: false, error: 'not_found' }
//   401                               -> { ok: false, error: 'unauthenticated' }
//   429                               -> header Retry-After, body
//                                        { ok:false, error:'rate_limited',
//                                          retryAfterSeconds, scope:'api-key' }
//
// NON-VACUITY: the "throws rather than answering empty" assertions are paired
// with the same call succeeding against a well-formed body, so a transport that
// answered `[]` or `null` everywhere would fail the first half.

import {
  HttpStorageAdapter,
  HttpTransport,
  TzunCloudReadUnsupportedError,
  TzunReadError,
  type FetchFn,
} from '../../src/sdk/http-transport';
import type { EvidenceEnvelope, RecordVerdict } from '@tzun/engine';

const SECRET_KEY = 'sk_test_reads_secret';
const API_URL = 'https://api.example.test';

function makeEnvelope(id = 'ev-1', sequenceNumber = 2): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: id,
      schemaVersion: 'v1.0',
      aiSystemId: 'default',
      aiOutput: { text: 'do the thing' },
      action: 'approved',
      reason: 'looks good',
      capturedAt: '2026-09-19T00:00:00.000Z',
      sequenceNumber,
      contributions: null,
    },
    integrity: { canonicalDigest: 'digest-2', chainLink: 'link-2' },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  } as unknown as EvidenceEnvelope;
}

/** A verdict as the platform sends it: the engine's `RecordVerdict` shape. */
function makeVerdict(over: Partial<RecordVerdict> = {}): RecordVerdict {
  return {
    status: 'valid',
    digest: { status: 'valid', stored: 'digest-2', recomputed: 'digest-2' },
    custodyTrail: {
      status: 'unmeasured',
      reason: 'nothing_to_measure',
      ledger: {
        evidenceId: 'ev-1',
        valid: true,
        rows: 0,
        hashedEntries: 0,
        unhashedEntries: 0,
        failures: [],
      },
    },
    chainLink: { status: 'unmeasured', reason: 'not_checked_on_read', predecessorDigest: null },
    checkedAt: '2026-09-19T01:00:00.000Z',
    ...over,
  } as RecordVerdict;
}

interface Call {
  url: string;
  init?: RequestInit;
}

/** A fetch that records every request and answers with one fixed response. */
function recordingFetch(opts: {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
  calls?: Call[];
}): FetchFn {
  return async (url, init) => {
    opts.calls?.push({ url, init });
    return {
      ok: opts.status >= 200 && opts.status < 300,
      status: opts.status,
      headers: new Headers(opts.headers ?? {}),
      async json() {
        if (opts.body === undefined) throw new SyntaxError('Unexpected token');
        return opts.body;
      },
    } as unknown as Response;
  };
}

function transportWith(fetchFn: FetchFn): HttpTransport {
  return new HttpTransport({ apiKey: SECRET_KEY, apiUrl: API_URL, fetchFn });
}

describe('the cloud transport retrieves a record with its verdict', () => {
  it('GETs /v1/app/evidence/:id with the bearer key and returns { envelope, verdict }', async () => {
    const calls: Call[] = [];
    const envelope = makeEnvelope();
    const verdict = makeVerdict();
    const t = transportWith(recordingFetch({ status: 200, body: { envelope, verdict }, calls }));

    const read = await t.retrieve('ev-1');

    expect(read).toEqual({ envelope, verdict });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${API_URL}/v1/app/evidence/ev-1`);
    expect(calls[0]!.init?.method).toBe('GET');
    expect((calls[0]!.init?.headers as Record<string, string>).Authorization).toBe(
      `Bearer ${SECRET_KEY}`,
    );
    // A 3xx must never re-point a read that carries the key.
    expect(calls[0]!.init?.redirect).toBe('error');
  });

  it('percent-encodes an id so it cannot reach another path', async () => {
    const calls: Call[] = [];
    const t = transportWith(
      recordingFetch({ status: 200, body: { envelope: makeEnvelope(), verdict: makeVerdict() }, calls }),
    );
    await t.retrieve('../keys');
    expect(calls[0]!.url).toBe(`${API_URL}/v1/app/evidence/..%2Fkeys`);
  });

  it('answers null for a record the key cannot see, which is the 404 the platform sends', async () => {
    const t = transportWith(recordingFetch({ status: 404, body: { ok: false, error: 'not_found' } }));
    await expect(t.retrieve('ev-not-mine')).resolves.toBeNull();
  });

  it('never answers a 2xx of the wrong shape with an empty result', async () => {
    const t = transportWith(recordingFetch({ status: 200, body: { evidence: [] } }));
    const err = await t.retrieve('ev-1').then(
      () => null,
      (e) => e as TzunReadError,
    );
    expect(err).toBeInstanceOf(TzunReadError);
    expect(err!.code).toBe('transport_error');
    expect(err!.retryable).toBe(true);
  });
});

describe('the cloud transport lists records with their verdicts', () => {
  it('asks for whole records and returns one { envelope, verdict } per row', async () => {
    const calls: Call[] = [];
    const envelope = makeEnvelope();
    const verdict = makeVerdict();
    const t = transportWith(
      recordingFetch({
        status: 200,
        // The platform's row: the portal projection plus the two fields
        // `include=envelope` adds.
        body: {
          evidence: [
            {
              evidenceId: 'ev-1',
              sequenceNumber: 2,
              capturedAt: '2026-09-19T00:00:00.000Z',
              canonicalDigest: 'digest-2',
              attestationStatus: 'none',
              attestationState: 'pending',
              attestationStatusClaimed: null,
              receivedAt: '2026-09-19T00:00:01.000Z',
              envelope,
              verdict,
            },
          ],
        },
        calls,
      }),
    );

    const page = await t.list({ limit: 25, offset: 50 });

    expect(page).toEqual([{ envelope, verdict }]);
    const url = new URL(calls[0]!.url);
    expect(url.pathname).toBe('/v1/app/evidence');
    expect(url.searchParams.get('include')).toBe('envelope');
    expect(url.searchParams.get('limit')).toBe('25');
    expect(url.searchParams.get('offset')).toBe('50');
  });

  it('refuses a filter the endpoint does not apply rather than returning a page that ignored it', async () => {
    const calls: Call[] = [];
    const fetchFn = recordingFetch({ status: 200, body: { evidence: [] }, calls });
    const t = transportWith(fetchFn);

    for (const options of [
      { aiSystemId: 'crm' },
      { chainId: 'chain-a' },
      { order: 'asc' as const },
    ]) {
      await expect(t.list(options)).rejects.toThrow(TzunCloudReadUnsupportedError);
    }
    // Refused before the request, so nothing was asked of the server.
    expect(calls).toHaveLength(0);

    // Non-vacuity: the filters the endpoint DOES apply are answered.
    await expect(t.list({ limit: 1, offset: 0, order: 'desc' })).resolves.toEqual([]);
    expect(calls).toHaveLength(1);
  });

  it('never answers a 2xx of the wrong shape with an empty page', async () => {
    const t = transportWith(recordingFetch({ status: 200, body: { evidence: 'nope' } }));
    await expect(t.list()).rejects.toBeInstanceOf(TzunReadError);

    // A row missing its envelope is the same refusal: half a record is not a page.
    const partial = transportWith(
      recordingFetch({ status: 200, body: { evidence: [{ evidenceId: 'ev-1' }] } }),
    );
    await expect(partial.list()).rejects.toBeInstanceOf(TzunReadError);
  });
});

describe('the cloud transport verifies and exports', () => {
  const chain = {
    chainId: 'chain-a',
    predecessor: { evidenceId: 'ev-0', sequenceNumber: 1, canonicalDigest: 'digest-1' },
  };

  it('returns the verdict with the chain link measured, and what it was measured against', async () => {
    const calls: Call[] = [];
    const verdict = makeVerdict({
      chainLink: { status: 'valid', predecessorDigest: 'digest-1' },
    });
    const t = transportWith(
      recordingFetch({ status: 200, body: { evidenceId: 'ev-1', verdict, chain }, calls }),
    );

    const verification = await t.verify('ev-1');

    expect(verification).toEqual({ evidenceId: 'ev-1', verdict, chain });
    expect(calls[0]!.url).toBe(`${API_URL}/v1/app/evidence/ev-1/verify`);
  });

  it('returns the export bundle verbatim, verdict, chain and server sidecar', async () => {
    const calls: Call[] = [];
    const envelope = makeEnvelope();
    const verdict = makeVerdict({ chainLink: { status: 'valid', predecessorDigest: 'digest-1' } });
    const bundle = {
      envelope,
      verdict,
      chain,
      server: {
        receivedAt: '2026-09-19T00:00:01.000Z',
        attestation: {
          state: 'attested',
          status: 'partial',
          claimedStatus: 'none',
          rfc3161Token: 'TOKEN',
          artifact: { token: 'TOKEN' },
        },
        custody: {
          hashPreimage: 'sha256(lp(prevEntryHash)||…)',
          entries: [],
          trail: verdict.custodyTrail.ledger,
          offlineTrail: { valid: null, hashedEntries: 0, unhashedEntries: 0, failures: [] },
        },
      },
    };
    const t = transportWith(recordingFetch({ status: 200, body: bundle, calls }));

    await expect(t.exportEvidence('ev-1')).resolves.toEqual(bundle);
    expect(calls[0]!.url).toBe(`${API_URL}/v1/app/evidence/ev-1/export`);
  });

  it('answers null for a record the key cannot see', async () => {
    const notFound = { status: 404, body: { ok: false, error: 'not_found' } };
    await expect(transportWith(recordingFetch(notFound)).verify('x')).resolves.toBeNull();
    await expect(transportWith(recordingFetch(notFound)).exportEvidence('x')).resolves.toBeNull();
  });
});

describe('a failed cloud read carries its wire code to the caller', () => {
  async function readError(opts: {
    status: number;
    body?: unknown;
    headers?: Record<string, string>;
  }): Promise<TzunReadError> {
    const t = transportWith(recordingFetch(opts));
    const err = await t.list().then(
      () => null,
      (e) => e as TzunReadError,
    );
    expect(err).toBeInstanceOf(TzunReadError);
    return err!;
  }

  it('401 reports unauthenticated and is not retryable', async () => {
    const err = await readError({ status: 401, body: { ok: false, error: 'unauthenticated' } });
    expect(err.code).toBe('unauthenticated');
    expect(err.status).toBe(401);
    expect(err.retryable).toBe(false);
    expect(err.operation).toBe('list');
  });

  it('429 reports rate_limited, is retryable, and carries the wait and the scope', async () => {
    const err = await readError({
      status: 429,
      headers: { 'Retry-After': '42' },
      body: { ok: false, error: 'rate_limited', retryAfterSeconds: 42, scope: 'api-key' },
    });
    expect(err.code).toBe('rate_limited');
    expect(err.retryable).toBe(true);
    expect(err.context.retryAfterSeconds).toBe(42);
    expect(err.context.scope).toBe('api-key');
  });

  it("a proxy's 429 with no usable body still yields the wait from Retry-After", async () => {
    const err = await readError({ status: 429, headers: { 'Retry-After': '7' } });
    expect(err.code).toBe('rate_limited');
    expect(err.context.retryAfterSeconds).toBe(7);
  });

  it('404 on a list reaches the caller as not_found rather than an empty page', async () => {
    const err = await readError({ status: 404, body: { ok: false, error: 'not_found' } });
    expect(err.code).toBe('not_found');
  });

  it("the platform's 500 body code reaches the caller, and is retryable", async () => {
    const err = await readError({ status: 500, body: { ok: false, error: 'internal_error' } });
    expect(err.code).toBe('internal_error');
    expect(err.retryable).toBe(true);
  });

  it('never puts the API key in the message or the context', async () => {
    for (const opts of [
      { status: 401, body: { ok: false, error: 'unauthenticated' } },
      { status: 429, body: { ok: false, error: 'rate_limited', retryAfterSeconds: 1 } },
      { status: 500, body: { ok: false, error: 'internal_error' } },
    ]) {
      const err = await readError(opts);
      expect(err.message).not.toContain(SECRET_KEY);
      expect(JSON.stringify(err.context)).not.toContain(SECRET_KEY);
    }
  });

  it('a network failure is a retryable transport_error naming no credential', async () => {
    const t = new HttpTransport({
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      fetchFn: async () => {
        throw new TypeError('fetch failed');
      },
    });
    const err = await t.retrieve('ev-1').then(
      () => null,
      (e) => e as TzunReadError,
    );
    expect(err!.code).toBe('transport_error');
    expect(err!.status).toBe(0);
    expect(err!.retryable).toBe(true);
    expect(err!.message).not.toContain(SECRET_KEY);
  });

  it('a read that outlives its deadline reports the timeout', async () => {
    const t = new HttpTransport({
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      timeoutMs: 5,
      fetchFn: (_url, init) =>
        new Promise((_resolve, reject) => {
          (init?.signal as AbortSignal | undefined)?.addEventListener('abort', () => {
            reject(new Error('aborted'));
          });
        }),
    });
    const err = await t.retrieve('ev-1').then(
      () => null,
      (e) => e as TzunReadError,
    );
    expect(err!.code).toBe('transport_error');
    expect(err!.context.cause).toBe('timeout');
    expect(err!.context.timeoutMs).toBe(5);
  });
});

describe('the cloud storage adapter serves the four reads from the server', () => {
  it('delegates each read to the transport and keeps the verdict', async () => {
    const envelope = makeEnvelope();
    const verdict = makeVerdict();
    const chain = { chainId: 'chain-a', predecessor: null };
    const calls: Call[] = [];
    // One body per path, so each read is answered with the shape its own
    // endpoint sends.
    const byPath: Record<string, unknown> = {
      '/v1/app/evidence/ev-1': { envelope, verdict },
      '/v1/app/evidence': { evidence: [{ evidenceId: 'ev-1', envelope, verdict }] },
      '/v1/app/evidence/ev-1/verify': { evidenceId: 'ev-1', verdict, chain },
      '/v1/app/evidence/ev-1/export': {
        envelope,
        verdict,
        chain,
        server: { receivedAt: null, attestation: {}, custody: {} },
      },
    };
    const transport = new HttpTransport({
      apiKey: SECRET_KEY,
      apiUrl: API_URL,
      fetchFn: async (url, init) => {
        calls.push({ url, init });
        const body = byPath[new URL(url).pathname];
        return {
          ok: body !== undefined,
          status: body !== undefined ? 200 : 404,
          headers: new Headers(),
          async json() {
            return body ?? { ok: false, error: 'not_found' };
          },
        } as unknown as Response;
      },
    });
    const adapter = new HttpStorageAdapter(transport);

    await expect(adapter.retrieveWithVerdict('ev-1')).resolves.toEqual({ envelope, verdict });
    await expect(adapter.listWithVerdicts()).resolves.toEqual([{ envelope, verdict }]);
    await expect(adapter.verifyRecord('ev-1')).resolves.toMatchObject({ evidenceId: 'ev-1' });
    await expect(adapter.exportEvidence('ev-1')).resolves.toMatchObject({ envelope, verdict });
    expect(calls.map((c) => new URL(c.url).pathname)).toEqual([
      '/v1/app/evidence/ev-1',
      '/v1/app/evidence',
      '/v1/app/evidence/ev-1/verify',
      '/v1/app/evidence/ev-1/export',
    ]);
  });

  it('keeps refusing the reads that would have to walk a whole chain', async () => {
    const adapter = new HttpStorageAdapter(
      transportWith(recordingFetch({ status: 200, body: {} })),
    );
    // A verifier handed `[]` / `0` here reads it as "nothing wrong".
    await expect(adapter.listBySequence()).rejects.toThrow(TzunCloudReadUnsupportedError);
    await expect(adapter.getChainLength()).rejects.toThrow(TzunCloudReadUnsupportedError);
    await expect(adapter.listCustodyEntries('ev-1')).rejects.toThrow(TzunCloudReadUnsupportedError);
    await expect(adapter.getChainForRecord()).rejects.toThrow(TzunCloudReadUnsupportedError);
    // `retrieve`/`list` return bare envelopes, which cannot carry the server's
    // verdict — `retrieveWithVerdict`/`listWithVerdicts` are the same reads kept whole.
    await expect(adapter.retrieve('ev-1')).rejects.toThrow(TzunCloudReadUnsupportedError);
    await expect(adapter.list()).rejects.toThrow(TzunCloudReadUnsupportedError);
  });
});

describe('an id no record can have names no request', () => {
  // '.' and '..' pass encodeURIComponent unchanged, and a URL resolver reads
  // them as path segments: /evidence/. is the list route, /evidence/.. its parent.
  it.each(['', '.', '..'])('%j: retrieve, verify and export answer null and send nothing', async (id) => {
    const calls: Call[] = [];
    const t = transportWith(recordingFetch({ status: 200, body: { evidence: [] }, calls }));
    expect(await t.retrieve(id)).toBeNull();
    expect(await t.verify(id)).toBeNull();
    expect(await t.exportEvidence(id)).toBeNull();
    expect(calls).toEqual([]);
  });

  it('an id that only contains dots is still a record id', async () => {
    const calls: Call[] = [];
    const t = transportWith(recordingFetch({ status: 404, body: { ok: false, error: 'not_found' }, calls }));
    expect(await t.retrieve('...')).toBeNull();
    expect(calls.map((c) => c.url)).toEqual([`${API_URL}/v1/app/evidence/...`]);
  });
});
