// tests/ts/http-attestation-default.test.ts — the HTTP transport's attestation defaults: an
// apiKey init with no attestation config performs no TSA I/O.
import { Tzun } from '../../src/sdk/index';

const okJson = () =>
  new Response(JSON.stringify({ evidenceId: 'e1', canonicalDigest: 'a'.repeat(64), sequenceNumber: 1 }),
    { status: 200, headers: { 'content-type': 'application/json' } }); // the capture success shape

describe('HTTP transport attestation defaults', () => {
  it('apiKey init with NO attestation config performs zero TSA I/O and captures fine', async () => {
    const urls: string[] = [];
    const fetchFn = (async (url: string) => { urls.push(String(url)); return okJson(); }) as unknown as typeof fetch;
    const tzun = await Tzun.init({ apiKey: 'tk_test', apiUrl: 'https://api.example.test', _httpFetchFn: fetchFn });
    const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'approved', reason: 'ok' });
    expect(r.stored).toBe(true);
    expect(urls.every((u) => u.startsWith('https://api.example.test'))).toBe(true); // no freetsa.org
  });

  it('explicit attestation: { require: ["timestamp"] } config is still honored verbatim (client-side attest runs)', async () => {
    // Spy on globalThis.fetch to observe whether a TSA call is attempted — no fetchFn plumbing
    // needed through buildOrchestrator (AttestationConfig has no fetchFn field; the orchestrator
    // uses globalThis.fetch / the rfc3161 client directly).
    const origFetch = globalThis.fetch;
    const tsaUrls: string[] = [];
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input: unknown, init?: unknown) => {
      const url = String(input);
      if (url.includes('tsa.example.test')) {
        tsaUrls.push(url);
        return new Response(new ArrayBuffer(8), { status: 200 });
      }
      // pass through capture POSTs to the fetchFn below
      return origFetch(input as Parameters<typeof fetch>[0], init as Parameters<typeof fetch>[1]);
    });
    const fetchFn = (async () => okJson()) as unknown as typeof fetch;
    try {
      const tzun = await Tzun.init({
        apiKey: 'tk_test', apiUrl: 'https://api.example.test', _httpFetchFn: fetchFn,
        // Use the actual AttestationConfig shape: timestamp.rfc3161Url threads through
        // to RFC3161Client.tsaUrl so the spy can intercept it.
        attestation: { require: ['timestamp'], timestamp: { rfc3161Url: 'https://tsa.example.test/tsr' } },
      } as never);
      await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'approved', reason: 'ok' });
      expect(tsaUrls.some((u) => u.includes('tsa.example.test'))).toBe(true); // TSA attempt observed
    } finally {
      jest.restoreAllMocks();
    }
  });

  it('explicit attestation: { require: [] } + apiKey → no throw, no TSA I/O (mandate bypass applies to explicit path too)', async () => {
    const urls: string[] = [];
    const fetchFn = (async (url: string) => { urls.push(String(url)); return okJson(); }) as unknown as typeof fetch;
    // explicit require:[] without mode on HTTP transport ALSO bypasses the prod mandate
    // (validateAttestationConfig is told the transport is HTTP: usesHttpTransport)
    const tzun = await Tzun.init({
      apiKey: 'tk_test', apiUrl: 'https://api.example.test', _httpFetchFn: fetchFn,
      attestation: { require: [] },
    } as never);
    const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'approved', reason: 'ok' });
    expect(r.stored).toBe(true);
    expect(urls.every((u) => u.startsWith('https://api.example.test'))).toBe(true); // no TSA
  });
});
