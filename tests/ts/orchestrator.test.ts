import { AttestationOrchestrator } from '../../src/attestation/orchestrator';
import { RFC3161Client } from '../../src/attestation/rfc3161';
import { createHash } from 'crypto';
import { makeSigningTsa, type SigningTsa, type TokenFaults } from './rfc3161-fixture';
import { makeResponse, mockTsaFetch, parseTimestampQuery } from './helpers/mock-tsa';

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

describe('AttestationOrchestrator', () => {
  const testDigest = sha256('test-evidence');

  function createMockTimestampClient(token?: string, error?: Error) {
    return {
      requestTimestamp: error
        ? jest.fn().mockRejectedValue(error)
        : jest.fn().mockResolvedValue({ token: token || 'base64-tsa-token', metadata: null }),
      // The real client always has one; the failure report reads it.
      breakerState: jest.fn().mockReturnValue('closed'),
    } as unknown as RFC3161Client;
  }

  it('returns the timestamp token when the TSA answers', async () => {
    const orchestrator = new AttestationOrchestrator({
      timestampClient: createMockTimestampClient('tsa-token-abc'),
    });

    const result = await orchestrator.attest(testDigest);

    expect(result.rfc3161Token).toBe('tsa-token-abc');
    expect(result.anchor).toBeUndefined();
  });

  it('returns no token, rather than failing, when the timestamp fails', async () => {
    const orchestrator = new AttestationOrchestrator({
      timestampClient: createMockTimestampClient(undefined, new Error('TSA down')),
    });

    const result = await orchestrator.attest(testDigest);

    expect(result).toEqual({});
  });

  it('returns empty artifacts with no timestamp client', async () => {
    const orchestrator = new AttestationOrchestrator({});
    expect(await orchestrator.attest(testDigest)).toEqual({});
  });

  it('includes WebAuthn assertion when provided as input', async () => {
    const orchestrator = new AttestationOrchestrator({
      timestampClient: createMockTimestampClient(),
    });

    const webauthnAssertion = {
      signature: 'sig-data',
      credentialKeyId: 'cred-123',
      algorithm: 'ES256' as const,
    };

    const result = await orchestrator.attest(testDigest, { webauthnAssertion });

    expect(result.webauthnAssertion).toEqual(webauthnAssertion);
  });

  describe('component failures are never silent', () => {
    // sdkLog()'s fallback is one JSON line per event on console.log, and a
    // component failure must reach it when no onLog sink is configured.
    // Otherwise a failed TSA round trip leaves no trace at all: capture()
    // comes back { stored: false, failure: attestation_failure }, the only
    // reason string is in the failures table, and a customer's default logs
    // cannot say why captures fail.
    let logSpy: jest.SpyInstance;
    beforeEach(() => {
      logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    });
    afterEach(() => {
      logSpy.mockRestore();
    });

    function loggedEvents(): Array<Record<string, unknown>> {
      return logSpy.mock.calls
        .map((call) => {
          try {
            return JSON.parse(String(call[0])) as Record<string, unknown>;
          } catch {
            return null;
          }
        })
        .filter((e): e is Record<string, unknown> => e !== null);
    }

    it('logs attestation_component_failed to the console when no onLog sink is configured', async () => {
      const orchestrator = new AttestationOrchestrator({
        timestampClient: createMockTimestampClient(
          undefined,
          new Error('getaddrinfo ENOTFOUND typo-tsa.example'),
        ),
      });

      const result = await orchestrator.attest(testDigest);

      // The outcome is still a partial attestation; the log line is what lets
      // somebody see why.
      expect(result.rfc3161Token).toBeUndefined();
      const failed = loggedEvents().filter((e) => e.event === 'attestation_component_failed');
      expect(failed).toHaveLength(1);
      expect(failed[0]).toMatchObject({
        component: 'timestamp',
        digest: testDigest,
        errorName: 'Error',
        error: 'getaddrinfo ENOTFOUND typo-tsa.example',
        breaker: 'closed',
      });
    });

    it('routes through onLog alone — not the console — when a sink is configured', async () => {
      const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
      const orchestrator = new AttestationOrchestrator({
        timestampClient: createMockTimestampClient(undefined, new Error('TSA down')),
        onLog: (event, fields) => events.push({ event, fields }),
      });

      await orchestrator.attest(testDigest);

      expect(events.map((e) => e.event)).toEqual(['attestation_component_failed']);
      expect(events[0].fields).toMatchObject({ component: 'timestamp', error: 'TSA down' });
      expect(logSpy).not.toHaveBeenCalled();
    });
  });

  describe('a token every verifier will refuse is reported at capture (tzun-anchor/1 §10.5)', () => {
    const URL = 'https://private-tsa.example/tsr';
    let tsa: SigningTsa;
    beforeAll(async () => {
      tsa = await makeSigningTsa();
    });

    /** A client whose one authority answers with the fixture's tokens, `faults` broken. */
    const clientFor = (faults: TokenFaults = {}) =>
      new RFC3161Client({
        tsaUrl: URL,
        fetchFn: (async (_url: string, init: RequestInit) => {
          const { digest, nonce } = parseTimestampQuery(Buffer.from(init.body as unknown as Uint8Array));
          return makeResponse(await tsa.issue(digest, nonce, undefined, faults), 'application/timestamp-reply');
        }) as unknown as typeof fetch,
      });

    async function attestWith(client: RFC3161Client) {
      const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
      const orchestrator = new AttestationOrchestrator({ timestampClient: client, onLog: (event, fields) => events.push({ event, fields }) });
      const artifacts = await orchestrator.attest(testDigest);
      return { artifacts, events };
    }

    it('keeps a conformant token and reports nothing', async () => {
      expect((await clientFor().requestTimestamp(testDigest)).conformance).toEqual({ holds: true });
      const { artifacts, events } = await attestWith(clientFor());
      expect(artifacts.rfc3161Token).toBeDefined();
      expect(events).toEqual([]);
    });

    it.each<[string, TokenFaults | 'unsigned', string]>([
      ['a TSTInfo in BER', { berTstInfo: true }, 'malformed'],
      ['no signingCertificate(V2)', { signingCertificate: 'none' }, 'verification_failed'],
      ['a signer with no critical timestamping-only extendedKeyUsage', { signerEku: 'non-critical' }, 'verification_failed'],
      ['no SignerInfo at all', 'unsigned', 'malformed'],
    ])('keeps a token with %s, and reports it as attestation_timestamp_nonconformant', async (_label, faults, reason) => {
      const client = faults === 'unsigned' ? new RFC3161Client({ tsaUrl: URL, fetchFn: mockTsaFetch() as unknown as typeof fetch }) : clientFor(faults);
      const { artifacts, events } = await attestWith(client);
      // The capture is not failed for it: the token passes the client's own checks.
      expect(artifacts.rfc3161Token).toBeDefined();
      expect(events.map((e) => e.event)).toEqual(['attestation_timestamp_nonconformant']);
      expect(events[0].fields).toMatchObject({ digest: testDigest, authorityUrl: URL, reason });
      expect(typeof events[0].fields.error).toBe('string');
    });
  });
});
