import {
  requestTimestamp,
  buildTimestampQuery,
  RFC3161Client,
  RFC3161Config,
} from '../../src/attestation/rfc3161';
import { createHash } from 'crypto';
import {
  mockTsaFetch,
  buildTimestampResponse,
  parseTimestampQuery,
  makeResponse,
} from './helpers/mock-tsa';

/** The bodies a misconfigured or fronted TSA URL actually returns on HTTP 200. */
const HTML_ERROR_PAGE = '<!doctype html><html><body><h1>503 Service Unavailable</h1></body></html>';

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

describe('RFC 3161 Timestamp Client', () => {
  const testDigest = sha256('test-evidence-record');

  describe('buildTimestampQuery', () => {
    it('produces a Buffer containing the digest bytes', () => {
      const query = buildTimestampQuery(testDigest);
      expect(Buffer.isBuffer(query)).toBe(true);
      expect(query.length).toBeGreaterThan(0);
      const digestBytes = Buffer.from(testDigest, 'hex');
      expect(query.includes(digestBytes)).toBe(true);
    });

    it('throws on invalid hex digest', () => {
      expect(() => buildTimestampQuery('not-hex')).toThrow('Invalid digest');
    });

    it('throws on wrong-length digest', () => {
      expect(() => buildTimestampQuery('abcd')).toThrow('Invalid digest');
    });

    // Cross-language parity guard. The Python port
    // (python/src/tzun_sdk/attestation/rfc3161.py build_timestamp_query) is a
    // byte-for-byte port pinned by python/tests/attestation/fixtures/
    // tsq_golden.hex for the digest 'ab' * 32. Adding the optional nonce must
    // not move the no-nonce encoding, or the two SDKs diverge on the wire.
    it('no-nonce encoding is byte-identical to the Python golden fixture', () => {
      const fs = require('fs');
      const path = require('path');
      const golden = fs
        .readFileSync(
          path.join(__dirname, '../../python/tests/attestation/fixtures/tsq_golden.hex'),
          'utf-8',
        )
        .trim();
      expect(buildTimestampQuery('ab'.repeat(32)).toString('hex')).toBe(golden);
    });

    it('emits the nonce between messageImprint and certReq when supplied', () => {
      const nonce = Buffer.from('0123456789abcdef', 'hex');
      const withNonce = buildTimestampQuery(testDigest, nonce);
      const withoutNonce = buildTimestampQuery(testDigest);

      expect(withNonce.length).toBe(withoutNonce.length + 2 + nonce.length);
      expect(parseTimestampQuery(withNonce).nonce!.toString('hex')).toBe(
        nonce.toString('hex'),
      );
      // certReq must still be the final element (RFC 3161 field order).
      expect(withNonce.subarray(-3).toString('hex')).toBe('0101ff');
    });
  });

  describe('requestTimestamp', () => {
    // An HTTP-200 body is a timestamp only when it is a DER TimeStampResp.
    // Every downstream timestamp decision in the SDK and the platform is a
    // presence check on `rfc3161Token`, so a client that accepted any 200 body
    // would make `require: ['timestamp']` satisfiable by an HTML error page.
    // The positive case, "a 200 from the TSA yields a token", is 'returns the
    // token for a well-formed TimeStampResp' below.
    it('rejects an HTTP-200 body that is not a DER TimeStampResp', async () => {
      const mockFetch = jest
        .fn()
        .mockResolvedValue(makeResponse(Buffer.from('mock-tsa-response', 'utf8'), null));

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(
        /not a parseable RFC 3161 TimeStampResp/
      );
    });

    it('rejects an HTML error page served with HTTP 200', async () => {
      // The production misconfiguration this covers: TZUN_TSA_URL set to the
      // site root instead of .../tsr, or a CDN/captive portal fronting the TSA.
      const mockFetch = jest
        .fn()
        .mockResolvedValue(makeResponse(Buffer.from(HTML_ERROR_PAGE, 'utf8'), 'text/html'));

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(
        /Content-Type "text\/html"/
      );
    });

    it('returns the token for a well-formed TimeStampResp', async () => {
      const mockFetch = mockTsaFetch();

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      const result = await client.requestTimestamp(testDigest);

      expect(typeof result.token).toBe('string');
      expect(() => Buffer.from(result.token, 'base64')).not.toThrow();
      expect(result.metadata?.status).toBe('granted');
    });

    it('rejects a token whose imprint is for a different digest', async () => {
      // A caching proxy (or a swapped-in token) hands back a genuine, fully
      // parseable TimeStampResp — for somebody else's record.
      const otherDigest = sha256('a completely different decision');
      const mockFetch = mockTsaFetch({ overrideDigest: otherDigest });

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(
        /imprint does not match the requested digest/
      );
    });

    it('rejects a response with a non-success PKIStatus', async () => {
      const mockFetch = mockTsaFetch({ status: 2 }); // rejection

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(
        /non-success PKIStatus: rejection/
      );
    });

    it('rejects a token that does not echo the requested nonce', async () => {
      // Replay: the token is genuine and for the right digest, but it was
      // minted for an earlier request, so its nonce is somebody else's.
      const mockFetch = mockTsaFetch({ overrideNonce: Buffer.from('0011223344556677', 'hex') });

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(
        /nonce does not match/
      );
    });

    it('rejects a token that omits the nonce entirely', async () => {
      const mockFetch = mockTsaFetch({ overrideNonce: null });

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(
        /omitted the nonce/
      );
    });

    it('sends a fresh nonce on every request', async () => {
      const mockFetch = mockTsaFetch();
      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await client.requestTimestamp(testDigest);
      await client.requestTimestamp(testDigest);

      const nonces = mockFetch.mock.calls.map(
        (call: any[]) => parseTimestampQuery(Buffer.from(call[1].body))!.nonce!.toString('hex'),
      );
      expect(nonces).toHaveLength(2);
      expect(nonces[0]).not.toBe(nonces[1]);
    });

    it('accepts a nonce the TSA re-encoded with different zero padding', async () => {
      // DER INTEGERs may carry a leading 0x00; a TSA that re-encodes must not
      // be treated as a replay.
      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: (async (_url: string, init: RequestInit) => {
          const { digest, nonce } = parseTimestampQuery(Buffer.from(init.body as any));
          const padded = Buffer.concat([Buffer.from([0x00]), nonce!]);
          const b64 = buildTimestampResponse(digest, padded);
          return makeResponse(Buffer.from(b64, 'base64'), 'application/timestamp-reply');
        }) as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).resolves.toHaveProperty('token');
    });

    it('sends correct Content-Type header', async () => {
      const mockFetch = mockTsaFetch();

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await client.requestTimestamp(testDigest);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://freetsa.org/tsr',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/timestamp-query',
          }),
        })
      );
    });

    it('throws on HTTP error response', async () => {
      const mockFetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(
        'TSA request failed'
      );
    });

    it('throws on network error', async () => {
      const mockFetch = jest.fn().mockRejectedValue(new Error('Network error'));

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(
        'Network error'
      );
    });

    it('uses default FreeTSA URL when not configured', async () => {
      const mockFetch = mockTsaFetch();

      const client = new RFC3161Client({
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await client.requestTimestamp(testDigest);

      expect(mockFetch).toHaveBeenCalledWith(
        'https://freetsa.org/tsr',
        expect.anything()
      );
    });

    it('aborts fetch after configured timeoutMs', async () => {
      const mockFetch = jest.fn().mockImplementation((_url: string, options: RequestInit) => {
        return new Promise((_resolve, reject) => {
          options.signal?.addEventListener('abort', () => {
            reject(new DOMException('The operation was aborted.', 'AbortError'));
          });
        });
      });

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        timeoutMs: 100,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow();
      expect(mockFetch).toHaveBeenCalledWith(
        'https://freetsa.org/tsr',
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      );
    }, 5000);

    it('timeout produces a clear error message', async () => {
      const mockFetch = jest.fn().mockImplementation((_url: string, options: RequestInit) => {
        return new Promise((_resolve, reject) => {
          options.signal?.addEventListener('abort', () => {
            reject(new DOMException('The operation was aborted.', 'AbortError'));
          });
        });
      });

      const client = new RFC3161Client({
        tsaUrl: 'https://freetsa.org/tsr',
        timeoutMs: 50,
        fetchFn: mockFetch as unknown as typeof fetch,
      });

      await expect(client.requestTimestamp(testDigest)).rejects.toThrow(/abort|timeout/i);
    }, 5000);
  });
});
