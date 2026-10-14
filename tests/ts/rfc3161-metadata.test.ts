import { createHash } from 'crypto';
import { AttestationArtifacts } from '@tzun/engine';
import {
  parseTimestampResponse,
  extractTSTInfo,
  parsePKIStatus,
  extractPKIStatus,
  extractRFC3161Metadata,
} from '../../src/attestation/rfc3161-verify';

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

describe('RFC 3161 Metadata', () => {
  describe('AttestationArtifacts.rfc3161Metadata type', () => {
    it('accepts valid rfc3161Metadata', () => {
      const artifacts: AttestationArtifacts = {
        rfc3161Token: 'base64-token',
        rfc3161Metadata: {
          genTime: '2026-04-09T12:00:00.000Z',
          tsaName: 'FreeTSA',
          policyOid: '1.2.3.4',
          status: 'granted',
        },
      };

      expect(artifacts.rfc3161Metadata).toBeDefined();
      expect(artifacts.rfc3161Metadata!.status).toBe('granted');
    });

    it('accepts rfc3161Metadata with only required fields', () => {
      const artifacts: AttestationArtifacts = {
        rfc3161Token: 'base64-token',
        rfc3161Metadata: {
          genTime: '2026-04-09T12:00:00.000Z',
          status: 'granted',
        },
      };

      expect(artifacts.rfc3161Metadata!.tsaName).toBeUndefined();
      expect(artifacts.rfc3161Metadata!.policyOid).toBeUndefined();
    });
  });

  describe('parsePKIStatus', () => {
    it('maps 0 to granted', () => {
      expect(parsePKIStatus(0)).toBe('granted');
    });

    it('maps 1 to grantedWithMods', () => {
      expect(parsePKIStatus(1)).toBe('grantedWithMods');
    });

    it('maps 2 to rejection', () => {
      expect(parsePKIStatus(2)).toBe('rejection');
    });

    it('maps 3 to waiting', () => {
      expect(parsePKIStatus(3)).toBe('waiting');
    });

    it('maps unknown values to rejection', () => {
      expect(parsePKIStatus(99)).toBe('rejection');
    });
  });

  describe('PKIStatusInfo parsing', () => {
    it('extractTSTInfo throws on non-success PKIStatus', () => {
      const asn1js = require('asn1js');
      const rejectionStatus = new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.Integer({ value: 2 }), // rejection
            ],
          }),
        ],
      });

      expect(() => extractTSTInfo(rejectionStatus)).toThrow(/non-success status/);
    });

    it('extractTSTInfo accepts PKIStatus 0 (granted)', () => {
      const asn1js = require('asn1js');
      const grantedStatus = new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.Integer({ value: 0 }), // granted
            ],
          }),
          // Missing timeStampToken -- will throw "does not contain"
        ],
      });

      expect(() => extractTSTInfo(grantedStatus)).toThrow(/does not contain/);
    });

    it('extractTSTInfo accepts PKIStatus 1 (grantedWithMods)', () => {
      const asn1js = require('asn1js');
      const grantedWithMods = new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.Integer({ value: 1 }), // grantedWithMods
            ],
          }),
        ],
      });

      expect(() => extractTSTInfo(grantedWithMods)).toThrow(/does not contain/);
    });
  });

  describe('extractPKIStatus', () => {
    it('extracts status from valid TimeStampResp structure', () => {
      const asn1js = require('asn1js');
      const tsResp = new asn1js.Sequence({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.Integer({ value: 0 }),
            ],
          }),
        ],
      });

      expect(extractPKIStatus(tsResp)).toBe(0);
    });

    it('throws on malformed structure', () => {
      const asn1js = require('asn1js');
      const malformed = new asn1js.Sequence({ value: [] });

      expect(() => extractPKIStatus(malformed)).toThrow(/Could not extract/);
    });
  });

  describe('extractRFC3161Metadata', () => {
    it('returns null for invalid token', () => {
      expect(extractRFC3161Metadata('not-valid')).toBeNull();
    });

    it('returns null for empty string', () => {
      expect(extractRFC3161Metadata('')).toBeNull();
    });
  });

  describe('RFC3161Client metadata extraction', () => {
    // The fixture below is a PKIStatusInfo saying "granted" with no
    // timeStampToken at all. Stored as an rfc3161Token, that 12-byte
    // non-token would satisfy any check that only asks whether a token is
    // present. The client requires a readable TSTInfo, so it refuses the
    // response. The test below covers metadata coming back alongside a
    // response that actually contains a token.
    it('rejects a granted PKIStatus that carries no timeStampToken', async () => {
      const { RFC3161Client } = require('../../src/attestation/rfc3161');

      const mockTsaResponse = createMockTsaResponse();
      const mockFetch = jest.fn().mockResolvedValue({
        ok: true,
        arrayBuffer: async () => mockTsaResponse.buffer.slice(
          mockTsaResponse.buffer.byteOffset,
          mockTsaResponse.buffer.byteOffset + mockTsaResponse.buffer.byteLength,
        ),
      });

      const client = new RFC3161Client({ fetchFn: mockFetch });

      await expect(client.requestTimestamp(sha256('test'))).rejects.toThrow(
        /does not contain a readable TSTInfo/,
      );
    });

    it('requestTimestamp returns metadata alongside token', async () => {
      const { RFC3161Client } = require('../../src/attestation/rfc3161');
      const { mockTsaFetch } = require('./helpers/mock-tsa');

      const client = new RFC3161Client({ fetchFn: mockTsaFetch() });
      const result = await client.requestTimestamp(sha256('test'));

      expect(typeof result.token).toBe('string');
      expect(result.metadata).not.toBeNull();
      expect(result.metadata.status).toBe('granted');
      expect(typeof result.metadata.genTime).toBe('string');
    });
  });
});

/**
 * Create a minimal mock TSA response buffer.
 * This is a valid DER-encoded TimeStampResp with PKIStatus = 0 (granted)
 * but without a real timestamp token. Used to test the response handling path.
 */
function createMockTsaResponse(): { buffer: Buffer } {
  const asn1js = require('asn1js');
  const resp = new asn1js.Sequence({
    value: [
      new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: 0 }),
        ],
      }),
    ],
  });
  const der = Buffer.from(resp.toBER(false));
  return { buffer: der };
}
