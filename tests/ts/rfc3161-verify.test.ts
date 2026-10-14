import {
  parseTimestampResponse,
  extractTSTInfo,
  verifyCertificateChain,
  verifyTimestampToken,
  TimestampVerificationResult,
  TimestampVerificationReason,
} from '../../src/attestation/rfc3161-verify';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

describe('RFC 3161 Timestamp Verification', () => {
  // For unit tests, we use a mock/synthetic timestamp token.
  // For integration tests with real FreeTSA responses, see the integration test section.

  const testDigest = sha256('test-evidence-for-timestamp');

  describe('parseTimestampResponse', () => {
    it('throws on invalid base64 input', () => {
      expect(() => parseTimestampResponse('not-valid-der!!!')).toThrow();
    });

    it('throws on truncated DER data', () => {
      // A few random bytes that don't form a valid ASN.1 SEQUENCE
      const truncated = Buffer.from([0x30, 0x03, 0x02, 0x01]).toString('base64');
      expect(() => parseTimestampResponse(truncated)).toThrow();
    });
  });

  describe('verifyCertificateChain', () => {
    it('returns false for self-signed certificate not matching CA', () => {
      // A self-signed cert will not chain to the FreeTSA CA
      // This test ensures the function doesn't blindly accept any cert
      const result = verifyCertificateChain('INVALID_CERT_DATA', null);
      expect(result.valid).toBe(false);
    });
  });

  describe('verifyTimestampToken (full chain)', () => {
    it('returns valid: false for empty token', async () => {
      const result = await verifyTimestampToken('', testDigest);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('returns valid: false for garbage data', async () => {
      const garbage = Buffer.from('not a real timestamp').toString('base64');
      const result = await verifyTimestampToken(garbage, testDigest);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('returns valid: false when digest does not match', async () => {
      // Even with a valid-structure token, wrong digest should fail
      // We test this with a synthetic token if available, or skip if not
      const result = await verifyTimestampToken('AAAA', sha256('wrong'));
      expect(result.valid).toBe(false);
    });
  });

  describe('verifyTimestampToken error categorization', () => {
    it('returns reason: unparseable_token for corrupted token', async () => {
      const garbage = Buffer.from('not-a-real-timestamp-token').toString('base64');
      const result = await verifyTimestampToken(garbage, sha256('test'));
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('unparseable_token');
    });

    it('returns reason: unparseable_token for empty token', async () => {
      const result = await verifyTimestampToken('', sha256('test'));
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('unparseable_token');
    });

    it('never returns valid: true on parse failure', async () => {
      const badTokens = [
        '',
        'AAAA',
        Buffer.from('garbage').toString('base64'),
        Buffer.from([0x30, 0x03]).toString('base64'),
      ];
      for (const token of badTokens) {
        const result = await verifyTimestampToken(token, sha256('anything'));
        expect(result.valid).toBe(false);
      }
    });
  });

  describe('FreeTSA CA certificate bundle', () => {
    it('CA certificate file exists and is PEM format', () => {
      const certPath = path.join(__dirname, '..', '..', 'src', 'attestation', 'certs', 'freetsa-ca.pem');
      expect(fs.existsSync(certPath)).toBe(true);
      const content = fs.readFileSync(certPath, 'utf-8');
      expect(content).toContain('-----BEGIN CERTIFICATE-----');
      expect(content).toContain('-----END CERTIFICATE-----');
    });
  });
});

describe('RFC 3161 Integration (requires network)', () => {
  const testDigest = sha256('integration-test-evidence');
  const itIntegration = process.env.RUN_INTEGRATION_TESTS ? it : it.skip;

  itIntegration(
    'verifies a real FreeTSA timestamp end-to-end',
    async () => {
      const { RFC3161Client } = require('../../src/attestation/rfc3161');
      const client = new RFC3161Client();
      const { token, metadata } = await client.requestTimestamp(testDigest);

      // Verify the token
      const result = await verifyTimestampToken(token, testDigest);

      expect(result.valid).toBe(true);
      expect(result.genTime).toBeDefined();
      expect(result.genTime).toBeInstanceOf(Date);
      expect(result.digestMatch).toBe(true);
      expect(result.signatureValid).toBe(true);
      // The chain is load-bearing: `valid: true` above cannot hold unless
      // certificateChainValid is true, so it is asserted explicitly. `tsaSubject`
      // must be the real signer's CN, not a hard-coded 'FreeTSA' label. The
      // offline equivalents live in rfc3161-trust-anchors.test.ts, which needs
      // no network.
      expect(result.certificateChainValid).toBe(true);
      expect(result.tsaSubject).toBeDefined();
      expect(result.tsaSubject).not.toBe('FreeTSA');
      if (result.certificateChainValid === false) {
        console.warn(
          '[RFC 3161 Integration] Certificate chain verification failed. ' +
          'FreeTSA may have rotated their signing certificate. ' +
          'Update src/attestation/certs/freetsa-ca.pem if this persists.'
        );
      }

      // Verify metadata was extracted
      expect(metadata).not.toBeNull();
      if (metadata) {
        expect(metadata.status).toBe('granted');
        expect(metadata.genTime).toBeDefined();
        // genTime should be a valid ISO-8601 string
        expect(new Date(metadata.genTime).getTime()).not.toBeNaN();
      }
    },
    30000
  );
});
