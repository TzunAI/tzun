/**
 * The RFC 3161 verifier's trust store is injectable, builds a real path, and
 * reports who actually signed the token, with an offline positive fixture.
 *
 * A customer who sets `attestation.timestamp.rfc3161Url` to DigiCert — which
 * the config type supports and production modes mandate — needs a genuine
 * timestamp from that authority to verify, labelled with its real signer. So
 * `verifyTimestampToken` takes the trust anchors to verify against, the path
 * may run through an intermediate rather than being issued *directly* by a
 * bundled root, and `tsaSubject` is the signer certificate's CN on every
 * return path, never a fixed 'FreeTSA' label.
 */
import { makeTsaFixture } from './rfc3161-fixture';
import {
  verifyTimestampToken,
  verifyCertificatePath,
  resolveTrustAnchors,
} from '../../src/attestation/rfc3161-verify';
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import { verifyAnchor } from '../../src/attestation/anchor-verify';
import { trustAnchorsFromPem, UnreadableTrustAnchorError } from '../../src/attestation/rfc3161-token';
import { verifyBundle } from '../../src/export/verify-bundle';

jest.setTimeout(30_000);

describe('RFC 3161 trust anchors', () => {
  const savedEnv = process.env.TZUN_TSA_TRUST_ANCHORS;
  afterEach(() => {
    if (savedEnv === undefined) delete process.env.TZUN_TSA_TRUST_ANCHORS;
    else process.env.TZUN_TSA_TRUST_ANCHORS = savedEnv;
  });

  it('verifies a genuine non-FreeTSA token when its root is supplied', async () => {
    const f = await makeTsaFixture();

    const result = await verifyTimestampToken(f.tokenBase64, f.digestHex, {
      trustAnchorsPem: [f.caPem],
    });

    expect(result.reason).toBeUndefined();
    expect(result.valid).toBe(true);
    expect(result.digestMatch).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.certificateChainValid).toBe(true);
    // Not the string literal 'FreeTSA'.
    expect(result.tsaSubject).toBe(f.signerCN);
    expect(result.genTime?.toISOString()).toBe(f.genTime.toISOString());
  });

  it('still rejects that same token when only the bundled FreeTSA root is trusted', async () => {
    // Non-vacuity for the test above: the token is not universally accepted.
    // Without its root among the anchors, a genuine token is untrusted_chain.
    const f = await makeTsaFixture();

    const result = await verifyTimestampToken(f.tokenBase64, f.digestHex);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('untrusted_chain');
    expect(result.digestMatch).toBe(true);
    expect(result.signatureValid).toBe(true);
    // And even on the failure path it names the real signer rather than
    // asserting FreeTSA issued something FreeTSA never touched.
    expect(result.tsaSubject).toBe(f.signerCN);
  });

  it('builds a path through an intermediate instead of requiring direct issuance', async () => {
    // A public TSA's signing certificate is issued by an intermediate. A check
    // that accepted only certificates issued directly by the root would refuse
    // every such token, so a FreeTSA rotation to an intermediate-issued signer
    // would make every token it issues unverifiable.
    const f = await makeTsaFixture({ withIntermediate: true });
    expect(f.intermediatePem).toBeDefined();

    const result = await verifyTimestampToken(f.tokenBase64, f.digestHex, {
      trustAnchorsPem: [f.caPem],
    });

    expect(result.reason).toBeUndefined();
    expect(result.valid).toBe(true);
    expect(result.tsaSubject).toBe(f.signerCN);
  });

  it('rejects a token whose signing certificate had expired at genTime', async () => {
    // The validity-window branch, reached offline by giving the positive
    // fixture a signing certificate that expired before genTime.
    const f = await makeTsaFixture({
      genTime: new Date('2026-06-01T12:00:00.000Z'),
      signerNotBefore: new Date('2020-01-01T00:00:00Z'),
      signerNotAfter: new Date('2021-01-01T00:00:00Z'),
    });

    const result = await verifyTimestampToken(f.tokenBase64, f.digestHex, {
      trustAnchorsPem: [f.caPem],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('untrusted_chain');
    expect(result.error).toMatch(/not valid at the timestamp's genTime/);
  });

  it('rejects the token when the anchor supplied is a different CA of the same shape', async () => {
    const f = await makeTsaFixture();
    const other = await makeTsaFixture({ caCN: 'Acme Test Root CA' });

    // Same subject CN, different key: the metadata match passes and the
    // signature check is what has to reject it.
    const result = await verifyTimestampToken(f.tokenBase64, f.digestHex, {
      trustAnchorsPem: [other.caPem],
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('untrusted_chain');
  });

  it('rejects a genuine token presented for a different digest', async () => {
    const f = await makeTsaFixture();
    const otherDigest = 'a'.repeat(64);

    const result = await verifyTimestampToken(f.tokenBase64, otherDigest, {
      trustAnchorsPem: [f.caPem],
    });

    expect(result.valid).toBe(false);
    expect(result.digestMatch).toBe(false);
    expect(result.reason).toBe('verification_failed');
  });

  describe('TZUN_TSA_TRUST_ANCHORS', () => {
    it('accepts inline PEM from the environment', async () => {
      const f = await makeTsaFixture();
      process.env.TZUN_TSA_TRUST_ANCHORS = f.caPem;

      const result = await verifyTimestampToken(f.tokenBase64, f.digestHex);
      expect(result.valid).toBe(true);
    });

    it('is overridden by an explicit option', async () => {
      const f = await makeTsaFixture();
      const other = await makeTsaFixture();
      process.env.TZUN_TSA_TRUST_ANCHORS = other.caPem;

      const result = await verifyTimestampToken(f.tokenBase64, f.digestHex, {
        trustAnchorsPem: [f.caPem],
      });
      expect(result.valid).toBe(true);
    });

    it('falls back to the default pair, FreeTSA and Sectigo, when unset', () => {
      delete process.env.TZUN_TSA_TRUST_ANCHORS;
      const anchors = resolveTrustAnchors();
      expect(anchors).toHaveLength(2);
      const { X509Certificate } = require('crypto');
      const subjects = anchors.map((pem: string) => new X509Certificate(pem).subject);
      expect(subjects.some((s: string) => s.includes('www.freetsa.org'))).toBe(true);
      expect(
        subjects.some((s: string) => s.includes('Sectigo Public Time Stamping Root R46')),
      ).toBe(true);
    });
  });

  describe('verifyAttestation plumbing', () => {
    it('passes trustAnchorsPem down to the timestamp check', async () => {
      const f = await makeTsaFixture();

      const withAnchor = await verifyAttestation({ rfc3161Token: f.tokenBase64 }, f.digestHex, undefined, {
        trustAnchorsPem: [f.caPem],
      });
      expect(withAnchor.timestampValid).toBe(true);

      const withoutAnchor = await verifyAttestation({ rfc3161Token: f.tokenBase64 }, f.digestHex);
      expect(withoutAnchor.timestampValid).toBe(false);
      expect(withoutAnchor.timestampReason).toBe('untrusted_chain');
    });
  });

  describe('verifyCertificatePath', () => {
    it('reports the anchor it terminated at', async () => {
      const f = await makeTsaFixture({ withIntermediate: true });
      const result = verifyCertificatePath(f.signerPem, {
        intermediatesPem: [f.intermediatePem!],
        trustAnchorsPem: [f.caPem],
        atTime: f.genTime,
      });
      expect(result.valid).toBe(true);
      expect(result.anchorSubject).toBe('Acme Test Root CA');
    });

    it('fails when the intermediate is withheld', async () => {
      const f = await makeTsaFixture({ withIntermediate: true });
      const result = verifyCertificatePath(f.signerPem, {
        trustAnchorsPem: [f.caPem],
        atTime: f.genTime,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toMatch(/not issued by the trusted CA/);
    });

    it('fails closed, naming it, on an anchor it cannot read, and never searches without it', async () => {
      const f = await makeTsaFixture();
      const result = verifyCertificatePath(f.signerPem, { trustAnchorsPem: ['not a pem'] });
      expect(result.valid).toBe(false);
      expect(result.error).toBe('trust anchor 1 holds no PEM CERTIFICATE block');
      // Beside the genuine anchor, too: the unreadable one is refused, not dropped.
      expect(verifyCertificatePath(f.signerPem, { trustAnchorsPem: [f.caPem, 'not a pem'] })).toEqual({
        valid: false,
        error: 'trust anchor 2 holds no PEM CERTIFICATE block',
      });
    });
  });
});

describe("the environment's RFC 3161 trust, refused when it cannot be read (Verification §3.1)", () => {
  const NAMES = ['TZUN_TSA_TRUST_ANCHORS', 'TZUN_TSA_AUTHORITIES'] as const;
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const name of NAMES) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
  });
  afterEach(() => {
    for (const name of NAMES) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  });

  // verifyBundle refuses before it reads the bundle, and verifyAnchor whatever the artifact holds.
  const verifiers: Array<[string, () => Promise<unknown>]> = [
    ['verifyBundle', () => verifyBundle({})],
    ['verifyAnchor', () => verifyAnchor({}, 'x')],
  ];
  const unreadable: Array<[string, Partial<Record<(typeof NAMES)[number], string>>, string]> = [
    [
      'a TZUN_TSA_TRUST_ANCHORS file that does not exist',
      { TZUN_TSA_TRUST_ANCHORS: '/nonexistent/tzun-trust-root.pem' },
      'TZUN_TSA_TRUST_ANCHORS: /nonexistent/tzun-trust-root.pem cannot be read',
    ],
    [
      'an inline TZUN_TSA_TRUST_ANCHORS block that is not a certificate',
      { TZUN_TSA_TRUST_ANCHORS: '-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----' },
      'trust anchor 1 does not read as a certificate: ',
    ],
    [
      'a TZUN_TSA_AUTHORITIES name the registry does not know',
      { TZUN_TSA_AUTHORITIES: 'no-such-authority' },
      'the trust anchors cannot be read: Unknown timestamp authority "no-such-authority"',
    ],
  ];

  for (const [verifier, run] of verifiers) {
    it.each(unreadable)(`${verifier} refuses %s`, async (_what, env, message) => {
      Object.assign(process.env, env);
      const refusal = run();
      await expect(refusal).rejects.toBeInstanceOf(UnreadableTrustAnchorError);
      await expect(refusal).rejects.toThrow(message);
    });

    it(`${verifier} reads white space alone as no configuration`, async () => {
      process.env.TZUN_TSA_TRUST_ANCHORS = ' \t\n ';
      process.env.TZUN_TSA_AUTHORITIES = '   ';
      await expect(run()).resolves.toBeDefined();
    });
  }

  it('refuses an authority that is not a string as a list that is not one of names', async () => {
    await expect(verifyAnchor({}, 'x', { authorities: [42] as unknown as string[] })).rejects.toThrow('the authorities are not a list of names');
  });
});

describe('a PEM body between its base64 lines', () => {
  it('strips ASCII tab, line feed, vertical tab, form feed, carriage return and space, and nothing else', async () => {
    const f = await makeTsaFixture();
    const lines = f.caPem.trim().split('\n');
    const joined = (separator: string) => `${lines[0]}\n${lines.slice(1, -1).join(separator)}\n${lines[lines.length - 1]}`;
    for (const separator of ['\t', '\v', '\f', '\r\n', '  ']) {
      expect(trustAnchorsFromPem([joined(separator)])).toHaveLength(1);
    }
    for (const separator of ['\x1c', '\x85', '\u00a0', '\u2028', '\u3000', '\ufeff']) {
      expect(() => trustAnchorsFromPem([joined(separator)])).toThrow('trust anchor 1 is not base64');
    }
  });
});
