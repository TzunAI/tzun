/**
 * An RFC 3161 token held to tzun-anchor/1 §10.5, steps 1 to 4, in order
 *: the shared verifier behind `verifyTimestampToken`,
 * `verifyAttestation()` and a bundle's `ts.record.token` / `ts.record.trust`.
 *
 * Real FreeTSA and Sectigo tokens (stored responses, no network) meet every
 * rule, as does every other stored authority's. The offline fixture breaks
 * one rule at a time, and each is refused at its step, with its reason.
 */
import { createHash, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { verifyTimestampSteps, verifyTimestampToken } from '../../src/attestation/rfc3161-verify';
import {
  authorityOf,
  readCertificatePem,
  readRfc3161Token,
  searchTrustPath,
  trustAnchorsFromPem,
  UnreadableTrustAnchorError,
  VERIFIER_FAILED,
} from '../../src/attestation/rfc3161-token';
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import { verifyAnchor } from '../../src/attestation/anchor-verify';
import { timestampAuthorityAnchorsPem, listTimestampAuthorities } from '../../src/attestation/tsa-registry';
import { makeTsaFixture, withUnreadableKey, type TokenFaults, type UnreadableKey } from './rfc3161-fixture';

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

interface StoredToken {
  digestHex: string;
  tokenBase64: string;
  signerCommonName: string;
}
const STORED = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'tsa-tokens.json'), 'utf8')) as Record<string, StoredToken>;

/** A PEM certificate with its key made unreadable (`withUnreadableKey`). */
function pemWithUnreadableKey(pem: string, how: UnreadableKey): string {
  const der = withUnreadableKey(Buffer.from(pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, ''), 'base64'), how);
  return `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----`;
}

/** A DER TLV with a definite length. */
function tlv(tag: number, body: Buffer): Buffer {
  const n = body.length;
  const len = n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
}

/** The elements of a DER constructed TLV. */
function children(der: Buffer): Buffer[] {
  let i = 1;
  let len = der[i++];
  if (len & 0x80) {
    const k = len & 0x7f;
    len = 0;
    for (let j = 0; j < k; j++) len = len * 256 + der[i++];
  }
  const end = i + len;
  const out: Buffer[] = [];
  while (i < end) {
    const start = i++;
    let l = der[i++];
    if (l & 0x80) {
      const k = l & 0x7f;
      l = 0;
      for (let j = 0; j < k; j++) l = l * 256 + der[i++];
    }
    i += l;
    out.push(der.subarray(start, i));
  }
  return out;
}

function oidDer(dotted: string): Buffer {
  const p = dotted.split('.').map(Number);
  const out = [p[0] * 40 + p[1]];
  for (const n of p.slice(2)) {
    const chunk = [n & 0x7f];
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift(0x80 | (v & 0x7f));
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

const derOfPem = (pem: string) => Buffer.from(pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, ''), 'base64');
const pemOfDer = (der: Buffer) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;

/**
 * `pem` signed again by `key` under the signature algorithm `oid` with the digest `digest`
 * (`null` for EdDSA), the AlgorithmIdentifier inside and outside tbsCertificate alike, and
 * its SubjectPublicKeyInfo replaced by `spki` when given.
 */
function signedAs(pem: string, key: KeyObject, oid: string, digest: string | null, spki?: Buffer): string {
  const [tbs] = children(derOfPem(pem));
  const fields = children(tbs);
  const at = fields[0][0] === 0xa0 ? 1 : 0;
  const algorithm = tlv(0x30, oidDer(oid));
  fields[at + 1] = algorithm;
  if (spki) fields[at + 5] = spki;
  const newTbs = tlv(0x30, Buffer.concat(fields));
  const signature = cryptoSign(digest, newTbs, key);
  return pemOfDer(tlv(0x30, Buffer.concat([newTbs, algorithm, tlv(0x03, Buffer.concat([Buffer.from([0]), signature]))])));
}

/** `pem` with one bit of its signature flipped. */
function withBrokenSignature(pem: string): string {
  const der = Buffer.from(derOfPem(pem));
  der[der.length - 3] ^= 0x01;
  return pemOfDer(der);
}

/** A subject Name: RDNs in order, each a list of [type OID, string tag, value], the attributes of each RDN in DER order. */
type Rdn = Array<[string, number, string]>;
function nameDer(rdns: Rdn[]): Buffer {
  const tlv = (tag: number, body: Buffer): Buffer => {
    const len = body.length < 0x80 ? Buffer.from([body.length]) : Buffer.from([0x81, body.length]);
    return Buffer.concat([Buffer.from([tag]), len, body]);
  };
  const oidDer = (dotted: string): Buffer => {
    const p = dotted.split('.').map(Number);
    const out = [p[0] * 40 + p[1]];
    for (const n of p.slice(2)) {
      const chunk = [n & 0x7f];
      for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift(0x80 | (v & 0x7f));
      out.push(...chunk);
    }
    return tlv(0x06, Buffer.from(out));
  };
  const value = (tag: number, text: string): Buffer =>
    tag === 30 ? Buffer.from(text, 'utf16le').swap16() : tag === 20 ? Buffer.from(text, 'latin1') : tag === 28 ? Buffer.concat([...text].map((c) => { const b = Buffer.alloc(4); b.writeUInt32BE(c.codePointAt(0)!); return b; })) : Buffer.from(text, 'utf8');
  return tlv(
    0x30,
    Buffer.concat(
      rdns.map((rdn) => tlv(0x31, Buffer.concat(rdn.map(([oid, tag, text]) => tlv(0x30, Buffer.concat([oidDer(oid), tlv(tag, value(tag, text))]))).sort(Buffer.compare)))),
    ),
  );
}

/** `token` with the last occurrence of `from` replaced by `to` (same length, so every length stays true). */
function patchLast(tokenBase64: string, from: string, to: string): string {
  const der = Buffer.from(tokenBase64, 'base64');
  const at = der.lastIndexOf(Buffer.from(from, 'hex'));
  if (at < 0) throw new Error(`no ${from} in the token`);
  Buffer.from(to, 'hex').copy(der, at);
  return der.toString('base64');
}

describe('tzun-anchor/1 §10.5 over an RFC 3161 token', () => {
  describe('real authorities meet every rule', () => {
    it.each(['freetsa', 'sectigo'])('%s: all four steps hold under its bundled root, in every verifier', async (name) => {
      const t = STORED[name];
      const steps = verifyTimestampSteps(t.tokenBase64, t.digestHex, timestampAuthorityAnchorsPem([name]));
      expect(steps).toMatchObject({ token: 'held', trust: 'valid', authority: t.signerCommonName });
      expect(steps.error).toBeUndefined();

      const direct = await verifyTimestampToken(t.tokenBase64, t.digestHex, { authorities: [name] });
      expect(direct).toMatchObject({ valid: true, digestMatch: true, signatureValid: true, certificateChainValid: true });

      const verdict = await verifyAttestation({ rfc3161Token: t.tokenBase64 }, t.digestHex, undefined, { authorities: [name] });
      expect(verdict.timestampValid).toBe(true);
      const structural = await verifyAttestation({ rfc3161Token: t.tokenBase64 }, t.digestHex, undefined, { timestampVerification: 'structural' });
      expect(structural.timestampValid).toBe(true);
    });

    it('every stored authority token meets steps 1 to 3, and chains to its registry root', () => {
      for (const [name, t] of Object.entries(STORED)) {
        const roots = timestampAuthorityAnchorsPem([name]);
        expect([name, verifyTimestampSteps(t.tokenBase64, t.digestHex, roots)]).toEqual([
          name,
          expect.objectContaining({ token: 'held', trust: 'valid' }),
        ]);
      }
    });

    it('a real token checked against another authority\'s root reaches none: not a forgery', () => {
      const t = STORED.freetsa;
      expect(verifyTimestampSteps(t.tokenBase64, t.digestHex, timestampAuthorityAnchorsPem(['sectigo']))).toMatchObject({ token: 'held', trust: 'none' });
      expect(verifyTimestampSteps(t.tokenBase64, t.digestHex, [])).toMatchObject({ token: 'held', trust: 'none' });
    });
  });

  describe('step 1: a DER TimeStampResp carrying its signer certificate', () => {
    it('holds for the fixture\'s default token, through an intermediate, and with a signer named by its key identifier', async () => {
      for (const opts of [{}, { withIntermediate: true }, { signerKeyIdentifier: true }]) {
        const f = await makeTsaFixture(opts);
        expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'valid', authority: f.signerCN });
      }
    });

    it.each<[string, TokenFaults]>([
      ['a TSTInfo in a constructed (BER) OCTET STRING', { berTstInfo: true }],
      ['a genTime whose fraction keeps its trailing zeros', { nonDerGenTime: true }],
      ['no certificate for the SignerInfo', { withoutSignerCertificate: true }],
      ['a digestAlgorithms member that is not an AlgorithmIdentifier', { digestAlgorithms: 'bare-oid' }],
      ['a signer certificate whose public key does not decode', { signerKey: 'bad-key' }],
      ['a certificate of its issuer\'s name, added to a genuine token, whose public key does not decode', { issuerCopy: 'bad-key' }],
    ])('refuses %s: malformed, and nothing after it is checked', async (_label, faults) => {
      const f = await makeTsaFixture({ genTime: new Date('2026-06-01T12:00:00.500Z'), faults });
      const steps = verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem]);
      expect(steps.token).toBe('malformed');
      expect(steps.trust).toBeUndefined();
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: false, reason: 'unparseable_token' });
      const structural = await verifyAttestation({ rfc3161Token: f.tokenBase64 }, f.digestHex, undefined, { timestampVerification: 'structural' });
      expect(structural).toMatchObject({ timestampValid: false, timestampReason: 'unparseable_token' });
    });

    it('refuses text that is not RFC 4648 base64, a rejected status, and bytes after the TimeStampResp', async () => {
      const f = await makeTsaFixture();
      const der = Buffer.from(f.tokenBase64, 'base64');
      const rejected = Buffer.from(der);
      // TimeStampResp ::= SEQUENCE { status PKIStatusInfo { INTEGER 0 } ... }: the status byte.
      const status = rejected.indexOf(Buffer.from('3003020100', 'hex'));
      expect(status).toBeGreaterThan(0);
      rejected[status + 4] = 2;
      for (const token of [
        f.tokenBase64.replace(/(.{64})/g, '$1\n'),
        f.tokenBase64.replace(/\+/g, '-').replace(/\//g, '_'),
        `${f.tokenBase64}=`,
        ` ${f.tokenBase64}`,
        rejected.toString('base64'),
        Buffer.concat([der, Buffer.from([0x00])]).toString('base64'),
        '',
      ]) {
        expect(verifyTimestampSteps(token, f.digestHex, [f.caPem]).token).toBe('malformed');
      }
      expect(verifyTimestampSteps(7 as unknown as string, f.digestHex, [f.caPem]).token).toBe('malformed');
    });

    it('refuses a SignerInfo attribute whose values are not a SET', async () => {
      const f = await makeTsaFixture();
      // The content-type attribute: SEQUENCE { OID 1.2.840.113549.1.9.3, SET { ... } }, its SET retagged SEQUENCE.
      const token = patchLast(f.tokenBase64, '06092a864886f70d01090331', '06092a864886f70d01090330');
      expect(verifyTimestampSteps(token, f.digestHex, [f.caPem])).toMatchObject({ token: 'malformed' });
    });

    it('refuses a carried certificate that is not an RFC 5280 certificate: its version, its two signature algorithms, its key, its extensions', async () => {
      const f = await makeTsaFixture();
      const der = Buffer.from(f.tokenBase64, 'base64');
      const signerDer = Buffer.from(f.signerPem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, ''), 'base64');
      const at = der.indexOf(signerDer);
      expect(at).toBeGreaterThan(0);
      /** The token with the signer certificate's first `from` changed to `to`. */
      const inSigner = (from: string, to: string, nth = 0): string => {
        const cert = Buffer.from(signerDer);
        let i = -1;
        for (let n = 0; n <= nth; n++) i = cert.indexOf(Buffer.from(from, 'hex'), i + 1);
        expect(i).toBeGreaterThanOrEqual(0);
        Buffer.from(to, 'hex').copy(cert, i);
        const out = Buffer.from(der);
        cert.copy(out, at);
        return out.toString('base64');
      };
      for (const [label, token] of [
        ['version v4', inSigner('a003020102', 'a003020103')],
        // ecdsa-with-SHA256 inside tbsCertificate, and ecdsa-with-SHA384 outside it.
        ['another signature algorithm inside tbsCertificate', inSigner('06082a8648ce3d040302', '06082a8648ce3d040303')],
        ['another signature algorithm outside it', inSigner('06082a8648ce3d040302', '06082a8648ce3d040303', 1)],
        ['a public key with an unused bit', inSigner('034200', '034201')],
        // keyUsage's BIT STRING retagged INTEGER; extendedKeyUsage's OID retagged.
        ['a keyUsage that is not a BIT STRING', inSigner('0603551d0f0101ff040403', '0603551d0f0101ff040402')],
        ['an extendedKeyUsage that is not a SEQUENCE OF OBJECT IDENTIFIER', inSigner('0603551d250101ff040c300a06', '0603551d250101ff040c300a07')],
      ] as const) {
        expect([label, verifyTimestampSteps(token, f.digestHex, [f.caPem]).token]).toEqual([label, 'malformed']);
      }
    });
  });

  describe('step 2: SHA-256 over the expected value', () => {
    it('refuses another value, and the same bytes under another hash algorithm, before the signer is looked at', async () => {
      const f = await makeTsaFixture({ faults: { signerEku: 'none' } });
      // The imprint runs before step 3: a token over another value is imprint_mismatch, whatever its signer.
      expect(verifyTimestampSteps(f.tokenBase64, sha256('another value'), [])).toMatchObject({ token: 'imprint_mismatch' });
      const sha512 = await makeTsaFixture({ imprintAlgorithmOid: '2.16.840.1.101.3.4.2.3' });
      expect(verifyTimestampSteps(sha512.tokenBase64, sha512.digestHex, [sha512.caPem])).toMatchObject({ token: 'imprint_mismatch' });
      expect(await verifyTimestampToken(sha512.tokenBase64, sha512.digestHex, { trustAnchorsPem: [sha512.caPem] })).toMatchObject({
        valid: false,
        reason: 'verification_failed',
        digestMatch: false,
      });
      const structural = await verifyAttestation({ rfc3161Token: sha512.tokenBase64 }, sha512.digestHex, undefined, { timestampVerification: 'structural' });
      expect(structural).toMatchObject({ timestampValid: false, timestampReason: 'imprint_mismatch' });
    });
  });

  describe('step 3: the signature, the signer binding and a timestamping certificate', () => {
    it('accepts a signingCertificate (ESSCertID, SHA-1) as well as a signingCertificateV2', async () => {
      const f = await makeTsaFixture({ faults: { signingCertificate: 'v1' } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'valid' });
    });

    it.each<[string, TokenFaults]>([
      ['a content-type attribute naming id-data', { contentType: 'data' }],
      ['a message-digest attribute over other bytes than the TSTInfo', { messageDigest: 'other' }],
      ['no signingCertificate or signingCertificateV2', { signingCertificate: 'none' }],
      ['a signingCertificateV2 whose certHash names another certificate', { signingCertificate: 'other-certificate' }],
      ['a signer with no extendedKeyUsage', { signerEku: 'none' }],
      ['a timestamping extendedKeyUsage not marked critical', { signerEku: 'non-critical' }],
      ['a TLS server certificate', { signerEku: 'tls-server' }],
      ['an extendedKeyUsage with a second purpose', { signerEku: 'second-purpose' }],
    ])('refuses %s: verification_failed under the root the verifier trusts, and with no root at all', async (_label, faults) => {
      const f = await makeTsaFixture({ faults });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'verification_failed' });
      // Step 3 runs before step 4: no root is needed to refuse it.
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [])).toMatchObject({ token: 'verification_failed' });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({
        valid: false,
        reason: 'verification_failed',
        digestMatch: true,
        signatureValid: false,
        certificateChainValid: true,
      });
      const verdict = await verifyAttestation({ rfc3161Token: f.tokenBase64 }, f.digestHex, undefined, { trustAnchorsPem: [f.caPem] });
      expect(verdict).toMatchObject({ timestampValid: false, timestampReason: 'verification_failed' });
    });

    it('refuses a signature with one byte flipped', async () => {
      const f = await makeTsaFixture();
      const der = Buffer.from(f.tokenBase64, 'base64');
      der[der.length - 5] ^= 0x01; // inside the SignerInfo's signature, the last member of the token
      expect(verifyTimestampSteps(der.toString('base64'), f.digestHex, [f.caPem])).toMatchObject({
        token: 'verification_failed',
        error: 'the signature does not verify under the signer certificate',
      });
    });

    it('is missing_dependency for a signature algorithm this verifier does not implement (step 5)', async () => {
      const f = await makeTsaFixture();
      // The SignerInfo's ecdsa-with-SHA256 (1.2.840.10045.4.3.2) becomes 1.2.840.10045.4.3.127.
      const token = patchLast(f.tokenBase64, '06082a8648ce3d040302', '06082a8648ce3d04037f');
      expect(verifyTimestampSteps(token, f.digestHex, [f.caPem])).toMatchObject({ token: 'missing_dependency' });
      expect(await verifyTimestampToken(token, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: false, reason: 'missing_dependency' });

      // The imprint is step 2: over another value the token fails, whatever algorithm it names.
      const other = sha256('another value');
      expect(verifyTimestampSteps(token, other, [f.caPem])).toMatchObject({ token: 'imprint_mismatch' });
      expect(await verifyTimestampToken(token, other, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: false, reason: 'verification_failed', digestMatch: false });
      const verdict = await verifyAttestation({ rfc3161Token: token }, other, undefined, { trustAnchorsPem: [f.caPem] });
      expect(verdict).toMatchObject({ timestampValid: false, timestampReason: 'imprint_mismatch' });
    });

    it('is missing_dependency for a signer certificate whose key algorithm this verifier does not implement (step 5)', async () => {
      const f = await makeTsaFixture({ faults: { signerKey: 'unknown-key-algorithm' } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'missing_dependency' });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: false, reason: 'missing_dependency' });
    });
  });

  describe('step 4: a valid path to a supplied root', () => {
    it('is reached, and holds on no path, for an intermediate that is not a CA and for a signer expired at genTime', async () => {
      const notCa = await makeTsaFixture({ withIntermediate: true, intermediateNotCa: true });
      expect(verifyTimestampSteps(notCa.tokenBase64, notCa.digestHex, [notCa.caPem])).toMatchObject({ token: 'held', trust: 'reached' });
      const expired = await makeTsaFixture({ signerNotAfter: new Date('2021-01-01T00:00:00Z') });
      const steps = verifyTimestampSteps(expired.tokenBase64, expired.digestHex, [expired.caPem]);
      expect(steps).toMatchObject({ token: 'held', trust: 'reached' });
      expect(steps.error).toMatch(/not valid at the timestamp's genTime/);
      // verifyTimestampToken and verifyAttestation name every failed path untrusted_chain.
      expect(await verifyTimestampToken(notCa.tokenBase64, notCa.digestHex, { trustAnchorsPem: [notCa.caPem] })).toMatchObject({
        valid: false,
        reason: 'untrusted_chain',
        certificateChainValid: false,
      });
    });

    it('reaches a root of the same name and another key, and holds on none: reached; a root of another name: none', async () => {
      const f = await makeTsaFixture();
      const sameName = await makeTsaFixture();
      const otherName = await makeTsaFixture({ caCN: 'Another Test Root CA' });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [sameName.caPem])).toMatchObject({ token: 'held', trust: 'reached' });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [otherName.caPem])).toMatchObject({ token: 'held', trust: 'none' });
    });

    it('matches names byte for byte: an issuer name that writes the root\'s CN as a UTF8String reaches no root', async () => {
      const f = await makeTsaFixture({ faults: { signerIssuerName: 'utf8' } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'none' });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: false, reason: 'untrusted_chain' });
    });

    it('holds past a certificate of its issuer\'s name whose key algorithm it does not implement: that certificate signs nothing', async () => {
      for (const withIntermediate of [false, true]) {
        const f = await makeTsaFixture({ withIntermediate, faults: { issuerCopy: 'unknown-key-algorithm' } });
        expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'valid' });
        expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: true });
      }
    });

    it('holds past a carried certificate no path needs whose key is on a curve assigned to none: it is not examined (step 5)', async () => {
      const f = await makeTsaFixture({ faults: { unneededCertificate: 'unassigned-curve' } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'valid' });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: true });
      const copy = await makeTsaFixture({ faults: { issuerCopy: 'unassigned-curve' } });
      expect(verifyTimestampSteps(copy.tokenBase64, copy.digestHex, [copy.caPem])).toMatchObject({ token: 'held', trust: 'valid' });
    });

    it('is missing_dependency on the trust check for an intermediate whose key is on a curve it does not implement (step 5)', async () => {
      const f = await makeTsaFixture({ faults: { signerIssuer: 'intermediate-unassigned-curve' } });
      const steps = verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem]);
      expect(steps).toMatchObject({ token: 'held', trust: 'missing_dependency' });
      expect(steps.error).toMatch(/cannot be checked/);
      // Steps 1 to 3 hold, so verifyTimestampToken says so beside the reason.
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({
        valid: false,
        reason: 'missing_dependency',
        digestMatch: true,
        signatureValid: true,
        certificateChainValid: false,
      });
      // A root of another name leaves no path at all: none, not missing_dependency.
      const other = await makeTsaFixture({ caCN: 'Another Test Root CA' });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [other.caPem])).toMatchObject({ token: 'held', trust: 'none' });
    });
  });

  describe('step 4: certificate signatures under each algorithm (tzun-anchor/1 §10.5 steps 4 and 5)', () => {
    // A root of the fixture's name with a key of each type, and the fixture's signer
    // signed by it under each algorithm: genuine, the path holds; one bit flipped, the
    // path is reached and holds on none, since Node verifies the algorithm and a
    // signature that fails under it is wrong. Under an algorithm Node does not verify,
    // the signature cannot be checked, genuine or not: missing_dependency.
    const keys = {
      rsa: generateKeyPairSync('rsa', { modulusLength: 2048 }),
      ec: generateKeyPairSync('ec', { namedCurve: 'P-256' }),
      dsa: generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 }),
      ed25519: generateKeyPairSync('ed25519'),
    };
    const implemented: Array<[string, string, keyof typeof keys, string | null]> = [
      ['sha256WithRSAEncryption', '1.2.840.113549.1.1.11', 'rsa', 'sha256'],
      ['md5WithRSAEncryption', '1.2.840.113549.1.1.4', 'rsa', 'md5'],
      ['RSA with SHA3-224', '2.16.840.1.101.3.4.3.13', 'rsa', 'sha3-224'],
      ['RSA with SHA3-256', '2.16.840.1.101.3.4.3.14', 'rsa', 'sha3-256'],
      ['RSA with SHA3-384', '2.16.840.1.101.3.4.3.15', 'rsa', 'sha3-384'],
      ['RSA with SHA3-512', '2.16.840.1.101.3.4.3.16', 'rsa', 'sha3-512'],
      ['ecdsa-with-SHA256', '1.2.840.10045.4.3.2', 'ec', 'sha256'],
      ['ECDSA with SHA3-224', '2.16.840.1.101.3.4.3.9', 'ec', 'sha3-224'],
      ['ECDSA with SHA3-256', '2.16.840.1.101.3.4.3.10', 'ec', 'sha3-256'],
      ['ECDSA with SHA3-384', '2.16.840.1.101.3.4.3.11', 'ec', 'sha3-384'],
      ['ECDSA with SHA3-512', '2.16.840.1.101.3.4.3.12', 'ec', 'sha3-512'],
      ['dsa-with-SHA256', '2.16.840.1.101.3.4.3.2', 'dsa', 'sha256'],
      ['Ed25519', '1.3.101.112', 'ed25519', null],
    ];
    const unimplemented: Array<[string, string, keyof typeof keys, string]> = [
      ['sha512-224WithRSAEncryption', '1.2.840.113549.1.1.15', 'rsa', 'sha512-224'],
      ['dsa-with-SHA384', '2.16.840.1.101.3.4.3.3', 'dsa', 'sha384'],
    ];
    let fixture: Awaited<ReturnType<typeof makeTsaFixture>>;
    beforeAll(async () => {
      fixture = await makeTsaFixture();
    });
    const pathFor = (kind: keyof typeof keys, oid: string, digest: string | null, broken: boolean) => {
      const { privateKey, publicKey } = keys[kind];
      const spki = publicKey.export({ type: 'spki', format: 'der' });
      const root = signedAs(fixture.caPem, privateKey, oid, digest, spki);
      const signer = signedAs(fixture.signerPem, privateKey, oid, digest);
      return searchTrustPath(readCertificatePem(broken ? withBrokenSignature(signer) : signer)!, [], trustAnchorsFromPem([root]), fixture.genTime);
    };

    it.each(implemented)('%s: genuine holds, one bit flipped is reached', (_name, oid, kind, digest) => {
      expect(pathFor(kind, oid, digest, false)).toMatchObject({ outcome: 'valid' });
      const broken = pathFor(kind, oid, digest, true);
      expect(broken).toMatchObject({ outcome: 'reached' });
      expect(broken.error).toBe('TSA certificate signature does not verify against the trusted CA public key');
    });

    it.each(unimplemented)('%s: a signature Node does not verify cannot be checked, genuine or not', (_name, oid, kind, digest) => {
      for (const broken of [false, true]) {
        expect(pathFor(kind, oid, digest, broken)).toEqual({
          outcome: 'missing_dependency',
          error: 'TSA certificate signature cannot be checked: its signature algorithm is not supported',
        });
      }
    });

    it('names the rule a path breaks, not the signature it could not check, when it is reached', async () => {
      // The intermediate's key is on a curve assigned to none, so the signer's signature
      // cannot be checked; the root's signature on the intermediate is broken, so no path
      // holds even taking that signature as good.
      const f = await makeTsaFixture({ faults: { signerIssuer: 'intermediate-unassigned-curve' } });
      const read = readRfc3161Token(f.tokenBase64);
      if (!read.ok) throw new Error(read.error);
      const [intermediate] = read.token.certificates.filter((c) => c !== read.token.signer);
      const broken = readCertificatePem(withBrokenSignature(pemOfDer(intermediate.der)))!;
      expect(searchTrustPath(read.token.signer, [broken], trustAnchorsFromPem([f.caPem]), f.genTime)).toEqual({
        outcome: 'reached',
        error: 'Intermediate CA certificate signature does not verify against the trusted CA public key',
      });
      // Genuine, the path meets every rule but that signature: missing_dependency, naming it.
      expect(searchTrustPath(read.token.signer, [intermediate], trustAnchorsFromPem([f.caPem]), f.genTime)).toEqual({
        outcome: 'missing_dependency',
        error: "TSA certificate signature cannot be checked: its issuer's key is of an algorithm or curve this verifier does not implement",
      });
    });
  });

  describe('keys and curves this verifier does not implement (tzun-anchor/1 §10.5 steps 1 and 5)', () => {
    it('is missing_dependency, never malformed, for a signer whose key names a curve assigned to no curve', async () => {
      const f = await makeTsaFixture({ faults: { signerKey: 'unassigned-curve' } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({
        token: 'missing_dependency',
        error: "the signer certificate's elliptic curve is not supported",
      });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: false, reason: 'missing_dependency' });
    });

    it('is malformed for a P-256 signer whose point is not on the curve: a curve it implements', async () => {
      const f = await makeTsaFixture({ faults: { signerKey: 'bad-key' } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'malformed' });
    });
  });

  describe('the roots the auditor supplies (Verification §3.1)', () => {
    it('refuses a root it cannot read, beside a genuine one as alone, in every verifier: never a root dropped', async () => {
      const f = await makeTsaFixture();
      const unreadable: Array<[string, unknown]> = [
        ['a key that does not decode', pemWithUnreadableKey(f.caPem, 'bad-key')],
        ['a key algorithm it does not implement', pemWithUnreadableKey(f.caPem, 'unknown-key-algorithm')],
        ['a curve assigned to no curve', pemWithUnreadableKey(f.caPem, 'unassigned-curve')],
        ['no PEM block', 'not a certificate'],
        ['a block that is not base64', '-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----'],
        ['a block that is not a certificate', '-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----'],
        ['not a string', 42],
      ];
      for (const [what, root] of unreadable) {
        for (const roots of [[root], [f.caPem, root]]) {
          expect([what, () => verifyTimestampSteps(f.tokenBase64, f.digestHex, roots as string[])]).toEqual([what, expect.any(Function)]);
          expect(() => verifyTimestampSteps(f.tokenBase64, f.digestHex, roots as string[])).toThrow(UnreadableTrustAnchorError);
          await expect(verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: roots as string[] })).rejects.toThrow(UnreadableTrustAnchorError);
          await expect(verifyAttestation({ rfc3161Token: f.tokenBase64 }, f.digestHex, undefined, { trustAnchorsPem: roots as string[] })).rejects.toThrow(
            UnreadableTrustAnchorError,
          );
          await expect(verifyAnchor({}, f.digestHex, { trustAnchorsPem: roots as string[] })).rejects.toThrow(UnreadableTrustAnchorError);
        }
      }
      expect(() => trustAnchorsFromPem([pemWithUnreadableKey(f.caPem, 'unassigned-curve')])).toThrow(
        'trust anchor 1 has a key this verifier does not implement: its elliptic curve is not supported',
      );
      expect(() => trustAnchorsFromPem([f.caPem, 'garbage'])).toThrow('trust anchor 2 holds no PEM CERTIFICATE block');
    });

    it('refuses an authority name the registry does not know rather than trusting nothing', async () => {
      const f = await makeTsaFixture();
      await expect(verifyTimestampToken(f.tokenBase64, f.digestHex, { authorities: ['no-such-authority'] })).rejects.toThrow(UnreadableTrustAnchorError);
      await expect(verifyAnchor({}, f.digestHex, { authorities: ['no-such-authority'] })).rejects.toThrow(UnreadableTrustAnchorError);
    });

    it('reads every root the registry ships', () => {
      for (const authority of listTimestampAuthorities()) {
        expect([authority.key, trustAnchorsFromPem(timestampAuthorityAnchorsPem([authority.key])).length > 0]).toEqual([authority.key, true]);
      }
    });
  });

  describe('the authority fact (tzun-anchor/1 §10.5 step 4)', () => {
    const CN = '2.5.4.3';
    const cases: Array<[string, Rdn[], string]> = [
      ['one CN among other RDNs', [[['2.5.4.6', 19, 'US']], [['2.5.4.10', 12, 'Probe Org']], [[CN, 12, 'Probe TSA']]], 'Probe TSA'],
      ['two CN RDNs: the first', [[['2.5.4.6', 19, 'US']], [[CN, 12, 'First CN']], [[CN, 12, 'Second CN']]], 'First CN'],
      ['a CN in a multi-valued RDN: its value alone', [[['2.5.4.10', 12, 'Probe Org'], [CN, 12, 'Multi CN']]], 'Multi CN'],
      ['specials, kept as they are: no escaping, no trimming', [[[CN, 12, ' Acme, Inc. + "TSA" = #1 \\ <x>; ']]], ' Acme, Inc. + "TSA" = #1 \\ <x>; '],
      ['a line feed', [[[CN, 12, 'Line1\nLine2']]], 'Line1\nLine2'],
      ['non-ASCII UTF8String', [[[CN, 12, 'Zeitstempel Zürich Ω 時']]], 'Zeitstempel Zürich Ω 時'],
      ['a BMPString', [[[CN, 30, 'Zürich BMP']]], 'Zürich BMP'],
      ['a TeletexString, read as ISO 8859-1', [[[CN, 20, 'Zürich T61']]], 'Zürich T61'],
      ['a UniversalString', [[[CN, 28, 'Zürich 😀']]], 'Zürich 😀'],
      ['an empty CN: the empty string', [[['2.5.4.10', 12, 'Probe Org']], [[CN, 12, '']]], ''],
      ['no CN: the empty string', [[['2.5.4.6', 19, 'US']], [['2.5.4.10', 12, 'Probe Org']]], ''],
      ['no RDN: the empty string', [], ''],
    ];
    it.each(cases)('%s', async (_what, rdns, authority) => {
      const f = await makeTsaFixture({ faults: { signerSubject: nameDer(rdns) } });
      const steps = verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem]);
      expect(steps).toMatchObject({ token: 'held', trust: 'valid' });
      expect(steps.authority).toBe(authority);
      expect((await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).tsaSubject).toBe(authority);
    });

    it('writes a code unit sequence that does not decode as U+FFFD', () => {
      const name = (tag: number, bytes: string) => {
        const value = Buffer.concat([Buffer.from([tag, bytes.length / 2]), Buffer.from(bytes, 'hex')]);
        const atv = Buffer.concat([Buffer.from([0x30, value.length + 5, 0x06, 0x03, 0x55, 0x04, 0x03]), value]);
        return Buffer.concat([Buffer.from([0x30, atv.length + 2, 0x31, atv.length]), atv]);
      };
      expect(authorityOf({ subject: name(30, 'd800005a') })).toBe('\ufffdZ');
      expect(authorityOf({ subject: name(30, '005a00') })).toBe('Z\ufffd');
      expect(authorityOf({ subject: name(28, '00110000') })).toBe('\ufffd');
      expect(authorityOf({ subject: Buffer.from('3000', 'hex') })).toBe('');
    });
  });

  describe('a hostile token never makes the verifier fail', () => {
    it('answers every one-bit change of a conformant token with a verdict, in every verifier', async () => {
      const f = await makeTsaFixture({ withIntermediate: true, genTime: new Date('2026-06-01T12:00:00.25Z') });
      const der = Buffer.from(f.tokenBase64, 'base64');
      const seen = new Set<string>();
      for (let i = 0; i < der.length; i++) {
        const flipped = Buffer.from(der);
        flipped[i] ^= 0x01;
        const token = flipped.toString('base64');
        const steps = verifyTimestampSteps(token, f.digestHex, [f.caPem]);
        expect([i, steps.error?.startsWith(VERIFIER_FAILED) ?? false]).toEqual([i, false]);
        seen.add(steps.token);
        const direct = await verifyTimestampToken(token, f.digestHex, { trustAnchorsPem: [f.caPem] });
        expect([i, direct.error?.startsWith(VERIFIER_FAILED) ?? false]).toEqual([i, false]);
      }
      // The sweep reaches steps 1, 2 and 3, and some flips (an unsigned byte, a
      // name's string type in the carried intermediate) leave the token whole.
      expect([...seen].sort()).toEqual(['held', 'imprint_mismatch', 'malformed', 'missing_dependency', 'verification_failed']);
    }, 60_000);
  });
});
