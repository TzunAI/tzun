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

/** A DER element to edit and write back: its identifier octets, and its content or, when constructed, its elements. */
interface El {
  id: Buffer;
  content: Buffer;
  children?: El[];
}

/** `der`, one definite-length element, as an `El` tree. */
function el(der: Buffer): El {
  const one = (pos: number): [El, number] => {
    let at = pos + 1;
    if ((der[pos] & 0x1f) === 0x1f) while (der[at++] & 0x80);
    const id = der.subarray(pos, at);
    let length = der[at++];
    if (length & 0x80) {
      const n = length & 0x7f;
      length = der.readUIntBE(at, n);
      at += n;
    }
    const content = der.subarray(at, at + length);
    if ((der[pos] & 0x20) === 0) return [{ id, content }, at + length];
    const kids: El[] = [];
    for (let p = at; p < at + length; ) {
      const [kid, next] = one(p);
      kids.push(kid);
      p = next;
    }
    return [{ id, content, children: kids }, at + length];
  };
  const [root, end] = one(0);
  if (end !== der.length) throw new Error('bytes after the element');
  return root;
}

/** An `El` tree written back as DER. */
function der(node: El): Buffer {
  const body = node.children ? Buffer.concat(node.children.map(der)) : node.content;
  const n = body.length;
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  const len = n < 0x80 ? Buffer.from([n]) : Buffer.from([0x80 | bytes.length, ...bytes]);
  return Buffer.concat([node.id, len, body]);
}

const leaf = (id: number | Buffer, content: Buffer = Buffer.alloc(0)): El => ({ id: typeof id === 'number' ? Buffer.from([id]) : id, content });
const node = (id: number, ...children: El[]): El => ({ id: Buffer.from([id]), content: Buffer.alloc(0), children });

/** The parts of a token an edit reaches: its SignedData's members, and its one SignerInfo's. */
function editToken(tokenBase64: string, edit: (parts: { signedData: El[]; signerInfo: El[]; certificates: El }) => void): string {
  const resp = el(Buffer.from(tokenBase64, 'base64'));
  const signedData = resp.children![1].children![1].children![0].children!;
  const certificates = signedData.find((m) => m.id[0] === 0xa0)!;
  const signerInfo = signedData[signedData.length - 1].children![0].children!;
  edit({ signedData, signerInfo, certificates });
  return der(resp).toString('base64');
}

/** The token with an unsigned attribute of `values` (a SET's elements) added to its SignerInfo, which no signature covers. */
function withUnsignedAttribute(tokenBase64: string, values: El[]): string {
  return editToken(tokenBase64, ({ signerInfo }) => {
    signerInfo.push(node(0xa1, node(0x30, leaf(0x06, Buffer.from('2a0304', 'hex')), node(0x31, ...values))));
  });
}

/** The token with its TSTInfo replaced by `edit`'s: the message-digest attribute no longer matches, so a TSTInfo step 1 accepts fails step 3. */
function withTstInfo(tokenBase64: string, edit: (members: El[]) => void): string {
  return editToken(tokenBase64, ({ signedData }) => {
    const octets = signedData[2].children![1].children![0];
    const tstInfo = el(octets.content);
    edit(tstInfo.children!);
    octets.content = der(tstInfo);
  });
}

/** The token with `cert` (DER) added to its certificates, which no signature covers. */
function withCertificate(tokenBase64: string, cert: Buffer | El): string {
  return editToken(tokenBase64, ({ certificates }) => {
    certificates.children!.push(Buffer.isBuffer(cert) ? el(cert) : cert);
  });
}

/**
 * `pem`'s certificate with serial number 7, edited by `edit` (its tbsCertificate's
 * members, and where the serial number is): its signature no longer verifies, which
 * nothing reads before step 4, and a certificate no path names is not examined there.
 */
function editedCertificate(pem: string, edit: (fields: El[], at: number) => void): Buffer {
  const cert = el(derOfPem(pem));
  const fields = cert.children![0].children!;
  const at = fields[0].id[0] === 0xa0 ? 1 : 0;
  fields[at] = leaf(0x02, Buffer.from([7]));
  edit(fields, at);
  return der(cert);
}

/** `pem`'s certificate with its validity's two times written as `notBefore` and `notAfter` (a UTCTime when 13 characters long, else a GeneralizedTime). */
function withValidity(pem: string, notBefore: string, notAfter: string): Buffer {
  const time = (text: string) => leaf(text.length === 13 ? 0x17 : 0x18, Buffer.from(text, 'latin1'));
  return editedCertificate(pem, (fields, at) => {
    fields[at + 3] = node(0x30, time(notBefore), time(notAfter));
  });
}

/** `pem`'s certificate with what follows its subjectPublicKeyInfo replaced by `after(extensions)`. */
function withMembersAfterKey(pem: string, after: (extensions: El) => El[]): Buffer {
  return editedCertificate(pem, (fields, at) => {
    const extensions = fields[at + 6];
    fields.splice(at + 6, fields.length - at - 6, ...after(extensions));
  });
}

/** How deep the constructed elements of `der` nest, the outermost at depth 1, and how many elements it holds, neither looking inside a primitive element. */
function shapeOf(der: Buffer): { depth: number; count: number } {
  let depth = 0;
  let count = 0;
  const walk = (node: El, d: number) => {
    count++;
    if (!node.children) return;
    depth = Math.max(depth, d);
    for (const kid of node.children) walk(kid, d + 1);
  };
  walk(el(der), 1);
  return { depth, count };
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

  describe('step 1: the TSTInfo decodes whole (RFC 3161 §2.4.2)', () => {
    const AFTER_GEN_TIME = 'TSTInfo holds members after genTime other than accuracy, ordering, nonce, tsa and extensions, in that order';
    const ACCURACY = "the accuracy's millis or micros is not an INTEGER from 1 to 999";

    it('holds with every optional member after genTime, ordering written out as FALSE among them', async () => {
      const f = await makeTsaFixture({ faults: { tstInfoTail: 'all' } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'valid' });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: true });
    });

    it.each<[string, NonNullable<TokenFaults['tstInfoTail']>, string]>([
      ['a member after the last one', 'member-after-extensions', AFTER_GEN_TIME],
      ['ordering after the nonce', 'ordering-after-nonce', AFTER_GEN_TIME],
      ['a millis of 0', 'millis-zero', ACCURACY],
      ['a micros of 1000', 'micros-1000', ACCURACY],
      ['a tsa holding no GeneralName', 'tsa-empty', 'tsa is not one GeneralName'],
      ['a tsa whose dNSName is constructed', 'tsa-dns-name-constructed', 'tsa is not one GeneralName'],
      ['extensions holding none', 'extensions-empty', 'the TSTInfo extensions are not one or more extensions'],
    ])('refuses %s, in a token signed over it: malformed', async (_label, tstInfoTail, error) => {
      const f = await makeTsaFixture({ faults: { tstInfoTail } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toEqual({ token: 'malformed', error });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: false, reason: 'unparseable_token' });
    });

    it('reads accuracy, tsa and extensions by their shape alone, and the INTEGERs at any width', async () => {
      const f = await makeTsaFixture();
      const hex = (h: string) => Buffer.from(h, 'hex');
      const extension = node(0x30, leaf(0x06, hex('2a0304')), leaf(0x01, hex('ff')), leaf(0x04, hex('0500')));
      /** The step 1 verdict on the token with `tail` after genTime: its TSTInfo is no longer the one signed, so step 1 holding is verification_failed. */
      const tail = (...members: El[]) => {
        const steps = verifyTimestampSteps(withTstInfo(f.tokenBase64, (m) => m.splice(5, m.length - 5, ...members)), f.digestHex, [f.caPem]);
        return steps.token === 'malformed' ? steps.error : 'step 1 holds';
      };
      const accuracy = (...parts: El[]) => node(0x30, ...parts);
      const tsa = (name: El) => node(0xa0, name);
      expect([
        tail(accuracy(leaf(0x02, hex('0102030405060708ff')), leaf(0x80, hex('01')), leaf(0x81, hex('03e7')))),
        tail(accuracy(leaf(0x80, hex('0080')), leaf(0x81, hex('01')))),
        tail(accuracy()),
        tail(leaf(0x01, hex('00')), leaf(0x02, hex('00')), node(0xa1, extension, extension)),
        // GeneralName: otherName, x400Address, directoryName and ediPartyName constructed, the others primitive.
        ...[0, 3, 4, 5].map((n) => tail(tsa(node(0xa0 + n)))),
        ...[1, 2, 6, 7, 8].map((n) => tail(tsa(leaf(0x80 + n, hex('00'))))),
      ]).toEqual(Array(13).fill('step 1 holds'));
      expect([
        tail(accuracy(leaf(0x80, hex('0001')))),
        tail(accuracy(leaf(0x80, hex('ff')))),
        tail(accuracy(leaf(0x80, hex('03e8')))),
        tail(accuracy(leaf(0x81, hex('01')), leaf(0x80, hex('01')))),
        tail(accuracy(node(0xa0, leaf(0x02, hex('01'))))),
        tail(accuracy(leaf(0x02, hex('01')), leaf(0x02, hex('01')))),
        ...[0, 3, 4, 5].map((n) => tail(tsa(leaf(0x80 + n, hex('00'))))),
        ...[1, 2, 6, 7, 8].map((n) => tail(tsa(node(0xa0 + n)))),
        tail(tsa(leaf(0x89, hex('00')))),
        tail(tsa(node(0x30))),
        // Not of the context-specific class, with a tag number from 0 to 8 and the form that alternative has.
        tail(tsa(leaf(0x02, hex('01')))),
        tail(tsa(leaf(0x01, hex('ff')))),
        tail(tsa(leaf(0x42, hex('00')))),
        tail(tsa(node(0xe0))),
        tail(node(0xa0, leaf(0x82, hex('00')), leaf(0x82, hex('00')))),
        tail(node(0xa1, node(0x30, leaf(0x06, hex('2a0304'))))),
        tail(leaf(0x02, hex('01')), leaf(0x01, hex('00'))),
        tail(leaf(0x02, hex('01')), leaf(0x02, hex('01'))),
      ]).toEqual([
        ...Array(6).fill(ACCURACY).map((e, i) => (i < 3 ? e : 'accuracy is not seconds, millis and micros, each optional, in that order')),
        ...Array(16).fill('tsa is not one GeneralName'),
        'the TSTInfo extensions are not one or more extensions',
        AFTER_GEN_TIME,
        AFTER_GEN_TIME,
      ]);
    });

    it('holds genTime to the ranges of a validity time, its year 0000 to 9999 by the Gregorian rule, and keeps its fraction', async () => {
      const f = await makeTsaFixture();
      /** The token with its genTime written as `text` (the same length), its TSTInfo no longer the one signed. */
      const at = (text: string) => verifyTimestampSteps(patchLast(f.tokenBase64, Buffer.from('20260601120000Z', 'latin1').toString('hex'), Buffer.from(text, 'latin1').toString('hex')), f.digestHex, [f.caPem]);
      for (const text of ['00000229120000Z', '20240229120000Z', '99991231235959Z']) {
        expect([text, at(text).token]).toEqual([text, 'verification_failed']);
      }
      for (const text of ['20261301120000Z', '20260001120000Z', '20260631120000Z', '20230229120000Z', '01000229120000Z', '20260601240000Z', '20260601126000Z', '20260601120060Z']) {
        expect([text, at(text)]).toEqual([text, { token: 'malformed', error: 'genTime is not a GeneralizedTime' }]);
      }
      // A genuine token from the year 0000, its fraction kept: steps 1 to 3 hold, and the signer was not valid then.
      const early = await makeTsaFixture({ genTime: new Date('0000-02-29T12:00:00.5Z') });
      const steps = verifyTimestampSteps(early.tokenBase64, early.digestHex, [early.caPem]);
      expect(steps).toMatchObject({ token: 'held', trust: 'reached' });
      expect(steps.genTime?.toISOString()).toBe('0000-02-29T12:00:00.500Z');
    });
  });

  describe('step 1: every element of certificates is an RFC 5280 certificate', () => {
    const NOT_X509_AFTER_KEY = 'tbsCertificate holds fields after its subjectPublicKeyInfo other than a primitive [1], a primitive [2] and a constructed [3], in that order';

    it('refuses an element of certificates that is not the Certificate choice (RFC 5652 §10.2.2): malformed', async () => {
      const f = await makeTsaFixture();
      for (const tag of [0xa0, 0xa1, 0xa2, 0xa3]) {
        // A CertificateChoices other than certificate: [tag] IMPLICIT, here SEQUENCE { OID 1.2.3.4, NULL } retagged.
        const choice = node(tag, leaf(0x06, Buffer.from('2a0304', 'hex')), leaf(0x05));
        expect([tag, verifyTimestampSteps(withCertificate(f.tokenBase64, choice), f.digestHex, [f.caPem])]).toEqual([
          tag,
          { token: 'malformed', error: 'certificate is not a SEQUENCE' },
        ]);
      }
    });

    it('reads a validity time with no fraction of a second, a year from 0000 to 9999, a UTCTime\'s year as RFC 5280 maps it, by the Gregorian rule', async () => {
      const f = await makeTsaFixture();
      const read = (notBefore: string, notAfter: string) => {
        const cert = readCertificatePem(pemOfDer(withValidity(f.signerPem, notBefore, notAfter)));
        return cert && [new Date(cert.notBefore).toISOString(), new Date(cert.notAfter).toISOString()];
      };
      expect(read('500101000000Z', '491231235959Z')).toEqual(['1950-01-01T00:00:00.000Z', '2049-12-31T23:59:59.000Z']);
      expect(read('00000229000000Z', '99991231235959Z')).toEqual(['0000-02-29T00:00:00.000Z', '9999-12-31T23:59:59.000Z']);
      expect(read('00500101000000Z', '00991231235959Z')).toEqual(['0050-01-01T00:00:00.000Z', '0099-12-31T23:59:59.000Z']);
      expect(read('20000229000000Z', '24000229000000Z')).toEqual(['2000-02-29T00:00:00.000Z', '2400-02-29T00:00:00.000Z']);
      for (const [notBefore, notAfter] of [
        ['01000229000000Z', '20400101000000Z'],
        ['260101000000Z', '21000229000000Z'],
        ['230229000000Z', '400101000000Z'],
        ['260431000000Z', '400101000000Z'],
        ['20260101000000.5Z', '20400101000000Z'],
        ['260101000000Z', '20400101000000.25Z'],
        ['20261301000000Z', '20400101000000Z'],
        ['260101240000Z', '400101000000Z'],
        ['260101006000Z', '400101000000Z'],
        ['260101000060Z', '400101000000Z'],
      ]) {
        expect([notBefore, notAfter, read(notBefore, notAfter)]).toEqual([notBefore, notAfter, null]);
      }
      // In a token, a certificate no step needs: the year 0050 reads, a fraction does not.
      const steps = (cert: Buffer) => verifyTimestampSteps(withCertificate(f.tokenBase64, cert), f.digestHex, [f.caPem]);
      expect(steps(withValidity(f.signerPem, '00500101000000Z', '20400101000000Z'))).toMatchObject({ token: 'held', trust: 'valid' });
      expect(steps(withValidity(f.signerPem, '20260101000000.5Z', '20400101000000Z'))).toEqual({ token: 'malformed', error: 'unreadable validity' });
    });

    it('holds what follows subjectPublicKeyInfo to issuerUniqueID, subjectUniqueID and extensions, each in its form, at most once, in that order', async () => {
      const f = await makeTsaFixture();
      const uid = (tag: number) => leaf(tag, Buffer.from('00ab', 'hex'));
      const read = (after: (extensions: El) => El[]) => readCertificatePem(pemOfDer(withMembersAfterKey(f.signerPem, after)));
      expect([read((x) => [uid(0x81), uid(0x82), x]), read((x) => [uid(0x82), x]), read((x) => [uid(0x81)]), read(() => [])].map((c) => c !== null)).toEqual([
        true,
        true,
        true,
        true,
      ]);
      const refused: Array<[string, (extensions: El) => El[]]> = [
        ['extensions retagged as a constructed [2]', (x) => [{ ...x, id: Buffer.from([0xa2]) }]],
        ['a constructed issuerUniqueID', (x) => [node(0xa1, leaf(0x03, Buffer.from('00ab', 'hex'))), x]],
        ['a primitive extensions', (x) => [leaf(0x83, der(x.children![0]))]],
        ['subjectUniqueID before issuerUniqueID', (x) => [uid(0x82), uid(0x81), x]],
        ['issuerUniqueID twice', (x) => [uid(0x81), uid(0x81), x]],
        ['extensions twice', (x) => [x, x]],
        ['an element after extensions', (x) => [x, leaf(0x05)]],
        ['an element of another tag', (x) => [leaf(0x84, Buffer.from('00', 'hex')), x]],
        ['extensions holding two elements', (x) => [node(0xa3, ...x.children!, node(0x30))]],
        ['extensions holding none', () => [node(0xa3)]],
      ];
      for (const [label, after] of refused) expect([label, read(after)]).toEqual([label, null]);
      // In a token, a certificate no step needs: refused by this rule, not by any X.509 library.
      const steps = (cert: Buffer) => verifyTimestampSteps(withCertificate(f.tokenBase64, cert), f.digestHex, [f.caPem]);
      expect(steps(withMembersAfterKey(f.signerPem, (x) => [uid(0x81), uid(0x82), x]))).toMatchObject({ token: 'held', trust: 'valid' });
      expect(steps(withMembersAfterKey(f.signerPem, (x) => [{ ...x, id: Buffer.from([0xa2]) }]))).toEqual({ token: 'malformed', error: NOT_X509_AFTER_KEY });
      expect(steps(withMembersAfterKey(f.signerPem, (x) => [node(0xa3, ...x.children!, node(0x30))]))).toEqual({
        token: 'malformed',
        error: 'extensions are not one SEQUENCE',
      });
    });
  });

  describe('step 1: the forms of universal types, and the decoder bounds', () => {
    it('reads the unrestricted CHARACTER STRING (29) constructed, and OID-IRI and RELATIVE-OID-IRI (35, 36) primitive, as X.690 encodes them', async () => {
      const f = await makeTsaFixture();
      const id = (hex: string) => Buffer.from(hex, 'hex');
      // An unsigned attribute, which no signature covers: the token holds whenever step 1 does.
      const steps = (value: El) => verifyTimestampSteps(withUnsignedAttribute(f.tokenBase64, [value]), f.digestHex, [f.caPem]);
      expect(steps({ id: id('3d'), content: Buffer.alloc(0), children: [leaf(0x02, id('01'))] })).toMatchObject({ token: 'held' });
      expect(steps(leaf(id('1f23'), Buffer.from('/tzun', 'latin1')))).toMatchObject({ token: 'held' });
      expect(steps(leaf(id('1f24'), Buffer.from('tzun', 'latin1')))).toMatchObject({ token: 'held' });
      expect(steps(leaf(id('1d'), Buffer.from('00', 'hex')))).toEqual({ token: 'malformed', error: 'primitive form of universal type 29' });
      expect(steps({ id: id('3f23'), content: Buffer.alloc(0), children: [] })).toEqual({ token: 'malformed', error: 'constructed form of universal type 35' });
      expect(steps({ id: id('3f24'), content: Buffer.alloc(0), children: [] })).toEqual({ token: 'malformed', error: 'constructed form of universal type 36' });
    });

    it('holds a TimeStampResp nested exactly 64 deep and of exactly 100,000 elements; one more of either is malformed', async () => {
      const f = await makeTsaFixture();
      const tokenDer = (token: string) => Buffer.from(token, 'base64');
      const nested = (levels: number): El => {
        let inner = node(0x30);
        for (let i = 1; i < levels; i++) inner = node(0x30, inner);
        return inner;
      };
      // An attribute's values sit at depth 10: TimeStampResp, ContentInfo, [0], SignedData,
      // signerInfos, SignerInfo, unsignedAttrs [1], Attribute, its SET.
      const deep = (depth: number) => withUnsignedAttribute(f.tokenBase64, [nested(depth - 9)]);
      expect(shapeOf(tokenDer(deep(64))).depth).toBe(64);
      expect(verifyTimestampSteps(deep(64), f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'valid' });
      expect(shapeOf(tokenDer(deep(65))).depth).toBe(65);
      expect(verifyTimestampSteps(deep(65), f.digestHex, [f.caPem])).toEqual({ token: 'malformed', error: 'nested too deep' });

      const base = shapeOf(tokenDer(withUnsignedAttribute(f.tokenBase64, []))).count;
      const many = (count: number) => withUnsignedAttribute(f.tokenBase64, Array.from({ length: count - base }, () => leaf(0x05)));
      expect(shapeOf(tokenDer(many(100_000))).count).toBe(100_000);
      expect(verifyTimestampSteps(many(100_000), f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'valid' });
      expect(verifyTimestampSteps(many(100_001), f.digestHex, [f.caPem])).toEqual({ token: 'malformed', error: 'too many elements' });
    });

    it('bounds the TSTInfo, carried in an OCTET STRING, as an encoding of its own', async () => {
      const f = await makeTsaFixture();
      /** A TSTInfo with a tsa whose otherName holds SEQUENCEs nested down to `depth`, which step 1 does not read past their form. */
      const tstInfoOfDepth = (depth: number): string =>
        withTstInfo(f.tokenBase64, (members) => {
          let inner = node(0x30);
          for (let d = depth; d > 4; d--) inner = node(0x30, inner);
          members.push(node(0xa0, node(0xa0, inner)));
        });
      const depthOf = (token: string) => shapeOf(el(Buffer.from(token, 'base64')).children![1].children![1].children![0].children![2].children![1].children![0].content).depth;
      expect(depthOf(tstInfoOfDepth(64))).toBe(64);
      // Step 1 holds, and the message-digest attribute is over the TSTInfo as it was.
      expect(verifyTimestampSteps(tstInfoOfDepth(64), f.digestHex, [f.caPem])).toMatchObject({ token: 'verification_failed' });
      expect(depthOf(tstInfoOfDepth(65))).toBe(65);
      expect(verifyTimestampSteps(tstInfoOfDepth(65), f.digestHex, [f.caPem])).toEqual({ token: 'malformed', error: 'TSTInfo is not DER: nested too deep' });
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

  describe('step 3: a requirement it can check decides before one it cannot (step 5)', () => {
    const EKU = 'the signer certificate has no critical extendedKeyUsage whose only purpose is id-kp-timeStamping';
    const UNKNOWN_SIGNATURE = node(0x30, leaf(0x06, Buffer.from('2a8648ce3d04037f', 'hex'))); // 1.2.840.10045.4.3.127
    const UNKNOWN_DIGEST = node(0x30, leaf(0x06, Buffer.from('60864801650304027f', 'hex'))); // 2.16.840.1.101.3.4.2.127

    it.each<[string, TokenFaults, string]>([
      ['a signer key of an algorithm it does not implement, not a timestamping certificate', { signerKey: 'unknown-key-algorithm', signerEku: 'none' }, EKU],
      ['a signer key on a curve assigned to none, not a timestamping certificate', { signerKey: 'unassigned-curve', signerEku: 'none' }, EKU],
      [
        'a signer key on a curve assigned to none, and no signer binding',
        { signerKey: 'unassigned-curve', signingCertificate: 'none' },
        'no signingCertificate or signingCertificateV2 attribute binds the signer certificate',
      ],
      ['an ESSCertIDv2 hash algorithm it does not implement, not a timestamping certificate', { signingCertificate: 'v2-unknown-hash', signerEku: 'none' }, EKU],
      [
        'an ESSCertIDv2 hash algorithm it does not implement, its issuerSerial naming another serial number',
        { signingCertificate: 'v2-unknown-hash-other-serial' },
        'the signingCertificate issuerSerial names another certificate',
      ],
    ])('%s: verification_failed, not missing_dependency', async (_label, faults, error) => {
      const f = await makeTsaFixture({ faults });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'verification_failed', error });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [])).toMatchObject({ token: 'verification_failed', error });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({
        valid: false,
        reason: 'verification_failed',
        digestMatch: true,
        signatureValid: false,
      });
    });

    it('is missing_dependency for an ESSCertIDv2 hash algorithm it does not implement, when every other requirement holds', async () => {
      const f = await makeTsaFixture({ faults: { signingCertificate: 'v2-unknown-hash' } });
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({
        token: 'missing_dependency',
        error: 'the ESSCertIDv2 hash algorithm is not supported',
      });
    });

    it('refuses a token whose signatureAlgorithm it does not implement, when its message digest or its binding fails', async () => {
      for (const [faults, error] of [
        [{ messageDigest: 'other' }, 'the message-digest attribute is not the digest of the TSTInfo'],
        [{ signingCertificate: 'none' }, 'no signingCertificate or signingCertificateV2 attribute binds the signer certificate'],
        [{ signerEku: 'tls-server' }, EKU],
      ] as Array<[TokenFaults, string]>) {
        const f = await makeTsaFixture({ faults });
        const token = editToken(f.tokenBase64, ({ signerInfo }) => {
          signerInfo[4] = UNKNOWN_SIGNATURE;
        });
        expect(verifyTimestampSteps(token, f.digestHex, [f.caPem])).toMatchObject({ token: 'verification_failed', error });
      }
    });

    it('checks the signature under its own algorithm when the digestAlgorithm is one it does not implement', async () => {
      const f = await makeTsaFixture();
      const unknownDigest = editToken(f.tokenBase64, ({ signerInfo }) => {
        signerInfo[2] = UNKNOWN_DIGEST;
      });
      expect(verifyTimestampSteps(unknownDigest, f.digestHex, [f.caPem])).toMatchObject({
        token: 'missing_dependency',
        error: 'digest algorithm 2.16.840.1.101.3.4.2.127 is not supported',
      });
      const broken = editToken(unknownDigest, ({ signerInfo }) => {
        const signature = Buffer.from(signerInfo[5].content);
        signature[signature.length - 1] ^= 0x01;
        signerInfo[5] = leaf(0x04, signature);
      });
      expect(verifyTimestampSteps(broken, f.digestHex, [f.caPem])).toMatchObject({ token: 'verification_failed' });
    });

    it('verifies the signature over the signed attributes as carried, in other than DER SET OF order', async () => {
      const f = await makeTsaFixture({ faults: { signedAttrsOrder: 'reversed' } });
      let carried: Buffer[] = [];
      editToken(f.tokenBase64, ({ signerInfo }) => {
        carried = signerInfo[3].children!.map(der);
      });
      expect([...carried].sort(Buffer.compare)).not.toEqual(carried);
      expect(verifyTimestampSteps(f.tokenBase64, f.digestHex, [f.caPem])).toMatchObject({ token: 'held', trust: 'valid' });
      expect(await verifyTimestampToken(f.tokenBase64, f.digestHex, { trustAnchorsPem: [f.caPem] })).toMatchObject({ valid: true });
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
