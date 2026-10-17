/**
 * An RFC 3161 timestamp token read and checked by tzun-anchor/1 §10.5, one
 * step at a time:
 *
 *   1. parse (`readRfc3161Token`): base64 (RFC 4648 §4) of a DER
 *      TimeStampResp whose status is granted or grantedWithMods, carrying a
 *      CMS SignedData over a DER TSTInfo that decodes whole by RFC 3161
 *      §2.4.2, with exactly one SignerInfo whose certificate the token
 *      carries, and nothing but certificates in its certificates. A
 *      constructed (BER) OCTET STRING, an indefinite or non-minimal length, a
 *      non-minimal INTEGER, or a GeneralizedTime with a trailing zero in its
 *      fraction is not DER;
 *   2. imprint (`imprintHolds`): SHA-256, and the expected value;
 *   3. signature and signer (`checkSignatureAndSigner`): the content-type and
 *      message-digest attributes, the CMS signature, a signingCertificate
 *      (ESSCertID) or signingCertificateV2 (ESSCertIDv2) attribute that names
 *      the signer certificate, and on that certificate a critical
 *      extendedKeyUsage whose only purpose is id-kp-timeStamping;
 *   4. trust (`searchTrustPath`): some path from the signer to a supplied
 *      root on which every issuer signed its subject, every certificate
 *      between the two is a CA within its path length, and every certificate
 *      is valid at genTime.
 *
 * `verifyRfc3161Steps` runs them in order and reports the first that does not
 * hold. A step that needs an algorithm this verifier does not implement (a
 * digest, signature or public-key algorithm outside the tables below, or an
 * elliptic curve Node's OpenSSL does not implement) is `missing_dependency`
 * (tzun-anchor/1 §10.5 step 5); at step 3, only once every requirement it can
 * check holds. Nothing here throws on a token: it is
 * untrusted data, and every certificate is read whole, its public key
 * included, before any check uses it. A key whose algorithm or named curve
 * this verifier does not implement is left unread, and only a step that needs
 * it says so.
 *
 * The roots are the auditor's own input, not the token's: `trustAnchorsFromPem`
 * reads them, and throws `UnreadableTrustAnchorError` for one it cannot read,
 * its key included (Verification §3.1).
 */
import { createHash, createPublicKey, verify as cryptoVerify, X509Certificate, type KeyObject } from 'crypto';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SIGNING_CERTIFICATE = '1.2.840.113549.1.9.16.2.12';
const OID_SIGNING_CERTIFICATE_V2 = '1.2.840.113549.1.9.16.2.47';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_EXT_KEY_USAGE = '2.5.29.37';
const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_SUBJECT_KEY_IDENTIFIER = '2.5.29.14';
const OID_KP_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_COMMON_NAME = '2.5.4.3';

/**
 * Public-key algorithms whose keys this verifier decodes: RSA, EC, Ed25519,
 * and the DSA and X25519 keys a certificate may also carry. A certificate
 * naming one of them whose key does not decode is not a certificate, unless
 * it is an EC key on a named curve Node's OpenSSL does not implement
 * (`namedCurveImplemented`). A key of any other algorithm, and an EC key on
 * such a curve, is kept unread, and a step that needs it is
 * `missing_dependency` (tzun-anchor/1 §10.5 steps 1 and 5).
 */
const KEY_ALGORITHMS = new Set(['1.2.840.113549.1.1.1', OID_EC_PUBLIC_KEY, '1.3.101.112', '1.2.840.10040.4.1', '1.3.101.110']);

/**
 * Certificate signature algorithms Node's X.509 verifier implements, each
 * one it verifies a genuine signature under: RSASSA-PKCS1-v1_5 with MD5,
 * SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and SHA3-224 to SHA3-512;
 * RSASSA-PSS; ECDSA with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and
 * SHA3-224 to SHA3-512; Ed25519 and Ed448; DSA with SHA-1, SHA-224 and
 * SHA-256. A signature that fails under one of them is wrong. A certificate
 * signature under another algorithm, which Node does not verify, cannot be
 * told from a wrong one, so at step 4 it is a signature the verifier cannot
 * check.
 */
const CERTIFICATE_SIGNATURES = new Set([
  '1.2.840.113549.1.1.4',
  '1.2.840.113549.1.1.5',
  '1.2.840.113549.1.1.14',
  '1.2.840.113549.1.1.11',
  '1.2.840.113549.1.1.12',
  '1.2.840.113549.1.1.13',
  '2.16.840.1.101.3.4.3.13',
  '2.16.840.1.101.3.4.3.14',
  '2.16.840.1.101.3.4.3.15',
  '2.16.840.1.101.3.4.3.16',
  '1.2.840.113549.1.1.10',
  '1.2.840.10045.4.1',
  '1.2.840.10045.4.3.1',
  '1.2.840.10045.4.3.2',
  '1.2.840.10045.4.3.3',
  '1.2.840.10045.4.3.4',
  '2.16.840.1.101.3.4.3.9',
  '2.16.840.1.101.3.4.3.10',
  '2.16.840.1.101.3.4.3.11',
  '2.16.840.1.101.3.4.3.12',
  '1.3.101.112',
  '1.3.101.113',
  '1.2.840.10040.4.3',
  '2.16.840.1.101.3.4.3.1',
  '2.16.840.1.101.3.4.3.2',
]);

/** Digest algorithms by OID, as Node's crypto names them. */
const DIGESTS: Record<string, string> = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.4': 'sha224',
  [OID_SHA256]: 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

/**
 * Signature algorithms by OID: the key type they need, and the digest they
 * name (absent for the bare key OIDs, which take the SignerInfo's
 * digestAlgorithm, as CMS allows).
 */
const SIGNATURES: Record<string, { key: 'rsa' | 'ec' | 'ed25519'; digest?: string }> = {
  '1.2.840.113549.1.1.1': { key: 'rsa' },
  '1.2.840.113549.1.1.5': { key: 'rsa', digest: 'sha1' },
  '1.2.840.113549.1.1.14': { key: 'rsa', digest: 'sha224' },
  '1.2.840.113549.1.1.11': { key: 'rsa', digest: 'sha256' },
  '1.2.840.113549.1.1.12': { key: 'rsa', digest: 'sha384' },
  '1.2.840.113549.1.1.13': { key: 'rsa', digest: 'sha512' },
  '1.2.840.10045.2.1': { key: 'ec' },
  '1.2.840.10045.4.1': { key: 'ec', digest: 'sha1' },
  '1.2.840.10045.4.3.1': { key: 'ec', digest: 'sha224' },
  '1.2.840.10045.4.3.2': { key: 'ec', digest: 'sha256' },
  '1.2.840.10045.4.3.3': { key: 'ec', digest: 'sha384' },
  '1.2.840.10045.4.3.4': { key: 'ec', digest: 'sha512' },
  '1.3.101.112': { key: 'ed25519' },
};

// ---- DER --------------------------------------------------------------------------

/** A token or certificate that is not what step 1 reads: not DER, or not of its type. */
class Malformed extends Error {}

/** One DER element: its tag, its bytes with the header, and its content. */
interface Der {
  /** 0 universal, 1 application, 2 context-specific, 3 private. */
  cls: number;
  constructed: boolean;
  tag: number;
  raw: Buffer;
  content: Buffer;
}

/**
 * The decoder bounds of tzun-anchor/1 §10.5 step 1: each encoding the DER
 * rules apply to (the TimeStampResp, the TSTInfo, each typed extension value)
 * holds at most `MAX_ELEMENTS` elements, the outermost included, and its
 * constructed elements, of any class, nest at most `MAX_DEPTH` deep, the
 * outermost at depth 1. Elements inside a primitive element are not counted:
 * the TSTInfo and the extension values, carried in OCTET STRINGs, are bounded
 * as encodings of their own (`parseDer`).
 */
const MAX_DEPTH = 64;
const MAX_ELEMENTS = 100_000;

/**
 * Universal types X.690 encodes only in the primitive form: BOOLEAN, INTEGER,
 * BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER, ObjectDescriptor, REAL,
 * ENUMERATED, the restricted string types, RELATIVE-OID, the time types, and
 * OID-IRI and RELATIVE-OID-IRI (35, 36).
 */
const PRIMITIVE_ONLY = new Set([1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30, 31, 32, 33, 34, 35, 36]);
/**
 * Universal types X.690 encodes only in the constructed form: EXTERNAL,
 * EMBEDDED PDV, SEQUENCE, SET, and the unrestricted CHARACTER STRING (29).
 */
const CONSTRUCTED_ONLY = new Set([8, 11, 16, 17, 29]);

/** The element at `pos`, which must end at or before `limit`. */
function readElement(buf: Buffer, pos: number, limit: number): Der {
  const start = pos;
  if (pos >= limit) throw new Malformed('truncated element');
  const first = buf[pos++];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  if (tag === 0x1f) {
    tag = 0;
    for (let i = 0; ; i++) {
      if (pos >= limit) throw new Malformed('truncated tag');
      const b = buf[pos++];
      if (i === 0 && b === 0x80) throw new Malformed('non-minimal tag');
      if (tag > 0x00ffffff) throw new Malformed('tag number too large');
      tag = tag * 128 + (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
    if (tag < 31) throw new Malformed('non-minimal tag');
  }
  if (pos >= limit) throw new Malformed('truncated length');
  let length = buf[pos++];
  if (length === 0x80) throw new Malformed('indefinite length');
  if (length > 0x80) {
    const n = length & 0x7f;
    if (n > 4) throw new Malformed('length too long');
    if (pos + n > limit) throw new Malformed('truncated length');
    if (buf[pos] === 0) throw new Malformed('non-minimal length');
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + buf[pos++];
    if (length < 0x80) throw new Malformed('non-minimal length');
  }
  const end = pos + length;
  if (end > limit) throw new Malformed('element runs past its container');
  return { cls, constructed, tag, raw: buf.subarray(start, end), content: buf.subarray(pos, end) };
}

/** The elements of `content`, in order. */
function elementsOf(content: Buffer): Der[] {
  const out: Der[] = [];
  let pos = 0;
  while (pos < content.length) {
    const el = readElement(content, pos, content.length);
    out.push(el);
    pos += el.raw.length;
  }
  return out;
}

const GENERALIZED_TIME_DER = /^\d{14}(\.\d*[1-9])?Z$/;
const UTC_TIME_DER = /^\d{12}Z$/;

/**
 * Whether `content` (every element in it, recursively) is DER as X.690 §10
 * and §11 define it, for what can be decided without a schema: definite,
 * minimal lengths and tags; the primitive form for strings and the other
 * primitive types, and the constructed form for the constructed ones; minimal
 * INTEGERs; BOOLEAN as 00 or FF; a BIT STRING's unused bits zero; and the DER
 * forms of UTCTime and GeneralizedTime. A context-specific primitive is not
 * read inside: its type is the schema's. The elements of `content` sit at
 * depth `depth + 1`, so a constructed element at depth 65 fails, as does the
 * 100,001st element (`MAX_DEPTH`, `MAX_ELEMENTS`).
 */
function checkDer(content: Buffer, depth: number, count: { n: number }): void {
  if (depth > MAX_DEPTH) throw new Malformed('nested too deep');
  let pos = 0;
  while (pos < content.length) {
    if (++count.n > MAX_ELEMENTS) throw new Malformed('too many elements');
    const el = readElement(content, pos, content.length);
    pos += el.raw.length;
    const c = el.content;
    if (el.cls === 0) {
      if (el.tag === 0) throw new Malformed('end-of-contents in DER');
      if (el.constructed && PRIMITIVE_ONLY.has(el.tag)) throw new Malformed(`constructed form of universal type ${el.tag}`);
      if (!el.constructed && CONSTRUCTED_ONLY.has(el.tag)) throw new Malformed(`primitive form of universal type ${el.tag}`);
      switch (el.tag) {
        case 1:
          if (c.length !== 1 || (c[0] !== 0x00 && c[0] !== 0xff)) throw new Malformed('BOOLEAN not 00 or FF');
          break;
        case 2:
        case 10:
          if (c.length === 0) throw new Malformed('empty INTEGER');
          if (c.length > 1 && ((c[0] === 0x00 && (c[1] & 0x80) === 0) || (c[0] === 0xff && (c[1] & 0x80) !== 0))) {
            throw new Malformed('non-minimal INTEGER');
          }
          break;
        case 3: {
          if (c.length === 0 || c[0] > 7 || (c.length === 1 && c[0] !== 0)) throw new Malformed('malformed BIT STRING');
          if (c.length > 1 && (c[c.length - 1] & ((1 << c[0]) - 1)) !== 0) throw new Malformed('BIT STRING unused bits not zero');
          break;
        }
        case 5:
          if (c.length !== 0) throw new Malformed('NULL with content');
          break;
        case 6:
        case 13:
          if (c.length === 0 || (c[c.length - 1] & 0x80) !== 0) throw new Malformed('truncated OBJECT IDENTIFIER');
          for (let i = 0; i < c.length; i++) {
            if (c[i] === 0x80 && (i === 0 || (c[i - 1] & 0x80) === 0)) throw new Malformed('non-minimal OBJECT IDENTIFIER');
          }
          break;
        case 23:
          if (!UTC_TIME_DER.test(c.toString('latin1'))) throw new Malformed('UTCTime not in DER form');
          break;
        case 24:
          if (!GENERALIZED_TIME_DER.test(c.toString('latin1'))) throw new Malformed('GeneralizedTime not in DER form');
          break;
      }
    }
    if (el.constructed) checkDer(c, depth + 1, count);
  }
}

/** `bytes` as exactly one DER element, checked through. */
function parseDer(bytes: Buffer): Der {
  checkDer(bytes, 0, { n: 0 });
  const el = readElement(bytes, 0, bytes.length);
  if (el.raw.length !== bytes.length) throw new Malformed('bytes after the element');
  return el;
}

function is(el: Der | undefined, cls: number, tag: number, constructed: boolean): el is Der {
  return el !== undefined && el.cls === cls && el.tag === tag && el.constructed === constructed;
}
const isSequence = (el: Der | undefined): el is Der => is(el, 0, 16, true);
const isSet = (el: Der | undefined): el is Der => is(el, 0, 17, true);
const isInteger = (el: Der | undefined): el is Der => is(el, 0, 2, false);
const isOid = (el: Der | undefined): el is Der => is(el, 0, 6, false);
const isOctets = (el: Der | undefined): el is Der => is(el, 0, 4, false);

/** The dotted form of an OBJECT IDENTIFIER's content. */
function oid(el: Der): string {
  const parts: number[] = [];
  let value = 0;
  for (const b of el.content) {
    value = value * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      if (parts.length === 0) {
        const head = value < 40 ? 0 : value < 80 ? 1 : 2;
        parts.push(head, value - head * 40);
      } else {
        parts.push(value);
      }
      value = 0;
    }
  }
  return parts.join('.');
}

/** An AlgorithmIdentifier's OID, or `null` when it is not one. */
function algorithmOf(el: Der | undefined): { oid: string; params?: Der } | null {
  if (!isSequence(el)) return null;
  const [id, params, ...rest] = elementsOf(el.content);
  if (!isOid(id) || rest.length > 0) return null;
  return { oid: oid(id), ...(params && { params }) };
}

/**
 * A DER UTCTime or GeneralizedTime as milliseconds since the epoch,
 * sub-milliseconds truncated, or `null` when it is neither or not a time
 * (tzun-anchor/1 §10.5 step 1). A GeneralizedTime may carry a fraction of a
 * second only where `fraction` allows one: in genTime, and not in a
 * certificate's validity (RFC 5280 §4.1.2.5.2). A UTCTime's year is 19YY
 * from 50 to 99 and 20YY from 00 to 49 (RFC 5280 §4.1.2.5.1); a
 * GeneralizedTime's is its four digits, 0000 to 9999.
 */
function timeOf(el: Der | undefined, fraction: boolean): number | null {
  if (el === undefined || el.cls !== 0 || el.constructed) return null;
  const text = el.content.toString('latin1');
  let m: RegExpMatchArray | null;
  if (el.tag === 23 && (m = text.match(/^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/))) {
    const yy = Number(m[1]);
    return utc(yy < 50 ? 2000 + yy : 1900 + yy, m.slice(2, 7).map(Number), '');
  }
  if (el.tag === 24 && (m = text.match(/^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.(\d+))?Z$/))) {
    if (m[7] !== undefined && !fraction) return null;
    return utc(Number(m[1]), m.slice(2, 7).map(Number), m[7] ?? '');
  }
  return null;
}

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * The instant of a date and time of day, or `null` when it is not one: a
 * month from 1 to 12, a day its month has in that year, by the Gregorian rule
 * in every year (0000 is a leap year, 0100 is not), an hour to 23 and a minute
 * and second to 59, so no leap second.
 */
function utc(year: number, [month, day, hour, minute, second]: number[], fraction: string): number | null {
  if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) return null;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  if (day > DAYS_IN_MONTH[month - 1] + (month === 2 && leap ? 1 : 0)) return null;
  // Date.UTC reads a year from 0 to 99 as 1900 to 1999; setUTCFullYear takes it as it is.
  const d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, minute, second, Number((fraction + '000').slice(0, 3)));
  return d.getTime();
}

// ---- Certificates -----------------------------------------------------------------

/** A certificate as the checks read it: its bytes, names, serial, key, validity and extensions. */
export interface Rfc3161Certificate {
  der: Buffer;
  x509: X509Certificate;
  /** The DER of its subject and issuer Names. */
  subject: Buffer;
  issuer: Buffer;
  /** The DER of its SubjectPublicKeyInfo. */
  spki: Buffer;
  /**
   * Its public key, or `null` for a key this verifier does not read: of an
   * algorithm outside `KEY_ALGORITHMS`, or an EC key on a named curve Node's
   * OpenSSL does not implement. `keyUnread` says which.
   */
  publicKey: KeyObject | null;
  keyUnread?: 'algorithm' | 'curve';
  /** The OID of the signature algorithm it is signed with. */
  signatureAlgorithm: string;
  /** The content of its serialNumber INTEGER. */
  serial: Buffer;
  notBefore: number;
  notAfter: number;
  extensions: Map<string, { critical: boolean; value: Buffer }>;
}

/**
 * The RFC 5280 type of each standard extension a certificate is held to: its
 * extnValue must be one DER element of that type. These are the extensions
 * the steps read (keyUsage, basicConstraints, extendedKeyUsage,
 * subjectKeyIdentifier) and the others an X.509 parser reads to build a
 * certificate. A value of another type is not the extension it names.
 */
const EXTENSION_TYPES: Record<string, (value: Der) => boolean> = {
  [OID_KEY_USAGE]: (v) => is(v, 0, 3, false),
  [OID_BASIC_CONSTRAINTS]: (v) => {
    if (!isSequence(v)) return false;
    const parts = elementsOf(v.content);
    const rest = is(parts[0], 0, 1, false) ? parts.slice(1) : parts;
    return rest.length === 0 || (rest.length === 1 && isInteger(rest[0]));
  },
  [OID_EXT_KEY_USAGE]: (v) => isSequence(v) && elementsOf(v.content).every(isOid),
  [OID_SUBJECT_KEY_IDENTIFIER]: isOctets,
  '2.5.29.35': isSequence, // authorityKeyIdentifier
  '2.5.29.17': isSequence, // subjectAltName
  '2.5.29.30': isSequence, // nameConstraints
  '2.5.29.31': isSequence, // cRLDistributionPoints
  '2.5.29.32': isSequence, // certificatePolicies
  '1.3.6.1.5.5.7.1.1': isSequence, // authorityInfoAccess
};

/**
 * An Extension (RFC 5280 §4.1): a SEQUENCE of an OBJECT IDENTIFIER, an
 * optional BOOLEAN and an OCTET STRING, as its OID, whether it is critical,
 * and its value's element; `null` when it is not one.
 */
function extensionParts(ext: Der): { id: string; critical: boolean; value: Der } | null {
  // Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
  const parts = isSequence(ext) ? elementsOf(ext.content) : [];
  const flagged = is(parts[1], 0, 1, false);
  const value = parts[flagged ? 2 : 1];
  if (!isOid(parts[0]) || !isOctets(value) || parts.length !== (flagged ? 3 : 2)) return null;
  return { id: oid(parts[0]), critical: flagged && parts[1].content[0] === 0xff, value };
}

/** Whether Node's OpenSSL implements each named curve asked about, by the hex of its OID's DER. */
const namedCurves = new Map<string, boolean>();

/**
 * Whether Node's OpenSSL implements the named curve `curve` (the DER of its
 * OBJECT IDENTIFIER): whether it reads an EC key on that curve at all, asked
 * with the point at infinity, which needs no field element and which OpenSSL
 * reads on every curve it implements. A curve OID assigned to no curve reads
 * as one it does not implement, since no verifier can tell the two apart
 * (tzun-anchor/1 §10.5 step 1).
 */
function namedCurveImplemented(curve: Der): boolean {
  // No curve's OID is anywhere near this long; the lengths below are short-form.
  if (curve.raw.length > 64) return false;
  const key = curve.raw.toString('hex');
  const known = namedCurves.get(key);
  if (known !== undefined) return known;
  const algorithm = Buffer.concat([Buffer.from('06072a8648ce3d0201', 'hex'), curve.raw]);
  // SubjectPublicKeyInfo { AlgorithmIdentifier { id-ecPublicKey, curve }, BIT STRING { 00 } }
  const spki = Buffer.concat([
    Buffer.from([0x30, 2 + algorithm.length + 4, 0x30, algorithm.length]),
    algorithm,
    Buffer.from([0x03, 0x02, 0x00, 0x00]),
  ]);
  let implemented: boolean;
  try {
    createPublicKey({ key: spki, format: 'der', type: 'spki' });
    implemented = true;
  } catch {
    implemented = false;
  }
  if (namedCurves.size < 1024) namedCurves.set(key, implemented);
  return implemented;
}

/**
 * Read a DER X.509 certificate, or throw `Malformed` when it is not one
 * (tzun-anchor/1 §10.5 step 1): version v1 to v3; the signature
 * AlgorithmIdentifier inside tbsCertificate the same bytes as the one outside
 * it (RFC 5280 §4.1.1.2); a validity of two times, a GeneralizedTime among them
 * with no fraction of a second; a subjectPublicKeyInfo whose key, for an
 * algorithm in `KEY_ALGORITHMS`, has no unused bits and decodes, unless it is
 * an EC key on a named curve Node's OpenSSL does not implement, which is left
 * unread; after it only a primitive issuerUniqueID [1], a primitive
 * subjectUniqueID [2] and a constructed extensions [3] holding one SEQUENCE,
 * each at most once and in that order; and extensions that are not repeated,
 * each standard one of its type (`EXTENSION_TYPES`).
 */
function readCertificate(der: Buffer): Rfc3161Certificate {
  const cert = parseDer(der);
  if (!isSequence(cert)) throw new Malformed('certificate is not a SEQUENCE');
  const [tbs, outerAlgorithm, signatureValue, ...extra] = elementsOf(cert.content);
  const signatureAlgorithm = algorithmOf(outerAlgorithm);
  if (!isSequence(tbs) || signatureAlgorithm === null || !is(signatureValue, 0, 3, false) || extra.length > 0) {
    throw new Malformed('certificate is not a tbsCertificate, a signatureAlgorithm and a signature');
  }
  const fields = elementsOf(tbs.content);
  let i = 0;
  if (is(fields[0], 2, 0, true)) {
    const [version, ...rest] = elementsOf(fields[i++].content);
    if (!isInteger(version) || rest.length > 0 || version.content.length !== 1 || version.content[0] > 2) {
      throw new Malformed('certificate version is not v1, v2 or v3');
    }
  }
  const serial = fields[i++];
  const innerAlgorithm = fields[i++];
  const issuer = fields[i++];
  const validity = fields[i++];
  const subject = fields[i++];
  const spki = fields[i++];
  if (!isInteger(serial) || !isSequence(issuer) || !isSequence(validity) || !isSequence(subject) || !isSequence(spki)) {
    throw new Malformed('tbsCertificate does not have the X.509 fields');
  }
  if (innerAlgorithm === undefined || !innerAlgorithm.raw.equals(outerAlgorithm.raw)) {
    throw new Malformed('the signature algorithm inside tbsCertificate is not the one outside it');
  }
  const [spkiAlgorithmEl, spkiKey, ...spkiRest] = elementsOf(spki.content);
  const spkiAlgorithm = algorithmOf(spkiAlgorithmEl);
  if (spkiAlgorithm === null || !is(spkiKey, 0, 3, false) || spkiRest.length > 0) {
    throw new Malformed('subjectPublicKeyInfo is not an AlgorithmIdentifier and a BIT STRING');
  }
  if (KEY_ALGORITHMS.has(spkiAlgorithm.oid) && spkiKey.content[0] !== 0) throw new Malformed('subjectPublicKey has unused bits');
  const [from, to] = elementsOf(validity.content);
  const notBefore = timeOf(from, false);
  const notAfter = timeOf(to, false);
  if (notBefore === null || notAfter === null) throw new Malformed('unreadable validity');
  // After subjectPublicKeyInfo: issuerUniqueID [1] and subjectUniqueID [2],
  // each primitive, then extensions [3], constructed, each at most once, in
  // that order, and nothing else.
  const after = fields.slice(i);
  let k = 0;
  if (is(after[k], 2, 1, false)) k++;
  if (is(after[k], 2, 2, false)) k++;
  const block = is(after[k], 2, 3, true) ? after[k++] : undefined;
  if (k !== after.length) {
    throw new Malformed('tbsCertificate holds fields after its subjectPublicKeyInfo other than a primitive [1], a primitive [2] and a constructed [3], in that order');
  }
  const extensions = new Map<string, { critical: boolean; value: Buffer }>();
  if (block) {
    const lists = elementsOf(block.content);
    if (lists.length !== 1 || !isSequence(lists[0])) throw new Malformed('extensions are not one SEQUENCE');
    for (const ext of elementsOf(lists[0].content)) {
      const parts = extensionParts(ext);
      if (parts === null) throw new Malformed('malformed extension');
      const { id, critical, value } = parts;
      if (extensions.has(id)) throw new Malformed('repeated extension');
      const type = EXTENSION_TYPES[id];
      if (type !== undefined) {
        let inner: Der;
        try {
          inner = parseDer(value.content);
        } catch {
          throw new Malformed(`extension ${id} is not DER`);
        }
        if (!type(inner)) throw new Malformed(`extension ${id} is not of its type`);
      }
      extensions.set(id, { critical, value: value.content });
    }
  }
  let x509: X509Certificate;
  try {
    x509 = new X509Certificate(der);
  } catch (err) {
    throw new Malformed(`certificate does not parse: ${(err as Error).message}`);
  }
  // Node decodes the key only when it is first asked for, and throws then: it
  // is read here, once, so no later step meets a key that does not decode.
  let publicKey: KeyObject | null;
  let keyUnread: Rfc3161Certificate['keyUnread'];
  try {
    publicKey = x509.publicKey;
  } catch (err) {
    publicKey = null;
    const curve = spkiAlgorithm.params;
    if (spkiAlgorithm.oid === OID_EC_PUBLIC_KEY && isOid(curve) && !namedCurveImplemented(curve)) {
      keyUnread = 'curve';
    } else if (KEY_ALGORITHMS.has(spkiAlgorithm.oid)) {
      throw new Malformed(`the certificate's public key does not decode: ${(err as Error).message}`);
    } else {
      keyUnread = 'algorithm';
    }
  }
  return {
    der,
    x509,
    subject: subject.raw,
    issuer: issuer.raw,
    spki: spki.raw,
    publicKey,
    ...(keyUnread && { keyUnread }),
    signatureAlgorithm: signatureAlgorithm.oid,
    serial: serial.content,
    notBefore,
    notAfter,
    extensions,
  };
}

/**
 * A trust root or intermediate the auditor supplied that the verifier cannot
 * read: an input error, never a verdict on a token (Verification §3.1, §6.6).
 * The verifier refuses it rather than drop it and go on, since a dropped root
 * reads as a token that chains to no root.
 */
export class UnreadableTrustAnchorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnreadableTrustAnchorError';
  }
}

const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;

/**
 * The whitespace a PEM body may carry between its base64 lines: ASCII tab,
 * line feed, vertical tab, form feed, carriage return and space. Any other
 * character, Unicode whitespace included, makes the body not base64. The
 * Python SDK strips the same six.
 */
const PEM_WHITESPACE = /[\t\n\v\f\r ]+/g;

/**
 * The certificates of the auditor's PEM inputs, every one of them: each entry
 * must hold at least one `CERTIFICATE` block, and each block must read as a
 * certificate by the rules of tzun-anchor/1 §10.5 step 1 with a key this
 * verifier reads. A root or intermediate whose key algorithm or curve it does
 * not implement cannot anchor a path it can check, so it is refused like one
 * that does not parse (Verification §3.1).
 *
 * @throws UnreadableTrustAnchorError naming the entry and why.
 */
export function trustAnchorsFromPem(pems: readonly unknown[]): Rfc3161Certificate[] {
  const out: Rfc3161Certificate[] = [];
  pems.forEach((pem, i) => {
    const which = `trust anchor ${i + 1}`;
    if (typeof pem !== 'string') throw new UnreadableTrustAnchorError(`${which} is not a PEM string`);
    const blocks = [...pem.matchAll(PEM_CERTIFICATE)];
    if (blocks.length === 0) throw new UnreadableTrustAnchorError(`${which} holds no PEM CERTIFICATE block`);
    blocks.forEach((block, j) => {
      const where = blocks.length > 1 ? `${which}, certificate ${j + 1}` : which;
      const body = block[1].replace(PEM_WHITESPACE, '');
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length % 4 !== 0) {
        throw new UnreadableTrustAnchorError(`${where} is not base64`);
      }
      let cert: Rfc3161Certificate;
      try {
        cert = readCertificate(Buffer.from(body, 'base64'));
      } catch (err) {
        throw new UnreadableTrustAnchorError(`${where} does not read as a certificate: ${(err as Error).message}`);
      }
      if (cert.publicKey === null) {
        throw new UnreadableTrustAnchorError(
          `${where} has a key this verifier does not implement: its ${cert.keyUnread === 'curve' ? 'elliptic curve' : 'public-key algorithm'} is not supported`,
        );
      }
      out.push(cert);
    });
  });
  return out;
}

/**
 * The `authority` fact of a trust check (tzun-anchor/1 §10.5 step 4, §10.7):
 * from the certificate's subject Name alone, the value of its first
 * commonName (2.5.4.3), taking the RDNs and the attributes of each RDN in the
 * order they are encoded, as the characters its string type holds (a
 * UTF8String as UTF-8, a TeletexString as ISO 8859-1, a BMPString as UTF-16, a
 * UniversalString as UTF-32, the other string types byte for byte), with no
 * escaping, no trimming and no normalization, even when it is empty. With no
 * commonName, the empty string.
 */
export function authorityOf(cert: Pick<Rfc3161Certificate, 'subject'>): string {
  try {
    const name = parseDer(cert.subject);
    if (!isSequence(name)) return '';
    for (const rdn of elementsOf(name.content)) {
      if (!isSet(rdn)) continue;
      for (const atv of elementsOf(rdn.content)) {
        const [type, value] = isSequence(atv) ? elementsOf(atv.content) : [];
        if (isOid(type) && oid(type) === OID_COMMON_NAME && value !== undefined) return stringValue(value);
      }
    }
  } catch {
    // A subject that does not parse names no commonName.
  }
  return '';
}

/**
 * The characters a Name's string value holds, by its type. A code unit
 * sequence that does not decode (a lone UTF-16 surrogate, invalid UTF-8, a
 * UTF-32 value past U+10FFFF) is U+FFFD, so the result is always a string a
 * report can write.
 */
function stringValue(value: Der): string {
  const bytes = value.content;
  if (value.cls !== 0) return bytes.toString('latin1');
  switch (value.tag) {
    case 12:
      // Buffer keeps a leading U+FEFF, which TextDecoder would drop.
      return bytes.toString('utf8');
    case 30: {
      let out = '';
      for (let i = 0; i + 1 < bytes.length; i += 2) out += String.fromCharCode(bytes.readUInt16BE(i));
      if (bytes.length % 2 !== 0) out += '�';
      return out.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '�');
    }
    case 28: {
      let out = '';
      for (let i = 0; i + 3 < bytes.length; i += 4) {
        const cp = bytes.readUInt32BE(i);
        out += cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? '�' : String.fromCodePoint(cp);
      }
      if (bytes.length % 4 !== 0) out += '�';
      return out;
    }
    default:
      return bytes.toString('latin1');
  }
}

/** A certificate's subject common name, or its whole subject when it has none. */
export function subjectCommonName(cert: { subject: string }): string {
  const subject = typeof cert.subject === 'string' ? cert.subject : '';
  const cn = subject
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.startsWith('CN='));
  return cn ? cn.slice(3) : subject.replace(/\n/g, ', ');
}

// ---- Step 1: the token -------------------------------------------------------------

/** A token that step 1 read. */
export interface Rfc3161Token {
  tstInfo: {
    imprintAlgorithm: string;
    /** The imprint algorithm's parameters: absent, or their DER. */
    imprintParams?: Buffer;
    hashedMessage: Buffer;
    genTime: Date;
  };
  signer: Rfc3161Certificate;
  /** Every certificate the token carries, the signer included. */
  certificates: Rfc3161Certificate[];
  signerInfo: {
    digestAlgorithm: string;
    /** The signed attributes' element, `[0] IMPLICIT`, absent when the SignerInfo has none. */
    signedAttrs?: Der;
    signatureAlgorithm: string;
    signature: Buffer;
  };
  /** The encapsulated TSTInfo's bytes. */
  eContent: Buffer;
}

export type Rfc3161ReadResult =
  | { ok: true; token: Rfc3161Token }
  | { ok: false; reason: 'malformed'; error: string };

/** RFC 4648 §4 base64 with `=` padding, and nothing else: no whitespace, no URL-safe alphabet, no stray bits. */
function strictBase64(text: string): Buffer | null {
  if (text.length === 0 || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  const bytes = Buffer.from(text, 'base64');
  return bytes.toString('base64') === text ? bytes : null;
}

/**
 * tzun-anchor/1 §10.5 step 1: whether `token` is the base64 of a DER
 * TimeStampResp that carries a readable timestamp and the certificate its
 * SignerInfo names.
 */
export function readRfc3161Token(token: unknown): Rfc3161ReadResult {
  const malformed = (error: string): Rfc3161ReadResult => ({ ok: false, reason: 'malformed', error });
  if (typeof token !== 'string') return malformed('the token is not a string');
  const der = strictBase64(token);
  if (der === null) return malformed('the token is not RFC 4648 base64');
  try {
    const resp = parseDer(der);
    if (!isSequence(resp)) return malformed('TimeStampResp is not a SEQUENCE');
    const [statusInfo, contentInfo, ...extra] = elementsOf(resp.content);
    if (!isSequence(statusInfo) || extra.length > 0) return malformed('TimeStampResp does not have its two members');
    const [status] = elementsOf(statusInfo.content);
    if (!isInteger(status)) return malformed('PKIStatus is not an INTEGER');
    if (status.content.length !== 1 || status.content[0] > 1) return malformed('PKIStatus is neither granted nor grantedWithMods');
    if (!isSequence(contentInfo)) return malformed('TimeStampResp carries no timeStampToken');

    const [contentType, explicit] = elementsOf(contentInfo.content);
    if (!isOid(contentType) || oid(contentType) !== OID_SIGNED_DATA || !is(explicit, 2, 0, true)) {
      return malformed('timeStampToken is not a ContentInfo of SignedData');
    }
    const [signedData] = elementsOf(explicit.content);
    if (!isSequence(signedData)) return malformed('SignedData is not a SEQUENCE');
    const sd = elementsOf(signedData.content);
    let i = 0;
    const version = sd[i++];
    const digestAlgorithms = sd[i++];
    if (!isInteger(version) || !isSet(digestAlgorithms) || !elementsOf(digestAlgorithms.content).every((a) => algorithmOf(a) !== null)) {
      return malformed('SignedData does not open with a version and a SET OF AlgorithmIdentifier');
    }
    const encap = sd[i++];
    let certificatesEl: Der | undefined;
    if (is(sd[i], 2, 0, true)) certificatesEl = sd[i++];
    if (is(sd[i], 2, 1, true)) i++;
    const signerInfos = sd[i++];
    if (!isSequence(encap) || !isSet(signerInfos) || i !== sd.length) return malformed('SignedData does not have the CMS members');

    const [eContentType, eContentExplicit] = elementsOf(encap.content);
    if (!isOid(eContentType) || oid(eContentType) !== OID_TST_INFO) return malformed('eContentType is not id-ct-TSTInfo');
    if (!is(eContentExplicit, 2, 0, true)) return malformed('SignedData carries no encapsulated TSTInfo');
    const octets = elementsOf(eContentExplicit.content);
    if (octets.length !== 1 || !isOctets(octets[0])) return malformed('eContent is not one OCTET STRING');
    const eContent = octets[0].content;
    const tstInfo = readTstInfo(eContent);
    if (typeof tstInfo === 'string') return malformed(tstInfo);

    const infos = elementsOf(signerInfos.content);
    if (infos.length !== 1 || !isSequence(infos[0])) return malformed('SignedData does not carry exactly one SignerInfo');
    const si = elementsOf(infos[0].content);
    let j = 0;
    if (!isInteger(si[j++])) return malformed('SignerInfo has no version');
    const sid = si[j++];
    const digestAlgorithm = algorithmOf(si[j++]);
    let signedAttrs: Der | undefined;
    if (is(si[j], 2, 0, true)) signedAttrs = si[j++];
    const signatureAlgorithm = algorithmOf(si[j++]);
    const signature = si[j++];
    const unsignedAttrs = is(si[j], 2, 1, true) ? si[j++] : undefined;
    if (sid === undefined || digestAlgorithm === null || signatureAlgorithm === null || !isOctets(signature) || j !== si.length) {
      return malformed('SignerInfo does not have the CMS members');
    }
    // Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF AttributeValue }
    for (const attrs of [signedAttrs, unsignedAttrs]) {
      for (const attr of attrs ? elementsOf(attrs.content) : []) {
        const [type, values, ...rest] = isSequence(attr) ? elementsOf(attr.content) : [];
        if (!isOid(type) || !isSet(values) || rest.length > 0) return malformed('a SignerInfo attribute is not an OBJECT IDENTIFIER and a SET');
      }
    }

    // Every element of certificates is a certificate: a tagged CertificateChoices
    // element (RFC 5652 §10.2.2) is not one, and makes the token malformed.
    const certificates: Rfc3161Certificate[] = [];
    for (const choice of certificatesEl ? elementsOf(certificatesEl.content) : []) {
      certificates.push(readCertificate(Buffer.from(choice.raw)));
    }
    const signer = findSigner(sid, certificates);
    if (signer === undefined) return malformed('the token does not carry the certificate its SignerInfo names');

    return {
      ok: true,
      token: {
        tstInfo,
        signer,
        certificates,
        signerInfo: {
          digestAlgorithm: digestAlgorithm.oid,
          ...(signedAttrs && { signedAttrs }),
          signatureAlgorithm: signatureAlgorithm.oid,
          signature: signature.content,
        },
        eContent,
      },
    };
  } catch (err) {
    if (err instanceof Malformed) return malformed(err.message);
    return malformed(`unreadable: ${(err as Error).message}`);
  }
}

/**
 * The TSTInfo in `bytes`, decoded whole by RFC 3161 §2.4.2 (tzun-anchor/1
 * §10.5 step 1), or why it is not one:
 *
 *   TSTInfo ::= SEQUENCE { version INTEGER, policy OBJECT IDENTIFIER,
 *     messageImprint, serialNumber INTEGER, genTime GeneralizedTime,
 *     accuracy OPTIONAL, ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
 *     tsa [0] GeneralName OPTIONAL, extensions [1] IMPLICIT Extensions OPTIONAL }
 *
 * genTime has the field ranges of a validity time, its year included, and may
 * carry a fraction of a second.
 */
function readTstInfo(bytes: Buffer): Rfc3161Token['tstInfo'] | string {
  let seq: Der;
  try {
    seq = parseDer(bytes);
  } catch (err) {
    return `TSTInfo is not DER: ${(err as Error).message}`;
  }
  if (!isSequence(seq)) return 'TSTInfo is not a SEQUENCE';
  const members = elementsOf(seq.content);
  const [version, policy, imprint, serial, genTime] = members;
  if (!isInteger(version) || !isOid(policy) || !isSequence(imprint) || !isInteger(serial)) return 'TSTInfo does not have its fields';
  const [algorithmEl, hashed, ...rest] = elementsOf(imprint.content);
  const algorithm = algorithmOf(algorithmEl);
  if (algorithm === null || !isOctets(hashed) || rest.length > 0) return 'messageImprint is not an AlgorithmIdentifier and an OCTET STRING';
  const at = is(genTime, 0, 24, false) ? timeOf(genTime, true) : null;
  if (at === null) return 'genTime is not a GeneralizedTime';
  const optional = tstInfoOptionalMembers(members.slice(5));
  if (optional !== null) return optional;
  return {
    imprintAlgorithm: algorithm.oid,
    ...(algorithm.params && { imprintParams: algorithm.params.raw }),
    hashedMessage: hashed.content,
    genTime: new Date(at),
  };
}

/**
 * Why the members after a TSTInfo's genTime are not accuracy, ordering, nonce,
 * tsa and extensions, each optional, in that order, and nothing else; `null`
 * when they are.
 */
function tstInfoOptionalMembers(members: Der[]): string | null {
  let i = 0;
  if (isSequence(members[i])) {
    // Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER (1..999) OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }
    const parts = elementsOf(members[i++].content);
    let j = 0;
    if (isInteger(parts[j])) j++;
    for (const tag of [0, 1]) {
      if (!is(parts[j], 2, tag, false)) continue;
      if (!fromOneTo999(parts[j++].content)) return 'the accuracy\'s millis or micros is not an INTEGER from 1 to 999';
    }
    if (j !== parts.length) return 'accuracy is not seconds, millis and micros, each optional, in that order';
  }
  if (is(members[i], 0, 1, false)) i++; // ordering
  if (isInteger(members[i])) i++; // nonce
  if (is(members[i], 2, 0, true)) {
    // tsa [0] GeneralName: one of its alternatives, by tag and form; its contents are not read.
    const names = elementsOf(members[i++].content);
    const [name] = names;
    if (names.length !== 1 || name.cls !== 2 || name.tag > 8 || name.constructed !== [0, 3, 4, 5].includes(name.tag)) {
      return 'tsa is not one GeneralName';
    }
  }
  if (is(members[i], 2, 1, true)) {
    // extensions [1] IMPLICIT Extensions: one or more, their values not read.
    const list = elementsOf(members[i++].content);
    if (list.length === 0 || !list.every((ext) => extensionParts(ext) !== null)) return 'the TSTInfo extensions are not one or more extensions';
  }
  if (i !== members.length) return 'TSTInfo holds members after genTime other than accuracy, ordering, nonce, tsa and extensions, in that order';
  return null;
}

/** Whether `content` is that of a DER INTEGER from 1 to 999: positive, in its shortest form. */
function fromOneTo999(content: Buffer): boolean {
  if (content.length === 0 || content.length > 2 || (content[0] & 0x80) !== 0) return false;
  if (content.length === 2 && content[0] === 0x00 && (content[1] & 0x80) === 0) return false;
  const value = content.length === 1 ? content[0] : content[0] * 256 + content[1];
  return value >= 1 && value <= 999;
}

/** The certificate `sid` names: by issuer and serial number, or by subjectKeyIdentifier. */
function findSigner(sid: Der, certificates: Rfc3161Certificate[]): Rfc3161Certificate | undefined {
  const keyId = sid.content;
  if (isSequence(sid)) {
    const [issuer, serial] = elementsOf(sid.content);
    if (!isSequence(issuer) || !isInteger(serial)) return undefined;
    return certificates.find((c) => c.issuer.equals(issuer.raw) && c.serial.equals(serial.content));
  }
  if (is(sid, 2, 0, false)) {
    return certificates.find((c) => {
      const ski = c.extensions.get(OID_SUBJECT_KEY_IDENTIFIER);
      if (!ski) return false;
      try {
        const id = parseDer(ski.value);
        return isOctets(id) && id.content.equals(keyId);
      } catch {
        return false;
      }
    });
  }
  return undefined;
}

// ---- Step 2: the imprint ------------------------------------------------------------

/** tzun-anchor/1 §10.5 step 2: the imprint is SHA-256 (parameters absent or NULL) over `expectedHex`. */
export function imprintHolds(token: Rfc3161Token, expectedHex: string): boolean {
  const { imprintAlgorithm, imprintParams, hashedMessage } = token.tstInfo;
  if (imprintAlgorithm !== OID_SHA256) return false;
  if (imprintParams !== undefined && !imprintParams.equals(Buffer.from([0x05, 0x00]))) return false;
  if (typeof expectedHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(expectedHex)) return false;
  return hashedMessage.equals(Buffer.from(expectedHex, 'hex'));
}

// ---- Step 3: the signature and the signer ---------------------------------------------

export type Rfc3161SignerResult = { ok: true } | { ok: false; reason: 'verification_failed' | 'missing_dependency'; error: string };

/**
 * tzun-anchor/1 §10.5 step 3: the signed attributes carry content-type
 * id-ct-TSTInfo and a message-digest of the TSTInfo; the signature over them,
 * as the token carries them, verifies under the signer certificate's key; a
 * signingCertificate or signingCertificateV2 names the signer certificate
 * (each one present must); and that certificate has a critical
 * extendedKeyUsage whose only purpose is id-kp-timeStamping.
 *
 * Every requirement this verifier can check decides before one it cannot
 * (§10.5 step 5): a requirement that needs a digest or signature algorithm it
 * does not implement, the signer's key left unread, or an ESSCertIDv2 hash
 * algorithm it does not implement is set aside, the others are checked, and
 * the first that fails is `verification_failed`. Only when none fails is the
 * first set aside `missing_dependency`.
 */
export function checkSignatureAndSigner(token: Rfc3161Token): Rfc3161SignerResult {
  const failed = (error: string): Rfc3161SignerResult => ({ ok: false, reason: 'verification_failed', error });
  const { signerInfo, signer } = token;
  if (signerInfo.signedAttrs === undefined) return failed('the SignerInfo has no signed attributes');
  /** The first requirement set aside for an algorithm or key this verifier lacks. */
  let missing: string | undefined;

  const attributes = new Map<string, Der[][]>();
  for (const attr of elementsOf(signerInfo.signedAttrs.content)) {
    const [type, values, ...rest] = isSequence(attr) ? elementsOf(attr.content) : [];
    if (!isOid(type) || !isSet(values) || rest.length > 0) return failed('a signed attribute is malformed');
    const list = attributes.get(oid(type)) ?? [];
    list.push(elementsOf(values.content));
    attributes.set(oid(type), list);
  }
  const single = (id: string): Der | null | 'absent' => {
    const list = attributes.get(id);
    if (list === undefined) return 'absent';
    return list.length === 1 && list[0].length === 1 ? list[0][0] : null;
  };

  const contentType = single(OID_CONTENT_TYPE);
  if (contentType === 'absent' || contentType === null || !isOid(contentType) || oid(contentType) !== OID_TST_INFO) {
    return failed('the content-type attribute is not one id-ct-TSTInfo');
  }
  const messageDigest = single(OID_MESSAGE_DIGEST);
  if (messageDigest === 'absent' || messageDigest === null || !isOctets(messageDigest)) {
    return failed('the message-digest attribute is not one OCTET STRING');
  }
  const digest: string | undefined = DIGESTS[signerInfo.digestAlgorithm];
  if (digest === undefined) {
    missing ??= `digest algorithm ${signerInfo.digestAlgorithm} is not supported`;
  } else if (!createHash(digest).update(token.eContent).digest().equals(messageDigest.content)) {
    return failed('the message-digest attribute is not the digest of the TSTInfo');
  }

  const algorithm = SIGNATURES[signerInfo.signatureAlgorithm];
  const key = signer.publicKey;
  if (algorithm === undefined) {
    missing ??= `signature algorithm ${signerInfo.signatureAlgorithm} is not supported`;
  } else if (key === null) {
    missing ??=
      signer.keyUnread === 'curve'
        ? "the signer certificate's elliptic curve is not supported"
        : "the signer certificate's public-key algorithm is not supported";
  } else if (key.asymmetricKeyType !== algorithm.key) {
    return failed(`a ${key.asymmetricKeyType} key cannot verify a ${algorithm.key} signature`);
  } else {
    // A bare key OID takes the SignerInfo's digestAlgorithm, set aside above when this verifier lacks it.
    const hash = algorithm.key === 'ed25519' ? null : (algorithm.digest ?? digest);
    if (hash !== undefined) {
      // CMS signs the DER of the attributes as a SET OF, not as the [0] IMPLICIT tag they are carried under.
      const signed = Buffer.from(signerInfo.signedAttrs.raw);
      signed[0] = 0x31;
      let verified: boolean;
      try {
        verified = cryptoVerify(hash, signed, key, signerInfo.signature);
      } catch (err) {
        return failed(`the signature does not verify: ${(err as Error).message}`);
      }
      if (!verified) return failed('the signature does not verify under the signer certificate');
    }
  }

  let bound = 0;
  for (const [id, v2] of [
    [OID_SIGNING_CERTIFICATE, false],
    [OID_SIGNING_CERTIFICATE_V2, true],
  ] as const) {
    const value = single(id);
    if (value === 'absent') continue;
    if (value === null) return failed('a signingCertificate attribute is repeated or has more than one value');
    const binding = bindsSigner(value, v2, signer);
    if (binding === 'missing_dependency') missing ??= 'the ESSCertIDv2 hash algorithm is not supported';
    else if (binding !== true) return failed(binding);
    bound++;
  }
  if (bound === 0) return failed('no signingCertificate or signingCertificateV2 attribute binds the signer certificate');

  if (!timestampingOnly(signer)) {
    return failed('the signer certificate has no critical extendedKeyUsage whose only purpose is id-kp-timeStamping');
  }
  return missing === undefined ? { ok: true } : { ok: false, reason: 'missing_dependency', error: missing };
}

/**
 * Whether the first certificate identifier of a SigningCertificate (ESSCertID,
 * RFC 2634) or SigningCertificateV2 (ESSCertIDv2, RFC 5816) names `signer`:
 * its certHash over the certificate's DER, and its issuerSerial, when present,
 * naming its issuer and serial number. `true`, why not, or
 * `'missing_dependency'` when everything but a certHash under a hash algorithm
 * this verifier does not implement holds.
 */
function bindsSigner(value: Der, v2: boolean, signer: Rfc3161Certificate): true | 'missing_dependency' | string {
  if (!isSequence(value)) return 'the signingCertificate attribute is not a SEQUENCE';
  const [certs] = elementsOf(value.content);
  if (!isSequence(certs)) return 'the signingCertificate attribute has no certs';
  const [first] = elementsOf(certs.content);
  if (!isSequence(first)) return 'the signingCertificate attribute names no certificate';
  const parts = elementsOf(first.content);
  let i = 0;
  let digest: string | undefined = v2 ? 'sha256' : 'sha1';
  if (v2 && isSequence(parts[0])) {
    const algorithm = algorithmOf(parts[i++]);
    if (algorithm === null) return 'the ESSCertIDv2 hash algorithm is malformed';
    digest = DIGESTS[algorithm.oid];
  }
  const certHash = parts[i++];
  if (!isOctets(certHash)) return 'the certificate identifier has no certHash';
  if (digest !== undefined && !createHash(digest).update(signer.der).digest().equals(certHash.content)) {
    return 'the signingCertificate certHash names another certificate';
  }
  const issuerSerial = parts[i];
  if (issuerSerial !== undefined) {
    const [names, serial] = isSequence(issuerSerial) ? elementsOf(issuerSerial.content) : [];
    if (!isSequence(names) || !isInteger(serial)) return 'the issuerSerial is malformed';
    const directory = elementsOf(names.content).find((n) => is(n, 2, 4, true));
    const [name] = directory ? elementsOf(directory.content) : [];
    if (!isSequence(name)) return 'the issuerSerial names no directoryName';
    if (!name.raw.equals(signer.issuer) || !serial.content.equals(signer.serial)) {
      return 'the signingCertificate issuerSerial names another certificate';
    }
  }
  return digest === undefined ? 'missing_dependency' : true;
}

/** Whether `cert` has a critical extendedKeyUsage whose only purpose is id-kp-timeStamping (RFC 3161 §2.3). */
function timestampingOnly(cert: Rfc3161Certificate): boolean {
  const eku = cert.extensions.get(OID_EXT_KEY_USAGE);
  if (!eku || !eku.critical) return false;
  try {
    const seq = parseDer(eku.value);
    if (!isSequence(seq)) return false;
    const purposes = elementsOf(seq.content);
    return purposes.length === 1 && isOid(purposes[0]) && oid(purposes[0]) === OID_KP_TIME_STAMPING;
  } catch {
    return false;
  }
}

// ---- Step 4: the trust path -------------------------------------------------------------

/** How far the search of step 4 goes: a hostile token chooses its own certificates. */
const MAX_PATH_CERTS = 10;
const MAX_CANDIDATES = 256;
const MAX_SIGNATURE_CHECKS = 1024;
const MAX_EDGES = 1 << 16;

export interface TrustPathResult {
  /**
   * - `valid`: some path to a supplied root holds;
   * - `missing_dependency`: none holds, and some path to a supplied root
   *   meets every rule but for signatures this verifier cannot check, under
   *   an issuing key or a signature algorithm it does not implement
   *   (tzun-anchor/1 §10.5 step 5);
   * - `reached`: some path of names reaches a supplied root, and none holds;
   * - `none`: no path reaches a supplied root (or the search ran out of its
   *   bounds before deciding, which says nothing against the token).
   */
  outcome: 'valid' | 'missing_dependency' | 'reached' | 'none';
  /** The root a valid path ends at. */
  root?: Rfc3161Certificate;
  /** Why no path held, when `outcome` is not `valid`. */
  error?: string;
}

/** A CA may sit at index `i` of a path (the signer is 0): `cA`, `keyCertSign` when keyUsage is present, and its path length. */
function intermediateHolds(cert: Rfc3161Certificate, i: number): string | null {
  const bc = cert.extensions.get(OID_BASIC_CONSTRAINTS);
  if (!bc) return 'has no basicConstraints';
  let pathLen: number | undefined;
  try {
    const seq = parseDer(bc.value);
    if (!isSequence(seq)) return 'has malformed basicConstraints';
    const [ca, len] = elementsOf(seq.content);
    if (!is(ca, 0, 1, false) || ca.content[0] !== 0xff) return 'is not a CA';
    if (len !== undefined) {
      if (!isInteger(len) || len.content.length > 4 || (len.content[0] & 0x80) !== 0) return 'has a malformed pathLenConstraint';
      pathLen = len.content.readUIntBE(0, len.content.length);
    }
  } catch {
    return 'has malformed basicConstraints';
  }
  const ku = cert.extensions.get(OID_KEY_USAGE);
  if (ku) {
    try {
      const bits = parseDer(ku.value);
      // keyCertSign is bit 5 of the BIT STRING: the first content byte after the unused-bits count.
      if (!is(bits, 0, 3, false) || bits.content.length < 2 || (bits.content[1] & 0x04) === 0) return 'may not sign certificates';
    } catch {
      return 'has a malformed keyUsage';
    }
  }
  if (pathLen !== undefined && i - 1 > pathLen) return 'has more CAs below it than its pathLenConstraint allows';
  return null;
}

/**
 * tzun-anchor/1 §10.5 step 4: every path from `signer` to one of `roots`, in
 * which each certificate's issuer name is the next one's subject name, byte
 * for byte (the same Name written with other string types is another name),
 * drawn from `intermediates` and the roots. A path is valid when each
 * issuer's signature over its subject verifies, every certificate between the
 * two ends is a CA within its path length, and every certificate, both ends
 * included, is valid at `atTime` (unchecked when `atTime` is undefined).
 *
 * The search goes breadth first, visiting each certificate once, at its
 * shallowest depth along valid edges: the rules hold or fail per certificate
 * and per edge, except the path length, which only gets harder with depth, so
 * it finds a valid path whenever one exists within its bounds. When none is
 * valid, the same search again, taking a signature this verifier cannot check
 * (an issuer whose key it does not read, or a signature algorithm it does not
 * implement) as one that may hold, tells `missing_dependency` (tzun-anchor/1
 * §10.5 step 5); then a search by names alone tells `reached` from `none`.
 */
export function searchTrustPath(
  signer: Rfc3161Certificate,
  intermediates: Rfc3161Certificate[],
  roots: Rfc3161Certificate[],
  atTime?: Date,
): TrustPathResult {
  const t = atTime?.getTime();
  const validAt = (c: Rfc3161Certificate) => t === undefined || (c.notBefore <= t && t <= c.notAfter);
  const window = (c: Rfc3161Certificate, label: string) =>
    `${label} was not valid at the timestamp's genTime ` +
    `(${new Date(t!).toISOString()} outside ${new Date(c.notBefore).toISOString()}..${new Date(c.notAfter).toISOString()})`;
  const isRoot = (c: Rfc3161Certificate) => roots.some((r) => r.der.equals(c.der));
  const issuedBy = (subject: Rfc3161Certificate, issuer: Rfc3161Certificate) => subject.issuer.equals(issuer.subject);
  const outOfBounds: TrustPathResult = { outcome: 'none', error: 'the certificate path search ran out of its bounds' };

  if (roots.length === 0) return { outcome: 'none', error: 'No trust anchors configured' };
  const candidates: Rfc3161Certificate[] = [];
  const seen = new Set<string>();
  for (const c of [...roots, ...intermediates]) {
    const key = c.der.toString('base64');
    if (seen.has(key)) continue;
    seen.add(key);
    candidates.push(c);
  }
  if (candidates.length > MAX_CANDIDATES) return { outcome: 'none', error: 'too many certificates to search' };

  if (isRoot(signer)) {
    return validAt(signer) ? { outcome: 'valid', root: signer } : { outcome: 'reached', error: window(signer, 'TSA certificate') };
  }

  let edges = 0;
  let checks = 0;
  const cache = new Map<string, boolean | 'unknown'>();
  /**
   * Whether `issuer` signed `subject`: `true`, `false`, `'unknown'` when this
   * verifier cannot check it (the issuer's key is unread, or the signature
   * fails under an algorithm outside `CERTIFICATE_SIGNATURES`), or `null`
   * once the search is out of signature checks.
   */
  const signs = (issuer: Rfc3161Certificate, subject: Rfc3161Certificate): boolean | 'unknown' | null => {
    if (issuer.publicKey === null) return 'unknown';
    const key = `${subject.der.toString('base64')}|${issuer.spki.toString('base64')}`;
    const known = cache.get(key);
    if (known !== undefined) return known;
    if (++checks > MAX_SIGNATURE_CHECKS) return null;
    let ok = false;
    try {
      ok = subject.x509.verify(issuer.publicKey);
    } catch {
      ok = false;
    }
    const signed = ok ? true : CERTIFICATE_SIGNATURES.has(subject.signatureAlgorithm) ? false : 'unknown';
    cache.set(key, signed);
    return signed;
  };

  let firstFailure: string | undefined = validAt(signer) ? undefined : window(signer, 'TSA certificate');
  let unverifiable: string | undefined;
  /**
   * Whether a path to a root meets every rule, a signature this verifier
   * cannot check counting as one that holds when `unchecked`; `null` when the
   * search ran out of its bounds.
   */
  const search = (unchecked: boolean): Rfc3161Certificate | 'none' | null => {
    const visited = new Set([signer.der.toString('base64')]);
    const queue: Array<{ c: Rfc3161Certificate; depth: number }> = [{ c: signer, depth: 0 }];
    while (queue.length > 0) {
      const n = queue.shift()!;
      if (n.depth > 0 && isRoot(n.c)) return n.c;
      if (n.depth + 1 >= MAX_PATH_CERTS) continue;
      const label = n.depth === 0 ? 'TSA certificate' : 'Intermediate CA certificate';
      for (const next of candidates) {
        const key = next.der.toString('base64');
        if (visited.has(key)) continue;
        if (++edges > MAX_EDGES) return null;
        if (!issuedBy(n.c, next)) continue;
        const signed = signs(next, n.c);
        if (signed === null) return null;
        if (signed === 'unknown' && !unchecked) {
          unverifiable ??= `${label} signature cannot be checked: ${
            next.publicKey === null ? "its issuer's key is of an algorithm or curve this verifier does not implement" : 'its signature algorithm is not supported'
          }`;
          continue;
        }
        if (signed === false) {
          firstFailure ??= `${label} signature does not verify against ${isRoot(next) ? 'the trusted CA public key' : "its issuer's public key"}`;
          continue;
        }
        if (!validAt(next)) {
          firstFailure ??= window(next, isRoot(next) ? 'Trust anchor' : 'Intermediate CA certificate');
          continue;
        }
        const depth = n.depth + 1;
        if (!isRoot(next)) {
          const why = intermediateHolds(next, depth);
          if (why !== null) {
            firstFailure ??= `Intermediate CA certificate ${why}`;
            continue;
          }
        }
        visited.add(key);
        queue.push({ c: next, depth });
      }
    }
    return 'none';
  };

  if (validAt(signer)) {
    const valid = search(false);
    if (valid === null) return outOfBounds;
    if (valid !== 'none') return { outcome: 'valid', root: valid };
    const unchecked = search(true);
    if (unchecked === null) return outOfBounds;
    if (unchecked !== 'none') return { outcome: 'missing_dependency', error: unverifiable ?? 'a signature on the path cannot be checked' };
  }

  const visited = new Set([signer.der.toString('base64')]);
  const queue: Array<{ c: Rfc3161Certificate; depth: number }> = [{ c: signer, depth: 0 }];
  while (queue.length > 0) {
    const n = queue.shift()!;
    if (n.depth > 0 && isRoot(n.c)) {
      return { outcome: 'reached', error: firstFailure ?? 'no path to the trusted CA is valid' };
    }
    if (n.depth + 1 >= MAX_PATH_CERTS) continue;
    for (const next of candidates) {
      const key = next.der.toString('base64');
      if (visited.has(key)) continue;
      if (++edges > MAX_EDGES) return outOfBounds;
      if (issuedBy(n.c, next)) {
        visited.add(key);
        queue.push({ c: next, depth: n.depth + 1 });
      }
    }
  }
  return { outcome: 'none', error: 'TSA certificate was not issued by the trusted CA' };
}

/** Read the first certificate of a PEM text, for the path check of a certificate a caller holds; `null` when it does not read. */
export function readCertificatePem(pem: string): Rfc3161Certificate | null {
  const block = typeof pem === 'string' ? [...pem.matchAll(PEM_CERTIFICATE)][0] : undefined;
  if (block === undefined) return null;
  try {
    return readCertificate(Buffer.from(block[1].replace(PEM_WHITESPACE, ''), 'base64'));
  } catch {
    return null;
  }
}

// ---- The steps in order -------------------------------------------------------------------

export interface Rfc3161Verdict {
  /** Steps 1 to 3: `held`, or the reason of the first that did not. */
  token: 'held' | 'malformed' | 'imprint_mismatch' | 'verification_failed' | 'missing_dependency';
  /** Step 4, once steps 1 to 3 hold. */
  trust?: TrustPathResult['outcome'];
  /** The TSTInfo's genTime, once step 1 holds. */
  genTime?: Date;
  /** The signer certificate's `authorityOf`, once step 1 holds. */
  authority?: string;
  error?: string;
}

/**
 * tzun-anchor/1 §10.5 steps 1 to 4 over `token`, with `imprintHex` as the value
 * its imprint must be, in order: the first step that does not hold decides, and
 * step 4 runs only once steps 1 to 3 hold. `roots` are the only trust anchors
 * (`trustAnchorsFromPem` reads them); with none, step 4 is `none`.
 *
 * It does not throw. Should a step fail in a way none of them foresees, the
 * verdict is `missing_dependency` with an error that says the verifier failed:
 * a verifier fault to report, never a verdict on the token (tzun-anchor/1
 * §10.1), and never a reason for a report to lose its other checks.
 */
export function verifyRfc3161Steps(token: unknown, imprintHex: string, roots: Rfc3161Certificate[]): Rfc3161Verdict {
  try {
    return rfc3161Steps(token, imprintHex, roots);
  } catch (err) {
    return { token: 'missing_dependency', error: `${VERIFIER_FAILED}: ${(err as Error)?.message ?? String(err)}` };
  }
}

/** The start of the error a verdict carries when the verifier itself failed. */
export const VERIFIER_FAILED = 'the RFC 3161 verifier failed on this token';

function rfc3161Steps(token: unknown, imprintHex: string, roots: Rfc3161Certificate[]): Rfc3161Verdict {
  const read = readRfc3161Token(token);
  if (!read.ok) return { token: read.reason, error: read.error };
  const t = read.token;
  const facts = { genTime: t.tstInfo.genTime, authority: authorityOf(t.signer) };
  if (!imprintHolds(t, imprintHex)) return { token: 'imprint_mismatch', ...facts, error: 'the imprint is not SHA-256 over the expected value' };
  const signer = checkSignatureAndSigner(t);
  if (!signer.ok) return { token: signer.reason, ...facts, error: signer.error };
  const path = searchTrustPath(t.signer, t.certificates.filter((c) => c !== t.signer), roots, t.tstInfo.genTime);
  return { token: 'held', trust: path.outcome, ...facts, ...(path.error !== undefined && path.outcome !== 'valid' && { error: path.error }) };
}
