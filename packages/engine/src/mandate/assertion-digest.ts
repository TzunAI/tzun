/**
 * The assertion digest (Record §9.6): one value per WebAuthn ceremony,
 * whatever encoding of its signature a party holds.
 *
 *   assertionDigest = hex(SHA-256(UTF8("tzun-assertion-v1")
 *                                 ‖ SHA-256(authenticatorData)
 *                                 ‖ SHA-256(clientDataJSON)
 *                                 ‖ SHA-256(signature')))
 *
 * For ES256, `signature'` is the signature parsed as DER and re-encoded in
 * minimal DER, with `s` replaced by `n − s` when `s > n/2` (low-S). A
 * signature that is not DER is refused. For Ed25519, `signature'` is the
 * signature as given. Each member is decoded from base64 or base64url text,
 * padded or not, so two encodings of the same bytes give one digest.
 */
import { createHash } from 'crypto';

/** The domain separator (17 bytes). Not a prefix of any other Tzun separator. */
const ASSERTION_DOMAIN = 'tzun-assertion-v1';

/** The order of the P-256 group. */
export const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const P256_HALF_ORDER = P256_ORDER >> BigInt(1);

/** Why an assertion has no assertion digest. */
export type AssertionDigestFailure =
  | 'not_an_object'
  | 'unsupported_algorithm'
  | 'missing_authenticator_data'
  | 'missing_client_data'
  | 'invalid_encoding'
  | 'signature_not_der';

export type AssertionDigestResult = { ok: true; digest: string } | { ok: false; reason: AssertionDigestFailure };

/**
 * Decode base64 or base64url text, padded or not, or `null` when it is not
 * such text. The two alphabets may not be mixed within one value.
 */
export function decodeBase64Text(text: unknown): Buffer | null {
  if (typeof text !== 'string' || text.length === 0) return null;
  const body = text.replace(/=+$/, '');
  if (text.length - body.length > 2) return null;
  const standard = /^[A-Za-z0-9+/]*$/.test(body);
  const url = /^[A-Za-z0-9_-]*$/.test(body);
  if (!standard && !url) return null;
  if (body.length % 4 === 1) return null;
  if (text.length !== body.length && text.length % 4 !== 0) return null;
  return Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

interface DerReader {
  bytes: Buffer;
  pos: number;
}

function readLength(r: DerReader): number | null {
  if (r.pos >= r.bytes.length) return null;
  const first = r.bytes[r.pos++];
  if (first < 0x80) return first;
  const count = first & 0x7f;
  if (count === 0 || count > 4) return null;
  let len = 0;
  for (let i = 0; i < count; i++) {
    if (r.pos >= r.bytes.length) return null;
    len = len * 256 + r.bytes[r.pos++];
  }
  return len;
}

function readInteger(r: DerReader): bigint | null {
  if (r.pos >= r.bytes.length || r.bytes[r.pos++] !== 0x02) return null;
  const len = readLength(r);
  if (len === null || len === 0 || r.pos + len > r.bytes.length) return null;
  const content = r.bytes.subarray(r.pos, r.pos + len);
  r.pos += len;
  if (content[0] & 0x80) return null; // negative
  return BigInt('0x' + content.toString('hex'));
}

function encodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeInteger(value: bigint): Buffer {
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let content = Buffer.from(hex, 'hex');
  if (content[0] & 0x80) content = Buffer.concat([Buffer.from([0]), content]);
  return Buffer.concat([Buffer.from([0x02]), encodeLength(content.length), content]);
}

/**
 * An ECDSA P-256 signature re-encoded in minimal DER with low S, or `null`
 * when `der` is not a DER `SEQUENCE { INTEGER r, INTEGER s }` with `r` and `s`
 * in 1..n−1 and nothing after it. Non-minimal length and integer encodings are
 * read; the output is always the one minimal, low-S encoding.
 */
export function normaliseEs256Signature(der: Buffer): Buffer | null {
  const r: DerReader = { bytes: der, pos: 0 };
  if (der.length === 0 || der[r.pos++] !== 0x30) return null;
  const seqLen = readLength(r);
  if (seqLen === null || r.pos + seqLen !== der.length) return null;
  const rValue = readInteger(r);
  const sValue = readInteger(r);
  if (rValue === null || sValue === null || r.pos !== der.length) return null;
  const zero = BigInt(0);
  if (rValue <= zero || rValue >= P256_ORDER || sValue <= zero || sValue >= P256_ORDER) return null;
  const lowS = sValue > P256_HALF_ORDER ? P256_ORDER - sValue : sValue;
  const body = Buffer.concat([encodeInteger(rValue), encodeInteger(lowS)]);
  return Buffer.concat([Buffer.from([0x30]), encodeLength(body.length), body]);
}

function sha256(bytes: Buffer): Buffer {
  return createHash('sha256').update(bytes).digest();
}

/** The assertion digest of a WebAuthn assertion, or why it has none. Never throws. */
export function assertionDigestResult(assertion: unknown): AssertionDigestResult {
  if (assertion === null || typeof assertion !== 'object' || Array.isArray(assertion)) {
    return { ok: false, reason: 'not_an_object' };
  }
  const a = assertion as Record<string, unknown>;
  if (a.algorithm !== 'ES256' && a.algorithm !== 'Ed25519') return { ok: false, reason: 'unsupported_algorithm' };
  if (a.authenticatorData === undefined || a.authenticatorData === null) {
    return { ok: false, reason: 'missing_authenticator_data' };
  }
  if (a.clientDataJSON === undefined || a.clientDataJSON === null) return { ok: false, reason: 'missing_client_data' };
  const authenticatorData = decodeBase64Text(a.authenticatorData);
  const clientData = decodeBase64Text(a.clientDataJSON);
  const signature = decodeBase64Text(a.signature);
  if (authenticatorData === null || clientData === null || signature === null) {
    return { ok: false, reason: 'invalid_encoding' };
  }
  let normalised = signature;
  if (a.algorithm === 'ES256') {
    const der = normaliseEs256Signature(signature);
    if (der === null) return { ok: false, reason: 'signature_not_der' };
    normalised = der;
  }
  const digest = createHash('sha256')
    .update(ASSERTION_DOMAIN, 'utf8')
    .update(sha256(authenticatorData))
    .update(sha256(clientData))
    .update(sha256(normalised))
    .digest('hex');
  return { ok: true, digest };
}

/** The assertion digest, 64 lowercase hex, or `null` when the assertion has none. Never throws. */
export function assertionDigest(assertion: unknown): string | null {
  const result = assertionDigestResult(assertion);
  return result.ok ? result.digest : null;
}
