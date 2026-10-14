import { createPublicKey, type KeyObject } from 'crypto';

/**
 * COSE_Key decoding for WebAuthn credential public keys.
 *
 * WebAuthn authenticators hand the relying party a COSE_Key (RFC 8152, a CBOR
 * map), not an SPKI DER SubjectPublicKeyInfo. `@simplewebauthn/server` returns
 * exactly those COSE bytes as `registrationInfo.credential.publicKey`, and it
 * wants them back in that same form for `verifyAuthenticationResponse`.
 *
 * Node's `crypto.createPublicKey` cannot read COSE. So anything that verifies a
 * raw WebAuthn signature itself — `verifySignatureCrypto` in
 * `verify-attestation.ts` — has to convert first. This module is that
 * conversion, deliberately self-contained: the offline export verifier must not
 * need `@simplewebauthn/server` (or any CBOR package) on its dependency path.
 *
 * It also answers the question the browser-only `getPublicKeyAlgorithm()` was
 * being asked: the COSE key states its own algorithm in label 3, and that value
 * survives JSON transport to the server, which the method does not.
 */

/** COSE key type (label 1). */
const COSE_KTY_OKP = 1;
const COSE_KTY_EC2 = 2;

/** COSE elliptic curve (label -1). */
const COSE_CRV_P256 = 1;
const COSE_CRV_P384 = 2;
const COSE_CRV_P521 = 3;
const COSE_CRV_ED25519 = 6;

/** COSE algorithm (label 3). */
export const COSE_ALG_ES256 = -7;
export const COSE_ALG_EDDSA = -8;
export const COSE_ALG_ES384 = -35;
export const COSE_ALG_ES512 = -36;

export interface CoseKeyInfo {
  /** COSE key type: 1 = OKP, 2 = EC2. */
  kty: number;
  /** COSE algorithm identifier, e.g. -7 (ES256) or -8 (EdDSA). */
  alg?: number;
  /** COSE curve identifier, e.g. 1 (P-256) or 6 (Ed25519). */
  crv?: number;
  x?: Buffer;
  y?: Buffer;
}

type CborValue = number | Buffer | string | boolean | null | Map<CborValue, CborValue> | CborValue[];

interface Cursor {
  buf: Buffer;
  pos: number;
}

function readHead(c: Cursor): { mt: number; val: number } {
  if (c.pos >= c.buf.length) {
    throw new Error('CBOR: truncated');
  }
  const ib = c.buf[c.pos++];
  const mt = ib >> 5;
  const ai = ib & 0x1f;
  let val: number;
  if (ai < 24) {
    val = ai;
  } else if (ai === 24) {
    if (c.pos + 1 > c.buf.length) throw new Error('CBOR: truncated');
    val = c.buf.readUInt8(c.pos);
    c.pos += 1;
  } else if (ai === 25) {
    if (c.pos + 2 > c.buf.length) throw new Error('CBOR: truncated');
    val = c.buf.readUInt16BE(c.pos);
    c.pos += 2;
  } else if (ai === 26) {
    if (c.pos + 4 > c.buf.length) throw new Error('CBOR: truncated');
    val = c.buf.readUInt32BE(c.pos);
    c.pos += 4;
  } else {
    // 27 (64-bit), 28-30 (reserved) and 31 (indefinite length) do not occur in
    // a COSE_Key produced by an authenticator.
    throw new Error(`CBOR: unsupported additional info ${ai}`);
  }
  return { mt, val };
}

function readValue(c: Cursor): CborValue {
  const { mt, val } = readHead(c);
  switch (mt) {
    case 0: // unsigned integer
      return val;
    case 1: // negative integer: -1 - n
      return -1 - val;
    case 2: {
      // byte string
      if (c.pos + val > c.buf.length) throw new Error('CBOR: truncated byte string');
      const bytes = c.buf.subarray(c.pos, c.pos + val);
      c.pos += val;
      return Buffer.from(bytes);
    }
    case 3: {
      // text string
      if (c.pos + val > c.buf.length) throw new Error('CBOR: truncated text string');
      const s = c.buf.toString('utf8', c.pos, c.pos + val);
      c.pos += val;
      return s;
    }
    case 4: {
      // array
      const arr: CborValue[] = [];
      for (let i = 0; i < val; i++) arr.push(readValue(c));
      return arr;
    }
    case 5: {
      // map
      const m = new Map<CborValue, CborValue>();
      for (let i = 0; i < val; i++) {
        const k = readValue(c);
        m.set(k, readValue(c));
      }
      return m;
    }
    case 7:
      if (val === 20) return false;
      if (val === 21) return true;
      if (val === 22) return null;
      throw new Error(`CBOR: unsupported simple value ${val}`);
    default:
      throw new Error(`CBOR: unsupported major type ${mt}`);
  }
}

/**
 * Decode a COSE_Key into its labelled parts.
 *
 * @returns the decoded key, or `undefined` if the bytes are not a COSE_Key map.
 */
export function decodeCoseKey(publicKey: Buffer | Uint8Array): CoseKeyInfo | undefined {
  try {
    const c: Cursor = { buf: Buffer.from(publicKey), pos: 0 };
    const decoded = readValue(c);
    if (!(decoded instanceof Map)) return undefined;
    const kty = decoded.get(1);
    if (typeof kty !== 'number') return undefined;
    const alg = decoded.get(3);
    const crv = decoded.get(-1);
    const x = decoded.get(-2);
    const y = decoded.get(-3);
    return {
      kty,
      ...(typeof alg === 'number' && { alg }),
      ...(typeof crv === 'number' && { crv }),
      ...(Buffer.isBuffer(x) && { x }),
      ...(Buffer.isBuffer(y) && { y }),
    };
  } catch {
    return undefined;
  }
}

/**
 * The COSE algorithm identifier a credential public key declares.
 *
 * This is the value `getPublicKeyAlgorithm()` would have returned in the
 * browser. Reading it from the key works on the server, where the browser
 * method does not exist because it does not survive `JSON.stringify`.
 */
export function coseAlgorithmOf(publicKey: Buffer | Uint8Array): number | undefined {
  const key = decodeCoseKey(publicKey);
  if (!key) return undefined;
  if (typeof key.alg === 'number') return key.alg;
  // Some authenticators omit label 3. The curve is enough to disambiguate the
  // two algorithms Tzun registers.
  if (key.kty === COSE_KTY_OKP && key.crv === COSE_CRV_ED25519) return COSE_ALG_EDDSA;
  if (key.kty === COSE_KTY_EC2 && key.crv === COSE_CRV_P256) return COSE_ALG_ES256;
  return undefined;
}

function b64url(b: Buffer): string {
  return b.toString('base64url');
}

const EC_CURVE_BY_COSE: Record<number, { name: string; coordLen: number }> = {
  [COSE_CRV_P256]: { name: 'P-256', coordLen: 32 },
  [COSE_CRV_P384]: { name: 'P-384', coordLen: 48 },
  [COSE_CRV_P521]: { name: 'P-521', coordLen: 66 },
};

/**
 * Import a COSE_Key as a Node `KeyObject`.
 *
 * @returns the key, or `undefined` if the bytes are not a COSE_Key of a
 *          supported type.
 */
export function coseToKeyObject(publicKey: Buffer | Uint8Array): KeyObject | undefined {
  const key = decodeCoseKey(publicKey);
  if (!key) return undefined;
  try {
    if (key.kty === COSE_KTY_EC2) {
      const curve = key.crv !== undefined ? EC_CURVE_BY_COSE[key.crv] : undefined;
      if (!curve || !key.x || !key.y) return undefined;
      // Left-pad: JWK requires the full fixed-width coordinate.
      const pad = (b: Buffer): Buffer =>
        b.length >= curve.coordLen
          ? b.subarray(b.length - curve.coordLen)
          : Buffer.concat([Buffer.alloc(curve.coordLen - b.length), b]);
      return createPublicKey({
        key: { kty: 'EC', crv: curve.name, x: b64url(pad(key.x)), y: b64url(pad(key.y)) },
        format: 'jwk',
      });
    }
    if (key.kty === COSE_KTY_OKP) {
      if (key.crv !== COSE_CRV_ED25519 || !key.x) return undefined;
      return createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: b64url(key.x) },
        format: 'jwk',
      });
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Import a stored WebAuthn public key regardless of which of the two formats it
 * was persisted in.
 *
 * Registrations that went through `TzunWebAuthn.finishRegistration` store the
 * authenticator's COSE_Key, because that is what
 * `verifyAuthenticationResponse` needs handed back. Credentials registered
 * directly by an integrator (and every fixture in the test suite before this
 * was understood) hold an SPKI DER export. Both are legitimate; the verifier
 * accepts either rather than silently reporting `signatureValid: false` for one
 * of them.
 */
export function importCredentialPublicKey(publicKey: Buffer | Uint8Array): KeyObject | undefined {
  const buf = Buffer.from(publicKey);
  // An SPKI DER SubjectPublicKeyInfo is a DER SEQUENCE (0x30). A COSE_Key is a
  // CBOR map (major type 5 => 0xa0-0xbf). The tags cannot collide, so this
  // dispatch is exact rather than a guess; the fallback covers nothing but
  // corrupt input.
  if (buf[0] === 0x30) {
    try {
      return createPublicKey({ key: buf, format: 'der', type: 'spki' });
    } catch {
      return coseToKeyObject(buf);
    }
  }
  return coseToKeyObject(buf) ?? trySpki(buf);
}

function trySpki(buf: Buffer): KeyObject | undefined {
  try {
    return createPublicKey({ key: buf, format: 'der', type: 'spki' });
  } catch {
    return undefined;
  }
}

/**
 * Map a Node `KeyObject` onto the two signature algorithms Tzun records.
 *
 * The point of asking the key rather than trusting `StoredCredential.algorithm`
 * is that a stored label can be wrong: credentials registered by earlier SDK
 * versions carry `'ES256'` unconditionally, Ed25519 ones included. A
 * mislabelled Ed25519 key verified with `createVerify('SHA256')` never
 * validates.
 */
export function signatureAlgorithmOfKey(key: KeyObject): 'Ed25519' | 'ES256' | undefined {
  const t = key.asymmetricKeyType;
  if (t === 'ed25519') return 'Ed25519';
  if (t === 'ec') {
    // Only P-256 is ES256. A P-384 key would need SHA-384, so returning
    // 'ES256' for it would be a different silent mislabel; leave it undefined
    // and let the caller fall back to the stored label.
    const curve = key.asymmetricKeyDetails?.namedCurve;
    if (curve === 'prime256v1' || curve === 'P-256') return 'ES256';
    return undefined;
  }
  return undefined;
}
