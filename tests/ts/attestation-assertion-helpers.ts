/**
 * Shared fixtures for the attestation verification tests.
 *
 * Not a suite — jest's testMatch is `**\/tests/**\/*.test.ts`, so this file is
 * only ever imported.
 */
import { AttestationArtifacts } from '@tzun/engine';
import { CredentialStore } from '../../src/attestation/credential-store';
import {
  createHash,
  createSign,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  type KeyObject,
} from 'crypto';

export const RP_ID = 'localhost';
export const ORIGIN = 'http://localhost:3847';

export function sha256hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

/**
 * Build a *genuine* WebAuthn-shaped ES256 assertion: a real P-256 signature
 * over `authenticatorData ++ SHA-256(clientDataJSON)`, the way an authenticator
 * actually signs.
 *
 * `authenticatorData` is realistic rather than a placeholder string: 32-byte
 * rpIdHash ++ 1 flags byte ++ 4-byte counter (37 bytes). Flags 0x05 =
 * User Present | User Verified.
 */
export function makeGenuineAssertion(opts: {
  challenge: string;
  credentialId: string;
  rpId?: string;
  origin?: string;
  flags?: number;
  type?: string;
  /** More `clientDataJSON` members — `crossOrigin`, `topOrigin` — as a browser adds them. */
  clientData?: Record<string, unknown>;
}): { publicKeyBase64: string; assertion: NonNullable<AttestationArtifacts['webauthnAssertion']> } {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKeyBase64 = (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64');

  const authenticatorData = Buffer.concat([
    createHash('sha256').update(opts.rpId ?? RP_ID, 'utf8').digest(),
    Buffer.from([opts.flags ?? 0x05]),
    Buffer.from([0x00, 0x00, 0x00, 0x01]),
  ]);

  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: opts.type ?? 'webauthn.get',
      challenge: opts.challenge,
      origin: opts.origin ?? ORIGIN,
      ...opts.clientData,
    }),
  );

  const signer = createSign('SHA256');
  signer.update(Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]));

  return {
    publicKeyBase64,
    assertion: {
      signature: signer.sign(privateKey).toString('base64'),
      credentialKeyId: opts.credentialId,
      algorithm: 'ES256',
      authenticatorData: authenticatorData.toString('base64'),
      clientDataJSON: clientDataJSON.toString('base64'),
    },
  };
}

export function storeWith(
  credentialId: string,
  publicKey: string,
  status: 'active' | 'revoked' = 'active',
): CredentialStore {
  const store = new CredentialStore();
  store.register({
    credentialId,
    publicKey,
    userId: 'jane@acme.example',
    algorithm: 'ES256',
    counter: 0,
    status: 'active',
    registeredAt: '2026-03-22T10:00:00.000Z',
  });
  if (status === 'revoked') store.revoke(credentialId);
  return store;
}

// --- COSE_Key fixtures -----------------------------------------------------
//
// A real authenticator hands the relying party a COSE_Key, and
// `@simplewebauthn/server` passes those bytes straight through as
// `registrationInfo.credential.publicKey`. Every fixture above uses an SPKI DER
// export instead, which is why the suite could not see that the verifier's
// `createPublicKey({type:'spki'})` throws on the format the product actually
// stores. These helpers produce the genuine article.

function cborHead(mt: number, val: number): Buffer {
  if (val < 24) return Buffer.from([(mt << 5) | val]);
  if (val < 0x100) return Buffer.from([(mt << 5) | 24, val]);
  if (val < 0x10000) return Buffer.from([(mt << 5) | 25, val >> 8, val & 0xff]);
  throw new Error('fixture: value too large for the minimal CBOR encoder');
}

function cborItem(v: number | Buffer): Buffer {
  if (Buffer.isBuffer(v)) return Buffer.concat([cborHead(2, v.length), v]);
  return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
}

/** Encode a COSE_Key map from `[label, value]` pairs, in the given order. */
export function encodeCoseKey(entries: Array<[number, number | Buffer]>): Buffer {
  return Buffer.concat([
    cborHead(5, entries.length),
    ...entries.flatMap(([k, v]) => [cborItem(k), cborItem(v)]),
  ]);
}

function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

/** The COSE_Key an authenticator would emit for this public key. */
export function coseKeyFor(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
  if (jwk.kty === 'EC') {
    // kty=EC2(2), alg=ES256(-7), crv=P-256(1), x, y
    return encodeCoseKey([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, b64urlToBuf(jwk.x)],
      [-3, b64urlToBuf(jwk.y)],
    ]);
  }
  if (jwk.kty === 'OKP') {
    // kty=OKP(1), alg=EdDSA(-8), crv=Ed25519(6), x
    return encodeCoseKey([
      [1, 1],
      [3, -8],
      [-1, 6],
      [-2, b64urlToBuf(jwk.x)],
    ]);
  }
  throw new Error(`fixture: unsupported key type ${jwk.kty}`);
}

export interface GenuineCredential {
  /** COSE_Key bytes, exactly as `finishRegistration` receives them. */
  coseKey: Buffer;
  /** SPKI DER, base64 — the encoding a direct integrator registration holds. */
  spkiBase64: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function makeCredential(algorithm: 'ES256' | 'Ed25519'): GenuineCredential {
  const { privateKey, publicKey } =
    algorithm === 'Ed25519'
      ? generateKeyPairSync('ed25519')
      : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    coseKey: coseKeyFor(publicKey),
    spkiBase64: (publicKey.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64'),
    privateKey,
    publicKey,
  };
}

/**
 * Sign an assertion the way an authenticator does, with a caller-supplied key
 * so the test controls both encodings of the SAME key pair.
 */
export function signAssertionWith(
  cred: GenuineCredential,
  algorithm: 'ES256' | 'Ed25519',
  opts: { challenge: string; credentialId: string; rpId?: string; origin?: string; flags?: number },
): NonNullable<AttestationArtifacts['webauthnAssertion']> {
  const authenticatorData = Buffer.concat([
    createHash('sha256').update(opts.rpId ?? RP_ID, 'utf8').digest(),
    Buffer.from([opts.flags ?? 0x05]),
    Buffer.from([0x00, 0x00, 0x00, 0x01]),
  ]);
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: opts.challenge,
      origin: opts.origin ?? ORIGIN,
    }),
  );
  const signedData = Buffer.concat([
    authenticatorData,
    createHash('sha256').update(clientDataJSON).digest(),
  ]);

  const signature =
    algorithm === 'Ed25519'
      ? cryptoSign(null, signedData, cred.privateKey)
      : (() => {
          const signer = createSign('SHA256');
          signer.update(signedData);
          return signer.sign(cred.privateKey);
        })();

  return {
    signature: signature.toString('base64'),
    credentialKeyId: opts.credentialId,
    algorithm,
    authenticatorData: authenticatorData.toString('base64'),
    clientDataJSON: clientDataJSON.toString('base64'),
  };
}

/**
 * An authentication response as the server receives it from the browser
 * (`AuthenticationResponseJSON`): base64url throughout, `id === rawId`, and
 * signed with `cred`'s private key, which must be ES256, over authenticator
 * data for {@link RP_ID} with flags User Present | User Verified and counter 1.
 * `clientData` adds members to clientDataJSON — `crossOrigin`, `topOrigin` —
 * as a browser does.
 */
export function authenticationResponse(
  cred: GenuineCredential,
  opts: { credentialId: string; challenge: string; clientData?: Record<string, unknown> },
): any {
  const authenticatorData = Buffer.concat([
    createHash('sha256').update(RP_ID, 'utf8').digest(),
    Buffer.from([0x05]),
    Buffer.from([0x00, 0x00, 0x00, 0x01]),
  ]);
  const clientDataJSON = Buffer.from(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: opts.challenge,
      origin: ORIGIN,
      ...opts.clientData,
    }),
  );
  const signer = createSign('SHA256');
  signer.update(Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]));
  return {
    id: opts.credentialId,
    rawId: opts.credentialId,
    type: 'public-key',
    response: {
      clientDataJSON: clientDataJSON.toString('base64url'),
      authenticatorData: authenticatorData.toString('base64url'),
      signature: signer.sign(cred.privateKey).toString('base64url'),
    },
    clientExtensionResults: {},
  };
}

// --- Registration responses ------------------------------------------------

export type Cbor = number | string | Buffer | Cbor[] | Map<Cbor, Cbor>;

/** The CBOR subset an attestation object needs: ints, byte and text strings, arrays, maps. */
export function cbor(v: Cbor): Buffer {
  if (typeof v === 'number') return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (typeof v === 'string') {
    const bytes = Buffer.from(v, 'utf8');
    return Buffer.concat([cborHead(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(v)) return Buffer.concat([cborHead(2, v.length), v]);
  if (Array.isArray(v)) return Buffer.concat([cborHead(4, v.length), ...v.map(cbor)]);
  return Buffer.concat([
    cborHead(5, v.size),
    ...[...v.entries()].flatMap(([k, val]) => [cbor(k), cbor(val)]),
  ]);
}

/** The challenge in the clientDataJSON of every `registrationResponse()`. */
export const REGISTRATION_CHALLENGE = createHash('sha256')
  .update('registration-verify', 'utf8')
  .digest('base64url');

/** Flags: User Present (0x01) | User Verified (0x04) | Attested credential data (0x40). */
const FLAGS_UP_UV_AT = 0x45;

/**
 * A registration response as the server receives it: plain JSON off the wire,
 * built the way an authenticator and browser would (authenticator data holding
 * `coseKey`, a CBOR attestation object, clientDataJSON for
 * {@link REGISTRATION_CHALLENGE} and {@link ORIGIN}). The attestation format is
 * "none" unless `fmt` and `attStmt` say otherwise.
 */
export function registrationResponse(opts: {
  coseKey: Buffer;
  fmt?: string;
  attStmt?: Map<Cbor, Cbor>;
}): any {
  const credentialId = randomBytes(16);
  const credentialIdLength = Buffer.alloc(2);
  credentialIdLength.writeUInt16BE(credentialId.length);
  const authData = Buffer.concat([
    createHash('sha256').update(RP_ID, 'utf8').digest(),
    Buffer.from([FLAGS_UP_UV_AT]),
    Buffer.from([0, 0, 0, 0]), // signature counter
    Buffer.alloc(16), // AAGUID
    credentialIdLength,
    credentialId,
    opts.coseKey,
  ]);
  const attestationObject = cbor(
    new Map<Cbor, Cbor>([
      ['fmt', opts.fmt ?? 'none'],
      ['attStmt', opts.attStmt ?? new Map()],
      ['authData', authData],
    ]),
  );
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: 'webauthn.create', challenge: REGISTRATION_CHALLENGE, origin: ORIGIN }),
  );
  const id = credentialId.toString('base64url');
  return JSON.parse(
    JSON.stringify({
      id,
      rawId: id,
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSON.toString('base64url'),
        attestationObject: attestationObject.toString('base64url'),
        transports: ['internal'],
      },
      clientExtensionResults: {},
    }),
  );
}
