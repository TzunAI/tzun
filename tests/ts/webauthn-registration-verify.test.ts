/**
 * Registration verification through the real `@simplewebauthn/server`.
 *
 * The other WebAuthn suites mock the library, so they can check what
 * `TzunWebAuthn` hands it but not what the library then does. Here nothing is
 * mocked: each test builds a registration response the way an authenticator
 * and browser would (a real key pair, authenticator data, a CBOR attestation
 * object, clientDataJSON) and runs it through `finishRegistration()`.
 *
 * No test here reaches the network. The jest setup file refuses every
 * non-loopback fetch, and the attestation cases also replace `fetch` and
 * assert how often it was called.
 */
import { generateKeyPairSync, randomBytes, X509Certificate } from 'crypto';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { CredentialStore } from '../../src/attestation/credential-store';
import { TzunWebAuthn } from '../../src/attestation/webauthn';
import {
  cbor,
  coseKeyFor,
  encodeCoseKey,
  makeCredential,
  ORIGIN,
  REGISTRATION_CHALLENGE as CHALLENGE,
  registrationResponse,
  RP_ID,
  type Cbor,
} from './attestation-assertion-helpers';

function rs256CoseKey(): Buffer {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
  // kty=RSA(3), alg=RS256(-257), n, e
  return encodeCoseKey([
    [1, 3],
    [3, -257],
    [-1, Buffer.from(jwk.n, 'base64url')],
    [-2, Buffer.from(jwk.e, 'base64url')],
  ]);
}

function mlDsa44CoseKey(): Buffer {
  // kty=AKP(7), alg=ML-DSA-44(-48), pub. The verifier refuses on the alg
  // label before it reads the key, so the key bytes need not be a real key.
  return encodeCoseKey([
    [1, 7],
    [3, -48],
    [-1, randomBytes(1312)],
  ]);
}

/**
 * An attestation certificate chain anyone can make: LEAF is signed by ROOT, a
 * self-signed P-256 CA that no relying party trusts. Both are valid from
 * 2026-01-01 to 2126-01-01.
 *
 * LEAF carries a CRL Distribution Points extension naming LEAF_CRL_URL, and
 * the Android key attestation extension (1.3.6.1.4.1.11129.2.1.17): a
 * KeyDescription whose attestationChallenge is SHA-256 of the clientDataJSON
 * `registrationResponse()` builds, with empty authorization lists, so no
 * allApplications. ROOT names no CRL. LEAF's private key was not kept: the
 * credential key in each response below is LEAF's public key, and nothing
 * here needs a signature that verifies.
 */
const LEAF_CRL_URL = 'http://crl.invalid/tzun-attestation-leaf.crl';
const LEAF = Buffer.from(
  'MIIB8zCCAZmgAwIBAgIBAjAKBggqhkjOPQQDAjAlMSMwIQYDVQQDDBpUenVuIHRlc3QgYXR0ZXN0' +
    'YXRpb24gcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMTI2MDEwMTAwMDAwMFowJTEjMCEGA1UEAwwa' +
    'VHp1biB0ZXN0IGF0dGVzdGF0aW9uIGxlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAStkioB' +
    'xyq3VJ+XcbBsTiajcr8TJfofmlJAN3b2VCyuxvhMCe181n1ys1vVCxw7ozuZvEGsUM2SuZTY0nvJ' +
    'oFNXo4G3MIG0MAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUMWlJr2niOs7daFcHHGKQc9FZ6Aww' +
    'PQYDVR0fBDYwNDAyoDCgLoYsaHR0cDovL2NybC5pbnZhbGlkL3R6dW4tYXR0ZXN0YXRpb24tbGVh' +
    'Zi5jcmwwRAYKKwYBBAHWeQIBEQQ2MDQCAQMKAQACAQAKAQAEIPIQu8lVuQ4A13Xh+IxoLA1CKtAH' +
    '2GaMethUZswB5M3SBAAwADAAMAoGCCqGSM49BAMCA0gAMEUCIAzIxMdEnWtkaNTFxiebwXe3yQcK' +
    'l5Ttq6Cl9JCanDLKAiEAqYRXz3lWiNsQbL+eqfiio6wxbYq08e18cKHlhXTVwBQ=',
  'base64',
);
const ROOT = Buffer.from(
  'MIIBfDCCASOgAwIBAgIBATAKBggqhkjOPQQDAjAlMSMwIQYDVQQDDBpUenVuIHRlc3QgYXR0ZXN0' +
    'YXRpb24gcm9vdDAgFw0yNjAxMDEwMDAwMDBaGA8yMTI2MDEwMTAwMDAwMFowJTEjMCEGA1UEAwwa' +
    'VHp1biB0ZXN0IGF0dGVzdGF0aW9uIHJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATUVjOn' +
    'gVeePHGdCZEIoJ7YSMkQcXqU2MpSExUPXfoaxznaO8ruMdR+mDdvgLaXYPvwcxmonS8Ecpom7SJ3' +
    'XJebo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUMWlJr2ni' +
    'Os7daFcHHGKQc9FZ6AwwCgYIKoZIzj0EAwIDRwAwRAIgCtUbgJUGXs7ANYciVymnn/T9MXcGtOiT' +
    'qX2hLNftaxcCIHhB7MNLycasrx8wcsQD3Ou6BpCuwRAc7Y0IMIR1b1jM',
  'base64',
);

/** LEAF's public key as the authenticator's COSE_Key (ES256). */
const LEAF_COSE_KEY = coseKeyFor(new X509Certificate(LEAF).publicKey);

/** A signature of the right size. No verifier checks it before the certificate path. */
const SIG = Buffer.alloc(70);

/** An android-safetynet `response`: a JWS whose header carries the x5c. */
function safetyNetJws(): Buffer {
  const part = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const header = part({ alg: 'ES256', x5c: [LEAF.toString('base64'), ROOT.toString('base64')] });
  const payload = part({ nonce: '', timestampMs: Date.now(), ctsProfileMatch: true, basicIntegrity: true });
  return Buffer.from(`${header}.${payload}.${SIG.toString('base64url')}`);
}

/**
 * One attestation statement per format the library verifies, each in its
 * format's shape and each carrying LEAF, so that a verifier handed the
 * statement would take that format's certificate path. The android-key one is
 * complete up to the certificate path: LEAF's key is the credential key, its
 * challenge is the clientDataJSON hash, and its chain ends at its own root.
 */
const ANDROID_KEY_STATEMENT = new Map<Cbor, Cbor>([
  ['alg', -7],
  ['sig', SIG],
  ['x5c', [LEAF, ROOT]],
]);
const ATTESTATION_STATEMENTS: Array<[string, Map<Cbor, Cbor>]> = [
  ['packed', new Map<Cbor, Cbor>([['alg', -7], ['sig', SIG], ['x5c', [LEAF, ROOT]]])],
  [
    'tpm',
    new Map<Cbor, Cbor>([
      ['ver', '2.0'],
      ['alg', -7],
      ['x5c', [LEAF, ROOT]],
      ['sig', SIG],
      ['certInfo', randomBytes(64)],
      ['pubArea', randomBytes(64)],
    ]),
  ],
  ['android-key', ANDROID_KEY_STATEMENT],
  ['android-safetynet', new Map<Cbor, Cbor>([['ver', '1'], ['response', safetyNetJws()]])],
  ['apple', new Map<Cbor, Cbor>([['x5c', [LEAF, ROOT]]])],
  ['fido-u2f', new Map<Cbor, Cbor>([['sig', SIG], ['x5c', [LEAF]]])],
];

function stubFetch(): jest.SpyInstance {
  return jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('test: fetch is not available'));
}

describe('finishRegistration against the real @simplewebauthn/server', () => {
  let store: CredentialStore;
  let webauthn: TzunWebAuthn;

  beforeEach(() => {
    store = new CredentialStore();
    webauthn = new TzunWebAuthn({ rpID: RP_ID, rpName: 'Tzun Evidence', origin: ORIGIN }, store);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each(['ES256', 'Ed25519'] as const)(
    'verifies and stores an %s credential under its own label',
    async (algorithm) => {
      const cred = makeCredential(algorithm);
      const response = registrationResponse({ coseKey: cred.coseKey });

      const result = await webauthn.finishRegistration('jane@acme.example', response, CHALLENGE);

      expect(result).toEqual({ verified: true, credentialId: response.id });
      const stored = store.getByCredentialId(response.id);
      expect(stored?.algorithm).toBe(algorithm);
      expect(Buffer.from(stored!.publicKey, 'base64').equals(cred.coseKey)).toBe(true);
    },
  );

  // RS256 is in the verifier's default list on every runtime, so this case
  // tells a verifier that was handed the offered list from one left to its
  // default. ML-DSA-44 joins the default list only on runtimes with
  // post-quantum support.
  it.each([
    ['RS256', -257, rs256CoseKey],
    ['ML-DSA-44', -48, mlDsa44CoseKey],
  ])('refuses an %s credential, which the options never offered', async (_name, alg, coseKey) => {
    const response = registrationResponse({ coseKey: coseKey() });

    const result = await webauthn.finishRegistration('jane@acme.example', response, CHALLENGE);

    expect(result.verified).toBe(false);
    expect(result.error).toContain(`Unexpected public key alg "${alg}"`);
    expect(store.getByCredentialId(response.id)).toBeUndefined();
  });

  // What finishRegistration() guards against, shown on the library alone:
  // for android-key, `verifyRegistrationResponse()` validates the x5c against
  // the x5c's own last certificate, checks revocation along that chain, and
  // only then finds that ROOT is not a Google root. So it fetches the CRL
  // that LEAF names. This also shows the android-key fixture reaches the
  // fetch, so the next test does not pass for want of it. Should a library
  // release stop this fetch, this test fails and can go; finishRegistration()
  // does not depend on the fetch happening.
  it('canary: pins that 14.0.3 fetches the CRL named by an android-key leaf that chains to its own root; expected to fail when upstream stops the fetch', async () => {
    const fetchSpy = stubFetch();
    const response = registrationResponse({
      coseKey: LEAF_COSE_KEY,
      fmt: 'android-key',
      attStmt: ANDROID_KEY_STATEMENT,
    });

    await expect(
      verifyRegistrationResponse({
        response,
        expectedChallenge: CHALLENGE,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        supportedAlgorithmIDs: [-8, -7],
      }),
    ).rejects.toThrow('x5c root certificate was not a known root certificate');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(String(fetchSpy.mock.calls[0][0])).toBe(LEAF_CRL_URL);
  });

  // An attestation statement comes from the client, and verifying one is what
  // fetches. finishRegistration() replaces every statement with "none" before
  // the library sees the response, so no format reaches a certificate, and
  // the credential registers as it would have under "none".
  it.each(ATTESTATION_STATEMENTS)(
    'registers a response in attestation format %s as "none" and fetches nothing',
    async (fmt, attStmt) => {
      const fetchSpy = stubFetch();
      const response = registrationResponse({ coseKey: LEAF_COSE_KEY, fmt, attStmt });
      const sent = response.response.attestationObject;

      const result = await webauthn.finishRegistration('jane@acme.example', response, CHALLENGE);

      expect(fetchSpy).not.toHaveBeenCalled();
      expect(result).toEqual({ verified: true, credentialId: response.id });
      const stored = store.getByCredentialId(response.id);
      expect(stored?.algorithm).toBe('ES256');
      expect(Buffer.from(stored!.publicKey, 'base64').equals(LEAF_COSE_KEY)).toBe(true);
      // The caller's response is left as it was sent.
      expect(response.response.attestationObject).toBe(sent);
    },
  );

  it.each([
    ['no attestation object', (r: any) => delete r.response.attestationObject, 'has no attestationObject'],
    [
      'an attestation object that is not a map',
      (r: any) => (r.response.attestationObject = cbor([1, 2]).toString('base64url')),
      'has no authData',
    ],
    [
      'an attestation object without authData',
      (r: any) =>
        (r.response.attestationObject = cbor(
          new Map<Cbor, Cbor>([
            ['fmt', 'none'],
            ['attStmt', new Map()],
          ]),
        ).toString('base64url')),
      'has no authData',
    ],
  ])('refuses a response with %s', async (_name, spoil, error) => {
    const fetchSpy = stubFetch();
    const response = registrationResponse({ coseKey: makeCredential('ES256').coseKey });
    spoil(response);

    const result = await webauthn.finishRegistration('jane@acme.example', response, CHALLENGE);

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result.verified).toBe(false);
    expect(result.error).toContain(error);
    expect(store.getByCredentialId(response.id)).toBeUndefined();
  });
});
