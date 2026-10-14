/**
 * Registration → CredentialStore → verifyAttestation, with the key in the
 * format a real authenticator produces.
 *
 * The other WebAuthn suites do not cover this path: `webauthn.test.ts` checks
 * what registration stores but never hands a stored key to the verifier, and
 * `verify-attestation.test.ts` registers an SPKI DER export directly. Neither
 * puts a COSE_Key — the thing `finishRegistration` actually persists — in
 * front of the verifier.
 *
 * `@simplewebauthn/server` is mocked here only for the ceremony verdict. The
 * key bytes, the signature, and the verification path are all genuine, which is
 * the whole point.
 */
import { createHash } from 'crypto';
import { CredentialStore } from '../../src/attestation/credential-store';
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import {
  makeCredential,
  signAssertionWith,
  encodeCoseKey,
  ORIGIN,
  registrationResponse,
  RP_ID,
} from './attestation-assertion-helpers';
import {
  decodeCoseKey,
  coseAlgorithmOf,
  importCredentialPublicKey,
  signatureAlgorithmOfKey,
} from '../../src/attestation/cose-key';

jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
}));

import {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { TzunWebAuthn } from '../../src/attestation/webauthn';

const mockVerifyReg = verifyRegistrationResponse as jest.MockedFunction<typeof verifyRegistrationResponse>;
const mockVerifyAuth = verifyAuthenticationResponse as jest.MockedFunction<typeof verifyAuthenticationResponse>;

const CHALLENGE = createHash('sha256').update('cose-regression', 'utf8').digest('base64url');
const DIGEST = createHash('sha256').update('cose-regression-record', 'utf8').digest('hex');

function config() {
  return { rpID: RP_ID, rpName: 'Tzun Evidence', origin: ORIGIN };
}

describe('COSE credential keys survive registration and verification', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('cose-key decoding', () => {
    it('reads the algorithm out of the key, which the browser-only probe cannot do on a server', () => {
      const es256 = makeCredential('ES256');
      const ed = makeCredential('Ed25519');

      expect(coseAlgorithmOf(es256.coseKey)).toBe(-7);
      expect(coseAlgorithmOf(ed.coseKey)).toBe(-8);

      const decoded = decodeCoseKey(es256.coseKey);
      expect(decoded?.kty).toBe(2);
      expect(decoded?.crv).toBe(1);
      expect(decoded?.x).toHaveLength(32);
      expect(decoded?.y).toHaveLength(32);
    });

    it('falls back to the curve when the authenticator omits the alg label', () => {
      const ed = makeCredential('Ed25519');
      const decoded = decodeCoseKey(ed.coseKey)!;
      // kty=OKP(1), crv=Ed25519(6), x — no label 3.
      const noAlg = encodeCoseKey([[1, 1], [-1, 6], [-2, decoded.x!]]);
      expect(decodeCoseKey(noAlg)?.alg).toBeUndefined();
      expect(coseAlgorithmOf(noAlg)).toBe(-8);
    });

    it('imports both encodings of the same key to the same public key', () => {
      const cred = makeCredential('ES256');
      const fromCose = importCredentialPublicKey(cred.coseKey)!;
      const fromSpki = importCredentialPublicKey(Buffer.from(cred.spkiBase64, 'base64'))!;
      expect(fromCose).toBeDefined();
      expect(fromSpki).toBeDefined();
      expect((fromCose.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64')).toBe(
        cred.spkiBase64,
      );
      expect(signatureAlgorithmOfKey(fromCose)).toBe('ES256');
      expect(signatureAlgorithmOfKey(importCredentialPublicKey(makeCredential('Ed25519').coseKey)!)).toBe(
        'Ed25519',
      );
    });

    it('returns undefined rather than throwing on bytes that are neither', () => {
      expect(importCredentialPublicKey(Buffer.from([1, 2, 3]))).toBeUndefined();
      expect(decodeCoseKey(Buffer.from([1, 2, 3]))).toBeUndefined();
    });
  });

  describe('finishRegistration', () => {
    it('records Ed25519 from the COSE key when the browser-only probe is absent', async () => {
      // `getPublicKeyAlgorithm` is undefined on a JSON response, so the label
      // has to come from the COSE key. An Ed25519 credential stored as ES256
      // would carry a label that is wrong for every signature it makes.
      const cred = makeCredential('Ed25519');
      const store = new CredentialStore();
      mockVerifyReg.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: { id: 'cred-ed', publicKey: new Uint8Array(cred.coseKey), counter: 0 },
        },
      } as any);

      const result = await new TzunWebAuthn(config(), store).finishRegistration(
        'jane@acme.example',
        registrationResponse({ coseKey: cred.coseKey }),
        CHALLENGE,
      );

      expect(result.verified).toBe(true);
      expect(store.getByCredentialId('cred-ed')?.algorithm).toBe('Ed25519');
    });

    it('records ES256 from the COSE key', async () => {
      const cred = makeCredential('ES256');
      const store = new CredentialStore();
      mockVerifyReg.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: { id: 'cred-ec', publicKey: new Uint8Array(cred.coseKey), counter: 0 },
        },
      } as any);

      await new TzunWebAuthn(config(), store).finishRegistration(
        'jane@acme.example',
        registrationResponse({ coseKey: cred.coseKey }),
        CHALLENGE,
      );

      expect(store.getByCredentialId('cred-ec')?.algorithm).toBe('ES256');
    });

    it('lets the key overrule a client-declared algorithm that disagrees with it', async () => {
      // A client that sends `publicKeyAlgorithm: -7` alongside an Ed25519 key
      // must not be able to mislabel the credential. The key is authoritative.
      const cred = makeCredential('Ed25519');
      const store = new CredentialStore();
      mockVerifyReg.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: { id: 'cred-lying', publicKey: new Uint8Array(cred.coseKey), counter: 0 },
        },
      } as any);

      const response = registrationResponse({ coseKey: cred.coseKey });
      response.response.publicKeyAlgorithm = -7;

      await new TzunWebAuthn(config(), store).finishRegistration('jane@acme.example', response, CHALLENGE);

      expect(store.getByCredentialId('cred-lying')?.algorithm).toBe('Ed25519');
    });
  });

  describe('registration → verifyAttestation, end to end', () => {
    it.each(['ES256', 'Ed25519'] as const)(
      'verifies a genuine %s assertion against the COSE key that registration stored',
      async (algorithm) => {
        // The stored key is CBOR, not SPKI DER. Reading it with
        // createPublicKey({format:'der',type:'spki'}) throws "Failed to read
        // asymmetric key", which the verifier would report as
        // `signatureValid: false`: honest evidence, rejected. The key has to
        // be decoded as a COSE_Key for a genuine assertion to verify.
        const cred = makeCredential(algorithm);
        const store = new CredentialStore();
        const credentialId = `cred-e2e-${algorithm}`;

        mockVerifyReg.mockResolvedValue({
          verified: true,
          registrationInfo: {
            credential: { id: credentialId, publicKey: new Uint8Array(cred.coseKey), counter: 0 },
          },
        } as any);

        const reg = await new TzunWebAuthn(config(), store).finishRegistration(
          'jane@acme.example',
          registrationResponse({ coseKey: cred.coseKey }),
          CHALLENGE,
        );
        expect(reg.verified).toBe(true);

        // Non-vacuity: the store really is holding CBOR, not SPKI.
        const stored = store.getByCredentialId(credentialId)!;
        expect(Buffer.from(stored.publicKey, 'base64')[0]).not.toBe(0x30);
        expect(decodeCoseKey(Buffer.from(stored.publicKey, 'base64'))).toBeDefined();
        expect(stored.algorithm).toBe(algorithm);

        const assertion = signAssertionWith(cred, algorithm, {
          challenge: DIGEST,
          credentialId,
        });

        const result = await verifyAttestation({ webauthnAssertion: assertion }, DIGEST, store, {
          expectedChallenge: DIGEST,
          allowedOrigins: [ORIGIN],
          rpId: RP_ID,
        });

        expect(result.signatureReason).toBeUndefined();
        expect(result.signatureValid).toBe(true);
      },
    );

    it('still rejects a tampered signature over a COSE-stored key', async () => {
      // Decoding the COSE key must not turn the verifier into a rubber stamp:
      // the same COSE path with a corrupted signature has to stay false.
      const cred = makeCredential('ES256');
      const store = new CredentialStore();
      store.register({
        credentialId: 'cred-tamper-cose',
        publicKey: cred.coseKey.toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });

      const good = signAssertionWith(cred, 'ES256', {
        challenge: DIGEST,
        credentialId: 'cred-tamper-cose',
      });
      const sigBytes = Buffer.from(good.signature, 'base64');
      sigBytes[sigBytes.length - 1] ^= 0xff;

      const result = await verifyAttestation(
        { webauthnAssertion: { ...good, signature: sigBytes.toString('base64') } },
        DIGEST,
        store,
        { expectedChallenge: DIGEST, allowedOrigins: [ORIGIN], rpId: RP_ID },
      );

      expect(result.signatureValid).toBe(false);
      expect(result.signatureReason).toBe('invalid_signature');
    });

    it('rejects a genuine assertion checked against a different credential of the same type', async () => {
      const signing = makeCredential('ES256');
      const other = makeCredential('ES256');
      const store = new CredentialStore();
      store.register({
        credentialId: 'cred-wrong-key',
        publicKey: other.coseKey.toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });

      const assertion = signAssertionWith(signing, 'ES256', {
        challenge: DIGEST,
        credentialId: 'cred-wrong-key',
      });

      const result = await verifyAttestation({ webauthnAssertion: assertion }, DIGEST, store, {
        expectedChallenge: DIGEST,
        allowedOrigins: [ORIGIN],
        rpId: RP_ID,
      });

      expect(result.signatureValid).toBe(false);
      expect(result.signatureReason).toBe('invalid_signature');
    });
  });

  describe('credentials an earlier release registered with the wrong algorithm label', () => {
    it('verifies an Ed25519 credential that the store records as ES256', async () => {
      // Credentials an earlier release registered all carry `algorithm: 'ES256'`,
      // whatever their key type. Trusting that label routes an Ed25519
      // signature through createVerify('SHA256'), which never validates. The
      // key settles it.
      const cred = makeCredential('Ed25519');
      const store = new CredentialStore();
      store.register({
        credentialId: 'cred-legacy',
        publicKey: cred.coseKey.toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256', // the mislabel
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });

      const assertion = signAssertionWith(cred, 'Ed25519', {
        challenge: DIGEST,
        credentialId: 'cred-legacy',
      });

      const result = await verifyAttestation({ webauthnAssertion: assertion }, DIGEST, store, {
        expectedChallenge: DIGEST,
        allowedOrigins: [ORIGIN],
        rpId: RP_ID,
      });

      expect(result.signatureValid).toBe(true);
    });

    it('labels the assertion artifact from the key, not from the stored label', async () => {
      const cred = makeCredential('Ed25519');
      const store = new CredentialStore();
      store.register({
        credentialId: 'cred-artifact-label',
        publicKey: cred.coseKey.toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256', // the mislabel
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });

      mockVerifyAuth.mockResolvedValue({
        verified: true,
        authenticationInfo: { newCounter: 1 },
      } as any);

      const signed = signAssertionWith(cred, 'Ed25519', {
        challenge: DIGEST,
        credentialId: 'cred-artifact-label',
      });

      const res = await new TzunWebAuthn(config(), store).verifyAssertion(
        {
          id: 'cred-artifact-label',
          response: {
            signature: signed.signature,
            authenticatorData: signed.authenticatorData,
            clientDataJSON: signed.clientDataJSON,
          },
        },
        DIGEST,
      );

      expect(res.verified).toBe(true);
      expect(res.artifact?.algorithm).toBe('Ed25519');
    });
  });
});
