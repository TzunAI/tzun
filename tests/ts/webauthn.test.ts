import {
  TzunWebAuthn,
  WebAuthnConfig,
  RegistrationResult,
  AssertionResult,
} from '../../src/attestation/webauthn';
import { CredentialStore } from '../../src/attestation/credential-store';
import { webauthnChallengeForDigest } from '../../src/attestation/verify-attestation';
import { decodeAttestationObject, isoBase64URL } from '@simplewebauthn/server/helpers';
import {
  encodeCoseKey,
  makeCredential,
  registrationResponse,
  type Cbor,
} from './attestation-assertion-helpers';

// Mock @simplewebauthn/server
jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
}));

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const mockGenRegOpts = generateRegistrationOptions as jest.MockedFunction<typeof generateRegistrationOptions>;
const mockVerifyReg = verifyRegistrationResponse as jest.MockedFunction<typeof verifyRegistrationResponse>;
const mockGenAuthOpts = generateAuthenticationOptions as jest.MockedFunction<typeof generateAuthenticationOptions>;
const mockVerifyAuth = verifyAuthenticationResponse as jest.MockedFunction<typeof verifyAuthenticationResponse>;

/**
 * A registration response that also claims algorithm `alg`, both ways a client
 * can: the serialisable `publicKeyAlgorithm` field and the browser's
 * `getPublicKeyAlgorithm()` method.
 */
function withAlgorithmClaims(response: any, alg: number): any {
  response.response.publicKeyAlgorithm = alg;
  response.response.getPublicKeyAlgorithm = () => alg;
  return response;
}

describe('TzunWebAuthn', () => {
  let webauthn: TzunWebAuthn;
  let credStore: CredentialStore;

  const config: WebAuthnConfig = {
    rpID: 'tzun.ai',
    rpName: 'Tzun Evidence',
    origin: 'https://tzun.ai',
  };

  beforeEach(() => {
    credStore = new CredentialStore();
    webauthn = new TzunWebAuthn(config, credStore);
    jest.clearAllMocks();
  });

  describe('generateRegistrationOptions', () => {
    it('generates registration options with correct RP info', async () => {
      mockGenRegOpts.mockResolvedValue({
        challenge: 'test-challenge',
        rp: { name: 'Tzun Evidence', id: 'tzun.ai' },
        user: { id: 'user-id', name: 'jane@acme.example', displayName: 'Jane' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      } as any);

      const options = await webauthn.startRegistration('jane@acme.example', 'Jane');

      expect(mockGenRegOpts).toHaveBeenCalledWith(
        expect.objectContaining({
          rpName: 'Tzun Evidence',
          rpID: 'tzun.ai',
          userName: 'jane@acme.example',
          userDisplayName: 'Jane',
        })
      );
      expect(options.challenge).toBe('test-challenge');
    });

    it('requests Ed25519 and ES256 algorithms', async () => {
      mockGenRegOpts.mockResolvedValue({ challenge: 'c' } as any);

      await webauthn.startRegistration('user', 'User');

      expect(mockGenRegOpts).toHaveBeenCalledWith(
        expect.objectContaining({
          supportedAlgorithmIDs: [-8, -7], // Ed25519, ES256
        })
      );
    });

    it('asks for attestation "none"', async () => {
      mockGenRegOpts.mockResolvedValue({ challenge: 'c' } as any);

      await webauthn.startRegistration('user', 'User');

      expect(mockGenRegOpts).toHaveBeenCalledWith(expect.objectContaining({ attestationType: 'none' }));
    });
  });

  describe('startAuthentication', () => {
    it('generates authentication options for a registered credential', async () => {
      // Register a credential first
      credStore.register({
        credentialId: 'cred-auth-test',
        publicKey: Buffer.from([1, 2, 3]).toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });

      mockGenAuthOpts.mockResolvedValue({
        challenge: 'auth-challenge-123',
        rpId: 'tzun.ai',
        allowCredentials: [{ id: 'cred-auth-test', type: 'public-key' }],
        userVerification: 'preferred',
      } as any);

      // The ceremony has to say what it is FOR: the challenge is a function of
      // the record's digest. Passing back whatever nonce the library invented
      // would produce a signature that verifies against every evidence record
      // equally, which is the same as verifying against none.
      const digest = 'a'.repeat(64);
      const options = await webauthn.startAuthentication('cred-auth-test', { digest });

      expect(mockGenAuthOpts).toHaveBeenCalledWith(
        expect.objectContaining({
          rpID: 'tzun.ai',
          allowCredentials: expect.arrayContaining([
            expect.objectContaining({
              id: 'cred-auth-test',
            }),
          ]),
        })
      );
      // The library's own nonce does not survive: the returned options carry
      // the digest-derived challenge, so the browser signs the decision.
      expect(options.challenge).toBe(webauthnChallengeForDigest(digest));
      expect(options.challenge).not.toBe('auth-challenge-123');
    });

    it('refuses a ceremony that states no purpose', async () => {
      credStore.register({
        credentialId: 'cred-auth-test',
        publicKey: Buffer.from([1, 2, 3]).toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });
      // A binding that names neither a digest nor an explicit challenge is not
      // a ceremony about anything, and inventing a nonce for it would produce
      // unbound evidence.
      await expect(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (webauthn as any).startAuthentication('cred-auth-test', {}),
      ).rejects.toThrow(/digest|challenge/i);
    });

    it('carries an explicit challenge through for a ceremony about no record', async () => {
      credStore.register({
        credentialId: 'cred-auth-test',
        publicKey: Buffer.from([1, 2, 3]).toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });
      mockGenAuthOpts.mockResolvedValue({ challenge: 'library-nonce' } as any);
      // The login-gate case, spelled out rather than defaulted. An assertion
      // from here binds no record and verifies `assertion_not_bound_to_digest`
      // forever — which is the honest outcome, and here a deliberate one.
      const options = await webauthn.startAuthentication('cred-auth-test', {
        challenge: 'a-login-nonce-the-caller-owns',
      });
      expect(options.challenge).toBe('a-login-nonce-the-caller-owns');
    });

    it('throws for unknown credential ID', async () => {
      await expect(
        webauthn.startAuthentication('nonexistent-cred', { digest: 'a'.repeat(64) })
      ).rejects.toThrow(/not found/);
    });

    it('throws for revoked credential', async () => {
      credStore.register({
        credentialId: 'cred-revoked-auth',
        publicKey: Buffer.from([1, 2, 3]).toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });
      credStore.revoke('cred-revoked-auth');

      await expect(
        webauthn.startAuthentication('cred-revoked-auth', { digest: 'a'.repeat(64) })
      ).rejects.toThrow(/revoked/);
    });
  });

  describe('verifyRegistration', () => {
    it('stores credential on successful verification', async () => {
      const cred = makeCredential('ES256');
      mockVerifyReg.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'cred-123',
            publicKey: new Uint8Array(cred.coseKey),
            counter: 0,
          },
          credentialType: 'public-key',
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      } as any);

      const result = await webauthn.finishRegistration(
        'jane@acme.example',
        registrationResponse({ coseKey: cred.coseKey }),
        'expected-challenge'
      );

      expect(result.verified).toBe(true);
      expect(result.credentialId).toBe('cred-123');
      const stored = credStore.getByCredentialId('cred-123');
      expect(stored).toBeDefined();
      expect(stored?.userId).toBe('jane@acme.example');
    });

    it('does not store credential on failed verification', async () => {
      mockVerifyReg.mockResolvedValue({
        verified: false,
      } as any);

      const result = await webauthn.finishRegistration(
        'jane@acme.example',
        registrationResponse({ coseKey: makeCredential('ES256').coseKey }),
        'expected-challenge'
      );

      expect(result.verified).toBe(false);
      expect(credStore.getByCredentialId('cred-123')).toBeUndefined();
    });

    // Left to its default, `verifyRegistrationResponse()` accepts algorithms
    // the options never offered: RS256 always, and ML-DSA-44 on a runtime
    // with post-quantum support. The verifier has to be handed the offered
    // list.
    it('verifies with exactly the algorithms the registration options offered', async () => {
      mockGenRegOpts.mockResolvedValue({ challenge: 'c' } as any);
      mockVerifyReg.mockResolvedValue({ verified: false } as any);

      await webauthn.startRegistration('jane@acme.example', 'Jane');
      await webauthn.finishRegistration(
        'jane@acme.example',
        registrationResponse({ coseKey: makeCredential('ES256').coseKey }),
        'c'
      );

      const offered = mockGenRegOpts.mock.calls[0][0].supportedAlgorithmIDs;
      const enforced = mockVerifyReg.mock.calls[0][0].supportedAlgorithmIDs;
      expect(enforced).toEqual([-8, -7]);
      expect(enforced).toEqual(offered);
    });

    // The SDK's own check, for when a verifier lets such a key through. The
    // label mapping knows -8 and -7 only and would otherwise file the
    // credential as ES256, a label wrong for every signature it makes.
    it.each([
      ['RS256', encodeCoseKey([[1, 3], [3, -257], [-1, Buffer.alloc(256, 0xab)], [-2, Buffer.from([1, 0, 1])]])],
      ['ML-DSA-44', encodeCoseKey([[1, 7], [3, -48], [-1, Buffer.alloc(1312, 0xab)]])],
    ])('refuses an %s credential instead of storing it under an ES256 label', async (_name, coseKey) => {
      mockVerifyReg.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: { id: 'cred-other-alg', publicKey: new Uint8Array(coseKey), counter: 0 },
          credentialType: 'public-key',
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      } as any);

      const result = await webauthn.finishRegistration(
        'jane@acme.example',
        registrationResponse({ coseKey }),
        'expected-challenge'
      );

      expect(result.verified).toBe(false);
      expect(result.error).toMatch(/not offered/);
      expect(credStore.getByCredentialId('cred-other-alg')).toBeUndefined();
    });

    // `getPublicKeyAlgorithm` is a method on the browser's
    // AuthenticatorAttestationResponse and does not survive JSON.stringify, so
    // on a real server it is always undefined; registration that relied on it
    // would record every credential — Ed25519 included — as ES256. The
    // algorithm comes from the COSE key itself, so these fixtures carry a real
    // COSE key and the browser-only probe is either absent or made to disagree
    // with it.
    it('stores ES256 for a COSE key that declares alg -7, with no browser probe present', async () => {
      const cred = makeCredential('ES256');
      mockVerifyReg.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'cred-es256',
            publicKey: new Uint8Array(cred.coseKey),
            counter: 0,
          },
          credentialType: 'public-key',
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      } as any);

      const result = await webauthn.finishRegistration(
        'jane@acme.example',
        registrationResponse({ coseKey: cred.coseKey }),
        'expected-challenge'
      );

      expect(result.verified).toBe(true);
      const stored = credStore.getByCredentialId('cred-es256');
      expect(stored?.algorithm).toBe('ES256');
    });

    it('stores Ed25519 for a COSE key that declares alg -8, even when the browser probe says otherwise', async () => {
      const cred = makeCredential('Ed25519');
      mockVerifyReg.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'cred-ed25519',
            publicKey: new Uint8Array(cred.coseKey),
            counter: 0,
          },
          credentialType: 'public-key',
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      } as any);

      const result = await webauthn.finishRegistration(
        'jane@acme.example',
        // The probe lies. The key is authoritative.
        withAlgorithmClaims(registrationResponse({ coseKey: cred.coseKey }), -7),
        'expected-challenge'
      );

      expect(result.verified).toBe(true);
      const stored = credStore.getByCredentialId('cred-ed25519');
      expect(stored?.algorithm).toBe('Ed25519');
      // And the stored bytes are the authenticator's COSE key, not SPKI DER.
      expect(Buffer.from(stored!.publicKey, 'base64')[0]).not.toBe(0x30);
    });

    // Without an algorithm read from the key, the label would be a guess. The
    // client's claims are not read, so they cannot supply one.
    it('refuses a key that states no readable algorithm, whatever the client claims', async () => {
      mockVerifyReg.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: { id: 'cred-no-alg', publicKey: new Uint8Array([1, 2, 3]), counter: 0 },
          credentialType: 'public-key',
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      } as any);

      const result = await webauthn.finishRegistration(
        'jane@acme.example',
        withAlgorithmClaims(registrationResponse({ coseKey: makeCredential('ES256').coseKey }), -7),
        'expected-challenge'
      );

      expect(result.verified).toBe(false);
      expect(result.error).toMatch(/no readable algorithm/);
      expect(credStore.getByCredentialId('cred-no-alg')).toBeUndefined();
    });

    it('hands the verifier attestation "none" with the client\'s authenticator data', async () => {
      mockVerifyReg.mockResolvedValue({ verified: false } as any);
      const response = registrationResponse({
        coseKey: makeCredential('ES256').coseKey,
        fmt: 'android-key',
        attStmt: new Map<Cbor, Cbor>([
          ['alg', -7],
          ['sig', Buffer.alloc(70)],
          ['x5c', [Buffer.from('not a certificate')]],
        ]),
      });
      const sent = decodeAttestationObject(isoBase64URL.toBuffer(response.response.attestationObject));

      await webauthn.finishRegistration('jane@acme.example', response, 'expected-challenge');

      const verified = mockVerifyReg.mock.calls[0][0].response;
      const handed = decodeAttestationObject(isoBase64URL.toBuffer(verified.response.attestationObject));
      expect(handed.get('fmt')).toBe('none');
      expect(handed.get('attStmt').size).toBe(0);
      expect(Buffer.from(handed.get('authData')).equals(Buffer.from(sent.get('authData')))).toBe(true);
      // Everything else in the response reaches the verifier as sent.
      expect({ ...verified, response: { ...verified.response, attestationObject: undefined } }).toEqual({
        ...response,
        response: { ...response.response, attestationObject: undefined },
      });
    });
  });

  describe('verifyAssertion', () => {
    it('returns attestation artifact on successful assertion', async () => {
      credStore.register({
        credentialId: 'cred-123',
        publicKey: Buffer.from([1, 2, 3]).toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });

      mockVerifyAuth.mockResolvedValue({
        verified: true,
        authenticationInfo: {
          newCounter: 1,
          credentialID: 'cred-123',
        },
      } as any);

      const result = await webauthn.verifyAssertion(
        { id: 'cred-123', response: { signature: 'sig-data' } } as any,
        'expected-challenge'
      );

      expect(result.verified).toBe(true);
      expect(result.artifact).toBeDefined();
      expect(result.artifact?.credentialKeyId).toBe('cred-123');
      expect(result.artifact?.algorithm).toBe('ES256');
      expect(result.artifact?.signature).toBe('sig-data');
    });

    it('rejects assertion for revoked credential', async () => {
      credStore.register({
        credentialId: 'cred-revoked',
        publicKey: Buffer.from([1, 2, 3]).toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });
      credStore.revoke('cred-revoked');

      const result = await webauthn.verifyAssertion(
        { id: 'cred-revoked', response: { signature: 'sig' } } as any,
        'challenge'
      );

      expect(result.verified).toBe(false);
      expect(result.error).toMatch(/revoked/);
    });

    it('rejects assertion for unknown credential', async () => {
      const result = await webauthn.verifyAssertion(
        { id: 'unknown-cred', response: { signature: 'sig' } } as any,
        'challenge'
      );

      expect(result.verified).toBe(false);
      expect(result.error).toMatch(/not found/);
    });

    it('updates credential counter on successful assertion', async () => {
      credStore.register({
        credentialId: 'cred-123',
        publicKey: Buffer.from([1, 2, 3]).toString('base64'),
        userId: 'jane@acme.example',
        algorithm: 'ES256',
        counter: 0,
        status: 'active',
        registeredAt: '2026-03-22T10:00:00.000Z',
      });

      mockVerifyAuth.mockResolvedValue({
        verified: true,
        authenticationInfo: {
          newCounter: 5,
          credentialID: 'cred-123',
        },
      } as any);

      await webauthn.verifyAssertion(
        { id: 'cred-123', response: { signature: 'sig' } } as any,
        'challenge'
      );

      const stored = credStore.getByCredentialId('cred-123');
      expect(stored?.counter).toBe(5);
    });
  });
});
