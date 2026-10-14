import { TzunWebAuthn } from '../../src/attestation/webauthn';
import { CredentialStore } from '../../src/attestation/credential-store';

// Mock @simplewebauthn/server
jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn().mockResolvedValue({
    verified: true,
    authenticationInfo: {
      newCounter: 1,
    },
  }),
}));

describe('TzunWebAuthn enhanced assertion artifacts', () => {
  let webauthn: TzunWebAuthn;
  let credStore: CredentialStore;

  beforeEach(() => {
    credStore = new CredentialStore();
    credStore.register({
      credentialId: 'cred-enhanced-test',
      publicKey: 'test-key',
      userId: 'user@example.com',
      algorithm: 'ES256',
      counter: 0,
      status: 'active',
      registeredAt: new Date().toISOString(),
    });

    webauthn = new TzunWebAuthn(
      { rpID: 'localhost', rpName: 'Test', origin: 'http://localhost' },
      credStore,
    );
  });

  it('includes authenticatorData and clientDataJSON in assertion artifact', async () => {
    const mockAuthenticatorData = Buffer.from('mock-auth-data-32-bytes!--------').toString('base64');
    const mockClientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get',
      challenge: 'test-challenge',
      origin: 'http://localhost',
    })).toString('base64');

    const assertionResponse = {
      id: 'cred-enhanced-test',
      rawId: 'cred-enhanced-test',
      response: {
        authenticatorData: mockAuthenticatorData,
        clientDataJSON: mockClientDataJSON,
        signature: 'mock-signature-base64',
      },
      type: 'public-key',
    };

    const result = await webauthn.verifyAssertion(assertionResponse, 'test-challenge');

    expect(result.verified).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.authenticatorData).toBe(mockAuthenticatorData);
    expect(result.artifact!.clientDataJSON).toBe(mockClientDataJSON);
    expect(result.artifact!.signature).toBe('mock-signature-base64');
    expect(result.artifact!.credentialKeyId).toBe('cred-enhanced-test');
    expect(result.artifact!.algorithm).toBe('ES256');
  });

  it('handles missing authenticatorData/clientDataJSON gracefully', async () => {
    const assertionResponse = {
      id: 'cred-enhanced-test',
      rawId: 'cred-enhanced-test',
      response: {
        signature: 'mock-signature-base64',
        // No authenticatorData or clientDataJSON
      },
      type: 'public-key',
    };

    const result = await webauthn.verifyAssertion(assertionResponse, 'test-challenge');

    expect(result.verified).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.authenticatorData).toBeUndefined();
    expect(result.artifact!.clientDataJSON).toBeUndefined();
  });
});
