/**
 * Assertion verification through the real `@simplewebauthn/server`.
 *
 * The other `verifyAssertion()` suites mock the library. Here each test signs
 * an authentication response with a real P-256 key, stores that key as the
 * COSE_Key registration would, and runs the response through
 * `verifyAssertion()`.
 *
 * What these pin is where the ceremony ran. `clientDataJSON` says so in
 * `crossOrigin` and, for a ceremony in a cross-origin frame such as the
 * browser-extension side panel, `topOrigin`. 14.x refuses a response with
 * `crossOrigin: true` and a `topOrigin` unless the caller passes
 * `expectedTopOrigin`; `TzunWebAuthn` passes `allowedTopOrigins` as that.
 */
import { randomBytes } from 'crypto';
import { CredentialStore } from '../../src/attestation/credential-store';
import { TzunWebAuthn, type WebAuthnConfig } from '../../src/attestation/webauthn';
import { authenticationResponse, makeCredential, ORIGIN, RP_ID } from './attestation-assertion-helpers';

/** The origin of the extension whose side panel frames the ceremony. */
const EXTENSION = 'chrome-extension://pfdlpfencoofghoglkocjbbhoogghfee';

const CHALLENGE = randomBytes(32).toString('base64url');

const TOP_LEVEL = { crossOrigin: false };
const IN_SIDE_PANEL = { crossOrigin: true, topOrigin: EXTENSION };

function setup(config: Partial<WebAuthnConfig> = {}) {
  const cred = makeCredential('ES256');
  const credentialId = randomBytes(16).toString('base64url');
  const store = new CredentialStore();
  store.register({
    credentialId,
    publicKey: cred.coseKey.toString('base64'),
    userId: 'jane@acme.example',
    algorithm: 'ES256',
    counter: 0,
    status: 'active',
    registeredAt: '2026-03-22T10:00:00.000Z',
  });
  const webauthn = new TzunWebAuthn({ rpID: RP_ID, rpName: 'Tzun Evidence', origin: ORIGIN, ...config }, store);
  const respond = (clientData: Record<string, unknown>) =>
    authenticationResponse(cred, { credentialId, challenge: CHALLENGE, clientData });
  const counter = () => store.getByCredentialId(credentialId)!.counter;
  return { webauthn, respond, counter, credentialId };
}

describe('verifyAssertion against the real @simplewebauthn/server: where the ceremony ran', () => {
  it('verifies an assertion from a top-level ceremony', async () => {
    const { webauthn, respond, counter, credentialId } = setup();

    const result = await webauthn.verifyAssertion(respond(TOP_LEVEL), { challenge: CHALLENGE });

    expect(result.error).toBeUndefined();
    expect(result.verified).toBe(true);
    expect(result.artifact).toMatchObject({ credentialKeyId: credentialId, algorithm: 'ES256' });
    expect(counter()).toBe(1);
  });

  it('verifies an assertion from a top-level ceremony when allowedTopOrigins lists only the extension', async () => {
    const { webauthn, respond } = setup({ allowedTopOrigins: [EXTENSION] });

    const result = await webauthn.verifyAssertion(respond(TOP_LEVEL), { challenge: CHALLENGE });

    expect(result.error).toBeUndefined();
    expect(result.verified).toBe(true);
  });

  it('verifies an assertion from a cross-origin frame whose topOrigin is in allowedTopOrigins', async () => {
    const { webauthn, respond, counter } = setup({ allowedTopOrigins: ['https://other.example', EXTENSION] });

    const result = await webauthn.verifyAssertion(respond(IN_SIDE_PANEL), { challenge: CHALLENGE });

    expect(result.error).toBeUndefined();
    expect(result.verified).toBe(true);
    expect(counter()).toBe(1);
  });

  it('refuses an assertion from a cross-origin frame that names its topOrigin when allowedTopOrigins is not set', async () => {
    const { webauthn, respond, counter } = setup();

    const result = await webauthn.verifyAssertion(respond(IN_SIDE_PANEL), { challenge: CHALLENGE });

    expect(result.verified).toBe(false);
    expect(result.error).toContain(
      `Detected cross-origin authentication response from top origin of "${EXTENSION}", ` +
        'but a value for `expectedTopOrigin` was not specified',
    );
    expect(counter()).toBe(0);
  });

  it('refuses an assertion from a cross-origin frame whose topOrigin is not in allowedTopOrigins', async () => {
    const { webauthn, respond, counter } = setup({ allowedTopOrigins: ['https://other.example'] });

    const result = await webauthn.verifyAssertion(respond(IN_SIDE_PANEL), { challenge: CHALLENGE });

    expect(result.verified).toBe(false);
    expect(result.error).toContain(`Unexpected cross-origin authentication response top origin of "${EXTENSION}"`);
    expect(counter()).toBe(0);
  });

  it('refuses every cross-origin frame that names its topOrigin when allowedTopOrigins is empty', async () => {
    const { webauthn, respond } = setup({ allowedTopOrigins: [] });

    const result = await webauthn.verifyAssertion(respond(IN_SIDE_PANEL), { challenge: CHALLENGE });

    expect(result.verified).toBe(false);
    expect(result.error).toContain(`Unexpected cross-origin authentication response top origin of "${EXTENSION}"`);
  });

  it('keeps its own copy of allowedTopOrigins: a later change to the caller\'s list changes nothing', async () => {
    const list = ['https://other.example'];
    const { webauthn, respond } = setup({ allowedTopOrigins: list });
    list.push(EXTENSION);

    const result = await webauthn.verifyAssertion(respond(IN_SIDE_PANEL), { challenge: CHALLENGE });

    expect(result.verified).toBe(false);
    expect(result.error).toContain(`Unexpected cross-origin authentication response top origin of "${EXTENSION}"`);
  });

  it('validates its copy, not the caller\'s array', () => {
    const list: unknown[] = [EXTENSION, 1];
    Object.defineProperty(list, 'every', { value: () => true });
    expect(
      () => new TzunWebAuthn({ rpID: RP_ID, origin: ORIGIN, allowedTopOrigins: list as string[] }),
    ).toThrow(new TypeError('WebAuthnConfig.allowedTopOrigins must be an array of origin strings'));
  });

  it.each([
    ['a bare string', EXTENSION],
    ['an array holding a non-string', [EXTENSION, 1]],
    ['null', null],
  ])('refuses allowedTopOrigins given as %s', (_name, value) => {
    expect(
      () => new TzunWebAuthn({ rpID: RP_ID, origin: ORIGIN, allowedTopOrigins: value as unknown as string[] }),
    ).toThrow(new TypeError('WebAuthnConfig.allowedTopOrigins must be an array of origin strings'));
  });

  // 14.0.3 checks the top origin only when the response names one: Safari
  // sends `crossOrigin: true` with no `topOrigin`. So allowedTopOrigins does
  // not refuse such a response; Tzun.verify() reports it as
  // `topOriginValid: false` / `top_origin_unknown` when given the same list.
  it('verifies an assertion from a cross-origin frame that names no topOrigin, set or not', async () => {
    for (const config of [{}, { allowedTopOrigins: [EXTENSION] }]) {
      const { webauthn, respond } = setup(config);

      const result = await webauthn.verifyAssertion(respond({ crossOrigin: true }), { challenge: CHALLENGE });

      expect(result.error).toBeUndefined();
      expect(result.verified).toBe(true);
    }
  });
});
