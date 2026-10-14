import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type VerifyRegistrationResponseOpts,
  type GenerateAuthenticationOptionsOpts,
  type VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import { decodeAttestationObject, isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers';
import { CredentialStore } from './credential-store';
import {
  COSE_ALG_EDDSA,
  COSE_ALG_ES256,
  coseAlgorithmOf,
  importCredentialPublicKey,
  signatureAlgorithmOfKey,
} from './cose-key';
import { webauthnChallengeForDigest } from './verify-attestation';
import type { AttestationArtifacts } from '@tzun/engine';

/**
 * The COSE algorithms a Tzun credential may use, most preferred first: Ed25519
 * (-8), then ES256 (-7). These are the two algorithms Tzun can label and
 * verify.
 *
 * Registration offers this list and registration verification enforces it.
 * Without the list, `verifyRegistrationResponse()` accepts its own default
 * set, which includes RS256 and, on runtimes with post-quantum support,
 * ML-DSA-44. Tzun would store such a credential under a label that matches
 * none of its signatures.
 */
const REGISTRATION_ALGORITHM_IDS: readonly number[] = [COSE_ALG_EDDSA, COSE_ALG_ES256];

/** A value `isoCBOR.encode()` accepts. */
type CborValue = Parameters<typeof isoCBOR.encode>[0];

/**
 * A copy of a registration response whose attestation object holds format
 * "none", an empty attestation statement, and the client's authenticator data
 * unchanged. Throws when the response carries no attestation object with
 * authenticator data in it.
 *
 * Tzun does not use attestation. It registers the credential key from the
 * authenticator data and stores nothing from the attestation statement. But
 * verifying a statement is the part of `verifyRegistrationResponse()` that
 * can reach the network: the library checks the revocation of attestation
 * certificates by fetching the CRL URLs they name. For "android-key" it
 * validates the `x5c` chain against the chain's own last certificate, and
 * only then checks that this root is a known Google root, so the CRL URL of a
 * certificate the client made up is fetched. With the statement replaced, the
 * library takes its "none" path, which reads no certificate and fetches
 * nothing, whatever the client sent.
 *
 * The rebuilt response is accepted exactly when the same authenticator data
 * sent with format "none" would be, and a client can send "none" for any
 * authenticator data, so the replacement accepts nothing new. It is also what
 * a WebAuthn client may do itself when the relying party asks for attestation
 * "none", as `startRegistration()` does. An authenticator whose client returns
 * a real attestation anyway still registers.
 *
 * Only the authenticator data is taken from the client's object, read with the
 * library's own decoder. The library then decodes the object built here, so
 * the format and statement it acts on are never the client's.
 */
function withNoneAttestation(response: any): any {
  const encoded: unknown = response?.response?.attestationObject;
  if (typeof encoded !== 'string') {
    throw new Error('Registration response has no attestationObject');
  }
  const decoded: unknown = decodeAttestationObject(isoBase64URL.toBuffer(encoded));
  const authData = decoded instanceof Map ? decoded.get('authData') : undefined;
  if (!(authData instanceof Uint8Array)) {
    throw new Error('Registration response attestationObject has no authData');
  }
  const attestationObject = isoCBOR.encode(
    new Map<string, CborValue>([
      ['fmt', 'none'],
      ['attStmt', new Map<string, CborValue>()],
      ['authData', authData],
    ]),
  );
  return {
    ...response,
    response: { ...response.response, attestationObject: isoBase64URL.fromBuffer(attestationObject) },
  };
}

export interface WebAuthnConfig {
  rpID: string;
  rpName: string;
  origin: string;
  /**
   * Top-level origins an assertion's ceremony may have run under, for a
   * ceremony in a cross-origin frame — for the browser-extension side panel,
   * the extension's own origins. `verifyAssertion()` passes the list to the
   * library as `expectedTopOrigin`.
   *
   * Enforced only for an assertion whose `clientDataJSON` states
   * `crossOrigin: true` and names a `topOrigin`: it verifies only if that
   * `topOrigin` is listed, and unset or `[]`, it is refused (@simplewebauthn/
   * server 14 refuses such a response unless the caller names the top origins
   * it expects). No other assertion is affected: one that names no
   * `topOrigin` (a ceremony run directly in a tab, one that does not state
   * `crossOrigin`, or a cross-origin frame in Safari) verifies whether or not
   * its top-level origin is listed, and one that names a `topOrigin` without
   * `crossOrigin: true` is always refused. Entries are serialized origins
   * (`chrome-extension://<id>`, no trailing slash), compared exactly.
   *
   * `allowedTopOrigins` in `AttestationVerifyOptions` and
   * `VerifySignatureOptions` takes the same list but checks every assertion,
   * reporting `top_origin_unknown` or `top_origin_not_allowed` in
   * `assertionProvenance.topOriginValid`; a passing `verifyAssertion()` does
   * not establish that. Anything other than an array of strings is a
   * `TypeError`.
   */
  allowedTopOrigins?: string[];
}

export interface RegistrationResult {
  verified: boolean;
  credentialId?: string;
  error?: string;
}

export interface AssertionResult {
  verified: boolean;
  artifact?: AttestationArtifacts['webauthnAssertion'];
  error?: string;
}

/**
 * What an authentication ceremony is FOR, and why its binding is mandatory.
 *
 * `{ digest }` is the form that produces evidence: the challenge becomes
 * `webauthnChallengeForDigest(digest)`, so the reviewer's authenticator signs
 * the decision record itself and the resulting assertion verifies against that
 * record and no other. Obtain the digest from
 * `Tzun.prepareAssertionChallenge()` — the record has to be built before its
 * digest exists, so the ordering is build → derive → ceremony → attach.
 *
 * `{ challenge }` is the escape hatch for a ceremony that is genuinely NOT
 * about a record — a login gate, say. It is spelled out rather than defaulted
 * because a defaulted random nonce from `generateAuthenticationOptions` yields
 * signatures over login nonces, which then get stored and labelled
 * non-repudiation. An
 * assertion from this form binds no record and verifies as
 * `assertion_not_bound_to_digest` forever.
 */
export type AssertionBinding = { digest: string } | { challenge: string };

/**
 * Resolve an {@link AssertionBinding} to the challenge string the ceremony
 * must present. Throws rather than inventing a nonce: a ceremony with no
 * stated purpose is the bug.
 */
export function challengeForBinding(binding: AssertionBinding | string): string {
  if (typeof binding === 'string') return binding;
  if ('digest' in binding && binding.digest) return webauthnChallengeForDigest(binding.digest);
  if ('challenge' in binding && binding.challenge) return binding.challenge;
  throw new Error(
    '[Tzun] A WebAuthn ceremony needs a binding: pass { digest } to bind the ' +
      'assertion to an evidence record (Tzun.prepareAssertionChallenge() supplies ' +
      'the digest), or { challenge } for a ceremony that is deliberately about no ' +
      'record. A random challenge would produce a signature that verifies against ' +
      'every record equally — see verify-attestation.ts assertion_not_bound_to_digest.',
  );
}

/**
 * WebAuthn server wrapper for Tzun evidence signing.
 *
 * Wraps @simplewebauthn/server to produce AttestationArtifacts.webauthnAssertion
 * objects that the Evidence Engine consumes for non-repudiation.
 *
 * Defaults:
 * - rpID: 'tzun.ai'
 * - rpName: 'Tzun Evidence'
 * - Preferred algorithm: Ed25519 (-8), fallback: ES256 (-7)
 */
export class TzunWebAuthn {
  private config: WebAuthnConfig;
  private credentialStore: CredentialStore;

  constructor(config: Partial<WebAuthnConfig> & { origin?: string } = {}, credentialStore?: CredentialStore) {
    // Copied first, so the caller can neither change the list later nor
    // override a method of its own array to pass validation.
    const given: unknown = config.allowedTopOrigins;
    const topOrigins = given === undefined ? undefined : Array.isArray(given) ? Array.from(given) : given;
    if (
      topOrigins !== undefined &&
      !(Array.isArray(topOrigins) && topOrigins.every((o) => typeof o === 'string'))
    ) {
      // A bare string would be spread into its characters.
      throw new TypeError('WebAuthnConfig.allowedTopOrigins must be an array of origin strings');
    }
    this.config = {
      rpID: config.rpID || 'tzun.ai',
      rpName: config.rpName || 'Tzun Evidence',
      origin: config.origin || 'https://tzun.ai',
      ...(topOrigins !== undefined && { allowedTopOrigins: topOrigins as string[] }),
    };
    this.credentialStore = credentialStore || new CredentialStore();
  }

  /**
   * Start the registration ceremony — generate options for the client.
   */
  async startRegistration(userName: string, userDisplayName: string): Promise<any> {
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpID,
      userName,
      userDisplayName,
      supportedAlgorithmIDs: [...REGISTRATION_ALGORITHM_IDS],
      // Tzun uses no attestation; finishRegistration() replaces any statement
      // the client returns with "none" (see withNoneAttestation).
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    } as GenerateRegistrationOptionsOpts);

    return options;
  }

  /**
   * Finish the registration ceremony — verify the response and store the credential.
   *
   * The response is verified as attestation format "none": any attestation
   * statement the client sent is discarded unread (see withNoneAttestation).
   */
  async finishRegistration(
    userId: string,
    response: any,
    expectedChallenge: string
  ): Promise<RegistrationResult> {
    try {
      const verification = await verifyRegistrationResponse({
        response: withNoneAttestation(response),
        expectedChallenge,
        expectedOrigin: this.config.origin,
        expectedRPID: this.config.rpID,
        // The same list the options offered, so a credential of any other
        // algorithm is refused here rather than stored.
        supportedAlgorithmIDs: [...REGISTRATION_ALGORITHM_IDS],
      } as VerifyRegistrationResponseOpts);

      if (!verification.verified || !verification.registrationInfo) {
        return { verified: false, error: 'Registration verification failed' };
      }

      const { credential } = verification.registrationInfo;

      // The label comes from the credential key alone: `credential.publicKey`
      // is the COSE_Key from the authenticator data, which states its own
      // algorithm (label 3; -8 = Ed25519, -7 = ES256). The response's
      // `publicKeyAlgorithm` field and the browser's `getPublicKeyAlgorithm()`
      // are the client's word, not the key's, and are not read. A key whose
      // algorithm cannot be read, or was not offered, is refused rather than
      // stored: a label that does not match the key is wrong for every
      // signature the credential makes.
      const alg = coseAlgorithmOf(credential.publicKey);
      if (alg === undefined) {
        return { verified: false, error: 'Credential public key states no readable algorithm' };
      }
      if (!REGISTRATION_ALGORITHM_IDS.includes(alg)) {
        return {
          verified: false,
          error:
            `Credential public key algorithm ${alg} was not offered at registration ` +
            `(offered: ${REGISTRATION_ALGORITHM_IDS.join(', ')})`,
        };
      }
      const algorithm: 'Ed25519' | 'ES256' = alg === COSE_ALG_EDDSA ? 'Ed25519' : 'ES256';

      const publicKeyBase64 = Buffer.from(credential.publicKey).toString('base64');

      this.credentialStore.register({
        credentialId: credential.id,
        publicKey: publicKeyBase64,
        userId,
        algorithm,
        counter: credential.counter,
        status: 'active',
        registeredAt: new Date().toISOString(),
      });

      return {
        verified: true,
        credentialId: credential.id,
      };
    } catch (err) {
      return {
        verified: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Start the authentication ceremony — generate options for the client.
   *
   * Looks up the credential in the store to provide as an allowed credential,
   * then calls generateAuthenticationOptions from @simplewebauthn/server with
   * the challenge `binding` resolves to.
   *
   * **The `binding` argument is why this method exists in this shape.** With
   * no challenge of its own, `generateAuthenticationOptions` mints a random
   * nonce, and the reviewer's authenticator signs a login rather than a
   * decision. Such an assertion verifies identically against every record ever
   * captured, which is the same as verifying against none: `verifyAttestation`
   * reports it `assertion_not_bound_to_digest`.
   *
   * Ordering, because the digest does not exist until the record does:
   *
   *   1. `const prepared = await tzun.prepareAssertionChallenge(input)`
   *   2. `const options = await webauthn.startAuthentication(id, { digest: prepared.digest })`
   *   3. the browser signs `options.challenge`
   *   4. `await tzun.capture({ ...input, attestationInputs: { webauthnAssertion } }, { prepared })`
   *
   * @param credentialId - The credential ID to authenticate with
   * @param binding - `{ digest }` to bind the ceremony to an evidence record,
   *        or `{ challenge }` for a ceremony deliberately about no record.
   * @returns Authentication options to pass to navigator.credentials.get()
   * @throws Error if the credential is not found, is revoked, or `binding`
   *         states neither a digest nor a challenge.
   */
  async startAuthentication(credentialId: string, binding: AssertionBinding): Promise<any> {
    const stored = this.credentialStore.getByCredentialId(credentialId);
    if (!stored) {
      throw new Error(`Credential "${credentialId}" not found.`);
    }
    if (stored.status === 'revoked') {
      throw new Error(`Credential "${credentialId}" has been revoked.`);
    }

    // Resolved BEFORE the ceremony options are generated, so a binding that
    // states nothing fails here rather than silently becoming a nonce.
    const challenge = challengeForBinding(binding);

    const options = await generateAuthenticationOptions({
      rpID: this.config.rpID,
      allowCredentials: [
        {
          id: stored.credentialId,
        },
      ],
      userVerification: 'preferred',
      challenge: Buffer.from(challenge, 'base64url'),
    } as GenerateAuthenticationOptionsOpts);

    // `generateAuthenticationOptions` re-encodes the challenge it was handed as
    // unpadded base64url. Return the string the verifier will compare against,
    // not a re-encoding of it, so the two can never drift.
    return { ...options, challenge };
  }

  /**
   * Verify a WebAuthn assertion (signature) and return an attestation artifact.
   *
   * `binding` takes the same shapes as {@link startAuthentication} — pass the
   * SAME one, so the challenge the relying party enforces is the challenge the
   * ceremony was started with. A bare string is accepted for callers that
   * carried the challenge themselves.
   */
  async verifyAssertion(
    assertionResponse: any,
    binding: AssertionBinding | string
  ): Promise<AssertionResult> {
    const expectedChallenge = challengeForBinding(binding);
    const credentialId = assertionResponse.id;

    // Look up the credential
    const stored = this.credentialStore.getByCredentialId(credentialId);
    if (!stored) {
      return { verified: false, error: `Credential "${credentialId}" not found.` };
    }

    if (stored.status === 'revoked') {
      return { verified: false, error: `Credential "${credentialId}" has been revoked.` };
    }

    try {
      const verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge,
        expectedOrigin: this.config.origin,
        expectedRPID: this.config.rpID,
        // Unset, the library refuses an assertion from a cross-origin frame
        // that names its top origin (see WebAuthnConfig.allowedTopOrigins).
        ...(this.config.allowedTopOrigins !== undefined && {
          expectedTopOrigin: this.config.allowedTopOrigins,
        }),
        credential: {
          id: stored.credentialId,
          publicKey: new Uint8Array(Buffer.from(stored.publicKey, 'base64')),
          counter: stored.counter,
        },
      } as VerifyAuthenticationResponseOpts);

      if (!verification.verified) {
        return { verified: false, error: 'Assertion verification failed' };
      }

      // Update counter for replay prevention
      this.credentialStore.updateCounter(
        credentialId,
        verification.authenticationInfo.newCounter
      );

      // Extract signature and raw assertion data from the response
      const signature = assertionResponse.response?.signature || '';
      const authenticatorData: string | undefined = assertionResponse.response?.authenticatorData;
      const clientDataJSON: string | undefined = assertionResponse.response?.clientDataJSON;

      // Label the artifact from the key material, not from `stored.algorithm`.
      // A stored label can disagree with the key it sits beside: a store
      // filled by code other than finishRegistration() may hold any label.
      // An artifact that says ES256
      // over an Ed25519 signature is unverifiable evidence that reads as a
      // forgery. The key cannot lie about its type; the stored label is used
      // only when the key's type cannot be read.
      const storedKey = importCredentialPublicKey(Buffer.from(stored.publicKey, 'base64'));
      const algorithm =
        (storedKey ? signatureAlgorithmOfKey(storedKey) : undefined) ?? stored.algorithm;

      return {
        verified: true,
        artifact: {
          signature,
          credentialKeyId: credentialId,
          algorithm,
          ...(authenticatorData !== undefined && { authenticatorData }),
          ...(clientDataJSON !== undefined && { clientDataJSON }),
        },
      };
    } catch (err) {
      return {
        verified: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
