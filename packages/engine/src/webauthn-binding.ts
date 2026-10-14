/**
 * The binding between a decision record and the human who signed it.
 *
 * A WebAuthn assertion is only evidence about a decision if the reviewer's
 * authenticator signed THAT decision. An assertion over a random login nonce
 * verifies against every record ever captured — which is the same as
 * verifying against none. It can be lifted off a login and attached to
 * decisions the reviewer never saw, and each of those records then carries
 * their credential id as non-repudiation evidence. So the challenge is
 * derived from the record's digest. (Records captured before 0.3.16 carry an
 * assertion over a login nonce.)
 *
 * It lives in the engine, not in `src/attestation`, for two reasons:
 *
 *  - it is part of the wire contract, like the canonical serializer and the
 *    chain link, and the Python twin
 *    (`tzun_sdk.attestation.webauthn_challenge_for_digest`) is pinned to it by
 *    `tests/cross-sdk/test_webauthn_challenge_parity.py`;
 *  - `assembleEnvelope()` needs it to decide whether a record's assertion is a
 *    signature over that record, and the engine takes no dependencies.
 *
 * Pure: SHA-256 and base64, no I/O, no key material, no configuration.
 */
import { createHash } from 'crypto';
import type { AttestationArtifacts } from './types/evidence';

/** The one binding scheme, spelled out so a reader never has to guess it. */
const CHALLENGE_DOMAIN = 'tzun-decision-v1';

/**
 * Derive the WebAuthn challenge that binds an assertion to an evidence digest:
 * `base64url(SHA-256("tzun-decision-v1" || digest))`, unpadded.
 *
 * The ceremony must present this as its challenge. Because a record's canonical
 * digest covers its `sequenceNumber`, `evidenceId` and `capturedAt`, the digest
 * does not exist until the record has been built at a chain position — so the
 * ordering is build the record, derive the challenge, run the ceremony, attach
 * the assertion. `Tzun.prepareAssertionChallenge()` is the SDK's front door to
 * that sequence.
 */
export function webauthnChallengeForDigest(digest: string): string {
  return createHash('sha256').update(CHALLENGE_DOMAIN + digest, 'utf8').digest('base64url');
}

/**
 * Compare two WebAuthn challenges.
 *
 * Exact string match, plus a padding-insensitive comparison: browsers emit the
 * challenge in `clientDataJSON` as unpadded base64url, while a challenge that
 * made a round trip through a padded base64 encoder keeps its '='.
 */
export function challengeMatches(actual: string, expected: string): boolean {
  const norm = (v: string) => v.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return actual === expected || norm(actual) === norm(expected);
}

/**
 * Decode a base64 or base64url `clientDataJSON` into the object it must be,
 * or `null` when it is not one: not a string, not decodable, not JSON, or JSON
 * that is not an object (`null`, a number, an array). Every reader of
 * `clientDataJSON` goes through this, so a value that is not a client-data
 * object is one verdict everywhere rather than a `TypeError` in whichever
 * reader touched a field first.
 */
export function parseClientDataJSON(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  try {
    // Node's base64 decoder reads the url-safe alphabet too, and a browser
    // hands `clientDataJSON` back as unpadded base64url.
    const parsed: unknown = JSON.parse(Buffer.from(value, 'base64').toString('utf8'));
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Why an assertion does not bind a digest. A subset of `AttestationSignatureReason`. */
export type AssertionBindingFailure =
  | 'unverifiable_assertion'
  | 'malformed_client_data'
  | 'wrong_client_data_type'
  | 'challenge_mismatch';

/**
 * Does this assertion's ceremony actually cover `digest`?
 *
 * The one question about a WebAuthn artifact that needs no key material, no
 * credential store and no network: `clientDataJSON` states, inside the bytes
 * the authenticator signed over, which challenge was presented, and the
 * challenge is a pure function of the digest. So a verifier holding nothing at
 * all can still say "this assertion is not about this record" — and the capture
 * path can say "the assertion this caller handed me is not about the record I
 * am building", which is where the whole problem started.
 *
 * Returns `null` when the assertion binds `digest`, otherwise the reason it
 * does not. A missing `clientDataJSON` is `unverifiable_assertion`: there is no
 * signed statement of what was signed, so the artifact binds nothing by
 * construction.
 *
 * This is deliberately NOT a signature check. It says the ceremony was about
 * this record; whether the signature is genuine needs the registered public key
 * and belongs to `verifyAttestation`.
 */
export function assertionBindingFailure(
  assertion: NonNullable<AttestationArtifacts['webauthnAssertion']>,
  digest: string,
): AssertionBindingFailure | null {
  if (!assertion.clientDataJSON) return 'unverifiable_assertion';

  const clientData = parseClientDataJSON(assertion.clientDataJSON);
  if (clientData === null) return 'malformed_client_data';

  if (clientData.type !== 'webauthn.get') return 'wrong_client_data_type';

  if (
    typeof clientData.challenge !== 'string' ||
    !challengeMatches(clientData.challenge, webauthnChallengeForDigest(digest))
  ) {
    return 'challenge_mismatch';
  }

  return null;
}

/** True when the ceremony behind `assertion` signed a challenge derived from `digest`. */
export function assertionBindsDigest(
  assertion: NonNullable<AttestationArtifacts['webauthnAssertion']>,
  digest: string,
): boolean {
  return assertionBindingFailure(assertion, digest) === null;
}
