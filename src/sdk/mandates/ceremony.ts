/**
 * The WebAuthn checks every mandate ceremony passes (Record §9.6): the
 * principal's assertion over a statement, a revoker's over the revocation
 * record, a confirmer's over a mandated record.
 *
 * The SDK's existing verification (`verifyAttestation`) is run against the
 * instance's credential store with the ceremony's challenge as the expected
 * one: `clientDataJSON` of type `webauthn.get`, the User Present flag, the
 * signature under the registered key, a credential that is not revoked, and
 * the challenge. On top of it a mandate ceremony requires User Verification
 * (the UV flag of `authenticatorData`), and answers with the user the
 * credential is registered to, so the caller can name or compare the person.
 */
import { verifyAttestation } from '../../attestation/verify-attestation';
import type { WebauthnAssertion } from '@tzun/engine';
import type { SdkHost } from '../extension-points';

/** Why a ceremony's assertion was not accepted. */
export type CeremonyFailure =
  | 'no_credential_store'
  | 'malformed_assertion'
  | 'user_not_verified'
  /** One of `verifyAttestation`'s signature reasons: `unknown_credential`, `revoked_credential`, `invalid_signature`, `challenge_mismatch`, … */
  | string;

/** The answer of {@link verifyCeremony}. */
export type CeremonyResult = { ok: true; userId: string; credentialId: string } | { ok: false; reason: CeremonyFailure };

const USER_VERIFIED = 0x04;

function isAssertion(value: unknown): value is WebauthnAssertion {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const a = value as Record<string, unknown>;
  return (
    typeof a.signature === 'string' &&
    typeof a.credentialKeyId === 'string' &&
    (a.algorithm === 'Ed25519' || a.algorithm === 'ES256') &&
    typeof a.authenticatorData === 'string' &&
    typeof a.clientDataJSON === 'string'
  );
}

/**
 * Verify `assertion` as a user-verifying WebAuthn assertion presenting
 * `challenge`, made by a credential the instance's credential store holds.
 * Never throws.
 */
export async function verifyCeremony(host: SdkHost, assertion: unknown, challenge: string): Promise<CeremonyResult> {
  const store = host.credentialStore();
  if (!store) return { ok: false, reason: 'no_credential_store' };
  if (!isAssertion(assertion)) return { ok: false, reason: 'malformed_assertion' };
  let snapshot;
  try {
    snapshot = await store.snapshot([assertion.credentialKeyId]);
  } catch {
    return { ok: false, reason: 'no_credential_store' };
  }
  const verdict = await verifyAttestation({ webauthnAssertion: assertion }, '', snapshot, {
    expectedChallenge: challenge,
    expectedChallengeSource: 'caller-asserted',
  }).catch(() => null);
  if (verdict === null) return { ok: false, reason: 'malformed_assertion' };
  if (verdict.signatureValid !== true) return { ok: false, reason: verdict.signatureReason ?? 'invalid_signature' };
  const authData = Buffer.from(assertion.authenticatorData!, 'base64');
  if (authData.length < 37 || (authData[32] & USER_VERIFIED) === 0) return { ok: false, reason: 'user_not_verified' };
  const credential = snapshot.getByCredentialId(assertion.credentialKeyId);
  if (!credential) return { ok: false, reason: 'unknown_credential' };
  return { ok: true, userId: credential.userId, credentialId: credential.credentialId };
}
