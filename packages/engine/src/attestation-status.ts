import type { AttestationArtifacts, EvidenceEnvelope } from './types/evidence';
import type { RetryObtainableComponent } from './types/config';
import { assertionBindsDigest } from './webauthn-binding';

/**
 * The attestation components a writer expects every record it stores to
 * hold.
 *
 * An RFC 3161 timestamp, an anchor (`nonRepudiation.anchor`), both, or
 * neither. A WebAuthn signature is not one of these: it is produced by a
 * human ceremony over the record's digest, which no writer can obtain, or
 * retry, on its own.
 */
export interface AttestationExpectation {
  timestamp?: boolean;
  anchor?: boolean;
}

/**
 * An expected component a stored record can still be missing, in two kinds:
 *
 * - retry-obtainable ({@link RetryObtainableComponent}): `'timestamp'`, which
 *   the pending-attestation retry lists records by and obtains;
 * - scheduler-filled: `'anchor'`, which is published for a batch of records
 *   and filled in afterwards. The retry never lists or requests it, so
 *   records waiting for one never take the retry's page.
 */
export type ObtainableAttestationComponent = RetryObtainableComponent | 'anchor';

const RETRY_OBTAINABLE: ReadonlySet<string> = new Set<RetryObtainableComponent>(['timestamp']);

/** Whether `component` is one the pending-attestation retry obtains. */
export function isRetryObtainableComponent(component: unknown): component is RetryObtainableComponent {
  return typeof component === 'string' && RETRY_OBTAINABLE.has(component);
}

/**
 * The expected components the record has no artifact for, timestamp first.
 * Presence is the test: an artifact that is present but does not verify is
 * not missing. Verifying it is the verifier's job, and replacing it would
 * erase what the verifier has to report. An artifact that is absent, `null`
 * or an empty string is missing.
 */
export function missingAttestationComponents(
  artifacts: AttestationArtifacts | undefined,
  expected: AttestationExpectation,
): ObtainableAttestationComponent[] {
  const missing: ObtainableAttestationComponent[] = [];
  if (expected.timestamp && !artifacts?.rfc3161Token) missing.push('timestamp');
  if (expected.anchor && !artifacts?.anchor) missing.push('anchor');
  return missing;
}

/**
 * The one rule for a record's `attestationStatus`. Capture, the pending-
 * attestation retry and `assembleEnvelope` all call this, so the same
 * artifacts under the same expectation always get the same status.
 *
 * - `'pending'`: a component in `expected` has no artifact on the record
 *   (see {@link missingAttestationComponents}). Checked first, so a record
 *   with a timestamp and a missing expected anchor is `'pending'`, not
 *   `'partial'`. A record stays `'pending'` until every expected component
 *   is present. `retryPendingAttestations()` works on the 'pending' records
 *   missing a retry-obtainable component, not on every 'pending' record.
 * - `'complete'`: a signature bound to `digest`, a timestamp and an anchor.
 * - `'partial'`: at least one of those three, and nothing expected missing.
 * - `'none'`: none of the three, and nothing expected missing.
 *
 * The signature counts only when it is a binding: the assertion's challenge
 * is derived from `digest` (`assertionBindsDigest`). An unbound
 * assertion is stored but counts for nothing. That check needs no key
 * material, so it is always available here.
 *
 * `expected` defaults to nothing, which makes `'pending'` unreachable: an
 * assembler that obtains no attestation of its own never waits for one.
 */
export function determineAttestationStatus(
  artifacts: AttestationArtifacts | undefined,
  digest: string,
  expected: AttestationExpectation = {},
): EvidenceEnvelope['attestationStatus'] {
  if (missingAttestationComponents(artifacts, expected).length > 0) return 'pending';
  if (!artifacts) return 'none';

  const hasSignature =
    !!artifacts.webauthnAssertion && assertionBindsDigest(artifacts.webauthnAssertion, digest);
  const hasTimestamp = !!artifacts.rfc3161Token;
  const hasAnchor = !!artifacts.anchor;

  if (hasSignature && hasTimestamp && hasAnchor) return 'complete';
  if (hasSignature || hasTimestamp || hasAnchor) return 'partial';
  return 'none';
}
