import { AttestationArtifacts, AttestationStatusOf, EvidenceEnvelope } from '@tzun/engine';

/**
 * The fill-only rule for `updateAttestation()`, stated once for every backend.
 *
 * `retryPendingAttestations()` runs on a timer, and a self-hosted deployment
 * can run several replicas against one store. Two passes then work the same
 * pending record, both ask a TSA, and both come back with a token. An update
 * that spread the caller's artifacts over the stored ones would let whoever
 * committed second replace a timestamp that had already landed: a second
 * token over already-attested evidence, and a second `attestation_retry`
 * revision row claiming the record had been written again.
 *
 * So an update FILLS, it does not replace. Each adapter applies these rules
 * inside the lock it already takes around the read and the write — SQLite's
 * IMMEDIATE transaction, the Postgres row lock, the memory adapter's
 * synchronous section — which is what makes "still absent" true at the moment
 * of writing rather than at the moment of reading.
 */

/**
 * A component counts as present unless it is absent, null or an empty string.
 * This is the engine's reading (`missingAttestationComponents`) and the one
 * `listByMissingObtainable()` lists by, so a record the retry is sent to is a
 * record the retry's token can fill, and an empty token from a caller fills
 * nothing.
 */
export function isAbsent(value: unknown): boolean {
  return value === undefined || value === null || value === '';
}

/**
 * The artifacts to store: everything the record already has, plus the
 * caller's components that it does not have yet. `filled` is false when the
 * caller brought nothing new, which is the losing pass of a race.
 */
export function fillAbsentArtifacts(
  stored: AttestationArtifacts | undefined,
  artifacts: AttestationArtifacts,
): { merged: AttestationArtifacts; filled: boolean } {
  const merged: Record<string, unknown> = { ...(stored ?? {}) };
  let filled = false;
  for (const [component, value] of Object.entries(artifacts as Record<string, unknown>)) {
    if (isAbsent(value) || !isAbsent(merged[component])) continue;
    merged[component] = value;
    filled = true;
  }
  return { merged: merged as AttestationArtifacts, filled };
}

/**
 * The status to store.
 *
 * The caller computes `newStatus` with the engine's one rule over the
 * artifacts it merged, which is right for everything it could see. A pass
 * that lost a race saw less: it may have missed a component another pass had
 * already landed, and its status would then walk a finished record backwards.
 * A record that is already `'complete'` therefore stays `'complete'`; every
 * other status is the caller's.
 */
export function nextAttestationStatus(
  stored: EvidenceEnvelope['attestationStatus'],
  newStatus: EvidenceEnvelope['attestationStatus'],
): EvidenceEnvelope['attestationStatus'] {
  return stored === 'complete' ? 'complete' : newStatus;
}

/**
 * The status `updateAttestation()` stores for `stored` once `merged` is its
 * `nonRepudiation`. A function `newStatus` is called with the envelope as it
 * will be stored, inside the adapter's lock, so a component another writer
 * filled after the caller's read counts (the anchor fill, for a retry that
 * waited on its timestamp authority). Then `nextAttestationStatus` applies.
 */
export function statusAfterFill(
  stored: EvidenceEnvelope,
  merged: AttestationArtifacts,
  newStatus: EvidenceEnvelope['attestationStatus'] | AttestationStatusOf,
): EvidenceEnvelope['attestationStatus'] {
  const computed = typeof newStatus === 'function' ? newStatus({ ...stored, nonRepudiation: merged }) : newStatus;
  return nextAttestationStatus(stored.attestationStatus, computed);
}
