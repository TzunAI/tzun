/**
 * A rejected timestamp or anchor is never reported as 'pending'.
 *
 * The verifier's verdict (`attestationVerdict`) tells a timestamp that is
 * ABSENT (`timestampValid: null`) apart from one that was CHECKED AND REJECTED
 * (`false`). A rule keyed on "not verified" alone would treat the two the
 * same, so a signed record carrying a forged, self-signed or expired RFC 3161
 * token would report the identical status to one that never had a timestamp.
 *
 * That matters because 'pending' is not a neutral word here: it means "a
 * verified signature whose companions are absent". A cryptographically
 * rejected artifact must not be summarised as not-yet-attached.
 *
 * The anchor side of that distinction has three cases, and this file pins
 * all three (tzun-anchor/1 §10.1, §10.3):
 *   - absent      — no anchor artifact at all                          → null  → 'pending'
 *   - rejected    — an `anchor` whose proof does not hold               → false → 'partial'
 *   - unreadable  — an anchor this verifier does not read: an unknown
 *                   `anchorSpec` or `merkleSpec`, or a `blockchainAnchor`
 *                   (`legacy_blockchain_anchor`). The verdict is withheld
 *                   (`merkleProofValid: null`), but the record is NOT
 *                   awaiting attestation, so still 'partial'.
 * The middle case must read as a failure, not as absence; the third must not
 * be allowed to leak back into 'pending', which would report an attached
 * artifact as though nothing had ever been attached.
 */
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import type { AttestationArtifacts } from '@tzun/engine';
import { makeGenuineAssertion, storeWith, ORIGIN, RP_ID } from './attestation-assertion-helpers';
import { anchoredRecord } from './helpers/anchor-fixtures';
import { createHash } from 'crypto';

const testDigest = createHash('sha256').update('test-evidence', 'utf8').digest('hex');

/**
 * A well-formed tzun-anchor/1 artifact that is simply not about this record:
 * `testDigest` is none of its evidence log's leaves, so step 4 (inclusion)
 * refuses it. The paths are genuine RFC 6962 audit paths, so the rejection is
 * a cryptographic one — the path folds, it just folds to another root.
 */
const otherRecordsAnchor = anchoredRecord().anchor;

async function verifyWithSignature(extra: Partial<AttestationArtifacts>) {
  const { assertion, publicKeyBase64 } = await makeGenuineAssertion({
    challenge: testDigest,
    credentialId: 'cred-rejected',
  });
  const credStore = storeWith('cred-rejected', publicKeyBase64);
  return verifyAttestation(
    { webauthnAssertion: assertion, ...extra } as AttestationArtifacts,
    testDigest,
    credStore,
    { expectedChallenge: testDigest, allowedOrigins: [ORIGIN], rpId: RP_ID },
  );
}

describe("'pending' is reserved for absent companions, not failed ones", () => {
  it('a verified signature with NO timestamp and no anchor is pending', async () => {
    const result = await verifyWithSignature({});
    expect(result.signatureValid).toBe(true);
    expect(result.timestampValid).toBeNull();
    expect(result.anchorValid).toBeNull();
    expect(result.attestationVerdict).toBe('pending');
  });

  it('a verified signature with a REJECTED timestamp is partial, not pending', async () => {
    const result = await verifyWithSignature({ rfc3161Token: 'not-a-real-token' });
    expect(result.signatureValid).toBe(true);
    // Present and checked, and it did not hold up.
    expect(result.timestampValid).toBe(false);
    expect(result.anchorValid).toBeNull();
    // The whole point: this must not read as "awaiting attestation".
    expect(result.attestationVerdict).not.toBe('pending');
    expect(result.attestationVerdict).toBe('partial');
  });

  it('the two cases are distinguishable on attestationVerdict alone', async () => {
    const absent = await verifyWithSignature({});
    const failed = await verifyWithSignature({ rfc3161Token: 'not-a-real-token' });
    expect(absent.attestationVerdict).not.toBe(failed.attestationVerdict);
  });

  it('a verified signature with a rejected anchor is also partial', async () => {
    const result = await verifyWithSignature({ anchor: otherRecordsAnchor });
    expect(result.signatureValid).toBe(true);
    // Read, folded, and refused — a verdict, not an abstention. That is what
    // separates this case from the unreadable ones below.
    expect(result.merkleProofValid).toBe(false);
    expect(result.anchorReason).toBe('merkle_proof_invalid');
    expect(result.anchorValid).toBe(false);
    expect(result.attestationVerdict).not.toBe('pending');
    expect(result.attestationVerdict).toBe('partial');
  });

  /**
   * The property pinned here: an abstention on the
   * anchor must not be laundered back into 'pending'. Something IS attached
   * to this record, so it is not awaiting attestation.
   */
  it.each([
    ['an unknown anchorSpec', { anchor: { ...otherRecordsAnchor, anchorSpec: 'tzun-anchor/2' } }, 'unsupported_anchor_spec'],
    ['an unknown merkleSpec', { anchor: { ...otherRecordsAnchor, merkleSpec: 'sha256-v0' } }, 'unsupported_merkle_spec'],
    [
      'a blockchainAnchor',
      {
        blockchainAnchor: {
          chain: 'ethereum',
          transactionId: '0x' + '0'.repeat(64),
          merklePath: ['left:' + 'ab'.repeat(32)],
        },
      },
      'legacy_blockchain_anchor',
    ],
  ])('an anchor this verifier does not read (%s) is unresolved, and still not pending', async (_label, extra, reason) => {
    const result = await verifyWithSignature(extra as unknown as Partial<AttestationArtifacts>);
    expect(result.signatureValid).toBe(true);
    expect(result.anchorReason).toBe(reason);
    // Withheld, not refused: the paths were never read under any rule.
    expect(result.merkleProofValid).toBeNull();
    expect(result.anchorValid).toBeNull();
    expect(result.attestationVerdict).toBe('partial');
  });

  it('nothing verifying at all is still none, not pending', async () => {
    const result = await verifyAttestation(
      { rfc3161Token: 'not-a-real-token' } as AttestationArtifacts,
      testDigest,
    );
    expect(result.attestationVerdict).toBe('none');
  });
});
