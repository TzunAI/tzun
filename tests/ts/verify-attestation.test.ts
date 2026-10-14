/**
 * End-to-end verification of the attestation artifacts on an evidence record.
 *
 * The anchor is `nonRepudiation.anchor` (tzun-anchor/1 §8). Its fixtures are
 * built by tests/ts/helpers/anchor-fixtures.ts from a real evidence log and a
 * real anchor log, so every inclusion proof here is a genuine RFC 6962 path;
 * `verifyAnchor`'s steps are pinned one by one by
 * vectors/checkpoint-vectors.json and tests/ts/anchor-verify.test.ts. What is
 * under test here is how `verifyAttestation` reports the anchor beside the
 * signature and the timestamp.
 */
import {
  verifyAttestation,
  AttestationVerificationResult,
} from '../../src/attestation/verify-attestation';
import { AttestationArtifacts } from '@tzun/engine';
import { CredentialStore } from '../../src/attestation/credential-store';
import type { AnchorArtifact } from '@tzun/engine';
import { makeGenuineAssertion, storeWith, ORIGIN, RP_ID } from './attestation-assertion-helpers';
import { anchoredRecord } from './helpers/anchor-fixtures';
import { makeTsaFixture } from './rfc3161-fixture';
import { checkpointDigest } from '../../src/attestation/checkpoint';
import { createHash } from 'crypto';

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

/** An anchor over an evidence log whose leaf `index` is `digest`: both proofs hold, and no publication is listed. */
function anchorFor(digest: string, index = 1): AnchorArtifact {
  const digests = [sha256('before'), sha256('also before'), sha256('after')];
  digests.splice(index, 0, digest);
  return anchoredRecord({ digests, leafIndex: index }).anchor;
}

describe('verifyAttestation', () => {
  const testDigest = sha256('test-evidence');

  it('returns all-null for empty artifacts', async () => {
    const result = await verifyAttestation({}, testDigest);
    expect(result.signatureValid).toBeNull();
    expect(result.timestampValid).toBeNull();
    expect(result.anchorValid).toBeNull();
    expect(result.attestationVerdict).toBe('none');
  });

  it('returns timestampValid false for a garbage RFC 3161 token', async () => {
    // verifyTimestampToken returns { valid: false, reason: 'unparseable_token' }
    // for garbage input, and verifyAttestation reports it as false: no
    // compatibility path accepts an unparseable token as valid.
    const artifacts: AttestationArtifacts = {
      rfc3161Token: 'base64-encoded-token',
    };

    const result = await verifyAttestation(artifacts, testDigest);

    expect(result.timestampValid).toBe(false);
    // 'none', not 'partial'. Nothing verified: there is no signature and no
    // anchor, and the only artifact present failed. A verdict that counted
    // artifacts by presence (`!== null`) would read a garbage token alone as a
    // partially-attested record.
    expect(result.attestationVerdict).toBe('none');
  });

  it('returns timestampValid false for completely unparseable garbage token', async () => {
    // A token that is not even valid base64-decodable ASN.1 must not be
    // accepted as valid under any backward-compat path.
    const artifacts: AttestationArtifacts = {
      rfc3161Token: '!!!not-base64-at-all!!!',
    };

    const result = await verifyAttestation(artifacts, testDigest);

    expect(result.timestampValid).toBe(false);
  });

  // The roots arrive inside the artifact under
  // examination, so no proof against them can establish that anything was
  // published. A proof that holds is reported as such, and the anchor stays
  // undecided until a publication of P is checked.
  it('reports valid inclusion proofs as merkleProofValid, not as a verified anchor', async () => {
    const result = await verifyAttestation({ anchor: anchorFor(testDigest) }, testDigest);

    expect(result.merkleProofValid).toBe(true);
    expect(result.anchorValid).toBeNull();
    expect(result.anchorPosition).toMatchObject({ leafIndex: 1, treeSize: 4, leafIndexChecked: false });
    expect(result.attestationVerdict).toBe('none');
  });

  it('returns anchorValid false for an inclusion proof of another record', async () => {
    const result = await verifyAttestation({ anchor: anchorFor(sha256('another record')) }, testDigest);

    expect(result.anchorValid).toBe(false);
    expect(result.merkleProofValid).toBe(false);
    expect(result.anchorReason).toBe('merkle_proof_invalid');
    // A failing anchor reports no fact about where the record sits.
    expect(result.anchorPosition).toBeNull();
  });

  it('fails a correct audit path presented at the wrong leaf index', async () => {
    const result = await verifyAttestation({ anchor: { ...anchorFor(testDigest, 1), leafIndex: 2 } }, testDigest);

    expect(result.anchorValid).toBe(false);
    expect(result.anchorReason).toBe('merkle_proof_invalid');
  });

  it('checks leafIndex against the sequence number when one is supplied', async () => {
    const anchor = anchorFor(testDigest, 1);
    const right = await verifyAttestation({ anchor }, testDigest, undefined, { sequenceNumber: 2 });
    expect(right.anchorPosition).toMatchObject({ leafIndex: 1, leafIndexChecked: true });

    const wrong = await verifyAttestation({ anchor }, testDigest, undefined, { sequenceNumber: 3 });
    expect(wrong.anchorValid).toBe(false);
    expect(wrong.anchorReason).toBe('leaf_index_mismatch');
  });

  it('abstains on an unknown merkleSpec rather than reading the paths under another rule', async () => {
    const result = await verifyAttestation(
      { anchor: { ...anchorFor(testDigest), merkleSpec: 'sha256-v0' } } as unknown as AttestationArtifacts,
      testDigest,
    );

    expect(result.anchorValid).toBeNull();
    expect(result.anchorReason).toBe('unsupported_merkle_spec');
    expect(result.merkleProofValid).toBeNull();
  });

  // An active credential with a status-only assertion. `signature: 'sig-data'`
  // is never read by any cryptographic operation, so a "signature verified"
  // verdict here would really be the answer to "is this credential id
  // unrevoked?". The signature is reported unverifiable instead.
  it('does not report a status-only assertion as a valid signature', async () => {
    const credStore = storeWith('cred-123', 'key-data');

    const artifacts: AttestationArtifacts = {
      webauthnAssertion: {
        signature: 'sig-data',
        credentialKeyId: 'cred-123',
        algorithm: 'ES256',
      },
    };

    const result = await verifyAttestation(artifacts, testDigest, credStore);
    expect(result.signatureValid).toBe(false);
    expect(result.signatureReason).toBe('unverifiable_assertion');
    // Credential status is still reported, as a field of its own rather than as
    // a signature verdict.
    expect(result.credentialStatus).toBe('active');
  });

  it('returns signatureValid false for revoked credential', async () => {
    const credStore = new CredentialStore();
    credStore.register({
      credentialId: 'cred-revoked',
      publicKey: 'key-data',
      userId: 'jane@acme.example',
      algorithm: 'ES256',
      counter: 0,
      status: 'active',
      registeredAt: '2026-03-22T10:00:00.000Z',
    });
    credStore.revoke('cred-revoked');

    const artifacts: AttestationArtifacts = {
      webauthnAssertion: {
        signature: 'sig-data',
        credentialKeyId: 'cred-revoked',
        algorithm: 'ES256',
      },
    };

    const result = await verifyAttestation(artifacts, testDigest, credStore);
    expect(result.signatureValid).toBe(false);
    expect(result.credentialStatus).toBe('revoked');
  });

  // A verified signature with no timestamp and no anchor reports 'pending'.
  // The fixture is a genuine ES256 assertion, because a status-only assertion
  // is not a verified signature; this keeps 'pending' reachable for real
  // evidence.
  it('returns pending when a genuine signature is present but no timestamp or anchor', async () => {
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge: testDigest,
      credentialId: 'cred-pending',
    });
    const credStore = storeWith('cred-pending', publicKeyBase64);

    // `expectedChallenge`: without it a genuine assertion is
    // reported `null`, because a signature over a challenge unrelated to the
    // digest binds this record to nothing.
    const result = await verifyAttestation({ webauthnAssertion: assertion }, testDigest, credStore, {
      expectedChallenge: testDigest,
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });
    expect(result.attestationVerdict).toBe('pending');
    expect(result.signatureValid).toBe(true);
    expect(result.timestampValid).toBeNull();
    expect(result.anchorValid).toBeNull();
  });

  // Every one of the three artifacts here is
  // unverifiable — a status-only assertion, a token that is not one, and an
  // anchor whose proofs hold but whose publication nobody checked — so the
  // honest summary is 'none'. The proofs holding is exactly why the verdict
  // that matters is `anchorValid: null`, not `merkleProofValid`.
  it('reports none when every artifact present is unverifiable', async () => {
    const credStore = storeWith('cred-123', 'key-data');

    const artifacts: AttestationArtifacts = {
      webauthnAssertion: {
        signature: 'sig-data',
        credentialKeyId: 'cred-123',
        algorithm: 'ES256',
      },
      rfc3161Token: 'token-data',
      anchor: anchorFor(testDigest),
    };

    const result = await verifyAttestation(artifacts, testDigest, credStore);
    expect(result.signatureValid).toBe(false);
    expect(result.timestampValid).toBe(false);
    expect(result.merkleProofValid).toBe(true);
    expect(result.anchorValid).toBeNull();
    expect(result.attestationVerdict).toBe('none');
  });

  describe('Cryptographic Signature Verification at Rest', () => {
    // The fixture carries realistic authenticatorData (the mandatory 32-byte
    // rpIdHash ++ flags ++ counter, which the verifier parses) and supplies the
    // digest-derived challenge, which is what `signatureValid: true` requires.
    it('performs cryptographic verification when authenticatorData and clientDataJSON are present', async () => {
      const { publicKeyBase64, assertion } = makeGenuineAssertion({
        challenge: testDigest,
        credentialId: 'cred-crypto-test',
      });
      const credStore = storeWith('cred-crypto-test', publicKeyBase64);

      const result = await verifyAttestation({ webauthnAssertion: assertion }, testDigest, credStore, {
        expectedChallenge: testDigest,
        allowedOrigins: [ORIGIN],
        rpId: RP_ID,
      });
      expect(result.signatureValid).toBe(true);
      expect(result.credentialStatus).toBe('active');
    });

    // Companion: the same genuine assertion, checked
    // without an expected challenge, is not a verified signature for this record.
    it('reports a cryptographically genuine but unbound assertion as null, not true', async () => {
      const { publicKeyBase64, assertion } = makeGenuineAssertion({
        challenge: 'a-login-nonce',
        credentialId: 'cred-unbound',
      });
      const credStore = storeWith('cred-unbound', publicKeyBase64);

      const result = await verifyAttestation({ webauthnAssertion: assertion }, testDigest, credStore);
      expect(result.signatureValid).toBeNull();
      expect(result.signatureReason).toBe('assertion_not_bound_to_digest');
    });

    // The fixture is well-formed everywhere EXCEPT the signature, so
    // 'invalid_signature' is the only thing it can be testing. With placeholder
    // authenticatorData it would pass for the wrong reason (malformed
    // authenticatorData rather than a bad signature), which is exactly the
    // vacuous-test shape that hides a broken verifier.
    it('returns signatureValid false for tampered signature', async () => {
      const { publicKeyBase64, assertion } = makeGenuineAssertion({
        challenge: testDigest,
        credentialId: 'cred-tamper-test',
      });
      const credStore = storeWith('cred-tamper-test', publicKeyBase64);

      const artifacts: AttestationArtifacts = {
        webauthnAssertion: {
          ...assertion,
          signature: Buffer.from('invalid-signature-data').toString('base64'),
        },
      };

      const result = await verifyAttestation(artifacts, testDigest, credStore, {
        expectedChallenge: testDigest,
        allowedOrigins: [ORIGIN],
        rpId: RP_ID,
      });
      expect(result.signatureValid).toBe(false);
      expect(result.signatureReason).toBe('invalid_signature');
    });

    // With no authenticatorData there is no signed message, so there is nothing
    // the signature could be verified against, and an active credential's
    // status must not stand in for a signature verdict.
    it('does NOT fall back to a credential status check when authenticatorData is missing', async () => {
      const credStore = storeWith('cred-fallback', 'key-data');

      const artifacts: AttestationArtifacts = {
        webauthnAssertion: {
          signature: 'sig-data',
          credentialKeyId: 'cred-fallback',
          algorithm: 'ES256',
          // No authenticatorData or clientDataJSON
        },
      };

      const result = await verifyAttestation(artifacts, testDigest, credStore);
      expect(result.signatureValid).toBe(false);
      expect(result.signatureReason).toBe('unverifiable_assertion');
      expect(result.credentialStatus).toBe('active');
    });
  });
});

describe('determineVerdict — verification, not presence', () => {
  const testDigest = sha256('test-evidence');

  it('does NOT report complete when all three components FAILED', async () => {
    // The verdict counts verifications, not artifacts. A rule that tested
    // `!== null` would, since `false !== null`, report 'complete' for an
    // envelope whose signature, timestamp and Merkle proof every one verified
    // FALSE.
    const credStore = new CredentialStore();
    credStore.register({
      credentialId: 'revoked-cred',
      publicKey: 'key-data',
      userId: 'jane@acme.example',
      algorithm: 'ES256',
      counter: 0,
      status: 'revoked',
      registeredAt: '2026-03-22T10:00:00.000Z',
    });

    const artifacts: AttestationArtifacts = {
      webauthnAssertion: { signature: 'sig', credentialKeyId: 'revoked-cred', algorithm: 'ES256' },
      rfc3161Token: 'not-a-real-token',
      anchor: anchorFor(sha256('another record')),
    };

    const result = await verifyAttestation(artifacts, testDigest, credStore);

    expect(result.signatureValid).toBe(false);
    expect(result.timestampValid).toBe(false);
    expect(result.anchorValid).toBe(false);
    // Checked and failed, not unchecked.
    expect(result.merkleProofValid).toBe(false);
    expect(result.anchorReason).toBe('merkle_proof_invalid');
    expect(result.attestationVerdict).not.toBe('complete');
    expect(result.attestationVerdict).toBe('none');
  });

  it('still reports complete when all three genuinely verify', async () => {
    // Counting verifications must not make 'complete' unreachable — a real
    // all-good envelope has to report complete, or the status is useless in
    // the other direction. Guards against over-correction.
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge: testDigest,
      credentialId: 'good-cred',
    });
    const credStore = storeWith('good-cred', publicKeyBase64);

    // An anchor whose proofs hold, published through a token over P from a
    // TSA whose root the caller supplies: what "genuinely verify" has to mean
    // for an anchor (a publication checked, not just proofs that fold).
    const anchor = anchorFor(testDigest);
    const tsa = await makeTsaFixture({ digestHex: checkpointDigest(anchor.anchorCheckpoint), genTime: new Date('2026-09-20T12:00:00Z') });
    const recordTsa = await makeTsaFixture({
      digestHex: testDigest,
      genTime: new Date('2026-09-20T12:00:00Z'),
      caCN: 'Record TSA Root',
      signerCN: 'Record TSA',
    });
    const artifacts: AttestationArtifacts = {
      webauthnAssertion: assertion,
      rfc3161Token: recordTsa.tokenBase64,
      anchor: { ...anchor, publications: [{ kind: 'rfc3161/1', token: tsa.tokenBase64 }] },
    };
    const result = await verifyAttestation(artifacts, testDigest, credStore, {
      trustAnchorsPem: [tsa.caPem, recordTsa.caPem],
      expectedChallenge: testDigest,
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });

    expect(result.signatureValid).toBe(true);
    expect(result.timestampValid).toBe(true);
    expect(result.anchorValid).toBe(true);
    expect(result.anchorPublication).toBe('rfc3161');
    expect(result.attestationVerdict).toBe('complete');
  });
});
