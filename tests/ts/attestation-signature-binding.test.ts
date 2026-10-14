/**
 * Tests for the attestation signature checks in
 * `src/attestation/verify-attestation.ts`.
 *
 * Two properties: credential status alone is never reported as a signature
 * verdict, and an assertion counts only when its challenge is bound to the
 * evidence digest.
 */
import {
  verifyAttestation,
  webauthnChallengeForDigest,
} from '../../src/attestation/verify-attestation';
import { AttestationArtifacts } from '@tzun/engine';
import { makeGenuineAssertion, storeWith, sha256hex, ORIGIN, RP_ID } from './attestation-assertion-helpers';

describe('an assertion with nothing to verify is not a verified signature', () => {
  const digest = sha256hex('test-evidence');

  it('does not report signatureValid true for a one-character signature with no authenticatorData', async () => {
    // `signature: 'x'` with no authenticatorData gives no cryptographic
    // operation anything to check, so the answer must be 'unverifiable', not
    // "is this credential id currently unrevoked?". If status alone counted as
    // `signatureValid`, anyone who could write `nonRepudiation` — an SDK cloud
    // caller, the demo passthrough, a DB writer — could mint non-repudiation
    // evidence for a reviewer who never touched the record.
    const credStore = storeWith('cred-active', 'irrelevant-public-key');

    const artifacts: AttestationArtifacts = {
      webauthnAssertion: { signature: 'x', credentialKeyId: 'cred-active', algorithm: 'ES256' },
    };

    const result = await verifyAttestation(artifacts, digest, credStore);

    expect(result.signatureValid).not.toBe(true);
    expect(result.signatureValid).toBe(false);
    expect(result.signatureReason).toBe('unverifiable_assertion');
    // The credential really is active. That fact is still reported, as
    // credential status, never as a signature verdict.
    expect(result.credentialStatus).toBe('active');
  });

  it('does not let an unverifiable assertion count toward attestationVerdict', async () => {
    // A signature that cannot be checked must not push the record from 'none'
    // to 'pending'; 'pending' means "signed, awaiting timestamp and anchor".
    const credStore = storeWith('cred-active-2', 'irrelevant-public-key');

    const result = await verifyAttestation(
      { webauthnAssertion: { signature: 'zzz', credentialKeyId: 'cred-active-2', algorithm: 'ES256' } },
      digest,
      credStore,
    );

    expect(result.attestationVerdict).toBe('none');
  });

  it('reports an unverifiable assertion as such even when clientDataJSON is present but authenticatorData is not', async () => {
    const credStore = storeWith('cred-half', 'irrelevant-public-key');
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: digest, origin: ORIGIN }),
    ).toString('base64');

    const result = await verifyAttestation(
      {
        webauthnAssertion: {
          signature: 'x',
          credentialKeyId: 'cred-half',
          algorithm: 'ES256',
          clientDataJSON,
        },
      },
      digest,
      credStore,
    );

    expect(result.signatureValid).toBe(false);
    expect(result.signatureReason).toBe('unverifiable_assertion');
  });
});

describe('a genuine assertion over an unrelated challenge binds nothing', () => {
  const digestA = sha256hex('loan-application-4471-APPROVED');
  const digestB = sha256hex('loan-application-9902-DENIED');

  it('does not report signatureValid true for an assertion signed over a login nonce', async () => {
    // A ceremony whose challenge comes from generateAuthenticationOptions — a
    // random nonce — has the reviewer sign a login, not a decision, so the
    // signature binds nothing about this record.
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge: 'random-login-nonce-not-a-digest',
      credentialId: 'reviewer-key',
    });
    const credStore = storeWith('reviewer-key', publicKeyBase64);

    const result = await verifyAttestation({ webauthnAssertion: assertion }, digestA, credStore);

    expect(result.signatureValid).not.toBe(true);
    expect(result.signatureValid).toBeNull();
    expect(result.signatureReason).toBe('assertion_not_bound_to_digest');
    expect(result.attestationVerdict).toBe('none');
  });

  it('does not verify one reviewer assertion against a second, unrelated record', async () => {
    // The attack in one test: capture a reviewer's assertion once, attach it to
    // a decision they never saw. Neither record may report signatureValid
    // true, or the reviewer's key id would stand as non-repudiation evidence
    // for a decision they never signed.
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge: 'random-login-nonce-not-a-digest',
      credentialId: 'reviewer-key-2',
    });
    const credStore = storeWith('reviewer-key-2', publicKeyBase64);

    for (const digest of [digestA, digestB]) {
      const result = await verifyAttestation({ webauthnAssertion: assertion }, digest, credStore);
      expect(result.signatureValid).not.toBe(true);
    }
  });

  it('reports signatureValid true only when the challenge is derived from the digest', async () => {
    // Guards against over-correction: a properly bound ceremony must still
    // verify, or the whole mechanism is dead.
    const expectedChallenge = webauthnChallengeForDigest(digestA);
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge: expectedChallenge,
      credentialId: 'bound-key',
    });
    const credStore = storeWith('bound-key', publicKeyBase64);

    const bound = await verifyAttestation({ webauthnAssertion: assertion }, digestA, credStore, {
      expectedChallenge,
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });
    expect(bound.signatureValid).toBe(true);
    expect(bound.signatureReason).toBeUndefined();
    expect(bound.attestationVerdict).toBe('pending');

    // The very same assertion, checked against a different record, is rejected.
    const reused = await verifyAttestation({ webauthnAssertion: assertion }, digestB, credStore, {
      expectedChallenge: webauthnChallengeForDigest(digestB),
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });
    expect(reused.signatureValid).toBe(false);
    expect(reused.signatureReason).toBe('challenge_mismatch');
  });

  it('derives a distinct, digest-dependent challenge', () => {
    expect(webauthnChallengeForDigest(digestA)).not.toBe(webauthnChallengeForDigest(digestB));
    expect(webauthnChallengeForDigest(digestA)).toBe(webauthnChallengeForDigest(digestA));
    // base64url: no +, / or = characters, so it drops straight into clientDataJSON.
    expect(webauthnChallengeForDigest(digestA)).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe('the verifier reads clientDataJSON and authenticatorData', () => {
  const digest = sha256hex('a-decision');
  const challenge = webauthnChallengeForDigest(digest);

  /** Verify a genuine assertion built with `overrides`, fully bound. */
  async function check(
    overrides: Partial<Parameters<typeof makeGenuineAssertion>[0]>,
    opts: Record<string, unknown> = {},
  ) {
    const credentialId = 'cred-' + Math.random().toString(36).slice(2);
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge,
      credentialId,
      ...overrides,
    });
    return verifyAttestation({ webauthnAssertion: assertion }, digest, storeWith(credentialId, publicKeyBase64), {
      expectedChallenge: challenge,
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
      ...opts,
    });
  }

  it('rejects a registration ceremony replayed as an assertion', async () => {
    // clientDataJSON.type must be 'webauthn.get': a 'webauthn.create'
    // ceremony is a registration, not an approval.
    const r = await check({ type: 'webauthn.create' });
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('wrong_client_data_type');
  });

  it('rejects an assertion from an origin outside allowedOrigins', async () => {
    const r = await check({ origin: 'https://evil.example' });
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('untrusted_origin');
  });

  it('rejects an assertion scoped to a different relying party', async () => {
    const r = await check({ rpId: 'attacker.example' });
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('rp_id_mismatch');
  });

  it('rejects an assertion with the User Present flag clear', async () => {
    // Flags 0x00: the authenticator reports no human interaction. A record of a
    // human approving something must not be built out of one of these.
    const r = await check({ flags: 0x00 });
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('user_not_present');
  });

  it('rejects authenticatorData shorter than the mandatory 37 bytes', async () => {
    const credStore = storeWith('short-authdata', 'key');
    const r = await verifyAttestation(
      {
        webauthnAssertion: {
          signature: 'AAAA',
          credentialKeyId: 'short-authdata',
          algorithm: 'ES256',
          // A placeholder-shaped value: a 33-byte ASCII string.
          authenticatorData: Buffer.from('mock-authenticator-data-32-bytes!').toString('base64'),
          clientDataJSON: Buffer.from(
            JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN }),
          ).toString('base64'),
        },
      },
      digest,
      credStore,
      { expectedChallenge: challenge },
    );
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('malformed_authenticator_data');
  });

  it('rejects clientDataJSON that is not decodable JSON', async () => {
    const credStore = storeWith('bad-clientdata', 'key');
    const r = await verifyAttestation(
      {
        webauthnAssertion: {
          signature: 'AAAA',
          credentialKeyId: 'bad-clientdata',
          algorithm: 'ES256',
          authenticatorData: Buffer.alloc(37, 1).toString('base64'),
          clientDataJSON: Buffer.from('this is not json').toString('base64'),
        },
      },
      digest,
      credStore,
      { expectedChallenge: challenge },
    );
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('malformed_client_data');
  });

  it('rejects a genuine signature made by a revoked credential', async () => {
    // A genuine signature is not enough: the verdict also consults credential
    // status, so a revoked key's genuine signature does not read as a valid one.
    const { publicKeyBase64, assertion } = makeGenuineAssertion({ challenge, credentialId: 'revoked-key' });
    const credStore = storeWith('revoked-key', publicKeyBase64, 'revoked');

    const r = await verifyAttestation({ webauthnAssertion: assertion }, digest, credStore, {
      expectedChallenge: challenge,
    });
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('revoked_credential');
    expect(r.credentialStatus).toBe('revoked');
  });
});
