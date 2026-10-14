/**
 * Who approved, and what proves it.
 *
 * Who decided is the record's hashed `payload.decider`, and
 * `custodyChain[0].actor` copies its identifier outside the digest, where an
 * ordinary storage mutation can rewrite it. These tests pin both halves:
 *
 *  - rewriting the custody actor does NOT flip verification (the custody
 *    entry is outside the digest; the decider inside it is what a reader
 *    takes as who decided);
 *  - `verifyAttestation` reports attribution via `actorBound`, which is `true`
 *    only when a WebAuthn assertion verified, was bound to THIS record's
 *    digest, and was produced by a credential registered to the account the
 *    record names (`acct:<user id>`).
 */
import { assembleEnvelope, verifyEnvelope, SchemaRegistry } from '@tzun/engine';
import { EnvelopeInput } from '@tzun/engine';
import {
  verifyAttestation,
  webauthnChallengeForDigest,
} from '../../src/attestation/verify-attestation';
import { CredentialStore } from '../../src/attestation/credential-store';
import { makeGenuineAssertion, ORIGIN, RP_ID } from './attestation-assertion-helpers';

const input: EnvelopeInput = {
  aiSystemId: 'sys-1',
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'criteria met',
  decider: { kind: 'human' as const, id: 'acct:u-jane', agent: null, credential: null, freshness: null },
};

function storeFor(credentialId: string, publicKey: string, userId: string): CredentialStore {
  const store = new CredentialStore();
  store.register({
    credentialId,
    publicKey,
    userId,
    algorithm: 'ES256',
    counter: 0,
    status: 'active',
    registeredAt: '2026-03-22T10:00:00.000Z',
  });
  return store;
}

describe('the custody actor is outside the hashed field set; the decider is inside it', () => {
  it('rewriting custodyChain[0].actor does not flip verifyEnvelope', async () => {
    // This is the finding, asserted rather than argued. A database edit of the
    // custody actor leaves every cryptographic check green.
    const registry = new SchemaRegistry();
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    expect(envelope.custodyChain[0].actor).toBe('acct:u-jane');

    const before = verifyEnvelope(envelope, undefined, registry);
    expect(before.verified).toBe(true);

    envelope.custodyChain[0].actor = 'acct:u-bob';

    const after = verifyEnvelope(envelope, undefined, registry);
    expect(after.verified).toBe(true);
    expect(after.recomputedDigest).toBe(before.recomputedDigest);
  });

  it('reports actorBound false when nothing binds the actor', async () => {
    const registry = new SchemaRegistry();
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });

    const result = await verifyAttestation(
      envelope.nonRepudiation,
      envelope.integrity.canonicalDigest,
      undefined,
      { expectedActor: envelope.custodyChain[0].actor },
    );

    expect(result.actorBound).toBe(false);
    expect(result.actorReason).toBe('no_verified_signature');
  });

  it('reports actorBound true only for a digest-bound assertion by the actor’s credential', async () => {
    const registry = new SchemaRegistry();
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const digest = envelope.integrity.canonicalDigest;
    const challenge = webauthnChallengeForDigest(digest);

    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge,
      credentialId: 'cred-jane',
    });
    const store = storeFor('cred-jane', publicKeyBase64, 'u-jane');

    const result = await verifyAttestation(
      { webauthnAssertion: assertion },
      digest,
      store,
      {
        expectedChallenge: challenge,
        expectedActor: envelope.custodyChain[0].actor,
        allowedOrigins: [ORIGIN],
        rpId: RP_ID,
      },
    );

    expect(result.signatureValid).toBe(true);
    expect(result.actorBound).toBe(true);
    expect(result.actorReason).toBeUndefined();
  });

  it('flips actorBound to false when the actor is rewritten under a genuine assertion', async () => {
    // The DBA edit again, this time against a record that DOES carry a bound
    // assertion. Verification still passes — that has not changed — but the
    // attribution claim is now visibly broken.
    const registry = new SchemaRegistry();
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const digest = envelope.integrity.canonicalDigest;
    const challenge = webauthnChallengeForDigest(digest);

    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge,
      credentialId: 'cred-jane-2',
    });
    const store = storeFor('cred-jane-2', publicKeyBase64, 'u-jane');

    envelope.custodyChain[0].actor = 'acct:u-bob';

    const result = await verifyAttestation({ webauthnAssertion: assertion }, digest, store, {
      expectedChallenge: challenge,
      expectedActor: envelope.custodyChain[0].actor,
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });

    expect(verifyEnvelope(envelope, undefined, registry).verified).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.actorBound).toBe(false);
    expect(result.actorReason).toBe('actor_mismatch');
  });

  it('never reports actorBound true just because a signature verified', async () => {
    // Without an expectedActor there is no claim to check the credential
    // against, so the answer is "unbound", not "bound".
    const registry = new SchemaRegistry();
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const digest = envelope.integrity.canonicalDigest;
    const challenge = webauthnChallengeForDigest(digest);

    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge,
      credentialId: 'cred-jane-3',
    });
    const store = storeFor('cred-jane-3', publicKeyBase64, 'u-jane');

    const result = await verifyAttestation({ webauthnAssertion: assertion }, digest, store, {
      expectedChallenge: challenge,
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });

    expect(result.signatureValid).toBe(true);
    expect(result.actorBound).toBe(false);
    expect(result.actorReason).toBe('no_expected_actor');
  });

  it('does not report actorBound true for a genuine assertion over an unrelated nonce', async () => {
    // The signature is real and the credential is jane's, but the ceremony
    // signed a login nonce, so it verifies against every record equally.
    const registry = new SchemaRegistry();
    const envelope = assembleEnvelope(input, { sequenceNumber: 1 });
    const digest = envelope.integrity.canonicalDigest;

    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge: 'a-random-login-nonce',
      credentialId: 'cred-jane-4',
    });
    const store = storeFor('cred-jane-4', publicKeyBase64, 'u-jane');

    const result = await verifyAttestation({ webauthnAssertion: assertion }, digest, store, {
      expectedActor: 'u-jane',
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });

    expect(result.signatureValid).not.toBe(true);
    expect(result.actorBound).toBe(false);
    expect(result.actorReason).toBe('no_verified_signature');
  });
});
