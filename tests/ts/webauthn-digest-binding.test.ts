/**
 * The capture half of WebAuthn digest binding — the WebAuthn ceremony must
 * sign the record, and `verify()` must check that it did.
 *
 * `verifyAttestation` refuses to report `signatureValid: true` without an
 * `expectedChallenge`, and `webauthnChallengeForDigest()` derives that
 * challenge from a record's canonical digest. These tests pin what makes a
 * bound assertion reachable and checked:
 *
 *   - `TzunWebAuthn.startAuthentication()` derives the ceremony challenge from
 *     a digest (or takes an explicit challenge) and refuses a ceremony with
 *     neither. A ceremony over a random nonce would produce an assertion
 *     bound to nothing;
 *   - capture counts an assertion as a signature only when its challenge is
 *     bound to the record's digest. Counting it by PRESENCE would let a login
 *     nonce promote a record to `attestationStatus: 'partial'`;
 *   - `Tzun.verify()` calls `verifyAttestation`, so the signature and its
 *     binding are checked at rest.
 *
 * The ordering these tests pin: build the record → derive the challenge from
 * its canonical digest → run the ceremony → attach → store.
 */
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Tzun } from '../../src/sdk/index';
import { CaptureInput } from '@tzun/engine';
import { TzunWebAuthn } from '../../src/attestation/webauthn';
import { webauthnChallengeForDigest, verifyAttestation } from '../../src/attestation/verify-attestation';
import { makeGenuineAssertion, storeWith, ORIGIN, RP_ID } from './attestation-assertion-helpers';

let tmpRoot: string;
beforeAll(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), 'tzun-test-'));
});
afterAll(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});
let dbSeq = 0;
const tmpDb = (name: string) => join(tmpRoot, `${name}-${dbSeq++}.db`);

function logSink() {
  const lines: Array<[string, Record<string, unknown>]> = [];
  return { lines, onLog: (event: string, fields: Record<string, unknown>) => lines.push([event, fields]) };
}

const input = (reason: string): CaptureInput => ({
  aiOutput: { recommendation: 'approve', confidence: 0.91 },
  action: 'approved',
  reason: reason,
  decider: { kind: 'human' as const, id: 'acct:jane-acme.com', agent: null, credential: null, freshness: null },
});

// ---------------------------------------------------------------------------
// 1. The ceremony
// ---------------------------------------------------------------------------

describe('the ceremony challenge is derived from the record digest', () => {
  it('startAuthentication binds the ceremony to a digest', async () => {
    // Without a challenge input, `generateAuthenticationOptions` invents a
    // random nonce: the reviewer would sign a login, and the assertion would
    // verify against every record equally.
    const wa = new TzunWebAuthn(
      { rpID: RP_ID, origin: ORIGIN },
      storeWith('cred-jane', 'irrelevant-for-options'),
    );

    const digest = 'a'.repeat(64);
    const options = await wa.startAuthentication('cred-jane', { digest });

    expect(options.challenge).toBe(webauthnChallengeForDigest(digest));
  });

  it('refuses a ceremony with neither a digest nor an explicit challenge', async () => {
    const wa = new TzunWebAuthn({ rpID: RP_ID, origin: ORIGIN }, storeWith('cred-x', 'k'));

    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (wa as any).startAuthentication('cred-x', {}),
    ).rejects.toThrow(/digest|challenge/i);
  });
});

// ---------------------------------------------------------------------------
// 2. The capture ordering: build → derive → sign → attach
// ---------------------------------------------------------------------------

describe('prepareAssertionChallenge gives the ceremony the record it must sign', () => {
  it('returns the digest the capture will carry, and its derived challenge', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('prepare') });
    try {
      const captureInput = input('meets policy');
      const prepared = await tzun.prepareAssertionChallenge(captureInput);

      expect(prepared.challenge).toBe(webauthnChallengeForDigest(prepared.digest));
      expect(prepared.sequenceNumber).toBe(1);
      expect(prepared.previousDigest).toBeNull();

      // The whole point: the record actually stored carries the digest the
      // ceremony was told to sign. Without `prepared` the evidenceId and
      // capturedAt are minted fresh per capture, so the digest moves.
      const result = await tzun.capture(captureInput, { prepared });
      expect(result.stored).toBe(true);
      expect(result.envelope.integrity.canonicalDigest).toBe(prepared.digest);
      expect(result.envelope.payload.evidenceId).toBe(prepared.evidenceId);
    } finally {
      await tzun.close();
    }
  });

  it('a bound assertion is counted as a signature; verify() confirms it', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('bound') });
    try {
      const captureInput = input('bound ceremony');
      const prepared = await tzun.prepareAssertionChallenge(captureInput);

      const { publicKeyBase64, assertion } = makeGenuineAssertion({
        challenge: prepared.challenge,
        credentialId: 'cred-jane',
      });
      const credentialStore = storeWith('cred-jane', publicKeyBase64);

      const result = await tzun.capture(
        { ...captureInput, attestationInputs: { webauthnAssertion: assertion } },
        { prepared },
      );
      expect(result.stored).toBe(true);
      expect(result.envelope.attestationStatus).toBe('partial');

      const verification = await tzun.verify(result.envelope.payload.evidenceId, undefined, {
        attestation: { credentialStore, allowedOrigins: [ORIGIN], rpId: RP_ID },
      });
      expect(verification.verified).toBe(true);
      expect(verification.signatureValid).toBe(true);
      expect(verification.signatureReason).toBeUndefined();
      expect(verification.credentialStatus).toBe('active');
    } finally {
      await tzun.close();
    }
  });

  it('refuses a prepared capture whose record moved under it', async () => {
    // Prepare against an empty chain, let another writer take sequence 1, then
    // capture: the rebuilt record has a different digest, so the ceremony the
    // reviewer performed signed a record that will never exist. Storing the
    // assertion anyway would attach a signature to a record it is not about;
    // the honest answer is the same refusal the CAS path gives.
    const dbPath = tmpDb('prepared-moved');
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const b = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const captureInput = input('prepared then lost the race');
      const prepared = await b.prepareAssertionChallenge(captureInput);
      expect((await a.capture(input('from-a'))).stored).toBe(true);

      const { assertion } = makeGenuineAssertion({
        challenge: prepared.challenge,
        credentialId: 'cred-jane',
      });
      const rb = await b.capture(
        { ...captureInput, attestationInputs: { webauthnAssertion: assertion } },
        { prepared },
      );

      expect(rb.stored).toBe(false);
      expect(rb.failure?.diagnosticMetadata.retryRefused).toBe('caller_attestation_is_digest_bound');
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('refuses before storing when the head moved inside this process', async () => {
    // Same hazard, the cheap way round: this writer itself captured something
    // else between prepare and capture. The rebuilt record sits one position
    // later, so its digest is not the one the reviewer signed, and the SDK can
    // see that before it ever asks the store — no CAS refusal involved.
    const log = logSink();
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('prepared-local-move'), onLog: log.onLog });
    try {
      const captureInput = input('prepared, then jumped');
      const prepared = await tzun.prepareAssertionChallenge(captureInput);
      expect((await tzun.capture(input('an unrelated decision'))).stored).toBe(true);

      const { assertion } = makeGenuineAssertion({
        challenge: prepared.challenge,
        credentialId: 'cred-jane',
      });
      const r = await tzun.capture(
        { ...captureInput, attestationInputs: { webauthnAssertion: assertion } },
        { prepared },
      );

      expect(r.stored).toBe(false);
      expect(r.failure?.failureType).toBe('chain_conflict');
      expect(r.failure?.diagnosticMetadata.retryRefused).toBe('caller_attestation_is_digest_bound');

      const moved = log.lines.filter(([e]) => e === 'capture_prepared_record_moved');
      expect(moved).toHaveLength(1);
      expect(moved[0][1]).toMatchObject({
        preparedDigest: prepared.digest,
        preparedSequence: 1,
        actualSequence: 2,
      });

      // Only the unrelated decision is in the store.
      const stored = await tzun.list();
      expect(stored.map((r) => r.envelope.payload.reason)).toEqual(['an unrelated decision']);
    } finally {
      await tzun.close();
    }
  });
});

describe('an unbound assertion is not counted as a signature', () => {
  it('stores the artifact but does not promote the record to partial', async () => {
    // A login-nonce assertion passed straight through to capture(). Recording
    // it as `attestationStatus: 'partial'` would make a record that claims a
    // human signed it, over a challenge unrelated to it.
    const log = logSink();
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('unbound'), onLog: log.onLog });
    try {
      const { assertion } = makeGenuineAssertion({
        challenge: 'random-login-nonce-not-a-digest',
        credentialId: 'cred-jane',
      });

      const result = await tzun.capture({
        ...input('unbound passthrough'),
        attestationInputs: { webauthnAssertion: assertion },
      });

      expect(result.stored).toBe(true);
      // The artifact is preserved verbatim — deleting it would destroy
      // evidence — it just does not count as non-repudiation.
      expect(result.envelope.nonRepudiation.webauthnAssertion).toEqual(assertion);
      expect(result.envelope.attestationStatus).toBe('none');

      const said = log.lines.filter(([e]) => e === 'capture_assertion_not_bound_to_digest');
      expect(said).toHaveLength(1);
      expect(said[0][1]).toMatchObject({ reason: 'challenge_mismatch' });
    } finally {
      await tzun.close();
    }
  });

  it('refuses the capture outright when webauthn is a REQUIRED attestation', async () => {
    const tzun = await Tzun.init({
      mode: 'dev',
      dbPath: tmpDb('unbound-required'),
      attestation: { require: ['webauthn'] },
    });
    try {
      const { assertion } = makeGenuineAssertion({
        challenge: 'random-login-nonce-not-a-digest',
        credentialId: 'cred-jane',
      });

      const result = await tzun.capture({
        ...input('required webauthn, unbound assertion'),
        attestationInputs: { webauthnAssertion: assertion },
      });

      expect(result.stored).toBe(false);
      expect(result.failure?.failureType).toBe('attestation_failure');
      expect(result.failure?.diagnosticMetadata.missingServices).toEqual(['webauthn']);
    } finally {
      await tzun.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Verification at rest
// ---------------------------------------------------------------------------

describe('verify() checks the assertion instead of ignoring it', () => {
  it('a ceremony bound to record A does not verify against record B', async () => {
    // The attack, end to end through the product surface. Capture two records;
    // take the genuine, correctly-bound assertion from A and staple it onto B.
    const dbPath = tmpDb('replay');
    const tzun = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const inputA = input('record A');
      const preparedA = await tzun.prepareAssertionChallenge(inputA);
      const { publicKeyBase64, assertion } = makeGenuineAssertion({
        challenge: preparedA.challenge,
        credentialId: 'cred-jane',
      });
      const credentialStore = storeWith('cred-jane', publicKeyBase64);

      const a = await tzun.capture(
        { ...inputA, attestationInputs: { webauthnAssertion: assertion } },
        { prepared: preparedA },
      );
      expect(a.stored).toBe(true);

      // Record B, captured honestly, then tampered at rest: A's assertion
      // attached to B. This is a store-write attacker; a verifier that checked
      // the signature but not its binding would certify it `signatureValid: true`.
      const b = await tzun.capture(input('record B'));
      const storage = tzun.getStorage();
      const envB = (await storage.retrieve(b.envelope.payload.evidenceId))!;
      await storage.updateAttestation(
        envB.payload.evidenceId,
        { webauthnAssertion: assertion },
        'partial',
      );

      const vb = await tzun.verify(b.envelope.payload.evidenceId, undefined, {
        attestation: { credentialStore, allowedOrigins: [ORIGIN], rpId: RP_ID },
      });
      expect(vb.signatureValid).not.toBe(true);
      expect(vb.signatureReason).toBe('assertion_not_bound_to_digest');

      // And A, the record the ceremony was actually for, still verifies.
      const va = await tzun.verify(a.envelope.payload.evidenceId, undefined, {
        attestation: { credentialStore, allowedOrigins: [ORIGIN], rpId: RP_ID },
      });
      expect(va.signatureValid).toBe(true);
    } finally {
      await tzun.close();
    }
  });

  it('a verifier told what to expect calls the replay a challenge_mismatch', async () => {
    // Same attack at the `verifyAttestation` layer, where the caller ASSERTS
    // the expected challenge (the scanner's mode via `expectedChallengeFor`).
    // There the verdict is the sharper one: false, not null.
    const digestA = 'a'.repeat(64);
    const digestB = 'b'.repeat(64);
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge: webauthnChallengeForDigest(digestA),
      credentialId: 'cred-jane',
    });
    const credentialStore = storeWith('cred-jane', publicKeyBase64);

    const r = await verifyAttestation({ webauthnAssertion: assertion }, digestB, credentialStore, {
      expectedChallenge: webauthnChallengeForDigest(digestB),
      allowedOrigins: [ORIGIN],
      rpId: RP_ID,
    });
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('challenge_mismatch');
  });

  it('a legacy unbound assertion is reported unbound, not tampered', async () => {
    // Backwards compatibility. A record captured before 0.3.16 can carry an
    // assertion over a login nonce. Verification must read that as "this
    // artifact binds nothing", never as a failed record: the decision, its
    // digest and its chain link are all intact.
    const dbPath = tmpDb('legacy');
    const tzun = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const { publicKeyBase64, assertion } = makeGenuineAssertion({
        challenge: 'random-login-nonce-not-a-digest',
        credentialId: 'cred-jane',
      });
      const credentialStore = storeWith('cred-jane', publicKeyBase64);

      const r = await tzun.capture(input('legacy record'));
      const storage = tzun.getStorage();
      await storage.updateAttestation(
        r.envelope.payload.evidenceId,
        { webauthnAssertion: assertion },
        'partial',
      );

      const v = await tzun.verify(r.envelope.payload.evidenceId, undefined, {
        attestation: { credentialStore, allowedOrigins: [ORIGIN], rpId: RP_ID },
      });
      expect(v.verified).toBe(true);
      expect(v.signatureValid).toBeNull();
      expect(v.signatureReason).toBe('assertion_not_bound_to_digest');
    } finally {
      await tzun.close();
    }
  });

  it('without a credential store, verify() reports what it cannot check — never a pass', async () => {
    const dbPath = tmpDb('no-store');
    const tzun = await Tzun.init({ mode: 'dev', dbPath });
    try {
      const captureInput = input('bound but unverifiable here');
      const prepared = await tzun.prepareAssertionChallenge(captureInput);
      const { assertion } = makeGenuineAssertion({
        challenge: prepared.challenge,
        credentialId: 'cred-jane',
      });

      const r = await tzun.capture(
        { ...captureInput, attestationInputs: { webauthnAssertion: assertion } },
        { prepared },
      );

      const v = await tzun.verify(r.envelope.payload.evidenceId);
      expect(v.signatureValid).not.toBe(true);
      expect(v.signatureValid).toBeNull();
      expect(v.signatureReason).toBe('no_credential_store');
    } finally {
      await tzun.close();
    }
  });

  it('catches a replay with no key material at all', async () => {
    // The binding is checkable without the credential store: the challenge is
    // a pure function of the digest. A verifier that holds no keys can still
    // say "this assertion is not about this record".
    const digestA = 'a'.repeat(64);
    const { assertion } = makeGenuineAssertion({
      challenge: webauthnChallengeForDigest(digestA),
      credentialId: 'cred-jane',
    });

    const r = await verifyAttestation({ webauthnAssertion: assertion }, 'b'.repeat(64), undefined, {
      expectedChallenge: webauthnChallengeForDigest('b'.repeat(64)),
    });
    expect(r.signatureValid).toBe(false);
    expect(r.signatureReason).toBe('challenge_mismatch');
  });

  it('leaves a record with no assertion exactly as it was', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('no-assertion') });
    try {
      const r = await tzun.capture(input('no ceremony at all'));
      const v = await tzun.verify(r.envelope.payload.evidenceId);
      expect(v.verified).toBe(true);
      expect(v.signatureValid).toBeNull();
      expect(v.signatureReason).toBeUndefined();
    } finally {
      await tzun.close();
    }
  });
});
