/**
 * The verifier records where the human signed and what kind of key signed,
 * and checks it when asked.
 *
 * The shape under test is the one the code-review sign-off design
 * produces, confirmed on real hardware on 2026-09-21: the ceremony runs on a
 * Tzun origin inside a cross-origin frame in a browser-extension side panel,
 * so `clientDataJSON` carries `crossOrigin: true` and names the extension as
 * `topOrigin`, and an iCloud Keychain passkey signs with `BE` and `BS` set.
 */
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { Tzun } from '../../src/sdk/index';
import type { CaptureInput } from '@tzun/engine';
import { verifyAttestation, webauthnChallengeForDigest } from '../../src/attestation/verify-attestation';
import { makeGenuineAssertion, storeWith, sha256hex, RP_ID } from './attestation-assertion-helpers';
import { verifyExported } from './helpers/verify-exported';

const PANEL_ORIGIN = 'https://panel.example';
const EXTENSION = 'chrome-extension://cjdhdebnabcamkngfcpipeapbpgdfjlg';
const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;

/** The shape confirmed on real hardware: framed by the extension, synced passkey. */
function sidePanelAssertion(challenge: string, credentialId = 'cred-panel', flags = UP | UV | BE | BS) {
  return makeGenuineAssertion({
    challenge,
    credentialId,
    origin: PANEL_ORIGIN,
    flags,
    clientData: { crossOrigin: true, topOrigin: EXTENSION },
  });
}

describe('verifyAttestation records the assertion provenance', () => {
  const digest = sha256hex('pr-4471-head-4f1c0a9e');
  const expectedChallenge = webauthnChallengeForDigest(digest);

  it('accepts crossOrigin: true — a framed ceremony verifies as a signature', async () => {
    const { publicKeyBase64, assertion } = sidePanelAssertion(expectedChallenge);
    const result = await verifyAttestation(
      { webauthnAssertion: assertion },
      digest,
      storeWith('cred-panel', publicKeyBase64),
      { expectedChallenge, allowedOrigins: [PANEL_ORIGIN], rpId: RP_ID },
    );

    expect(result.signatureValid).toBe(true);
    expect(result.signatureReason).toBeUndefined();
    expect(result.assertionProvenance).toMatchObject({
      origin: PANEL_ORIGIN,
      crossOrigin: true,
      topOrigin: EXTENSION,
      flags: { UP: true, UV: true, BE: true, BS: true },
      originValid: true,
    });
  });

  it('checks topOrigin against the allowlist only when one is supplied', async () => {
    const { publicKeyBase64, assertion } = sidePanelAssertion(expectedChallenge);
    const credentialStore = storeWith('cred-panel', publicKeyBase64);

    const unchecked = await verifyAttestation({ webauthnAssertion: assertion }, digest, credentialStore, {
      expectedChallenge,
    });
    expect(unchecked.assertionProvenance?.topOriginValid).toBeNull();
    expect(unchecked.assertionProvenance?.topOriginReason).toBe('top_origin_not_checked');

    const allowed = await verifyAttestation({ webauthnAssertion: assertion }, digest, credentialStore, {
      expectedChallenge,
      allowedTopOrigins: [EXTENSION],
    });
    expect(allowed.assertionProvenance?.topOriginValid).toBe(true);
    expect(allowed.assertionProvenance?.topOriginReason).toBeUndefined();
  });

  it('reports a ceremony framed by a page off the list, without failing the signature', async () => {
    const { publicKeyBase64, assertion } = makeGenuineAssertion({
      challenge: expectedChallenge,
      credentialId: 'cred-framed',
      origin: PANEL_ORIGIN,
      clientData: { crossOrigin: true, topOrigin: 'https://evil.example' },
    });
    const result = await verifyAttestation(
      { webauthnAssertion: assertion },
      digest,
      storeWith('cred-framed', publicKeyBase64),
      { expectedChallenge, allowedTopOrigins: [EXTENSION] },
    );

    expect(result.assertionProvenance?.topOrigin).toBe('https://evil.example');
    expect(result.assertionProvenance?.topOriginValid).toBe(false);
    expect(result.assertionProvenance?.topOriginReason).toBe('top_origin_not_allowed');
    // The signature is genuine and bound; where it was produced is its own finding.
    expect(result.signatureValid).toBe(true);
  });

  it('reports a synced passkey under a device-bound requirement as a lower rung, not a failure', async () => {
    const { publicKeyBase64, assertion } = sidePanelAssertion(expectedChallenge);
    const result = await verifyAttestation(
      { webauthnAssertion: assertion },
      digest,
      storeWith('cred-panel', publicKeyBase64),
      { expectedChallenge, requireDeviceBound: true },
    );

    expect(result.assertionProvenance?.deviceBound).toBe(false);
    expect(result.assertionProvenance?.deviceBoundReason).toBe('credential_synced');
    expect(result.signatureValid).toBe(true);
    expect(result.signatureReason).toBeUndefined();
    expect(result.attestationVerdict).toBe('pending');
  });

  it('confirms a device-bound key only under a verified signature', async () => {
    const { publicKeyBase64, assertion } = sidePanelAssertion(expectedChallenge, 'cred-key', UP | UV);

    const verified = await verifyAttestation(
      { webauthnAssertion: assertion },
      digest,
      storeWith('cred-key', publicKeyBase64),
      { expectedChallenge, requireDeviceBound: true },
    );
    expect(verified.assertionProvenance?.deviceBound).toBe(true);

    // No credential store: the flags byte is readable but nothing proves the
    // authenticator wrote it.
    const unverified = await verifyAttestation({ webauthnAssertion: assertion }, digest, undefined, {
      expectedChallenge,
      requireDeviceBound: true,
    });
    expect(unverified.signatureValid).toBeNull();
    expect(unverified.assertionProvenance?.flags?.BE).toBe(false);
    expect(unverified.assertionProvenance?.deviceBound).toBeNull();
    expect(unverified.assertionProvenance?.deviceBoundReason).toBe('no_verified_signature');
  });

  it('does not vouch for the provenance of an assertion that is not about this record', async () => {
    const { publicKeyBase64, assertion } = sidePanelAssertion('random-login-nonce', 'cred-nonce', UP | UV);
    const result = await verifyAttestation(
      { webauthnAssertion: assertion },
      digest,
      storeWith('cred-nonce', publicKeyBase64),
      {
        expectedChallenge,
        expectedChallengeSource: 'derived-from-digest',
        allowedOrigins: [PANEL_ORIGIN],
        allowedTopOrigins: [EXTENSION],
        requireDeviceBound: true,
      },
    );

    expect(result.signatureReason).toBe('assertion_not_bound_to_digest');
    expect(result.assertionProvenance).toMatchObject({
      originValid: null,
      originReason: 'no_verified_signature',
      topOriginValid: null,
      topOriginReason: 'no_verified_signature',
      deviceBound: null,
      deviceBoundReason: 'no_verified_signature',
    });
  });

  it('reports an origin off allowedOrigins in the provenance as well as in the signature', async () => {
    const { publicKeyBase64, assertion } = sidePanelAssertion(expectedChallenge);
    const result = await verifyAttestation(
      { webauthnAssertion: assertion },
      digest,
      storeWith('cred-panel', publicKeyBase64),
      { expectedChallenge, allowedOrigins: ['https://app.example'] },
    );

    expect(result.signatureValid).toBe(false);
    expect(result.signatureReason).toBe('untrusted_origin');
    expect(result.assertionProvenance?.originValid).toBe(false);
    expect(result.assertionProvenance?.originReason).toBe('origin_mismatch');
  });

  it('reports origin_not_checked when no allowedOrigins is supplied', async () => {
    const { publicKeyBase64, assertion } = sidePanelAssertion(expectedChallenge);
    const result = await verifyAttestation(
      { webauthnAssertion: assertion },
      digest,
      storeWith('cred-panel', publicKeyBase64),
      { expectedChallenge },
    );
    expect(result.signatureValid).toBe(true);
    expect(result.assertionProvenance?.originValid).toBeNull();
    expect(result.assertionProvenance?.originReason).toBe('origin_not_checked');
  });

  it('carries no provenance for artifacts with no assertion', async () => {
    const result = await verifyAttestation({}, digest);
    expect(result).not.toHaveProperty('assertionProvenance');
  });
});

// ---------------------------------------------------------------------------
// Tzun.verify() and Tzun.exportEvidence()
// ---------------------------------------------------------------------------

let tmpRoot: string;
beforeAll(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), 'tzun-test-'));
});
afterAll(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});
let dbSeq = 0;
const tmpDb = (name: string) => join(tmpRoot, `${name}-${dbSeq++}.db`);

const input = (reason: string): CaptureInput => ({
  aiOutput: { recommendation: 'merge', pr: 4471 },
  action: 'approved',
  reason: reason,
  decider: { kind: 'human' as const, id: 'acct:jane-acme.com', agent: null, credential: null, freshness: null },
});

/** Capture one record signed through the side panel; returns its id and key. */
async function captureSigned(tzun: Tzun, flags = UP | UV | BE | BS) {
  const captureInput = input('reviewed in the side panel');
  const prepared = await tzun.prepareAssertionChallenge(captureInput);
  const { publicKeyBase64, assertion } = sidePanelAssertion(prepared.challenge, 'cred-jane', flags);
  const result = await tzun.capture(
    { ...captureInput, attestationInputs: { webauthnAssertion: assertion } },
    { prepared },
  );
  expect(result.stored).toBe(true);
  return { evidenceId: result.envelope.payload.evidenceId, credentialStore: storeWith('cred-jane', publicKeyBase64) };
}

describe('Tzun.verify() reports the provenance of the record signature', () => {
  it('records where the reviewer signed and checks the framer and key kind it is given', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('verify') });
    try {
      const { evidenceId, credentialStore } = await captureSigned(tzun);

      const verification = await tzun.verify(evidenceId, undefined, {
        attestation: {
          credentialStore,
          allowedOrigins: [PANEL_ORIGIN],
          allowedTopOrigins: [EXTENSION],
          requireDeviceBound: true,
          rpId: RP_ID,
        },
      });

      expect(verification.verified).toBe(true);
      expect(verification.signatureValid).toBe(true);
      expect(verification.assertionProvenance).toEqual({
        origin: PANEL_ORIGIN,
        crossOrigin: true,
        topOrigin: EXTENSION,
        flags: { UP: true, UV: true, BE: true, BS: true },
        originValid: true,
        topOriginValid: true,
        deviceBound: false,
        deviceBoundReason: 'credential_synced',
      });
    } finally {
      await tzun.close();
    }
  });

  it('without a credential store, records the provenance and vouches for none of it', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('verify-no-store') });
    try {
      const { evidenceId } = await captureSigned(tzun, UP | UV);
      const verification = await tzun.verify(evidenceId, undefined, {
        attestation: { allowedTopOrigins: [EXTENSION], requireDeviceBound: true },
      });

      expect(verification.signatureValid).toBeNull();
      expect(verification.signatureReason).toBe('no_credential_store');
      expect(verification.assertionProvenance).toMatchObject({
        topOrigin: EXTENSION,
        topOriginValid: null,
        topOriginReason: 'no_verified_signature',
        deviceBound: null,
        deviceBoundReason: 'no_verified_signature',
      });
    } finally {
      await tzun.close();
    }
  });

  it('carries no provenance for a record with no assertion', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('verify-unsigned') });
    try {
      const result = await tzun.capture(input('unsigned'));
      const verification = await tzun.verify(result.envelope.payload.evidenceId);
      expect(verification).not.toHaveProperty('assertionProvenance');
    } finally {
      await tzun.close();
    }
  });
});

describe('Tzun.exportEvidence() records the provenance in the bundle', () => {
  it('records where the reviewer signed and what kind of key signed, and the offline verifier agrees', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('export') });
    try {
      const { evidenceId } = await captureSigned(tzun);
      const bundle = await tzun.exportEvidence(evidenceId);

      expect(bundle.assertionProvenance).toEqual({
        origin: PANEL_ORIGIN,
        crossOrigin: true,
        topOrigin: EXTENSION,
        flags: { UP: true, UV: true, BE: true, BS: true },
        originValid: null,
        originReason: 'origin_not_checked',
        topOriginValid: null,
        topOriginReason: 'top_origin_not_checked',
        deviceBound: null,
        deviceBoundReason: 'device_bound_not_required',
      });
      expect(await verifyExported(bundle)).toEqual({ ok: true });
    } finally {
      await tzun.close();
    }
  });

  it('runs the checks the exporter asks for; the export verifies no signature, so it vouches for none', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('export-checks') });
    try {
      const { evidenceId } = await captureSigned(tzun);
      const bundle = await tzun.exportEvidence(evidenceId, {
        assertion: { allowedTopOrigins: [EXTENSION], requireDeviceBound: true },
      });

      expect(bundle.assertionProvenance).toMatchObject({
        topOriginValid: null,
        topOriginReason: 'no_verified_signature',
        deviceBound: false,
        deviceBoundReason: 'credential_synced',
      });
    } finally {
      await tzun.close();
    }
  });

  it('records null for a record with no assertion', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('export-unsigned') });
    try {
      const result = await tzun.capture(input('unsigned'));
      const bundle = await tzun.exportEvidence(result.envelope.payload.evidenceId);
      expect(bundle.assertionProvenance).toBeNull();
    } finally {
      await tzun.close();
    }
  });

  it.each(['originValid', 'topOriginValid', 'deviceBound'] as const)(
    'the offline verifier reports a bundle that claims %s: true — an export verifies no signature',
    async (check) => {
      const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb(`export-claims-${check}`) });
      try {
        const { evidenceId } = await captureSigned(tzun);
        const bundle = await tzun.exportEvidence(evidenceId);
        (bundle.assertionProvenance as unknown as Record<string, unknown>)[check] = true;

        const verified = await verifyExported(bundle);
        expect(verified.ok).toBe(false);
        expect((verified as { errors: string[] }).errors.join('\n')).toContain(`assertionProvenance.${check}`);
      } finally {
        await tzun.close();
      }
    },
  );

  it('the offline verifier reads the flags by value, whatever order an exporter wrote their keys in', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('export-sorted') });
    try {
      const { evidenceId } = await captureSigned(tzun);
      const bundle = await tzun.exportEvidence(evidenceId);
      const { UP: up, UV: uv, BE: be, BS: bs } = bundle.assertionProvenance!.flags!;
      bundle.assertionProvenance!.flags = { BE: be, BS: bs, UP: up, UV: uv };
      expect(await verifyExported(bundle)).toEqual({ ok: true });

      bundle.assertionProvenance!.flags = { BE: be, BS: !bs, UP: up, UV: uv };
      const edited = await verifyExported(bundle);
      expect(edited.ok).toBe(false);
      expect((edited as { errors: string[] }).errors.join('\n')).toContain('assertionProvenance.flags');
    } finally {
      await tzun.close();
    }
  });

  it('the offline verifier reports a bundle whose recorded provenance disagrees with its envelope', async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: tmpDb('export-edited') });
    try {
      const { evidenceId } = await captureSigned(tzun);
      const bundle = await tzun.exportEvidence(evidenceId);
      bundle.assertionProvenance!.topOrigin = 'chrome-extension://someone-else';

      const verified = await verifyExported(bundle);
      expect(verified.ok).toBe(false);
      expect((verified as { errors: string[] }).errors.join('\n')).toContain('assertionProvenance');
    } finally {
      await tzun.close();
    }
  });
});
