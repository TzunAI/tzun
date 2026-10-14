/**
 * Where the human signed, and with what kind of key.
 *
 * The first fixture is reconstructed from the fields recorded for one sign-off
 * run (macOS, Chrome 154, iCloud Keychain passkey) through the Tzun-origin
 * iframe inside a browser extension's side panel: a cross-origin ceremony
 * framed by a `chrome-extension://` page, signed by a synced passkey. The run
 * recorded the parsed `clientDataJSON` members and the four flags, not the
 * bytes, so `clientDataJSON` is those members re-serialized and
 * `authenticatorData` is synthesized for the run's RP ID, `localhost`. There
 * is no signature.
 */
import { createHash } from 'crypto';
import { assertionProvenance } from './assertion-provenance';
import type { AttestationArtifacts } from './types/evidence';

type Assertion = NonNullable<AttestationArtifacts['webauthnAssertion']>;

const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;

const PANEL_ORIGIN = 'http://localhost:17893';
const EXTENSION = 'chrome-extension://cjdhdebnabcamkngfcpipeapbpgdfjlg';

function authData(flags: number, rpId = 'localhost'): string {
  return Buffer.concat([
    createHash('sha256').update(rpId, 'utf8').digest(),
    Buffer.from([flags]),
    Buffer.from([0, 0, 0, 7]),
  ]).toString('base64');
}

function clientData(fields: Record<string, unknown>, encoding: BufferEncoding = 'base64'): string {
  return Buffer.from(JSON.stringify(fields), 'utf8').toString(encoding);
}

function assertion(over: Partial<Assertion> = {}): Assertion {
  return {
    signature: 'c2lnbmF0dXJl',
    credentialKeyId: 'cred-1',
    algorithm: 'ES256',
    ...over,
  };
}

/** The extension run as recorded: framed by the extension, synced passkey, UP/UV/BE/BS all set. */
const danaRun = assertion({
  clientDataJSON: clientData({
    type: 'webauthn.get',
    challenge: 'z6vWQ94pDixn-eZz7Ycgx8QKsSwjIncqUyTpmdSiDBw',
    origin: PANEL_ORIGIN,
    crossOrigin: true,
    topOrigin: EXTENSION,
  }),
  authenticatorData: authData(UP | UV | BE | BS),
});

/** A top-level ceremony on the panel origin, from a device-bound security key. */
const securityKeyRun = assertion({
  clientDataJSON: clientData({
    type: 'webauthn.get',
    challenge: 'abc',
    origin: PANEL_ORIGIN,
    crossOrigin: false,
  }),
  authenticatorData: authData(UP | UV),
});

describe('what the assertion states is recorded', () => {
  it('records origin, crossOrigin, topOrigin and the four flags of the extension run', () => {
    const p = assertionProvenance(danaRun);
    expect(p.origin).toBe(PANEL_ORIGIN);
    expect(p.crossOrigin).toBe(true);
    expect(p.topOrigin).toBe(EXTENSION);
    expect(p.flags).toEqual({ UP: true, UV: true, BE: true, BS: true });
  });

  it.each([
    ['UP', UP],
    ['UV', UV],
    ['BE', BE],
    ['BS', BS],
  ] as const)('reads %s from its own bit of the flags byte (WebAuthn L3 §6.1)', (name, bit) => {
    const p = assertionProvenance(assertion({ authenticatorData: authData(bit) }));
    expect(p.flags).toEqual({ UP: false, UV: false, BE: false, BS: false, [name]: true });
  });

  it('reads none of the four from the RFU, AT and ED bits', () => {
    const p = assertionProvenance(assertion({ authenticatorData: authData(0x02 | 0x20 | 0x40 | 0x80) }));
    expect(p.flags).toEqual({ UP: false, UV: false, BE: false, BS: false });
  });

  it('reads base64url clientDataJSON, as a browser returns it, the same as base64', () => {
    const fields = {
      type: 'webauthn.get',
      challenge: 'z6vWQ94pDixn-eZz7Ycgx8QKsSwjIncqUyTpmdSiDBw',
      origin: 'https://panel.example',
      crossOrigin: true,
      topOrigin: 'chrome-extension://pfdlpfencoofghoglkocjbbhoogghfee',
    };
    const a = assertionProvenance(assertion({ clientDataJSON: clientData(fields, 'base64url') }));
    const b = assertionProvenance(assertion({ clientDataJSON: clientData(fields, 'base64') }));
    expect(a).toEqual(b);
    expect(a.topOrigin).toBe(fields.topOrigin);
  });

  it('records no flags for authenticatorData shorter than 37 bytes, or none at all', () => {
    const short = Buffer.alloc(36, 0xff).toString('base64');
    expect(assertionProvenance(assertion({ authenticatorData: short })).flags).toBeNull();
    expect(assertionProvenance(assertion()).flags).toBeNull();
  });

  it('records null for a field the assertion states in the wrong type', () => {
    const p = assertionProvenance(
      assertion({
        clientDataJSON: clientData({
          type: 'webauthn.get',
          challenge: 'x',
          origin: 42,
          crossOrigin: 'true',
          topOrigin: ['chrome-extension://x'],
        }),
      }),
    );
    expect(p.origin).toBeNull();
    expect(p.crossOrigin).toBeNull();
    expect(p.topOrigin).toBeNull();
  });

  it.each([
    ['absent', undefined],
    ['not JSON', Buffer.from('not json').toString('base64')],
    ['a JSON array', clientData([] as unknown as Record<string, unknown>)],
    ['JSON null', Buffer.from('null').toString('base64')],
  ])('records nothing from clientDataJSON that is %s', (_label, value) => {
    const p = assertionProvenance(assertion({ clientDataJSON: value }));
    expect(p.origin).toBeNull();
    expect(p.crossOrigin).toBeNull();
    expect(p.topOrigin).toBeNull();
  });

  it('records a lone UTF-16 surrogate in origin or topOrigin as U+FFFD', () => {
    // JSON.parse keeps a lone surrogate escape; a store that rejects one (a
    // Postgres jsonb column) or a serializer that does (pydantic's
    // model_dump_json) could then not hold the verdict. The raw
    // clientDataJSON is still in the envelope.
    const json = '{"type":"webauthn.get","challenge":"x","origin":"https://panel.example\\ud800",' +
      '"crossOrigin":true,"topOrigin":"\\udc00chrome-extension://x\\ud83d\\ude00"}';
    const p = assertionProvenance(
      assertion({ clientDataJSON: Buffer.from(json, 'utf8').toString('base64') }),
    );
    expect(p.origin).toBe('https://panel.example\uFFFD');
    expect(p.topOrigin).toBe('\uFFFDchrome-extension://x\u{1F600}');
  });

  it('never throws on artifacts JSON never promised the shape of', () => {
    for (const bad of [null, undefined, 7, 'x', [], { clientDataJSON: 5, authenticatorData: {} }]) {
      expect(() => assertionProvenance(bad as unknown as Assertion)).not.toThrow();
      const p = assertionProvenance(bad as unknown as Assertion);
      expect(p.origin).toBeNull();
      expect(p.flags).toBeNull();
    }
  });
});

describe('the origin check', () => {
  it('says it was not checked when no allowedOrigins is supplied — never a pass', () => {
    const p = assertionProvenance(danaRun, { signatureVerified: true });
    expect(p.originValid).toBeNull();
    expect(p.originReason).toBe('origin_not_checked');
  });

  it('is true for an allowed origin under a verified signature', () => {
    const p = assertionProvenance(danaRun, { allowedOrigins: [PANEL_ORIGIN], signatureVerified: true });
    expect(p.originValid).toBe(true);
    expect(p.originReason).toBeUndefined();
  });

  it('does not vouch for an allowed origin that no verified signature covers', () => {
    const p = assertionProvenance(danaRun, { allowedOrigins: [PANEL_ORIGIN] });
    expect(p.originValid).toBeNull();
    expect(p.originReason).toBe('no_verified_signature');
  });

  it('reports origin_mismatch for an origin not on the list, signature or not', () => {
    for (const signatureVerified of [true, false]) {
      const p = assertionProvenance(danaRun, {
        allowedOrigins: ['https://panel.example'],
        signatureVerified,
      });
      expect(p.originValid).toBe(false);
      expect(p.originReason).toBe('origin_mismatch');
    }
  });

  it('reports origin_mismatch when the assertion states no origin at all', () => {
    const p = assertionProvenance(assertion(), { allowedOrigins: [PANEL_ORIGIN], signatureVerified: true });
    expect(p.originValid).toBe(false);
    expect(p.originReason).toBe('origin_mismatch');
  });
});

describe('the topOrigin check', () => {
  it('says it was not checked when no allowedTopOrigins is supplied', () => {
    const p = assertionProvenance(danaRun, { signatureVerified: true });
    expect(p.topOriginValid).toBeNull();
    expect(p.topOriginReason).toBe('top_origin_not_checked');
  });

  it('accepts a cross-origin ceremony framed by an allowed page', () => {
    const p = assertionProvenance(danaRun, { allowedTopOrigins: [EXTENSION], signatureVerified: true });
    expect(p.topOriginValid).toBe(true);
    expect(p.topOriginReason).toBeUndefined();
  });

  it('reports top_origin_not_allowed for a ceremony a page off the list framed', () => {
    const framed = assertion({
      clientDataJSON: clientData({
        type: 'webauthn.get',
        challenge: 'x',
        origin: PANEL_ORIGIN,
        crossOrigin: true,
        topOrigin: 'https://evil.example',
      }),
    });
    for (const signatureVerified of [true, false]) {
      const p = assertionProvenance(framed, { allowedTopOrigins: [EXTENSION], signatureVerified });
      expect(p.topOriginValid).toBe(false);
      expect(p.topOriginReason).toBe('top_origin_not_allowed');
    }
  });

  it('reports top_origin_unknown for a cross-origin ceremony that names no top-level origin', () => {
    const framed = assertion({
      clientDataJSON: clientData({ type: 'webauthn.get', challenge: 'x', origin: PANEL_ORIGIN, crossOrigin: true }),
    });
    const p = assertionProvenance(framed, { allowedTopOrigins: [EXTENSION], signatureVerified: true });
    expect(p.topOriginValid).toBe(false);
    expect(p.topOriginReason).toBe('top_origin_unknown');
  });

  it('reports top_origin_unknown when the assertion does not say whether it was framed', () => {
    const silent = assertion({
      clientDataJSON: clientData({ type: 'webauthn.get', challenge: 'x', origin: PANEL_ORIGIN }),
    });
    const p = assertionProvenance(silent, { allowedTopOrigins: [EXTENSION], signatureVerified: true });
    expect(p.topOriginValid).toBe(false);
    expect(p.topOriginReason).toBe('top_origin_unknown');
  });

  it('checks a top-level ceremony\'s own origin against the list: it is its own top-level page', () => {
    // crossOrigin: false means same-origin with every ancestor, so the
    // top-level page is `origin`. A ceremony run in a tab on a page off the
    // list is not one run inside the listed framer.
    for (const signatureVerified of [true, false]) {
      const p = assertionProvenance(securityKeyRun, { allowedTopOrigins: [EXTENSION], signatureVerified });
      expect(p.topOriginValid).toBe(false);
      expect(p.topOriginReason).toBe('top_origin_not_allowed');
    }
  });

  it('accepts a top-level ceremony whose origin is on the list', () => {
    const allowedTopOrigins = [EXTENSION, PANEL_ORIGIN];
    const p = assertionProvenance(securityKeyRun, { allowedTopOrigins, signatureVerified: true });
    expect(p.topOriginValid).toBe(true);
    expect(p.topOriginReason).toBeUndefined();

    const unverified = assertionProvenance(securityKeyRun, { allowedTopOrigins });
    expect(unverified.topOriginValid).toBeNull();
    expect(unverified.topOriginReason).toBe('no_verified_signature');
  });

  it('reports top_origin_unknown for a top-level ceremony that states no origin', () => {
    const originless = assertion({
      clientDataJSON: clientData({ type: 'webauthn.get', challenge: 'x', crossOrigin: false }),
    });
    const p = assertionProvenance(originless, { allowedTopOrigins: [EXTENSION], signatureVerified: true });
    expect(p.topOriginValid).toBe(false);
    expect(p.topOriginReason).toBe('top_origin_unknown');
  });

  it('does not vouch for an allowed framer that no verified signature covers', () => {
    const p = assertionProvenance(danaRun, { allowedTopOrigins: [EXTENSION] });
    expect(p.topOriginValid).toBeNull();
    expect(p.topOriginReason).toBe('no_verified_signature');
  });
});

describe('the device-bound requirement', () => {
  it('records the flags and judges nothing when device-bound is not required', () => {
    const p = assertionProvenance(securityKeyRun, { signatureVerified: true });
    expect(p.flags?.BE).toBe(false);
    expect(p.deviceBound).toBeNull();
    expect(p.deviceBoundReason).toBe('device_bound_not_required');
  });

  it('is true for a single-device credential under a verified signature', () => {
    const p = assertionProvenance(securityKeyRun, { requireDeviceBound: true, signatureVerified: true });
    expect(p.deviceBound).toBe(true);
    expect(p.deviceBoundReason).toBeUndefined();
  });

  it('does not vouch for BE clear when no verified signature covers the flags', () => {
    const p = assertionProvenance(securityKeyRun, { requireDeviceBound: true });
    expect(p.deviceBound).toBeNull();
    expect(p.deviceBoundReason).toBe('no_verified_signature');
  });

  it('reports the extension run\'s synced passkey as the lower rung credential_synced', () => {
    const p = assertionProvenance(danaRun, { requireDeviceBound: true, signatureVerified: true });
    expect(p.deviceBound).toBe(false);
    expect(p.deviceBoundReason).toBe('credential_synced');
  });

  it('does not call BE set, BS clear device-bound: it is backup-eligible, not backed up now', () => {
    const p = assertionProvenance(assertion({ authenticatorData: authData(UP | BE) }), {
      requireDeviceBound: true,
      signatureVerified: true,
    });
    expect(p.deviceBound).toBe(false);
    expect(p.deviceBoundReason).toBe('credential_backup_eligible');
  });

  it('reports BS set on a credential that is not backup-eligible as invalid_backup_flags', () => {
    const p = assertionProvenance(assertion({ authenticatorData: authData(UP | BS) }), {
      requireDeviceBound: true,
      signatureVerified: true,
    });
    expect(p.deviceBound).toBe(false);
    expect(p.deviceBoundReason).toBe('invalid_backup_flags');
  });

  it('reports flags_unreadable when there are no flags to read', () => {
    const p = assertionProvenance(assertion(), { requireDeviceBound: true, signatureVerified: true });
    expect(p.deviceBound).toBe(false);
    expect(p.deviceBoundReason).toBe('flags_unreadable');
  });
});
