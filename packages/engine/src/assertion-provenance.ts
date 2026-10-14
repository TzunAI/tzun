/**
 * Where a WebAuthn ceremony ran, and what kind of key signed it
 *.
 *
 * `assertionBindingFailure` reads two fields of `clientDataJSON` — `type` and
 * `challenge` — because those decide whether an assertion is about a record.
 * This reads the rest of what the signed bytes say about the signature's
 * provenance:
 *
 *   - `origin`, `crossOrigin`, `topOrigin` from `clientDataJSON`: which
 *     origin ran the ceremony and, for a ceremony in a cross-origin frame,
 *     which top-level page framed it. For a browser extension's side panel
 *     the ceremony runs on a Tzun origin inside a frame, so
 *     `crossOrigin` is `true` and `topOrigin` is the extension. A hostile page
 *     framing the ceremony shows up in `topOrigin` and nowhere else.
 *   - the `UP`, `UV`, `BE`, `BS` flags from `authenticatorData`: whether a
 *     human was present, whether they were verified, and whether the key can
 *     leave the authenticator — the difference between a device-bound key and
 *     a synced passkey.
 *
 * It lives in the engine beside the binding because both are pure reads of the
 * assertion that need no key material, and the Python twin
 * (`tzun_sdk.attestation.assertion_provenance`) is pinned to it by
 * `tests/cross-sdk/test_assertion_provenance_parity.py`.
 *
 * What the bytes cannot prove on their own is that the authenticator wrote
 * them: that takes the signature, checked against the registered public key.
 * So a requirement the statement meets is reported `true` only when the
 * caller says a verified signature covers it (`signatureVerified`), and a
 * requirement it fails is reported `false` either way.
 */
import { parseClientDataJSON } from './webauthn-binding';
import type { AttestationArtifacts } from './types/evidence';
import type {
  AssertionOriginReason,
  AssertionProvenance,
  AssertionTopOriginReason,
  AuthenticatorFlags,
  DeviceBoundReason,
} from './types/verification';

/** What a caller requires of an assertion's provenance, and what it already knows. */
export interface AssertionProvenanceOptions {
  /** Origins the ceremony may have run on. Unset: `originValid` is not checked. */
  allowedOrigins?: readonly string[];
  /**
   * Top-level origins the ceremony may have run under — for the extension
   * side panel, Tzun's own extension origins. The top-level origin is
   * `topOrigin` for a cross-origin ceremony, and the ceremony's own `origin`
   * for one that states `crossOrigin: false`, so a ceremony run directly in a
   * tab passes only when its origin is listed too. Unset: `topOriginValid` is
   * not checked.
   */
  allowedTopOrigins?: readonly string[];
  /**
   * Require a single-device credential (`BE` clear). A synced or
   * backup-eligible credential is then reported `deviceBound: false` with its
   * reason — a lower rung, not a failed signature.
   */
  requireDeviceBound?: boolean;
  /**
   * Whether the signature over these bytes verified as a signature over this
   * record (`signatureValid: true`). Only then is a met requirement `true`.
   * Default `false`: a caller that has not checked the signature has not.
   */
  signatureVerified?: boolean;
}

/** `authenticatorData` is a 32-byte rpIdHash, a flags byte and a 4-byte counter. */
const AUTHENTICATOR_DATA_MIN_LENGTH = 37;
const FLAGS_OFFSET = 32;

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;

/**
 * Read the provenance an assertion states and check it against `options`.
 *
 * Never throws: the assertion is JSON a client supplied, so a
 * field that is missing, undecodable or the wrong type is recorded as `null`.
 */
export function assertionProvenance(
  assertion: NonNullable<AttestationArtifacts['webauthnAssertion']>,
  options: AssertionProvenanceOptions = {},
): AssertionProvenance {
  const raw: unknown = assertion;
  const bag =
    raw !== null && typeof raw === 'object' && !Array.isArray(raw)
      ? (raw as { clientDataJSON?: unknown; authenticatorData?: unknown })
      : {};

  const clientData = parseClientDataJSON(bag.clientDataJSON) ?? {};
  const origin = wellFormedString(clientData.origin);
  const crossOrigin = typeof clientData.crossOrigin === 'boolean' ? clientData.crossOrigin : null;
  const topOrigin = wellFormedString(clientData.topOrigin);
  const flags = decodeFlags(bag.authenticatorData);

  const verified = options.signatureVerified === true;
  const origins = originCheck(origin, options.allowedOrigins, verified);
  const top = topOriginCheck(origin, crossOrigin, topOrigin, options.allowedTopOrigins, verified);
  const device = deviceBoundCheck(flags, options.requireDeviceBound === true, verified);

  return {
    origin,
    crossOrigin,
    topOrigin,
    flags,
    originValid: origins.valid,
    ...(origins.reason !== undefined && { originReason: origins.reason }),
    topOriginValid: top.valid,
    ...(top.reason !== undefined && { topOriginReason: top.reason }),
    deviceBound: device.valid,
    ...(device.reason !== undefined && { deviceBoundReason: device.reason }),
  };
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * A string field, with each lone UTF-16 surrogate replaced by U+FFFD (what
 * `String.prototype.toWellFormed` does); `null` for any other type. JSON.parse
 * keeps a lone surrogate escape, and a verdict carrying one cannot be stored
 * in a Postgres `jsonb` column or dumped by pydantic's `model_dump_json`. The
 * Python twin replaces them the same way.
 */
function wellFormedString(value: unknown): string | null {
  return typeof value === 'string' ? value.replace(LONE_SURROGATE, '\uFFFD') : null;
}

interface Check<R> {
  valid: boolean | null;
  reason?: R;
}

/** A requirement the statement meets: `true` only under a verified signature. */
function met<R>(verified: boolean, unverified: R): Check<R> {
  return verified ? { valid: true } : { valid: null, reason: unverified };
}

function originCheck(
  origin: string | null,
  allowed: readonly string[] | undefined,
  verified: boolean,
): Check<AssertionOriginReason> {
  if (!Array.isArray(allowed)) return { valid: null, reason: 'origin_not_checked' };
  if (origin === null || !allowed.includes(origin)) return { valid: false, reason: 'origin_mismatch' };
  return met(verified, 'no_verified_signature');
}

function topOriginCheck(
  origin: string | null,
  crossOrigin: boolean | null,
  topOrigin: string | null,
  allowed: readonly string[] | undefined,
  verified: boolean,
): Check<AssertionTopOriginReason> {
  if (!Array.isArray(allowed)) return { valid: null, reason: 'top_origin_not_checked' };
  // The top-level page the ceremony ran under. A browser names it in
  // `topOrigin` only for a ceremony that is not same-origin with its
  // ancestors; one that says it was NOT cross-origin is same-origin with every
  // ancestor, so its top-level page is its own `origin`. A ceremony that says
  // it was cross-origin, or does not say, and names no `topOrigin` leaves the
  // top-level page unknown.
  const top = topOrigin ?? (crossOrigin === false ? origin : null);
  if (top === null) return { valid: false, reason: 'top_origin_unknown' };
  return allowed.includes(top)
    ? met(verified, 'no_verified_signature')
    : { valid: false, reason: 'top_origin_not_allowed' };
}

function deviceBoundCheck(
  flags: AuthenticatorFlags | null,
  required: boolean,
  verified: boolean,
): Check<DeviceBoundReason> {
  if (!required) return { valid: null, reason: 'device_bound_not_required' };
  if (flags === null) return { valid: false, reason: 'flags_unreadable' };
  if (!flags.BE) {
    return flags.BS
      ? { valid: false, reason: 'invalid_backup_flags' }
      : met(verified, 'no_verified_signature');
  }
  return { valid: false, reason: flags.BS ? 'credential_synced' : 'credential_backup_eligible' };
}

/** The four flags, or `null` when there is no flags byte to read. */
function decodeFlags(value: unknown): AuthenticatorFlags | null {
  if (typeof value !== 'string') return null;
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < AUTHENTICATOR_DATA_MIN_LENGTH) return null;
  const byte = bytes[FLAGS_OFFSET]!;
  return {
    UP: (byte & FLAG_UP) !== 0,
    UV: (byte & FLAG_UV) !== 0,
    BE: (byte & FLAG_BE) !== 0,
    BS: (byte & FLAG_BS) !== 0,
  };
}
