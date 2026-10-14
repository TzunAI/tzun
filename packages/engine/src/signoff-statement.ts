/**
 * Sign-off statements (Record §9.4): their digest and the WebAuthn
 * challenge a ceremony over one presents. Shared by the signature-expectation
 * check (batch and session statements) and the mandate rules (the
 * `tzun-signoff-mandate/1` statement).
 */
import { createHash } from 'crypto';
import { canonicalSerialize } from './canonical';
import { challengeMatches, parseClientDataJSON } from './webauthn-binding';

/** Printable ASCII, 0x20 to 0x7E: the only characters a statement's strings hold (Record §9.4). */
const PRINTABLE_ASCII_RE = /^[\x20-\x7e]*$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/**
 * Whether `statement` is in the value domain Record §9.4 defines
 * canonical bytes for: a plain object whose keys and string values are
 * printable ASCII, and whose other values are non-negative safe integers.
 * Nothing nested, no fraction, no boolean, no `null`. The Python twin applies
 * the same rule, so the two never hash a statement differently: a number past
 * 2^53 - 1 is read differently by the two languages' JSON parsers, and it is
 * outside the domain here.
 */
export function isStatementDomain(statement: Record<string, unknown>): boolean {
  for (const [key, value] of Object.entries(statement)) {
    if (!PRINTABLE_ASCII_RE.test(key)) return false;
    if (typeof value === 'string') {
      if (!PRINTABLE_ASCII_RE.test(value)) return false;
    } else if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
      return false;
    }
  }
  return true;
}

/**
 * A sign-off statement's digest (Record §9.4): lowercase hex SHA-256 of
 * the statement's canonical bytes, every member included. `null` when the
 * statement is not a plain object whose keys and string values are printable
 * ASCII and whose other values are non-negative safe integers, the only
 * statements Record §9.4 defines canonical bytes for. Whether its keys are the fixed
 * set for its mode is the sign-off verifier's check, not this one.
 */
export function signoffStatementDigest(statement: unknown): string | null {
  if (!isPlainObject(statement) || !isStatementDomain(statement)) return null;
  try {
    const canonical = canonicalSerialize(statement, Object.keys(statement));
    return createHash('sha256').update(canonical, 'utf8').digest('hex');
  } catch {
    return null;
  }
}

/** The domain separator of a sign-off statement's WebAuthn challenge (Record §9.4). */
const SIGNOFF_CHALLENGE_DOMAIN = 'tzun-signoff-v1';

/**
 * The WebAuthn challenge a batch, session or mandate ceremony presents
 * (Record §9.4): `base64url_nopad(SHA-256("tzun-signoff-v1" ||
 * statementDigest))`. Its preimage is 79 bytes, a per-record challenge's 80,
 * so the two can never coincide.
 */
export function signoffStatementChallenge(statementDigest: string): string {
  return createHash('sha256').update(SIGNOFF_CHALLENGE_DOMAIN + statementDigest, 'utf8').digest('base64url');
}

/**
 * Whether `assertion`'s `clientDataJSON` is a `webauthn.get` that presented
 * `challenge`. Read from the signed client data alone: no key is needed, and
 * no signature is checked.
 */
export function assertionPresentsChallenge(assertion: Record<string, unknown>, challenge: string): boolean {
  const clientData = parseClientDataJSON(assertion.clientDataJSON);
  return (
    clientData !== null &&
    clientData.type === 'webauthn.get' &&
    typeof clientData.challenge === 'string' &&
    challengeMatches(clientData.challenge, challenge)
  );
}
