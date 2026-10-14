/**
 * The mandate form of the signature expectation (Record §9.1, §9.2) and the
 * keyless checks of a record's mandate block against it (Verification §5,
 * rows 17 to 24).
 *
 *   { "mandateAssertion": <64 hex>, "mandateSeq": <safe integer ≥ 1>,
 *     "totals": { "<cap>": <safe integer ≥ 0>, … } | null, "confirm": true | false }
 */
import {
  canonicalValue,
  hasExactKeys,
  isBareDigest,
  isNonNegativeSafeInteger,
  isPlainObject,
  isPositiveSafeInteger,
  utf8Length,
} from '../record-rules-util';
import { assertionPresentsChallenge } from '../signoff-statement';
import { assertionDigest } from './assertion-digest';
import { MANDATE_MAX_CAPS, MANDATE_NAME_RE, mandateDigest } from './document';
import { mandateConfirmationChallenge, mandateStatementChallenge, mandateStatementDigest } from './statement';
import type { SignoffExpectationCheck } from '../types/verification';
import type { SignoffExpectationViolation } from '../types/evidence';

/** The members of the mandate form. */
export const MANDATE_EXPECTATION_KEYS = ['confirm', 'mandateAssertion', 'mandateSeq', 'totals'] as const;

/** The most canonical bytes a `mandate` or `mandateIssuance` block has (a writer limit). */
export const MANDATE_BLOCK_MAX_BYTES = 48 * 1024;

/** Whether `value` has exactly the members of the mandate form (whatever their values). */
export function hasMandateExpectationMembers(value: Record<string, unknown>): boolean {
  return hasExactKeys(value, MANDATE_EXPECTATION_KEYS);
}

/**
 * Why an object with exactly the mandate form's members is not one, or
 * `null`: `mandateAssertion` 64 lowercase hex; `mandateSeq` a safe integer of
 * at least 1; `totals` `null` or 1 to 16 caps named `[A-Za-z0-9._-]{1,64}`,
 * each a non-negative safe integer; `confirm` `true` or `false`.
 */
export function mandateExpectationMemberViolation(value: Record<string, unknown>): SignoffExpectationViolation | null {
  if (!isBareDigest(value.mandateAssertion)) return 'invalid_mandate_assertion';
  if (!isPositiveSafeInteger(value.mandateSeq)) return 'invalid_mandate_seq';
  const totals = value.totals;
  if (totals !== null) {
    if (!isPlainObject(totals)) return 'invalid_totals';
    const caps = Object.keys(totals);
    if (caps.length < 1 || caps.length > MANDATE_MAX_CAPS) return 'invalid_totals';
    if (!caps.every((cap) => MANDATE_NAME_RE.test(cap) && isNonNegativeSafeInteger(totals[cap]))) return 'invalid_totals';
  }
  if (typeof value.confirm !== 'boolean') return 'invalid_confirm';
  return null;
}

/**
 * Why a `mandate` or `mandateIssuance` block is refused at capture, or
 * `null`: its canonical bytes exceed 48 KiB. Checked separately from the
 * hashed object's cap, by the writer and by the platform.
 */
export function mandateBlockViolation(
  block: unknown,
  field = 'nonRepudiation.mandate',
): { code: 'mandate_block_too_large'; field: string; message: string } | null {
  let bytes: number;
  try {
    bytes = utf8Length(canonicalValue(block));
  } catch {
    bytes = Infinity;
  }
  if (bytes > MANDATE_BLOCK_MAX_BYTES) {
    return {
      code: 'mandate_block_too_large',
      field,
      message: `${field}'s canonical bytes exceed ${MANDATE_BLOCK_MAX_BYTES}, or it cannot be canonically serialized`,
    };
  }
  return null;
}

/**
 * The mandate-form rows of the signature-expectation check (Verification §5), for a
 * record whose expectation is a well-formed mandate form:
 *
 *   17  a session sign-off                       → false, session_signoff_not_expected
 *   18  no `mandate` block                       → false, mandate_stripped
 *   19  its statement is not a well-formed mandate statement
 *                                                → false, malformed_mandate_statement
 *   20  its assertion's digest is not `mandateAssertion`
 *                                                → false, mandate_assertion_mismatch
 *   21  its assertion did not present the statement's challenge
 *                                                → false, mandate_unbound
 *   22  its document does not hash to `statement.mandateDigest`, or its
 *       principal is not the statement's signer → false, mandate_document_mismatch
 *   23  `confirm` is true and no confirmation presents the record's
 *       confirmation challenge                   → null, confirmation_missing
 *   24  otherwise                                → true
 *
 * A block with no document is not refused here: the scope row reports the
 * document missing. Never throws.
 */
export function checkMandateExpectationMaterial(
  expectation: Record<string, unknown>,
  nonRepudiation: Record<string, unknown>,
  digest: unknown,
  isSessionSignoff: boolean,
): SignoffExpectationCheck {
  if (isSessionSignoff) return { valid: false, reason: 'session_signoff_not_expected' };
  const block = nonRepudiation.mandate;
  if (block === undefined || block === null) return { valid: false, reason: 'mandate_stripped' };
  if (!isPlainObject(block)) return { valid: false, reason: 'malformed_mandate_statement' };
  const statementDigest = mandateStatementDigest(block.statement);
  if (statementDigest === null) return { valid: false, reason: 'malformed_mandate_statement' };
  const assertion = block.assertion;
  if (assertionDigest(assertion) !== expectation.mandateAssertion) {
    return { valid: false, reason: 'mandate_assertion_mismatch' };
  }
  if (!isPlainObject(assertion) || !assertionPresentsChallenge(assertion, mandateStatementChallenge(statementDigest))) {
    return { valid: false, reason: 'mandate_unbound' };
  }
  const document = block.document;
  if (document !== undefined && document !== null) {
    const statement = block.statement as Record<string, unknown>;
    if (mandateDigest(document) !== statement.mandateDigest) {
      return { valid: false, reason: 'mandate_document_mismatch' };
    }
    const principal = isPlainObject(document) && isPlainObject(document.principal) ? document.principal : null;
    if (principal === null || principal.signer !== statement.signer) {
      return { valid: false, reason: 'mandate_document_mismatch' };
    }
  }
  if (expectation.confirm === true) {
    const confirmation = nonRepudiation.confirmation;
    const confirmed =
      isPlainObject(confirmation) &&
      typeof digest === 'string' &&
      digest !== '' &&
      assertionPresentsChallenge(confirmation, mandateConfirmationChallenge(digest));
    if (!confirmed) return { valid: null, reason: 'confirmation_missing' };
  }
  return { valid: true };
}
