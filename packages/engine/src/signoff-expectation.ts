/**
 * `payload.signoffExpectation`: what signature a record expects, stated in its
 * hashed payload (Record §9.1). One implementation of its shape rule
 * and of the check a verifier makes with it; the Python twin is
 * `tzun_sdk.signoff_expectation`, and `vectors/signoff-expectation-vectors.json`
 * holds the two to the same answers.
 *
 * The value is one of:
 *
 *   - `null`: no signature is expected;
 *   - `{ policyDigest }`: a signature is required under that sign-off policy,
 *     attached at capture or later;
 *   - `{ statementDigest, sessionSeq }`: the record was captured into a
 *     sign-off session, in slot `sessionSeq`;
 *   - the mandate form `{ mandateAssertion, mandateSeq, totals, confirm }`:
 *     an agent decided under the mandate whose principal's assertion has that
 *     digest, in slot `mandateSeq` (Record §9.1). Only a capture under
 *     a mandate writes it.
 *
 * It is hashed, so a signature stripped from a record that expects one, or a
 * session signature moved onto a record that does not name that session, is
 * visible from the record alone (21 CFR 11.70). The value is fixed when the
 * digest is built, which is why a session slot must be claimed before the
 * record is built, never after.
 */
import { verifyMerkleProof } from './merkle';
import { assertionBindsDigest } from './webauthn-binding';
import {
  assertionPresentsChallenge,
  signoffStatementChallenge,
  signoffStatementDigest,
} from './signoff-statement';
import {
  checkMandateExpectationMaterial,
  hasMandateExpectationMembers,
  mandateExpectationMemberViolation,
} from './mandate/expectation';
import type { SignoffExpectation, SignoffExpectationViolation } from './types/evidence';
import type { MandateExpectation } from './types/mandate';
import type { SignoffExpectationCheck } from './types/verification';

export { signoffStatementChallenge, signoffStatementDigest } from './signoff-statement';

/** A policy or statement digest: 64 lowercase hex, and nothing around it. */
export const SIGNOFF_DIGEST_RE = /^[0-9a-f]{64}$/;

const VIOLATION_MESSAGES: Record<SignoffExpectationViolation, string> = {
  not_an_object: 'signoffExpectation must be null or an object',
  unknown_members:
    'signoffExpectation must have exactly the member policyDigest, exactly the members statementDigest and ' +
    'sessionSeq, or exactly the members mandateAssertion, mandateSeq, totals and confirm',
  invalid_policy_digest: 'signoffExpectation.policyDigest must be 64 lowercase hex characters',
  invalid_statement_digest: 'signoffExpectation.statementDigest must be 64 lowercase hex characters',
  invalid_session_seq: 'signoffExpectation.sessionSeq must be a safe integer of at least 1',
  invalid_mandate_assertion: 'signoffExpectation.mandateAssertion must be 64 lowercase hex characters',
  invalid_mandate_seq: 'signoffExpectation.mandateSeq must be a safe integer of at least 1',
  invalid_totals:
    'signoffExpectation.totals must be null or 1 to 16 caps named [A-Za-z0-9._-]{1,64}, each a non-negative safe integer',
  invalid_confirm: 'signoffExpectation.confirm must be true or false',
};

/** The sentence a refusal carries for `violation`. */
export function describeSignoffExpectationViolation(violation: SignoffExpectationViolation): string {
  return VIOLATION_MESSAGES[violation];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

function isDigest(value: unknown): value is string {
  return typeof value === 'string' && SIGNOFF_DIGEST_RE.test(value);
}

/**
 * Why `value` is not a signoff expectation, or `null` when it is one. `null`
 * and `undefined` are the "none expected" value: a payload with no
 * `signoffExpectation` key canonicalizes exactly as one whose value is
 * `null`.
 */
export function signoffExpectationViolation(value: unknown): SignoffExpectationViolation | null {
  if (value === null || value === undefined) return null;
  if (!isPlainObject(value)) return 'not_an_object';
  const keys = Object.keys(value).sort();
  if (keys.length === 1 && keys[0] === 'policyDigest') {
    return isDigest(value.policyDigest) ? null : 'invalid_policy_digest';
  }
  if (keys.length === 2 && keys[0] === 'sessionSeq' && keys[1] === 'statementDigest') {
    if (!isDigest(value.statementDigest)) return 'invalid_statement_digest';
    const seq = value.sessionSeq;
    return typeof seq === 'number' && Number.isSafeInteger(seq) && seq >= 1 ? null : 'invalid_session_seq';
  }
  if (hasMandateExpectationMembers(value)) return mandateExpectationMemberViolation(value);
  return 'unknown_members';
}

/** Whether `value` is a signoff expectation (not `null`: one of the three forms). */
export function isSignoffExpectation(value: unknown): value is SignoffExpectation {
  return value !== null && value !== undefined && signoffExpectationViolation(value) === null;
}

/** Whether `value` is the mandate form, `{ mandateAssertion, mandateSeq, totals, confirm }`, well formed. */
export function isMandateExpectation(value: unknown): value is MandateExpectation {
  return isPlainObject(value) && hasMandateExpectationMembers(value) && signoffExpectationViolation(value) === null;
}

/**
 * The form of a well-formed expectation: `none`, `policy`, `session` or
 * `mandate`; `null` when it is not well formed.
 */
export function signoffExpectationForm(value: unknown): 'none' | 'policy' | 'session' | 'mandate' | null {
  if (signoffExpectationViolation(value) !== null) return null;
  if (value === null || value === undefined) return 'none';
  const v = value as Record<string, unknown>;
  if ('policyDigest' in v) return 'policy';
  if ('sessionSeq' in v) return 'session';
  return 'mandate';
}

/** Whether `value` is the session form, `{ statementDigest, sessionSeq }`. */
export function isSessionAttachmentExpectation(
  value: unknown,
): value is Extract<SignoffExpectation, { sessionSeq: number }> {
  return isSignoffExpectation(value) && 'sessionSeq' in value;
}

/**
 * Whether a record whose stored digest is `digest` carries a batch sign-off
 * that covers it, by every check that needs no key (Record §9.5,
 * Verification §5):
 * the block is an object whose statement is an object with `mode: 'batch'`
 * that has a digest, the assertion presented that statement's challenge, and
 * the inclusion proof puts `digest` in the tree of `statement.treeSize`
 * leaves whose root is `statement.root`. A junk block, a relabelled
 * statement, an assertion from another ceremony, or a batch that does not
 * hold this record is not a batch sign-off of it.
 */
export function carriesBatchSignoff(
  block: Record<string, unknown> | null,
  assertion: Record<string, unknown>,
  digest: unknown,
): boolean {
  if (block === null) return false;
  const statement = block.statement;
  if (!isPlainObject(statement) || statement.mode !== 'batch') return false;
  const statementDigest = signoffStatementDigest(statement);
  if (statementDigest === null) return false;
  if (!assertionPresentsChallenge(assertion, signoffStatementChallenge(statementDigest))) return false;
  const inclusion = block.inclusion;
  if (!isPlainObject(inclusion) || typeof digest !== 'string') return false;
  return verifyMerkleProof(
    digest,
    inclusion.leafIndex as number,
    statement.treeSize as number,
    inclusion.path as string[],
    statement.root as string,
  );
}

/**
 * Check a record's sign-off material against its hashed expectation.
 *
 * A sign-off is carried when the record holds a `signoff` block (any value
 * but `null`) and a `webauthnAssertion` object. It binds when every check
 * that needs no key holds: for a batch, the statement is an object with
 * `mode: 'batch'`, the assertion presented that statement's challenge
 * (Record §9.4), and the inclusion proof puts the record's stored digest under the
 * statement's `root` and `treeSize`; for a session, the assertion presented
 * the session statement's challenge. A session sign-off is a `signoff` whose
 * statement's `mode` is `session`, or that carries `sessionSeq`.
 *
 *   a record carrying a `mandate` block under an expectation that is not
 *   the mandate form                      → false, mandate_not_expected
 *                                           (row 1a, tried first on every
 *                                           record)
 *   expectation `null`:
 *     a session sign-off                  → false, session_signoff_not_expected
 *     a carried sign-off that does not bind as a batch sign-off of the record
 *                                         → false, signoff_unbound
 *     otherwise                           → true
 *   `{ policyDigest }`:
 *     a session sign-off                  → false, session_signoff_not_expected
 *     no `webauthnAssertion`              → null, signature_missing
 *     a `signoff` block: it binds as a batch sign-off of the record
 *                                         → true
 *                        otherwise        → false, signoff_unbound
 *     no `signoff` block: an assertion whose challenge is derived from the
 *     record's digest (per record)        → true
 *                        otherwise        → null, signature_missing
 *   `{ statementDigest, sessionSeq }`:
 *     no `signoff` block                  → false, signoff_stripped
 *     its statement's digest differs      → false, statement_digest_mismatch
 *     its `sessionSeq` differs            → false, session_seq_mismatch
 *     no `webauthnAssertion`              → false, signoff_stripped
 *     an assertion that did not present the statement's challenge
 *                                         → false, signoff_unbound
 *     otherwise                           → true
 *   the mandate form: `checkMandateExpectationMaterial`
 *     (mandate/expectation.ts), the mandate block against the expectation
 *   a value of none of the forms its schema version admits
 *                                         → false, malformed_signoff_expectation
 *
 * `null` is left to the policy form, the one form whose signature may arrive
 * after capture. A session record is written with its sign-off in the
 * same write, so one without it had it removed. A carried
 * sign-off that does not bind was moved, relabelled or made up: the SDK never
 * writes one, and fill-only attachment never replaces it.
 *
 * `true` says the record carries the sign-off its expectation names, as far
 * as can be read without a key. Whether the signature itself verifies, and
 * the statement's shape and limits, are the signature verifier's answer. The
 * policy a batch statement names may be a successor of the one the record
 * names, so the two are not compared here. Never throws: an envelope is
 * untrusted input.
 */
export function checkSignoffExpectation(envelope: unknown): SignoffExpectationCheck {
  const env = (isPlainObject(envelope) ? envelope : {}) as Record<string, unknown>;
  const payload = isPlainObject(env.payload) ? env.payload : {};
  const integrity = isPlainObject(env.integrity) ? env.integrity : {};
  const nonRepudiation = isPlainObject(env.nonRepudiation) ? env.nonRepudiation : {};
  const expectation: unknown = payload.signoffExpectation;

  const form = signoffExpectationForm(expectation);
  if (form === null) {
    return { valid: false, reason: 'malformed_signoff_expectation' };
  }

  const signoff: unknown = nonRepudiation.signoff;
  const hasSignoff = signoff !== undefined && signoff !== null;
  const signoffBlock = isPlainObject(signoff) ? signoff : null;
  const statement = signoffBlock && isPlainObject(signoffBlock.statement) ? signoffBlock.statement : null;
  const isSessionSignoff =
    signoffBlock !== null && (statement?.mode === 'session' || signoffBlock.sessionSeq !== undefined);
  const assertion: unknown = nonRepudiation.webauthnAssertion;
  const assertionBlock = isPlainObject(assertion) ? assertion : null;
  const digest = integrity.canonicalDigest;

  if (form === 'mandate') {
    return checkMandateExpectationMaterial(expectation as Record<string, unknown>, nonRepudiation, digest, isSessionSignoff);
  }

  // Row 1a: a mandate block is carried only by a record in the mandate form.
  if (nonRepudiation.mandate !== undefined && nonRepudiation.mandate !== null) {
    return { valid: false, reason: 'mandate_not_expected' };
  }

  if (expectation === null || expectation === undefined) {
    if (isSessionSignoff) return { valid: false, reason: 'session_signoff_not_expected' };
    if (hasSignoff && assertionBlock !== null && !carriesBatchSignoff(signoffBlock, assertionBlock, digest)) {
      return { valid: false, reason: 'signoff_unbound' };
    }
    return { valid: true };
  }

  const expected = expectation as Record<string, unknown>;
  if ('policyDigest' in expected) {
    if (isSessionSignoff) return { valid: false, reason: 'session_signoff_not_expected' };
    if (assertionBlock === null) return { valid: null, reason: 'signature_missing' };
    if (hasSignoff) {
      return carriesBatchSignoff(signoffBlock, assertionBlock, digest)
        ? { valid: true }
        : { valid: false, reason: 'signoff_unbound' };
    }
    // An empty stored digest binds nothing (the Python twin's challenge
    // derivation refuses it).
    const bound =
      typeof digest === 'string' &&
      digest !== '' &&
      assertionBindsDigest(assertionBlock as unknown as Parameters<typeof assertionBindsDigest>[0], digest);
    return bound ? { valid: true } : { valid: null, reason: 'signature_missing' };
  }

  if (!hasSignoff) return { valid: false, reason: 'signoff_stripped' };
  if (signoffStatementDigest(signoffBlock?.statement) !== expected.statementDigest) {
    return { valid: false, reason: 'statement_digest_mismatch' };
  }
  if (signoffBlock!.sessionSeq !== expected.sessionSeq) {
    return { valid: false, reason: 'session_seq_mismatch' };
  }
  if (assertionBlock === null) return { valid: false, reason: 'signoff_stripped' };
  return assertionPresentsChallenge(assertionBlock, signoffStatementChallenge(expected.statementDigest as string))
    ? { valid: true }
    : { valid: false, reason: 'signoff_unbound' };
}
