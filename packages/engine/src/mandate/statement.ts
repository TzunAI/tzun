/**
 * The mandate statement `tzun-signoff-mandate/1` (Record §9.6) and the
 * confirmation challenge (Record §9.4).
 *
 * The statement is a flat statement in the sign-off value domain with exactly
 * eight keys. It carries no printed name: `signer` is the principal's opaque
 * relying-party user id. Its digest and challenge are those of every sign-off
 * statement: `statementDigest = hex(SHA-256(C(statement)))` and the challenge
 * `B64URL(SHA-256("tzun-signoff-v1" ‖ statementDigest))`.
 */
import { createHash } from 'crypto';
import { hasExactKeys, isBareDigest, isPlainObject } from '../record-rules-util';
import { ACCT_VALUE_RE, isFreshnessReference } from '../decider';
import { signoffStatementChallenge, signoffStatementDigest } from '../signoff-statement';
import type { MandateStatement } from '../types/mandate';

export const MANDATE_STATEMENT_VERSION = 'tzun-signoff-mandate/1';

const STATEMENT_KEYS = ['v', 'mode', 'mandateDigest', 'signer', 'signerKind', 'meaning', 'policyDigest', 'notBefore'] as const;

/**
 * Why `statement` is not a well-formed mandate statement, or `null` when it is
 * one: exactly the eight keys (a statement carrying `signerName` is
 * malformed); `v` the version tag; `mode` `mandate`; `mandateDigest` 64
 * lowercase hex; `signer` the `acct` value grammar; `signerKind` `human`;
 * `meaning` `responsibility`; `policyDigest` 64 lowercase hex or `none`;
 * `notBefore` a finalized-block reference or `none`.
 */
export function mandateStatementViolation(statement: unknown): string | null {
  if (!isPlainObject(statement)) return 'a mandate statement must be an object';
  if (!hasExactKeys(statement, STATEMENT_KEYS)) return `a mandate statement has exactly the keys ${STATEMENT_KEYS.join(', ')}`;
  const s = statement;
  if (s.v !== MANDATE_STATEMENT_VERSION) return `v must be ${MANDATE_STATEMENT_VERSION}`;
  if (s.mode !== 'mandate') return 'mode must be mandate';
  if (!isBareDigest(s.mandateDigest)) return 'mandateDigest must be 64 lowercase hex';
  if (typeof s.signer !== 'string' || !ACCT_VALUE_RE.test(s.signer)) return 'signer must be [A-Za-z0-9._-]{1,128}';
  if (s.signerKind !== 'human') return 'signerKind must be human';
  if (s.meaning !== 'responsibility') return 'meaning must be responsibility';
  if (s.policyDigest !== 'none' && !isBareDigest(s.policyDigest)) return 'policyDigest must be 64 lowercase hex or none';
  if (s.notBefore !== 'none' && !isFreshnessReference(s.notBefore)) return 'notBefore must be a finalized-block reference or none';
  return null;
}

/** The statement digest of a well-formed mandate statement, or `null`. Never throws. */
export function mandateStatementDigest(statement: unknown): string | null {
  if (mandateStatementViolation(statement) !== null) return null;
  return signoffStatementDigest(statement);
}

/** The challenge a principal's ceremony over the statement presents. */
export function mandateStatementChallenge(statementDigest: string): string {
  return signoffStatementChallenge(statementDigest);
}

/**
 * The statement `prepare` forms for a document whose digest is
 * `mandateDigest`: `policyDigest` is the document's or `none`, `notBefore`
 * the header follower's finalized-block reference or `none`.
 *
 * @throws when the parts do not make a well-formed statement.
 */
export function buildMandateStatement(parts: {
  mandateDigest: string;
  signer: string;
  policyDigest: string | null;
  notBefore: string | null;
}): MandateStatement {
  const statement: MandateStatement = {
    v: MANDATE_STATEMENT_VERSION,
    mode: 'mandate',
    mandateDigest: parts.mandateDigest,
    signer: parts.signer,
    signerKind: 'human',
    meaning: 'responsibility',
    policyDigest: parts.policyDigest ?? 'none',
    notBefore: parts.notBefore ?? 'none',
  };
  const reason = mandateStatementViolation(statement);
  if (reason !== null) throw new Error(`Invalid mandate statement: ${reason}`);
  return statement;
}

/** The domain separator of a confirmation challenge. Not a prefix of any other Tzun separator. */
const CONFIRM_CHALLENGE_DOMAIN = 'tzun-confirm-v1';

/**
 * The challenge a human's confirmation of a mandated record presents:
 * `B64URL(SHA-256("tzun-confirm-v1" ‖ digest))`, `digest` the record's
 * canonical digest.
 */
export function mandateConfirmationChallenge(digest: string): string {
  return createHash('sha256').update(CONFIRM_CHALLENGE_DOMAIN + digest, 'utf8').digest('base64url');
}
