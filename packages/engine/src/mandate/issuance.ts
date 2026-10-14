/**
 * Mandate issuance records (Record §9.6; the `mandate.issuance` row,
 * Verification §4.12) and mandate event bodies.
 *
 * An issuance record is captured under `aiSystemId "tzun:mandate"`, action
 * `issue-mandate`, with `aiOutput { mandateDigest, statementDigest,
 * assertionDigest }`, the decider `{ kind: "human", id:
 * "acct:<principal.signer>" }`, and the issuance material in
 * `nonRepudiation.mandateIssuance`. Its keyless chain: a well-formed document
 * → `statement.mandateDigest` → statement challenge presented by the
 * assertion → `assertionDigest` = `aiOutput.assertionDigest`, with the
 * statement's signer and the record's decider both the document's principal.
 */
import {
  canonicalValue,
  hasExactKeys,
  isBareDigest,
  isNonNegativeSafeInteger,
  isPlainObject,
  sha256Hex,
} from '../record-rules-util';
import { assertionPresentsChallenge } from '../signoff-statement';
import { assertionDigest } from './assertion-digest';
import { MANDATE_MAX_CAPS, MANDATE_NAME_RE, mandateDigest, mandateDocumentViolation } from './document';
import { mandateStatementChallenge, mandateStatementDigest } from './statement';
import type { MandateEventBody } from '../types/mandate';
import type { MandateIssuanceCheck } from '../types/verification';

/** The `aiSystemId` of mandate issuance and revocation records. */
export const MANDATE_AI_SYSTEM_ID = 'tzun:mandate';
/** The action of an issuance record. */
export const MANDATE_ISSUE_ACTION = 'issue-mandate';
/** The action of a revocation record. */
export const MANDATE_REVOKE_ACTION = 'revoke-mandate';
/** The version tag of a mandate event body. */
export const MANDATE_EVENT_VERSION = 'tzun-mandate-event/1';

const EVENT_KEYS = ['v', 'event', 'mandateDigest', 'record', 'successor', 'used', 'totals'] as const;
const EVENTS = ['issued', 'revoked', 'superseded', 'expired'];

/**
 * The `mandate.issuance` row, or `null` when it is not reported: it is
 * reported for a record carrying `nonRepudiation.mandateIssuance`, or whose
 * `aiSystemId` is `tzun:mandate` and action `issue-mandate`. Never throws.
 *
 *   issuance material on a record that is not an issuance record
 *                                  → checked-wrong, issuance_not_expected
 *   an issuance record without it  → checked-wrong, issuance_material_stripped
 *   a broken link                  → checked-wrong, issuance_material_mismatch, with `link`:
 *     `document`   the document is not a well-formed mandate document (read
 *                  as a reader reads one: no `prepare` rules), or its digest
 *                  is not `statement.mandateDigest` and `aiOutput.mandateDigest`
 *     `statement`  the statement is not well formed, or its digest is not
 *                  `aiOutput.statementDigest`
 *     `signer`     `statement.signer` is not `document.principal.signer`
 *     `challenge`  the assertion did not present the statement's challenge
 *     `assertion`  the assertion's digest is not `aiOutput.assertionDigest`
 *     `decider`    the record's decider is not `{ kind: "human", id:
 *                  "acct:<principal.signer>" }`
 *   otherwise                      → checked-correct (who signed is not proven in this version)
 */
export function checkMandateIssuance(envelope: unknown): MandateIssuanceCheck | null {
  const env = isPlainObject(envelope) ? envelope : {};
  const payload = isPlainObject(env.payload) ? env.payload : {};
  const nr = isPlainObject(env.nonRepudiation) ? env.nonRepudiation : {};
  const block = nr.mandateIssuance;
  const hasBlock = block !== undefined && block !== null;
  const isIssuance = payload.aiSystemId === MANDATE_AI_SYSTEM_ID && payload.action === MANDATE_ISSUE_ACTION;
  if (!hasBlock && !isIssuance) return null;
  if (hasBlock && !isIssuance) return { outcome: 'checked-wrong', valid: false, reason: 'issuance_not_expected' };
  if (!hasBlock) return { outcome: 'checked-wrong', valid: false, reason: 'issuance_material_stripped' };
  const mismatch = (link: string): MandateIssuanceCheck => ({
    outcome: 'checked-wrong',
    valid: false,
    reason: 'issuance_material_mismatch',
    link,
  });
  if (!isPlainObject(block)) return mismatch('statement');
  const aiOutput = isPlainObject(payload.aiOutput) ? payload.aiOutput : {};
  const statement = isPlainObject(block.statement) ? block.statement : null;
  const document = block.document;
  if (statement === null || !isPlainObject(document) || mandateDocumentViolation(document, { prepare: false }) !== null) {
    return mismatch('document');
  }
  const docDigest = mandateDigest(document);
  if (docDigest === null || docDigest !== statement.mandateDigest || docDigest !== aiOutput.mandateDigest) {
    return mismatch('document');
  }
  const statementDigest = mandateStatementDigest(statement);
  if (statementDigest === null || statementDigest !== aiOutput.statementDigest) return mismatch('statement');
  const signer = (document.principal as Record<string, unknown>).signer;
  if (statement.signer !== signer) return mismatch('signer');
  const assertion = block.assertion;
  if (!isPlainObject(assertion) || !assertionPresentsChallenge(assertion, mandateStatementChallenge(statementDigest))) {
    return mismatch('challenge');
  }
  if (assertionDigest(assertion) !== aiOutput.assertionDigest) return mismatch('assertion');
  const decider = isPlainObject(payload.decider) ? payload.decider : null;
  if (decider === null || decider.kind !== 'human' || decider.id !== `acct:${signer as string}`) return mismatch('decider');
  return { outcome: 'checked-correct', valid: true };
}

/**
 * Why `body` is not a mandate event body `tzun-mandate-event/1`, or `null`:
 * exactly `v`, `event` (issued, revoked, superseded or expired),
 * `mandateDigest` and `record` (64 lowercase hex), `successor` (64 lowercase
 * hex or `null`), `used` (a non-negative safe integer or `null`) and `totals`
 * (`null` or 1 to 16 caps, each a non-negative safe integer).
 */
export function mandateEventBodyViolation(body: unknown): string | null {
  if (!isPlainObject(body) || !hasExactKeys(body, EVENT_KEYS)) return `an event body has exactly the keys ${EVENT_KEYS.join(', ')}`;
  if (body.v !== MANDATE_EVENT_VERSION) return `v must be ${MANDATE_EVENT_VERSION}`;
  if (!EVENTS.includes(body.event as string)) return `event must be one of ${EVENTS.join(', ')}`;
  if (!isBareDigest(body.mandateDigest)) return 'mandateDigest must be 64 lowercase hex';
  if (!isBareDigest(body.record)) return 'record must be 64 lowercase hex';
  if (body.successor !== null && !isBareDigest(body.successor)) return 'successor must be null or 64 lowercase hex';
  if (body.used !== null && !isNonNegativeSafeInteger(body.used)) return 'used must be null or a non-negative integer';
  const totals = body.totals;
  if (totals !== null) {
    if (!isPlainObject(totals)) return 'totals must be null or an object of caps';
    const caps = Object.keys(totals);
    if (caps.length < 1 || caps.length > MANDATE_MAX_CAPS) return `totals holds 1 to ${MANDATE_MAX_CAPS} caps`;
    if (!caps.every((c) => MANDATE_NAME_RE.test(c) && isNonNegativeSafeInteger(totals[c]))) {
      return 'each total is a non-negative integer under a cap name';
    }
  }
  return null;
}

/** `hex(SHA-256(C(body)))` of a well-formed event body, or `null`. */
export function mandateEventBodyDigest(body: unknown): string | null {
  if (mandateEventBodyViolation(body) !== null) return null;
  return sha256Hex(canonicalValue(body));
}

/**
 * A mandate event body `tzun-mandate-event/1`, checked: one per state
 * change. `record` is the digest of the record that records the event (the
 * issuance record for `issued` and `expired`, the revocation record for
 * `revoked`, the successor's issuance record for `superseded`); `successor`
 * is the successor's `mandateDigest` for `superseded` and `null` otherwise;
 * `used` and `totals` are `null` for `issued` and the values at the change
 * otherwise (`totals` `null` when the document has no cap).
 *
 * @throws when the parts do not make a well-formed body.
 */
export function buildMandateEventBody(parts: {
  event: MandateEventBody['event'];
  mandateDigest: string;
  record: string;
  successor?: string | null;
  used?: number | null;
  totals?: Record<string, number> | null;
}): MandateEventBody {
  const body: MandateEventBody = {
    v: MANDATE_EVENT_VERSION,
    event: parts.event,
    mandateDigest: parts.mandateDigest,
    record: parts.record,
    successor: parts.successor ?? null,
    used: parts.used ?? null,
    totals: parts.totals ?? null,
  };
  const reason = mandateEventBodyViolation(body);
  if (reason !== null) throw new Error(`Invalid mandate event body: ${reason}`);
  if ((body.event === 'superseded') !== (body.successor !== null)) {
    throw new Error('Invalid mandate event body: successor is set exactly on a superseded event');
  }
  if ((body.event === 'issued') !== (body.used === null)) {
    throw new Error('Invalid mandate event body: used is null exactly on an issued event');
  }
  return body;
}
