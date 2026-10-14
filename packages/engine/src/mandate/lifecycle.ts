/**
 * The mandate lifecycle, as pure functions (Record §9.6): what a
 * capture under a mandate claims, the issuance and revocation records the
 * mandate API captures, and the refusals of revocation, succession and
 * confirmation. The SDKs' mandate services call these, so TypeScript and
 * Python claim, issue and refuse alike; the storage and the ceremony
 * verification are theirs.
 */
import { assertionDigest } from './assertion-digest';
import { isMandateInstant, mandateDigest } from './document';
import { MANDATE_AI_SYSTEM_ID, MANDATE_ISSUE_ACTION, MANDATE_REVOKE_ACTION } from './issuance';
import { checkMandateLimits, deciderInMandate, evaluateMandateConfirm, evaluateMandateScope, mandateCapValues } from './scope';
import { mandateStatementDigest } from './statement';
import { compareLinks, linksGrammarViolation } from '../links';
import { isNonNegativeSafeInteger, isPlainObject } from '../record-rules-util';
import type { Decider } from '../types/decider';
import type { EnvelopeInput, WebauthnAssertion } from '../types/evidence';
import type { Link, LinkTarget } from '../types/links';
import type {
  MandateCapClaim,
  MandateClaimPlan,
  MandateDocument,
  MandateExpectation,
  MandateRecordState,
  MandateStatement,
  MandateViolationCode,
} from '../types/mandate';

function refused(code: MandateViolationCode, field: string, message: string, extra: object = {}): MandateClaimPlan {
  return { ok: false, code, field, message, ...extra };
}

/**
 * What a capture under a mandate claims (Record §9.6), or why it is
 * refused, from the mandate document, the mandate record's state, the
 * record's payload as built so far (its `decider`, `aiSystemId`, `action`,
 * `aiOutput`, `contributions`, `links`, `capturedAt` and `schemaVersion`;
 * its expectation is what this plans) and `issuance`, the `mandate` link's
 * target. Every predicate, cap path and scope constraint is read over the
 * payload with its final `links`: the payload's links with the `mandate`
 * link added (kept once when the payload already carries that pair), sorted,
 * which the plan returns for the capture to write. A verifier reads the
 * stored record, so a predicate over `/links` reads the same list at claim
 * and at verification. In order:
 *
 *   - the decider's kind is `agent-mandated`, and it is one of the document's
 *     agents (`agent_not_in_mandate`);
 *   - the mandate is open (`mandate_not_open`);
 *   - `capturedAt` is inside the validity window (`outside_validity`; past
 *     `notAfter` also sets `expired`, so the caller moves the mandate to
 *     `expired` with its event, in a transaction of its own);
 *   - the record's schema version is the document's (`schema_version_mismatch`);
 *   - the scope is within (`outside_scope`, `scope_undeterminable`, with the
 *     findings), read with the confirmation flag below;
 *   - the confirmation flag: `true` when a confirm predicate holds, `false`
 *     when none holds and none is undeterminable, refused otherwise
 *     (`confirm_undeterminable`);
 *   - each cap's value is a non-negative integer (`cap_value_invalid`);
 *   - a slot is free (`mandate_full`) and every new total within its cap
 *     (`cap_exceeded`).
 *
 * The plan's expectation is `{ mandateAssertion, mandateSeq: used + 1,
 * totals, confirm }`; `expectUsed` and `caps` are the claim's
 * compare-and-swap guards. A freshness reference where one is required is
 * the capture's check, not this one. Never throws.
 */
export function planMandateClaim(args: {
  document: unknown;
  mandate: MandateRecordState;
  payload: Record<string, unknown>;
  assertionDigest: string;
  /** The issuance record, as the `mandate` link names it: digest, evidence id and locator from the mandate row and the store. */
  issuance: LinkTarget;
}): MandateClaimPlan {
  const d = isPlainObject(args.document) ? (args.document as Record<string, unknown>) : {};
  const links = linksWithMandate(args.payload.links, args.issuance);
  const p: Record<string, unknown> = { ...args.payload, links };
  const decider = isPlainObject(p.decider) ? p.decider : null;
  if (decider === null || decider.kind !== 'agent-mandated') {
    return refused('agent_not_in_mandate', 'decider.kind', 'a decision under a mandate has the decider kind agent-mandated');
  }
  if (!deciderInMandate(decider, d.agents)) {
    return refused('agent_not_in_mandate', 'decider', "the decider is not one of the mandate's agents");
  }
  if (args.mandate.state !== 'open') return refused('mandate_not_open', 'mandate', 'the mandate is not open');
  const validity = isPlainObject(d.validity) ? d.validity : {};
  const at = typeof p.capturedAt === 'string' ? Date.parse(p.capturedAt) : NaN;
  if (Number.isNaN(at)) return refused('outside_validity', 'capturedAt', "the record's capturedAt is not an instant");
  if (typeof validity.notBefore === 'string' && at < Date.parse(validity.notBefore)) {
    return refused('outside_validity', 'capturedAt', "the record's capturedAt is before the mandate's validity window");
  }
  if (typeof validity.notAfter === 'string' && at > Date.parse(validity.notAfter)) {
    return refused('outside_validity', 'capturedAt', "the record's capturedAt is after the mandate's validity window", { expired: true });
  }
  if (p.schemaVersion !== d.schemaVersion) {
    return refused('schema_version_mismatch', 'schemaVersion', "the record's schema version is not the mandate document's");
  }
  const limits = isPlainObject(d.limits) ? d.limits : {};
  const cumulative = isPlainObject(limits.cumulative) ? (limits.cumulative as Record<string, { max: number }>) : null;
  const used = args.mandate.used;
  const { values, invalid } = mandateCapValues(d, p);
  const caps: MandateCapClaim[] = [];
  let totals: Record<string, number> | null = null;
  if (cumulative !== null && values !== null) {
    totals = {};
    for (const cap of Object.keys(cumulative).sort()) {
      const expectTotal = args.mandate.totals?.[cap] ?? 0;
      const newTotal = expectTotal + (values[cap] ?? 0);
      totals[cap] = newTotal;
      caps.push({ cap, expectTotal, newTotal });
    }
  }
  const confirm = evaluateMandateConfirm(d, p);
  const expectation: MandateExpectation = {
    mandateAssertion: args.assertionDigest,
    mandateSeq: used + 1,
    totals,
    // An undeterminable flag is refused below; the scope is read as if one
    // were owed, so its other constraints are reported first.
    confirm: confirm.confirm ?? true,
  };
  const scope = evaluateMandateScope(d, { ...p, signoffExpectation: expectation });
  if (scope.verdict === 'outside') {
    return refused('outside_scope', 'payload', "the record is outside the mandate's scope", { findings: scope.failures });
  }
  if (scope.verdict === 'undeterminable') {
    return refused('scope_undeterminable', 'payload', "the record's scope cannot be determined", { findings: scope.undeterminable });
  }
  if (confirm.confirm === null) {
    return refused('confirm_undeterminable', 'confirm', 'no confirm predicate holds and one cannot be evaluated', {
      findings: confirm.undeterminable.map((name) => ({ constraint: 'confirm', name })),
    });
  }
  if (invalid.length > 0) {
    return refused(
      'cap_value_invalid',
      `limits.cumulative.${invalid[0]}`,
      `the value at the path of cap ${invalid[0]} is not a non-negative integer`,
    );
  }
  if (isNonNegativeSafeInteger(limits.maxRecords) && used >= limits.maxRecords) {
    return refused('mandate_full', 'mandate', 'every slot of the mandate is used');
  }
  for (const c of caps) {
    if (!Number.isSafeInteger(c.newTotal) || c.newTotal > cumulative![c.cap].max) {
      return refused('cap_exceeded', `limits.cumulative.${c.cap}`, `the record would take cap ${c.cap} past its maximum`);
    }
  }
  const check = checkMandateLimits(d, { ...p, signoffExpectation: expectation });
  if (!check.valid) return refused('cap_exceeded', 'limits', 'the planned slot and totals break the mandate limits');
  return { ok: true, expectation, links, expectUsed: used, caps, confirmHolding: confirm.holding };
}

/**
 * The payload's links with the `mandate` link to `issuance` added, sorted by
 * (`rel`, `target.digest`). A payload that already carries that pair keeps
 * its link once. Anything else is left to the payload gate: a second
 * `mandate` link is refused there (`mandate_link`); links, or an issuance
 * target, that do not meet the grammar are kept as they are, the mandate
 * link after them, unsorted, so the gate refuses them too.
 */
function linksWithMandate(links: unknown, issuance: LinkTarget): Link[] {
  const own: unknown[] = links === null || links === undefined ? [] : Array.isArray(links) ? links : [links];
  const t = (isPlainObject(issuance) ? issuance : {}) as Partial<LinkTarget>;
  const mandateLink: Link = {
    rel: 'mandate',
    target: {
      digest: t.digest as string,
      evidenceId: t.evidenceId ?? null,
      locator: isPlainObject(t.locator) ? { ...t.locator } : null,
    },
    attrs: null,
  };
  if (linksGrammarViolation(own.length === 0 ? null : own) !== null || linksGrammarViolation([mandateLink]) !== null) {
    return [...own, mandateLink] as Link[];
  }
  const list = own as Link[];
  const present = list.some((l) => l.rel === 'mandate' && l.target.digest === t.digest);
  return (present ? [...list] : [...list, mandateLink]).sort(compareLinks);
}

/** The `decider` of a mandate's issuance record: the principal, `acct:<principal.signer>`. */
export function mandatePrincipalDecider(document: MandateDocument, freshness: string | null = null): Decider {
  return { kind: 'human', id: `acct:${document.principal.signer}`, agent: null, credential: document.principal.credential, freshness };
}

/**
 * The capture input of a mandate's issuance record (Record §9.6): `aiSystemId`
 * `tzun:mandate`, action `issue-mandate`, `aiOutput { mandateDigest,
 * statementDigest, assertionDigest }`, the principal as decider, no
 * contributions, and a `supersedes` link to the predecessor's issuance record
 * for a successor. Captured with `systemRecord: 'mandate'` and the issuance
 * material in `nonRepudiation.mandateIssuance`.
 *
 * @throws when the document or statement is not well formed, or the assertion has no digest.
 */
export function mandateIssuanceInput(args: {
  document: MandateDocument;
  statement: MandateStatement;
  assertion: WebauthnAssertion;
  reason: string;
  predecessorIssuance?: LinkTarget | null;
  freshness?: string | null;
}): EnvelopeInput {
  const mDigest = mandateDigest(args.document);
  const sDigest = mandateStatementDigest(args.statement);
  const aDigest = assertionDigest(args.assertion);
  if (mDigest === null || sDigest === null || aDigest === null) {
    throw new Error('An issuance record needs a well-formed document and statement, and an assertion with a digest.');
  }
  return {
    aiSystemId: MANDATE_AI_SYSTEM_ID,
    aiOutput: { assertionDigest: aDigest, mandateDigest: mDigest, statementDigest: sDigest },
    action: MANDATE_ISSUE_ACTION,
    reason: args.reason,
    decider: mandatePrincipalDecider(args.document, args.freshness ?? null),
    contributions: null,
    links: args.predecessorIssuance ? [{ rel: 'supersedes', target: args.predecessorIssuance, attrs: null }] : null,
  };
}

/**
 * Why a revocation's claimed instant is refused (Record §9.6), or `null`: an ISO
 * 8601 UTC instant with milliseconds, no later than the revocation record's
 * `capturedAt` (the state moves to `revoked` at capture, so a future instant
 * would misstate when claims stopped). An earlier instant is recorded as
 * claimed.
 */
export function revocationInstantViolation(
  claimedRevocationInstant: unknown,
  capturedAt: string,
): { code: 'invalid_revocation_instant'; field: string; message: string } | null {
  if (!isMandateInstant(claimedRevocationInstant) || Date.parse(claimedRevocationInstant) > Date.parse(capturedAt)) {
    return {
      code: 'invalid_revocation_instant',
      field: 'effectiveAt',
      message: 'effectiveAt must be an ISO 8601 UTC instant with milliseconds, no later than the revocation is captured',
    };
  }
  return null;
}

/**
 * The capture input of a revocation record (Record §9.6): `aiSystemId`
 * `tzun:mandate`, action `revoke-mandate`, `aiOutput { mandateDigest,
 * statementDigest, claimedRevocationInstant, reason }`, the revoker (the user
 * the asserting credential is registered to) as decider, and a `revokes`
 * link to the issuance record. Captured with `systemRecord: 'mandate'`, the
 * expectation `null` and the revoker's per-record assertion.
 */
export function mandateRevocationInput(args: {
  mandateDigest: string;
  statementDigest: string;
  claimedRevocationInstant: string;
  reason: string;
  revokerUserId: string;
  issuance: LinkTarget;
  freshness?: string | null;
}): EnvelopeInput {
  return {
    aiSystemId: MANDATE_AI_SYSTEM_ID,
    aiOutput: {
      claimedRevocationInstant: args.claimedRevocationInstant,
      mandateDigest: args.mandateDigest,
      reason: args.reason,
      statementDigest: args.statementDigest,
    },
    action: MANDATE_REVOKE_ACTION,
    reason: args.reason,
    decider: { kind: 'human', id: `acct:${args.revokerUserId}`, agent: null, credential: null, freshness: args.freshness ?? null },
    contributions: null,
    links: [{ rel: 'revokes', target: args.issuance, attrs: null }],
  };
}

/**
 * Why a successor's document is refused against its predecessor's,
 * or `null`: its `predecessor` is the predecessor's `mandateDigest`, and it
 * names the same principal (`predecessor_principal_mismatch`: a new principal
 * revokes the old mandate and issues afresh).
 */
export function predecessorPrincipalViolation(
  document: MandateDocument,
  predecessor: MandateDocument,
): { code: 'predecessor_principal_mismatch'; field: string; message: string } | null {
  if (document.predecessor !== mandateDigest(predecessor) || document.principal.signer !== predecessor.principal.signer) {
    return {
      code: 'predecessor_principal_mismatch',
      field: 'document.predecessor',
      message: "a successor names its predecessor's digest and the same principal",
    };
  }
  return null;
}

/**
 * Why a confirmation of a stored record is refused (Record §9.6), or `null`: the
 * record's expectation is the mandate form with `confirm: true`
 * (`confirmation_not_owed`), and it carries no confirmation yet
 * (`already_confirmed`: the member is fill-only and filled once).
 *
 * It reads the envelope it is given, a snapshot: two confirmations of one
 * record can both pass it. The store's write of `nonRepudiation.confirmation`
 * is therefore fill-only (written only where it is still null, under the
 * record's lock, as `updateAttestation` fills a component), so a second
 * confirmation never replaces the first.
 */
export function mandateConfirmationViolation(
  envelope: unknown,
): { code: 'confirmation_not_owed' | 'already_confirmed'; field: string; message: string } | null {
  const env = isPlainObject(envelope) ? envelope : {};
  const payload = isPlainObject(env.payload) ? env.payload : {};
  const expectation = isPlainObject(payload.signoffExpectation) ? payload.signoffExpectation : {};
  if (expectation.confirm !== true || !('mandateAssertion' in expectation)) {
    return { code: 'confirmation_not_owed', field: 'signoffExpectation.confirm', message: 'the record owes no confirmation' };
  }
  const nr = isPlainObject(env.nonRepudiation) ? env.nonRepudiation : {};
  if (nr.confirmation !== undefined && nr.confirmation !== null) {
    return { code: 'already_confirmed', field: 'nonRepudiation.confirmation', message: 'the record is already confirmed' };
  }
  return null;
}

/** Whether a mandate whose window ends at `notAfter` has expired at `instant` (later than `notAfter`). */
export function mandateExpiredAt(notAfter: string | null, instant: string): boolean {
  return notAfter !== null && Date.parse(instant) > Date.parse(notAfter);
}
