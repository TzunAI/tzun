/**
 * One gate for every writer rule of a built payload (Record §2.2): the SDK's
 * `buildEvidencePayload` runs it over the payload it builds, and a platform
 * runs it over a partial or sealed envelope's payload, so the two refuse the
 * same bytes for the same reason.
 */
import { contributionsViolation } from './contributions';
import { deciderAgreesWithExpectation, deciderViolation, deciderViolationOf } from './decider';
import { linksViolation } from './links';
import {
  PAYLOAD_MEMBERS,
  actionViolation,
  aiOutputViolation,
  aiSystemIdViolation,
  captureTimeViolation,
  evidenceIdViolation,
  movedFieldViolation,
  payloadSizeViolation,
  reasonViolation,
  renamedFieldViolation,
  sequenceNumberViolation,
} from './payload-rules';
import type { SystemRecordKind } from './payload-rules';
import { isPlainObject } from './record-rules-util';
import { CURRENT_SCHEMA_VERSION, V1_0_HASHED_FIELDS } from './schema-registry';
import { describeSignoffExpectationViolation, signoffExpectationViolation } from './signoff-expectation';

/** The member whose closed list a record-rule refusal's code is from. */
export type EnvelopeInputRule = 'payload' | 'decider' | 'contributions' | 'links' | 'signoffExpectation' | 'mandate';

/** A writer's refusal of a payload: the member's rule, its code, the field, and a message that never echoes a value. */
export interface RecordRuleViolation {
  rule: EnvelopeInputRule;
  code: string;
  field: string;
  message: string;
  /** For a `links` refusal that names a rule: the rule (`mandate_link`, `subject_link`, ...). */
  linkRule?: string;
}

/** Options of {@link payloadRecordRuleViolation}. */
export interface PayloadRecordRuleOptions {
  /**
   * A system record, admitting the one reserved `aiSystemId` of its kind:
   * `mandate` admits `tzun:mandate` (the SDK's mandate issuance and
   * revocation records), `link` admits `tzun:link` (link records, which the
   * SDK's link API writes and a platform admits when the link-record rules
   * hold). Never set from a caller's ordinary capture; by default every
   * `tzun:` prefix is refused (`reserved_ai_system_id`), and each kind
   * refuses the other's id.
   */
  systemRecord?: SystemRecordKind;
}

function of(rule: EnvelopeInputRule, v: { code: string; field: string; message: string }): RecordRuleViolation {
  return { rule, code: v.code, field: v.field, message: v.message };
}

/**
 * Why a built payload is not one a writer may hash, first failure first, or
 * `null` when it is one. Never throws. In order:
 *
 *   1. the renamed 0.7 names `humanAction`, `humanReason` and `reviewer`
 *      (`renamed_field`), and the moved `aiBom` and `lineage`
 *      (`moved_field`);
 *   2. `schemaVersion` is `v1.0` (`unsupported_schema_version`);
 *   3. no member outside the twelve names (`unknown_payload_member`), and
 *      every one of them written (`missing_members`);
 *   4. `evidenceId` (a v4 UUID), `capturedAt` (ISO-8601), `sequenceNumber`
 *      (a safe integer of at least 1), `aiSystemId` (non-empty; `tzun:` only
 *      for a system record of its kind), `aiOutput`, `action`, `reason`;
 *   5. `decider` (`decider`), the expectation (`signoffExpectation`) and
 *      their agreement (`decider`/`kind_contradicts_expectation`);
 *   6. `contributions`, against the payload's own decider, action and reason
 *      (`contributions`);
 *   7. `links`: grammar, registry, profiles, record-local and list-level
 *      rules (`links`);
 *   8. the 256 KiB cap on the hashed object (`payload_too_large`).
 *
 * Steps 1 to 4 and 8 are `payload` refusals.
 */
export function payloadRecordRuleViolation(
  payload: unknown,
  options: PayloadRecordRuleOptions = {},
): RecordRuleViolation | null {
  if (!isPlainObject(payload)) {
    return of('payload', {
      code: 'missing_members',
      field: 'payload',
      message: 'payload must be an object with every member of the format',
    });
  }
  const renamed = renamedFieldViolation(payload) ?? movedFieldViolation(payload);
  if (renamed) return of('payload', renamed);

  if (payload.schemaVersion !== CURRENT_SCHEMA_VERSION) {
    return of('payload', {
      code: 'unsupported_schema_version',
      field: 'schemaVersion',
      message: `schemaVersion must be ${CURRENT_SCHEMA_VERSION}`,
    });
  }
  const unknown = Object.keys(payload).find((k) => !PAYLOAD_MEMBERS.includes(k));
  if (unknown !== undefined) {
    return of('payload', {
      code: 'unknown_payload_member',
      field: unknown,
      message: `${unknown} is not a member of the payload`,
    });
  }
  const missing = PAYLOAD_MEMBERS.find((k) => !Object.prototype.hasOwnProperty.call(payload, k));
  if (missing !== undefined) {
    return of('payload', {
      code: 'missing_members',
      field: missing,
      message: `${missing} is required: a writer writes every member, null where it does not apply`,
    });
  }

  const p = payload;
  const memberIssue =
    evidenceIdViolation(p.evidenceId) ??
    captureTimeViolation(p.capturedAt) ??
    sequenceNumberViolation(p.sequenceNumber) ??
    aiSystemIdViolation(p.aiSystemId === undefined ? null : p.aiSystemId, { systemRecord: options.systemRecord }) ??
    aiOutputViolation(p.aiOutput) ??
    actionViolation(p.action) ??
    reasonViolation(p.reason);
  if (memberIssue) return of('payload', memberIssue);

  const deciderIssue = deciderViolation(p.decider);
  if (deciderIssue) return of('decider', deciderIssue);
  const expectationIssue = signoffExpectationViolation(p.signoffExpectation);
  if (expectationIssue !== null) {
    return of('signoffExpectation', {
      code: expectationIssue,
      field: 'signoffExpectation',
      message: describeSignoffExpectationViolation(expectationIssue),
    });
  }
  if (deciderAgreesWithExpectation((p.decider as Record<string, unknown>).kind, p.signoffExpectation) === false) {
    return of('decider', deciderViolationOf('kind_contradicts_expectation', 'decider.kind'));
  }

  const contributionsIssue = contributionsViolation(p.contributions, {
    decider: p.decider,
    action: p.action,
    reason: p.reason,
  });
  if (contributionsIssue) return of('contributions', contributionsIssue);
  const linksIssue = linksViolation(p.links, p);
  if (linksIssue) {
    return { ...of('links', linksIssue), ...(linksIssue.rule !== undefined && { linkRule: linksIssue.rule }) };
  }

  const sizeIssue = payloadSizeViolation(p, V1_0_HASHED_FIELDS);
  if (sizeIssue) return of('payload', sizeIssue);
  return null;
}
