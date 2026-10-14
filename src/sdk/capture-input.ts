/**
 * The capture input's shape rules, checked before anything is resolved,
 * built or hashed, and the translation of the engine's builder refusals into
 * what `capture()` reports.
 *
 * A refusal is `FailureRecord { failureType: 'validation_failure',
 * diagnosticMetadata: { field, reason, code, message, ... } }`: `reason` and
 * `code` are the refusal's code (`invalid_action`, `renamed_field`,
 * `not_a_set`, …), `field` names the member, and `message` names the field
 * and the rule. Nothing here echoes a value: `providedType` is the most a
 * refusal says about what was given.
 */
import {
  ContributionsBuildError,
  EnvelopeInputError,
  LinksBuildError,
  actionViolation,
  aiSystemIdViolation,
  canonicalSerialize,
  capturedAtViolation,
  describeSignoffExpectationViolation,
  isEvidenceId,
  isMandateExpectation,
  isSessionAttachmentExpectation,
  movedFieldViolation,
  reasonViolation,
  renamedFieldViolation,
  signoffExpectationViolation,
} from '@tzun/engine';
import type { AiBom, AiBomWithInlineDescriptor, SignatureRequiredExpectation } from '@tzun/engine';

/** A refusal's diagnostic metadata. */
export interface CaptureInputViolation {
  /** The member it concerns, e.g. `action`, `decider.kind`, `contributions.steps[1].inputs`, `prepared.evidenceId`. */
  field: string;
  /** The code (the same value as `code`). */
  reason: string;
  code: string;
  /** Names the field and the rule; never a value. */
  message: string;
  /** What was given, by type, when that helps. */
  providedType?: string;
  /** `renamed_field`: the field's new name. */
  renamedTo?: string;
  /** `moved_field`: where the field's content now lives. */
  movedTo?: string;
  /** The index of the step or link concerned. */
  step?: number;
  link?: number;
  /** A broken link rule. */
  rule?: string;
}

function violation(field: string, code: string, message: string, extra: Partial<CaptureInputViolation> = {}): CaptureInputViolation {
  return { field, reason: code, code, message, ...extra };
}

/** The members `CaptureInput.decider` takes. */
const DECIDER_INPUT_KEYS = ['kind', 'id', 'agent', 'credential', 'freshness', 'commit'];

/** The members `CaptureInput` takes. */
const CAPTURE_INPUT_KEYS = ['aiSystemId', 'aiOutput', 'action', 'reason', 'decider', 'contributions', 'links', 'attestationInputs'];

/**
 * The capture input's shape, first failure first:
 *
 *   - an object;
 *   - no 0.7 name: `humanAction`, `humanReason`, `reviewer` (`renamed_field`),
 *     a top-level `aiBom` or `lineage` (`moved_field`);
 *   - no other member outside the input's (`unknown_payload_member`);
 *   - `aiOutput` a plain object; `action` and `reason` as the engine's
 *     payload rules; `aiSystemId` absent or a non-empty string that is not a
 *     reserved `tzun:` id;
 *   - `decider` an object of `DeciderInput`'s members (`missing_members`,
 *     `unknown_members`);
 *   - `contributions` absent, `null` or an object; `links` absent, `null` or
 *     a non-empty array (`empty_links`: "no link" is `null`).
 *
 * `CaptureInput` declares these types, but `POST /v1/evidence` and the vendor
 * wrappers hand `capture()` whatever they were given, so the rule runs here
 * at runtime. The members' own grammars (the decider's, contributions',
 * links') are the engine's, applied when the record is built.
 */
export function captureInputViolation(input: unknown): CaptureInputViolation | null {
  if (!isPlainObject(input)) {
    return violation('input', 'missing_members', 'capture input must be an object', { providedType: describeType(input) });
  }
  const moved = renamedFieldViolation(input) ?? movedFieldViolation(input);
  if (moved) {
    return violation(moved.field, moved.code, moved.message, {
      ...(moved.renamedTo !== undefined && { renamedTo: moved.renamedTo }),
      ...(moved.movedTo !== undefined && { movedTo: moved.movedTo }),
    });
  }
  const unknown = Object.keys(input).find((k) => !CAPTURE_INPUT_KEYS.includes(k));
  if (unknown !== undefined) {
    return violation(unknown, 'unknown_payload_member', `${unknown} is not a member of the capture input`);
  }
  if (!isPlainObject(input.aiOutput)) {
    return violation('aiOutput', 'invalid_ai_output', 'aiOutput is required and must be a plain object', {
      providedType: describeType(input.aiOutput),
    });
  }
  const member = actionViolation(input.action) ?? reasonViolation(input.reason);
  if (member) return violation(member.field, member.code, member.message, { providedType: describeType(input[member.field]) });
  if (input.aiSystemId != null) {
    const id = aiSystemIdViolation(input.aiSystemId);
    if (id) return violation(id.field, id.code, id.message, { providedType: describeType(input.aiSystemId) });
  }
  if (input.decider === undefined || input.decider === null) {
    return violation('decider', 'missing_members', 'decider is required: who decided, for example { kind: "human", id: "acct:<account id>" }');
  }
  if (!isPlainObject(input.decider)) {
    return violation('decider', 'not_an_object', 'decider must be an object', { providedType: describeType(input.decider) });
  }
  const deciderKey = Object.keys(input.decider).find((k) => !DECIDER_INPUT_KEYS.includes(k));
  if (deciderKey !== undefined) {
    return violation(`decider.${deciderKey}`, 'unknown_members', `decider.${deciderKey} is not a member of a decider input`);
  }
  if (input.contributions != null && !isPlainObject(input.contributions)) {
    return violation('contributions', 'not_an_object', 'contributions must be an object or null', {
      providedType: describeType(input.contributions),
    });
  }
  if (input.links != null) {
    if (!Array.isArray(input.links)) {
      return violation('links', 'not_an_array', 'links must be an array or null', { providedType: describeType(input.links) });
    }
    if (input.links.length === 0) {
      return violation('links', 'empty_links', 'links must not be empty: write null (or leave it out) for no link');
    }
  }
  return null;
}

/**
 * The identity rule for a `prepared` capture. `prepared.evidenceId` and
 * `prepared.capturedAt` become the stored record's evidenceId and capturedAt,
 * so they are held to the platform's rules for a client-chosen identity: the
 * evidenceId is a v4 UUID, and capturedAt is an ISO-8601 date-time no more
 * than five minutes ahead of now (`@tzun/engine` capture-claims). Returns the
 * first violation, or `null` when there is no `prepared` or it conforms.
 */
export function preparedIdentityViolation(prepared: unknown): CaptureInputViolation | null {
  if (prepared === undefined) return null;
  if (!isPlainObject(prepared)) {
    return violation('prepared', 'invalid_prepared', 'prepared must be the object prepareAssertionChallenge() returned', {
      providedType: describeType(prepared),
    });
  }
  const { evidenceId, capturedAt } = prepared;
  if (!isEvidenceId(evidenceId)) {
    return violation('prepared.evidenceId', 'invalid_evidence_id', 'prepared.evidenceId must be a v4 UUID', {
      providedType: describeType(evidenceId),
    });
  }
  const refusal = capturedAtViolation(capturedAt);
  if (refusal) {
    return violation(
      'prepared.capturedAt',
      'invalid_captured_at',
      refusal === 'future_dated'
        ? 'prepared.capturedAt is more than five minutes in the future'
        : 'prepared.capturedAt must be an ISO-8601 date-time with a zone',
      { providedType: describeType(capturedAt) },
    );
  }
  if (!isPlainObject(prepared.decider)) {
    return violation('prepared.decider', 'invalid_prepared', 'prepared must be the object prepareAssertionChallenge() returned', {
      providedType: describeType(prepared.decider),
    });
  }
  return null;
}

/**
 * The rule for a capture's `signoffExpectation` (Record §9.1, §9.2). The
 * value becomes the record's hashed `payload.signoffExpectation`, so it is
 * checked before anything is built:
 *
 *   - it is `null`, absent, or exactly `{ policyDigest }` with 64 lowercase
 *     hex (the engine's `signoffExpectationViolation`);
 *   - it is not the session form, which only the capture that claimed a
 *     session slot may write (this SDK opens no sign-off sessions), and not
 *     the mandate form, which only `capture(…, { mandate })` writes;
 *   - with `mandate`, it is absent or `null`;
 *   - with `prepared`, `prepared.signoffExpectation` passes the same rules,
 *     and an explicit `signoffExpectation` equals it: the ceremony signed a
 *     digest over the prepared one.
 *
 * Each value is read once and copied, and the copies are what the rules
 * judge and what is returned.
 */
export function settleSignoffExpectation(
  options: { signoffExpectation?: unknown; prepared?: unknown; mandate?: unknown } | undefined,
): { expectation: SignatureRequiredExpectation | null } | { violation: CaptureInputViolation } {
  const given = snapshot(options?.signoffExpectation);
  const refusal = expectationRefusal('signoffExpectation', given);
  if (refusal) return { violation: refusal };
  if (options?.mandate !== undefined && given != null) {
    return {
      violation: violation(
        'signoffExpectation',
        'expectation_with_mandate',
        'signoffExpectation cannot be given with mandate: a capture under a mandate writes the mandate form itself',
      ),
    };
  }

  const prepared = options?.prepared;
  if (!isPlainObject(prepared)) return { expectation: (given ?? null) as SignatureRequiredExpectation | null };
  const preparedExpectation = snapshot(prepared.signoffExpectation);
  const preparedRefusal = expectationRefusal('prepared.signoffExpectation', preparedExpectation);
  if (preparedRefusal) return { violation: preparedRefusal };
  if (given !== undefined && !sameCanonical(given, preparedExpectation)) {
    return {
      violation: violation(
        'signoffExpectation',
        'prepared_expectation_differs',
        'signoffExpectation differs from prepared.signoffExpectation, which is inside the digest ' +
          'the ceremony signed; omit it, or prepare the record with this one',
        { providedType: describeType(given) },
      ),
    };
  }
  return { expectation: (preparedExpectation ?? null) as SignatureRequiredExpectation | null };
}

function expectationRefusal(field: 'signoffExpectation' | 'prepared.signoffExpectation', value: unknown): CaptureInputViolation | null {
  const shape = signoffExpectationViolation(value);
  if (shape !== null) {
    return violation(field, shape, describeSignoffExpectationViolation(shape).replace(/^signoffExpectation/, field), {
      providedType: describeType(value),
    });
  }
  if (isSessionAttachmentExpectation(value)) {
    return violation(
      field,
      'session_form_not_writable',
      `${field} names a sign-off session slot ({ statementDigest, sessionSeq }); only the capture ` +
        'that claimed the slot may write that, and this SDK opens no sign-off sessions',
      { providedType: describeType(value) },
    );
  }
  if (isMandateExpectation(value)) {
    return violation(
      field,
      'mandate_form_not_writable',
      `${field} is the mandate form; only capture(input, { mandate: { mandateId } }) writes it, from the mandate's claim`,
      { providedType: describeType(value) },
    );
  }
  return null;
}

/** A plain object copied member by member, each read once; any other value as it is. */
function snapshot(value: unknown): unknown {
  return isPlainObject(value) ? { ...value } : value;
}

/** Whether two values (`undefined` reading as `null`) have the same canonical bytes. */
export function sameCanonical(a: unknown, b: unknown): boolean {
  const bytes = (v: unknown) => canonicalSerialize({ v: v ?? null }, ['v']);
  return bytes(a) === bytes(b);
}

/**
 * An engine builder's refusal (`EnvelopeInputError`, `ContributionsBuildError`,
 * `LinksBuildError`) as a capture refusal, or `null` for any other error.
 */
export function engineRefusal(error: unknown): CaptureInputViolation | null {
  if (error instanceof EnvelopeInputError) {
    // A links refusal names its link rule (`subject_link`, `at_most_one`,
    // `revokes_link`, `mandate_link`) as `linkRule`, beside the member.
    return violation(error.field, error.code, error.message, {
      rule: error.rule,
      ...(error.linkRule !== undefined && { linkRule: error.linkRule }),
    });
  }
  if (error instanceof ContributionsBuildError) {
    return violation(error.field, error.code, error.message, error.step !== undefined ? { step: error.step } : {});
  }
  if (error instanceof LinksBuildError) {
    return violation(error.field, error.code, error.message, {
      ...(error.link !== undefined && { link: error.link }),
      ...(error.rule !== undefined && { rule: error.rule }),
    });
  }
  return null;
}

/** A refusal of a capture with the given code, for a member the SDK resolves. */
export function resolutionRefusal(field: string, code: string, message: string): CaptureInputViolation {
  return violation(field, code, message);
}

/**
 * An object whose prototype is `Object.prototype` or `null`: the test the
 * canonical serializer applies to every object it serialises.
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/**
 * Past this depth `toJsonDataModel` returns the value as it is. The canonical
 * serializer refuses anything nested this deep (its limit is lower), so the
 * record is refused there, and a cyclic `aiOutput` cannot overflow the stack
 * here first.
 */
const JSON_DATA_MODEL_MAX_DEPTH = 128;

/**
 * The value `JSON.parse(JSON.stringify(value))` gives back, for the JSON
 * parts of it: an `undefined` object member is dropped, and an `undefined`
 * array element or a hole becomes `null`. Plain objects and arrays are
 * copied, never mutated; every other value is returned as it is, so what the
 * canonical serializer refuses (a Date, a function, NaN) it still refuses.
 *
 * Capture hashes the payload with the canonical serializer, which writes an
 * `undefined` member as `null`. Every store and the cloud transport keep the
 * payload as JSON, which drops the member. Hashing the normalised copy makes
 * those the same bytes, so the digest a capture reports is the digest its
 * stored record recomputes to, and the one the platform computes from the
 * request body.
 */
export function toJsonDataModel(value: unknown, depth = 0): unknown {
  if (depth > JSON_DATA_MODEL_MAX_DEPTH) return value;
  if (Array.isArray(value)) {
    return Array.from(value, (item) => (item === undefined ? null : toJsonDataModel(item, depth + 1)));
  }
  if (isPlainObject(value)) {
    const copy: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      const member = value[key];
      if (member === undefined) continue;
      // defineProperty, not assignment: an own `__proto__` key (JSON.parse
      // makes one) must stay a member, not become the copy's prototype.
      Object.defineProperty(copy, key, {
        value: toJsonDataModel(member, depth + 1),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return copy;
  }
  return value;
}

/** `typeof`, with null, arrays and class instances told apart. */
export function describeType(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'object' && !isPlainObject(value)) {
    return (value as object).constructor?.name ?? 'object';
  }
  return typeof value;
}

/** Whether an `AiBom` input carries its descriptor inline (the convenience form) rather than its digest. */
export function isInlineDescriptorForm(value: AiBom | AiBomWithInlineDescriptor): value is AiBomWithInlineDescriptor {
  return isPlainObject(value) && 'modelDescriptor' in value;
}
