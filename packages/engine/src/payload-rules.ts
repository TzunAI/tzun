/**
 * Writer rules for the top-level members of a payload (Record §2.2, §11):
 * `evidenceId`, `capturedAt`, `sequenceNumber`, `action`, `reason`,
 * `aiSystemId`, `aiOutput`, the renamed and moved 0.7 fields, the members
 * outside the format, and the size cap on the hashed object. One
 * implementation for the SDK's capture and the platform's capture paths.
 *
 * A refusal names the field and the rule and never echoes the value.
 */
import { canonicalSerialize } from './canonical';
import { ISO_8601_RE, isEvidenceId } from './capture-claims';
import { hasLoneSurrogate, isPlainObject, isPositiveSafeInteger, utf8Length } from './record-rules-util';
import { V1_0_HASHED_FIELDS } from './schema-registry';
import type { PayloadViolation } from './types/evidence';

/** Every member of a payload: `schemaVersion` and the eleven hashed names, in byte order. */
export const PAYLOAD_MEMBERS: readonly string[] = Object.freeze(['schemaVersion', ...V1_0_HASHED_FIELDS].sort());

/** The most canonical bytes a hashed object may have (a writer limit). */
export const PAYLOAD_MAX_CANONICAL_BYTES = 256 * 1024;
/** The longest `action`, in characters. */
export const ACTION_MAX_LENGTH = 128;
/** The longest `reason` (and step `reason`), in UTF-16 code units. */
export const REASON_MAX_LENGTH = 16384;
/** The `aiSystemId` prefix reserved for system records (`tzun:mandate`, `tzun:link`). */
export const RESERVED_AI_SYSTEM_ID_PREFIX = 'tzun:';
/** The system records' `aiSystemId`s: mandate issuance and revocation records, and link records. */
export const SYSTEM_AI_SYSTEM_IDS: readonly string[] = Object.freeze(['tzun:mandate', 'tzun:link']);

/**
 * A kind of system record, each admitting its one reserved `aiSystemId`:
 * `mandate` (`tzun:mandate`, the SDK's issuance and revocation records) and
 * `link` (`tzun:link`, link records).
 */
export type SystemRecordKind = 'mandate' | 'link';

/** The reserved `aiSystemId` each system record kind admits. */
export const SYSTEM_RECORD_AI_SYSTEM_IDS: Readonly<Record<SystemRecordKind, string>> = Object.freeze({
  mandate: 'tzun:mandate',
  link: 'tzun:link',
});

const ACTION_RE = /^[\x20-\x7e]+$/;
/**
 * Why a record id is refused: a v4 UUID (`EVIDENCE_ID_RE` of
 * capture-claims.ts, the platform's rule for a client-chosen id).
 */
export function evidenceIdViolation(evidenceId: unknown): PayloadViolation | null {
  if (!isEvidenceId(evidenceId)) {
    return { code: 'invalid_evidence_id', field: 'evidenceId', message: 'evidenceId must be a v4 UUID' };
  }
  return null;
}

/**
 * Why a payload's capture time is refused: an ISO-8601 date-time with
 * seconds and a zone designator that `Date.parse` reads. How far ahead of
 * now a client's claim may be is the capture path's rule
 * (`capturedAtViolation` of capture-claims.ts), not the payload's.
 */
export function captureTimeViolation(capturedAt: unknown): PayloadViolation | null {
  if (typeof capturedAt !== 'string' || !ISO_8601_RE.test(capturedAt) || Number.isNaN(Date.parse(capturedAt))) {
    return { code: 'invalid_captured_at', field: 'capturedAt', message: 'capturedAt must be an ISO-8601 timestamp' };
  }
  return null;
}

/**
 * Why a sequence number is refused: a JSON number that is a safe integer of
 * at least 1. A string (`"3"`), a fraction and a boolean are refused before
 * hashing; `3.0` is the integer 3.
 */
export function sequenceNumberViolation(sequenceNumber: unknown): PayloadViolation | null {
  if (!isPositiveSafeInteger(sequenceNumber)) {
    return {
      code: 'invalid_sequence_number',
      field: 'sequenceNumber',
      message: 'sequenceNumber must be a safe integer of at least 1',
    };
  }
  return null;
}

/** Why `action` is refused: 1 to 128 printable ASCII characters (0x20–0x7E), no leading or trailing space. */
export function actionViolation(action: unknown): PayloadViolation | null {
  if (
    typeof action !== 'string' ||
    action.length < 1 ||
    action.length > ACTION_MAX_LENGTH ||
    !ACTION_RE.test(action) ||
    action.startsWith(' ') ||
    action.endsWith(' ')
  ) {
    return {
      code: 'invalid_action',
      field: 'action',
      message:
        `action must be 1 to ${ACTION_MAX_LENGTH} printable ASCII characters (0x20-0x7E) ` +
        'with no leading or trailing space',
    };
  }
  return null;
}

/** Why a reason is refused: 1 to 16,384 UTF-16 code units with no lone surrogate. */
export function reasonViolation(reason: unknown, field = 'reason'): PayloadViolation | null {
  if (typeof reason !== 'string' || reason.length < 1 || reason.length > REASON_MAX_LENGTH || hasLoneSurrogate(reason)) {
    return {
      code: 'invalid_reason',
      field,
      message: `${field} must be a string of 1 to ${REASON_MAX_LENGTH} UTF-16 code units with no lone surrogate`,
    };
  }
  return null;
}

/**
 * Why a caller's `aiSystemId` is refused: absent is accepted (the writer uses
 * `default`); otherwise a non-empty string, not beginning with `tzun:`,
 * which only system records use (`tzun:mandate`, `tzun:link`).
 * `systemRecord` admits the one reserved id of that kind: `mandate` for the
 * SDK's own mandate API, `link` for its link API and for a platform
 * admitting a link record. Never set for a caller's ordinary capture.
 */
export function aiSystemIdViolation(
  aiSystemId: unknown,
  options: { systemRecord?: SystemRecordKind } = {},
): PayloadViolation | null {
  if (aiSystemId === undefined) return null;
  if (typeof aiSystemId !== 'string' || aiSystemId.length === 0) {
    return { code: 'invalid_ai_system_id', field: 'aiSystemId', message: 'aiSystemId must be a non-empty string' };
  }
  const admitted =
    options.systemRecord !== undefined && Object.prototype.hasOwnProperty.call(SYSTEM_RECORD_AI_SYSTEM_IDS, options.systemRecord)
      ? SYSTEM_RECORD_AI_SYSTEM_IDS[options.systemRecord]
      : null;
  if (aiSystemId.startsWith(RESERVED_AI_SYSTEM_ID_PREFIX) && aiSystemId !== admitted) {
    return {
      code: 'reserved_ai_system_id',
      field: 'aiSystemId',
      message: `aiSystemId may not begin with "${RESERVED_AI_SYSTEM_ID_PREFIX}", which system records use`,
    };
  }
  return null;
}

/** Why `aiOutput` is refused at capture: it must be a plain object. */
export function aiOutputViolation(aiOutput: unknown): PayloadViolation | null {
  if (!isPlainObject(aiOutput)) {
    return { code: 'invalid_ai_output', field: 'aiOutput', message: 'aiOutput must be a plain object' };
  }
  return null;
}

const RENAMED_FIELDS: Readonly<Record<string, string>> = {
  humanAction: 'action',
  humanReason: 'reason',
  reviewer: 'decider',
};

/**
 * Why a capture input or payload is refused for naming a renamed 0.7 field:
 * `humanAction` (now `action`), `humanReason` (now `reason`) or `reviewer`
 * (now `decider`). A 0.7 client is refused rather than mis-stored.
 */
export function renamedFieldViolation(input: unknown): PayloadViolation | null {
  if (!isPlainObject(input)) return null;
  for (const [field, renamedTo] of Object.entries(RENAMED_FIELDS)) {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      return {
        code: 'renamed_field',
        field,
        renamedTo,
        message: `${field} was renamed: pass ${renamedTo}`,
      };
    }
  }
  return null;
}

const MOVED_FIELDS: Readonly<Record<string, string>> = {
  aiBom: 'contributions.steps[].aiBom',
  lineage: 'links',
};

/**
 * Why a capture input or payload is refused for naming a moved 0.7 field: a
 * top-level `aiBom` (a model's bill of materials is a contribution step's:
 * pass `contributions: singleModel(aiBom)`) or `lineage` (now `links`).
 */
export function movedFieldViolation(input: unknown): PayloadViolation | null {
  if (!isPlainObject(input)) return null;
  for (const [field, movedTo] of Object.entries(MOVED_FIELDS)) {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      return { code: 'moved_field', field, movedTo, message: `${field} moved: pass ${movedTo}` };
    }
  }
  return null;
}

/**
 * The payload members outside the format's twelve names, sorted by bytes
 * (Record §2.2; Verification §4.7). A reader hashes only the eleven names, so such a member
 * changes no digest; it is reported (`payload.<name>`, abstain), never passed
 * over in silence. Empty for a payload that is not an object.
 */
export function unhashedPayloadMembers(payload: unknown): string[] {
  if (!isPlainObject(payload)) return [];
  return Object.keys(payload)
    .filter((k) => !PAYLOAD_MEMBERS.includes(k))
    .sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
}

/**
 * Why a payload is refused for its size: the canonical bytes of its hashed
 * object, under `hashedFieldSet`, exceed {@link PAYLOAD_MAX_CANONICAL_BYTES}.
 * A payload the serializer cannot render is left to the serializer's own
 * refusal.
 */
export function payloadSizeViolation(
  payload: Record<string, unknown>,
  hashedFieldSet: readonly string[],
): PayloadViolation | null {
  let bytes: number;
  try {
    bytes = utf8Length(canonicalSerialize(payload, [...hashedFieldSet]));
  } catch {
    return null;
  }
  if (bytes > PAYLOAD_MAX_CANONICAL_BYTES) {
    return {
      code: 'payload_too_large',
      field: 'payload',
      message: `the hashed object's canonical bytes exceed ${PAYLOAD_MAX_CANONICAL_BYTES}`,
    };
  }
  return null;
}
