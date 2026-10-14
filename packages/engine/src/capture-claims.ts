/**
 * Rules for the two record-identity fields a client can choose: a record's
 * evidenceId and its capturedAt claim. They are the hosted service's capture
 * rules (its `EVIDENCE_ID_RE` and `validateCapturedAtClaim`), so a record the
 * SDK stores locally is one the hosted service would accept.
 */

/**
 * A v4 UUID, case-insensitive: what `randomUUID()` mints, and what the
 * platform accepts as a client-chosen evidence id.
 */
export const EVIDENCE_ID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** An ISO-8601 date-time with seconds and a zone designator. */
export const ISO_8601_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** How far ahead of the current time a capturedAt claim may be. */
export const CAPTURED_AT_MAX_SKEW_MS = 5 * 60 * 1000;

/** Why a capturedAt claim is refused, in the platform's `invalid_captured_at` reasons. */
export type CapturedAtViolation = 'unparsable' | 'future_dated';

/** Whether `value` is an evidence id the platform accepts from a client. */
export function isEvidenceId(value: unknown): value is string {
  return typeof value === 'string' && EVIDENCE_ID_RE.test(value);
}

/**
 * Why a capturedAt claim is refused, or `null` when it is accepted. A claim is
 * accepted when it is an ISO-8601 date-time that `Date.parse` reads and that
 * is no more than {@link CAPTURED_AT_MAX_SKEW_MS} ahead of `nowMs`.
 */
export function capturedAtViolation(
  claim: unknown,
  nowMs: number = Date.now(),
): CapturedAtViolation | null {
  if (typeof claim !== 'string' || !ISO_8601_RE.test(claim) || Number.isNaN(Date.parse(claim))) {
    return 'unparsable';
  }
  if (Date.parse(claim) > nowMs + CAPTURED_AT_MAX_SKEW_MS) return 'future_dated';
  return null;
}
