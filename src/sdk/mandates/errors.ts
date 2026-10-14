/**
 * What `tzun.mandates.*` throws when it refuses.
 *
 * Every refusal is a {@link MandateError} with its `code` and the `field` it
 * concerns. `failureType` says which kind it is: `validation_failure`
 * for a request the store cannot take (a malformed document, an assertion that
 * does not verify, a store without mandates), `mandate_refused` for a mandate
 * that cannot take it (not open, a successor naming another principal, a
 * confirmation not owed). When the refusal came from capturing a system
 * record, `failure` is that capture's `FailureRecord`. Messages name the field
 * and the rule and never echo a value. `code` is always a code, never a
 * message.
 */
import type { FailureRecord } from '@tzun/engine';

/** A refusal of `tzun.mandates.*`. */
export class MandateError extends Error {
  constructor(
    readonly code: string,
    readonly field: string,
    message: string,
    readonly failureType: 'validation_failure' | 'mandate_refused' = 'validation_failure',
    readonly details: Record<string, unknown> = {},
    readonly failure?: FailureRecord,
  ) {
    super(message);
    this.name = 'MandateError';
    Object.setPrototypeOf(this, MandateError.prototype);
  }
}

/** The store's compare-and-swap codes a system record's own write can lose with. */
export type MandateSwapConflict = 'mandate_state_conflict' | 'mandate_claim_conflict';

const CODE_RE = /^[a-z][a-z0-9_]{0,63}$/;

function isHead(value: unknown): value is { sequence: unknown; digest: unknown } {
  return typeof value === 'object' && value !== null && 'sequence' in value && 'digest' in value;
}

/**
 * The code and message of a system record's failed capture:
 *
 *   - a prepared record refused before it was stored (`retryRefused`
 *     `caller_attestation_is_digest_bound` on a `chain_conflict`): the chain
 *     head it was prepared on is still the head, so the request is not the one
 *     prepared (`invalid_prepared`); or another record was appended since
 *     (`prepared_record_stale`: prepare and sign again);
 *   - a store refusal of the record's own compare-and-swap (`lost`, as its
 *     `classifyStoreError` saw it): that conflict's code;
 *   - otherwise the failure's `code`, a `reason` that is a code (a refusal's),
 *     or the failure type.
 */
function codeOfFailure(failure: FailureRecord | undefined, what: string, lost: MandateSwapConflict | null): { code: string; message: string | null } {
  const meta = (failure?.diagnosticMetadata ?? {}) as Record<string, unknown>;
  if (failure?.failureType === 'chain_conflict' && meta.retryRefused === 'caller_attestation_is_digest_bound') {
    const expected = meta.expectedHead;
    const actual = meta.actualHead;
    const sameHead = isHead(expected) && isHead(actual) && expected.sequence === actual.sequence && expected.digest === actual.digest;
    return sameHead
      ? { code: 'invalid_prepared', message: `${what} is not the record prepared for this request` }
      : { code: 'prepared_record_stale', message: `${what} was prepared on a chain head that has since moved; prepare and sign it again` };
  }
  if (failure?.failureType === 'serialization_failure' && lost !== null) {
    return { code: lost, message: `${what}: the mandate's slots, totals or state moved while it was stored` };
  }
  if (typeof meta.code === 'string' && CODE_RE.test(meta.code)) return { code: meta.code, message: null };
  if (typeof meta.reason === 'string' && CODE_RE.test(meta.reason)) return { code: meta.reason, message: null };
  return { code: failure?.failureType ?? 'capture_failed', message: null };
}

/**
 * The refusal of a system record's capture, as a {@link MandateError}.
 * `what` names the record ("the revocation record"); `lost` is the
 * compare-and-swap conflict the record's own write last lost with, if any.
 */
export function mandateErrorOfFailure(failure: FailureRecord | undefined, what: string, lost: MandateSwapConflict | null = null): MandateError {
  const meta = (failure?.diagnosticMetadata ?? {}) as Record<string, unknown>;
  const derived = codeOfFailure(failure, what, lost);
  const field = typeof meta.field === 'string' ? meta.field : 'record';
  const message =
    derived.message ?? (typeof meta.message === 'string' ? `${what}: ${meta.message}` : `${what} could not be stored (${derived.code})`);
  const failureType = failure?.failureType === 'mandate_refused' ? 'mandate_refused' : 'validation_failure';
  return new MandateError(derived.code, field, message, failureType, {}, failure);
}
