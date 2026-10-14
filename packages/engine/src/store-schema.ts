/**
 * Recognising a record an earlier release captured (Record §4.1).
 *
 * The v1.0 hashed field set has been revised in place twice: 0.7.0 added
 * `signoffExpectation` (Record §9.1), and 0.8.0 renamed `humanAction`
 * and `humanReason` to `action` and `reason`, added `decider`,
 * `contributions` and `links`, and moved `aiBom` into the contribution steps.
 * A record built under an earlier set recomputes to a different digest under
 * the current one, so it reads as `digest_mismatch`. These functions name the
 * set a stored digest does recompute under, so `Tzun.init()` can refuse a store
 * holding such records (`StoreSchemaOutdatedError`) and a verifier can explain
 * a mismatch. The explanation never excuses one: a store-write attacker can
 * rewrite a 0.8 record into an earlier field set and recompute its digest.
 */
import { canonicalSerialize } from './canonical';
import { computeDigest } from './digest';
import { V1_0_HASHED_FIELDS } from './schema-registry';

/**
 * The v1.0 hashed field set of the 0.7 releases (nine names). A detection
 * constant only: nothing is built or verified under it.
 */
export const FIELD_SET_0_7: readonly string[] = Object.freeze([
  'aiBom', 'aiOutput', 'aiSystemId', 'capturedAt', 'evidenceId', 'humanAction', 'humanReason', 'sequenceNumber',
  'signoffExpectation',
]);

/**
 * The v1.0 hashed field set before 0.7.0 (eight names). A detection constant
 * only: nothing is built or verified under it.
 */
export const FIELD_SET_BEFORE_0_7: readonly string[] = Object.freeze([
  'aiBom', 'aiOutput', 'aiSystemId', 'capturedAt', 'evidenceId', 'humanAction', 'humanReason', 'sequenceNumber',
]);

/** The generation of field set a stored record's digest recomputes under. */
export type RecordFieldSetGeneration = '0.8' | '0.7' | 'before-0.7';

/** The earlier field sets a digest mismatch is explained by, as the `fieldSet` fact names them. */
export type EarlierFieldSet = '0.7' | 'before-0.7';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

function recomputesUnder(payload: Record<string, unknown>, digest: string, fields: readonly string[]): boolean {
  try {
    return computeDigest(canonicalSerialize(payload, [...fields])) === digest;
  } catch {
    return false;
  }
}

function storedParts(envelope: unknown): { payload: Record<string, unknown>; digest: string } | null {
  if (!isPlainObject(envelope)) return null;
  const payload = envelope.payload;
  const integrity = envelope.integrity;
  if (!isPlainObject(payload) || !isPlainObject(integrity) || typeof integrity.canonicalDigest !== 'string') return null;
  return { payload, digest: integrity.canonicalDigest };
}

/**
 * Whether `envelope` is a record a release before 0.7.0 captured: its payload
 * has no `signoffExpectation` key, and its stored `canonicalDigest`
 * recomputes under {@link FIELD_SET_BEFORE_0_7}. Never throws.
 */
export function recordPredatesSignoffExpectation(envelope: unknown): boolean {
  const parts = storedParts(envelope);
  if (parts === null) return false;
  if (Object.prototype.hasOwnProperty.call(parts.payload, 'signoffExpectation')) return false;
  return recomputesUnder(parts.payload, parts.digest, FIELD_SET_BEFORE_0_7);
}

/**
 * Which field set a stored record's digest recomputes under, tried in this
 * order: the current v1.0 set (`'0.8'`), the 0.7 set (`'0.7'`), the set before
 * 0.7.0 (`'before-0.7'`); `null` when none does (a payload or digest altered
 * after capture, or not an envelope). The schema version the record names is
 * not trusted: the generation is found by recomputation. Never throws.
 */
export function recordFieldSetGeneration(envelope: unknown): RecordFieldSetGeneration | null {
  const parts = storedParts(envelope);
  if (parts === null) return null;
  if (recomputesUnder(parts.payload, parts.digest, V1_0_HASHED_FIELDS)) return '0.8';
  if (recomputesUnder(parts.payload, parts.digest, FIELD_SET_0_7)) return '0.7';
  if (recomputesUnder(parts.payload, parts.digest, FIELD_SET_BEFORE_0_7)) return 'before-0.7';
  return null;
}

/**
 * The earlier field set a stored digest recomputes under, for a record whose
 * digest does not recompute under the current set: the `fieldSet` fact of a
 * `digest_mismatch`. `null` when no earlier set explains it. The fact explains
 * and never excuses: no reader and no scanner lowers a severity because of it.
 * Never throws.
 */
export function earlierFieldSet(payload: unknown, storedDigest: unknown): EarlierFieldSet | null {
  if (!isPlainObject(payload) || typeof storedDigest !== 'string') return null;
  if (recomputesUnder(payload, storedDigest, FIELD_SET_0_7)) return '0.7';
  if (recomputesUnder(payload, storedDigest, FIELD_SET_BEFORE_0_7)) return 'before-0.7';
  return null;
}
