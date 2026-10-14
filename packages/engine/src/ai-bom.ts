/**
 * The `aiBom` exact-keys rule (Record §7.4). An `AiBom` carries exactly
 * its five members, and each nested object exactly its members, nullable ones
 * written as `null`: inside a member a missing key and a `null` one serialize
 * differently, so two constructions of one bill of materials would otherwise
 * have two digests. The rule applies to every contribution step's `aiBom`,
 * the only place a record states a model's bill of materials.
 *
 * Writers fill absent nullable members with `null` (`fillAiBomNulls`) before
 * hashing and refuse what is still not exact (`aiBomViolation`). A reader
 * hashes whatever is stored.
 */
import {
  hasExactKeys,
  isNonNegativeSafeInteger,
  isPlainObject,
} from './record-rules-util';
import type { AiBomViolation } from './types/ai-bom';

/** `sha256:` and 64 lowercase hex: the model descriptor digest format. */
export const MODEL_DESCRIPTOR_DIGEST_RE = /^sha256:[a-f0-9]{64}$/;

/** The most stop sequences an `aiBom` carries. */
export const AI_BOM_MAX_STOP_SEQUENCES = 16;
/** The longest stop sequence, and the longest `infrastructure` string, in UTF-16 code units. */
export const AI_BOM_MAX_STRING_LENGTH = 256;

const AI_BOM_KEYS = [
  'modelDescriptorDigest', 'vendorFingerprint', 'promptTemplate', 'inferenceParameters', 'infrastructure',
] as const;
const PROMPT_TEMPLATE_KEYS = ['templateId', 'templateDigest'] as const;
const INFERENCE_PARAMETER_KEYS = ['temperature', 'topP', 'maxTokens', 'seed', 'stopSequences'] as const;
const INFRASTRUCTURE_KEYS = ['provider', 'region', 'apiVersion', 'endpoint'] as const;


function fillObject(value: unknown, keys: readonly string[]): unknown {
  if (!isPlainObject(value)) return value;
  const out: Record<string, unknown> = { ...value };
  for (const key of keys) {
    if (out[key] === undefined) out[key] = null;
  }
  return out;
}

/**
 * A copy of `value` with every absent (or `undefined`) nullable member set to
 * `null`, at the top level and inside `promptTemplate`, `inferenceParameters`
 * and `infrastructure` when they are objects. Nothing else changes: a member
 * the shape does not have is kept, so `aiBomViolation` then refuses it. A
 * value that is not a plain object is returned as it is.
 */
export function fillAiBomNulls<T>(value: T): T {
  if (!isPlainObject(value)) return value;
  const out = fillObject(value, AI_BOM_KEYS.filter((k) => k !== 'modelDescriptorDigest')) as Record<string, unknown>;
  out.promptTemplate = fillObject(out.promptTemplate, PROMPT_TEMPLATE_KEYS);
  out.inferenceParameters = fillObject(out.inferenceParameters, INFERENCE_PARAMETER_KEYS);
  out.infrastructure = fillObject(out.infrastructure, INFRASTRUCTURE_KEYS);
  return out as T;
}

function nullableString(value: unknown, maxLength?: number): boolean {
  if (value === null) return true;
  if (typeof value !== 'string') return false;
  return maxLength === undefined || value.length <= maxLength;
}

function nullableFiniteNumber(value: unknown): boolean {
  return value === null || (typeof value === 'number' && Number.isFinite(value));
}

/**
 * Why `value` is not an exact `AiBom`, or `null` when it is one. `prefix` is
 * the field path the value sits at (`aiBom`, or `contributions.steps[1].aiBom`).
 *
 *   - exactly `modelDescriptorDigest` (`sha256:` and 64 lowercase hex),
 *     `vendorFingerprint` (string or `null`), `promptTemplate`,
 *     `inferenceParameters` and `infrastructure`;
 *   - `promptTemplate`: `null`, or exactly `templateId` and `templateDigest`,
 *     each a string or `null`;
 *   - `inferenceParameters`: `null`, or exactly `temperature` and `topP`
 *     (finite numbers or `null`), `maxTokens` (a non-negative safe integer or
 *     `null`), `seed` (a safe integer or `null`) and `stopSequences` (`null`
 *     or at most 16 strings of at most 256 UTF-16 code units);
 *   - `infrastructure`: `null`, or exactly `provider`, `region`, `apiVersion`
 *     and `endpoint`, each `null` or a string of at most 256 UTF-16 code units.
 *
 * `null` itself is not an `AiBom`: a caller asks this only of a value that is
 * not `null`.
 */
export function aiBomViolation(value: unknown, prefix = 'aiBom'): AiBomViolation | null {
  if (!isPlainObject(value)) {
    return { field: prefix, message: `${prefix} must be an object` };
  }
  if (!hasExactKeys(value, AI_BOM_KEYS)) {
    return {
      field: prefix,
      message: `${prefix} must have exactly the members ${AI_BOM_KEYS.join(', ')}, nullable ones written as null`,
    };
  }
  if (typeof value.modelDescriptorDigest !== 'string' || !MODEL_DESCRIPTOR_DIGEST_RE.test(value.modelDescriptorDigest)) {
    return {
      field: `${prefix}.modelDescriptorDigest`,
      message: `${prefix}.modelDescriptorDigest must be sha256: followed by 64 lowercase hex characters`,
    };
  }
  if (!nullableString(value.vendorFingerprint)) {
    return { field: `${prefix}.vendorFingerprint`, message: `${prefix}.vendorFingerprint must be a string or null` };
  }

  const pt = value.promptTemplate;
  if (pt !== null) {
    const f = `${prefix}.promptTemplate`;
    if (!isPlainObject(pt) || !hasExactKeys(pt, PROMPT_TEMPLATE_KEYS)) {
      return { field: f, message: `${f} must be null or have exactly the members templateId and templateDigest` };
    }
    for (const k of PROMPT_TEMPLATE_KEYS) {
      if (!nullableString(pt[k])) return { field: `${f}.${k}`, message: `${f}.${k} must be a string or null` };
    }
  }

  const ip = value.inferenceParameters;
  if (ip !== null) {
    const f = `${prefix}.inferenceParameters`;
    if (!isPlainObject(ip) || !hasExactKeys(ip, INFERENCE_PARAMETER_KEYS)) {
      return {
        field: f,
        message: `${f} must be null or have exactly the members ${INFERENCE_PARAMETER_KEYS.join(', ')}`,
      };
    }
    for (const k of ['temperature', 'topP'] as const) {
      if (!nullableFiniteNumber(ip[k])) return { field: `${f}.${k}`, message: `${f}.${k} must be a finite number or null` };
    }
    if (ip.maxTokens !== null && !isNonNegativeSafeInteger(ip.maxTokens)) {
      return { field: `${f}.maxTokens`, message: `${f}.maxTokens must be a non-negative safe integer or null` };
    }
    if (ip.seed !== null && !(typeof ip.seed === 'number' && Number.isSafeInteger(ip.seed))) {
      return { field: `${f}.seed`, message: `${f}.seed must be a safe integer or null` };
    }
    const stops = ip.stopSequences;
    if (stops !== null) {
      if (
        !Array.isArray(stops) ||
        stops.length > AI_BOM_MAX_STOP_SEQUENCES ||
        !stops.every((s) => typeof s === 'string' && s.length <= AI_BOM_MAX_STRING_LENGTH)
      ) {
        return {
          field: `${f}.stopSequences`,
          message:
            `${f}.stopSequences must be null or at most ${AI_BOM_MAX_STOP_SEQUENCES} strings of at most ` +
            `${AI_BOM_MAX_STRING_LENGTH} characters`,
        };
      }
    }
  }

  const inf = value.infrastructure;
  if (inf !== null) {
    const f = `${prefix}.infrastructure`;
    if (!isPlainObject(inf) || !hasExactKeys(inf, INFRASTRUCTURE_KEYS)) {
      return { field: f, message: `${f} must be null or have exactly the members ${INFRASTRUCTURE_KEYS.join(', ')}` };
    }
    for (const k of INFRASTRUCTURE_KEYS) {
      if (!nullableString(inf[k], AI_BOM_MAX_STRING_LENGTH)) {
        return {
          field: `${f}.${k}`,
          message: `${f}.${k} must be null or a string of at most ${AI_BOM_MAX_STRING_LENGTH} characters`,
        };
      }
    }
  }
  return null;
}

/** Whether `value` is an exact `AiBom`. */
export function isExactAiBom(value: unknown): boolean {
  return aiBomViolation(value) === null;
}
