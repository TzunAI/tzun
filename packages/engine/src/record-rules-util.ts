/**
 * Shared predicates for the record rules (decider, contributions,
 * links, mandates, agent descriptors). Internal to the engine: every rule
 * module reads the same definitions, so one string is never judged two ways.
 *
 * Every pattern is anchored over the whole string and uses ASCII classes only.
 * A Python twin uses `re.fullmatch` with `re.ASCII` and `[0-9]`, never
 * `re.match(…$)` (which accepts a trailing newline) or `\d`.
 */
import { createHash } from 'crypto';
import { canonicalSerializeValue } from './canonical';

/** A bare digest, as evidence records and registrations write one: 64 lowercase hex. */
export const BARE_DIGEST_RE = /^[0-9a-f]{64}$/;

/** A prefixed digest, as content-addressed documents write one: `sha256:` and 64 lowercase hex. */
export const PREFIXED_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

/** Printable ASCII, 0x20 to 0x7E, possibly empty. */
export const PRINTABLE_ASCII_RE = /^[\x20-\x7e]*$/;

/** Printable ASCII other than space, 0x21 to 0x7E, possibly empty. */
export const VISIBLE_ASCII_RE = /^[\x21-\x7e]*$/;

/** The largest integer a JSON number carries exactly. */
export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/** The object's own keys, sorted, compared with `expected` (any order). */
export function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  if (keys.length !== expected.length) return false;
  return expected.every((k) => Object.prototype.hasOwnProperty.call(value, k));
}

/** Whether `value` has an own key not in `expected`. */
export function hasUnknownKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(value).some((k) => !expected.includes(k));
}

export function isBareDigest(value: unknown): value is string {
  return typeof value === 'string' && BARE_DIGEST_RE.test(value);
}

export function isPrefixedDigest(value: unknown): value is string {
  return typeof value === 'string' && PREFIXED_DIGEST_RE.test(value);
}

/** A non-negative integer no greater than 2^53 − 1. `1.0` and `1e0` are the integer 1. */
export function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** A safe integer of at least 1. */
export function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;
}

/** Length in UTF-16 code units (Python: `len(s.encode('utf-16-le')) // 2`). */
export function utf16Length(value: string): number {
  return value.length;
}

/** Whether a string holds an unpaired UTF-16 surrogate, which the canonical serializer refuses. */
export function hasLoneSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : -1;
      if (next < 0xdc00 || next > 0xdfff) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/** Compare two strings by their UTF-8 bytes. */
export function compareBytes(a: string, b: string): number {
  return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/** Whether `values` is strictly increasing by bytes: sorted, with no repeated element. */
export function isStrictlyIncreasing(values: readonly string[]): boolean {
  for (let i = 1; i < values.length; i++) {
    if (compareBytes(values[i - 1], values[i]) >= 0) return false;
  }
  return true;
}

/** The canonical bytes of a whole value (every key of every object). */
export function canonicalValue(value: unknown): string {
  return canonicalSerializeValue(value);
}

/** Lowercase hex SHA-256 of a string's UTF-8 bytes. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** UTF-8 byte length of a string. */
export function utf8Length(text: string): number {
  return Buffer.byteLength(text, 'utf8');
}
