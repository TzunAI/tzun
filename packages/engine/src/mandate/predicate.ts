/**
 * Mandate predicates (Record §9.8): their grammar, and their exact
 * evaluation over a record's evidence payload, so TypeScript, Python and Go
 * agree on every record.
 *
 * A predicate is `{ path, op, value, quant }`. It evaluates to `'true'`,
 * `'false'` or `'undeterminable'`.
 */
import { isNonNegativeSafeInteger, isPlainObject, isStrictlyIncreasing, PRINTABLE_ASCII_RE } from '../record-rules-util';
import type { MandatePredicateOp, PredicateOutcome } from '../types/mandate';

export const PREDICATE_OPS: readonly MandatePredicateOp[] = Object.freeze([
  'eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'notIn', 'prefix', 'glob',
]);

/** The most elements an `in`, `notIn` or `glob` set holds. */
export const PREDICATE_MAX_SET = 64;
/** The longest glob pattern, in characters. */
export const GLOB_MAX_PATTERN_LENGTH = 256;
/** A string subject longer than this, in code points, is undeterminable. */
export const PREDICATE_MAX_SUBJECT_CODE_POINTS = 4096;
/** An array subject longer than this is undeterminable. */
export const PREDICATE_MAX_ARRAY_ELEMENTS = 10000;

const PREDICATE_KEYS = ['path', 'op', 'value', 'quant'] as const;
const ARRAY_INDEX_RE = /^(0|[1-9][0-9]*)$/;

/**
 * The reference tokens of an RFC 6901 JSON Pointer, unescaped, or `null` when
 * `path` is not one: it begins with `/`, and `~` appears only as `~0` or `~1`.
 */
export function parseJsonPointer(path: unknown): string[] | null {
  if (typeof path !== 'string' || !path.startsWith('/')) return null;
  const tokens = path.slice(1).split('/');
  const out: string[] = [];
  for (const raw of tokens) {
    if (/~(?![01])/.test(raw)) return null;
    out.push(raw.replace(/~1/g, '/').replace(/~0/g, '~'));
  }
  return out;
}

/** What a pointer resolves to: `{ found: false }` for nothing. */
export type PointerResolution = { found: true; value: unknown } | { found: false };

/**
 * Resolve the tokens against `root`. On an object a token names an own
 * member; on an array it is `0` or `[1-9][0-9]*` below the length (`-` and
 * any other token resolve to nothing); on anything else it resolves to
 * nothing.
 */
export function resolvePointer(root: unknown, tokens: readonly string[]): PointerResolution {
  let current: unknown = root;
  for (const token of tokens) {
    if (Array.isArray(current)) {
      if (!ARRAY_INDEX_RE.test(token)) return { found: false };
      const index = Number(token);
      if (!Number.isSafeInteger(index) || index >= current.length) return { found: false };
      current = current[index];
    } else if (isPlainObject(current)) {
      if (!Object.prototype.hasOwnProperty.call(current, token)) return { found: false };
      current = current[token];
    } else {
      return { found: false };
    }
  }
  return { found: true, value: current };
}

/** The code points of a string. */
function codePoints(text: string): string[] {
  return Array.from(text);
}

/** Match one segment against one pattern segment: `*` any run, `?` one code point; iterative two-pointer. */
function matchSegment(pattern: string[], subject: string[]): boolean {
  let p = 0;
  let s = 0;
  let star = -1;
  let mark = 0;
  while (s < subject.length) {
    if (p < pattern.length && (pattern[p] === '?' || (pattern[p] !== '*' && pattern[p] === subject[s]))) {
      p++;
      s++;
    } else if (p < pattern.length && pattern[p] === '*') {
      star = p;
      mark = s;
      p++;
    } else if (star !== -1) {
      p = star + 1;
      mark++;
      s = mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}

/**
 * Whether `subject` matches the glob `pattern` (Record §9.8). Characters are code
 * points. `*` matches any run of code points other than `/`; `?` matches one
 * code point other than `/`; `**` as a whole segment matches any run of whole
 * segments, including none; every other character matches itself; the whole
 * subject must match. Pattern and subject are split on `/`, `**` is matched
 * segment-wise and every other segment with the iterative two-pointer
 * algorithm, so the worst case is O(|pattern| × |subject|), with no recursion.
 */
export function globMatch(pattern: string, subject: string): boolean {
  const ps = pattern.split('/').map((seg) => (seg === '**' ? null : codePoints(seg)));
  const ss = subject.split('/').map(codePoints);
  let p = 0;
  let s = 0;
  let star = -1;
  let mark = 0;
  while (s < ss.length) {
    const seg = p < ps.length ? ps[p] : undefined;
    if (seg !== undefined && seg !== null && matchSegment(seg, ss[s])) {
      p++;
      s++;
    } else if (seg === null) {
      star = p;
      mark = s;
      p++;
    } else if (star !== -1) {
      p = star + 1;
      mark++;
      s = mark;
    } else {
      return false;
    }
  }
  while (p < ps.length && ps[p] === null) p++;
  return p === ps.length;
}

/** A predicate integer: a JSON number, mathematically integral, from 0 to 2^53 − 1. */
function isPredicateInteger(value: unknown): value is number {
  return isNonNegativeSafeInteger(value);
}

function isStringSet(value: unknown, maxLength?: number): value is string[] {
  return (
    Array.isArray(value) &&
    value.length >= 1 &&
    value.length <= PREDICATE_MAX_SET &&
    value.every(
      (v) =>
        typeof v === 'string' &&
        PRINTABLE_ASCII_RE.test(v) &&
        (maxLength === undefined || (v.length >= 1 && v.length <= maxLength)),
    ) &&
    isStrictlyIncreasing(value as string[])
  );
}

/**
 * Why `predicate` is not a well-formed predicate, or `null` when it is one
 * (the grammar `prepare` applies): exactly `path`, `op`, `value`, `quant`;
 * `path` a JSON Pointer of printable ASCII whose `~` appear only as `~0` and
 * `~1`; `op` one of the ten; `quant` `null`, `all` or `any`; and `value` per
 * `op`:
 *
 *   - `eq`, `ne`: a string, an integer or a boolean (`null` is refused: a
 *     subject that is `null` is undeterminable, so such a predicate could
 *     never hold);
 *   - `lt`, `le`, `gt`, `ge`: an integer;
 *   - `in`, `notIn`: a sorted set of 1 to 64 strings;
 *   - `prefix`: a string;
 *   - `glob`: a sorted set of 1 to 64 patterns of 1 to 256 characters.
 */
export function predicateViolation(predicate: unknown): string | null {
  if (!isPlainObject(predicate)) return 'a predicate must be an object';
  const keys = Object.keys(predicate);
  if (keys.length !== PREDICATE_KEYS.length || !PREDICATE_KEYS.every((k) => keys.includes(k))) {
    return 'a predicate must have exactly the members path, op, value and quant';
  }
  const { path, op, value, quant } = predicate as Record<string, unknown>;
  if (typeof path !== 'string' || !PRINTABLE_ASCII_RE.test(path) || parseJsonPointer(path) === null) {
    return 'path must be a JSON Pointer of printable ASCII whose ~ appear only as ~0 or ~1';
  }
  if (quant !== null && quant !== 'all' && quant !== 'any') return 'quant must be null, all or any';
  switch (op) {
    case 'eq':
    case 'ne':
      if (typeof value === 'string' ? PRINTABLE_ASCII_RE.test(value) : typeof value === 'boolean' || isPredicateInteger(value)) {
        return null;
      }
      return `${op} takes a printable-ASCII string, a non-negative safe integer or a boolean`;
    case 'lt':
    case 'le':
    case 'gt':
    case 'ge':
      return isPredicateInteger(value) ? null : `${op} takes a non-negative safe integer`;
    case 'in':
    case 'notIn':
      return isStringSet(value) ? null : `${op} takes a sorted set of 1 to ${PREDICATE_MAX_SET} strings`;
    case 'prefix':
      return typeof value === 'string' && PRINTABLE_ASCII_RE.test(value) ? null : 'prefix takes a printable-ASCII string';
    case 'glob':
      return isStringSet(value, GLOB_MAX_PATTERN_LENGTH)
        ? null
        : `glob takes a sorted set of 1 to ${PREDICATE_MAX_SET} patterns of 1 to ${GLOB_MAX_PATTERN_LENGTH} characters`;
    default:
      return `op must be one of ${PREDICATE_OPS.join(', ')}`;
  }
}

/** One subject under one operation. */
function evaluateOne(op: MandatePredicateOp, value: unknown, subject: unknown): PredicateOutcome {
  if (subject === null || subject === undefined) return 'undeterminable';
  if (typeof subject === 'string' && codePoints(subject).length > PREDICATE_MAX_SUBJECT_CODE_POINTS) {
    return 'undeterminable';
  }
  const truth = (b: boolean): PredicateOutcome => (b ? 'true' : 'false');
  switch (op) {
    case 'eq':
    case 'ne': {
      let same: boolean;
      if (typeof subject === 'boolean') same = typeof value === 'boolean' && subject === value;
      else if (typeof subject === 'string') same = typeof value === 'string' && subject === value;
      else if (isPredicateInteger(subject)) same = isPredicateInteger(value) && subject === value;
      else return 'undeterminable';
      return truth(op === 'eq' ? same : !same);
    }
    case 'lt':
    case 'le':
    case 'gt':
    case 'ge': {
      if (!isPredicateInteger(subject) || !isPredicateInteger(value)) return 'undeterminable';
      if (op === 'lt') return truth(subject < value);
      if (op === 'le') return truth(subject <= value);
      if (op === 'gt') return truth(subject > value);
      return truth(subject >= value);
    }
    case 'in':
    case 'notIn': {
      if (typeof subject !== 'string' || !Array.isArray(value)) return 'undeterminable';
      const member = value.includes(subject);
      return truth(op === 'in' ? member : !member);
    }
    case 'prefix':
      if (typeof subject !== 'string' || typeof value !== 'string') return 'undeterminable';
      return truth(subject.startsWith(value));
    case 'glob':
      if (typeof subject !== 'string' || !Array.isArray(value)) return 'undeterminable';
      return truth(value.some((pattern) => typeof pattern === 'string' && globMatch(pattern, subject)));
    default:
      return 'undeterminable';
  }
}

/**
 * Evaluate `predicate` over `payload` (Record §9.8). Undeterminable when the
 * predicate is not well formed; when the path resolves to nothing or to
 * `null`; when the subject is of a type the operation does not take; when
 * `quant` does not agree with whether the subject is an array; when a string
 * subject exceeds 4,096 code points; or when an array subject exceeds 10,000
 * elements. `all` over `[]` is true, `any` over `[]` is false; with `all` any
 * element false makes it false, otherwise any undeterminable element makes it
 * undeterminable; with `any` any element true makes it true, otherwise any
 * undeterminable element makes it undeterminable. Never throws.
 */
export function evaluatePredicate(predicate: unknown, payload: unknown): PredicateOutcome {
  if (predicateViolation(predicate) !== null) return 'undeterminable';
  const { path, op, value, quant } = predicate as { path: string; op: MandatePredicateOp; value: unknown; quant: unknown };
  const resolved = resolvePointer(payload, parseJsonPointer(path)!);
  if (!resolved.found) return 'undeterminable';
  const subject = resolved.value;
  if (subject === null) return 'undeterminable';
  if (quant === null) {
    if (Array.isArray(subject)) return 'undeterminable';
    return evaluateOne(op, value, subject);
  }
  if (!Array.isArray(subject) || subject.length > PREDICATE_MAX_ARRAY_ELEMENTS) return 'undeterminable';
  let sawUndeterminable = false;
  for (const element of subject) {
    const outcome = evaluateOne(op, value, element);
    if (quant === 'all' && outcome === 'false') return 'false';
    if (quant === 'any' && outcome === 'true') return 'true';
    if (outcome === 'undeterminable') sawUndeterminable = true;
  }
  if (sawUndeterminable) return 'undeterminable';
  return quant === 'all' ? 'true' : 'false';
}
