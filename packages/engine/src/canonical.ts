/**
 * Custom Canonical Serializer. Serialization-critical: changing it changes every digest.
 *
 * Produces a deterministic byte sequence from a set of evidence fields.
 * Does NOT use JSON.stringify. Every character in the output is explicitly
 * controlled by this implementation.
 *
 * Rules (v1.0):
 * - UTF-8 encoding
 * - Valid JSON output, no formatting whitespace
 * - Separators: exactly "," between items, ":" between key-value pairs
 * - Keys sorted by UTF-16 CODE UNIT at every level (`Object.keys(o).sort()`).
 *   NOT Unicode code-point order: the two disagree whenever a BMP key in
 *   U+E000..U+FFFF sits next to an astral key, because an astral key's first
 *   UTF-16 unit is a high surrogate (U+D800..U+DBFF) and sorts BEFORE it.
 *   The Python port matches (`key=lambda s: s.encode('utf-16-be')`), as does
 *   schema/README.md's `@tzun-canonical-sort utf16` marker.
 * - undefined → null; explicit null preserved
 * - Numbers: finite only, no trailing zeros, integers have no decimal
 * - Arrays: preserve insertion order, elements recursively processed
 * - Strings: standard JSON escaping, no Unicode normalization
 *
 * Descriptor sub-rule:
 *   `ModelDescriptor` set-valued fields are sorted before serialization.
 *   See `canonicalSerializeDescriptor` below. The sub-rule applies ONLY
 *   to `ModelDescriptor` — envelope payloads and the `AiBom` subtree
 *   continue to preserve insertion order for their arrays.
 */

import type { ModelDescriptor } from './types/ai-bom';

/**
 * Serialize a subset of fields into a canonical byte string.
 *
 * @param fields - The full set of fields from the evidence record
 * @param hashedFieldSet - Ordered list of field names to include (from schema registry)
 * @returns Canonical JSON string (deterministic, cross-language identical)
 */
const MAX_DEPTH = 64;

export function canonicalSerialize(
  fields: Record<string, unknown>,
  hashedFieldSet: string[]
): string {
  // Select only the fields in the hashed set
  const subset: Record<string, unknown> = {};
  for (const key of hashedFieldSet) {
    subset[key] = fields[key];
  }
  return serializeValue(subset);
}

/**
 * The canonical bytes of any value under the same rules: `C(v)` for a value
 * that is not a payload, such as a contribution step's output, a step, a
 * mandate document or an agent descriptor. Every key of every object is
 * included. Python twin: `tzun_sdk._generated.canonical._serialize_value`.
 */
export function canonicalSerializeValue(value: unknown): string {
  return serializeValue(value, 0);
}

function serializeValue(value: unknown, depth: number = 0): string {
  if (depth > MAX_DEPTH) {
    throw new Error(
      'Canonical serialization error: maximum nesting depth exceeded (circular reference?).'
    );
  }

  if (value === undefined || value === null) {
    return 'null';
  }

  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(
        `Canonical serialization error: non-finite number (${value}). ` +
        'Numbers must be finite — NaN and Infinity are not allowed.'
      );
    }
    // JavaScript's number-to-string conversion already omits trailing zeros
    // and omits decimal points for integers.
    return String(value);
  }

  if (typeof value === 'string') {
    return serializeString(value);
  }

  if (Array.isArray(value)) {
    // Array.from — NOT Array.prototype.map. `map` skips holes in a sparse
    // array and leaves the corresponding slot empty in the result, so
    // `join(',')` would render `[1,,3]`: not valid JSON, and not what any
    // storage round-trip produces. Both SQLite and Postgres persist the
    // envelope via JSON.stringify, which materialises a hole as `null`;
    // re-canonicalising the re-parsed value would then yield `[1,null,3]` and
    // the digest of an honest record would not match itself. Array.from
    // visits every index, so a hole arrives as `undefined` and falls through
    // to the `undefined -> null` rule above — matching JSON.stringify, the
    // Python serializer, and the v1.0 'Valid JSON output' guarantee.
    const items = Array.from(value, (item) => serializeValue(item, depth + 1));
    return '[' + items.join(',') + ']';
  }

  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== null && proto !== Object.prototype) {
      throw new Error(
        `Canonical serialization error: non-plain object (${(value as object).constructor?.name ?? 'unknown'}). ` +
        'Only plain objects, arrays, strings, numbers, booleans, and null are supported.'
      );
    }
    return serializeObject(value as Record<string, unknown>, depth);
  }

  throw new Error(
    `Canonical serialization error: unsupported type "${typeof value}".`
  );
}

function serializeObject(obj: Record<string, unknown>, depth: number): string {
  const keys = Object.keys(obj).sort();
  const pairs: string[] = [];
  for (const key of keys) {
    const val = obj[key];
    // undefined values in objects are serialized as null (spec rule 5)
    const serializedValue = val === undefined ? 'null' : serializeValue(val, depth + 1);
    pairs.push(serializeString(key) + ':' + serializedValue);
  }
  return '{' + pairs.join(',') + '}';
}

/**
 * Canonicalize a ModelDescriptor per the descriptor sub-rule.
 *
 * Set-valued fields are sorted before serialization:
 *   - `regulatoryMarkings`     by (authority, identifier) ascending
 *   - `training.evaluations`   by name ascending
 *   - `externalIdentifiers`    by (scheme, value) ascending
 *
 * The descriptor's own keys are sorted lexicographically by the base
 * serializer; what we do here is pre-sort the arrays so the resulting
 * canonical bytes are stable under input reordering.
 */
export function canonicalSerializeDescriptor(descriptor: ModelDescriptor): string {
  // Shallow-clone the top level and any objects whose arrays we sort. We avoid
  // structuredClone here because the canonical serializer's strict plain-object
  // check (Object.prototype identity) does not always accept its output across
  // Jest realms — and we only need to mutate the three set-valued arrays, so a
  // targeted clone is both safer and cheaper.
  const d: ModelDescriptor = {
    ...descriptor,
    training: { ...descriptor.training, evaluations: [...descriptor.training.evaluations] },
    regulatoryMarkings: [...descriptor.regulatoryMarkings],
    externalIdentifiers: [...descriptor.externalIdentifiers],
  };
  d.regulatoryMarkings.sort((a, b) =>
    cmpTuple([a.authority, a.identifier], [b.authority, b.identifier]));
  d.training.evaluations.sort((a, b) => cmpString(a.name, b.name));
  d.externalIdentifiers.sort((a, b) =>
    cmpTuple([a.scheme, a.value], [b.scheme, b.value]));
  return canonicalSerialize(
    d as unknown as Record<string, unknown>,
    Object.keys(d).sort(),
  );
}

/**
 * Strict ordinal (UTF-16 code-unit) comparison.
 *
 * Avoids `localeCompare()` because it is locale- and ICU-version-sensitive
 * (Czech treats "ch" as a digraph; case- and accent-folding differs by
 * locale), which would let descriptor digests diverge across runtimes and
 * break the byte-identical-across-languages guarantee. JavaScript's
 * `<`/`>` on strings is UTF-16 code-unit order, matching the
 * `Object.keys(obj).sort()` used elsewhere in this file.
 */
function cmpString(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function cmpTuple(a: string[], b: string[]): number {
  for (let i = 0; i < a.length; i++) {
    const c = cmpString(a[i], b[i]);
    if (c !== 0) return c;
  }
  return 0;
}

function serializeString(str: string): string {
  let result = '"';
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    switch (ch) {
      case 0x22: // "
        result += '\\"';
        break;
      case 0x5c: // \
        result += '\\\\';
        break;
      case 0x08: // backspace
        result += '\\b';
        break;
      case 0x0c: // form feed
        result += '\\f';
        break;
      case 0x0a: // newline
        result += '\\n';
        break;
      case 0x0d: // carriage return
        result += '\\r';
        break;
      case 0x09: // tab
        result += '\\t';
        break;
      default:
        if (ch < 0x20) {
          // Control characters: \u00XX
          result += '\\u' + ch.toString(16).padStart(4, '0');
        } else if (ch >= 0xd800 && ch <= 0xdbff) {
          // High surrogate — valid ONLY when immediately followed by a low
          // surrogate. See the block comment on `assertNoLoneSurrogate`.
          const next = i + 1 < str.length ? str.charCodeAt(i + 1) : -1;
          if (next < 0xdc00 || next > 0xdfff) {
            throw loneSurrogate(ch);
          }
          // Emit the well-formed pair together and skip its low half.
          result += str[i] + str[i + 1];
          i++;
        } else if (ch >= 0xdc00 && ch <= 0xdfff) {
          // A low surrogate reached here without a preceding high one (the
          // paired case consumed both above), so it is unpaired by definition.
          throw loneSurrogate(ch);
        } else {
          result += str[i];
        }
    }
  }
  result += '"';
  return result;
}

/**
 * Reject an unpaired UTF-16 surrogate.
 *
 * Copying every code unit above U+001F through verbatim would let an unpaired
 * surrogate reach `createHash('sha256').update(canonical, 'utf8')` — and
 * Node's UTF-8 encoder silently replaces it with U+FFFD (EF BF BD).
 * "\uD800", "\uDC00" and a literal U+FFFD would therefore all canonicalize to
 * the SAME bytes: the serializer would not be injective, and injectivity is
 * the property every record digest relies on.
 *
 * Two consequences, both real:
 *
 *  1. Cross-implementation disagreement. The Python port rejects lone
 *     surrogates (`_generated/canonical.py`, "lone surrogate U+XXXX"), so
 *     accepting one here would make the two reference implementations
 *     disagree on whether such a record even HAS a digest. A TS-captured
 *     record containing one would fail verification forever in a Python
 *     verifier or a customer's Python export check — an honest record that
 *     can never be re-verified.
 *
 *  2. A (narrow) forgery surface. A store-write attacker could swap a lone
 *     surrogate for U+FFFD, or one lone surrogate for another, in aiOutput or
 *     reason and the TS verifier would still report verified: true. No
 *     meaningful content can be altered this way, so this is an injectivity
 *     defect rather than a practical forgery primitive — but it is a hole in
 *     the "the digest covers the payload" claim.
 *
 * These are not exotic inputs: an LLM completion truncated at max_tokens in
 * the middle of an emoji yields one, and JSON.stringify preserves it as
 * \ud800, so it round-trips through every adapter into the store.
 *
 * Rejecting (rather than escaping as \uXXXX) is deliberate: it matches Python
 * byte-for-byte and keeps the digest contract for every well-formed string
 * unchanged. Escaping would change the digest contract.
 */
function loneSurrogate(codeUnit: number): Error {
  return new Error(
    'Canonical serialization error: lone surrogate U+' +
      codeUnit.toString(16).toUpperCase().padStart(4, '0') +
      ' in string. Unpaired UTF-16 surrogates have no UTF-8 encoding — Node ' +
      'would silently substitute U+FFFD, making the digest non-injective, and ' +
      'the Python reference implementation rejects them outright.'
  );
}
