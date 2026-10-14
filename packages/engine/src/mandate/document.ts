/**
 * The mandate document `tzun-mandate/1` (Record §9.7): its grammar,
 * its digest, and the restriction applied at signing.
 *
 * The document grammar: nested objects; arrays that are sets of printable
 * ASCII strings, already sorted by byte with no duplicate (a reader never
 * re-sorts); the literals `true`, `false` and `null`; non-negative safe
 * integers; printable-ASCII strings; every key required, `null` where it does
 * not apply. `mandateDigest = hex(SHA-256(C(document)))`, over at most 16 KiB
 * of canonical bytes.
 */
import { SchemaRegistry } from '../schema-registry';
import {
  canonicalValue,
  hasExactKeys,
  isBareDigest,
  isNonNegativeSafeInteger,
  isPlainObject,
  isPrefixedDigest,
  isStrictlyIncreasing,
  PRINTABLE_ASCII_RE,
  sha256Hex,
  utf8Length,
} from '../record-rules-util';
import { ACCT_VALUE_RE, identifierScheme, isKnownSchemeIdentifier } from '../decider';
import { parseJsonPointer, predicateViolation } from './predicate';
import type { MandateDocumentViolation, MandateDocumentViolationCode } from '../types/mandate';

/** The version tag of a mandate document. */
export const MANDATE_DOCUMENT_VERSION = 'tzun-mandate/1';
/** The most canonical bytes a mandate document has (a grammar maximum). */
export const MANDATE_DOCUMENT_MAX_BYTES = 16 * 1024;
/** The most caps in `limits.cumulative` (and in an expectation's `totals`). */
export const MANDATE_MAX_CAPS = 16;
/** The most predicates in a document, `scope.predicates` and `confirm` together. */
export const MANDATE_MAX_PREDICATES = 64;
/** A cap or predicate name. */
export const MANDATE_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

const DOCUMENT_KEYS = [
  'v', 'mandateId', 'principal', 'agents', 'schemaVersion', 'scope', 'confirm', 'validity', 'limits', 'delegation',
  'review', 'policyDigest', 'predecessor', 'parent',
] as const;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const INSTANT_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;
const AGENT_SCHEMES = ['spiffe', 'jkt', 'desc', 'cmt'];

/**
 * The members a mandate's scope restricts, which must be hashed in the
 * document's schema version: the models it names are the contribution
 * steps' bills of materials.
 */
const SCOPED_MEMBERS = ['aiSystemId', 'action', 'contributions'];

function violation(code: MandateDocumentViolationCode, field: string, message: string): MandateDocumentViolation {
  return { code, field, message };
}

/** An ISO 8601 UTC instant with milliseconds that names a real instant. */
export function isMandateInstant(value: unknown): value is string {
  if (typeof value !== 'string' || !INSTANT_RE.test(value)) return false;
  const ms = Date.parse(value);
  return !Number.isNaN(ms) && new Date(ms).toISOString() === value;
}

/**
 * Whether `value` is in the document grammar: objects, sorted sets of
 * printable-ASCII strings, booleans, `null`, non-negative safe integers and
 * printable-ASCII strings, with printable-ASCII keys. The path of the first
 * failure, or `null`.
 */
export function documentGrammarFailure(value: unknown, path = ''): string | null {
  if (value === null || typeof value === 'boolean') return null;
  if (typeof value === 'string') return PRINTABLE_ASCII_RE.test(value) ? null : path || '.';
  if (typeof value === 'number') return isNonNegativeSafeInteger(value) ? null : path || '.';
  if (Array.isArray(value)) {
    if (!value.every((v) => typeof v === 'string' && PRINTABLE_ASCII_RE.test(v))) return path || '.';
    return isStrictlyIncreasing(value as string[]) ? null : path || '.';
  }
  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (!PRINTABLE_ASCII_RE.test(k)) return `${path}.${k}`;
      const failure = documentGrammarFailure(v, `${path}.${k}`);
      if (failure !== null) return failure;
    }
    return null;
  }
  return path || '.';
}

/** `hex(SHA-256(C(document)))`. Assumes a document `mandateDocumentViolation` accepts; never throws. */
export function mandateDigest(document: unknown): string | null {
  try {
    return sha256Hex(canonicalValue(document));
  } catch {
    return null;
  }
}

/** The first reference token of every predicate path and cap path of a document. */
export function documentPathMembers(document: Record<string, unknown>): string[] {
  const out: string[] = [];
  const add = (path: unknown) => {
    const tokens = parseJsonPointer(path);
    if (tokens !== null) out.push(tokens[0]);
  };
  const scope = isPlainObject(document.scope) ? document.scope : {};
  for (const group of [scope.predicates, document.confirm]) {
    if (isPlainObject(group)) for (const p of Object.values(group)) if (isPlainObject(p)) add(p.path);
  }
  const limits = isPlainObject(document.limits) ? document.limits : {};
  if (isPlainObject(limits.cumulative)) {
    for (const c of Object.values(limits.cumulative)) if (isPlainObject(c)) add(c.path);
  }
  return out;
}

/**
 * Whether the document's paths read only members hashed in `schemaVersion`,
 * and that version hashes the members the scope restricts: the restriction
 * of Record §9.7, applied at signing against the document's version and by a
 * verifier against the record's own.
 */
export function mandateRestrictionHolds(document: Record<string, unknown>, schemaVersion: string, registry: SchemaRegistry): boolean {
  const schema = registry.get(schemaVersion);
  if (!schema) return false;
  const hashed = new Set(schema.hashedFieldSet);
  if (!SCOPED_MEMBERS.every((m) => hashed.has(m))) return false;
  return documentPathMembers(document).every((m) => hashed.has(m));
}

function checkPredicateGroup(group: unknown, field: string): MandateDocumentViolation | null {
  if (group === null) return null;
  if (!isPlainObject(group) || Object.keys(group).length === 0) {
    return violation('invalid_document', field, `${field} must be null or an object of named predicates`);
  }
  for (const [name, predicate] of Object.entries(group)) {
    if (!MANDATE_NAME_RE.test(name)) {
      return violation('invalid_predicate', `${field}.${name}`, `${field}: a predicate name is [A-Za-z0-9._-]{1,64}`);
    }
    const reason = predicateViolation(predicate);
    if (reason !== null) return violation('invalid_predicate', `${field}.${name}`, `${field}.${name}: ${reason}`);
  }
  return null;
}

function nullableStringSet(value: unknown, item: (v: string) => boolean): boolean {
  return value === null || (Array.isArray(value) && value.every((v) => typeof v === 'string' && item(v)));
}

export interface MandateDocumentOptions {
  registry?: SchemaRegistry;
  /**
   * Apply the rules `prepare` applies before a principal signs: the document
   * names a registered version that passes the restriction, `delegation` is
   * `{ allowed: false, maxDepth: 0, attenuation: 'subset' }` (sub-mandates are
   * not in this version), `parent` is `null`, and the validity window does not
   * end before it begins. Default `true`.
   */
  prepare?: boolean;
}

const defaultRegistry = new SchemaRegistry();

/**
 * Why `document` is not a mandate document, first failure first, or `null`
 * when it is one. Never throws.
 */
export function mandateDocumentViolation(
  document: unknown,
  options: MandateDocumentOptions = {},
): MandateDocumentViolation | null {
  const registry = options.registry ?? defaultRegistry;
  const prepare = options.prepare ?? true;
  if (!isPlainObject(document)) return violation('invalid_document', 'document', 'a mandate document must be an object');
  if (!hasExactKeys(document, DOCUMENT_KEYS)) {
    return violation('invalid_document', 'document', `a mandate document has exactly the keys ${DOCUMENT_KEYS.join(', ')}`);
  }
  const grammar = documentGrammarFailure(document);
  if (grammar !== null) {
    return violation(
      'invalid_document',
      `document${grammar}`,
      'a mandate document holds only objects, sorted sets of printable-ASCII strings, booleans, null, ' +
        'non-negative safe integers and printable-ASCII strings',
    );
  }
  let canonical: string;
  try {
    canonical = canonicalValue(document);
  } catch {
    return violation('invalid_document', 'document', 'a mandate document must be canonically serializable');
  }
  if (utf8Length(canonical) > MANDATE_DOCUMENT_MAX_BYTES) {
    return violation('document_too_large', 'document', `a mandate document's canonical bytes are at most ${MANDATE_DOCUMENT_MAX_BYTES}`);
  }
  const d = document;
  if (d.v !== MANDATE_DOCUMENT_VERSION) return violation('invalid_document', 'document.v', `v must be ${MANDATE_DOCUMENT_VERSION}`);
  if (typeof d.mandateId !== 'string' || !UUID_RE.test(d.mandateId)) {
    return violation('invalid_document', 'document.mandateId', 'mandateId must be a lowercase UUID');
  }
  const principal = d.principal;
  if (!isPlainObject(principal) || !hasExactKeys(principal, ['signer', 'credential'])) {
    return violation('invalid_principal', 'document.principal', 'principal has exactly the members signer and credential');
  }
  if (typeof principal.signer !== 'string' || !ACCT_VALUE_RE.test(principal.signer)) {
    return violation(
      'invalid_principal',
      'document.principal.signer',
      'principal.signer must be an opaque account id [A-Za-z0-9._-]{1,128}, never an email address or a name',
    );
  }
  if (principal.credential !== null && !isBareDigest(principal.credential)) {
    return violation('invalid_principal', 'document.principal.credential', 'principal.credential must be null or 64 lowercase hex');
  }
  if (
    !Array.isArray(d.agents) ||
    !d.agents.every(
      (a) => typeof a === 'string' && isKnownSchemeIdentifier(a) && AGENT_SCHEMES.includes(identifierScheme(a)!),
    )
  ) {
    return violation('invalid_document', 'document.agents', 'agents must be a set of agent identifiers (spiffe, jkt, desc or cmt)');
  }
  if (typeof d.schemaVersion !== 'string' || d.schemaVersion.length === 0) {
    return violation('invalid_document', 'document.schemaVersion', 'schemaVersion must name a schema version');
  }
  const scope = d.scope;
  if (!isPlainObject(scope) || !hasExactKeys(scope, ['aiSystemIds', 'actions', 'models', 'predicates'])) {
    return violation('invalid_document', 'document.scope', 'scope has exactly the members aiSystemIds, actions, models and predicates');
  }
  if (!nullableStringSet(scope.aiSystemIds, (v) => v.length > 0)) {
    return violation('invalid_document', 'document.scope.aiSystemIds', 'scope.aiSystemIds must be null or a set of strings');
  }
  if (!nullableStringSet(scope.actions, (v) => v.length > 0)) {
    return violation('invalid_document', 'document.scope.actions', 'scope.actions must be null or a set of strings');
  }
  if (!nullableStringSet(scope.models, isPrefixedDigest)) {
    return violation('invalid_document', 'document.scope.models', 'scope.models must be null or a set of model descriptor digests');
  }
  const scopePredicates = checkPredicateGroup(scope.predicates, 'document.scope.predicates');
  if (scopePredicates) return scopePredicates;
  const confirm = checkPredicateGroup(d.confirm, 'document.confirm');
  if (confirm) return confirm;
  const predicateCount =
    (isPlainObject(scope.predicates) ? Object.keys(scope.predicates).length : 0) +
    (isPlainObject(d.confirm) ? Object.keys(d.confirm).length : 0);
  if (predicateCount > MANDATE_MAX_PREDICATES) {
    return violation('invalid_document', 'document', `a mandate document holds at most ${MANDATE_MAX_PREDICATES} predicates`);
  }
  const validity = d.validity;
  if (
    !isPlainObject(validity) ||
    !hasExactKeys(validity, ['notBefore', 'notAfter']) ||
    (validity.notBefore !== null && !isMandateInstant(validity.notBefore)) ||
    (validity.notAfter !== null && !isMandateInstant(validity.notAfter))
  ) {
    return violation(
      'invalid_document',
      'document.validity',
      'validity has exactly notBefore and notAfter, each null or an ISO 8601 UTC instant with milliseconds',
    );
  }
  const limits = d.limits;
  if (!isPlainObject(limits) || !hasExactKeys(limits, ['maxRecords', 'cumulative'])) {
    return violation('invalid_document', 'document.limits', 'limits has exactly the members maxRecords and cumulative');
  }
  if (limits.maxRecords !== null && !(isNonNegativeSafeInteger(limits.maxRecords) && limits.maxRecords >= 1)) {
    return violation('invalid_document', 'document.limits.maxRecords', 'limits.maxRecords must be null or an integer of at least 1');
  }
  const cumulative = limits.cumulative;
  if (cumulative !== null) {
    if (!isPlainObject(cumulative)) {
      return violation('invalid_cap', 'document.limits.cumulative', 'limits.cumulative must be null or an object of named caps');
    }
    const names = Object.keys(cumulative);
    if (names.length === 0) {
      return violation('empty_cumulative', 'document.limits.cumulative', 'limits.cumulative with no cap must be written null');
    }
    if (names.length > MANDATE_MAX_CAPS) {
      return violation('invalid_cap', 'document.limits.cumulative', `limits.cumulative holds at most ${MANDATE_MAX_CAPS} caps`);
    }
    for (const name of names) {
      const cap = cumulative[name];
      const field = `document.limits.cumulative.${name}`;
      if (!MANDATE_NAME_RE.test(name)) return violation('invalid_cap', field, 'a cap name is [A-Za-z0-9._-]{1,64}');
      if (
        !isPlainObject(cap) ||
        !hasExactKeys(cap, ['path', 'max']) ||
        parseJsonPointer(cap.path) === null ||
        !isNonNegativeSafeInteger(cap.max)
      ) {
        return violation('invalid_cap', field, 'a cap has exactly a JSON Pointer path and a non-negative integer max');
      }
    }
  }
  const delegation = d.delegation;
  if (
    !isPlainObject(delegation) ||
    !hasExactKeys(delegation, ['allowed', 'maxDepth', 'attenuation']) ||
    typeof delegation.allowed !== 'boolean' ||
    !isNonNegativeSafeInteger(delegation.maxDepth) ||
    delegation.attenuation !== 'subset'
  ) {
    return violation('invalid_document', 'document.delegation', 'delegation has exactly allowed (boolean), maxDepth (integer) and attenuation (subset)');
  }
  const review = d.review;
  if (review !== null && (!isPlainObject(review) || !hasExactKeys(review, ['maxAgeMs']) || !isNonNegativeSafeInteger(review.maxAgeMs))) {
    return violation('invalid_document', 'document.review', 'review must be null or have exactly an integer maxAgeMs');
  }
  for (const key of ['policyDigest', 'predecessor', 'parent'] as const) {
    if (d[key] !== null && !isBareDigest(d[key])) {
      return violation('invalid_document', `document.${key}`, `${key} must be null or 64 lowercase hex`);
    }
  }
  if (prepare) {
    if (!registry.get(d.schemaVersion) || !mandateRestrictionHolds(d, d.schemaVersion, registry)) {
      return violation(
        'restriction_failed',
        'document.schemaVersion',
        'the document must name a registered schema version (v1.0) that hashes aiSystemId, action and ' +
          'contributions, and every predicate and cap path must begin with a member that version hashes',
      );
    }
    if (delegation.allowed !== false || delegation.maxDepth !== 0) {
      return violation('invalid_document', 'document.delegation', 'this version issues no sub-mandates: delegation.allowed is false and maxDepth 0');
    }
    if (d.parent !== null) {
      return violation('invalid_document', 'document.parent', 'this version issues no sub-mandates: parent is null');
    }
    if (
      typeof validity.notBefore === 'string' &&
      typeof validity.notAfter === 'string' &&
      Date.parse(validity.notAfter) < Date.parse(validity.notBefore)
    ) {
      return violation('invalid_document', 'document.validity', 'the validity window must not end before it begins');
    }
  }
  return null;
}
