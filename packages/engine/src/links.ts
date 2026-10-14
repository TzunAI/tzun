/**
 * The links member (Record §8): a hashed, generic, extensible list of
 * relations to other records. Its grammar, the relation registry with closed
 * attribute profiles, the record-local, list-level and target rules, the
 * builder, link records, and the reader's `links`, `links[<i>]` and
 * `links[<i>].edge` rows.
 *
 *   links   := null | [ link ×1..256 ]   strictly increasing by (rel, target.digest), bytewise
 *   link    := { rel, target: { digest, evidenceId, locator }, attrs }
 *
 * A relation is a registered name or an extension `x-<org>.<name>`. A writer
 * refuses an unregistered unprefixed name; a reader abstains on any relation
 * it does not know, so adding a relation is a registry entry and never
 * changes a digest, the grammar or the schema version. This version proves no
 * edge: every `links[<i>].edge` row abstains (`unsupported_link_edge`).
 */
import { canonicalSerialize } from './canonical';
import { computeDigest } from './digest';
import { identifierScheme } from './decider';
import {
  compareBytes,
  hasExactKeys,
  isBareDigest,
  isNonNegativeSafeInteger,
  isPlainObject,
  isPositiveSafeInteger,
} from './record-rules-util';
import { V1_0_HASHED_FIELDS } from './schema-registry';
import { signoffExpectationForm } from './signoff-expectation';
import type {
  HeldLinkTarget,
  Link,
  LinkInput,
  LinkLocator,
  LinkRelationProfile,
  LinkTarget,
  LinkTargetResolver,
  LinksViolation,
  LinksViolationCode,
} from './types/links';
import type { LinkRelationCheck, LinksCheck, RecordRuleRow } from './types/verification';

/** The most links a record carries (a grammar maximum). */
export const LINKS_MAX = 256;
/** The longest `target.evidenceId`. */
export const LINK_EVIDENCE_ID_MAX_LENGTH = 128;
/** The most attributes a link carries (a grammar maximum). */
export const LINK_ATTRS_MAX = 16;
/** The longest attribute string value. */
export const LINK_ATTR_STRING_MAX_LENGTH = 256;

/** A registered relation name, and an attribute name: `[a-z][A-Za-z0-9]{0,31}`. */
export const REGISTERED_RELATION_RE = /^[a-z][A-Za-z0-9]{0,31}$/;
/** An extension relation (or attribute) name `x-<org>.<name>`: at most 67 characters, never registered. */
export const EXTENSION_RELATION_RE = /^x-[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.[a-z][A-Za-z0-9]{0,31}$/;

/** A relation name: the registered-name pattern or the extension pattern, over the whole string. */
export const RELATION_NAME_RE = /^(?:[a-z][A-Za-z0-9]{0,31}|x-[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.[a-z][A-Za-z0-9]{0,31})$/;

/** The `aiSystemId` of a link record (Record §8.6). */
export const LINK_RECORD_AI_SYSTEM_ID = 'tzun:link';
/** The `action` of a link record. */
export const LINK_RECORD_ACTION = 'link';

/** `aiSystemId` and actions of the mandate system records (Record §9.6). */
const MANDATE_AI_SYSTEM_ID = 'tzun:mandate';
const MANDATE_ISSUE_ACTION = 'issue-mandate';
const MANDATE_REVOKE_ACTION = 'revoke-mandate';

const LINK_KEYS = ['rel', 'target', 'attrs'] as const;
const TARGET_KEYS = ['digest', 'evidenceId', 'locator'] as const;
const LOCATOR_KEYS = ['origin', 'seq'] as const;
const INPUT_KEYS = ['rel', 'target', 'attrs'] as const;
const TARGET_INPUT_KEYS = ['digest', 'evidenceId', 'locator', 'external'] as const;
/** A target's evidence id: 1 to 128 characters of 0x21–0x7E. */
const EVIDENCE_ID_RE = /^[\x21-\x7e]{1,128}$/;
/** An attribute string value: 0 to 256 characters of 0x20–0x7E. */
const ATTR_STRING_RE = /^[\x20-\x7e]{0,256}$/;

const profile = (
  name: string,
  lineage: boolean,
  writer: LinkRelationProfile['writer'],
  requiredAttrs: readonly string[] = [],
): LinkRelationProfile => Object.freeze({ name, lineage, requiredAttrs: Object.freeze([...requiredAttrs]), optionalAttrs: Object.freeze([]), writer });

/**
 * The relation registry (Record §8.3, §8.4). A registered relation's profile and rules
 * never change; a changed meaning takes a new name. Profiles are closed: an
 * attribute outside the profile, an `x-` attribute included, is refused.
 */
export const LINK_RELATIONS: Readonly<Record<string, LinkRelationProfile>> = Object.freeze({
  derivedFrom: profile('derivedFrom', true, 'caller'),
  reviews: profile('reviews', true, 'caller'),
  supersedes: profile('supersedes', true, 'caller'),
  appeals: profile('appeals', true, 'caller'),
  ratifies: profile('ratifies', true, 'caller'),
  implements: profile('implements', true, 'caller'),
  delegatedBy: profile('delegatedBy', true, 'caller'),
  closes: profile('closes', true, 'none', ['size', 'statement', 'treeRoot']),
  fanoutOf: profile('fanoutOf', true, 'none', ['slot', 'statement']),
  root: profile('root', false, 'caller'),
  mandate: profile('mandate', false, 'reserved'),
  revokes: profile('revokes', false, 'reserved'),
  subject: profile('subject', false, 'reserved'),
});

/** The registered relation names. */
export const LINK_RELATION_NAMES: readonly string[] = Object.freeze(Object.keys(LINK_RELATIONS));

/** The relations a link record may not carry beside its `subject` link. */
const NOT_IN_LINK_RECORD = ['root', 'mandate', 'revokes', 'closes', 'fanoutOf'];
/** The relations a record carries at most once. */
const AT_MOST_ONE = ['root', 'closes', 'fanoutOf'];

/** Whether `rel` is a registered relation. */
export function isRegisteredRelation(rel: unknown): rel is string {
  return typeof rel === 'string' && Object.prototype.hasOwnProperty.call(LINK_RELATIONS, rel);
}

/** Whether `rel` is an extension relation name `x-<org>.<name>`. */
export function isExtensionRelation(rel: unknown): rel is string {
  return typeof rel === 'string' && EXTENSION_RELATION_RE.test(rel);
}

/** Whether `rel` meets the relation grammar: the registered-name pattern or the extension pattern. */
export function isRelationName(rel: unknown): rel is string {
  return typeof rel === 'string' && RELATION_NAME_RE.test(rel);
}

/** Whether a registered relation makes this record a child of its target (a lineage relation). */
export function isLineageRelation(rel: unknown): boolean {
  return isRegisteredRelation(rel) && LINK_RELATIONS[rel].lineage;
}

// ── Evidence-log origins (tzun-anchor/1 §4.3) ─────────────────────────────

/** Origin text (tzun-anchor/1 §4.3): printable ASCII other than space and `+`. */
const ORIGIN_TEXT_RE = /^[\x21-\x2a\x2c-\x7e]+$/;
/** A namespace label (tzun-anchor/1 §4.3.2): a-z and 0-9, with `-` only inside it. */
const NAMESPACE_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const NAMESPACE_MAX_LENGTH = 253;
const NAMESPACE_LABEL_MAX_LENGTH = 63;
/** An SDK store id: 32 lowercase hex characters. */
const STORE_ID_RE = /^[0-9a-f]{32}$/;
/** A chain segment: lowercase hex of whole bytes. */
const CHAIN_SEGMENT_RE = /^(?:[0-9a-f]{2})+$/;
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function isLogNamespace(ns: string): boolean {
  if (ns.length === 0 || ns.length > NAMESPACE_MAX_LENGTH) return false;
  return ns.split('.').every((label) => label.length <= NAMESPACE_LABEL_MAX_LENGTH && NAMESPACE_LABEL_RE.test(label));
}

function isChainSegment(segment: string): boolean {
  if (!CHAIN_SEGMENT_RE.test(segment)) return false;
  let chainId: string;
  try {
    chainId = UTF8_STRICT.decode(Buffer.from(segment, 'hex'));
  } catch {
    return false;
  }
  return !chainId.includes('\u0000') && Buffer.from(chainId, 'utf8').toString('hex') === segment;
}

/**
 * Whether `origin` names a log that holds evidence records, under the origin
 * grammar of tzun-anchor/1 §4.3 (held to `vectors/evidence-log-origin-vectors.json`):
 *
 *   - an SDK store's evidence log, four segments:
 *     `<ns>/<store id>/evidence/<chain segment>`, where `ns` is a lowercase
 *     DNS-style name, the store id 32 lowercase hex, and the chain segment
 *     the lowercase hex of a chain id's UTF-8 bytes;
 *   - a hosted deployment's log, three segments: `<ns>/<deployment
 *     id>/<log id>`, the ids opaque origin text. The last segment is neither
 *     `anchors` (an anchor log holds no records) nor `evidence` (an SDK
 *     evidence log names its chain).
 *
 * Every segment is non-empty origin text (printable ASCII other than space
 * and `+`). A four-segment origin of any other kind (`…/custody/…`) is not an
 * evidence log.
 */
export function isEvidenceLogOrigin(origin: unknown): origin is string {
  if (typeof origin !== 'string' || !ORIGIN_TEXT_RE.test(origin)) return false;
  const segments = origin.split('/');
  if (segments.length < 3 || segments.length > 4 || segments.some((s) => s.length === 0)) return false;
  if (!isLogNamespace(segments[0])) return false;
  if (segments.length === 4) {
    return STORE_ID_RE.test(segments[1]) && segments[2] === 'evidence' && isChainSegment(segments[3]);
  }
  return segments[2] !== 'anchors' && segments[2] !== 'evidence';
}

// ── Grammar ───────────────────────────────────────────────────────────────

/** Order links by (`rel`, `target.digest`), each bytewise (a shorter prefix sorts first). */
export function compareLinks(a: { rel: string; target: { digest: string } }, b: { rel: string; target: { digest: string } }): number {
  return compareBytes(a.rel, b.rel) || compareBytes(a.target.digest, b.target.digest);
}

const MESSAGES: Record<LinksViolationCode, string> = {
  not_an_array: 'links must be null or an array of links',
  empty_links: 'links must be null when there is no link, never []',
  too_many_links: `links holds at most ${LINKS_MAX} links`,
  not_a_set: 'links must be strictly increasing by (rel, target.digest) bytewise, with no repeated pair',
  link_unknown_members: 'a link has exactly the members rel, target and attrs',
  link_missing_members: 'a link has every member (rel, target, attrs), null where it does not apply',
  invalid_relation: 'rel must be [a-z][A-Za-z0-9]{0,31} or an extension x-<org>.<name>',
  unknown_relation: `rel must be a registered relation (${Object.keys(LINK_RELATIONS).join(', ')}) or an extension x-<org>.<name>`,
  relation_reserved: 'this relation is written only by the SDK (mandate, revokes and subject)',
  relation_not_writable: 'this relation has no writer in this version (closes and fanoutOf)',
  invalid_target: 'target has exactly the members digest, evidenceId and locator',
  invalid_target_digest: 'target.digest must be 64 lowercase hex characters',
  invalid_target_evidence_id: 'target.evidenceId must be null or 1 to 128 characters of 0x21-0x7E',
  invalid_locator: 'target.locator must be null or exactly an evidence-log origin and a seq of at least 1',
  invalid_attrs:
    'attrs must be null or an object of 1 to 16 attributes, each named [a-z][A-Za-z0-9]{0,31} or x-<org>.<name>, ' +
    'whose value is a string of at most 256 characters 0x20-0x7E, a non-negative safe integer, or a boolean',
  too_many_attrs: `attrs holds at most ${LINK_ATTRS_MAX} attributes`,
  attrs_not_allowed: "an attribute outside the relation's profile",
  missing_attr: "an attribute the relation's profile requires is missing",
  link_rule_violated: "the relation's rule does not hold",
  required_link_missing: 'the record requires a link it does not carry',
  link_target_not_found: 'the store holds no record the target names; a record of another store is passed with external: true',
  link_target_mismatch: 'a member of the target disagrees with the record the store holds',
  root_without_lineage: 'a root link stands only beside a lineage link',
};

function violation(code: LinksViolationCode, field: string, extra: { link?: number; rule?: string } = {}): LinksViolation {
  return { code, field, message: `${field}: ${MESSAGES[code]}`, ...extra };
}

function isAttrName(name: string): boolean {
  return REGISTERED_RELATION_RE.test(name) || EXTENSION_RELATION_RE.test(name);
}

function isAttrValue(value: unknown): boolean {
  if (typeof value === 'boolean') return true;
  if (typeof value === 'string') return ATTR_STRING_RE.test(value);
  return isNonNegativeSafeInteger(value);
}

function locatorWellFormed(locator: unknown): locator is LinkLocator {
  return (
    isPlainObject(locator) &&
    hasExactKeys(locator, LOCATOR_KEYS) &&
    isEvidenceLogOrigin(locator.origin) &&
    isPositiveSafeInteger(locator.seq)
  );
}

/** The general grammar of one link (Record §8.2), first failure first, or `null`. */
function linkGrammarViolation(link: unknown, i: number): LinksViolation | null {
  const f = `links[${i}]`;
  if (!isPlainObject(link)) return violation('link_unknown_members', f, { link: i });
  if (Object.keys(link).some((k) => !(LINK_KEYS as readonly string[]).includes(k))) {
    return violation('link_unknown_members', f, { link: i });
  }
  if (!hasExactKeys(link, LINK_KEYS)) return violation('link_missing_members', f, { link: i });
  if (!isRelationName(link.rel)) return violation('invalid_relation', `${f}.rel`, { link: i });
  const target = link.target;
  if (!isPlainObject(target) || !hasExactKeys(target, TARGET_KEYS)) return violation('invalid_target', `${f}.target`, { link: i });
  if (!isBareDigest(target.digest)) return violation('invalid_target_digest', `${f}.target.digest`, { link: i });
  if (target.evidenceId !== null && !(typeof target.evidenceId === 'string' && EVIDENCE_ID_RE.test(target.evidenceId))) {
    return violation('invalid_target_evidence_id', `${f}.target.evidenceId`, { link: i });
  }
  if (target.locator !== null && !locatorWellFormed(target.locator)) {
    return violation('invalid_locator', `${f}.target.locator`, { link: i });
  }
  const attrs = link.attrs;
  if (attrs !== null) {
    if (!isPlainObject(attrs)) return violation('invalid_attrs', `${f}.attrs`, { link: i });
    const names = Object.keys(attrs);
    if (names.length === 0) return violation('invalid_attrs', `${f}.attrs`, { link: i });
    if (names.length > LINK_ATTRS_MAX) return violation('too_many_attrs', `${f}.attrs`, { link: i });
    for (const name of names) {
      if (!isAttrName(name) || !isAttrValue(attrs[name])) return violation('invalid_attrs', `${f}.attrs`, { link: i });
    }
  }
  return null;
}

/**
 * Why `value` breaks the general grammar of `links` (Record §8.2), first failure
 * first, or `null` when it meets it (or is `null`): an array of 1 to 256
 * links, each with exactly `rel`, `target` and `attrs`, strictly increasing by
 * (`rel`, `target.digest`). It does not read the registry: a relation this
 * version does not know is well formed.
 */
export function linksGrammarViolation(value: unknown): LinksViolation | null {
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value)) return violation('not_an_array', 'links');
  if (value.length === 0) return violation('empty_links', 'links');
  if (value.length > LINKS_MAX) return violation('too_many_links', 'links');
  for (let i = 0; i < value.length; i++) {
    const v = linkGrammarViolation(value[i], i);
    if (v) return v;
  }
  for (let i = 1; i < value.length; i++) {
    if (compareLinks(value[i - 1] as Link, value[i] as Link) >= 0) return violation('not_a_set', 'links', { link: i });
  }
  return null;
}

/**
 * Why a link's attributes break its registered relation's closed profile, or
 * `null` (an unregistered relation is not judged here): every required
 * attribute present with its value grammar (`statement`, `treeRoot` 64
 * lowercase hex; `size` an integer of at least 0; `slot` of at least 1), and
 * no other attribute.
 */
export function linkAttrsViolation(link: Link, i: number): LinksViolation | null {
  if (!isRegisteredRelation(link.rel)) return null;
  const p = LINK_RELATIONS[link.rel];
  const f = `links[${i}].attrs`;
  const attrs = link.attrs ?? {};
  const names = Object.keys(attrs);
  const allowed = [...p.requiredAttrs, ...p.optionalAttrs];
  if (names.some((n) => !allowed.includes(n))) return violation('attrs_not_allowed', f, { link: i });
  for (const name of p.requiredAttrs) {
    if (!Object.prototype.hasOwnProperty.call(attrs, name)) return violation('missing_attr', `${f}.${name}`, { link: i });
    const value = attrs[name];
    const ok =
      name === 'statement' || name === 'treeRoot'
        ? isBareDigest(value)
        : name === 'size'
          ? isNonNegativeSafeInteger(value)
          : name === 'slot'
            ? isPositiveSafeInteger(value)
            : true;
    if (!ok) return violation('invalid_attrs', `${f}.${name}`, { link: i });
  }
  return null;
}

// ── Rules ─────────────────────────────────────────────────────────────────

/** The record members the list-level and record-local rules read. */
export interface LinksContext {
  aiSystemId?: unknown;
  action?: unknown;
  decider?: unknown;
  contributions?: unknown;
  aiOutput?: unknown;
  signoffExpectation?: unknown;
}

function isRevocationRecord(ctx: LinksContext): boolean {
  return ctx.aiSystemId === MANDATE_AI_SYSTEM_ID && ctx.action === MANDATE_REVOKE_ACTION;
}

function isIssuanceRecord(payload: Record<string, unknown>): boolean {
  return payload.aiSystemId === MANDATE_AI_SYSTEM_ID && payload.action === MANDATE_ISSUE_ACTION;
}

/** Whether a record is a link record (Record §8.6): its `aiSystemId` is `tzun:link`. */
export function isLinkRecord(payload: unknown): boolean {
  return isPlainObject(payload) && payload.aiSystemId === LINK_RECORD_AI_SYSTEM_ID;
}

const countOf = (links: readonly Link[], rel: string) => links.filter((l) => l.rel === rel).length;

/**
 * The list-level rules (Record §8.3) over a well-formed `links` (or `null`), first
 * broken first: `{ rule, missing }` where `missing` says a required link is
 * absent (the writer's `required_link_missing`), or `null` when they hold.
 *
 *   mandate_link  exactly one `mandate` link when the expectation is the
 *                 mandate form, none otherwise (not applied when the
 *                 expectation is malformed: that row already fails);
 *   revokes_link  exactly one `revokes` link on a revocation record
 *                 (`tzun:mandate`, `revoke-mandate`), none elsewhere;
 *   subject_link  exactly one `subject` link on a link record (`tzun:link`),
 *                 none elsewhere; with it, `action` is `link`, `contributions`
 *                 is `null`, at least one other link exists, no other link
 *                 has the subject's target digest, and no `root`, `mandate`,
 *                 `revokes`, `closes` or `fanoutOf` link is beside it;
 *   at_most_one   at most one `root`, one `closes` and one `fanoutOf` link.
 */
export function linksListRuleViolation(
  links: readonly Link[] | null,
  ctx: LinksContext,
): { rule: string; missing: boolean } | null {
  const list = links ?? [];
  const form = signoffExpectationForm(ctx.signoffExpectation);
  if (form !== null) {
    const expected = form === 'mandate' ? 1 : 0;
    const n = countOf(list, 'mandate');
    if (n !== expected) return { rule: 'mandate_link', missing: n < expected };
  }
  {
    const expected = isRevocationRecord(ctx) ? 1 : 0;
    const n = countOf(list, 'revokes');
    if (n !== expected) return { rule: 'revokes_link', missing: n < expected };
  }
  {
    const linkRecord = ctx.aiSystemId === LINK_RECORD_AI_SYSTEM_ID;
    const n = countOf(list, 'subject');
    if (n !== (linkRecord ? 1 : 0)) return { rule: 'subject_link', missing: linkRecord && n === 0 };
    if (linkRecord) {
      const subject = list.find((l) => l.rel === 'subject')!;
      const others = list.filter((l) => l.rel !== 'subject');
      if (
        ctx.action !== LINK_RECORD_ACTION ||
        (ctx.contributions !== null && ctx.contributions !== undefined) ||
        others.length === 0 ||
        others.some((l) => l.target.digest === subject.target.digest) ||
        others.some((l) => NOT_IN_LINK_RECORD.includes(l.rel))
      ) {
        return { rule: 'subject_link', missing: others.length === 0 };
      }
    }
  }
  for (const rel of AT_MOST_ONE) if (countOf(list, rel) > 1) return { rule: 'at_most_one', missing: false };
  return null;
}

/**
 * Whether any link of the list has an unregistered unprefixed relation: one
 * a later registry may define, possibly as a lineage relation. An `x-`
 * relation is never registered, so it can never be one.
 */
function hasUnregisteredUnprefixedRelation(links: readonly Link[]): boolean {
  return links.some((l) => !isRegisteredRelation(l.rel) && !isExtensionRelation(l.rel));
}

/**
 * The record-local rule of link `i` (Record §8.3), read from this record alone:
 * `ok`, `violated` with the rule, or `abstain` (`root` with no lineage link
 * beside it but an unregistered unprefixed relation, which a later registry
 * may define as a lineage relation; an `x-` relation is never registered, so
 * beside one alone `root` is violated).
 * In a link record the record-local rules bind the subject, not the link
 * record, so they are not applied here (`checkLinkTarget` applies them to a
 * held subject).
 *
 *   ratifies  this record's decider is a `human` (ratifies_decider_human)
 *   root      at least one lineage link beside it (root_without_lineage)
 */
export function linkRecordLocalRule(
  links: readonly Link[],
  i: number,
  ctx: LinksContext,
): { result: 'ok' } | { result: 'violated'; rule: string } | { result: 'abstain' } {
  const link = links[i];
  if (ctx.aiSystemId === LINK_RECORD_AI_SYSTEM_ID) return { result: 'ok' };
  if (link.rel === 'ratifies') {
    const decider = isPlainObject(ctx.decider) ? ctx.decider : null;
    if (decider === null || decider.kind !== 'human') return { result: 'violated', rule: 'ratifies_decider_human' };
  }
  if (link.rel === 'root') {
    const lineage = links.some((l, j) => j !== i && isLineageRelation(l.rel));
    if (!lineage) {
      return hasUnregisteredUnprefixedRelation(links) ? { result: 'abstain' } : { result: 'violated', rule: 'root_without_lineage' };
    }
  }
  return { result: 'ok' };
}

/** The canonical digest a held payload recomputes to under the v1.0 hashed field set, or `null`. */
function heldDigest(payload: Record<string, unknown>): string | null {
  try {
    return computeDigest(canonicalSerialize(payload, [...V1_0_HASHED_FIELDS]));
  } catch {
    return null;
  }
}

/**
 * Which non-null member of `target` disagrees with the held record (Record §8.8),
 * or `null`: `digest` (the held payload does not recompute to it),
 * `evidenceId`, or `locator` (its `seq` is not the record's sequence number,
 * or its origin is not the record's chain's origin, when known).
 */
export function linkTargetMemberMismatch(target: LinkTarget, held: HeldLinkTarget): 'digest' | 'evidenceId' | 'locator' | null {
  if (held.digest !== target.digest || heldDigest(held.payload) !== target.digest) return 'digest';
  if (target.evidenceId !== null && target.evidenceId !== held.payload.evidenceId) return 'evidenceId';
  if (target.locator !== null) {
    if (target.locator.seq !== held.payload.sequenceNumber) return 'locator';
    if (held.origin !== null && target.locator.origin !== held.origin) return 'locator';
  }
  return null;
}

function deciderOf(payload: Record<string, unknown> | LinksContext): Record<string, unknown> | null {
  const d = (payload as { decider?: unknown }).decider;
  return isPlainObject(d) ? d : null;
}

/**
 * Whether two deciders are the same for the `reviews` rule: equal `kind` and
 * `id` as strings, after opening a `cmt:` identifier with `open`. `null`
 * (undetermined) when a `cmt:` identifier on either side cannot be opened.
 */
function sameDecider(
  a: Record<string, unknown> | null,
  b: Record<string, unknown> | null,
  open?: (id: string) => string | null,
): boolean | null {
  if (a === null || b === null) return null;
  if (a.kind === b.kind && a.id === b.id) return true;
  const idOf = (id: unknown): string | null => {
    if (typeof id !== 'string') return null;
    if (identifierScheme(id) !== 'cmt') return id;
    return open ? open(id) : null;
  };
  const ia = idOf(a.id);
  const ib = idOf(b.id);
  if (ia === null || ib === null) return null;
  return a.kind === b.kind && ia === ib;
}

/** What the target rule of one link concluded. */
export type LinkTargetRuleResult =
  | { result: 'ok'; rootInconsistent?: boolean }
  | { result: 'violated'; rule: string }
  | { result: 'undetermined'; rule: string }
  | { result: 'unsupported' }
  | { result: 'not-held' };

/**
 * The target rule of `link` (Record §8.3) with the record `child` in the child's
 * place: for an ordinary record, the record itself; in a link record, its
 * subject (whose record-local rules then apply as target rules). `target` is
 * the held target record, or `null` when the verifier does not hold it.
 *
 *   reviews      the child's decider is not the target's (same = kind and id
 *                equal); a `cmt:` that cannot be opened → undetermined
 *   supersedes   the same `aiSystemId`
 *   ratifies     the target's decider is not a `human` (and, in a link
 *                record, the subject's decider is)
 *   mandate      the target is an issuance record whose
 *                `aiOutput.assertionDigest` is the child's `mandateAssertion`
 *   revokes      the target is an issuance record with the child's
 *                `aiOutput.mandateDigest`
 *   root         facts only (`rootInconsistent`), never a failure
 *   delegatedBy, closes, fanoutOf   not implemented → unsupported
 *   derivedFrom, appeals, implements, subject   no target rule → ok
 */
export function checkLinkTarget(
  link: Link,
  child: Record<string, unknown> | null,
  target: HeldLinkTarget | null,
  options: { links?: readonly Link[]; resolver?: LinkTargetResolver } = {},
): LinkTargetRuleResult {
  switch (link.rel) {
    case 'delegatedBy':
    case 'closes':
    case 'fanoutOf':
      return { result: 'unsupported' };
    case 'derivedFrom':
    case 'appeals':
    case 'implements':
    case 'subject':
      return { result: 'ok' };
    case 'root':
      return target === null ? { result: 'ok' } : { result: 'ok', rootInconsistent: rootInconsistent(link, target, options) };
    default:
      break;
  }
  if (child === null || target === null) return { result: 'not-held' };
  const t = target.payload;
  switch (link.rel) {
    case 'reviews': {
      const same = sameDecider(deciderOf(child), deciderOf(t), options.resolver?.openCommitment?.bind(options.resolver));
      if (same === null) return { result: 'undetermined', rule: 'reviews_distinct_decider' };
      return same ? { result: 'violated', rule: 'reviews_distinct_decider' } : { result: 'ok' };
    }
    case 'supersedes':
      return child.aiSystemId === t.aiSystemId ? { result: 'ok' } : { result: 'violated', rule: 'supersedes_same_system' };
    case 'ratifies': {
      if (deciderOf(t)?.kind === 'human') return { result: 'violated', rule: 'ratifies_target_not_human' };
      return { result: 'ok' };
    }
    case 'mandate': {
      const expectation = isPlainObject(child.signoffExpectation) ? child.signoffExpectation : {};
      const out = isPlainObject(t.aiOutput) ? t.aiOutput : {};
      return isIssuanceRecord(t) && out.assertionDigest === expectation.mandateAssertion
        ? { result: 'ok' }
        : { result: 'violated', rule: 'mandate_target' };
    }
    case 'revokes': {
      const own = isPlainObject(child.aiOutput) ? child.aiOutput : {};
      const out = isPlainObject(t.aiOutput) ? t.aiOutput : {};
      return isIssuanceRecord(t) && typeof own.mandateDigest === 'string' && out.mandateDigest === own.mandateDigest
        ? { result: 'ok' }
        : { result: 'violated', rule: 'revokes_target' };
    }
    default:
      return { result: 'ok' };
  }
}

/**
 * The `root` facts (Record §8.5): the root target has a lineage link of its
 * own, or a held lineage target of this record names another root (its own
 * `root` link's target, or itself when it has no lineage link).
 */
function rootInconsistent(link: Link, target: HeldLinkTarget, options: { links?: readonly Link[]; resolver?: LinkTargetResolver }): boolean {
  const ownLinks = Array.isArray(target.payload.links) ? (target.payload.links as Link[]) : [];
  if (ownLinks.some((l) => isPlainObject(l) && isLineageRelation(l.rel))) return true;
  const resolver = options.resolver;
  if (!options.links || !resolver?.byDigest) return false;
  for (const other of options.links) {
    if (!isLineageRelation(other.rel)) continue;
    const held = resolver.byDigest(other.target.digest);
    if (held === null) continue;
    const named = rootNamedBy(held);
    if (named !== null && named !== link.target.digest) return true;
  }
  return false;
}

/** The root a held record names: its `root` link's target digest, itself when it has no lineage link, or `null`. */
function rootNamedBy(held: HeldLinkTarget): string | null {
  const own = Array.isArray(held.payload.links) ? (held.payload.links as unknown[]) : [];
  const root = own.find((l): l is Link => isPlainObject(l) && l.rel === 'root');
  if (root && isPlainObject(root.target) && typeof root.target.digest === 'string') return root.target.digest;
  if (own.some((l) => isPlainObject(l) && isLineageRelation(l.rel))) return null;
  return held.digest;
}

/**
 * The rules of a link record's link `link` (Record §8.6), other than `subject`,
 * with the held `subject` in the child's place: a record-local rule of the
 * relation becomes a target rule on the subject (`ratifies`: the subject's
 * decider is a `human`), and the relation's target rule reads the subject.
 * `not-held` when a rule needs the subject or the target and it is not held.
 */
export function checkLinkRecordLink(
  link: Link,
  subject: HeldLinkTarget | null,
  target: HeldLinkTarget | null,
  options: { links?: readonly Link[]; resolver?: LinkTargetResolver } = {},
): LinkTargetRuleResult {
  if (link.rel === 'ratifies') {
    if (subject === null) return { result: 'not-held' };
    if (deciderOf(subject.payload)?.kind !== 'human') return { result: 'violated', rule: 'ratifies_decider_human' };
  }
  return checkLinkTarget(link, subject === null ? null : subject.payload, target, options);
}

// ── Writer ────────────────────────────────────────────────────────────────

/**
 * Why `value` is not a `links` member a 0.8.0 writer may write, first failure
 * first, or `null` when it is one (or is `null` and no list-level rule
 * requires a link). `ctx` holds the record's `aiSystemId`, `action`,
 * `decider`, `contributions` and `signoffExpectation`.
 *
 *   - the general grammar (Record §8.2);
 *   - each relation registered (`unknown_relation`) or an extension; `closes`
 *     and `fanoutOf` have no writer in this version (`relation_not_writable`);
 *   - each registered relation's closed attribute profile
 *     (`attrs_not_allowed`, `missing_attr`, `invalid_attrs`);
 *   - each record-local rule (`link_rule_violated`; `root_without_lineage`);
 *   - the list-level rules (`required_link_missing` when a required link is
 *     absent, `link_rule_violated` otherwise).
 *
 * Reserved relations (`mandate`, `revokes`, `subject`) are accepted here,
 * under their list-level rules: the payload gate runs over records the SDK's
 * mandate and link APIs build. A caller's capture is refused them by
 * `buildLinks` (`relation_reserved`).
 */
export function linksViolation(value: unknown, ctx: LinksContext): LinksViolation | null {
  const grammar = linksGrammarViolation(value);
  if (grammar) return grammar;
  const links = (value ?? null) as Link[] | null;
  if (links !== null) {
    for (let i = 0; i < links.length; i++) {
      const rel = links[i].rel;
      if (!isRegisteredRelation(rel) && !isExtensionRelation(rel)) return violation('unknown_relation', `links[${i}].rel`, { link: i });
      if (isRegisteredRelation(rel) && LINK_RELATIONS[rel].writer === 'none') {
        return violation('relation_not_writable', `links[${i}].rel`, { link: i });
      }
      const attrs = linkAttrsViolation(links[i], i);
      if (attrs) return attrs;
    }
    for (let i = 0; i < links.length; i++) {
      const local = linkRecordLocalRule(links, i, ctx);
      if (local.result === 'violated') {
        return local.rule === 'root_without_lineage'
          ? violation('root_without_lineage', `links[${i}]`, { link: i, rule: local.rule })
          : violation('link_rule_violated', `links[${i}]`, { link: i, rule: local.rule });
      }
      if (local.result === 'abstain') return violation('root_without_lineage', `links[${i}]`, { link: i, rule: 'root_without_lineage' });
    }
  }
  const list = linksListRuleViolation(links, ctx);
  if (list) {
    return list.missing
      ? violation('required_link_missing', 'links', { rule: list.rule })
      : violation('link_rule_violated', 'links', { rule: list.rule });
  }
  return null;
}

/**
 * Why a link record (Record §8.6) is refused, or `null` when the payload is one
 * whose links meet the `subject` rules, or is not a link record: exactly one
 * `subject` link, `action` `link`, `contributions` `null`, at least one other
 * link, no other link with the subject's target digest, and no `root`,
 * `mandate`, `revokes`, `closes` or `fanoutOf` link.
 */
export function linkRecordViolation(payload: unknown): LinksViolation | null {
  if (!isLinkRecord(payload)) return null;
  const p = payload as Record<string, unknown>;
  const grammar = linksGrammarViolation(p.links);
  if (grammar) return grammar;
  const list = linksListRuleViolation((p.links ?? null) as Link[] | null, p);
  if (list && list.rule === 'subject_link') {
    return list.missing
      ? violation('required_link_missing', 'links', { rule: 'subject_link' })
      : violation('link_rule_violated', 'links', { rule: 'subject_link' });
  }
  return null;
}

/** Thrown by `buildLinks` for input a writer refuses. */
export class LinksBuildError extends Error {
  readonly code: LinksViolationCode;
  readonly field: string;
  readonly link?: number;
  readonly rule?: string;
  constructor(v: LinksViolation) {
    super(v.message);
    this.name = 'LinksBuildError';
    this.code = v.code;
    this.field = v.field;
    if (v.link !== undefined) this.link = v.link;
    if (v.rule !== undefined) this.rule = v.rule;
  }
}

/** Options of {@link buildLinks}. */
export interface BuildLinksOptions {
  /**
   * One entry per input, in input order: the same-store record the caller
   * resolved the target to (by `evidenceId` when given, otherwise by
   * `digest`), or `null` when it resolved none. A target marked `external`
   * that resolves in this store is passed resolved, and handled as a
   * same-store target. Absent: every target is unresolved.
   */
  held?: ReadonlyArray<HeldLinkTarget | null>;
  /** The reserved relations this build may write: the SDK's mandate and link APIs only. */
  allowReserved?: readonly ('mandate' | 'revokes' | 'subject')[];
  /**
   * A link record (`tzun.links.relate`): no `root` link is added, and with
   * `context` each relation's rules take the held subject in the child's
   * place.
   */
  linkRecord?: boolean;
  /**
   * The record being built, for the target rules of same-store targets. When
   * absent, no target rule is applied (the payload gate still applies the
   * list-level and record-local rules).
   */
  context?: LinksContext;
  /**
   * The identifier a `cmt:` decider commits to, or `null` when the writer
   * cannot open it: the record's own decider from the capture's opening, and
   * a held target's from the store's openings. The `reviews` rule opens both
   * sides with it, as store-level verification does; absent, a `cmt:`
   * decider on either side leaves the rule undetermined and the link is
   * written.
   */
  openCommitment?: (id: string) => string | null;
}

function sameLocator(a: LinkLocator | null, b: LinkLocator | null): boolean {
  if (a === null || b === null) return a === b;
  return a.origin === b.origin && a.seq === b.seq;
}

/**
 * Build `links` from capture input (Record §8.7):
 *
 *   - an empty input array is refused (`empty_links`): "no link" is `null`;
 *   - each relation registered or an extension; a reserved relation only
 *     where `allowReserved` names it (`relation_reserved`); `closes` and
 *     `fanoutOf` never (`relation_not_writable`);
 *   - a same-store target (its `held` entry): `digest`, `evidenceId` and the
 *     locator filled from the held record, a supplied member that disagrees
 *     refused (`link_target_mismatch`); an input `locator: null` stays `null`;
 *   - an unresolved target: with `external: true`, `digest` required and the
 *     other members written as given (`null` when omitted); without it,
 *     refused (`link_target_not_found`);
 *   - `attrs` absent written as `null`, and held to the relation's profile;
 *   - sorted by (`rel`, `target.digest`); a repeated pair is refused
 *     (`not_a_set`), never removed;
 *   - when the input has a lineage link and no `root` link, and this is not
 *     a link record, a `root` link from the first lineage link in sorted
 *     order whose target is held: that target's own `root` link's target, or
 *     the target itself when it has no lineage link; when that target has a
 *     lineage link but no `root` link, or no lineage target is held, none;
 *   - with `context`, the target rule of each held target (a `cmt:` decider
 *     opened with `openCommitment`); in a link record
 *     (`linkRecord`, or a `tzun:link` context) with its subject held, each
 *     other link's rules with the subject in the child's place (Record §8.6): the
 *     `ratifies` subject is a `human`, and each held target's rule reads the
 *     subject.
 *
 * @throws LinksBuildError
 */
export function buildLinks(inputs: readonly LinkInput[], options: BuildLinksOptions = {}): Link[] {
  if (!Array.isArray(inputs)) throw new LinksBuildError(violation('not_an_array', 'links'));
  if (inputs.length === 0) throw new LinksBuildError(violation('empty_links', 'links'));
  if (inputs.length > LINKS_MAX) throw new LinksBuildError(violation('too_many_links', 'links'));
  const allowReserved = options.allowReserved ?? [];
  const built: { link: Link; held: HeldLinkTarget | null }[] = [];
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i] as unknown;
    const f = `links[${i}]`;
    if (!isPlainObject(input) || Object.keys(input).some((k) => !(INPUT_KEYS as readonly string[]).includes(k))) {
      throw new LinksBuildError(violation('link_unknown_members', f, { link: i }));
    }
    const rel = input.rel;
    if (!isRelationName(rel)) throw new LinksBuildError(violation('invalid_relation', `${f}.rel`, { link: i }));
    if (!isRegisteredRelation(rel) && !isExtensionRelation(rel)) {
      throw new LinksBuildError(violation('unknown_relation', `${f}.rel`, { link: i }));
    }
    if (isRegisteredRelation(rel)) {
      const writer = LINK_RELATIONS[rel].writer;
      if (writer === 'none') throw new LinksBuildError(violation('relation_not_writable', `${f}.rel`, { link: i }));
      if (writer === 'reserved' && !(allowReserved as readonly string[]).includes(rel)) {
        throw new LinksBuildError(violation('relation_reserved', `${f}.rel`, { link: i }));
      }
    }
    const t = input.target;
    if (!isPlainObject(t) || Object.keys(t).some((k) => !(TARGET_INPUT_KEYS as readonly string[]).includes(k))) {
      throw new LinksBuildError(violation('invalid_target', `${f}.target`, { link: i }));
    }
    const held = options.held?.[i] ?? null;
    let target: LinkTarget;
    if (held !== null) {
      const filledLocator: LinkLocator | null =
        t.locator === null
          ? null
          : held.origin !== null && isPositiveSafeInteger(held.payload.sequenceNumber)
            ? { origin: held.origin, seq: held.payload.sequenceNumber }
            : null;
      if (t.digest !== undefined && t.digest !== held.digest) {
        throw new LinksBuildError(violation('link_target_mismatch', `${f}.target.digest`, { link: i }));
      }
      if (t.evidenceId !== undefined && t.evidenceId !== null && t.evidenceId !== held.payload.evidenceId) {
        throw new LinksBuildError(violation('link_target_mismatch', `${f}.target.evidenceId`, { link: i }));
      }
      if (t.locator !== undefined && t.locator !== null && !sameLocator(t.locator as LinkLocator, filledLocator)) {
        throw new LinksBuildError(violation('link_target_mismatch', `${f}.target.locator`, { link: i }));
      }
      target = {
        digest: held.digest,
        evidenceId: typeof held.payload.evidenceId === 'string' ? held.payload.evidenceId : null,
        locator: filledLocator,
      };
    } else {
      if (t.external !== true) throw new LinksBuildError(violation('link_target_not_found', `${f}.target`, { link: i }));
      target = {
        digest: t.digest as string,
        evidenceId: (t.evidenceId ?? null) as string | null,
        locator: (t.locator ?? null) as LinkLocator | null,
      };
    }
    const link: Link = { rel, target, attrs: (input.attrs ?? null) as Link['attrs'] };
    const grammar = linkGrammarViolation(link, i);
    if (grammar) throw new LinksBuildError(grammar);
    const attrs = linkAttrsViolation(link, i);
    if (attrs) throw new LinksBuildError(attrs);
    built.push({ link, held });
  }
  built.sort((a, b) => compareLinks(a.link, b.link));
  for (let i = 1; i < built.length; i++) {
    if (compareLinks(built[i - 1].link, built[i].link) === 0) throw new LinksBuildError(violation('not_a_set', 'links', { link: i }));
  }
  if (!options.linkRecord && !built.some((b) => b.link.rel === 'root')) {
    const first = built.find((b) => isLineageRelation(b.link.rel) && b.held !== null);
    if (first) {
      const held = first.held!;
      const own = Array.isArray(held.payload.links) ? (held.payload.links as unknown[]) : [];
      const ownRoot = own.find((l): l is Link => isPlainObject(l) && l.rel === 'root' && isPlainObject(l.target));
      let rootTarget: LinkTarget | null = null;
      if (ownRoot) rootTarget = { ...ownRoot.target, locator: ownRoot.target.locator === null ? null : { ...ownRoot.target.locator } };
      else if (!own.some((l) => isPlainObject(l) && isLineageRelation(l.rel))) rootTarget = { ...first.link.target };
      if (rootTarget !== null) {
        built.push({ link: { rel: 'root', target: rootTarget, attrs: null }, held: null });
        built.sort((a, b) => compareLinks(a.link, b.link));
      }
    }
  }
  const links = built.map((b) => b.link);
  const grammar = linksGrammarViolation(links);
  if (grammar) throw new LinksBuildError(grammar);
  if (options.context) {
    const ctx = options.context;
    const linkRecord = options.linkRecord === true || isLinkRecord(ctx);
    const subject = linkRecord ? built.find((b) => b.link.rel === 'subject')?.held ?? null : null;
    const resolver: LinkTargetResolver | undefined = options.openCommitment ? { openCommitment: options.openCommitment } : undefined;
    for (let i = 0; i < built.length; i++) {
      const { link, held } = built[i];
      let r: LinkTargetRuleResult;
      if (linkRecord) {
        if (link.rel === 'subject' || subject === null) continue;
        r = checkLinkRecordLink(link, subject, held, { links, resolver });
      } else {
        if (held === null) continue;
        r = checkLinkTarget(link, ctx as Record<string, unknown>, held, { links, resolver });
      }
      if (r.result === 'violated') {
        throw new LinksBuildError(violation('link_rule_violated', `links[${links.indexOf(link)}]`, { link: links.indexOf(link), rule: r.rule }));
      }
    }
  }
  return links;
}

// ── Reader ────────────────────────────────────────────────────────────────

function row(index: number, rel: string, outcome: LinkRelationCheck['outcome'], reason?: string, extra: Partial<LinkRelationCheck> = {}): LinkRelationCheck {
  return {
    index,
    rel,
    outcome,
    valid: outcome === 'checked-correct' ? true : outcome === 'checked-wrong' ? false : null,
    ...(reason !== undefined && { reason }),
    ...extra,
  };
}

const EDGE: RecordRuleRow = { outcome: 'abstain', reason: 'unsupported_link_edge' };

/**
 * The reader's `links` row and the rows under it (Record §8.8; Verification §4.11) for a record
 * whose digest holds. `resolver` is what a store-level verifier holds; a
 * bundle verifier passes none and holds no target. Never throws.
 *
 * The `links` row, the first that applies:
 *   `null` and no list-level rule requires a link → not-checked, absent
 *   `null` and a list-level rule requires one     → checked-wrong, link_rule_violated (rule)
 *   the grammar broken                            → checked-wrong, malformed_links (failedLink, rule)
 *   a list-level rule broken                      → checked-wrong, link_rule_violated (rule)
 *   otherwise                                     → checked-correct (count, relationNames, extensions)
 *
 * Each `links[<i>]` row, the first that applies:
 *   the `links` row not correct                   → not-checked, blocked_by:links
 *   a `mandate` link and a malformed expectation  → not-checked, blocked_by:signoff.expectation
 *   a relation this version does not know         → abstain, unsupported_link_relation
 *   the attribute profile broken                  → checked-wrong, link_attrs_invalid
 *   a record-local rule broken                    → checked-wrong, link_rule_violated (rule)
 *   the target held and a member disagrees        → checked-wrong, link_target_mismatch (member)
 *   the target held and its rule broken           → checked-wrong, link_rule_violated (rule)
 *   a rule not implemented, or `root` whose only possible lineage is an
 *   unregistered unprefixed relation              → abstain, unsupported_link_rule
 *   a rule left undetermined                      → not-checked, link_rule_undetermined (rule)
 *   a target rule needed and the target not held  → not-checked, not_in_bundle:link_target (missing: target)
 *   otherwise                                     → checked-correct (targetHeld, rootInconsistent)
 *
 * In a link record the rules of each link other than `subject` take the
 * subject in the child's place, so a rule that reads the child needs the
 * subject held: without it the row is not-checked, not_in_bundle:link_target
 * with `missing: 'subject'`. Every `links[<i>].edge` row abstains,
 * `unsupported_link_edge`.
 */
export function checkLinks(payload: unknown, options: { resolver?: LinkTargetResolver } = {}): LinksCheck {
  const p = isPlainObject(payload) ? payload : {};
  const resolver = options.resolver;
  const value = p.links;
  // A malformed expectation reads as no form: the mandate rule is then not
  // applied (the expectation row already fails), and each `mandate` link's
  // row is blocked by it.
  const expectationMalformed = signoffExpectationForm(p.signoffExpectation) === null;
  const ctx: LinksContext = p;
  if (value === null || value === undefined) {
    const list = linksListRuleViolation(null, ctx);
    if (list) return { outcome: 'checked-wrong', valid: false, reason: 'link_rule_violated', rule: list.rule, relations: [], edges: [] };
    return { outcome: 'not-checked', valid: null, reason: 'absent', relations: [], edges: [] };
  }
  const grammar = linksGrammarViolation(value);
  const links = Array.isArray(value) ? (value as Link[]) : [];
  const edges = links.map(() => ({ ...EDGE }));
  const blocked = (reason: string) =>
    links.map((l, i) => row(i, isPlainObject(l) && typeof l.rel === 'string' ? l.rel : '', 'not-checked', reason));
  if (grammar) {
    return {
      outcome: 'checked-wrong',
      valid: false,
      reason: 'malformed_links',
      rule: grammar.code,
      ...(grammar.link !== undefined && { failedLink: grammar.link }),
      relations: blocked('blocked_by:links'),
      edges,
    };
  }
  const list = linksListRuleViolation(links, ctx);
  if (list) {
    return { outcome: 'checked-wrong', valid: false, reason: 'link_rule_violated', rule: list.rule, relations: blocked('blocked_by:links'), edges };
  }

  const linkRecord = isLinkRecord(p);
  const subjectLink = linkRecord ? links.find((l) => l.rel === 'subject') ?? null : null;
  const byDigest = (digest: string): HeldLinkTarget | null => (resolver?.byDigest ? resolver.byDigest(digest) : null);
  const subject = subjectLink !== null ? byDigest(subjectLink.target.digest) : null;
  const relations = links.map((link, i): LinkRelationCheck => {
    if (link.rel === 'mandate' && expectationMalformed) return row(i, link.rel, 'not-checked', 'blocked_by:signoff.expectation');
    if (!isRegisteredRelation(link.rel)) return row(i, link.rel, 'abstain', 'unsupported_link_relation');
    if (linkAttrsViolation(link, i) !== null) return row(i, link.rel, 'checked-wrong', 'link_attrs_invalid');
    const local = linkRecordLocalRule(links, i, ctx);
    if (local.result === 'violated') return row(i, link.rel, 'checked-wrong', 'link_rule_violated', { rule: local.rule });

    const held = byDigest(link.target.digest);
    if (held !== null) {
      const member = linkTargetMemberMismatch(link.target, held);
      if (member !== null) return row(i, link.rel, 'checked-wrong', 'link_target_mismatch', { member, targetHeld: true });
    } else if (
      link.target.locator !== null &&
      resolver?.isOwnOrigin?.(link.target.locator.origin) === true &&
      resolver.digestAt !== undefined &&
      resolver.digestAt(link.target.locator.origin, link.target.locator.seq) !== link.target.digest
    ) {
      return row(i, link.rel, 'checked-wrong', 'link_target_mismatch', { member: 'locator', targetHeld: false });
    }

    // In a link record the subject takes the child's place: a record-local
    // rule of the relation binds the subject, and every target rule reads it.
    const subjectInPlace = linkRecord && link.rel !== 'subject';
    const rule = subjectInPlace
      ? checkLinkRecordLink(link, subject, held, { links, resolver })
      : checkLinkTarget(link, p, held, { links, resolver });
    if (rule.result === 'violated') return row(i, link.rel, 'checked-wrong', 'link_rule_violated', { rule: rule.rule, targetHeld: held !== null });
    if (rule.result === 'unsupported' || local.result === 'abstain') {
      return row(i, link.rel, 'abstain', 'unsupported_link_rule', { targetHeld: held !== null });
    }
    if (rule.result === 'undetermined') {
      return row(i, link.rel, 'not-checked', 'link_rule_undetermined', { rule: rule.rule, targetHeld: held !== null });
    }
    if (rule.result === 'not-held') {
      return row(i, link.rel, 'not-checked', 'not_in_bundle:link_target', {
        targetHeld: held !== null,
        missing: subjectInPlace && subject === null ? 'subject' : 'target',
      });
    }
    return row(i, link.rel, 'checked-correct', undefined, {
      targetHeld: held !== null,
      ...(rule.rootInconsistent === true && { rootInconsistent: true }),
    });
  });
  const names: string[] = [];
  for (const l of links) if (!names.includes(l.rel)) names.push(l.rel);
  return {
    outcome: 'checked-correct',
    valid: true,
    count: links.length,
    relationNames: names,
    extensions: links.filter((l) => isExtensionRelation(l.rel)).length,
    relations,
    edges,
  };
}

/**
 * The link targets a step's inputs may name (Record §7.5): `sha256:` and the target
 * digest of each link, when `links` meets the general grammar; none
 * otherwise, so every verifier reads the same inputs.
 */
export function linkTargetInputs(links: unknown): Set<string> {
  if (links === null || links === undefined || linksGrammarViolation(links) !== null) return new Set();
  return new Set((links as Link[]).map((l) => `sha256:${l.target.digest}`));
}
