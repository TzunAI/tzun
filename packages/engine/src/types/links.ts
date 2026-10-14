/**
 * The links member of a v1.0 record (Record §8): a hashed, generic,
 * extensible list of relations to other records. Pure type definitions; the
 * rules are in `packages/engine/src/links.ts`.
 */

/**
 * Where a target is on record: its chain's evidence-log origin
 * (tzun-anchor/1 §4.3) and its sequence number (leaf index `seq - 1`).
 *
 * @tzun-canonical-sort utf16
 */
export interface LinkLocator {
  origin: string;
  /** A safe integer of at least 1. */
  seq: number;
}

/**
 * The record a link names. Every member is present, `null` where it does not
 * apply.
 *
 * @tzun-canonical-sort utf16
 */
export interface LinkTarget {
  /** The target record's canonical digest, 64 lowercase hex (or, for an `x-` relation, any SHA-256 digest). */
  digest: string;
  /** 1 to 128 characters of 0x21–0x7E, or `null`. */
  evidenceId: string | null;
  locator: LinkLocator | null;
}

/**
 * One link: this record's relation to the record its target names.
 *
 * @tzun-canonical-sort utf16
 */
export interface Link {
  /** A registered relation name, or an extension `x-<org>.<name>`. */
  rel: string;
  target: LinkTarget;
  /**
   * `null`, or 1 to 16 attributes the relation's profile admits. A name is
   * `[a-z][A-Za-z0-9]{0,31}` or an extension name; a value is a string of 0 to
   * 256 characters of 0x20–0x7E, a safe integer of at least 0, or `true` or
   * `false`. An attribute that does not apply is left out, never `null`.
   */
  attrs: Record<string, string | number | boolean> | null;
}

/**
 * A link target as a capture names it. Without `external`, the target is a
 * record of the same store: the SDK resolves it by `evidenceId` when given,
 * otherwise by `digest`, fills the members it omits, and refuses a member that
 * disagrees with the held record. With `external: true`, `digest` is required
 * and `evidenceId` and `locator` are written as given (`null` when omitted).
 * An input `locator: null` keeps the locator `null`; an omitted locator is
 * filled.
 */
export interface LinkTargetInput {
  digest?: string;
  evidenceId?: string | null;
  locator?: LinkLocator | null;
  external?: boolean;
}

/** A link as a capture names it. */
export interface LinkInput {
  rel: string;
  target: LinkTargetInput;
  attrs?: Record<string, string | number | boolean> | null;
}

/** What a relation of the registry is. */
export interface LinkRelationProfile {
  /** The relation's name. */
  name: string;
  /** Whether it makes this record a child of the target: `root` requires one beside it. */
  lineage: boolean;
  /** The attributes it requires; its profile is closed, so no other is admitted. */
  requiredAttrs: readonly string[];
  /** The attributes it admits beside the required ones. */
  optionalAttrs: readonly string[];
  /**
   * Who writes it: `caller` (any capture), `reserved` (only the SDK's mandate
   * and link APIs), or `none` (no 0.8.0 writer: `closes` and `fanoutOf`).
   */
  writer: 'caller' | 'reserved' | 'none';
}

/** Why links are refused at capture, first failure first (`linksViolation`, `buildLinks`). */
export type LinksViolationCode =
  | 'not_an_array'
  | 'empty_links'
  | 'too_many_links'
  | 'not_a_set'
  | 'link_unknown_members'
  | 'link_missing_members'
  | 'invalid_relation'
  | 'unknown_relation'
  | 'relation_reserved'
  | 'relation_not_writable'
  | 'invalid_target'
  | 'invalid_target_digest'
  | 'invalid_target_evidence_id'
  | 'invalid_locator'
  | 'invalid_attrs'
  | 'too_many_attrs'
  | 'attrs_not_allowed'
  | 'missing_attr'
  | 'link_rule_violated'
  | 'required_link_missing'
  | 'link_target_not_found'
  | 'link_target_mismatch'
  | 'root_without_lineage';

/** A links refusal. `link` is the index of the link concerned, when one is; `rule` names a broken rule. */
export interface LinksViolation {
  code: LinksViolationCode;
  field: string;
  message: string;
  link?: number;
  rule?: string;
}

/**
 * A record a verifier or a writer holds as a link's target: its payload as
 * stored, its stored canonical digest, and the evidence-log origin of its
 * chain (`null` when the holder does not know it).
 */
export interface HeldLinkTarget {
  payload: Record<string, unknown>;
  digest: string;
  origin: string | null;
}

/**
 * What a store-level verifier holds beside the record (Record §8.8),
 * read synchronously: the caller resolves what it needs first. Every member
 * is optional; a verifier given none holds no target, as a bundle verifier.
 */
export interface LinkTargetResolver {
  /** The held record whose stored digest is `digest`, or `null`. */
  byDigest?(digest: string): HeldLinkTarget | null;
  /** Whether `origin` is an evidence-log origin of this store. */
  isOwnOrigin?(origin: string): boolean;
  /** The stored digest of the record at `(origin, seq)` of this store, or `null` when that position holds none. */
  digestAt?(origin: string, seq: number): string | null;
  /** The identifier a `cmt:` decider commits to, from the store's openings, or `null` when it is not opened. */
  openCommitment?(id: string): string | null;
}
