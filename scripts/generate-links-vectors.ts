/**
 * Generate vectors/links-vectors.json: the answers every implementation of
 * the links member (Record §8) must give.
 *
 * Every case but `capture` is a whole payload, read twice:
 *
 *   - `writer`  why a 0.8.0 writer refuses its `links` (`linksViolation`
 *               against the payload: `{ code, field, rule? }`, or `null`);
 *   - `reader`  the reader's `links` row and the `links[<i>]` and
 *               `links[<i>].edge` rows under it (`checkLinks`, Verification §4.11), given
 *               what the verifier holds. A case with no `resolver` is read as
 *               a bundle verifier reads it, holding no target. A `resolver`
 *               lists what a store-level verifier holds:
 *                 held        records, each `{ payload, digest, origin }`, found
 *                             by their stored digest;
 *                 ownOrigins  the evidence-log origins of the verifier's own
 *                             store; with them, `positions` lists what each
 *                             position of the store holds
 *                             (`{ origin, seq, digest }`), and a position not
 *                             listed holds nothing;
 *                 openings    `cmt:` identifiers the store can open, and the
 *                             identifier each commits to.
 *
 * The groups:
 *
 *   - shapes     the grammar of Record §8.2: order, repeats, `[]`, 257 links, every
 *                registered relation, an unregistered unprefixed relation
 *                (a writer refuses, a reader abstains), `x-` names, the
 *                attribute grammar, target and locator forms;
 *   - profiles   each relation's closed attribute profile and record-local
 *                rule;
 *   - listLevel  the list-level rules (Record §8.3), including a required link that
 *                is missing and the mandate rule under a malformed
 *                expectation;
 *   - targets    each target rule with the target held, a held target whose
 *                members disagree (read by digest first), a same-store locator
 *                whose position holds another record or nothing, `reviews`
 *                with an unopened commitment, and link records read with their
 *                subject in the child's place;
 *   - capture    `buildLinks`: capture input, the record each target resolved
 *                to in the store, and the links built, or the refusal.
 *
 *   pnpm exec tsx scripts/generate-links-vectors.ts > vectors/links-vectors.json
 *
 * Every expected answer is written here from the specification, and the script
 * stops if the engine disagrees. The TS replay is tests/cross-sdk/ts/links-vectors.test.ts;
 * the Python recomputation is tests/cross-sdk/test_links_vectors.py.
 */
import {
  LINK_RELATION_NAMES,
  buildLinks,
  checkLinks,
  linksViolation,
  type HeldLinkTarget,
  type LinkInput,
  type LinkTargetResolver,
} from '@tzun/engine';
import {
  ACCT,
  AGENT,
  CLAIMS_ORIGIN,
  CMT,
  LENDER_ORIGIN,
  W4_ASSERTION_DIGEST,
  W4_MANDATE_DIGEST,
  W4_STATEMENT_DIGEST,
  agentDecider,
  checker,
  digestOf,
  emit,
  human,
  payload,
  recordDigest,
} from './generate-vectors-shared';

const { agree } = checker('generate-links-vectors');

type Locator = { origin: string; seq: number } | null;
type Link = { rel: string; target: { digest: string; evidenceId: string | null; locator: Locator }; attrs: Record<string, unknown> | null };
const L = (rel: string, digest: string, o: { evidenceId?: string | null; locator?: Locator; attrs?: Record<string, unknown> | null } = {}): Link => ({
  rel,
  target: { digest, evidenceId: o.evidenceId ?? null, locator: o.locator ?? null },
  attrs: o.attrs ?? null,
});
const D1 = digestOf('target 1');
const D2 = digestOf('target 2');
const [DA, DB] = [D1, D2].sort();
const EDGE = { outcome: 'abstain', reason: 'unsupported_link_edge' };

interface ResolverSpec {
  held?: HeldLinkTarget[];
  ownOrigins?: string[];
  positions?: Array<{ origin: string; seq: number; digest: string }>;
  openings?: Record<string, string>;
}
function resolverOf(spec: ResolverSpec | undefined): LinkTargetResolver | undefined {
  if (spec === undefined) return undefined;
  const r: LinkTargetResolver = {
    byDigest: (d) => spec.held?.find((h) => h.digest === d) ?? null,
    openCommitment: (id) => spec.openings?.[id] ?? null,
  };
  if (spec.ownOrigins !== undefined) {
    r.isOwnOrigin = (o) => spec.ownOrigins!.includes(o);
    r.digestAt = (o, seq) => spec.positions?.find((p) => p.origin === o && p.seq === seq)?.digest ?? null;
  }
  return r;
}

type Row = Record<string, unknown>;
const rowOf = (index: number, rel: string, outcome: string, extra: Row = {}): Row => ({
  index,
  rel,
  outcome,
  valid: outcome === 'checked-correct' ? true : outcome === 'checked-wrong' ? false : null,
  ...extra,
});
const ok = (i: number, rel: string, targetHeld = false, extra: Row = {}) => rowOf(i, rel, 'checked-correct', { targetHeld, ...extra });
const notHeld = (i: number, rel: string, missing = 'target') => rowOf(i, rel, 'not-checked', { reason: 'not_in_bundle:link_target', targetHeld: false, missing });
const unknownRel = (i: number, rel: string) => rowOf(i, rel, 'abstain', { reason: 'unsupported_link_relation' });
const unsupportedRule = (i: number, rel: string, targetHeld = false) => rowOf(i, rel, 'abstain', { reason: 'unsupported_link_rule', targetHeld });
const attrsInvalid = (i: number, rel: string) => rowOf(i, rel, 'checked-wrong', { reason: 'link_attrs_invalid' });
const violated = (i: number, rel: string, rule: string, targetHeld?: boolean) =>
  rowOf(i, rel, 'checked-wrong', { reason: 'link_rule_violated', rule, ...(targetHeld !== undefined && { targetHeld }) });
const mismatch = (i: number, rel: string, member: string, targetHeld = true) =>
  rowOf(i, rel, 'checked-wrong', { reason: 'link_target_mismatch', member, targetHeld });
const blockedRow = (i: number, rel: string, reason = 'blocked_by:links') => rowOf(i, rel, 'not-checked', { reason });

const correctList = (links: Link[], relations: Row[]) => {
  const names: string[] = [];
  for (const l of links) if (!names.includes(l.rel)) names.push(l.rel);
  return {
    outcome: 'checked-correct',
    valid: true,
    count: links.length,
    relationNames: names,
    extensions: links.filter((l) => l.rel.startsWith('x-')).length,
    relations,
    edges: links.map(() => EDGE),
  };
};
const malformed = (links: unknown[], rule: string, failedLink?: number) => ({
  outcome: 'checked-wrong',
  valid: false,
  reason: 'malformed_links',
  rule,
  ...(failedLink !== undefined && { failedLink }),
  relations: links.map((l, i) => blockedRow(i, typeof (l as Link)?.rel === 'string' ? (l as Link).rel : '')),
  edges: links.map(() => EDGE),
});
const listRule = (links: unknown[], rule: string) => ({
  outcome: 'checked-wrong',
  valid: false,
  reason: 'link_rule_violated',
  rule,
  relations: links.map((l, i) => blockedRow(i, (l as Link).rel)),
  edges: links.map(() => EDGE),
});
const W = (code: string, field: string, rule?: string) => ({ code, field, ...(rule !== undefined && { rule }) });

interface Case {
  case: string;
  payload: Record<string, unknown>;
  resolver?: ResolverSpec;
  writer: { code: string; field: string; rule?: string } | null;
  reader: unknown;
}
const groups: Record<'shapes' | 'profiles' | 'listLevel' | 'targets', Case[]> = { shapes: [], profiles: [], listLevel: [], targets: [] };
function add(group: keyof typeof groups, c: string, p: Record<string, unknown>, writer: Case['writer'], reader: unknown, resolver?: ResolverSpec) {
  groups[group].push({ case: c, payload: p, ...(resolver !== undefined && { resolver }), writer, reader });
}
const P = (links: unknown, extra: Record<string, unknown> = {}) => payload({ links, ...extra });

// ── shapes ───────────────────────────────────────────────────────────────

add('shapes', 'null: no link', P(null), null, { outcome: 'not-checked', valid: null, reason: 'absent', relations: [], edges: [] });
{
  const links = [L('derivedFrom', D1)];
  add('shapes', 'one derivedFrom link', P(links), null, correctList(links, [ok(0, 'derivedFrom')]));
}
{
  const links = [L('appeals', D2), L('derivedFrom', D1)];
  add('shapes', 'two relations, sorted by rel', P(links), null, correctList(links, [ok(0, 'appeals'), ok(1, 'derivedFrom')]));
}
{
  const links = [L('derivedFrom', DA), L('derivedFrom', DB)];
  add('shapes', 'one relation, sorted by target digest', P(links), null, correctList(links, [ok(0, 'derivedFrom'), ok(1, 'derivedFrom')]));
}
{
  const links = [L('derivedFrom', D1), L('root', D1)];
  add('shapes', 'one digest under two relations (derivedFrom and root)', P(links), null, correctList(links, [ok(0, 'derivedFrom'), ok(1, 'root')]));
}
{
  const links = [L('derivedFrom', D1), L('derivedFromX', D1)];
  add('shapes', 'a shorter rel sorts first (derivedFrom before derivedFromX, an unregistered name)', P(links), W('unknown_relation', 'links[1].rel'), correctList(links, [ok(0, 'derivedFrom'), unknownRel(1, 'derivedFromX')]));
}
{
  const links = [L('root', D1), L('derivedFrom', D1)];
  add('shapes', 'unsorted by rel', P(links), W('not_a_set', 'links'), malformed(links, 'not_a_set', 1));
}
{
  const links = [L('derivedFrom', DB), L('derivedFrom', DA)];
  add('shapes', 'unsorted by target digest', P(links), W('not_a_set', 'links'), malformed(links, 'not_a_set', 1));
}
{
  const links = [L('derivedFrom', D1), L('derivedFrom', D1)];
  add('shapes', 'a repeated (rel, target.digest) pair', P(links), W('not_a_set', 'links'), malformed(links, 'not_a_set', 1));
}
{
  const links = [L('derivedFrom', D1, { evidenceId: 'a' }), L('derivedFrom', D1, { evidenceId: 'b' })];
  add('shapes', 'a repeated pair whose evidence ids differ', P(links), W('not_a_set', 'links'), malformed(links, 'not_a_set', 1));
}
add('shapes', '[] (no link has one spelling: null)', P([]), W('empty_links', 'links'), malformed([], 'empty_links'));
add('shapes', 'an object, not an array', P({ derivedFrom: D1 }), W('not_an_array', 'links'), malformed([], 'not_an_array'));
{
  const digests = Array.from({ length: 257 }, (_, i) => digestOf(`many ${i}`)).sort();
  const links257 = digests.map((d) => L('derivedFrom', d));
  add('shapes', '257 links', P(links257), W('too_many_links', 'links'), malformed(links257, 'too_many_links'));
  const links256 = links257.slice(0, 256);
  add('shapes', '256 links', P(links256), null, correctList(links256, links256.map((_, i) => ok(i, 'derivedFrom'))));
}
{
  const links = [{ ...L('derivedFrom', D1), note: 'x' }];
  add('shapes', 'a member outside rel, target and attrs', P(links), W('link_unknown_members', 'links[0]'), malformed(links, 'link_unknown_members', 0));
}
{
  const links = [{ rel: 'derivedFrom', target: L('derivedFrom', D1).target }];
  add('shapes', 'attrs missing (a missing key is not null)', P(links), W('link_missing_members', 'links[0]'), malformed(links, 'link_missing_members', 0));
}
add('shapes', 'a link that is a string', P(['derivedFrom']), W('link_unknown_members', 'links[0]'), malformed(['derivedFrom'], 'link_unknown_members', 0));
for (const [label, rel] of [
  ['a rel with a dash', 'derived-from'],
  ['a rel beginning in uppercase', 'DerivedFrom'],
  ['an empty rel', ''],
  ['a rel of 33 characters', 'a' + 'b'.repeat(32)],
  ['an x- name whose name begins in uppercase', 'x-acme.ContractRenewal'],
  ['an x- name with an empty org', 'x-.renewal'],
  ['an x- name whose org ends with a dash', 'x-acme-.renewal'],
  ['an x- name with no name', 'x-acme'],
  ['an x- name whose org is uppercase', 'x-Acme.renewal'],
  ['an x- name of 68 characters', 'x-' + 'o'.repeat(33) + '.' + 'n'.repeat(32)],
  ['a rel with a trailing newline', 'derivedFrom\n'],
] as const) {
  const links = [L(rel, D1)];
  add('shapes', label, P(links), W('invalid_relation', 'links[0].rel'), malformed(links, 'invalid_relation', 0));
}
{
  const links = [L('inspiredBy', D1)];
  add('shapes', 'an unregistered unprefixed relation: a writer refuses it, a reader abstains (a later registry may define it)', P(links), W('unknown_relation', 'links[0].rel'), correctList(links, [unknownRel(0, 'inspiredBy')]));
}
{
  const links = [L('x-acme.contractRenewal', D1, { attrs: { final: true, region: 'eu west', renewals: 3 } })];
  add('shapes', 'an x- relation with attributes (string with a space, integer, boolean)', P(links), null, correctList(links, [unknownRel(0, 'x-acme.contractRenewal')]));
}
{
  const rel = 'x-' + 'o'.repeat(32) + '.' + 'n'.repeat(32);
  const links = [L(rel, D1)];
  add('shapes', 'an x- name of 67 characters', P(links), null, correctList(links, [unknownRel(0, rel)]));
}
{
  const links = [L('x-a.b', D1, { attrs: { 'x-acme.tier': 'gold' } })];
  add('shapes', 'an extension attribute name on an x- relation', P(links), null, correctList(links, [unknownRel(0, 'x-a.b')]));
}
for (const [label, attrs] of [
  ['attrs {} (write null)', {}],
  ['an attribute whose value is null (leave it out)', { region: null }],
  ['an attribute whose value is an object', { region: { code: 'eu' } }],
  ['an attribute whose value is an array', { regions: ['eu'] }],
  ['a negative integer attribute', { count: -1 }],
  ['a fractional attribute', { ratio: 1.5 }],
  ['an integer attribute past 2^53 - 1', { count: 9007199254740992 }],
  ['a string attribute of 257 characters', { note: 'n'.repeat(257) }],
  ['a string attribute outside printable ASCII', { note: 'café' }],
  ['a string attribute with a tab', { note: 'a\tb' }],
  ['an attribute name beginning in uppercase', { Region: 'eu' }],
  ['an attribute name with a dash', { 'the-region': 'eu' }],
] as const) {
  const links = [L('x-acme.renewal', D1, { attrs: attrs as Record<string, unknown> })];
  add('shapes', label, P(links), W('invalid_attrs', 'links[0].attrs'), malformed(links, 'invalid_attrs', 0));
}
{
  const attrs = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`a${i}`, i]));
  const links = [L('x-acme.renewal', D1, { attrs })];
  add('shapes', '17 attributes', P(links), W('too_many_attrs', 'links[0].attrs'), malformed(links, 'too_many_attrs', 0));
  const attrs16 = Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`a${i}`, i]));
  const links16 = [L('x-acme.renewal', D1, { attrs: attrs16 })];
  add('shapes', '16 attributes', P(links16), null, correctList(links16, [unknownRel(0, 'x-acme.renewal')]));
}
for (const [label, target, code, field] of [
  ['an uppercase target digest', { digest: D1.toUpperCase(), evidenceId: null, locator: null }, 'invalid_target_digest', 'links[0].target.digest'],
  ['a prefixed target digest', { digest: `sha256:${D1}`, evidenceId: null, locator: null }, 'invalid_target_digest', 'links[0].target.digest'],
  ['a target without locator', { digest: D1, evidenceId: null }, 'invalid_target', 'links[0].target'],
  ['a target carrying external (an input member, never stored)', { digest: D1, evidenceId: null, locator: null, external: true }, 'invalid_target', 'links[0].target'],
  ['a target evidence id with a space', { digest: D1, evidenceId: 'case 7', locator: null }, 'invalid_target_evidence_id', 'links[0].target.evidenceId'],
  ['an empty target evidence id', { digest: D1, evidenceId: '', locator: null }, 'invalid_target_evidence_id', 'links[0].target.evidenceId'],
  ['a target evidence id of 129 characters', { digest: D1, evidenceId: 'e'.repeat(129), locator: null }, 'invalid_target_evidence_id', 'links[0].target.evidenceId'],
  ['a locator at seq 0', { digest: D1, evidenceId: null, locator: { origin: LENDER_ORIGIN, seq: 0 } }, 'invalid_locator', 'links[0].target.locator'],
  ['a locator at a fractional seq', { digest: D1, evidenceId: null, locator: { origin: LENDER_ORIGIN, seq: 1.5 } }, 'invalid_locator', 'links[0].target.locator'],
  ['a locator whose seq is a string', { digest: D1, evidenceId: null, locator: { origin: LENDER_ORIGIN, seq: '3' } }, 'invalid_locator', 'links[0].target.locator'],
  ['a locator naming an anchor log', { digest: D1, evidenceId: null, locator: { origin: 'test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/anchors', seq: 3 } }, 'invalid_locator', 'links[0].target.locator'],
  ['a locator naming a store custody log (four segments)', { digest: D1, evidenceId: null, locator: { origin: 'test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/custody/6c656e64696e67', seq: 3 } }, 'invalid_locator', 'links[0].target.locator'],
  ['a locator whose namespace is uppercase', { digest: D1, evidenceId: null, locator: { origin: LENDER_ORIGIN.replace('test.lender', 'Test.lender'), seq: 3 } }, 'invalid_locator', 'links[0].target.locator'],
  ['a locator whose chain segment is not hex of UTF-8', { digest: D1, evidenceId: null, locator: { origin: LENDER_ORIGIN.replace('6c656e64696e67', 'ff'), seq: 3 } }, 'invalid_locator', 'links[0].target.locator'],
  ['a locator with a member outside origin and seq', { digest: D1, evidenceId: null, locator: { origin: LENDER_ORIGIN, seq: 3, leafIndex: 2 } }, 'invalid_locator', 'links[0].target.locator'],
] as const) {
  const links = [{ rel: 'derivedFrom', target, attrs: null }];
  add('shapes', label, P(links), W(code, field), malformed(links, code, 0));
}
{
  const links = [L('derivedFrom', D1, { evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000006', locator: { origin: LENDER_ORIGIN, seq: 6 } })];
  add('shapes', 'a full target: an evidence id and a store locator', P(links), null, correctList(links, [ok(0, 'derivedFrom')]));
}
{
  const links = [L('derivedFrom', D1, { evidenceId: 'C-1182', locator: { origin: 'log.tzun.ai/dep-7f3a/log-2', seq: 9007199254740991 } })];
  add('shapes', 'a hosted locator at seq 2^53 - 1, an evidence id of another system', P(links), null, correctList(links, [ok(0, 'derivedFrom')]));
}

// Every registered relation, alone where its rules allow, in a record its list-level rules admit.
const REGISTERED = [...LINK_RELATION_NAMES].sort();
agree('the registry', REGISTERED, ['appeals', 'closes', 'delegatedBy', 'derivedFrom', 'fanoutOf', 'implements', 'mandate', 'ratifies', 'reviews', 'revokes', 'root', 'subject', 'supersedes']);

// ── profiles ─────────────────────────────────────────────────────────────

{
  const links = [L('derivedFrom', D1, { attrs: { note: 'x' } })];
  add('profiles', 'an attribute on derivedFrom, whose profile admits none', P(links), W('attrs_not_allowed', 'links[0].attrs'), correctList(links, [attrsInvalid(0, 'derivedFrom')]));
}
{
  const links = [L('derivedFrom', D1, { attrs: { 'x-acme.tier': 'gold' } })];
  add('profiles', 'an x- attribute on a registered relation (profiles are closed)', P(links), W('attrs_not_allowed', 'links[0].attrs'), correctList(links, [attrsInvalid(0, 'derivedFrom')]));
}
const closesAttrs = { size: 12, statement: digestOf('fan-out statement'), treeRoot: digestOf('fan-out tree') };
{
  const links = [L('closes', D1, { attrs: closesAttrs })];
  add('profiles', 'closes with its profile: no writer in this version; the reader abstains on its rule', P(links), W('relation_not_writable', 'links[0].rel'), correctList(links, [unsupportedRule(0, 'closes')]));
}
{
  const links = [L('closes', D1, { attrs: { size: 12, statement: closesAttrs.statement } })];
  add('profiles', 'closes without treeRoot', P(links), W('relation_not_writable', 'links[0].rel'), correctList(links, [attrsInvalid(0, 'closes')]));
}
{
  const links = [L('closes', D1, { attrs: { ...closesAttrs, treeRoot: `sha256:${closesAttrs.treeRoot}` } })];
  add('profiles', 'closes whose treeRoot is prefixed', P(links), W('relation_not_writable', 'links[0].rel'), correctList(links, [attrsInvalid(0, 'closes')]));
}
{
  const links = [L('fanoutOf', D1, { attrs: { slot: 1, statement: closesAttrs.statement } })];
  add('profiles', 'fanoutOf with its profile', P(links), W('relation_not_writable', 'links[0].rel'), correctList(links, [unsupportedRule(0, 'fanoutOf')]));
}
{
  const links = [L('fanoutOf', D1, { attrs: { slot: 0, statement: closesAttrs.statement } })];
  add('profiles', 'fanoutOf at slot 0', P(links), W('relation_not_writable', 'links[0].rel'), correctList(links, [attrsInvalid(0, 'fanoutOf')]));
}
{
  const links = [L('fanoutOf', D1, { attrs: { slot: 2, statement: closesAttrs.statement, size: 4 } })];
  add('profiles', 'fanoutOf carrying size, which only closes admits', P(links), W('relation_not_writable', 'links[0].rel'), correctList(links, [attrsInvalid(0, 'fanoutOf')]));
}
{
  const links = [L('root', D1)];
  add('profiles', 'root with no lineage link beside it', P(links), W('root_without_lineage', 'links[0]', 'root_without_lineage'), correctList(links, [violated(0, 'root', 'root_without_lineage')]));
}
{
  const links = [L('inspiredBy', D2), L('root', D1)];
  add('profiles', 'root beside only an unregistered relation, which a later registry may make a lineage relation: the reader abstains', P(links), W('unknown_relation', 'links[0].rel'), correctList(links, [unknownRel(0, 'inspiredBy'), unsupportedRule(1, 'root')]));
}
{
  const links = [L('root', D1), L('x-acme.renewal', D2)];
  add('profiles', 'root beside only an x- relation (never registered, so never lineage)', P(links), W('root_without_lineage', 'links[0]', 'root_without_lineage'), correctList(links, [violated(0, 'root', 'root_without_lineage'), unknownRel(1, 'x-acme.renewal')]));
}
{
  const links = [L('appeals', D2), L('root', D1)];
  add('profiles', 'root beside appeals (a lineage relation)', P(links), null, correctList(links, [ok(0, 'appeals'), ok(1, 'root')]));
}
{
  const links = [L('ratifies', D1)];
  add('profiles', 'ratifies by an agent: the decider must be a human', P(links, { decider: agentDecider() }), W('link_rule_violated', 'links[0]', 'ratifies_decider_human'), correctList(links, [violated(0, 'ratifies', 'ratifies_decider_human')]));
  add('profiles', 'ratifies by a human, the target not held', P(links), null, correctList(links, [notHeld(0, 'ratifies')]));
}
{
  const links = [L('reviews', D1)];
  add('profiles', 'reviews, the target not held', P(links), null, correctList(links, [notHeld(0, 'reviews')]));
}
{
  const links = [L('supersedes', D1)];
  add('profiles', 'supersedes, the target not held', P(links), null, correctList(links, [notHeld(0, 'supersedes')]));
}
{
  const links = [L('delegatedBy', D1)];
  add('profiles', 'delegatedBy: its target rule is not implemented in this version', P(links), null, correctList(links, [unsupportedRule(0, 'delegatedBy')]));
}
{
  const links = [L('implements', D1)];
  add('profiles', 'implements: no rule', P(links), null, correctList(links, [ok(0, 'implements')]));
}
{
  const links = [L('derivedFrom', D1), L('root', DA), L('root', DB)];
  add('profiles', 'two root links', P(links), W('link_rule_violated', 'links', 'at_most_one'), listRule(links, 'at_most_one'));
}
{
  const links = [L('closes', DA, { attrs: closesAttrs }), L('closes', DB, { attrs: closesAttrs })];
  add('profiles', 'two closes links', P(links), W('relation_not_writable', 'links[0].rel'), listRule(links, 'at_most_one'));
}

// ── list level ──────────────────────────────────────────────────────────

const mandateForm = { mandateAssertion: W4_ASSERTION_DIGEST, mandateSeq: 1, totals: null, confirm: false };
const mandated = (links: unknown) => P(links, { decider: agentDecider('agent-mandated'), signoffExpectation: mandateForm });
add('listLevel', 'the mandate form with links null', mandated(null), W('required_link_missing', 'links', 'mandate_link'), {
  outcome: 'checked-wrong', valid: false, reason: 'link_rule_violated', rule: 'mandate_link', relations: [], edges: [],
});
{
  const links = [L('mandate', D1)];
  add('listLevel', 'the mandate form with one mandate link, its target not held', mandated(links), null, correctList(links, [notHeld(0, 'mandate')]));
}
{
  const links = [L('derivedFrom', D2)];
  add('listLevel', 'the mandate form with no mandate link among others', mandated(links), W('required_link_missing', 'links', 'mandate_link'), listRule(links, 'mandate_link'));
}
{
  const links = [L('mandate', DA), L('mandate', DB)];
  add('listLevel', 'the mandate form with two mandate links', mandated(links), W('link_rule_violated', 'links', 'mandate_link'), listRule(links, 'mandate_link'));
}
{
  const links = [L('mandate', D1)];
  add('listLevel', 'a mandate link without the mandate form', P(links), W('link_rule_violated', 'links', 'mandate_link'), listRule(links, 'mandate_link'));
  add('listLevel', 'a mandate link under a malformed expectation: the mandate rule is not applied, its row is blocked by the expectation', P(links, { signoffExpectation: { policyDigest: 'x' } }), null, correctList(links, [blockedRow(0, 'mandate', 'blocked_by:signoff.expectation')]));
}
const revocation = (links: unknown) =>
  P(links, {
    aiSystemId: 'tzun:mandate',
    action: 'revoke-mandate',
    aiOutput: { claimedRevocationInstant: '2026-10-05T10:00:00.000Z', mandateDigest: W4_MANDATE_DIGEST, reason: 'Revoked', statementDigest: W4_STATEMENT_DIGEST },
  });
add('listLevel', 'a revocation record with links null', revocation(null), W('required_link_missing', 'links', 'revokes_link'), {
  outcome: 'checked-wrong', valid: false, reason: 'link_rule_violated', rule: 'revokes_link', relations: [], edges: [],
});
{
  const links = [L('revokes', D1)];
  add('listLevel', 'a revocation record with its revokes link, the target not held', revocation(links), null, correctList(links, [notHeld(0, 'revokes')]));
  add('listLevel', 'a revokes link on a record that is not a revocation record', P(links), W('link_rule_violated', 'links', 'revokes_link'), listRule(links, 'revokes_link'));
}
const linkRecord = (links: unknown, extra: Record<string, unknown> = {}) =>
  P(links, { aiSystemId: 'tzun:link', action: 'link', aiOutput: {}, reason: 'Complaint C-1182 contests the decision', ...extra });
add('listLevel', 'a link record with links null', linkRecord(null), W('required_link_missing', 'links', 'subject_link'), {
  outcome: 'checked-wrong', valid: false, reason: 'link_rule_violated', rule: 'subject_link', relations: [], edges: [],
});
{
  const links = [L('subject', D1)];
  add('listLevel', 'a link record with only its subject link', linkRecord(links), W('required_link_missing', 'links', 'subject_link'), listRule(links, 'subject_link'));
}
{
  const links = [L('appeals', D2), L('subject', D1)];
  add('listLevel', 'a link record: appeals and subject, neither held', linkRecord(links), null, correctList(links, [ok(0, 'appeals'), ok(1, 'subject')]));
  add('listLevel', 'a link record whose action is not link', linkRecord(links, { action: 'appeal' }), W('link_rule_violated', 'links', 'subject_link'), listRule(links, 'subject_link'));
  add('listLevel', 'a link record carrying contributions', linkRecord(links, { contributions: { pipeline: null, externals: [], steps: [] } }), W('link_rule_violated', 'links', 'subject_link'), listRule(links, 'subject_link'));
  add('listLevel', 'a subject link outside a link record', P(links), W('link_rule_violated', 'links', 'subject_link'), listRule(links, 'subject_link'));
}
{
  const links = [L('appeals', D1), L('subject', D1)];
  add('listLevel', 'a link record whose other link names the subject itself', linkRecord(links), W('link_rule_violated', 'links', 'subject_link'), listRule(links, 'subject_link'));
}
{
  const links = [L('appeals', D2), L('root', D2), L('subject', D1)];
  add('listLevel', 'a link record carrying root', linkRecord(links), W('link_rule_violated', 'links', 'subject_link'), listRule(links, 'subject_link'));
}
{
  const links = [L('appeals', D2), L('mandate', DA), L('subject', D1)].sort((a, b) => (a.rel < b.rel ? -1 : 1));
  add('listLevel', 'a link record carrying a mandate link (the mandate rule is tried first)', linkRecord(links), W('link_rule_violated', 'links', 'mandate_link'), listRule(links, 'mandate_link'));
}
{
  const links = [L('appeals', D2), L('subject', DA), L('subject', DB)];
  add('listLevel', 'a link record with two subject links', linkRecord(links), W('link_rule_violated', 'links', 'subject_link'), listRule(links, 'subject_link'));
}

// ── targets ─────────────────────────────────────────────────────────────

/** A held record: its payload, the digest it recomputes to, its chain's origin. */
const heldRecord = (p: Record<string, unknown>, origin: string | null = LENDER_ORIGIN): HeldLinkTarget => ({ payload: p, digest: recordDigest(p), origin });
const T_HUMAN = heldRecord(payload({ evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000006', sequenceNumber: 6, aiSystemId: 'intake-model', decider: human() }));
const T_AGENT = heldRecord(payload({ evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000008', sequenceNumber: 8, aiSystemId: 'lending-model', decider: agentDecider() }));
const T_CMT = heldRecord(payload({ evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000009', sequenceNumber: 9, decider: human(CMT) }));
const T_CHILD = heldRecord(
  payload({
    evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000010',
    sequenceNumber: 10,
    links: [L('derivedFrom', T_HUMAN.digest), L('root', T_HUMAN.digest)],
  }),
);
const ISSUANCE = heldRecord(
  payload({
    evidenceId: '7a2c0d4e-1111-4a1a-8a1a-000000000001',
    aiSystemId: 'tzun:mandate',
    action: 'issue-mandate',
    aiOutput: { assertionDigest: W4_ASSERTION_DIGEST, mandateDigest: W4_MANDATE_DIGEST, statementDigest: W4_STATEMENT_DIGEST },
    reason: 'Claims-triage mandate for Q4 2026',
    decider: human('acct:user-2c9d'),
  }),
  CLAIMS_ORIGIN,
);
const tampered = (h: HeldLinkTarget): HeldLinkTarget => ({ ...h, payload: { ...h.payload, reason: 'edited after capture' } });
const full = (h: HeldLinkTarget) => ({
  evidenceId: h.payload.evidenceId as string,
  locator: h.origin === null ? null : { origin: h.origin, seq: h.payload.sequenceNumber as number },
});
const T = (rel: string, h: HeldLinkTarget, edit: Partial<{ evidenceId: string | null; locator: Locator }> = {}) => L(rel, h.digest, { ...full(h), ...edit });

{
  const links = [T('derivedFrom', T_HUMAN)];
  add('targets', 'derivedFrom, the target held, every member agreeing', P(links), null, correctList(links, [ok(0, 'derivedFrom', true)]), { held: [T_HUMAN] });
  add('targets', 'derivedFrom, the held target altered after capture (read by digest: its payload no longer recomputes to it)', P(links), null, correctList(links, [mismatch(0, 'derivedFrom', 'digest')]), { held: [tampered(T_HUMAN)] });
}
{
  const links = [T('derivedFrom', T_HUMAN, { evidenceId: T_AGENT.payload.evidenceId as string })];
  add('targets', 'the digest of one record and the evidence id of another: read by digest first', P(links), null, correctList(links, [mismatch(0, 'derivedFrom', 'evidenceId')]), { held: [T_HUMAN, T_AGENT] });
}
{
  const links = [T('derivedFrom', T_HUMAN, { locator: { origin: LENDER_ORIGIN, seq: 7 } })];
  add('targets', 'the locator naming another seq', P(links), null, correctList(links, [mismatch(0, 'derivedFrom', 'locator')]), { held: [T_HUMAN] });
}
{
  const links = [T('derivedFrom', T_HUMAN, { locator: { origin: CLAIMS_ORIGIN, seq: 6 } })];
  add('targets', 'the locator naming another chain\'s origin', P(links), null, correctList(links, [mismatch(0, 'derivedFrom', 'locator')]), { held: [T_HUMAN] });
}
{
  const links = [T('derivedFrom', T_HUMAN, { evidenceId: null, locator: null })];
  add('targets', 'evidence id and locator null: only the digest is compared', P(links), null, correctList(links, [ok(0, 'derivedFrom', true)]), { held: [T_HUMAN] });
}
{
  const links = [L('derivedFrom', D1, { locator: { origin: LENDER_ORIGIN, seq: 6 } })];
  add('targets', 'a same-store locator whose position holds another record', P(links), null, correctList(links, [mismatch(0, 'derivedFrom', 'locator', false)]), {
    held: [T_HUMAN], ownOrigins: [LENDER_ORIGIN], positions: [{ origin: LENDER_ORIGIN, seq: 6, digest: T_HUMAN.digest }],
  });
  add('targets', 'a same-store locator whose position holds nothing', P(links), null, correctList(links, [mismatch(0, 'derivedFrom', 'locator', false)]), {
    held: [], ownOrigins: [LENDER_ORIGIN], positions: [],
  });
  add('targets', 'a locator naming another store, the target not held', P(links), null, correctList(links, [ok(0, 'derivedFrom', false)]), {
    held: [], ownOrigins: [CLAIMS_ORIGIN], positions: [],
  });
}
{
  const links = [T('reviews', T_HUMAN)];
  add('targets', 'reviews by another person', P(links, { decider: human('acct:u-7702') }), null, correctList(links, [ok(0, 'reviews', true)]), { held: [T_HUMAN] });
  add('targets', 'reviews by the target\'s own decider', P(links), null, correctList(links, [violated(0, 'reviews', 'reviews_distinct_decider', true)]), { held: [T_HUMAN] });
  add('targets', 'reviews by a commitment the store cannot open: undetermined', P(links, { decider: human(CMT) }), null, correctList(links, [
    rowOf(0, 'reviews', 'not-checked', { reason: 'link_rule_undetermined', rule: 'reviews_distinct_decider', targetHeld: true }),
  ]), { held: [T_HUMAN] });
  add('targets', 'reviews by a commitment the store opens to the target\'s decider', P(links, { decider: human(CMT) }), null, correctList(links, [
    violated(0, 'reviews', 'reviews_distinct_decider', true),
  ]), { held: [T_HUMAN], openings: { [CMT]: ACCT } });
  add('targets', 'reviews by a commitment the store opens to another person', P(links, { decider: human(CMT) }), null, correctList(links, [ok(0, 'reviews', true)]), {
    held: [T_HUMAN], openings: { [CMT]: 'acct:u-7702' },
  });
}
{
  const links = [T('reviews', T_CMT)];
  const other = 'cmt:' + 'd5'.repeat(32);
  add('targets', 'reviews: two different commitments, neither opened', P(links, { decider: human(other) }), null, correctList(links, [
    rowOf(0, 'reviews', 'not-checked', { reason: 'link_rule_undetermined', rule: 'reviews_distinct_decider', targetHeld: true }),
  ]), { held: [T_CMT] });
  add('targets', 'reviews: the same commitment on both sides (same kind and id)', P(links, { decider: human(CMT) }), null, correctList(links, [
    violated(0, 'reviews', 'reviews_distinct_decider', true),
  ]), { held: [T_CMT] });
}
{
  const links = [T('supersedes', T_AGENT)];
  add('targets', 'supersedes a decision of the same system', P(links, { aiSystemId: 'lending-model' }), null, correctList(links, [ok(0, 'supersedes', true)]), { held: [T_AGENT] });
  add('targets', 'supersedes a decision of another system', P(links), null, correctList(links, [violated(0, 'supersedes', 'supersedes_same_system', true)]), { held: [T_AGENT] });
}
{
  const links = [T('ratifies', T_AGENT)];
  add('targets', 'a human ratifies an agent\'s decision', P(links), null, correctList(links, [ok(0, 'ratifies', true)]), { held: [T_AGENT] });
}
{
  const links = [T('ratifies', T_HUMAN)];
  add('targets', 'a human ratifies a human\'s decision', P(links), null, correctList(links, [violated(0, 'ratifies', 'ratifies_target_not_human', true)]), { held: [T_HUMAN] });
}
{
  const links = [T('mandate', ISSUANCE)];
  add('targets', 'a mandate link to the issuance record of the assertion the record names', mandated(links), null, correctList(links, [ok(0, 'mandate', true)]), { held: [ISSUANCE] });
  add('targets', 'a mandate link to an issuance record of another assertion', P(links, {
    decider: agentDecider('agent-mandated'), signoffExpectation: { ...mandateForm, mandateAssertion: digestOf('another assertion') },
  }), null, correctList(links, [violated(0, 'mandate', 'mandate_target', true)]), { held: [ISSUANCE] });
}
{
  const links = [T('mandate', T_HUMAN)];
  add('targets', 'a mandate link to a record that is not an issuance record', mandated(links), null, correctList(links, [violated(0, 'mandate', 'mandate_target', true)]), { held: [T_HUMAN] });
}
{
  const links = [T('revokes', ISSUANCE)];
  add('targets', 'a revocation of the mandate the issuance record issued', revocation(links), null, correctList(links, [ok(0, 'revokes', true)]), { held: [ISSUANCE] });
  const r = revocation(links);
  add('targets', 'a revocation naming another mandate digest', { ...r, aiOutput: { ...(r.aiOutput as object), mandateDigest: digestOf('another mandate') } }, null, correctList(links, [
    violated(0, 'revokes', 'revokes_target', true),
  ]), { held: [ISSUANCE] });
}
{
  const links = [T('appeals', T_HUMAN), T('root', T_HUMAN)];
  add('targets', 'root naming the root it should: no fact', P(links), null, correctList(links, [ok(0, 'appeals', true), ok(1, 'root', true)]), { held: [T_HUMAN] });
}
{
  const links = [T('derivedFrom', T_CHILD), T('root', T_HUMAN)];
  add('targets', 'root naming the root of a held lineage target (consistent)', P(links), null, correctList(links, [ok(0, 'derivedFrom', true), ok(1, 'root', true)]), {
    held: [T_CHILD, T_HUMAN],
  });
}
{
  const links = [T('derivedFrom', T_CHILD), T('root', T_CHILD)];
  add('targets', 'root naming a target that has a lineage link of its own: a fact, never a failure', P(links), null, correctList(links, [
    ok(0, 'derivedFrom', true), ok(1, 'root', true, { rootInconsistent: true }),
  ]), { held: [T_CHILD] });
}
{
  const links = [T('derivedFrom', T_CHILD), T('root', T_AGENT)].sort((a, b) => (a.rel < b.rel ? -1 : 1));
  add('targets', 'root naming another root than its held lineage target names', P(links), null, correctList(links, [
    ok(0, 'derivedFrom', true), ok(1, 'root', true, { rootInconsistent: true }),
  ]), { held: [T_CHILD, T_AGENT] });
}
{
  const links = [T('delegatedBy', T_AGENT)];
  add('targets', 'delegatedBy, the target held: its rule is not implemented', P(links), null, correctList(links, [unsupportedRule(0, 'delegatedBy', true)]), { held: [T_AGENT] });
}
{
  const links = [T('ratifies', T_AGENT), L('subject', T_HUMAN.digest)].sort((a, b) => (a.rel < b.rel ? -1 : 1));
  const lr = linkRecord(links, { decider: human('acct:u-7702') });
  add('targets', 'a link record: its subject (a human\'s decision) ratifies an agent\'s decision', lr, null, correctList(links, [ok(0, 'ratifies', true), ok(1, 'subject', true)]), {
    held: [T_HUMAN, T_AGENT],
  });
  add('targets', 'a link record whose subject is not held: a rule that reads the subject is not checked', lr, null, correctList(links, [
    rowOf(0, 'ratifies', 'not-checked', { reason: 'not_in_bundle:link_target', targetHeld: true, missing: 'subject' }), ok(1, 'subject', false),
  ]), { held: [T_AGENT] });
}
{
  const links = [T('ratifies', T_HUMAN), L('subject', T_AGENT.digest)].sort((a, b) => (a.rel < b.rel ? -1 : 1));
  add('targets', 'a link record whose subject is an agent\'s decision cannot have it ratify', linkRecord(links), null, correctList(links, [
    violated(0, 'ratifies', 'ratifies_decider_human', true), ok(1, 'subject', true),
  ]), { held: [T_HUMAN, T_AGENT] });
}
{
  const links = [T('supersedes', T_AGENT), L('subject', T_HUMAN.digest)].sort((a, b) => (a.rel < b.rel ? -1 : 1));
  add('targets', 'a link record: its subject supersedes a decision of another system', linkRecord(links), null, correctList(links, [
    ok(0, 'subject', true), violated(1, 'supersedes', 'supersedes_same_system', true),
  ]), { held: [T_HUMAN, T_AGENT] });
}

for (const [group, cases] of Object.entries(groups)) {
  for (const c of cases) {
    const w = linksViolation(c.payload.links, c.payload);
    agree(`${group} "${c.case}" writer`, w && { code: w.code, field: w.field, ...(w.rule !== undefined && { rule: w.rule }) }, c.writer);
    agree(`${group} "${c.case}" reader`, checkLinks(c.payload, { resolver: resolverOf(c.resolver) }), c.reader);
  }
}

// ── capture ─────────────────────────────────────────────────────────────

interface CaptureCase {
  case: string;
  inputs: unknown;
  held: Array<HeldLinkTarget | null>;
  options: { allowReserved?: string[]; linkRecord?: boolean; context?: Record<string, unknown> };
  links?: Link[];
  refused?: { code: string; field: string; rule?: string };
}
const capture: CaptureCase[] = [];
const built = (c: string, inputs: LinkInput[], held: Array<HeldLinkTarget | null>, links: Link[], options: CaptureCase['options'] = {}) =>
  capture.push({ case: c, inputs, held, options, links });
const refused = (c: string, inputs: unknown, held: Array<HeldLinkTarget | null>, code: string, field: string, options: CaptureCase['options'] = {}, rule?: string) =>
  capture.push({ case: c, inputs, held, options, refused: { code, field, ...(rule !== undefined && { rule }) } });

built('a same-store target by evidence id: digest and locator filled; root added (the target has no lineage link)', [
  { rel: 'derivedFrom', target: { evidenceId: T_HUMAN.payload.evidenceId as string } },
], [T_HUMAN], [T('derivedFrom', T_HUMAN), T('root', T_HUMAN)]);
built('a same-store target by digest', [{ rel: 'appeals', target: { digest: T_HUMAN.digest } }], [T_HUMAN], [T('appeals', T_HUMAN), T('root', T_HUMAN)]);
built('locator: null is kept, and the root copies it', [
  { rel: 'derivedFrom', target: { evidenceId: T_HUMAN.payload.evidenceId as string, locator: null } },
], [T_HUMAN], [T('derivedFrom', T_HUMAN, { locator: null }), T('root', T_HUMAN, { locator: null })]);
built('the root of a target that has one: its root link\'s target', [
  { rel: 'derivedFrom', target: { evidenceId: T_CHILD.payload.evidenceId as string } },
], [T_CHILD], [T('derivedFrom', T_CHILD), L('root', T_HUMAN.digest)]);
{
  const lineageNoRoot = heldRecord(payload({ evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000011', sequenceNumber: 11, links: [L('derivedFrom', D1)] }));
  built('a target with a lineage link and no root link: no root added', [
    { rel: 'derivedFrom', target: { evidenceId: lineageNoRoot.payload.evidenceId as string } },
  ], [lineageNoRoot], [T('derivedFrom', lineageNoRoot)]);
}
built('a root the caller supplies is kept, and no second one added', [
  { rel: 'derivedFrom', target: { evidenceId: T_HUMAN.payload.evidenceId as string } },
  { rel: 'root', target: { digest: D1, external: true } },
], [T_HUMAN, null], [T('derivedFrom', T_HUMAN), L('root', D1)]);
built('an external target: written as given, null where omitted; no root (no held lineage target)', [
  { rel: 'appeals', target: { digest: D1, external: true } },
], [null], [L('appeals', D1)]);
built('an external target with its evidence id and locator from the other store\'s receipt', [
  { rel: 'derivedFrom', target: { digest: D1, evidenceId: 'C-1182', locator: { origin: CLAIMS_ORIGIN, seq: 40 }, external: true } },
], [null], [L('derivedFrom', D1, { evidenceId: 'C-1182', locator: { origin: CLAIMS_ORIGIN, seq: 40 } })]);
built('an external target that resolves in this store is handled as a same-store target', [
  { rel: 'derivedFrom', target: { digest: T_HUMAN.digest, external: true } },
], [T_HUMAN], [T('derivedFrom', T_HUMAN), T('root', T_HUMAN)]);
built('links sorted by (rel, target.digest), attrs absent written as null', [
  { rel: 'x-acme.renewal', target: { digest: D2, external: true }, attrs: { renewals: 2 } },
  { rel: 'appeals', target: { digest: D1, external: true } },
], [null, null], [L('appeals', D1), L('x-acme.renewal', D2, { attrs: { renewals: 2 } })]);
built('a link record: no root link, even beside a lineage link to a held target', [
  { rel: 'appeals', target: { evidenceId: T_HUMAN.payload.evidenceId as string } },
  { rel: 'subject', target: { digest: D1, external: true } },
], [T_HUMAN, null], [T('appeals', T_HUMAN), L('subject', D1)], { allowReserved: ['subject'], linkRecord: true });
refused('a same-store target the store does not hold', [{ rel: 'derivedFrom', target: { evidenceId: 'no-such-record' } }], [null], 'link_target_not_found', 'links[0].target');
refused('a supplied digest that is not the held record\'s', [
  { rel: 'derivedFrom', target: { evidenceId: T_HUMAN.payload.evidenceId as string, digest: D1 } },
], [T_HUMAN], 'link_target_mismatch', 'links[0].target.digest');
refused('a supplied evidence id that is not the held record\'s', [
  { rel: 'derivedFrom', target: { digest: T_HUMAN.digest, evidenceId: 'another-id' } },
], [T_HUMAN], 'link_target_mismatch', 'links[0].target.evidenceId');
refused('a supplied locator that is not the held record\'s position', [
  { rel: 'derivedFrom', target: { digest: T_HUMAN.digest, locator: { origin: LENDER_ORIGIN, seq: 5 } } },
], [T_HUMAN], 'link_target_mismatch', 'links[0].target.locator');
refused('an empty input', [], [], 'empty_links', 'links');
refused('a caller\'s mandate link', [{ rel: 'mandate', target: { digest: D1, external: true } }], [null], 'relation_reserved', 'links[0].rel');
refused('a caller\'s revokes link', [{ rel: 'revokes', target: { digest: D1, external: true } }], [null], 'relation_reserved', 'links[0].rel');
refused('a caller\'s subject link', [{ rel: 'subject', target: { digest: D1, external: true } }], [null], 'relation_reserved', 'links[0].rel');
refused('a closes link (no writer until the fan-out coordinator)', [{ rel: 'closes', target: { digest: D1, external: true }, attrs: closesAttrs }], [null], 'relation_not_writable', 'links[0].rel');
refused('a fanoutOf link', [{ rel: 'fanoutOf', target: { digest: D1, external: true }, attrs: { slot: 1, statement: closesAttrs.statement } }], [null], 'relation_not_writable', 'links[0].rel');
refused('an unregistered unprefixed relation', [{ rel: 'inspiredBy', target: { digest: D1, external: true } }], [null], 'unknown_relation', 'links[0].rel');
refused('a repeated pair (the builder sorts, never removes)', [
  { rel: 'appeals', target: { digest: D1, external: true } },
  { rel: 'appeals', target: { digest: D1, external: true } },
], [null, null], 'not_a_set', 'links');
refused('a target member the input form does not have', [{ rel: 'appeals', target: { digest: D1, external: true, seq: 3 } }], [null], 'invalid_target', 'links[0].target');
refused('an attribute on a registered relation', [{ rel: 'appeals', target: { digest: D1, external: true }, attrs: { note: 'x' } }], [null], 'attrs_not_allowed', 'links[0].attrs');
refused('an external target with no digest', [{ rel: 'appeals', target: { external: true } }], [null], 'invalid_target_digest', 'links[0].target.digest');
refused('with the record\'s context, a target rule broken at capture (supersedes a decision of another system; the added root link sorts first)', [
  { rel: 'supersedes', target: { evidenceId: T_AGENT.payload.evidenceId as string } },
], [T_AGENT], 'link_rule_violated', 'links[1]', { context: { aiSystemId: 'intake-model', action: 'approve', decider: human() } }, 'supersedes_same_system');

for (const c of capture) {
  let got: unknown;
  try {
    got = { links: buildLinks(c.inputs as LinkInput[], { held: c.held, allowReserved: c.options.allowReserved as never, linkRecord: c.options.linkRecord, context: c.options.context }) };
  } catch (e) {
    const err = e as { code?: string; field?: string; rule?: string };
    got = { refused: { code: err.code, field: err.field, ...(err.rule !== undefined && { rule: err.rule }) } };
  }
  agree(`capture "${c.case}"`, got, c.links !== undefined ? { links: c.links } : { refused: c.refused });
}

emit({
  description:
    'The links member of a v1.0 record (Record §8): its grammar, the relation registry\'s closed profiles and record-local rules, ' +
    'the list-level rules, the target rules a store-level verifier checks with the targets it holds, and the builder a capture runs; ' +
    'the rows of Verification §4.11.',
  source:
    'Generated by scripts/generate-links-vectors.ts. Every expected answer is written in the script from the specification, and the ' +
    'script stops if the engine disagrees with one. A writer tries its rules in this order: the grammar, each relation registered (and ' +
    'writable), each profile, each record-local rule, the list-level rules (mandate_link, revokes_link, subject_link, at_most_one). ' +
    'A case without a resolver is read as a bundle verifier reads it, holding no target.',
  registry: REGISTERED,
  ...groups,
  capture,
});
