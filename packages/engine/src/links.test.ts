import { readFileSync } from 'fs';
import { join } from 'path';
import { canonicalSerialize } from './canonical';
import { computeDigest } from './digest';
import { V1_0_HASHED_FIELDS } from './schema-registry';
import {
  LINK_RELATIONS,
  LINK_RELATION_NAMES,
  buildLinks,
  checkLinks,
  isEvidenceLogOrigin,
  linkRecordViolation,
  linksGrammarViolation,
  linksViolation,
  linkTargetInputs,
} from './links';
import type { HeldLinkTarget, Link } from './types/links';

const ORIGIN = 'test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/6c656e64696e67';
const OTHER_ORIGIN = 'test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/6f74686572';
const D1 = '11'.repeat(32);
const D2 = '22'.repeat(32);
const D3 = '33'.repeat(32);
const human = (id = 'acct:u-4821') => ({ kind: 'human', id, agent: null, credential: null, freshness: null });
const agent = { kind: 'agent', id: 'desc:sha256:' + 'a1'.repeat(32), agent: 'sha256:' + 'a1'.repeat(32), credential: null, freshness: null };
const target = (digest: string, evidenceId: string | null = null, locator: Link['target']['locator'] = null) => ({ digest, evidenceId, locator });
const link = (rel: string, digest: string, attrs: Link['attrs'] = null): Link => ({ rel, target: target(digest), attrs });
const sorted = (links: Link[]) => [...links].sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : a.target.digest < b.target.digest ? -1 : 1));
const payload = (links: unknown, extra: Record<string, unknown> = {}) => ({
  schemaVersion: 'v1.0', aiSystemId: 'lending-model', action: 'approve', reason: 'r', aiOutput: {},
  decider: human(), contributions: null, links, signoffExpectation: null, ...extra,
});

/**
 * A held record whose stored digest is what its payload recomputes to: the
 * test stores whatever payload it builds and reads the digest back.
 */
function held(p: Record<string, unknown>, origin: string | null = ORIGIN): HeldLinkTarget {
  return { payload: p, digest: computeDigest(canonicalSerialize(p, [...V1_0_HASHED_FIELDS])), origin };
}
const record = (seq: number, extra: Record<string, unknown> = {}) =>
  payload(null, { evidenceId: `5f0c1f0e-3333-4c3c-9c3c-${String(seq).padStart(12, '0')}`, sequenceNumber: seq, ...extra });
const resolverOf = (...records: HeldLinkTarget[]) => ({
  byDigest: (digest: string) => records.find((r) => r.digest === digest) ?? null,
});

describe('the relation registry (Record §8.3)', () => {
  it('registers the thirteen relations', () => {
    expect(LINK_RELATION_NAMES).toEqual([
      'derivedFrom', 'reviews', 'supersedes', 'appeals', 'ratifies', 'implements', 'delegatedBy', 'closes', 'fanoutOf',
      'root', 'mandate', 'revokes', 'subject',
    ]);
    expect(LINK_RELATIONS.closes.requiredAttrs).toEqual(['size', 'statement', 'treeRoot']);
    expect(LINK_RELATIONS.fanoutOf.requiredAttrs).toEqual(['slot', 'statement']);
    expect(LINK_RELATIONS.mandate.writer).toBe('reserved');
    expect(LINK_RELATIONS.closes.writer).toBe('none');
  });
});

describe('the grammar (Record §8.2)', () => {
  it('accepts null and a sorted list, and refuses [] and 257 links', () => {
    expect(linksGrammarViolation(null)).toBeNull();
    expect(linksGrammarViolation([link('derivedFrom', D1), link('root', D1)])).toBeNull();
    expect(linksGrammarViolation([])?.code).toBe('empty_links');
    const many = Array.from({ length: 257 }, (_, i) => link('derivedFrom', i.toString(16).padStart(64, '0')));
    expect(linksGrammarViolation(many)?.code).toBe('too_many_links');
    expect(linksGrammarViolation({})?.code).toBe('not_an_array');
  });

  it.each([
    ['unsorted by rel', [link('root', D1), link('derivedFrom', D1)], 'not_a_set'],
    ['unsorted by digest', [link('derivedFrom', D2), link('derivedFrom', D1)], 'not_a_set'],
    ['a repeated pair', [link('derivedFrom', D1), link('derivedFrom', D1)], 'not_a_set'],
    ['an extra link member', [{ ...link('derivedFrom', D1), note: 'x' }], 'link_unknown_members'],
    ['a missing link member', [{ rel: 'derivedFrom', target: target(D1) }], 'link_missing_members'],
    ['a relation with a dash', [link('derived-from', D1)], 'invalid_relation'],
    ['an extension with an uppercase org', [link('x-Acme.thing', D1)], 'invalid_relation'],
    ['a target member missing', [{ rel: 'derivedFrom', target: { digest: D1, evidenceId: null }, attrs: null }], 'invalid_target'],
    ['a prefixed target digest', [link('derivedFrom', 'sha256:' + D1)], 'invalid_target_digest'],
    ['an evidence id with a space', [{ rel: 'derivedFrom', target: target(D1, 'a b'), attrs: null }], 'invalid_target_evidence_id'],
    ['an evidence id of 129 characters', [{ rel: 'derivedFrom', target: target(D1, 'e'.repeat(129)), attrs: null }], 'invalid_target_evidence_id'],
    ['a locator at seq 0', [{ rel: 'derivedFrom', target: target(D1, null, { origin: ORIGIN, seq: 0 }), attrs: null }], 'invalid_locator'],
    ['a locator naming an anchor log', [{ rel: 'derivedFrom', target: target(D1, null, { origin: 'ns.example/d/anchors', seq: 1 }), attrs: null }], 'invalid_locator'],
    ['attrs {}', [link('derivedFrom', D1, {})], 'invalid_attrs'],
    ['17 attrs', [link('x-acme.thing', D1, Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`a${i}`, i])))], 'too_many_attrs'],
    ['a null attribute value', [link('x-acme.thing', D1, { a: null as never })], 'invalid_attrs'],
    ['a nested attribute value', [link('x-acme.thing', D1, { a: { b: 1 } as never })], 'invalid_attrs'],
    ['a negative attribute', [link('x-acme.thing', D1, { a: -1 })], 'invalid_attrs'],
    ['a fractional attribute', [link('x-acme.thing', D1, { a: 1.5 })], 'invalid_attrs'],
    ['an attribute string of 257 characters', [link('x-acme.thing', D1, { a: 'v'.repeat(257) })], 'invalid_attrs'],
  ])('refuses %s', (_name, links, code) => {
    expect(linksGrammarViolation(links)?.code).toBe(code);
  });

  it('admits an attribute value with a space, an extension attribute name, and an integer written 1.0', () => {
    expect(linksGrammarViolation([link('x-acme.thing', D1, { note: 'a b', 'x-acme.flag': true, n: 1.0 })])).toBeNull();
  });

  it('reads evidence-log origins by the tzun-anchor/1 grammar', () => {
    expect(isEvidenceLogOrigin(ORIGIN)).toBe(true);
    expect(isEvidenceLogOrigin('log.tzun.ai/deploy-1/' + 'f'.repeat(16))).toBe(true);
    expect(isEvidenceLogOrigin('ns/store')).toBe(false);
    expect(isEvidenceLogOrigin('ns//evidence/x')).toBe(false);
    expect(isEvidenceLogOrigin('ns/store/a+b')).toBe(false);
    const file = JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'vectors', 'evidence-log-origin-vectors.json'), 'utf8'));
    for (const v of file.vectors) expect([v.name, isEvidenceLogOrigin(v.origin)]).toEqual([v.name, true]);
    const origin = (ns: string) => `${ns}/${file.storeId}/evidence/64656661756c74`;
    for (const n of file.namespaces.valid) expect([n.name, isEvidenceLogOrigin(origin(n.ns))]).toEqual([n.name, true]);
    for (const n of file.namespaces.invalid) expect([n.name, isEvidenceLogOrigin(origin(n.ns))]).toEqual([n.name, false]);
  });
});

describe('linksViolation (writer)', () => {
  const ctx = payload(null);

  it('accepts derivedFrom with its root, and an extension with attributes', () => {
    expect(linksViolation([link('derivedFrom', D1), link('root', D1)], ctx)).toBeNull();
    expect(linksViolation([link('x-acme.contractRenewal', D1, { term: 12 })], ctx)).toBeNull();
  });

  it.each([
    ['an unregistered unprefixed relation', [link('contests', D1)], 'unknown_relation'],
    ['closes, which has no writer', [link('closes', D1, { size: 1, statement: D2, treeRoot: D3 })], 'relation_not_writable'],
    ['an x- attribute on a registered relation', [link('derivedFrom', D1, { 'x-acme.note': 'x' })], 'attrs_not_allowed'],
    ['a root alone', [link('root', D1)], 'root_without_lineage'],
    ['a root beside only an extension', sorted([link('root', D1), link('x-acme.thing', D2)]), 'root_without_lineage'],
    ['ratifies by an agent', [link('ratifies', D1)], 'link_rule_violated'],
    ['a mandate link without the mandate form', [link('mandate', D1)], 'link_rule_violated'],
    ['a subject link outside a link record', [link('subject', D1)], 'link_rule_violated'],
    ['two roots', sorted([link('derivedFrom', D1), link('root', D1), link('root', D2)]), 'link_rule_violated'],
  ])('refuses %s', (_name, links, code) => {
    expect(linksViolation(links, { ...ctx, decider: _name.includes('agent') ? agent : human() })?.code).toBe(code);
  });

  it('requires the mandate, revokes and subject links where the record needs them', () => {
    const mandateForm = { mandateAssertion: D1, mandateSeq: 1, totals: null, confirm: false };
    expect(linksViolation(null, { ...ctx, signoffExpectation: mandateForm })).toMatchObject({ code: 'required_link_missing', rule: 'mandate_link' });
    expect(linksViolation([link('mandate', D1)], { ...ctx, signoffExpectation: mandateForm })).toBeNull();
    expect(linksViolation(null, { ...ctx, aiSystemId: 'tzun:mandate', action: 'revoke-mandate' })).toMatchObject({
      code: 'required_link_missing', rule: 'revokes_link',
    });
    expect(linksViolation(null, { ...ctx, aiSystemId: 'tzun:link', action: 'link' })).toMatchObject({
      code: 'required_link_missing', rule: 'subject_link',
    });
    expect(linksViolation([link('subject', D1)], { ...ctx, aiSystemId: 'tzun:link', action: 'link' })).toMatchObject({
      code: 'required_link_missing', rule: 'subject_link',
    });
  });
});

describe('link records (Record §8.6, W7)', () => {
  const W3 = '6fb46fa4724f9e1689a2a18fe465e8aedeaee6a5742878983a181084602b0e2e';
  const subjectDigest = 'c0'.repeat(32);
  const w7Links = (): Link[] => [
    { rel: 'appeals', target: target(W3, '5f0c1f0e-3333-4c3c-9c3c-000000000007', { origin: ORIGIN, seq: 7 }), attrs: null },
    { rel: 'subject', target: target(subjectDigest), attrs: null },
  ];
  const linkRecord = (links: unknown, extra: Record<string, unknown> = {}) =>
    payload(links, { aiSystemId: 'tzun:link', action: 'link', reason: 'Complaint C-1182 contests the underwriting decision', decider: human('acct:u-7702'), ...extra });

  it('accepts W7', () => {
    expect(linkRecordViolation(linkRecord(w7Links()))).toBeNull();
    expect(linksViolation(w7Links(), linkRecord(null))).toBeNull();
    expect(linkRecordViolation(payload(null))).toBeNull();
  });

  it.each([
    ['another action', linkRecord(w7Links(), { action: 'approve' })],
    ['contributions', linkRecord(w7Links(), { contributions: { steps: [] } })],
    ['no other link', linkRecord([w7Links()[1]])],
    ['another link to the subject', linkRecord(sorted([w7Links()[0], w7Links()[1], link('derivedFrom', subjectDigest)]))],
    ['a root beside the subject', linkRecord(sorted([...w7Links(), link('root', W3)]))],
    ['two subjects', linkRecord(sorted([...w7Links(), link('subject', D1)]))],
  ])('refuses a link record with %s', (_name, p) => {
    expect(linkRecordViolation(p)?.rule).toBe('subject_link');
  });

  it('builds W7 with external: true for the subject and no root', () => {
    const w3 = held(record(7, { links: [link('derivedFrom', D1), link('root', D1)] }));
    const links = buildLinks(
      [
        { rel: 'appeals', target: { evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000007' } },
        { rel: 'subject', target: { digest: subjectDigest, external: true } },
      ],
      { held: [w3, null], allowReserved: ['subject'], linkRecord: true },
    );
    expect(links).toEqual([
      { rel: 'appeals', target: { digest: w3.digest, evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000007', locator: { origin: ORIGIN, seq: 7 } }, attrs: null },
      { rel: 'subject', target: target(subjectDigest), attrs: null },
    ]);
  });

  it('reads a ratifies link with the subject in the child’s place', () => {
    const subject = held(record(3, { decider: human('acct:u-1') }));
    const autonomous = held(record(2, { decider: agent }));
    const p = linkRecord(sorted([link('ratifies', autonomous.digest), link('subject', subject.digest)]));
    const r = checkLinks(p, { resolver: resolverOf(subject, autonomous) });
    expect(r.outcome).toBe('checked-correct');
    expect(r.relations.find((x) => x.rel === 'ratifies')).toMatchObject({ outcome: 'checked-correct' });
    const agentSubject = held(record(4, { decider: agent }));
    const p2 = linkRecord(sorted([link('ratifies', autonomous.digest), link('subject', agentSubject.digest)]));
    expect(checkLinks(p2, { resolver: resolverOf(agentSubject, autonomous) }).relations.find((x) => x.rel === 'ratifies')).toMatchObject({
      outcome: 'checked-wrong', reason: 'link_rule_violated', rule: 'ratifies_decider_human',
    });
    // The subject not held: the rule that reads it is not checked, and the row names the subject.
    expect(checkLinks(p, { resolver: resolverOf(autonomous) }).relations.find((x) => x.rel === 'ratifies')).toMatchObject({
      outcome: 'not-checked', reason: 'not_in_bundle:link_target', targetHeld: true, missing: 'subject',
    });
  });

  it('names the subject when a reviews or supersedes row cannot read it', () => {
    const target = held(record(5));
    for (const rel of ['reviews', 'supersedes']) {
      const p = linkRecord(sorted([link(rel, target.digest), link('subject', D1)]));
      expect(checkLinks(p, { resolver: resolverOf(target) }).relations.find((x) => x.rel === rel)).toMatchObject({
        outcome: 'not-checked', reason: 'not_in_bundle:link_target', targetHeld: true, missing: 'subject',
      });
    }
  });

  describe('builds a link record under the rules the reader applies (subject in the child’s place)', () => {
    const subjectAgent = held(record(21, { decider: agent }));
    const subjectHuman = held(record(22, { decider: human('acct:u-1') }));
    const targetAgent = held(record(23, { decider: agent }));
    const targetHuman = held(record(24, { decider: human('acct:u-1') }));
    const targetOtherSystem = held(record(25, { aiSystemId: 'intake-model', decider: human('acct:u-2') }));
    const context = linkRecord(null);
    const relate = (rel: string, subject: HeldLinkTarget, target: HeldLinkTarget) =>
      buildLinks(
        [
          { rel, target: { digest: target.digest } },
          { rel: 'subject', target: { digest: subject.digest } },
        ],
        { held: [target, subject], allowReserved: ['subject'], linkRecord: true, context },
      );
    const readerRow = (rel: string, subject: HeldLinkTarget, target: HeldLinkTarget) =>
      checkLinks(linkRecord(sorted([link(rel, target.digest), link('subject', subject.digest)])), {
        resolver: resolverOf(subject, target),
      }).relations.find((x) => x.rel === rel);

    it.each([
      ['ratifies with an agent subject', 'ratifies', subjectAgent, targetAgent, 'ratifies_decider_human'],
      ['ratifies of a human decision', 'ratifies', subjectHuman, targetHuman, 'ratifies_target_not_human'],
      ['reviews by the subject’s own decider', 'reviews', subjectHuman, targetHuman, 'reviews_distinct_decider'],
      ['supersedes across systems', 'supersedes', subjectHuman, targetOtherSystem, 'supersedes_same_system'],
    ])('refuses %s, as the reader fails it', (_name, rel, subject, target, rule) => {
      expect(() => relate(rel, subject, target)).toThrow(expect.objectContaining({ code: 'link_rule_violated', rule }));
      expect(readerRow(rel, subject, target)).toMatchObject({ outcome: 'checked-wrong', reason: 'link_rule_violated', rule });
    });

    it.each([
      ['ratifies', subjectHuman, targetAgent],
      ['reviews', subjectHuman, targetAgent],
      ['supersedes', subjectHuman, targetHuman],
    ])('builds %s that holds, and the reader passes it', (rel, subject, target) => {
      expect(() => relate(rel, subject, target)).not.toThrow();
      expect(readerRow(rel, subject, target)).toMatchObject({ outcome: 'checked-correct' });
    });

    it('applies no subject rule when the subject is in another store', () => {
      const links = buildLinks(
        [
          { rel: 'ratifies', target: { digest: targetAgent.digest } },
          { rel: 'subject', target: { digest: D1, external: true } },
        ],
        { held: [targetAgent, null], allowReserved: ['subject'], linkRecord: true, context },
      );
      expect(links.map((l) => l.rel)).toEqual(['ratifies', 'subject']);
    });
  });
});

describe('buildLinks (capture, Record §8.7)', () => {
  const w2 = held(record(6));
  const w1 = held(record(1));
  const child = held(record(5, { links: [link('derivedFrom', w1.digest), link('root', w1.digest)] }));

  it('fills a same-store target, sorts, and adds the root of the first held lineage target', () => {
    const links = buildLinks([{ rel: 'derivedFrom', target: { evidenceId: w2.payload.evidenceId as string } }], { held: [w2] });
    const filled = { digest: w2.digest, evidenceId: w2.payload.evidenceId, locator: { origin: ORIGIN, seq: 6 } };
    expect(links).toEqual([
      { rel: 'derivedFrom', target: filled, attrs: null },
      { rel: 'root', target: filled, attrs: null },
    ]);
  });

  it("takes a held target's own root when it has one", () => {
    const links = buildLinks([{ rel: 'derivedFrom', target: { digest: child.digest } }], { held: [child] });
    expect(links.find((l) => l.rel === 'root')!.target.digest).toBe(w1.digest);
  });

  it('adds no root when no lineage target is held, or the first held one has lineage but no root', () => {
    expect(buildLinks([{ rel: 'derivedFrom', target: { digest: D1, external: true } }]).map((l) => l.rel)).toEqual(['derivedFrom']);
    const noRoot = held(record(8, { links: [link('derivedFrom', D1)] }));
    expect(buildLinks([{ rel: 'derivedFrom', target: { digest: noRoot.digest } }], { held: [noRoot] }).map((l) => l.rel)).toEqual(['derivedFrom']);
  });

  it('keeps an input locator: null, so the origin is not disclosed', () => {
    const links = buildLinks([{ rel: 'derivedFrom', target: { digest: w2.digest, locator: null } }], { held: [w2] });
    expect(links[0].target.locator).toBeNull();
  });

  it.each([
    ['an empty list', [], [], 'empty_links'],
    ['a missing same-store target', [{ rel: 'derivedFrom', target: { digest: D1 } }], [null], 'link_target_not_found'],
    ['a supplied digest that disagrees', [{ rel: 'derivedFrom', target: { digest: D1, evidenceId: w2.payload.evidenceId } }], [w2], 'link_target_mismatch'],
    ['a supplied locator seq that disagrees', [{ rel: 'derivedFrom', target: { digest: w2.digest, locator: { origin: ORIGIN, seq: 7 } } }], [w2], 'link_target_mismatch'],
    ['a supplied locator origin that disagrees', [{ rel: 'derivedFrom', target: { digest: w2.digest, locator: { origin: OTHER_ORIGIN, seq: 6 } } }], [w2], 'link_target_mismatch'],
    ['a reserved relation from a caller', [{ rel: 'mandate', target: { digest: w2.digest } }], [w2], 'relation_reserved'],
    ['fanoutOf', [{ rel: 'fanoutOf', target: { digest: w2.digest }, attrs: { slot: 1, statement: D1 } }], [w2], 'relation_not_writable'],
    ['an unknown relation', [{ rel: 'contests', target: { digest: w2.digest } }], [w2], 'unknown_relation'],
    ['an external target without a digest', [{ rel: 'derivedFrom', target: { external: true } }], [null], 'invalid_target_digest'],
    ['a repeated pair', [{ rel: 'appeals', target: { digest: w2.digest } }, { rel: 'appeals', target: { digest: w2.digest } }], [w2, w2], 'not_a_set'],
    ['an attribute outside the profile', [{ rel: 'appeals', target: { digest: w2.digest }, attrs: { note: 'x' } }], [w2], 'attrs_not_allowed'],
  ])('refuses %s', (_name, inputs, heldList, code) => {
    expect(() => buildLinks(inputs as never, { held: heldList as never })).toThrow(expect.objectContaining({ code }));
  });

  it('applies the target rules of same-store targets when given the record', () => {
    const other = held(record(9, { aiSystemId: 'intake-model' }));
    expect(() =>
      buildLinks([{ rel: 'supersedes', target: { digest: other.digest } }], { held: [other], context: payload(null) }),
    ).toThrow(expect.objectContaining({ code: 'link_rule_violated', rule: 'supersedes_same_system' }));
    const same = held(record(10));
    expect(() =>
      buildLinks([{ rel: 'reviews', target: { digest: same.digest } }], { held: [same], context: payload(null) }),
    ).toThrow(expect.objectContaining({ rule: 'reviews_distinct_decider' }));
  });
});

describe('checkLinks (reader rows, Verification §4.11)', () => {
  const w2 = held(record(6));
  const w2Target = { digest: w2.digest, evidenceId: w2.payload.evidenceId as string, locator: { origin: ORIGIN, seq: 6 } };
  const w3Links = (): Link[] => [
    { rel: 'derivedFrom', target: { ...w2Target }, attrs: null },
    { rel: 'root', target: { ...w2Target }, attrs: null },
  ];

  it('reads absent, the facts, and an abstaining edge per link', () => {
    expect(checkLinks(payload(null))).toEqual({ outcome: 'not-checked', valid: null, reason: 'absent', relations: [], edges: [] });
    const r = checkLinks(payload(w3Links()));
    expect(r).toMatchObject({ outcome: 'checked-correct', count: 2, relationNames: ['derivedFrom', 'root'], extensions: 0 });
    expect(r.edges).toEqual([
      { outcome: 'abstain', reason: 'unsupported_link_edge' },
      { outcome: 'abstain', reason: 'unsupported_link_edge' },
    ]);
    expect(r.relations).toEqual([
      { index: 0, rel: 'derivedFrom', outcome: 'checked-correct', valid: true, targetHeld: false },
      { index: 1, rel: 'root', outcome: 'checked-correct', valid: true, targetHeld: false },
    ]);
  });

  it('fails the list-level rules from the links row, so a missing link is not passed over', () => {
    const mandateForm = { mandateAssertion: D1, mandateSeq: 1, totals: null, confirm: false };
    expect(checkLinks(payload(null, { signoffExpectation: mandateForm }))).toMatchObject({
      outcome: 'checked-wrong', reason: 'link_rule_violated', rule: 'mandate_link',
    });
    expect(checkLinks(payload(null, { aiSystemId: 'tzun:mandate', action: 'revoke-mandate' }))).toMatchObject({ rule: 'revokes_link' });
    expect(checkLinks(payload(null, { aiSystemId: 'tzun:link', action: 'link' }))).toMatchObject({ rule: 'subject_link' });
    // A mandate link replaced by an extension: the mandate rule fails, never only an abstention.
    expect(checkLinks(payload([link('x-acme.mandate', D1)], { signoffExpectation: mandateForm }))).toMatchObject({ rule: 'mandate_link' });
    const r = checkLinks(payload([link('subject', D1)]));
    expect(r).toMatchObject({ outcome: 'checked-wrong', reason: 'link_rule_violated', rule: 'subject_link' });
    expect(r.relations[0]).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:links' });
  });

  it('blocks a mandate link on a malformed expectation, and does not apply the mandate rule', () => {
    const r = checkLinks(payload([link('mandate', D1)], { signoffExpectation: { mandateAssertion: D1, mandateSeq: 0, totals: null, confirm: false } }));
    expect(r.outcome).toBe('checked-correct');
    expect(r.relations[0]).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:signoff.expectation' });
  });

  it('reads malformed links with the rule and the link', () => {
    expect(checkLinks(payload([link('root', D1), link('derivedFrom', D1)]))).toMatchObject({
      outcome: 'checked-wrong', reason: 'malformed_links', rule: 'not_a_set', failedLink: 1,
    });
    expect(checkLinks(payload([]))).toMatchObject({ reason: 'malformed_links', rule: 'empty_links' });
  });

  it('abstains on an unknown relation, an unimplemented rule, and root beside an unknown relation', () => {
    const r = checkLinks(payload(sorted([link('contests', D1), link('x-acme.thing', D2, { a: 1 }), link('delegatedBy', D3)])));
    expect(r.outcome).toBe('checked-correct');
    expect(r.extensions).toBe(1);
    expect(r.relations.map((x) => [x.rel, x.outcome, x.reason])).toEqual([
      ['contests', 'abstain', 'unsupported_link_relation'],
      ['delegatedBy', 'abstain', 'unsupported_link_rule'],
      ['x-acme.thing', 'abstain', 'unsupported_link_relation'],
    ]);
    const rootBesideUnknown = checkLinks(payload(sorted([link('contests', D1), link('root', D1)])));
    expect(rootBesideUnknown.relations.find((x) => x.rel === 'root')).toMatchObject({ outcome: 'abstain', reason: 'unsupported_link_rule' });
    // An x- relation is never registered, so it can never be a lineage relation: root beside one alone fails.
    const rootBesideExtension = checkLinks(payload(sorted([link('x-acme.thing', D1), link('root', D1)])));
    expect(rootBesideExtension.relations.find((x) => x.rel === 'root')).toMatchObject({
      outcome: 'checked-wrong', reason: 'link_rule_violated', rule: 'root_without_lineage',
    });
    const closes = checkLinks(payload(sorted([link('closes', D1, { size: 2, statement: D2, treeRoot: D3 })])));
    expect(closes.relations[0]).toMatchObject({ outcome: 'abstain', reason: 'unsupported_link_rule' });
  });

  it('fails a broken profile and a broken record-local rule', () => {
    const r = checkLinks(payload(sorted([link('derivedFrom', D1, { 'x-acme.note': 'x' }), link('root', D2)])));
    expect(r.relations[0]).toMatchObject({ outcome: 'checked-wrong', reason: 'link_attrs_invalid' });
    expect(checkLinks(payload([link('root', D1)])).relations[0]).toMatchObject({ reason: 'link_rule_violated', rule: 'root_without_lineage' });
    expect(checkLinks(payload([link('ratifies', D1)], { decider: agent })).relations[0]).toMatchObject({ rule: 'ratifies_decider_human' });
    expect(checkLinks(payload([link('closes', D1, { size: 2 })])).relations[0]).toMatchObject({ reason: 'link_attrs_invalid' });
  });

  it('checks a held target member by member, resolving by digest first', () => {
    const resolver = resolverOf(w2);
    expect(checkLinks(payload(w3Links()), { resolver }).relations[0]).toMatchObject({ outcome: 'checked-correct', targetHeld: true });
    const otherId = w3Links();
    otherId[0].target.evidenceId = '5f0c1f0e-3333-4c3c-9c3c-000000000099';
    expect(checkLinks(payload(otherId), { resolver }).relations[0]).toMatchObject({ reason: 'link_target_mismatch', member: 'evidenceId' });
    const otherSeq = w3Links();
    otherSeq[0].target.locator = { origin: ORIGIN, seq: 5 };
    expect(checkLinks(payload(otherSeq), { resolver }).relations[0]).toMatchObject({ reason: 'link_target_mismatch', member: 'locator' });
    const otherOrigin = w3Links();
    otherOrigin[0].target.locator = { origin: OTHER_ORIGIN, seq: 6 };
    expect(checkLinks(payload(otherOrigin), { resolver }).relations[0]).toMatchObject({ reason: 'link_target_mismatch', member: 'locator' });
    // The held record was edited after the link named it: it no longer hashes to the link's digest.
    const edited = { ...w2, payload: { ...w2.payload, reason: 'edited' } };
    expect(checkLinks(payload(w3Links()), { resolver: resolverOf(edited) }).relations[0]).toMatchObject({
      reason: 'link_target_mismatch', member: 'digest',
    });
  });

  it('reads a same-store locator whose position holds another digest, or nothing, as a mismatch', () => {
    const resolver = { byDigest: () => null, isOwnOrigin: (o: string) => o === ORIGIN, digestAt: () => D3 };
    expect(checkLinks(payload(w3Links()), { resolver }).relations[0]).toMatchObject({ reason: 'link_target_mismatch', member: 'locator' });
    const empty = { ...resolver, digestAt: () => null };
    expect(checkLinks(payload(w3Links()), { resolver: empty }).relations[0]).toMatchObject({ reason: 'link_target_mismatch' });
  });

  it('checks the target rules of held targets, and reports one not held', () => {
    const otherSystem = held(record(11, { aiSystemId: 'intake-model' }));
    const supersedes = payload([link('supersedes', otherSystem.digest)]);
    expect(checkLinks(supersedes, { resolver: resolverOf(otherSystem) }).relations[0]).toMatchObject({
      reason: 'link_rule_violated', rule: 'supersedes_same_system',
    });
    expect(checkLinks(supersedes).relations[0]).toMatchObject({
      outcome: 'not-checked', reason: 'not_in_bundle:link_target', targetHeld: false, missing: 'target',
    });
    const humanTarget = held(record(12));
    expect(checkLinks(payload([link('ratifies', humanTarget.digest)]), { resolver: resolverOf(humanTarget) }).relations[0]).toMatchObject({
      rule: 'ratifies_target_not_human',
    });
  });

  it('leaves reviews undetermined on an unopened commitment, and decides it once opened', () => {
    const cmt = 'cmt:' + 'ab'.repeat(32);
    const reviewed = held(record(13, { decider: human(cmt) }));
    const p = payload([link('reviews', reviewed.digest)]);
    expect(checkLinks(p, { resolver: resolverOf(reviewed) }).relations[0]).toMatchObject({
      outcome: 'not-checked', reason: 'link_rule_undetermined', rule: 'reviews_distinct_decider',
    });
    const opened = { ...resolverOf(reviewed), openCommitment: (id: string) => (id === cmt ? 'acct:u-4821' : null) };
    expect(checkLinks(p, { resolver: opened }).relations[0]).toMatchObject({ reason: 'link_rule_violated' });
    const otherReviewer = { ...resolverOf(reviewed), openCommitment: (id: string) => (id === cmt ? 'acct:u-9' : null) };
    expect(checkLinks(p, { resolver: otherReviewer }).relations[0]).toMatchObject({ outcome: 'checked-correct' });
  });

  it('reports root facts, never a failure', () => {
    const child = held(record(14, { links: [link('derivedFrom', D1), link('root', D1)] }));
    const p = payload(sorted([link('derivedFrom', child.digest), link('root', child.digest)]));
    const r = checkLinks(p, { resolver: resolverOf(child) });
    expect(r.relations.find((x) => x.rel === 'root')).toMatchObject({ outcome: 'checked-correct', rootInconsistent: true });
  });

  it('declares link targets as step inputs only when the list is well formed', () => {
    expect([...linkTargetInputs(w3Links())]).toEqual([`sha256:${w2.digest}`]);
    expect(linkTargetInputs([w3Links()[1], w3Links()[0]]).size).toBe(0);
    expect(linkTargetInputs(null).size).toBe(0);
  });

  it('never throws on untrusted input', () => {
    for (const v of [null, 5, 'x', [], {}, { links: 'x' }, { links: [null] }, { links: [{ rel: 1 }] }]) {
      expect(() => checkLinks(v)).not.toThrow();
    }
  });
});
