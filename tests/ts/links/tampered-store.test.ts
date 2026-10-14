/**
 * The link service on a store someone has written to behind the adapter, on
 * every store: a rewritten record is never linked at capture, except as an
 * external target named by its stored digest, which is written as given and
 * reported by verification; `of` reports a rewritten record's links blocked
 * by its `links` row; the walk marks a rewritten node and a rewritten
 * asserting link record; and a deleted record's index rows are not returned.
 */
import { hex, captured, decision, human, refusalOf, removeSqliteFiles, storeLegs, type LinkedTzun } from './fixtures';
import { deleteStoredEnvelope, rewriteStoredEnvelope } from '../helpers/tamper-store';
import { pgSuiteSchema } from '../helpers/postgres-test-db';

const pg = pgSuiteSchema('links_tampered');
afterAll(() => removeSqliteFiles());

const COMPLAINT = hex('complaint');

describe.each(storeLegs(pg))('links over a tampered $name store', (leg) => {
  let s: LinkedTzun;
  beforeEach(async () => {
    s = await leg.open();
  });
  afterEach(async () => {
    await s.close();
  });

  it('refuses to link a record rewritten after capture, by evidence id or by digest', async () => {
    const target = await captured(s.tzun, decision('target'));
    await rewriteStoredEnvelope(s.tzun.getStorage(), target.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten after capture';
    });
    for (const t of [{ evidenceId: target.payload.evidenceId }, { digest: target.integrity.canonicalDigest }]) {
      expect(refusalOf(await s.tzun.capture({ ...decision('child'), links: [{ rel: 'derivedFrom', target: t }] }))).toMatchObject({
        code: 'link_target_mismatch',
        field: 'links[0].target.digest',
      });
    }
  });

  it('writes an external target named by the stored digest of a rewritten record as given; verification reports it', async () => {
    const target = await captured(s.tzun, decision('target'));
    await rewriteStoredEnvelope(s.tzun.getStorage(), target.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten after capture';
    });
    const given = { digest: target.integrity.canonicalDigest, evidenceId: target.payload.evidenceId, locator: null };
    const child = await captured(s.tzun, { ...decision('child'), links: [{ rel: 'appeals', target: { ...given, external: true } }] });
    expect(child.payload.links).toEqual([{ rel: 'appeals', target: given, attrs: null }]);
    const verdict = await s.tzun.verify(child.payload.evidenceId);
    expect(verdict.links?.relations[0]).toMatchObject({ index: 0, outcome: 'checked-wrong', reason: 'link_target_mismatch' });
  });

  it("of reports a rewritten record's links blocked by its links row", async () => {
    const parent = await captured(s.tzun, decision('parent'));
    const child = await captured(s.tzun, { ...decision('child'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] });
    await rewriteStoredEnvelope(s.tzun.getStorage(), child.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten';
    });
    const of = await s.links.of(child.payload.evidenceId);
    expect(of!.map((l) => [l.link.rel, l.held, l.check.outcome, l.check.reason])).toEqual([
      ['derivedFrom', true, 'not-checked', 'blocked_by:links'],
      ['root', true, 'not-checked', 'blocked_by:links'],
    ]);
  });

  it('the walk marks a rewritten node and a rewritten asserting link record', async () => {
    const w2 = await captured(s.tzun, decision('intake'));
    const w3 = await captured(s.tzun, { ...decision('underwriting'), links: [{ rel: 'derivedFrom', target: { evidenceId: w2.payload.evidenceId } }] });
    const lr = await s.links.relate({
      subject: { digest: COMPLAINT, external: true },
      relations: [{ rel: 'appeals', target: { evidenceId: w3.payload.evidenceId } }],
      reason: 'complaint',
      decider: human('acct:u-7702'),
    });
    await rewriteStoredEnvelope(s.tzun.getStorage(), w2.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten';
    });
    await rewriteStoredEnvelope(s.tzun.getStorage(), lr.envelope.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten';
    });
    expect((await s.links.to(w3.integrity.canonicalDigest, { rels: ['appeals'] })).rows).toEqual([
      expect.objectContaining({ evidenceId: lr.envelope.payload.evidenceId, statement: true, intact: false }),
    ]);
    const walk = await s.graph.walk(w3.payload.evidenceId);
    expect(walk.details[w2.integrity.canonicalDigest]).toMatchObject({ held: true, intact: false });
    expect(walk.details[w3.integrity.canonicalDigest]).toMatchObject({ held: true, intact: true });
    const statement = walk.edges.find((e) => e.statement)!;
    expect(statement).toMatchObject({ rel: 'appeals', assertedBy: lr.envelope.payload.evidenceId, assertedByIntact: false });
    expect(walk.edges.filter((e) => !e.statement).every((e) => e.assertedByIntact)).toBe(true);
  });

  it("a deleted record's index rows are not returned, and the walk draws nothing from them", async () => {
    const w3 = await captured(s.tzun, decision('underwriting'));
    const lr = await s.links.relate({
      subject: { digest: COMPLAINT, external: true },
      relations: [{ rel: 'appeals', target: { evidenceId: w3.payload.evidenceId } }],
      reason: 'complaint',
      decider: human('acct:u-7702'),
    });
    expect((await s.links.to(w3.integrity.canonicalDigest)).rows).toHaveLength(1);
    await deleteStoredEnvelope(s.tzun.getStorage(), lr.envelope.payload.evidenceId);
    if (leg.name === 'memory') {
      // The memory helper deletes the Map entry only; the adapter's own record list has to lose it too.
      const inner = s.tzun.getStorage() as unknown as { insertionOrder: string[] };
      inner.insertionOrder = inner.insertionOrder.filter((id) => id !== lr.envelope.payload.evidenceId);
    }
    expect((await s.links.to(w3.integrity.canonicalDigest)).rows).toEqual([]);
    const walk = await s.graph.walk(w3.payload.evidenceId);
    expect(walk.edges).toEqual([]);
  });
});
