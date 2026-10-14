/**
 * `tzun.links` on every store: `relate` captures
 * a link record (`tzun:link`, a `subject` link, no `root`) whose relations
 * are judged with the subject in the child's place; `of` lists a record's
 * links with their resolution and their store-level row; `to` lists, a page
 * at a time, the records that name a digest, telling a link record's
 * statement from a record's own link, and confirms every index row against
 * the record it names.
 */
import { Pool } from 'pg';
import { LINK_RECORD_AI_SYSTEM_ID } from '@tzun/engine';
import { LinkIndexQueryError } from '../../../src/storage/links-sql';
import { hex, captured, decision, human, refusalOf, removeSqliteFiles, storeLegs, type LinkedTzun } from './fixtures';
import { pgSuiteSchema } from '../helpers/postgres-test-db';

const pg = pgSuiteSchema('links_relate');
afterAll(() => removeSqliteFiles());

const COMPLAINT = hex('complaint C-1182');
const complainant = human('acct:u-7702');

/** Run a statement on the store's own database, behind the adapter (the SQL legs). */
async function behindTheAdapter(leg: 'sqlite' | 'postgres', s: LinkedTzun, statement: string): Promise<void> {
  if (leg === 'sqlite') {
    const inner = (s.host.storage as unknown as { unwrap(): unknown }).unwrap() as { db: { exec(sql: string): void } };
    inner.db.exec(statement);
    return;
  }
  const pool = new Pool({ connectionString: pg.url });
  try {
    await pool.query(statement);
  } finally {
    await pool.end();
  }
}

describe.each(storeLegs(pg))('tzun.links on $name', (leg) => {
  let s: LinkedTzun;
  beforeEach(async () => {
    s = await leg.open();
  });
  afterEach(async () => {
    await s.close();
  });

  it('relate captures a link record: a subject held elsewhere appeals a decision held here (W7)', async () => {
    const w3 = await captured(s.tzun, decision('underwriting'));
    const result = await s.links.relate({
      subject: { digest: COMPLAINT, external: true },
      relations: [{ rel: 'appeals', target: { evidenceId: w3.payload.evidenceId } }],
      reason: 'Complaint C-1182 contests the underwriting decision',
      decider: complainant,
    });
    expect(result.stored).toBe(true);
    const p = result.envelope.payload;
    expect(p.aiSystemId).toBe(LINK_RECORD_AI_SYSTEM_ID);
    expect(p.action).toBe('link');
    expect(p.aiOutput).toEqual({});
    expect(p.contributions).toBeNull();
    const origin = await s.host.evidenceLogOrigin('default');
    // No root link in a link record, although its target is held.
    expect(p.links).toEqual([
      { rel: 'appeals', target: { digest: w3.integrity.canonicalDigest, evidenceId: w3.payload.evidenceId, locator: { origin, seq: 1 } }, attrs: null },
      { rel: 'subject', target: { digest: COMPLAINT, evidenceId: null, locator: null }, attrs: null },
    ]);
    const verdict = await s.tzun.verify(p.evidenceId);
    expect(verdict.verified).toBe(true);
    expect(verdict.links?.outcome).toBe('checked-correct');
  });

  it("judges a link record's relations with a held subject in the child's place", async () => {
    const autonomous = await captured(s.tzun, { ...decision('autonomous'), decider: { kind: 'policy-engine', agent: `sha256:${hex('engine')}` } });
    const humanSubject = await captured(s.tzun, decision('human follow-up', human('acct:u-3')));
    const agentSubject = await captured(s.tzun, { ...decision('agent follow-up'), decider: { kind: 'agent', agent: `sha256:${hex('agent')}` } });
    // ratifies in a link record: the subject's decider is a human, the target's is not.
    const ok = await s.links.relate({
      subject: { evidenceId: humanSubject.payload.evidenceId },
      relations: [{ rel: 'ratifies', target: { evidenceId: autonomous.payload.evidenceId } }],
      reason: 'the follow-up ratifies the autonomous decision',
      decider: human('acct:u-9'),
    });
    expect(ok.stored).toBe(true);
    expect(
      refusalOf(
        await s.links.relate({
          subject: { evidenceId: agentSubject.payload.evidenceId },
          relations: [{ rel: 'ratifies', target: { evidenceId: autonomous.payload.evidenceId } }],
          reason: 'an agent cannot ratify',
          decider: human('acct:u-9'),
        }),
      ),
    ).toMatchObject({ code: 'link_rule_violated', rule: 'ratifies_decider_human' });
  });

  it('refuses a link record without a relation, with a reserved or root relation, or naming its subject as a target', async () => {
    const held = await captured(s.tzun, decision('held'));
    const base = { subject: { digest: COMPLAINT, external: true }, reason: 'r', decider: complainant };
    // The payload gate names the member (`links`), the code says which kind of rule.
    expect(refusalOf(await s.links.relate({ ...base, relations: [] }))).toMatchObject({ code: 'required_link_missing', field: 'links' });
    expect(refusalOf(await s.links.relate({ ...base, relations: [{ rel: 'mandate', target: { evidenceId: held.payload.evidenceId } }] }))).toMatchObject({
      code: 'relation_reserved',
    });
    expect(refusalOf(await s.links.relate({ ...base, relations: [{ rel: 'closes', target: { digest: hex('x'), external: true } }] }))).toMatchObject({
      code: 'relation_not_writable',
    });
    expect(
      refusalOf(
        await s.links.relate({
          ...base,
          relations: [
            { rel: 'derivedFrom', target: { evidenceId: held.payload.evidenceId } },
            { rel: 'root', target: { evidenceId: held.payload.evidenceId } },
          ],
        }),
      ),
    ).toMatchObject({ code: 'link_rule_violated', field: 'links', linkRule: 'subject_link' });
    // The subject's digest as a target under another relation: the subject rule.
    expect(refusalOf(await s.links.relate({ ...base, relations: [{ rel: 'appeals', target: { digest: COMPLAINT, external: true } }] }))).toMatchObject({
      code: 'link_rule_violated',
      field: 'links',
      linkRule: 'subject_link',
    });
    expect(await s.host.storage.getChainLength()).toBe(1);
  });

  it('replays a keyed relate, and prepares the link record a signature would be made over', async () => {
    const held = await captured(s.tzun, decision('held'));
    const request = {
      subject: { digest: COMPLAINT, external: true },
      relations: [{ rel: 'appeals', target: { evidenceId: held.payload.evidenceId } }],
      reason: 'keyed',
      decider: complainant,
    };
    const prepared = await s.links.prepareRelate(request);
    expect(prepared.links!.map((l) => l.rel)).toEqual(['appeals', 'subject']);
    expect(prepared.sequenceNumber).toBe(2);
    const first = await s.links.relate(request, { idempotencyKey: 'relate-1' });
    const again = await s.links.relate(request, { idempotencyKey: 'relate-1' });
    expect(again.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
    expect(await s.host.storage.getChainLength()).toBe(2);
  });

  it('of lists a record’s links with their resolution and their store-level row', async () => {
    const parent = await captured(s.tzun, decision('parent'));
    const child = await captured(s.tzun, {
      ...decision('child', human('acct:u-2')),
      links: [
        { rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } },
        { rel: 'reviews', target: { digest: hex('elsewhere'), external: true } },
        { rel: 'x-acme.contract', target: { digest: hex('contract'), external: true }, attrs: { ref: 'K-9' } },
      ],
    });
    const of = await s.links.of(child.payload.evidenceId);
    expect(of!.map((l) => [l.link.rel, l.held, l.check.outcome, l.check.reason ?? null])).toEqual([
      ['derivedFrom', true, 'checked-correct', null],
      ['reviews', false, 'not-checked', 'not_in_bundle:link_target'],
      ['root', true, 'checked-correct', null],
      ['x-acme.contract', false, 'abstain', 'unsupported_link_relation'],
    ]);
    expect(of![0].target).toEqual({ evidenceId: parent.payload.evidenceId, chainId: 'default', sequenceNumber: 1 });
    expect(of![1].target).toBeNull();
    expect(await s.links.of(parent.payload.evidenceId)).toEqual([]);
    expect(await s.links.of('no-such-record')).toBeNull();
  });

  it('to lists the records naming a digest, a page at a time, telling statements from own links', async () => {
    const w3 = await captured(s.tzun, decision('underwriting'));
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      ids.push((await captured(s.tzun, { ...decision(`child ${i}`), links: [{ rel: 'derivedFrom', target: { evidenceId: w3.payload.evidenceId } }] })).payload.evidenceId);
    }
    const lr = await s.links.relate({
      subject: { digest: COMPLAINT, external: true },
      relations: [{ rel: 'appeals', target: { evidenceId: w3.payload.evidenceId } }],
      reason: 'complaint',
      decider: complainant,
    });
    const digest = w3.integrity.canonicalDigest;
    const rows = [];
    let page = await s.links.to(digest, { limit: 3 });
    rows.push(...page.rows);
    while (page.cursor !== null) {
      page = await s.links.to(digest, { limit: 3, cursor: page.cursor });
      rows.push(...page.rows);
    }
    // Three children, each with a derivedFrom and a root link, and one statement.
    expect(rows).toHaveLength(7);
    const statement = rows.find((r) => r.evidenceId === lr.envelope.payload.evidenceId)!;
    expect(statement).toMatchObject({ rel: 'appeals', linkRecord: true, statement: true, subjectDigest: COMPLAINT, idx: 0, intact: true });
    expect(rows.filter((r) => !r.statement).every((r) => ids.includes(r.evidenceId) && !r.linkRecord)).toBe(true);
    expect((await s.links.to(digest, { rels: ['appeals'] })).rows.map((r) => r.evidenceId)).toEqual([lr.envelope.payload.evidenceId]);
    // The subject row: a link record about the complaint, not a statement.
    expect((await s.links.to(COMPLAINT)).rows).toEqual([
      expect.objectContaining({ evidenceId: lr.envelope.payload.evidenceId, rel: 'subject', linkRecord: true, statement: false, subjectDigest: null }),
    ]);
  });

  if (leg.name !== 'memory') {
    const sql = leg.name;
    it('to confirms each index row against its record: a row the record does not carry is left out', async () => {
      const a = await captured(s.tzun, decision('a'));
      const b = await captured(s.tzun, decision('b'));
      const digest = a.integrity.canonicalDigest;
      // A forged row: B is no link record and has no links; it would read as a statement about A.
      await behindTheAdapter(
        sql,
        s,
        `INSERT INTO evidence_links (evidence_id, idx, rel, target_digest, subject_digest)
         VALUES ('${b.payload.evidenceId}', 7, 'reviews', '${digest}', '${hex('fake subject')}')`,
      );
      expect(await s.links.to(digest)).toEqual({ rows: [], cursor: null });
      // A row the record carries is kept, and described from the record.
      const child = await captured(s.tzun, { ...decision('child'), links: [{ rel: 'derivedFrom', target: { evidenceId: a.payload.evidenceId } }] });
      expect((await s.links.to(digest)).rows).toEqual([
        { evidenceId: child.payload.evidenceId, idx: 0, rel: 'derivedFrom', targetDigest: digest, subjectDigest: null, linkRecord: false, statement: false, intact: true },
        { evidenceId: child.payload.evidenceId, idx: 1, rel: 'root', targetDigest: digest, subjectDigest: null, linkRecord: false, statement: false, intact: true },
      ]);
    });

    it("to names a statement's subject from the link record, not from the index row", async () => {
      const w3 = await captured(s.tzun, decision('underwriting'));
      const lr = await s.links.relate({
        subject: { digest: COMPLAINT, external: true },
        relations: [{ rel: 'appeals', target: { evidenceId: w3.payload.evidenceId } }],
        reason: 'complaint',
        decider: complainant,
      });
      // The row's subject rewritten behind the adapter, the update trigger dropped first.
      const drop = sql === 'sqlite' ? 'DROP TRIGGER evidence_links_block_update' : 'DROP TRIGGER evidence_links_block_mutation_trigger ON evidence_links';
      await behindTheAdapter(sql, s, drop);
      await behindTheAdapter(sql, s, `UPDATE evidence_links SET subject_digest = '${hex('another subject')}' WHERE evidence_id = '${lr.envelope.payload.evidenceId}' AND idx = 0`);
      expect((await s.links.to(w3.integrity.canonicalDigest)).rows).toEqual([
        expect.objectContaining({ evidenceId: lr.envelope.payload.evidenceId, rel: 'appeals', statement: true, subjectDigest: COMPLAINT }),
      ]);
    });
  }

  it('to refuses a malformed query', async () => {
    await expect(s.links.to('not-a-digest')).rejects.toBeInstanceOf(LinkIndexQueryError);
    await expect(s.links.to(hex('x'), { limit: 500 })).rejects.toMatchObject({ code: 'invalid_limit' });
    await expect(s.links.to(hex('x'), { cursor: '!!' })).rejects.toMatchObject({ code: 'invalid_cursor' });
  });
});

describe('the required links, through capture', () => {
  it('refuses what the list-level rules and the writer rules refuse', async () => {
    const [memory] = storeLegs(pg);
    const s = await memory.open();
    try {
      const p = await captured(s.tzun, decision('parent'));
      const at = (links: unknown[]) => s.tzun.capture({ ...decision('x'), links: links as never });
      expect(refusalOf(await at([]))).toMatchObject({ code: 'empty_links' });
      expect(refusalOf(await at([{ rel: 'root', target: { evidenceId: p.payload.evidenceId } }]))).toMatchObject({ code: 'root_without_lineage' });
      expect(
        refusalOf(
          await at([
            { rel: 'derivedFrom', target: { evidenceId: p.payload.evidenceId } },
            { rel: 'root', target: { evidenceId: p.payload.evidenceId } },
            { rel: 'root', target: { digest: hex('other root'), external: true } },
          ]),
        ),
      ).toMatchObject({ code: 'link_rule_violated', field: 'links', linkRule: 'at_most_one' });
      expect(refusalOf(await at([{ rel: 'revokes', target: { evidenceId: p.payload.evidenceId } }]))).toMatchObject({ code: 'relation_reserved' });
      expect(refusalOf(await at([{ rel: 'fanoutOf', target: { evidenceId: p.payload.evidenceId }, attrs: { slot: 1, statement: hex('s') } }]))).toMatchObject({
        code: 'relation_not_writable',
      });
      expect(refusalOf(await at([{ rel: 'fooBar', target: { evidenceId: p.payload.evidenceId } }]))).toMatchObject({ code: 'unknown_relation' });
      expect(refusalOf(await at([{ rel: 'derivedFrom', target: { evidenceId: p.payload.evidenceId }, attrs: { note: 'x' } }]))).toMatchObject({
        code: 'attrs_not_allowed',
      });
      // A revocation record must carry its revokes link; a link record its subject.
      const revocation = await s.host.captureSystemRecord({
        kind: 'mandate',
        aiOutput: { mandateDigest: hex('mandate') },
        action: 'revoke-mandate',
        reason: 'revoked',
        decider: human(),
        links: null,
      });
      expect(refusalOf(revocation)).toMatchObject({ code: 'required_link_missing', field: 'links' });
      const noSubject = await s.host.captureSystemRecord({
        kind: 'link',
        aiOutput: {},
        action: 'link',
        reason: 'no subject',
        decider: human(),
        links: [{ rel: 'appeals', target: { evidenceId: p.payload.evidenceId } }],
        linkRecord: true,
      });
      expect(refusalOf(noSubject)).toMatchObject({ code: 'required_link_missing', field: 'links' });
      expect(await s.host.storage.getChainLength()).toBe(1);
    } finally {
      await s.close();
    }
  });
});
