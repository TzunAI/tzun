/**
 * The decision-graph walk on every store: a record's
 * own links, a link record's statements found through the link index, each
 * edge naming the record that asserts it; the depth bound, the node budget,
 * the one-page-per-node bound and the visited set; the relation filter; and
 * an index row that does not match its record drawing nothing.
 */
import { hex, captured, decision, human, removeSqliteFiles, storeLegs, sqlitePath, openLinked, type LinkedTzun } from './fixtures';
import { DecisionGraphError, DECISION_GRAPH_PAGE } from '../../../src/sdk/decision-graph';
import { pgSuiteSchema } from '../helpers/postgres-test-db';
import type { EvidenceEnvelope } from '@tzun/engine';

const pg = pgSuiteSchema('links_graph');
afterAll(() => removeSqliteFiles());

const COMPLAINT = hex('complaint C-1182');

/** W2 (intake), W3 (derivedFrom W2), and a link record: the complaint appeals W3 (W7). */
async function lending(s: LinkedTzun): Promise<{ w2: EvidenceEnvelope; w3: EvidenceEnvelope; w7: EvidenceEnvelope }> {
  const w2 = await captured(s.tzun, decision('intake'));
  const w3 = await captured(s.tzun, { ...decision('underwriting'), links: [{ rel: 'derivedFrom', target: { evidenceId: w2.payload.evidenceId } }] });
  const w7 = await s.links.relate({
    subject: { digest: COMPLAINT, evidenceId: 'C-1182', external: true },
    relations: [{ rel: 'appeals', target: { evidenceId: w3.payload.evidenceId } }],
    reason: 'Complaint C-1182 contests the underwriting decision',
    decider: human('acct:u-7702'),
  });
  if (!w7.stored) throw new Error('link record refused');
  return { w2, w3, w7: w7.envelope };
}

const edgeView = (e: { from: string; to: string; rel: string; assertedBy: string; statement: boolean }, names: Record<string, string>) =>
  `${names[e.from] ?? e.from.slice(0, 6)} -${e.rel}-> ${names[e.to] ?? e.to.slice(0, 6)} by ${names[e.assertedBy] ?? e.assertedBy}${e.statement ? ' (statement)' : ''}`;

describe.each(storeLegs(pg))('the decision graph on $name', (leg) => {
  let s: LinkedTzun;
  beforeEach(async () => {
    s = await leg.open();
  });
  afterEach(async () => {
    await s.close();
  });

  it("walks a record's own links and the statements of link records about it, each edge naming its asserter", async () => {
    const { w2, w3, w7 } = await lending(s);
    const walk = await s.graph.walk(w3.payload.evidenceId);
    const names: Record<string, string> = {
      [w2.integrity.canonicalDigest]: 'W2',
      [w3.integrity.canonicalDigest]: 'W3',
      [COMPLAINT]: 'C',
      [w3.payload.evidenceId]: 'W3',
      [w7.payload.evidenceId]: 'W7',
    };
    expect(walk.root).toBe(w3.integrity.canonicalDigest);
    expect(walk.rootEvidenceId).toBe(w3.payload.evidenceId);
    expect(walk.nodes.map((d) => names[d])).toEqual(['W3', 'W2', 'C']);
    expect(walk.edges.map((e) => edgeView(e, names))).toEqual(['W3 -derivedFrom-> W2 by W3', 'W3 -root-> W2 by W3', 'C -appeals-> W3 by W7 (statement)']);
    const statement = walk.edges[2];
    expect(statement).toMatchObject({ decider: { kind: 'human', id: 'acct:u-7702' }, assertedByIntact: true, linkIndex: 0, assertedByDigest: w7.integrity.canonicalDigest });
    // The link record is the asserter, not a node; the complaint is held elsewhere.
    expect(walk.details[COMPLAINT]).toMatchObject({ held: false, evidenceId: 'C-1182', depth: 1 });
    expect(walk.details[w2.integrity.canonicalDigest]).toMatchObject({ held: true, intact: true, depth: 1, aiSystemId: w2.payload.aiSystemId });
    expect(walk.truncated).toBe(false);
    expect(walk.truncatedBy).toEqual([]);
  });

  it('from a link record: its subject link and its statements', async () => {
    const { w2, w3, w7 } = await lending(s);
    const walk = await s.graph.walk(w7.payload.evidenceId);
    const names: Record<string, string> = {
      [w2.integrity.canonicalDigest]: 'W2',
      [w3.integrity.canonicalDigest]: 'W3',
      [w7.integrity.canonicalDigest]: 'W7',
      [COMPLAINT]: 'C',
      [w3.payload.evidenceId]: 'W3',
      [w7.payload.evidenceId]: 'W7',
    };
    expect(walk.nodes.map((d) => names[d])).toEqual(['W7', 'C', 'W3', 'W2']);
    expect(walk.edges.map((e) => edgeView(e, names))).toEqual([
      'C -appeals-> W3 by W7 (statement)',
      'W7 -subject-> C by W7',
      'W3 -derivedFrom-> W2 by W3',
      'W3 -root-> W2 by W3',
    ]);
  });

  it('follows only outbound links and statements: the intake record does not reach the records derived from it', async () => {
    const { w2 } = await lending(s);
    const walk = await s.graph.walk(w2.payload.evidenceId);
    expect(walk.nodes).toEqual([w2.integrity.canonicalDigest]);
    expect(walk.edges).toEqual([]);
  });

  it('stops at the depth bound and the node budget, and says so', async () => {
    const { w3 } = await lending(s);
    const shallow = await s.graph.walk(w3.payload.evidenceId, { depth: 0 });
    expect(shallow.nodes).toEqual([w3.integrity.canonicalDigest]);
    expect(shallow.edges).toEqual([]);
    expect(shallow).toMatchObject({ truncated: true, truncatedBy: ['depth'] });
    const one = await s.graph.walk(w3.payload.evidenceId, { depth: 1 });
    expect(one.nodes).toHaveLength(3);
    expect(one.truncated).toBe(false);
    const small = await s.graph.walk(w3.payload.evidenceId, { maxNodes: 2 });
    expect(small.nodes).toHaveLength(2);
    expect(small).toMatchObject({ truncated: true, truncatedBy: ['maxNodes'] });
    // Every edge drawn joins two nodes of the walk.
    expect(small.edges.every((e) => small.nodes.includes(e.from) && small.nodes.includes(e.to))).toBe(true);
  });

  it('takes both endpoints of an edge or neither: no node is left without an edge', async () => {
    const w3 = await captured(s.tzun, decision('w3'));
    const w4 = await captured(s.tzun, decision('w4'));
    const r = await s.links.relate({
      subject: { digest: COMPLAINT, external: true },
      relations: [
        { rel: 'appeals', target: { evidenceId: w3.payload.evidenceId } },
        { rel: 'appeals', target: { evidenceId: w4.payload.evidenceId } },
      ],
      reason: 'one complaint, two decisions',
      decider: human('acct:u-7702'),
    });
    expect(r.stored).toBe(true);
    // From W3: the complaint fits the budget of 2, the second statement's W4 does not.
    const walk = await s.graph.walk(w3.payload.evidenceId, { maxNodes: 2 });
    expect(walk.nodes).toEqual([w3.integrity.canonicalDigest, COMPLAINT]);
    expect(walk.edges).toHaveLength(1);
    expect(walk.truncatedBy).toEqual(['maxNodes']);
    const full = await s.graph.walk(w3.payload.evidenceId);
    expect(new Set(full.nodes)).toEqual(new Set([w3.integrity.canonicalDigest, COMPLAINT, w4.integrity.canonicalDigest]));
    for (const node of full.nodes.slice(1)) expect(full.edges.some((e) => e.from === node || e.to === node)).toBe(true);
  });

  it('follows only the named relations', async () => {
    const { w3 } = await lending(s);
    const walk = await s.graph.walk(w3.payload.evidenceId, { rels: ['appeals'] });
    expect(walk.edges.map((e) => e.rel)).toEqual(['appeals']);
    expect(walk.nodes).toEqual([w3.integrity.canonicalDigest, COMPLAINT]);
  });

  it('terminates on a cycle that link records state', async () => {
    const a = await captured(s.tzun, decision('a'));
    const b = await captured(s.tzun, decision('b'));
    for (const [subject, target] of [
      [a, b],
      [b, a],
    ]) {
      const r = await s.links.relate({
        subject: { evidenceId: subject.payload.evidenceId },
        relations: [{ rel: 'supersedes', target: { evidenceId: target.payload.evidenceId } }],
        reason: 'disputed order',
        decider: human('acct:u-1'),
      });
      expect(r.stored).toBe(true);
    }
    const walk = await s.graph.walk(a.payload.evidenceId);
    expect(new Set(walk.nodes)).toEqual(new Set([a.integrity.canonicalDigest, b.integrity.canonicalDigest]));
    expect(walk.edges.map((e) => `${e.from === a.integrity.canonicalDigest ? 'A' : 'B'}->${e.to === a.integrity.canonicalDigest ? 'A' : 'B'}`).sort()).toEqual(['A->B', 'B->A']);
    expect(walk.edges.every((e) => e.statement)).toBe(true);
    expect(walk.truncated).toBe(false);
  });

  it('refuses a walk it cannot run', async () => {
    await expect(s.graph.walk('no-such-record')).rejects.toMatchObject({ code: 'record_not_found' });
    await expect(s.graph.walk('')).rejects.toBeInstanceOf(DecisionGraphError);
    const any = await captured(s.tzun, decision('any'));
    await expect(s.graph.walk(any.payload.evidenceId, { depth: -1 })).rejects.toMatchObject({ code: 'invalid_depth' });
    await expect(s.graph.walk(any.payload.evidenceId, { depth: 257 })).rejects.toMatchObject({ code: 'invalid_depth' });
    await expect(s.graph.walk(any.payload.evidenceId, { maxNodes: 0 })).rejects.toMatchObject({ code: 'invalid_max_nodes' });
    await expect(s.graph.walk(any.payload.evidenceId, { rels: ['Bad Rel'] })).rejects.toMatchObject({ code: 'invalid_relation' });
  });
});

describe('the decision graph, bounded and not led by the index', () => {
  it('reads one page of link records per node: a flood of statements is truncated, not scanned', async () => {
    const s = await openLinked({});
    try {
      const target = await captured(s.tzun, decision('popular'));
      for (let i = 0; i <= DECISION_GRAPH_PAGE; i++) {
        const r = await s.links.relate({
          subject: { digest: hex(`complaint ${i}`), external: true },
          relations: [{ rel: 'appeals', target: { evidenceId: target.payload.evidenceId } }],
          reason: `complaint ${i}`,
          decider: human('acct:u-5'),
        });
        expect(r.stored).toBe(true);
      }
      const walk = await s.graph.walk(target.payload.evidenceId);
      expect(walk.edges).toHaveLength(DECISION_GRAPH_PAGE);
      expect(walk).toMatchObject({ truncated: true, truncatedBy: ['page'] });
    } finally {
      await s.close();
    }
  });

  it('draws nothing from an index row that does not match the link its record carries', async () => {
    const s = await openLinked({ dbPath: sqlitePath() });
    try {
      const { w2, w7 } = await lending(s);
      // A forged row: W7 states nothing towards W2, and has no link at index 5.
      const db = ((s.host.storage as unknown as { unwrap(): unknown }).unwrap() as { db: { prepare(sql: string): { run(...a: unknown[]): void } } }).db;
      db.prepare('INSERT INTO evidence_links (evidence_id, idx, rel, target_digest, subject_digest) VALUES (?, 5, ?, ?, ?)').run(
        w7.payload.evidenceId,
        'appeals',
        w2.integrity.canonicalDigest,
        COMPLAINT,
      );
      // The index holds the row; `to` and the walk read W7 and find no such link.
      expect((await s.links.to(w2.integrity.canonicalDigest, { rels: ['appeals'] })).rows).toHaveLength(0);
      const walk = await s.graph.walk(w2.payload.evidenceId);
      expect(walk.edges).toEqual([]);
      expect(walk.nodes).toEqual([w2.integrity.canonicalDigest]);
    } finally {
      await s.close();
    }
  });

  it("draws nothing from a row whose relation and index match a link record's link but whose target is another digest", async () => {
    const s = await openLinked({ dbPath: sqlitePath() });
    try {
      const { w2, w7 } = await lending(s);
      // W7's appeals row (index 0) is rewritten to name W2: what a writer of the database can do once it drops the trigger.
      const db = ((s.host.storage as unknown as { unwrap(): unknown }).unwrap() as { db: { exec(sql: string): void } }).db;
      db.exec(
        `DROP TRIGGER evidence_links_block_update;
         UPDATE evidence_links SET target_digest = '${w2.integrity.canonicalDigest}' WHERE evidence_id = '${w7.payload.evidenceId}' AND idx = 0;`,
      );
      // W3's own links name W2; nothing of W7 does.
      expect((await s.links.to(w2.integrity.canonicalDigest)).rows.map((r) => r.rel)).toEqual(['derivedFrom', 'root']);
      const walk = await s.graph.walk(w2.payload.evidenceId);
      expect(walk.edges).toEqual([]);
      expect(walk.nodes).toEqual([w2.integrity.canonicalDigest]);
    } finally {
      await s.close();
    }
  });
});
