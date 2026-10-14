/**
 * Link-target resolution at capture,
 * through `Tzun.capture()` with the link service installed, on every store: a
 * same-store target named by evidence id or digest and filled from the held
 * record; each member the caller supplies checked against it; an `external`
 * target written as given unless it resolves here (by evidence id, digest or
 * a locator of this store); `locator: null` kept; the `root` link; the target
 * rules of held targets; a list over the link limit refused before any read;
 * and resolution that never leaves the store.
 */
import { hex, captured, decision, human, refusalOf, removeSqliteFiles, storeLegs, type LinkedTzun, openLinked } from './fixtures';
import { pgSuiteSchema } from '../helpers/postgres-test-db';

const pg = pgSuiteSchema('links_capture');
afterAll(() => removeSqliteFiles());

describe.each(storeLegs(pg))('link capture on $name', (leg) => {
  let s: LinkedTzun;
  beforeEach(async () => {
    s = await leg.open();
  });
  afterEach(async () => {
    await s.close();
  });

  it('resolves a target by evidence id: digest, evidence id and locator filled, the root added', async () => {
    const parent = await captured(s.tzun, decision('intake'));
    const child = await captured(s.tzun, { ...decision('underwriting'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] });
    const origin = await s.host.evidenceLogOrigin('default');
    const target = { digest: parent.integrity.canonicalDigest, evidenceId: parent.payload.evidenceId, locator: { origin, seq: 1 } };
    expect(child.payload.links).toEqual([
      { rel: 'derivedFrom', target, attrs: null },
      { rel: 'root', target, attrs: null },
    ]);
    const verdict = await s.tzun.verify(child.payload.evidenceId);
    expect(verdict.verified).toBe(true);
    expect(verdict.links).toMatchObject({ outcome: 'checked-correct', count: 2 });
    expect(verdict.links!.relations.map((r) => [r.outcome, r.targetHeld])).toEqual([
      ['checked-correct', true],
      ['checked-correct', true],
    ]);
  });

  it('resolves a target by digest alone; a locator of this store resolves an external target only', async () => {
    const parent = await captured(s.tzun, decision('parent'));
    const byDigest = await captured(s.tzun, { ...decision('by digest'), links: [{ rel: 'implements', target: { digest: parent.integrity.canonicalDigest } }] });
    expect(byDigest.payload.links![0].target.evidenceId).toBe(parent.payload.evidenceId);
    const origin = (await s.host.evidenceLogOrigin('default'))!;
    // A same-store target is resolved by evidence id, otherwise by digest.
    expect(refusalOf(await s.tzun.capture({ ...decision('by locator'), links: [{ rel: 'appeals', target: { locator: { origin, seq: 1 } } }] }))).toMatchObject({
      code: 'link_target_not_found',
      field: 'links[0].target',
    });
    const byLocator = await captured(s.tzun, { ...decision('by locator'), links: [{ rel: 'appeals', target: { locator: { origin, seq: 1 }, external: true } }] });
    expect(byLocator.payload.links![0].target).toEqual({ digest: parent.integrity.canonicalDigest, evidenceId: parent.payload.evidenceId, locator: { origin, seq: 1 } });
  });

  it('resolves by the evidence id when one is given: a digest of a held record does not stand in for an id it does not hold', async () => {
    const held = await captured(s.tzun, decision('held'));
    expect(
      refusalOf(await s.tzun.capture({ ...decision('missing id'), links: [{ rel: 'derivedFrom', target: { evidenceId: 'missing', digest: held.integrity.canonicalDigest } }] })),
    ).toMatchObject({ code: 'link_target_not_found', field: 'links[0].target' });
  });

  it('judges a locator seq that is not a position by the locator grammar', async () => {
    await captured(s.tzun, decision('one'));
    const origin = (await s.host.evidenceLogOrigin('default'))!;
    const malformed = { origin, seq: '1' as unknown as number };
    expect(
      refusalOf(await s.tzun.capture({ ...decision('seq'), links: [{ rel: 'derivedFrom', target: { digest: hex('ghost'), locator: malformed, external: true } }] })),
    ).toMatchObject({ code: 'invalid_locator' });
    expect(refusalOf(await s.tzun.capture({ ...decision('seq'), links: [{ rel: 'derivedFrom', target: { locator: malformed } }] }))).toMatchObject({
      code: 'link_target_not_found',
    });
  });

  it('refuses a supplied member that disagrees with the held record: digest, evidence id, locator seq, locator origin', async () => {
    const a = await captured(s.tzun, decision('a'));
    const b = await captured(s.tzun, decision('b'));
    const origin = (await s.host.evidenceLogOrigin('default'))!;
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ evidenceId: a.payload.evidenceId, digest: b.integrity.canonicalDigest }, 'links[0].target.digest'],
      [{ digest: a.integrity.canonicalDigest, evidenceId: b.payload.evidenceId }, 'links[0].target.digest'],
      [{ evidenceId: a.payload.evidenceId, locator: { origin, seq: 2 } }, 'links[0].target.locator'],
      [{ evidenceId: a.payload.evidenceId, locator: { origin: `example.com/${'0'.repeat(32)}/evidence/64656661756c74`, seq: 1 } }, 'links[0].target.locator'],
    ];
    for (const [target, field] of cases) {
      const refused = refusalOf(await s.tzun.capture({ ...decision('mismatch'), links: [{ rel: 'derivedFrom', target }] }));
      expect(refused).toMatchObject({ code: 'link_target_mismatch', field });
    }
    // Resolved by evidence id first: the evidence id names a, the digest b.
    expect(await s.host.storage.getChainLength()).toBe(2);
  });

  it('refuses a same-store target this store does not hold, by evidence id, digest or locator', async () => {
    await captured(s.tzun, decision('only'));
    const origin = (await s.host.evidenceLogOrigin('default'))!;
    for (const target of [{ evidenceId: 'nope' }, { digest: hex('nothing') }, { locator: { origin, seq: 9 } }, {}]) {
      expect(refusalOf(await s.tzun.capture({ ...decision('missing'), links: [{ rel: 'derivedFrom', target }] }))).toMatchObject({
        code: 'link_target_not_found',
        field: 'links[0].target',
      });
    }
  });

  it('writes an external target as given, and handles one this store holds as a same-store target', async () => {
    const held = await captured(s.tzun, decision('held'));
    const elsewhere = { origin: `other.example/${'1'.repeat(32)}/evidence/64656661756c74`, seq: 7 };
    const out = await captured(s.tzun, {
      ...decision('external'),
      links: [
        { rel: 'derivedFrom', target: { digest: hex('elsewhere'), evidenceId: 'case-17', locator: elsewhere, external: true } },
        { rel: 'appeals', target: { digest: held.integrity.canonicalDigest, external: true } },
      ],
    });
    const origin = await s.host.evidenceLogOrigin('default');
    const heldTarget = { digest: held.integrity.canonicalDigest, evidenceId: held.payload.evidenceId, locator: { origin, seq: 1 } };
    // The root comes from the first lineage link whose target is held: the external one is not.
    expect(out.payload.links).toEqual([
      { rel: 'appeals', target: heldTarget, attrs: null },
      { rel: 'derivedFrom', target: { digest: hex('elsewhere'), evidenceId: 'case-17', locator: elsewhere }, attrs: null },
      { rel: 'root', target: heldTarget, attrs: null },
    ]);
    // An external target named only by digest keeps null members.
    const bare = await captured(s.tzun, { ...decision('bare'), links: [{ rel: 'x-acme.contract', target: { digest: hex('bare'), external: true }, attrs: { ref: 'C-1' } }] });
    expect(bare.payload.links).toEqual([{ rel: 'x-acme.contract', target: { digest: hex('bare'), evidenceId: null, locator: null }, attrs: { ref: 'C-1' } }]);
  });

  it('refuses an external target whose locator names a position of this store that holds no record', async () => {
    await captured(s.tzun, decision('one'));
    const origin = (await s.host.evidenceLogOrigin('default'))!;
    const refused = refusalOf(
      await s.tzun.capture({ ...decision('ghost'), links: [{ rel: 'derivedFrom', target: { digest: hex('ghost'), locator: { origin, seq: 5 }, external: true } }] }),
    );
    expect(refused).toMatchObject({ code: 'link_target_not_found', field: 'links[0].target' });
    // The same position holding a record that is not the digest: a mismatch.
    const mismatch = refusalOf(
      await s.tzun.capture({ ...decision('wrong'), links: [{ rel: 'derivedFrom', target: { digest: hex('ghost'), locator: { origin, seq: 1 }, external: true } }] }),
    );
    expect(mismatch).toMatchObject({ code: 'link_target_mismatch', field: 'links[0].target.digest' });
  });

  it('keeps an input locator: null, so the target position is not disclosed', async () => {
    const parent = await captured(s.tzun, decision('private'));
    const child = await captured(s.tzun, { ...decision('child'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId, locator: null } }] });
    expect(child.payload.links![0].target).toEqual({ digest: parent.integrity.canonicalDigest, evidenceId: parent.payload.evidenceId, locator: null });
    expect((await s.tzun.verify(child.payload.evidenceId)).verified).toBe(true);
  });

  it("adds the root from the first held lineage target: that target's own root, or the target itself", async () => {
    const w1 = await captured(s.tzun, decision('first'));
    const w2 = await captured(s.tzun, { ...decision('second'), links: [{ rel: 'derivedFrom', target: { evidenceId: w1.payload.evidenceId } }] });
    const w3 = await captured(s.tzun, { ...decision('third'), links: [{ rel: 'supersedes', target: { evidenceId: w2.payload.evidenceId } }] });
    const root = w3.payload.links!.find((l) => l.rel === 'root');
    expect(root?.target.digest).toBe(w1.integrity.canonicalDigest);
    // No lineage link: no root.
    const plain = await captured(s.tzun, { ...decision('plain'), links: [{ rel: 'x-acme.ref', target: { evidenceId: w1.payload.evidenceId } }] });
    expect(plain.payload.links!.map((l) => l.rel)).toEqual(['x-acme.ref']);
  });

  it('applies the target rules of a held target at capture', async () => {
    const agentDecision = await captured(s.tzun, { ...decision('autonomous'), decider: { kind: 'policy-engine', agent: `sha256:${hex('engine')}` } });
    const humanDecision = await captured(s.tzun, decision('signed off', human('acct:u-1')));
    // ratifies: the target's decider is not a human.
    expect(refusalOf(await s.tzun.capture({ ...decision('ratify', human('acct:u-2')), links: [{ rel: 'ratifies', target: { evidenceId: humanDecision.payload.evidenceId } }] }))).toMatchObject({
      code: 'link_rule_violated',
      rule: 'ratifies_target_not_human',
    });
    await captured(s.tzun, { ...decision('ratify', human('acct:u-2')), links: [{ rel: 'ratifies', target: { evidenceId: agentDecision.payload.evidenceId } }] });
    // reviews: the reviewer is not the decider under review.
    expect(refusalOf(await s.tzun.capture({ ...decision('self review', human('acct:u-1')), links: [{ rel: 'reviews', target: { evidenceId: humanDecision.payload.evidenceId } }] }))).toMatchObject({
      code: 'link_rule_violated',
      rule: 'reviews_distinct_decider',
    });
    // supersedes: the same aiSystemId.
    expect(
      refusalOf(await s.tzun.capture({ ...decision('other system'), aiSystemId: 'another-system', links: [{ rel: 'supersedes', target: { evidenceId: humanDecision.payload.evidenceId } }] })),
    ).toMatchObject({ code: 'link_rule_violated', rule: 'supersedes_same_system' });
  });

  it('opens a committed decider at capture: a reviews link by the same person behind a commitment is refused', async () => {
    const committed = await captured(s.tzun, decision('committed', { kind: 'human', id: 'acct:u-1', commit: true } as ReturnType<typeof human>));
    expect(committed.payload.decider!.id).toMatch(/^cmt:/);
    const reviews = (evidenceId: string) => [{ rel: 'reviews', target: { evidenceId } }];
    // The target's commitment is opened from the store's openings.
    expect(refusalOf(await s.tzun.capture({ ...decision('self review', human('acct:u-1')), links: reviews(committed.payload.evidenceId) }))).toMatchObject({
      code: 'link_rule_violated',
      rule: 'reviews_distinct_decider',
    });
    // Both sides committed: this capture's own opening opens its decider.
    expect(
      refusalOf(
        await s.tzun.capture({
          ...decision('committed self review', { kind: 'human', id: 'acct:u-1', commit: true } as ReturnType<typeof human>),
          links: reviews(committed.payload.evidenceId),
        }),
      ),
    ).toMatchObject({ code: 'link_rule_violated', rule: 'reviews_distinct_decider' });
    const plain = await captured(s.tzun, decision('plain', human('acct:u-1')));
    expect(
      refusalOf(
        await s.tzun.capture({
          ...decision('committed reviewer', { kind: 'human', id: 'acct:u-1', commit: true } as ReturnType<typeof human>),
          links: reviews(plain.payload.evidenceId),
        }),
      ),
    ).toMatchObject({ code: 'link_rule_violated', rule: 'reviews_distinct_decider' });
    // Another person reviews either record.
    const other = await captured(s.tzun, { ...decision('other reviewer', human('acct:u-2')), links: reviews(committed.payload.evidenceId) });
    expect((await s.tzun.verify(other.payload.evidenceId)).links!.relations[0]).toMatchObject({ rel: 'reviews', outcome: 'checked-correct' });
    await captured(s.tzun, {
      ...decision('other committed reviewer', { kind: 'human', id: 'acct:u-2', commit: true } as ReturnType<typeof human>),
      links: reviews(committed.payload.evidenceId),
    });
    // A link record whose held subject was decided by the same committed person.
    const subject = await captured(s.tzun, decision('subject', { kind: 'human', id: 'acct:u-1', commit: true } as ReturnType<typeof human>));
    expect(
      refusalOf(
        await s.links.relate({
          subject: { evidenceId: subject.payload.evidenceId },
          relations: reviews(plain.payload.evidenceId),
          reason: 'the subject reviews its own decision',
          decider: human('acct:u-9'),
        }),
      ),
    ).toMatchObject({ code: 'link_rule_violated', rule: 'reviews_distinct_decider' });
  });

  it('refuses a prepared capture whose links or step model differ from what its input resolves to, digest recomputed or not', async () => {
    const parent = await captured(s.tzun, decision('parent'));
    const input = { ...decision('prepared'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] };
    const prepared = await s.tzun.prepareAssertionChallenge(input);
    const altered = JSON.parse(JSON.stringify(prepared)) as typeof prepared;
    for (const l of altered.links!) {
      if (l.rel === 'derivedFrom') {
        l.target.evidenceId = '9b2f6f1e-4d1a-4c3b-8a2e-1f0e9d8c7b6a';
        l.target.locator = l.target.locator === null ? null : { origin: l.target.locator.origin, seq: 77 };
      }
    }
    expect(refusalOf(await s.tzun.capture(input, { prepared: altered }))).toMatchObject({ code: 'invalid_prepared', field: 'prepared.links' });
    // The same with the digest and challenge replaced, as a caller who rebuilt the record would.
    const { webauthnChallengeForDigest } = await import('@tzun/engine');
    const forged = { ...altered, digest: 'f'.repeat(64), challenge: webauthnChallengeForDigest('f'.repeat(64)) };
    expect(refusalOf(await s.tzun.capture(input, { prepared: forged }))).toMatchObject({ code: 'invalid_prepared', field: 'prepared.links' });

    const model = {
      descriptorVersion: 'd1', vendor: 'openai', modelName: 'prepared-model', modelVersion: 'v1', modelType: 'llm',
      integrityTier: 'vendor-asserted', modelDigest: null, parentModelDescriptorDigest: null, derivation: null,
      trainedBy: 'TestCorp', license: 'mit', modelCardUrl: null,
      training: { trainingDataDigest: null, trainingDataRef: null, lastTrainingDate: null, evaluations: [] },
      regulatoryMarkings: [], externalIdentifiers: [],
    };
    const withModel = {
      ...decision('with model'),
      contributions: { steps: [{ role: 'propose' as const, actor: null, aiBom: { modelDescriptor: model, vendorFingerprint: null }, inputs: [] }] },
    } as unknown as Parameters<typeof s.tzun.capture>[0];
    const prep2 = await s.tzun.prepareAssertionChallenge(withModel);
    const alt2 = JSON.parse(JSON.stringify(prep2)) as typeof prep2;
    alt2.contributions!.steps[0].aiBom!.modelDescriptorDigest = `sha256:${'9f'.repeat(32)}`;
    expect(refusalOf(await s.tzun.capture(withModel, { prepared: alt2 }))).toMatchObject({ code: 'invalid_prepared', field: 'prepared.contributions' });
    // The unaltered prepared objects still capture, and nothing was stored by the refusals.
    expect(await s.host.storage.getChainLength()).toBe(1);
    const ok = await s.tzun.capture(input, { prepared });
    expect(ok.stored).toBe(true);
    expect(ok.envelope.integrity.canonicalDigest).toBe(prepared.digest);
  });

  it('replays a keyed capture with links, and resolves the targets the same way on a retry', async () => {
    const parent = await captured(s.tzun, decision('keyed parent'));
    const input = { ...decision('keyed'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] };
    const first = await s.tzun.capture(input, { idempotencyKey: 'link-key-1' });
    const again = await s.tzun.capture(input, { idempotencyKey: 'link-key-1' });
    expect(first.stored).toBe(true);
    expect(again.envelope.payload.evidenceId).toBe(first.envelope.payload.evidenceId);
    expect(await s.host.storage.getChainLength()).toBe(2);
  });
});

describe('link capture reads nothing for a list over the link limit', () => {
  it('refuses 257 links and a 300-relation relate too_many_links without a store read', async () => {
    const s = await openLinked({});
    try {
      const parent = await captured(s.tzun, decision('parent'));
      let reads = 0;
      const storage = s.host.storage as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
      for (const name of ['retrieve', 'retrieveByDigest', 'getBySequenceRange']) {
        const original = storage[name].bind(storage);
        storage[name] = async (...a: unknown[]) => {
          reads++;
          return original(...a);
        };
      }
      const targets = Array.from({ length: 300 }, (_, i) => ({ evidenceId: `id-${i}` }));
      const refused = refusalOf(await s.tzun.capture({ ...decision('flood'), links: targets.slice(0, 257).map((target) => ({ rel: 'derivedFrom', target })) }));
      expect(refused).toMatchObject({ code: 'too_many_links', field: 'links' });
      expect(
        refusalOf(
          await s.links.relate({
            subject: { evidenceId: parent.payload.evidenceId },
            relations: targets.map((target) => ({ rel: 'appeals', target })),
            reason: 'flood',
            decider: human('acct:u-9'),
          }),
        ),
      ).toMatchObject({ code: 'too_many_links', field: 'links' });
      expect(reads).toBe(0);
      // At the limit, every target is read.
      expect(refusalOf(await s.tzun.capture({ ...decision('at the limit'), links: targets.slice(0, 256).map((target) => ({ rel: 'derivedFrom', target })) }))).toMatchObject({
        code: 'link_target_not_found',
      });
      expect(reads).toBeGreaterThan(0);
    } finally {
      await s.close();
    }
  });
});

describe('link capture never leaves the store', () => {
  it('a record of another store is not found without external, and written as given with it', async () => {
    const a = await openLinked({});
    const b = await openLinked({});
    try {
      const inA = await captured(a.tzun, decision('in a'));
      expect(refusalOf(await b.tzun.capture({ ...decision('in b'), links: [{ rel: 'derivedFrom', target: { evidenceId: inA.payload.evidenceId } }] }))).toMatchObject({
        code: 'link_target_not_found',
      });
      expect(refusalOf(await b.tzun.capture({ ...decision('in b'), links: [{ rel: 'derivedFrom', target: { digest: inA.integrity.canonicalDigest } }] }))).toMatchObject({
        code: 'link_target_not_found',
      });
      const external = await captured(b.tzun, {
        ...decision('in b'),
        links: [{ rel: 'derivedFrom', target: { digest: inA.integrity.canonicalDigest, evidenceId: inA.payload.evidenceId, external: true } }],
      });
      expect(external.payload.links).toEqual([
        { rel: 'derivedFrom', target: { digest: inA.integrity.canonicalDigest, evidenceId: inA.payload.evidenceId, locator: null }, attrs: null },
      ]);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('a record on another chain of the same store is a same-store target, located on its own chain', async () => {
    const { sqlitePath } = await import('./fixtures');
    const file = sqlitePath();
    const first = await openLinked({ dbPath: file });
    const parent = await captured(first.tzun, decision('default chain'));
    await first.close();
    const second = await openLinked({ dbPath: file, chainId: 'tenant-b' });
    try {
      const child = await captured(second.tzun, { ...decision('tenant-b chain'), links: [{ rel: 'derivedFrom', target: { evidenceId: parent.payload.evidenceId } }] });
      expect(child.payload.links![0].target.locator).toEqual({ origin: await second.host.evidenceLogOrigin('default'), seq: 1 });
      expect(child.payload.sequenceNumber).toBe(1);
      expect((await second.tzun.verify(child.payload.evidenceId)).links?.outcome).toBe('checked-correct');
    } finally {
      await second.close();
    }
  });
});
