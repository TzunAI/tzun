import {
  ContributionsBuildError,
  buildContributions,
  checkContributions,
  contributionsViolation,
  decidingOutput,
  outputDigest,
  singleModel,
  stepDigest,
} from './contributions';
import type { ContributionsInput } from './types/contributions';

const A = 'sha256:' + 'a1'.repeat(32);
const B = 'sha256:' + 'b2'.repeat(32);
const ip = { temperature: 0, topP: null, maxTokens: 800, seed: null, stopSequences: null };
const bom = (d: string) => ({
  modelDescriptorDigest: 'sha256:' + d.repeat(32), vendorFingerprint: null, promptTemplate: null, inferenceParameters: ip, infrastructure: null,
});
const aiOutput = { recommendation: 'approve', maxApprovedAmount: 25000, riskScore: 31 };
const action = 'approve';
const reason = 'Income verified; reviewer found no fair-lending concerns';
const human = { kind: 'human' as const, id: 'acct:u-4821', agent: null, credential: null, freshness: null };
const reviewOutput = { factors: ['debtToIncome', 'incomeStability'], verdict: 'approve' };
const REVIEW_OUT = outputDigest(reviewOutput);
const PROPOSED = outputDigest(aiOutput);
/** W2's digest: W3 derives from it. */
const W2 = '71bcc81edb3e12119420c8a6fc8188a9206b1afd7c6e46a09dc409c480377a83';
const W2_TARGET = { digest: W2, evidenceId: '5f0c1f0e-3333-4c3c-9c3c-000000000006', locator: null };
const W3_LINKS = [
  { rel: 'derivedFrom', target: W2_TARGET, attrs: null },
  { rel: 'root', target: W2_TARGET, attrs: null },
];

/** Worked example W3 (Record §4.4): propose, review, decide, the proposal taking W2 as an input. */
function example(): ContributionsInput {
  return {
    steps: [
      { role: 'propose:underwriting', actor: { kind: 'agent', agent: A }, aiBom: bom('0a'), inputs: ['sha256:' + W2] },
      {
        role: 'review:fair-lending', actor: { kind: 'agent', agent: B }, aiBom: bom('0b'), inputs: [PROPOSED],
        outputOf: reviewOutput, verdict: 'approve', reason: 'No protected-class proxies in the factors',
      },
      { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null }, inputs: [REVIEW_OUT, PROPOSED], verdict: 'approve' },
    ],
  };
}

const ctx = { decider: human, action, reason, aiOutput };

/** Recompute every prev, so a mutation tests the rule it targets rather than the chain. */
function rechain(c: any): any {
  c.steps.forEach((step: any, i: number) => {
    step.prev = i === 0 ? null : stepDigest(c.steps[i - 1]);
  });
  return c;
}
const payloadWith = (contributions: unknown, extra: Record<string, unknown> = {}) => ({
  schemaVersion: 'v1.0', aiOutput, action, reason, decider: human, contributions, links: W3_LINKS, ...extra,
});

describe('digests', () => {
  it("reproduces W3's output and step digests", () => {
    expect(PROPOSED).toBe('sha256:acda70afa64735b0b4889f7ca04b6b80998031b2d82696e37b97b03331869b57');
    expect(REVIEW_OUT).toBe('sha256:f59684773ae5ce28f65e4c311fa0052fb81e235ac322de987813ef39252d737f');
    expect(decidingOutput(action, reason)).toBe('sha256:ef9b809ada8800da4257ccfb6dacffbb62fe5d09ad8ab3adf1dbf236ffc9ad4a');
    expect(outputDigest({ ...aiOutput, maxApprovedAmount: 45000 })).toBe(
      'sha256:137c3b2a21a338f02db7041a8c7409f8b70bb38bafb56ee7c7326d3063aadc9e',
    );
    const built = buildContributions(example(), ctx);
    expect(built.steps.map(stepDigest)).toEqual([
      'sha256:32a1ccc01f6eb79975fef13137aca3f4984454bf779f62218b82a630c0d86a10',
      'sha256:c8eb7215f2d39fa10a06375e225c0b35e9dd2dec2cac1314fa8b023396ff7d8b',
      'sha256:a355a0cefe7b2020f5ff81eec4aef5a51349260813791f84b62935e4053485fd',
    ]);
  });
});

describe('buildContributions', () => {
  it('defaults agent ids, fills nulls, sorts inputs, chains prev, fills the proposal, decide output and reason', () => {
    const built = buildContributions(example(), ctx);
    expect(built.steps[0].actor!.id).toBe(`desc:${A}`);
    expect(built.steps[0].output).toBe(PROPOSED);
    expect(built.steps[2].inputs).toEqual([PROPOSED, REVIEW_OUT].sort());
    expect(built.steps[0].prev).toBeNull();
    expect(built.steps[2].prev).toBe(stepDigest(built.steps[1]));
    expect(built.steps[2].output).toBe(decidingOutput(action, reason));
    expect(built.steps[2].reason).toBe(reason);
    expect(built.pipeline).toBeNull();
    expect(built.externals).toEqual([]);
  });

  it('fills absent nullable members of a step bill of materials', () => {
    const built = buildContributions(
      { steps: [{ role: 'propose', aiBom: { modelDescriptorDigest: 'sha256:' + '0a'.repeat(32), inferenceParameters: { temperature: 0 } } as never }] },
      ctx,
    );
    expect(built.steps[0].aiBom).toEqual({
      modelDescriptorDigest: 'sha256:' + '0a'.repeat(32), vendorFingerprint: null, promptTemplate: null,
      inferenceParameters: { temperature: 0, topP: null, maxTokens: null, seed: null, stopSequences: null },
      infrastructure: null,
    });
  });

  it('builds a single model as a list of one, the model called directly (actor null)', () => {
    const built = buildContributions(singleModel(bom('0c')), ctx);
    expect(built).toEqual({
      pipeline: null,
      externals: [],
      steps: [{ role: 'propose', actor: null, aiBom: bom('0c'), inputs: [], output: PROPOSED, verdict: null, reason: null, prev: null }],
    });
    const byAgent = buildContributions(singleModel(bom('0c'), { actor: { kind: 'agent', agent: A } }), ctx);
    expect(byAgent.steps[0].actor).toEqual({ kind: 'agent', id: `desc:${A}`, agent: A });
    expect(contributionsViolation(built, ctx)).toBeNull();
    expect(checkContributions(payloadWith(built, { links: null }))).toMatchObject({
      outcome: 'checked-correct', steps: 1, models: ['sha256:' + '0c'.repeat(32)], decidingStep: 'record',
      binding: { outcome: 'checked-correct', decisionBinding: 'checked', proposals: [0] },
    });
  });

  it('refuses a null actor on a decide step, and on a step that records no model', () => {
    expect(() => buildContributions({ steps: [{ role: 'decide', actor: null }] }, ctx)).toThrow(
      expect.objectContaining({ code: 'actor_required', step: 0 }),
    );
    expect(() => buildContributions({ steps: [{ role: 'propose', actor: null }] }, ctx)).toThrow(
      expect.objectContaining({ code: 'actor_required', step: 0 }),
    );
  });

  it('refuses a member the builder form does not have, rather than dropping it', () => {
    const typo = example() as any;
    typo.steps[0].outptu = typo.steps[0].outputOf;
    expect(() => buildContributions(typo, ctx)).toThrow(expect.objectContaining({ code: 'step_unknown_members', step: 0 }));
    const actorExtra = example() as any;
    actorExtra.steps[2].actor.credential = null;
    expect(() => buildContributions(actorExtra, ctx)).toThrow(expect.objectContaining({ code: 'invalid_actor', step: 2 }));
    expect(() => buildContributions({ ...example(), extra: 1 } as never, ctx)).toThrow(
      expect.objectContaining({ code: 'unknown_members' }),
    );
  });

  it('refuses a supplied prev that differs, a repeated input, and a decider that is not the decide actor', () => {
    const badPrev = example();
    badPrev.steps[1].prev = 'sha256:' + '00'.repeat(32);
    expect(() => buildContributions(badPrev, ctx)).toThrow(ContributionsBuildError);
    try {
      buildContributions(badPrev, ctx);
    } catch (e) {
      expect((e as ContributionsBuildError).code).toBe('prev_mismatch');
      expect((e as ContributionsBuildError).step).toBe(1);
    }
    const repeated = example();
    repeated.steps[1].inputs = [PROPOSED, PROPOSED];
    expect(() => buildContributions(repeated, ctx)).toThrow(expect.objectContaining({ code: 'not_a_set' }));
    expect(() => buildContributions(example(), { ...ctx, decider: { ...human, id: 'acct:other' } })).toThrow(
      expect.objectContaining({ code: 'decider_not_deciding_actor' }),
    );
  });
});

describe('contributionsViolation (writer)', () => {
  const built = () => JSON.parse(JSON.stringify(buildContributions(example(), ctx)));

  it('accepts the built member and null', () => {
    expect(contributionsViolation(built(), ctx)).toBeNull();
    expect(contributionsViolation(null, ctx)).toBeNull();
  });

  const cases: [string, (c: any) => unknown, string][] = [
    ['not an object', () => [], 'not_an_object'],
    ['an extra member', (c) => ({ ...c, extra: 1 }), 'unknown_members'],
    ['a missing member', (c) => { delete c.externals; return c; }, 'missing_members'],
    ['a bare pipeline digest', (c) => ({ ...c, pipeline: 'aa'.repeat(32) }), 'invalid_pipeline'],
    ['65 externals', (c) => ({ ...c, externals: Array.from({ length: 65 }, (_, i) => 'sha256:' + i.toString(16).padStart(64, '0')) }), 'invalid_externals'],
    ['unsorted externals', (c) => ({ ...c, externals: [B, A] }), 'not_a_set'],
    ['no steps', (c) => ({ ...c, steps: [] }), 'no_steps'],
    ['33 steps', (c) => ({ ...c, steps: Array.from({ length: 33 }, () => c.steps[0]) }), 'too_many_steps'],
    ['a step member missing', (c) => { delete c.steps[0].reason; return c; }, 'step_missing_members'],
    ['a step member extra', (c) => { c.steps[0].note = 'x'; return c; }, 'step_unknown_members'],
    ['an unknown role class', (c) => { c.steps[0].role = 'suggest'; return c; }, 'invalid_role'],
    ['an actor of an unknown kind', (c) => { c.steps[0].actor.kind = 'committee'; return c; }, 'invalid_actor'],
    ['a null actor with no model', (c) => { c.steps[1].actor = null; c.steps[1].aiBom = null; return c; }, 'actor_required'],
    ['a null actor on the decide step', (c) => { c.steps[2].actor = null; return c; }, 'actor_required'],
    ['a step aiBom missing a key', (c) => { delete c.steps[0].aiBom.vendorFingerprint; return c; }, 'invalid_step_ai_bom'],
    ['a bare input digest', (c) => { c.steps[1].inputs = ['aa'.repeat(32)]; return c; }, 'invalid_inputs'],
    ['unsorted inputs', (c) => { c.steps[2].inputs = [...c.steps[2].inputs].reverse(); return c; }, 'not_a_set'],
    ['a bare output', (c) => { c.steps[0].output = 'aa'.repeat(32); return c; }, 'invalid_output'],
    ['an unknown verdict', (c) => { c.steps[1].verdict = 'maybe'; return c; }, 'invalid_verdict'],
    ['a verdict on a propose step', (c) => { c.steps[0].verdict = 'approve'; return c; }, 'verdict_not_allowed'],
    ['an empty step reason', (c) => { c.steps[1].reason = ''; return c; }, 'invalid_step_reason'],
    ['a broken chain', (c) => { c.steps[2].prev = c.steps[1].prev; return c; }, 'prev_mismatch'],
    ['two decide steps', (c) => { c.steps[1].role = 'decide'; return rechain(c); }, 'multiple_deciding_steps'],
  ];
  it.each(cases)('refuses %s', (_name, mutate, code) => {
    expect(contributionsViolation(mutate(built()), ctx)?.code).toBe(code);
  });

  it('accepts a null actor on a model-bearing step that is not a decide step', () => {
    const c = built();
    c.steps[0].actor = null;
    expect(contributionsViolation(rechain(c), ctx)).toBeNull();
  });

  it('refuses a propose step after the decide step', () => {
    const input: ContributionsInput = {
      steps: [
        { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null } },
        { role: 'propose', actor: { kind: 'agent', agent: A }, outputOf: { x: 1 } },
      ],
    };
    expect(() => buildContributions(input, ctx)).toThrow(expect.objectContaining({ code: 'step_after_deciding', step: 1 }));
    const c = rechain(built());
    c.steps.push({ ...c.steps[0], prev: null });
    expect(contributionsViolation(rechain(c), ctx)?.code).toBe('step_after_deciding');
  });

  it('refuses a review after the decide step, as writer and as reader; accepts an other step after it', () => {
    const input: ContributionsInput = {
      steps: [
        { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null } },
        { role: 'review', actor: { kind: 'agent', agent: B }, output: REVIEW_OUT, verdict: 'approve' },
      ],
    };
    expect(() => buildContributions(input, ctx)).toThrow(expect.objectContaining({ code: 'step_after_deciding', step: 1 }));
    const c = rechain(built());
    c.steps.push({ ...c.steps[1], prev: null });
    expect(contributionsViolation(rechain(c), ctx)?.code).toBe('step_after_deciding');
    expect(checkContributions(payloadWith(rechain(c)))).toMatchObject({ outcome: 'checked-wrong', reason: 'malformed_contributions' });
    const carriedOut = buildContributions(
      {
        steps: [
          { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null } },
          { role: 'other:execute', actor: { kind: 'agent', agent: A }, outputOf: { executed: true } },
        ],
      },
      ctx,
    );
    expect(contributionsViolation(carriedOut, ctx)).toBeNull();
  });

  it('skips no rule when the context lacks a member', () => {
    expect(contributionsViolation(built(), { ...ctx, decider: undefined })?.code).toBe('decider_not_deciding_actor');
    expect(contributionsViolation(built(), { ...ctx, action: undefined })?.code).toBe('deciding_output_mismatch');
    expect(contributionsViolation(built(), undefined as never)?.code).toBe('decider_not_deciding_actor');
    expect(() =>
      buildContributions({ steps: [{ role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null } }] }, {
        decider: human, action: undefined, reason,
      }),
    ).toThrow(expect.objectContaining({ code: 'deciding_output_mismatch' }));
  });

  it('refuses a decider that is not the decide actor and a wrong decide output', () => {
    expect(contributionsViolation(built(), { ...ctx, decider: { ...human, id: 'acct:other' } })?.code).toBe('decider_not_deciding_actor');
    expect(contributionsViolation(built(), { ...ctx, reason: 'another reason' })?.code).toBe('deciding_output_mismatch');
  });

  it.each([
    ['spiffe', 'spiffe://agents.example/underwriter'],
    ['jkt', 'jkt:' + 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'],
    ['cmt', 'cmt:' + 'ab'.repeat(32)],
  ])('compares the agent too: a %s decider with the decide actor’s id and another agent is not that actor', (_scheme, id) => {
    const agentDecider = { kind: 'agent' as const, id, agent: A, credential: null, freshness: null };
    const agentCtx = { ...ctx, decider: agentDecider };
    const c = buildContributions(
      {
        steps: [
          { role: 'propose', actor: { kind: 'agent', agent: B }, inputs: [] },
          { role: 'decide', actor: { kind: 'agent', id, agent: A }, inputs: [PROPOSED] },
        ],
      },
      agentCtx,
    );
    expect(contributionsViolation(c, agentCtx)).toBeNull();
    expect(contributionsViolation(c, { ...agentCtx, decider: { ...agentDecider, agent: B } })?.code).toBe('decider_not_deciding_actor');
  });

  it('with no decide step, the decider is not compared with any step actor', () => {
    const c = buildContributions(singleModel(bom('0c'), { actor: { kind: 'agent', agent: A } }), ctx);
    expect(contributionsViolation(c, { ...ctx, decider: { ...human, id: 'acct:anyone' } })).toBeNull();
  });
});

describe('checkContributions (reader rows)', () => {
  const built = () => JSON.parse(JSON.stringify(buildContributions(example(), ctx)));

  it('reads absent, and checked-correct with the facts and the binding facts', () => {
    expect(checkContributions(payloadWith(null)).reason).toBe('absent');
    expect(checkContributions({ schemaVersion: 'v1.0' }).reason).toBe('absent');
    expect(checkContributions(payloadWith(built()))).toEqual({
      outcome: 'checked-correct', valid: true, steps: 3,
      models: ['sha256:' + '0a'.repeat(32), 'sha256:' + '0b'.repeat(32)], decidingStep: 2,
      binding: {
        outcome: 'checked-correct', valid: true, approvals: [1], staleApprovals: [], uncoveredReviews: [],
        proposals: [0], decisionBinding: 'checked',
      },
    });
  });

  it('reports the structure failures, a failure before an abstention', () => {
    const chain = built();
    chain.steps[1].prev = 'sha256:' + '00'.repeat(32);
    expect(checkContributions(payloadWith(chain))).toMatchObject({ reason: 'step_chain_broken', failedStep: 1 });
    expect(checkContributions(payloadWith(built(), { decider: { ...human, id: 'acct:x' } }))).toMatchObject({ reason: 'decider_not_deciding_actor' });
    expect(checkContributions(payloadWith(built(), { reason: 'changed' }))).toMatchObject({ reason: 'deciding_output_mismatch' });
    const malformed = built();
    malformed.steps[0].inputs = [B, A];
    expect(checkContributions(payloadWith(malformed))).toMatchObject({ outcome: 'checked-wrong', reason: 'malformed_contributions' });
    expect(checkContributions(payloadWith(chain)).binding.reason).toBe('blocked_by:contributions');
    // An unknown actor kind in step 1 and a broken chain: the failure is reported, not hidden by the abstention.
    const both = built();
    both.steps[1].actor.kind = 'committee';
    both.steps[2].prev = 'sha256:' + '00'.repeat(32);
    expect(checkContributions(payloadWith(both))).toMatchObject({ outcome: 'checked-wrong', reason: 'step_chain_broken' });
    const nullDecide = rechain(built());
    nullDecide.steps[2].actor = null;
    expect(checkContributions(payloadWith(rechain(nullDecide)))).toMatchObject({ reason: 'malformed_contributions' });
  });

  it('abstains on an actor kind or scheme it does not know, and on a pipeline', () => {
    const unknownKind = built();
    unknownKind.steps[1].actor.kind = 'committee';
    rechain(unknownKind);
    expect(checkContributions(payloadWith(unknownKind))).toMatchObject({ outcome: 'abstain', reason: 'unsupported_actor_kind' });
    const unknownScheme = built();
    unknownScheme.steps[1].actor.id = 'did:example:1';
    rechain(unknownScheme);
    expect(checkContributions(payloadWith(unknownScheme))).toMatchObject({ outcome: 'abstain', reason: 'unsupported_identifier_scheme' });
    const pipeline = buildContributions({ ...example(), pipeline: 'sha256:' + 'cd'.repeat(32) }, ctx);
    expect(checkContributions(payloadWith(pipeline)).pipeline).toEqual({ outcome: 'abstain', reason: 'unsupported_pipeline' });
  });

  it('reports a swapped output as decided_output_differs, from the record alone (W3s)', () => {
    const r = checkContributions(payloadWith(built(), { aiOutput: { ...aiOutput, maxApprovedAmount: 45000 } }));
    expect(r.outcome).toBe('checked-correct');
    expect(r.binding).toMatchObject({ outcome: 'checked-wrong', reason: 'decided_output_differs', failedDigest: PROPOSED });
  });

  it('takes link targets as declared inputs only when links is well formed', () => {
    expect(checkContributions(payloadWith(built())).binding.outcome).toBe('checked-correct');
    expect(checkContributions(payloadWith(built(), { links: null })).binding).toMatchObject({
      reason: 'input_undeclared', failedStep: 0, failedDigest: 'sha256:' + W2,
    });
    const unsorted = [W3_LINKS[1], W3_LINKS[0]];
    expect(checkContributions(payloadWith(built(), { links: unsorted })).binding).toMatchObject({ reason: 'input_undeclared' });
  });

  it('reports a step that lists its own output among its inputs', () => {
    const selfInput = buildContributions(
      {
        steps: [
          { role: 'propose', actor: { kind: 'agent', agent: A }, inputs: [PROPOSED] },
          { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null }, inputs: [PROPOSED] },
        ],
      },
      ctx,
    );
    expect(selfInput.steps[0].output).toBe(PROPOSED);
    expect(checkContributions(payloadWith(selfInput)).binding).toMatchObject({
      reason: 'input_undeclared', failedStep: 0, failedDigest: PROPOSED,
    });
  });

  it('reports an undeclared input, and accepts a declared external', () => {
    const X = 'sha256:' + 'ee'.repeat(32);
    const steps = (inputs: string[]) => ({
      steps: [
        { role: 'propose', actor: { kind: 'agent' as const, agent: A }, inputs },
        { role: 'decide', actor: { kind: 'human' as const, id: 'acct:u-4821', agent: null }, inputs: [PROPOSED] },
      ],
    });
    expect(checkContributions(payloadWith(buildContributions(steps([X]), ctx))).binding).toMatchObject({
      reason: 'input_undeclared', failedStep: 0, failedDigest: X,
    });
    const withExternal = buildContributions({ ...steps([X]), externals: [X] }, ctx);
    expect(checkContributions(payloadWith(withExternal)).binding.outcome).toBe('checked-correct');
  });

  it('reports an unbound review and an unbound decision', () => {
    const unboundReview = buildContributions(
      {
        steps: [
          { role: 'propose', actor: { kind: 'agent', agent: A } },
          { role: 'review', actor: { kind: 'agent', agent: B }, output: REVIEW_OUT, verdict: 'approve' },
          { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null }, inputs: [PROPOSED] },
        ],
      },
      ctx,
    );
    expect(checkContributions(payloadWith(unboundReview)).binding).toMatchObject({ reason: 'review_unbound', failedStep: 1 });
    const unboundDecision = buildContributions(
      {
        steps: [
          { role: 'propose', actor: { kind: 'agent', agent: A } },
          { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null } },
        ],
      },
      ctx,
    );
    expect(checkContributions(payloadWith(unboundDecision)).binding).toMatchObject({ reason: 'decision_unbound', failedStep: 1 });
  });

  it('counts a review of the final proposal and reports one of an earlier proposal as stale', () => {
    const first = { draft: 1 };
    const c = buildContributions(
      {
        steps: [
          { role: 'propose', actor: { kind: 'agent', agent: A }, outputOf: first },
          { role: 'review', actor: { kind: 'agent', agent: B }, inputs: [outputDigest(first)], output: REVIEW_OUT, verdict: 'approve' },
          { role: 'propose', actor: { kind: 'agent', agent: A }, inputs: [REVIEW_OUT] },
          { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null }, inputs: [PROPOSED] },
        ],
      },
      ctx,
    );
    expect(checkContributions(payloadWith(c)).binding).toMatchObject({
      outcome: 'checked-correct', approvals: [], staleApprovals: [1], proposals: [0, 2], decisionBinding: 'checked',
    });
  });

  it('reads a decide step alone, and a review with no proposal before it, as not-applicable binding', () => {
    const alone = buildContributions({ steps: [{ role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null } }] }, ctx);
    expect(checkContributions(payloadWith(alone))).toMatchObject({ decidingStep: 0, models: [] });
    expect(checkContributions(payloadWith(alone)).binding).toMatchObject({ outcome: 'checked-correct', decisionBinding: 'not-applicable' });
    const reviewFirst = buildContributions(
      {
        externals: [PROPOSED],
        steps: [
          { role: 'review', actor: { kind: 'agent', agent: B }, inputs: [PROPOSED], output: REVIEW_OUT, verdict: 'concerns' },
          { role: 'decide', actor: { kind: 'human', id: 'acct:u-4821', agent: null }, inputs: [REVIEW_OUT] },
        ],
      },
      ctx,
    );
    expect(checkContributions(payloadWith(reviewFirst)).binding).toMatchObject({
      outcome: 'checked-correct', uncoveredReviews: [0], decisionBinding: 'not-applicable',
    });
  });

  it('with no decide step, binds the record decision to the last proposal (review + record decider)', () => {
    const c = buildContributions(
      {
        steps: [
          { role: 'propose', actor: null, aiBom: bom('0a') },
          { role: 'review', actor: { kind: 'agent', agent: B }, aiBom: bom('0b'), inputs: [PROPOSED], outputOf: reviewOutput, verdict: 'approve' },
        ],
      },
      ctx,
    );
    const r = checkContributions(payloadWith(c, { links: null }));
    expect(r).toMatchObject({ outcome: 'checked-correct', decidingStep: 'record' });
    expect(r.binding).toMatchObject({ outcome: 'checked-correct', approvals: [1], decisionBinding: 'checked' });
    expect(checkContributions(payloadWith(c, { links: null, aiOutput: { other: 1 } })).binding).toMatchObject({
      reason: 'decided_output_differs',
    });
  });
});
