/**
 * Generate vectors/contributions-vectors.json: the answers every
 * implementation of the contributions member (Record §7) must give.
 *
 *   - outputDigests  a value and `outputDigest(value)`, including the salted
 *                    convention of Record §7.6 and a byte output's `{ mediaType,
 *                    sha256 }` value;
 *   - stepDigests    a step and `stepDigest(step)`;
 *   - shapes         a contributions value with the record's decider, action
 *                    and reason, and why a writer refuses it
 *                    (`contributionsViolation`: `{ code, field, step? }`, or
 *                    `null`). Each case breaks one rule;
 *   - builder        builder input and the member `buildContributions`
 *                    builds from it, or the code it refuses with;
 *   - checks         a whole payload and the reader's `contributions` and
 *                    `contributions.binding` rows (`checkContributions`,
 *                    Record §7.5, Verification §4.10), every reason and fact.
 *
 *   pnpm exec tsx scripts/generate-contributions-vectors.ts > vectors/contributions-vectors.json
 *
 * Every expected answer is written here from the specification, and the
 * script stops if the engine disagrees. The TS replay is
 * tests/cross-sdk/ts/contributions-vectors.test.ts; the Python recomputation
 * is tests/cross-sdk/test_contributions_vectors.py.
 */
import {
  buildContributions,
  checkContributions,
  contributionsViolation,
  outputDigest,
  stepDigest,
  type ContributionsInput,
} from '@tzun/engine';
import {
  ACCT,
  AGENT,
  AGENT_B,
  MODEL,
  MODEL_B,
  SPIFFE,
  agentDecider,
  bom,
  checker,
  digestOf,
  emit,
  human,
  payload,
  prefixed,
} from './generate-vectors-shared';

const { agree, stop } = checker('generate-contributions-vectors');

// ── output and step digests ─────────────────────────────────────────────

const outputDigests = [
  { label: 'an empty object', value: {} },
  { label: 'a proposal', value: { maxApprovedAmount: 25000, recommendation: 'approve', riskScore: 31 } },
  { label: 'the same proposal, members in another order (one digest)', value: { riskScore: 31, recommendation: 'approve', maxApprovedAmount: 25000 } },
  { label: 'a decision { action, reason }', value: { action: 'approve', reason: 'Income verified; reviewer found no fair-lending concerns' } },
  { label: 'a low-entropy verdict (guessable by enumeration)', value: { verdict: 'approve' } },
  {
    label: 'the salted convention of Record §7.6: the same verdict under a 16-byte salt',
    value: { salt: Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex').toString('base64url'), value: { verdict: 'approve' } },
  },
  { label: 'a byte output, as its { mediaType, sha256 } value', value: { mediaType: 'application/pdf', sha256: digestOf('a pdf') } },
  { label: 'a string', value: 'approve' },
  { label: 'null', value: null },
  { label: 'non-ASCII text, not normalised', value: { note: 'café \u{1F600}' } },
].map((o) => ({ ...o, digest: prefixed(o.value) }));
for (const o of outputDigests) agree(`outputDigest(${o.label})`, outputDigest(o.value), o.digest);
if (outputDigests[1].digest !== outputDigests[2].digest) stop('member order changed an output digest');

// ── a reference set of records ──────────────────────────────────────────

const ctxHuman = { decider: human(), action: 'approve', reason: 'Reviewed' };
const AI_OUTPUT = { recommendation: 'approve', score: 82 };
const P_OUT = outputDigest(AI_OUTPUT);
const REVIEW_OUT = outputDigest({ verdict: 'approve', factors: ['income'] });
const DECISION_OUT = outputDigest({ action: 'approve', reason: 'Reviewed' });
const agentActor = (agent = AGENT) => ({ kind: 'agent', id: `desc:${agent}`, agent });
const humanActor = (id = ACCT) => ({ kind: 'human', id, agent: null });

type Step = Record<string, unknown>;
/** Steps chained: each step's prev is the digest of the step before it. */
function chain(steps: Step[]): Step[] {
  const out: Step[] = [];
  for (let i = 0; i < steps.length; i++) out.push({ ...steps[i], prev: i === 0 ? null : stepDigest(out[i - 1]) });
  return out;
}
const step = (s: Partial<Record<string, unknown>>): Step => ({
  role: 'propose',
  actor: null,
  aiBom: null,
  inputs: [],
  output: P_OUT,
  verdict: null,
  reason: null,
  prev: null,
  ...s,
});
const C = (steps: Step[], extra: Record<string, unknown> = {}) => ({ pipeline: null, externals: [], steps: chain(steps), ...extra });

const one = C([step({ aiBom: bom() })]);
const proposeReviewDecide = C([
  step({ actor: agentActor(), aiBom: bom(MODEL) }),
  step({ role: 'review:fair-lending', actor: agentActor(AGENT_B), aiBom: bom(MODEL_B), inputs: [P_OUT], output: REVIEW_OUT, verdict: 'approve', reason: 'No concerns' }),
  step({ role: 'decide', actor: humanActor(), inputs: [P_OUT, REVIEW_OUT].sort(), output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
]);

// ── shapes ───────────────────────────────────────────────────────────────

type Violation = { code: string; field: string; step?: number } | null;
const shapes: Array<{ case: string; value: unknown; context: Record<string, unknown>; violation: Violation }> = [];
const shape = (c: string, value: unknown, violation: Violation, context: Record<string, unknown> = ctxHuman) =>
  shapes.push({ case: c, value, context, violation });
const v = (code: string, field: string, s?: number): Violation => ({ code, field, ...(s !== undefined && { step: s }) });
const withStep = (base: ReturnType<typeof C>, i: number, edit: (s: Step) => Step, rechain = true) => {
  const steps = base.steps.map((s, j) => (j === i ? edit({ ...s }) : { ...s }));
  return { ...base, steps: rechain ? chain(steps) : steps };
};

shape('null: no contributions', null, null);
shape('a list of one, a model called directly (actor null)', one, null);
shape('propose, review and decide', proposeReviewDecide, null);
shape('declared externals, sorted', { ...one, externals: [prefixed('request a'), prefixed('request b')].sort() }, null);
shape('a pipeline digest (accepted; the reader abstains on it)', { ...one, pipeline: prefixed('pipeline') }, null);
shape('a step reason of 16,384 UTF-16 code units', withStep(one, 0, (s) => ({ ...s, role: 'other', reason: 'r'.repeat(16384) })), null);
shape('a step reason holding astral characters', withStep(one, 0, (s) => ({ ...s, role: 'other', reason: '\u{1F600}'.repeat(3) })), null);
shape('an other step after the decide step (it carries the decision out)', C([
  ...proposeReviewDecide.steps.map((s) => ({ ...s })),
  step({ role: 'other:execute', actor: agentActor(), inputs: [DECISION_OUT], output: prefixed('executed') }),
]), null);
shape('a role at its longest name (48 characters)', withStep(one, 0, (s) => ({ ...s, role: 'propose:' + 'n'.repeat(48) })), null);

shape('an array', [one], v('not_an_object', 'contributions'));
shape('a string', 'contributions', v('not_an_object', 'contributions'));
shape('a member outside the three', { ...one, note: 'x' }, v('unknown_members', 'contributions'));
shape('pipeline missing', { externals: [], steps: one.steps }, v('missing_members', 'contributions'));
shape('a bare pipeline digest', { ...one, pipeline: digestOf('pipeline') }, v('invalid_pipeline', 'contributions.pipeline'));
shape('a bare external', { ...one, externals: [digestOf('request')] }, v('invalid_externals', 'contributions.externals'));
shape('65 externals', { ...one, externals: Array.from({ length: 65 }, (_, i) => prefixed(`external ${i}`)).sort() }, v('invalid_externals', 'contributions.externals'));
shape('externals unsorted', { ...one, externals: [prefixed('request a'), prefixed('request b')].sort().reverse() }, v('not_a_set', 'contributions.externals'));
shape('an external repeated', { ...one, externals: [prefixed('request a'), prefixed('request a')] }, v('not_a_set', 'contributions.externals'));
shape('no steps', { ...one, steps: [] }, v('no_steps', 'contributions.steps'));
shape('33 steps', C(Array.from({ length: 33 }, (_, i) => step({ aiBom: bom(), output: prefixed(`proposal ${i}`) }))), v('too_many_steps', 'contributions.steps'));
shape('a step member outside the eight (outputOf belongs to builder input)', withStep(one, 0, (s) => ({ ...s, outputOf: AI_OUTPUT })), v('step_unknown_members', 'contributions.steps[0]', 0));
shape('a step without prev', withStep(one, 0, (s) => {
  const { prev: _prev, ...rest } = s;
  return rest;
}, false), v('step_missing_members', 'contributions.steps[0]', 0));
shape('a role outside the four classes', withStep(one, 0, (s) => ({ ...s, role: 'approve' })), v('invalid_role', 'contributions.steps[0].role', 0));
shape('a role with an empty name', withStep(one, 0, (s) => ({ ...s, role: 'propose:' })), v('invalid_role', 'contributions.steps[0].role', 0));
shape('a role name of 49 characters', withStep(one, 0, (s) => ({ ...s, role: 'propose:' + 'n'.repeat(49) })), v('invalid_role', 'contributions.steps[0].role', 0));
shape('a role in another case', withStep(one, 0, (s) => ({ ...s, role: 'Propose' })), v('invalid_role', 'contributions.steps[0].role', 0));
shape('an actor of a kind this version does not know (a writer refuses it)', withStep(one, 0, (s) => ({ ...s, actor: { kind: 'committee', id: SPIFFE, agent: AGENT } })), v('invalid_actor', 'contributions.steps[0].actor', 0));
shape('an actor without its agent member', withStep(one, 0, (s) => ({ ...s, actor: { kind: 'human', id: ACCT } })), v('invalid_actor', 'contributions.steps[0].actor', 0));
shape('an actor carrying freshness (a step actor has exactly kind, id and agent)', withStep(one, 0, (s) => ({ ...s, actor: { ...humanActor(), freshness: null } })), v('invalid_actor', 'contributions.steps[0].actor', 0));
shape('an actor under acct with an email address', withStep(one, 0, (s) => ({ ...s, actor: humanActor('acct:jane@example.com') })), v('invalid_actor', 'contributions.steps[0].actor', 0));
shape('an agent actor naming no reference', withStep(one, 0, (s) => ({ ...s, actor: { kind: 'agent', id: SPIFFE, agent: null } })), v('invalid_actor', 'contributions.steps[0].actor', 0));
shape('a null actor on a step with no model', withStep(one, 0, (s) => ({ ...s, aiBom: null })), v('actor_required', 'contributions.steps[0].actor', 0));
shape('a null actor on the decide step', withStep(proposeReviewDecide, 2, (s) => ({ ...s, actor: null, aiBom: bom() })), v('actor_required', 'contributions.steps[2].actor', 2));
shape('a step aiBom missing a nullable key', withStep(one, 0, (s) => {
  const { vendorFingerprint: _vf, ...rest } = bom();
  return { ...s, aiBom: rest };
}), v('invalid_step_ai_bom', 'contributions.steps[0].aiBom', 0));
shape('a step aiBom with inferenceParameters missing seed', withStep(one, 0, (s) => ({
  ...s,
  aiBom: { ...bom(), inferenceParameters: { temperature: 0, topP: null, maxTokens: 800, stopSequences: null } },
})), v('invalid_step_ai_bom', 'contributions.steps[0].aiBom', 0));
shape('a step aiBom with a bare model digest', withStep(one, 0, (s) => ({ ...s, aiBom: bom(MODEL.slice(7)) })), v('invalid_step_ai_bom', 'contributions.steps[0].aiBom', 0));
shape('a bare input', withStep(one, 0, (s) => ({ ...s, inputs: [digestOf('input')] })), v('invalid_inputs', 'contributions.steps[0].inputs', 0));
shape('65 inputs', { ...withStep(one, 0, (s) => ({ ...s, inputs: Array.from({ length: 65 }, (_, i) => prefixed(`input ${i}`)).sort() })), externals: [] }, v('invalid_inputs', 'contributions.steps[0].inputs', 0));
shape('inputs unsorted', withStep(one, 0, (s) => ({ ...s, inputs: [prefixed('a'), prefixed('b')].sort().reverse() })), v('not_a_set', 'contributions.steps[0].inputs', 0));
shape('an input repeated', withStep(one, 0, (s) => ({ ...s, inputs: [prefixed('a'), prefixed('a')] })), v('not_a_set', 'contributions.steps[0].inputs', 0));
shape('a bare output', withStep(one, 0, (s) => ({ ...s, output: P_OUT.slice(7) })), v('invalid_output', 'contributions.steps[0].output', 0));
shape('a verdict outside the three', withStep(proposeReviewDecide, 1, (s) => ({ ...s, verdict: 'approved' })), v('invalid_verdict', 'contributions.steps[1].verdict', 1));
shape('a verdict on a propose step', withStep(one, 0, (s) => ({ ...s, verdict: 'approve' })), v('verdict_not_allowed', 'contributions.steps[0].verdict', 0));
shape('a verdict on an other step', withStep(one, 0, (s) => ({ ...s, role: 'other', verdict: 'concerns' })), v('verdict_not_allowed', 'contributions.steps[0].verdict', 0));
shape('an empty step reason (write null)', withStep(one, 0, (s) => ({ ...s, reason: '' })), v('invalid_step_reason', 'contributions.steps[0].reason', 0));
shape('a step reason of 16,385 UTF-16 code units', withStep(one, 0, (s) => ({ ...s, reason: 'r'.repeat(16385) })), v('invalid_step_reason', 'contributions.steps[0].reason', 0));
shape('a step reason of 8,193 astral characters (16,386 UTF-16 code units)', withStep(one, 0, (s) => ({ ...s, reason: '\u{1F600}'.repeat(8193) })), v('invalid_step_reason', 'contributions.steps[0].reason', 0));
shape('a step reason that is a number', withStep(one, 0, (s) => ({ ...s, reason: 3 })), v('invalid_step_reason', 'contributions.steps[0].reason', 0));
shape('a prev on step 0', withStep(one, 0, (s) => ({ ...s, prev: prefixed('earlier') }), false), v('prev_mismatch', 'contributions.steps[0].prev', 0));
shape('a malformed prev', withStep(one, 0, (s) => ({ ...s, prev: 'x' }), false), v('prev_mismatch', 'contributions.steps[0].prev', 0));
shape('step 1 chained to another step', { ...proposeReviewDecide, steps: proposeReviewDecide.steps.map((s, i) => (i === 1 ? { ...s, prev: prefixed('another step') } : s)) }, v('prev_mismatch', 'contributions.steps[1].prev', 1));
shape('two decide steps', C([
  step({ aiBom: bom() }),
  step({ role: 'decide', actor: humanActor(), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  step({ role: 'decide:again', actor: humanActor(), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
]), v('multiple_deciding_steps', 'contributions.steps'));
shape('a propose step after the decide step', C([
  step({ aiBom: bom() }),
  step({ role: 'decide', actor: humanActor(), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  step({ aiBom: bom(), output: prefixed('late proposal') }),
]), v('step_after_deciding', 'contributions.steps[2].role', 2));
shape('a review step after the decide step', C([
  step({ aiBom: bom() }),
  step({ role: 'decide', actor: humanActor(), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  step({ role: 'review', actor: agentActor(), aiBom: bom(), inputs: [P_OUT], output: REVIEW_OUT, verdict: 'approve' }),
]), v('step_after_deciding', 'contributions.steps[2].role', 2));
shape('a decide step whose actor is another person', proposeReviewDecide, v('decider_not_deciding_actor', 'contributions.steps[2].actor', 2), {
  ...ctxHuman,
  decider: human('acct:u-7702'),
});
shape('a decide step whose actor is the decider under another kind', proposeReviewDecide, v('decider_not_deciding_actor', 'contributions.steps[2].actor', 2), {
  ...ctxHuman,
  decider: agentDecider(),
});
shape('a decide step whose output is not the record\'s decision', proposeReviewDecide, v('deciding_output_mismatch', 'contributions.steps[2].output', 2), {
  ...ctxHuman,
  action: 'reject',
});
shape('a decide step, the record\'s reason another', proposeReviewDecide, v('deciding_output_mismatch', 'contributions.steps[2].output', 2), {
  ...ctxHuman,
  reason: 'Reviewed again',
});
for (const s of shapes) {
  const got = contributionsViolation(s.value, s.context as never);
  agree(`shapes "${s.case}"`, got && { code: got.code, field: got.field, ...(got.step !== undefined && { step: got.step }) }, s.violation);
}

// ── builder ──────────────────────────────────────────────────────────────

const builder: Array<{ case: string; input: unknown; context: Record<string, unknown>; built?: unknown; refused?: { code: string; field: string } }> = [];
const built = (c: string, input: ContributionsInput, context: Record<string, unknown>, expected: unknown) => builder.push({ case: c, input, context, built: expected });
const refused = (c: string, input: unknown, context: Record<string, unknown>, code: string, field: string) =>
  builder.push({ case: c, input, context, refused: { code, field } });
const bctx = { ...ctxHuman, aiOutput: AI_OUTPUT };

built('a list of one: the propose step\'s output from aiOutput, every nullable aiBom member written', {
  steps: [{ role: 'propose', actor: null, aiBom: { modelDescriptorDigest: MODEL }, inputs: [] }],
} as unknown as ContributionsInput, bctx, { pipeline: null, externals: [], steps: [step({ aiBom: bom() })] });
built('an agent actor without an id gets desc:<agent>', {
  steps: [{ role: 'propose', actor: { kind: 'agent', agent: AGENT }, aiBom: bom() }],
}, bctx, { pipeline: null, externals: [], steps: [step({ actor: agentActor(), aiBom: bom() })] });
built('inputs and externals sorted by bytes', {
  externals: [prefixed('request b'), prefixed('request a')],
  steps: [{ role: 'propose', actor: null, aiBom: bom(), inputs: [prefixed('request b'), prefixed('request a')] }],
}, bctx, {
  pipeline: null,
  externals: [prefixed('request a'), prefixed('request b')].sort(),
  steps: [step({ aiBom: bom(), inputs: [prefixed('request a'), prefixed('request b')].sort() })],
});
built('propose, review and decide: outputs from outputOf, aiOutput and the decision; the decide step takes the record\'s reason; prev chained', {
  steps: [
    { role: 'propose', actor: { kind: 'agent', agent: AGENT }, aiBom: bom(MODEL) },
    { role: 'review:fair-lending', actor: { kind: 'agent', agent: AGENT_B }, aiBom: bom(MODEL_B), inputs: [P_OUT], outputOf: { verdict: 'approve', factors: ['income'] }, verdict: 'approve', reason: 'No concerns' },
    { role: 'decide', actor: { kind: 'human', id: ACCT, agent: null }, inputs: [REVIEW_OUT, P_OUT], verdict: 'approve' },
  ],
}, bctx, proposeReviewDecide);
built('the last propose step before the decide step takes aiOutput; an earlier one keeps its own output', {
  steps: [
    { role: 'propose', actor: null, aiBom: bom(), output: prefixed('first proposal') },
    { role: 'propose', actor: null, aiBom: bom() },
  ],
}, bctx, C([step({ aiBom: bom(), output: prefixed('first proposal') }), step({ aiBom: bom() })]));
refused('a supplied prev that differs from the computed one', {
  steps: [{ role: 'propose', actor: null, aiBom: bom(), prev: prefixed('elsewhere') }],
}, bctx, 'prev_mismatch', 'contributions.steps[0].prev');
refused('an input repeated (the builder sorts, never removes)', {
  steps: [{ role: 'propose', actor: null, aiBom: bom(), inputs: [prefixed('a'), prefixed('a')] }],
}, bctx, 'not_a_set', 'contributions.steps[0].inputs');
refused('a member the builder form does not have', {
  steps: [{ role: 'propose', actor: null, aiBom: bom(), note: 'x' }],
}, bctx, 'step_unknown_members', 'contributions.steps[0]');
refused('an actor member outside kind, id and agent', {
  steps: [{ role: 'propose', actor: { kind: 'agent', agent: AGENT, credential: null }, aiBom: bom() }],
}, bctx, 'invalid_actor', 'contributions.steps[0].actor');
refused('a member outside pipeline, externals and steps', { steps: [{ role: 'propose', aiBom: bom() }], lineage: [] }, bctx, 'unknown_members', 'contributions');
refused('no steps', { steps: [] }, bctx, 'no_steps', 'contributions.steps');
refused('a decide step whose actor is not the decider', {
  steps: [{ role: 'propose', aiBom: bom() }, { role: 'decide', actor: { kind: 'human', id: 'acct:u-7702', agent: null }, inputs: [P_OUT] }],
}, bctx, 'decider_not_deciding_actor', 'contributions.steps[1].actor');
for (const b of builder) {
  let got: unknown;
  try {
    got = { built: buildContributions(b.input as ContributionsInput, b.context as never) };
  } catch (e) {
    const err = e as { code?: string; field?: string };
    got = { refused: { code: err.code, field: err.field } };
  }
  agree(`builder "${b.case}"`, got, b.built !== undefined ? { built: b.built } : { refused: b.refused });
}

// ── checks: the reader's rows ───────────────────────────────────────────

const BLOCKED = (reason: string) => ({
  outcome: 'not-checked', valid: null, reason, approvals: [], staleApprovals: [], uncoveredReviews: [], proposals: [], decisionBinding: 'not-applicable',
});
const correct = (steps: number, models: string[], decidingStep: number | 'record', binding: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  outcome: 'checked-correct', valid: true, steps, models, decidingStep, binding, ...extra,
});
const bound = (b: Partial<Record<string, unknown>>) => ({
  outcome: 'checked-correct', valid: true, approvals: [], staleApprovals: [], uncoveredReviews: [], proposals: [], decisionBinding: 'checked', ...b,
});
const unbound = (reason: string, failedStep: number, failedDigest: string | undefined, b: Partial<Record<string, unknown>>) => ({
  outcome: 'checked-wrong', valid: false, reason, approvals: [], staleApprovals: [], uncoveredReviews: [], proposals: [], decisionBinding: 'checked',
  ...b, failedStep, ...(failedDigest !== undefined && { failedDigest }),
});
const wrong = (reason: string, failedStep?: number) => ({
  outcome: 'checked-wrong', valid: false, reason, ...(failedStep !== undefined && { failedStep }), binding: BLOCKED('blocked_by:contributions'),
});

const checks: Array<{ case: string; payload: Record<string, unknown>; expect: unknown }> = [];
const check = (c: string, p: Record<string, unknown>, expect: unknown) => checks.push({ case: c, payload: p, expect });

const linkTarget = digestOf('intake decision');
const link = (rel: string, digest = linkTarget) => ({ rel, target: { digest, evidenceId: null, locator: null }, attrs: null });

check('contributions null', payload(), { outcome: 'not-checked', valid: null, reason: 'absent', binding: BLOCKED('absent') });
check('a list of one by the deciding agent itself (as W1)', payload({
  decider: agentDecider(),
  contributions: C([step({ actor: agentActor(), aiBom: bom() })]),
}), correct(1, [MODEL], 'record', bound({ proposals: [0] })));
check('a list of one, the model called directly (as W2)', payload({ contributions: one }), correct(1, [MODEL], 'record', bound({ proposals: [0] })));
check('propose, review and decide', payload({ contributions: proposeReviewDecide }), correct(3, [MODEL, MODEL_B], 2, bound({ proposals: [0], approvals: [1] })));
check('a pipeline digest: the structure holds and the pipeline row abstains', payload({ contributions: { ...one, pipeline: prefixed('pipeline') } }), correct(
  1, [MODEL], 'record', bound({ proposals: [0] }), { pipeline: { outcome: 'abstain', reason: 'unsupported_pipeline' } },
));
check('the chain broken at step 1', payload({
  contributions: { ...proposeReviewDecide, steps: proposeReviewDecide.steps.map((s, i) => (i === 1 ? { ...s, prev: prefixed('another step') } : s)) },
}), wrong('step_chain_broken', 1));
check('a prev on step 0', payload({ contributions: { ...one, steps: [{ ...one.steps[0], prev: prefixed('earlier') }] } }), wrong('step_chain_broken', 0));
check('a decide step whose actor is not the decider', payload({ decider: human('acct:u-7702'), contributions: proposeReviewDecide }), wrong('decider_not_deciding_actor', 2));
check('a decide step whose output is not the record\'s decision', payload({ action: 'reject', contributions: proposeReviewDecide }), wrong('deciding_output_mismatch', 2));
check('an input that no step produced, no link names and no external declares', payload({
  contributions: C([step({ aiBom: bom(), inputs: [prefixed('undeclared')] })]),
}), correct(1, [MODEL], 'record', unbound('input_undeclared', 0, prefixed('undeclared'), { proposals: [0] })));
check('an input that is a link target (accepted)', payload({
  contributions: C([step({ aiBom: bom(), inputs: [`sha256:${linkTarget}`] })]),
  links: [link('derivedFrom')],
}), correct(1, [MODEL], 'record', bound({ proposals: [0] })));
check('an input that is a link target, the links malformed (they declare none)', payload({
  contributions: C([step({ aiBom: bom(), inputs: [`sha256:${linkTarget}`] })]),
  links: [link('derivedFrom'), link('derivedFrom')],
}), correct(1, [MODEL], 'record', unbound('input_undeclared', 0, `sha256:${linkTarget}`, { proposals: [0] })));
check('an input that is a declared external', payload({
  contributions: { ...C([step({ aiBom: bom(), inputs: [prefixed('the request')] })]), externals: [prefixed('the request')] },
}), correct(1, [MODEL], 'record', bound({ proposals: [0] })));
check('a review that does not include the proposal it covers', payload({
  contributions: C([
    step({ aiBom: bom() }),
    step({ role: 'review', actor: agentActor(AGENT_B), aiBom: bom(MODEL_B), inputs: [], output: REVIEW_OUT, verdict: 'approve' }),
    step({ role: 'decide', actor: humanActor(), inputs: [P_OUT, REVIEW_OUT].sort(), output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  ]),
}), correct(3, [MODEL, MODEL_B], 2, unbound('review_unbound', 1, P_OUT, { proposals: [0] })));
const P2 = outputDigest({ recommendation: 'approve', score: 82, revised: true });
check('a stale approval: the proposal revised after the review, the new one unreviewed', payload({
  aiOutput: { recommendation: 'approve', score: 82, revised: true },
  contributions: C([
    step({ aiBom: bom() }),
    step({ role: 'review', actor: agentActor(AGENT_B), aiBom: bom(MODEL_B), inputs: [P_OUT], output: REVIEW_OUT, verdict: 'approve' }),
    step({ role: 'propose:revised', aiBom: bom(), inputs: [REVIEW_OUT], output: P2 }),
    step({ role: 'decide', actor: humanActor(), inputs: [P2], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  ]),
}), correct(4, [MODEL, MODEL_B], 3, bound({ proposals: [0, 2], staleApprovals: [1] })));
check('a concerns review of the final proposal: bound, not an approval', payload({
  contributions: C([
    step({ aiBom: bom() }),
    step({ role: 'review', actor: agentActor(AGENT_B), aiBom: bom(MODEL_B), inputs: [P_OUT], output: REVIEW_OUT, verdict: 'concerns', reason: 'Income proof is old' }),
    step({ role: 'decide', actor: humanActor(), inputs: [P_OUT, REVIEW_OUT].sort(), output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  ]),
}), correct(3, [MODEL, MODEL_B], 2, bound({ proposals: [0] })));
check('a decision whose inputs do not include the final proposal', payload({
  contributions: C([
    step({ aiBom: bom() }),
    step({ role: 'decide', actor: humanActor(), inputs: [], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  ]),
}), correct(2, [MODEL], 1, unbound('decision_unbound', 1, P_OUT, { proposals: [0] })));
const W3S_OUTPUT = { recommendation: 'approve', score: 82, amount: 45000 };
check('the output swapped after the review, re-hashed (as W3s)', payload({ aiOutput: W3S_OUTPUT, contributions: proposeReviewDecide }), correct(
  3, [MODEL, MODEL_B], 2, unbound('decided_output_differs', 0, P_OUT, { proposals: [0], approvals: [1] }),
));
check('a decide step alone: decision binding not applicable', payload({
  contributions: C([step({ role: 'decide', actor: humanActor(), inputs: [], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' })]),
}), correct(1, [], 0, bound({ decisionBinding: 'not-applicable' })));
check('review and decide with no proposal: the review covers no step', payload({
  contributions: C([
    step({ role: 'review', actor: agentActor(), aiBom: bom(), inputs: [], output: REVIEW_OUT, verdict: 'approve' }),
    step({ role: 'decide', actor: humanActor(), inputs: [REVIEW_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  ]),
}), correct(2, [MODEL], 1, bound({ uncoveredReviews: [0], decisionBinding: 'not-applicable' })));
check('a review before the first proposal covers no step', payload({
  contributions: C([
    step({ role: 'review', actor: agentActor(AGENT_B), aiBom: bom(MODEL_B), inputs: [], output: REVIEW_OUT, verdict: 'approve' }),
    step({ aiBom: bom(), inputs: [REVIEW_OUT] }),
    step({ role: 'decide', actor: humanActor(), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  ]),
}), correct(3, [MODEL_B, MODEL], 2, bound({ proposals: [1], uncoveredReviews: [0] })));
check('an actor of a kind this version does not know: abstain', payload({
  contributions: C([step({ actor: { kind: 'committee', id: SPIFFE, agent: AGENT }, aiBom: bom() })]),
}), { outcome: 'abstain', valid: null, reason: 'unsupported_actor_kind', binding: BLOCKED('blocked_by:contributions') });
check('an actor under a scheme this version does not know: abstain', payload({
  contributions: C([step({ actor: { kind: 'agent', id: 'did:example:7', agent: AGENT }, aiBom: bom() })]),
}), { outcome: 'abstain', valid: null, reason: 'unsupported_identifier_scheme', binding: BLOCKED('blocked_by:contributions') });
check('an unknown actor kind and a broken chain: the failure is reported, not the abstention', payload({
  contributions: { pipeline: null, externals: [], steps: [
    step({ actor: { kind: 'committee', id: SPIFFE, agent: AGENT }, aiBom: bom() }),
    step({ actor: agentActor(), aiBom: bom(), output: prefixed('second'), prev: prefixed('not the first step') }),
  ] },
}), wrong('step_chain_broken', 1));
check('a null actor on the decide step', payload({
  contributions: { ...proposeReviewDecide, steps: chain(proposeReviewDecide.steps.map((s, i) => (i === 2 ? { ...s, actor: null, aiBom: bom() } : s))) },
}), wrong('malformed_contributions', 2));
check('a null actor and a null aiBom', payload({ contributions: C([step({})]) }), wrong('malformed_contributions', 0));
check('inputs unsorted (a reader never re-sorts)', payload({
  contributions: C([step({ aiBom: bom(), inputs: [prefixed('a'), prefixed('b')].sort().reverse() })]),
}), wrong('malformed_contributions', 0));
check('a step aiBom missing a key is hashed as given (a reader does not interpret it)', payload({
  contributions: C([step({ aiBom: { modelDescriptorDigest: MODEL } })]),
}), correct(1, [MODEL], 'record', bound({ proposals: [0] })));
check('no steps', payload({ contributions: { pipeline: null, externals: [], steps: [] } }), wrong('malformed_contributions'));
check('two decide steps', payload({
  contributions: C([
    step({ aiBom: bom() }),
    step({ role: 'decide', actor: humanActor(), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
    step({ role: 'decide', actor: humanActor(), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  ]),
}), wrong('malformed_contributions'));
check('a propose step after the decide step', payload({
  contributions: C([
    step({ aiBom: bom() }),
    step({ role: 'decide', actor: humanActor(), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
    step({ aiBom: bom(), output: prefixed('late') }),
  ]),
}), wrong('malformed_contributions', 2));
check('an acct actor value with @: the reader applies only the general grammar', payload({
  decider: human('acct:jane@example.com'),
  contributions: C([
    step({ aiBom: bom() }),
    step({ role: 'decide', actor: humanActor('acct:jane@example.com'), inputs: [P_OUT], output: DECISION_OUT, verdict: 'approve', reason: 'Reviewed' }),
  ]),
}), correct(2, [MODEL], 1, bound({ proposals: [0] })));
check('contributions that are not an object', payload({ contributions: [] }), wrong('malformed_contributions'));
for (const c of checks) agree(`checks "${c.case}"`, checkContributions(c.payload), c.expect);

const stepDigests = [
  ...one.steps.map((s, index) => ({ label: `a list of one, step ${index}`, step: s })),
  ...proposeReviewDecide.steps.map((s, index) => ({ label: `propose, review and decide, step ${index}`, step: s })),
].map((s) => ({ ...s, digest: prefixed(s.step) }));
for (const s of stepDigests) agree(`stepDigest(${s.label})`, stepDigest(s.step), s.digest);

emit({
  description:
    'The contributions member of a v1.0 record (Record §7): output and step digests, the writer\'s structure rules, the builder, ' +
    'and the reader\'s contributions and contributions.binding rows (Verification §4.10).',
  source:
    'Generated by scripts/generate-contributions-vectors.ts. Every expected answer is written in the script from the specification, and the ' +
    'script stops if the engine disagrees with one. A shapes case breaks one rule. A checks payload is read as stored: the reader ' +
    'applies the general identifier grammar and abstains on actor kinds and schemes it does not know, after every check that does not ' +
    'depend on them.',
  outputDigests,
  stepDigests,
  shapes,
  builder,
  checks,
});
