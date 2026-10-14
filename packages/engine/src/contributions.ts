/**
 * The contributions member (Record §7): output and step digests, the
 * builder, the writer's structure rules and the reader's two rows
 * (`contributions` for structure, `contributions.binding` for process). It is
 * the only place a record states a model's bill of materials: a single model
 * is a list of one `propose` step (`singleModel`).
 *
 *   outputDigest(v) = "sha256:" ‖ hex(SHA-256(C(v)))
 *   stepDigest(i)   = "sha256:" ‖ hex(SHA-256(C(steps[i])))
 *
 * A `decide` step is optional. When one exists it is the deciding step: the
 * record's decider is its actor and its output is the record's decision. When
 * none does, the record's decider decided after the last step.
 *
 * Capture refuses broken structure (a malformed shape, a broken step chain, a
 * decide step whose actor is not the decider, a decide step whose output is
 * not the record's decision); it accepts a flawed process (an unbound review,
 * a stale approval, a changed output), which the reader reports.
 */
import { aiBomViolation, fillAiBomNulls } from './ai-bom';
import {
  actorViolation,
  defaultAgentDeciderId,
  identifierScheme,
  isDeciderKind,
  readerActorInconsistent,
  DECIDER_SCHEMES,
  sameActor,
} from './decider';
import { linkTargetInputs } from './links';
import { REASON_MAX_LENGTH } from './payload-rules';
import {
  canonicalValue,
  compareBytes,
  hasExactKeys,
  hasLoneSurrogate,
  isPlainObject,
  isPrefixedDigest,
  isStrictlyIncreasing,
  sha256Hex,
} from './record-rules-util';
import type { AiBom, AiBomWithInlineDescriptor } from './types/ai-bom';
import type {
  ContributionStep,
  ContributionStepClass,
  Contributions,
  ContributionsInput,
  ContributionsViolation,
  ContributionsViolationCode,
  StepActorInput,
} from './types/contributions';
import type { ContributionsBindingCheck, ContributionsCheck } from './types/verification';

/** The most steps a contributions member holds (a grammar maximum). */
export const CONTRIBUTIONS_MAX_STEPS = 32;
/** The most `inputs` per step, and the most `externals` (grammar maxima). */
export const CONTRIBUTIONS_MAX_SET = 64;

const CONTRIBUTIONS_KEYS = ['pipeline', 'externals', 'steps'] as const;
const STEP_KEYS = ['role', 'actor', 'aiBom', 'inputs', 'output', 'verdict', 'reason', 'prev'] as const;
const ACTOR_KEYS = ['kind', 'id', 'agent'] as const;
/** The members a builder step may carry: a step's, plus `outputOf`. */
const STEP_INPUT_KEYS = [...STEP_KEYS, 'outputOf'] as const;
const ROLE_RE = /^(propose|review|decide|other)(:[A-Za-z0-9._-]{1,48})?$/;
const VERDICTS = ['approve', 'reject', 'concerns'];

/** `"sha256:" ‖ hex(SHA-256(C(value)))`. @throws when the value cannot be canonically serialized. */
export function outputDigest(value: unknown): string {
  return 'sha256:' + sha256Hex(canonicalValue(value));
}

/** The step digest of one step: `"sha256:" ‖ hex(SHA-256(C(step)))`. @throws as `outputDigest`. */
export function stepDigest(step: unknown): string {
  return outputDigest(step);
}

/** The class of a role, read from the part before the first `:`; `null` for a role that is not one. */
export function stepClass(role: unknown): ContributionStepClass | null {
  if (typeof role !== 'string' || !ROLE_RE.test(role)) return null;
  return role.split(':')[0] as ContributionStepClass;
}

/**
 * The index of the deciding step (Record §7.3): the one `decide` step, or `null`
 * when no step has the class (the record's decider decided after the last
 * step). `-1` when more than one step has it, which is malformed.
 */
export function decidingStepIndex(steps: readonly unknown[]): number | null {
  const decides = steps
    .map((s, i) => (isPlainObject(s) && stepClass(s.role) === 'decide' ? i : -1))
    .filter((i) => i >= 0);
  if (decides.length > 1) return -1;
  return decides.length === 1 ? decides[0] : null;
}

/** The output a decide step must have: `outputDigest({ action, reason })`. */
export function decidingOutput(action: unknown, reason: unknown): string {
  return outputDigest({ action, reason });
}

/** The index of the last `propose` step before `before` (exclusive), or `undefined`. */
function lastProposalBefore(steps: readonly { role?: unknown }[], before: number): number | undefined {
  for (let i = Math.min(before, steps.length) - 1; i >= 0; i--) if (stepClass(steps[i].role) === 'propose') return i;
  return undefined;
}

const MESSAGES: Record<ContributionsViolationCode, string> = {
  not_an_object: 'contributions must be null or an object',
  unknown_members: 'contributions may have only the members pipeline, externals and steps',
  missing_members: 'contributions must have every member (pipeline, externals, steps)',
  invalid_pipeline: 'contributions.pipeline must be null or sha256: followed by 64 lowercase hex',
  invalid_externals: `contributions.externals must be an array of at most ${CONTRIBUTIONS_MAX_SET} prefixed digests`,
  not_a_set: 'the array must be strictly increasing by bytes, with no repeated element',
  no_steps: 'contributions.steps must be a non-empty array',
  too_many_steps: `contributions.steps holds at most ${CONTRIBUTIONS_MAX_STEPS} steps`,
  step_unknown_members: `a step may have only the members ${STEP_KEYS.join(', ')}`,
  step_missing_members: `a step must have every member (${STEP_KEYS.join(', ')}), null where it does not apply`,
  invalid_role: 'role must be propose, review, decide or other, optionally followed by :[A-Za-z0-9._-]{1,48}',
  invalid_actor: 'actor must be null or have exactly kind, id and agent, with the decider grammar and consistency',
  actor_required: 'actor may be null only on a step that is not a decide step and records a model (aiBom)',
  invalid_step_ai_bom: 'a step aiBom must be null or an exact AiBom naming a catalogued descriptor',
  invalid_inputs: `inputs must be an array of at most ${CONTRIBUTIONS_MAX_SET} prefixed digests`,
  invalid_output: 'output must be sha256: followed by 64 lowercase hex',
  invalid_verdict: 'verdict must be null, approve, reject or concerns',
  verdict_not_allowed: 'a propose or other step must have verdict null',
  invalid_step_reason: `a step reason must be null or 1 to ${REASON_MAX_LENGTH} UTF-16 code units with no lone surrogate`,
  prev_mismatch: 'prev must be null on step 0 and the step digest of the step before on every later step',
  multiple_deciding_steps: 'at most one step has the decide class',
  step_after_deciding: 'no propose or review step follows the decide step',
  decider_not_deciding_actor: "the record's decider must equal the decide step's actor (kind, id, agent)",
  deciding_output_mismatch: "a decide step's output must be outputDigest({ action, reason }) of the record",
};

function violation(code: ContributionsViolationCode, field: string, step?: number): ContributionsViolation {
  return { code, field, message: `${field}: ${MESSAGES[code]}`, ...(step !== undefined && { step }) };
}

/**
 * The record members the rules read beside the contributions member: the
 * record's `decider`, `action` and `reason`, and (for the builder) its
 * `aiOutput`. The structure rules require `decider`, `action` and `reason`,
 * so no rule is skipped for want of one: a missing `decider` is not the decide
 * step's actor, and a missing `action` or `reason` is no decision a decide
 * step's output can equal.
 */
export interface ContributionsContext {
  decider: unknown;
  action: unknown;
  reason: unknown;
  /** The builder fills the last `propose` step's output from it, when the step gives none. */
  aiOutput?: unknown;
}

/** Shape of one step, as a writer requires it. */
function stepShapeViolation(step: unknown, i: number): ContributionsViolation | null {
  const f = `contributions.steps[${i}]`;
  if (!isPlainObject(step)) return violation('step_unknown_members', f, i);
  if (Object.keys(step).some((k) => !(STEP_KEYS as readonly string[]).includes(k))) return violation('step_unknown_members', f, i);
  if (!hasExactKeys(step, STEP_KEYS)) return violation('step_missing_members', f, i);
  const cls = stepClass(step.role);
  if (cls === null) return violation('invalid_role', `${f}.role`, i);
  const actor = step.actor;
  if (actor === null) {
    if (step.aiBom === null || cls === 'decide') return violation('actor_required', `${f}.actor`, i);
  } else if (!isPlainObject(actor) || !hasExactKeys(actor, ACTOR_KEYS) || actorViolation(actor, `${f}.actor`, false) !== null) {
    return violation('invalid_actor', `${f}.actor`, i);
  }
  if (step.aiBom !== null && aiBomViolation(step.aiBom, `${f}.aiBom`) !== null) {
    return violation('invalid_step_ai_bom', `${f}.aiBom`, i);
  }
  const inputs = step.inputs;
  if (!Array.isArray(inputs) || inputs.length > CONTRIBUTIONS_MAX_SET || !inputs.every(isPrefixedDigest)) {
    return violation('invalid_inputs', `${f}.inputs`, i);
  }
  if (!isStrictlyIncreasing(inputs as string[])) return violation('not_a_set', `${f}.inputs`, i);
  if (!isPrefixedDigest(step.output)) return violation('invalid_output', `${f}.output`, i);
  if (step.verdict !== null && !(typeof step.verdict === 'string' && VERDICTS.includes(step.verdict))) {
    return violation('invalid_verdict', `${f}.verdict`, i);
  }
  if (step.verdict !== null && (cls === 'propose' || cls === 'other')) {
    return violation('verdict_not_allowed', `${f}.verdict`, i);
  }
  const reason = step.reason;
  if (
    reason !== null &&
    (typeof reason !== 'string' || reason.length < 1 || reason.length > REASON_MAX_LENGTH || hasLoneSurrogate(reason))
  ) {
    return violation('invalid_step_reason', `${f}.reason`, i);
  }
  if (step.prev !== null && !isPrefixedDigest(step.prev)) return violation('prev_mismatch', `${f}.prev`, i);
  return null;
}

/**
 * Why `value` is not a contributions member a writer may write, first failure
 * first, or `null` when it is one (or is `null`). `context` holds the record's
 * `decider`, `action` and `reason`.
 */
export function contributionsViolation(value: unknown, context: ContributionsContext): ContributionsViolation | null {
  if (value === null || value === undefined) return null;
  const ctx: Partial<ContributionsContext> = isPlainObject(context) ? context : {};
  if (!isPlainObject(value)) return violation('not_an_object', 'contributions');
  if (Object.keys(value).some((k) => !(CONTRIBUTIONS_KEYS as readonly string[]).includes(k))) {
    return violation('unknown_members', 'contributions');
  }
  if (!hasExactKeys(value, CONTRIBUTIONS_KEYS)) return violation('missing_members', 'contributions');
  if (value.pipeline !== null && !isPrefixedDigest(value.pipeline)) return violation('invalid_pipeline', 'contributions.pipeline');
  const externals = value.externals;
  if (!Array.isArray(externals) || externals.length > CONTRIBUTIONS_MAX_SET || !externals.every(isPrefixedDigest)) {
    return violation('invalid_externals', 'contributions.externals');
  }
  if (!isStrictlyIncreasing(externals as string[])) return violation('not_a_set', 'contributions.externals');
  const steps = value.steps;
  if (!Array.isArray(steps) || steps.length === 0) return violation('no_steps', 'contributions.steps');
  if (steps.length > CONTRIBUTIONS_MAX_STEPS) return violation('too_many_steps', 'contributions.steps');
  for (let i = 0; i < steps.length; i++) {
    const shape = stepShapeViolation(steps[i], i);
    if (shape) return shape;
  }
  const chain = brokenChainIndex(steps);
  if (chain !== null) return violation('prev_mismatch', `contributions.steps[${chain}].prev`, chain);
  const deciding = decidingStepIndex(steps);
  if (deciding === -1) return violation('multiple_deciding_steps', 'contributions.steps');
  if (deciding !== null) {
    for (let i = deciding + 1; i < steps.length; i++) {
      const cls = stepClass(steps[i].role);
      if (cls === 'propose' || cls === 'review') return violation('step_after_deciding', `contributions.steps[${i}].role`, i);
    }
    if (!sameActor(ctx.decider, steps[deciding].actor)) {
      return violation('decider_not_deciding_actor', `contributions.steps[${deciding}].actor`, deciding);
    }
    let expected: string | null;
    try {
      expected = typeof ctx.action === 'string' && typeof ctx.reason === 'string' ? decidingOutput(ctx.action, ctx.reason) : null;
    } catch {
      expected = null;
    }
    if (steps[deciding].output !== expected) {
      return violation('deciding_output_mismatch', `contributions.steps[${deciding}].output`, deciding);
    }
  }
  return null;
}

/** The index of the first step whose `prev` is not the chain's, or `null` when the chain holds. */
function brokenChainIndex(steps: readonly unknown[]): number | null {
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i] as Record<string, unknown>;
    let expected: string | null = null;
    if (i > 0) {
      try {
        expected = stepDigest(steps[i - 1]);
      } catch {
        return i;
      }
    }
    if (step.prev !== expected) return i;
  }
  return null;
}

/** Thrown by `buildContributions` for input a writer refuses. */
export class ContributionsBuildError extends Error {
  readonly code: ContributionsViolationCode;
  readonly field: string;
  readonly step?: number;
  constructor(v: ContributionsViolation) {
    super(v.message);
    this.name = 'ContributionsBuildError';
    this.code = v.code;
    this.field = v.field;
    if (v.step !== undefined) this.step = v.step;
  }
}

/**
 * The builder form of a list of one (Record §7.3): one `propose` step
 * recording `aiBom`, by `actor` (an agent that called the model), or with a
 * `null` actor when the model was called directly. `buildContributions` fills
 * its output from the record's `aiOutput`. Wrappers and connectors use it
 * wherever a record names one model.
 */
export function singleModel(
  aiBom: AiBom | AiBomWithInlineDescriptor,
  options: { actor?: StepActorInput | null } = {},
): ContributionsInput {
  return { steps: [{ role: 'propose', actor: options.actor ?? null, aiBom, inputs: [] }] };
}

/**
 * Build a contributions member from builder input, against the
 * record's `context`:
 *
 *   - each step's actor gets `desc:<agent>` as its id when an agent kind names
 *     none; an absent actor is `null` (a model called directly);
 *   - each step's `aiBom` has its absent nullable members written as `null`;
 *   - each step's output is its `output`, or `outputDigest(outputOf)`; the
 *     last `propose` step with neither gets `outputDigest(aiOutput)`, and a
 *     `decide` step with neither gets `outputDigest({ action, reason })`;
 *   - a `decide` step with no reason gets the record's `reason`;
 *   - `inputs` and `externals` are sorted by bytes (a repeated element is refused);
 *   - every `prev` is computed in order, and a supplied `prev` that differs is refused;
 *   - a member the builder form does not have is refused, never dropped: on
 *     the input (`unknown_members`), on a step (`step_unknown_members`; a
 *     step takes a step's members and `outputOf`) and on an actor
 *     (`invalid_actor`; `kind`, `id` and `agent`);
 *   - the result is checked with `contributionsViolation` against `context`.
 *
 * Step `aiBom`s must already be in the pre-built form: an inline descriptor
 * is resolved (registered or looked up) before building, because it changes
 * the step's digest.
 *
 * @throws ContributionsBuildError
 */
export function buildContributions(input: ContributionsInput, context: ContributionsContext): Contributions {
  if (!isPlainObject(input)) throw new ContributionsBuildError(violation('not_an_object', 'contributions'));
  if (Object.keys(input).some((k) => !(CONTRIBUTIONS_KEYS as readonly string[]).includes(k))) {
    throw new ContributionsBuildError(violation('unknown_members', 'contributions'));
  }
  const ctx: Partial<ContributionsContext> = isPlainObject(context) ? context : {};
  const rawSteps = (input as { steps?: unknown }).steps;
  if (!Array.isArray(rawSteps) || rawSteps.length === 0) throw new ContributionsBuildError(violation('no_steps', 'contributions.steps'));
  if (rawSteps.length > CONTRIBUTIONS_MAX_STEPS) {
    throw new ContributionsBuildError(violation('too_many_steps', 'contributions.steps'));
  }
  const sortSet = (values: unknown, field: string, step?: number): string[] => {
    if (values === undefined) return [];
    if (!Array.isArray(values) || !values.every((v) => typeof v === 'string')) {
      throw new ContributionsBuildError(violation(step === undefined ? 'invalid_externals' : 'invalid_inputs', field, step));
    }
    const sorted = [...(values as string[])].sort(compareBytes);
    if (!isStrictlyIncreasing(sorted)) throw new ContributionsBuildError(violation('not_a_set', field, step));
    return sorted;
  };
  const deciding = decidingStepIndex(rawSteps);
  const lastProposal = lastProposalBefore(
    rawSteps.map((s) => (isPlainObject(s) ? s : {})),
    deciding === null || deciding === -1 ? rawSteps.length : deciding,
  );
  const steps: ContributionStep[] = [];
  for (let i = 0; i < rawSteps.length; i++) {
    const s = rawSteps[i] as Record<string, unknown>;
    const f = `contributions.steps[${i}]`;
    if (!isPlainObject(s) || Object.keys(s).some((k) => !(STEP_INPUT_KEYS as readonly string[]).includes(k))) {
      throw new ContributionsBuildError(violation('step_unknown_members', f, i));
    }
    let actor: ContributionStep['actor'] = null;
    if (s.actor !== undefined && s.actor !== null) {
      const actorIn = isPlainObject(s.actor) ? s.actor : null;
      if (actorIn === null || Object.keys(actorIn).some((k) => !(ACTOR_KEYS as readonly string[]).includes(k))) {
        throw new ContributionsBuildError(violation('invalid_actor', `${f}.actor`, i));
      }
      const agent = actorIn.agent === undefined ? null : actorIn.agent;
      let id = actorIn.id;
      if (id === undefined && isDeciderKind(actorIn.kind) && actorIn.kind !== 'human' && typeof agent === 'string') {
        id = defaultAgentDeciderId(agent);
      }
      actor = { kind: actorIn.kind as NonNullable<ContributionStep['actor']>['kind'], id: id as string, agent: agent as string | null };
    }
    const cls = stepClass(s.role);
    let output = s.output;
    if (output === undefined && s.outputOf !== undefined) {
      try {
        output = outputDigest(s.outputOf);
      } catch {
        throw new ContributionsBuildError(violation('invalid_output', `${f}.outputOf`, i));
      }
    }
    if (output === undefined && i === lastProposal && ctx.aiOutput !== undefined) {
      try {
        output = outputDigest(ctx.aiOutput);
      } catch {
        throw new ContributionsBuildError(violation('invalid_output', `${f}.output`, i));
      }
    }
    if (output === undefined && cls === 'decide') {
      if (typeof ctx.action !== 'string' || typeof ctx.reason !== 'string') {
        throw new ContributionsBuildError(violation('deciding_output_mismatch', `${f}.output`, i));
      }
      try {
        output = decidingOutput(ctx.action, ctx.reason);
      } catch {
        throw new ContributionsBuildError(violation('deciding_output_mismatch', `${f}.output`, i));
      }
    }
    let reason = s.reason === undefined ? null : s.reason;
    if (reason === null && cls === 'decide' && typeof ctx.reason === 'string') reason = ctx.reason;
    const step: ContributionStep = {
      role: s.role as string,
      actor,
      aiBom: (s.aiBom === undefined || s.aiBom === null ? null : fillAiBomNulls(s.aiBom)) as ContributionStep['aiBom'],
      inputs: sortSet(s.inputs, `${f}.inputs`, i),
      output: output as string,
      verdict: (s.verdict === undefined ? null : s.verdict) as ContributionStep['verdict'],
      reason: reason as string | null,
      prev: null,
    };
    const shape = stepShapeViolation(step, i);
    if (shape) throw new ContributionsBuildError(shape);
    const prev = i === 0 ? null : stepDigest(steps[i - 1]);
    if (s.prev !== undefined && s.prev !== prev) {
      throw new ContributionsBuildError(violation('prev_mismatch', `${f}.prev`, i));
    }
    step.prev = prev;
    steps.push(step);
  }
  const built: Contributions = {
    pipeline: ((input as { pipeline?: unknown }).pipeline ?? null) as string | null,
    externals: sortSet((input as { externals?: unknown }).externals, 'contributions.externals'),
    steps,
  };
  const v = contributionsViolation(built, ctx as ContributionsContext);
  if (v) throw new ContributionsBuildError(v);
  return built;
}

/** Whether an actor's kind and scheme are ones this version reads. */
function actorSupported(actor: Record<string, unknown>): 'kind' | 'scheme' | null {
  if (!isDeciderKind(actor.kind)) return 'kind';
  const scheme = identifierScheme(actor.id);
  if (scheme === null || !DECIDER_SCHEMES.includes(scheme)) return 'scheme';
  return null;
}

/**
 * The reader's grammar of a step: the writer's, except that an actor's kind
 * and scheme may be ones it does not know, and an actor of a known kind and
 * scheme is held to the reader's consistency test (`readerActorInconsistent`,
 * as the `decider` row is), not to the writer's per-scheme value grammars. A
 * `null` actor is malformed where Record §7.1 forbids it.
 */
function readerStepMalformed(step: unknown): boolean {
  if (!isPlainObject(step) || !hasExactKeys(step, STEP_KEYS)) return true;
  const cls = stepClass(step.role);
  if (cls === null) return true;
  const actor = step.actor;
  if (actor === null) {
    if (step.aiBom === null || cls === 'decide') return true;
  } else {
    if (!isPlainObject(actor) || !hasExactKeys(actor, ACTOR_KEYS)) return true;
    if (typeof actor.kind !== 'string' || identifierScheme(actor.id) === null) return true;
    if (actor.agent !== null && !isPrefixedDigest(actor.agent)) return true;
    if (actorSupported(actor) === null && readerActorInconsistent(actor.kind as never, actor.id as string, actor.agent)) return true;
  }
  if (!Array.isArray(step.inputs) || step.inputs.length > CONTRIBUTIONS_MAX_SET || !step.inputs.every(isPrefixedDigest)) {
    return true;
  }
  if (!isStrictlyIncreasing(step.inputs as string[])) return true;
  if (!isPrefixedDigest(step.output)) return true;
  if (step.verdict !== null && !(typeof step.verdict === 'string' && VERDICTS.includes(step.verdict))) return true;
  if (step.verdict !== null && (cls === 'propose' || cls === 'other')) return true;
  if (step.reason !== null && typeof step.reason !== 'string') return true;
  if (step.prev !== null && !isPrefixedDigest(step.prev)) return true;
  return false;
}

function bindingBlocked(reason: string): ContributionsBindingCheck {
  return {
    outcome: 'not-checked',
    valid: null,
    reason,
    approvals: [],
    staleApprovals: [],
    uncoveredReviews: [],
    proposals: [],
    decisionBinding: 'not-applicable',
  };
}

function notChecked(reason: string): ContributionsCheck {
  return { outcome: 'not-checked', valid: null, reason, binding: bindingBlocked(reason) };
}

function wrong(reason: string, extra: Partial<ContributionsCheck> = {}): ContributionsCheck {
  return {
    outcome: 'checked-wrong',
    valid: false,
    reason,
    ...extra,
    binding: bindingBlocked('blocked_by:contributions'),
  };
}

/**
 * The reader's `contributions` and `contributions.binding` rows
 * (Verification §4.10) for a record whose digest holds, read from the record alone. A
 * failure that does not depend on actor kinds is never hidden behind an
 * abstention, so the row tries, in order:
 *
 *   1. `null`                                   → not-checked, absent
 *   2. the grammar, including a `null` actor where it is forbidden
 *                                               → checked-wrong, malformed_contributions
 *   3. the step chain                           → checked-wrong, step_chain_broken
 *   4. the decide step's actor is not the decider (canonical bytes)
 *                                               → checked-wrong, decider_not_deciding_actor
 *   5. the decide step's output is not the decision
 *                                               → checked-wrong, deciding_output_mismatch
 *   6. an actor kind or scheme this version does not implement
 *                                               → abstain, unsupported_actor_kind / unsupported_identifier_scheme
 *   7. otherwise                                → checked-correct (steps, models, decidingStep)
 *
 * A step's inputs may name a link target as `sha256:` and its bare digest,
 * when `links` meets the grammar of Record §8.2. A step's `aiBom` is hashed as given
 * and not interpreted. Never throws.
 */
export function checkContributions(payload: unknown): ContributionsCheck {
  const p = isPlainObject(payload) ? payload : {};
  const value = p.contributions;
  if (value === null || value === undefined) return notChecked('absent');
  if (!isPlainObject(value) || !hasExactKeys(value, CONTRIBUTIONS_KEYS)) return wrong('malformed_contributions');
  if (value.pipeline !== null && !isPrefixedDigest(value.pipeline)) return wrong('malformed_contributions');
  const externals = value.externals;
  if (
    !Array.isArray(externals) ||
    externals.length > CONTRIBUTIONS_MAX_SET ||
    !externals.every(isPrefixedDigest) ||
    !isStrictlyIncreasing(externals as string[])
  ) {
    return wrong('malformed_contributions');
  }
  const steps = value.steps;
  if (!Array.isArray(steps) || steps.length === 0 || steps.length > CONTRIBUTIONS_MAX_STEPS) {
    return wrong('malformed_contributions');
  }
  for (let i = 0; i < steps.length; i++) {
    if (readerStepMalformed(steps[i])) return wrong('malformed_contributions', { failedStep: i });
  }
  const deciding = decidingStepIndex(steps);
  if (deciding === -1) return wrong('malformed_contributions');
  if (deciding !== null) {
    for (let i = deciding + 1; i < steps.length; i++) {
      const cls = stepClass(steps[i].role);
      if (cls === 'propose' || cls === 'review') return wrong('malformed_contributions', { failedStep: i });
    }
  }
  const chain = brokenChainIndex(steps);
  if (chain !== null) return wrong('step_chain_broken', { failedStep: chain });
  if (deciding !== null) {
    if (!sameActor(p.decider, steps[deciding].actor)) return wrong('decider_not_deciding_actor', { failedStep: deciding });
    let expected: string | null;
    try {
      expected = decidingOutput(p.action, p.reason);
    } catch {
      expected = null;
    }
    if (steps[deciding].output !== expected) return wrong('deciding_output_mismatch', { failedStep: deciding });
  }
  for (const step of steps) {
    if (step.actor === null) continue;
    const unsupported = actorSupported(step.actor);
    if (unsupported !== null) {
      return {
        outcome: 'abstain',
        valid: null,
        reason: unsupported === 'kind' ? 'unsupported_actor_kind' : 'unsupported_identifier_scheme',
        binding: bindingBlocked('blocked_by:contributions'),
      };
    }
  }

  const models: string[] = [];
  for (const step of steps as ContributionStep[]) {
    const digest = step.aiBom?.modelDescriptorDigest;
    if (typeof digest === 'string' && !models.includes(digest)) models.push(digest);
  }
  const result: ContributionsCheck = {
    outcome: 'checked-correct',
    valid: true,
    steps: steps.length,
    models,
    decidingStep: deciding === null ? 'record' : deciding,
    binding: checkBinding(steps as ContributionStep[], deciding, externals as string[], p),
  };
  if (value.pipeline !== null) result.pipeline = { outcome: 'abstain', reason: 'unsupported_pipeline' };
  return result;
}

/**
 * The `contributions.binding` row over well-formed steps (Record §7.5). P* is the
 * last `propose` step, before the decide step when there is one. Tried in
 * order: input provenance (`input_undeclared`), review binding
 * (`review_unbound`), the decided output (`decided_output_differs`), the
 * decision's inputs (`decision_unbound`).
 */
function checkBinding(
  steps: ContributionStep[],
  deciding: number | null,
  externals: string[],
  payload: Record<string, unknown>,
): ContributionsBindingCheck {
  const proposals = steps.map((s, i) => (stepClass(s.role) === 'propose' ? i : -1)).filter((i) => i >= 0);
  const linkTargets = linkTargetInputs(payload.links);
  const externalSet = new Set(externals);
  const finalProposal = lastProposalBefore(steps, deciding === null ? steps.length : deciding);
  const decisionBinding: ContributionsBindingCheck['decisionBinding'] = finalProposal === undefined ? 'not-applicable' : 'checked';
  const base = { approvals: [] as number[], staleApprovals: [] as number[], uncoveredReviews: [] as number[], proposals };
  const failure = (reason: string, failedStep: number, failedDigest?: string): ContributionsBindingCheck => ({
    outcome: 'checked-wrong',
    valid: false,
    reason,
    ...base,
    decisionBinding,
    failedStep,
    ...(failedDigest !== undefined && { failedDigest }),
  });

  // Input provenance: every input is an earlier step's output, a link target, or a declared external.
  const outputs: string[] = [];
  for (let i = 0; i < steps.length; i++) {
    for (const input of steps[i].inputs) {
      if (!outputs.includes(input) && !linkTargets.has(input) && !externalSet.has(input)) {
        return failure('input_undeclared', i, input);
      }
    }
    outputs.push(steps[i].output);
  }

  for (let i = 0; i < steps.length; i++) {
    if (stepClass(steps[i].role) !== 'review') continue;
    const covered = lastProposalBefore(steps, i);
    if (covered === undefined) {
      base.uncoveredReviews.push(i);
      continue;
    }
    if (!steps[i].inputs.includes(steps[covered].output)) return failure('review_unbound', i, steps[covered].output);
    if (steps[i].verdict !== 'approve') continue;
    if (covered === finalProposal) base.approvals.push(i);
    else base.staleApprovals.push(i);
  }

  if (finalProposal === undefined) return { outcome: 'checked-correct', valid: true, ...base, decisionBinding };
  const proposed = steps[finalProposal].output;
  let decided: string | null;
  try {
    decided = outputDigest(payload.aiOutput);
  } catch {
    decided = null;
  }
  if (decided !== proposed) return failure('decided_output_differs', finalProposal, proposed);
  if (deciding !== null && !steps[deciding].inputs.includes(proposed)) return failure('decision_unbound', deciding, proposed);
  return { outcome: 'checked-correct', valid: true, ...base, decisionBinding };
}
