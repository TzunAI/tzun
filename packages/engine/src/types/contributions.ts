/**
 * The contributions member of a v1.0 record (Record §7): the steps
 * contributors took in turn, inside the digest, and the only place a model's
 * bill of materials is recorded. A single model is a list of one `propose`
 * step. Pure type definitions; the rules are in
 * `packages/engine/src/contributions.ts`.
 */
import type { AiBom, AiBomWithInlineDescriptor } from './ai-bom';
import type { DeciderKind } from './decider';

/** The class of a step, read from its role before the first `:`. */
export type ContributionStepClass = 'propose' | 'review' | 'decide' | 'other';

/** A review or decide step's verdict. */
export type ContributionVerdict = 'approve' | 'reject' | 'concerns';

/**
 * Who took a step: the decider grammar without `credential` and `freshness`.
 *
 * @tzun-canonical-sort utf16
 */
export interface StepActor {
  kind: DeciderKind;
  id: string;
  /** `sha256:` and 64 lowercase hex; `null` only for a human. */
  agent: string | null;
}

/**
 * A contribution step's bill of materials: an exact {@link AiBom}, the same
 * shape. A writer validates a step's members strictly before hashing them
 * (Record §7.4), so the generated Python model of this name is
 * strict, with every nullable member a required key. `AiBom` itself is also
 * the writer-input shape, beside its inline-descriptor form.
 */
export type StepAiBom = AiBom;

/**
 * One step. Every key is required; a key that does not apply is `null`.
 *
 * @tzun-canonical-sort utf16
 */
export interface ContributionStep {
  /** `<class>` or `<class>:<name>`, name `[A-Za-z0-9._-]{1,48}`. */
  role: string;
  /**
   * Who took the step, or `null` for a model called directly with no agent
   * identity. `null` only when `aiBom` is not `null` and the step is not of
   * the `decide` class.
   */
  actor: StepActor | null;
  /** The model that drove the step, or `null` when no model did (a human's or a policy engine's step). */
  aiBom: StepAiBom | null;
  /** Prefixed digests, strictly increasing by bytes, 0 to 64. */
  inputs: string[];
  /** `outputDigest` of what the step produced. */
  output: string;
  verdict: ContributionVerdict | null;
  /** 1 to 16,384 UTF-16 code units, or `null`. */
  reason: string | null;
  /** `null` on step 0; `stepDigest(i - 1)` after it. */
  prev: string | null;
}

/**
 * `payload.contributions`.
 *
 * @tzun-canonical-sort utf16
 */
export interface Contributions {
  /** The pipeline definition digest, or `null`. */
  pipeline: string | null;
  /** Declared external inputs: prefixed digests, strictly increasing by bytes, 0 to 64. */
  externals: string[];
  /** 1 to 32 steps, in the order the contributors acted. */
  steps: ContributionStep[];
}

/** A step actor as a builder takes it: `id` defaults to `desc:<agent>` for the agent kinds. */
export interface StepActorInput {
  kind: DeciderKind;
  id?: string;
  agent?: string | null;
}

/**
 * A step as `buildContributions` takes it. Give `output` (a prefixed digest)
 * or `outputOf` (the value, whose `outputDigest` the builder computes); the
 * builder fills the last `propose` step's output from the record's `aiOutput`
 * and a `decide` step's output from the record's action and reason when the
 * step gives neither. `aiBom` in the inline-descriptor form is resolved by the
 * SDK or the platform before the builder runs.
 */
export interface ContributionStepInput {
  role: string;
  /** `null` (or omitted) for a model called directly: the step must carry an `aiBom`. */
  actor?: StepActorInput | null;
  aiBom?: AiBom | AiBomWithInlineDescriptor | null;
  inputs?: string[];
  output?: string;
  outputOf?: unknown;
  verdict?: ContributionVerdict | null;
  reason?: string | null;
  prev?: string | null;
}

/** `contributions` in builder form. */
export interface ContributionsInput {
  pipeline?: string | null;
  externals?: string[];
  steps: ContributionStepInput[];
}

/** Why contributions are refused at capture, first failure first (`contributionsViolation`). */
export type ContributionsViolationCode =
  | 'not_an_object'
  | 'unknown_members'
  | 'missing_members'
  | 'invalid_pipeline'
  | 'invalid_externals'
  | 'not_a_set'
  | 'no_steps'
  | 'too_many_steps'
  | 'step_unknown_members'
  | 'step_missing_members'
  | 'invalid_role'
  | 'invalid_actor'
  | 'actor_required'
  | 'invalid_step_ai_bom'
  | 'invalid_inputs'
  | 'invalid_output'
  | 'invalid_verdict'
  | 'verdict_not_allowed'
  | 'invalid_step_reason'
  | 'prev_mismatch'
  | 'multiple_deciding_steps'
  | 'step_after_deciding'
  | 'decider_not_deciding_actor'
  | 'deciding_output_mismatch';

/** A contributions refusal. `step` is the index of the step concerned, when one is. */
export interface ContributionsViolation {
  code: ContributionsViolationCode;
  field: string;
  message: string;
  step?: number;
}
