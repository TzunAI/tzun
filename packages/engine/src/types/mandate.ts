/**
 * Mandates: a human principal's signed authorisation for an
 * agent to decide within stated terms, and the form a record decided under one
 * carries. Pure type definitions; the rules are in
 * `packages/engine/src/mandate/`.
 */
import type { WebauthnAssertion } from './evidence';
import type { Link } from './links';

/** A predicate's operation. */
export type MandatePredicateOp =
  | 'eq'
  | 'ne'
  | 'lt'
  | 'le'
  | 'gt'
  | 'ge'
  | 'in'
  | 'notIn'
  | 'prefix'
  | 'glob';

/**
 * A predicate over the record's evidence payload. `path` is an RFC 6901 JSON
 * Pointer; `value` is a string, a non-negative safe integer, a boolean, or a
 * sorted set of strings (`in`, `notIn`, `glob`); `quant` is `null` for a
 * single value and `all` or `any` for an array.
 *
 * @tzun-canonical-sort utf16
 */
export interface MandatePredicate {
  path: string;
  op: MandatePredicateOp;
  value: string | number | boolean | string[];
  quant: 'all' | 'any' | null;
}

/** @tzun-canonical-sort utf16 */
export interface MandatePrincipal {
  /** The principal's opaque relying-party user id (the `acct` value grammar), never an email address or a name. */
  signer: string;
  /** The digest of the principal's credential registration record, or `null`. */
  credential: string | null;
}

/**
 * What the agent may decide. For each set, `null` places no restriction and
 * `[]` permits nothing.
 *
 * @tzun-canonical-sort utf16
 */
export interface MandateScope {
  aiSystemIds: string[] | null;
  actions: string[] | null;
  /** Model descriptor digests, `sha256:` and 64 lowercase hex. */
  models: string[] | null;
  predicates: Record<string, MandatePredicate> | null;
}

/** Both ends inclusive, ISO 8601 UTC with milliseconds; `null` is open. @tzun-canonical-sort utf16 */
export interface MandateValidity {
  notBefore: string | null;
  notAfter: string | null;
}

/** A cumulative cap: the greatest sum of the integer at `path` over every record under the mandate. @tzun-canonical-sort utf16 */
export interface MandateCap {
  path: string;
  max: number;
}

/** @tzun-canonical-sort utf16 */
export interface MandateLimits {
  maxRecords: number | null;
  /** 1 to 16 caps, or `null`. */
  cumulative: Record<string, MandateCap> | null;
}

/** A 0.8.0 document states `{ allowed: false, maxDepth: 0, attenuation: 'subset' }`. @tzun-canonical-sort utf16 */
export interface MandateDelegation {
  allowed: boolean;
  maxDepth: number;
  attenuation: 'subset';
}

/** @tzun-canonical-sort utf16 */
export interface MandateReview {
  maxAgeMs: number;
}

/**
 * The mandate document `tzun-mandate/1`. Every key is required, `null` where
 * it does not apply; arrays are sorted sets of printable-ASCII strings; every
 * string is printable ASCII; integers are non-negative safe integers. Its
 * digest is lowercase hex SHA-256 of its canonical bytes, at most 16 KiB.
 *
 * @tzun-canonical-sort utf16
 */
export interface MandateDocument {
  v: 'tzun-mandate/1';
  mandateId: string;
  principal: MandatePrincipal;
  /** Decider identifiers of the agents that may decide (agent schemes or `cmt`). */
  agents: string[];
  /** `"v1.0"`, the only registered schema version. */
  schemaVersion: string;
  scope: MandateScope;
  confirm: Record<string, MandatePredicate> | null;
  validity: MandateValidity;
  limits: MandateLimits;
  delegation: MandateDelegation;
  review: MandateReview | null;
  policyDigest: string | null;
  predecessor: string | null;
  parent: string | null;
}

/**
 * The mandate statement `tzun-signoff-mandate/1`: a flat statement in the
 * sign-off value domain that the principal signs in one WebAuthn ceremony.
 * It carries no printed name: `signer` is the principal's opaque relying-party
 * user id.
 *
 * @tzun-canonical-sort utf16
 */
export interface MandateStatement {
  v: 'tzun-signoff-mandate/1';
  mode: 'mandate';
  mandateDigest: string;
  signer: string;
  signerKind: 'human';
  meaning: 'responsibility';
  /** The document's policy digest, or `none`. */
  policyDigest: string;
  /** A finalized-block reference, or `none`. */
  notBefore: string;
}

/**
 * The mandate form of `payload.signoffExpectation`: only a capture under a
 * mandate writes it.
 *
 * @tzun-canonical-sort utf16
 */
export interface MandateExpectation {
  /** The principal's `assertionDigest`, 64 lowercase hex. */
  mandateAssertion: string;
  /** The claimed slot: a safe integer of at least 1. */
  mandateSeq: number;
  /** One member per cap, the running total including this record; `null` when the mandate has no cap. */
  totals: Record<string, number> | null;
  /** Whether a human confirmation is owed. */
  confirm: boolean;
}

/**
 * `nonRepudiation.mandate` and `nonRepudiation.mandateIssuance`: the signed
 * authorisation, carried outside the digest and bound by the hashed assertion
 * digest. Its canonical bytes are at most 48 KiB.
 *
 * @tzun-canonical-sort utf16
 */
export interface MandateBlock {
  statement: MandateStatement;
  assertion: WebauthnAssertion;
  /** Base64 of the DER TimeStampResp over the assertion digest, or `null`. */
  assertionTimestamp: string | null;
  document: MandateDocument | null;
}

/** A mandate's life event. */
export type MandateEvent = 'issued' | 'revoked' | 'superseded' | 'expired';

/**
 * A mandate event body `tzun-mandate-event/1`, in the document grammar.
 *
 * @tzun-canonical-sort utf16
 */
export interface MandateEventBody {
  v: 'tzun-mandate-event/1';
  event: MandateEvent;
  mandateDigest: string;
  /** The digest of the record that records the event. */
  record: string;
  successor: string | null;
  used: number | null;
  totals: Record<string, number> | null;
}

/** Why a mandate document is refused (`mandateDocumentViolation`). */
export type MandateDocumentViolationCode =
  | 'invalid_document'
  | 'document_too_large'
  | 'restriction_failed'
  | 'invalid_predicate'
  | 'invalid_cap'
  | 'empty_cumulative'
  | 'invalid_principal';

/** A mandate document refusal. */
export interface MandateDocumentViolation {
  code: MandateDocumentViolationCode;
  field: string;
  message: string;
}

/** Why a capture under a mandate is refused. */
export type MandateViolationCode =
  | 'mandate_not_found'
  | 'mandate_not_open'
  | 'agent_not_in_mandate'
  | 'schema_version_mismatch'
  | 'outside_scope'
  | 'scope_undeterminable'
  | 'confirm_undeterminable'
  | 'cap_value_invalid'
  | 'mandate_full'
  | 'cap_exceeded'
  | 'outside_validity'
  | 'mandate_block_too_large'
  | 'mandate_not_supported_by_store'
  | 'invalid_revocation_instant'
  | 'predecessor_principal_mismatch'
  | 'confirmation_not_owed'
  | 'already_confirmed';

/** A capture-under-mandate refusal. */
export interface MandateViolation {
  code: MandateViolationCode;
  field: string;
  message: string;
}

/** A predicate's value: it holds, it does not, or it cannot be evaluated. */
export type PredicateOutcome = 'true' | 'false' | 'undeterminable';

/** One constraint of a scope evaluation that failed or could not be evaluated. */
export interface MandateScopeFinding {
  /**
   * `agents`, `aiSystemIds`, `actions`, `models`, `predicate`, `restriction`,
   * or `confirm` (a confirm predicate undeterminable on a record that says no
   * confirmation is owed).
   */
  constraint: string;
  /** The predicate's name, for `predicate` and `confirm`. */
  name?: string;
}

/** `evaluateMandateScope`: whether a record is within its mandate's scope. */
export interface MandateScopeEvaluation {
  verdict: 'within' | 'outside' | 'undeterminable';
  /** Constraints that failed (verdict `outside`). */
  failures: MandateScopeFinding[];
  /** Constraints that could not be evaluated. */
  undeterminable: MandateScopeFinding[];
  /** Whether the record's decider is one of the document's agents. */
  agentInMandate: boolean;
  /** The record's `confirm` is `false` while a confirm predicate holds. */
  confirmationEvaded: boolean;
}

/** `evaluateMandateConfirm`: the confirmation flag a capture writes, or why none can be. */
export interface MandateConfirmEvaluation {
  /** `null` when no predicate holds and one is undeterminable. */
  confirm: boolean | null;
  /** Names of the confirm predicates that hold. */
  holding: string[];
  /** Names of the confirm predicates that could not be evaluated. */
  undeterminable: string[];
}

/** A missing run of slots between two held ones, with the amount each cap leaves unexplained. */
export interface MandateSlotGap {
  /** First missing slot. */
  from: number;
  /** Last missing slot. */
  to: number;
  unexplained: Record<string, number>;
}

/** A difference between consecutive totals that the later record's own value does not explain. */
export interface MandateUnexplainedStep {
  slot: number;
  cap: string;
  expected: number;
  actual: number;
}

/** A record the consumption check could not read. */
export interface MandateMalformedRecord {
  index: number;
  reason: string;
}

/** `checkMandateConsumption` over the records of one mandate. */
export interface MandateConsumptionResult {
  /** Slots held by more than one record. */
  duplicateSlots: number[];
  gaps: MandateSlotGap[];
  unexplainedSteps: MandateUnexplainedStep[];
  malformed: MandateMalformedRecord[];
  /** The greatest n such that every slot 1..n is held. */
  completeUpTo: number;
  /**
   * The held slots above the latest event body's `used`, ascending: records
   * captured after the terminal event, or ones it does not account for.
   * Empty when no closing event body was supplied.
   */
  beyondEvent: number[];
  /**
   * Against the latest event body: `true` when every slot up to its `used`
   * is held, the totals at that slot equal its totals, and no slot above it
   * is held; `false` when not; `null` when no closing event body was
   * supplied (an open mandate).
   */
  complete: boolean | null;
}

/** A mandate record's state (`mandates.state`): it moves only from `open`. */
export type MandateState = 'open' | 'revoked' | 'superseded' | 'expired';

/** What a capture under a mandate reads of the mandate record before it claims a slot. */
export interface MandateRecordState {
  state: MandateState;
  /** Slots claimed so far. */
  used: number;
  /** The running total of each cap; `null` when the document has no cap. */
  totals: Record<string, number> | null;
}

/** One cap's compare-and-swap step of a claim. */
export interface MandateCapClaim {
  cap: string;
  expectTotal: number;
  newTotal: number;
}

/**
 * `planMandateClaim`: what a capture under a mandate writes, or why it is
 * refused. `expectation` is the record's mandate form and `links` its links
 * with the `mandate` link, the members the scope was evaluated over; `caps`
 * and `expectUsed` are the claim's compare-and-swap guards.
 */
export type MandateClaimPlan =
  | {
      ok: true;
      expectation: MandateExpectation;
      /** The record's `links`: the payload's links with the `mandate` link to the issuance record, sorted. */
      links: Link[];
      expectUsed: number;
      caps: MandateCapClaim[];
      /** Names of the confirm predicates that hold (the reason `confirm` is `true`). */
      confirmHolding: string[];
    }
  | {
      ok: false;
      code: MandateViolationCode;
      field: string;
      message: string;
      /** For `outside_scope` and `scope_undeterminable`: the constraints concerned. */
      findings?: MandateScopeFinding[];
      /** `true` when the refusal is `outside_validity` because the window has ended: the mandate is now expired. */
      expired?: boolean;
    };
