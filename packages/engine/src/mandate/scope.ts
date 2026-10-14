/**
 * What a mandate permits, checked against a record (Record §9.9, §9.10): the
 * scope, the confirmation flag, the single-record limits, and the
 * consumption of slots and totals over a set of records.
 */
import { SchemaRegistry } from '../schema-registry';
import { isNonNegativeSafeInteger, isPlainObject, isPositiveSafeInteger } from '../record-rules-util';
import { mandateRestrictionHolds } from './document';
import { evaluatePredicate, parseJsonPointer, resolvePointer } from './predicate';
import type {
  MandateConfirmEvaluation,
  MandateConsumptionResult,
  MandateScopeEvaluation,
  MandateScopeFinding,
  MandateSlotGap,
} from '../types/mandate';

const defaultRegistry = new SchemaRegistry();

/** Whether a decider is one of the document's agents: its id, `desc:` + its agent, or the same `cmt`. */
export function deciderInMandate(decider: unknown, agents: unknown): boolean {
  if (!isPlainObject(decider) || !Array.isArray(agents)) return false;
  if (typeof decider.id === 'string' && agents.includes(decider.id)) return true;
  return typeof decider.agent === 'string' && agents.includes(`desc:${decider.agent}`);
}

/**
 * Every model a record names: each non-null contribution step `aiBom`'s
 * `modelDescriptorDigest`, in step order. A model outside a mandate's scope
 * may not propose or review either.
 */
export function recordedModels(payload: Record<string, unknown>): unknown[] {
  const models: unknown[] = [];
  const contributions = isPlainObject(payload.contributions) ? payload.contributions : null;
  if (contributions && Array.isArray(contributions.steps)) {
    for (const step of contributions.steps) {
      if (isPlainObject(step) && isPlainObject(step.aiBom)) models.push(step.aiBom.modelDescriptorDigest);
    }
  }
  return models;
}

function evaluateGroup(group: unknown, payload: unknown): { holding: string[]; failing: string[]; undeterminable: string[] } {
  const out = { holding: [] as string[], failing: [] as string[], undeterminable: [] as string[] };
  if (!isPlainObject(group)) return out;
  for (const name of Object.keys(group).sort()) {
    const outcome = evaluatePredicate(group[name], payload);
    if (outcome === 'true') out.holding.push(name);
    else if (outcome === 'false') out.failing.push(name);
    else out.undeterminable.push(name);
  }
  return out;
}

/**
 * Whether the record whose payload is `payload` is within the scope of
 * `document` (Record §9.9). `within` when the decider is an agent of the mandate,
 * `aiSystemId` and `action` are in their sets, every model the record names
 * is in `scope.models`, and every scope predicate holds; `outside` when any
 * of these fails; `undeterminable` otherwise. Also undeterminable: a model
 * set while the record names no model, and a document path whose first token
 * is not hashed in the record's schema version (the restriction re-applied),
 * and a record whose expectation says `confirm: false` while no confirm
 * predicate holds and one is undeterminable (`{ constraint: 'confirm', name
 * }` for each): a capture refuses that record (Record §9.6), so a reader
 * cannot call it within, since the confirmation it owes cannot be ruled out.
 * `confirmationEvaded` is set when the record's expectation says `confirm:
 * false` while a confirm predicate holds. Never throws.
 */
export function evaluateMandateScope(
  document: unknown,
  payload: unknown,
  options: { registry?: SchemaRegistry } = {},
): MandateScopeEvaluation {
  const registry = options.registry ?? defaultRegistry;
  const failures: MandateScopeFinding[] = [];
  const undeterminable: MandateScopeFinding[] = [];
  const d = isPlainObject(document) ? document : {};
  const p = isPlainObject(payload) ? payload : {};
  const scope = isPlainObject(d.scope) ? d.scope : {};
  const agentInMandate = deciderInMandate(p.decider, d.agents);
  if (!agentInMandate) failures.push({ constraint: 'agents' });

  const version = typeof p.schemaVersion === 'string' ? p.schemaVersion : '';
  if (!mandateRestrictionHolds(d, version, registry)) undeterminable.push({ constraint: 'restriction' });

  if (Array.isArray(scope.aiSystemIds) && !scope.aiSystemIds.includes(p.aiSystemId)) failures.push({ constraint: 'aiSystemIds' });
  if (Array.isArray(scope.actions) && !scope.actions.includes(p.action)) failures.push({ constraint: 'actions' });
  if (Array.isArray(scope.models)) {
    const models = recordedModels(p);
    if (models.length === 0) undeterminable.push({ constraint: 'models' });
    else if (!models.every((m) => (scope.models as unknown[]).includes(m))) failures.push({ constraint: 'models' });
  }
  const predicates = evaluateGroup(scope.predicates, p);
  for (const name of predicates.failing) failures.push({ constraint: 'predicate', name });
  for (const name of predicates.undeterminable) undeterminable.push({ constraint: 'predicate', name });

  const expectation = isPlainObject(p.signoffExpectation) ? p.signoffExpectation : {};
  const confirm = evaluateGroup(d.confirm, p);
  const confirmationEvaded = expectation.confirm === false && confirm.holding.length > 0;
  if (expectation.confirm === false && confirm.holding.length === 0) {
    for (const name of confirm.undeterminable) undeterminable.push({ constraint: 'confirm', name });
  }

  let verdict: MandateScopeEvaluation['verdict'] = 'within';
  if (failures.length > 0) verdict = 'outside';
  else if (undeterminable.length > 0) verdict = 'undeterminable';
  return { verdict, failures, undeterminable, agentInMandate, confirmationEvaded };
}

/**
 * The confirmation flag a capture under `document` writes (Record §9.6):
 * `true` when a confirm predicate holds, `false` when none holds and none is
 * undeterminable, `null` (the capture is refused) when none holds and one is
 * undeterminable. A document with no confirm predicates gives `false`.
 */
export function evaluateMandateConfirm(document: unknown, payload: unknown): MandateConfirmEvaluation {
  const d = isPlainObject(document) ? document : {};
  const group = evaluateGroup(d.confirm, payload);
  const confirm = group.holding.length > 0 ? true : group.undeterminable.length > 0 ? null : false;
  return { confirm, holding: group.holding, undeterminable: group.undeterminable };
}

/**
 * The value at each cap's path in `payload`, which must be a non-negative
 * safe integer (Record §9.9): `{ values }`, or `{ invalid }` naming the caps whose
 * value is not one. `values` is `null` for a document with no cap.
 */
export function mandateCapValues(
  document: unknown,
  payload: unknown,
): { values: Record<string, number> | null; invalid: string[] } {
  const d = isPlainObject(document) ? document : {};
  const limits = isPlainObject(d.limits) ? d.limits : {};
  if (!isPlainObject(limits.cumulative)) return { values: null, invalid: [] };
  const values: Record<string, number> = {};
  const invalid: string[] = [];
  for (const [cap, def] of Object.entries(limits.cumulative)) {
    const tokens = isPlainObject(def) ? parseJsonPointer(def.path) : null;
    const resolved = tokens === null ? { found: false as const } : resolvePointer(payload, tokens);
    if (resolved.found && isNonNegativeSafeInteger(resolved.value)) values[cap] = resolved.value;
    else invalid.push(cap);
  }
  return { values, invalid };
}

/**
 * The single-record limits (Record §9.9): `mandateSeq` at most `limits.maxRecords`;
 * `totals` with exactly the document's caps (`null` when it has none); the
 * value at each cap's path an integer; each running total at least that value
 * and at most the cap's maximum. Never throws.
 */
export function checkMandateLimits(
  document: unknown,
  payload: unknown,
): { valid: boolean; reason?: 'mandate_totals_malformed' | 'mandate_limit_exceeded'; slot?: number; totals?: Record<string, number> | null } {
  const d = isPlainObject(document) ? document : {};
  const p = isPlainObject(payload) ? payload : {};
  const expectation = isPlainObject(p.signoffExpectation) ? p.signoffExpectation : {};
  const limits = isPlainObject(d.limits) ? d.limits : {};
  const slot = expectation.mandateSeq;
  if (!isPositiveSafeInteger(slot)) return { valid: false, reason: 'mandate_totals_malformed' };
  const totals = expectation.totals;
  const facts = { slot, totals: (isPlainObject(totals) ? totals : null) as Record<string, number> | null };
  if (isNonNegativeSafeInteger(limits.maxRecords) && slot > limits.maxRecords) {
    return { valid: false, reason: 'mandate_limit_exceeded', ...facts };
  }
  const cumulative = isPlainObject(limits.cumulative) ? limits.cumulative : null;
  if (cumulative === null) {
    return totals === null ? { valid: true, ...facts } : { valid: false, reason: 'mandate_totals_malformed', ...facts };
  }
  if (!isPlainObject(totals)) return { valid: false, reason: 'mandate_totals_malformed', ...facts };
  const caps = Object.keys(cumulative).sort();
  const totalCaps = Object.keys(totals).sort();
  if (caps.length !== totalCaps.length || caps.some((c, i) => c !== totalCaps[i])) {
    return { valid: false, reason: 'mandate_totals_malformed', ...facts };
  }
  const { values, invalid } = mandateCapValues(d, p);
  if (invalid.length > 0 || values === null) return { valid: false, reason: 'mandate_totals_malformed', ...facts };
  for (const cap of caps) {
    const total = totals[cap];
    const def = cumulative[cap] as Record<string, unknown>;
    if (!isNonNegativeSafeInteger(total)) return { valid: false, reason: 'mandate_totals_malformed', ...facts };
    if (total < values[cap] || !isNonNegativeSafeInteger(def.max) || total > def.max) {
      return { valid: false, reason: 'mandate_limit_exceeded', ...facts };
    }
  }
  return { valid: true, ...facts };
}

interface SlotRecord {
  slot: number;
  totals: Record<string, number>;
  values: Record<string, number>;
}

/**
 * Consumption over the records of one mandate (Record §9.10),
 * pure: no slot held twice; slots contiguous, a missing run reported with the
 * amount each cap leaves unexplained; consecutive totals stepping by exactly
 * the later record's own value (slot 1's totals equal its own values);
 * completeness against `lastEvent`, the newest event body (revoked,
 * superseded or expired) with its `used` and `totals`: every slot up to
 * `used` held, the totals at slot `used` equal to the event's, and no slot
 * above `used` held (`beyondEvent`: a record captured after the terminal
 * event, or one the event does not account for). `envelopes` are the
 * records naming the mandate, in any order. Never throws.
 */
export function checkMandateConsumption(
  document: unknown,
  envelopes: readonly unknown[],
  options: { lastEvent?: unknown } = {},
): MandateConsumptionResult {
  const malformed: MandateConsumptionResult['malformed'] = [];
  const bySlot = new Map<number, SlotRecord[]>();
  const d = isPlainObject(document) ? document : {};
  const limits = isPlainObject(d.limits) ? d.limits : {};
  const caps = isPlainObject(limits.cumulative) ? Object.keys(limits.cumulative).sort() : [];
  envelopes.forEach((envelope, index) => {
    const env = isPlainObject(envelope) ? envelope : {};
    const payload = isPlainObject(env.payload) ? env.payload : {};
    const expectation = isPlainObject(payload.signoffExpectation) ? payload.signoffExpectation : {};
    const slot = expectation.mandateSeq;
    if (!isPositiveSafeInteger(slot)) {
      malformed.push({ index, reason: 'mandate_seq_malformed' });
      return;
    }
    const { values, invalid } = mandateCapValues(d, payload);
    const totals = isPlainObject(expectation.totals) ? expectation.totals : {};
    if (invalid.length > 0 || !caps.every((c) => isNonNegativeSafeInteger(totals[c]))) {
      malformed.push({ index, reason: 'mandate_totals_malformed' });
      return;
    }
    const record: SlotRecord = { slot, totals: totals as Record<string, number>, values: values ?? {} };
    bySlot.set(slot, [...(bySlot.get(slot) ?? []), record]);
  });

  const slots = [...bySlot.keys()].sort((a, b) => a - b);
  const duplicateSlots = slots.filter((s) => bySlot.get(s)!.length > 1);
  const gaps: MandateSlotGap[] = [];
  const unexplainedSteps: MandateConsumptionResult['unexplainedSteps'] = [];
  let previous: SlotRecord | null = null;
  let completeUpTo = 0;
  for (const slot of slots) {
    const record = bySlot.get(slot)![0];
    const previousSlot = previous?.slot ?? 0;
    if (slot === completeUpTo + 1) completeUpTo = slot;
    const previousTotals = (cap: string) => (previous ? previous.totals[cap] : 0);
    if (slot > previousSlot + 1) {
      const unexplained: Record<string, number> = {};
      for (const cap of caps) unexplained[cap] = record.totals[cap] - previousTotals(cap) - record.values[cap];
      gaps.push({ from: previousSlot + 1, to: slot - 1, unexplained });
    } else {
      for (const cap of caps) {
        const expected = previousTotals(cap) + record.values[cap];
        if (record.totals[cap] !== expected) unexplainedSteps.push({ slot, cap, expected, actual: record.totals[cap] });
      }
    }
    previous = record;
  }

  let complete: boolean | null = null;
  let beyondEvent: number[] = [];
  const event = isPlainObject(options.lastEvent) ? options.lastEvent : null;
  if (event !== null && isNonNegativeSafeInteger(event.used)) {
    const used = event.used;
    const last = used === 0 ? null : bySlot.get(used)?.[0] ?? null;
    const eventTotals = isPlainObject(event.totals) ? event.totals : null;
    const totalsMatch =
      used === 0 ||
      (last !== null && caps.every((cap) => eventTotals !== null && eventTotals[cap] === last.totals[cap]));
    beyondEvent = slots.filter((s) => s > used);
    complete = completeUpTo >= used && totalsMatch && beyondEvent.length === 0;
  }
  return { duplicateSlots, gaps, unexplainedSteps, malformed, completeUpTo, beyondEvent, complete };
}
