/**
 * Capture under a mandate (Record §9.6): `capture(input, { mandate: {
 * mandateId } })`.
 *
 * `open` reads the mandate once, before any sequence number is taken, and
 * refuses what does not depend on the slot: a store without mandates, a
 * mandate it does not hold, a mandate that is not open. Every build attempt
 * then calls the claim's `plan` with the payload as built so far: it re-reads
 * the mandate row and its totals and runs the engine's `planMandateClaim`
 * (decider in `agents`, open, inside the window, the schema version, the
 * scope within, the confirmation flag, the cap values, a free slot and room
 * under every cap). The plan gives the record its mandate expectation
 * (`mandateSeq = used + 1`, the new totals, the flag), its `mandate` link to
 * the issuance record, `nonRepudiation.mandate`, the custody entries
 * `captured_under_mandate` and, when a confirmation is owed,
 * `confirmation_required`, and the claim the store makes by compare-and-swap
 * in the storing transaction.
 *
 * A claim that lost to another capture (`used` or a total moved since the
 * plan read them) is retried: the SDK rebuilds at its next attempt and the
 * plan reads again. A closed, full or over-cap mandate is terminal. A plan
 * that finds the record's `capturedAt` past `notAfter` moves the mandate to
 * `expired`, in a transaction of its own, and refuses `outside_validity`.
 *
 * A capture under an idempotency key keeps the store's lookup-before-claim
 * order: the key is looked up inside the storing transaction, before the claim.
 * So a keyed capture that the mandate refuses for its state or its window
 * (`mandate_not_open`, `mandate_full`, a cap's `cap_exceeded`,
 * `outside_validity`) is not refused here. It is planned as if the mandate
 * could take it, built, and refused by the store's claim after the key lookup,
 * with the same code; a retry of a capture that was stored replays its receipt
 * instead. Each of these refusals holds for good once it holds (a mandate
 * leaves `open` for good, `used` and every total only grow, and a record's
 * `capturedAt` and the window never change), so the store refuses such a claim
 * whenever it reaches the claim.
 */
import { planMandateClaim } from '@tzun/engine';
import type { EvidencePayload, LinkTarget, MandateBlock, MandateClaimPlan, MandateDocument, MandateRow } from '@tzun/engine';
import type {
  CaptureHookContext,
  CaptureRefusal,
  MandateAttemptPlan,
  MandateCaptureClaim,
  MandateCaptureHook,
  SdkHost,
} from '../extension-points';
import { expireMandateIfEnded } from './expiry';
import { issuanceTargetOf, mandatePartsOf, mandateStoreOf, totalsOf, type MandateParts, type MandateStore } from './store';
import { classifyMandateStoreError } from './store-errors';

function refusal(
  failureType: CaptureRefusal['failureType'],
  code: string,
  field: string,
  message: string,
  details?: Record<string, unknown>,
): CaptureRefusal {
  return { failureType, code, field, message, ...(details !== undefined && { details }) };
}

/** The mandate service's capture hook, over the store the capturing instance writes to. */
export function mandateCaptureHook(): MandateCaptureHook {
  return {
    async open({ mandateId }: { mandateId: string }, ctx: CaptureHookContext): Promise<MandateCaptureClaim | CaptureRefusal> {
      const store = mandateStoreOf(ctx.host);
      if (store === null) {
        return refusal('validation_failure', 'mandate_not_supported_by_store', 'mandate', 'this store does not hold mandates');
      }
      if (typeof mandateId !== 'string' || mandateId.length === 0) {
        return refusal('validation_failure', 'mandate_not_found', 'mandate.mandateId', 'mandate.mandateId must name a mandate');
      }
      const row = await store.getMandate(mandateId);
      // A digest is not a mandate id: a capture names its mandate by id.
      if (row === null || row.mandateId !== mandateId) {
        return refusal('validation_failure', 'mandate_not_found', 'mandate.mandateId', 'this store holds no mandate with that id');
      }
      const keyed = ctx.idempotencyKey !== undefined;
      if (row.state !== 'open' && !keyed) {
        return refusal('mandate_refused', 'mandate_not_open', 'mandate', `the mandate is ${row.state}, not open`);
      }
      const parts = mandatePartsOf(row);
      const issuance = await issuanceTargetOf(ctx.host, row);
      return mandateClaim(ctx.host, store, row, parts, issuance, keyed);
    },
  };
}

/** The refusals a keyed capture leaves to the store's claim (see the module comment). */
const DEFERRED_WHEN_KEYED: ReadonlySet<string> = new Set(['mandate_not_open', 'mandate_full', 'cap_exceeded', 'outside_validity']);

/** The document as if it had no window, no slot limit and no cap maximum: what a deferred plan is planned under. */
function withoutLimits(document: MandateDocument): MandateDocument {
  const cumulative = document.limits.cumulative;
  return {
    ...document,
    validity: { notBefore: null, notAfter: null },
    limits: {
      maxRecords: null,
      cumulative:
        cumulative === null
          ? null
          : Object.fromEntries(Object.entries(cumulative).map(([cap, c]) => [cap, { ...c, max: Number.MAX_SAFE_INTEGER }])),
    },
  };
}

/** Whether the store refuses `planned`'s claim on `row` for `code`, as the strict plan did. */
function storeRefuses(code: string, row: MandateRow, document: MandateDocument, planned: Extract<MandateClaimPlan, { ok: true }>, capturedAt: string): boolean {
  switch (code) {
    case 'mandate_not_open':
      return row.state !== 'open';
    case 'mandate_full':
      return row.maxRecords !== null && row.used >= row.maxRecords;
    case 'outside_validity': {
      const at = Date.parse(capturedAt);
      return (row.notBefore !== null && at < Date.parse(row.notBefore)) || (row.notAfter !== null && at > Date.parse(row.notAfter));
    }
    case 'cap_exceeded':
      return planned.caps.some((c) => {
        const max = document.limits.cumulative?.[c.cap]?.max;
        return typeof max === 'number' && Number.isSafeInteger(c.newTotal) && c.newTotal > max;
      });
    default:
      return false;
  }
}

function mandateClaim(host: SdkHost, store: MandateStore, opened: MandateRow, parts: MandateParts, issuance: LinkTarget, keyed: boolean): MandateCaptureClaim {
  const block: MandateBlock = {
    statement: parts.statement,
    assertion: parts.assertion,
    assertionTimestamp: opened.assertionTimestamp,
    document: parts.document,
  };
  // The refusal the last plan left to the store, or `null` when it planned a claim the mandate can take.
  let deferred: CaptureRefusal | null = null;

  function attemptPlan(row: MandateRow, payload: EvidencePayload, planned: Extract<MandateClaimPlan, { ok: true }>): MandateAttemptPlan {
    const slot = planned.expectation.mandateSeq;
    const custody: MandateAttemptPlan['custody'] = [
      {
        action: 'captured_under_mandate',
        actor: payload.decider!.id,
        metadata: {
          mandateId: row.mandateId,
          slot,
          statementDigest: row.statementDigest,
          assertionDigest: row.assertionDigest,
        },
      },
    ];
    if (planned.expectation.confirm) {
      custody.push({
        action: 'confirmation_required',
        actor: payload.decider!.id,
        metadata: { mandateId: row.mandateId, slot, predicates: [...planned.confirmHolding] },
      });
    }
    return {
      signoffExpectation: planned.expectation,
      links: planned.links,
      block,
      custody,
      claim: { mandateId: row.mandateId, expectUsed: planned.expectUsed, caps: planned.caps, now: payload.capturedAt },
      result: { mandateId: row.mandateId, slot, totals: planned.expectation.totals },
    };
  }

  return {
    async plan(payload: EvidencePayload): Promise<MandateAttemptPlan | CaptureRefusal> {
      deferred = null;
      const row = await store.getMandate(opened.mandateId);
      if (row === null) return refusal('validation_failure', 'mandate_not_found', 'mandate.mandateId', 'this store holds no mandate with that id');
      const totals = await totalsOf(store, row, parts.document);
      const claimArgs = {
        payload: payload as unknown as Record<string, unknown>,
        assertionDigest: row.assertionDigest,
        issuance,
      };
      const planned = planMandateClaim({ document: parts.document, mandate: { state: row.state, used: row.used, totals }, ...claimArgs });
      if (planned.ok) return attemptPlan(row, payload, planned);

      if (planned.expired === true) {
        const outcome = await expireMandateIfEnded(store, row.mandateId, payload.capturedAt).catch((error: unknown) => {
          host.log('mandate_expiry_failed', {
            mandateId: row.mandateId,
            errorName: error instanceof Error ? error.name : typeof error,
          });
          return null;
        });
        if (outcome === 'expired') host.log('mandate_expired', { mandateId: row.mandateId, used: row.used });
      }
      const details = planned.findings !== undefined ? { findings: planned.findings } : undefined;
      const refused = refusal('mandate_refused', planned.code, planned.field, planned.message, details);
      if (!keyed || !DEFERRED_WHEN_KEYED.has(planned.code)) return refused;

      const relaxed = planMandateClaim({ document: withoutLimits(parts.document), mandate: { state: 'open', used: row.used, totals }, ...claimArgs });
      if (!relaxed.ok || !storeRefuses(planned.code, row, parts.document, relaxed, payload.capturedAt)) return refused;
      deferred = refused;
      host.log('mandate_claim_deferred_to_store', { mandateId: row.mandateId, code: planned.code });
      return attemptPlan(row, payload, relaxed);
    },

    classifyStoreError(error: unknown): 'retry' | CaptureRefusal | null {
      const kind = classifyMandateStoreError(error);
      if (kind === null) return null;
      if (kind.kind === 'conflict') return 'retry';
      if (kind.kind === 'refused') {
        // A deferred plan is refused by the store with the plan's own answer (a
        // plan past the window moved the mandate to expired, which the store
        // then reads as not open).
        if (deferred !== null) return deferred;
        const failureType = kind.code === 'mandate_not_found' ? 'validation_failure' : 'mandate_refused';
        return refusal(failureType, kind.code, kind.field, kind.message);
      }
      return null;
    },
  };
}
