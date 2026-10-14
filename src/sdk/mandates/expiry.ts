/**
 * Expiry: `state = 'expired'` is written when the mandate service first
 * observes that a mandate's validity window has ended: by a claim whose
 * record's `capturedAt` is later than `notAfter`, by a read of the mandate
 * through `tzun.mandates` (`get`, `events`, `list`), or by a scheduled pass
 * over the open mandates ({@link expireEndedMandates}).
 * Expiry captures no record: the store's `expireMandate()` moves the mandate
 * and writes its `expired` event, whose `record` is the issuance record and
 * whose `used` and `totals` are the final values, in one transaction with
 * the mandate row locked.
 */
import { buildMandateEventBody, mandateExpiredAt } from '@tzun/engine';
import type { MandateListFilter, MandateListPage } from '../../storage/mandate-sql';
import { mandateEventRow, mandatePartsOf, totalsOf, type MandateStore } from './store';
import { classifyMandateStoreError } from './store-errors';

/** What {@link expireMandateIfEnded} found. */
export type MandateExpiryOutcome = 'expired' | 'not_open' | 'not_ended' | 'not_found';

/** How many times a lost compare-and-swap (a claim committed in between) is read again. */
const EXPIRY_ATTEMPTS = 5;

/**
 * Move `mandateId` to `expired` when it is open and `instant` is later than
 * its `notAfter`, with its `expired` event. A claim that commits between the
 * read and the write moves `used` and the totals, so the event is rebuilt
 * from a fresh read. Another writer that closed the mandate first wins; the
 * answer is then `not_open`.
 */
export async function expireMandateIfEnded(store: MandateStore, mandateId: string, instant: string): Promise<MandateExpiryOutcome> {
  for (let attempt = 1; ; attempt++) {
    const row = await store.getMandate(mandateId);
    if (row === null) return 'not_found';
    if (row.state !== 'open') return 'not_open';
    if (!mandateExpiredAt(row.notAfter, instant)) return 'not_ended';
    const { document } = mandatePartsOf(row);
    const totals = await totalsOf(store, row, document);
    const body = buildMandateEventBody({
      event: 'expired',
      mandateDigest: row.mandateDigest,
      record: row.issuanceDigest,
      used: row.used,
      totals,
    });
    try {
      await store.expireMandate({
        mandateId: row.mandateId,
        expectState: 'open',
        expectUsed: row.used,
        expectTotals: totals,
        event: mandateEventRow(row.mandateId, body),
      });
      return 'expired';
    } catch (error) {
      const kind = classifyMandateStoreError(error);
      if (kind?.kind === 'conflict' && attempt < EXPIRY_ATTEMPTS) continue;
      if (kind?.kind === 'refused' && kind.code === 'mandate_not_open') return 'not_open';
      if (kind?.kind === 'refused' && kind.code === 'mandate_not_expired') return 'not_ended';
      throw error;
    }
  }
}

/** A store that lists its mandates (`listMandates`) besides the mandate methods. */
export interface MandateListingStore extends MandateStore {
  listMandates(filter?: MandateListFilter): Promise<MandateListPage>;
}

/** What {@link expireEndedMandates} did. */
export interface MandateExpiryPass {
  /** Open mandates past their window that were moved to `expired` by this pass. */
  expired: string[];
  /** Mandates this pass could not move, by id, with the error's name (logged by the caller). */
  failed: Array<{ mandateId: string; errorName: string }>;
}

/**
 * The scheduled expiry pass: every mandate still open whose `notAfter` is
 * earlier than `instant` is moved to `expired` with its event
 * ({@link expireMandateIfEnded}), a page at a time. A mandate another writer
 * closed first is skipped; one whose move fails is reported in `failed` and
 * the pass goes on.
 */
export async function expireEndedMandates(store: MandateListingStore, instant: string, pageSize = 100): Promise<MandateExpiryPass> {
  const pass: MandateExpiryPass = { expired: [], failed: [] };
  let cursor: string | null = null;
  do {
    const page: MandateListPage = await store.listMandates({ state: 'open', notAfterBefore: instant, limit: pageSize, cursor });
    for (const row of page.rows) {
      try {
        if ((await expireMandateIfEnded(store, row.mandateId, instant)) === 'expired') pass.expired.push(row.mandateId);
      } catch (error) {
        pass.failed.push({ mandateId: row.mandateId, errorName: error instanceof Error ? error.name : typeof error });
      }
    }
    cursor = page.cursor;
  } while (cursor !== null);
  return pass;
}
