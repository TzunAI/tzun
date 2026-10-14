/**
 * How the mandate service reads a store's mandate errors
 * (`src/storage/mandate-sql.ts`): by their `name` and `code`, so an error
 * that crossed a module boundary (a bundled copy of the storage module, a
 * custom adapter that throws the same shape) is read the same way.
 */
import type { MandateStoreRefusalCode } from '../../storage/mandate-sql';

/** A store's mandate error, classified. */
export type ClassifiedMandateStoreError =
  | { kind: 'refused'; code: MandateStoreRefusalCode; field: string; message: string }
  | { kind: 'conflict'; code: 'mandate_claim_conflict' | 'mandate_state_conflict' }
  | { kind: 'input'; message: string };

/** `null` when `error` is not one of the store's mandate errors. */
export function classifyMandateStoreError(error: unknown): ClassifiedMandateStoreError | null {
  if (typeof error !== 'object' || error === null) return null;
  const e = error as { name?: unknown; code?: unknown; field?: unknown; message?: unknown };
  const message = typeof e.message === 'string' ? e.message : '';
  if (e.name === 'MandateStoreRefusalError' && typeof e.code === 'string') {
    return { kind: 'refused', code: e.code as MandateStoreRefusalCode, field: typeof e.field === 'string' ? e.field : 'mandate', message };
  }
  if (e.name === 'MandateStoreConflictError' && (e.code === 'mandate_claim_conflict' || e.code === 'mandate_state_conflict')) {
    return { kind: 'conflict', code: e.code };
  }
  if (e.name === 'MandateStoreInputError') return { kind: 'input', message };
  return null;
}
