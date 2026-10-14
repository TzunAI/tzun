/**
 * Pagination-bound validation shared by the storage adapters and the REST API.
 *
 * LIMIT/OFFSET cannot be expressed as a bound parameter in every dialect the
 * SDK targets, so an adapter may have to interpolate them into the SQL text.
 * `ListOptions.limit` is declared `number`, but a TypeScript type is not a
 * runtime boundary: a JavaScript integrator writing
 * `tzun.list({ limit: req.query.limit })` hands over a string, and a string in
 * the LIMIT position is SQL, not data.
 *
 * Validating here — rather than only at the HTTP edge — means every caller
 * gets the same rejection, including the in-process JS callers that never pass
 * through a route handler.
 */

import { InvalidPaginationError } from '@tzun/engine';

/**
 * Thrown when a pagination bound is not a usable non-negative integer. The
 * class is the engine's, because the contract it enforces is the engine's
 * `ListOptions`; it is re-exported here for the adapters and routes that
 * import it from this module.
 */
export { InvalidPaginationError };

/**
 * Return `value` as a safe non-negative integer, or throw.
 *
 * Rejects strings (including numeric-looking ones — a caller passing "10"
 * should be corrected, not silently coerced), NaN, Infinity, negatives,
 * fractions, and anything non-numeric.
 */
export function assertNonNegativeInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new InvalidPaginationError(field, value);
  }
  return value;
}

/**
 * Parse an untrusted query-string value into a pagination bound.
 * Returns undefined when absent; throws InvalidPaginationError when present
 * but unusable, so the route can answer 400 rather than letting the storage
 * layer produce a 500.
 */
export function parsePaginationParam(raw: unknown, field: string): number | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw === 'number') return assertNonNegativeInteger(raw, field);
  if (typeof raw !== 'string') throw new InvalidPaginationError(field, raw);
  // Reject anything that is not purely digits: this rules out "10; DROP",
  // "(SELECT ...)", "1e3", "0x10", "-1", "1.5" and leading/trailing space.
  if (!/^\d+$/.test(raw)) throw new InvalidPaginationError(field, raw);
  const n = Number(raw);
  return assertNonNegativeInteger(n, field);
}
