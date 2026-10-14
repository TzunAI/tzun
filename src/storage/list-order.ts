/**
 * The ordering contract for `StorageAdapter.list()`, stated once.
 *
 * `capturedAt` is integrator-supplied and nothing normalises it, so sorting on
 * the raw STRING (`localeCompare`, or `ORDER BY` a TEXT column) puts any set
 * of timestamps that is not uniform millisecond-precision UTC in the WRONG
 * order — `2026-05-01T10:00:00Z` sorts after `2026-05-01T10:00:00.500Z`
 * because `Z` > `.`, and a `+02:00` offset sorts by its wall-clock digits —
 * while Postgres, which parses the instant (TIMESTAMPTZ), puts it in the right
 * one. Ties need a rule too, or each backend breaks them its own way.
 *
 * The contract every adapter honours, and the conformance suite asserts:
 *
 *   1. Records are ordered by the UTC INSTANT of `payload.capturedAt`, compared
 *      at MILLISECOND precision. Sub-millisecond digits are truncated (never
 *      rounded) on every backend: V8's `Date.parse` truncates, Postgres uses
 *      `date_trunc('milliseconds', ...)`, and SQLite stores the value this
 *      function computes. Millisecond precision is the finest all three can
 *      agree on — a JS `Date` has no finer, and SQLite's own date parser ROUNDS
 *      sub-millisecond input, which is why the instant is computed here rather
 *      than in SQL.
 *   2. Ties are broken by `payload.sequenceNumber`, then by `evidenceId`
 *      (ordinal string comparison), so the order is total.
 *   3. `order: 'desc'` (the default) is the exact reverse of `'asc'`: all three
 *      keys descend.
 *   4. A `capturedAt` that does not parse as an instant sorts FIRST under
 *      'asc' and LAST under 'desc' — the same place SQL puts a NULL key.
 *      Postgres never stores one at all (TIMESTAMPTZ refuses it at insert).
 *
 * `capturedAt` is expected to be RFC 3339 with an explicit offset or `Z`,
 * which is what `capture()` emits. A zone-less string is interpreted by
 * `Date.parse` (as local time) on memory and SQLite and by Postgres' parser
 * (as UTC) on Postgres; that input is outside the contract.
 */

/**
 * The millisecond UTC instant `list()` orders on, or `null` when the string
 * is not a parseable instant.
 */
export function capturedAtInstantMs(capturedAt: string): number | null {
  const ms = Date.parse(capturedAt);
  return Number.isNaN(ms) ? null : ms;
}

/** Ordinal (UTF-16 code unit) string comparison — never `localeCompare`. */
function cmpString(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Compare two records under the 'asc' contract. Callers negate for 'desc'.
 */
export function compareForList(
  a: { capturedAt: string; sequenceNumber: number; evidenceId: string },
  b: { capturedAt: string; sequenceNumber: number; evidenceId: string },
): number {
  const ia = capturedAtInstantMs(a.capturedAt);
  const ib = capturedAtInstantMs(b.capturedAt);
  // Unparseable sorts first, like a NULL key in SQL ASC.
  const ka = ia === null ? Number.NEGATIVE_INFINITY : ia;
  const kb = ib === null ? Number.NEGATIVE_INFINITY : ib;
  if (ka !== kb) return ka < kb ? -1 : 1;
  if (a.sequenceNumber !== b.sequenceNumber) return a.sequenceNumber < b.sequenceNumber ? -1 : 1;
  return cmpString(a.evidenceId, b.evidenceId);
}
