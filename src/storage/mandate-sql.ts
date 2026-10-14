/**
 * The mandate tables' statements, and the one rule every adapter applies to a
 * mandate write (Record §9.6).
 *
 * A mandate write rides on `store()`: the record it is stored with names it
 * through `StoreOptions.mandateClaim` (a capture under a mandate takes its
 * slot and running totals), `mandateIssue` (an issuance record inserts the
 * mandate, its caps and its `issued` event) or `mandateRevoke` (a revocation
 * record, or a successor's issuance record, closes the mandate and writes its
 * event). Expiry captures no record and is `expireMandate()`, a transaction
 * of its own.
 *
 * The decision is made once, here, by {@link planMandateWrite} and
 * {@link planMandateExpiry}, over a {@link MandateSnapshot} each adapter reads
 * inside its own critical section (SQLite's IMMEDIATE transaction, the
 * Postgres row lock, the memory adapter's synchronous section). The adapter
 * then applies the plan with the compare-and-swap statements below, so the
 * three backends refuse, conflict and write alike:
 *
 *   - {@link MandateStoreRefusalError}: the mandate cannot take this write
 *     (not held, not open, full, over a cap, outside its window, already
 *     issued). Terminal.
 *   - {@link MandateStoreConflictError}: another writer moved the slot count,
 *     a running total or the state since the caller read them. The caller
 *     re-reads and rebuilds.
 *   - {@link MandateStoreInputError}: the write contradicts itself or the
 *     record it is stored with (a claim whose slot is not the record's
 *     `mandateSeq`, an event body that does not hash to its digest). A bug in
 *     the caller, never retried.
 */
import { createHash } from 'crypto';
import {
  assertionDigest,
  BARE_DIGEST_RE,
  canonicalSerializeValue,
  InvalidPaginationError,
  mandateEventBodyViolation,
  mandateStatementDigest,
  MANDATE_AI_SYSTEM_ID,
  MANDATE_ISSUE_ACTION,
  MANDATE_REVOKE_ACTION,
} from '@tzun/engine';
import type {
  MandateCapClaim,
  MandateCapLimit,
  MandateEventRow,
  MandateExpireStore,
  MandateRow,
  MandateState,
} from '@tzun/engine';
import type { StoreWrite } from './extensions';

// ── Errors ─────────────────────────────────────────────────────────────────

/** Why a mandate cannot take a write. */
export type MandateStoreRefusalCode =
  | 'mandate_not_found'
  | 'mandate_not_open'
  | 'mandate_full'
  | 'cap_exceeded'
  | 'outside_validity'
  | 'mandate_already_issued'
  | 'mandate_not_expired';

/** A mandate write the mandate cannot take. Terminal: the store is rolled back and nothing is retried. */
export class MandateStoreRefusalError extends Error {
  constructor(
    readonly code: MandateStoreRefusalCode,
    readonly mandateId: string,
    readonly field: string,
    message: string,
  ) {
    super(message);
    this.name = 'MandateStoreRefusalError';
    Object.setPrototypeOf(this, MandateStoreRefusalError.prototype);
  }
}

/**
 * A mandate write whose compare-and-swap lost: the slot count, a running
 * total or the state is not what the caller read. The caller re-reads the
 * mandate and rebuilds the write.
 */
export class MandateStoreConflictError extends Error {
  constructor(
    readonly code: 'mandate_claim_conflict' | 'mandate_state_conflict',
    readonly mandateId: string,
    message: string,
  ) {
    super(message);
    this.name = 'MandateStoreConflictError';
    Object.setPrototypeOf(this, MandateStoreConflictError.prototype);
  }
}

/** A mandate write that contradicts itself or the record it is stored with. */
export class MandateStoreInputError extends Error {
  readonly code = 'mandate_store_input_invalid' as const;
  constructor(message: string) {
    super(message);
    this.name = 'MandateStoreInputError';
    Object.setPrototypeOf(this, MandateStoreInputError.prototype);
  }
}

// ── What an adapter reads before it decides ────────────────────────────────

/** The columns of a `mandates` row a write is decided over. */
export interface MandateStateRow {
  mandateId: string;
  mandateDigest: string;
  assertionDigest: string;
  state: MandateState;
  used: number;
  maxRecords: number | null;
  notBefore: string | null;
  notAfter: string | null;
  issuanceDigest: string;
}

/** One cap's maximum and running total. */
export interface MandateTotalRow {
  max: number;
  total: number;
}

/** What an adapter read, inside its critical section, for one write. */
export interface MandateSnapshot {
  /** The rows of the mandates the write names ({@link mandateIdsOf}), by id; absent when not held. */
  rows: ReadonlyMap<string, MandateStateRow>;
  /** Their caps, by mandate id, then cap. */
  totals: ReadonlyMap<string, ReadonlyMap<string, MandateTotalRow>>;
  /** Whether a mandate with the id or the digest `mandateIssue` inserts is already held. */
  issueTaken: boolean;
}

/** The mandate ids a write reads and locks: its claim's and its transition's (each once, in that order). */
export function mandateIdsOf(write: Pick<StoreWrite, 'options'>): string[] {
  const ids: string[] = [];
  const claim = write.options.mandateClaim;
  const revoke = write.options.mandateRevoke;
  if (claim && typeof claim.mandateId === 'string') ids.push(claim.mandateId);
  if (revoke && typeof revoke.mandateId === 'string' && !ids.includes(revoke.mandateId)) ids.push(revoke.mandateId);
  return ids;
}

/** The id and digest `mandateIssue` inserts, or `null`. */
export function issuedKeyOf(write: Pick<StoreWrite, 'options'>): { mandateId: string; mandateDigest: string } | null {
  const record = write.options.mandateIssue?.record;
  if (!record) return null;
  return { mandateId: String(record.mandateId), mandateDigest: String(record.mandateDigest) };
}

// ── The plan ───────────────────────────────────────────────────────────────

/** The value of JSON text, or `undefined` when it is not JSON. */
function parsedJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Why a new mandate row disagrees with its own parts, or `null`: the
 * document, statement and assertion are kept as their canonical bytes; the
 * document names the row's mandate id; the statement is well formed, names
 * the mandate's digest and hashes to the statement digest; the assertion
 * gives the assertion digest; and the row's slot limit, window and caps
 * (each cap's name and maximum) are the document's. The store enforces the
 * row while a verifier reads the document, so the two never differ.
 */
export function mandateRowPartsViolation(record: MandateRow, caps: ReadonlyArray<{ cap: unknown; max: unknown }>): string | null {
  const document = parsedJson(record.documentBytes);
  if (!isPlainObject(document) || canonical(document) !== record.documentBytes) return 'the document bytes are the canonical bytes of a document';
  if (document.mandateId !== record.mandateId) return "the row's mandate id is its document's";
  const statement = parsedJson(record.statementJson);
  if (
    statement === undefined ||
    canonical(statement) !== record.statementJson ||
    mandateStatementDigest(statement) !== record.statementDigest ||
    (statement as Record<string, unknown>).mandateDigest !== record.mandateDigest
  ) {
    return "the statement names the mandate's digest and hashes to the statement digest";
  }
  const assertion = parsedJson(record.assertionJson);
  if (assertion === undefined || canonical(assertion) !== record.assertionJson || assertionDigest(assertion) !== record.assertionDigest) {
    return 'the assertion gives the assertion digest';
  }
  const limits = isPlainObject(document.limits) ? document.limits : {};
  const validity = isPlainObject(document.validity) ? document.validity : {};
  if (limits.maxRecords !== record.maxRecords || validity.notBefore !== record.notBefore || validity.notAfter !== record.notAfter) {
    return "the row's slot limit and validity window are its document's";
  }
  const cumulative = limits.cumulative === null ? {} : isPlainObject(limits.cumulative) ? limits.cumulative : null;
  if (
    cumulative === null ||
    Object.keys(cumulative).length !== caps.length ||
    !caps.every((c) => typeof c.cap === 'string' && isPlainObject(cumulative[c.cap]) && (cumulative[c.cap] as Record<string, unknown>).max === c.max)
  ) {
    return "the row's caps and their maximums are its document's";
  }
  return null;
}

/** What an adapter writes for one mandate write, in this order. */
export interface MandateWritePlan {
  /** The slot claim: `used` from `expectUsed` to `expectUsed + 1`, and each cap's total. */
  claim: { mandateId: string; expectUsed: number; caps: MandateCapClaim[] } | null;
  /** The state move out of `open`, guarded on `used`. */
  transition: { mandateId: string; newState: 'revoked' | 'superseded' | 'expired'; expectUsed: number } | null;
  /** The mandate inserted with its caps, each at total 0. */
  insert: { record: MandateRow; caps: MandateCapLimit[] } | null;
  /** The event rows inserted. */
  events: MandateEventRow[];
}

function isBareDigest(value: unknown): value is string {
  return typeof value === 'string' && BARE_DIGEST_RE.test(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The canonical bytes of a value, or `null` when it has none. */
function canonical(value: unknown): string | null {
  try {
    return canonicalSerializeValue(value);
  } catch {
    return null;
  }
}

/** Why an event row is not a well-formed row of `mandateId`, or `null`. */
export function mandateEventRowViolation(row: unknown, mandateId: string): string | null {
  if (!isPlainObject(row)) return 'an event row is an object';
  if (row.mandateId !== mandateId) return 'the event row names another mandate';
  const reason = mandateEventBodyViolation(row.body);
  if (reason !== null) return `the event body is not well formed: ${reason}`;
  if (row.canonical !== canonical(row.body)) return "the event row's canonical bytes are not its body's";
  if (typeof row.canonical !== 'string' || row.digest !== sha256Hex(row.canonical)) return "the event row's digest is not its canonical bytes'";
  return null;
}

function eventRow(row: MandateEventRow, mandateId: string): MandateEventRow {
  const reason = mandateEventRowViolation(row, mandateId);
  if (reason !== null) throw new MandateStoreInputError(`mandate ${mandateId}: ${reason}`);
  return { mandateId, body: row.body, canonical: row.canonical, digest: row.digest };
}

/** Whether the totals an event or a guard names are the held ones (`null` when the mandate has no cap). */
function sameTotals(expected: Record<string, number> | null, held: ReadonlyMap<string, MandateTotalRow> | undefined): boolean {
  const caps = held ? [...held.keys()] : [];
  if (expected === null) return caps.length === 0;
  if (!isPlainObject(expected)) return false;
  const names = Object.keys(expected);
  if (names.length !== caps.length) return false;
  return names.every((cap) => held!.get(cap)?.total === expected[cap]);
}

function refuse(code: MandateStoreRefusalCode, mandateId: string, field: string, message: string): never {
  throw new MandateStoreRefusalError(code, mandateId, field, message);
}

function conflict(code: 'mandate_claim_conflict' | 'mandate_state_conflict', mandateId: string, message: string): never {
  throw new MandateStoreConflictError(code, mandateId, message);
}

function openRow(snap: MandateSnapshot, mandateId: string, field: string): MandateStateRow {
  const row = snap.rows.get(mandateId);
  if (!row) refuse('mandate_not_found', mandateId, field, `mandate ${mandateId} is not held by this store`);
  if (row.state !== 'open') refuse('mandate_not_open', mandateId, field, `mandate ${mandateId} is ${row.state}, not open`);
  return row;
}

/**
 * What a mandate write writes, or `null` when the write carries no mandate
 * option. Throws {@link MandateStoreRefusalError}, {@link
 * MandateStoreConflictError} or {@link MandateStoreInputError}; never
 * changes `snap`.
 *
 *   - `mandateClaim`: the mandate is held and open, `used` is `expectUsed`, a
 *     slot is free (`maxRecords`), `now` is inside the validity window (both
 *     ends inclusive), the claim names exactly the mandate's caps, each total
 *     is `expectTotal` and `newTotal` is within its maximum. The record it is
 *     stored with carries the mandate form with `mandateSeq = expectUsed + 1`,
 *     the new totals, the mandate's assertion digest, a `mandate` link to the
 *     issuance record, and `capturedAt = now`.
 *   - `mandateIssue`: no mandate with its id or digest is held; the row is
 *     open with no slot used; the document's bytes hash to its digest; the
 *     row agrees with its own parts ({@link mandateRowPartsViolation}: the
 *     statement and the assertion give their digests, and the slot limit,
 *     the window and the caps are the document's); the record it is stored
 *     with is the issuance record the row names (`tzun:mandate`,
 *     `issue-mandate`, its `aiOutput` digests); the event is the `issued`
 *     body of that record.
 *   - `mandateRevoke`: the mandate is held and open, `used` and every total
 *     are what the event body records; `revoked` with a revocation record,
 *     `superseded` only beside `mandateIssue` (the successor), whose digest
 *     the body names as `successor`. The event's `record` is the record this
 *     write stores.
 */
export function planMandateWrite(write: StoreWrite, snap: MandateSnapshot): MandateWritePlan | null {
  const { mandateClaim: claim, mandateIssue: issue, mandateRevoke: revoke } = write.options;
  if (!claim && !issue && !revoke) return null;
  const payload = write.envelope.payload as unknown as Record<string, unknown>;
  const digest = write.envelope.integrity?.canonicalDigest;
  if (claim && (issue || revoke)) {
    throw new MandateStoreInputError('a capture under a mandate neither issues nor closes a mandate');
  }
  if (revoke && revoke.newState === 'superseded' && !issue) {
    throw new MandateStoreInputError("a mandate is superseded only by its successor's issuance");
  }
  const plan: MandateWritePlan = { claim: null, transition: null, insert: null, events: [] };

  if (claim) {
    const id = claim.mandateId;
    const row = openRow(snap, id, 'mandate');
    if (row.used !== claim.expectUsed) {
      conflict('mandate_claim_conflict', id, `mandate ${id} has ${row.used} slots used, not ${claim.expectUsed}`);
    }
    if (row.maxRecords !== null && row.used >= row.maxRecords) {
      refuse('mandate_full', id, 'mandate', `every slot of mandate ${id} is used`);
    }
    const now = typeof claim.now === 'string' ? Date.parse(claim.now) : NaN;
    if (Number.isNaN(now)) throw new MandateStoreInputError(`mandate ${id}: the claim's instant is not an instant`);
    if ((row.notBefore !== null && now < Date.parse(row.notBefore)) || (row.notAfter !== null && now > Date.parse(row.notAfter))) {
      refuse('outside_validity', id, 'capturedAt', `the record's capturedAt is outside the validity window of mandate ${id}`);
    }
    const held = snap.totals.get(id) ?? new Map<string, MandateTotalRow>();
    const caps = Array.isArray(claim.caps) ? claim.caps : [];
    const names = new Set(caps.map((c) => c.cap));
    if (names.size !== caps.length || names.size !== held.size || ![...held.keys()].every((cap) => names.has(cap))) {
      throw new MandateStoreInputError(`mandate ${id}: a claim names exactly the mandate's caps, each once`);
    }
    const newTotals: Record<string, number> = {};
    for (const c of caps) {
      const cap = held.get(c.cap)!;
      if (!isNonNegativeSafeInteger(c.expectTotal) || !isNonNegativeSafeInteger(c.newTotal) || c.newTotal < c.expectTotal) {
        throw new MandateStoreInputError(`mandate ${id}: cap ${c.cap}'s totals are non-negative integers that never decrease`);
      }
      if (cap.total !== c.expectTotal) {
        conflict('mandate_claim_conflict', id, `cap ${c.cap} of mandate ${id} totals ${cap.total}, not ${c.expectTotal}`);
      }
      if (c.newTotal > cap.max) refuse('cap_exceeded', id, `limits.cumulative.${c.cap}`, `the record would take cap ${c.cap} past its maximum`);
      newTotals[c.cap] = c.newTotal;
    }
    const expectation = isPlainObject(payload.signoffExpectation) ? payload.signoffExpectation : null;
    if (
      expectation === null ||
      expectation.mandateSeq !== claim.expectUsed + 1 ||
      expectation.mandateAssertion !== row.assertionDigest ||
      canonical(expectation.totals) !== canonical(caps.length === 0 ? null : newTotals)
    ) {
      throw new MandateStoreInputError(
        `mandate ${id}: the record's mandate expectation must name the mandate's assertion, the claimed slot and the new totals`,
      );
    }
    if (payload.capturedAt !== claim.now) throw new MandateStoreInputError(`mandate ${id}: the claim's instant is the record's capturedAt`);
    const links = Array.isArray(payload.links) ? payload.links : [];
    const mandateLinks = links.filter((l) => isPlainObject(l) && l.rel === 'mandate');
    if (mandateLinks.length !== 1 || !isPlainObject(mandateLinks[0].target) || mandateLinks[0].target.digest !== row.issuanceDigest) {
      throw new MandateStoreInputError(`mandate ${id}: the record carries one mandate link, to the mandate's issuance record`);
    }
    plan.claim = { mandateId: id, expectUsed: claim.expectUsed, caps: caps.map((c) => ({ ...c })) };
  }

  if (revoke) {
    const id = revoke.mandateId;
    const row = openRow(snap, id, 'mandate');
    if (revoke.expectState !== 'open' || (revoke.newState !== 'revoked' && revoke.newState !== 'superseded')) {
      throw new MandateStoreInputError(`mandate ${id}: a revocation moves the mandate from open to revoked or superseded`);
    }
    if (row.used !== revoke.expectUsed || !sameTotals(revoke.expectTotals, snap.totals.get(id))) {
      conflict('mandate_state_conflict', id, `mandate ${id}'s slots or totals moved since they were read`);
    }
    const event = eventRow(revoke.event, id);
    const body = event.body;
    if (
      body.event !== revoke.newState ||
      body.mandateDigest !== row.mandateDigest ||
      body.record !== digest ||
      body.used !== revoke.expectUsed ||
      canonical(body.totals) !== canonical(revoke.expectTotals)
    ) {
      throw new MandateStoreInputError(
        `mandate ${id}: the ${revoke.newState} event names this mandate, the record stored with it, and the slots and totals it closes on`,
      );
    }
    if (revoke.newState === 'revoked' && (payload.aiSystemId !== MANDATE_AI_SYSTEM_ID || payload.action !== MANDATE_REVOKE_ACTION)) {
      throw new MandateStoreInputError(`mandate ${id}: a mandate is revoked with its revocation record`);
    }
    if (revoke.newState === 'superseded' && body.successor !== issue?.record?.mandateDigest) {
      throw new MandateStoreInputError(`mandate ${id}: the superseded event names the successor issued with it`);
    }
    plan.transition = { mandateId: id, newState: revoke.newState, expectUsed: revoke.expectUsed };
    plan.events.push(event);
  }

  if (issue) {
    const record = issue.record;
    if (!isPlainObject(record) || typeof record.mandateId !== 'string') {
      throw new MandateStoreInputError('an issuance carries the mandate record it inserts');
    }
    const id = record.mandateId;
    if (snap.issueTaken) refuse('mandate_already_issued', id, 'document.mandateId', `a mandate with the id or digest of mandate ${id} is already issued`);
    const aiOutput = isPlainObject(payload.aiOutput) ? payload.aiOutput : {};
    const rowRule =
      !isBareDigest(record.mandateDigest) ||
      !isBareDigest(record.statementDigest) ||
      !isBareDigest(record.assertionDigest) ||
      typeof record.documentBytes !== 'string' ||
      sha256Hex(record.documentBytes) !== record.mandateDigest ||
      typeof record.statementJson !== 'string' ||
      typeof record.assertionJson !== 'string' ||
      (record.assertionTimestamp !== null && typeof record.assertionTimestamp !== 'string') ||
      record.state !== 'open' ||
      record.used !== 0 ||
      (record.maxRecords !== null && !(isNonNegativeSafeInteger(record.maxRecords) && record.maxRecords >= 1)) ||
      (record.notBefore !== null && (typeof record.notBefore !== 'string' || Number.isNaN(Date.parse(record.notBefore)))) ||
      (record.notAfter !== null && (typeof record.notAfter !== 'string' || Number.isNaN(Date.parse(record.notAfter)))) ||
      typeof record.createdAt !== 'string';
    if (rowRule) throw new MandateStoreInputError(`mandate ${id}: the mandate record is not a new, open mandate whose document hashes to its digest`);
    const partsRule = mandateRowPartsViolation(record, Array.isArray(issue.caps) ? issue.caps : []);
    if (partsRule !== null) throw new MandateStoreInputError(`mandate ${id}: ${partsRule}`);
    if (
      record.issuanceEvidenceId !== payload.evidenceId ||
      record.issuanceDigest !== digest ||
      payload.aiSystemId !== MANDATE_AI_SYSTEM_ID ||
      payload.action !== MANDATE_ISSUE_ACTION ||
      aiOutput.mandateDigest !== record.mandateDigest ||
      aiOutput.statementDigest !== record.statementDigest ||
      aiOutput.assertionDigest !== record.assertionDigest
    ) {
      throw new MandateStoreInputError(`mandate ${id}: a mandate is issued with the issuance record that names it`);
    }
    const caps = Array.isArray(issue.caps) ? issue.caps : [];
    const capNames = new Set(caps.map((c) => c.cap));
    if (capNames.size !== caps.length || !caps.every((c) => typeof c.cap === 'string' && c.cap.length > 0 && isNonNegativeSafeInteger(c.max))) {
      throw new MandateStoreInputError(`mandate ${id}: each cap is named once, with a non-negative integer maximum`);
    }
    const event = eventRow(issue.event, id);
    const body = event.body;
    if (body.event !== 'issued' || body.mandateDigest !== record.mandateDigest || body.record !== digest || body.used !== null || body.totals !== null) {
      throw new MandateStoreInputError(`mandate ${id}: the issued event names this mandate and its issuance record`);
    }
    plan.insert = { record: { ...record }, caps: caps.map((c) => ({ cap: c.cap, max: c.max })) };
    plan.events.push(event);
  }
  return plan;
}

/**
 * What `expireMandate()` writes: the mandate is held and open, its window
 * has ended (`notAfter` is earlier than this store's clock), `used` and
 * every total are what the event body records, and the event is the
 * `expired` body of the mandate's issuance record.
 */
export function planMandateExpiry(expiry: MandateExpireStore, snap: MandateSnapshot, nowMs: number = Date.now()): MandateWritePlan {
  const id = expiry.mandateId;
  const row = openRow(snap, id, 'mandate');
  if (expiry.expectState !== 'open') throw new MandateStoreInputError(`mandate ${id}: expiry moves an open mandate`);
  if (row.notAfter === null || !(nowMs > Date.parse(row.notAfter))) {
    refuse('mandate_not_expired', id, 'validity.notAfter', `the validity window of mandate ${id} has not ended`);
  }
  if (row.used !== expiry.expectUsed || !sameTotals(expiry.expectTotals, snap.totals.get(id))) {
    conflict('mandate_state_conflict', id, `mandate ${id}'s slots or totals moved since they were read`);
  }
  const event = eventRow(expiry.event, id);
  const body = event.body;
  if (
    body.event !== 'expired' ||
    body.mandateDigest !== row.mandateDigest ||
    body.record !== row.issuanceDigest ||
    body.used !== expiry.expectUsed ||
    canonical(body.totals) !== canonical(expiry.expectTotals)
  ) {
    throw new MandateStoreInputError(`mandate ${id}: the expired event names this mandate, its issuance record, and its final slots and totals`);
  }
  return { claim: null, transition: { mandateId: id, newState: 'expired', expectUsed: expiry.expectUsed }, insert: null, events: [event] };
}

// ── Rows ───────────────────────────────────────────────────────────────────

/** A `mandates` row as both SQL dialects return it (Postgres BIGINT columns arrive as strings). */
export interface MandateDbRow {
  mandate_id: string;
  mandate_digest: string;
  document_bytes: string;
  statement_json: string;
  statement_digest: string;
  assertion_json: string;
  assertion_digest: string;
  assertion_timestamp: string | null;
  state: string;
  used: number | string;
  max_records: number | string | null;
  not_before: string | null;
  not_after: string | null;
  issuance_evidence_id: string;
  issuance_digest: string;
  created_at: string;
}

/** A `mandates` row as the engine's `MandateRow`. */
export function mandateRowOf(row: MandateDbRow): MandateRow {
  return {
    mandateId: row.mandate_id,
    mandateDigest: row.mandate_digest,
    documentBytes: row.document_bytes,
    statementJson: row.statement_json,
    statementDigest: row.statement_digest,
    assertionJson: row.assertion_json,
    assertionDigest: row.assertion_digest,
    assertionTimestamp: row.assertion_timestamp,
    state: row.state as MandateState,
    used: Number(row.used),
    maxRecords: row.max_records === null ? null : Number(row.max_records),
    notBefore: row.not_before,
    notAfter: row.not_after,
    issuanceEvidenceId: row.issuance_evidence_id,
    issuanceDigest: row.issuance_digest,
    createdAt: row.created_at,
  };
}

/** The columns a write is decided over. */
export function mandateStateOf(row: MandateRow): MandateStateRow {
  return {
    mandateId: row.mandateId,
    mandateDigest: row.mandateDigest,
    assertionDigest: row.assertionDigest,
    state: row.state,
    used: row.used,
    maxRecords: row.maxRecords,
    notBefore: row.notBefore,
    notAfter: row.notAfter,
    issuanceDigest: row.issuanceDigest,
  };
}

/** A `mandate_events` row as the engine's `MandateEventRow`. */
export function mandateEventRowOf(row: { mandate_id: string; canonical: string; digest: string }): MandateEventRow {
  return { mandateId: row.mandate_id, body: JSON.parse(row.canonical), canonical: row.canonical, digest: row.digest };
}

/** The values of an insert into `mandates`, in {@link MANDATE_COLUMNS} order. */
export function mandateInsertValues(record: MandateRow): unknown[] {
  return [
    record.mandateId,
    record.mandateDigest,
    record.documentBytes,
    record.statementJson,
    record.statementDigest,
    record.assertionJson,
    record.assertionDigest,
    record.assertionTimestamp,
    record.state,
    record.used,
    record.maxRecords,
    record.notBefore,
    record.notAfter,
    record.issuanceEvidenceId,
    record.issuanceDigest,
    record.createdAt,
  ];
}

/** Every column of `mandates`, in the order {@link mandateInsertValues} gives them. */
const MANDATE_COLUMNS =
  'mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, ' +
  'assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at';

// ── Statements ─────────────────────────────────────────────────────────────

/** SQLite statements (positional `?`). */
export const SQLITE_MANDATE_SQL = {
  selectById: `SELECT ${MANDATE_COLUMNS} FROM mandates WHERE mandate_id = ?`,
  /** A mandate by its id or by its digest: the two forms never collide (a UUID is not 64 hex). */
  selectByIdOrDigest: `SELECT ${MANDATE_COLUMNS} FROM mandates WHERE mandate_id = ? OR mandate_digest = ?`,
  issueTaken: 'SELECT 1 AS taken FROM mandates WHERE mandate_id = ? OR mandate_digest = ?',
  selectTotals: 'SELECT cap, max, total FROM mandate_totals WHERE mandate_id = ? ORDER BY cap',
  claimSlot:
    "UPDATE mandates SET used = used + 1 WHERE mandate_id = ? AND state = 'open' AND used = ? " +
    'AND (max_records IS NULL OR used < max_records)',
  claimCap: 'UPDATE mandate_totals SET total = ? WHERE mandate_id = ? AND cap = ? AND total = ? AND ? <= max',
  transition: "UPDATE mandates SET state = ? WHERE mandate_id = ? AND state = 'open' AND used = ?",
  insertMandate: `INSERT INTO mandates (${MANDATE_COLUMNS}) VALUES (${Array(16).fill('?').join(', ')})`,
  insertCap: 'INSERT INTO mandate_totals (mandate_id, cap, max, total) VALUES (?, ?, ?, 0)',
  insertEvent: 'INSERT INTO mandate_events (mandate_id, event, canonical, digest, recorded_at) VALUES (?, ?, ?, ?, ?)',
  selectEvents: 'SELECT mandate_id, canonical, digest FROM mandate_events WHERE mandate_id = ? ORDER BY id',
  /** A page of {@link listMandatesQuery}: state, then the window's end, then the cursor, then the limit. */
  list:
    `SELECT ${MANDATE_COLUMNS} FROM mandates ` +
    'WHERE (? IS NULL OR state = ?) AND (? IS NULL OR (not_after IS NOT NULL AND not_after < ?)) AND mandate_id > ? ' +
    'ORDER BY mandate_id LIMIT ?',
} as const;

/** Postgres statements (`$n`), unqualified table names (the connection's `search_path`). */
export const POSTGRES_MANDATE_SQL = {
  lock: 'SELECT mandate_id FROM mandates WHERE mandate_id = $1 FOR UPDATE',
  selectByIdForUpdate: `SELECT ${MANDATE_COLUMNS} FROM mandates WHERE mandate_id = $1 FOR UPDATE`,
  selectByIdOrDigest: `SELECT ${MANDATE_COLUMNS} FROM mandates WHERE mandate_id = $1 OR mandate_digest = $1`,
  issueTaken: 'SELECT 1 AS taken FROM mandates WHERE mandate_id = $1 OR mandate_digest = $2',
  selectTotals: 'SELECT cap, max, total FROM mandate_totals WHERE mandate_id = $1 ORDER BY cap',
  claimSlot:
    "UPDATE mandates SET used = used + 1 WHERE mandate_id = $1 AND state = 'open' AND used = $2 " +
    'AND (max_records IS NULL OR used < max_records)',
  claimCap: 'UPDATE mandate_totals SET total = $1 WHERE mandate_id = $2 AND cap = $3 AND total = $4 AND $1 <= max',
  transition: "UPDATE mandates SET state = $1 WHERE mandate_id = $2 AND state = 'open' AND used = $3",
  insertMandate: `INSERT INTO mandates (${MANDATE_COLUMNS}) VALUES (${Array.from({ length: 16 }, (_, i) => `$${i + 1}`).join(', ')})`,
  insertCap: 'INSERT INTO mandate_totals (mandate_id, cap, max, total) VALUES ($1, $2, $3, 0)',
  insertEvent: 'INSERT INTO mandate_events (mandate_id, event, canonical, digest) VALUES ($1, $2, $3, $4)',
  selectEvents: 'SELECT mandate_id, canonical, digest FROM mandate_events WHERE mandate_id = $1 ORDER BY id',
  /** A page of {@link listMandatesQuery}: `$1` state, `$2` the window's end, `$3` the cursor, `$4` the limit. */
  list:
    `SELECT ${MANDATE_COLUMNS} FROM mandates ` +
    'WHERE ($1::text IS NULL OR state = $1) AND ($2::text IS NULL OR (not_after IS NOT NULL AND not_after COLLATE "C" < $2)) ' +
    'AND mandate_id COLLATE "C" > $3 ORDER BY mandate_id COLLATE "C" LIMIT $4',
} as const;

/** The totals rows of one mandate as a map. */
export function totalsMapOf(rows: ReadonlyArray<{ cap: string; max: number | string; total: number | string }>): Map<string, MandateTotalRow> {
  return new Map(rows.map((r) => [r.cap, { max: Number(r.max), total: Number(r.total) }]));
}

/** A compare-and-swap statement that changed no row lost to another writer under the adapter's lock: never expected, reported as a conflict. */
export function assertChanged(changes: number, mandateId: string, what: string): void {
  if (changes !== 1) conflict(what === 'state' ? 'mandate_state_conflict' : 'mandate_claim_conflict', mandateId, `the ${what} of mandate ${mandateId} moved under the write`);
}

// ── Listing ────────────────────────────────────────────────────────────────

/** What `listMandates` selects: a state, mandates whose window ended before an instant, a page. */
export interface MandateListFilter {
  state?: MandateState;
  /** Mandates whose `notAfter` is earlier than this ISO 8601 UTC instant (a mandate with no end never matches). */
  notAfterBefore?: string;
  /** 1 to 200; 100 when absent. */
  limit?: number;
  /** The `cursor` of the previous page. */
  cursor?: string | null;
}

/** One page of mandates, in mandate id order, and the cursor of the next (`null` after the last). */
export interface MandateListPage {
  rows: MandateRow[];
  cursor: string | null;
}

/** The default and the largest page of `listMandates`. */
export const MANDATE_LIST_DEFAULT_LIMIT = 100;
export const MANDATE_LIST_MAX_LIMIT = 200;

const MANDATE_STATES: ReadonlySet<string> = new Set(['open', 'revoked', 'superseded', 'expired']);

/** A {@link MandateListFilter} checked and normalised for the statements (`InvalidPaginationError` names a bad member). */
export interface MandateListQuery {
  state: MandateState | null;
  /** The instant as `Date.toISOString()` writes it, the form the window's bounds are kept in. */
  notAfterBefore: string | null;
  limit: number;
  /** The last mandate id of the previous page; `''` for the first page. */
  after: string;
}

/**
 * The listing's query, or `InvalidPaginationError` for a member that is not
 * usable: a state that is not one of the four, an instant that does not
 * parse, a limit outside 1 to 200, a cursor that is not a mandate id.
 */
export function listMandatesQuery(filter: MandateListFilter = {}): MandateListQuery {
  const f = isPlainObject(filter) ? (filter as Record<string, unknown>) : {};
  const state = f.state === undefined || f.state === null ? null : f.state;
  if (state !== null && (typeof state !== 'string' || !MANDATE_STATES.has(state))) throw new InvalidPaginationError('state', state);
  let notAfterBefore: string | null = null;
  if (f.notAfterBefore !== undefined && f.notAfterBefore !== null) {
    const at = typeof f.notAfterBefore === 'string' ? Date.parse(f.notAfterBefore) : NaN;
    if (Number.isNaN(at)) throw new InvalidPaginationError('notAfterBefore', f.notAfterBefore);
    notAfterBefore = new Date(at).toISOString();
  }
  const limit = f.limit === undefined || f.limit === null ? MANDATE_LIST_DEFAULT_LIMIT : f.limit;
  if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > MANDATE_LIST_MAX_LIMIT) {
    throw new InvalidPaginationError('limit', limit);
  }
  const cursor = f.cursor === undefined || f.cursor === null ? '' : f.cursor;
  if (typeof cursor !== 'string' || cursor.length > 128) throw new InvalidPaginationError('cursor', cursor);
  return { state: state as MandateState | null, notAfterBefore, limit, after: cursor };
}

/** Whether a mandate row is selected by `query` (the memory adapter's filter; the SQL statements say the same). */
export function mandateListed(row: MandateRow, query: MandateListQuery): boolean {
  return (
    (query.state === null || row.state === query.state) &&
    (query.notAfterBefore === null || (row.notAfter !== null && row.notAfter < query.notAfterBefore)) &&
    row.mandateId > query.after
  );
}

/** The page of `rows` (one more than the limit was read, when there is one): the rows and the next cursor. */
export function mandateListPage(rows: MandateRow[], query: MandateListQuery): MandateListPage {
  const page = rows.slice(0, query.limit);
  return { rows: page, cursor: rows.length > query.limit ? page[page.length - 1].mandateId : null };
}
