import { AttestationArtifacts, CustodyAction, CustodyEntry, EvidenceEnvelope } from './evidence';
import { FailureRecord } from './failure';
import { ListOptions, RetryObtainableComponent } from './config';
import { TamperIncident, TamperIncidentStatus } from './monitoring-events';
import { ChainIdentity, AnnotationRecord, RelinkRecord, ForkRecord } from './recovery';
import {
  ModelDescriptor,
  ModelDescriptorRow,
  ModelDescriptorAnnotationRow,
} from './ai-bom';
import type { AgentDescriptor } from './agent';
import type { DeciderOpening } from './decider';
import type { MandateCapClaim, MandateEventBody, MandateState } from './mandate';

/**
 * The head of an evidence chain: the last record's sequence number and digest.
 *
 * `{ sequence: 0, digest: null }` is an empty chain.
 */
export interface ChainHead {
  /** Sequence number of the last record in the chain (0 = empty chain). */
  sequence: number;
  /** Canonical digest of the last record (null = empty chain). */
  digest: string | null;
}

/**
 * A record's `attestationStatus`, computed from the envelope as a store will
 * write it (see `StorageAdapter.updateAttestation`).
 */
export type AttestationStatusOf = (envelope: EvidenceEnvelope) => EvidenceEnvelope['attestationStatus'];

/** Per-store options. */
export interface StoreOptions {
  /**
   * The caller's idempotency key, as the HTTP transport sends it
   * (`Idempotency-Key`). `store()` on a local adapter does not
   * read it: local replay is `storeIdempotent()`, which takes the key and the
   * input fingerprint together.
   */
  idempotencyKey?: string;
  /**
   * Compare-and-swap guard for a chain append.
   *
   * When present, the adapter MUST refuse the store — atomically, against the
   * live head OF THE CHAIN BEING APPENDED TO — unless that head is exactly
   * this. `Tzun.capture()` always supplies it, because a record's sequence
   * number and chain link are hashed into its digest and therefore have to be
   * chosen before the write; if the head moved in between, the record no longer
   * belongs at that position. It is the target chain's head and no other's
   *: an append to one chain is not refused because a different
   * chain moved.
   *
   * Omit it for a low-level store that is not a chain append (imports, test
   * fixtures, recovery flows) — the adapter then skips the head check. The
   * evidence log's own rules still apply (see `store()`).
   *
   * `{ sequence: 0, digest: null }` means "the chain must still be empty".
   *
   * @throws {ChainConflictError} (from `@tzun/engine`) if the head differs.
   */
  expectChainHead?: ChainHead;
  /**
   * A capture under a mandate (Record §9.6): claim the record's slot and
   * running totals in the same transaction as the insert, the mandate row
   * locked before the chain head. The adapter refuses the store when the
   * mandate is not open, `used` is not `expectUsed`, the mandate is full, a
   * cap's total is not `expectTotal` or `newTotal` exceeds its maximum, or
   * `now` (the record's `capturedAt`) is outside the validity window.
   */
  mandateClaim?: MandateClaimStore;
  /** An issuance record: insert the mandate record and its `issued` event with it. */
  mandateIssue?: MandateIssueStore;
  /** A revocation record, or a successor's issuance record: move the mandate out of `open` and write its event, guarded on `used` and the totals the event records. */
  mandateRevoke?: MandateRevokeStore;
  /** A `decider.commit: true` capture: keep the commitment's opening in `decider_openings`, in the same transaction. */
  deciderOpening?: DeciderOpening;
}

/** `StoreOptions.mandateClaim`: the compare-and-swap of a slot and the running totals. */
export interface MandateClaimStore {
  mandateId: string;
  expectUsed: number;
  caps: MandateCapClaim[];
  /** The record's `capturedAt`: the instant compared with the validity window. */
  now: string;
}

/** A mandate record as a store keeps it (`mandates`). Digests, document, statement and assertion are immutable. */
export interface MandateRow {
  mandateId: string;
  /** 64 lowercase hex. */
  mandateDigest: string;
  /** The document's canonical bytes. */
  documentBytes: string;
  statementJson: string;
  statementDigest: string;
  assertionJson: string;
  assertionDigest: string;
  /** Base64 DER TimeStampResp over the assertion digest, or `null`. */
  assertionTimestamp: string | null;
  state: MandateState;
  used: number;
  maxRecords: number | null;
  notBefore: string | null;
  notAfter: string | null;
  issuanceEvidenceId: string;
  issuanceDigest: string;
  createdAt: string;
}

/** A mandate event as a store keeps it (`mandate_events`, insert-only). */
export interface MandateEventRow {
  mandateId: string;
  body: MandateEventBody;
  /** The body's canonical bytes. */
  canonical: string;
  /** `hex(SHA-256(canonical))`. */
  digest: string;
}

/** One cap of a mandate as its `mandate_totals` row starts: the name and its maximum, total 0. */
export interface MandateCapLimit {
  cap: string;
  max: number;
}

/** `StoreOptions.mandateIssue`. */
export interface MandateIssueStore {
  record: MandateRow;
  /** The document's caps, each starting at total 0. */
  caps: MandateCapLimit[];
  event: MandateEventRow;
}

/**
 * `StoreOptions.mandateRevoke`: a compare-and-swap of the mandate's state,
 * slot count and running totals. The event body carries `used` and `totals`
 * as the caller read them, so the adapter, holding the mandate row locked,
 * refuses the store when the state is not `open`, `used` is not
 * `expectUsed`, or a cap's total is not its `expectTotals` entry. A claim
 * that committed after the caller's read then makes the caller re-read and
 * rebuild the event, so no terminal event records a stale `used` or
 * `totals`.
 */
export interface MandateRevokeStore {
  mandateId: string;
  expectState: 'open';
  newState: 'revoked' | 'superseded';
  /** The `used` the event body records. */
  expectUsed: number;
  /** The running totals the event body records, one entry per cap; `null` when the document has no cap. */
  expectTotals: Record<string, number> | null;
  event: MandateEventRow;
}

/**
 * `StorageAdapter.expireMandate`: expiry captures no record. The same
 * compare-and-swap as {@link MandateRevokeStore}: refused when the state is
 * not `open`, or `used` or a total is not what the event body records.
 */
export interface MandateExpireStore {
  mandateId: string;
  expectState: 'open';
  /** The `used` the event body records. */
  expectUsed: number;
  /** The running totals the event body records, one entry per cap; `null` when the document has no cap. */
  expectTotals: Record<string, number> | null;
  event: MandateEventRow;
}

/** An agent descriptor as the catalog keeps it (`agent_descriptors`). Verification reads only `canonicalBytes`. */
export interface AgentDescriptorRow {
  /** `sha256:` and 64 lowercase hex. */
  digest: string;
  /** The exact canonical bytes that were hashed. */
  canonicalBytes: string;
  /** Lookup columns, never read by verification. */
  name: string;
  organization: string;
  parent: string | null;
  registeredAt: string;
}

/** One row of the derived link index (`evidence_links`): a stored link, by its target digest. */
export interface EvidenceLinkRow {
  /** The record that carries the link. */
  evidenceId: string;
  /** The link's index in that record's `links`. */
  idx: number;
  rel: string;
  /** 64 lowercase hex. */
  targetDigest: string;
}

/**
 * One capture's claim on an idempotency key.
 *
 * The replay contract, shared with the platform:
 *   - the same key with the same caller input replays the original receipt;
 *   - the same key with different caller input is refused as a conflict.
 *
 * `fingerprint` covers the CALLER-SUPPLIED capture input only — never the
 * `evidenceId`, `capturedAt` or sequence number the SDK generates, which
 * differ on every attempt and would make a retry look like different input.
 * It is `captureIdempotencyFingerprint()` (engine idempotency-fingerprint.ts),
 * the platform's rule, over `{ completeness: 'partial', chainId, envelope }`
 * for the envelope `capture()` built. The adapter treats it as opaque and
 * compares it for equality.
 */
export interface IdempotencyClaim {
  /** The caller's key. Scoped to the store: one key names one record in it. */
  key: string;
  /** Fingerprint of the caller-supplied input the key was used with. */
  fingerprint: string;
}

/** What the capture that first claimed a key stored — the receipt a replay returns. */
export interface IdempotencyReceipt {
  evidenceId: string;
  /** The chain the record was stored under (`'default'` when none was named). */
  chainId: string;
  sequenceNumber: number;
  canonicalDigest: string;
}

/**
 * What `storeIdempotent()` did. It carries no error code on
 * purpose: mapping a conflict to what a caller sees is the capture layer's
 * job, so local and cloud can report the same thing.
 *
 *   - `claimed`  — the key was free; the record is stored and the key now
 *                  names it. `receipt` describes the record just stored.
 *   - `replay`   — the key already names a record, claimed with the same
 *                  fingerprint. Nothing was stored; `receipt` is the original.
 *   - `conflict` — the key already names a record, claimed with a different
 *                  fingerprint. Nothing was stored.
 */
export type IdempotencyOutcome =
  | { kind: 'claimed'; receipt: IdempotencyReceipt }
  | { kind: 'replay'; receipt: IdempotencyReceipt }
  | { kind: 'conflict' };

/** Options for `storeIdempotent()`: everything `store()` takes, plus the claim. */
export interface IdempotentStoreOptions extends StoreOptions {
  idempotency: IdempotencyClaim;
}

/**
 * Options for `appendCustodyEntry`.
 */
export interface CustodyAppendOptions {
  /**
   * The recovery record (annotation / fork id) this custody action belongs
   * to, kept on the `custody_entries` row so a later compensator can name
   * it. Not part of the entry hash.
   */
  recoveryId?: string | null;
}

/** One custody append that `applyRelink` performs inside its transaction. */
export interface RelinkCustodyAppend {
  evidenceId: string;
  entry: CustodyEntry;
}

/**
 * A `custody_entries` row — the writer-side ledger behind every hashed entry
 * mirrored into `envelope.custodyChain`, the SDK's counterpart of the hosted
 * service's custody ledger. Append-only on every adapter: SQLite and Postgres
 * refuse UPDATE/DELETE with a trigger; the memory adapter exposes no path to
 * either.
 *
 * `entryHash` is `computeCustodyEntryHash` (engine custody-hash.ts) over
 * `prevEntryHash`, `evidenceId`, `canonicalDigest`, `action`, `actor`,
 * `timestamp`, `systemId` and the canonical bytes of `metadata`, and is the
 * same value the mirrored envelope entry carries as `entryHash`.
 */
export interface StoredCustodyEntry {
  /** Adapter-assigned, monotonic per store; orders the rows of one record. */
  id: number;
  evidenceId: string;
  /** The record's chain at the time of the action, when the adapter tracks one. */
  chainId: string | null;
  /** The record's `integrity.canonicalDigest` at the time of the action. */
  canonicalDigest: string;
  action: CustodyAction;
  actor: string;
  /** The entry timestamp exactly as mirrored into `custodyChain[i].timestamp`. */
  timestamp: string;
  systemId: string;
  metadata: Record<string, unknown> | null;
  /** `entryHash` of the previous row for the SAME record, null for the first. */
  prevEntryHash: string | null;
  entryHash: string;
  /** The relink / fork / annotation record this action belongs to, if any. */
  recoveryId: string | null;
}

/**
 * Why a row was written to the append-only revision log.
 *
 * - `capture` — revision 0, written by `store()`. The digest this record was
 *   captured with; the value every later revision is compared against.
 * - `relink` — a Tier-2 recovery rewrote `integrity.chainLink`.
 * - `attestation_retry` — `updateAttestation()` re-stamped the record's
 *   attestation artifacts.
 * - `anchor_fill` — the anchor scheduler filled `nonRepudiation.anchor`
 *   after the record's epoch was final.
 *
 * None of them may legitimately change `canonicalDigest`: the SDK has no
 * operation that re-hashes a stored payload (`relink()` refuses
 * `correctedPayload` for exactly this reason). That is what makes "current
 * digest != the capture revision's digest" a sound tamper verdict rather than
 * a heuristic.
 */
export type RevisionCause = 'capture' | 'relink' | 'attestation_retry' | 'anchor_fill';

/**
 * One row of the append-only revision log.
 *
 * WHAT IT IS FOR. Without this log, nothing in an evidence store remembers
 * what a record hashed to at capture. An attacker with store-write access can
 * rewrite record N's payload, RECOMPUTE `canonicalDigest`, and REPAIR N's own
 * `chainLink` to `H(digest(N-1) ‖ digest'(N))`. N then hashes to its stored
 * digest and N's own link is consistent; the single surviving trace is
 * N+1's link, which still names the OLD digest(N) — and one inconsistent link
 * is precisely the signature of an honestly corrupted link, the case
 * `relink()` exists to repair. Without the log, `relink()` would repair it,
 * return `chainVerified: true`, and append operator-signed `relinked` custody
 * entries vouching for the laundered record.
 *
 * The log closes that gap by remembering the capture digest. A record whose
 * current `canonicalDigest` differs from its `revisionNo: 0` row was
 * rewritten after capture — REGARDLESS of how consistent its links now look —
 * and both `verifyChainCompleteness()` (as `digestSuperseded`) and `relink()`
 * (as a refusal) say so.
 *
 * APPEND-ONLY, ENFORCED. Postgres and SQLite refuse UPDATE and DELETE on the
 * table with a trigger, exactly as `custody_entries` does, and SQLite also
 * refuses an insert over an existing row, which is how `INSERT OR REPLACE`
 * would reseat a revision; the memory adapter exposes no path to any of
 * them. The rewrite itself is refused too: both SQL adapters freeze a stored
 * record's payload and `canonicalDigest` with a trigger on `envelopes`. On
 * SQLite, whose REPLACE conflict resolution deletes a row without firing a
 * DELETE trigger, `envelopes` also refuses an insert over an existing record
 * and any change to a record's rowid, so neither INSERT OR REPLACE nor
 * UPDATE OR REPLACE can delete a record to write it again. So laundering a
 * record is not a row edit: it takes stepping around a trigger, by dropping
 * it or, on Postgres, under `session_replication_role = 'replica'`. What the
 * log adds is that a rewrite made that way still disagrees with revision 0
 * unless the log's own triggers are stepped around as well. A table owner can
 * do both, and a SQLite database is a file: the log does not make the store
 * un-editable.
 */
export interface EnvelopeRevision {
  /** The record this revision belongs to. */
  evidenceId: string;
  /** 0 for the capture revision; 1, 2, … for each later legitimate write. */
  revisionNo: number;
  /** `integrity.canonicalDigest` as it stood after this write. */
  canonicalDigest: string;
  /** `integrity.chainLink` as it stood after this write. */
  chainLink: string | null;
  /** ISO 8601 timestamp the row was written. */
  recordedAt: string;
  /** Which legitimate operation wrote it. */
  cause: RevisionCause;
  /**
   * Who it is attributable to: the capturing actor for `capture`, the
   * `relinkedBy` operator for `relink`, and the subsystem id for an
   * unattended write (`tzun-attestation`, `tzun-recovery`).
   */
  actor: string;
}

/**
 * Abstract storage adapter interface.
 *
 * All adapters (in-memory, SQLite, PostgreSQL) implement this interface.
 * Methods return Promises for async compatibility even when the underlying
 * storage is synchronous.
 */
export interface StorageAdapter {
  /**
   * Store an evidence envelope. Append-only — no updates allowed.
   * When chainId is not provided, uses 'default'.
   *
   * On the SDK's local adapters (memory, SQLite, Postgres) the record also
   * gets its leaf in its chain's evidence log (Tree §5.2), written in
   * the same transaction: leaf `sequenceNumber − 1`, the record's
   * `canonicalDigest`. The log is dense and written once. A record whose
   * position already has a leaf keeps the leaf that was logged first and is
   * stored as usual. A record the log cannot take is refused, and nothing of
   * it is written: its chain id is empty or is not a string of Unicode scalar
   * values other than U+0000, its `sequenceNumber` is not a positive integer,
   * its digest is not 64 lowercase hex, the leaf before its position is
   * missing, or its evidence id or digest is already a leaf of the log at
   * another position. So a chain is written in sequence order, whether or not
   * `expectChainHead` is given.
   *
   * @param envelope - The evidence envelope to store.
   * @param chainId - The chain this record belongs to.
   * @param options - Per-store options (e.g. idempotencyKey for the HTTP transport).
   * @throws If an envelope with the same evidenceId already exists.
   * @throws `EvidenceLogRefusalError` (`code: 'evidence_log_refused'`, from the
   *   SDK's src/storage/log-store.ts) when the evidence log refuses the record.
   */
  store(envelope: EvidenceEnvelope, chainId?: string, options?: StoreOptions): Promise<void>;

  /**
   * `store()` under an idempotency key: claim the key or
   * return what already holds it, atomically with the write.
   *
   * The key is looked up first, inside the same transaction (or synchronous
   * section) as the write. If it is taken, nothing is stored and the outcome
   * is `replay` (same fingerprint) or `conflict` (different fingerprint) —
   * whatever the chain head is now, so a retry replays even after other
   * records were appended or the chain was sealed. If it is free, the record
   * is stored exactly as `store()` would store it — every `store()` check
   * applies, `expectChainHead` included — and the key is recorded with it in
   * the same transaction. A `store()` refusal therefore throws and leaves the
   * key unclaimed, so a failed capture never consumes its key (as on the
   * hosted service). Two concurrent calls with one key store one record:
   * one is `claimed`, the other `replay` (or `conflict`).
   *
   * Keys are kept for the life of the store, as the platform keeps them: there
   * is no expiry.
   *
   * Optional: an adapter without it (the HTTP adapter, which sends the key as
   * `Idempotency-Key` and lets the server decide) is called through `store()`.
   */
  storeIdempotent?(
    envelope: EvidenceEnvelope,
    chainId: string | undefined,
    options: IdempotentStoreOptions,
  ): Promise<IdempotencyOutcome>;

  /**
   * Retrieve an evidence envelope by its evidenceId.
   * @returns The envelope, or null if not found.
   */
  retrieve(evidenceId: string): Promise<EvidenceEnvelope | null>;

  /**
   * List evidence envelopes with optional filtering and pagination.
   *
   * Ordered by the UTC instant of `payload.capturedAt` at millisecond
   * precision, then `sequenceNumber`, then `evidenceId` — a total order that
   * is identical on every adapter (see `ListOptions.order`). `limit` and
   * `offset` are applied after ordering and must be non-negative safe
   * integers; anything else throws `InvalidPaginationError` on every adapter.
   */
  list(options?: ListOptions): Promise<EvidenceEnvelope[]>;

  /**
   * Store a failure record. Append-only.
   */
  storeFailure(failure: FailureRecord): Promise<void>;

  /**
   * The canonical digest of the last record appended to `chainId`.
   *
   * Per chain: every chain in one store has its own head, so
   * two writers on two chains do not read or advance each other's. The
   * parameter is optional, and omitting it names `'default'` — the chain
   * `store()` writes to when no chain is named — exactly as it does for
   * `getChainLength()` and `resetChainState()` beside it.
   *
   * Used to restore chain state on startup and to link the next append.
   * @param chainId - The chain to read (default: `'default'`).
   * @returns The last digest, or null if that chain holds no records.
   */
  getLastDigest(chainId?: string): Promise<string | null>;

  /**
   * The highest sequence number `chainId` has reached.
   *
   * Per chain, and a HIGH-WATER MARK rather than a count: it
   * does not fall when a record is deleted, which is the only thing that makes
   * a deleted tail — or a chain whose every record is gone — detectable. It is
   * reset for one chain, deliberately, by `resetChainState(chainId)` after a
   * fork restarts that chain at sequence 1.
   *
   * @param chainId - The chain to read (default: `'default'`).
   * @returns The last sequence number, or 0 if that chain holds no records.
   */
  getLastSequence(chainId?: string): Promise<number>;

  /**
   * List evidence envelopes ordered by sequence number ascending.
   * Used by chain completeness verification to detect gaps and broken links.
   * @param fromSequence - Inclusive lower bound (default: 1).
   * @param toSequence - Inclusive upper bound (default: no upper bound).
   * @param chainId - Optional chain ID filter. When provided, only records belonging to this chain are returned.
   * @returns Envelopes sorted by sequenceNumber ascending.
   */
  listBySequence(fromSequence?: number, toSequence?: number, chainId?: string): Promise<EvidenceEnvelope[]>;

  /**
   * Update attestation artifacts and status on an existing envelope.
   *
   * This is the ONE permitted mutation — only nonRepudiation and attestationStatus
   * may change. The payload and integrity digest are never modified.
   *
   * FILL-ONLY, and atomic. A component already on the
   * record is KEPT: only components the record does not have yet (absent,
   * `null` or an empty string) are filled in, and an absent, `null` or empty
   * component from the caller fills nothing. The filling happens under the
   * same row lock (or synchronous section) as the read, so two schedulers on
   * one store cannot replace a token that has already landed — the second
   * one's token is dropped, not written over the first.
   *
   * `newStatus` is the status to store, or a function the adapter calls with
   * the envelope as it will be stored (the stored row with the fill applied),
   * under the same lock. The function form is the one to use when another
   * writer can fill a component between the caller's read and this update:
   * the anchor scheduler fills `anchor` while a pending-attestation retry
   * waits on its timestamp authority, and a status the retry computed from
   * its older copy would still count the anchor as missing. Either way a
   * record already `'complete'` stays `'complete'`, so a writer working from
   * an older view cannot walk a finished record backwards. An update that
   * fills nothing and changes no status writes nothing at all, and leaves no
   * revision row.
   *
   * @param evidenceId - The ID of the envelope to update.
   * @param artifacts - Attestation artifacts to fill in where the record has none.
   * @param newStatus - The status to store, or how to compute it from the envelope as it will be stored.
   * @throws If no envelope with the given evidenceId exists.
   */
  updateAttestation(
    evidenceId: string,
    artifacts: AttestationArtifacts,
    newStatus: EvidenceEnvelope['attestationStatus'] | AttestationStatusOf
  ): Promise<void>;

  /**
   * List evidence envelopes filtered by attestation status, OLDEST FIRST.
   *
   * `limit` bounds the read, and oldest-first order means
   * successive bounded reads walk a backlog rather than re-reading its head.
   * The order is the `list()` order ascending (src/storage/list-order.ts):
   * capture instant, then sequence number, then evidenceId — the same on
   * every adapter. The pending-attestation retry does not read this: it
   * reads {@link listByMissingObtainable}.
   *
   * @param status - The attestation status to filter by.
   * @param limit - At most this many envelopes; absent means all of them.
   * @throws {InvalidPaginationError} if `limit` is not a non-negative integer.
   * @returns Envelopes matching the given status, oldest first.
   */
  listByAttestationStatus(
    status: EvidenceEnvelope['attestationStatus'],
    limit?: number,
  ): Promise<EvidenceEnvelope[]>;

  /**
   * List the 'pending' records that have no artifact for at least one of
   * `components`, OLDEST FIRST: the records the pending-attestation retry can
   * help. This is the retry's work queue.
   *
   * It is keyed on the missing component, not on the status alone. A record
   * that holds its timestamp and waits for an anchor, which is published for
   * a batch of records and never obtained by the retry, is 'pending' too, but
   * it is not listed. However many of those there are, they never fill the
   * page ahead of a record whose timestamp the retry can obtain.
   *
   * A component is missing when its artifact is absent, `null` or an empty
   * string: the reading `missingAttestationComponents()` makes, and the
   * absence {@link updateAttestation} fills. `'timestamp'` is
   * `nonRepudiation.rfc3161Token`. The order is the `list()` order ascending,
   * as in {@link listByAttestationStatus}.
   *
   * @param components - Retry-obtainable components (`RetryObtainableComponent`).
   *   An empty list lists nothing.
   * @param limit - At most this many envelopes; absent means all of them.
   * @throws {TypeError} if a component is not retry-obtainable, `'anchor'`
   *   included.
   * @throws {InvalidPaginationError} if `limit` is not a non-negative integer.
   * @returns Matching envelopes, oldest first.
   */
  listByMissingObtainable(
    components: readonly RetryObtainableComponent[],
    limit?: number,
  ): Promise<EvidenceEnvelope[]>;

  /**
   * Store a tamper incident. Append-only — no updates allowed on stored fields.
   * @param incident - The tamper incident to store.
   * @throws If an incident with the same id already exists.
   */
  storeIncident(incident: TamperIncident): Promise<void>;

  /**
   * Retrieve a tamper incident by its id.
   * @returns The incident, or null if not found.
   */
  getIncident(id: string): Promise<TamperIncident | null>;

  /**
   * List tamper incidents with optional filtering by status and/or severity.
   * Ordered by `detectedAt` descending, ties by `id` descending, on every
   * adapter.
   */
  listIncidents(filter?: { status?: TamperIncidentStatus; severity?: string }): Promise<TamperIncident[]>;

  /**
   * Update the status of a tamper incident.
   *
   * When resolving, `resolvedAt` is stamped on the FIRST transition into
   * 'resolved' and kept on any later one; `resolvedBy` / `resolutionNotes` are
   * replaced only when supplied, so a metadata-less re-resolve (a retry, a
   * double-submit, a replayed message) preserves the recorded sign-off.
   * Transitioning away from 'resolved' leaves all three fields as they are.
   * Identical on every adapter.
   * @param id - The incident id to update.
   * @param status - The new status.
   * @param metadata - Optional resolution metadata (resolvedBy, resolutionNotes).
   * @throws If no incident with the given id exists.
   */
  updateIncidentStatus(
    id: string,
    status: TamperIncidentStatus,
    metadata?: { resolvedBy?: string; resolutionNotes?: string }
  ): Promise<void>;

  /**
   * Record that a scan observed this incident's finding again, at `observedAt`
   * — the ONLY field of a stored incident that a later pass may move, and the
   * one exception to `storeIncident`'s append-only rule. It says nothing about
   * the incident's lifecycle: status, resolution and every other field are left
   * exactly as the operator left them.
   *
   * `TamperDetector` calls this instead of raising a second incident for a
   * finding that already has one, whatever that incident's status. Without it
   * a resolved-but-still-present finding cannot be told from one that is gone
   * (see `TamperIncident.lastObservedAt`).
   *
   * `observedAt` is supplied by the caller rather than taken from the database
   * clock ON PURPOSE: it is compared against `ScanSummary.startedAt`, which the
   * scanner stamps from the process clock, and a comparison across two clocks
   * would be wrong by their skew.
   *
   * OPTIONAL on the interface. An adapter that does not implement it is
   * detected and skipped (the HTTP transport, which has no local store, and the
   * platform's chain-scoped view, which records observations in its own incident
   * writer). A finding is then still raised only once; it just cannot be told
   * apart from one that has gone away.
   *
   * @param id - The incident id to stamp.
   * @param observedAt - ISO-8601 instant the finding was observed.
   * @throws If no incident with the given id exists.
   */
  recordIncidentObservation?(id: string, observedAt: string): Promise<void>;

  /**
   * Get the chain ID associated with a stored evidence record.
   * @returns The chain ID, or null if the record does not exist.
   */
  getChainForRecord(evidenceId: string): Promise<string | null>;

  /**
   * Store a chain identity record.
   */
  storeChain(chain: ChainIdentity): Promise<void>;

  /**
   * Retrieve a chain identity by its chainId.
   * @returns The chain identity, or null if not found.
   */
  getChain(chainId: string): Promise<ChainIdentity | null>;

  /**
   * List all chain identities, ordered by `createdAt` ascending, ties by
   * `chainId`, on every adapter.
   */
  listChains(): Promise<ChainIdentity[]>;

  /**
   * Seal a chain — mark it as read-only, no new records can be appended.
   * @param chainId - The chain to seal.
   * @param sealedAt - ISO 8601 timestamp of the seal.
   */
  sealChain(chainId: string, sealedAt: string): Promise<void>;

  /**
   * The chain `Tzun.capture()` appends to.
   *
   * Contract (since 0.3.15) — one rule on every adapter, implemented
   * by the engine's `resolveActiveChainId(chains, recordChainIds)` over
   * `listChains()` and `listRecordChainIds()`. A chain accepts appends when
   * its identity row says `status: 'active'` OR when it holds records and has
   * no identity row at all (`'default'` before a fork materialises it, or any
   * id handed to `store()` — the sealed-chain guard only refuses a chain whose
   * row says sealed). Over that set:
   *   - exactly one such chain → that chain;
   *   - none, and no identity rows → `'default'` (nothing written yet);
   *   - none, but rows → throws `NoActiveChainError`
   *     (`code: 'no_active_chain'`; every chain is sealed);
   *   - more than one → throws `AmbiguousActiveChainError`
   *     (`code: 'ambiguous_active_chain'`).
   * Both errors carry the rows in `chains`; the ambiguous one also names the
   * implicit chains. The simpler rule "the newest active row, else
   * 'default'" would name the SEALED default chain on a store whose chains
   * had all been sealed, and on a store with records on the implicit default
   * chain plus one active row would pick the row — a silent decision about
   * where evidence lands, and a chain born with the other chain's next
   * sequence number.
   *
   * The cloud transport is the one adapter that does not run this rule: it
   * answers the constant `'default'` without reading anything, because the
   * server owns chain state and resolves it on its side — the SDK reads no
   * chain rows over HTTP.
   */
  getActiveChainId(): Promise<string>;

  /**
   * Every distinct chain id that at least one stored record belongs to,
   * sorted ascending, whether or not the chain has an identity row.
   *
   * A chain can hold records without ever having an identity row: `'default'`
   * is implicit until a fork materialises it, and `store(envelope, chainId)`
   * accepts any id. A whole-store verifier that enumerated `listChains()`
   * alone therefore skipped every record on such a chain the moment one
   * identity row existed, and an empty chain is vacuously valid, so the AND
   * over its results stayed `true` over a tampered record it never read
   *. This is the query that makes "every chain in the store"
   * mean every record in the store.
   */
  listRecordChainIds(): Promise<string[]>;

  /**
   * Store an annotation record. Append-only.
   */
  storeAnnotation(annotation: AnnotationRecord): Promise<void>;

  /**
   * Retrieve an annotation by ID.
   */
  getAnnotation(id: string): Promise<AnnotationRecord | null>;

  /**
   * List annotations for a given incident, ordered by `annotatedAt` ascending,
   * ties by `id`. (The ledger lists — annotations, relinks, forks — all order
   * by their own timestamp ascending then `id`, on every adapter.)
   */
  listAnnotations(incidentId: string): Promise<AnnotationRecord[]>;

  /**
   * List annotations that reference a specific evidence record, in the same
   * order as `listAnnotations`.
   */
  listAnnotationsForRecord(evidenceId: string): Promise<AnnotationRecord[]>;

  /**
   * Store a re-link record. Append-only.
   */
  storeRelink(relink: RelinkRecord): Promise<void>;

  /**
   * Retrieve a re-link record by ID.
   */
  getRelink(id: string): Promise<RelinkRecord | null>;

  /**
   * List re-link records for a given incident.
   */
  listRelinks(incidentId: string): Promise<RelinkRecord[]>;

  /**
   * Store a fork record. Append-only.
   */
  storeFork(fork: ForkRecord): Promise<void>;

  /**
   * Retrieve a fork record by ID.
   */
  getFork(id: string): Promise<ForkRecord | null>;

  /**
   * List fork records for a given incident.
   */
  listForks(incidentId: string): Promise<ForkRecord[]>;

  /**
   * List fork records involving a specific chain (as old or new chain).
   */
  listForksForChain(chainId: string): Promise<ForkRecord[]>;

  /**
   * Update the chain link on a stored envelope. Used by re-link recovery.
   * This is the one exception to the strict append-only policy for evidence records.
   * Only the integrity.chainLink field is modified; the payload and digest are immutable.
   * @param evidenceId - The evidence record to update.
   * @param newChainLink - The recomputed chain link value.
   */
  updateEnvelopeChainLink(evidenceId: string, newChainLink: string | null): Promise<void>;

  /**
   * Append an entry to the custody chain of a stored envelope.
   * Used by recovery operations to document 'reviewed', 'relinked', 'chain_forked' actions.
   *
   * This is a HASHED, CHAINED append, and the
   * adapter — not the caller — mints the hash: it reads the record's current
   * `integrity.canonicalDigest` and the previous `custody_entries` row for the
   * record, computes `entryHash` with the engine's `computeCustodyEntryHash`,
   * inserts the append-only row, and mirrors `{ ...entry, entryHash,
   * prevEntryHash }` into `envelope.custodyChain` — the row insert and the
   * envelope rewrite in ONE transaction. Any `entryHash` / `prevEntryHash`
   * the caller puts on `entry` is ignored and replaced.
   *
   * Written as plain JSON into `custodyChain` in a separate write from
   * everything else, an entry an insider deleted would leave a record that
   * presented as never repaired; the hashed row and the single transaction
   * are what make the deletion visible.
   *
   * @param evidenceId - The evidence record to update.
   * @param entry - The custody chain entry to append.
   * @param options - The recovery record the action belongs to.
   */
  appendCustodyEntry(evidenceId: string, entry: CustodyEntry, options?: CustodyAppendOptions): Promise<void>;

  /**
   * Apply a re-link as ONE transaction: every
   * `relink.modifiedLinks[i].newChainLink` written to its record's
   * `integrity.chainLink`, the `RelinkRecord` stored (append-only, duplicate
   * id refused exactly as `storeRelink`), and every custody entry in
   * `custodyEntries` appended and hashed exactly as `appendCustodyEntry`
   * does, with `recoveryId` = `relink.id` — all of it committed together or
   * none of it. SQLite: one `BEGIN IMMEDIATE`; Postgres: one client, one
   * transaction; memory: one synchronous critical section with no `await`.
   *
   * One transaction, because as separate writes (links, then the record,
   * then the entries) a crash — or an insider — between them would leave
   * rewritten links with no record and no custody entry saying who rewrote
   * them.
   */
  applyRelink(relink: RelinkRecord, custodyEntries: RelinkCustodyAppend[]): Promise<void>;

  /**
   * The `custody_entries` rows for one record, in insertion (`id`) order —
   * the writer-side ledger the mirrored `custodyChain` entries are checked
   * against. Empty for a record that has never been repaired or reviewed.
   */
  listCustodyEntries(evidenceId: string): Promise<StoredCustodyEntry[]>;

  /**
   * Every revision row for one record, in `revisionNo` order.
   * Empty only for a record captured by an SDK older than 0.3.16 — every
   * `store()` from 0.3.16 on writes revision 0.
   */
  listEnvelopeRevisions(evidenceId: string): Promise<EnvelopeRevision[]>;

  /**
   * The CAPTURE-revision (`revisionNo: 0`) digest of each named record, as an
   * `evidenceId -> digest` map.
   *
   * One indexed lookup per id, in one query — the check a verifier needs is
   * "is the current digest still the captured one", and doing it as an O(1)
   * probe per record is what lets `verifyChainCompleteness()` add
   * `digestSuperseded` without changing its complexity class.
   *
   * An id with no revision row is ABSENT from the result rather than mapped
   * to null. That is the compatibility position: a record written before
   * 0.3.16 has no capture revision, and treating "no row" as "superseded"
   * would report every pre-existing record in a migrated store as tampered.
   * A caller must therefore read an absent id as "not provable either way",
   * never as "clean".
   */
  getCaptureDigests(evidenceIds: string[]): Promise<Record<string, string>>;

  /**
   * Retrieve envelopes by sequence number range (inclusive).
   * Used by re-link to walk the chain forward from a point.
   * @param fromSequence - Start of range (inclusive).
   * @param toSequence - End of range (inclusive).
   * @param chainId - Optional chain ID filter.
   */
  getBySequenceRange(fromSequence: number, toSequence: number, chainId?: string): Promise<EvidenceEnvelope[]>;

  /**
   * Get the total count of records in a chain.
   */
  getChainLength(chainId?: string): Promise<number>;

  /**
   * Reset one chain's state to empty (null digest, sequence 0).
   *
   * Called after a fork so that if the process restarts, the chain's restored
   * state is not the old chain's. Scoped to `chainId`: clearing a store-wide
   * row would make forking one chain destroy every other chain's high-water
   * mark, and with it the only thing that could report a deleted tail on
   * them.
   *
   * @param chainId - The chain to reset (default: `'default'`).
   */
  resetChainState(chainId?: string): Promise<void>;

  /**
   * Release any backend resources (connection pools, file handles, timers).
   *
   * Optional: in-memory adapters have nothing to close. Adapters that hold
   * external resources (Postgres pool, SQLite file handle) MUST implement
   * this so `Tzun.close()` can propagate cleanup; otherwise the resources
   * leak past the SDK lifecycle and the host process may hang on exit
   * waiting for unclosed connections.
   *
   * Idempotent: callers may invoke `close()` more than once safely.
   */
  close?(): Promise<void>;

  // ── Catalog (AI-BOM model descriptors) ───────────────────────────
  //
  // The catalog stores three logical tables identically across backends:
  // model_descriptors, model_descriptor_annotations, and
  // model_descriptor_aliases. Methods are optional on this interface so a
  // custom adapter can omit catalog support; every in-tree adapter
  // (memory / SQLite / Postgres) implements them.

  /**
   * Register a `ModelDescriptor`. Idempotent on identical canonical bytes:
   * the same descriptor produces the same digest and returns the existing
   * row (`alreadyExisted: true`).
   */
  registerModelDescriptor?(
    descriptor: ModelDescriptor,
    source: ModelDescriptorRow['source'],
    registeredBy: string,
  ): Promise<{ digest: string; alreadyExisted: boolean }>;

  /** Canonical view. Returns the row whose `canonicalBytes` are the exact bytes that were hashed. */
  getModelDescriptor?(digest: string): Promise<ModelDescriptorRow | null>;

  /** Enriched view: canonical descriptor with annotation history applied. */
  getEnrichedModelDescriptor?(digest: string): Promise<ModelDescriptor | null>;

  /** List descriptors with optional filters + pagination. */
  listModelDescriptors?(filter?: {
    vendor?: string;
    modelName?: string;
    modelVersion?: string;
    integrityTier?: 'weight-attested' | 'vendor-asserted';
    hasRegulatoryMarking?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<ModelDescriptorRow[]>;

  /** DAG descent: direct children whose `parentModelDescriptorDigest === parentDigest`. */
  listDescendantDescriptors?(parentDigest: string): Promise<ModelDescriptorRow[]>;

  /** Append an annotation. Append-only. */
  appendModelDescriptorAnnotation?(annotation: ModelDescriptorAnnotationRow): Promise<void>;

  /**
   * All annotations for a descriptor, ordered by `annotatedAt` ascending then
   * `annotationId` ascending (ordinal), identically on every adapter. Not
   * insertion order: that is not a property a SQL table has without an
   * explicit ordinal column.
   */
  listModelDescriptorAnnotations?(digest: string): Promise<ModelDescriptorAnnotationRow[]>;

  /**
   * Bind a slug → digest. Append-only; latest `setAt` wins on resolve. The
   * binding's key is `(slug, setAt)` at millisecond resolution, so a rebind in
   * the same millisecond REPLACES that instant's row — last writer wins — on
   * every adapter.
   */
  setModelDescriptorAlias?(slug: string, digest: string, setBy: string): Promise<void>;

  /** Resolve a slug to its current digest, or `null` if no binding exists. */
  resolveModelDescriptorAlias?(slug: string): Promise<string | null>;

  // ── Agent catalog (Record §6.9) ──────────────────────────────────
  //
  // Optional: an adapter without them is a store without the catalog, where
  // capture accepts agent references as given and store-level verification
  // reports them unresolved (`catalog_absent`).

  /** Register an agent descriptor. Idempotent on identical canonical bytes. */
  putAgentDescriptor?(
    descriptor: AgentDescriptor,
  ): Promise<{ digest: string; alreadyExisted: boolean }>;

  /** The row whose `canonicalBytes` are the exact bytes that were hashed, or `null`. */
  getAgentDescriptor?(digest: string): Promise<AgentDescriptorRow | null>;

  /** List descriptors by lookup column, a page at a time (`limit` at most 200). */
  listAgentDescriptors?(filter?: {
    name?: string;
    organization?: string;
    limit?: number;
    cursor?: string;
  }): Promise<{ rows: AgentDescriptorRow[]; cursor: string | null }>;

  // ── Mandates (Record §9.6) ───────────────────────────────────────

  /** The mandate record, or `null`. */
  getMandate?(mandateId: string): Promise<MandateRow | null>;

  /** The running total of each cap of a mandate. */
  getMandateTotals?(mandateId: string): Promise<Record<string, number>>;

  /** Every event of a mandate, oldest first. */
  listMandateEvents?(mandateId: string): Promise<MandateEventRow[]>;

  /** Move an open mandate past `notAfter` to `expired`, with its event, in one transaction (mandate row locked), guarded on `used` and the totals the event records. */
  expireMandate?(expiry: MandateExpireStore): Promise<void>;

  /**
   * A page of mandates in mandate id order (`limit` 1 to 200, 100 when
   * absent): those in `state`, and those whose `notAfter` is earlier than
   * `notAfterBefore` (a mandate with no end never matches). `cursor` is the
   * previous page's; it is `null` after the last page.
   */
  listMandates?(filter?: {
    state?: MandateState;
    notAfterBefore?: string;
    limit?: number;
    cursor?: string | null;
  }): Promise<{ rows: MandateRow[]; cursor: string | null }>;

  /**
   * Fill a mandated record's confirmation and append its custody entry in one
   * transaction under the record's row lock (Record §9.6). Fill-only: a
   * record that already holds a confirmation is left as it is and nothing is
   * appended, and `filled` is `false`. The fill leaves an `attestation_retry`
   * revision row, as `updateAttestation` does.
   *
   * @throws If no envelope with the given evidenceId exists.
   */
  confirmRecord?(
    evidenceId: string,
    confirmation: NonNullable<AttestationArtifacts['confirmation']>,
    custodyEntry: CustodyEntry,
  ): Promise<{ filled: boolean }>;

  // ── Decider openings (Record §6.3) and links ─────────────────────

  /** The opening of a record's `cmt:` decider, from `decider_openings`, or `null`. */
  getDeciderOpening?(evidenceId: string): Promise<DeciderOpening | null>;

  /**
   * The store's commitment-salt secret: at least 32 bytes, minted on first
   * read and kept for the life of the store. A `decider.commit: true` capture
   * under an idempotency key derives its salt from it (`deciderCommitmentSalt`).
   * A store without it refuses `commit: true` (`commitment_not_supported_by_store`).
   */
  getDeciderCommitmentSecret?(): Promise<Uint8Array>;

  /** The record whose stored canonical digest is `digest`, or `null`: resolves a link target. */
  retrieveByDigest?(digest: string): Promise<EvidenceEnvelope | null>;

  /** The records that link to `digest`, from the link index, a page at a time (`limit` at most 200, default 100). */
  listLinksTo?(
    digest: string,
    options?: { rels?: string[]; limit?: number; cursor?: string },
  ): Promise<{ rows: EvidenceLinkRow[]; cursor: string | null }>;

  /**
   * Return the most recently stored evidence envelope for the default chain,
   * or null if the store is empty. Equivalent to list({limit:1, order:'asc'})
   * in terms of result but optimised per-backend (e.g. Python head-of-chain).
   * Optional: all in-tree adapters implement it; custom adapters that omit it
   * may not be compatible with tests/demo code that calls it.
   */
  head?(): Promise<EvidenceEnvelope | null>;

  // ── Demo/test-only tamper hooks (since engine 0.2.0) ──────────────────────
  // DEMO/TEST ONLY: violates append-only invariant for tamper-simulation.
  // Inert unless the adapter is ARMED (TzunConfig.demoTamperHooks + the
  // same-store sentinel, or an empty store the adapter shows is loopback-local
  // — see src/storage/demo-tamper-guard.ts). NEVER exposed on the REST API,
  // CLI, or Tzun public methods.

  /**
   * Delete an evidence envelope by its ID, bypassing the append-only invariant.
   * Only available when the adapter has been armed via `TzunConfig.demoTamperHooks`.
   * @internal
   */
  deleteEnvelopeForDemo?(evidenceId: string): Promise<void>;

  /**
   * Overwrite a catalog row's stored `canonicalBytes` WITHOUT recomputing the
   * content-address; returns the previous bytes so the caller can restore.
   * Serves the demo's descriptor tamper: `descriptor_digest_mismatch`
   * fires exactly when `hashCanonicalBytes(row.canonicalBytes) !== digest`.
   * @internal
   */
  overwriteModelDescriptorBytesForDemo?(digest: string, canonicalBytes: string): Promise<string>;
}
