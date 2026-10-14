/**
 * Recovery types for the chain recovery subsystem.
 *
 * Three tiers of recovery:
 * - Tier 1: Annotation — document the issue, chain stays broken
 * - Tier 2: Re-link — recompute chain links forward over a range of one chain; no payload or digest is rewritten
 * - Tier 3: Fork — seal old chain, create new chain
 *
 * All operations require explicit human authorization.
 */

/** Record created when a tamper incident is annotated (Tier 1). */
export interface AnnotationRecord {
  /** Unique identifier for this annotation. */
  id: string;
  /** The tamper incident this annotation addresses. */
  incidentId: string;
  /** Evidence IDs of all affected records. */
  affectedRecords: string[];
  /** ISO 8601 timestamp when the annotation was created. */
  annotatedAt: string;
  /** Identity of the person who authorized the annotation. */
  annotatedBy: string;
  /** Human-written explanation of the issue and response. */
  notes: string;
  /** Map of evidenceId -> digest at time of annotation, for audit trail. */
  originalDigests: Record<string, string>;
}

/** A single modified chain link entry in a re-link operation. */
export interface ModifiedLink {
  /** Evidence ID of the affected record. */
  evidenceId: string;
  /** Sequence number of the affected record. */
  sequenceNumber: number;
  /**
   * Chain link value before re-linking, or `null` when the record genuinely
   * had no link (a genesis record, or one whose link had been nulled).
   *
   * `null`, never the four-character string `"null"`: that string is
   * indistinguishable from a record whose link literally was "null", and is
   * the one value an undo built on `modifiedLinks` would write back into
   * `integrity.chainLink` verbatim. A recovery record is itself evidence; it
   * has to state what it found honestly.
   */
  previousChainLink: string | null;
  /** Chain link value after re-linking, or `null` for a genesis record. */
  newChainLink: string | null;
}

/** Record created when chain links are recomputed (Tier 2). */
export interface RelinkRecord {
  /** Unique identifier for this re-link operation. */
  id: string;
  /** The tamper incident this re-link addresses. */
  incidentId: string;
  /** ISO 8601 timestamp when the re-link was performed. */
  relinkedAt: string;
  /** Identity of the person who authorized the re-link. */
  relinkedBy: string;
  /** First sequence number in the re-linked range. */
  fromSequence: number;
  /** Last sequence number in the re-linked range. */
  toSequence: number;
  /** Before/after state for every modified chain link. */
  modifiedLinks: ModifiedLink[];
}

/** Record created when a chain is forked (Tier 3). */
export interface ForkRecord {
  /** Unique identifier for this fork operation. */
  id: string;
  /** The tamper incident this fork addresses. */
  incidentId: string;
  /** ISO 8601 timestamp when the fork was performed. */
  forkedAt: string;
  /** Identity of the person who authorized the fork. */
  forkedBy: string;
  /** Mandatory explanation for why the fork was necessary. */
  reason: string;
  /** Chain ID of the sealed (old) chain. */
  oldChainId: string;
  /** Chain ID of the new chain. */
  newChainId: string;
  /** Last trusted sequence number in the old chain. */
  forkAfterSequence: number;
  /**
   * Number of records the sealed old chain held at seal time — a ROW COUNT.
   *
   * This is NOT the chain's highest sequence number: the two agree only while
   * the chain has no gaps, and a sealed chain is precisely the one that may
   * already have lost a record. It was used as the sealed chain's sequence
   * upper bound, which put the last record of any gapped sealed chain outside
   * every verifier's range. Kept for wire and database compatibility;
   * use `sealedOldChainHead` for anything that walks sequence numbers.
   */
  sealedOldChainLength: number;
  /**
   * Highest sequence number the sealed old chain reached, captured by `fork()`
   * before the live counter was reset for the new chain. This is the sealed
   * chain's inclusive sequence upper bound for `verifyChainCompleteness()`,
   * `relink()` and the scheduled scanner — the number that makes a deleted
   * TAIL on a sealed chain detectable.
   *
   * Absent only on fork records written by SDK versions before 0.3.14, whose
   * database rows carry NULL in this column; `chainUpperBound()` recomputes
   * a bound for those from the chain's surviving records.
   */
  sealedOldChainHead?: number;
}

/** Identity and lineage of an evidence chain. */
export interface ChainIdentity {
  /** Unique identifier for this chain. */
  chainId: string;
  /** Chain ID of the parent chain (if this chain was created by a fork). */
  parentChainId?: string;
  /** Sequence number in the parent chain where the fork occurred. */
  forkPoint?: number;
  /** Whether this chain is active (accepts new records) or sealed (read-only). */
  status: 'active' | 'sealed';
  /** ISO 8601 timestamp when this chain was created. */
  createdAt: string;
  /** ISO 8601 timestamp when this chain was sealed (only if status is 'sealed'). */
  sealedAt?: string;
}

/** Options for an annotation operation. */
export interface AnnotateOptions {
  /** Identity of the person authorizing the annotation. */
  authorizedBy: string;
  /** Human-written explanation of the issue and response. */
  notes: string;
  /**
   * Chain the incident is about.
   *
   * Only consulted for a sequence-shaped incident (sequence_gap,
   * missing_record) — one that names a range of sequence numbers and no
   * evidence ids. Sequence numbers restart at 1 per chain, so on a store that
   * has forked the range alone does not identify records, and annotate()
   * refuses rather than resolving it against whichever chain happens to be
   * active: the wrong answer appends a 'reviewed' custody entry, part of the
   * evidence envelope, to records the incident was never about.
   */
  chainId?: string;
}

/** Options for a re-link operation. */
export interface RelinkOptions {
  /** Identity of the person authorizing the re-link. */
  authorizedBy: string;
  /**
   * Corrected payload for the tampered record.
   *
   * NOT IMPLEMENTED: `RecoveryManager.relink()` raises when it is supplied.
   * `relink()` recomputes chain links and never rewrites a payload, so
   * accepting this option would discard the genuine text an operator supplied
   * while the tampered record was re-linked into the chain and reported as
   * repaired.
   *
   * The append-only revision log is what makes a rewritten payload
   * DETECTABLE, and implementing this option would mean the SDK itself
   * rewriting a payload and re-hashing it, which is the one thing revision 0
   * asserts never happens. Restoring a corrected payload is a new record plus
   * an annotation, or a fork; it is not an edit.
   */
  correctedPayload?: Record<string, unknown>;
  /** First sequence number in the range to re-link. */
  fromSequence: number;
  /** Last sequence number in the range to re-link. Defaults to chain head. */
  toSequence?: number;
  /**
   * Chain to re-link. Defaults to the active chain.
   *
   * Sequence numbers restart at 1 per chain, so an unscoped range mixes
   * same-numbered records from different chains: after a fork, a relink meant
   * for the active chain rewrote links in the SEALED parent chain.
   */
  chainId?: string;
}

/** Options for a fork operation. */
export interface ForkOptions {
  /** Identity of the person authorizing the fork. */
  authorizedBy: string;
  /** Mandatory explanation for why the fork is necessary. */
  reason: string;
  /** Last trusted sequence number in the old chain. New chain starts after this point. */
  forkAfterSequence: number;
}

/** Result of an annotation operation. */
export interface AnnotationResult {
  /** The created annotation record. */
  annotation: AnnotationRecord;
  /**
   * Status of the tamper incident as stored after the annotation. An open
   * incident is acknowledged; every other status is kept, so this is
   * 'in_progress' when an incident with a recovery under way is annotated and
   * 'resolved' when a resolved one is. A review never moves an incident
   * backwards, which is why 'open' is not among the answers.
   */
  updatedIncidentStatus: 'acknowledged' | 'in_progress' | 'resolved';
}

/** Result of a re-link operation. */
export interface RelinkResult {
  /** The created re-link record. */
  relink: RelinkRecord;
  /** Whether the chain verifies clean after re-linking. */
  chainVerified: boolean;
}

/** Result of a fork operation. */
export interface ForkResult {
  /** The created fork record. */
  fork: ForkRecord;
  /** Identity of the sealed old chain. */
  oldChain: ChainIdentity;
  /** Identity of the new active chain. */
  newChain: ChainIdentity;
}
