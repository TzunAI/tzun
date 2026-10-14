/**
 * Monitoring subsystem types for Tzun system hardening.
 *
 * Covers the full monitoring pipeline: tamper detection events, incident
 * tracking, scanner configuration and state, scan summaries, notification
 * channels, and top-level MonitoringConfig for Tzun.init().
 */

import type { CustodyLedgerFailure, CustodyRelinkFailure, CustodyTrailFailure, EvmFinality } from './verification';

// ---------------------------------------------------------------------------
// Primitive union types
// ---------------------------------------------------------------------------

/** All possible monitoring event type strings. */
export type MonitoringEventType =
  | 'digest_mismatch'
  | 'chain_break'
  | 'sequence_gap'
  | 'duplicate_sequence'
  | 'digest_superseded'
  | 'captured_at_regression'
  | 'custody_trail_invalid'
  | 'missing_record'
  | 'attestation_invalid'
  | 'attestation_unverifiable'
  | 'record_verified'
  | 'scan_completed'
  | 'chain_relinked'
  | 'chain_forked'
  | 'incident_annotated'
  // AI-BOM — descriptor catalog integrity failures.
  | 'descriptor_resolution_failure'
  | 'descriptor_digest_mismatch'
  | 'parent_descriptor_resolution_failure'
  | 'parent_descriptor_digest_mismatch'
  // Evidence logs and anchoring: the scanner's log and anchor checks.
  | 'digest_differs_from_logged_leaf'
  | 'log_rewritten_below_anchor'
  | 'log_truncated_below_anchor'
  | 'log_inconsistent_with_anchor'
  | 'split_view'
  | 'anchor_overdue'
  | 'anchor_wallet_nonce_unaccounted'
  | 'anchor_stripped'
  | 'anchor_transplanted'
  // Record rules and mandates.
  | 'record_rule_violated'
  | 'mandate_slot_duplicate'
  | 'mandate_slot_gap'
  | 'mandate_totals_unexplained'
  | 'freshness_reference_invalid';

/** Severity levels for tamper incidents. */
export type TamperSeverity = 'critical' | 'warning' | 'info';

/**
 * AI-BOM tamper-incident severity mapping.
 *
 * - `*_digest_mismatch` is `critical` — bytes don't hash to the claimed
 *   digest, which is unambiguous evidence of tampering.
 * - `*_resolution_failure` is `warning` — often benign (cross-environment
 *   export where the receiver hasn't seen the descriptor yet) but still
 *   reportable.
 */
export const AI_BOM_TAMPER_INCIDENT_SEVERITY: {
  descriptor_resolution_failure: TamperSeverity;
  descriptor_digest_mismatch: TamperSeverity;
  parent_descriptor_resolution_failure: TamperSeverity;
  parent_descriptor_digest_mismatch: TamperSeverity;
} = {
  descriptor_resolution_failure: 'warning',
  descriptor_digest_mismatch: 'critical',
  parent_descriptor_resolution_failure: 'warning',
  parent_descriptor_digest_mismatch: 'critical',
};

/**
 * Lifecycle status of a tamper incident — the state machine the hosted
 * service stores.
 *
 *   open         raised and not yet looked at.
 *   acknowledged a human has seen it.
 *   in_progress  a recovery action is under way on it. The hosted service
 *                moves an acknowledged incident here when a recovery starts;
 *                the SDK never writes it, but reads it back from a store the
 *                hosted service also writes, so the union names it to match
 *                the wire (the hosted service's adapter casts its rows to
 *                this type).
 *   resolved     closed, with resolution metadata.
 *
 * `open`, `acknowledged` and `in_progress` all mean "being handled": a finding
 * whose incident is in one of them is not raised again (`TamperDetector`).
 */
export type TamperIncidentStatus = 'open' | 'acknowledged' | 'in_progress' | 'resolved';

/** Operating mode for the integrity scanner. */
export type ScannerMode = 'continuous' | 'interval';

// ---------------------------------------------------------------------------
// MonitoringEvent — discriminated union
// ---------------------------------------------------------------------------

/** A stored digest does not match the recomputed digest for the same evidence record. */
export interface DigestMismatchEvent {
  type: 'digest_mismatch';
  evidenceId: string;
  /** Hex digest as stored in the database. */
  stored: string;
  /** Hex digest recomputed from the raw payload at scan time. */
  recomputed: string;
  /**
   * When the stored digest recomputes under an earlier hashed field set
   * (Record §4.1): which one. It explains the mismatch and never lowers
   * its severity: a store-write attacker can rewrite a record into an earlier
   * field set and recompute its digest.
   */
  fieldSet?: '0.7' | 'before-0.7';
}

/** The chain link for a record does not match the digest of the preceding record. */
export interface ChainBreakEvent {
  type: 'chain_break';
  evidenceId: string;
  sequenceNumber: number;
  /** The chain-link value expected based on the prior record's canonical digest. */
  expectedPrevDigest: string;
}

/** A monotonic sequence contains a jump — one or more sequence numbers are missing. */
export interface SequenceGapEvent {
  type: 'sequence_gap';
  expectedSequence: number;
  foundSequence: number;
}

/**
 * A record reuses (or goes backwards from) a sequence number already seen in
 * the same scan.
 *
 * Distinct from `sequence_gap`, which reports records that are ABSENT. A
 * duplicate means an EXTRA record exists at a position the chain already
 * occupies, which is the mid-chain-insertion shape: the forged record can be
 * linked to the honest record it shadows, so every existing canonicalDigest,
 * RFC 3161 token and Merkle anchor stays valid while the chain silently gains
 * a decision nobody made.
 */
export interface DuplicateSequenceEvent {
  type: 'duplicate_sequence';
  /** The record carrying the reused/backwards sequence number. */
  evidenceId: string;
  /** The offending sequence number. */
  sequenceNumber: number;
  /** The sequence number of the record that preceded it in store order. */
  previousSequence: number;
}

/**
 * A record's current `canonicalDigest` is not the digest it was CAPTURED with:
 * its payload was rewritten after capture and the digest recomputed to match
 * (`verifyChainCompleteness().digestSuperseded`).
 *
 * Distinct from `digest_mismatch`, and the difference is the point. A mismatch
 * is a record that does not hash to the digest it carries. A superseded record
 * DOES — the attacker recomputed it and reseated the record's link — so every
 * check computed from the store's present state passes it. Only the capture
 * revision in the append-only revision log remembers the digest it had.
 */
export interface DigestSupersededEvent {
  type: 'digest_superseded';
  evidenceId: string;
  sequenceNumber: number;
  /** The digest recorded when the record was captured (revision 0). */
  capturedDigest: string;
  /** The digest the record carries now, and hashes to. */
  currentDigest: string;
}

/**
 * A record's `capturedAt` predates the record before it in the chain
 * (`verifyChainCompleteness().timeRegressions`).
 *
 * Suspicious, not proof: an NTP correction produces one honestly. Reported so
 * that an operator looks at it once — backdating is the direction with legal
 * value, and no RFC 3161 token can contradict it — but it is not a tamper
 * finding and does not make a pass unclean.
 */
export interface CapturedAtRegressionEvent {
  type: 'captured_at_regression';
  evidenceId: string;
  sequenceNumber: number;
  /** The record's own `capturedAt`. */
  capturedAt: string;
}

/**
 * A record's custody trail — the hashed, chained entries recording who
 * relinked, forked or reviewed it — failed verification.
 *
 * `custodyChain` sits outside the v1.0 hashed field set, so a rewritten,
 * reordered or deleted custody entry changes no digest and breaks no chain
 * link; this is the only event that reports it. `failures` carries what the
 * envelope alone shows (`verifyCustodyTrail`: an entry that no longer
 * recomputes, a broken `prevEntryHash`, an unhashed entry after a hashed one)
 * and what only the store's `custody_entries` ledger shows (`verifyCustodyLedger`:
 * the deleted last entry, a row rewritten, a relink record altered after the
 * relink).
 */
export interface CustodyTrailInvalidEvent {
  type: 'custody_trail_invalid';
  evidenceId: string;
  failures: Array<CustodyTrailFailure | CustodyLedgerFailure | CustodyRelinkFailure>;
}

/** A specific sequence number is absent from the store entirely. */
export interface MissingRecordEvent {
  type: 'missing_record';
  sequenceNumber: number;
}

/** One or more attestation components failed verification for a given record. */
export interface AttestationInvalidEvent {
  type: 'attestation_invalid';
  evidenceId: string;
  /** Which attestation component failed. */
  component: 'timestamp' | 'signature' | 'anchor';
  /**
   * Why the component failed, when the checker knows.
   *
   * Optional and additive: `'missing'` is the presence case (the record claims
   * an attestation status it has no artifact for), and any other value comes
   * from the verifier — e.g. `'unparseable_token'` for a TSA response that was
   * stored on an HTTP 200 but is not a DER TimeStampResp, or
   * `'imprint_mismatch'` for a real token issued over some other record.
   * Without it an operator cannot tell an absent artifact from a forged one.
   */
  reason?: string;
  /**
   * `genTime - capturedAt` in milliseconds, set when the failure is the
   * record's `capturedAt` checked against the genTime of the token that
   * notarised it (`reason: 'captured_after_timestamp'`). Negative: the record
   * claims to have been captured after the TSA stamped it. The magnitude is
   * what separates a capturing clock that drifted ahead from one that was far
   * off.
   */
  capturedAtSkewMs?: number;
  /**
   * On the anchor component: what the header sources that took part in the
   * verdict counted as final (tzun-anchor/1 §10.4 item 14, the fact
   * `finality` of each EVM publication), `'finalized'` or a confirmation
   * depth, so an `anchor_not_found_on_chain` judged at 2 confirmations is not
   * read as one judged at the chain's finalized block. `null` when those
   * sources declare different modes. Absent when no source that took part
   * declares one, including when none took part (a proof that fails, say);
   * `ScanSummary.evmFinality` names a chain that declares none.
   */
  anchorFinality?: EvmFinality | null;
}

/**
 * An attestation artifact is PRESENT but this build cannot check it.
 *
 * Deliberately distinct from `attestation_invalid`, and the distinction is
 * operational rather than cosmetic. `attestation_invalid` says "I checked this
 * and it failed" — a statement about the record. This says "I could not check
 * this" — a statement about the verifier: the remedy is to upgrade the verifier
 * or re-attest, not to investigate a tampering.
 *
 * It is still an incident. Stored evidence nobody can verify is exactly what an
 * unattended scan exists to surface, so silence would be worse than either
 * label.
 */
export interface AttestationUnverifiableEvent {
  type: 'attestation_unverifiable';
  evidenceId: string;
  /** Which attestation component could not be checked. */
  component: 'timestamp' | 'signature' | 'anchor';
  /**
   * Why it could not be checked. Comes from the verifier's own reason union —
   * e.g. `'unsupported_publication_kind'` for an anchor whose publications are
   * all of a kind this build does not implement.
   *
   * Note what does NOT belong here:
   *   - an anchor under an `anchorSpec` or `merkleSpec` this build does not
   *     implement, or a `blockchainAnchor` (`unsupported_anchor_spec`,
   *     `unsupported_merkle_spec`, `legacy_blockchain_anchor`). The scanner
   *     raises those as `attestation_invalid` (tzun-anchor/1 §10.10): a record
   *     whose whole anchor has become unverifiable is a finding;
   *   - `'publication_not_checked'`, also an abstention, but the normal state
   *     of an anchor whose publications the scanner has no header source or
   *     trust roots to check, so emitting it would be permanent noise rather
   *     than a finding.
   */
  reason?: string;
}

/** A record passed all integrity checks during a scan pass. */
export interface RecordVerifiedEvent {
  type: 'record_verified';
  evidenceId: string;
}

/**
 * How many of the records a scan pass checked CARRY each attestation
 * artifact — an RFC 3161 token, a WebAuthn assertion signature, an anchor
 * (`nonRepudiation.anchor`, or a `blockchainAnchor` the verifier abstains
 * on). Presence, not validity: a record counts whether or not its artifact
 * verified, so a placeholder string or a captive-portal page stored on an
 * HTTP 200 counts here. Served as `lastFullScan.attestationPresence`; it is
 * NOT what `attestationCoverage` is derived from — that is
 * `AttestationValidityCounts`.
 */
export interface AttestationPresenceCounts {
  timestamp: number;
  signature: number;
  anchor: number;
}

/**
 * How many of the records a scan pass checked carry an attestation artifact
 * the pass VERIFIED — parsed, bound to this record's digest, and, where the
 * scanner holds the trust anchor for it, cryptographically checked. This is
 * what `GET /v1/integrity/status` divides by `recordsChecked` to report
 * `attestationCoverage` (spec 7.2: "percentage with valid timestamps").
 *
 * `null` for a component this pass did not verify at all — every component
 * when `ScannerConfig.verifyAttestation` is off; `signature` unless the
 * scanner was constructed with both a `credentialStore` and an
 * `expectedChallengeFor` (without them the verifier reports a signature as
 * unchecked, never as valid); `anchor` unless the scanner was given a
 * publisher manifest and a chain for its header source (without them an EVM
 * publication is not checked, and the proofs alone confirm nothing was
 * published). `null` means "not measured", never "none
 * valid": a store of a hundred genuine tokens reports `timestamp: null` under
 * a scanner that does not verify, not `0`.
 *
 * Counted over the records the attestation check looks at — those claiming
 * `'complete'`, `'partial'` or `'pending'` — so a record whose status is
 * `'none'` never counts as valid, whatever it carries. A `'pending'` record's
 * artifacts count as they arrive.
 */
export interface AttestationValidityCounts {
  timestamp: number | null;
  signature: number | null;
  anchor: number | null;
}

/** Emitted when a full scan pass finishes. */
export interface ScanCompletedEvent {
  type: 'scan_completed';
  recordsChecked: number;
  /**
   * Total number of issues detected, across every check category except
   * `timeRegressions` and `anchorOverdue`, which are reported but do not make
   * a pass unclean.
   */
  issuesFound: number;
  /** Wall-clock duration of the pass in milliseconds. */
  durationMs: number;
  /** Count of records where recomputed digest did not match stored digest. */
  digestMismatches: number;
  /** Count of chain-link violations detected. */
  chainBreaks: number;
  /** Count of sequence number gaps detected. */
  sequenceGaps: number;
  /**
   * Count of duplicate / backwards sequence numbers detected.
   *
   * Optional so existing producers and stored events stay valid; the scanner
   * always sets it, and the count is also folded into `issuesFound`, which is
   * what decides whether a pass was clean.
   */
  duplicateSequences?: number;
  /**
   * Count of records rewritten after capture — see `DigestSupersededEvent`.
   * Folded into `issuesFound`: a superseded record makes the chain invalid.
   *
   * Optional so existing producers and stored events stay valid; the scanner
   * always sets it.
   */
  digestSuperseded?: number;
  /**
   * Count of records whose `capturedAt` predates the record before them — see
   * `CapturedAtRegressionEvent`. NOT folded into `issuesFound`: a regression
   * is suspicious rather than proof, and it is not part of chain validity.
   *
   * Optional so existing producers and stored events stay valid; the scanner
   * always sets it.
   */
  timeRegressions?: number;
  /**
   * Count of records whose custody trail failed verification — see
   * `CustodyTrailInvalidEvent`. Folded into `issuesFound`.
   *
   * Optional so existing producers and stored events stay valid; the scanner
   * always sets it.
   */
  custodyTrailInvalid?: number;
  /**
   * Count of `record_rule_violated` events: records whose digest holds and
   * that break a structure rule a conforming writer refuses. Folded into
   * `issuesFound`.
   *
   * Optional so existing producers and stored summaries stay valid; the
   * scanner always sets it.
   */
  recordRuleViolations?: number;
  /**
   * Count of mandate consumption findings (`mandate_slot_duplicate`,
   * `mandate_slot_gap`, `mandate_totals_unexplained`; Record §9.10)
   * on a store with the mandate tables. Folded into `issuesFound`.
   *
   * Optional so existing producers and stored summaries stay valid; the
   * scanner always sets it.
   */
  mandateFindings?: number;
  /**
   * Count of attestation components that failed the scanner's check.
   *
   * What "failed" covers depends on how the scanner was constructed — see
   * `ScannerConfig.verifyAttestation`. Every component is at minimum checked
   * for presence against the record's claimed `attestationStatus`; timestamps
   * are additionally parsed and required to be stamped over this record's
   * digest; signatures and anchors get full cryptographic verification only
   * when the scanner is given a credential store, and a publisher manifest
   * and header source, respectively.
   */
  attestationFailures: number;
  /**
   * Records whose attestation could not be CHECKED — see
   * `AttestationUnverifiableEvent`. Counted apart from `attestationFailures`
   * on purpose: rolling the two together makes a fleet of merely-unreadable
   * records indistinguishable from a fleet of failing ones.
   *
   * Optional so stored events from before this existed stay valid; the scanner
   * always sets it.
   */
  attestationUnverifiable?: number;
  /**
   * Findings about the store's evidence logs and anchoring: records
   * rewritten after they were logged, logs that no longer reproduce an
   * anchored checkpoint, logs truncated below one, logs whose anchored
   * checkpoints are inconsistent or split, unaccounted publisher nonces,
   * stripped anchors and anchors made for another leaf
   * (`anchor_transplanted`). One per event. Folded into `issuesFound`.
   *
   * Optional so existing producers and stored events stay valid; the scanner
   * always sets it.
   */
  logFindings?: number;
  /**
   * Chains whose oldest leaf has waited longer than T_max for its anchor —
   * see `AnchorOverdueEvent`. NOT folded into `issuesFound`: an anchoring
   * delay is not a finding about the evidence.
   *
   * Optional so existing producers and stored events stay valid; the scanner
   * always sets it.
   */
  anchorOverdue?: number;
  /**
   * Presence counts for the records this pass checked — see
   * `AttestationPresenceCounts`. Optional so existing producers and stored
   * events stay valid; the scanner always sets it.
   */
  attestationPresence?: AttestationPresenceCounts;
  /**
   * Verified-valid counts for the records this pass checked — see
   * `AttestationValidityCounts`; `null` per component the pass did not
   * verify. Optional so existing producers and stored events stay valid; the
   * scanner always sets it.
   */
  attestationValid?: AttestationValidityCounts;
  /**
   * What each EVM chain the scanner reads (`ScannerAnchoringDeps.evmChains`)
   * counts as final, by CAIP-2 chain (`eip155:1`): the finality it
   * declares (`EvmHeaderSource.finality`; `JsonRpcEvmChain` declares
   * `'finalized'`), or `null` for one that declares none. Every anchor
   * verdict of the pass, and every check that read the chain, was judged
   * under it, so `attestationValid.anchor` counts anchors final under these
   * modes, which with `acceptNonFinal` may not be final at all. `{}` when the
   * scanner reads no chain. Optional so existing producers and stored events
   * stay valid; the scanner always sets it.
   */
  evmFinality?: Record<string, EvmFinality | null>;
}

/** A broken chain segment has been re-linked under authorized remediation. */
export interface ChainRelinkedEvent {
  type: 'chain_relinked';
  incidentId: string;
  relinkId: string;
  fromSequence: number;
  toSequence: number;
  authorizedBy: string;
  modifiedCount: number;
  timestamp: string;
}

/** The chain has been forked into a new chain ID under authorized remediation. */
export interface ChainForkedEvent {
  type: 'chain_forked';
  incidentId: string;
  forkId: string;
  oldChainId: string;
  newChainId: string;
  forkPoint: number;
  authorizedBy: string;
  timestamp: string;
}

/** A tamper incident has been annotated (documented) under authorized remediation. */
export interface IncidentAnnotatedEvent {
  type: 'incident_annotated';
  incidentId: string;
  annotationId: string;
  authorizedBy: string;
  affectedRecords: string[];
  timestamp: string;
}

// ---------------------------------------------------------------------------
// AI-BOM — descriptor catalog integrity failures
// ---------------------------------------------------------------------------

/**
 * The `aiBom.modelDescriptorDigest` referenced by an evidence record could not
 * be resolved in the descriptor catalog. Often benign (cross-environment
 * export where the receiver hasn't seen the descriptor yet), but reportable.
 */
export interface DescriptorResolutionFailureEvent {
  type: 'descriptor_resolution_failure';
  /** Evidence record whose step `aiBom` references the missing descriptor. */
  evidenceId: string;
  /** Digest that could not be resolved. */
  modelDescriptorDigest: string;
  /** The contribution step whose bill of materials names the descriptor. */
  step?: number;
}

/**
 * The descriptor row was resolved, but its stored `canonicalBytes` do not
 * hash to the claimed `modelDescriptorDigest`. Unambiguous evidence of
 * tampering with the catalog.
 */
export interface DescriptorDigestMismatchEvent {
  type: 'descriptor_digest_mismatch';
  evidenceId: string;
  /** The contribution step whose bill of materials names the descriptor. */
  step?: number;
  /** Digest claimed by the evidence record / catalog primary key. */
  claimedDigest: string;
  /** Digest recomputed from the stored `canonicalBytes`. */
  recomputedDigest: string;
}

/**
 * An ancestor descriptor in the parent DAG could not be resolved. Also
 * raised when cycle detection short-circuits the walk.
 */
export interface ParentDescriptorResolutionFailureEvent {
  type: 'parent_descriptor_resolution_failure';
  /** Evidence record at the root of the lineage walk. */
  evidenceId: string;
  /** The contribution step whose model's lineage was walked. */
  step?: number;
  /** Ancestor digest that could not be resolved (or that closed the cycle). */
  modelDescriptorDigest: string;
  /** Optional diagnostic note (e.g. `cycle detected`). */
  note?: string;
}

/**
 * An ancestor descriptor's stored `canonicalBytes` do not hash to its claimed
 * digest. Tampering of catalog ancestor row.
 */
export interface ParentDescriptorDigestMismatchEvent {
  type: 'parent_descriptor_digest_mismatch';
  evidenceId: string;
  /** The contribution step whose model's lineage was walked. */
  step?: number;
  claimedDigest: string;
  recomputedDigest: string;
}

// ---------------------------------------------------------------------------
// Evidence logs and anchoring: the scanner's log and anchor checks
// ---------------------------------------------------------------------------

/**
 * A record's `canonicalDigest` is not the leaf its chain's evidence log holds
 * at its position. The leaf is written inside the transaction
 * that stored the record and the log is insert-only, so the record was
 * rewritten after it was logged: the runtime role's rewrite-and-reseat, or a
 * record deleted and stored again at its position.
 */
export interface DigestDiffersFromLoggedLeafEvent {
  type: 'digest_differs_from_logged_leaf';
  evidenceId: string;
  sequenceNumber: number;
  /** The record's evidence log. */
  origin: string;
  /** The digest the log holds for the position. */
  loggedDigest: string;
  /** The digest the record carries now. */
  currentDigest: string;
}

/** Why a log no longer reproduces what was anchored. */
export type LogRewriteReason =
  /** The log's leaves below the anchored size no longer rebuild the anchored root. */
  | 'leaves_do_not_rebuild_root'
  /** The store holds no checkpoint at a size it anchored or published. */
  | 'checkpoint_missing'
  /** The store's checkpoint at that size is not the body that was anchored: it hashes to another value. */
  | 'checkpoint_rewritten'
  /** The transaction the store names for a publication was not sent by a publisher of this store. */
  | 'publication_not_from_publisher'
  /** That transaction's nonce is not the one the store recorded for the publication. */
  | 'publication_nonce_mismatch'
  /** That transaction's calldata is not 32 bytes, so it carries no P. */
  | 'publication_calldata_not_p';

/**
 * Leaves `from <= leafIndex < to` of a log. For an evidence log, leaf `i` is
 * the record at sequence number `i + 1`.
 */
export interface LogLeafRange {
  from: number;
  to: number;
}

/**
 * A log no longer reproduces a checkpoint that was anchored:
 * its leaves below the anchored size have been rewritten, or the store's
 * record of what was anchored has.
 *
 * `authenticated` says where the anchored root came from. `true`: from a
 * published P, the calldata of a transaction read over RPC and sent by a
 * publisher the scanner's manifest lists, or a record's embedded checkpoint
 * included under such a P. That is the database owner's rewrite, and editing
 * `anchor_publications` does not hide it. `false`: from the store's own
 * checkpoint, because the scanner has no chain to read P from, or from a P
 * whose sender only the store's own wallet rows vouch for, because the
 * manifest lists no publisher for the store; the store contradicts itself.
 */
export interface LogRewrittenBelowAnchorEvent {
  type: 'log_rewritten_below_anchor';
  /** The log: an evidence log, or the store's anchor log. */
  origin: string;
  /** The chain, for an evidence log; `null` for the anchor log. */
  chainId: string | null;
  /** The anchored size the log no longer reproduces. */
  anchoredSize: number;
  reason: LogRewriteReason;
  authenticated: boolean;
  /**
   * The leaves the rewrite lies in: above the largest anchored size the log
   * still reproduces.
   */
  leafRange?: LogLeafRange;
  /**
   * The records named through their own embedded paths: each carries a
   * `nonRepudiation.anchor` whose `logPath` no longer places the leaf the log
   * holds at its position under its anchored checkpoint.
   */
  evidenceIds: string[];
  /** The publication whose transaction was read, for a reason about a publication. */
  publicationId?: number;
  /** That transaction. */
  transactionId?: string;
}

/**
 * A log is shorter than a size that was anchored, or an evidence log's chain
 * head (`chain_state.last_sequence`) is below it.
 */
export interface LogTruncatedBelowAnchorEvent {
  type: 'log_truncated_below_anchor';
  origin: string;
  /** The chain, for an evidence log; `null` for the anchor log. */
  chainId: string | null;
  /** The largest size anchored. */
  anchoredSize: number;
  /** One past the log's highest leaf now. */
  logSize: number;
  /** For an evidence log, the chain's `last_sequence`; `null` for the anchor log. */
  lastSequence: number | null;
}

/** Why the store's checkpoints of one log are not consistent with each other. */
export type LogInconsistencyReason =
  /** A stored consistency proof between two anchored checkpoints does not verify. */
  | 'consistency_proof_invalid'
  /** A checkpoint names a predecessor the store no longer holds. */
  | 'predecessor_missing'
  /** An anchored checkpoint is not proved consistent with the anchored checkpoint before it. */
  | 'proof_chain_broken'
  /** A checkpoint's body does not state its own log, size and root. */
  | 'checkpoint_body_mismatch';

/**
 * The store's anchored checkpoints of one log are not provably one growing
 * log. Found from the stored checkpoints and proofs alone.
 */
export interface LogInconsistentWithAnchorEvent {
  type: 'log_inconsistent_with_anchor';
  origin: string;
  /** The chain, for an evidence log; `null` for the anchor log. */
  chainId: string | null;
  /** The earlier checkpoint's size, when the finding is about a pair. */
  fromSize: number | null;
  /** The checkpoint the finding is about. */
  toSize: number;
  reason: LogInconsistencyReason;
}

/**
 * Two authenticated checkpoint bodies of one log state the same size with
 * different roots (tzun-anchor/1 §10.8): the domain published two
 * histories. A body is authenticated only by a published P, the calldata of a
 * publisher's transaction, directly or through an inclusion path under it.
 */
export interface SplitViewEvent {
  type: 'split_view';
  origin: string;
  /** The chain, for an evidence log; `null` for the anchor log. */
  chainId: string | null;
  size: number;
  /** The roots published for that size, hex, sorted. */
  roots: string[];
}

/**
 * Why a leaf has not been filled within T_max:
 *
 *   not_published     no publication covering it has been mined: no epoch has
 *                     taken it, or the epoch's transaction is not mined;
 *   finality_stalled  the covering publication is mined and its block is not
 *                     final;
 *   not_filled        the covering publication is final and its fill has not
 *                     finished.
 */
export type AnchorOverdueReason = 'not_published' | 'finality_stalled' | 'not_filled';

/**
 * A chain's oldest leaf without a filled anchor was logged more than T_max
 * (`maxStalenessMs`) ago.
 */
export interface AnchorOverdueEvent {
  type: 'anchor_overdue';
  origin: string;
  chainId: string;
  reason: AnchorOverdueReason;
  /** The oldest leaf without a filled anchor. */
  leafIndex: number;
  /** The record that leaf was logged for. */
  evidenceId: string;
  /** When the leaf was logged, ISO 8601. */
  loggedAt: string;
  maxStalenessMs: number;
}

/**
 * A nonce of a publisher wallet maps to nothing the store holds:
 * the chain counts a transaction from the wallet at that nonce, and it is
 * neither a stored publication whose anchor checkpoint hashes to its calldata
 * nor a stored accounted transaction (`sweep`, `handover`) with its hash.
 * Someone else sends from the dedicated wallet, or the store lost the record
 * of a publication.
 */
export interface AnchorWalletNonceUnaccountedEvent {
  type: 'anchor_wallet_nonce_unaccounted';
  /** The wallet, `0x` and 40 lowercase hex. */
  address: string;
  /** CAIP-2. */
  chain: string;
  nonce: number;
  /**
   * The first nonce accounted: the scanner's floor for a wallet its manifest
   * lists (default 0), else the wallet's stored enrolment `nonce_base`.
   */
  nonceBase: number;
  /** The epoch whose stored publication holds the nonce, when one does: its transaction is not the one the chain counted. */
  epochId: number | null;
  publicationId: number | null;
}

/**
 * A record carries no `nonRepudiation.anchor` although its position lies in
 * an epoch whose fill the store has finished. The fill writes
 * each record once and never revisits a finished range, so the anchor was
 * removed.
 */
export interface AnchorStrippedEvent {
  type: 'anchor_stripped';
  evidenceId: string;
  sequenceNumber: number;
  /** The record's evidence log. */
  origin: string;
}

/**
 * A record carries a `tzun-anchor/1` artifact made for another leaf than its
 * own: the artifact's log checkpoint names another log than the record's
 * evidence log, or its `leafIndex` is not the record's leaf. The fill writes
 * each record the artifact of its own leaf, so this one was copied from
 * another record. The verifier cannot tie an evidence log with an opaque
 * origin to a chain, so on such a store this is the check that ties a
 * record's anchor to its chain.
 */
export interface AnchorTransplantedEvent {
  type: 'anchor_transplanted';
  evidenceId: string;
  sequenceNumber: number;
  /** The record's evidence log. */
  origin: string;
  /** The log the artifact's log checkpoint names. */
  artifactOrigin: string;
  /** The leaf the artifact names. The record's own leaf is `sequenceNumber - 1`. */
  artifactLeafIndex: number;
}

// ---------------------------------------------------------------------------
// Record rules and mandates
// ---------------------------------------------------------------------------

/**
 * A record whose digest holds breaks a structure rule a conforming writer
 * would have refused: a malformed decider, contributions or links
 * member, a link target that no longer agrees with its link, or a payload
 * member outside the format's twelve names (`rule: 'payload.members'`). Its
 * bytes are as captured, so this is not tampering. A flawed process
 * (`contributions.binding`) never raises it: capture accepts one on purpose.
 */
export interface RecordRuleViolatedEvent {
  type: 'record_rule_violated';
  evidenceId: string;
  /** The row or rule: `decider`, `contributions`, `links`, `links.target`, `payload.members`, ... */
  rule: string;
  /** The row's reason (`malformed_links`, `link_target_mismatch`, ...). */
  reason: string;
}

/** Two or more records under one mandate hold the same slot (Record §9.10). */
export interface MandateSlotDuplicateEvent {
  type: 'mandate_slot_duplicate';
  /** The mandate document's digest, 64 lowercase hex. */
  mandateDigest: string;
  slot: number;
  evidenceIds: string[];
}

/** Slots `from` to `to` of a mandate are held by no record (Record §9.10). */
export interface MandateSlotGapEvent {
  type: 'mandate_slot_gap';
  mandateDigest: string;
  from: number;
  to: number;
  /** The amount each cap's running total moved across the gap that no held record explains. */
  unexplained: Record<string, number>;
}

/**
 * Consecutive running totals of a mandate do not step by the later record's
 * own value (Record §9.10).
 */
export interface MandateTotalsUnexplainedEvent {
  type: 'mandate_totals_unexplained';
  mandateDigest: string;
  slot: number;
  cap: string;
  expected: number;
  actual: number;
}

/**
 * A record's `decider.freshness` names a block that is not the canonical
 * block at that height on the store's anchoring chain (Record §6.6): a
 * planted `anchor_freshness` row, caught by the scheduler's epoch re-check.
 */
export interface FreshnessReferenceInvalidEvent {
  type: 'freshness_reference_invalid';
  evidenceId: string;
  /** The reference the record carries. */
  reference: string;
}

/**
 * Discriminated union of all monitoring events emitted by the scanner and
 * integrity-check pipeline.
 */
export type MonitoringEvent =
  | DigestMismatchEvent
  | ChainBreakEvent
  | SequenceGapEvent
  | DuplicateSequenceEvent
  | DigestSupersededEvent
  | CapturedAtRegressionEvent
  | CustodyTrailInvalidEvent
  | MissingRecordEvent
  | AttestationInvalidEvent
  | AttestationUnverifiableEvent
  | RecordVerifiedEvent
  | ScanCompletedEvent
  | ChainRelinkedEvent
  | ChainForkedEvent
  | IncidentAnnotatedEvent
  | DescriptorResolutionFailureEvent
  | DescriptorDigestMismatchEvent
  | ParentDescriptorResolutionFailureEvent
  | ParentDescriptorDigestMismatchEvent
  | DigestDiffersFromLoggedLeafEvent
  | LogRewrittenBelowAnchorEvent
  | LogTruncatedBelowAnchorEvent
  | LogInconsistentWithAnchorEvent
  | SplitViewEvent
  | AnchorOverdueEvent
  | AnchorWalletNonceUnaccountedEvent
  | AnchorStrippedEvent
  | AnchorTransplantedEvent
  | RecordRuleViolatedEvent
  | MandateSlotDuplicateEvent
  | MandateSlotGapEvent
  | MandateTotalsUnexplainedEvent
  | FreshnessReferenceInvalidEvent;

// ---------------------------------------------------------------------------
// TamperIncident
// ---------------------------------------------------------------------------

/**
 * A persisted incident record raised when the scanner detects one or more
 * integrity violations.
 */
export interface TamperIncident {
  /** Unique incident identifier (UUID). */
  id: string;
  /** ISO-8601 timestamp when the incident was first detected. */
  detectedAt: string;
  /** Severity classification. */
  severity: TamperSeverity;
  /** The primary monitoring event type that triggered this incident. */
  type: MonitoringEventType;
  /** IDs of affected evidence records (may be empty for sequence/gap events). */
  affectedRecords: string[];
  /** Inclusive range of affected sequence numbers, if applicable. */
  affectedSequenceRange?: { from: number; to: number };
  /** Human-readable description and raw event data. */
  details: string;
  /** Current lifecycle status. */
  status: TamperIncidentStatus;
  /**
   * ISO-8601 timestamp when a scan last OBSERVED this incident's finding —
   * stamped when the incident is raised, and again by every later pass that
   * sees the same finding (`TamperDetector`, which raises a finding once and
   * records the re-observation thereafter).
   *
   * A hashed record can never be repaired in place, so `status: 'resolved'` on
   * a tamper finding means a human reviewed it, not that it is gone. Compared
   * against the start of the last completed pass (`ScanSummary.startedAt`),
   * this is what tells a reviewed finding that is STILL THERE — which holds the
   * store at 'degraded' — from one a later pass no longer sees, which lets it
   * reach 'healthy'. Mirrors `incidents.last_observed_at` in the hosted
   * service's store.
   *
   * Optional: an incident raised before this field existed has none, and is
   * counted in neither direction.
   */
  lastObservedAt?: string;
  /** ISO-8601 timestamp when the incident was resolved, if applicable. */
  resolvedAt?: string;
  /** Identity of the operator who resolved the incident. */
  resolvedBy?: string;
  /** Free-text notes describing the resolution action taken. */
  resolutionNotes?: string;
}

// ---------------------------------------------------------------------------
// ScannerConfig
// ---------------------------------------------------------------------------

/** Configuration for the integrity scanner. */
export interface ScannerConfig {
  /** Number of records processed per database batch. */
  batchSize: number;
  /** Number of parallel worker coroutines for scan passes. */
  workers: number;
  /** Whether to run continuously or on a timed interval. */
  mode: ScannerMode;
  /**
   * Milliseconds between scan passes when mode is 'interval'. `0` (or absent)
   * means the scanner has no schedule: passes run only when the caller asks,
   * through `Tzun.runScan()`. Ignored in 'continuous' mode.
   */
  intervalMs?: number;
  /**
   * Whether `Tzun.init()` starts the scan loop itself. Default: `true` when the
   * config names a schedule — `mode: 'continuous'`, or `mode: 'interval'` with
   * `intervalMs > 0`. Has no effect without a schedule.
   *
   * Set `false` to keep a scheduled config manual — for example when many
   * processes share one store and a single designated worker should scan it,
   * rather than every instance scanning the same records.
   */
  autoStart?: boolean;
  /**
   * Whether the scanner checks attestation artifacts (timestamp, signature,
   * anchor) on records claiming `complete`, `partial` or `pending`
   * attestation.
   *
   * What each component actually gets, when this is on:
   *
   * - **timestamp** — the stored `rfc3161Token` is parsed as a DER
   *   TimeStampResp and its TSTInfo messageImprint must equal the record's
   *   canonical digest. This is TSA-agnostic and is what catches the case an
   *   emptiness check cannot: a captive-portal or CDN HTML page stored as a
   *   token because the TSA answered HTTP 200, or a genuine token replayed
   *   from another record. Full trust-chain verification (chaining the TSA
   *   certificate to a pinned root) additionally runs only when the scanner is
   *   constructed with `attestation.timestampVerification: 'trust-chain'`; it
   *   is not the default because the bundled root is FreeTSA's and would
   *   report every other TSA's genuine tokens as invalid.
   * - **signature** — full WebAuthn verification (clientDataJSON, rpIdHash,
   *   User Present, and the signature itself) only when the scanner is
   *   constructed with a `credentialStore`. Without one, presence only: there
   *   is no public key to verify against.
   * - **anchor** — `verifyAnchor` (tzun-anchor/1 §10.3) with the record's
   *   sequence number and chain: the tags, both checkpoint bodies, the origin
   *   binding, the position and both inclusion proofs. A step that fails is a
   *   failure, and so is an artifact this build does not read
   *   (`unsupported_anchor_spec`, `unsupported_merkle_spec`,
   *   `legacy_blockchain_anchor`, tzun-anchor/1 §10.10). An EVM publication
   *   of P is checked end to end only when the scanner is constructed with a
   *   publisher manifest and a chain to use as the header source
   *   (`attestation.anchoring`); otherwise it stays not checked.
   *
   * The presence check always runs on top: a record claiming `complete` with a
   * component missing, or `partial` with all three missing, is a failure. A
   * `pending` record is still waiting for a component, so it has no presence
   * check: what it carries is verified, and what it lacks raises nothing.
   */
  verifyAttestation: boolean;
  /** Whether to verify monotonic sequence completeness across the full chain. */
  verifyChainCompleteness: boolean;
  /**
   * When true (default), the scheduled scanner verifies the referenced
   * `ModelDescriptor` for each envelope with `aiBom !== null`, including
   * the parent-DAG walk via the verifier's `walkLineage` option. Set
   * `false` to skip descriptor verification (e.g., to reduce scanner load
   * on large catalogs or when the receiver knowingly lacks the catalog).
   *
   * Renamed from `verifyDescriptors`: clean break, no alias — a stale
   * spelling fails typecheck by design.
   */
  scannerVerifyDescriptors?: boolean;
}

// ---------------------------------------------------------------------------
// ScannerState
// ---------------------------------------------------------------------------

/** Runtime state snapshot for a running scanner instance. */
export interface ScannerState {
  /** ISO-8601 timestamp when the current pass started. */
  currentPassStartedAt: string | null;
  /** ISO-8601 timestamp when the last pass completed successfully. */
  lastCompletedPassAt: string | null;
  /**
   * What the last pass that ran to completion measured, or `null` if no pass
   * has completed since this scanner was started. Set together with
   * `lastCompletedPassAt`; a pass that threw sets neither.
   *
   * This is what `GET /v1/integrity/status` reports as `lastFullScan`,
   * `lastFullScanDuration` and `attestationCoverage`, and what lets it say
   * `'unknown'` instead of `'healthy'` for a store nothing has scanned.
   */
  lastCompletedPass: ScanSummary | null;
  /** Total number of completed passes since the scanner was started. */
  totalPasses: number;
  /**
   * The highest sequence number successfully verified in any completed pass.
   * Used to resume interrupted scans efficiently.
   */
  highWaterMark: number;
  /** Sequence ranges currently being processed by in-flight worker segments. */
  segmentsInProgress: Array<{ from: number; to: number }>;
}

// ---------------------------------------------------------------------------
// ScanSummary
// ---------------------------------------------------------------------------

/** Summary record produced at the end of each completed scan pass. */
export interface ScanSummary {
  /** Monotonically increasing pass counter. */
  passNumber: number;
  /** ISO-8601 timestamp when this pass started. */
  startedAt: string;
  /** ISO-8601 timestamp when this pass completed. */
  completedAt: string;
  /** Wall-clock duration of the pass in milliseconds. */
  durationMs: number;
  /** Total number of evidence records checked in this pass. */
  recordsChecked: number;
  /**
   * Total number of issues detected, across every check category except
   * `timeRegressions` and `anchorOverdue`, which are reported but do not make
   * a pass unclean.
   */
  issuesFound: number;
  /** Count of records where recomputed digest did not match stored digest. */
  digestMismatches: number;
  /** Count of chain-link violations detected. */
  chainBreaks: number;
  /** Count of sequence number gaps detected. */
  sequenceGaps: number;
  /**
   * Count of duplicate / backwards sequence numbers detected.
   *
   * Optional so existing producers and stored events stay valid; the scanner
   * always sets it, and the count is also folded into `issuesFound`, which is
   * what decides whether a pass was clean.
   */
  duplicateSequences?: number;
  /**
   * Count of records rewritten after capture — see `DigestSupersededEvent`.
   * Folded into `issuesFound`: a superseded record makes the chain invalid.
   *
   * Optional so existing producers and stored summaries stay valid; the
   * scanner always sets it.
   */
  digestSuperseded?: number;
  /**
   * Count of records whose `capturedAt` predates the record before them — see
   * `CapturedAtRegressionEvent`. NOT folded into `issuesFound`: a regression
   * is suspicious rather than proof, and it is not part of chain validity.
   *
   * Optional so existing producers and stored summaries stay valid; the
   * scanner always sets it.
   */
  timeRegressions?: number;
  /**
   * Count of records whose custody trail failed verification — see
   * `CustodyTrailInvalidEvent`. Folded into `issuesFound`.
   *
   * Optional so existing producers and stored events stay valid; the scanner
   * always sets it.
   */
  custodyTrailInvalid?: number;
  /**
   * Count of `record_rule_violated` events: records whose digest holds and
   * that break a structure rule a conforming writer refuses. Folded into
   * `issuesFound`.
   *
   * Optional so existing producers and stored summaries stay valid; the
   * scanner always sets it.
   */
  recordRuleViolations?: number;
  /**
   * Count of mandate consumption findings (`mandate_slot_duplicate`,
   * `mandate_slot_gap`, `mandate_totals_unexplained`; Record §9.10)
   * on a store with the mandate tables. Folded into `issuesFound`.
   *
   * Optional so existing producers and stored summaries stay valid; the
   * scanner always sets it.
   */
  mandateFindings?: number;
  /**
   * Count of attestation components that failed the scanner's check.
   *
   * What "failed" covers depends on how the scanner was constructed — see
   * `ScannerConfig.verifyAttestation`. Every component is at minimum checked
   * for presence against the record's claimed `attestationStatus`; timestamps
   * are additionally parsed and required to be stamped over this record's
   * digest; signatures and anchors get full cryptographic verification only
   * when the scanner is given a credential store, and a publisher manifest
   * and header source, respectively.
   */
  attestationFailures: number;
  /**
   * Records whose attestation could not be CHECKED — see
   * `AttestationUnverifiableEvent`. Counted apart from `attestationFailures`
   * on purpose: rolling the two together makes a fleet of merely-unreadable
   * records indistinguishable from a fleet of failing ones.
   *
   * Optional so stored events from before this existed stay valid; the scanner
   * always sets it.
   */
  attestationUnverifiable?: number;
  /**
   * Findings about the store's evidence logs and anchoring: records
   * rewritten after they were logged, logs that no longer reproduce an
   * anchored checkpoint, logs truncated below one, logs whose anchored
   * checkpoints are inconsistent or split, unaccounted publisher nonces,
   * stripped anchors and anchors made for another leaf
   * (`anchor_transplanted`). One per event. Folded into `issuesFound`.
   *
   * Optional so existing producers and stored summaries stay valid; the scanner
   * always sets it.
   */
  logFindings?: number;
  /**
   * Chains whose oldest leaf has waited longer than T_max for its anchor —
   * see `AnchorOverdueEvent`. NOT folded into `issuesFound`: an anchoring
   * delay is not a finding about the evidence.
   *
   * Optional so existing producers and stored summaries stay valid; the scanner
   * always sets it.
   */
  anchorOverdue?: number;
  /**
   * Presence counts for the records this pass checked — see
   * `AttestationPresenceCounts`. Optional so existing producers and stored
   * summaries stay valid; the scanner always sets it.
   */
  attestationPresence?: AttestationPresenceCounts;
  /**
   * Verified-valid counts for the records this pass checked — see
   * `AttestationValidityCounts`; `null` per component the pass did not
   * verify. This, not presence, is what `attestationCoverage` is derived
   * from. Optional so existing producers and stored summaries stay valid;
   * the scanner always sets it.
   */
  attestationValid?: AttestationValidityCounts;
  /**
   * What each EVM chain the scanner reads (`ScannerAnchoringDeps.evmChains`)
   * counts as final, by CAIP-2 chain (`eip155:1`): the finality it
   * declares (`EvmHeaderSource.finality`; `JsonRpcEvmChain` declares
   * `'finalized'`), or `null` for one that declares none. Every anchor
   * verdict of the pass, and every check that read the chain, was judged
   * under it, so `attestationValid.anchor` counts anchors final under these
   * modes, which with `acceptNonFinal` may not be final at all. `{}` when the
   * scanner reads no chain. Optional so existing producers and stored summaries
   * stay valid; the scanner always sets it.
   */
  evmFinality?: Record<string, EvmFinality | null>;
}

// ---------------------------------------------------------------------------
// Notification channel configs
// ---------------------------------------------------------------------------

/** Configuration for webhook-based notifications. */
export interface WebhookNotificationConfig {
  /** HTTPS endpoint to POST incident payloads to. */
  url: string;
  /** Optional shared-secret value included as `X-Tzun-Signature` header. */
  secret?: string;
  /** Request timeout in milliseconds (default: 5000). */
  timeoutMs?: number;
}

/** Configuration for Slack incoming-webhook notifications. */
export interface SlackNotificationConfig {
  /** Slack incoming webhook URL. */
  webhookUrl: string;
  /** Override the display name used in Slack messages. */
  username?: string;
  /** Override the emoji icon used in Slack messages. */
  iconEmoji?: string;
  /** Request timeout in milliseconds (default: 5000). */
  timeoutMs?: number;
}

/** Configuration for PagerDuty Events API v2. */
export interface PagerDutyNotificationConfig {
  /** PagerDuty integration key (routing key). */
  integrationKey: string;
  /** Override the PagerDuty Events API endpoint (default: production). */
  apiUrl?: string;
  /** Request timeout in milliseconds (default: 5000). */
  timeoutMs?: number;
}

/** Configuration for email notifications via SMTP. */
export interface EmailNotificationConfig {
  /** SMTP host. */
  host: string;
  /** SMTP port (default: 587). */
  port?: number;
  /** Whether to use TLS (default: true). */
  secure?: boolean;
  /** SMTP auth credentials. */
  auth: { user: string; pass: string };
  /** Sender address shown in the From header. */
  from: string;
  /** One or more recipient addresses. */
  to: string[];
  /** Optional subject prefix (default: '[Tzun Alert]'). */
  subjectPrefix?: string;
}

/** Aggregated notification configuration for all supported channels. */
export interface NotificationConfig {
  webhook?: WebhookNotificationConfig;
  slack?: SlackNotificationConfig;
  pagerduty?: PagerDutyNotificationConfig;
  email?: EmailNotificationConfig;
}

/**
 * SDK-level notification configuration used in MonitoringConfig.
 * Extends each channel config with severity routing and retry options.
 */
export interface MonitoringNotificationConfig {
  webhook?: WebhookNotificationConfig & {
    severities: TamperSeverity[];
    retries?: number;
    retryDelayMs?: number;
  };
  slack?: SlackNotificationConfig & {
    severities: TamperSeverity[];
  };
  pagerduty?: PagerDutyNotificationConfig & {
    severities: TamperSeverity[];
  };
  email?: EmailNotificationConfig;
}

// ---------------------------------------------------------------------------
// NotificationChannel
// ---------------------------------------------------------------------------

/**
 * Interface that every notification channel adapter must implement.
 * Implementations are registered with the NotificationDispatcher.
 */
export interface NotificationChannel {
  /** Human-readable channel name used in logs and diagnostics. */
  name: string;
  /**
   * Deliver a notification for the given tamper incident.
   * Resolves when delivery is confirmed; rejects on failure.
   */
  send(incident: TamperIncident): Promise<void>;
  /**
   * Send a no-op test message to verify channel connectivity.
   * Resolves when the test succeeds; rejects on failure.
   */
  test(): Promise<void>;
}

// ---------------------------------------------------------------------------
// MonitoringConfig — top-level, added to TzunConfig
// ---------------------------------------------------------------------------

/**
 * Top-level monitoring configuration passed to Tzun.init() alongside
 * the existing TzunConfig.
 */
export interface MonitoringConfig {
  /** Whether the monitoring subsystem is active (default: false). */
  enabled: boolean;
  /** Scanner configuration. Defaults applied per ScannerConfig field docs. */
  scanner?: ScannerConfig;
  /** Notification channel configuration. */
  notifications?: MonitoringNotificationConfig;
}

// ---------------------------------------------------------------------------
// DeduplicationEntry
// ---------------------------------------------------------------------------

/**
 * Tracks incident deduplication state so repeated detections of the same
 * underlying problem do not flood notification channels.
 */
export interface DeduplicationEntry {
  /**
   * Stable key identifying the logical incident (e.g.
   * `digest_mismatch:<evidenceId>` or `sequence_gap:<expected>`).
   */
  key: string;
  /** ISO-8601 timestamp when this key was first observed. */
  firstSeenAt: string;
  /** Number of times this key has been observed (including the first). */
  count: number;
}

// ---------------------------------------------------------------------------
// Event handler callback type
// ---------------------------------------------------------------------------

/**
 * Callback signature for subscribing to monitoring events.
 * Handlers must not throw — errors should be caught internally.
 */
export type MonitoringEventHandler = (event: MonitoringEvent) => void;
