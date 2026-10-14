/** Failure type taxonomy — illustrative, not exhaustive. */
export type FailureType =
  | 'validation_failure'
  | 'schema_mismatch'
  | 'serialization_failure'
  | 'integrity_mismatch'
  | 'attestation_failure'
  /**
   * A capture input's step `aiBom` was pre-built, and its
   * `modelDescriptorDigest` is not present in the catalog. The capture is
   * rejected without raising; the failure record carries the offending
   * digest in `diagnosticMetadata.modelDescriptorDigest`.
   */
  | 'descriptor_not_registered'
  /**
   * A local-adapter conditional append was refused because the chain head
   * moved — another writer (a second SDK instance, a second replica on the
   * same database) appended between this capture reading the head and
   * storing — and `Tzun.capture()`'s bounded rebuild-and-retry
   * (`TzunConfig.chainConflictMaxAttempts`) did not get a turn in time.
   * `diagnosticMetadata` carries `code: 'chain_conflict'`, `retryable: true`,
   * `attempts`, and the `expectedHead` / `actualHead` of the final refusal.
   * Re-capturing the decision is the right response; nothing is wrong with
   * the store. It is its own type, not `serialization_failure`, so a moved
   * head is distinguishable from a payload the canonicalizer could not
   * serialise.
   */
  | 'chain_conflict'
  /**
   * A local store refused the record because its `evidenceId` already belongs
   * to a stored record. The local twin of `cloud_evidence_id_conflict`.
   * `diagnosticMetadata` carries `code: 'evidence_id_conflict'` and
   * `retryable: false`: the same record is refused every time.
   */
  | 'evidence_id_conflict'
  /**
   * A local store refused the append because the chain it was aimed at is
   * sealed (the read-only remainder of a fork). The platform refuses the same
   * append with the code `chain_sealed`. `diagnosticMetadata` carries
   * `code: 'chain_sealed'`, `retryable: false`, `chainId` and `sealedAt`.
   */
  | 'chain_sealed'
  /**
   * A keyed capture was refused because `CaptureOptions.idempotencyKey` already
   * names a record in the store and the input behind it is not this input (or
   * the record it names is gone). The platform refuses the same capture 422
   * `idempotency_conflict`. `diagnosticMetadata` carries
   * `code: 'idempotency_conflict'`, `retryable: false`, the `idempotencyKey`
   * and `conflictReason` (`fingerprint_mismatch` | `missing_replay_target`).
   * A key whose input DOES match is not a failure: the capture replays, and
   * `CaptureResult.replayed` says so.
   */
  | 'idempotency_conflict'
  /**
   * A local store refused the record because its chain's evidence log cannot
   * take it (Tree §5.2): the leaf before its position is missing
   * (`log_gap`: the chain lost records before its log existed, and forking it
   * continues on a new chain), its evidence id or digest is already a leaf of
   * the log (`duplicate_leaf`), or its chain id, sequence number or digest
   * names no position. `diagnosticMetadata` carries
   * `code: 'evidence_log_refused'`, `refusalReason`, `retryable: false`,
   * `chainId` and `sequenceNumber`.
   */
  | 'evidence_log_refused'
  /**
   * Cloud-transport failures: `cloud_` + the backend's stable wire error code
   * (`cloud_unauthenticated`, `cloud_chain_conflict`, `cloud_payload_too_large`,
   * `cloud_store_unavailable`, `cloud_transport_error`, …), never
   * `serialization_failure`, so a revoked API key is distinguishable from a
   * malformed payload. `diagnosticMetadata` carries
   * `code`, `status` and `retryable` alongside the server's own context
   * fields; branch on `retryable` to decide whether to re-submit.
   */
  | string;

/** A typed failure record. */
export interface FailureRecord {
  failureType: FailureType;
  evidenceId?: string;
  diagnosticMetadata: Record<string, unknown>;
  capturedAt: string;
}
