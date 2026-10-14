/**
 * The anchoring module's refusals and alarms.
 *
 * A refusal is thrown: the caller asked for something the configuration or
 * the rules do not allow. An alarm is reported: the scheduler found something
 * an operator must look at, and keeps running unless the alarm stops it.
 */

/** The configuration cannot be used. */
export class AnchoringConfigError extends Error {
  readonly code = 'anchoring_config_invalid' as const;

  constructor(message: string) {
    super(message);
    this.name = 'AnchoringConfigError';
    Object.setPrototypeOf(this, AnchoringConfigError.prototype);
  }
}

/**
 * The activation guard: the store would publish production
 * anchors, and `anchoring.production: true` is not set.
 */
export class AnchorActivationError extends Error {
  readonly code = 'anchor_production_not_enabled' as const;

  constructor(readonly anchorOrigin: string, readonly why: string) {
    super(
      `Anchoring for ${anchorOrigin} would publish production anchors (${why}), and anchoring.production is not true. ` +
        'A production anchor needs an explicit go (the first one published by a timestamp authority, or on a chain tzun-anchor/1 §9 names mainnet, freezes the anchor format): ' +
        'set anchoring.production: true, or create the store with a test. namespace.',
    );
    this.name = 'AnchorActivationError';
    Object.setPrototypeOf(this, AnchorActivationError.prototype);
  }
}

/** `anchorNow({ force: true })` beyond the rolling limit. */
export class AnchorForceRateLimitedError extends Error {
  readonly code = 'anchor_force_rate_limited' as const;

  constructor(readonly limit: number, readonly nextAllowedAt: string) {
    super(
      `anchorNow({ force: true }) is limited to ${limit} forced publications per rolling 24 hours; ` +
        `the next is allowed at ${nextAllowedAt}.`,
    );
    this.name = 'AnchorForceRateLimitedError';
    Object.setPrototypeOf(this, AnchorForceRateLimitedError.prototype);
  }
}

/** The publisher wallet cannot publish for this store. */
export class AnchorWalletError extends Error {
  constructor(readonly code: 'anchor_wallet_not_dedicated' | 'anchor_wallet_retired' | 'anchor_wallet_chain_mismatch', message: string) {
    super(message);
    this.name = 'AnchorWalletError';
    Object.setPrototypeOf(this, AnchorWalletError.prototype);
  }
}

/**
 * The publisher's signer returned something other than the transaction it
 * was asked to sign: another address signed it, or a field differs (a nonce,
 * a fee, the calldata). Nothing it returned is stored or sent, because the
 * outbox and the nonce accounting depend on those exact bytes. `field` names
 * what differs; nothing here carries key material.
 */
export class AnchorSignerError extends Error {
  readonly code = 'anchor_signer_mismatch' as const;

  constructor(readonly field: string, detail: string) {
    super(`The publisher's signer returned a transaction other than the one it was asked to sign (${field}: ${detail}). Nothing was stored or sent.`);
    this.name = 'AnchorSignerError';
    Object.setPrototypeOf(this, AnchorSignerError.prototype);
  }
}

/**
 * The publisher's signer did not answer: `getAddress()` or
 * `signTransaction()` threw, or did not settle within
 * `anchoring.publishers.evm.signTimeoutMs` (a KMS, an HSM or an approval
 * tool that never replies). Nothing was stored or sent; a pass that asked
 * fails and is retried, and the scheduler raises the
 * `anchor_signer_unavailable` alarm. A signature that arrives after the
 * deadline is dropped. `step` names the call; nothing here carries key
 * material.
 */
export class AnchorSignerUnavailableError extends Error {
  readonly code = 'anchor_signer_unavailable' as const;

  constructor(readonly step: 'getAddress' | 'signTransaction', detail: string) {
    super(`The publisher's signer did not answer ${step}() (${detail}). Nothing was stored or sent.`);
    this.name = 'AnchorSignerUnavailableError';
    Object.setPrototypeOf(this, AnchorSignerUnavailableError.prototype);
  }
}

/**
 * A wallet operation (`sweep`, `handover`, `rebroadcastAccountedTransaction`)
 * on an instance that does not hold the domain's anchor lease: another
 * instance is anchoring, and only the lease holder may use the wallet's
 * nonces.
 */
export class AnchorNotLeaderError extends Error {
  readonly code = 'anchor_not_leader' as const;

  constructor(readonly holder: string) {
    super(
      `Another instance (${holder}) holds the anchor lease: run the wallet operation there, ` +
        'or stop that instance and wait for its lease to expire.',
    );
    this.name = 'AnchorNotLeaderError';
    Object.setPrototypeOf(this, AnchorNotLeaderError.prototype);
  }
}

/** How loud an alarm is. */
export type AnchorAlarmSeverity = 'warning' | 'critical';

/**
 * What an alarm says.
 *
 *   anchor_history_mismatch          the last published transaction or the stored anchor log
 *                                    no longer matches what was published. Stops anchoring.
 *   log_inconsistent_with_anchor     a source log's new checkpoint is not provably consistent with
 *                                    its anchored one (tzun-anchor/1 §11 item 1). That log is left
 *                                    out; others continue.
 *   anchor_tx_stuck                  replacements are exhausted and the transaction is still unmined.
 *   anchor_nonce_consumed_externally a nonce of the dedicated wallet was used by a transaction this
 *                                    store never made. A security finding. Stops anchoring.
 *   anchor_wallet_insufficient_funds the balance is under 3x the cost of one publication at the hard cap.
 *   anchor_fee_above_hard_cap        the fee is above the hard cap and a leaf has waited T_max.
 *   anchor_runway_low                the projected runway is under 30 days.
 *   anchor_runway_critical           the projected runway is under 7 days.
 *   anchor_history_unverified        the node could not confirm a publication whose finality or block
 *                                    carries trust (the last finalized, the published size's, one
 *                                    awaiting its fill): the pass defers what depends on it. A warning,
 *                                    critical once it has lasted `tuning.unverifiedEscalateMs`.
 *   anchor_publication_other_wallet  an unmined publication was signed by a wallet other than the
 *                                    configured publisher (the key was changed while it was in flight).
 *                                    Its stored transaction is rebroadcast, never replaced, and no epoch
 *                                    is cut until it is mined.
 *   anchor_signer_mismatch           the publisher's signer returned a transaction other than the one it
 *                                    was asked to sign (another address, or a changed field). Nothing it
 *                                    returned is stored or sent; the pass fails and is retried.
 *   anchor_signer_unavailable        the publisher's signer threw, or did not answer within
 *                                    `signTimeoutMs`. Nothing is stored or sent; the pass fails and is
 *                                    retried.
 *   anchor_expectation_mismatch      the store's latest fill recomputed statuses with a timestamp
 *                                    expectation other than this instance's. Every writer of an anchored
 *                                    store must share one: a fill applies the leader's to every record,
 *                                    so a record waiting for a timestamp can leave the retry's queue, or
 *                                    one waiting only for its anchor can stay pending.
 *   anchor_log_leaf_unexplained      a leaf of the anchor log above the published size is not the
 *                                    digest of a source checkpoint the scheduler can re-derive.
 *                                    Stops anchoring: publishing past it would vouch for it, and the
 *                                    log is insert-only, so the domain moves to a new identity.
 *   anchor_publication_unexplained   a publication row is not one the scheduler made: an attempt not
 *                                    signed by an allowed publisher inside its window, or a prepared
 *                                    row whose P the scheduler cannot re-derive. Nothing is signed.
 *                                    Stops anchoring.
 *   anchor_wallet_tx_unexplained     an accounted wallet transaction is not the signed transaction it
 *                                    claims to be. Stops anchoring.
 *   anchor_fill_conflict             a record does not match its evidence leaf (another chain, another
 *                                    position, or a digest the leaf's path does not place); the fill
 *                                    skipped it. A store written before 0.8.0, the demo-tamper hooks or
 *                                    a writer the triggers do not hold.
 *   anchor_publisher_outside_window  the publisher manifest lists the configured publisher, and none of
 *                                    its windows contains now: nothing is signed, since verifiers would
 *                                    refuse it. The pass defers until a window opens or the key changes.
 *   anchor_block_material_unreadable a mined publication's block cannot be stored: its header does not
 *                                    rebuild to its hash (a field a later fork added) or its transactions
 *                                    are not the ones the header commits to. The publication cannot
 *                                    become final until the SDK reads that block.
 */
export type AnchorAlarmCode =
  | 'anchor_history_mismatch'
  | 'log_inconsistent_with_anchor'
  | 'anchor_tx_stuck'
  | 'anchor_nonce_consumed_externally'
  | 'anchor_wallet_insufficient_funds'
  | 'anchor_fee_above_hard_cap'
  | 'anchor_runway_low'
  | 'anchor_runway_critical'
  | 'anchor_history_unverified'
  | 'anchor_publication_other_wallet'
  | 'anchor_signer_mismatch'
  | 'anchor_signer_unavailable'
  | 'anchor_expectation_mismatch'
  | 'anchor_log_leaf_unexplained'
  | 'anchor_publication_unexplained'
  | 'anchor_wallet_tx_unexplained'
  | 'anchor_fill_conflict'
  | 'anchor_publisher_outside_window'
  | 'anchor_block_material_unreadable';

/** The alarms that stop anchoring until an operator has looked. */
export const STOPPING_ALARMS: ReadonlySet<AnchorAlarmCode> = new Set<AnchorAlarmCode>([
  'anchor_history_mismatch',
  'anchor_nonce_consumed_externally',
  'anchor_log_leaf_unexplained',
  'anchor_publication_unexplained',
  'anchor_wallet_tx_unexplained',
]);

export const ALARM_SEVERITY: Readonly<Record<AnchorAlarmCode, AnchorAlarmSeverity>> = Object.freeze({
  anchor_history_mismatch: 'critical',
  log_inconsistent_with_anchor: 'critical',
  anchor_tx_stuck: 'critical',
  anchor_nonce_consumed_externally: 'critical',
  anchor_wallet_insufficient_funds: 'critical',
  anchor_fee_above_hard_cap: 'critical',
  anchor_runway_low: 'warning',
  anchor_runway_critical: 'critical',
  anchor_history_unverified: 'warning',
  anchor_publication_other_wallet: 'critical',
  anchor_signer_mismatch: 'critical',
  anchor_signer_unavailable: 'warning',
  anchor_expectation_mismatch: 'warning',
  anchor_log_leaf_unexplained: 'critical',
  anchor_publication_unexplained: 'critical',
  anchor_wallet_tx_unexplained: 'critical',
  anchor_fill_conflict: 'critical',
  anchor_publisher_outside_window: 'critical',
  anchor_block_material_unreadable: 'critical',
});

/** One alarm, as the scheduler reports it. */
export interface AnchorAlarm {
  code: AnchorAlarmCode;
  severity: AnchorAlarmSeverity;
  message: string;
  /** What the alarm is about: an origin, a publication id, a nonce. Never key material. */
  subject?: string;
  /** ISO 8601, from the scheduler's clock. */
  raisedAt: string;
}
