/**
 * Anchoring at runtime (tzun-anchor/1 §5 to §7, §11): the scheduler that cuts
 * epochs, publishes P through a crash-safe outbox, waits for finality and fills
 * each record's `nonRepudiation.anchor`.
 *
 * `Tzun.init({ anchoring })` runs one on its store and stops it on
 * `close()`. `createAnchorScheduler()` runs one on its own, on a SQLite or
 * Postgres store, for a process that anchors a store without capturing into
 * it (the dry run, an operator's wallet operations).
 */
export {
  createAnchorScheduler,
  DEFAULT_ANCHOR_TUNING,
  type AnchorScheduler,
  type AnchorSchedulerOptions,
  type AnchorSchedulerTuning,
  type AnchorSchedulerTestHooks,
  type AnchorPassReport,
  type AnchorState,
  type AnchorPublicationSummary,
  type AccountedTransactionResult,
  type NonceAccounting,
} from './scheduler';
export {
  resolveAnchoringConfig,
  DEFAULT_ANCHOR_CADENCE,
  DEFAULT_ANCHOR_BUDGET,
  DEFAULT_SIGN_TIMEOUT_MS,
  type AnchoringConfig,
  type AnchorCadence,
  type AnchorBudget,
  type AnchorTransactionRequest,
  type AnchorTransactionSigner,
  type EvmPublisherConfig,
  type WriteOnceSink,
  type ResolvedAnchoringConfig,
  type ResolvedEvmPublisher,
} from './config';
export {
  AnchoringConfigError,
  AnchorActivationError,
  AnchorForceRateLimitedError,
  AnchorNotLeaderError,
  AnchorSignerError,
  AnchorSignerUnavailableError,
  AnchorWalletError,
  ALARM_SEVERITY,
  STOPPING_ALARMS,
  type AnchorAlarm,
  type AnchorAlarmCode,
  type AnchorAlarmSeverity,
} from './errors';
export {
  createEvmPublisher,
  createSignerPublisher,
  publisherFor,
  checkSignedTransaction,
  JsonRpcEvmChain,
  EvmBlockMaterialError,
  classifyBroadcastError,
  type EvmChainClient,
  type EvmPublisher,
  type EvmFees,
  type EvmReceipt,
  type EvmBroadcastResult,
  type EvmBroadcastReason,
  type EvmTransactionView,
  type EvmBlockMaterial,
  type EvmTransactionFields,
  type SignedTransaction,
} from './evm-chain';
export {
  ANCHOR_PUBLICATION_GAS,
  ANCHOR_PUBLICATION_GAS_LIMIT,
  DEFAULT_MIN_PRIORITY_FEE_GWEI,
  minPriorityFeeWei,
  withPriorityFeeFloor,
  MAX_REPLACEMENTS,
  cadenceDecision,
  feeDecision,
  governorView,
  gweiToWei,
  publicationFees,
  replacementFees,
  type CadenceDecision,
  type CadenceInput,
  type FeeDecision,
  type GovernorView,
} from './governor';
export { planEpoch, expectedOrigin, type EpochPlan, type EpochMember, type RefusedLog } from './epoch';
export {
  fillPublication,
  fillDoneHolds,
  readFillProgress,
  AnchorFillIntegrityError,
  type FillProgress,
  type FillOutcome,
  type FillAuthority,
  type FillContext,
} from './fill';
export {
  AnchorLogTrust,
  AnchorTrustError,
  DEFAULT_SOURCE_LOG_KINDS,
  PublicationTrust,
  allowedPublishers,
  headerSourceOf,
  manifestOf,
  senderAllowed,
  type AllowedPublisher,
  type AnchorBase,
  type Confirmation,
  type ExplainedRange,
} from './explain';
export { buildTxTrie, blockHeaderRlp, txKey, type BuiltTrie } from './tx-trie';
