import { randomBytes, randomUUID } from 'crypto';
import { CaptureInput, EvidenceEnvelope, EvidencePayload, AttestationArtifacts } from '@tzun/engine';
import type { SignatureRequiredExpectation, SignoffExpectation } from '@tzun/engine';
import {
  CURRENT_SCHEMA_VERSION,
  DECIDER_COMMITMENT_SALT_BYTES,
  SYSTEM_RECORD_AI_SYSTEM_IDS,
  buildContributions,
  buildEvidencePayload,
  buildLinks,
  canonicalSerializeValue,
  defaultAgentDeciderId,
  deciderCommitment,
  deciderCommitmentSalt,
  deciderMaterialViolation,
  deciderViolation,
  fillAiBomNulls,
  identifierScheme,
  isKnownSchemeIdentifier,
  mandateBlockViolation,
  stepClass,
  verifyDeciderOpening,
} from '@tzun/engine';
import type {
  Contributions,
  ContributionsInput,
  ContributionStepInput,
  Decider,
  DeciderInput,
  DeciderOpening,
  EnvelopeInput,
  HeldLinkTarget,
  Link,
  LinkInput,
  MandateBlock,
  StoreOptions,
  SystemRecordKind,
} from '@tzun/engine';
import {
  captureInputViolation,
  describeType,
  engineRefusal,
  isInlineDescriptorForm,
  isPlainObject,
  preparedIdentityViolation,
  resolutionRefusal,
  settleSignoffExpectation,
  toJsonDataModel,
  type CaptureInputViolation,
} from './capture-input';
import { FailureRecord } from '@tzun/engine';
import { VerificationResult } from '@tzun/engine';
import { TzunConfig, CaptureResult, Mode, RemoteCaptureReceipt } from '@tzun/engine';
import { StorageAdapter } from '@tzun/engine';
import { MemoryStorageAdapter } from '../storage/memory';
import { SqliteStorageAdapter } from '../storage/sqlite';
import { PostgresStorageAdapter } from '../storage/postgres';
import { HttpStorageAdapter, HttpTransport, TzunCaptureError, TzunCatalogError, TzunCloudReadUnsupportedError, isModelCatalogUnsupported } from './http-transport';
import { AsyncCredentialStore } from '../attestation/credential-store';
import { credentialStoreFor } from '../storage/credential-stores';
import { ChainConflictError, ChainSealedError, IdempotencyConflictError } from '@tzun/engine';
import { captureIdempotencyFingerprint } from '@tzun/engine';
import type { IdempotencyClaim, IdempotencyReceipt } from '@tzun/engine';
import { DuplicateRecordError } from '../storage/append-only';
import { ANCHOR_LOG_KIND, EvidenceLogRefusalError, anchorStoreFor, evidenceLogOrigin, logStoreFor } from '../storage/log-store';
import type { LogPosition } from '../storage/log-store';
import { readRecordLog, recordLogPosition } from './anchor-state';
import {
  refusePostgresStoreBeforeSignoffExpectation,
  refuseSqliteStoreBeforeSignoffExpectation,
} from './store-schema-guard';
import { createAnchorScheduler, publisherFor, JsonRpcEvmChain } from '../anchoring';
import type { AnchorPassReport, AnchorScheduler, AnchorState, EvmChainClient, ResolvedAnchoringConfig } from '../anchoring';
import { eip155ChainId } from '../anchoring/evm-chain';
import { HeaderFollower, freshnessRowStoreFor } from '../anchoring/header-follower';
import { needsStoreLevelVerification, stepModelDigests } from './step-models';
import { StoreLogs, type ScannerAnchoringDeps, type ScannerEvmChain } from '../monitoring/anchor-log-checks';
import { verifyAnchor, type AnchorVerifyOptions } from '../attestation/anchor-verify';
import { bundleAnchoring } from '../export/bundle';
import { BUNDLE_VERSION, type ProofBundle } from '../export/bundle-types';
import type { StorageExtension } from '../storage/extensions';
import {
  installSdkExtensions,
  isCaptureRefusal,
  type AgentReference,
  type AgentsApi,
  type CaptureHookContext,
  type CaptureRefusal,
  type MandateAttemptPlan,
  type MandateCaptureClaim,
  type DecidersApi,
  type DecisionGraphApi,
  type InstalledSdkExtensions,
  type LinksApi,
  type MandatesApi,
  type SdkExtensionFactory,
  type SdkHost,
  type SystemRecordCapture,
  type SystemRecordCaptureOptions,
} from './extension-points';
import { DEFAULT_SDK_EXTENSIONS } from './extensions-registry';
// Cloud transport surface — re-exported so callers can catch these by name.
// `TzunCloudReadUnsupportedError` in particular has to be catchable: it is what
// a cloud-mode read throws rather than returning empty data.
export {
  HttpTransport,
  HttpStorageAdapter,
  TzunCaptureError,
  TzunCatalogError,
  TzunCloudReadUnsupportedError,
  ModelCatalogUnsupportedError,
  CATALOG_REPROBE_MS,
  DEFAULT_API_URL,
} from './http-transport';
export type { CaptureSuccess, CaptureErrorCode, CatalogErrorCode, CatalogOperation } from './http-transport';
// The two cloud read shapes the Tzun class maps: the server's verify block and
// its export bundle. Re-exported so a caller can hold either by name.
export type { CloudVerification, CloudExportBundle } from './http-transport';
import type { CloudExportBundle, CloudVerification } from './http-transport';
// The local-adapter twin of a 409: a conditional append the store refused
// because the head moved. Re-exported beside `TzunCaptureError` so a caller
// that drives a `StorageAdapter` directly can catch it by name and read the
// same `{ code, retryable }` pair off either.
export { ChainConflictError } from '@tzun/engine';
// The builders of a record's contributions (Record §7.2, §7.3): a single model
// is `singleModel(aiBom)`; `outputDigest` is the digest a step's output names.
export { buildContributions, singleModel, outputDigest, stepDigest } from '@tzun/engine';
// The extension points mandates, the agent catalog and links plug into, and
// the error a namespace whose feature is not installed rejects with.
export { ExtensionNotInstalledError, isCaptureRefusal } from './extension-points';
import { exportAgentDescriptors } from './agents';
export type {
  AgentCaptureHook,
  AgentReference,
  AgentsApi,
  CaptureHookContext,
  CaptureRefusal,
  DecidersApi,
  DecisionGraphApi,
  DecisionGraphEdge,
  DecisionGraphWalk,
  LinkCaptureHook,
  LinksApi,
  MandateAttemptPlan,
  MandateCaptureClaim,
  MandateCaptureHook,
  MandateIssueResult,
  MandatesApi,
  SdkExtension,
  SdkExtensionFactory,
  SdkHost,
  SystemRecordCapture,
  SystemRecordCaptureOptions,
} from './extension-points';
export type {
  StorageExtension,
  SqliteStorageExtension,
  PostgresStorageExtension,
  MemoryStorageExtension,
  StoreWrite,
} from '../storage/extensions';
export { decidersExtension } from '../storage/ddl/deciders';
export {
  agentsSdkExtension,
  agentsStorageExtension,
  AgentCatalogUnsupportedError,
  AgentDescriptorConflictError,
  InvalidAgentDescriptorError,
  exportAgentDescriptors,
  exportedAgentCatalog,
} from './agents';
// resetChainState() refused for a chain whose evidence log holds leaves.
export { ChainStateResetRefusedError } from '../storage/chain-head-guard';
// The two answers `getActiveChainId()` refuses to guess at:
// a store whose every chain is sealed, and a store with more than one active
// chain. Both surface from `Tzun.init()` on such a store — the chain named
// there is the chain `capture()` writes evidence into, so a wrong one is a
// wrong home for evidence, not a default. Re-exported so a caller can catch
// them by name or by `code`.
export { NoActiveChainError, AmbiguousActiveChainError } from '@tzun/engine';
// A keyed capture refused because the key names a record captured from other
// input. Re-exported so a caller can catch it by name or by `code`; it is also
// what `CaptureResult.failure` reports as `idempotency_conflict`.
export { IdempotencyConflictError } from '@tzun/engine';
// A `list()` limit or offset that is not a safe non-negative integer, refused
// by every adapter. The class is the engine's, beside the
// `ListOptions` contract it enforces; re-exported so a caller or a server
// implementing `StorageAdapter` can catch or throw it by name or by `code`.
export { InvalidPaginationError } from '@tzun/engine';
// A store a release before 0.7.0 wrote, refused by `Tzun.init()`: its records'
// digests are over the earlier v1.0 hashed field set. Re-exported so a caller
// can catch it by name or by `code`; the remedy is a new store.
export { StoreSchemaOutdatedError } from '@tzun/engine';
export type {
  SessionAttachmentExpectation,
  SignatureRequiredExpectation,
  SignoffExpectation,
  SignoffExpectationReason,
} from '@tzun/engine';
// What a local store refuses because of its evidence logs (Tree §5.2;
// Anchor §4.3.2): a record the chain's log cannot take (also what
// `CaptureResult.failure` reports as `evidence_log_refused`), and the store
// identity and namespace refusals an adapter raises when it is opened.
// Re-exported so a caller can catch them by name or by `code`.
export {
  EvidenceLogRefusalError,
  InvalidLogNamespaceError,
  LogNamespaceMismatchError,
  SqliteEncodingError,
  StoreIdentityMissingError,
} from '../storage/log-store';
export type { EvidenceLogRefusalReason } from '../storage/log-store';

/**
 * Default for `TzunConfig.chainConflictMaxAttempts`. See that option for the
 * reasoning; in short, each attempt past the first means another writer made
 * progress, so the bound is "how many other writers can beat this capture to
 * the head in a row before we stop trying", not a timeout.
 */
export const DEFAULT_CHAIN_CONFLICT_MAX_ATTEMPTS = 10;
import {
  resolveMode,
  validateAttestationConfig,
  ValidatedAttestationConfig,
  anchoringConfigFor,
  logNamespaceFor,
} from './mode-resolver';
import {
  AttestationRetryScheduler,
  DEFAULT_ATTESTATION_RETRY_INTERVAL_MS,
  validateAttestationRetryOptions,
  type AttestationRetrySchedulerOptions,
  type AttestationRetryState,
} from './attestation-retry-scheduler';
import { assembleEnvelope, verifyEnvelope, EvidenceChain, SchemaRegistry, canonicalSerialize, computeDigest } from '@tzun/engine';
import {
  isEvidenceId,
  capturedAtViolation,
  describeSignoffExpectationViolation,
  isSessionAttachmentExpectation,
  signoffExpectationViolation,
  determineAttestationStatus,
  missingAttestationComponents,
  isRetryObtainableComponent,
} from '@tzun/engine';
import type { RetryObtainableComponent } from '@tzun/engine';
import { verifyChainCompleteness, ChainCompletenessResult, MultiChainCompletenessResult, type ChainEvidenceLog } from '@tzun/engine';
import {
  assertionProvenance,
  CUSTODY_ENTRY_HASH_PREIMAGE,
  recordVerdict,
  toCustodyLedgerEntry,
  unmeasuredRecordVerdict,
  verifyCustodyTrail,
} from '@tzun/engine';
import type {
  AssertionProvenance,
  AssertionProvenanceOptions,
  CustodyLedgerEntry,
  EvidenceRead,
  ExportedChainPosition,
  ExportedChainPredecessor,
  ExportedCustody,
  RecordVerdict,
  RecordVerdictInput,
} from '@tzun/engine';
import { chainUpperBound, listStoreChainIds } from '../storage/chain-bounds';
import { AttestationOrchestrator } from '../attestation/orchestrator';
import { RFC3161Client } from '../attestation/rfc3161';
import { CredentialStore } from '../attestation/credential-store';
import {
  verifyAttestation,
  webauthnChallengeForDigest,
  assertionBindingFailure,
} from '../attestation/verify-attestation';

// The binding between a decision record and the human who signed it.
// Re-exported from the package entry point because both halves of the contract
// have to be reachable by an integrator: the ceremony derives the challenge
// with `webauthnChallengeForDigest`, and anyone holding an envelope can check
// the binding with `assertionBindsDigest` without a credential store.
export {
  webauthnChallengeForDigest,
  assertionBindsDigest,
  assertionBindingFailure,
  verifyAttestation,
} from '../attestation/verify-attestation';
export type {
  AttestationVerifyOptions,
  AttestationVerificationResult,
  AttestationSignatureReason,
  AttestationAnchorReason,
  AttestationTimestampReason,
  AttestationActorReason,
  AttestationCapturedAtReason,
} from '../attestation/verify-attestation';
// The anchoring verification surface (tzun-anchor/1 §4 to §8, §10; Tree §3.5):
// a record's `nonRepudiation.anchor`, the checkpoint bodies and origins
// it names, the RFC 6962 proofs under it, and the publications of P. A holder
// of an envelope, or of an export bundle, verifies with these and nothing
// else, imported from the package root (tests/ts/package-root-exports.test.ts
// imports each from the built package).
export { verifyAnchor, ANCHOR_SPEC } from '../attestation/anchor-verify';
// The b1 proof bundle (Bundle §3): its shape, `verifyBundle()` and the report
// and exit codes (Verification §6). `Tzun.exportBundle()` writes one; a holder
// of one verifies it with these and nothing else.
export { BUNDLE_VERSION, BUNDLE_REPORT_VERSION, verifyBundle, bundleExitCode, comparableReport } from '../export';
// What `verifyBundle()`, `verifyAnchor()` and the RFC 3161 verifiers throw for
// a trust anchor they cannot read: the auditor's input, refused rather than
// dropped (Verification §3.1).
export { UnreadableTrustAnchorError } from '../attestation/rfc3161-token';
export type {
  ProofBundle,
  BundleProfile,
  BundleSubject,
  BundleChain,
  BundleChainPredecessor,
  BundleCustody,
  BundlePublication,
  BundleEvmPublication,
  BundleRfc3161Publication,
  BundleCheckpoint,
  BundleConsistencyProof,
  BundleLogMaterial,
  BundleAnchorPending,
  BundleExporter,
  BundleCheck,
  BundleCheckOutcome,
  BundleExistedBy,
  BundleReportSummary,
  BundleReportInputs,
  BundleVerificationReport,
  VerifyBundleOptions,
  BundleExitOptions,
  BundleExitCode,
} from '../export';
export type {
  AnchorArtifact,
  AnchorPublication,
  Rfc3161AnchorPublication,
  AnchorVerifyOptions,
  AnchorVerification,
  AnchorCheckId,
  AnchorPublicationCheckId,
  AnchorNotCheckedReason,
  AnchorCheckResult,
  AnchorPublicationVerdict,
  AnchorPosition,
  AnchorExistedBy,
} from '../attestation/anchor-verify';
export {
  parseCheckpoint,
  formatCheckpoint,
  checkpointDigest,
  isOriginText,
  parseOrigin,
  chainIdRefusal,
  chainSegment,
  chainIdFromSegment,
  anchorLogOrigin,
  evidenceLogOrigin,
  sourceLogOrigin,
  isTestNamespace,
  isPlatformNamespace,
  checkOriginBinding,
  ANCHOR_LOG_KIND,
  EVIDENCE_LOG_KIND,
  TEST_NAMESPACE_PREFIX,
  PLATFORM_NAMESPACE,
} from '../attestation/checkpoint';
export type {
  ChainIdRefusalReason,
  Checkpoint,
  CheckpointMalformedReason,
  CheckpointParseResult,
  TzunOrigin,
  OriginBinding,
  OriginBindingReason,
} from '../attestation/checkpoint';
export {
  MERKLE_SPEC,
  merkleLeafHash,
  verifyMerkleProof,
  verifyConsistencyProof,
} from '../attestation/merkle';
export type { ConsistencyProofReason, ConsistencyVerification } from '../attestation/merkle';
export {
  verifyEvmPublication,
  verifyEvmTransactionProof,
  parseEvmBlockHeader,
  RpcEvmHeaderSource,
  EthereumAnchorVerifier,
  EvmPublicationNotCheckedError,
  DEFAULT_EVM_NETWORKS,
  DEFAULT_EVM_TIMEOUT_MS,
  EVM_MIN_FINAL_CONFIRMATIONS,
} from '../attestation/blockchain';
export type {
  EthereumAnchorVerifierConfig,
  EthereumAnchorVerification,
  AnchorTransaction,
  AnchorTransactionProvider,
  EvmPublicationReason,
  EvmNotCheckedReason,
  EvmCheckOutcome,
  EvmCheckResult,
  PublisherManifest,
  PublisherManifestEntry,
  EvmCalldataPublication,
  EvmHeaderSource,
  EvmSourceTransaction,
  EvmPublicationInput,
  EvmPublicationFacts,
  EvmPublicationVerdict,
  EvmNetwork,
  EvmFinality,
  EvmBlockHeader,
} from '../attestation/blockchain';
// Anchoring at runtime: the `anchoring` config
// `Tzun.init()` takes (with an external signer for a key the SDK never holds),
// the state `tzun.getAnchorState()` reports and the pass `tzun.anchorNow()`
// runs, the refusals and alarms, and the standalone scheduler for a process
// that anchors a store it does not capture into (wallet operations included).
export {
  createAnchorScheduler,
  AnchoringConfigError,
  AnchorActivationError,
  AnchorForceRateLimitedError,
  AnchorNotLeaderError,
  AnchorSignerError,
  AnchorSignerUnavailableError,
  AnchorWalletError,
  DEFAULT_ANCHOR_CADENCE,
  DEFAULT_ANCHOR_BUDGET,
} from '../anchoring';
export type {
  AnchoringConfig,
  AnchorCadence,
  AnchorBudget,
  AnchorTransactionRequest,
  AnchorTransactionSigner,
  EvmPublisherConfig,
  WriteOnceSink,
  AnchorScheduler,
  AnchorSchedulerOptions,
  AnchorState,
  AnchorPassReport,
  AnchorPublicationSummary,
  AnchorAlarm,
  AnchorAlarmCode,
  AnchorAlarmSeverity,
  AccountedTransactionResult,
  NonceAccounting,
} from '../anchoring';
// The storage the scheduler, the fill and the anchor-state read work on. A
// deployment that keeps its logs and anchoring tables in a schema of its own
// implements `LogStore` and `AnchorStore` over them and hands them to
// `createAnchorScheduler`; these are the rows, the publication state machine
// its tables must hold, the refusal its epoch guard throws, the pure fill merge
// and wallet-transaction check its writes apply, and the record read over its
// tables. The row type the verifier calls `AnchorPublication` is the
// publication an artifact carries; the stored row is `StoredAnchorPublication`.
export {
  AnchorEpochFenceError,
  ANCHOR_PUBLICATION_KINDS,
  ANCHOR_PUBLICATION_STATES,
  ANCHOR_PUBLICATION_STATES_BY_KIND,
  ANCHOR_PUBLICATION_TRANSITIONS,
  isAllowedPublicationTransition,
  ANCHOR_BROADCAST_OUTCOMES,
  ANCHOR_WALLET_TX_KINDS,
  ANCHOR_FILL_CAUSE,
  REVISION_ACTOR_ANCHOR,
  filledEnvelope,
  fillStatus,
  assertWalletTx as assertAnchorWalletTx,
} from '../storage/log-store';
export type {
  LogStore,
  AnchorStore,
  LogStoreProvider,
  AnchorStoreProvider,
  StoreIdentity,
  LogRecord,
  LogLeaf,
  LogLeafSource,
  NewLogLeaf,
  LogPosition,
  LogSize,
  LeafIndexRange,
  EvidenceLogCoverage,
  LogCheckpoint,
  NewLogCheckpoint,
  LeafAnchorProgress,
  LeafAnchorPublication,
  AnchorPublicationKind,
  AnchorPublicationState,
  AnchorBroadcastOutcome,
  AnchorPublicationAttempt,
  AnchorPublication as StoredAnchorPublication,
  NewAnchorPublication,
  AnchorPublicationPatch,
  EpochWrite,
  EpochGuard,
  AnchorEpochFenceReason,
  AnchorLease,
  AnchorWallet,
  AnchorWalletTxKind,
  AnchorWalletTx,
  NewAnchorWalletTx,
  AnchorFill,
  AnchorFillChunk,
  AnchorFillResult,
} from '../storage/log-store';
export { readRecordLog, recordLogPosition } from './anchor-state';
export type { RecordLogRead } from './anchor-state';
// The conformance kit for such a store: the SDK's own SQLite and Postgres
// stores pass it (tests/ts/anchor-store-conformance.test.ts), and a store
// kept outside the SDK runs the same cases against its own tables.
export { anchorStoreConformanceCases, runAnchorStoreConformance } from '../testing/anchor-store-conformance';
export type {
  AnchorStoreConformanceHarness,
  AnchorStoreConformanceStore,
  AnchorStoreConformanceCase,
  AnchorStoreConformanceReport,
} from '../testing/anchor-store-conformance';
// Where the ceremony ran and what kind of key signed: the same
// read `verify()` and `exportEvidence()` report, for a holder of an envelope.
export { assertionProvenance } from '@tzun/engine';
export type {
  AssertionProvenance,
  AssertionProvenanceOptions,
  AssertionOriginReason,
  AssertionTopOriginReason,
  AuthenticatorFlags,
  DeviceBoundReason,
} from '@tzun/engine';
export { TzunWebAuthn, challengeForBinding } from '../attestation/webauthn';
export type { AssertionBinding, AssertionResult } from '../attestation/webauthn';
export { CredentialStore } from '../attestation/credential-store';
export type { StoredCredential } from '../attestation/credential-store';

// Public re-export for server-side reuse: a backend that timestamps on its own
// imports RFC3161Client from @tzun/sdk rather than vendoring a copy of it.
export {
  RFC3161Client,
  TimestampAuthorityError,
  DEFAULT_TIMESTAMP_AUTHORITIES,
} from '../attestation/rfc3161';
export type {
  RFC3161Config,
  TimestampResult,
  TimestampProvenance,
  TimestampConformance,
  AuthorityAttempt,
  AuthorityBreakerState,
} from '../attestation/rfc3161';
// The public-TSA registry. Exported from the SDK root rather than only from
// `src/attestation` because the two call sites that need it are an
// integrator's `init()` (capture-side URLs) and their `verify()` (verify-side
// anchors) — both of which reach for '@tzun/sdk' and neither of which has
// any reason to know the attestation subtree exists.
export {
  DEFAULT_TRUST_ANCHOR_AUTHORITIES,
  listTimestampAuthorities,
  independentAuthorities,
  getTimestampAuthority,
  resolveTimestampAuthorities,
  timestampAuthorityUrls,
  timestampAuthorityAnchorsPem,
  addTimestampAuthority,
} from '../attestation/tsa-registry';
export type { TimestampAuthority } from '../attestation/tsa-registry';
// Public re-export for server-side reuse: a backend runs the scanner pipeline
// (ScheduledScanner → MonitoringEventBus → TamperDetector) over its own
// StorageAdapter rather than vendoring copies. A scanner that checks what was
// anchored takes `ScannerAttestationDeps.anchoring`, whose chain readers
// `JsonRpcEvmChain` implements.
export { MonitoringEventBus, TamperDetector, ScheduledScanner, runAnchorScanPass } from '../monitoring/index';
export type { ScannerAttestationDeps, ScannerAnchoringDeps, ScannerEvmChain, ScannerEvmTransaction, ScannerLogScope, AnchorScanCache, AnchorScanCarry } from '../monitoring/index';
export { JsonRpcEvmChain, EvmRpcError } from '../anchoring/evm-chain';
export type { EvmChainClient } from '../anchoring/evm-chain';
// The wrapper surface, and the named per-vendor aliases.
export type { DecisionInput, AttachOptions, SupportedVendor } from './wrappers';
export {
  SUPPORTED_VENDORS, TZUN_CAPTURE_KWARG,
  wrapOpenAI, wrapAnthropic, wrapAwsBedrock, wrapGcpVertex,
  wrapAzureAI, wrapNvidiaNim, wrapHFInference, wrapOpenRouter,
} from './wrappers';
import {
  MonitoringEventBus,
  VerifyingStorageProxy,
  TamperDetector,
  ScheduledScanner,
  NotificationRouter,
  EventEmitterChannel,
  WebhookChannel,
  SlackChannel,
  PagerDutyChannel,
  EmailChannel,
} from '../monitoring/index';
import { MonitoringEvent, TamperIncident, ScannerState, ScanSummary, NotificationChannel, TamperSeverity } from '@tzun/engine';
import { RecoveryManager } from '../monitoring/recovery-manager';
import {
  ChainIdentity,
  AnnotateOptions,
  RelinkOptions,
  ForkOptions,
  AnnotationResult,
  RelinkResult,
  ForkResult,
} from '@tzun/engine';
import {
  AiBom,
  AiBomWithInlineDescriptor,
  ExportedDescriptorEntry,
  ExportedEvidenceEnvelope,
  ModelDescriptor,
  ModelDescriptorAnnotationRow,
  ModelDescriptorRow,
} from '@tzun/engine';
import { registerModel, RegisterOptions } from '../models/register';
import { computeModelDigest } from '../models/compute-model-digest';
import { sdkLog, type LogSink } from './log';
import { walkLineage, walkLineageDetailed } from '../models/lineage';
import type { LineageWalkResult } from '../models/lineage';
import {
  annotateModelDescriptor,
  ModelAnnotateInput,
  ModelAnnotateOptions,
} from '../models/annotations';
import { buildEnrichedView } from '../models/enriched-view';

/**
 * SDK-facing recovery API. Delegates to RecoveryManager.
 */
export interface RecoveryAPI {
  annotate(incidentId: string, options: AnnotateOptions): Promise<AnnotationResult>;
  relink(incidentId: string, options: RelinkOptions): Promise<RelinkResult>;
  fork(incidentId: string, options: ForkOptions): Promise<ForkResult>;
}

/**
 * SDK-facing models API. Thin pass-through to the storage catalog +
 * `registerModel` + `computeModelDigest`. The non-null `!` assertions are
 * warranted: every concrete adapter implements these catalog methods.
 */
export interface ModelsApi {
  register(
    descriptor: Partial<ModelDescriptor>,
    options?: RegisterOptions,
  ): Promise<{ digest: string; descriptor: ModelDescriptor; alreadyExisted: boolean }>;
  get(digest: string): Promise<ModelDescriptorRow | null>;
  getEnriched(digest: string): Promise<ModelDescriptor | null>;
  list(
    filter?: Parameters<NonNullable<StorageAdapter['listModelDescriptors']>>[0],
  ): Promise<ModelDescriptorRow[]>;
  listDescendants(parentDigest: string): Promise<ModelDescriptorRow[]>;
  computeModelDigest(path: string): ReturnType<typeof computeModelDigest>;
  /**
   * Append an annotation to a descriptor. Typed annotations require
   * `options.isAdmin: true`; `freeform-note` is open to any authenticated
   * actor.
   */
  annotate(
    digest: string,
    input: ModelAnnotateInput,
    options: ModelAnnotateOptions,
  ): Promise<ModelDescriptorAnnotationRow>;
  /** Bind a slug to a descriptor digest. Append-only; latest setAt wins on resolve. */
  setAlias(slug: string, digest: string, setBy: string): Promise<void>;
  /** Resolve a slug to its current digest, or null if no binding exists. */
  resolveAlias(slug: string): Promise<string | null>;
  /**
   * All annotations for a descriptor — exactly `GET /v1/models/:digest/annotations`.
   * Returns an empty array when no annotations exist.
   */
  getAnnotations(digest: string): Promise<ModelDescriptorAnnotationRow[]>;
  /**
   * Walk the parent DAG from `digest` leaf→root.
   * Exactly the REST contract: entries leaf→root, null ⇔ the route's 404.
   */
  getLineage(digest: string): Promise<import('@tzun/engine').ModelLineageEntry[] | null>;
  /**
   * Same walk as `getLineage`, plus why it stopped. `getLineage` returns the
   * same one-entry array for a base model and for a fine-tune whose parent is
   * not in the catalog; this distinguishes them via `complete` / `terminal`.
   */
  getLineageDetailed(digest: string): Promise<LineageWalkResult | null>;
}

/** Result of a pending attestation retry batch. */
export interface RetryResult {
  attempted: number;
  /** Records that now hold every configured component the retry obtains. */
  succeeded: number;
  /** Records still missing a configured component the retry obtains. */
  failed: number;
  details: Array<{
    evidenceId: string;
    success: boolean;
    error?: string;
    /** On a failed retry: the configured components the record still lacks. */
    stillMissing?: RetryObtainableComponent[];
  }>;
}

/** Options for `tzun.retryPendingAttestations()`. */
export interface RetryPendingOptions {
  /**
   * Most records to request attestation for (an integer >= 1). The pass
   * lists only records missing a component this instance obtains, so every
   * record it reads is one it requests for. Absent: every such record.
   */
  limit?: number;
}

export {
  DEFAULT_ATTESTATION_RETRY_INTERVAL_MS,
  DEFAULT_ATTESTATION_RETRY_BATCH_SIZE,
  DEFAULT_ATTESTATION_RETRY_MAX_BACKOFF_MS,
} from './attestation-retry-scheduler';
export type { AttestationRetryState } from './attestation-retry-scheduler';

/**
 * Options for `tzun.exportEvidence`.
 *
 * `walkLineage` defaults to `true` — a court-ready bundle should be
 * self-contained including the ancestor DAG, not just the leaf.
 */
export interface ExportEvidenceOptions {
  /** Bundle every ancestor descriptor (depth-limited, cycle-safe). Default: true. */
  walkLineage?: boolean;
  /** Identity recorded on the bundle's `exportedBy` field. Default: 'tzun-sdk'. */
  exportedBy?: string;
  /** Override the maximum number of descriptors walked (default: 16, mirrors verifier). */
  maxLineageDepth?: number;
  /**
   * What the bundle's `assertionProvenance` checks the record's WebAuthn
   * assertion against. Unset: the provenance is recorded and
   * every check reads "not checked". An export verifies no signature, so a
   * requirement the assertion meets is reported `null` /
   * `no_verified_signature`; one it fails is reported `false`.
   */
  assertion?: Pick<AssertionProvenanceOptions, 'allowedOrigins' | 'allowedTopOrigins' | 'requireDeviceBound'>;
}

/** Options for `tzun.exportBundle`. */
export interface ExportBundleOptions {
  /** Identity recorded as the bundle's `exporter.exportedBy`. Default: 'tzun-sdk'. */
  exportedBy?: string;
}

/**
 * What `Tzun.verify()` may check about a record's WebAuthn assertion, beyond
 * the binding it always checks.
 */
export interface VerifySignatureOptions {
  /** The registered public keys. Without it the signature is not checked (`no_credential_store`). */
  credentialStore?: CredentialStore;
  /** Origins the ceremony is allowed to have run on. Unset means unchecked. */
  allowedOrigins?: string[];
  /**
   * Top-level origins the ceremony may have run under, reported as
   * `assertionProvenance.topOriginValid`: `topOrigin` for a cross-origin
   * ceremony, the ceremony's own `origin` for one run directly in a tab.
   * Unset means unchecked.
   */
  allowedTopOrigins?: string[];
  /**
   * Require a single-device credential, reported as
   * `assertionProvenance.deviceBound`. A synced credential is a lower rung,
   * not a failed signature.
   */
  requireDeviceBound?: boolean;
  /** Relying Party ID the assertion must be scoped to. Unset means unchecked. */
  rpId?: string;
}

/**
 * What `Tzun.verify()` may use to decide a record's anchor (tzun-anchor/1
 * §10.2), beyond the record itself: the verifier's own inputs, none of which
 * comes from the artifact. Each one omitted leaves what it decides undecided,
 * never passed. On a local store the publication's heavy material (the raw
 * transaction, header, index and trie proof the scheduler stored at
 * finality) is joined in from the store, so an EVM publication needs only the
 * manifest and a header source to be `true`.
 */
export type VerifyAnchorOptions = Pick<
  AnchorVerifyOptions,
  'publisherManifest' | 'evmHeaderSources' | 'evmNetworks' | 'evmTimeoutMs' | 'publicationMaterial' | 'trustAnchorsPem' | 'authorities'
>;

/** Maximum descriptors walked in a single export (matches verifier / models-routes). */
const EXPORT_MAX_LINEAGE_DEPTH = 16;

/**
 * Tzun SDK — the developer-facing entry point for evidence capture.
 *
 * Usage:
 *   const tzun = await Tzun.init();
 *   const result = await tzun.capture({ aiOutput, humanAction, humanReason });
 *   const verification = await tzun.verify(result.envelope.payload.evidenceId);
 */
/**
 * The record a WebAuthn ceremony is about to sign, handed out BEFORE the
 * capture so the ceremony can be bound to it.
 *
 * A decision record's digest covers its sequence number and its predecessor's
 * digest, so it does not exist until the record is built at a position — which
 * is why the ordering has to be build → derive → ceremony → attach, and why
 * this type exists at all. `Tzun.prepareAssertionChallenge()` builds the record
 * the next `capture()` would build, without storing it, and hands back both
 * the digest and the challenge derived from it.
 *
 * Hand the whole object back as `capture(input, { prepared })`. It carries the
 * record's identity (`evidenceId`, `capturedAt`) because those are minted per
 * capture and are inside the digest: mint them again and the digest moves, and
 * the reviewer's signature is left pointing at a record that never existed.
 */
export interface PreparedAssertionChallenge {
  /** The canonical digest the record will carry, if the chain head has not moved. */
  digest: string;
  /** `webauthnChallengeForDigest(digest)` — hand to `startAuthentication(id, { digest })`. */
  challenge: string;
  /** The record id the capture must reuse. */
  evidenceId: string;
  /** The capture timestamp the capture must reuse (it is a hashed field). */
  capturedAt: string;
  /** The chain position this digest assumes. */
  sequenceNumber: number;
  /** The predecessor this digest assumes; `null` at genesis. */
  previousDigest: string | null;
  /**
   * The record's `signoffExpectation` (a hashed field): what
   * `prepareAssertionChallenge()` was given, or `null`. The capture reuses it.
   */
  signoffExpectation: SignatureRequiredExpectation | null;
  /**
   * The record's decider as resolved (its freshness reference and any
   * commitment are hashed). The capture resolves its input's decider again
   * with this freshness reference, and refuses `invalid_prepared` when the
   * result differs.
   */
  decider: Decider;
  /** The record's contributions as built, or `null`. The capture builds them again and refuses `invalid_prepared` when they differ. */
  contributions: Contributions | null;
  /** The record's links as built, or `null`. The capture builds them again and refuses `invalid_prepared` when they differ. */
  links: Link[] | null;
  /**
   * The opening of a committed decider, when `decider.commit` was given. The
   * capture commits with its salt, and the store keeps it when the capture
   * stores the record.
   */
  deciderOpening?: DeciderOpening;
}

/** Options for `Tzun#prepareAssertionChallenge`. */
export interface PrepareAssertionOptions {
  /** As `CaptureOptions.signoffExpectation`; the capture that uses the result reuses it. */
  signoffExpectation?: SignatureRequiredExpectation | null;
}

/** Per-capture options for `Tzun#capture`. */
export interface CaptureOptions {
  /**
   * A caller-chosen key that makes this capture at-most-once: retrying the same
   * decision under the same key returns the first capture's record instead of
   * storing a second one.
   *
   * Both transports honour it, and both compare the same fingerprint of the
   * caller's input (`captureIdempotencyFingerprint`, the platform's rule):
   *
   *   - local adapters claim the key atomically with the write
   *     (`StorageAdapter.storeIdempotent`), so a refused capture leaves the key
   *     free and two concurrent captures under one key store one record;
   *   - the cloud transport sends it as `Idempotency-Key` and the platform
   *     applies the same rule server-side.
   *
   * The same key with the SAME input replays: `stored: true` with
   * `replayed: true`, and locally `envelope` is the original record read back
   * from the store. The same key with DIFFERENT input is refused — failure type
   * `idempotency_conflict`, `retryable: false` — because the key already names
   * another decision.
   *
   * A key is kept for the life of the store: neither the platform nor the local
   * adapters expire one. An adapter that cannot claim a key locally (a custom
   * `StorageAdapter` without `storeIdempotent`) stores unconditionally, as
   * before.
   */
  idempotencyKey?: string;
  /**
   * The `prepareAssertionChallenge()` result the caller's WebAuthn ceremony
   * signed. Reusing it pins the record identity so the stored record is the
   * one the reviewer was shown.
   *
   * Its `evidenceId` must be a v4 UUID and its `capturedAt` an ISO-8601
   * date-time no more than five minutes ahead — the platform's rules for a
   * client-chosen identity. Anything else is refused as a
   * `validation_failure` naming the field, before the record is built.
   *
   * If the chain head moved between prepare and capture the rebuilt record has
   * a different digest, so the assertion binds a record that will never exist.
   * That is refused, not stored: `chain_conflict` with
   * `retryRefused: 'caller_attestation_is_digest_bound'`, the same answer the
   * CAS-retry path gives, because the same thing is true and the remedy is the
   * same — re-run the ceremony against the current head.
   */
  prepared?: PreparedAssertionChallenge;
  /**
   * What signature this record expects, written into its hashed
   * `payload.signoffExpectation` (Record §9.1, §9.2). Omitted or `null`:
   * none (the default). `{ policyDigest }`: a signature is required under the
   * sign-off policy with that digest (64 lowercase hex), whether it is attached
   * at this capture or later. Because the value is hashed, `verify()` then
   * reports a record that does not carry the signature it expects
   * (`signoffExpectationValid: null`, `signature_missing`), and a signature
   * stripped from it later reads the same way from the record alone.
   *
   * Anything else is refused as a `validation_failure` naming
   * `signoffExpectation`, before a sequence number is taken: another shape, an
   * unknown member, a digest that is not 64 lowercase hex. So is the session
   * form, `{ statementDigest, sessionSeq }`: it states that the record holds a
   * slot of a sign-off session, and only the capture that claimed that slot may
   * write it. This SDK opens no sign-off sessions.
   *
   * With `prepared`, the expectation is the one `prepareAssertionChallenge()`
   * was given (it is inside the digest the ceremony signed); a different one
   * here is refused.
   *
   * With `idempotencyKey`, a non-null expectation is part of the input the key
   * names: a retry under the key that asks for another expectation is an
   * `idempotency_conflict`, never a replay of a record that owes a different
   * signature.
   */
  signoffExpectation?: SignatureRequiredExpectation | null;
  /**
   * Capture under a mandate (Record §9.6): the record claims the
   * mandate's next slot and its running totals in the storing transaction,
   * and carries the mandate form of `signoffExpectation`, a `mandate` link to
   * the issuance record and `nonRepudiation.mandate`. The decider's kind is
   * `agent-mandated`. With `signoffExpectation` it is refused.
   */
  mandate?: { mandateId: string };
  /**
   * Refuse the capture (`freshness_required`) when the decider has no
   * finalized-block reference (Record §6.6). Implied for an
   * `agent-mandated` decider when anchoring is configured.
   */
  requireFreshness?: boolean;
}

/**
 * The verdict-carrying reads a storage layer offers when it has them:
 * `VerifyingStorageProxy` (computed locally) and `HttpStorageAdapter` (from the
 * server). The two answer to the same names on purpose — one branch in `get()`
 * and `list()` serves both.
 */
interface VerdictReads {
  retrieveWithVerdict(evidenceId: string): Promise<EvidenceRead | null>;
  listWithVerdicts(options?: import('@tzun/engine').ListOptions): Promise<EvidenceRead[]>;
}

/**
 * The per-record server round trips only a remote store has: the verdict with
 * the chain link measured against the predecessor the SERVER holds, and the
 * export bundle the server assembled. A local store computes both here, from
 * the records.
 */
interface RemoteRecordReads {
  verifyRecord(evidenceId: string): Promise<CloudVerification | null>;
  exportEvidence(evidenceId: string): Promise<CloudExportBundle | null>;
}

export class Tzun {
  private storage: StorageAdapter;
  private chain: EvidenceChain;
  private registry: SchemaRegistry;
  private mode: Mode;
  private defaultAiSystemId: string;
  private schemaVersion: string;
  private nextSequence: number;
  /** Tail of the per-instance capture queue — see runCaptureExclusive(). */
  private captureQueue: Promise<void> = Promise.resolve();
  /**
   * Upper bound on build-and-append attempts per capture before a moved head
   * is surfaced as a `chain_conflict` failure. See `captureLocked()`.
   */
  private chainConflictMaxAttempts: number = DEFAULT_CHAIN_CONFLICT_MAX_ATTEMPTS;
  private orchestrator: AttestationOrchestrator | null;
  /** The clients `orchestrator` was built from; the retry attests with them per component. */
  private attestationClients: AttestationClients;
  private attestationConfig: ValidatedAttestationConfig;
  /** Runs every pending-attestation retry pass, on its schedule or on request. */
  private attestationRetry: AttestationRetryScheduler<RetryResult>;

  /**
   * Which attestation components this instance's records are expected to
   * hold: the timestamp when it is configured to obtain one (`require` +
   * `deferrable`), and the anchor when it anchors its store (`anchoring`).
   * The expectation the engine's status rule is given, so a component
   * expected and not yet held lands as 'pending' rather than 'partial' or
   * 'none'. The retry pass obtains only the timestamp; the anchor scheduler
   * fills the anchor.
   */
  private get attestationExpects(): { timestamp: boolean; anchor: boolean } {
    const all = [...this.attestationConfig.require, ...this.attestationConfig.deferrable];
    return { timestamp: all.includes('timestamp'), anchor: this.anchorScheduler !== null };
  }
  /** The anchor scheduler `anchoring` runs on this instance's store; null when the instance does not anchor. */
  private anchorScheduler: AnchorScheduler | null = null;
  /** The finalized block of the anchoring chain, for decider freshness (Record §6.6); set when anchoring is configured. */
  private headerFollower: HeaderFollower | null = null;
  /** The follower's chain client, when this instance created it (closed with the instance). */
  private headerFollowerClient: { close(): void } | null = null;
  /** The JSON-RPC client this instance opened for its scanner's chain reads, closed after the scanner stops. */
  private scannerChainClient: { close(): void } | null = null;
  private closed = false;
  private eventBus: MonitoringEventBus | null = null;
  private tamperDetector: TamperDetector | null = null;
  private scanner: ScheduledScanner | null = null;
  private notificationRouter: NotificationRouter | null = null;
  private eventEmitterChannel: EventEmitterChannel | null = null;
  private recoveryManager: RecoveryManager;
  private activeChainId: string;
  private _models?: ModelsApi;
  private onLog: LogSink | undefined;
  /** The installed SDK extensions (`extension-points.ts`): each namespace and capture hook, stubs where none is installed. */
  private sdkExtensions: InstalledSdkExtensions;

  private constructor(
    storage: StorageAdapter,
    chain: EvidenceChain,
    registry: SchemaRegistry,
    mode: Mode,
    defaultAiSystemId: string,
    schemaVersion: string,
    nextSequence: number = 1,
    orchestrator: AttestationOrchestrator | null = null,
    attestationConfig: ValidatedAttestationConfig = { require: [], deferrable: [] },
    eventBus: MonitoringEventBus | null = null,
    tamperDetector: TamperDetector | null = null,
    scanner: ScheduledScanner | null = null,
    notificationRouter: NotificationRouter | null = null,
    eventEmitterChannel: EventEmitterChannel | null = null,
    activeChainId: string = 'default',
    onLog?: LogSink,
    attestationClients: AttestationClients = {},
    attestationRetryOptions: AttestationRetrySchedulerOptions = {},
  ) {
    this.storage = storage;
    this.chain = chain;
    this.registry = registry;
    this.mode = mode;
    this.defaultAiSystemId = defaultAiSystemId;
    this.schemaVersion = schemaVersion;
    this.nextSequence = nextSequence;
    this.orchestrator = orchestrator;
    this.attestationConfig = attestationConfig;
    this.eventBus = eventBus;
    this.tamperDetector = tamperDetector;
    this.scanner = scanner;
    this.notificationRouter = notificationRouter;
    this.eventEmitterChannel = eventEmitterChannel;
    this.activeChainId = activeChainId;
    this.onLog = onLog;
    this.attestationClients = attestationClients;
    this.attestationRetry = new AttestationRetryScheduler(
      (limit) => this.retryPendingPass(limit),
      { ...attestationRetryOptions, onLog },
    );
    this.recoveryManager = new RecoveryManager(storage, registry, eventBus ?? undefined);
    this.sdkExtensions = installSdkExtensions(this.extensionHost(), []);
  }

  /**
   * Initialize the Tzun SDK.
   *
   * Resolves deployment mode, creates the appropriate storage adapter,
   * and restores the evidence chain state.
   */
  static async init(config?: TzunConfig): Promise<Tzun> {
    // An `apiKey` property that is present but empty is almost always
    // `apiKey: process.env.<NAME>` with the variable unset or renamed.
    // Treating it as "no key" makes resolveMode infer `dev`, which selects
    // in-memory storage and reports `stored: true` for every capture. Fail
    // on the typo instead of failing open. Omitting the property entirely is
    // a legitimate non-cloud configuration.
    if (config !== undefined && 'apiKey' in config && !config.apiKey) {
      throw new Error(
        '[Tzun] `apiKey` was provided but is empty or undefined. ' +
        'Pass a non-empty `apiKey` to Tzun.init() (if you read it from an ' +
        'environment variable, check that the variable is set), or omit ' +
        '`apiKey` entirely for non-cloud modes — an empty key would silently ' +
        'fall back to in-memory storage.'
      );
    }
    const mode = resolveMode(config);
    // A deliberate security posture: on the HTTP transport the CLOUD CONTRACT
    // is server-side attestation — the backend attestation worker stamps
    // every ingested envelope. A default-on client-side TSA call
    // would add per-capture latency and a second TSA dependency without adding
    // evidence value, and a TSA outage would leave captures 'pending' on a
    // client that cannot list them to retry. An EXPLICIT attestation config is
    // still honored verbatim.
    const usesHttpTransport = Boolean(config?.apiKey);
    const attestationConfig: ValidatedAttestationConfig =
      usesHttpTransport && config?.attestation === undefined
        ? { require: [], deferrable: [] }
        : validateAttestationConfig(mode, config?.attestation, usesHttpTransport);
    const attestationRetryOptions = resolveAttestationRetryOptions(
      mode,
      attestationConfig,
      config?.attestation?.retry,
      usesHttpTransport,
    );
    const schemaVersion = config?.schemaVersion ?? 'v1.0';
    const aiSystemId = config?.aiSystemId ?? 'default';
    // Validated up front, like the empty-apiKey check above: a bound of 0 or
    // NaN would silently turn every contended capture into a dropped one,
    // which is the failure this option exists to prevent.
    const chainConflictMaxAttempts =
      config?.chainConflictMaxAttempts ?? DEFAULT_CHAIN_CONFLICT_MAX_ATTEMPTS;
    if (!Number.isInteger(chainConflictMaxAttempts) || chainConflictMaxAttempts < 1) {
      throw new Error(
        '[Tzun] `chainConflictMaxAttempts` must be an integer >= 1 ' +
        `(got ${String(config?.chainConflictMaxAttempts)}). It bounds how many ` +
        'times capture() rebuilds a record after another writer moved the chain head.',
      );
    }
    const registry = new SchemaRegistry();
    const chain = new EvidenceChain();

    // Storage resolution is independent of mode.
    // Mode controls attestation enforcement, not storage backend.
    //
    // Priority:
    //   0. config.apiKey → cloud HTTP transport (selection is by the PRESENCE
    //      of apiKey, independent of `mode`). apiKey
    //      alone → default base URL; apiKey + apiUrl → that base URL. Captures
    //      are POSTed to the backend's `POST /v1/evidence`; the server is
    //      authoritative for chain/sequence/digest.
    //   1. config.dbUrl → PostgreSQL (explicit config wins)
    //   2. config.dbPath → SQLite (explicit config wins)
    //   3. DATABASE_URL env → PostgreSQL (env var fallback, see test-mode note below)
    //   4. mode === 'local' with no explicit storage → SQLite (default path)
    //   5. Else → in-memory (with warning for non-dev modes)
    //
    // Test-mode env-var guard:
    // Under Jest (`JEST_WORKER_ID` set) the `DATABASE_URL` fallback is
    // suppressed by default. Without this guard, an integration-suite
    // invocation like `DATABASE_URL=... npm test` would cause every test
    // that calls `Tzun.init()` (~18 files) to open a Postgres pool, blowing
    // past `max_connections` and polluting test isolation. Tests that
    // specifically exercise the env-var-fallback wiring opt back in via
    // `config._readDatabaseUrlEnv: true`.
    let storage: StorageAdapter;

    const shouldReadDatabaseUrlEnv =
      !process.env.JEST_WORKER_ID || config?._readDatabaseUrlEnv === true;

    // `anchoring` and `logNamespace` are checked in every branch before its
    // store is opened, with a message for that store: a config
    // refused here creates no file and makes no connection. That covers the
    // namespace half of the activation guard, since `anchoring` needs a
    // namespace. `anchoring` is refused on the memory adapter and the cloud
    // transport. A namespace is given to the store, which mints a new identity
    // with it and refuses a different one on an existing store: `logNamespace`,
    // or `anchoring.namespace` when only that is given. What needs the
    // publisher (its address against the manifest, the signer answering) is
    // checked once the store is open, and a refusal there closes it again.
    let anchoring: ResolvedAnchoringConfig | null = null;
    const storageExtensions = config?._storageExtensions as readonly StorageExtension[] | undefined;
    const logOptions = (
      store: 'memory' | 'sqlite' | 'postgres',
    ): { logNamespace?: string; extensions?: readonly StorageExtension[] } => {
      const logNamespace = logNamespaceFor(config, store) ?? anchoring?.namespace;
      return {
        ...(logNamespace === undefined ? {} : { logNamespace }),
        ...(storageExtensions === undefined ? {} : { extensions: storageExtensions }),
      };
    };
    if (config?.apiKey) {
      // Cloud HTTP transport, selected purely by the presence of an API key.
      // `apiUrl` overrides the default managed base URL.
      anchoringConfigFor(config, 'cloud');
      logNamespaceFor(config, 'cloud');
      const transport = new HttpTransport({
        apiKey: config.apiKey,
        apiUrl: config.apiUrl,
        ...(config.apiTimeoutMs !== undefined ? { timeoutMs: config.apiTimeoutMs } : {}),
        fetchFn: config._httpFetchFn,
      });
      storage = new HttpStorageAdapter(transport);
    } else if (config?.dbUrl) {
      anchoring = anchoringConfigFor(config, 'postgres');
      storage = await openPostgresStore(config.dbUrl, logOptions('postgres'));
    } else if (config?.dbPath) {
      anchoring = anchoringConfigFor(config, 'sqlite');
      await refuseSqliteStoreBeforeSignoffExpectation(config.dbPath);
      storage = new SqliteStorageAdapter(config.dbPath, logOptions('sqlite'));
    } else if (shouldReadDatabaseUrlEnv && process.env.DATABASE_URL) {
      anchoring = anchoringConfigFor(config, 'postgres');
      storage = await openPostgresStore(process.env.DATABASE_URL, logOptions('postgres'));
    } else if (mode === 'local') {
      anchoring = anchoringConfigFor(config, 'sqlite');
      const dbPath = './tzun.db';
      await refuseSqliteStoreBeforeSignoffExpectation(dbPath);
      storage = new SqliteStorageAdapter(dbPath, logOptions('sqlite'));
    } else if (mode !== 'dev') {
      // Reached only when a production mode has no credential and no
      // database of any kind. Refuse to start rather than warn and fall back
      // to memory: a process on in-memory storage boots, answers healthily,
      // and returns `stored: true` for every decision while the evidence
      // lives in RAM until the next deploy. The message names the API key
      // first, because for a cloud deployment that is the missing piece.
      throw new Error(
        `[Tzun] Mode "${mode}" has no persistent storage configured. ` +
        'Pass `apiKey` for the managed backend, `dbUrl` (or set ' +
        'DATABASE_URL) for PostgreSQL, or `dbPath` for SQLite. ' +
        'In-memory storage is available in dev mode only, and would lose ' +
        'every captured decision when the process exits.'
      );
    } else {
      anchoringConfigFor(config, 'memory');
      storage = new MemoryStorageAdapter(logOptions('memory'));
    }

    // Demo tamper hooks, condition 1 of 2: arm them BEFORE the proxy wrap so
    // the sentinel write hits the real store, not the proxy.
    if (config?.demoTamperHooks === true && 'armDemoTamperHooks' in storage) {
      await (storage as { armDemoTamperHooks(): Promise<void> }).armDemoTamperHooks();
    }

    const attestationClients =
      usesHttpTransport && config?.attestation === undefined
        ? null // zero TSA I/O — no orchestrator built (the posture above)
        : buildAttestationClients(attestationConfig, config?.attestation);
    const orchestrator = attestationClients
      ? new AttestationOrchestrator({ ...attestationClients, onLog: config?.onLog })
      : null;

    // Set up monitoring if enabled
    let monitoringBus: MonitoringEventBus | null = null;
    let monitoringDetector: TamperDetector | null = null;
    let monitoringScanner: ScheduledScanner | null = null;
    let scannerChainClient: JsonRpcEvmChain | null = null;
    let monitoringRouter: NotificationRouter | null = null;
    let monitoringEmitter: EventEmitterChannel | null = null;

    const monitoringConfig = config?.monitoring;

    // Cloud transport: refuse the features that can only pretend to work here.
    //
    // `ScheduledScanner` and read verification both need to READ records back.
    // The cloud adapter cannot — there is no API-key-authenticated read route
    // on the backend — so a scanner there would emit `scan_completed` with zero
    // records checked and zero issues on every pass, forever, over evidence it
    // had never fetched. A customer alerting on `issuesFound > 0` would be
    // alerting on a constant. Refusing at init turns a silent false "healthy"
    // into a loud configuration error.
    if (usesHttpTransport && monitoringConfig?.enabled && monitoringConfig.scanner) {
      throw new Error(
        'Tzun.init: monitoring.scanner is not supported on the cloud transport ' +
          '(apiKey set). A pass walks a chain by sequence number and enumerates the ' +
          "store's chains, and that transport serves neither — it serves the four " +
          'per-record customer reads and nothing that walks a range — so the scanner ' +
          'would report "0 issues" on every pass without checking anything. Remove ' +
          'monitoring.scanner, or run verification against a local adapter ' +
          '(dbUrl / dbPath).',
      );
    }
    if (usesHttpTransport && config?.verifyReads === true) {
      throw new Error(
        'Tzun.init: verifyReads is not supported on the cloud transport ' +
          '(apiKey set). It switches on the verifying storage proxy, which wraps a ' +
          'LOCAL adapter and recomputes each record as it comes out of it; there is ' +
          'no local adapter here to wrap. A cloud read is not unverified — ' +
          'get() and list() carry the verdict the server computed, and verify() ' +
          'recomputes the record in this process against the predecessor the server ' +
          'measured against. Remove verifyReads, or run against a local adapter ' +
          '(dbUrl / dbPath) to have this process do the recomputing on every read.',
      );
    }

    if (monitoringConfig?.enabled) {
      monitoringBus = new MonitoringEventBus();
    }

    // Read verification: every local adapter is wrapped in the
    // verifying proxy unless `verifyReads: false`, so every get() and list()
    // carries a verdict, and a tampered read is reported on the monitoring bus
    // when there is one. Wrapped before the monitoring subsystem below is given
    // the store, so its reads go through the proxy too.
    if (config?.verifyReads ?? !usesHttpTransport) {
      storage = new VerifyingStorageProxy(storage, monitoringBus, registry);
    }

    if (monitoringConfig?.enabled && monitoringBus) {
      const monitoringRegistry = new SchemaRegistry();

      // Create event emitter channel (always available when monitoring is enabled)
      monitoringEmitter = new EventEmitterChannel();

      // Build notification channels
      const channels: Array<{ channel: NotificationChannel; severities: TamperSeverity[] }> = [];
      channels.push({
        channel: monitoringEmitter,
        severities: ['critical', 'warning', 'info'],
      });

      const notifications = monitoringConfig.notifications;
      if (notifications?.webhook) {
        channels.push({
          channel: new WebhookChannel(notifications.webhook),
          severities: notifications.webhook.severities,
        });
      }
      if (notifications?.slack) {
        channels.push({
          channel: new SlackChannel(notifications.slack),
          severities: notifications.slack.severities,
        });
      }
      if (notifications?.pagerduty) {
        channels.push({
          channel: new PagerDutyChannel(notifications.pagerduty),
          severities: notifications.pagerduty.severities,
        });
      }
      if (notifications?.email) {
        channels.push({
          channel: new EmailChannel(notifications.email),
          severities: ['critical', 'warning', 'info'],
        });
      }

      monitoringRouter = new NotificationRouter({ channels });

      // Create tamper detector and wire it to the notification router
      monitoringDetector = new TamperDetector(monitoringBus, storage);
      monitoringDetector.onIncident((incident) => {
        monitoringRouter!.dispatch(incident).catch((err) => {
          console.error('[Tzun] Notification dispatch error:', err);
        });
      });

      // Create scanner if configured
      if (monitoringConfig.scanner) {
        // On an instance that anchors, the scanner checks the store against
        // what was published: the publisher's chain is its header source and
        // where it reads P and the wallet's transaction count, the manifest
        // says who publishes, and the cadence's T_max is how long a logged
        // record may wait for its epoch. It only reads the chain; the key
        // stays with the publisher.
        let scannerDeps = {};
        if (anchoring) {
          const given = config?._anchorChainClient as EvmChainClient | undefined;
          if (given === undefined) scannerChainClient = new JsonRpcEvmChain(anchoring.evm.rpcUrl, eip155ChainId(anchoring.evm.chain));
          scannerDeps = { anchoring: scannerAnchoringDeps(anchoring, given ?? (scannerChainClient as JsonRpcEvmChain)) };
        }
        monitoringScanner = new ScheduledScanner(
          storage, monitoringBus, monitoringRegistry, monitoringConfig.scanner, scannerDeps,
        );

        // Wire scan_completed events to the public `tzun.on('scan.completed')`
        // emitter. The scanner records the pass on its state BEFORE emitting,
        // so `lastCompletedPass` is this pass, and forwarding it as-is is what
        // makes the summary a subscriber sees the same object
        // `GET /v1/integrity/status` reports as `lastFullScan`.
        //
        // A second ScanSummary built here from the event plus `getState()`
        // would be a second answer to "what did the last pass measure": a
        // `passNumber` read at emit time, a `completedAt` from another
        // `new Date()` that does not equal `lastCompletedPassAt`, and no
        // presence or validity counts.
        monitoringBus.subscribe((event) => {
          if (event.type === 'scan_completed') {
            const last = monitoringScanner!.getState().lastCompletedPass;
            if (last) monitoringEmitter!.emitScanCompleted(last);
          }
        });
      }
    }

    const tzun = new Tzun(
      storage, chain, registry, mode, aiSystemId, schemaVersion,
      1, orchestrator, attestationConfig,
      monitoringBus, monitoringDetector, monitoringScanner,
      monitoringRouter, monitoringEmitter,
      'default',
      config?.onLog,
      attestationClients ?? {},
      attestationRetryOptions,
    );

    tzun.chainConflictMaxAttempts = chainConflictMaxAttempts;
    tzun.scannerChainClient = scannerChainClient;

    // Which chain this instance writes evidence into.
    //
    // `config.chainId` names it outright: one chain per
    // instance, many chains per store, which is the Python SDK's shape. With a
    // chain named there is nothing to resolve, so the two refusals below do not
    // arise — naming a chain IS the remedy they ask for — but a chain the store
    // records as sealed is still refused, because it accepts no records.
    //
    // Without one, the chain is resolved from the store, and the adapter is not
    // allowed to guess: a store whose chains are all sealed, or with several
    // chains open for appends, throws NoActiveChainError /
    // AmbiguousActiveChainError here, naming the rows. Answering the first
    // case with 'default' would, on a forked store, aim every capture at the
    // sealed chain while the process reported itself healthy. Failing here, not on
    // the first capture, is the same posture as the storage checks above: a
    // process that cannot record evidence must not come up reporting that it
    // can. The store handle is released before the error leaves, so a caller
    // that retries after repairing the rows does not fight its own lock.
    let activeChainId: string;
    try {
      activeChainId = config?.chainId ?? (await storage.getActiveChainId());
      if (config?.chainId !== undefined) {
        await assertNamedChainAppendable(storage, config.chainId);
      }
    } catch (err) {
      await storage.close?.().catch(() => { /* the resolution error is the one to report */ });
      throw err;
    }
    tzun.activeChainId = activeChainId;

    // The chain's head, read after the chain is known: every head in the store
    // is per chain, so restoring one before knowing which chain would restore
    // whichever chain happened to be named 'default'.
    await tzun.restoreChain();

    // The anchor scheduler, on the store as the rest of the SDK sees it (the
    // verifying proxy forwards the log and anchor stores). Created before the
    // first capture, so every record this instance stores expects an anchor.
    // It reads the store's identity and applies the activation guard here; it touches no chain until its first pass. A refusal
    // releases the store before it leaves, as the chain resolution above does.
    if (anchoring && config) {
      try {
        await tzun.openAnchoring(anchoring, config);
      } catch (err) {
        await storage.close?.().catch(() => { /* the anchoring error is the one to report */ });
        throw err;
      }
    }
    // The SDK extensions (mandates, the agent catalog, links), installed on
    // the instance as it will serve captures.
    tzun.sdkExtensions = installSdkExtensions(
      tzun.extensionHost(),
      (config?._sdkExtensions as readonly SdkExtensionFactory[] | undefined) ?? DEFAULT_SDK_EXTENSIONS,
    );

    // The SDK's own scanner is deliberately left UNSCOPED, which means "one
    // bounded pass per chain in the store", not "one interleaved pass over
    // the union of them". Scoping it to `activeChainId` here would stop
    // the false-tamper flood on a forked store — but by no longer looking at
    // the sealed chain at all, and a sealed chain is the read-only remainder
    // of a fork, which is exactly where an insider would tamper. That trades a
    // false alarm for a missed one, the worse of the two errors for an
    // evidence store. `setChainScope()` stays available for a caller that owns
    // one scanner per chain and wants to divide the work.
    //
    // FULL COVERAGE HERE IS A PRODUCT DECISION, NOT AN OVERSIGHT. Ending
    // sealed-chain monitoring is not acceptable, because scoping it away buys
    // silence by not looking. If you are here to narrow this, that is a
    // product decision to reopen, not a cleanup to land.
    //
    // Pinned by `tests/ts/sdk-scanner-sealed-chain-coverage.test.ts`. Note what
    // that file exists for: adding `setChainScope(activeChainId)` on this line
    // does NOT fail the fork tests in `tests/ts/post-fork-scanning.test.ts`,
    // because those fork within one `Tzun.init()`, so the chain this method saw
    // as active is the one the fork later SEALS — the scope lands on the sealed
    // chain and the live one goes dark instead. The regression that actually
    // ends sealed-chain monitoring needs a RESTART on an already-forked store,
    // which is the ordinary deployed shape and what that file builds.

    // A scanner configured with a schedule runs on it. Started last, once init
    // can no longer fail, so a throw above never leaves a loop running against
    // a store the caller never received. The loop logs and survives a failed
    // pass, and its timer is unref'd, so it never holds the process open.
    if (
      monitoringScanner &&
      monitoringScanner.isScheduled() &&
      monitoringConfig?.scanner?.autoStart !== false
    ) {
      void monitoringScanner.start();
    }

    // The pending-attestation retry, on the same terms: started last, an
    // unref'd timer, and a failed pass does not end it. It has a schedule by
    // default in a production mode on a local store with a deferrable
    // component (see resolveAttestationRetryOptions), and runs independently
    // of the scanner, which may be disabled.
    if (
      tzun.attestationRetry.isScheduled() &&
      config?.attestation?.retry?.autoStart !== false
    ) {
      void tzun.attestationRetry.start();
    }

    // The anchor scheduler, on the same terms: a pass every tick, an unref'd
    // timer, backing off while passes fail. `anchoring.autoStart: false` leaves
    // it to `anchorNow()`.
    if (tzun.anchorScheduler && anchoring?.autoStart) {
      void tzun.anchorScheduler.start();
      tzun.headerFollower?.start();
    }

    return tzun;
  }

  /**
   * Create the anchor scheduler for `anchoring` on this instance's store, and
   * the store's anchor log with it: from here the store expects an anchor for
   * every record, so `get()` reports `awaiting_epoch` from the first capture
   * rather than from the first epoch.
   */
  private async openAnchoring(anchoring: ResolvedAnchoringConfig, config: TzunConfig): Promise<void> {
    const raw = config.anchoring as NonNullable<TzunConfig['anchoring']>;
    const client = config._anchorChainClient as EvmChainClient | undefined;
    const scheduler = await createAnchorScheduler({
      storage: this.storage,
      config: { ...raw, namespace: raw.namespace ?? config.logNamespace },
      // What this instance's records are expected to hold once it anchors: the
      // expectation a fill recomputes their status with.
      expectation: { ...this.attestationExpects, anchor: true },
      ...(client !== undefined && { publisher: await publisherFor(anchoring.evm, client) }),
      ...(config.onLog && { onLog: config.onLog }),
    });
    try {
      await anchorStoreFor(this.storage)!.ensureStoreLog(ANCHOR_LOG_KIND);
    } catch (err) {
      await scheduler.close().catch(() => { /* the store's error is the one to report */ });
      throw err;
    }
    this.anchorScheduler = scheduler;

    // The header follower reads the anchoring chain's finalized block, which
    // capture copies into a decider's freshness, and shares it through a
    // Postgres store's anchor_freshness row. It runs on the scheduler's
    // schedule (autoStart), and `anchorNow()` reads once more before its pass.
    const followerClient = client ?? new JsonRpcEvmChain(anchoring.evm.rpcUrl, eip155ChainId(anchoring.evm.chain));
    if (client === undefined) this.headerFollowerClient = followerClient;
    this.headerFollower = new HeaderFollower(followerClient, {
      chain: anchoring.evm.chain,
      ...(raw.freshnessMaxAgeMs !== undefined && { maxAgeMs: raw.freshnessMaxAgeMs }),
      ...(freshnessRowStoreFor(this.getStorage()) && { row: freshnessRowStoreFor(this.getStorage())! }),
      recheck: {
        source: { newest: (limit: number) => this.storage.list({ limit, order: 'desc', chainId: this.activeChainId }) },
        report: (event) => this.emitMonitoringEvent(event),
      },
      onError: (error) =>
        sdkLog(this.onLog, 'header_follower_read_failed', {
          errorName: error instanceof Error ? error.name : typeof error,
          errorMessage: error instanceof Error ? error.message : String(error),
        }),
    });
  }

  /** Restore this instance's in-memory head from its own chain's stored head. */
  private async restoreChain(): Promise<void> {
    const lastDigest = await this.storage.getLastDigest(this.activeChainId);
    if (lastDigest) {
      this.chain.restore(lastDigest);
    }
    const lastSequence = await this.storage.getLastSequence(this.activeChainId);
    this.nextSequence = lastSequence + 1;
  }

  /**
   * Get the current deployment mode.
   */
  getMode(): Mode {
    return this.mode;
  }

  /**
   * Recovery API for handling tamper incidents.
   * Three tiers: annotate (default) -> relink (admin) -> fork (last resort).
   */
  get recovery(): RecoveryAPI {
    return {
      annotate: (incidentId: string, options: AnnotateOptions) =>
        this.recoveryManager.annotate(incidentId, options),
      relink: (incidentId: string, options: RelinkOptions) =>
        this.recoveryManager.relink(incidentId, options),
      fork: async (incidentId: string, options: ForkOptions) => {
        const result = await this.recoveryManager.fork(incidentId, options);
        // Point this instance at the new chain and start it at sequence 1.
        //
        // Nothing is reset in the store. Chain state is per chain, so the new
        // chain has no head row until its first record and already restores as
        // empty, while the chain the fork sealed KEEPS its high-water mark —
        // which is what makes a record deleted from its tail detectable
        // afterwards. A reset here would destroy the sealed chain's bound in
        // the fork that sealed it, leaving `chainUpperBound()` to recover it
        // from the fork record.
        this.activeChainId = result.newChain.chainId;
        this.chain = new EvidenceChain();
        this.nextSequence = 1;
        // No `setChainScope()` here on purpose. The next pass already picks
        // the new chain up — it re-resolves the store's chains every pass —
        // and it keeps scanning the chain this fork just sealed, which is the
        // whole point of forking after a suspected compromise.
        return result;
      },
    };
  }

  /**
   * AI-BOM model catalog API. Register descriptors, look them up canonically
   * or with annotation history applied, list/filter the catalog, walk
   * derivation DAGs, compute weight digests, append annotations, and manage
   * slug aliases.
   */
  get models(): ModelsApi {
    if (!this._models) {
      this._models = {
        register: async (d, o) => {
          const result = await registerModel(this.storage, d, o);
          sdkLog(this.onLog, 'registration', {
            digest: result.digest,
            source: o?.source ?? 'manual',
            registeredBy: o?.registeredBy ?? 'cli',
            alreadyExisted: result.alreadyExisted,
          });
          return result;
        },
        get: (digest) => this.storage.getModelDescriptor!(digest),
        getEnriched: (digest) => this.storage.getEnrichedModelDescriptor!(digest),
        list: (filter) => this.storage.listModelDescriptors!(filter),
        listDescendants: (p) => this.storage.listDescendantDescriptors!(p),
        computeModelDigest: (p) => computeModelDigest(p),
        annotate: (digest, input, options) =>
          annotateModelDescriptor(this.storage, digest, input, options),
        setAlias: (slug, digest, setBy) =>
          this.storage.setModelDescriptorAlias!(slug, digest, setBy),
        resolveAlias: (slug) => this.storage.resolveModelDescriptorAlias!(slug),
        getAnnotations: (digest) =>
          this.storage.listModelDescriptorAnnotations
            ? this.storage.listModelDescriptorAnnotations(digest)
            : Promise.resolve([]),
        getLineage: (digest) => walkLineage(this.storage, digest),
        getLineageDetailed: (digest) => walkLineageDetailed(this.storage, digest),
      };
    }
    return this._models;
  }

  /**
   * Capture an evidence record.
   *
   * Before any sequence number is taken, the input is shape-checked and its
   * members resolved once (`resolveMembers`): the decider (its identifier,
   * its freshness reference, a commitment), the contributions (each step's
   * model descriptor registered or looked up, then built), the agent
   * references (the agent catalog's hook), the links (the link hook resolves
   * same-store targets, then `buildLinks`), and a mandate's claim (the
   * mandate hook). Then, under the per-instance capture lock, for each
   * append attempt:
   *   1. Build the payload at the chain's next position (a mandate's slot is
   *      planned here) and compute its digest
   *   2. Check the decider against the material presented with it
   *   3. Attest the digest: the RFC 3161 token, when a timestamp is
   *      configured, plus the caller's pre-verified inputs
   *   4. Check required attestations — return a FailureRecord if any is missing
   *   5. Assemble the envelope with the attestation artifacts
   *   6. Store it (with a mandate claim and a decider opening, in the same
   *      transaction), then advance the chain head and sequence
   *
   * A capture performs no chain I/O. An anchor is published for a batch of
   * stored records, never obtained by a capture, so nothing under the lock
   * waits on a chain; a freshness reference is the header follower's last
   * reading.
   */
  async capture(input: CaptureInput, options?: CaptureOptions): Promise<CaptureResult> {
    // Shape check, before anything is built or hashed: a refused input takes
    // no sequence number and never reaches storage. The expectation is
    // settled here, before the first await: the check copies the caller's
    // value and judges the copy, and the capture hashes that copy, so a
    // caller that changes its object (or a getter that answers differently)
    // while the capture runs cannot put an unchecked value in the record.
    const settled = settleSignoffExpectation(options);
    const violation =
      captureInputViolation(input) ??
      preparedIdentityViolation(options?.prepared) ??
      ('violation' in settled ? settled.violation : null) ??
      (options?.mandate !== undefined && options?.prepared !== undefined
        ? resolutionRefusal('prepared', 'prepared_with_mandate', 'a capture under a mandate is not prepared for a signature')
        : null);
    if (violation) return this.refused(violation);

    const signoffExpectation = 'expectation' in settled ? settled.expectation : null;
    const request: CaptureRequest = {
      input: { ...input, aiSystemId: input.aiSystemId ?? this.defaultAiSystemId },
      signoffExpectation,
      ...(options?.idempotencyKey !== undefined && { idempotencyKey: options.idempotencyKey }),
      ...(options?.prepared !== undefined && { prepared: options.prepared }),
      ...(options?.mandate !== undefined && { mandate: { mandateId: options.mandate.mandateId } }),
      ...(options?.requireFreshness !== undefined && { requireFreshness: options.requireFreshness }),
    };
    // Serialise the whole reserve -> build -> attest -> store -> advance
    // sequence on this instance. Everything up to `store()` is derived from
    // `this.chain` / `this.nextSequence`, and both are read, then awaited
    // across (attestation round trips, store I/O), then written — so without
    // this mutex two overlapping `capture()` calls would each reserve the SAME
    // sequence number and the SAME predecessor digest. The adapter's
    // `expectChainHead` check makes the second write fail rather than
    // duplicate; this mutex makes it not need to, by letting the second
    // capture read the head the first one left behind.
    const result = await this.runCaptureExclusive(() => this.captureLocked(request));
    // Read after the lock is released: the leaf was written in the storing
    // transaction, and the read holds up no other capture.
    return this.withCapturedLogPosition(result);
  }

  /** A capture refused before anything was built: recorded, and returned `stored: false`. */
  private async refused(violation: CaptureInputViolation, failureType = 'validation_failure'): Promise<CaptureResult> {
    const failure: FailureRecord = {
      failureType,
      diagnosticMetadata: { ...violation },
      capturedAt: new Date().toISOString(),
    };
    await this.recordFailure(failure);
    return { envelope: {} as EvidenceEnvelope, stored: false, failure };
  }

  /**
   * Build the record the next `capture()` would build, without storing it, and
   * hand back the challenge a WebAuthn ceremony must sign to be about it.
   *
   * **The ceremony comes after the record is built.** A decision record's
   * canonical digest covers its `sequenceNumber`, its `evidenceId` and its
   * `capturedAt`, so the digest does not exist until the record has been built
   * at a chain position.
   * A ceremony started before that can only sign a nonce, and a signature over
   * a nonce verifies against every record equally, which is the same as
   * verifying against none. So:
   *
   * ```ts
   * const prepared = await tzun.prepareAssertionChallenge(input);
   * const options  = await webauthn.startAuthentication(credId, { digest: prepared.digest });
   * //   → options.challenge === prepared.challenge; the browser signs it
   * const { artifact } = await webauthn.verifyAssertion(response, { digest: prepared.digest });
   * await tzun.capture({ ...input, attestationInputs: { webauthnAssertion: artifact } },
   *                    { prepared });
   * ```
   *
   * The resolved members are fixed here and handed back in the result: the
   * decider (its freshness reference is hashed, so the signer signs over it,
   * and a commitment's opening), the contributions and the links. The capture
   * resolves them again from its input, with the prepared freshness reference
   * and opening salt, and refuses `invalid_prepared` when they differ.
   *
   * Nothing is reserved and nothing is written, except what resolving a
   * member writes: an inline model descriptor is registered (register-if-
   * absent). If another writer appends between prepare and capture, the
   * record is rebuilt at the next position, its digest changes, and the
   * capture is REFUSED rather than storing an assertion that binds a record
   * which will never exist — the caller re-runs the ceremony.
   *
   * @throws Error naming the refusal, when `capture()` would refuse the input.
   */
  async prepareAssertionChallenge(
    input: CaptureInput,
    options?: PrepareAssertionOptions,
  ): Promise<PreparedAssertionChallenge> {
    const settled = settleSignoffExpectation({ signoffExpectation: options?.signoffExpectation });
    const violation = captureInputViolation(input) ?? ('violation' in settled ? settled.violation : null);
    if (violation) {
      throw new Error(`[Tzun] prepareAssertionChallenge: ${violation.field}: ${violation.message}`);
    }
    const signoffExpectation = 'expectation' in settled ? settled.expectation : null;
    return this.prepareRequest({
      input: { ...input, aiSystemId: input.aiSystemId ?? this.defaultAiSystemId },
      signoffExpectation,
    });
  }

  /** `prepareAssertionChallenge` for a request already shape-checked. */
  private prepareRequest(request: CaptureRequest): Promise<PreparedAssertionChallenge> {
    // Queued behind any in-flight capture so the head this reads is coherent
    // with the one the next capture will see. It mutates no chain state.
    return this.runCaptureExclusive(async () => {
      const resolved = await this.resolveMembers(request);
      if ('failure' in resolved) {
        const meta = resolved.failure.diagnosticMetadata;
        throw new Error(`[Tzun] prepareAssertionChallenge: ${String(meta.field)}: ${String(meta.message ?? meta.reason)}`);
      }
      const members = resolved.members;
      const previousDigest = this.chain.getLastDigest() ?? undefined;
      const sequenceNumber = this.nextSequence;
      const identity: RecordIdentity = { evidenceId: randomUUID(), capturedAt: new Date().toISOString() };
      let payload: EvidencePayload;
      try {
        payload = this.buildPayloadAt(request, members, sequenceNumber, identity, request.signoffExpectation);
      } catch (error) {
        const v = engineRefusal(error);
        if (v) throw new Error(`[Tzun] prepareAssertionChallenge: ${v.field}: ${v.message}`);
        throw error;
      }
      const digest = this.digestOf(payload);
      return {
        digest,
        challenge: webauthnChallengeForDigest(digest),
        evidenceId: identity.evidenceId,
        capturedAt: identity.capturedAt,
        sequenceNumber,
        previousDigest: previousDigest ?? null,
        // Copies: the caller holds none of the objects hashed into the record.
        signoffExpectation: request.signoffExpectation === null ? null : { ...request.signoffExpectation },
        decider: { ...members.decider },
        contributions: members.contributions === null ? null : (toJsonDataModel(members.contributions) as Contributions),
        links: members.links === null ? null : (toJsonDataModel(members.links) as Link[]),
        ...(members.deciderOpening !== null && { deciderOpening: { ...members.deciderOpening } }),
      };
    });
  }

  /**
   * `SdkHost.captureSystemRecord`: a `tzun:mandate` or `tzun:link` record
   * through the capture pipeline. The record's `aiSystemId` is its kind's
   * reserved id; the rest is resolved and stored as any capture's.
   */
  private async captureSystemRecord(
    request: SystemRecordCapture,
    options: SystemRecordCaptureOptions = {},
  ): Promise<CaptureResult> {
    const built = systemCaptureRequest(request, options);
    if ('violation' in built) return this.refused(built.violation);
    const prepared = preparedIdentityViolation(options.prepared);
    if (prepared) return this.refused(prepared);
    const result = await this.runCaptureExclusive(() => this.captureLocked(built.request));
    return this.withCapturedLogPosition(result);
  }

  /** `SdkHost.prepareSystemRecord`: the system record `captureSystemRecord(request)` would build next. */
  private async prepareSystemRecord(request: SystemRecordCapture): Promise<PreparedAssertionChallenge> {
    const built = systemCaptureRequest(request, {});
    if ('violation' in built) {
      throw new Error(`[Tzun] prepareSystemRecord: ${built.violation.field}: ${built.violation.message}`);
    }
    return this.prepareRequest(built.request);
  }

  /**
   * Resolve a capture's members once, before any sequence number is taken
   * (Record §6 to §8), in this order: the decider, the
   * contributions, the agent references, the links. A refusal is returned as
   * the failure `capture()` reports; nothing is stored.
   */
  private async resolveMembers(
    request: CaptureRequest,
  ): Promise<{ members: ResolvedMembers } | { failure: FailureRecord }> {
    const { input } = request;
    const failed = (v: CaptureInputViolation | CaptureRefusal, failureType?: string): { failure: FailureRecord } => ({
      failure: {
        failureType: failureType ?? ('failureType' in v && typeof v.failureType === 'string' ? v.failureType : 'validation_failure'),
        diagnosticMetadata: isCaptureRefusal(v)
          ? { field: v.field, reason: v.code, code: v.code, message: v.message, ...(v.details ?? {}) }
          : { ...v },
        capturedAt: new Date().toISOString(),
      },
    });
    const ctx: CaptureHookContext = {
      host: this.extensionHost(),
      ...(request.idempotencyKey !== undefined && { idempotencyKey: request.idempotencyKey }),
    };
    const aiOutput = toJsonDataModel(input.aiOutput) as Record<string, unknown>;
    // aiOutput must have canonical bytes before anything is built over it (a
    // step's output digest names them): a value the canonical serializer
    // refuses throws here and is reported as a serialization_failure.
    canonicalSerialize({ aiOutput }, ['aiOutput']);

    const decided = await this.resolveDecider(request);
    if ('violation' in decided) return failed(decided.violation);
    const { decider, opening } = decided;

    let contributions: Contributions | null = null;
    if (input.contributions != null) {
      const models = await this.resolveStepModels(input.contributions);
      if ('violation' in models) return failed(models.violation, models.failureType);
      try {
        contributions = buildContributions(
          committedDecideActor(models.contributions, input.decider, decider),
          { decider, action: input.action, reason: input.reason, aiOutput },
        );
      } catch (error) {
        const v = engineRefusal(error);
        if (v) return failed(v);
        throw error;
      }
    }

    const agentRefusal = await this.sdkExtensions.agents.captureHook.checkReferences(agentReferences(decider, contributions), ctx);
    if (agentRefusal) return failed(agentRefusal);

    let links: Link[] | null = null;
    if (input.links != null) {
      const linkInputs = toJsonDataModel(input.links) as LinkInput[];
      const held = await this.sdkExtensions.links.captureHook.resolveTargets(linkInputs, ctx);
      if (isCaptureRefusal(held)) return failed(held);
      const openings = await this.commitmentOpenings(decider, opening, held);
      try {
        links = buildLinks(linkInputs, {
          held,
          openCommitment: (cmt) => openings.get(cmt) ?? null,
          ...(request.allowReserved !== undefined && { allowReserved: request.allowReserved }),
          ...(request.linkRecord === true && { linkRecord: true }),
          context: {
            aiSystemId: input.aiSystemId,
            action: input.action,
            decider,
            contributions,
            aiOutput,
            signoffExpectation: request.signoffExpectation,
          },
        });
      } catch (error) {
        const v = engineRefusal(error);
        if (v) return failed(v);
        throw error;
      }
    }

    return { members: { decider, deciderOpening: opening, contributions, links } };
  }

  /**
   * The identifiers the `cmt:` deciders of a capture's link rules commit to
   * (Record §6.3; the `reviews` rule of Record §8.3): the capture's own
   * decider from its opening, and each held record's from the store's
   * `decider_openings`, kept only when the opening verifies against the
   * commitment. A commitment this store cannot open is left out, and its
   * rule stays undetermined.
   */
  private async commitmentOpenings(
    decider: Decider,
    opening: DeciderOpening | null,
    held: ReadonlyArray<HeldLinkTarget | null>,
  ): Promise<Map<string, string>> {
    const openings = new Map<string, string>();
    const ownId = (decider as { id?: unknown }).id;
    if (opening !== null && typeof ownId === 'string' && verifyDeciderOpening(ownId, opening)) openings.set(ownId, opening.id);
    if (typeof this.storage.getDeciderOpening !== 'function') return openings;
    for (const target of held) {
      if (target === null) continue;
      const d = target.payload.decider;
      const id = isPlainObject(d) ? d.id : undefined;
      const evidenceId = target.payload.evidenceId;
      if (typeof id !== 'string' || identifierScheme(id) !== 'cmt' || openings.has(id) || typeof evidenceId !== 'string') continue;
      const stored = await this.storage.getDeciderOpening(evidenceId);
      if (stored && verifyDeciderOpening(id, stored)) openings.set(id, stored.id);
    }
    return openings;
  }

  /**
   * The record's decider, from the caller's `DeciderInput` (Record §6.3,
   * §6.6): an agent kind without an `id` gets `desc:<agent>`; freshness
   * `'auto'` (the default) is the header follower's reference or `null`;
   * `requireFreshness` (implied for `agent-mandated` when anchoring is
   * configured) refuses a decider without one; `commit: true` replaces the
   * identifier with its `cmt:` commitment, with a salt derived from the
   * store's secret under an idempotency key and random otherwise. Checked
   * with the engine's `deciderViolation`.
   *
   * For a prepared capture, `'auto'` freshness is the prepared decider's
   * reference and a commitment's salt is the prepared opening's: the two
   * values a resolution does not reproduce, fixed when the ceremony's record
   * was built.
   */
  private async resolveDecider(
    request: CaptureRequest,
  ): Promise<{ decider: Decider; opening: DeciderOpening | null } | { violation: CaptureInputViolation }> {
    const d = request.input.decider as DeciderInput;
    const prepared = request.prepared;
    const agent = d.agent ?? null;
    let id = d.id;
    if (id === undefined && d.kind !== 'human' && typeof agent === 'string') id = defaultAgentDeciderId(agent);
    let freshness: string | null;
    if (d.freshness === undefined || d.freshness === 'auto') {
      freshness = prepared ? ((prepared.decider as { freshness?: string | null }).freshness ?? null) : await this.currentFreshnessReference();
    } else {
      freshness = d.freshness;
    }
    const required = request.requireFreshness === true || (d.kind === 'agent-mandated' && this.headerFollower !== null);
    if (required && freshness === null) {
      return {
        violation: resolutionRefusal(
          'decider.freshness',
          'freshness_required',
          'a finalized-block reference is required for this capture and none younger than freshnessMaxAgeMs is available',
        ),
      };
    }
    let opening: DeciderOpening | null = null;
    if (d.commit !== undefined && d.commit !== false && d.commit !== true) {
      return { violation: resolutionRefusal('decider.commit', 'invalid_identifier', 'decider.commit must be true or false') };
    }
    if (d.commit === true) {
      if (typeof id !== 'string' || !isKnownSchemeIdentifier(id) || identifierScheme(id) === 'cmt') {
        return {
          violation: resolutionRefusal(
            'decider.id',
            'invalid_identifier',
            'decider.commit needs decider.id to be an identifier of another scheme to commit to',
          ),
        };
      }
      if (typeof this.storage.getDeciderCommitmentSecret !== 'function') { // pragma: allowlist secret (a method name, not a secret)
        return {
          violation: resolutionRefusal(
            'decider.commit',
            'commitment_not_supported_by_store',
            'this store does not keep commitment openings; pass a cmt: identifier you computed, and keep its opening',
          ),
        };
      }
      let salt: string;
      if (prepared) {
        const held = prepared.deciderOpening;
        if (!isPlainObject(held) || typeof held.salt !== 'string') {
          return {
            violation: resolutionRefusal(
              'prepared.deciderOpening',
              'invalid_prepared',
              'a prepared capture under decider.commit carries the opening prepareAssertionChallenge() returned',
            ),
          };
        }
        salt = held.salt;
      } else {
        salt =
          request.idempotencyKey !== undefined
            ? deciderCommitmentSalt(await this.storage.getDeciderCommitmentSecret(), request.idempotencyKey, id)
            : randomBytes(DECIDER_COMMITMENT_SALT_BYTES).toString('base64url');
      }
      opening = { salt, id };
      id = deciderCommitment(id, salt);
    }
    const decider = {
      kind: d.kind,
      id,
      agent,
      credential: d.credential ?? null,
      freshness,
    } as Decider;
    const issue = deciderViolation(decider);
    if (issue) return { violation: resolutionRefusal(issue.field, issue.code, issue.message) };
    return { decider, opening };
  }

  /**
   * Each step's `aiBom`, in the pre-built form `buildContributions` takes
   * (Record §7.4): an inline descriptor is registered through
   * the catalog (register-if-absent) and replaced with its digest; a
   * pre-built digest must be in the catalog (`descriptor_not_registered`);
   * absent nullable members are written as `null`.
   */
  private async resolveStepModels(
    input: ContributionsInput,
  ): Promise<{ contributions: ContributionsInput } | { violation: CaptureInputViolation; failureType?: string }> {
    const raw = toJsonDataModel(input) as ContributionsInput;
    if (!Array.isArray(raw.steps)) return { contributions: raw };
    const steps: ContributionStepInput[] = [];
    for (let i = 0; i < raw.steps.length; i++) {
      const step = raw.steps[i];
      if (!isPlainObject(step) || step.aiBom == null || !isPlainObject(step.aiBom)) {
        steps.push(step);
        continue;
      }
      const field = `contributions.steps[${i}].aiBom`;
      const bom = step.aiBom as AiBom | AiBomWithInlineDescriptor;
      if (isInlineDescriptorForm(bom)) {
        const cannotRegister = {
          violation: resolutionRefusal(
            field,
            'invalid_step_ai_bom',
            `${field} carries an inline model descriptor, and this store cannot register one: register it first and pass its modelDescriptorDigest`,
          ),
        };
        if (typeof this.storage.registerModelDescriptor !== 'function') return cannotRegister;
        let digest: string;
        try {
          ({ digest } = await this.storage.registerModelDescriptor(bom.modelDescriptor, 'connector-auto', 'capture:inline-descriptor'));
        } catch (error) {
          // The cloud transport against a platform that does not serve the
          // model catalog: the same answer as an adapter without one.
          if (isModelCatalogUnsupported(error)) return cannotRegister;
          throw error;
        }
        const { modelDescriptor: _descriptor, ...rest } = bom;
        steps.push({ ...step, aiBom: fillAiBomNulls({ ...rest, modelDescriptorDigest: digest }) as AiBom });
        continue;
      }
      const digest = (bom as AiBom).modelDescriptorDigest;
      const row =
        typeof digest === 'string' && typeof this.storage.getModelDescriptor === 'function'
          ? await this.storage.getModelDescriptor(digest)
          : null;
      if (!row) {
        // The cloud transport against a platform that has just answered that
        // it does not serve the model catalog: neither remedy of the first
        // wording is open there.
        const cloudWithoutCatalog =
          this.storage instanceof HttpStorageAdapter && this.storage.modelCatalogKnownAbsent();
        return {
          failureType: 'descriptor_not_registered',
          violation: {
            ...resolutionRefusal(
              `${field}.modelDescriptorDigest`,
              'descriptor_not_registered',
              typeof this.storage.getModelDescriptor !== 'function'
                ? `this store does not implement getModelDescriptor, so ${field}.modelDescriptorDigest cannot be checked`
                : cloudWithoutCatalog
                  ? `this store cannot check ${field}.modelDescriptorDigest: the platform does not serve the model catalog`
                  : `${field}.modelDescriptorDigest is not in the catalog: register the descriptor before capture, or pass it inline`,
            ),
            modelDescriptorDigest: typeof digest === 'string' ? digest : null,
          } as CaptureInputViolation,
        };
      }
      steps.push({ ...step, aiBom: fillAiBomNulls(bom) as AiBom });
    }
    return { contributions: { ...raw, steps } };
  }

  /**
   * The body of {@link capture}, run under the per-instance capture mutex,
   * for a caller's capture and a system record alike.
   *
   * `request.signoffExpectation` is the value `capture()` settled before its
   * first await: a hashed field, so every rebuild at a new chain position
   * keeps it. For a `prepared` capture it is the one the ceremony's digest
   * covers; the prepared agent references are checked against this store's
   * catalog, and the members resolved from the input must equal the prepared
   * ones.
   */
  private async captureLocked(request: CaptureRequest): Promise<CaptureResult> {
    // Hoisted out of the try so the catch below can attribute the failure to a
    // specific record. A FailureRecord with no `evidenceId` cannot be
    // correlated with anything downstream.
    let envelope: EvidenceEnvelope | undefined;
    // How many build-and-append attempts were made, for the failure record:
    // "refused once" and "refused ten times in a row" are different operational
    // facts, and the second one is what tells an operator their replica count
    // has outgrown `chainConflictMaxAttempts`.
    let attempts = 0;
    // Set when a refusal could have been retried but must not be (see the
    // catch inside the loop). Surfaced on the failure record so the caller
    // can tell "the SDK gave up" from "the SDK must not try": the second is
    // resolved by re-running their ceremony, not by a larger bound.
    let retryRefused: RetryRefusedReason | undefined;
    const prepared = request.prepared;

    try {
      // The members, resolved once before the first attempt. For a prepared
      // capture they must also equal the prepared ones, which are inside the
      // digest the ceremony signed.
      if (prepared) {
        // The prepared agent references, checked against this store's
        // catalog: a prepared object may come from another instance or
        // store, or have been altered with its digest recomputed, so a
        // reference this catalog does not hold is refused here as it is on
        // an unprepared capture.
        const agentRefusal = await this.sdkExtensions.agents.captureHook.checkReferences(
          agentReferences(prepared.decider, prepared.contributions ?? null),
          {
            host: this.extensionHost(),
            ...(request.idempotencyKey !== undefined && { idempotencyKey: request.idempotencyKey }),
          },
        );
        if (agentRefusal) return this.refusedByHook(agentRefusal);
      }
      const resolved = await this.resolveMembers(request);
      if ('failure' in resolved) {
        await this.recordFailure(resolved.failure);
        return { envelope: {} as EvidenceEnvelope, stored: false, failure: resolved.failure };
      }
      const members: ResolvedMembers = resolved.members;
      if (prepared) {
        // A prepared object is the caller's, so its members are never taken
        // unchecked: they are resolved again from this capture's input, with
        // every rule a capture applies (the decider grammar, the step models,
        // the agent catalog, the link targets and the reserved relations),
        // and must be the same values.
        const moved = preparedMemberMismatch(prepared, members);
        if (moved) return this.refused(moved);
      }

      // A mandate's claim, opened once; its slot is planned per attempt.
      let mandateClaim: MandateCaptureClaim | null = null;
      if (request.mandate) {
        const opened = await this.sdkExtensions.mandates.captureHook.open(request.mandate, {
          host: this.extensionHost(),
          ...(request.idempotencyKey !== undefined && { idempotencyKey: request.idempotencyKey }),
        });
        if (isCaptureRefusal(opened)) return this.refusedByHook(opened);
        mandateClaim = opened;
      }

      // Build → append, as a bounded compare-and-swap loop.
      //
      // The sequence number and the chain link are both hashed into the
      // record, so a capture has to pick them BEFORE it can compute the digest
      // (and attest it), and the store enforces them on the way in via
      // `expectChainHead`. Inside one process the mutex in `capture()` keeps
      // the head we hold current. Across processes it cannot: a second replica
      // of the customer's service on the same DATABASE_URL, a second `Tzun` on
      // the same SQLite file, or a second client on one cloud chain appends
      // between our read and our write, and the adapter — doing exactly its
      // job — refuses our record. A CAS that is refused is retried against
      // the value it lost to: adopt the head the refusal reported, rebuild at
      // the next position, append again — bounded by
      // `chainConflictMaxAttempts` — then give up LOUDLY with a typed,
      // `retryable: true` failure that names both heads. A mandate's slot is
      // a compare-and-swap of the same kind, retried the same way.
      //
      // Re-attesting on each attempt is deliberate. An attestation covers a
      // digest, the digest covers the sequence number, and the record carrying
      // the old sequence number was never stored — so the old attestation is
      // evidence of nothing, and one extra TSA round trip is the price of not
      // losing the decision.
      //
      // The record's identity is minted ONCE, here, not per attempt. A retry
      // is the same decision at a new chain position: the sequence, link and
      // digest change; `evidenceId` and `capturedAt` do not. A `prepared`
      // capture reuses the identity `prepareAssertionChallenge()` minted,
      // because the reviewer's ceremony signed a challenge derived from a
      // digest that covers both fields.
      const identity: RecordIdentity = prepared
        ? { evidenceId: prepared.evidenceId, capturedAt: prepared.capturedAt }
        : { evidenceId: randomUUID(), capturedAt: new Date().toISOString() };
      let mandateResult: CaptureResult['mandate'];
      for (let attempt = 1; ; attempt++) {
        attempts = attempt;

        // Get the previous digest for chain linking
        const previousDigest = this.chain.getLastDigest() ?? undefined;

        // Reserve sequence number before assembly (increment only after confirmed store)
        const sequenceNumber = this.nextSequence;

        const built = await this.buildRecordAt(request, members, mandateClaim, sequenceNumber, previousDigest, identity);
        if ('failure' in built) {
          await this.recordFailure(built.failure);
          return { envelope: {} as EvidenceEnvelope, stored: false, failure: built.failure };
        }
        envelope = built.envelope;
        mandateResult = built.mandate?.result;

        // A prepared capture whose record moved. The reviewer signed
        // `webauthnChallengeForDigest(prepared.digest)`; this record has a
        // different digest, so the assertion is about a record that will never
        // exist. Refusing here — before the store attempt — is the same
        // judgement the CAS path makes below, reached one step earlier because
        // we can already see the digest moved. Storing it would produce
        // genuine evidence that reads as forged.
        if (prepared && envelope.integrity.canonicalDigest !== prepared.digest) {
          retryRefused = 'caller_attestation_is_digest_bound';
          sdkLog(this.onLog, 'capture_prepared_record_moved', {
            evidenceId: envelope.payload.evidenceId,
            attempt,
            reason: retryRefused,
            preparedDigest: prepared.digest,
            actualDigest: envelope.integrity.canonicalDigest,
            preparedSequence: prepared.sequenceNumber,
            actualSequence: sequenceNumber,
          });
          throw new ChainConflictError(
            { sequence: prepared.sequenceNumber - 1, digest: prepared.previousDigest },
            { sequence: sequenceNumber - 1, digest: previousDigest ?? null },
          );
        }

        // The store options this record is stored with: the conditional
        // append, a mandate's claim, a decider opening, and a system record's
        // own (an issuance or a revocation), read fresh for this attempt.
        let extraStoreOptions: Pick<StoreOptions, 'mandateIssue' | 'mandateRevoke'> = {};
        if (request.storeOptions) {
          const extra = await request.storeOptions({ envelope });
          if (isCaptureRefusal(extra)) return this.refusedByHook(extra, envelope.payload.evidenceId);
          extraStoreOptions = extra;
        }
        // Conditional append. The sequence number and chain link are hashed
        // into this record's digest, so they were chosen before the write; if
        // the head has moved since, this record does not belong at that
        // position and the adapter must refuse it rather than write a second
        // record at the same sequence.
        const expectChainHead = { sequence: sequenceNumber - 1, digest: previousDigest ?? null };
        const storeOptions: StoreOptions = {
          expectChainHead,
          ...(built.mandate && { mandateClaim: built.mandate.claim }),
          ...(members.deciderOpening !== null && { deciderOpening: members.deciderOpening }),
          ...extraStoreOptions,
        };
        // The key's claim on the store, when the caller named one and the
        // adapter can claim it. The fingerprint is over the caller's input, so
        // every attempt of one capture computes the same value: a retry after a
        // lost answer replays, while a rebuild at a new chain position does not
        // read as different input.
        const claim = this.idempotencyClaimFor(request.idempotencyKey, envelope);
        // The receipt a claim was answered with when the key was already taken.
        let replayed: IdempotencyReceipt | undefined;
        try {
          if (claim) {
            // Claim-or-replay, atomically with the write. A
            // refusal throws out of here exactly as `store()` would, leaving
            // the key unclaimed, so the CAS retry below applies unchanged.
            const outcome = await this.storage.storeIdempotent!(envelope, this.activeChainId, {
              idempotency: claim,
              ...storeOptions,
            });
            if (outcome.kind === 'conflict') {
              throw new IdempotencyConflictError(claim.key);
            }
            if (outcome.kind === 'replay') {
              replayed = outcome.receipt;
            }
          } else {
            // Store the envelope — sequence and chain state are updated atomically in storage
            await this.storage.store(envelope, this.activeChainId, {
              ...(request.idempotencyKey ? { idempotencyKey: request.idempotencyKey } : {}),
              ...storeOptions,
            });
          }
        } catch (error) {
          // A refusal of a mandate's claim, or of a system record's own
          // compare-and-swap: lost to another writer (rebuild and go round),
          // or terminal (a refusal the caller sees).
          const claimClassified = mandateClaim ? mandateClaim.classifyStoreError(error) : null;
          const ownClassified = claimClassified === null && request.classifyStoreError ? request.classifyStoreError(error) : null;
          const classified = claimClassified ?? ownClassified;
          if (classified !== null && classified !== 'retry') {
            return this.refusedByHook(classified, envelope.payload.evidenceId);
          }
          // Anything but a moved head (or a lost claim) is thrown as the
          // adapter threw it: a duplicate evidence id is a
          // DuplicateRecordError and an append to a sealed chain a
          // ChainSealedError, and buildCaptureFailure() gives each its own
          // failure type.
          const conflict = classified === 'retry' ? { claimLost: true } : describeChainConflict(error);
          if (!conflict) throw error;

          // A caller-supplied WebAuthn assertion signed a challenge derived
          // from THIS record's digest (`webauthnChallengeForDigest`). The
          // rebuilt record has a different digest, because the sequence number
          // is hashed, so re-attaching the assertion would store a signature
          // that verifies `challenge_mismatch` against its own record: genuine
          // evidence that reads as forged. The SDK cannot re-run a human
          // ceremony, so the refusal is surfaced instead of retried: the caller
          // re-signs against the head we lost to (adopted on the way out, in
          // the outer catch) and captures again. A `signerIdentity` is an IdP
          // token, not a signature over the digest, so it is not in this rule.
          const callerAssertion =
            request.input.attestationInputs?.webauthnAssertion;
          // A system record's own compare-and-swap (a revocation's state
          // close) lost to a claim on another chain: this chain's head did not
          // move, so the rebuilt record has the same digest (checked against
          // `prepared.digest` at the top of the loop) and the assertion still binds.
          if (callerAssertion != null && !(ownClassified === 'retry' && prepared)) {
            retryRefused = 'caller_attestation_is_digest_bound';
            sdkLog(this.onLog, 'capture_chain_conflict_retry_refused', {
              evidenceId: envelope.payload.evidenceId,
              attempt,
              maxAttempts: this.chainConflictMaxAttempts,
              reason: retryRefused,
              ...conflict,
            });
            throw error;
          }

          if (attempt >= this.chainConflictMaxAttempts) {
            sdkLog(this.onLog, 'capture_chain_conflict_exhausted', {
              evidenceId: envelope.payload.evidenceId,
              attempts: attempt,
              maxAttempts: this.chainConflictMaxAttempts,
              ...conflict,
            });
            throw error;
          }

          // Adopt the head we lost to, then go around. A local adapter's error
          // carries the head as read inside the adapter's own atomic section —
          // fresher and more coherent than a second round trip, which reads
          // digest and sequence in two statements and can tear between them.
          // The cloud adapter learned the server's head from the 409 body;
          // `resyncChainFromStore()` reads it back from there.
          if (error instanceof ChainConflictError) {
            this.adoptHead(error.actual);
          } else {
            await this.resyncChainFromStore();
          }
          sdkLog(this.onLog, 'capture_chain_conflict_retry', {
            evidenceId: envelope.payload.evidenceId,
            attempt,
            maxAttempts: this.chainConflictMaxAttempts,
            nextSequence: this.nextSequence,
            ...conflict,
          });
          continue;
        }

        // The key was already taken by an earlier capture of this decision, so
        // nothing was stored and the caller gets the record that exists — read
        // back from the store, not the one this attempt built. The receipt
        // names it; the envelope behind it is what the caller asked for, and
        // the two differ in `evidenceId`, `sequenceNumber` and digest because
        // this attempt minted its own identity at its own chain position.
        if (replayed) {
          const original = await this.storage.retrieve(replayed.evidenceId);
          if (!original) {
            // The key names a record the store no longer holds. Capturing a
            // second record under a key that already answered once would defeat
            // the key, so this is refused — the platform's
            // `missing_replay_target`.
            throw new IdempotencyConflictError(claim!.key, 'missing_replay_target');
          }
          // The store's head may have moved since our first capture under this
          // key (other writers, or another process). Adopt it so the next
          // capture links from a head that exists.
          await this.resyncChainFromStore();
          sdkLog(this.onLog, 'capture_idempotency_replay', {
            idempotencyKey: claim!.key,
            evidenceId: replayed.evidenceId,
            chainId: replayed.chainId,
            sequence: replayed.sequenceNumber,
            canonicalDigest: replayed.canonicalDigest,
            discardedEvidenceId: envelope.payload.evidenceId,
            note:
              'This capture was answered by the first capture under this key. ' +
              'Nothing was stored; CaptureResult.envelope is the record that exists.',
          });
          return { envelope: original, stored: true, replayed: true };
        }

        // Update chain and sequence state only after confirmed store — from the
        // STORE'S head, not from what we submitted. On local adapters the two
        // are the same value; on the cloud transport the backend re-stamps
        // `partial` captures onto its own locked head, so the digest it
        // committed (and the sequence it assigned) can differ from ours.
        const head = await this.readStoredHead();
        this.chain.restore(head.digest ?? envelope.integrity.canonicalDigest);
        this.nextSequence = (head.sequence > 0 ? head.sequence : sequenceNumber) + 1;
        break;
      }

      const extras: Pick<CaptureResult, 'deciderOpening' | 'mandate'> = {
        ...(members.deciderOpening !== null && { deciderOpening: { ...members.deciderOpening } }),
        ...(mandateResult !== undefined && { mandate: mandateResult }),
      };
      const serverReceipt = this.readRemoteReceipt();
      if (serverReceipt) {
        // A cloud replay. The platform answers a retried keyed capture with the
        // FIRST success's receipt and strips its own replay flag from the
        // single-capture response, so the only thing that says a replay
        // happened is the receipt naming a different record.
        if (serverReceipt.evidenceId !== envelope.payload.evidenceId) {
          sdkLog(this.onLog, 'capture_idempotency_replay', {
            ...(request.idempotencyKey ? { idempotencyKey: request.idempotencyKey } : {}),
            evidenceId: serverReceipt.evidenceId,
            chainId: serverReceipt.chainId,
            sequence: serverReceipt.sequence,
            canonicalDigest: serverReceipt.canonicalDigest,
            discardedEvidenceId: envelope.payload.evidenceId,
            note:
              'The server answered this capture with the first capture under this key. ' +
              'Nothing was stored; CaptureResult.serverReceipt names the record that exists ' +
              'and CaptureResult.envelope is only the submitted form.',
          });
          return { envelope, stored: true, serverReceipt, replayed: true };
        }
        this.warnOnReceiptDivergence(envelope, serverReceipt);
        return { envelope, stored: true, serverReceipt, ...extras };
      }

      return { envelope, stored: true, ...extras };
    } catch (error) {
      // Resync the local chain view from the store before reporting the
      // failure. On a rejected cloud capture the adapter has just learned the
      // server's real head from the 409 body; without adopting it here the
      // next capture would link from the same stale head and be rejected
      // again. On local adapters the store did not move, so this is a no-op
      // re-read of the same values.
      await this.resyncChainFromStore();

      const failure: FailureRecord = buildCaptureFailure(
        error,
        envelope?.payload.evidenceId,
        attempts,
        retryRefused,
      );
      await this.recordFailure(failure);
      return {
        envelope: {} as EvidenceEnvelope,
        stored: false,
        failure,
      };
    }
  }

  /** A capture an extension hook refused: recorded, and returned `stored: false`. */
  private async refusedByHook(refusal: CaptureRefusal, evidenceId?: string): Promise<CaptureResult> {
    const failure: FailureRecord = {
      failureType: refusal.failureType,
      ...(evidenceId !== undefined && { evidenceId }),
      diagnosticMetadata: {
        field: refusal.field,
        reason: refusal.code,
        code: refusal.code,
        message: refusal.message,
        ...(refusal.details ?? {}),
      },
      capturedAt: new Date().toISOString(),
    };
    await this.recordFailure(failure);
    return { envelope: {} as EvidenceEnvelope, stored: false, failure };
  }

  /**
   * Persist a FailureRecord, best-effort.
   *
   * Every caller of this is on a path that has already decided the capture
   * failed and is about to return `{ stored: false }`. Persisting the failure
   * record is bookkeeping; it must never become the thing that turns a
   * gracefully-dropped capture into a thrown error. Both SQLite and Postgres
   * `storeFailure` are real writes that throw on any DB error — which is
   * exactly the situation in which `store()` has just thrown — and one of
   * these call sites is inside a catch block, where a throw propagates out of
   * `capture()` entirely. That breaks the contract that a capture failure
   * never throws and never changes the response surface: the wrapped
   * vendor call would reject with a raw `pg`/`SQLITE_*` error *after* the LLM
   * had already answered, losing the model output and the human decision
   * along with the evidence.
   *
   * A failure we could not even record is itself worth a log line, so the
   * swallow is not silent.
   */
  private async recordFailure(failure: FailureRecord): Promise<void> {
    try {
      await this.storage.storeFailure(failure);
    } catch (error) {
      sdkLog(this.onLog, 'failure_record_unpersisted', {
        failureType: failure.failureType,
        errorName: error instanceof Error ? error.name : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * `result` with `logPosition`: where the store's evidence log holds the
   * record a capture stored, or, for a replay, the original record. Unchanged
   * for a capture that stored nothing and on a store without evidence logs
   * (the cloud transport). The record is stored whatever this read does, so a
   * read that fails leaves the result without a position and is logged,
   * rather than turning a stored capture into a failed one that a caller
   * would capture again.
   */
  private async withCapturedLogPosition(result: CaptureResult): Promise<CaptureResult> {
    const evidenceId = result.stored ? result.envelope.payload?.evidenceId : undefined;
    const logs = logStoreFor(this.getStorage());
    if (!logs || typeof evidenceId !== 'string') return result;
    try {
      const position = await logs.getEvidenceLogPosition(evidenceId);
      return position ? { ...result, logPosition: recordLogPosition(position) } : result;
    } catch (error) {
      sdkLog(this.onLog, 'capture_log_position_unread', {
        evidenceId,
        errorName: error instanceof Error ? error.name : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
      return result;
    }
  }

  /**
   * Re-point the in-memory chain/sequence at whatever the store now reports.
   *
   * Best-effort: a secondary read failure must never mask the primary capture
   * error, so it is swallowed and the local view is simply left alone.
   */
  private async resyncChainFromStore(): Promise<void> {
    try {
      this.adoptHead(await this.readStoredHead());
    } catch {
      /* leave the local view as-is */
    }
  }

  /**
   * Re-point the in-memory chain/sequence at a head the store has reported —
   * either read back from it, or carried on the `ChainConflictError` that
   * refused an append (which is the head as seen inside the adapter's own
   * atomic section, the most trustworthy value there is).
   */
  private adoptHead(head: { digest: string | null; sequence: number }): void {
    if (head.digest === null) {
      // The store reports no head at all (a virgin chain, or a chain reset
      // under us). Linking from our stale digest would conflict forever.
      this.chain = new EvidenceChain();
    } else {
      this.chain.restore(head.digest);
    }
    this.nextSequence = head.sequence + 1;
  }

  /**
   * Build the record that would sit at `sequenceNumber`, linked from
   * `previousDigest` — attesting its digest first when an orchestrator is
   * configured. Pure with respect to chain state: it reads none and advances
   * none, so `captureLocked()` can call it once per append attempt. The
   * record's `identity` (evidenceId, capturedAt) and its resolved `members`
   * are the same on every build of one capture.
   *
   * Under a mandate the payload is built twice: once with its links as
   * resolved and no expectation, for the mandate's claim to plan its slot
   * against, and again with the plan's expectation and links.
   *
   * Returns a `FailureRecord` instead of an envelope when the record is one a
   * writer refuses (an engine rule, the decider's material, a mandate's
   * plan) or a REQUIRED attestation could not be obtained.
   */
  private async buildRecordAt(
    request: CaptureRequest,
    members: ResolvedMembers,
    mandateClaim: MandateCaptureClaim | null,
    sequenceNumber: number,
    previousDigest: string | undefined,
    identity: RecordIdentity,
  ): Promise<{ envelope: EvidenceEnvelope; mandate?: MandateAttemptPlan } | { failure: FailureRecord }> {
    const refuse = (v: CaptureInputViolation): { failure: FailureRecord } => ({
      failure: {
        failureType: 'validation_failure',
        evidenceId: identity.evidenceId,
        diagnosticMetadata: { ...v },
        capturedAt: new Date().toISOString(),
      },
    });
    let payload: EvidencePayload;
    let plan: MandateAttemptPlan | undefined;
    try {
      if (mandateClaim) {
        // The claim is planned over the payload as built so far, before the
        // writer rules run: an agent-mandated decider contradicts every
        // expectation but the mandate form, which the plan supplies.
        const planned = await mandateClaim.plan(this.draftPayloadAt(request, members, sequenceNumber, identity));
        if (isCaptureRefusal(planned)) {
          return {
            failure: {
              failureType: planned.failureType,
              evidenceId: identity.evidenceId,
              diagnosticMetadata: {
                field: planned.field,
                reason: planned.code,
                code: planned.code,
                message: planned.message,
                ...(planned.details ?? {}),
              },
              capturedAt: new Date().toISOString(),
            },
          };
        }
        plan = planned;
        payload = this.buildPayloadAt(request, { ...members, links: plan.links }, sequenceNumber, identity, plan.signoffExpectation);
      } else {
        payload = this.buildPayloadAt(request, members, sequenceNumber, identity, request.signoffExpectation);
      }
    } catch (error) {
      const v = engineRefusal(error);
      if (v) return refuse(v);
      throw error;
    }
    const digest = this.digestOf(payload);

    // The decider against the material presented with it (Record §6.5): an
    // agent kind with a human's assertion over this record, or an `acct`
    // decider whose account is not the assertion's credential's user.
    const assertion = request.input.attestationInputs?.webauthnAssertion;
    const materialIssue = deciderMaterialViolation(payload.decider, {
      digest,
      assertion,
      assertionUserId: await this.assertionUserId(assertion),
    });
    if (materialIssue) return refuse(resolutionRefusal(materialIssue.field, materialIssue.code, materialIssue.message));

    const artifacts: AttestationArtifacts = this.orchestrator
      ? await this.orchestrator.attest(digest, request.input.attestationInputs)
      : // No orchestrator — dev-mode path. Still pass through any attestation
        // inputs provided directly by the caller (e.g. WebAuthn assertions the
        // caller has already verified).
        request.input.attestationInputs
        ? {
            webauthnAssertion: request.input.attestationInputs.webauthnAssertion,
            signerIdentity: request.input.attestationInputs.signerIdentity,
          }
        : {};
    if (request.extraAttestation?.mandateIssuance) artifacts.mandateIssuance = request.extraAttestation.mandateIssuance;
    if (plan) artifacts.mandate = plan.block;
    for (const key of ['mandate', 'mandateIssuance'] as const) {
      const block = artifacts[key];
      if (block === undefined) continue;
      const blockIssue = mandateBlockViolation(block, `nonRepudiation.${key}`);
      if (blockIssue) return refuse(resolutionRefusal(blockIssue.field, blockIssue.code, blockIssue.message));
    }

    // Is the assertion — whoever supplied it — actually about THIS record?
    const signatureBound = this.evaluateAssertionBinding(artifacts, digest, identity.evidenceId);

    // Enforce required attestations. `require: ['webauthn']` means a BOUND
    // assertion: an unbound one attests nothing, so accepting it would make
    // the strictest configuration the product offers the easiest to satisfy.
    const requiredFailure = this.checkRequiredAttestations(artifacts, signatureBound);
    if (requiredFailure) {
      return { failure: requiredFailure };
    }

    return {
      envelope: this.assembleWithPayload(payload, digest, previousDigest, artifacts, plan?.custody ?? []),
      ...(plan && { mandate: plan }),
    };
  }

  /** The user the credential store registers an assertion's credential to, or `null` (no assertion, no store, unknown credential). */
  private async assertionUserId(assertion: AttestationArtifacts['webauthnAssertion'] | undefined): Promise<string | null> {
    if (!assertion || typeof assertion.credentialKeyId !== 'string') return null;
    const store = this.getCredentialStore();
    if (!store) return null;
    const credential = await store.getByCredentialId(assertion.credentialKeyId).catch(() => undefined);
    return credential?.userId ?? null;
  }

  /**
   * Decide whether the WebAuthn artifact on this record is a signature over
   * this record, and say so on the log sink when it is not.
   *
   * Presence (`!!attestation.webauthnAssertion`) is not the answer. Counted
   * on presence, a reviewer's login assertion, handed to `capture()` by a
   * browser, an RP operator, or anyone who had ever seen one, would be written
   * into `nonRepudiation` and counted as a signature: the record would then
   * claim a named human had approved a decision they may never have seen, and
   * the artifact would verify identically against every other record too.
   *
   * The artifact is still stored verbatim when it does not bind — it is a real
   * thing that really happened, and deleting evidence at capture time is not
   * this SDK's job — it simply stops being counted. `verifyAttestation` reports
   * it as `assertion_not_bound_to_digest` at rest.
   */
  private evaluateAssertionBinding(
    artifacts: AttestationArtifacts,
    digest: string,
    evidenceId: string,
  ): boolean {
    const assertion = artifacts.webauthnAssertion;
    if (!assertion) return false;

    const reason = assertionBindingFailure(assertion, digest);
    if (reason === null) return true;

    sdkLog(this.onLog, 'capture_assertion_not_bound_to_digest', {
      evidenceId,
      digest,
      reason,
      credentialKeyId: assertion.credentialKeyId,
      expectedChallenge: webauthnChallengeForDigest(digest),
    });
    return false;
  }

  /**
   * Run `fn` after every previously queued capture on this instance has
   * settled.
   *
   * A plain promise chain, not a lock library: each call appends to the tail
   * and the tail is reset to a promise that never rejects, so one failed
   * capture cannot poison the queue for the ones behind it.
   */
  private runCaptureExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.captureQueue.then(fn);
    this.captureQueue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /**
   * The claim a keyed capture makes on the store, or `undefined` when there is
   * no key or the adapter cannot claim one.
   *
   * The fingerprint is the engine's one rule (`captureIdempotencyFingerprint`,
   * the platform's `requestFingerprint`) over the shape
   * `HttpStorageAdapter.store()` sends the platform for this record — a
   * `partial` capture of this envelope, on this chain — so one capture has one
   * fingerprint whichever transport it takes. It covers the caller's decision
   * and nothing this attempt minted, which is what lets a retry replay.
   */
  private idempotencyClaimFor(
    key: string | undefined,
    envelope: EvidenceEnvelope,
  ): IdempotencyClaim | undefined {
    if (key === undefined || !this.canClaimIdempotencyKey()) return undefined;
    return {
      key,
      fingerprint: captureIdempotencyFingerprint({
        completeness: 'partial',
        chainId: this.activeChainId,
        envelope,
      }),
    };
  }

  /**
   * Can a key be claimed in this store?
   *
   * Asked of the adapter BEHIND the verifying proxy, because the proxy declares
   * `storeIdempotent` whether or not its inner adapter has one — it forwards
   * the call and reports an inner adapter without the method as not
   * implementing it. The call itself still goes through the proxy.
   *
   * `false` for the cloud transport, which sends the key as `Idempotency-Key`
   * and lets the platform apply the rule, and for a custom `StorageAdapter`
   * that does not implement the method.
   */
  private canClaimIdempotencyKey(): boolean {
    const adapter =
      this.storage instanceof VerifyingStorageProxy ? this.storage.unwrap() : this.storage;
    return typeof adapter.storeIdempotent === 'function';
  }

  /**
   * Read the chain head back from storage after a confirmed store.
   *
   * The store is authoritative for the head. Local adapters echo exactly what
   * was just written; the cloud adapter returns the head the SERVER reported
   * in the capture response, which is the only head the next capture can
   * legally link from.
   */
  private async readStoredHead(): Promise<{ digest: string | null; sequence: number }> {
    const [digest, sequence] = await Promise.all([
      this.storage.getLastDigest(this.activeChainId),
      this.storage.getLastSequence(this.activeChainId),
    ]);
    return { digest, sequence };
  }

  /**
   * The remote store's authoritative stamp for the last successful store, when
   * the adapter has one (cloud transport only). Duck-typed so local adapters
   * need not implement it and the engine's `StorageAdapter` contract is
   * unchanged.
   */
  private readRemoteReceipt(): RemoteCaptureReceipt | undefined {
    const storage = this.storage as StorageAdapter & {
      getLastStoredReceipt?: () => RemoteCaptureReceipt | null;
    };
    if (typeof storage.getLastStoredReceipt !== 'function') return undefined;
    return storage.getLastStoredReceipt() ?? undefined;
  }

  /**
   * Surface — loudly, once per divergent capture — the case where the record
   * the server stored is not the record we handed back to the caller.
   *
   * This is not a failure: the evidence IS recorded, under the server's
   * sequence and digest. It is a receipt mismatch, and it went unnoticed for
   * as long as it did precisely because nothing said anything.
   *
   * A receipt naming a different record is not a restamp and does not reach
   * here — it is an idempotency replay, reported by the caller of this method.
   */
  private warnOnReceiptDivergence(
    envelope: EvidenceEnvelope,
    receipt: RemoteCaptureReceipt,
  ): void {
    const localSequence = envelope.payload.sequenceNumber;
    const localDigest = envelope.integrity.canonicalDigest;
    if (receipt.sequence === localSequence && receipt.canonicalDigest === localDigest) {
      return;
    }
    sdkLog(this.onLog, 'capture_receipt_restamped', {
      evidenceId: receipt.evidenceId,
      chainId: receipt.chainId,
      submittedSequence: localSequence,
      storedSequence: receipt.sequence,
      submittedDigest: localDigest,
      storedDigest: receipt.canonicalDigest,
      note:
        'The server re-stamped this capture onto its own chain head. ' +
        'CaptureResult.serverReceipt holds the record as stored; ' +
        'CaptureResult.envelope is the submitted form.',
    });
  }

  /**
   * The record's payload at `sequenceNumber`, from its resolved members: the
   * engine's `buildEvidencePayload`, which writes every member and applies
   * every writer rule (it throws `EnvelopeInputError`). The caller-shaped
   * members are copied into the JSON data model, so the bytes hashed are the
   * bytes a store or transport keeps.
   */
  private buildPayloadAt(
    request: CaptureRequest,
    members: ResolvedMembers,
    sequenceNumber: number,
    identity: RecordIdentity,
    signoffExpectation: SignoffExpectation | null,
  ): EvidencePayload {
    const input: EnvelopeInput = {
      aiSystemId: request.input.aiSystemId,
      aiOutput: toJsonDataModel(request.input.aiOutput) as Record<string, unknown>,
      action: request.input.action,
      reason: request.input.reason,
      decider: { ...members.decider },
      contributions: members.contributions === null ? null : (toJsonDataModel(members.contributions) as Contributions),
      links: members.links === null ? null : (toJsonDataModel(members.links) as Link[]),
    };
    return buildEvidencePayload(input, {
      evidenceId: identity.evidenceId,
      capturedAt: identity.capturedAt,
      sequenceNumber,
      // A copy per build: each payload holds its own object.
      signoffExpectation: signoffExpectation === null ? null : (toJsonDataModel(signoffExpectation) as SignoffExpectation),
      ...(request.systemRecord !== undefined && { systemRecord: request.systemRecord }),
    });
  }

  /**
   * The payload a mandate's claim is planned over: every member as the
   * record will have it, its expectation `null`, with no writer rule applied
   * (the record built from the plan is checked by every rule).
   */
  private draftPayloadAt(
    request: CaptureRequest,
    members: ResolvedMembers,
    sequenceNumber: number,
    identity: RecordIdentity,
  ): EvidencePayload {
    return {
      evidenceId: identity.evidenceId,
      schemaVersion: CURRENT_SCHEMA_VERSION,
      aiSystemId: request.input.aiSystemId === undefined || request.input.aiSystemId === '' ? 'default' : request.input.aiSystemId,
      aiOutput: toJsonDataModel(request.input.aiOutput) as Record<string, unknown>,
      action: request.input.action,
      reason: request.input.reason,
      capturedAt: identity.capturedAt,
      sequenceNumber,
      decider: { ...members.decider },
      contributions: members.contributions === null ? null : (toJsonDataModel(members.contributions) as Contributions),
      links: members.links === null ? null : (toJsonDataModel(members.links) as Link[]),
      signoffExpectation: null,
    };
  }

  /** The canonical digest of a payload under this instance's schema version. */
  private digestOf(payload: EvidencePayload): string {
    const schema = this.registry.get(this.schemaVersion);
    if (!schema) {
      throw new Error(`Unknown schema version "${this.schemaVersion}". Register it in the schema registry first.`);
    }
    if (schema.status === 'deprecated') {
      throw new Error(
        `Schema version "${this.schemaVersion}" is deprecated. New records must use an active schema version.`,
      );
    }
    return computeDigest(canonicalSerialize(payload as unknown as Record<string, unknown>, schema.hashedFieldSet));
  }

  /**
   * Assemble a complete EvidenceEnvelope from a pre-built payload and digest.
   * The custody chain starts with the client-attested `decision_captured`
   * entry, whose actor is the decider's identifier, then the SDK-derived
   * entries of a capture under a mandate.
   */
  private assembleWithPayload(
    payload: EvidencePayload,
    digest: string,
    previousDigest: string | undefined,
    attestation: AttestationArtifacts,
    extraCustody: MandateAttemptPlan['custody'],
  ): EvidenceEnvelope {
    // Compute chain link
    let chainLink: string | null = null;
    if (previousDigest) {
      const tempChain = new EvidenceChain();
      tempChain.restore(previousDigest);
      chainLink = tempChain.computeLink(digest);
    }

    // The engine's one status rule, with this instance's configured
    // components as the expectation: a configured component that produced no
    // artifact makes the record 'pending', which is what
    // `retryPendingAttestations()` lists.
    const attestationStatus = determineAttestationStatus(
      attestation,
      digest,
      this.attestationExpects,
    );

    return {
      envelopeVersion: 'e1',
      payload,
      integrity: {
        canonicalDigest: digest,
        chainLink,
      },
      nonRepudiation: attestation,
      custodyChain: [
        {
          timestamp: payload.capturedAt,
          actor: payload.decider!.id,
          action: 'decision_captured',
          systemId: payload.aiSystemId,
        },
        ...extraCustody.map((entry) => ({
          timestamp: payload.capturedAt,
          actor: entry.actor,
          action: entry.action,
          systemId: payload.aiSystemId,
          metadata: { ...entry.metadata },
        })),
      ],
      attestationStatus,
    };
  }

  /**
   * Check whether all required attestation services produced artifacts.
   * Returns a FailureRecord if a required attestation is missing, or null if all pass.
   */
  private checkRequiredAttestations(
    artifacts: AttestationArtifacts,
    signatureBound: boolean,
  ): FailureRecord | null {
    const missing: string[] = [];

    for (const service of this.attestationConfig.require) {
      switch (service) {
        case 'timestamp':
          if (!artifacts.rfc3161Token) missing.push('timestamp');
          break;
        case 'webauthn':
          // A present-but-unbound assertion is a missing signature, not a
          // satisfied requirement: it attests to no record, least of all this
          // one. An integrator who asked for `require: ['webauthn']` asked for
          // the record not to exist without a human's signature on it.
          if (!signatureBound) missing.push('webauthn');
          break;
      }
    }

    if (missing.length === 0) return null;

    return {
      failureType: 'attestation_failure',
      diagnosticMetadata: {
        reason: `Required attestation service(s) failed: ${missing.join(', ')}`,
        missingServices: missing,
      },
      capturedAt: new Date().toISOString(),
    };
  }

  /**
   * Verify a stored evidence record by its evidenceId.
   *
   * Retrieves the envelope from storage and recomputes the digest to verify
   * integrity.
   *
   * AI-BOM verification: when the envelope's payload has `aiBom !== null`,
   * descriptor resolution + parent-DAG walk run by default — `this.storage`
   * and `walkLineage: true` are passed to the verifier. Without this, a
   * tampered or missing descriptor would surface no incidents and the
   * top-level `verified` boolean would stay true, which the REST
   * `/v1/evidence/:id/verify` endpoint then returns to external callers.
   * Callers who need cheaper verification can pass `{ aiBom: false }` to
   * skip the descriptor path.
   */
  async verify(
    evidenceId: string,
    previousDigest?: string,
    options?: {
      aiBom?: boolean;
      maxLineageDepth?: number;
      /**
       * What the verifier is allowed to check about the WebAuthn artifact.
       *
       * The BINDING — is this assertion even about this record? — needs
       * nothing: the challenge is a pure function of the canonical digest, so
       * `verify()` always checks it. The SIGNATURE needs the registered public
       * key, and `verify()` looks for it only in the `credentialStore` given
       * here. On a SQLite, Postgres or memory store that can be a `snapshot()`
       * of `getCredentialStore()`; the cloud transport holds no credentials
       * (`getCredentialStore()` is `undefined`), so there the keys come from
       * the relying party that ran the WebAuthn ceremony. Supply one and
       * `verify()` checks the signature too; omit it and the result says
       * `no_credential_store` rather than reporting a pass it did not earn.
       */
      attestation?: VerifySignatureOptions;
      /**
       * The verifier's inputs for the record's anchor (tzun-anchor/1 §10.2):
       * a publisher manifest and header sources for an EVM publication, TSA
       * roots for an RFC 3161 one. Without them the proofs are still checked,
       * and a publication stays `null`, `publication_not_checked`.
       */
      anchor?: VerifyAnchorOptions;
    },
  ): Promise<VerificationResult> {
    const remote = this.remoteRecordReads();
    if (remote) {
      return this.verifyRemote(remote, evidenceId, previousDigest, options);
    }

    const envelope = await this.storage.retrieve(evidenceId);
    if (!envelope) {
      throw new Error(
        `Evidence record "${evidenceId}" not found. Cannot verify a non-existent record.`
      );
    }

    // Resolve the predecessor when the caller did not supply one. Without this,
    // a non-genesis record carries a non-null chainLink but no previousDigest to
    // check it against, so the engine scores chainLinkValid=false and verified=false.
    // The REST route then maps that to a `chain_break` monitoring event — meaning a
    // healthy system raised a tamper incident, and fired notifications, on virtually
    // every on-demand verify. Nothing was wrong with the evidence; the verifier was
    // simply never given the one input it needed.
    const resolvedPreviousDigest =
      previousDigest ?? (await this.resolvePredecessorDigest(envelope));

    const result = await this.verifyStored(envelope, resolvedPreviousDigest, {
      aiBom: options?.aiBom !== false,
      ...(options?.maxLineageDepth !== undefined && { maxLineageDepth: options.maxLineageDepth }),
    });

    const signed = await this.withSignatureVerdict(envelope, result, options?.attestation);
    return this.withAnchorVerdict(envelope, signed, options?.anchor);
  }

  /**
   * The engine's verdict on a stored record. A record that names a step
   * model, a link or an agent is verified at store level (Verification
   * §4.10, §4.11; Record §6.9): its step models' descriptors resolved and
   * re-hashed and their lineage walked, its same-store link targets resolved
   * and checked member by member, its agent references resolved. `aiBom:
   * false` leaves the descriptors out. A record that names none takes the
   * synchronous path.
   */
  private async verifyStored(
    envelope: EvidenceEnvelope,
    previousDigest: string | undefined,
    options: { aiBom: boolean; maxLineageDepth?: number },
  ): Promise<VerificationResult> {
    if (!needsStoreLevelVerification(envelope)) {
      return verifyEnvelope(envelope, previousDigest, this.registry);
    }
    const storage: StorageAdapter = options.aiBom
      ? this.storage
      : (Object.create(this.storage, { getModelDescriptor: { value: undefined } }) as StorageAdapter);
    const logs = logStoreFor(this.getStorage());
    let originOf: ((chainId: string) => string) | undefined;
    if (logs) {
      const identity = await logs.getStoreIdentity();
      // The engine reads the store's own origin prefix as the origin of the
      // empty chain id, which names no log: answered with the prefix itself.
      originOf = (chainId: string) =>
        chainId === '' ? `${evidenceLogOrigin(identity.ns, identity.storeId, 'x').slice(0, -2)}` : evidenceLogOrigin(identity.ns, identity.storeId, chainId);
    }
    return verifyEnvelope(envelope, previousDigest, this.registry, {
      storage,
      walkLineage: options.aiBom,
      ...(options.maxLineageDepth !== undefined && { maxLineageDepth: options.maxLineageDepth }),
      ...(originOf !== undefined && { evidenceLogOrigin: originOf }),
    });
  }

  /**
   * Fill in `anchorValid` / `anchorReason` (tzun-anchor/1 §10.6, §10.9) and
   * the store's `logFindings` on a verification result.
   *
   * A record that carries an anchor (`nonRepudiation.anchor`, or a legacy
   * `blockchainAnchor`, which is abstained on) is decided by `verifyAnchor`,
   * whose `anchorNamespace`, `anchorFinality` and `existedBy` ride along, so
   * a display can say "test" or "not final" rather than "anchored". It is decided
   * with the digest recomputed from the record's payload, its hashed
   * sequence number, the chain its store logged it under, the caller's
   * inputs, and the heavy material the store holds for the publication that
   * covers it. A record that carries none reads as its
   * store says (`get()`'s `anchorState`): `anchor_not_yet_published` while
   * the store expects an anchor for it, and nothing at all on a store that
   * does not anchor. A failure to read the store's logs is logged
   * (`verify_anchor_state_unread`) and leaves the record's own artifact to
   * decide.
   *
   * `verified` is untouched: it means "the decision record and its chain link
   * are intact", and an anchor says nothing about that.
   */
  private async withAnchorVerdict(
    envelope: EvidenceEnvelope,
    result: VerificationResult,
    inputs?: VerifyAnchorOptions,
  ): Promise<VerificationResult> {
    const storage = this.getStorage();
    const logs = logStoreFor(storage);
    const anchors = anchorStoreFor(storage);
    const evidenceId = envelope.payload?.evidenceId;
    let position: LogPosition | null = null;
    let findings: EvidenceRead['logFindings'];
    let stateReason: string | undefined;
    let expected = false;
    let material: unknown[] = [];
    try {
      position = logs && typeof evidenceId === 'string' ? await logs.getEvidenceLogPosition(evidenceId) : null;
      if (position) {
        const read = await readRecordLog(envelope, position, anchors, { registry: this.registry });
        findings = read.logFindings;
        expected = read.anchorState !== undefined;
        stateReason = read.anchorState?.anchorReason;
        material = await storedPublicationMaterial(anchors, position);
      }
    } catch (error) {
      sdkLog(this.onLog, 'verify_anchor_state_unread', {
        evidenceId,
        errorName: error instanceof Error ? error.name : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
    }
    const withFindings = (r: VerificationResult): VerificationResult =>
      findings && findings.length > 0 ? { ...r, logFindings: findings } : r;

    const artifacts = envelope.nonRepudiation as Record<string, unknown> | undefined;
    const carries = artifacts != null && (artifacts.anchor != null || artifacts.blockchainAnchor != null);
    if (carries) {
      const sequenceNumber = envelope.payload?.sequenceNumber;
      // The digest recomputed from the payload, as `get()` checks it: an
      // anchor that holds only for the stored digest does not hold for a
      // record whose payload was altered under it.
      const verdict = await verifyAnchor(artifacts, result.recomputedDigest, {
        ...(inputs ?? {}),
        ...(typeof sequenceNumber === 'number' && { sequenceNumber }),
        ...(position && { chainId: position.chainId }),
        publicationMaterial: [...(inputs?.publicationMaterial ?? []), ...material],
      });
      return withFindings({
        ...result,
        anchorValid: verdict.anchorValid,
        ...(verdict.anchorValid !== true && verdict.anchorReason !== undefined && { anchorReason: verdict.anchorReason }),
        anchorNamespace: verdict.anchorNamespace,
        anchorFinality: verdict.anchorFinality,
        existedBy: verdict.existedBy,
      });
    }
    if (expected) {
      return withFindings({ ...result, anchorValid: null, ...(stateReason !== undefined && { anchorReason: stateReason }) });
    }
    return withFindings(result);
  }

  /**
   * `verify()` against a remote store (the cloud transport).
   *
   * The SDK verifies the record ITSELF. The server's verdict is not passed
   * through as if the SDK had checked it — that is the same class of claim as a
   * chain walk reporting `valid: true` over records it never read, and `get()`
   * already returns the server's verdict for a caller who wants it. What only
   * the server can supply is the predecessor: `integrity.chainLink` is
   * SHA-256(predecessor digest ‖ this digest), and a client holding one record
   * cannot know the digest of the record before it. So this reads the record,
   * takes the predecessor the server measured against, and runs the same
   * `verifyEnvelope` the local path runs — two round trips, and every field of
   * the result computed here from bytes this process holds.
   *
   * `previousDigest` from the caller wins, as it does locally.
   *
   * AI-BOM DESCRIPTOR VERIFICATION DOES NOT RUN HERE. The lineage walk reads the
   * descriptor catalog, and this transport has no catalog read; passing
   * `storage` to the verifier would throw `TzunCloudReadUnsupportedError` out of
   * a verify. So a cloud verify checks the record and its chain link, and says
   * nothing about the descriptors its `aiBom` names — `tamperIncidents` and
   * `modelLineage` are absent rather than empty.
   */
  private async verifyRemote(
    remote: RemoteRecordReads,
    evidenceId: string,
    previousDigest: string | undefined,
    options?: {
      aiBom?: boolean;
      maxLineageDepth?: number;
      attestation?: VerifySignatureOptions;
      anchor?: VerifyAnchorOptions;
    },
  ): Promise<VerificationResult> {
    const read = await this.get(evidenceId);
    if (!read) {
      throw new Error(
        `Evidence record "${evidenceId}" not found. Cannot verify a non-existent record.`,
      );
    }

    let resolvedPreviousDigest = previousDigest;
    if (resolvedPreviousDigest === undefined) {
      const measured = await remote.verifyRecord(evidenceId);
      resolvedPreviousDigest = measured?.chain.predecessor?.canonicalDigest ?? undefined;
    }

    const result = verifyEnvelope(read.envelope, resolvedPreviousDigest, this.registry);
    const signed = await this.withSignatureVerdict(read.envelope, result, options?.attestation);
    return this.withAnchorVerdict(read.envelope, signed, options?.anchor);
  }

  /**
   * Fill in `signatureValid` / `signatureReason` on a verification result.
   *
   * `verifyEnvelope` always leaves `signatureValid` at `null`: the engine
   * verifies no signature. This is where the WebAuthn artifact — the only
   * thing in an envelope that claims a *human* approved the decision — is
   * looked at.
   *
   * What is checkable here, honestly:
   *
   *   - **the binding**, always. `webauthnChallengeForDigest(digest)` needs no
   *     key material, no store and no network, so a replayed assertion is
   *     caught with nothing in hand.
   *   - **the signature**, only with a credential store. Without one the
   *     verdict is `null` / `no_credential_store` — "not verified", never a
   *     pass.
   *
   * The expectation is DERIVED here rather than asserted by a caller, so a
   * mismatch reports `assertion_not_bound_to_digest` (`null`) and not
   * `challenge_mismatch` (`false`): a record captured before 0.3.16 carries an
   * assertion over a login nonce, and calling that a failed signature would
   * mark every pre-existing record as carrying broken evidence. The scanner,
   * which is configured with `expectedChallengeFor`, gets the sharper verdict.
   * Neither verdict is a pass.
   *
   * `verified` is deliberately untouched. It means "the decision record and its
   * chain link are intact", and an unbound or unverifiable assertion says
   * nothing about that.
   */
  private async withSignatureVerdict(
    envelope: EvidenceEnvelope,
    result: VerificationResult,
    attestation?: VerifySignatureOptions,
  ): Promise<VerificationResult> {
    if (!envelope.nonRepudiation?.webauthnAssertion) return result;

    const digest = envelope.integrity.canonicalDigest;
    const verdict = await verifyAttestation(
      { webauthnAssertion: envelope.nonRepudiation.webauthnAssertion },
      digest,
      attestation?.credentialStore,
      {
        expectedChallenge: webauthnChallengeForDigest(digest),
        expectedChallengeSource: 'derived-from-digest',
        ...(attestation?.allowedOrigins && { allowedOrigins: attestation.allowedOrigins }),
        ...(attestation?.allowedTopOrigins && { allowedTopOrigins: attestation.allowedTopOrigins }),
        ...(attestation?.requireDeviceBound && { requireDeviceBound: true }),
        ...(attestation?.rpId && { rpId: attestation.rpId }),
      },
    );

    return {
      ...result,
      signatureValid: verdict.signatureValid,
      ...(verdict.credentialStatus !== undefined && { credentialStatus: verdict.credentialStatus }),
      ...(verdict.signatureReason !== undefined && { signatureReason: verdict.signatureReason }),
      ...(verdict.assertionProvenance !== undefined && {
        assertionProvenance: verdict.assertionProvenance,
      }),
    };
  }

  /**
   * Look up the digest of the record immediately preceding `envelope` in its own
   * chain, or undefined when there is none to find.
   *
   * Scoped by chain deliberately. Sequence numbers restart at 1 per chain, so an
   * unscoped lookup would happily return a same-sequence record from a DIFFERENT
   * chain and validate the link against it — turning a false negative into a far
   * worse false positive. The storage adapter's own docs warn about exactly this.
   */
  /**
   * Public wrapper: resolve the digest of the record immediately preceding
   * `evidenceId` in its own chain, or undefined when there is none.
   *
   * The API layer needs this to fill `chain_break.expectedPrevDigest` with the
   * real predecessor instead of the placeholder empty string, without being
   * able to influence what the predecessor is.
   */
  async getPredecessorDigest(evidenceId: string): Promise<string | undefined> {
    const envelope = await this.storage.retrieve(evidenceId);
    if (!envelope) return undefined;
    return this.resolvePredecessorDigest(envelope);
  }

  private async resolvePredecessorDigest(
    envelope: EvidenceEnvelope,
  ): Promise<string | undefined> {
    const seq = envelope.payload?.sequenceNumber;
    // Genesis has no predecessor; its chainLink is legitimately null, and passing
    // no previousDigest lets the engine score chainLinkValid as null rather than false.
    if (typeof seq !== 'number' || seq <= 1) return undefined;

    // No catch here, deliberately. The blanket `catch { return undefined; }`
    // this replaces was justified as a fallback for "adapters that do not
    // implement chain-scoped lookups (e.g. the cloud transport)", but the cloud
    // transport never reaches this code: `verify()` and `getPredecessorDigest()`
    // both call `storage.retrieve()` first, which throws
    // TzunCloudReadUnsupportedError in cloud mode long before the predecessor
    // is resolved. So the only thing the catch actually did was convert a real
    // infrastructure fault — a dropped Postgres connection between `retrieve`
    // and `listBySequence`, SQLITE_BUSY, a permissions error — into
    // `undefined`, which the engine scores as chainLinkValid=false →
    // verified=false, and the REST route then reports as a `chain_break`
    // monitoring event. A transient database error must not open a tamper
    // incident on untampered evidence; it must surface as an error.
    const chainId = await this.storage.getChainForRecord(envelope.payload?.evidenceId);
    return (await this.resolvePredecessor(envelope, chainId))?.integrity.canonicalDigest;
  }

  /**
   * The record at the previous sequence number of `chainId`, or undefined for
   * a genesis record, a record filed under no chain, or a predecessor the
   * store does not hold. Chain-scoped for the reason `resolvePredecessorDigest`
   * gives.
   */
  private async resolvePredecessor(
    envelope: EvidenceEnvelope,
    chainId: string | null,
  ): Promise<EvidenceEnvelope | undefined> {
    const seq = envelope.payload?.sequenceNumber;
    if (typeof seq !== 'number' || seq <= 1 || !chainId) return undefined;
    const prev = await this.storage.listBySequence(seq - 1, seq - 1, chainId);
    return prev.find((e) => e.payload?.sequenceNumber === seq - 1);
  }

  /**
   * Export an evidence record into a self-contained bundle: everything an
   * auditor needs to verify it with no access to this store.
   *
   *   - `envelope` — the record, verbatim, even when it fails verification:
   *     an export is never refused over what the checks found.
   *   - `resolvedModelDescriptors` — every `ModelDescriptor` the envelope
   *     references (canonical bytes for re-hashing, enriched view, raw
   *     annotation log), keyed by digest. When `walkLineage` is true (the
   *     default), every ancestor reachable via `parentModelDescriptorDigest`
   *     too, walked leaf-to-root with the verifier's depth limit and cycle
   *     safety. A descriptor missing from the catalog is surfaced as
   *     `{ missing: true }` rather than dropped — the gap is real data loss.
   *   - `resolvedAgentDescriptors` — every agent descriptor the record's
   *     decider and step actors reference, keyed by the reference: the agent
   *     catalog's row verbatim (an offline verifier re-hashes it), or
   *     `{ missing: true, reason }` when the store keeps no catalog
   *     (`catalog_absent`) or holds no row (`not_registered`).
   *   - `chain` — the record's chain and its predecessor (evidenceId,
   *     sequence, digest), so `integrity.chainLink` can be recomputed offline.
   *   - `custody` — the record's `custody_entries` rows, the ledger verdict on
   *     them (`trail`) and the envelope-only verdict (`offlineTrail`), in the
   *     shape the hosted service's export ships as `server.custody`.
   *   - `verdict` — this store's `recordVerdict` on the record, with the
   *     chain link checked against the bundled predecessor. Computed whatever
   *     `verifyReads` says: the verdict is the point of the bundle.
   *
   * A custody ledger or predecessor that cannot be read does not stop the
   * export: `custody.entries` / `chain.predecessor` are null and the verdict
   * reports the check unmeasured with the error.
   *
   * `tests/ts/helpers/verify-exported.ts` is the reference offline verifier.
   *
   * Lives at the top of the `Tzun` class (not under `tzun.models`) because
   * the operation is per-evidence-record, not per-model — the model bundle
   * is incidental to the evidence record being exported.
   */
  async exportEvidence(
    evidenceId: string,
    options: ExportEvidenceOptions = {},
  ): Promise<ExportedEvidenceEnvelope> {
    const remote = this.remoteRecordReads();
    if (remote) {
      return this.exportRemote(remote, evidenceId, options.assertion);
    }

    const envelope = await this.storage.retrieve(evidenceId);
    if (!envelope) {
      throw new Error(
        `Evidence record "${evidenceId}" not found. Cannot export a non-existent record.`,
      );
    }

    const exportedAt = new Date().toISOString();
    const exportedBy = options.exportedBy ?? 'tzun-sdk';
    const resolvedModelDescriptors = await this.exportDescriptors(
      envelope,
      options.walkLineage !== false, // default true
      options.maxLineageDepth ?? EXPORT_MAX_LINEAGE_DEPTH,
    );
    const resolvedAgentDescriptors = await exportAgentDescriptors(envelope, this.storage);
    const { chain, custody, verdict } = await this.exportRecordParts(envelope, evidenceId);

    return {
      envelope,
      resolvedModelDescriptors,
      resolvedAgentDescriptors,
      exportedAt,
      exportedBy,
      verdict,
      chain,
      custody,
      assertionProvenance: exportedAssertionProvenance(envelope, options.assertion),
    };
  }

  /**
   * Export an evidence record as a `b1` proof bundle (Bundle §3): the
   * record and everything an auditor needs to verify it with no access to this
   * store, `verifyBundle()` being the verifier.
   *
   *   - `subject`, `envelope`, `chain`, `custody` — the record, its chain
   *     position and its custody ledger, as `exportEvidence()` reads them.
   *   - `anchoring` — for a record a final publication covers: its evidence
   *     log's and the domain's anchor log's checkpoints (the record's own, and
   *     the newest anchored when it is exported), each anchor checkpoint's
   *     publications with the heavy material the envelope leaves out (the raw
   *     transaction, the block header, the transaction's index and its trie
   *     proof), the record's anchor into the newest anchor checkpoint, and one
   *     direct consistency proof per log. Bounded by two checkpoints per log,
   *     whatever the record's age (Bundle §7.3).
   *   - `anchorPending` — on a store that anchors, for a record no final
   *     publication covers yet: its origin, its leaf and when it was logged.
   *     Never a marker in `nonRepudiation` (Bundle §7.7).
   *   - `credentials`, `relatedRecords`, `policy` — reserved sign-off slots,
   *     null; `extensions` — `witness/1`, reserved, null.
   *   - `exporter` — when, by whom, and this store's verdict on the record: a
   *     claim no check reads.
   *
   * The record is exported whatever its checks find. A custody ledger or
   * predecessor that cannot be read is reported as in `exportEvidence()`; a
   * failure to read the anchoring tables throws, because a bundle without the
   * record's anchoring material would read as a record that has none.
   *
   * @throws when the record is not found, and on the cloud transport
   *   (`TzunCloudReadUnsupportedError`): the platform's export carries no
   *   anchoring material.
   */
  async exportBundle(evidenceId: string, options: ExportBundleOptions = {}): Promise<ProofBundle> {
    if (this.remoteRecordReads()) {
      throw new TzunCloudReadUnsupportedError('exportBundle');
    }
    const envelope = await this.storage.retrieve(evidenceId);
    if (!envelope) {
      throw new Error(
        `Evidence record "${evidenceId}" not found. Cannot export a non-existent record.`,
      );
    }
    const exportedAt = new Date().toISOString();
    const { chain, custody, verdict } = await this.exportRecordParts(envelope, evidenceId);
    const storage = this.getStorage();
    const { anchoring, anchorPending } = await bundleAnchoring(envelope, logStoreFor(storage), anchorStoreFor(storage));
    return {
      bundleVersion: BUNDLE_VERSION,
      profile: 'record',
      subject: { evidenceId: envelope.payload.evidenceId, canonicalDigest: envelope.integrity.canonicalDigest },
      envelope,
      chain,
      custody,
      credentials: null,
      relatedRecords: null,
      anchoring,
      anchorPending,
      policy: null,
      extensions: { 'witness/1': null },
      exporter: { exportedAt, exportedBy: options.exportedBy ?? 'tzun-sdk', verdict },
    };
  }

  /**
   * The chain position, custody ledger and verdict of a stored record, as both
   * exports carry them. The ledger rows and the predecessor are each read so
   * that a failure is reported in the verdict rather than thrown: a store an
   * insider can make throw on one neighbouring row must not be able to refuse
   * the export.
   */
  private async exportRecordParts(
    envelope: EvidenceEnvelope,
    evidenceId: string,
  ): Promise<{ chain: ExportedChainPosition; custody: ExportedCustody; verdict: RecordVerdict }> {
    let entries: CustodyLedgerEntry[] | null = null;
    let custody: RecordVerdictInput['custody'];
    try {
      entries = (await this.storage.listCustodyEntries(evidenceId)).map(toCustodyLedgerEntry);
      custody = { entries };
    } catch (err) {
      custody = { error: errorMessage(err) };
    }

    let chainId: string | null = null;
    let predecessor: ExportedChainPredecessor | null = null;
    let predecessorInput: RecordVerdictInput['predecessor'];
    try {
      chainId = await this.storage.getChainForRecord(evidenceId);
      const prev = await this.resolvePredecessor(envelope, chainId);
      predecessor = prev
        ? {
            evidenceId: prev.payload?.evidenceId,
            sequenceNumber: prev.payload?.sequenceNumber,
            canonicalDigest: prev.integrity?.canonicalDigest,
          }
        : null;
      predecessorInput = { digest: predecessor?.canonicalDigest ?? null };
    } catch (err) {
      predecessorInput = { error: errorMessage(err) };
    }

    const verdict = recordVerdict(envelope, {
      registry: this.registry,
      custody,
      predecessor: predecessorInput,
    });

    return {
      chain: { chainId, predecessor },
      custody: {
        hashPreimage: CUSTODY_ENTRY_HASH_PREIMAGE,
        entries,
        trail: verdict.custodyTrail.ledger,
        offlineTrail: verifyCustodyTrail(envelope),
      },
      verdict,
    };
  }

  /**
   * The remote store's export bundle, in this SDK's bundle shape.
   *
   * The hosted service assembles the same bundle its portal downloads
   * (`GET /v1/app/evidence/:id/export`), and its `verdict` and `chain`
   * blocks already carry the same field names as this one's, with
   * `server.custody` carrying the ledger rows under the names `custody` uses —
   * so the mapping is a re-homing, not a translation, and one offline verifier
   * (`tests/ts/helpers/verify-exported.ts`) reads either bundle.
   *
   * What is NOT invented:
   *   - `exportedAt` / `exportedBy` are absent. The server did not send them,
   *     and a timestamp stamped here would say this bundle was assembled by
   *     this SDK, which it was not.
   *   - `resolvedModelDescriptors` marks every descriptor the envelope
   *     references as `missing: true`. The platform's bundle carries no resolved
   *     descriptors and this transport cannot read the catalog, so the
   *     descriptor is a verification GAP — which `missing` is exactly the flag
   *     for. Omitting the entry would have hidden it. Ancestors are not listed
   *     at all: nothing here can know which ancestors exist.
   *   - `custody.offlineTrail` is recomputed here when the server sent none.
   *     `verifyCustodyTrail` is a pure function of the envelope this bundle
   *     carries, so computing it adds no claim the bundle cannot back.
   *   - `assertionProvenance` is read here from the envelope's assertion, for
   *     the same reason.
   *
   * `server` carries the platform's own receipt block verbatim — when it
   * received the record, and the attestation state its worker recorded,
   * including an RFC 3161 token the platform obtained that the client envelope
   * may not hold. That is an independent witness's statement about the record,
   * and this SDK's bundle had nowhere to put it; dropping it would have made the
   * mapping lossy in the one place the product's claim rests. A locally
   * assembled bundle has no `server` block, because this SDK is not a witness to
   * its own store.
   */
  private async exportRemote(
    remote: RemoteRecordReads,
    evidenceId: string,
    assertion: ExportEvidenceOptions['assertion'],
  ): Promise<ExportedEvidenceEnvelope> {
    const bundle = await remote.exportEvidence(evidenceId);
    if (!bundle) {
      throw new Error(
        `Evidence record "${evidenceId}" not found. Cannot export a non-existent record.`,
      );
    }

    return {
      envelope: bundle.envelope,
      resolvedModelDescriptors: unresolvedDescriptorEntries(bundle.envelope),
      resolvedAgentDescriptors: await exportAgentDescriptors(bundle.envelope, this.storage),
      verdict: bundle.verdict,
      chain: bundle.chain,
      custody: {
        hashPreimage: bundle.server.custody.hashPreimage,
        entries: bundle.server.custody.entries,
        trail: bundle.server.custody.trail,
        offlineTrail: bundle.server.custody.offlineTrail ?? verifyCustodyTrail(bundle.envelope),
      },
      assertionProvenance: exportedAssertionProvenance(bundle.envelope, assertion),
      server: bundle.server,
    };
  }

  /**
   * The descriptors an export bundles for `envelope`: its leaf descriptor and,
   * with `walkLineage`, every ancestor, keyed by digest.
   */
  private async exportDescriptors(
    envelope: EvidenceEnvelope,
    walkLineage: boolean,
    maxDepth: number,
  ): Promise<{ [digest: string]: ExportedDescriptorEntry }> {
    const resolvedModelDescriptors: { [digest: string]: ExportedDescriptorEntry } = {};

    // Every step model's descriptor (a model's bill of materials lives only
    // in a contribution step). A stored row is whatever was written, and a
    // step whose aiBom is not an object with a string digest names none.
    const leafDigests = stepModelDigests(envelope);
    if (leafDigests.length === 0) {
      return resolvedModelDescriptors;
    }

    if (!this.storage.getModelDescriptor) {
      // Adapter doesn't support the catalog. Surface every referenced digest
      // as missing so the offline verifier can flag the gap.
      for (const leafDigest of leafDigests) {
        resolvedModelDescriptors[leafDigest] = {
          canonicalBytes: '',
          enrichedView: null,
          annotations: [],
          missing: true,
        };
      }
      return resolvedModelDescriptors;
    }

    // Walk lineage leaf-to-root with depth limit + cycle safety. This
    // mirrors the verifier (src/engine/verify.ts) and models-routes lineage
    // walker; the duplication is deliberate — sharing the walker across
    // the verifier (which emits incidents), the read API (which returns a
    // lineage entry array), and the exporter (which inlines full rows)
    // would have to thread three different output channels through one
    // function. Same shape, different output: keep them separate.
    const visited = new Set<string>();
    const queue: string[] = [...leafDigests];

    while (queue.length > 0 && Object.keys(resolvedModelDescriptors).length < maxDepth * leafDigests.length) {
      const digest = queue.shift()!;
      if (visited.has(digest)) {
        continue;
      }
      visited.add(digest);

      const row = await this.storage.getModelDescriptor(digest);
      if (!row) {
        // Missing descriptor: surface, don't silently drop. The bundle stops
        // walking through this hole — we have no idea what the parent chain
        // looked like — but the leaf-side entry is still recorded.
        resolvedModelDescriptors[digest] = {
          canonicalBytes: '',
          enrichedView: null,
          annotations: [],
          missing: true,
        };
        continue;
      }

      const annotations = this.storage.listModelDescriptorAnnotations
        ? await this.storage.listModelDescriptorAnnotations(digest)
        : [];
      const enrichedView = buildEnrichedView(row.descriptor, annotations);

      resolvedModelDescriptors[digest] = {
        canonicalBytes: row.canonicalBytes,
        enrichedView,
        annotations,
      };

      // Advance on the parent named INSIDE canonicalBytes, never on the
      // row's `parent_model_descriptor_digest` column. That column is
      // denormalized for indexed lookup and is covered by no digest, so a
      // single UPDATE against it would steer a walk that followed it: the
      // exporter would bundle the attacker's chosen ancestor set, every
      // bundled entry would re-hash correctly against its key, and the
      // offline verifier would return ok — an export whose lineage the
      // evidence never claimed. The in-process verifier
      // (packages/engine/src/verify.ts) follows the same rule. Unparseable
      // bytes stop the walk rather than falling back to the column; the entry
      // is still bundled, and the offline verifier reports the parse failure.
      if (walkLineage) {
        const parentFromBytes = parseDescriptorParent(row.canonicalBytes);
        if (parentFromBytes !== null) {
          queue.push(parentFromBytes);
        }
      }
    }

    return resolvedModelDescriptors;
  }

  /**
   * Obtain the retry-obtainable components each 'pending' record is missing.
   *
   * A record is 'pending' while a component its writer expects has no artifact
   * on it — the engine's status rule. The pass lists, oldest first, the
   * 'pending' records missing a component this instance obtains (a timestamp),
   * through `StorageAdapter.listByMissingObtainable`, and requests only what
   * each one is missing. It adds what it obtains and never replaces an
   * artifact the record already holds: a capture-time RFC 3161 token keeps its
   * genTime.
   *
   * It never lists or requests an anchor. An anchor is published for a batch
   * of records, so a record waiting only for one is not listed, and however
   * many there are, they never take the page ahead of a record this pass can
   * help. Such a record stays 'pending'.
   *
   * Records the pass can help but fails to are listed again on the next pass,
   * oldest first. So `limit` records whose timestamp request keeps failing
   * hold back every newer record until one of them succeeds.
   *
   * The record's status is recomputed by the same rule, by the store, from
   * the record as it stores it: an anchor the anchor scheduler filled while
   * the pass waited on its timestamp authority counts. A record counts as
   * `succeeded` once it holds every component this instance obtains; one that
   * still lacks one counts as `failed`, with those components in
   * `stillMissing`. A retry that obtains nothing writes nothing.
   *
   * `options.limit` bounds how many records the pass lists and requests
   * attestation for. The same passes run on the `attestation.retry` schedule,
   * and a call made while one is running waits for it: two passes never run at
   * once, so a record is never attested twice by this instance.
   */
  async retryPendingAttestations(options?: RetryPendingOptions): Promise<RetryResult> {
    const limit = options?.limit;
    if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1)) {
      throw new RangeError(
        `retryPendingAttestations: limit must be an integer >= 1 (got ${String(limit)}).`,
      );
    }
    return this.attestationRetry.runPass(limit);
  }

  /**
   * The pending-attestation retry schedule: whether it runs, its interval and
   * current wait, and what the last pass did.
   */
  getAttestationRetryState(): AttestationRetryState {
    return this.attestationRetry.getState();
  }

  /**
   * One retry pass: see {@link retryPendingAttestations}. Run only through
   * `attestationRetry`, which serialises passes. Also reports how many records
   * it requested attestation for and whether any gained an artifact, which is
   * what the schedule's backoff reads.
   */
  private async retryPendingPass(
    limit: number | undefined,
  ): Promise<{ result: RetryResult; requested: number; progressed: boolean }> {
    const result: RetryResult = {
      attempted: 0,
      succeeded: 0,
      failed: 0,
      details: [],
    };
    let requested = 0;
    let progressed = false;

    // The batch this pass works on: the oldest 'pending' records missing a
    // component this instance obtains. The read is bounded by the same `limit`
    // the pass requests attestation for, so a large backlog is walked a batch
    // at a time; successive passes take the next oldest. It is made even when
    // this instance obtains nothing, so a store that cannot list (the cloud
    // transport) refuses the pass instead of reporting it as done.
    const components = this.retryComponents();
    const candidates = await this.storage.listByMissingObtainable(components, limit);
    const missingOf = (artifacts: AttestationArtifacts | undefined): RetryObtainableComponent[] =>
      missingAttestationComponents(artifacts, this.attestationExpects)
        .filter(isRetryObtainableComponent)
        .filter((c) => components.includes(c));

    for (const envelope of candidates) {
      const evidenceId = envelope.payload.evidenceId;
      const digest = envelope.integrity.canonicalDigest;
      const missing = missingOf(envelope.nonRepudiation);

      requested++;
      result.attempted++;

      try {
        const obtained = pickComponents(await this.attestComponents(digest, missing), missing);
        const merged = { ...envelope.nonRepudiation, ...obtained };
        const stillMissing = missingOf(merged);

        if (Object.keys(obtained).length > 0) {
          // The status is computed by the store from the record as it will be
          // stored, not from `envelope`, which was read when the pass began:
          // the anchor scheduler may have filled the record's anchor while
          // this pass waited on its timestamp authority.
          const expects = this.attestationExpects;
          await this.storage.updateAttestation(evidenceId, obtained, (stored) =>
            determineAttestationStatus(stored.nonRepudiation, stored.integrity.canonicalDigest, expects),
          );
          progressed = true;
        }

        if (stillMissing.length === 0) {
          result.succeeded++;
          result.details.push({ evidenceId, success: true });
        } else {
          result.failed++;
          result.details.push({
            evidenceId,
            success: false,
            error: `Still missing: ${stillMissing.join(', ')}`,
            stillMissing,
          });
        }
      } catch (error) {
        result.failed++;
        result.details.push({
          evidenceId,
          success: false,
          error: error instanceof Error ? error.message : String(error),
          stillMissing: missing,
        });
      }
    }

    return { result, requested, progressed };
  }

  /**
   * The retry-obtainable components this instance is configured for and has
   * a client to obtain: what its retry pass lists records by.
   */
  private retryComponents(): RetryObtainableComponent[] {
    return this.attestationExpects.timestamp && this.attestationClients.timestampClient
      ? ['timestamp']
      : [];
  }

  /**
   * Attest `digest` for `components` only, with an orchestrator built from
   * the clients capture uses, so their circuit breakers are shared.
   */
  private attestComponents(
    digest: string,
    components: RetryObtainableComponent[],
  ): Promise<AttestationArtifacts> {
    const { timestampClient } = this.attestationClients;
    return new AttestationOrchestrator({
      timestampClient: components.includes('timestamp') ? timestampClient : undefined,
      onLog: this.onLog,
    }).attest(digest);
  }

  /**
   * Read one stored record, with the verdict on it.
   *
   * Returns `{ envelope, verdict }`, or `null` when the store holds no record
   * with that id. The verdict is the verifying proxy's `RecordVerdict`: the
   * payload's digest recomputed against the stored one, and the record's
   * custody ledger rows checked against its `custodyChain` mirror. The chain
   * link is a property of two records and is reported `not_checked_on_read`;
   * `verify()`, `exportEvidence()` and the chain walks check it.
   *
   * A record that fails is returned all the same, with `verdict.status`
   * `'invalid'` and each failed check's `reason`: reads are never blocked.
   * With `verifyReads: false` every check is `unmeasured`.
   *
   * On a local store the read also carries where the record sits in its
   * chain's evidence log (`logPosition`), what the store's logs show is wrong
   * with it (`logFindings`), and, on a store that anchors (one holding an
   * anchor log), how far its anchor has got (`anchorState`):
   * `awaiting_epoch`, then `awaiting_finality` once the epoch covering
   * the record is published, then `anchored` once that publication is final,
   * the record's payload still hashes to its stored digest and that digest is
   * its logged leaf, and the record carries an anchor for that leaf whose
   * proofs hold for that digest and whose anchor checkpoint the store
   * published (its digest is the P of a final publication of the store's).
   * A record whose publication is final and that is not anchored as stored
   * (an altered payload, a rewritten record under a forged artifact, an
   * anchor that does not hold, a fill that left it without one) is
   * `anchor_invalid`. The verifier's answer on the record's anchor rides
   * along as `anchorValid` and `anchorReason`. A failure to read the logs is logged
   * (`get_anchor_state_unread`) and leaves these fields out: it never blocks
   * the read.
   *
   * On the cloud transport the same shape comes from the server
   * (`GET /v1/app/evidence/:id`), scoped by the server to the key's own
   * account and env: `null` for a record that key cannot see, exactly
   * as for one that does not exist, so an id cannot be probed across accounts.
   */
  async get(evidenceId: string): Promise<EvidenceRead | null> {
    const reads = this.verdictReads();
    let read: EvidenceRead | null;
    if (reads) {
      read = await reads.retrieveWithVerdict(evidenceId);
    } else {
      const envelope = await this.storage.retrieve(evidenceId);
      read = envelope ? { envelope, verdict: unmeasuredRecordVerdict(envelope) } : null;
    }
    return read ? this.withRecordLog(evidenceId, read) : null;
  }

  /** `read` with what the store's logs say about the record, on a store with evidence logs. */
  private async withRecordLog(evidenceId: string, read: EvidenceRead): Promise<EvidenceRead> {
    const storage = this.getStorage();
    const logs = logStoreFor(storage);
    if (!logs) return read;
    try {
      const position = await logs.getEvidenceLogPosition(evidenceId);
      if (!position) return read;
      const scheduler = this.anchorScheduler;
      // `dueBy`: the record's leaf was logged at t, and the cadence cuts
      // an epoch once the oldest waiting leaf is the interval old, so its
      // epoch is due by t plus the interval. Known only where the cadence is:
      // on an instance that anchors.
      const dueBy = scheduler
        ? async (): Promise<string | undefined> => {
            const [leaf] = await logs.listLogLeaves(position.logId, position.leafIndex, position.leafIndex + 1);
            const loggedAt = leaf ? Date.parse(leaf.loggedAt) : Number.NaN;
            return Number.isFinite(loggedAt) ? new Date(loggedAt + scheduler.intervalMs()).toISOString() : undefined;
          }
        : undefined;
      return { ...read, ...(await readRecordLog(read.envelope, position, anchorStoreFor(storage), { registry: this.registry, dueBy })) };
    } catch (error) {
      sdkLog(this.onLog, 'get_anchor_state_unread', {
        evidenceId,
        errorName: error instanceof Error ? error.name : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
      return read;
    }
  }

  /**
   * List stored records with optional filtering and ordering, each with the
   * verdict on it — the same `{ envelope, verdict }` and the same checks as
   * `get()`, for every record the page holds.
   *
   * On the cloud transport the page comes from the server, which applies `limit`
   * and `offset` and nothing else: a `ListOptions` naming a filter it cannot
   * apply is refused rather than answered with a page that ignored it.
   */
  async list(options?: import('@tzun/engine').ListOptions): Promise<EvidenceRead[]> {
    const reads = this.verdictReads();
    if (reads) return reads.listWithVerdicts(options);
    const envelopes = await this.storage.list(options);
    return envelopes.map((envelope) => ({ envelope, verdict: unmeasuredRecordVerdict(envelope) }));
  }

  /**
   * The storage layer's verdict-carrying reads, when it has them.
   *
   * Structural, not `instanceof VerifyingStorageProxy`: the proxy computes the
   * verdict locally and the cloud adapter gets it from the server, and both
   * answer to the same two method names on purpose. Branching on the class left
   * the cloud adapter on the fallback path, where `storage.retrieve()` throws
   * `TzunCloudReadUnsupportedError` — so a cloud read reported the transport as
   * having no read path after it had one.
   */
  private verdictReads(): VerdictReads | undefined {
    const storage = this.storage as StorageAdapter & Partial<VerdictReads>;
    return typeof storage.retrieveWithVerdict === 'function' &&
      typeof storage.listWithVerdicts === 'function'
      ? (storage as VerdictReads)
      : undefined;
  }

  /**
   * The storage layer's server-side verify and export, when it has them (the
   * cloud transport). A local store has neither: its verify and export are
   * computed here, from the records.
   */
  private remoteRecordReads(): RemoteRecordReads | undefined {
    const storage = this.storage as StorageAdapter & Partial<RemoteRecordReads>;
    return typeof storage.verifyRecord === 'function' &&
      typeof storage.exportEvidence === 'function'
      ? (storage as RemoteRecordReads)
      : undefined;
  }

  /**
   * Extract an AI-BOM from a vendor SDK call's `(request, response)` pair.
   *
   * `vendor` is one of the eight supported labels: `openai`, `anthropic`,
   * `bedrock`, `vertex`, `azure-ai`, `nvidia-nim`, `hf-inference`,
   * `openrouter`. Unknown vendors throw with the supported list in the error
   * message. For `openrouter`, pass the gateway base URL the client called as
   * `request.openrouter_endpoint` to record it as `infrastructure.endpoint`;
   * nothing is assumed without it.
   *
   * Returns `null` when the connector cannot extract a model (e.g., no
   * `model` field on the response). Reuses the per-Tzun LRU cache for
   * descriptor registration — repeat calls with the same vendor/model
   * skip the catalog round trip.
   *
   * `hook()` does NOT call `tzun.capture()`. The caller passes the returned
   * `AiBom` to `tzun.capture({ ..., contributions: singleModel(aiBom) })`
   * when the call drives a decision. On a store with no model catalog (an
   * adapter without one, or the cloud transport against a platform that does
   * not serve `POST /v1/models`), the descriptor cannot be registered:
   * `hook()` returns `null` and logs `capture_model_not_recordable`.
   */
  async hook(
    vendor: string,
    request: Record<string, unknown>,
    response: Record<string, unknown>,
  ): Promise<AiBom | AiBomWithInlineDescriptor | null> {
    // Lazy import avoids a top-of-file circular: wrappers.ts imports Tzun
    // from this file, so we route through a function reference here.
    const { hook: hookFn } = await import('./wrappers');
    return hookFn(this, vendor, request, response);
  }

  /**
   * Wrap a vendor SDK client so per-call `tzun_capture` kwargs trigger
   * `tzun.capture()` automatically.
   *
   * Detection is duck-typed against the vendor call shapes:
   *   - `chat.completions.create` → openrouter when the client's `baseURL`
   *     host is `openrouter.ai`, else openai (also NIM via
   *     `{ vendor: 'nvidia-nim' }`)
   *   - `messages.create` → anthropic
   *   - `send` + `BedrockRuntimeClient` constructor → bedrock
   *   - `generateContent` or `predict` → vertex
   *   - `complete` or `getChatCompletions` → azure-ai
   *   - `chatCompletion` or `textGeneration` → hf-inference
   *
   * Returns a new object that shares the original's prototype + own props
   * (`Object.create` + `Object.assign`). Only the vendor-specific call
   * methods are intercepted; everything else passes through to the
   * underlying client unchanged.
   *
   * Calls that omit `tzun_capture` are pure pass-through — no AI-BOM
   * extraction, no capture. Calls that include `tzun_capture` strip it
   * from the forwarded params, call `tzun.hook()` to build an AI-BOM, then
   * `tzun.capture()` with the response and decision payload.
   *
   * Pass `options.emitAiBom: false` as a kill-switch — wrapper becomes a
   * true no-op regardless of `tzun_capture` presence.
   */
  attach<T extends object>(client: T, options?: import('./wrappers').AttachOptions): T {
    // Synchronous lazy require avoids the top-of-file circular import.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { attachClient } = require('./wrappers') as typeof import('./wrappers');
    return attachClient(client, this, options);
  }

  /**
   * The storage adapter this instance was configured with (for testing and
   * advanced use) — without the verifying proxy, so a read through it carries
   * no verdict and reports nothing. Read evidence with `get()` / `list()`.
   */
  getStorage(): StorageAdapter {
    return this.storage instanceof VerifyingStorageProxy ? this.storage.unwrap() : this.storage;
  }

  /** Mandates (Record §9.6): prepare, issue, revoke, confirm, read. */
  get mandates(): MandatesApi {
    return this.sdkExtensions.mandates.api;
  }

  /** The agent catalog (agent descriptors, Record §6.9): register, get, list. */
  get agents(): AgentsApi {
    return this.sdkExtensions.agents.api;
  }

  /** Links (Record §8): link records, a record's links, the records linking to a digest. */
  get links(): LinksApi {
    return this.sdkExtensions.links.api;
  }

  /** The decision graph: a bounded walk over links and link records. */
  get decisionGraph(): DecisionGraphApi {
    return this.sdkExtensions.links.decisionGraph;
  }

  /** Decider commitments (Record §6.3): a record's stored opening. */
  get deciders(): DecidersApi {
    return {
      opening: async (evidenceId: string) => {
        if (typeof this.storage.getDeciderOpening !== 'function') return null;
        return this.storage.getDeciderOpening(evidenceId);
      },
    };
  }

  /**
   * The reference `freshness: 'auto'` writes now (Record §6.6): the
   * header follower's finalized block when it is younger than
   * `anchoring.freshnessMaxAgeMs`, else the store's shared row under the same
   * rule, else `null`. `null` without anchoring. Never calls a chain.
   */
  private async currentFreshnessReference(): Promise<string | null> {
    return this.headerFollower ? this.headerFollower.reference() : null;
  }

  /** The evidence-log origin of `chainId` in this store, or `null` for a store without evidence logs. */
  private async evidenceLogOrigin(chainId: string): Promise<string | null> {
    const logs = logStoreFor(this.getStorage());
    if (!logs) return null;
    const identity = await logs.getStoreIdentity();
    return evidenceLogOrigin(identity.ns, identity.storeId, chainId);
  }

  /** An RFC 3161 token over `digestHex` from this instance's authorities, or `null` (none configured, none answered). */
  private async timestampDigest(digestHex: string): Promise<string | null> {
    const client = this.attestationClients.timestampClient;
    if (!client) return null;
    try {
      return (await client.requestTimestamp(digestHex)).token;
    } catch (error) {
      sdkLog(this.onLog, 'extension_timestamp_unavailable', {
        errorName: error instanceof Error ? error.name : typeof error,
      });
      return null;
    }
  }

  /**
   * What an SDK extension is given (`extension-points.ts`): the store, the
   * chain, freshness, timestamps, the credential store, the system-record
   * capture and the log sink of this instance.
   */
  private extensionHost(): SdkHost {
    return {
      storage: this.storage,
      activeChainId: () => this.activeChainId,
      evidenceLogOrigin: (chainId: string) => this.evidenceLogOrigin(chainId),
      freshnessReference: () => this.currentFreshnessReference(),
      anchoringConfigured: () => this.anchorScheduler !== null,
      timestampDigest: (digestHex: string) => this.timestampDigest(digestHex),
      credentialStore: () => this.getCredentialStore(),
      captureSystemRecord: (request: SystemRecordCapture, options?: SystemRecordCaptureOptions) =>
        this.captureSystemRecord(request, options),
      prepareSystemRecord: (request: SystemRecordCapture) => this.prepareSystemRecord(request),
      log: (event: string, fields: Record<string, unknown>) => sdkLog(this.onLog, event, fields),
    };
  }

  /**
   * The durable credential directory behind this instance's storage, or
   * `undefined` when the backend has none (cloud transport, or a third-party
   * adapter that does not provide one).
   *
   * `undefined` is a real answer, not a defect: it is what keeps
   * `verifyAttestation()` reporting `signatureValid: null` /
   * `no_credential_store` rather than inventing a verdict it cannot support.
   */
  getCredentialStore(): AsyncCredentialStore | undefined {
    return credentialStoreFor(this.storage);
  }

  /**
   * @internal — used by `wrappers.ts` to emit structured log events on behalf
   * of this Tzun instance. Not part of the public API surface.
   */
  getLogSink(): LogSink | undefined {
    return this.onLog;
  }

  /**
   * Return per-vendor connector usage counters accumulated since this Tzun
   * instance was created.
   *
   * Counters reset when the instance is disposed. For durable telemetry, route
   * via `TzunConfig.onLog` and aggregate externally.
   *
   * @returns A record keyed by vendor name with `calls` and `aiBomsProduced`.
   */
  getConnectorUsageStats(): Record<string, { calls: number; aiBomsProduced: number }> {
    // Lazily import to avoid the top-of-file circular import.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { hookStateByTzun } = require('./wrappers') as { hookStateByTzun: WeakMap<Tzun, { usage: Record<string, { calls: number; aiBomsProduced: number }> }> };
    const state = hookStateByTzun.get(this);
    return state ? { ...state.usage } : {};
  }

  /**
   * Get the current scanner state, or null if scanner is not configured.
   */
  getScannerState(): ScannerState | null {
    return this.scanner ? this.scanner.getState() : null;
  }

  /**
   * The anchor scheduler's state, or `null` when this instance does not anchor
   * (no `anchoring`): the lease holder, when the next epoch is due, the last
   * published and last finalized publication and what is in flight, the
   * publisher's wallet (nonce base, balance, runway), the fee caps, the
   * interval, the spend, the forced publications of the last 24 hours, the fill
   * backlog, stalled passes and the alarms, including a stopping one
   * (`halted`).
   *
   * @throws on an instance that anchors and is closed.
   */
  async getAnchorState(): Promise<AnchorState | null> {
    if (!this.anchorScheduler) return null;
    this.refuseClosed('getAnchorState()');
    return this.anchorScheduler.getAnchorState();
  }

  /**
   * Run an anchor pass now, after any pass in flight. With
   * `force: true` an epoch is cut even when the cadence says it is not due,
   * `minIntervalMs` included; the hard fee cap, the soft maximum, the 3×
   * balance refusal and the rolling limit (`anchoring.budget.forcePerDay`, 6
   * a day by default) still hold. The report says what the pass did, and why
   * a due epoch was put off (`deferred`).
   *
   * @throws when this instance does not anchor (no `anchoring`), or is closed.
   * @throws {AnchorForceRateLimitedError} a forced epoch past the rolling limit.
   */
  async anchorNow(options?: { force?: boolean }): Promise<AnchorPassReport> {
    if (!this.anchorScheduler) {
      throw new Error(
        '[Tzun] anchorNow(): this instance does not anchor. Configure `anchoring` in Tzun.init() on a SQLite or Postgres store.',
      );
    }
    this.refuseClosed('anchorNow()');
    const pass = this.anchorScheduler.anchorNow(options);
    // The header follower reads the finalized block beside the pass, so an
    // instance that drives anchoring by hand has a freshness reference too.
    // Both are awaited together: the pass has a handler from the start, so a
    // pass that fails while the read is in flight rejects this call at once
    // instead of going unhandled. The read logs its own failure.
    const read = this.headerFollower?.refresh().catch((error) =>
      sdkLog(this.onLog, 'header_follower_read_failed', {
        errorName: error instanceof Error ? error.name : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      }),
    );
    const [report] = await Promise.all([pass, read]);
    return report;
  }

  /** Refuse `what` on an instance whose `close()` has been called: its store is closed or closing. */
  private refuseClosed(what: string): void {
    if (this.closed) throw new Error(`[Tzun] ${what}: this instance is closed. Create a new one with Tzun.init().`);
  }

  /**
   * Get the active chain ID. Reads from the instance field which is set
   * during init() and updated on fork().
   */
  async getActiveChainId(): Promise<string> {
    return this.activeChainId;
  }

  /**
   * Get the count of sealed chains. Reads from storage on-demand.
   */
  async getSealedChainCount(): Promise<number> {
    const chains = await this.storage.listChains();
    return chains.filter((c: ChainIdentity) => c.status === 'sealed').length;
  }

  /**
   * Run chain completeness verification over ONE chain.
   *
   * Defaults to the active chain — the one `capture()` is appending to.
   *
   * Sequence numbers are unique only WITHIN a chain: `recovery.fork()` seals
   * the old chain and restarts the new one at 1. A walk of
   * `listBySequence(1, lastSequence)` with no chain filter would interleave
   * the two chains of a forked store into one sequence order and report the
   * collisions as `duplicateSequences` and every chain-boundary crossing as a
   * broken link: on a clean three-then-two fork, `valid: false` with two
   * duplicate sequences and three broken links — a false alarm, published
   * through `GET /v1/integrity/chain`, which trains an operator to ignore the
   * one control that tells them their evidence is intact. It would also drop
   * records silently: a `toSequence` taken from the post-fork chain state (2)
   * leaves the sealed chain's record 3 outside the range. So the walk covers
   * one chain, up to that chain's own upper bound.
   *
   * Use `verifyAllChains()` for the whole store, sealed chains included.
   *
   * The walk also recomputes every record's canonical digest and reports the
   * records that do not hash to their stored one, in `digestMismatches`. The
   * structural checks — sequence continuity, duplicates, and
   * `chainLink == SHA-256(prev ‖ cur)` — are all computed over digests, so a
   * rewritten payload with a stale digest disturbs none of them: without this
   * check a chain holding a forged record would read `valid: true`. That is
   * the attack the product exists to catch, and the only one of the four that
   * needs neither an added nor a deleted row. There is no opt-out; see the
   * engine function's own doc for why, and for the measured cost.
   *
   * The walk also compares every record against the digest it was CAPTURED
   * with, from the append-only revision log, and reports the differences in
   * `digestSuperseded`. That check exists because the other four are all
   * answers about the store's PRESENT state, and the rewrite-and-reseat attack
   * satisfies all four by construction: the attacker recomputes the digest (so
   * no `digestMismatch`) and repairs the record's own link (so `brokenLinks`
   * names only its SUCCESSOR, which looks exactly like one honestly corrupted
   * link). Records captured before 0.3.16 have no capture revision and can
   * never appear there; that absence means unprovable, not clean.
   */
  async verifyChainCompleteness(chainId?: string): Promise<ChainCompletenessResult> {
    const target = chainId ?? this.activeChainId;
    const toSequence = await this.chainUpperBound(target);
    const evidenceLog = await this.chainEvidenceLog(target);
    return verifyChainCompleteness(this.storage, this.registry, {
      toSequence,
      chainId: target,
      ...(evidenceLog && { evidenceLog }),
    });
  }

  /**
   * The chain's evidence log, for the walk's two checks against it (a record
   * that no longer matches its logged leaf, and a record left without the
   * anchor its finished epoch gave it): its leaves, and whether the fill of
   * the epoch that anchors a leaf has finished. Null on a store that keeps no
   * evidence logs (the cloud transport), before the chain's first record, and
   * when the logs cannot be read, which is logged
   * (`chain_walk_evidence_log_unread`); the walk then reports neither check.
   */
  private async chainEvidenceLog(chainId: string): Promise<ChainEvidenceLog | null> {
    try {
      return (await StoreLogs.open(this.storage))?.chainEvidenceLog(chainId)?.reader ?? null;
    } catch (error) {
      sdkLog(this.onLog, 'chain_walk_evidence_log_unread', {
        chainId,
        errorName: error instanceof Error ? error.name : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  /**
   * Run chain completeness verification over EVERY chain in the store.
   *
   * `valid` is the AND across all chains. A sealed chain is the read-only
   * remainder of a fork and is precisely where an insider would tamper, so
   * scoping the answer to the active chain alone would be wrong in the
   * reassuring direction — the worse of the two errors for an evidence store.
   */
  async verifyAllChains(): Promise<MultiChainCompletenessResult> {
    // Every chain that has RECORDS, not every chain that has an identity row.
    // Enumerating `listChains()` alone, falling back to the active chain only
    // when there are no rows at all, is not enough: 'default' is implicit
    // until something materialises it, so one non-default identity row (the
    // one thing the public storeChain() lets an integrator do towards
    // per-tenant chains) would drop every record on the implicit default
    // chain from the walk. An empty chain is vacuously valid, so the AND below
    // would stay `true` over a tampered record this method had never read:
    // three records on default, an empty tenant-b row, default's record 3
    // re-linked to the string 'TAMPERED' →
    // `{ valid: true, chains: [['tenant-b', true, 0]] }`. The union in
    // listStoreChainIds() is what makes the answer structurally about the
    // whole store; `chains` names every chain walked with its own verdict and
    // record count, so a reader can check the coverage against the store rather
    // than take `valid` on trust.
    const chainIds = await listStoreChainIds(this.storage, this.activeChainId);

    const chains: ChainCompletenessResult[] = [];
    for (const id of chainIds) {
      chains.push(await this.verifyChainCompleteness(id));
    }

    const active =
      chains.find((c) => c.chainId === this.activeChainId) ?? chains[0];

    return {
      valid: chains.every((c) => c.valid),
      activeChainId: this.activeChainId,
      active,
      chains,
    };
  }

  /**
   * Highest sequence number a chain is known to have reached.
   *
   * Passed to the engine as `toSequence` so that trailing gaps — a deleted
   * TAIL — are detected: without an upper bound the engine has nothing to
   * compare the last surviving record against and reports a truncated chain as
   * complete.
   *
   * Chain state is per chain, so this is the chain's OWN high-water mark,
   * whether it is the chain this instance writes to, another tenant's, or one
   * a fork sealed. A chain with no state row falls back to the head the seal
   * recorded (`sealedOldChainHead` — the head SEQUENCE, not
   * `sealedOldChainLength`, which is a row count and falls short of the head
   * on a gapped chain). A fork row written before 0.3.14 has no recorded
   * head; `chainUpperBound()` recomputes a bound for it rather than reading the
   * count as a sequence.
   *
   * `undefined` means the chain has never held a record — which is why an empty
   * chain verifies clean while a chain whose records were all deleted does not.
   */
  private async chainUpperBound(chainId: string): Promise<number | undefined> {
    return chainUpperBound(this.storage, chainId);
  }


  /**
   * Emit a monitoring event into the event bus.
   * Used by the API layer for on-demand verification.
   * No-op if monitoring is not enabled.
   */
  emitMonitoringEvent(event: MonitoringEvent): void {
    if (this.eventBus) {
      this.eventBus.emit(event);
    }
  }

  /**
   * Verify a range of records by sequence number.
   * Returns a summary of verified records and issues found.
   * Uses the same verification pipeline as the scanner.
   *
   * Records are verified in sequence order, with each record's chain link
   * validated against the previous record's digest.
   */
  async verifyRange(
    fromSequence: number,
    toSequence?: number,
    chainId?: string,
  ): Promise<{ recordsVerified: number; issuesFound: number; results: VerificationResult[] }> {
    // Scoped to one chain for the same reason as verifyChainCompleteness: a
    // sequence RANGE only identifies records within a chain. Unscoped, a
    // forked store would return both chains' record N side by side and then
    // validate each one's chain link against whichever of them the sort
    // happened to place first, emitting chain_break incidents on an
    // untampered store.
    const chain = chainId ?? this.activeChainId;
    const to = toSequence ?? await this.chainUpperBound(chain) ?? await this.storage.getLastSequence(chain);
    const records = await this.storage.listBySequence(fromSequence, to, chain);
    const results: VerificationResult[] = [];
    let issuesFound = 0;

    // If the range does not start at record 1, fetch the preceding record
    // so we can validate the first record's chain link.
    let prevDigest: string | undefined;
    if (fromSequence > 1) {
      const preceding = await this.storage.listBySequence(fromSequence - 1, fromSequence - 1, chain);
      if (preceding.length > 0) {
        prevDigest = preceding[0].integrity.canonicalDigest;
      }
    }

    for (const record of records) {
      // A record that names a step model, a link or an agent is verified at
      // store level; one that names none takes the cheap sync branch.
      const result = await this.verifyStored(record, prevDigest, { aiBom: true });
      results.push(result);

      if (!result.verified) {
        issuesFound++;
        // Emit the event that describes what actually failed.
        //
        // Not every failure is a 'digest_mismatch'. Reported as one, a broken
        // chain link, an unverifiable schema version, or any of the four
        // AI-BOM descriptor incidents would produce a CRITICAL incident whose
        // details string asserts a mismatch between two digests it then
        // prints identically ("stored=b008…2fe1, recomputed=b008…2fe1"). The
        // incident log — the artifact a regulator reads — would contain a
        // statement that is false on its face, the real cause would go
        // unrecorded, and NotificationRouter's `${evidenceId}:digest_mismatch`
        // dedup key would suppress a genuine later digest_mismatch on the same
        // record for an hour.
        //
        // An unknown schemaVersion leaves recomputedDigest === '' (no rules to
        // hash with) and so lands in the digest branch. That is deliberate: the
        // registry only ever holds v1.0, so any other value is itself evidence
        // of modification.
        if (result.storedDigest !== result.recomputedDigest) {
          this.emitMonitoringEvent({
            type: 'digest_mismatch',
            evidenceId: record.payload.evidenceId,
            stored: result.storedDigest,
            recomputed: result.recomputedDigest,
          });
        } else if (result.chainLinkValid === false) {
          this.emitMonitoringEvent({
            type: 'chain_break',
            evidenceId: record.payload.evidenceId,
            sequenceNumber: record.payload.sequenceNumber,
            expectedPrevDigest: prevDigest ?? '',
          });
        } else {
          // Descriptor-catalog tampering flips `verified` via the verifier's
          // own incidents. Re-emit them rather than inventing a digest claim.
          for (const incident of result.tamperIncidents ?? []) {
            this.emitMonitoringEvent(incident);
          }
        }
      }

      // Use this record's digest as the previous for the next iteration
      prevDigest = record.integrity.canonicalDigest;
    }

    return {
      recordsVerified: records.length,
      issuesFound,
      results,
    };
  }

  /**
   * Register a listener for monitoring events.
   * No-op if monitoring is not enabled.
   */
  on(event: 'tamper', listener: (incident: TamperIncident) => void): void;
  on(event: 'scan.completed', listener: (summary: ScanSummary) => void): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  on(event: string, listener: (...args: any[]) => void): void {
    if (this.eventEmitterChannel) {
      this.eventEmitterChannel.on(event as 'tamper', listener);
    }
  }

  /**
   * Remove a monitoring event listener.
   * No-op if monitoring is not enabled.
   */
  off(event: 'tamper', listener: (incident: TamperIncident) => void): void;
  off(event: 'scan.completed', listener: (summary: ScanSummary) => void): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  off(event: string, listener: (...args: any[]) => void): void {
    if (this.eventEmitterChannel) {
      this.eventEmitterChannel.off(event as 'tamper', listener);
    }
  }

  /**
   * Run a single full scan pass. Requires monitoring + scanner to be configured.
   * Returns when the pass is complete.
   */
  async runScan(): Promise<void> {
    if (!this.scanner) {
      throw new Error('Scanner is not configured. Enable monitoring with scanner config in Tzun.init().');
    }
    await this.scanner.runFullPass();
    // The pass has emitted every incident it found; TamperDetector persists
    // them without blocking the bus, so on Postgres they may still be in
    // flight here. Resolving before they land made "runScan(), then read the
    // incidents" a race the caller could not see.
    if (this.tamperDetector) {
      await this.tamperDetector.settle();
    }
  }

  /**
   * Gracefully shut down the SDK instance.
   *
   * Stops the pending-attestation retry schedule, the anchor scheduler and
   * the scanner (each after the pass in flight), lets incidents on their way
   * to storage land, and closes the store. It starts no chain call: an anchor
   * pass in flight finishes first, and the scheduler's outbox resumes in the
   * next process. The anchor lease is released. Safe to call multiple times
   * (idempotent).
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;

    // Awaited: stop() resolves once any pass in flight has finished, so the
    // store below is never closed underneath a running pass. The same holds
    // for a pending-attestation retry pass, scheduled or manual, which writes
    // the tokens it obtains, and for an anchor pass, which writes epochs,
    // attempts and fills.
    await this.attestationRetry.stop();
    this.headerFollower?.stop();
    this.headerFollowerClient?.close();
    if (this.anchorScheduler) {
      await this.anchorScheduler.close();
    }
    if (this.scanner) {
      await this.scanner.stop();
    }
    this.scannerChainClient?.close();

    // Incidents still on their way to storage must land before the pool
    // below is closed under them; otherwise the INSERT fails after the
    // scanner has already reported the tamper, and the failure is swallowed
    // by the detector's log-and-continue.
    if (this.tamperDetector) {
      await this.tamperDetector.settle();
    }

    // Propagate to storage so connection pools and file handles are
    // released. Without this, a Tzun.init({ dbUrl: ... }) + tzun.close()
    // pattern leaks the Postgres pool past the SDK lifecycle. The interface
    // method is optional; adapters that hold no external resource (memory)
    // implement it as a no-op.
    if (this.storage.close) {
      await this.storage.close();
    }
  }
}

/**
 * What the scanner of an instance that anchors reads the store against:
 * `chain`, the publisher's chain; the verifiers' manifest and the publisher
 * wallets' nonce floors when they are configured; the cadence's T_max.
 */
function scannerAnchoringDeps(anchoring: ResolvedAnchoringConfig, chain: ScannerEvmChain): ScannerAnchoringDeps {
  return {
    evmChains: { [anchoring.evm.chain]: chain },
    maxStalenessMs: anchoring.cadence.maxStalenessMs,
    ...(anchoring.publisherManifest && { publisherManifest: anchoring.publisherManifest }),
    ...(anchoring.nonceBases && { nonceBases: anchoring.nonceBases }),
  };
}

/** One capture, as the pipeline runs it: a caller's, or a system record's. */
interface CaptureRequest {
  /** The input, shape-checked, with `aiSystemId` resolved. */
  input: CaptureInput;
  /** A system record admits its kind's reserved `aiSystemId`. */
  systemRecord?: SystemRecordKind;
  /** The reserved relations a system record may carry. */
  allowReserved?: readonly ('mandate' | 'revokes' | 'subject')[];
  /** A link record (`tzun.links.relate`). */
  linkRecord?: boolean;
  /** Attestation a system record carries beside what the SDK obtains: an issuance block. */
  extraAttestation?: { mandateIssuance?: MandateBlock };
  /** A system record's own store options, per attempt. */
  storeOptions?: SystemRecordCapture['storeOptions'];
  /** A system record's classification of its own store refusals. */
  classifyStoreError?: SystemRecordCapture['classifyStoreError'];
  idempotencyKey?: string;
  prepared?: PreparedAssertionChallenge;
  /** The settled caller expectation (`null` for none); a mandate's plan replaces it. */
  signoffExpectation: SignatureRequiredExpectation | null;
  mandate?: { mandateId: string };
  requireFreshness?: boolean;
}

/** What every build attempt of one capture reuses, resolved once before the first. */
interface ResolvedMembers {
  decider: Decider;
  /** The opening of a `cmt:` decider the SDK committed, kept in the storing transaction. */
  deciderOpening: DeciderOpening | null;
  contributions: Contributions | null;
  links: Link[] | null;
}

/**
 * The first prepared member that is not what this capture's input resolves
 * to, as an `invalid_prepared` refusal on `prepared.<member>`, or `null`.
 * Members are compared by their canonical bytes.
 */
function preparedMemberMismatch(prepared: PreparedAssertionChallenge, resolved: ResolvedMembers): CaptureInputViolation | null {
  const same = (a: unknown, b: unknown): boolean => {
    try {
      return canonicalSerializeValue(a ?? null) === canonicalSerializeValue(b ?? null);
    } catch {
      return false;
    }
  };
  const pairs: Array<['decider' | 'contributions' | 'links', unknown, unknown]> = [
    ['decider', prepared.decider, resolved.decider],
    ['contributions', prepared.contributions, resolved.contributions],
    ['links', prepared.links, resolved.links],
  ];
  for (const [name, held, now] of pairs) {
    if (!same(held, now)) {
      return resolutionRefusal(
        `prepared.${name}`,
        'invalid_prepared',
        `prepared.${name} is not what this capture's input resolves to: capture with the input prepareAssertionChallenge() was given`,
      );
    }
  }
  return null;
}

/** A system record's capture request, or why it is refused. */
function systemCaptureRequest(
  request: SystemRecordCapture,
  options: SystemRecordCaptureOptions,
): { request: CaptureRequest } | { violation: CaptureInputViolation } {
  if (request.kind !== 'mandate' && request.kind !== 'link') {
    return { violation: resolutionRefusal('kind', 'invalid_system_record', 'a system record is of kind mandate or link') };
  }
  const input: CaptureInput = {
    aiOutput: request.aiOutput,
    action: request.action,
    reason: request.reason,
    decider: request.decider,
    links: request.links ?? null,
    ...(request.attestation?.webauthnAssertion !== undefined && {
      attestationInputs: { webauthnAssertion: request.attestation.webauthnAssertion },
    }),
  };
  const shape = captureInputViolation(input);
  if (shape) return { violation: shape };
  return {
    request: {
      input: { ...input, aiSystemId: SYSTEM_RECORD_AI_SYSTEM_IDS[request.kind] },
      systemRecord: request.kind,
      signoffExpectation: null,
      ...(request.allowReserved !== undefined && { allowReserved: request.allowReserved }),
      ...(request.linkRecord === true && { linkRecord: true }),
      ...(request.attestation?.mandateIssuance !== undefined && {
        extraAttestation: { mandateIssuance: request.attestation.mandateIssuance },
      }),
      ...(request.storeOptions !== undefined && { storeOptions: request.storeOptions }),
      ...(request.classifyStoreError !== undefined && { classifyStoreError: request.classifyStoreError }),
      ...(options.idempotencyKey !== undefined && { idempotencyKey: options.idempotencyKey }),
      ...(options.prepared !== undefined && { prepared: options.prepared }),
    },
  };
}

/**
 * Under `decider.commit: true`, a `decide` step whose actor is the caller's
 * decider carries the decider's commitment too (Record §7.3): the
 * one commitment, the same string in both. Any other actor is left as given.
 */
function committedDecideActor(
  contributions: ContributionsInput,
  deciderInput: DeciderInput,
  decider: Decider,
): ContributionsInput {
  if (deciderInput.commit !== true || !Array.isArray(contributions.steps)) return contributions;
  const innerId =
    deciderInput.id ?? (deciderInput.kind !== 'human' && typeof deciderInput.agent === 'string' ? defaultAgentDeciderId(deciderInput.agent) : undefined);
  const steps = contributions.steps.map((step) => {
    const actor = isPlainObject(step) ? step.actor : null;
    if (!isPlainObject(actor) || stepClass(step.role) !== 'decide') return step;
    const actorId = actor.id ?? (actor.kind !== 'human' && typeof actor.agent === 'string' ? defaultAgentDeciderId(actor.agent) : undefined);
    if (actor.kind !== deciderInput.kind || actorId !== innerId || (actor.agent ?? null) !== (deciderInput.agent ?? null)) return step;
    return { ...step, actor: { kind: decider.kind, id: decider.id, agent: decider.agent } };
  });
  return { ...contributions, steps };
}

/** Every agent reference a record names: the decider's, then each step actor's, in step order. */
function agentReferences(decider: Decider, contributions: Contributions | null): AgentReference[] {
  const refs: AgentReference[] = [];
  if (typeof decider.agent === 'string') refs.push({ field: 'decider.agent', kind: decider.kind, agent: decider.agent });
  contributions?.steps.forEach((step, i) => {
    if (step.actor && typeof step.actor.agent === 'string') {
      refs.push({ field: `contributions.steps[${i}].actor.agent`, kind: step.actor.kind, agent: step.actor.agent });
    }
  });
  return refs;
}

/** The client for each attestation component an instance obtains. */
interface AttestationClients {
  timestampClient?: RFC3161Client;
}

/**
 * Build the attestation clients from validated attestation config: capture's
 * orchestrator is built from them, and the pending-attestation retry attests
 * with them one component at a time.
 *
 * Returns null if no attestation services are required or deferrable, meaning
 * the SDK operates without attestation (typical for dev mode).
 */
function buildAttestationClients(
  validated: ValidatedAttestationConfig,
  raw?: TzunConfig['attestation'],
): AttestationClients | null {
  const allServices = [...validated.require, ...validated.deferrable];

  if (allServices.length === 0) {
    return null;
  }

  const timestampClient = allServices.includes('timestamp')
    ? new RFC3161Client({
        tsaUrl: raw?.timestamp?.rfc3161Url,
        tsaUrls: raw?.timestamp?.rfc3161Urls,
      })
    : undefined;

  return { timestampClient };
}

/**
 * The pending-attestation retry schedule for this instance, validated.
 *
 * A production mode on a local store with a deferrable component retries
 * every {@link DEFAULT_ATTESTATION_RETRY_INTERVAL_MS} unless `intervalMs` says
 * otherwise; anything else has no schedule unless one is configured. The cloud
 * transport refuses a configured schedule: the retry lists pending records by
 * reading the store, which that transport cannot do, and the platform's worker
 * attests cloud records.
 */
function resolveAttestationRetryOptions(
  mode: Mode,
  validated: ValidatedAttestationConfig,
  retry: NonNullable<TzunConfig['attestation']>['retry'],
  usesHttpTransport: boolean,
): AttestationRetrySchedulerOptions {
  if (usesHttpTransport && (retry?.intervalMs ?? 0) > 0) {
    throw new Error(
      '[Tzun] `attestation.retry.intervalMs` is not supported on the cloud transport (apiKey ' +
        'set). The retry finds its work with listByMissingObtainable, a queue read that ' +
        "transport does not serve, and it would have nothing to do if it could: the platform's " +
        'attestation worker timestamps cloud records. Remove attestation.retry, or run against ' +
        'a local store (dbUrl / dbPath).',
    );
  }
  const scheduledByDefault =
    mode !== 'dev' && !usesHttpTransport && validated.deferrable.length > 0;
  const options: AttestationRetrySchedulerOptions = {
    intervalMs: retry?.intervalMs ?? (scheduledByDefault ? DEFAULT_ATTESTATION_RETRY_INTERVAL_MS : 0),
    ...(retry?.batchSize !== undefined ? { batchSize: retry.batchSize } : {}),
    ...(retry?.maxBackoffMs !== undefined ? { maxBackoffMs: retry.maxBackoffMs } : {}),
  };
  validateAttestationRetryOptions(options);
  return options;
}

/**
 * The artifacts for `components` out of an attestation result, and nothing
 * else: what a retry may add to a record without replacing anything it holds.
 */
function pickComponents(
  artifacts: AttestationArtifacts,
  components: RetryObtainableComponent[],
): AttestationArtifacts {
  const picked: AttestationArtifacts = {};
  if (components.includes('timestamp') && artifacts.rfc3161Token) {
    picked.rfc3161Token = artifacts.rfc3161Token;
    if (artifacts.rfc3161Metadata) picked.rfc3161Metadata = artifacts.rfc3161Metadata;
  }
  return picked;
}

/**
 * Turn whatever `captureLocked()` threw into a FailureRecord that keeps the
 * information the caller needs to act.
 *
 * `HttpTransport.capture()` throws a `TzunCaptureError` carrying the
 * backend's stable wire code, the HTTP status, a `retryable` flag and
 * structured context, and `Tzun.capture()`, the only public surface, keeps
 * all of it. Flattened into `failureType: 'serialization_failure'` plus a
 * message string, a revoked API key (401), a chain conflict (409), an
 * over-size payload (413), a store outage (503) and a DNS failure would be
 * indistinguishable to the integrator, alerting keyed on `failureType` would
 * file every one of them as a payload bug, and nothing would tell a caller
 * that the 503 was safe to retry and the 401 was not.
 *
 * Cloud failures surface as `cloud_<code>` (e.g. `cloud_unauthenticated`,
 * `cloud_chain_conflict`, `cloud_transport_error`) with the status, the
 * retryable flag and the server's context in `diagnosticMetadata`.
 *
 * A LOCAL adapter's refused conditional append (`ChainConflictError`, the
 * SQLite/Postgres/memory twin of the 409) is not a `TzunCaptureError`, but it
 * must be just as distinguishable. It surfaces as `chain_conflict` with
 * `code`, `retryable: true`, the attempt count and both heads, so "the head
 * moved under me" reads differently from "the payload could not be
 * serialised" in the failure table and in whatever alerts on it.
 * A local store's refusal of a duplicate evidenceId surfaces as
 * `evidence_id_conflict`, an append to a sealed chain as `chain_sealed`, and a
 * keyed capture whose idempotency key names another decision as
 * `idempotency_conflict`, each with `code` and `retryable: false` — the local
 * twins of `cloud_evidence_id_conflict` and of the cloud backend's
 * `chain_sealed` and 422 `idempotency_conflict`. Every other non-cloud throw is
 * `serialization_failure`.
 *
 * `retryRefused` names the one conflict the loop will not retry however many
 * attempts remain — a caller-supplied WebAuthn assertion bound to the refused
 * record's digest. `retryable` stays `true` on that record: the capture CAN
 * be resubmitted, by the caller, with a fresh ceremony; the field says why the
 * SDK did not do it for them.
 *
 * The API key never appears in a TzunCaptureError's message or context, so
 * copying both here cannot leak it.
 */
function buildCaptureFailure(
  error: unknown,
  evidenceId?: string,
  attempts?: number,
  retryRefused?: RetryRefusedReason,
): FailureRecord {
  const capturedAt = new Date().toISOString();

  if (error instanceof ChainConflictError) {
    return {
      failureType: 'chain_conflict',
      ...(evidenceId !== undefined ? { evidenceId } : {}),
      diagnosticMetadata: {
        reason: error.message,
        code: error.code,
        retryable: error.retryable,
        ...(attempts !== undefined ? { attempts } : {}),
        ...(retryRefused !== undefined ? { retryRefused } : {}),
        expectedHead: error.expected,
        actualHead: error.actual,
      },
      capturedAt,
    };
  }

  // A local store's refusal of the record's evidenceId: the local twin of
  // `cloud_evidence_id_conflict`, and like it not retryable, because the same
  // record is refused every time.
  if (error instanceof DuplicateRecordError && error.recordType === 'Evidence record') {
    return {
      failureType: 'evidence_id_conflict',
      ...(evidenceId !== undefined ? { evidenceId } : {}),
      diagnosticMetadata: {
        reason: error.message,
        code: 'evidence_id_conflict',
        retryable: false,
      },
      capturedAt,
    };
  }

  // A record the chain's evidence log cannot take: a gap (a chain that lost
  // records before its log existed), a repeated leaf, or a malformed position
  // or chain id. The same record is refused every time.
  if (error instanceof EvidenceLogRefusalError) {
    return {
      failureType: 'evidence_log_refused',
      ...(evidenceId !== undefined ? { evidenceId } : {}),
      diagnosticMetadata: {
        reason: error.message,
        code: error.code,
        refusalReason: error.reason,
        retryable: error.retryable,
        chainId: error.chainId,
        sequenceNumber: error.sequenceNumber,
      },
      capturedAt,
    };
  }

  // An append to a sealed chain. `chain_sealed` is the platform's code for the
  // same refusal.
  if (error instanceof ChainSealedError) {
    return {
      failureType: 'chain_sealed',
      ...(evidenceId !== undefined ? { evidenceId } : {}),
      diagnosticMetadata: {
        reason: error.message,
        code: error.code,
        retryable: error.retryable,
        chainId: error.chainId,
        sealedAt: error.sealedAt,
      },
      capturedAt,
    };
  }

  // A keyed capture whose key already names another decision. `idempotency_conflict`
  // is the platform's code for the same refusal (it answers it 422).
  if (error instanceof IdempotencyConflictError) {
    return {
      failureType: 'idempotency_conflict',
      ...(evidenceId !== undefined ? { evidenceId } : {}),
      diagnosticMetadata: {
        reason: error.message,
        code: error.code,
        retryable: error.retryable,
        idempotencyKey: error.idempotencyKey,
        conflictReason: error.conflictReason,
      },
      capturedAt,
    };
  }

  if (error instanceof TzunCaptureError) {
    return {
      failureType: `cloud_${error.code}`,
      ...(evidenceId !== undefined ? { evidenceId } : {}),
      diagnosticMetadata: {
        reason: error.message,
        code: error.code,
        status: error.status,
        retryable: error.retryable,
        // Only a chain conflict is retried in-place, so only there does the
        // count say anything; every other cloud code is surfaced on its first
        // occurrence and carries no `attempts` or `retryRefused`.
        ...(error.code === 'chain_conflict' && attempts !== undefined ? { attempts } : {}),
        ...(error.code === 'chain_conflict' && retryRefused !== undefined ? { retryRefused } : {}),
        ...error.context,
      },
      capturedAt,
    };
  }

  // A catalog request the cloud transport made while resolving the record's
  // models or agents (a 401, a 429, a 5xx, a timeout): the same stable code
  // and `retryable` flag as a refused capture POST, and the operation.
  if (error instanceof TzunCatalogError) {
    return {
      failureType: `cloud_${error.code}`,
      ...(evidenceId !== undefined ? { evidenceId } : {}),
      diagnosticMetadata: {
        reason: error.message,
        code: error.code,
        status: error.status,
        retryable: error.retryable,
        operation: error.operation,
        ...error.context,
      },
      capturedAt,
    };
  }

  return {
    failureType: 'serialization_failure',
    ...(evidenceId !== undefined ? { evidenceId } : {}),
    diagnosticMetadata: {
      reason: error instanceof Error ? error.message : String(error),
    },
    capturedAt,
  };
}

/**
 * Why `captureLocked()` declined to retry a chain conflict it could have
 * retried. Carried on the failure record as `diagnosticMetadata.retryRefused`
 * and on the `capture_chain_conflict_retry_refused` log event as `reason`.
 */
type RetryRefusedReason = 'caller_attestation_is_digest_bound';

/**
 * The part of a record that is fixed the moment `capture()` is called and
 * survives every rebuild of that capture at a new chain position.
 */
interface RecordIdentity {
  evidenceId: string;
  capturedAt: string;
}

/**
 * Is this throw a chain-head compare-and-swap refusal — from a local adapter
 * (`ChainConflictError`) or from the cloud backend (`TzunCaptureError` with
 * the wire code `chain_conflict`)? Returns the fields worth logging about it,
 * or `null` for anything else. Nothing in either carries the API key
 * or payload content.
 */
/**
 * Refuse `Tzun.init({ chainId })` when the store records that chain as sealed.
 *
 * A sealed chain is the read-only remainder of a fork and every adapter's
 * `store()` refuses an append to one, so an instance aimed at it can capture
 * nothing. Failing here rather than on the first capture is the posture
 * `getActiveChainId()` already takes for a store whose every chain is sealed:
 * a process that cannot record evidence must not come up reporting that it
 * can.
 *
 * A chain with NO identity row is accepted, as `store()` accepts it: chain
 * identities are created lazily, `'default'` has none until the first fork, and
 * a caller naming a fresh per-tenant chain is naming a chain that does not exist
 * yet. Only an explicit `'sealed'` status closes the door. An adapter that
 * cannot answer `getChain()` — the HTTP transport refuses it — leaves the chain
 * accepted; the server holds the chain's status there and refuses the capture
 * itself.
 */
/**
 * The heavy material of the finalized `evm-calldata/1` publication that
 * covers the record at `position` (tzun-anchor/1 §7.2 rule 4): the raw
 * transaction, the block header, the transaction index and the trie proof the
 * scheduler stored at finality, in the export bundle's form. `verifyAnchor`
 * joins it to the record's own entry by transaction id, so it adds the bytes
 * to check and decides nothing by itself. Empty when the store holds none.
 */
async function storedPublicationMaterial(
  anchors: ReturnType<typeof anchorStoreFor>,
  position: LogPosition,
): Promise<unknown[]> {
  if (!anchors) return [];
  const progress = await anchors.getLeafAnchorProgress(position.logId, position.leafIndex);
  const covering = progress?.publications.find((p) => p.kind === 'evm-calldata/1' && p.state === 'finalized');
  if (!covering) return [];
  const publication = await anchors.getAnchorPublication(covering.id);
  const mined = publication?.attempts.find((a) => a.txHash === publication.minedTxHash);
  if (!publication || !mined) return [];
  return [
    {
      kind: 'evm-calldata/1',
      transactionId: publication.minedTxHash,
      rawTransaction: mined.rawTx,
      blockNumber: publication.blockNumber,
      blockHash: publication.blockHash,
      ...(publication.blockHeader !== null && { blockHeader: publication.blockHeader }),
      ...(publication.txIndex !== null && publication.txTrieProof !== null && { txIndex: publication.txIndex, txProof: publication.txTrieProof }),
    },
  ];
}

/**
 * Open a Postgres store for `Tzun.init()`: the 0.7.0 store check first,
 * which only reads, then the adapter's table setup. A refused store is closed
 * again, and left as it was.
 */
async function openPostgresStore(
  connectionString: string,
  logOptions: { logNamespace?: string; extensions?: readonly StorageExtension[] },
): Promise<PostgresStorageAdapter> {
  const adapter = new PostgresStorageAdapter(connectionString, undefined, logOptions);
  try {
    await refusePostgresStoreBeforeSignoffExpectation(adapter);
  } catch (err) {
    await adapter.close().catch(() => { /* the refusal is the error to report */ });
    throw err;
  }
  await adapter.ensureTables();
  return adapter;
}

async function assertNamedChainAppendable(storage: StorageAdapter, chainId: string): Promise<void> {
  let chain: ChainIdentity | null;
  try {
    chain = await storage.getChain(chainId);
  } catch {
    return;
  }
  if (chain?.status === 'sealed') {
    throw new ChainSealedError(chainId, chain.sealedAt ?? null);
  }
}

/**
 * Every descriptor digest an envelope references, each marked `missing: true`.
 *
 * For a bundle whose source cannot resolve descriptors at all (the cloud
 * transport has no catalog read, and the platform's export carries none). A
 * referenced descriptor that is not in the bundle is a verification gap the
 * offline verifier must flag, and `missing` is the flag for it; leaving the
 * entry out would have made the gap invisible.
 *
 * Only the leaf is listed. Ancestors are reachable only through the catalog, so
 * nothing here can know which ones exist, and inventing entries for ancestors
 * that may not exist would report a different gap from the real one.
 */
function unresolvedDescriptorEntries(
  envelope: EvidenceEnvelope,
): { [digest: string]: ExportedDescriptorEntry } {
  const entries: { [digest: string]: ExportedDescriptorEntry } = {};
  for (const digest of stepModelDigests(envelope)) {
    entries[digest] = { canonicalBytes: '', enrichedView: null, annotations: [], missing: true };
  }
  return entries;
}

function describeChainConflict(error: unknown): Record<string, unknown> | null {
  if (error instanceof ChainConflictError) {
    return { code: error.code, expectedHead: error.expected, actualHead: error.actual };
  }
  if (error instanceof TzunCaptureError && error.code === 'chain_conflict') {
    return { code: error.code, status: error.status, ...error.context };
  }
  return null;
}

/**
 * The bundle's `assertionProvenance`: what the record's WebAuthn assertion
 * states about where the ceremony ran and what kind of key signed, checked
 * against what the exporter asked for. `null` for a record with no assertion.
 * An export verifies no signature, so nothing here is vouched for as `true`.
 */
function exportedAssertionProvenance(
  envelope: EvidenceEnvelope,
  expectations: ExportEvidenceOptions['assertion'],
): AssertionProvenance | null {
  const assertion = envelope?.nonRepudiation?.webauthnAssertion;
  if (!assertion) return null;
  return assertionProvenance(assertion, { ...expectations, signatureVerified: false });
}

/** An error's message, for a verdict's `detail`. */
function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Read a descriptor's parent pointer out of its digest-covered canonical
 * bytes.
 *
 * `ModelDescriptorRow` also carries `parentModelDescriptorDigest` as a
 * denormalized SQL column (types/ai-bom.ts: "denormalized ... for indexed
 * lookup"), and the SQLite/Postgres adapters populate it from that column.
 * `modelDescriptorDigest` commits to `canonicalBytes` and nothing else, so
 * the export lineage walk reads the pointer from here.
 *
 * Returns null when the bytes are not a JSON object or carry no parent —
 * both mean "stop walking", and neither is a reason to consult the column.
 */
function parseDescriptorParent(canonicalBytes: string): string | null {
  try {
    const parsed = JSON.parse(canonicalBytes) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    const parent = (parsed as { parentModelDescriptorDigest?: unknown })
      .parentModelDescriptorDigest;
    return typeof parent === 'string' && parent.length > 0 ? parent : null;
  } catch {
    return null;
  }
}
