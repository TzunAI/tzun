// Functions
export { canonicalSerialize, canonicalSerializeDescriptor, canonicalSerializeValue } from './canonical';
export { computeDigest } from './digest';
export {
  DigestComputer, CpuDigestComputer, getDefaultDigestComputer, setDefaultDigestComputer,
} from './digest-computer';
export { SchemaRegistry, CURRENT_SCHEMA_VERSION, V1_0_HASHED_FIELDS } from './schema-registry';
export { EvidenceChain } from './evidence-chain';
export {
  ChainConflictError,
  ChainSealedError,
  IdempotencyConflictError,
  NoActiveChainError,
  AmbiguousActiveChainError,
  InvalidPaginationError,
  StoreSchemaOutdatedError,
} from './errors';
export {
  FIELD_SET_0_7,
  FIELD_SET_BEFORE_0_7,
  earlierFieldSet,
  recordFieldSetGeneration,
  recordPredatesSignoffExpectation,
} from './store-schema';
export type { EarlierFieldSet, RecordFieldSetGeneration } from './store-schema';
export type { IdempotencyConflictReason } from './errors';
export { resolveActiveChainId, implicitChainIds, DEFAULT_CHAIN_ID } from './active-chain';
export { assembleEnvelope, buildEvidencePayload, EnvelopeInputError } from './envelope';
export type { AssembleEnvelopeOptions, EnvelopeInputRule } from './envelope';
export { payloadRecordRuleViolation } from './record-rules';
export type { PayloadRecordRuleOptions, RecordRuleViolation } from './record-rules';
export { determineAttestationStatus, missingAttestationComponents } from './attestation-status';
export type { AttestationExpectation, ObtainableAttestationComponent } from './attestation-status';
export { isRetryObtainableComponent } from './attestation-status';
export {
  EVIDENCE_ID_RE,
  CAPTURED_AT_MAX_SKEW_MS,
  isEvidenceId,
  capturedAtViolation,
} from './capture-claims';
export { verifyEnvelope } from './verify';
export {
  SIGNOFF_DIGEST_RE,
  checkSignoffExpectation,
  describeSignoffExpectationViolation,
  isMandateExpectation,
  isSessionAttachmentExpectation,
  isSignoffExpectation,
  signoffExpectationForm,
  signoffExpectationViolation,
  signoffStatementChallenge,
  signoffStatementDigest,
} from './signoff-expectation';
// Record rules
export {
  AI_BOM_MAX_STOP_SEQUENCES,
  AI_BOM_MAX_STRING_LENGTH,
  MODEL_DESCRIPTOR_DIGEST_RE,
  aiBomViolation,
  fillAiBomNulls,
  isExactAiBom,
} from './ai-bom';
export { BARE_DIGEST_RE, PREFIXED_DIGEST_RE } from './record-rules-util';
export {
  ACTION_MAX_LENGTH,
  PAYLOAD_MAX_CANONICAL_BYTES,
  PAYLOAD_MEMBERS,
  REASON_MAX_LENGTH,
  RESERVED_AI_SYSTEM_ID_PREFIX,
  SYSTEM_AI_SYSTEM_IDS,
  SYSTEM_RECORD_AI_SYSTEM_IDS,
  actionViolation,
  aiOutputViolation,
  aiSystemIdViolation,
  captureTimeViolation,
  evidenceIdViolation,
  movedFieldViolation,
  payloadSizeViolation,
  reasonViolation,
  renamedFieldViolation,
  sequenceNumberViolation,
  unhashedPayloadMembers,
} from './payload-rules';
export type { SystemRecordKind } from './payload-rules';
export {
  ACCT_VALUE_RE,
  DECIDER_COMMITMENT_SALT_BYTES,
  DECIDER_COMMITMENT_SECRET_MIN_BYTES,
  DECIDER_ID_MAX_LENGTH,
  DECIDER_KINDS,
  DECIDER_MEMBERS,
  DECIDER_SCHEMES,
  FRESHNESS_REFERENCE_RE,
  bindsHumanDecisionMaterial,
  checkDecider,
  deciderAgreesWithExpectation,
  deciderCommitment,
  deciderCommitmentSalt,
  deciderMaterialViolation,
  deciderViolation,
  defaultAgentDeciderId,
  formatFreshnessReference,
  identifierScheme,
  isDeciderKind,
  isFreshnessReference,
  isKnownSchemeIdentifier,
  parseFreshnessReference,
  readerActorInconsistent,
  sameActor,
  verifyDeciderOpening,
} from './decider';
export type { DeciderMaterial } from './decider';
export {
  CONTRIBUTIONS_MAX_SET,
  CONTRIBUTIONS_MAX_STEPS,
  ContributionsBuildError,
  buildContributions,
  checkContributions,
  contributionsViolation,
  decidingOutput,
  decidingStepIndex,
  outputDigest,
  singleModel,
  stepClass,
  stepDigest,
} from './contributions';
export type { ContributionsContext } from './contributions';
export {
  EXTENSION_RELATION_RE,
  LINKS_MAX,
  LINK_ATTRS_MAX,
  LINK_ATTR_STRING_MAX_LENGTH,
  LINK_EVIDENCE_ID_MAX_LENGTH,
  LINK_RECORD_ACTION,
  LINK_RECORD_AI_SYSTEM_ID,
  LINK_RELATIONS,
  LINK_RELATION_NAMES,
  LinksBuildError,
  REGISTERED_RELATION_RE,
  RELATION_NAME_RE,
  buildLinks,
  checkLinkRecordLink,
  checkLinkTarget,
  checkLinks,
  compareLinks,
  isEvidenceLogOrigin,
  isExtensionRelation,
  isLineageRelation,
  isLinkRecord,
  isRegisteredRelation,
  isRelationName,
  linkAttrsViolation,
  linkRecordLocalRule,
  linkRecordViolation,
  linkTargetInputs,
  linkTargetMemberMismatch,
  linksGrammarViolation,
  linksListRuleViolation,
  linksViolation,
} from './links';
export type { BuildLinksOptions, LinkTargetRuleResult, LinksContext } from './links';
export {
  AGENT_DESCRIPTOR_MAX_ATTESTATION,
  AGENT_DESCRIPTOR_MAX_BYTES,
  AGENT_DESCRIPTOR_MAX_SET,
  AGENT_DESCRIPTOR_MAX_STRING,
  AGENT_DESCRIPTOR_VERSION,
  agentDescriptorDigest,
  agentDescriptorViolation,
  agentKindMismatch,
  canonicalSerializeAgentDescriptor,
  sortAgentDescriptorSets,
} from './agent';
export * from './mandate';
export type { VerifyEnvelopeOptions } from './verify';
export {
  MERKLE_SPEC,
  merkleLeafHash,
  buildMerkleTree,
  getMerkleRoot,
  getMerkleProof,
  verifyMerkleProof,
  getConsistencyProof,
  verifyConsistencyProof,
  compactRangeOf,
  compactRangeRoot,
  extendCompactRange,
  CompactRangeProver,
} from './merkle';
export type {
  MerkleTree,
  ConsistencyProofReason,
  ConsistencyProofResult,
  ConsistencyVerification,
  CompactRange,
  CompactRangeExtension,
  CompactRangeProofs,
} from './merkle';
export {
  codePointLength,
  lengthPrefix,
  normaliseCustodyMetadata,
  canonicalCustodyMetadata,
  custodyEntryPreimage,
  computeCustodyEntryHash,
  isHashedCustodyEntry,
  mirrorCustodyEntry,
  verifyCustodyTrail,
} from './custody-hash';
export type { HashedCustodyEntry, CustodyEntryPreimage } from './custody-hash';
export { captureIdempotencyFingerprint, captureCallerDecision } from './idempotency-fingerprint';
export type { IdempotencyFingerprintInput } from './idempotency-fingerprint';
export {
  CUSTODY_ENTRY_HASH_PREIMAGE,
  toCustodyLedgerEntry,
  verifyCustodyLedger,
} from './custody-ledger';
export { recordVerdict, recordDigestCheck, unmeasuredRecordVerdict } from './record-verdict';
export type { RecordVerdictInput } from './record-verdict';
export {
  webauthnChallengeForDigest,
  assertionBindingFailure,
  assertionBindsDigest,
  challengeMatches,
  parseClientDataJSON,
} from './webauthn-binding';
export type { AssertionBindingFailure } from './webauthn-binding';
export { assertionProvenance } from './assertion-provenance';
export type { AssertionProvenanceOptions } from './assertion-provenance';
export { verifyChainCompleteness } from './chain-completeness';
export type {
  ChainCompletenessResult,
  ChainCompletenessOptions,
  ChainEvidenceLog,
  EvidenceLogLeaf,
  MultiChainCompletenessResult,
} from './chain-completeness';
// Wire types (the engine is the source of truth)
export type * from './types/evidence';
export type * from './types/decider';
export type * from './types/contributions';
export type * from './types/links';
export type * from './types/mandate';
export type * from './types/agent';
export type * from './types/ai-bom';
export type * from './types/schema';
export type * from './types/verification';
export type * from './types/recovery';
export type * from './types/config';
export type * from './types/failure';
export type * from './types/monitoring-events';
export { AI_BOM_TAMPER_INCIDENT_SEVERITY } from './types/monitoring-events';
export type { StorageAdapter, StoreOptions, ChainHead, AttestationStatusOf, CustodyAppendOptions, RelinkCustodyAppend, StoredCustodyEntry, EnvelopeRevision, RevisionCause, IdempotencyClaim, IdempotencyReceipt, IdempotencyOutcome, IdempotentStoreOptions, MandateClaimStore, MandateRow, MandateEventRow, MandateCapLimit, MandateIssueStore, MandateRevokeStore, MandateExpireStore, AgentDescriptorRow, EvidenceLinkRow } from './types/storage-interface';
