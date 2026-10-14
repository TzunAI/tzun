// Merkle tree — pure computation
export {
  buildMerkleTree,
  getMerkleRoot,
  getMerkleProof,
  verifyMerkleProof,
  merkleLeafHash,
  MERKLE_SPEC,
  MerkleTree,
  getConsistencyProof,
  verifyConsistencyProof,
  compactRangeOf,
  compactRangeRoot,
  extendCompactRange,
  ConsistencyProofReason,
  ConsistencyProofResult,
  ConsistencyVerification,
  CompactRange,
  CompactRangeExtension,
} from './merkle';

// Checkpoint bodies and origins (tzun-anchor/1 §4)
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
  ChainIdRefusalReason,
  Checkpoint,
  CheckpointMalformedReason,
  CheckpointParseResult,
  TzunOrigin,
  OriginBinding,
  OriginBindingReason,
} from './checkpoint';

// A record's anchor, verified (tzun-anchor/1 §10)
export {
  verifyAnchor,
  ANCHOR_SPEC,
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
} from './anchor-verify';

// RFC 3161 timestamp client
export {
  RFC3161Client,
  RFC3161Config,
  TimestampResult,
  TimestampProvenance,
  TimestampConformance,
  AuthorityAttempt,
  AuthorityBreakerState,
  TimestampAuthorityError,
  DEFAULT_TIMESTAMP_AUTHORITIES,
  requestTimestamp,
  buildTimestampQuery,
} from './rfc3161';

// WebAuthn server wrapper
export {
  TzunWebAuthn,
  WebAuthnConfig,
  RegistrationResult,
  AssertionResult,
  AssertionBinding,
} from './webauthn';

// The evm-calldata/1 publication verifier (tzun-anchor/1 §10.4)
export {
  EthereumAnchorVerifier,
  EthereumAnchorVerifierConfig,
  EthereumAnchorVerification,
  AnchorTransaction,
  AnchorTransactionProvider,
  verifyEvmPublication,
  verifyEvmTransactionProof,
  parseEvmBlockHeader,
  RpcEvmHeaderSource,
  EvmPublicationNotCheckedError,
  DEFAULT_EVM_NETWORKS,
  DEFAULT_EVM_TIMEOUT_MS,
  EVM_MIN_FINAL_CONFIRMATIONS,
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
} from './blockchain';

// Credential store — the interface a verifier consumes, the in-memory
// reference implementation, and the async directory interface an integrator
// implements against their own IdP. See docs/design/credential-store.md.
export {
  CredentialStore,
  InMemoryCredentialStore,
  CredentialSnapshot,
  CredentialLookup,
  AsyncCredentialStore,
  StoredCredential,
  CredentialAlgorithm,
  CredentialStatus,
  CredentialEvent,
  RevocationOptions,
  CredentialAlreadyRegisteredError,
  CredentialNotFoundError,
  CredentialSnapshotReadOnlyError,
  credentialStatusAt,
  foldCredentialEvents,
} from './credential-store';

// COSE credential-key decoding (WebAuthn public keys are COSE_Key, not SPKI)
export {
  decodeCoseKey,
  coseAlgorithmOf,
  coseToKeyObject,
  importCredentialPublicKey,
  signatureAlgorithmOfKey,
  CoseKeyInfo,
} from './cose-key';

// Orchestrator
export {
  AttestationOrchestrator,
  OrchestratorConfig,
  AttestationInputs,
} from './orchestrator';

// RFC 3161 timestamp verification
export {
  verifyTimestampToken,
  parseTimestampResponse,
  extractTSTInfo,
  verifyCertificateChain,
  verifyCertificatePath,
  resolveTrustAnchors,
  readTrustAnchors,
  trustAnchorsFromPem,
  UnreadableTrustAnchorError,
  authorityOf,
  subjectCommonName,
  TrustAnchorOptions,
  CertificatePathOptions,
  extractRFC3161Metadata,
  parsePKIStatus,
  extractPKIStatus,
  extractPolicyOid,
  TimestampVerificationResult,
  TSTInfoParsed,
} from './rfc3161-verify';

// The registry of public RFC 3161 authorities and their pinned trust anchors.
export {
  TimestampAuthority,
  DEFAULT_TRUST_ANCHOR_AUTHORITIES,
  listTimestampAuthorities,
  independentAuthorities,
  getTimestampAuthority,
  resolveTimestampAuthorities,
  timestampAuthorityUrls,
  timestampAuthorityAnchorsPem,
  timestampAuthorityAnchorPath,
  readAuthorityAnchorPem,
  addTimestampAuthority,
} from './tsa-registry';

// Attestation verification
export {
  verifyAttestation,
  webauthnChallengeForDigest,
  assertionBindsDigest,
  assertionBindingFailure,
  AttestationVerificationResult,
  AttestationVerifyOptions,
  AttestationSignatureReason,
  AttestationAnchorReason,
  AttestationTimestampReason,
  AttestationActorReason,
  AttestationCapturedAtReason,
} from './verify-attestation';
