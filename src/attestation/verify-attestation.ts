import { createHash, createVerify } from 'crypto';
import {
  AttestationArtifacts,
  assertionProvenance,
  challengeMatches,
  parseClientDataJSON,
  webauthnChallengeForDigest,
} from '@tzun/engine';
import type { AssertionProvenance, AttestationSignatureReason } from '@tzun/engine';
import { CredentialStore } from './credential-store';
import { importCredentialPublicKey, signatureAlgorithmOfKey } from './cose-key';
import { verifyAnchor } from './anchor-verify';
import type { AnchorExistedBy, AnchorPosition } from './anchor-verify';
import type { EvmFinality, EvmHeaderSource, EvmNetwork, EvmPublicationReason, PublisherManifest } from './blockchain';
import {
  verifyTimestampToken,
  parseTimestampResponse,
  extractTSTInfo,
  TimestampVerificationResult,
} from './rfc3161-verify';
import { imprintHolds, readRfc3161Token, UnreadableTrustAnchorError } from './rfc3161-token';

/**
 * Why `signatureValid` came out the way it did.
 *
 * Additive field. `signatureValid` on its own cannot distinguish "this
 * assertion was checked and the signature is forged" from "this assertion
 * carries nothing that could be checked" from "the ceremony signed a login
 * nonce, so it binds no record at all", and an auditor reading an evidence
 * export needs to be able to tell those apart.
 *
 * The union itself lives in `@tzun/engine` (types/verification.ts) because
 * `VerificationResult.signatureReason` carries it out through `Tzun.verify()`;
 * it is re-exported here under the name every existing importer uses, and the
 * per-member reasoning is on the engine declaration.
 */
export type { AttestationSignatureReason } from '@tzun/engine';

/**
 * Why `anchorValid` came out the way it did.
 *
 * `nonRepudiation.anchor` (`tzun-anchor/1`) is decided by `verifyAnchor`
 * under tzun-anchor/1 §10. Abstentions and undecided results
 * are `null`, never `false`.
 */
export type AttestationAnchorReason =
  // ---- steps 1 to 5 -------------------------------------------------------------
  /** `anchorSpec` is absent or names a version this verifier does not implement. `null`. */
  | 'unsupported_anchor_spec'
  /**
   * `merkleSpec` was absent or names a construction this verifier does not
   * implement. Reported instead of a verdict: a verifier meeting a root built
   * under a rule it does not know must say "I cannot check this", never
   * "invalid". `null`.
   */
  | 'unsupported_merkle_spec'
  /**
   * The record carries a `blockchainAnchor` and no `anchor`. That artifact is
   * not part of tzun-anchor/1, whose §8.4 calls it legacy, so it is not read.
   * `null`.
   */
  | 'legacy_blockchain_anchor'
  /**
   * The anchor's members are not exactly those of tzun-anchor/1 §8.1 with
   * their types: a member missing or added, an index that is not a JSON
   * integer in [0, 2^53 − 1], or `publications` that is not a non-empty
   * array. `false`.
   */
  | 'malformed_anchor'
  /** A checkpoint body is not the exact C2SP form of tzun-anchor/1 §4.2, or its size is 0. `false`. */
  | 'malformed_checkpoint'
  /** `logPath` or `anchorPath` is not an array of 64-hex hashes. `false`. */
  | 'malformed_merkle_path'
  /**
   * The anchor origin is not `<ns>/<id>/anchors`, or the log origin is not a
   * source log of the same domain under the tzun-anchor/1 §4.3 scheme (a
   * non-canonical chain segment, or the anchor origin itself, included).
   * `false`.
   */
  | 'origin_not_in_domain'
  /**
   * A chain id was supplied and the log is not that chain's evidence log: an
   * evidence log for another chain, or a source log of another kind outside
   * the platform's opaque namespaces (`log.tzun.ai`, and `test.log.tzun.ai`
   * for a platform test deployment). `false`.
   */
  | 'chain_id_mismatch'
  /** `leafIndex` is not the supplied `sequenceNumber − 1`. `false`. */
  | 'leaf_index_mismatch'
  /** The digest is not in the tree under the log checkpoint's root. `false`. */
  | 'merkle_proof_invalid'
  /** `SHA-256(logCheckpoint)` is not in the anchor checkpoint's tree. `false`. */
  | 'anchor_proof_invalid'
  // ---- step 6: the publications of P ------------------------------------------
  /**
   * An `rfc3161/1` token's certificate path validates to a supplied root, but
   * its imprint is not `{SHA-256, P}`: another value, or P's bytes under
   * another algorithm's OID. `false`.
   */
  | 'rfc3161_imprint_mismatch'
  /** An `rfc3161/1` token's path validates to a supplied root, but its CMS signature does not verify. `false`. */
  | 'rfc3161_signature_invalid'
  /** An unforeseen failure inside `verifyAnchor`: a bug to report, never a verdict. `null`. */
  | 'anchor_verifier_error'
  /**
   * An `evm-calldata/1` publication's verdict, from `verifyEvmPublication`:
   * `evm_calldata_mismatch`, `evm_sender_mismatch`, `evm_chain_mismatch`,
   * `evm_tx_proof_invalid`, `anchor_not_found_on_chain` and
   * `malformed_publication` are `false`; `publication_not_checked`,
   * `unsupported_publication_kind` and `unsupported_evm_tx_type` are `null`.
   * `malformed_publication` is also a publication entry of any kind that is
   * not an object, or is unreadable; `unsupported_publication_kind` also any
   * kind other than `evm-calldata/1` and `rfc3161/1`. At the anchor's level,
   * `publication_not_checked` is the reason whenever no publication is decided
   * and any of them was not checked (tzun-anchor/1 §10.6).
   */
  | EvmPublicationReason;

/**
 * Why `actorBound` came out the way it did.
 *
 * The product claim is "a specific human acted on an AI recommendation". Who
 * decided is the record's hashed `payload.decider` (Record §6); the
 * custody entry's `custodyChain[0].actor` is a copy of its identifier,
 * outside the digest. A stated decider is still only asserted: the digest
 * binds the identifier, not the person behind it.
 *
 * `actorBound` reports whether a signature proves the identifier. It is
 * `true` only when a WebAuthn assertion cryptographically verified AND its
 * challenge was derived from THIS record's digest AND the credential it was
 * signed with is registered to the account the record names: the expected
 * actor is that user id, or the decider identifier `acct:<user id>`. Anything
 * less is `false` with a reason.
 */
export type AttestationActorReason =
  /** No `expectedActor` was supplied, so there was no claim to check against. */
  | 'no_expected_actor'
  /**
   * The signature did not verify, or verified without being bound to this
   * record's digest. Nothing was proven about who signed what.
   */
  | 'no_verified_signature'
  /**
   * The signature is genuine and bound to this record, but the credential is
   * registered to a different user than the one the record names as actor.
   */
  | 'actor_mismatch';

/**
 * Why `timestampValid` came out the way it did.
 *
 * Without it a caller cannot tell "this TSA response was never
 * a timestamp token at all" (an HTML error page stored by a capture that saw
 * HTTP 200) from "the token is a real one issued by a TSA we do not have a root
 * for" — the first is evidence of a broken pipeline, the second is a trust
 * configuration gap.
 */
export type AttestationTimestampReason =
  /**
   * The stored token is not the base64 of a DER TimeStampResp carrying a DER
   * TSTInfo and the certificate its SignerInfo names (tzun-anchor/1 §10.5
   * step 1). A BER encoding is not DER, whatever it decodes to.
   */
  | 'unparseable_token'
  /**
   * The token parses, but its TSTInfo messageImprint is not this record's
   * digest. The TSA stamped something else; the token is not evidence about
   * this record. This is the check that catches a replayed or substituted token.
   */
  | 'imprint_mismatch'
  /**
   * The CMS signature over the TSTInfo did not verify, no signingCertificate
   * or signingCertificateV2 attribute names the signer certificate, or that
   * certificate is not a timestamping certificate (a critical
   * extendedKeyUsage whose only purpose is id-kp-timeStamping; tzun-anchor/1
   * §10.5 step 3).
   */
  | 'verification_failed'
  /** A crypto dependency needed for CMS verification was unavailable. */
  | 'missing_dependency'
  /**
   * Digest and CMS signature are fine, but the signing certificate does not
   * chain to any configured trust anchor. Only reachable in
   * `timestampVerification: 'trust-chain'` mode. The anchors default to the
   * roots of the default capture authorities, FreeTSA and Sectigo
   * (`DEFAULT_TRUST_ANCHOR_AUTHORITIES`). `trustAnchorsPem` / `authorities` per
   * call, or `TZUN_TSA_TRUST_ANCHORS` / `TZUN_TSA_AUTHORITIES` process-wide,
   * replace them.
   */
  | 'untrusted_chain';

/**
 * Why `capturedAtValid` came out the way it did.
 *
 * `capturedAt` is minted from the CAPTURING MACHINE's clock and is in the v1.0
 * hashed field set, so the RFC 3161 token commits to it transitively — it
 * cannot be altered after capture. This is the other half: the TSA's genTime
 * is compared against the capturedAt it has just notarised. Without that, a
 * record minted on a skewed clock would verify clean and the attestation
 * layer would certify the false time.
 */
export type AttestationCapturedAtReason =
  /** `capturedAt` was absent, not a string, or not a parsable instant. */
  | 'unparsable_captured_at'
  /**
   * There is no timestamp token to compare against, so the claim is unchecked
   * rather than accepted. Reported instead of silently passing: a record with
   * no TSA token has nothing constraining its clock at all.
   */
  | 'no_timestamp_to_compare'
  /**
   * `capturedAt` is LATER than the genTime of the token that notarised it.
   *
   * The token is issued over a digest that commits to `capturedAt`, so
   * `capturedAt` necessarily existed before the TSA stamped it. A later claim
   * means the capturing clock ran ahead of the TSA's. That is usually drift
   * rather than dishonesty — which is why the tolerance matches the 5-minute
   * forward skew the hosted service accepts at capture: anything flagged
   * here is a record the hosted service would have refused.
   *
   * Note the asymmetry — the OPPOSITE direction is not checkable this way.
   * `retryPendingAttestations()` legitimately stamps a record hours after
   * capture, so a large positive skew cannot distinguish backdating from a
   * retried attestation. That direction is reported as `capturedAtSkewMs` and
   * left for the caller to judge; chain monotonicity catches it without
   * needing a TSA at all.
   */
  | 'captured_after_timestamp';

/**
 * Optional inputs that let verifyAttestation check things an artifact cannot
 * attest to about itself. All additive; omitting them is fail-closed, not
 * fail-open.
 */
export interface AttestationVerifyOptions {
  /**
   * This record's `payload.sequenceNumber` (hashed). For `nonRepudiation.anchor`,
   * `leafIndex` must be `sequenceNumber − 1`; omitted, that is not checked and
   * `anchorPosition.leafIndexChecked` is `false`.
   */
  sequenceNumber?: number;
  /**
   * The chain this record belongs to. For `nonRepudiation.anchor`, the log
   * must be this chain's evidence log (its chain segment names it), except
   * under the platform's opaque origins; omitted, that is not checked and
   * `anchorPosition.chainChecked` is `false`.
   */
  chainId?: string;
  /**
   * Which wallets may publish P for which anchor origin (tzun-anchor/1 §9). An
   * `evm-calldata/1` publication is `true` only when its recovered sender is
   * listed here for the anchor origin, on the chain it signed for, at the
   * block time. Never read from the artifact.
   */
  publisherManifest?: PublisherManifest;
  /**
   * The verifier's own view of each chain, keyed by CAIP-2 chain
   * (`eip155:11155111`). An `evm-calldata/1` publication is `true` only once
   * this source confirms its block canonical at finalized depth
   * (`RpcEvmHeaderSource` reads one over JSON-RPC). Omitted, an EVM
   * publication stays `null`, `publication_not_checked`.
   */
  evmHeaderSources?: Record<string, EvmHeaderSource>;
  /** Overrides or extends the CAIP-2 → `mainnet` / `testnet` registry. */
  evmNetworks?: Record<string, EvmNetwork>;
  /** One deadline for every header-source call an anchor verification makes. Default 30 s. */
  evmTimeoutMs?: number;
  /**
   * The export bundle's publications for the anchor checkpoint (Bundle §7.4).
   * An envelope's EVM publication carries no raw transaction, header or trie
   * proof, so without this, or a publication that carries them itself, an EVM
   * publication stays `null`, `publication_not_checked`.
   */
  anchorPublicationMaterial?: unknown[];
  /**
   * This record's `payload.capturedAt`, to be checked against the genTime of
   * the token that notarised it.
   *
   * Optional and additive: omitting it leaves `capturedAtValid` `null`
   * (unchecked), exactly as every caller predating this option behaves. It is
   * passed in rather than read from the artifacts because `capturedAt` lives in
   * the HASHED payload while this function only ever receives the attestation
   * bag — and the hashed copy is the one worth checking.
   */
  capturedAt?: string;
  /**
   * How far `capturedAt` may run AHEAD of the token's genTime before it is
   * reported. Default: {@link DEFAULT_CAPTURED_AT_TOLERANCE_MS}.
   *
   * Matches the forward skew the hosted service accepts at capture, so a
   * cloud record the hosted service accepted is never flagged here, and
   * ordinary clock drift on a local machine is absorbed. It is not a security
   * parameter in the backward direction, which this check deliberately does
   * not police.
   */
  capturedAtToleranceMs?: number;
  /**
   * The challenge the WebAuthn ceremony was required to sign, binding the
   * assertion to this specific record. Use `webauthnChallengeForDigest(digest)`
   * unless you have your own binding scheme.
   *
   * Required for `signatureValid: true`. Without it a genuine assertion is
   * reported `null` / 'assertion_not_bound_to_digest', because a signature over
   * an unrelated nonce says nothing about this record.
   */
  expectedChallenge?: string;
  /**
   * Where `expectedChallenge` came from, which decides how a mismatch reads.
   *
   * - `'caller-asserted'` (default): the caller knows what this record's
   *   ceremony was told to sign — it kept the challenge, or derived it and is
   *   willing to stand behind the claim that this record is supposed to be
   *   bound. A mismatch is then a positive finding: `challenge_mismatch`,
   *   `signatureValid: false`. This is the scanner's mode
   *   (`expectedChallengeFor`).
   * - `'derived-from-digest'`: the verifier derived the expectation itself
   *   from the digest and has no idea whether the ceremony ever intended to
   *   bind. A mismatch is reported `assertion_not_bound_to_digest` /
   *   `signatureValid: null` — because that verdict is true of BOTH a record
   *   captured before binding existed and a replayed assertion, and there is
   *   nothing in the artifact that tells them apart. Neither is a pass.
   *
   * This distinction is the whole of the 0.3.15→0.3.16 compatibility story:
   * `Tzun.verify()` uses `'derived-from-digest'`, so every pre-0.3.16 record
   * reads as "this artifact binds nothing" rather than as a broken signature
   * on an otherwise intact record.
   */
  expectedChallengeSource?: 'caller-asserted' | 'derived-from-digest';
  /**
   * Origins the ceremony is allowed to have run on. Unset means unchecked.
   *
   * With a credential store, an origin off the list fails the signature
   * (`untrusted_origin`). With or without one, `assertionProvenance` reports it
   * as `originValid: false` / `origin_mismatch`, and reports `originValid:
   * null` / `origin_not_checked` when this is unset.
   */
  allowedOrigins?: string[];
  /**
   * Top-level origins the ceremony may have run under — for the
   * browser-extension side panel, the extension's own origins.
   * The top-level origin is `topOrigin` for a cross-origin ceremony and the
   * ceremony's own `origin` for one that states `crossOrigin: false`, so a
   * ceremony run directly in a tab passes only when its origin is listed too.
   * Checked into `assertionProvenance.topOriginValid`; never fails the
   * signature. Unset means unchecked.
   */
  allowedTopOrigins?: string[];
  /**
   * Require a single-device credential (the `BE` flag clear). A synced or
   * backup-eligible credential is reported as the lower rung
   * `assertionProvenance.deviceBound: false` with its reason; the signature
   * verdict is unchanged.
   */
  requireDeviceBound?: boolean;
  /** Relying Party ID the assertion must be scoped to. Unset means unchecked. */
  rpId?: string;
  /**
   * How far to take RFC 3161 timestamp verification.
   *
   * - `'trust-chain'` (default): the full check of tzun-anchor/1 §10.5 —
   *   parse, imprint, CMS signature, the signer binding and its timestamping
   *   extendedKeyUsage, and a valid path to a trusted root. The
   *   default anchors are the FreeTSA and Sectigo roots; supply `authorities`
   *   or `trustAnchorsPem` (or set `TZUN_TSA_AUTHORITIES` /
   *   `TZUN_TSA_TRUST_ANCHORS`) to verify tokens from any other TSA.
   * - `'structural'`: parse the DER TimeStampResp (tzun-anchor/1 §10.5
   *   step 1) and require its TSTInfo messageImprint to be SHA-256 over
   *   `digest` (step 2). TSA-agnostic — it says "this is a real timestamp
   *   token, and it is a token over THIS record" without asserting who
   *   vouched for it.
   *
   * `'structural'` exists because the trust-chain mode cannot be applied
   * blanket-fashion to a store whose TSA is not among the trusted authorities:
   * it would report every genuine token as invalid. It is deliberately weaker, and a caller reading
   * `timestampValid: true` in this mode must not read it as "a trusted third
   * party attested to this time".
   */
  timestampVerification?: 'trust-chain' | 'structural';
  /**
   * PEM-encoded trust anchors for the RFC 3161 signing certificate, used only
   * in `'trust-chain'` mode.
   *
   * Capture accepts any TSA URL (`TzunConfig.attestation.timestamp.rfc3161Urls`,
   * the backend's `TZUN_TSA_URL`). A token from an authority outside the
   * default pair verifies only once its root is supplied here, through
   * `authorities`, or through `TZUN_TSA_TRUST_ANCHORS` / `TZUN_TSA_AUTHORITIES`.
   * Anchors supplied here replace the default pair rather than adding to it.
   */
  trustAnchorsPem?: string[];
  /**
   * Timestamp authorities to trust, by registry key or URL — the ergonomic
   * form of `trustAnchorsPem` for the authorities this package ships roots
   * for. Supplying it replaces the default pair (FreeTSA and Sectigo), so it
   * must name every authority capture may use
   * (`attestation.timestamp.rfc3161Urls`). See `src/attestation/tsa-registry`.
   */
  authorities?: string[];
  /**
   * The actor the record attributes the decision to: the decider's
   * identifier (`payload.decider.id`, which `custodyChain[0].actor` copies),
   * `acct:<user id>`, or the bare user id.
   *
   * Required for `actorBound: true`. Without it the verifier has no claim to
   * check the credential's registered user against, and reports
   * `actorBound: false` / 'no_expected_actor' rather than assuming.
   */
  expectedActor?: string;
}

/**
 * The record-binding primitives.
 *
 * They live in `@tzun/engine` (webauthn-binding.ts) because `assembleEnvelope`
 * needs them to decide whether a record's assertion is a signature over that
 * record, and because the derivation is a wire contract with the Python port.
 * Re-exported here under the names every existing importer already uses.
 *
 *   - `webauthnChallengeForDigest(digest)` — the challenge the ceremony must
 *     present: `base64url(SHA-256('tzun-decision-v1' || digest))`.
 *   - `assertionBindingFailure(assertion, digest)` / `assertionBindsDigest` —
 *     "is this assertion even about this record?", answerable with no key
 *     material, no credential store and no network.
 */
export {
  webauthnChallengeForDigest,
  assertionBindingFailure,
  assertionBindsDigest,
} from '@tzun/engine';
export type { AssertionBindingFailure } from '@tzun/engine';

export interface AttestationVerificationResult {
  signatureValid: boolean | null;
  timestampValid: boolean | null;
  /**
   * The anchor verdict (tzun-anchor/1 §10.6), from `nonRepudiation.anchor`:
   * `false` when a proof step fails or any publication is `false`, `true` when
   * the proofs hold and at least one publication is `true`, `null` otherwise.
   * `null` when no anchor is attached, and for a `blockchainAnchor`, which is
   * not read (`legacy_blockchain_anchor`).
   */
  anchorValid: boolean | null;
  /**
   * The verdict on the three components together: how many of them VERIFIED.
   * `'complete'` when all three did, `'partial'` when at least one did,
   * `'pending'` only for a verified signature whose timestamp and anchor are
   * absent (not failed), `'none'` otherwise.
   *
   * Not the envelope's `attestationStatus`, which uses the same four words
   * under a different rule: the engine's `determineAttestationStatus` decides
   * it at capture from which artifacts are PRESENT against what the writer
   * was configured to obtain, and there `'pending'` means a configured
   * component has not been obtained yet — what `retryPendingAttestations()`
   * lists. A record can be `'complete'` on the envelope and `'none'` here.
   */
  attestationVerdict: 'complete' | 'partial' | 'pending' | 'none';
  credentialStatus?: 'active' | 'revoked';
  /** Present whenever `signatureValid` is not `true`, explaining why. */
  signatureReason?: AttestationSignatureReason;
  /**
   * Whether the anchor's Merkle proofs hold: the digest in the log checkpoint
   * and the log checkpoint in the anchor checkpoint (tzun-anchor/1 §10.3
   * steps 4 and 5).
   *
   * This is what the artifact-only check actually establishes, and it is
   * strictly weaker than `anchorValid`: the roots are supplied by
   * whoever wrote the artifact, so a writer can always make this true. Read it
   * as "the Merkle paths are internally consistent", never as "anchored".
   */
  merkleProofValid: boolean | null;
  /**
   * The strongest publication that is `true`, so the anchor's rung is
   * visible. `'rfc3161'` alone means existed-by only. `null` unless
   * `anchorValid` is `true`.
   *
   * This field and the five after it (tzun-anchor/1 §10.6) are present
   * whenever an anchor artifact is attached, `blockchainAnchor` included.
   */
  anchorPublication?: 'evm-calldata' | 'rfc3161' | null;
  /**
   * `true` only when an `evm-calldata/1` publication is `true`, meaning a
   * publisher the manifest lists for this origin signed P and the verifier's
   * own header source confirmed the block. An RFC 3161 token authenticates
   * the TSA, not who named the origin.
   */
  anchorOriginAuthenticated?: boolean;
  /**
   * The record's log position, reported as fact only as far as its
   * `leafIndexChecked`, `chainChecked` and `authenticated` flags say. `null`
   * when a proof step fails, a publication is `false`, or the anchor was
   * abstained on.
   */
  anchorPosition?: AnchorPosition | null;
  /**
   * `mainnet` or `testnet`, from the manifest entry's CAIP-2 chain through the
   * verifier's registry, and only from a `true` EVM publication. Never from
   * the artifact.
   */
  anchorNetwork?: EvmNetwork | null;
  /**
   * `'test'` whenever the anchor checkpoint parses and its origin begins with
   * `test.`, whatever the verdict; otherwise the manifest entry's namespace
   * when the origin is authenticated, and `null` when it is not.
   */
  anchorNamespace?: 'production' | 'test' | null;
  /**
   * What the header source counted as final when it confirmed the anchor's
   * EVM publication (`EvmHeaderSource.finality`): `'finalized'`, or a
   * confirmation depth, which with `acceptNonFinal` may not be final. `null`
   * unless an EVM publication is `true`, and when the source declares none.
   */
  anchorFinality?: EvmFinality | null;
  /**
   * The earliest time a `true` publication proves P existed by (a TSA
   * genTime, or a block time the verifier's header source confirmed), and
   * which kind proved it.
   */
  existedBy?: AnchorExistedBy | null;
  /**
   * Whether `payload.capturedAt` is consistent with the TSA genTime that
   * notarised it. `null` when unchecked — no `capturedAt` was supplied, or
   * there is no token to compare against.
   */
  capturedAtValid: boolean | null;
  /** Present whenever `capturedAtValid` is not `true`, explaining why. */
  capturedAtReason?: AttestationCapturedAtReason;
  /**
   * `genTime - capturedAt` in milliseconds, when both were readable.
   *
   * Positive means the TSA stamped the record after it claims to have been
   * captured, which is the normal shape. A LARGE positive value is the
   * signature of either a backdated clock or a retried attestation, and this
   * function deliberately does not guess which — it reports the magnitude so a
   * caller that knows its own retry policy can rule.
   */
  capturedAtSkewMs?: number;
  /** Present whenever `anchorValid` is not `true` and an anchor artifact is attached, explaining why. */
  anchorReason?: AttestationAnchorReason;
  /** Present whenever `timestampValid` is `false`, explaining why. */
  timestampReason?: AttestationTimestampReason;
  /**
   * Whether the human this record names as actor is cryptographically bound to
   * it.
   *
   * `false` is the norm, not an anomaly: the actor lives in
   * `custodyChain[0].actor`, outside the v1.0 hashed field set, so nothing in a
   * default capture binds it. Read a green verification as "this decision
   * record is intact", never as "this person approved it", unless this is
   * `true`.
   */
  actorBound: boolean;
  /** Present whenever `actorBound` is `false`, explaining why. */
  actorReason?: AttestationActorReason;
  /**
   * Where the ceremony ran (`origin`, `crossOrigin`, `topOrigin`), what the
   * authenticator said about the human and the key (`UP`, `UV`, `BE`, `BS`),
   * and the checks `allowedOrigins`, `allowedTopOrigins` and
   * `requireDeviceBound` asked for. Present whenever the
   * artifacts carry a `webauthnAssertion`.
   *
   * A met requirement is `true` only when `signatureValid` is `true`: the
   * statements are inside the signed bytes, and only the signature proves the
   * browser and the authenticator made them.
   */
  assertionProvenance?: AssertionProvenance;
}

/**
 * Verify attestation artifacts.
 *
 * This function is designed to be called by the Evidence Engine's
 * verifyEnvelope() function (wiring deferred to Plan 3).
 *
 * Verification levels:
 * - Signature: full WebAuthn assertion verification against the registered
 *   public key — clientDataJSON type/origin, authenticatorData rpIdHash and the
 *   User Present flag, then the signature itself. An assertion that carries no
 *   `authenticatorData` / `clientDataJSON` has no signed message to verify and
 *   is reported invalid; there is deliberately no credential-status-only
 *   fallback. `signatureValid: true` additionally requires
 *   `options.expectedChallenge`, because a signature over a challenge that is
 *   not derived from `digest` verifies against every record equally and so
 *   binds this one to nothing.
 * - Timestamp: full RFC 3161 ASN.1/CMS verification with fallback to presence check
 * - Anchor: `nonRepudiation.anchor` is checked by `verifyAnchor` under
 *   tzun-anchor/1 §10.3: both checkpoints, the origin binding, the log
 *   position, both inclusion proofs, then each publication of P. An EVM
 *   publication counts only with `publisherManifest` and `evmHeaderSources`
 *   supplied; an RFC 3161 one only when its token chains to a root supplied
 *   through `trustAnchorsPem`, `authorities` or the environment (the built-in
 *   default roots do not count for an anchor). A `blockchainAnchor` is not
 *   read: alone it is abstained on (`legacy_blockchain_anchor`), and beside
 *   an `anchor` the `anchor` decides.
 *
 * Trust anchors that cannot be read (`readTrustAnchors`) are refused: the
 * call throws `UnreadableTrustAnchorError` rather than judge a token or an
 * anchor without them.
 *
 * @param artifacts - The attestation artifacts from the evidence envelope
 * @param digest - The evidence digest to verify against
 * @param credentialStore - Optional credential store for signature verification
 */
export async function verifyAttestation(
  artifacts: AttestationArtifacts,
  digest: string,
  credentialStore?: CredentialStore,
  options: AttestationVerifyOptions = {}
): Promise<AttestationVerificationResult> {
  // `nonRepudiation` is client-supplied JSON on every server that verifies what
  // a client sent, so nothing below may assume a shape JSON
  // never guaranteed. A null/non-object artifacts bag is read as an empty one —
  // every component absent, nothing attested — rather than throwing
  // `TypeError: Cannot read properties of null (reading 'webauthnAssertion')`
  // before any check runs.
  const art: AttestationArtifacts =
    artifacts !== null && typeof artifacts === 'object' && !Array.isArray(artifacts)
      ? artifacts
      : {};

  const signatureResult = verifySignature(art, credentialStore, options);
  const timestampResult = await verifyTimestamp(art, digest, options);
  const anchorResult = await verifyAnchorArtifact(art, digest, options);
  const capturedAtResult = checkCapturedAt(art, options);

  const actorResult = checkActorBinding(
    signatureResult.signatureValid,
    art,
    credentialStore,
    options,
  );

  const attestationVerdict = determineVerdict(
    signatureResult.signatureValid,
    timestampResult.timestampValid,
    anchorResult.anchorValid,
    anchorResult.anchorPresent
  );

  const provenance = art.webauthnAssertion
    ? assertionProvenance(art.webauthnAssertion, {
        ...(options.allowedOrigins && { allowedOrigins: options.allowedOrigins }),
        ...(options.allowedTopOrigins && { allowedTopOrigins: options.allowedTopOrigins }),
        requireDeviceBound: options.requireDeviceBound === true,
        signatureVerified: signatureResult.signatureValid === true,
      })
    : undefined;

  return {
    signatureValid: signatureResult.signatureValid,
    timestampValid: timestampResult.timestampValid,
    anchorValid: anchorResult.anchorValid,
    merkleProofValid: anchorResult.merkleProofValid,
    attestationVerdict,
    ...(anchorResult.anchorReason !== undefined && {
      anchorReason: anchorResult.anchorReason,
    }),
    ...anchorResult.anchorFacts,
    ...(timestampResult.timestampReason !== undefined && {
      timestampReason: timestampResult.timestampReason,
    }),
    capturedAtValid: capturedAtResult.capturedAtValid,
    ...(capturedAtResult.capturedAtReason !== undefined && {
      capturedAtReason: capturedAtResult.capturedAtReason,
    }),
    ...(capturedAtResult.capturedAtSkewMs !== undefined && {
      capturedAtSkewMs: capturedAtResult.capturedAtSkewMs,
    }),
    actorBound: actorResult.actorBound,
    ...(actorResult.actorReason !== undefined && {
      actorReason: actorResult.actorReason,
    }),
    ...(signatureResult.credentialStatus !== undefined && {
      credentialStatus: signatureResult.credentialStatus,
    }),
    ...(signatureResult.signatureReason !== undefined && {
      signatureReason: signatureResult.signatureReason,
    }),
    ...(provenance !== undefined && { assertionProvenance: provenance }),
  };
}

/**
 * Verify a WebAuthn signature cryptographically using the stored public key.
 *
 * WebAuthn signs over: authenticatorData + SHA-256(clientDataJSON)
 * We reconstruct the signed data and verify the signature.
 *
 * @param signatureBase64 - Base64-encoded signature
 * @param authenticatorDataBase64 - Base64-encoded authenticatorData
 * @param clientDataJSONBase64 - Base64-encoded clientDataJSON
 * @param publicKeyBase64 - Base64-encoded public key, either the
 *        authenticator's COSE_Key (what `TzunWebAuthn.finishRegistration`
 *        persists) or an SPKI DER export (what a direct integrator registration
 *        typically holds). Both are accepted.
 * @param algorithm - 'Ed25519' or 'ES256', used only as a fallback when the key
 *        itself does not settle the question.
 * @returns true if the signature is cryptographically valid
 */
function verifySignatureCrypto(
  signatureBase64: string,
  authenticatorDataBase64: string,
  clientDataJSONBase64: string,
  publicKeyBase64: string,
  algorithm: 'Ed25519' | 'ES256'
): boolean {
  try {
    const signature = Buffer.from(signatureBase64, 'base64');
    const authenticatorData = Buffer.from(authenticatorDataBase64, 'base64');
    const clientDataJSON = Buffer.from(clientDataJSONBase64, 'base64');

    // Reconstruct the signed data: authenticatorData + SHA-256(clientDataJSON)
    const clientDataHash = createHash('sha256').update(clientDataJSON).digest();
    const signedData = Buffer.concat([authenticatorData, clientDataHash]);

    // Import the public key, in either encoding.
    //
    // Real registrations do not store SPKI: `finishRegistration` persists the
    // authenticator's COSE_Key verbatim, because that is the form
    // `verifyAuthenticationResponse` wants handed back. Assuming SPKI DER
    // would make `createPublicKey({type:'spki'})` throw on CBOR, the catch
    // below would swallow it, and every honestly signed assertion would come
    // back `signatureValid: false`.
    const keyObject = importCredentialPublicKey(Buffer.from(publicKeyBase64, 'base64'));
    if (!keyObject) {
      return false;
    }

    // Prefer the key's own type over the stored label. Credentials registered
    // by earlier SDK versions are all labelled 'ES256', Ed25519 ones included,
    // and verifying an Ed25519 signature via createVerify('SHA256') never
    // succeeds.
    const effectiveAlgorithm = signatureAlgorithmOfKey(keyObject) ?? algorithm;

    if (effectiveAlgorithm === 'Ed25519') {
      // Ed25519 uses crypto.verify directly (no hash algorithm)
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { verify } = require('crypto');
      return verify(null, signedData, keyObject, signature);
    } else {
      // ES256 = ECDSA with P-256 and SHA-256
      const verifier = createVerify('SHA256');
      verifier.update(signedData);
      return verifier.verify(keyObject, signature);
    }
  } catch {
    return false;
  }
}

interface ActorCheck {
  actorBound: boolean;
  actorReason?: AttestationActorReason;
}

/**
 * Decide whether the human the record names is cryptographically bound to it.
 *
 * Three things all have to hold, and each is a separate way the claim fails:
 *
 *  1. the assertion verified — `signatureValid === true`, which already
 *     requires `options.expectedChallenge`, i.e. a challenge derived from this
 *     record's digest. A genuine signature over an unrelated nonce verifies
 *     against every record equally and binds this one to nothing;
 *  2. the caller told us who the record claims acted (`expectedActor`);
 *  3. the credential that produced the signature is registered to that person.
 *
 * Step 3 is the one that is easy to forget and the reason this function exists.
 * A valid assertion proves a registered credential signed this digest — not
 * that the credential belongs to the account the record names as its decider.
 */
function checkActorBinding(
  signatureValid: boolean | null,
  artifacts: AttestationArtifacts,
  credentialStore: CredentialStore | undefined,
  options: AttestationVerifyOptions,
): ActorCheck {
  if (signatureValid !== true) {
    return { actorBound: false, actorReason: 'no_verified_signature' };
  }
  if (options.expectedActor === undefined) {
    return { actorBound: false, actorReason: 'no_expected_actor' };
  }
  const assertion = artifacts.webauthnAssertion;
  const cred = assertion && credentialStore?.getByCredentialId(assertion.credentialKeyId);
  if (!cred || (cred.userId !== options.expectedActor && `acct:${cred.userId}` !== options.expectedActor)) {
    return { actorBound: false, actorReason: 'actor_mismatch' };
  }
  return { actorBound: true };
}

interface SignatureCheck {
  signatureValid: boolean | null;
  credentialStatus?: 'active' | 'revoked';
  signatureReason?: AttestationSignatureReason;
}

/**
 * The verdict on "is this assertion about THIS record", or `undefined` when it
 * is (or when no expectation was supplied to check it against).
 *
 * Two different verdicts come out of one comparison, and which one is honest
 * depends entirely on where the expectation came from — see
 * `AttestationVerifyOptions.expectedChallengeSource`:
 *
 * - a caller who ASSERTS the expected challenge is telling us this record is
 *   supposed to be bound, so a mismatch is a finding: `challenge_mismatch`,
 *   `false`;
 * - a verifier that DERIVED the expectation from the digest knows nothing
 *   about what the ceremony intended, and a mismatch is equally consistent
 *   with a record captured before binding existed and with a replayed
 *   assertion. Calling either one "mismatch/false" would mark every 0.3.15
 *   record as carrying a broken signature. `assertion_not_bound_to_digest`,
 *   `null`.
 *
 * Neither is a pass, which is the property that matters.
 *
 * `credentialStatus` is threaded through only so the caller's existing shape
 * is preserved; it is `undefined` on the no-credential-store path.
 */
function challengeVerdict(
  assertion: NonNullable<AttestationArtifacts['webauthnAssertion']>,
  options: AttestationVerifyOptions,
  credentialStatus: 'active' | 'revoked' | undefined,
): SignatureCheck | undefined {
  if (options.expectedChallenge === undefined) return undefined;
  if (!assertion.clientDataJSON) return undefined;

  // Not a client-data object: the dedicated 'malformed_client_data' branch
  // owns this case when a credential store is present, and without one there
  // is nothing further to say here.
  const clientData = parseClientDataJSON(assertion.clientDataJSON);
  if (clientData === null) return undefined;

  if (
    typeof clientData.challenge === 'string' &&
    challengeMatches(clientData.challenge, options.expectedChallenge)
  ) {
    return undefined;
  }

  const derived = options.expectedChallengeSource === 'derived-from-digest';
  return {
    signatureValid: derived ? null : false,
    ...(credentialStatus !== undefined && { credentialStatus }),
    signatureReason: derived ? 'assertion_not_bound_to_digest' : 'challenge_mismatch',
  };
}

function verifySignature(
  artifacts: AttestationArtifacts,
  credentialStore?: CredentialStore,
  options: AttestationVerifyOptions = {}
): SignatureCheck {
  if (!artifacts.webauthnAssertion) {
    return { signatureValid: null };
  }

  if (!credentialStore) {
    // No credential store available, so the SIGNATURE cannot be checked. The
    // BINDING still can: the challenge is a pure function of the digest, so a
    // verifier holding no key material at all can prove that an assertion is
    // not about this record. Reporting only 'no_credential_store' here would
    // throw away the one check that survives with nothing in hand.
    const unbound = challengeVerdict(artifacts.webauthnAssertion, options, undefined);
    if (unbound) return unbound;
    return { signatureValid: null, signatureReason: 'no_credential_store' };
  }

  const assertion = artifacts.webauthnAssertion;
  const cred = credentialStore.getByCredentialId(assertion.credentialKeyId);

  if (!cred) {
    return { signatureValid: false, signatureReason: 'unknown_credential' };
  }

  // A revoked credential cannot produce non-repudiation evidence, however good
  // its cryptography. Status is checked before the signature, so a revoked key
  // with a genuine signature is never reported as a valid signature.
  if (cred.status === 'revoked') {
    return {
      signatureValid: false,
      credentialStatus: 'revoked',
      signatureReason: 'revoked_credential',
    };
  }

  // `typeof === 'string'`, not truthiness. A truthy non-string
  // — `authenticatorData: 123` — passed to `Buffer.from(value, 'base64')`
  // throws `TypeError [ERR_INVALID_ARG_TYPE]` rather than returning bytes, and
  // that throw would escape `verifyAttestation` entirely. A non-string carries no
  // signed message, so it falls through to `unverifiable_assertion` below:
  // the artifact claims to be a signature over this record and that claim does
  // not hold up.
  if (typeof assertion.authenticatorData === 'string' && typeof assertion.clientDataJSON === 'string') {
    const status = cred.status;
    const fail = (signatureReason: AttestationSignatureReason): SignatureCheck => ({
      signatureValid: false,
      credentialStatus: status,
      signatureReason,
    });

    // --- clientDataJSON: what the browser says the ceremony was ---------------
    // Parsed and checked, not only hashed into the signature check: every
    // statement inside — what kind of ceremony this was, which site it ran on,
    // what was actually signed — is a claim to verify.
    const clientData = parseClientDataJSON(assertion.clientDataJSON);
    if (clientData === null) {
      return fail('malformed_client_data');
    }

    if (clientData.type !== 'webauthn.get') {
      return fail('wrong_client_data_type');
    }

    if (
      options.allowedOrigins &&
      (typeof clientData.origin !== 'string' || !options.allowedOrigins.includes(clientData.origin))
    ) {
      return fail('untrusted_origin');
    }

    // --- authenticatorData: what the authenticator says happened --------------
    // Layout: 32-byte rpIdHash ++ 1 flags byte ++ 4-byte counter.
    const authData = Buffer.from(assertion.authenticatorData, 'base64');
    if (authData.length < 37) {
      return fail('malformed_authenticator_data');
    }

    if (options.rpId) {
      const expectedRpIdHash = createHash('sha256').update(options.rpId, 'utf8').digest();
      if (!authData.subarray(0, 32).equals(expectedRpIdHash)) {
        return fail('rp_id_mismatch');
      }
    }

    const USER_PRESENT = 0x01;
    if ((authData[32] & USER_PRESENT) === 0) {
      // No human touched the authenticator. Whatever this is, it is not a
      // record of a person approving something.
      return fail('user_not_present');
    }

    // --- the signature itself -------------------------------------------------
    const cryptoValid = verifySignatureCrypto(
      assertion.signature,
      assertion.authenticatorData,
      assertion.clientDataJSON,
      cred.publicKey,
      cred.algorithm
    );

    if (!cryptoValid) {
      return fail('invalid_signature');
    }

    // --- and finally: is any of this about THIS record? ----------------------
    // Everything above establishes that this credential signed something. Only
    // the challenge can establish that the something was this decision. If the
    // ceremony used a random login nonce, the assertion verifies identically
    // against every record ever captured, so reporting `true` here would be
    // asserting a binding that was never created.
    if (options.expectedChallenge === undefined) {
      return {
        signatureValid: null,
        credentialStatus: status,
        signatureReason: 'assertion_not_bound_to_digest',
      };
    }

    const mismatch = challengeVerdict(assertion, options, status);
    if (mismatch) return mismatch;

    return { signatureValid: true, credentialStatus: status };
  }

  // No authenticatorData and no clientDataJSON: there is no signed message, so
  // the `signature` field cannot be checked against anything. Falling back to
  // `signatureValid: cred.status === 'active'` would answer "does this
  // signature verify?" with "is some credential with this id currently
  // unrevoked?": anyone able to write `nonRepudiation` could mint a
  // verified-looking signature by naming any active credential id and putting
  // a single character in `signature`. That is not a weaker check than
  // cryptographic verification, it is a different check wearing its name.
  //
  // An unverifiable assertion is reported as `false`, not `true` and not
  // `null`: the artifact IS present and claims to be a signature over this
  // record, and that claim did not hold up. `signatureReason` carries the
  // distinction between this and a genuinely forged signature.
  return {
    signatureValid: false,
    credentialStatus: cred.status,
    signatureReason: 'unverifiable_assertion',
  };
}

interface TimestampCheck {
  timestampValid: boolean | null;
  timestampReason?: AttestationTimestampReason;
}

async function verifyTimestamp(
  artifacts: AttestationArtifacts,
  digest: string,
  options: AttestationVerifyOptions = {},
): Promise<TimestampCheck> {
  if (!artifacts.rfc3161Token) {
    return { timestampValid: null };
  }

  if (options.timestampVerification === 'structural') {
    // TSA-agnostic boundary: is this a timestamp token at all, and is it a
    // token over THIS record? Both questions are answerable without knowing
    // who the TSA is; neither is answerable by looking at whether the string
    // is non-empty, which is what presence checks do. These are
    // tzun-anchor/1 §10.5 steps 1 and 2: the token is the base64 of a DER
    // TimeStampResp carrying a DER TSTInfo and the certificate its SignerInfo
    // names, and its imprint is SHA-256 over this record's digest.
    const read = readRfc3161Token(artifacts.rfc3161Token);
    if (!read.ok) return { timestampValid: false, timestampReason: 'unparseable_token' };
    if (!imprintHolds(read.token, digest)) return { timestampValid: false, timestampReason: 'imprint_mismatch' };
    return { timestampValid: true };
  }

  try {
    const result = await verifyTimestampToken(artifacts.rfc3161Token, digest, {
      ...(options.trustAnchorsPem ? { trustAnchorsPem: options.trustAnchorsPem } : {}),
      ...(options.authorities ? { authorities: options.authorities } : {}),
    });

    // Always respect valid: false — a result with valid: false is invalid regardless
    // of whether digestMatch/signatureValid are populated. verifyTimestampToken
    // returns { valid: false, reason: 'unparseable_token' } for garbage tokens,
    // and that is honoured like any other failure.
    if (result.valid) {
      return { timestampValid: true };
    }
    return {
      timestampValid: false,
      timestampReason: mapTimestampReason(result),
    };
  } catch (err) {
    // Trust anchors that cannot be read are the caller's input, not a
    // verdict on the token.
    if (err instanceof UnreadableTrustAnchorError) throw err;
    // If verification throws unexpectedly, treat as invalid (fail-closed).
    return { timestampValid: false, timestampReason: 'verification_failed' };
  }
}

/**
 * How far `capturedAt` may run ahead of the TSA genTime. Equal to the forward
 * skew the hosted service accepts at capture (its `CAPTURED_AT_MAX_SKEW_MS`),
 * so the two layers agree on what an acceptable clock is.
 */
export const DEFAULT_CAPTURED_AT_TOLERANCE_MS = 5 * 60 * 1000;

interface CapturedAtCheck {
  capturedAtValid: boolean | null;
  capturedAtReason?: AttestationCapturedAtReason;
  capturedAtSkewMs?: number;
}

/**
 * Check `capturedAt` against the genTime of the token that notarised it.
 *
 * genTime is re-derived FROM THE TOKEN, never read from
 * `rfc3161Metadata.genTime`. That parsed copy lives under `nonRepudiation`,
 * which is outside the v1.0 hashed field set, so a store-writer can edit it;
 * the token is TSA-signed and is the only trustworthy source. A record whose
 * metadata was doctored to excuse a bad capturedAt still fails here.
 *
 * Never throws — `capturedAt` is client-supplied JSON like everything else in
 * this file, so a malformed value is a reported verdict.
 */
function checkCapturedAt(
  artifacts: AttestationArtifacts,
  options: AttestationVerifyOptions,
): CapturedAtCheck {
  const claim = options.capturedAt;
  if (claim === undefined) return { capturedAtValid: null };

  if (typeof claim !== 'string' || claim.length === 0) {
    return { capturedAtValid: false, capturedAtReason: 'unparsable_captured_at' };
  }
  const capturedMs = Date.parse(claim);
  if (Number.isNaN(capturedMs)) {
    return { capturedAtValid: false, capturedAtReason: 'unparsable_captured_at' };
  }

  if (!artifacts.rfc3161Token) {
    // Unchecked, not accepted. A record with no token has nothing at all
    // constraining its clock, and saying so is the point.
    return { capturedAtValid: null, capturedAtReason: 'no_timestamp_to_compare' };
  }

  let genTimeMs: number;
  try {
    const tstInfo = extractTSTInfo(parseTimestampResponse(artifacts.rfc3161Token));
    genTimeMs = tstInfo.genTime.getTime();
    if (Number.isNaN(genTimeMs)) throw new Error('unreadable genTime');
  } catch {
    // The token itself is unreadable. verifyTimestamp reports that on its own
    // channel; here it simply means the comparison could not be made.
    return { capturedAtValid: null, capturedAtReason: 'no_timestamp_to_compare' };
  }

  const skewMs = genTimeMs - capturedMs;
  const tolerance = options.capturedAtToleranceMs ?? DEFAULT_CAPTURED_AT_TOLERANCE_MS;

  // Only the forward direction is decidable. See AttestationCapturedAtReason.
  if (skewMs < -tolerance) {
    return {
      capturedAtValid: false,
      capturedAtReason: 'captured_after_timestamp',
      capturedAtSkewMs: skewMs,
    };
  }

  return { capturedAtValid: true, capturedAtSkewMs: skewMs };
}

function mapTimestampReason(result: TimestampVerificationResult): AttestationTimestampReason {
  if (result.reason === 'unparseable_token') return 'unparseable_token';
  if (result.reason === 'missing_dependency') return 'missing_dependency';
  if (result.reason === 'untrusted_chain') return 'untrusted_chain';
  // `verification_failed` covers both a bad imprint and a bad CMS signature.
  // The imprint is the one an operator can act on, so name it when it is the
  // thing that failed.
  if (result.digestMatch === false) return 'imprint_mismatch';
  return 'verification_failed';
}

interface AnchorCheck {
  anchorValid: boolean | null;
  merkleProofValid: boolean | null;
  /** The tzun-anchor/1 §10.6 facts, whenever an anchor artifact is attached. */
  anchorFacts?: Pick<
    AttestationVerificationResult,
    'anchorPublication' | 'anchorOriginAuthenticated' | 'anchorPosition' | 'anchorNetwork' | 'anchorFinality' | 'anchorNamespace' | 'existedBy'
  >;
  /**
   * Whether an anchor artifact was attached at all: `anchor`, or a
   * `blockchainAnchor` that is abstained on.
   *
   * Distinct from `anchorValid === null`, which covers nothing attached and
   * every attached anchor that was not decided: no publication decided, or a
   * construction this verifier does not read. Only the first is absence —
   * see determineVerdict.
   */
  anchorPresent: boolean;
  anchorReason?: AttestationAnchorReason;
}

/**
 * The anchor verdict, decided by `verifyAnchor` (tzun-anchor/1 §10) with this
 * call's inputs. RFC 3161 publications are judged against the same supplied
 * trust anchors as the record's own token (`trustAnchorsPem`, `authorities`,
 * or `TZUN_TSA_TRUST_ANCHORS` / `TZUN_TSA_AUTHORITIES`). Unlike the record's
 * token, with none supplied they are not judged against the built-in default
 * roots: they stay `null`, `publication_not_checked`.
 */
async function verifyAnchorArtifact(
  artifacts: AttestationArtifacts,
  digest: string,
  options: AttestationVerifyOptions,
): Promise<AnchorCheck> {
  const v = await verifyAnchor(artifacts, digest, {
    ...(options.sequenceNumber !== undefined && { sequenceNumber: options.sequenceNumber }),
    ...(options.chainId !== undefined && { chainId: options.chainId }),
    ...(options.publisherManifest !== undefined && { publisherManifest: options.publisherManifest }),
    ...(options.evmHeaderSources !== undefined && { evmHeaderSources: options.evmHeaderSources }),
    ...(options.evmNetworks !== undefined && { evmNetworks: options.evmNetworks }),
    ...(options.evmTimeoutMs !== undefined && { evmTimeoutMs: options.evmTimeoutMs }),
    ...(options.anchorPublicationMaterial !== undefined && { publicationMaterial: options.anchorPublicationMaterial }),
    ...(options.trustAnchorsPem !== undefined && { trustAnchorsPem: options.trustAnchorsPem }),
    ...(options.authorities !== undefined && { authorities: options.authorities }),
  });
  if (!v.anchorPresent) return { anchorValid: null, merkleProofValid: null, anchorPresent: false };
  return {
    anchorValid: v.anchorValid,
    merkleProofValid: v.merkleProofValid,
    anchorPresent: true,
    ...(v.anchorReason !== undefined && { anchorReason: v.anchorReason }),
    anchorFacts: {
      anchorPublication: v.anchorPublication,
      anchorOriginAuthenticated: v.anchorOriginAuthenticated,
      anchorPosition: v.anchorPosition,
      anchorNetwork: v.anchorNetwork,
      anchorFinality: v.anchorFinality,
      anchorNamespace: v.anchorNamespace,
      existedBy: v.existedBy,
    },
  };
}

/**
 * The `attestationVerdict`: the three attestation checks summarised by how
 * many of them VERIFIED.
 *
 * A component counts only when its check returned `true`. An artifact that is
 * attached and fails (`false`), or attached and unchecked (`null`), counts for
 * nothing, so a record whose signature, timestamp and Merkle proof all fail
 * is `'none'`, not `'complete'`.
 *
 * The four words are the envelope `attestationStatus` vocabulary, shared with
 * the Python SDK, the backend and the operator console, and there is no fifth
 * word for "present but invalid": the individual `signatureValid` /
 * `timestampValid` / `anchorValid` booleans tell "absent" (null) from
 * "checked and failed" (false).
 */
function determineVerdict(
  signatureValid: boolean | null,
  timestampValid: boolean | null,
  anchorValid: boolean | null,
  anchorPresent: boolean
): 'complete' | 'partial' | 'pending' | 'none' {
  const signatureVerified = signatureValid === true;
  const timestampVerified = timestampValid === true;
  const anchorVerified = anchorValid === true;

  if (signatureVerified && timestampVerified && anchorVerified) return 'complete';

  // 'pending' is a verified signature whose companions are ABSENT — nothing
  // attached — never one whose companions failed: a signed record carrying a
  // forged or expired RFC 3161 token is 'partial', not 'pending'.
  //
  // `anchorValid === null` is not enough on its own, because only one of the
  // situations it covers is absence. The others are an anchor attached but
  // not decided (no publication decided) and one this verifier does not read
  // (`unsupported_merkle_spec`, `unsupported_anchor_spec`,
  // `legacy_blockchain_anchor`). Those are real artifacts someone wrote, so
  // `anchorPresent` rules the record out of 'pending'.
  if (signatureVerified && timestampValid === null && anchorValid === null && !anchorPresent) {
    return 'pending';
  }

  // A failed component alongside a verified sibling is 'partial': something
  // held up, something did not. All-failed falls through to 'none'.
  if (signatureVerified || timestampVerified || anchorVerified) return 'partial';
  return 'none';
}
