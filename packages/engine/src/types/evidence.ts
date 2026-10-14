import type { Contributions, ContributionsInput } from './contributions';
import type { Decider, DeciderInput } from './decider';
import type { Link, LinkInput } from './links';
import type { MandateBlock, MandateExpectation } from './mandate';

/**
 * What an application passes to capture a decision. The SDK resolves it into
 * an {@link EnvelopeInput}: the decider's identifier, freshness and
 * commitment, the contributions' digests and step descriptors, the links'
 * same-store targets.
 *
 * The 0.7 names are refused: `humanAction`, `humanReason` and `reviewer`
 * (`renamed_field`), a top-level `aiBom` and `lineage` (`moved_field`).
 */
export interface CaptureInput {
  aiSystemId?: string;
  aiOutput: Record<string, unknown>;
  /** The decision taken: 1 to 128 printable ASCII characters, no leading or trailing space. */
  action: string;
  /** The stated reason: 1 to 16,384 UTF-16 code units. */
  reason: string;
  /** Who decided. Required. */
  decider: DeciderInput;
  /**
   * Who contributed, in builder form. A single model is a list of one
   * (`singleModel(aiBom)`); a step's `aiBom` may carry its descriptor inline,
   * which the SDK registers and replaces with its digest.
   */
  contributions?: ContributionsInput | null;
  /** The records this decision relates to. Same-store targets may omit `digest` and `locator`. */
  links?: LinkInput[] | null;
  /**
   * Pre-verified attestation inputs to pass through to the orchestrator.
   *
   * An assertion passed here is not in the record's digest, so a record
   * alone does not show one that was later stripped: a verifier reads the
   * record as carrying no signature, and `verifyBundle()` reports
   * `signoff.key` absent and exits 0. A caller whose records must carry a
   * signature also sets the capture option `signoffExpectation: {
   * policyDigest }`, which is hashed, so a stripped signature then reads
   * `signature_missing` (`signoffExpectationValid: null`; exit 4 from
   * `verifyBundle()`, never 0).
   */
  attestationInputs?: {
    webauthnAssertion?: AttestationArtifacts['webauthnAssertion'];
    signerIdentity?: AttestationArtifacts['signerIdentity'];
  };
}

/**
 * `payload.signoffExpectation` `{ policyDigest }`: a human signature is
 * required on this record under the sign-off policy whose digest this is
 * (Record §9.1). The SDK takes it as lowercase hex SHA-256 of the policy's
 * canonical bytes; the specification does not interpret the policy. The
 * signature may arrive at capture or later (a record awaiting sign-off);
 * either way the record itself says one is owed.
 */
export interface SignatureRequiredExpectation {
  /** 64 lowercase hex. */
  policyDigest: string;
}

/**
 * `payload.signoffExpectation` `{ statementDigest, sessionSeq }`: the record
 * was captured into a sign-off session (Record §9.1) and holds slot
 * `sessionSeq` of it. `statementDigest` is the session statement's digest
 * (Record §9.4: lowercase hex SHA-256 of its canonical bytes). Only the
 * capture that claimed the slot may set it: the slot is claimed before the
 * record's digest is built, because this value is inside the digest.
 */
export interface SessionAttachmentExpectation {
  /** 64 lowercase hex. */
  statementDigest: string;
  /** The slot, 1-based: a safe integer, at least 1. */
  sessionSeq: number;
}

/**
 * What signature a record expects, stated in its hashed payload
 * (Record §9.1, §9.2). `null` on `EvidencePayload.signoffExpectation` means
 * none is expected. Because it is hashed, the record alone shows a
 * signature that was stripped from it, or one transplanted onto it from
 * another record (21 CFR 11.70: a signature "cannot be excised, copied, or
 * otherwise transferred"). The exact members of one form, and nothing else:
 * the policy form, the session form, or the mandate form, which only a capture
 * under a mandate writes.
 */
export type SignoffExpectation = SignatureRequiredExpectation | SessionAttachmentExpectation | MandateExpectation;

/**
 * Why a value is not a signoff expectation, first failure first (the engine's
 * `signoffExpectationViolation`):
 *
 *   - `not_an_object`             neither `null` nor a plain object;
 *   - `unknown_members`           an object whose members are not exactly
 *                                 those of one form (`policyDigest`;
 *                                 `statementDigest` and `sessionSeq`;
 *                                 `mandateAssertion`, `mandateSeq`, `totals`
 *                                 and `confirm`);
 *   - `invalid_policy_digest`     `policyDigest` is not 64 lowercase hex;
 *   - `invalid_statement_digest`  `statementDigest` is not 64 lowercase hex;
 *   - `invalid_session_seq`       `sessionSeq` is not a safe integer of at
 *                                 least 1;
 *   - `invalid_mandate_assertion` `mandateAssertion` is not 64 lowercase hex;
 *   - `invalid_mandate_seq`       `mandateSeq` is not a safe integer of at
 *                                 least 1;
 *   - `invalid_totals`            `totals` is neither `null` nor an object of
 *                                 1 to 16 caps named `[A-Za-z0-9._-]{1,64}`,
 *                                 each a non-negative safe integer;
 *   - `invalid_confirm`           `confirm` is not `true` or `false`.
 */
export type SignoffExpectationViolation =
  | 'not_an_object'
  | 'unknown_members'
  | 'invalid_policy_digest'
  | 'invalid_statement_digest'
  | 'invalid_session_seq'
  | 'invalid_mandate_assertion'
  | 'invalid_mandate_seq'
  | 'invalid_totals'
  | 'invalid_confirm';

/**
 * The payload of a v1.0 record: what gets serialized and digested
 * (Record §2.2, §4.1). `action` and `reason` are the decision taken and the
 * stated reason, whoever took it; `decider` says who that was;
 * `contributions` records who contributed and is the only place a model's
 * bill of materials is recorded;
 * `links` names the records the decision relates to. A writer writes every
 * key, `null` where a member does not apply, and no other key.
 *
 * @tzun-canonical-sort utf16
 * @tzun-hashed-fields action, aiOutput, aiSystemId, capturedAt, contributions, decider, evidenceId, links, reason, sequenceNumber, signoffExpectation
 */
export interface EvidencePayload {
  evidenceId: string;
  /** `"v1.0"`; outside the digest. */
  schemaVersion: string;
  aiSystemId: string;
  aiOutput: Record<string, unknown>;
  /** 1 to 128 printable ASCII characters, no leading or trailing space. */
  action: string;
  /** 1 to 16,384 UTF-16 code units. */
  reason: string;
  capturedAt: string;
  /** Monotonically increasing sequence number. Makes deletion detectable via gaps. */
  sequenceNumber: number;
  /** `null` reads "decider not recorded"; every 0.8.0 writer writes one. */
  decider: Decider | null;
  /** `null` when no contributor is recorded; a single model is a list of one step. */
  contributions: Contributions | null;
  /** `null` when the record links to none (never `[]`). */
  links: Link[] | null;
  /**
   * What signature this record expects (Record §9.1): `null` when
   * none is, a {@link SignatureRequiredExpectation} when a signature is
   * required under a sign-off policy, a {@link SessionAttachmentExpectation}
   * when the record was captured into a sign-off session, a
   * {@link MandateExpectation} when an agent decided under a mandate. It is
   * hashed, so it is fixed at capture: `verifyEnvelope` reports a signature
   * missing from a record that expects one, and a sign-off that is not the
   * one the record expects.
   */
  signoffExpectation: SignoffExpectation | null;
}

/**
 * What `assembleEnvelope` builds a v1.0 record from. Every member is resolved:
 * `decider` is the record's decider (its identifier and freshness chosen),
 * each step's `aiBom` names a catalogued descriptor, `contributions` is built
 * (`buildContributions`), and `links` is built (`buildLinks`).
 */
export interface EnvelopeInput {
  aiSystemId?: string;
  aiOutput: Record<string, unknown>;
  action: string;
  reason: string;
  decider: Decider;
  contributions?: Contributions | null;
  links?: Link[] | null;
}

/** The closed list of refusal codes for a payload's top-level members (the engine's payload rules). */
export type PayloadViolationCode =
  | 'payload_too_large'
  | 'reserved_ai_system_id'
  | 'invalid_ai_system_id'
  | 'unsupported_schema_version'
  | 'invalid_evidence_id'
  | 'invalid_captured_at'
  | 'invalid_sequence_number'
  | 'invalid_action'
  | 'invalid_reason'
  | 'invalid_ai_output'
  | 'unknown_payload_member'
  | 'missing_members'
  | 'renamed_field'
  | 'moved_field';

export interface PayloadViolation {
  code: PayloadViolationCode;
  field: string;
  message: string;
  /** For `renamed_field`: the field's new name. */
  renamedTo?: string;
  /** For `moved_field`: where the field's content now lives. */
  movedTo?: string;
}

/**
 * Constrained set of actions for the append-only custody chain.
 * New actions require explicit addition to this union type.
 */
export type CustodyAction =
  | 'decision_captured'
  | 'verified'
  | 'exported'
  | 'relinked'
  | 'chain_forked'
  | 'attested'
  | 'reviewed'
  | 'captured_under_mandate'
  | 'confirmation_required'
  | 'mandate_confirmed';

/**
 * A single entry in the append-only custody chain.
 *
 * `custodyChain` is OUTSIDE the v1.0 hashed field set (schema-registry.ts):
 * no field on this interface takes part in `integrity.canonicalDigest`, so
 * adding keys here changes no digest and no wire byte of the hashed payload.
 */
export interface CustodyEntry {
  timestamp: string;
  actor: string;
  action: CustodyAction;
  systemId: string;
  metadata?: Record<string, unknown>;
  /**
   * Writer-minted, by the hosted service's ledger or by the SDK's own
   * adapters. SHA-256 commitment to this entry, the record's
   * `integrity.canonicalDigest` at the time of the append, and the previous
   * hashed entry on the same record (`prevEntryHash`) — the rule is
   * `computeCustodyEntryHash` in custody-hash.ts, one implementation shared
   * with the platform's ledger. Written by a `custody_entries` ledger (the
   * platform's, or an SDK adapter's since 0.3.15) when it mirrors a row into
   * the envelope; ABSENT on client-attested entries (the `decision_captured`
   * entry `assembleEnvelope` writes). Outside the hashed field set: present
   * or not, the canonical digest is unchanged. `verifyEnvelope` checks it
   * (`custodyTrailValid`).
   * @tzun-omit-when-unset
   */
  entryHash?: string;
  /**
   * Server-minted. The `entryHash` of the previous
   * server-minted entry on this record, `null` for the first one. Absent on
   * client-attested entries. Outside the hashed field set.
   * @tzun-omit-when-unset
   */
  prevEntryHash?: string | null;
}

/** A WebAuthn assertion as a record carries it. */
export interface WebauthnAssertion {
  signature: string;
  credentialKeyId: string;
  algorithm: 'Ed25519' | 'ES256';
  /** Base64-encoded authenticatorData from the WebAuthn assertion (for at-rest verification) */
  authenticatorData?: string;
  /** Base64-encoded clientDataJSON from the WebAuthn assertion (for at-rest verification) */
  clientDataJSON?: string;
}

/** Attestation artifacts received from external services. */
export interface AttestationArtifacts {
  webauthnAssertion?: WebauthnAssertion;
  signerIdentity?: {
    idpToken: string;
    idpIssuer: string;
  };
  rfc3161Token?: string;
  /** Parsed metadata from the RFC 3161 timestamp response. Convenience layer -- the opaque
   *  base64 rfc3161Token remains the canonical artifact for full re-verification. */
  rfc3161Metadata?: {
    /** ISO-8601 timestamp from the TSA (genTime from TSTInfo). */
    genTime: string;
    /** Signing certificate subject (TSA name). */
    tsaName?: string;
    /** TSA policy OID from TSTInfo. */
    policyOid?: string;
    /** PKIStatus from the TimeStampResp. */
    status: 'granted' | 'grantedWithMods' | 'rejection' | 'waiting';
  };
  /**
   * The record's anchor (tzun-anchor/1 §8): its place in its chain's evidence
   * log, that log's checkpoint in the store's anchor log, and the epoch's
   * publications of P. Written once, when the epoch's publication is final
   * (its block at or below the chain's finalized height, or, for a store that
   * publishes only through RFC 3161, its token obtained), and never
   * overwritten. A record not yet anchored has no `anchor` key.
   * It sits under `nonRepudiation`, outside the v1.0 hashed field set, so
   * writing it moves no record's canonical digest.
   */
  anchor?: AnchorArtifact;
  /**
   * What ties the record's `webauthnAssertion` to a batch or session
   * sign-off (Record §9.3). Absent on a record signed per record, and
   * on an unsigned one. It sits under `nonRepudiation`, outside the hashed
   * field set: the record's hashed `payload.signoffExpectation` is what says
   * which sign-off, if any, the record must carry.
   * @tzun-omit-when-unset
   */
  signoff?: SignoffArtifact;
  /**
   * A record decided under a mandate: the principal's signed authorisation,
   * written in the capturing transaction. Outside the hashed field set; bound
   * by the hashed `signoffExpectation.mandateAssertion`.
   * @tzun-omit-when-unset
   */
  mandate?: MandateBlock;
  /**
   * A mandate's issuance record: the same material as `mandate`, bound by the
   * record's hashed `aiOutput` (`mandateDigest`, `statementDigest`,
   * `assertionDigest`).
   * @tzun-omit-when-unset
   */
  mandateIssuance?: MandateBlock;
  /**
   * A human's confirmation of a record whose mandate expectation says one is
   * owed: a WebAuthn assertion over `mandateConfirmationChallenge(digest)`,
   * attached fill-only after capture.
   * @tzun-omit-when-unset
   */
  confirmation?: WebauthnAssertion;
}

/**
 * `nonRepudiation.signoff`, the sign-off block (Record §9.3).
 */
export interface SignoffArtifact {
  /**
   * The sign-off statement, verbatim (Record §9.4). Its digest is lowercase hex
   * SHA-256 of its canonical bytes; its shape and version are the sign-off
   * verifier's to check, so a reader loads whatever object is here.
   */
  statement: Record<string, unknown>;
  /**
   * Batch only: the record's place in the batch tree. The root and size come
   * from the statement.
   * @tzun-omit-when-unset
   */
  inclusion?: SignoffInclusion;
  /**
   * Session only: the record's slot in the session, 1-based.
   * @tzun-omit-when-unset
   */
  sessionSeq?: number;
}

/** A batch-signed record's inclusion proof (Record §9.3), leaf-first lowercase hex. */
export interface SignoffInclusion {
  leafIndex: number;
  path: string[];
}

/**
 * `nonRepudiation.anchor` (tzun-anchor/1 §8.1). The members are exactly these;
 * a writer writes no other. Every hash is lowercase hex and every path is
 * leaf-first, under the RFC 6962 wire spec.
 */
export interface AnchorArtifact {
  /** The tag of the whole structure. A verifier that does not know it abstains. */
  anchorSpec: 'tzun-anchor/1';
  /** The tree construction of both logs. */
  merkleSpec: 'rfc6962';
  /** The record's index in its evidence log: `payload.sequenceNumber − 1`. */
  leafIndex: number;
  /** The body of the record's evidence log at a size greater than `leafIndex`: `<origin>\n<size>\n<base64 root>\n`. */
  logCheckpoint: string;
  /** `PATH(leafIndex, D[size])` of the evidence log. */
  logPath: string[];
  /** Where `SHA-256(logCheckpoint)` sits in the store's anchor log. */
  anchorLeafIndex: number;
  /** The body of the anchor log at the epoch's published size. `SHA-256` of it is P. */
  anchorCheckpoint: string;
  /** `PATH(anchorLeafIndex, A[size])` of the anchor log. */
  anchorPath: string[];
  /** The epoch's publications of P that were complete when the artifact was written, in any order. */
  publications: AnchorArtifactPublication[];
}

/**
 * An `evm-calldata/1` publication as the artifact carries it
 * (tzun-anchor/1 §8.2): the transaction that carried `0x ‖ P`. The raw
 * transaction, the block header and the trie proof travel in the export
 * bundle, never here.
 */
export interface EvmAnchorPublication {
  kind: 'evm-calldata/1';
  /** CAIP-2 chain, e.g. `eip155:1`. Display only: a verifier takes the chain from its manifest. */
  chain: string;
  /** `0x` and 64 lowercase hex: `keccak256` of the raw signed transaction. */
  transactionId: string;
  /** The block that includes the transaction. */
  blockNumber: number;
  /** `0x` and 64 lowercase hex. */
  blockHash: string;
  /** `0x` and 40 hex. Display only: a verifier recovers the sender from the signature. */
  publisher: string;
}

/** An `rfc3161/1` publication (tzun-anchor/1 §8.2): a timestamp token whose imprint is P. */
export interface Rfc3161AnchorPublication {
  kind: 'rfc3161/1';
  /** Base64 of the DER `TimeStampResp`. */
  token: string;
}

/** One publication entry of `nonRepudiation.anchor`. */
export type AnchorArtifactPublication = EvmAnchorPublication | Rfc3161AnchorPublication;

/**
 * The complete evidence envelope — payload + integrity + attestation.
 *
 * @tzun-canonical-sort utf16
 */
export interface EvidenceEnvelope {
  envelopeVersion: 'e1';
  payload: EvidencePayload;
  integrity: {
    canonicalDigest: string;
    chainLink: string | null;
  };
  nonRepudiation: AttestationArtifacts;
  custodyChain: CustodyEntry[];
  attestationStatus: 'complete' | 'partial' | 'pending' | 'none';
}
