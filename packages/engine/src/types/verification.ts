import type { MonitoringEvent } from './monitoring-events';
import type { EvidenceEnvelope } from './evidence';
import type { MandateScopeFinding } from './mandate';

/**
 * One descriptor on the path from a contribution step's
 * `aiBom.modelDescriptorDigest` (leaf, index 0) up to the root of the parent
 * DAG.
 */
export interface ModelLineageEntry {
  descriptorDigest: string;
  integrityTier: 'weight-attested' | 'vendor-asserted';
  derivation: string | null;
  trainedBy: string | null;
}

/**
 * The model lineage of one contribution step whose `aiBom` is not `null`:
 * the step's index, its model descriptor digest, and the walk from it to the
 * root.
 */
export interface StepModelLineage {
  step: number;
  descriptorDigest: string;
  lineage: ModelLineageEntry[];
}

/**
 * One agent reference of a record, resolved against the store's agent
 * catalog (Record §6.9): the decider's or a step actor's `agent`.
 *
 * Reasons when `resolved` is `false`: `catalog_absent` (the store keeps no
 * catalog), `not_registered`, `digest_mismatch` (the stored bytes do not hash
 * to the reference), `malformed_descriptor`, `agent_kind_mismatch` (a
 * `policy-engine` whose descriptor names a model).
 */
export interface AgentReferenceCheck {
  /** The agent descriptor digest, `sha256:` and 64 lowercase hex. */
  reference: string;
  /** `decider`, or `contributions.steps[<i>].actor`. */
  field: string;
  resolved: boolean;
  reason?: string;
}

/**
 * AI-BOM tamper-incident entries produced by the verifier.
 *
 * The verifier itself does not push events onto the MonitoringEventBus —
 * that wiring lives in the scanner. The verifier attaches `MonitoringEvent`
 * payloads here so callers (including the scanner) can decide where to
 * route them.
 */
export type VerifierTamperIncident = Extract<
  MonitoringEvent,
  {
    type:
      | 'descriptor_resolution_failure'
      | 'descriptor_digest_mismatch'
      | 'parent_descriptor_resolution_failure'
      | 'parent_descriptor_digest_mismatch';
  }
>;

/**
 * Why a hashed custody trail failed to verify. `index` is the
 * position in `envelope.custodyChain` of the entry the failure is about.
 *
 *   - `unhashed_after_hashed`    an entry without an `entryHash` sits after one
 *                                 with one — the shape a forged, unhashed
 *                                 append takes on an already-hashed trail.
 *   - `prev_entry_hash_mismatch` the entry's `prevEntryHash` is not the
 *                                 previous hashed entry's `entryHash` (null for
 *                                 the first) — an entry was removed, reordered
 *                                 or inserted.
 *   - `entry_hash_mismatch`      the entry's `entryHash` does not recompute
 *                                 from its own fields, the record's evidenceId
 *                                 and its canonicalDigest — a field was
 *                                 rewritten, or the record's content moved after
 *                                 the repair.
 *   - `entry_field_type`         a field the hash rule consumes is not the type
 *                                 the rule requires: `action` / `actor` /
 *                                 `timestamp` / `systemId` must be strings,
 *                                 `prevEntryHash` a string or null, `metadata`
 *                                 a plain object or null — and the record's own
 *                                 `payload.evidenceId` /
 *                                 `integrity.canonicalDigest`, which every
 *                                 entry's hash commits to, must be strings too.
 *                                 Nothing about this entry can be recomputed, so
 *                                 the trail is reported invalid rather than
 *                                 assumed intact. JSON guarantees none of
 *                                 these types, so an entry such as
 *                                 `{"actor": 123}` gets this answer rather
 *                                 than a `TypeError` thrown out of the engine.
 *   - `entry_metadata_unserializable`
 *                                 `metadata` is a plain object, but the engine's
 *                                 canonical serializer refuses it (a lone UTF-16
 *                                 surrogate, nesting past the depth limit, a
 *                                 non-plain nested object), so the entry hash has
 *                                 no preimage to recompute from.
 */
export type CustodyTrailFailureReason =
  | 'unhashed_after_hashed'
  | 'prev_entry_hash_mismatch'
  | 'entry_hash_mismatch'
  | 'entry_field_type'
  | 'entry_metadata_unserializable';

export interface CustodyTrailFailure {
  reason: CustodyTrailFailureReason;
  /** Index into `envelope.custodyChain`. */
  index: number;
}

/** What `verifyCustodyTrail` (engine custody-hash.ts) answers for one envelope. */
export interface CustodyTrailVerdict {
  /**
   * `null` when the chain carries no hashed entry — records written before
   * custody entries were hashed, and purely client-attested trails, are
   * unverified, never a vacuous `true`.
   */
  valid: boolean | null;
  /** Entries carrying a well-formed `entryHash` (writer-authenticated). */
  hashedEntries: number;
  /**
   * Entries without one (client-attested, or written before entries were
   * hashed): counted, not vouched for.
   */
  unhashedEntries: number;
  failures: CustodyTrailFailure[];
}

/**
 * Why `signatureValid` came out the way it did.
 *
 * `signatureValid` on its own cannot tell "this assertion was checked and the
 * signature is forged" from "this artifact carries nothing that could be
 * checked" from "the reviewer signed a login nonce, so it binds no record" —
 * and those are three different facts about an evidence export. The union
 * lives here, in the engine's verification types, because it is part of the
 * verification contract; `src/attestation/verify-attestation.ts` produces the
 * values and re-exports the type under the same name.
 *
 * Two of these are the heart of the distinction and are worth reading together:
 *
 *  - `challenge_mismatch` — someone who KNOWS what this record's ceremony was
 *    supposed to sign says it signed something else. A finding.
 *  - `assertion_not_bound_to_digest` — the assertion is cryptographically
 *    genuine but its challenge is not derived from this record's digest, so it
 *    verifies against every record equally, which is the same as verifying
 *    against none. Reported for records captured before the binding existed
 *    and for replayed assertions alike, because nothing in the artifact
 *    distinguishes them. Neither is a pass.
 */
export type AttestationSignatureReason =
  /** No credential store was supplied, so the signature could not be checked at all. */
  | 'no_credential_store'
  /** `credentialKeyId` does not resolve to a registered credential. */
  | 'unknown_credential'
  /** No `authenticatorData` / `clientDataJSON`: there is no signed message to check. */
  | 'unverifiable_assertion'
  /** The credential is revoked, so nothing it signed counts as non-repudiation. */
  | 'revoked_credential'
  /** `clientDataJSON` does not decode to a JSON object. */
  | 'malformed_client_data'
  /** `clientDataJSON.type` is not 'webauthn.get' — e.g. a registration ceremony replayed. */
  | 'wrong_client_data_type'
  /** `clientDataJSON.origin` is not in `allowedOrigins`. */
  | 'untrusted_origin'
  /** `authenticatorData` is shorter than the mandatory 37 bytes. */
  | 'malformed_authenticator_data'
  /** `authenticatorData.rpIdHash` is not SHA-256(rpId). */
  | 'rp_id_mismatch'
  /** The User Present flag is clear: no human interacted with the authenticator. */
  | 'user_not_present'
  /** The signature does not verify against the registered public key. */
  | 'invalid_signature'
  /** A caller who asserted the expected challenge found the ceremony signed another. */
  | 'challenge_mismatch'
  /** Genuine signature, but over a challenge not derived from this record's digest. */
  | 'assertion_not_bound_to_digest';

// ── Assertion provenance: where the human signed, and with what kind of key ──

/**
 * Four of the eight bits in the flags byte of a WebAuthn assertion's
 * `authenticatorData` (WebAuthn Level 3 §6.1): byte 32, after the 32-byte
 * rpIdHash. The authenticator sets them and signs over them.
 *
 *   - `UP` bit 0, User Present: a human interacted with the authenticator.
 *   - `UV` bit 2, User Verified: the authenticator also verified WHO — a PIN
 *     or a biometric. `UP` without `UV` says the device was touched; `UV` says
 *     a human proved it was them.
 *   - `BE` bit 3, Backup Eligibility: the credential may be backed up or
 *     synced to other devices (a multi-device credential). Fixed when the
 *     credential is created. `false` is a single-device credential: the key
 *     cannot leave the authenticator.
 *   - `BS` bit 4, Backup State: the credential is backed up at the moment of
 *     this assertion. It can change over the credential's life, so `false` on
 *     a backup-eligible credential means "not backed up now", never
 *     "device-bound".
 */
export interface AuthenticatorFlags {
  UP: boolean;
  UV: boolean;
  BE: boolean;
  BS: boolean;
}

/**
 * Why `AssertionProvenance.originValid` is not `true`.
 *
 *   - `origin_not_checked`     no `allowedOrigins` was supplied, so nothing
 *                              was compared. Not a pass.
 *   - `origin_mismatch`        `clientDataJSON.origin` is not in
 *                              `allowedOrigins`, or the assertion states no
 *                              readable origin.
 *   - `no_verified_signature`  the stated origin is allowed, but the signature
 *                              over `clientDataJSON` did not verify as a
 *                              signature over this record, so nothing proves
 *                              the statement is the browser's.
 */
export type AssertionOriginReason = 'origin_not_checked' | 'origin_mismatch' | 'no_verified_signature';

/**
 * Why `AssertionProvenance.topOriginValid` is not `true`.
 *
 *   - `top_origin_not_checked` no `allowedTopOrigins` was supplied.
 *   - `top_origin_not_allowed` the ceremony's top-level page is not on the
 *                              list: a frame whose `topOrigin` is off it (the
 *                              shape a hostile page framing the ceremony
 *                              takes), or a ceremony run directly in a tab
 *                              (`crossOrigin: false`) whose own `origin` is
 *                              off it.
 *   - `top_origin_unknown`     the ceremony ran cross-origin (or the assertion
 *                              does not say whether it did) and names no
 *                              top-level origin, so nothing shows which page
 *                              framed it; or it states `crossOrigin: false`
 *                              and no `origin`.
 *   - `no_verified_signature`  the statement satisfies the list, but the
 *                              signature over it did not verify as a signature
 *                              over this record.
 */
export type AssertionTopOriginReason =
  | 'top_origin_not_checked'
  | 'top_origin_not_allowed'
  | 'top_origin_unknown'
  | 'no_verified_signature';

/**
 * Why `AssertionProvenance.deviceBound` is not `true`. `false` is a LOWER
 * rung of signature strength, not a failed signature: `signatureValid` and
 * `verified` are untouched by it.
 *
 *   - `device_bound_not_required`   no device-bound credential was required,
 *                                   so the flags were recorded and not judged.
 *   - `credential_synced`           `BE` and `BS` set: a synced passkey. The
 *                                   signature implies access to the account
 *                                   it syncs through, on any of its devices.
 *   - `credential_backup_eligible`  `BE` set, `BS` clear: the credential can
 *                                   be synced and is not backed up at this
 *                                   moment. Not device-bound.
 *   - `invalid_backup_flags`        `BS` set on a credential that is not
 *                                   backup-eligible, which WebAuthn §6.1.3
 *                                   rules out.
 *   - `flags_unreadable`            no `authenticatorData` of at least 37
 *                                   bytes, so there are no flags to read.
 *   - `no_verified_signature`       `BE` is clear, but the signature over
 *                                   `authenticatorData` did not verify as a
 *                                   signature over this record, so nothing
 *                                   proves the authenticator said so.
 */
export type DeviceBoundReason =
  | 'device_bound_not_required'
  | 'credential_synced'
  | 'credential_backup_eligible'
  | 'invalid_backup_flags'
  | 'flags_unreadable'
  | 'no_verified_signature';

/**
 * Where a WebAuthn ceremony ran and what kind of key signed it, as the
 * assertion's signed bytes state it, and the checks a caller asked for
 *.
 *
 * The four recorded fields come from inside the signed message:
 * `clientDataJSON` (`origin`, `crossOrigin`, `topOrigin`) and
 * `authenticatorData` (`flags`). Each is `null` when the assertion does not
 * state it or states it in the wrong type.
 *
 * Each check has three answers, as `signatureValid` does:
 *
 *   - `true`   the caller's requirement was checked, the assertion meets it,
 *              and the signature over the statement verified as a signature
 *              over this record (`signatureValid: true`).
 *   - `false`  the requirement was checked and the assertion does not meet
 *              it. The artifact alone is enough to say so: a wrong statement
 *              is a finding whether the signature over it holds or not.
 *   - `null`   not checked (no requirement was supplied), or the statement
 *              meets the requirement but no verified signature vouches for
 *              it. The reason says which.
 *
 * `crossOrigin: true` is accepted: a ceremony in a cross-origin frame is how
 * a Tzun-origin ceremony runs inside a browser extension's side panel
 *, and `topOrigin` then names the page that framed it.
 */
export interface AssertionProvenance {
  /**
   * `clientDataJSON.origin`: the origin the ceremony ran on. Here and in
   * `topOrigin`, a lone UTF-16 surrogate is recorded as U+FFFD.
   */
  origin: string | null;
  /** `clientDataJSON.crossOrigin`: whether the ceremony ran in a frame cross-origin to its ancestors. */
  crossOrigin: boolean | null;
  /** `clientDataJSON.topOrigin`: the top-level origin that framed a cross-origin ceremony. */
  topOrigin: string | null;
  /** The flags byte of `authenticatorData`. */
  flags: AuthenticatorFlags | null;
  /** `origin` against `allowedOrigins`. */
  originValid: boolean | null;
  /** Present whenever `originValid` is not `true`. */
  originReason?: AssertionOriginReason;
  /**
   * The top-level origin against `allowedTopOrigins`: `topOrigin`, or, for a
   * ceremony that states `crossOrigin: false` and no `topOrigin`, its own
   * `origin` — it was not framed, so its top-level page is the page it ran on.
   */
  topOriginValid: boolean | null;
  /** Present whenever `topOriginValid` is not `true`. */
  topOriginReason?: AssertionTopOriginReason;
  /** Whether the key that signed is a single-device credential (`BE` clear). */
  deviceBound: boolean | null;
  /** Present whenever `deviceBound` is not `true`. */
  deviceBoundReason?: DeviceBoundReason;
}

/**
 * Why `signoffExpectationValid` is not `true` (Verification §5):
 *
 *   - `digest_invalid`                `null`: the record's digest does not
 *                                     recompute (the payload was changed
 *                                     under it, cannot be serialized, or
 *                                     names a schema version this engine
 *                                     does not know), so its
 *                                     `payload.signoffExpectation` is not
 *                                     authenticated and is not read. The
 *                                     record already reads `verified: false`;
 *                                     an expectation rewritten to `null`
 *                                     under a stripped signature reads this,
 *                                     never `true`.
 *   - `signature_missing`             `null`: the record's hashed
 *                                     `payload.signoffExpectation` is
 *                                     `{ policyDigest }`, and the record does
 *                                     not carry a signature that meets it. The
 *                                     record is not final: one awaiting
 *                                     sign-off reads this until it is signed,
 *                                     and one whose signature was stripped
 *                                     reads it for good.
 *   - `signoff_stripped`              `false`: the record names a session
 *                                     slot, and carries no `signoff` block, or
 *                                     no assertion. A session record is
 *                                     written with its sign-off, so it was
 *                                     removed.
 *   - `signoff_unbound`               `false`: the record carries a `signoff`
 *                                     block and an assertion that do not bind
 *                                     by the checks that need no key: for a
 *                                     batch block, its statement is not
 *                                     `mode: 'batch'`, the assertion did not
 *                                     present the statement's challenge, or
 *                                     the inclusion proof does not put the
 *                                     record's digest under the statement's
 *                                     root and size; for a session slot, the
 *                                     assertion did not present the session
 *                                     statement's challenge. A moved,
 *                                     relabelled or made-up sign-off reads
 *                                     this, whatever the expectation.
 *   - `statement_digest_mismatch`     `false`: the record names a session
 *                                     statement, and its `signoff` carries
 *                                     another statement (or none it can hash).
 *   - `session_seq_mismatch`          `false`: the record names a session slot,
 *                                     and its `signoff` names another.
 *   - `session_signoff_not_expected`  `false`: the record carries a session
 *                                     sign-off, and its expectation names no
 *                                     session.
 *   - `malformed_signoff_expectation` `false`: `payload.signoffExpectation` is
 *                                     neither `null` nor one of its three
 *                                     forms (policy, session, mandate).
 *   - `mandate_not_expected`          `false`: the record carries a `mandate`
 *                                     block and its expectation is not the
 *                                     mandate form.
 *   - `mandate_stripped`              `false`: the mandate form, and no
 *                                     `mandate` block.
 *   - `malformed_mandate_statement`   `false`: the block's statement is not a
 *                                     well-formed `tzun-signoff-mandate/1`
 *                                     statement.
 *   - `mandate_assertion_mismatch`    `false`: the block's assertion does not
 *                                     hash (minimal DER, low-S) to
 *                                     `mandateAssertion`.
 *   - `mandate_unbound`               `false`: the assertion did not present
 *                                     the statement's challenge.
 *   - `mandate_document_mismatch`     `false`: the block's document does not
 *                                     hash to `statement.mandateDigest`, or
 *                                     its principal is not the statement's
 *                                     signer.
 *   - `confirmation_missing`          `null`: `confirm` is `true` and no
 *                                     confirmation presents the record's
 *                                     confirmation challenge.
 */
export type SignoffExpectationReason =
  | 'digest_invalid'
  | 'signature_missing'
  | 'signoff_stripped'
  | 'signoff_unbound'
  | 'statement_digest_mismatch'
  | 'session_seq_mismatch'
  | 'session_signoff_not_expected'
  | 'malformed_signoff_expectation'
  | 'mandate_not_expected'
  | 'mandate_stripped'
  | 'malformed_mandate_statement'
  | 'mandate_assertion_mismatch'
  | 'mandate_unbound'
  | 'mandate_document_mismatch'
  | 'confirmation_missing';

// ── Record rules: decider, contributions, links, mandate ───

/**
 * The four outcomes of a record-rule check (Verification §2.1):
 * decided and holding, decided and failing, not checked (with a reason), and
 * abstained (a construction this version does not implement; never a
 * failure).
 */
export type RecordRuleOutcome = 'checked-correct' | 'checked-wrong' | 'not-checked' | 'abstain';

/** A row that carries an outcome and its reason only. */
export interface RecordRuleRow {
  outcome: RecordRuleOutcome;
  reason: string;
}

/**
 * The `decider` row (`checkDecider`). `valid` is `true` for checked-correct,
 * `false` for checked-wrong and `null` otherwise; `reason` is present
 * whenever `outcome` is not checked-correct.
 *
 * Reasons: `digest_invalid`,
 * `blocked_by:signoff.expectation`, `absent`, `malformed_decider`,
 * `unsupported_decider_kind`, `decider_inconsistent`,
 * `decider_kind_contradicted`, `unsupported_identifier_scheme`,
 * `material_unverified`.
 */
export interface DeciderCheck {
  outcome: RecordRuleOutcome;
  valid: boolean | null;
  reason?: string;
  kind?: string;
  scheme?: string;
  /** `human-asserted` or `agent-asserted`: this version verifies no signature. */
  level?: 'human-asserted' | 'agent-asserted';
  /** `human-proven` when human decision material is bound to the record, with no key to prove who signed. */
  levelUndetermined?: 'human-proven';
  /** `true` for a `cmt` identifier. */
  committed?: boolean;
  /** `undetermined` when material of the other class is bound but cannot be verified in this version. */
  kindContradiction?: 'undetermined';
}

/**
 * The `contributions.binding` row: the process checks, read from the record
 * alone. A review that covers no step is a fact, not a failure.
 *
 * Reasons: `digest_invalid`, `absent`,
 * `blocked_by:contributions`, `input_undeclared`, `review_unbound`,
 * `decision_unbound`, `decided_output_differs`.
 */
export interface ContributionsBindingCheck {
  outcome: RecordRuleOutcome;
  valid: boolean | null;
  reason?: string;
  /** Current, bound reviews whose verdict is `approve`. */
  approvals: number[];
  /** Reviews of an earlier proposal: reported, never counted. */
  staleApprovals: number[];
  /** Reviews with no proposal before them. */
  uncoveredReviews: number[];
  /** Indexes of the propose steps. */
  proposals: number[];
  decisionBinding: 'checked' | 'not-applicable';
  /** The step a failure names. */
  failedStep?: number;
  /** The digest a failure names. */
  failedDigest?: string;
}

/**
 * The `contributions` row: the structure checks. `binding` is the process
 * row, blocked unless this one is checked-correct; `pipeline` (the
 * `contributions.pipeline` row) is present when the member names a pipeline,
 * which this version does not verify.
 *
 * Reasons: `digest_invalid`, `absent`, `malformed_contributions`,
 * `step_chain_broken`, `decider_not_deciding_actor`,
 * `deciding_output_mismatch`, `unsupported_actor_kind`,
 * `unsupported_identifier_scheme`.
 */
export interface ContributionsCheck {
  outcome: RecordRuleOutcome;
  valid: boolean | null;
  reason?: string;
  /** The number of steps. */
  steps?: number;
  /** The distinct model descriptor digests of the steps' bills of materials, in step order. */
  models?: string[];
  /** The index of the `decide` step, or `record` when there is none (the record's decider decided after the last step). */
  decidingStep?: number | 'record';
  failedStep?: number;
  binding: ContributionsBindingCheck;
  pipeline?: RecordRuleRow;
}

/**
 * One `links[<i>]` row (Verification §4.11). Reasons: `blocked_by:links`,
 * `blocked_by:signoff.expectation`, `unsupported_link_relation`,
 * `link_attrs_invalid`, `link_rule_violated` (with `rule`),
 * `link_target_mismatch` (with `member`), `unsupported_link_rule`,
 * `link_rule_undetermined` (with `rule`), `not_in_bundle:link_target`.
 */
export interface LinkRelationCheck {
  index: number;
  rel: string;
  outcome: RecordRuleOutcome;
  valid: boolean | null;
  reason?: string;
  /** The rule a `link_rule_violated` or `link_rule_undetermined` names. */
  rule?: string;
  /** The target member a `link_target_mismatch` names: `digest`, `evidenceId` or `locator`. */
  member?: string;
  /** Whether the verifier held the target record. */
  targetHeld?: boolean;
  /**
   * On a `not_in_bundle:link_target` row, the record the verifier did not
   * hold: `target`, or `subject` for a link record's link whose rules read
   * its subject.
   */
  missing?: 'subject' | 'target';
  /** A `root` link whose target is not the root its held lineage target names, or has a lineage link of its own: a fact, never a failure. */
  rootInconsistent?: boolean;
}

/**
 * The `links` row and the rows under it (Record §8.8, Verification §4.11).
 *
 * Reasons of the `links` row: `digest_invalid`, `absent`, `malformed_links`
 * (with `failedLink` and `rule`), `link_rule_violated` (a list-level rule,
 * with `rule`: `mandate_link`, `revokes_link`, `subject_link`, `at_most_one`).
 * `relations` holds one row per link, in list order; `edges` one
 * `links[<i>].edge` row per link, each `abstain`, `unsupported_link_edge`, in
 * this version.
 */
export interface LinksCheck {
  outcome: RecordRuleOutcome;
  valid: boolean | null;
  reason?: string;
  rule?: string;
  failedLink?: number;
  /** The number of links. */
  count?: number;
  /** The distinct relation names, in list order. */
  relationNames?: string[];
  /** How many links have an `x-` relation. */
  extensions?: number;
  relations: LinkRelationCheck[];
  edges: RecordRuleRow[];
}

/**
 * The `mandate.issuance` row. Reasons: `issuance_not_expected`,
 * `issuance_material_stripped`, `issuance_material_mismatch` (with `link`).
 */
export interface MandateIssuanceCheck {
  outcome: RecordRuleOutcome;
  valid: boolean | null;
  reason?: string;
  /** The broken link: `document`, `statement`, `signer`, `challenge`, `assertion` or `decider`. */
  link?: string;
}

/**
 * The `mandate.scope` row. Reasons: `blocked_by:signoff.expectation`,
 * `not_in_bundle:mandate_document`, `malformed_mandate_document`,
 * `agent_not_in_mandate`, `outside_mandate_scope`, `confirmation_evaded`,
 * `scope_undeterminable`.
 */
export interface MandateScopeCheck {
  outcome: RecordRuleOutcome;
  valid: boolean | null;
  reason?: string;
  failures?: MandateScopeFinding[];
  undeterminable?: MandateScopeFinding[];
}

/**
 * The `mandate.limits` row. Reasons: `blocked_by:signoff.expectation`,
 * `not_in_bundle:mandate_document`, `malformed_mandate_document`,
 * `mandate_totals_malformed`, `mandate_limit_exceeded`.
 */
export interface MandateLimitsCheck {
  outcome: RecordRuleOutcome;
  valid: boolean | null;
  reason?: string;
  slot?: number;
  totals?: Record<string, number> | null;
}

/** The mandate rows of a record: the mandate form's scope and limits, and an issuance record's material. */
export interface MandateCheck {
  /** Present for the mandate form. */
  scope?: MandateScopeCheck;
  /** Present for the mandate form. */
  limits?: MandateLimitsCheck;
  /** Present for an issuance record, or a record carrying issuance material. */
  issuance?: MandateIssuanceCheck;
  /** `digest_invalid` when the record's digest does not recompute. */
  reason?: string;
}

/**
 * The expectation check's answer (the engine's `checkSignoffExpectation`, the
 * `signoff.expectation` row of Verification §5): `true` the record carries
 * what its expectation names, `false` it carries something its expectation
 * rules out, a sign-off that does not bind, or lacks the session sign-off it
 * was written with, `null` it lacks the signature its policy form requires (awaiting sign-off,
 * or stripped), or, in a verifier's answer, its digest does not recompute
 * (`digest_invalid`). `reason` is present whenever `valid` is not `true`.
 */
export interface SignoffExpectationCheck {
  valid: boolean | null;
  reason?: SignoffExpectationReason;
}

/** Result of verifying an evidence record's integrity. */
export interface VerificationResult {
  verified: boolean;
  storedDigest: string;
  recomputedDigest: string;
  schemaVersion: string;
  schemaValid: boolean;
  chainLinkValid: boolean | null;
  signatureValid: boolean | null;
  timestampValid: boolean | null;
  /**
   * The record's anchor (`nonRepudiation.anchor`, tzun-anchor/1 §10.6). `null`
   * from `verifyEnvelope`, which checks no attestation artifact. The SDK's
   * `Tzun.verify()` decides it with `verifyAnchor`: the proofs, and each
   * publication as far as the verifier's inputs allow (with no header source
   * an EVM publication is `null`, `publication_not_checked`).
   */
  anchorValid: boolean | null;
  /**
   * Why `anchorValid` is not `true` (tzun-anchor/1 §10.1, §10.6), from
   * `Tzun.verify()`: the verifier's reason for a record that carries an
   * anchor, and, for one that carries none on a store that expects one,
   * `anchor_not_yet_published` (tzun-anchor/1 §10.1) while its epoch is
   * awaited, or `absent` once the store has finished filling the epoch that
   * covers it (`logFindings` then holds `anchor_stripped`). Absent when
   * `anchorValid` is `true`, and for a record with no anchor on a store that
   * does not anchor.
   */
  anchorReason?: string;
  /**
   * What the store's logs show is wrong with the record, as `get()` reports
   * them, from `Tzun.verify()` on a local store. Present only
   * when there is a finding.
   */
  logFindings?: RecordLogFinding[];
  /**
   * From `Tzun.verify()`, for a record that carries an anchor: the
   * verifier's `anchorNamespace` (tzun-anchor/1 §10.6). `'test'` whenever
   * the anchor checkpoint parses and its origin begins with `test.`, whatever
   * the verdict; `'production'` only for an authenticated origin that is not
   * a test origin; otherwise `null`. A display says "test" on `'test'`, not
   * "anchored".
   */
  anchorNamespace?: 'production' | 'test' | null;
  /**
   * From `Tzun.verify()`, for a record that carries an anchor: what the
   * header source counted as final for the true EVM publications, the
   * verifier's `anchorFinality`. A confirmation depth with `acceptNonFinal`
   * may not be final at all: a display says "not final" on it, not
   * "anchored". `null` unless an EVM publication is `true`.
   */
  anchorFinality?: EvmFinality | null;
  /**
   * From `Tzun.verify()`, for a record that carries an anchor: the earliest
   * time a `true` publication proves P existed by, and its source. `null`
   * unless a publication is `true`.
   */
  existedBy?: AnchorExistedBy | null;
  attestationStatus: 'complete' | 'partial' | 'pending' | 'none';
  credentialStatus?: 'active' | 'revoked';
  /**
   * Why `signatureValid` is not `true`. Present only when the
   * envelope carries a `nonRepudiation.webauthnAssertion` and the verdict was
   * anything other than a pass. Absent on a clean pass and on records with no
   * assertion at all.
   */
  signatureReason?: AttestationSignatureReason;
  /**
   * Where the ceremony ran and what kind of key signed it, and the checks the
   * caller asked for. Present only when the envelope carries a
   * `nonRepudiation.webauthnAssertion` and the SDK's `verify()` read it.
   */
  assertionProvenance?: AssertionProvenance;
  verifiedAt: string;
  /**
   * The model lineage of each contribution step whose `aiBom` is not `null`,
   * in step order, each from the step's model descriptor (leaf) to the root.
   * Populated only when the verifier was called with
   * `options.walkLineage === true` AND a storage adapter.
   */
  modelLineage?: StepModelLineage[];
  /**
   * AI-BOM tamper incidents emitted by the verifier during descriptor
   * resolution / parent-DAG walking. Only populated when the verifier was
   * called with a storage adapter.
   */
  tamperIncidents?: VerifierTamperIncident[];
  /**
   * Whether the hashed custody trail the envelope carries verifies.
   * `true`/`false` when at least one `custodyChain` entry carries an
   * `entryHash`; `null` when none does — an unhashed trail is UNVERIFIED, not
   * invalid. Every relink, fork and annotation an SDK writer or the hosted
   * service records since 0.3.15 is hashed.
   *
   * Deliberately NOT folded into `verified`: `custodyChain` is outside the
   * hashed field set, so `verified` keeps meaning "the decision record and its
   * chain link are intact", and a `false` here means "the record of who did
   * what to it afterwards has been altered". Optional on the type for
   * additive compatibility; the engine always populates it.
   */
  custodyTrailValid?: boolean | null;
  /** Present only when `custodyTrailValid` is `false`: what failed, and where. */
  custodyTrailFailures?: CustodyTrailFailure[];
  /**
   * The record's sign-off material against its hashed
   * `payload.signoffExpectation` (Verification §5): `true` when it
   * carries what the expectation names (nothing, for a `null` expectation),
   * `false` when it carries a sign-off the expectation rules out, a sign-off
   * that does not bind, or lacks the session sign-off it was written with,
   * `null` when the signature its policy form requires is missing. Read from
   * the record alone, and only when its digest recomputes: the expectation
   * is authenticated by nothing else, so a record whose digest does not hold
   * reads `null`, `digest_invalid`. Whether a carried signature verifies is
   * `signatureValid`'s answer.
   *
   * Not folded into `verified`, which keeps meaning "the decision record and
   * its chain link are intact"; a read's `RecordVerdict` carries the same
   * answer as `signoffExpectation`, outside its `status`. Optional on the type
   * for additive compatibility; the engine always populates it.
   */
  signoffExpectationValid?: boolean | null;
  /** Present whenever `signoffExpectationValid` is not `true`. */
  signoffExpectationReason?: SignoffExpectationReason;
  /**
   * When the stored digest does not recompute under the current hashed field
   * set but does under an earlier one (Record §4.1): `'0.7'` or
   * `'before-0.7'`. It says why the digest does not hold, and never excuses
   * it: a store-write attacker can rewrite a record into an earlier field set
   * and recompute its digest, so `verified` stays `false`.
   */
  fieldSet?: '0.7' | 'before-0.7';
  /**
   * The payload members outside the twelve names of the format
   * (Record §2.2), sorted by bytes. They are not hashed, so they change no
   * digest; a reader reports each (`payload.<name>`, abstain) rather than
   * pass over one. Empty for every record an SDK writes. Absent when the
   * schema version is not registered.
   */
  unhashedPayloadMembers?: string[];
  /**
   * The record rules, each checked from the record alone and only where its
   * digest recomputes (otherwise `digest_invalid`). Absent when the schema
   * version is not registered. Not folded into `verified`, which keeps
   * meaning "the decision record and its chain link are intact".
   */
  decider?: DeciderCheck;
  /** The structure and process checks of `payload.contributions`. */
  contributions?: ContributionsCheck;
  /** The grammar, list-level and relation rules of `payload.links`; this version verifies no edge. */
  links?: LinksCheck;
  /** The mandate rows, present for the mandate form and for an issuance record. */
  mandate?: MandateCheck;
  /**
   * With storage: the decider's and every step actor's agent reference,
   * resolved against the store's agent catalog and re-hashed.
   */
  agents?: AgentReferenceCheck[];
  /**
   * Present only when the payload could not be canonically serialized at all,
   * so no digest could be recomputed from it. Carries the
   * serializer's own message — a lone UTF-16 surrogate, nesting past the depth
   * limit, a non-finite number, a non-plain object.
   *
   * `verified` is `false` and `recomputedDigest` is `''` whenever this is set:
   * a record this implementation cannot canonicalize is a record whose digest
   * cannot be true of it. The alternative — throwing the serializer's Error
   * out of `verifyEnvelope` — would turn a malformed client-supplied envelope
   * into a 500 on every server that verifies what a client sent.
   */
  payloadSerializationError?: string;
}

// ── Custody ledger: the rows behind the mirror ────────────────────────────

/**
 * One `custody_entries` ledger row, in the form an export bundle carries it.
 *
 * The field names are the ones the hosted service's customer export writes
 * into `server.custody.entries`, so one offline verifier reads the SDK's
 * bundle and the hosted service's alike. The row's
 * record is implicit: every entry in a bundle belongs to the bundle's
 * envelope.
 *
 * `actorParty` and `recordedAt` are platform columns. The SDK's ledger has
 * neither, so an SDK bundle carries `null` for both. Neither is part of the
 * entry hash.
 */
export interface CustodyLedgerEntry {
  /** The row's id, as text. Orders the rows of one record. */
  id: string;
  action: string;
  actor: string;
  /** Which party the actor acted for, where the ledger records it. */
  actorParty: string | null;
  /** The entry timestamp exactly as mirrored into `custodyChain[i].timestamp`. */
  timestamp: string;
  systemId: string;
  metadata: Record<string, unknown> | null;
  /** The record's `integrity.canonicalDigest` at the time of the action. */
  canonicalDigest: string;
  /** `entryHash` of the previous row for the same record; null for the first. */
  prevEntryHash: string | null;
  entryHash: string;
  /** The relink / fork / annotation record this action belongs to, if any. */
  recoveryId: string | null;
  /** When the ledger stored the row, where the ledger records it. */
  recordedAt: string | null;
}

/**
 * Why a record's custody ledger and its `custodyChain` mirror failed to agree.
 * The same ten reasons, with the same meanings, as the hosted service's
 * custody-trail check:
 *
 *   - `record_missing`           ledger rows for a record that is not there.
 *   - `row_hash_mismatch`        a row's `entryHash` does not recompute from its
 *                                 own fields and `prevEntryHash`.
 *   - `row_prev_mismatch`        a row's `prevEntryHash` is not the previous
 *                                 row's `entryHash` (null for the first).
 *   - `digest_moved_since_entry` the record's digest is no longer the one the
 *                                 row was recorded against: its content moved
 *                                 after the custody action.
 *   - `unhashed_after_hashed`    an unhashed mirror entry sits after a hashed one.
 *   - `mirror_entry_missing`     a row has no hashed mirror entry.
 *   - `mirror_entry_unexpected`  a hashed mirror entry has no row behind it.
 *   - `mirror_hash_mismatch`     a mirror entry's `entryHash` is not its row's.
 *   - `mirror_prev_mismatch`     a mirror entry's `prevEntryHash` is not its row's.
 *   - `mirror_fields_mismatch`   a mirror entry's `entryHash` does not recompute
 *                                 from the mirror entry's own fields.
 */
export type CustodyLedgerFailureReason =
  | 'record_missing'
  | 'row_hash_mismatch'
  | 'row_prev_mismatch'
  | 'digest_moved_since_entry'
  | 'unhashed_after_hashed'
  | 'mirror_entry_missing'
  | 'mirror_entry_unexpected'
  | 'mirror_hash_mismatch'
  | 'mirror_prev_mismatch'
  | 'mirror_fields_mismatch';

export interface CustodyLedgerFailure {
  reason: CustodyLedgerFailureReason;
  /** The ledger row's `id` when the failure is about a row. */
  rowId?: string;
  /** Index into `envelope.custodyChain` when the failure is about the mirror. */
  index?: number;
  detail?: string;
}

/**
 * What `verifyCustodyLedger` answers for one record: its ledger rows checked
 * against each other and against the envelope's `custodyChain` mirror. The
 * shape of the verdict the hosted service's export ships as
 * `server.custody.trail`.
 *
 * `valid` is `true` for a record with no rows and no hashed mirror entries:
 * there is nothing to disagree. Read `rows` and `hashedEntries` to tell that
 * record from one whose trail was checked.
 */
export interface CustodyLedgerVerdict {
  evidenceId: string;
  valid: boolean;
  /** Ledger rows for the record. */
  rows: number;
  /** Mirror entries carrying an `entryHash`. */
  hashedEntries: number;
  /**
   * Mirror entries without one (client-attested, or written before entries
   * were hashed): counted, not vouched for.
   */
  unhashedEntries: number;
  failures: CustodyLedgerFailure[];
}

/**
 * Why a `'relinked'` custody entry disagrees with the relink record it names.
 *
 *   - `relink_record_missing`    the entry names a relink record the store does
 *                                 not hold.
 *   - `relink_digest_mismatch`   the relink record the entry names no longer has
 *                                 the `relinkDigest` the entry recorded: the
 *                                 relink was altered after the fact — its range
 *                                 widened, its `modifiedLinks` rewritten.
 *
 * `ScheduledScanner` makes this check, and `verifyCustodyLedger` does not: the
 * rule that writes `relinkDigest` (`computeRelinkDigest`) lives in the SDK's
 * `RecoveryManager`, and the relink record it is checked against is in the
 * store, not in the envelope or an export bundle. The findings ride in the same
 * `custody_trail_invalid` event as the ledger's.
 */
export type CustodyRelinkFailureReason = 'relink_record_missing' | 'relink_digest_mismatch';

export interface CustodyRelinkFailure {
  reason: CustodyRelinkFailureReason;
  /** Index into `envelope.custodyChain` of the `'relinked'` entry. */
  index: number;
}

// ── Record verdict: what a read found ─────────────────────────────────────

/**
 * The answer one integrity check gives about one record.
 *
 *   - `valid`       the check ran and passed.
 *   - `invalid`     the check ran and failed; the check's `reason` says how.
 *   - `unmeasured`  the check did not run, or had nothing to run on; the
 *                   check's `reason` says which. Never a pass.
 */
export type RecordCheckStatus = 'valid' | 'invalid' | 'unmeasured';

/**
 * Why the digest check is not `valid`.
 *
 *   - `record_missing`          the store holds no record for the id: nothing
 *                               recomputes to the digest it holds for it.
 *   - `digest_mismatch`         the payload recomputes to a different digest.
 *   - `stored_digest_mismatch`  the payload recomputes to the envelope's
 *                               `integrity.canonicalDigest`, but that is not
 *                               the digest the store holds for the record
 *                               (`RecordVerdictInput.currentDigest`): the
 *                               envelope was rewritten consistently after the
 *                               store recorded it. `stored` and `recomputed`
 *                               are the envelope's; the store's digest is the
 *                               one the reader supplied.
 *   - `unknown_schema_version`  `payload.schemaVersion` names no rules this
 *                               engine has. `schemaVersion` is outside the
 *                               hashed field set and the registry holds only
 *                               the versions a writer can produce, so this is
 *                               itself evidence of modification.
 *   - `payload_unserializable`  the payload cannot be canonically serialized,
 *                               so no digest is true of it.
 *   - `read_verification_off`   unmeasured: the instance was initialised with
 *                               `verifyReads: false`.
 */
export type RecordDigestReason =
  | 'record_missing'
  | 'digest_mismatch'
  | 'stored_digest_mismatch'
  | 'unknown_schema_version'
  | 'payload_unserializable'
  | 'read_verification_off';

export interface RecordDigestCheck {
  status: RecordCheckStatus;
  /**
   * `integrity.canonicalDigest` as stored. For a record the store holds no
   * envelope for, the digest the store holds for it
   * (`RecordVerdictInput.currentDigest`), or `''` when it holds none.
   */
  stored: string;
  /** The digest recomputed from the payload; `''` when none was computed. */
  recomputed: string;
  /** Present whenever `status` is not `valid`. */
  reason?: RecordDigestReason;
}

/**
 * Why the custody-trail check is not `valid`: one of the ten
 * `CustodyLedgerFailureReason`s (the first failure; the ledger verdict lists
 * them all), or why it is unmeasured. Spelled out rather than written as a
 * union with `CustodyLedgerFailureReason`, which the Python codegen cannot
 * read.
 *
 *   - `nothing_to_measure`         no ledger rows and no hashed mirror entries:
 *                                  the record has never been repaired or
 *                                  reviewed, so there is no trail to check.
 *   - `custody_ledger_unreadable`  reading the ledger failed; `detail` carries
 *                                  the error. The record is still returned.
 *   - `no_custody_ledger`          the store keeps no custody ledger (the Python
 *                                  SDK's adapters), so only the envelope-only
 *                                  check is available.
 *   - `read_verification_off`      the instance was initialised with
 *                                  `verifyReads: false`.
 */
export type RecordCustodyReason =
  | 'record_missing'
  | 'row_hash_mismatch'
  | 'row_prev_mismatch'
  | 'digest_moved_since_entry'
  | 'unhashed_after_hashed'
  | 'mirror_entry_missing'
  | 'mirror_entry_unexpected'
  | 'mirror_hash_mismatch'
  | 'mirror_prev_mismatch'
  | 'mirror_fields_mismatch'
  | 'nothing_to_measure'
  | 'custody_ledger_unreadable'
  | 'no_custody_ledger'
  | 'read_verification_off';

export interface RecordCustodyCheck {
  status: RecordCheckStatus;
  /** Present whenever `status` is not `valid`. */
  reason?: RecordCustodyReason;
  /** The ledger-against-mirror verdict, or null when the ledger was not read. */
  ledger: CustodyLedgerVerdict | null;
  /** The error message when the ledger could not be read. */
  detail?: string;
}

/**
 * Why the chain-link check is not `valid`.
 *
 *   - `chain_link_mismatch`     `integrity.chainLink` is not
 *                               SHA-256(predecessor digest ‖ this digest).
 *   - `predecessor_missing`     the record carries a link, or its sequence
 *                               number says it has a predecessor, and the
 *                               store holds no record at the previous sequence
 *                               of its chain.
 *   - `chain_link_missing`      a record with a predecessor carries no link.
 *   - `predecessor_unreadable`  reading the predecessor failed; `detail`
 *                               carries the error.
 *   - `record_missing`          unmeasured: the store holds no record for the
 *                               id, so there is no link to check.
 *   - `not_checked_on_read`     unmeasured: a link is a property of two
 *                               records, and `get()` / `list()` read one. The
 *                               export, `verify()` and the chain walks check it.
 *   - `read_verification_off`   the instance was initialised with
 *                               `verifyReads: false`.
 */
export type RecordChainLinkReason =
  | 'chain_link_mismatch'
  | 'predecessor_missing'
  | 'chain_link_missing'
  | 'predecessor_unreadable'
  | 'record_missing'
  | 'not_checked_on_read'
  | 'read_verification_off';

export interface RecordChainLinkCheck {
  status: RecordCheckStatus;
  /** Present whenever `status` is not `valid`. */
  reason?: RecordChainLinkReason;
  /** The predecessor digest the link was checked against; null when none was. */
  predecessorDigest: string | null;
  /** The error message when the predecessor could not be read. */
  detail?: string;
}

/**
 * What the integrity checks found about one stored record when it was read.
 *
 * A verdict never withholds the record: a read of a tampered record returns
 * the record with an `invalid` verdict beside it. `status` is `invalid` when
 * any check that ran failed, `unmeasured` when the digest check did not run
 * (the instance was initialised with `verifyReads: false`), and `valid`
 * otherwise — so `valid` means every check that ran passed, and each check's
 * own `status` says whether it ran.
 */
export interface RecordVerdict {
  status: RecordCheckStatus;
  digest: RecordDigestCheck;
  custodyTrail: RecordCustodyCheck;
  chainLink: RecordChainLinkCheck;
  /**
   * The record's sign-off material against its hashed
   * `payload.signoffExpectation` (`checkSignoffExpectation`;
   * Verification §5): what `verify()` reports as `signoffExpectationValid`
   * and `signoffExpectationReason`: `null`, `digest_invalid` whenever `digest`
   * is not `valid`. It does not count towards `status`, which
   * says whether the record and its trail are intact. Absent when the store
   * holds no record for the id, when read verification is off, and on a
   * verdict computed before 0.7.0.
   */
  signoffExpectation?: SignoffExpectationCheck;
  /** When the checks ran. */
  checkedAt: string;
}

/** A stored record as a local read returns it: the envelope and the verdict on it. */
export interface EvidenceRead {
  envelope: EvidenceEnvelope;
  verdict: RecordVerdict;
  /**
   * Where the record sits in its chain's evidence log, as
   * `CaptureResult.logPosition` reports it. `get()` reports it for a record
   * its store holds a leaf for; `list()` and the cloud transport do not
   * report it.
   */
  logPosition?: RecordLogPosition;
  /**
   * How far the record's anchor has got: a store-side state, which
   * tzun-anchor/1 §10.9 leaves outside the specification. `get()` reports
   * it for a record with a leaf, on a store that anchors: one whose
   * anchoring tables hold an anchor log. `list()` and the cloud transport do
   * not report it.
   */
  anchorState?: RecordAnchorState;
  /**
   * What the store's logs show is wrong with the record. `get()` reports it
   * beside `logPosition`, only when there is a finding.
   */
  logFindings?: RecordLogFinding[];
}

/**
 * Where a stored record sits in its chain's evidence log (Tree §5.2).
 */
export interface RecordLogPosition {
  /** The evidence log's origin: `<ns>/<storeId>/evidence/<hex of the chain id's UTF-8>`. */
  origin: string;
  /** The record's leaf: `payload.sequenceNumber − 1`. */
  leafIndex: number;
}

/**
 * The stages of a record's anchor, read from its store:
 *
 *   - `awaiting_epoch`     no epoch has taken the record's leaf into the
 *                          store's anchor log, or the epoch that has is not
 *                          published yet: nothing of it has been sent;
 *   - `awaiting_finality`  the epoch is published (its transaction signed or
 *                          mined, or its token obtained) and not final yet,
 *                          or it is final and the fill has not reached the
 *                          record yet;
 *   - `anchored`           the epoch's publication is final, the record's
 *                          digest recomputed from its payload is its stored
 *                          `canonicalDigest` and the leaf its evidence log
 *                          holds for it, and the record carries a
 *                          `nonRepudiation.anchor` made for that log and
 *                          leaf, whose proofs hold for that digest
 *                          (tzun-anchor/1 §10.3 steps 1 to 5, with its
 *                          sequence number and chain), whose publications
 *                          none is `false`, and whose anchor checkpoint's
 *                          digest is the P of a final publication of the
 *                          store's that covers the record;
 *   - `anchor_invalid`     the epoch's publication is final and the record is
 *                          not anchored as stored, and never will be: its
 *                          recomputed digest is not its stored one or not its
 *                          logged leaf, or it carries an anchor that does not
 *                          hold for it (a proof fails, a publication is
 *                          `false`, or the verifier abstains on it), that was
 *                          made for another leaf, or whose anchor checkpoint
 *                          the store did not publish, or the fill finished
 *                          and left it without one. `anchorValid` and
 *                          `anchorReason` say what the verifier found, and
 *                          `logFindings` what the store's logs show.
 */
export type RecordAnchorStage = 'awaiting_epoch' | 'awaiting_finality' | 'anchored' | 'anchor_invalid';

/** The publication of the epoch that covers a record, as its store holds it. */
export interface RecordAnchorPublication {
  /** `evm-calldata/1` when the epoch has one, otherwise `rfc3161/1`. */
  kind: 'evm-calldata/1' | 'rfc3161/1';
  /** CAIP-2 chain of an EVM publication. */
  chain?: string;
  /** The transaction carrying P, once one is signed: the mined one, else the latest sent. */
  transactionId?: string;
  /** The block that includes the transaction, once it is mined. */
  blockNumber?: number;
}

/** How far a stored record's anchor has got (see {@link RecordAnchorStage}). */
export interface RecordAnchorState {
  state: RecordAnchorStage;
  /** The record's evidence log: `logPosition.origin`. */
  origin: string;
  /** The record's leaf: `logPosition.leafIndex`. */
  leafIndex: number;
  /**
   * While the record awaits its epoch (`awaiting_epoch`), when that epoch is
   * due, ISO 8601: the time its leaf was logged plus the interval the
   * cadence cuts epochs at (the governor's). Fees above
   * the soft maximum may defer the epoch to T_max (`maxStalenessMs`) after
   * the oldest waiting leaf. A `dueBy` in the past on a record still awaiting
   * its epoch means the epoch is overdue. Reported by an instance that
   * anchors (`anchoring`), which knows the cadence; absent otherwise.
   */
  dueBy?: string;
  /**
   * The verifier's answer on the record's `nonRepudiation.anchor`, from
   * `verifyAnchor` with the digest recomputed from the record's payload, its
   * sequence number and chain, and no other input: the proofs are checked,
   * and a publication is decided only as far as that allows (with no header
   * source an EVM publication is `null`, `publication_not_checked`). A record
   * whose payload was altered after it was anchored therefore reads `false`,
   * `merkle_proof_invalid`. `null` for a record that carries no anchor.
   */
  anchorValid: boolean | null;
  /**
   * The verifier's reason whenever `anchorValid` is not `true` and the record
   * carries an anchor (tzun-anchor/1 §10.1). For a record that carries none,
   * `anchor_not_yet_published` (tzun-anchor/1 §10.1), except once the
   * store has finished filling the epoch that covers it, when the reason is
   * `absent` and `logFindings` holds `anchor_stripped`.
   */
  anchorReason?: string;
  /**
   * The publication that decides the stage, once an epoch covers the record:
   * the epoch's `evm-calldata/1` publication when it has one, otherwise its
   * `rfc3161/1` one.
   */
  publication?: RecordAnchorPublication;
}

/** A confirmation depth that counts as final (see {@link EvmFinality}). */
export interface EvmConfirmationDepth {
  confirmations: number;
  acceptNonFinal?: boolean;
}

/**
 * What counts as final (tzun-anchor/1 §10.4, "the height of the newest block
 * it considers final"):
 *
 * - `'finalized'` (the default): the node's `finalized` block tag, the block
 *   Ethereum's consensus has finalized;
 * - `{ confirmations: n }`: a block with at least `n` blocks on top of it,
 *   counting itself. `n` is a positive integer of at least
 *   `EVM_MIN_FINAL_CONFIRMATIONS` (64, in the SDK);
 * - `{ confirmations: n, acceptNonFinal: true }`: any positive `n`. The caller
 *   accepts that an anchor judged this way may be reorganised away before the
 *   chain finalizes it (with `n = 2`, seconds after mining, where an Ethereum
 *   public network takes about 15 minutes to finalize).
 *
 * Anything else is refused when a header source or verifier is constructed.
 */
export type EvmFinality = 'finalized' | EvmConfirmationDepth;

/** The earliest proven time P existed by, and what proved it. */
export interface AnchorExistedBy {
  /** ISO 8601. */
  at: string;
  source: 'evm-calldata' | 'rfc3161';
}

/**
 * A finding about one record from its store's logs:
 *
 *   - `digest_differs_from_logged_leaf`  the record's
 *                                        `canonicalDigest` is not the leaf
 *                                        its evidence log holds for it: the
 *                                        record was rewritten after it was
 *                                        logged.
 *   - `anchor_stripped`                  the store has finished
 *                                        filling the final epoch that covers
 *                                        the record, and the record carries
 *                                        no `nonRepudiation.anchor`.
 *   - `anchor_transplanted`              the record carries a `tzun-anchor/1`
 *                                        artifact made for another leaf: its
 *                                        log checkpoint names another log
 *                                        than the record's evidence log, or
 *                                        its `leafIndex` is not the record's
 *                                        leaf.
 *   - `anchor_checkpoint_not_published`  the epoch that covers the record is
 *                                        final, and the record carries an
 *                                        anchor whose anchor checkpoint
 *                                        parses and whose digest is not the P
 *                                        of any final publication of the
 *                                        store's that covers the record: an
 *                                        artifact built over an anchor log
 *                                        the store did not publish, whatever
 *                                        its proofs say.
 */
export type RecordLogFinding =
  | 'digest_differs_from_logged_leaf'
  | 'anchor_stripped'
  | 'anchor_transplanted'
  | 'anchor_checkpoint_not_published';
