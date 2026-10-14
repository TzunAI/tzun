// scripts/codegen-python.ts — emits python/src/tzun_sdk/_generated/models.py
// (Pydantic v2) from packages/engine/src/types/*.ts. canonical.py / chain.py are stable
// committed outputs — verified present, never rewritten.
//
// Behavior contract:
//   - Every exported interface/type-alias in the nine engine type files that is a
//     pure data shape is emitted. Interfaces with method/call-signature/function-typed
//     members are auto-excluded; the explicit EXCLUDE table lists data-shaped types
//     that are deliberately TS-only. Both exclusion groups are listed in the output
//     footer, so every exclusion is auditable.
//   - Inline anonymous object types lift to named classes via LIFTED_NAMES; a missing
//     entry FAILS the build naming the ownerKey (fail-don't-guess).
//   - Unmapped TS constructs throw naming the construct + ownerKey.
//   - Output is byte-deterministic; `--stamp` appends a `# Source commit:`
//     line for local provenance runs only.
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ts from 'typescript';
import { listTimestampAuthorities, normaliseUrl } from '../src/attestation/tsa-registry';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const TS_TYPES_DIR = join(REPO_ROOT, 'packages', 'engine', 'src', 'types');
const ENGINE_SRC_DIR = join(REPO_ROOT, 'packages', 'engine', 'src'); // public entrypoint lives here
const PY_GENERATED_DIR = join(REPO_ROOT, 'python', 'src', 'tzun_sdk', '_generated');
const OUT_FILE = join(PY_GENERATED_DIR, 'models.py');

// The known-models seed catalog is authored once, at data/known-models.json,
// and consumed by both SDKs. The Python package used to reach it through a
// wheel-only hatch force-include of `../data/known-models.json`, a path that
// does not exist inside an sdist — so `pip install` from the sdist produced
// an SDK whose model catalog was silently empty. Syncing it here makes it an
// ordinary tracked package data file that the wheel AND the sdist both carry,
// and CI's existing codegen-drift check keeps the copy honest.
const KNOWN_MODELS_SRC = join(REPO_ROOT, 'data', 'known-models.json');
const KNOWN_MODELS_DST = join(REPO_ROOT, 'python', 'src', 'tzun_sdk', '_data', 'known-models.json');

// The timestamp authorities the TypeScript registry ships, by key and by URL
// in the form `getTimestampAuthority` compares a selector in. The Python SDK
// reads it to refuse an authority name the registry does not know with the
// TypeScript verifier's words (Verification §3.1); it holds no roots, since
// the Python SDK checks no trust path.
const TSA_AUTHORITIES_DST = join(REPO_ROOT, 'python', 'src', 'tzun_sdk', '_data', 'tsa-authorities.json');

function tsaAuthoritiesJson(): string {
  const authorities = listTimestampAuthorities().map((a) => {
    const normalisedUrl = normaliseUrl(a.url);
    if (normalisedUrl === undefined) throw new Error(`timestamp authority ${a.key}: its URL ${a.url} does not parse`);
    return { key: a.key, url: a.url, normalisedUrl };
  });
  return `${JSON.stringify({ source: 'src/attestation/tsa-registry.ts', authorities }, null, 2)}\n`;
}

// The supported JSDoc annotations, read by the tag reader below.
const CANONICAL_SORT_TAG = 'tzun-canonical-sort';
const HASHED_FIELDS_TAG = 'tzun-hashed-fields';
// A TS `?:` property has NO wire key when it is undefined — JSON.stringify
// drops it — but a Pydantic `x: T | None = None` field serialises as
// `"x": null`, a key the platform's exact-allowlist capture endpoint refuses
// as `unknown_field`. Properties tagged `@tzun-omit-when-unset` get a wrap
// serializer that drops the key unless the field was explicitly set, so an
// absent key stays absent across a Python round trip while an explicit
// `null` (a real wire value, e.g. the first server-minted custody entry's
// `prevEntryHash`) survives. Only legal on optional (`?:`) properties.
const OMIT_WHEN_UNSET_TAG = 'tzun-omit-when-unset';

// ── Pinned tables ────────────────────────────────────────────────────
// Inline anonymous nested types lifted to the hand-port's names.
// An inline object type with NO entry here fails the build (fail-don't-guess).
// Union-alias branches use `${AliasName}.${branchIndex}` keys.
const LIFTED_NAMES: Record<string, string> = {
  'ModelDescriptor.training': 'TrainingInfo',
  'AiBom.promptTemplate': 'PromptTemplate',
  'AiBom.inferenceParameters': 'InferenceParameters',
  'AiBom.infrastructure': 'Infrastructure',
  'StepAiBom.promptTemplate': 'StepPromptTemplate',
  'StepAiBom.inferenceParameters': 'StepInferenceParameters',
  'StepAiBom.infrastructure': 'StepInfrastructure',
  'AttestationArtifacts.webauthnAssertion': 'WebauthnAssertion',
  'AttestationArtifacts.signerIdentity': 'SignerIdentity',
  'AttestationArtifacts.rfc3161Metadata': 'Rfc3161Metadata',
  'EvidenceEnvelope.integrity': 'IntegrityBlock',
  // Surfaced by fail-on-unmapped runs:
  'CaptureInput.attestationInputs': 'CaptureAttestationInputs',
  'TamperIncident.affectedSequenceRange': 'SequenceRange',
  'ExportedDescriptorEntry.0': 'ExportedDescriptorEntryPresent',
  'ExportedDescriptorEntry.1': 'ExportedDescriptorEntryMissing',
  'ExportedAgentDescriptorEntry.0': 'ExportedAgentDescriptorEntryPresent',
  'ExportedAgentDescriptorEntry.1': 'ExportedAgentDescriptorEntryMissing',
  'ExportedServerReceipt.attestation': 'ExportedServerAttestation',
  'ExportedServerReceipt.custody': 'ExportedServerCustody',
};

// Fields the hand-port types as `int` (everything else numeric → `int | float`).
const NUMBER_AS_INT = new Set<string>([
  'EvidencePayload.sequenceNumber',
  'EvmConfirmationDepth.confirmations',
  'InferenceParameters.maxTokens',
  'InferenceParameters.seed',
  'StepInferenceParameters.maxTokens',
  'StepInferenceParameters.seed',
  'ModifiedLink.sequenceNumber',
  'RelinkRecord.fromSequence',
  'RelinkRecord.toSequence',
  'CustodyTrailFailure.index',
  'CustodyTrailVerdict.hashedEntries',
  'CustodyTrailVerdict.unhashedEntries',
  'StoredCustodyEntry.id',
  'CustodyLedgerFailure.index',
  'CustodyRelinkFailure.index',
  'CustodyLedgerVerdict.rows',
  'CustodyLedgerVerdict.hashedEntries',
  'CustodyLedgerVerdict.unhashedEntries',
  'ExportedChainPredecessor.sequenceNumber',
  'ForkRecord.forkAfterSequence',
  'ForkRecord.sealedOldChainLength',
  'ForkRecord.sealedOldChainHead',
  'AnchorArtifact.leafIndex',
  'AnchorArtifact.anchorLeafIndex',
  'EvmAnchorPublication.blockNumber',
  'RecordLogPosition.leafIndex',
  'RecordAnchorState.leafIndex',
  'RecordAnchorPublication.blockNumber',
  'SessionAttachmentExpectation.sessionSeq',
  'SignoffArtifact.sessionSeq',
  'SignoffInclusion.leafIndex',
  // The record rules: every number they carry is an integer.
  'FreshnessReference.blockNumber',
  'LinkLocator.seq',
  'Link.attrs',
  'LinkInput.attrs',
  'LinksViolation.link',
  'LinksCheck.failedLink',
  'LinksCheck.count',
  'LinksCheck.extensions',
  'LinkRelationCheck.index',
  'StepModelLineage.step',
  'ContributionsCheck.decidingStep',
  'ContributionsViolation.step',
  'MandatePredicate.value',
  'MandateCap.max',
  'MandateLimits.maxRecords',
  'MandateDelegation.maxDepth',
  'MandateReview.maxAgeMs',
  'MandateExpectation.mandateSeq',
  'MandateExpectation.totals',
  'MandateEventBody.used',
  'MandateEventBody.totals',
  'MandateSlotGap.from',
  'MandateSlotGap.to',
  'MandateSlotGap.unexplained',
  'MandateUnexplainedStep.slot',
  'MandateUnexplainedStep.expected',
  'MandateUnexplainedStep.actual',
  'MandateMalformedRecord.index',
  'MandateConsumptionResult.duplicateSlots',
  'MandateConsumptionResult.completeUpTo',
  'MandateConsumptionResult.beyondEvent',
  'ContributionsCheck.steps',
  'ContributionsCheck.failedStep',
  'ContributionsBindingCheck.approvals',
  'ContributionsBindingCheck.staleApprovals',
  'ContributionsBindingCheck.uncoveredReviews',
  'ContributionsBindingCheck.proposals',
  'ContributionsBindingCheck.failedStep',
  'MandateLimitsCheck.slot',
  'MandateLimitsCheck.totals',
  'MandateRecordState.used',
  'MandateRecordState.totals',
  'MandateCapClaim.expectTotal',
  'MandateCapClaim.newTotal',
  'MandateClaimStore.expectUsed',
  'MandateRevokeStore.expectUsed',
  'MandateRevokeStore.expectTotals',
  'MandateExpireStore.expectUsed',
  'MandateExpireStore.expectTotals',
  'MandateRow.used',
  'MandateRow.maxRecords',
  'MandateCapLimit.max',
  'EvidenceLinkRow.idx',
]);

// Fields that stay `float` (never `int`) — numeric measurement fields the
// hand-port types as `float`. Overrides the default `int | float`.
const NUMBER_AS_FLOAT = new Set<string>([
  'InferenceParameters.temperature',
  'InferenceParameters.topP',
  'StepInferenceParameters.temperature',
  'StepInferenceParameters.topP',
]);

// Required-literal-with-default fields and Field(default_factory) non-None
// defaults, populated from python/src/tzun_sdk/models.py (the hand-port is
// the defaults inventory of record). Value is the exact Python default
// expression to emit after `field: type = `.
const FIELD_DEFAULTS: Record<string, string> = {
  'ModelDescriptor.descriptorVersion': '"d1"',
  'ModelDescriptor.training': 'Field(default_factory=TrainingInfo)',
  'ModelDescriptor.regulatoryMarkings': 'Field(default_factory=list)',
  'ModelDescriptor.externalIdentifiers': 'Field(default_factory=list)',
  'TrainingInfo.evaluations': 'Field(default_factory=list)',
  'Evaluation.metrics': 'Field(default_factory=dict)',
  'EvidencePayload.schemaVersion': '"v1.0"',
  'EvidenceEnvelope.envelopeVersion': '"e1"',
  'EvidenceEnvelope.nonRepudiation': 'Field(default_factory=AttestationArtifacts)',
  'EvidenceEnvelope.custodyChain': 'Field(default_factory=list)',
  'EvidenceEnvelope.attestationStatus': '"none"',
};

// Field-level regex constraints copied from the hand-port's Field(pattern=...)
// declarations (the hand-port is the constraints inventory of record).
//
// These are NOT a constraint the generator invented, and they are NOT a
// divergence to be normalized away by weakening Python to match the bare
// `string` TS type. Both patterns are the SAME regex the TS side
// enforces at runtime — `MODEL_DIGEST_FORMAT` in
// src/models/descriptor-invariants.ts, applied by
// assertDescriptorIntegrityInvariants() on every registered descriptor and
// again in src/models/register.ts. TypeScript simply has no way to spell a
// regex-constrained string in its type system, so the invariant lives in
// the runtime guard on one side and in the Field(pattern=...) on the other.
// Python is the side that can express it; expressing it is correct.
//
// `tests/ts/codegen-python.test.ts` pins these two strings to
// MODEL_DIGEST_FORMAT.source so the two cannot drift apart silently.
const FIELD_PATTERNS: Record<string, string> = {
  'ModelDescriptor.modelDigest': '^sha256:[a-f0-9]{64}$',
  'AiBom.modelDescriptorDigest': '^sha256:[a-f0-9]{64}$',
  'StepAiBom.modelDescriptorDigest': '^sha256:[a-f0-9]{64}$',
  // SIGNOFF_DIGEST_RE in packages/engine/src/signoff-expectation.ts: a bare
  // digest (Record §9.2), 64 lowercase hex and nothing around it.
  'SignatureRequiredExpectation.policyDigest': '^[0-9a-f]{64}$',
  'SessionAttachmentExpectation.statementDigest': '^[0-9a-f]{64}$',
  // The record rules (Record §1.2 digest forms): the engine's PREFIXED_DIGEST_RE and
  // BARE_DIGEST_RE (packages/engine/src/record-rules-util.ts), its
  // FRESHNESS_REFERENCE_RE (packages/engine/src/decider.ts), whose eip155
  // and safe-integer rules the Decider.freshness validator adds, and its
  // RELATION_NAME_RE (packages/engine/src/links.ts).
  'Decider.agent': '^sha256:[0-9a-f]{64}$',
  'StepActor.agent': '^sha256:[0-9a-f]{64}$',
  'Contributions.pipeline': '^sha256:[0-9a-f]{64}$',
  'ContributionStep.output': '^sha256:[0-9a-f]{64}$',
  'ContributionStep.prev': '^sha256:[0-9a-f]{64}$',
  'Decider.credential': '^[0-9a-f]{64}$',
  'LinkTarget.digest': '^[0-9a-f]{64}$',
  'Link.rel': '^(?:[a-z][A-Za-z0-9]{0,31}|x-[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\\.[a-z][A-Za-z0-9]{0,31})$',
  'MandateExpectation.mandateAssertion': '^[0-9a-f]{64}$',
  'Decider.freshness': '^([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32})@(0|[1-9][0-9]{0,15}):(0x[0-9a-f]{64})$',
};

// Constraints the wire spec puts on a field that TypeScript's type cannot
// spell, as `Field(...)` arguments. tzun-anchor/1 §8.1 and §8.2: the anchor's
// indices and an EVM entry's block number are non-negative integers, and an
// anchor lists at least one publication. `strict=True` refuses what pydantic
// would otherwise coerce to an int (a numeric string, a float, a bool), which
// a model written back out would carry in its coerced form. The upper bound is
// the largest integer a JSON number carries exactly (2^53 − 1): the TS
// verifier takes no block number above it, and no index at or past a
// checkpoint size, which it caps there.
const SAFE_INDEX = ['strict=True', 'ge=0', 'le=9007199254740991'];
const FIELD_CONSTRAINTS: Record<string, string[]> = {
  'AnchorArtifact.leafIndex': SAFE_INDEX,
  'AnchorArtifact.anchorLeafIndex': SAFE_INDEX,
  'AnchorArtifact.publications': ['min_length=1'],
  'EvmAnchorPublication.blockNumber': SAFE_INDEX,
  // A session slot is 1-based (Record §9.2).
  'SessionAttachmentExpectation.sessionSeq': ['strict=True', 'ge=1', 'le=9007199254740991'],
  // The slot a record's `signoff` block names. Strict, so a stored "4" or
  // `true` is not read as the slot 4 or 1: the block fails to validate and
  // `AttestationArtifacts.signoff` (tolerant) keeps it as it was stored,
  // which the expectation check then compares as the TS engine does.
  'SignoffArtifact.sessionSeq': ['strict=True', 'ge=1', 'le=9007199254740991'],
  'SignoffInclusion.leafIndex': SAFE_INDEX,
  // The mandate form's slot is 1-based; its confirmation flag is JSON true or
  // false only (Record §9.2).
  'MandateExpectation.mandateSeq': ['strict=True', 'ge=1', 'le=9007199254740991'],
  'MandateExpectation.confirm': ['strict=True'],
  'LinkLocator.seq': ['strict=True', 'ge=1', 'le=9007199254740991'],
  // links.ts: a link carries 1 to 16 attributes (`{}` is written null), and a
  // capture names 1 to 256 links (`[]` is written null).
  'Link.attrs': ['min_length=1', 'max_length=16'],
  'CaptureInput.links': ['min_length=1', 'max_length=256'],
  // ai-bom.ts aiBomViolation, for a contribution step's bill of materials:
  // finite numbers, a non-negative safe-integer maxTokens, a safe-integer seed.
  'StepInferenceParameters.temperature': ['allow_inf_nan=False'],
  'StepInferenceParameters.topP': ['allow_inf_nan=False'],
  'StepInferenceParameters.maxTokens': ['ge=0', 'le=9007199254740991'],
  'StepInferenceParameters.seed': ['ge=-9007199254740991', 'le=9007199254740991'],
};

// Fields a reader must load whatever a stored envelope holds there, because
// the verifier, not the parser, decides them. The typed model is tried first
// (`union_mode="left_to_right"`), and a value it does not take is kept as it
// was read, so the envelope loads, round-trips unchanged, and the verifier
// abstains or fails on it. tzun-anchor/1 §10.1: verification never throws,
// and Anchor §10.3 step 1: an artifact under another `anchorSpec` is abstained on.
//
// `EvidencePayload.signoffExpectation`, `AttestationArtifacts.signoff` and
// `AttestationArtifacts.webauthnAssertion` are tolerant for the same reason: a
// value of neither expectation form, a sign-off block of the wrong shape, or
// an assertion that is not an object is the expectation check's to report
// (`malformed_signoff_expectation`, `statement_digest_mismatch`,
// `session_signoff_not_expected` beside an assertion that is a string, ...),
// so the record must load. A capture checks the expectation before it builds
// anything (`tzun_sdk.signoff_expectation`) and takes its assertion through
// the strict `CaptureAttestationInputs`, so a writer never produces one.
//
// The record-rule members are tolerant on the envelope models for the same
// reason: a stored decider, contributions, links, expectation or mandate
// block that does not fit its model is the verifier's to report
// (`malformed_decider`, `malformed_links`, ...), never a parse error. A writer
// validates them with their own strict models (`Decider`, `Contributions`,
// `Link`, ...) before it builds anything.
const TOLERANT_FIELDS = new Set<string>([
  'AttestationArtifacts.anchor',
  'AttestationArtifacts.signoff',
  'AttestationArtifacts.webauthnAssertion',
  'AttestationArtifacts.mandate',
  'AttestationArtifacts.mandateIssuance',
  'AttestationArtifacts.confirmation',
  'EvidencePayload.signoffExpectation',
  'EvidencePayload.decider',
  'EvidencePayload.contributions',
  'EvidencePayload.links',
]);

// Classes whose nullable members are REQUIRED keys (`X | None`, no default):
// inside a member a missing key and a `null` one serialize differently, so a
// model with `= None` would accept a missing key on input and emit `null` on
// output, turning a malformed member into a digest mismatch (Record §1.2).
// Every key of these shapes is required on the wire. A
// contribution step's bill of materials is `StepAiBom` (STRICT_TWINS), with
// its nested models. `AiBom` and its nested models (`PromptTemplate`,
// `InferenceParameters`, `Infrastructure`) are the writer-input shape, beside
// the inline-descriptor form, and stay lax: a writer fills absent nullable
// members (`fillAiBomNulls`) before it builds the step.
const REQUIRED_NULLABLE = new Set<string>([
  'Decider',
  'StepActor',
  'StepAiBom',
  'StepPromptTemplate',
  'StepInferenceParameters',
  'StepInfrastructure',
  'ContributionStep',
  'Contributions',
  'Link',
  'LinkTarget',
  'LinkLocator',
  'MandateExpectation',
  'MandateBlock',
  'MandateDocument',
  'MandatePrincipal',
  'MandateScope',
  'MandateValidity',
  'MandateLimits',
  'MandateCap',
  'MandateDelegation',
  'MandateReview',
  'MandatePredicate',
  'MandateStatement',
  'MandateEventBody',
  'AgentDescriptor',
  'AgentOperator',
  'AgentKey',
  'AgentRuntime',
]);

// Classes emitted with `ConfigDict(strict=True)`: no coercion of "3" to 3 or
// of 1 to true (Record §1.2). The record-rule member shapes, as a writer
// validates them. Strict models also refuse a JSON number written `1.0`
// where an integer is required, which TypeScript reads as the integer 1:
// they are for writers, and a reader judges a stored member with the rule
// functions, never with these models.
const STRICT_CLASSES = new Set<string>([
  'Decider',
  'StepActor',
  'StepAiBom',
  'StepPromptTemplate',
  'StepInferenceParameters',
  'StepInfrastructure',
  'ContributionStep',
  'Contributions',
  'Link',
  'LinkTarget',
  'LinkLocator',
  'MandateExpectation',
  'MandateBlock',
  'MandateDocument',
  'MandatePrincipal',
  'MandateScope',
  'MandateValidity',
  'MandateLimits',
  'MandateCap',
  'MandateDelegation',
  'MandateReview',
  'MandatePredicate',
  'MandateStatement',
  'MandateEventBody',
  'AgentDescriptor',
  'AgentOperator',
  'AgentKey',
  'AgentRuntime',
]);

// Type aliases emitted as a class of their own, with the members of the
// interface each one aliases: a strict, required-nullable twin of a lax model.
// Its inline nested objects lift under the twin's own
// LIFTED_NAMES entries, and its tables (STRICT_CLASSES, REQUIRED_NULLABLE,
// FIELD_PATTERNS, ...) are keyed by the twin's names.
const STRICT_TWINS: Record<string, string> = {
  StepAiBom: 'AiBom',
};

// Field validators: exact python lines emitted inside the class body after the
// field. A rule a Field pattern cannot spell in the Rust regex dialect pydantic
// uses (no lookahead), written with `re.fullmatch` and `re.ASCII`, never
// `re.match(...$)` (which accepts a trailing newline) or `\d`.
const VALIDATORS: Record<string, string[]> = {
  // decider.ts parseFreshnessReference: the eip155 reference has no leading
  // zero, and the block number is at most 2^53 - 1.
  'Decider.freshness': [
    '',
    '    @field_validator("freshness")',
    '    @classmethod',
    '    def _freshness_reference(cls, v: str | None) -> str | None:',
    '        if v is None:',
    '            return v',
    '        m = re.fullmatch(r"([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32})@(0|[1-9][0-9]{0,15}):0x[0-9a-f]{64}", v, re.ASCII)',
    '        if (',
    '            m is None',
    '            or (m.group(1) == "eip155" and re.fullmatch(r"[1-9][0-9]{0,30}", m.group(2), re.ASCII) is None)',
    '            or int(m.group(3)) > 9007199254740991',
    '        ):',
    '            raise ValueError("freshness must be a finalized-block reference <CAIP-2>@<block>:0x<64 hex>")',
    '        return v',
  ],
  // ai-bom.ts aiBomViolation: at most 16 stop sequences, and each stop
  // sequence and infrastructure string at most 256 UTF-16 code units.
  'StepInferenceParameters.stopSequences': [
    '',
    '    @field_validator("stopSequences")',
    '    @classmethod',
    '    def _stop_sequences(cls, v: list[str] | None) -> list[str] | None:',
    '        if v is not None and (len(v) > 16 or any(len(s.encode("utf-16-le")) // 2 > 256 for s in v)):',
    '            raise ValueError("stopSequences must be at most 16 strings of at most 256 UTF-16 code units")',
    '        return v',
  ],
  'StepInfrastructure.endpoint': [
    '',
    '    @field_validator("provider", "region", "apiVersion", "endpoint")',
    '    @classmethod',
    '    def _infrastructure_length(cls, v: str | None) -> str | None:',
    '        if v is not None and len(v.encode("utf-16-le")) // 2 > 256:',
    '            raise ValueError("an infrastructure string is at most 256 UTF-16 code units")',
    '        return v',
  ],
  // mandate/expectation.ts mandateExpectationMemberViolation: 1 to 16 caps
  // named [A-Za-z0-9._-]{1,64}, each a non-negative safe integer.
  'MandateExpectation.totals': [
    '',
    '    @field_validator("totals")',
    '    @classmethod',
    '    def _totals(cls, v: dict[str, int] | None) -> dict[str, int] | None:',
    '        if v is None:',
    '            return v',
    '        if not 1 <= len(v) <= 16 or not all(',
    '            re.fullmatch(r"[A-Za-z0-9._-]{1,64}", k, re.ASCII) and 0 <= n <= 9007199254740991',
    '            for k, n in v.items()',
    '        ):',
    '            raise ValueError("totals must be 1 to 16 caps, each a non-negative safe integer")',
    '        return v',
  ],
};

// Data-shaped types deliberately TS-only (audited, listed in the output footer).
const EXCLUDE = new Map<string, string>([
  ['Mode', 'Tzun.init() config surface — Python resolves mode via its own init kwargs'],
  ['CaptureAttestation', 'attestation-config surface — TS orchestrator-only'],
  ['AttestationConfig', 'Tzun.init() config surface — not a wire shape'],
  ['ListOptions', 'storage-adapter query options — Python adapters take kwargs'],
  ['ScannerMode', 'scanner config surface — TS monitoring subsystem only'],
  ['ScannerConfig', 'scanner config surface — TS monitoring subsystem only'],
  ['ScannerState', 'scanner runtime state — TS monitoring subsystem only'],
  ['ScanSummary', 'scanner pass summary — TS monitoring subsystem only'],
  ['WebhookNotificationConfig', 'notification config — TS monitoring subsystem only'],
  ['SlackNotificationConfig', 'notification config — TS monitoring subsystem only'],
  ['PagerDutyNotificationConfig', 'notification config — TS monitoring subsystem only'],
  ['EmailNotificationConfig', 'notification config — TS monitoring subsystem only'],
  ['NotificationConfig', 'notification config — TS monitoring subsystem only'],
  ['MonitoringNotificationConfig', 'notification config (intersection types) — TS monitoring subsystem only'],
  ['MonitoringConfig', 'Tzun.init() monitoring config — references TS-only config shapes'],
  ['AnchoringConfig', 'Tzun.init() anchoring config — configures the TS anchor scheduler; not a wire shape'],
  ['EvmPublisherConfig', 'anchoring config: the EVM publisher and its key or external signer — TS anchor scheduler only; not a wire shape'],
  ['AnchorCadence', 'anchoring config: the cadence — TS anchor scheduler only; not a wire shape'],
  ['AnchorBudget', 'anchoring config: the fee budget — TS anchor scheduler only; not a wire shape'],
  ['AnchorTransactionRequest', 'AnchorTransactionSigner.signTransaction() argument — the transaction an external signer signs; not a wire shape'],
  ['PublisherManifest', "verifier and activation-guard input: the members of a tzun-anchor/1 §9 manifest the TS verifier reads, not the whole manifest, so a forbid-extras model would refuse a real one"],
  ['PublisherManifestEntry', 'one entry of PublisherManifest — same reason'],
  ['DeduplicationEntry', 'notification dedup state — TS monitoring subsystem only'],
  // Public engine types declared OUTSIDE packages/engine/src/types/, so the
  // scan below never saw them. Listed explicitly so the public
  // surface audit can prove every exported type is a deliberate decision
  // rather than an accident of which directory it was declared in.
  ['ChainCompletenessResult', 'chain-walk result — TS verification surface; Python has no chain walker'],
  ['ChainCompletenessOptions', 'chain-walk call options — not a wire shape'],
  ['ChainEvidenceLog', 'chain-walk input: a reader over a store\'s evidence log — not a wire shape'],
  ['EvidenceLogLeaf', 'chain-walk input: one leaf that reader returns — not a wire shape'],
  ['MultiChainCompletenessResult', 'multi-chain walk result — TS verification surface'],
  ['VerifyEnvelopeOptions', 'verifyEnvelope() call options — not a wire shape'],
  ['MerkleTree', 'buildMerkleTree() result — in-memory layers a generator reads; not a wire shape (proofs travel as arrays of hex strings)'],
  ['ConsistencyProofReason', 'getConsistencyProof() / verifyConsistencyProof() refusal reason — a TS call result, not carried in any wire shape'],
  ['ConsistencyProofResult', 'getConsistencyProof() result — a TS call result, not a wire shape'],
  ['ConsistencyVerification', 'verifyConsistencyProof() result — a TS call result, not a wire shape'],
  ['CompactRange', 'compact range of a growing log — log-writer state, not carried in any wire shape'],
  ['CompactRangeExtension', 'extendCompactRange() result — log-writer output, not a wire shape'],
  ['CompactRangeProofs', 'CompactRangeProver.finish() result — an exporter\'s call result, not a wire shape (proofs travel as arrays of hex strings)'],
  ['HashedCustodyEntry', 'CustodyEntry with entryHash/prevEntryHash required — a TS type narrowing (isHashedCustodyEntry); Python reads the generated CustodyEntry and tzun_sdk.custody_hash.is_hashed_custody_entry narrows it'],
  ['CustodyEntryPreimage', 'computeCustodyEntryHash() argument shape — the keyword arguments of tzun_sdk.custody_hash.compute_custody_entry_hash, not a wire shape'],
  ['DigestComputer', 'behavioral interface (computeDigest method) — pluggable TS strategy'],
  ['IdempotencyClaim', 'storeIdempotent() options — TS storage-adapter surface; the Python adapters do not implement storeIdempotent'],
  ['IdempotencyReceipt', 'storeIdempotent() result — TS storage-adapter surface; the Python adapters do not implement storeIdempotent'],
  ['IdempotencyOutcome', 'storeIdempotent() result — TS storage-adapter surface; the Python adapters do not implement storeIdempotent'],
  ['IdempotentStoreOptions', 'storeIdempotent() options — TS storage-adapter surface; the Python adapters do not implement storeIdempotent'],
  ['IdempotencyFingerprintInput', 'captureIdempotencyFingerprint() argument shape — not a wire shape'],
  ['IdempotencyConflictReason', 'IdempotencyConflictError field — a TS error surface, not a wire shape'],
  ['RecordVerdictInput', 'recordVerdict() argument shape — the rows and predecessor a reader fetched, not a wire shape'],
  ['AttestationExpectation', 'determineAttestationStatus() / missingAttestationComponents() argument — which components a writer is configured to obtain; writer configuration, not a wire shape'],
  ['ObtainableAttestationComponent', 'missingAttestationComponents() result element — names a component the writer can still obtain; not carried in any wire shape'],
  ['RetryObtainableComponent', 'AttestationConfig.deferrable element and StorageAdapter.listByMissingObtainable() argument — a component the TS pending-attestation retry obtains; writer configuration, not a wire shape'],
  ['AssertionProvenanceOptions', 'assertionProvenance() call options — what the caller requires and whether it verified the signature; the keyword arguments of tzun_sdk.attestation.assertion_provenance, not a wire shape'],
  ['AssertionBindingFailure', 'return type of assertionBindingFailure() — a strict subset of the generated AttestationSignatureReason, and Python reports the binding as a bool from tzun_sdk.attestation.assertion_binds_digest. Not a wire shape'],
  ['AssembleEnvelopeOptions', 'assembleEnvelope() / buildEvidencePayload() options — writer call arguments, not a wire shape'],
  ['EnvelopeInputRule', 'EnvelopeInputError field — a TS error surface, not a wire shape'],
  ['SystemRecordKind', 'payloadRecordRuleViolation() / assembleEnvelope() option — call arguments, not a wire shape'],
  ['PayloadRecordRuleOptions', 'payloadRecordRuleViolation() options — writer call arguments, not a wire shape'],
  ['RecordRuleViolation', 'payloadRecordRuleViolation() result — a TS call result (EnvelopeInputError carries the same rule, code and field); Python raises its own errors with .code and .field. Not a wire shape'],
  ['ContributionsContext', 'contributionsViolation() / buildContributions() argument — the record members the rules read, not a wire shape'],
  ['DeciderMaterial', 'deciderMaterialViolation() argument — what a capture presents beside its decider, not a wire shape'],
  ['MandateDocumentOptions', 'mandateDocumentViolation() options — not a wire shape'],
  ['AssertionDigestFailure', 'assertionDigestResult() refusal reason — a TS call result, not carried in any wire shape'],
  ['AssertionDigestResult', 'assertionDigestResult() result — a TS call result, not a wire shape'],
  ['PointerResolution', 'resolvePointer() result — a TS call result, not a wire shape'],
  ['BuildLinksOptions', 'buildLinks() options — writer call arguments, not a wire shape'],
  ['LinksContext', 'linksViolation() / buildLinks() argument — the record members the rules read, not a wire shape'],
  ['LinkTargetRuleResult', 'checkLinkTarget() result — a TS call result, not a wire shape'],
  ['LinkTargetResolver', 'checkLinks() / verifyEnvelope() lookups — an interface of functions a store-level verifier supplies, not a wire shape'],
  ['HeldLinkTarget', 'a LinkTargetResolver / buildLinks() argument — a record the caller holds, not a wire shape'],
  ['LinkRelationProfile', 'LINK_RELATIONS entry — the relation registry as the engine holds it; Python keeps its own registry table'],
  ['MandateClaimPlan', 'planMandateClaim() result — a TS call result (a union of ok and refused), not a wire shape'],
  ['EarlierFieldSet', 'earlierFieldSet() result — the fieldSet fact, typed inline on VerificationResult.fieldSet'],
  ['RecordFieldSetGeneration', 'recordFieldSetGeneration() result — a TS call result; Python returns the same strings from record_field_set_generation'],
]);

// Self-check floor: the union of emitted classes + hand-retained classes
// must cover the hand-port inventory. Copied verbatim from the hand-port's
// __all__ (28 entries), plus `ModifiedLink` — a hand-port CLASS that the
// hand-port's __all__ currently omits (reviewer-confirmed correction).
const HAND_PORT_INVENTORY: string[] = [
  'AiBom',
  'AiBomWithInlineDescriptor',
  'AnnotationRecord',
  'AttestationArtifacts',
  'CaptureResult',
  'CustodyAction',
  'CustodyEntry',
  'DecisionInput',
  'Evaluation',
  'EvidenceEnvelope',
  'EvidencePayload',
  'ExternalIdentifier',
  'FailureRecord',
  'ForkRecord',
  'InferenceParameters',
  'Infrastructure',
  'IntegrityBlock',
  'ModelDescriptor',
  'ModifiedLink',
  'PromptTemplate',
  'RegulatoryMarking',
  'RelinkRecord',
  'Rfc3161Metadata',
  'SignerIdentity',
  'TamperIncident',
  'TrainingInfo',
  'VerificationResult',
  'WebauthnAssertion',
];
const HAND_RETAINED = new Set(['DecisionInput']); // TS source src/sdk/wrappers.ts — outside the scan

// Python reserved words that cannot be field names; emitted as `<name>_` with
// Field(alias=...) + populate_by_name (mechanical encoding, wire keys unchanged).
const PY_KEYWORDS = new Set([
  'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break',
  'class', 'continue', 'def', 'del', 'elif', 'else', 'except', 'finally',
  'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda', 'nonlocal',
  'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield',
]);

// ── JSDoc tag reader ─────────────────────────────────────────────────
function readJsdocTag(node: ts.Node, tagName: string): string | null {
  const tags = ts.getJSDocTags(node);
  for (const tag of tags) {
    if (tag.tagName.text === tagName) {
      if (typeof tag.comment === 'string') return tag.comment;
      if (Array.isArray(tag.comment)) {
        return tag.comment.map((c) => c.text).join('');
      }
    }
  }
  return null;
}

/** True when `@tagName` is on the node at all — `readJsdocTag` answers null for a bare tag with no text. */
function hasJsdocTag(node: ts.Node, tagName: string): boolean {
  return ts.getJSDocTags(node).some((tag) => tag.tagName.text === tagName);
}

// ── Emission ─────────────────────────────────────────────────────────

type DefKind = 'class' | 'alias';

interface PyDef {
  name: string;
  kind: DefKind;
  /** Full rendered source lines for this definition (no trailing blank lines). */
  lines: string[];
  /** Names of other emitted definitions this one needs defined BEFORE it. */
  deps: string[];
  sourceFile: string;
}

interface Registry {
  /** name → exported declaration, across all nine files. */
  decls: Map<string, ts.InterfaceDeclaration | ts.TypeAliasDeclaration>;
  program: ts.Program;
  checker: ts.TypeChecker;
}

interface PyType {
  py: string;
  nullable: boolean;
  deps: string[];
}

function isExported(node: ts.Declaration): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
}

function containsFunctionType(node: ts.Node): boolean {
  if (ts.isFunctionTypeNode(node) || ts.isConstructorTypeNode(node)) return true;
  let found = false;
  node.forEachChild((child) => {
    if (!found && containsFunctionType(child)) found = true;
  });
  return found;
}

function hasBehavioralMembers(iface: ts.InterfaceDeclaration): boolean {
  return iface.members.some((m) => {
    if (ts.isMethodSignature(m) || ts.isCallSignatureDeclaration(m)) return true;
    if (ts.isPropertySignature(m) && m.type && containsFunctionType(m.type)) return true;
    return false;
  });
}

function propName(m: ts.PropertySignature): string {
  if (ts.isIdentifier(m.name) || ts.isStringLiteral(m.name)) return m.name.text;
  throw new Error(`Unsupported property-name kind ${ts.SyntaxKind[m.name.kind]}`);
}

function pyStr(s: string): string {
  return JSON.stringify(s); // double-quoted, escapes — matches hand-port style
}

class Emitter {
  defs = new Map<string, PyDef>();
  excludedBehavioral: string[] = [];
  /** Set when any class emitted an `@tzun-omit-when-unset` serializer (drives the pydantic import line). */
  needsModelSerializer = false;
  /** Set when any class emitted a VALIDATORS entry (drives the `re` and `field_validator` imports). */
  needsValidators = false;

  constructor(private reg: Registry) {}

  // ── typeToPy ───────────────────────────────────────────────────────
  typeToPy(typeNode: ts.TypeNode, ownerKey: string, sourceFile: string): PyType {
    // Parenthesized → unwrap
    if (ts.isParenthesizedTypeNode(typeNode)) {
      return this.typeToPy(typeNode.type, ownerKey, sourceFile);
    }
    switch (typeNode.kind) {
      case ts.SyntaxKind.StringKeyword:
        return { py: 'str', nullable: false, deps: [] };
      case ts.SyntaxKind.NumberKeyword: {
        const py = NUMBER_AS_INT.has(ownerKey)
          ? 'int'
          : NUMBER_AS_FLOAT.has(ownerKey)
            ? 'float'
            : 'int | float';
        return { py, nullable: false, deps: [] };
      }
      case ts.SyntaxKind.BooleanKeyword:
        return { py: 'bool', nullable: false, deps: [] };
      case ts.SyntaxKind.UnknownKeyword:
      case ts.SyntaxKind.AnyKeyword:
        return { py: 'Any', nullable: false, deps: [] };
      case ts.SyntaxKind.UndefinedKeyword:
        return { py: '', nullable: true, deps: [] };
    }
    if (ts.isLiteralTypeNode(typeNode)) {
      const lit = typeNode.literal;
      if (lit.kind === ts.SyntaxKind.NullKeyword) return { py: '', nullable: true, deps: [] };
      if (ts.isStringLiteral(lit)) return { py: `Literal[${pyStr(lit.text)}]`, nullable: false, deps: [] };
      if (lit.kind === ts.SyntaxKind.TrueKeyword) return { py: 'Literal[True]', nullable: false, deps: [] };
      if (lit.kind === ts.SyntaxKind.FalseKeyword) return { py: 'Literal[False]', nullable: false, deps: [] };
      throw new Error(`Unmapped literal type at ${ownerKey}: ${ts.SyntaxKind[lit.kind]}`);
    }
    if (ts.isUnionTypeNode(typeNode)) {
      return this.unionToPy(typeNode.types, ownerKey, sourceFile);
    }
    if (ts.isArrayTypeNode(typeNode)) {
      const inner = this.typeToPy(typeNode.elementType, ownerKey, sourceFile);
      const innerPy = inner.nullable && inner.py ? `${inner.py} | None` : inner.py || 'None';
      return { py: `list[${innerPy}]`, nullable: false, deps: inner.deps };
    }
    if (ts.isTupleTypeNode(typeNode)) {
      const parts = typeNode.elements.map((el) => {
        const t = this.typeToPy(el, ownerKey, sourceFile);
        return t.nullable && t.py ? `${t.py} | None` : t.py || 'None';
      });
      return { py: `tuple[${parts.join(', ')}]`, nullable: false, deps: [] };
    }
    if (ts.isTypeReferenceNode(typeNode)) {
      const refName = ts.isIdentifier(typeNode.typeName)
        ? typeNode.typeName.text
        : typeNode.typeName.getText();
      if (refName === 'Array' && typeNode.typeArguments?.length === 1) {
        const inner = this.typeToPy(typeNode.typeArguments[0], ownerKey, sourceFile);
        const innerPy = inner.nullable && inner.py ? `${inner.py} | None` : inner.py || 'None';
        return { py: `list[${innerPy}]`, nullable: false, deps: inner.deps };
      }
      if (refName === 'Record' && typeNode.typeArguments?.length === 2) {
        const k = this.typeToPy(typeNode.typeArguments[0], ownerKey, sourceFile);
        const v = this.typeToPy(typeNode.typeArguments[1], ownerKey, sourceFile);
        const vPy = v.nullable && v.py ? `${v.py} | None` : v.py || 'None';
        return { py: `dict[${k.py}, ${vPy}]`, nullable: false, deps: [...k.deps, ...v.deps] };
      }
      // Plain reference to another scanned type. Emitted UNQUOTED: the
      // combination of `from __future__ import annotations` (all annotations
      // lazy) + topological definition order is the forward-ref mechanism —
      // quoting individual union members (`"X" | None`) is a runtime
      // TypeError when pydantic evaluates the annotation.
      if (!this.reg.decls.has(refName)) {
        throw new Error(`Unmapped type reference "${refName}" at ${ownerKey} (not an exported engine type)`);
      }
      if (EXCLUDE.has(refName)) {
        throw new Error(`Type reference "${refName}" at ${ownerKey} points at an EXCLUDE'd type — un-exclude it or exclude the referrer`);
      }
      this.emitDecl(refName); // ensure target is emitted
      return { py: refName, nullable: false, deps: [refName] };
    }
    if (ts.isIndexedAccessTypeNode(typeNode)) {
      // e.g. AiBom['promptTemplate'] — resolve via the referenced declaration's member.
      const obj = typeNode.objectType;
      const idx = typeNode.indexType;
      if (
        ts.isTypeReferenceNode(obj) && ts.isIdentifier(obj.typeName) &&
        ts.isLiteralTypeNode(idx) && ts.isStringLiteral(idx.literal)
      ) {
        const targetName = obj.typeName.text;
        const memberName = idx.literal.text;
        const decl = this.reg.decls.get(targetName);
        if (!decl || !ts.isInterfaceDeclaration(decl)) {
          throw new Error(`Indexed access ${targetName}[${pyStr(memberName)}] at ${ownerKey}: target is not a scanned interface`);
        }
        const member = decl.members.find(
          (m): m is ts.PropertySignature => ts.isPropertySignature(m) && propName(m) === memberName,
        );
        if (!member || !member.type) {
          throw new Error(`Indexed access ${targetName}[${pyStr(memberName)}] at ${ownerKey}: member not found`);
        }
        const t = this.typeToPy(member.type, `${targetName}.${memberName}`, sourceFile);
        // `?:` optionality on the source member does not transfer; the caller's
        // own optionality applies. Nullability of the member type DOES transfer.
        return t;
      }
      throw new Error(`Unmapped indexed-access type at ${ownerKey}`);
    }
    if (ts.isImportTypeNode(typeNode)) {
      // import('./evidence').EvidenceEnvelope → reference by qualifier name.
      const q = typeNode.qualifier;
      if (q && ts.isIdentifier(q)) {
        if (!this.reg.decls.has(q.text)) {
          throw new Error(`Unmapped import-type reference "${q.text}" at ${ownerKey}`);
        }
        this.emitDecl(q.text);
        return { py: q.text, nullable: false, deps: [q.text] };
      }
      throw new Error(`Unmapped import type at ${ownerKey}`);
    }
    if (ts.isTypeLiteralNode(typeNode)) {
      // Index-signature-only literal → dict.
      const indexSigs = typeNode.members.filter(ts.isIndexSignatureDeclaration);
      if (indexSigs.length === 1 && typeNode.members.length === 1) {
        const sig = indexSigs[0];
        const keyT = this.typeToPy(sig.parameters[0].type as ts.TypeNode, ownerKey, sourceFile);
        const valT = this.typeToPy(sig.type, ownerKey, sourceFile);
        const vPy = valT.nullable && valT.py ? `${valT.py} | None` : valT.py || 'None';
        return { py: `dict[${keyT.py}, ${vPy}]`, nullable: false, deps: [...keyT.deps, ...valT.deps] };
      }
      // Inline anonymous object → lift to a pinned name.
      const lifted = LIFTED_NAMES[ownerKey];
      if (!lifted) {
        throw new Error(
          `fail-on-unmapped: inline object type at "${ownerKey}" has no LIFTED_NAMES entry`,
        );
      }
      this.emitClassFromMembers(lifted, typeNode.members, sourceFile);
      return { py: lifted, nullable: false, deps: [lifted] };
    }
    throw new Error(`Unmapped TS construct ${ts.SyntaxKind[typeNode.kind]} at ${ownerKey} (fail-don't-guess)`);
  }

  unionToPy(parts: readonly ts.TypeNode[], ownerKey: string, sourceFile: string): PyType {
    let nullable = false;
    let sawPlainString = false;
    const stringLits: string[] = [];
    const boolLits: string[] = [];
    const others: PyType[] = [];
    for (const part of parts) {
      const unwrapped = ts.isParenthesizedTypeNode(part) ? part.type : part;
      if (
        unwrapped.kind === ts.SyntaxKind.UndefinedKeyword ||
        (ts.isLiteralTypeNode(unwrapped) && unwrapped.literal.kind === ts.SyntaxKind.NullKeyword)
      ) {
        nullable = true;
        continue;
      }
      if (ts.isLiteralTypeNode(unwrapped) && ts.isStringLiteral(unwrapped.literal)) {
        stringLits.push(unwrapped.literal.text);
        continue;
      }
      if (
        ts.isLiteralTypeNode(unwrapped) &&
        (unwrapped.literal.kind === ts.SyntaxKind.TrueKeyword ||
          unwrapped.literal.kind === ts.SyntaxKind.FalseKeyword)
      ) {
        boolLits.push(unwrapped.literal.kind === ts.SyntaxKind.TrueKeyword ? 'True' : 'False');
        continue;
      }
      if (unwrapped.kind === ts.SyntaxKind.StringKeyword) {
        sawPlainString = true;
        continue;
      }
      others.push(this.typeToPy(unwrapped, ownerKey, sourceFile));
    }
    const pieces: string[] = [];
    const deps: string[] = [];
    if (sawPlainString) {
      // literal-union ∪ string collapses to str (e.g. FailureType).
      pieces.push('str');
    } else if (stringLits.length > 0 || boolLits.length > 0) {
      const lits = [...stringLits.map(pyStr), ...boolLits];
      pieces.push(`Literal[${lits.join(', ')}]`);
    }
    for (const o of others) {
      if (o.nullable) nullable = true;
      if (o.py) pieces.push(o.py);
      deps.push(...o.deps);
    }
    if (pieces.length === 0) return { py: '', nullable, deps };
    return { py: pieces.join(' | '), nullable, deps };
  }

  // ── class emission ─────────────────────────────────────────────────
  emitClassFromMembers(pyName: string, members: readonly ts.TypeElement[], sourceFile: string): void {
    const fieldLines: string[] = [];
    const deps: string[] = [];
    let needsPopulateByName = false;
    const omitWhenUnset: string[] = [];

    for (const m of members) {
      if (!ts.isPropertySignature(m)) {
        throw new Error(`Non-property member in ${pyName} (kind ${ts.SyntaxKind[m.kind]}) — behavioral members must be pre-filtered`);
      }
      if (!m.type) throw new Error(`Untyped property ${pyName}.${propName(m)}`);
      const name = propName(m);
      const ownerKey = `${pyName}.${name}`;
      const t = this.typeToPy(m.type, ownerKey, sourceFile);
      deps.push(...t.deps);
      const optional = Boolean(m.questionToken) || t.nullable;
      // A required-nullable member is `X | None` with no default: the key is
      // required, its value may be null.
      const requiredNullable = REQUIRED_NULLABLE.has(pyName) && !m.questionToken && t.nullable;
      if (hasJsdocTag(m, OMIT_WHEN_UNSET_TAG)) {
        if (!m.questionToken) {
          throw new Error(`${ownerKey}: @${OMIT_WHEN_UNSET_TAG} is only legal on an optional (\`?:\`) property — a required key is always on the wire`);
        }
        if (PY_KEYWORDS.has(name)) {
          throw new Error(`${ownerKey}: @${OMIT_WHEN_UNSET_TAG} on a Python-keyword field name is unsupported (the serializer keys on the wire name)`);
        }
        omitWhenUnset.push(name);
      }
      let pyType = t.py || 'None';
      const tolerant = TOLERANT_FIELDS.has(ownerKey);
      if (tolerant) {
        if (!optional) throw new Error(`${ownerKey}: a tolerant field must be optional`);
        pyType = `${t.py} | Any`;
      }
      if (optional && t.py) pyType = `${pyType} | None`; // collapse double-optional

      let fieldName = name;
      const fieldArgs: string[] = [];
      if (PY_KEYWORDS.has(name)) {
        fieldName = `${name}_`;
        fieldArgs.push(`alias=${pyStr(name)}`);
        needsPopulateByName = true;
      }
      const pattern = FIELD_PATTERNS[ownerKey];
      const pinnedDefault = FIELD_DEFAULTS[ownerKey];
      const constraints = FIELD_CONSTRAINTS[ownerKey];
      if (pinnedDefault !== undefined && pattern !== undefined) {
        throw new Error(`${ownerKey}: FIELD_DEFAULTS and FIELD_PATTERNS overlap — fold the default into the pattern emission instead`);
      }
      if ((constraints !== undefined || tolerant) && (pinnedDefault !== undefined || pattern !== undefined)) {
        throw new Error(`${ownerKey}: FIELD_CONSTRAINTS or TOLERANT_FIELDS with a pinned default or a pattern is unsupported`);
      }
      if (constraints !== undefined) fieldArgs.push(...constraints);
      if (tolerant) fieldArgs.push('union_mode="left_to_right"');
      let line: string;
      if (requiredNullable && pinnedDefault !== undefined) {
        throw new Error(`${ownerKey}: REQUIRED_NULLABLE with a pinned default is unsupported`);
      }
      if (pattern !== undefined) {
        if (optional && !requiredNullable) fieldArgs.push('default=None');
        fieldArgs.push(`pattern=r"${pattern}"`);
        line = `    ${fieldName}: ${pyType} = Field(${fieldArgs.join(', ')})`;
      } else if (requiredNullable) {
        line = fieldArgs.length > 0
          ? `    ${fieldName}: ${pyType} = Field(${fieldArgs.join(', ')})`
          : `    ${fieldName}: ${pyType}`;
      } else if (pinnedDefault !== undefined) {
        if (fieldArgs.length > 0) {
          throw new Error(`${ownerKey}: pinned default on an aliased keyword field is unsupported`);
        }
        line = `    ${fieldName}: ${pyType} = ${pinnedDefault}`;
        const factoryRef = /default_factory=([A-Za-z_][A-Za-z0-9_]*)/.exec(pinnedDefault);
        if (factoryRef && this.reg.decls.has(factoryRef[1])) {
          this.emitDecl(factoryRef[1]);
          deps.push(factoryRef[1]);
        }
      } else if (optional) {
        if (fieldArgs.length > 0) {
          fieldArgs.unshift('default=None');
          line = `    ${fieldName}: ${pyType} = Field(${fieldArgs.join(', ')})`;
        } else {
          line = `    ${fieldName}: ${pyType} = None`;
        }
      } else if (fieldArgs.length > 0) {
        line = `    ${fieldName}: ${pyType} = Field(${fieldArgs.join(', ')})`;
      } else {
        line = `    ${fieldName}: ${pyType}`;
      }
      fieldLines.push(line);
      const validatorLines = VALIDATORS[ownerKey];
      if (validatorLines) {
        fieldLines.push(...validatorLines);
        this.needsValidators = true;
      }
    }

    const lines: string[] = [`class ${pyName}(_Forbid):`];
    lines.push(`    """Generated from packages/engine/src/types/${sourceFile}."""`);
    lines.push('');
    if (needsPopulateByName && STRICT_CLASSES.has(pyName)) {
      throw new Error(`${pyName}: a strict class with a Python-keyword field name is unsupported`);
    }
    if (needsPopulateByName) {
      lines.push('    # Python-keyword field names are emitted as `<name>_` with a wire alias;');
      lines.push('    # populate_by_name keeps attribute-name construction working too.');
      lines.push('    model_config = ConfigDict(extra="forbid", populate_by_name=True)');
      lines.push('');
    } else if (STRICT_CLASSES.has(pyName)) {
      lines.push('    # Strict: no coercion ("3" is not 3, 1 is not true).');
      lines.push('    model_config = ConfigDict(extra="forbid", strict=True)');
      lines.push('');
    }
    if (fieldLines.length === 0) lines.push('    pass');
    else lines.push(...fieldLines);
    if (omitWhenUnset.length > 0) {
      this.needsModelSerializer = true;
      const keys = omitWhenUnset.map(pyStr).join(', ');
      lines.push('');
      lines.push(`    # @${OMIT_WHEN_UNSET_TAG}: these TS \`?:\` properties have no wire key when`);
      lines.push('    # undefined (JSON.stringify drops them), and the platform capture endpoint');
      lines.push('    # refuses unknown keys even when null. Drop the key unless it was set;');
      lines.push('    # an explicit null round-trips.');
      lines.push('    @model_serializer(mode="wrap")');
      lines.push('    def _omit_when_unset(self, handler: SerializerFunctionWrapHandler) -> Any:');
      lines.push('        data = handler(self)');
      lines.push('        if isinstance(data, dict):');
      lines.push(`            for key in (${keys},):`);
      lines.push('                if key not in self.model_fields_set:');
      lines.push('                    data.pop(key, None)');
      lines.push('        return data');
    }

    this.registerDef({ name: pyName, kind: 'class', lines, deps: dedupe(deps), sourceFile });
  }

  registerDef(def: PyDef): void {
    const existing = this.defs.get(def.name);
    if (existing) {
      if (existing.lines.join('\n') !== def.lines.join('\n')) {
        throw new Error(
          `Conflicting bodies for generated name "${def.name}" — two different shapes mapped to the same lifted/declared name`,
        );
      }
      return; // identical dedupe
    }
    this.defs.set(def.name, def);
  }

  // ── declarations ───────────────────────────────────────────────────
  private inProgress = new Set<string>();

  emitDecl(name: string): void {
    if (this.defs.has(name) || EXCLUDE.has(name)) return;
    if (this.inProgress.has(name)) return; // field-ref cycles are fine (quoted forward refs)
    const decl = this.reg.decls.get(name);
    if (!decl) throw new Error(`emitDecl: "${name}" is not a scanned exported declaration`);
    this.inProgress.add(name);
    try {
      const sf = basename(decl.getSourceFile().fileName);
      if (ts.isInterfaceDeclaration(decl)) {
        if (hasBehavioralMembers(decl)) {
          if (!this.excludedBehavioral.includes(name)) this.excludedBehavioral.push(name);
          throw new Error(`emitDecl: "${name}" is behavioral and cannot be referenced by an emitted type`);
        }
        this.emitClassFromMembers(name, decl.members, sf);
      } else {
        this.emitTypeAlias(decl, sf);
      }
    } finally {
      this.inProgress.delete(name);
    }
  }

  emitTypeAlias(decl: ts.TypeAliasDeclaration, sourceFile: string): void {
    const name = decl.name.text;
    const t = decl.type;
    if (ts.isFunctionTypeNode(t)) {
      // behavioral alias — auto-excluded, recorded in the footer
      if (!this.excludedBehavioral.includes(name)) this.excludedBehavioral.push(name);
      return;
    }
    if (ts.isTypeLiteralNode(t)) {
      this.emitClassFromMembers(name, t.members, sourceFile);
      return;
    }
    if (ts.isUnionTypeNode(t)) {
      const allStringLits = t.types.every(
        (p) => ts.isLiteralTypeNode(p) && ts.isStringLiteral(p.literal),
      );
      if (allStringLits) {
        const lits = t.types.map((p) =>
          pyStr(((p as ts.LiteralTypeNode).literal as ts.StringLiteral).text),
        );
        this.registerDef({
          name, kind: 'alias', deps: [], sourceFile,
          lines: [`${name} = Literal[${lits.join(', ')}]`],
        });
        return;
      }
      const hasInlineLiteralBranch = t.types.some((p) => ts.isTypeLiteralNode(p));
      if (hasInlineLiteralBranch) {
        // Union of inline object shapes → lift each branch via `${name}.${i}` keys.
        const branchNames: string[] = [];
        t.types.forEach((p, i) => {
          if (!ts.isTypeLiteralNode(p)) {
            throw new Error(`Alias ${name}: mixed inline/non-inline union branches are unmapped`);
          }
          const key = `${name}.${i}`;
          const lifted = LIFTED_NAMES[key];
          if (!lifted) throw new Error(`fail-on-unmapped: union branch "${key}" has no LIFTED_NAMES entry`);
          this.emitClassFromMembers(lifted, p.members, sourceFile);
          branchNames.push(lifted);
        });
        this.registerDef({
          name, kind: 'alias', deps: branchNames, sourceFile,
          lines: [`${name} = ${branchNames.join(' | ')}`],
        });
        return;
      }
      // Union of named type references (e.g. MonitoringEvent) → module-level
      // alias with UNQUOTED names (runtime-evaluated, topo-ordered).
      const refParts = t.types.map((p) => (ts.isParenthesizedTypeNode(p) ? p.type : p));
      const allRefs = refParts.every((p) => ts.isTypeReferenceNode(p) && ts.isIdentifier(p.typeName));
      if (allRefs) {
        const refNames = refParts.map((p) => ((p as ts.TypeReferenceNode).typeName as ts.Identifier).text);
        for (const rn of refNames) {
          if (!this.reg.decls.has(rn)) throw new Error(`Alias ${name}: union member "${rn}" is not a scanned type`);
          this.emitDecl(rn);
        }
        this.registerDef({
          name, kind: 'alias', deps: dedupe(refNames), sourceFile,
          lines: [`${name} = ${refNames.join(' | ')}`],
        });
        return;
      }
      // String literals ∪ named type references (e.g. EvmFinality) → a
      // module-level alias `Literal[...] | Name`, the names emitted first.
      const isStringLit = (p: ts.TypeNode): p is ts.LiteralTypeNode =>
        ts.isLiteralTypeNode(p) && ts.isStringLiteral(p.literal);
      const isNamedRef = (p: ts.TypeNode): p is ts.TypeReferenceNode =>
        ts.isTypeReferenceNode(p) && ts.isIdentifier(p.typeName);
      if (refParts.some(isStringLit) && refParts.some(isNamedRef) && refParts.every((p) => isStringLit(p) || isNamedRef(p))) {
        const lits = refParts.filter(isStringLit).map((p) => pyStr((p.literal as ts.StringLiteral).text));
        const refNames = refParts.filter(isNamedRef).map((p) => (p.typeName as ts.Identifier).text);
        for (const rn of refNames) {
          if (!this.reg.decls.has(rn)) throw new Error(`Alias ${name}: union member "${rn}" is not a scanned type`);
          this.emitDecl(rn);
        }
        this.registerDef({
          name, kind: 'alias', deps: dedupe(refNames), sourceFile,
          lines: [`${name} = Literal[${lits.join(', ')}] | ${refNames.join(' | ')}`],
        });
        return;
      }
      // Literal-union ∪ plain string collapses to str (e.g. FailureType).
      const collapsible = refParts.every(
        (p) =>
          p.kind === ts.SyntaxKind.StringKeyword ||
          (ts.isLiteralTypeNode(p) && ts.isStringLiteral(p.literal)),
      );
      const sawString = refParts.some((p) => p.kind === ts.SyntaxKind.StringKeyword);
      if (collapsible && sawString) {
        this.registerDef({ name, kind: 'alias', deps: [], sourceFile, lines: [`${name} = str`] });
        return;
      }
      throw new Error(`Unmapped union-alias construct for "${name}" (fail-don't-guess)`);
    }
    if (ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName) && STRICT_TWINS[name] !== undefined) {
      if (STRICT_TWINS[name] !== t.typeName.text) {
        throw new Error(`Alias ${name}: STRICT_TWINS names ${STRICT_TWINS[name]}, the alias names ${t.typeName.text}`);
      }
      const target = this.reg.decls.get(t.typeName.text);
      if (!target || !ts.isInterfaceDeclaration(target)) {
        throw new Error(`Alias ${name}: its STRICT_TWINS target ${t.typeName.text} is not a scanned interface`);
      }
      this.emitClassFromMembers(name, target.members, sourceFile);
      return;
    }
    if (ts.isTypeReferenceNode(t) && ts.isIdentifier(t.typeName) && t.typeName.text === 'Extract') {
      // Conditional-type alias (e.g. VerifierTamperIncident). Resolve via the
      // checker to its constituent named union members — deterministic for a
      // pinned compiler version.
      const resolved = this.reg.checker.getTypeFromTypeNode(t);
      if (!resolved.isUnion()) throw new Error(`Alias ${name}: Extract<> did not resolve to a union`);
      const memberNames = resolved.types.map((m) => {
        const sym = m.aliasSymbol ?? m.symbol;
        if (!sym) throw new Error(`Alias ${name}: anonymous Extract<> constituent`);
        return sym.name;
      });
      for (const mn of memberNames) {
        if (!this.reg.decls.has(mn)) throw new Error(`Alias ${name}: constituent "${mn}" is not a scanned type`);
        this.emitDecl(mn);
      }
      this.registerDef({
        name, kind: 'alias', deps: memberNames, sourceFile,
        lines: [`${name} = ${memberNames.join(' | ')}`],
      });
      return;
    }
    // Single-keyword alias (none today) or anything else → fail-don't-guess.
    if (t.kind === ts.SyntaxKind.StringKeyword) {
      this.registerDef({ name, kind: 'alias', deps: [], sourceFile, lines: [`${name} = str`] });
      return;
    }
    throw new Error(`Unmapped type-alias construct ${ts.SyntaxKind[t.kind]} for "${name}" (fail-don't-guess)`);
  }
}

function dedupe(arr: string[]): string[] {
  return [...new Set(arr)];
}

// ── self-check ─────────────────────────────────────────────
function selfCheck(defs: Map<string, PyDef>): void {
  for (const name of HAND_PORT_INVENTORY) {
    if (!HAND_RETAINED.has(name) && !defs.has(name)) {
      throw new Error(`inventory self-check failed: ${name}`);
    }
  }
}

// ── rendering ────────────────────────────────────────────────────────
function topoSort(defs: Map<string, PyDef>): PyDef[] {
  const sorted: PyDef[] = [];
  const state = new Map<string, 'visiting' | 'done'>();
  const names = [...defs.keys()].sort();
  const visit = (name: string, chain: string[]): void => {
    const st = state.get(name);
    if (st === 'done') return;
    if (st === 'visiting') {
      // Cycles among field refs are tolerated by quoted forward refs at the
      // pydantic level, but default_factory/alias deps must be acyclic. The
      // engine type graph is acyclic today; treat a cycle as fatal so a future
      // one is surfaced rather than silently mis-ordered.
      throw new Error(`Dependency cycle in generated types: ${[...chain, name].join(' → ')}`);
    }
    state.set(name, 'visiting');
    const def = defs.get(name);
    if (!def) throw new Error(`topoSort: missing def "${name}"`);
    for (const dep of [...def.deps].sort()) {
      if (dep !== name && defs.has(dep)) visit(dep, [...chain, name]);
    }
    state.set(name, 'done');
    sorted.push(def);
  };
  for (const n of names) visit(n, []);
  return sorted;
}

function makeHeader(stamp: boolean): string {
  const lines = [
    '# AUTOGENERATED by scripts/codegen-python.ts. DO NOT EDIT.',
    '# Source: packages/engine/src/types/*.ts',
    '# Regenerate: pnpm run codegen:python',
  ];
  if (stamp) {
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf-8' })
      .trim()
      .slice(0, 12);
    lines.push(`# Source commit: ${sha}`);
  }
  return lines.join('\n');
}

function render(emitter: Emitter, stamp: boolean): string {
  const ordered = topoSort(emitter.defs);
  const out: string[] = [];
  out.push(makeHeader(stamp));
  out.push('"""Pydantic v2 wire models generated from the engine TypeScript types.');
  out.push('');
  out.push('Every class enforces ``extra="forbid"`` so unknown fields raise');
  out.push('``ValidationError`` early — load-bearing for catching wire-format drift.');
  out.push('"""');
  out.push('from __future__ import annotations');
  out.push('');
  if (emitter.needsValidators) out.push('import re');
  out.push('from typing import Any, Literal');
  out.push('');
  const pydanticNames = ['BaseModel', 'ConfigDict', 'Field'];
  if (emitter.needsModelSerializer) pydanticNames.push('SerializerFunctionWrapHandler');
  if (emitter.needsValidators) pydanticNames.push('field_validator');
  if (emitter.needsModelSerializer) pydanticNames.push('model_serializer');
  // ruff's isort wraps an import past the line length (python/pyproject.toml: 100).
  const pydanticImport = `from pydantic import ${pydanticNames.join(', ')}`;
  if (pydanticImport.length <= 100) {
    out.push(pydanticImport);
  } else {
    out.push('from pydantic import (');
    for (const n of pydanticNames) out.push(`    ${n},`);
    out.push(')');
  }
  out.push('');
  out.push('');
  out.push('class _Forbid(BaseModel):');
  out.push('    model_config = ConfigDict(extra="forbid")');
  for (const def of ordered) {
    out.push('');
    out.push('');
    out.push(...def.lines);
  }
  out.push('');
  out.push('');
  const allNames = [...emitter.defs.keys()].sort();
  out.push('__all__ = (');
  for (const n of allNames) out.push(`    ${pyStr(n)},`);
  out.push(')');
  out.push('');
  out.push('# ── Exclusion audit ─────────────────────────────────────────');
  out.push('# Auto-excluded behavioral interfaces/aliases (method, call-signature, or');
  out.push('# function-typed members — never data shapes):');
  for (const n of [...emitter.excludedBehavioral].sort()) {
    out.push(`#   - ${n}`);
  }
  out.push('# Explicitly excluded data-shaped types (deliberately TS-only):');
  for (const [n, reason] of [...EXCLUDE.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    out.push(`#   - ${n}: ${reason}`);
  }
  out.push('');
  return out.join('\n');
}

// ── discovery + main ─────────────────────────────────────────────────
function buildRegistry(): Registry {
  if (!existsSync(TS_TYPES_DIR)) {
    throw new Error(`Engine types dir missing: ${TS_TYPES_DIR}`);
  }
  const files = readdirSync(TS_TYPES_DIR)
    .filter((f) => f.endsWith('.ts'))
    .sort()
    .map((f) => join(TS_TYPES_DIR, f));
  const program = ts.createProgram(files, { target: ts.ScriptTarget.ES2022, strict: true });
  const checker = program.getTypeChecker();
  const decls = new Map<string, ts.InterfaceDeclaration | ts.TypeAliasDeclaration>();
  for (const sf of program.getSourceFiles()) {
    if (sf.isDeclarationFile || !sf.fileName.includes('engine/src/types')) continue;
    sf.forEachChild((node) => {
      if ((ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) && isExported(node)) {
        decls.set(node.name.text, node);
      }
    });
  }
  return { decls, program, checker };
}

/**
 * The inventory's completeness, extended to the whole public surface.
 *
 * `buildRegistry` only scans packages/engine/src/types/. Every other file in
 * the engine could export a data-shaped type through index.ts and this
 * generator would neither emit it nor list it in the exclusion-audit footer —
 * it would simply not exist as far as the Python port is concerned, and
 * nothing would say so. `ChainCompletenessResult` was in exactly that state:
 * on the engine's public surface, absent from _generated/models.py, and
 * absent from the footer that is supposed to account for absences.
 *
 * A silent gap is the failure mode this audit exists to prevent, so an
 * unaccounted-for public type is now a hard error. Resolving it is a
 * decision, not a chore: either move the type into types/ so it is
 * generated, or add it to EXCLUDE with the reason it is TS-only.
 */
function auditPublicSurface(emitter: Emitter): void {
  const indexPath = join(ENGINE_SRC_DIR, 'index.ts');
  if (!existsSync(indexPath)) {
    throw new Error(`Engine public entrypoint missing: ${indexPath}`);
  }
  const program = ts.createProgram([indexPath], {
    target: ts.ScriptTarget.ES2022,
    strict: true,
  });
  const checker = program.getTypeChecker();
  const sf = program.getSourceFile(indexPath);
  if (!sf) throw new Error(`Could not load ${indexPath}`);
  const moduleSymbol = checker.getSymbolAtLocation(sf);
  if (!moduleSymbol) throw new Error(`${indexPath} is not a module`);

  const behavioral = new Set(emitter.excludedBehavioral);
  const unaccounted: string[] = [];

  for (const sym of checker.getExportsOfModule(moduleSymbol)) {
    let resolved = sym;
    if (sym.flags & ts.SymbolFlags.Alias) {
      try {
        resolved = checker.getAliasedSymbol(sym);
      } catch {
        /* unresolvable alias — fall back to the local symbol */
      }
    }
    const decls = [
      ...(sym.getDeclarations() ?? []),
      ...(resolved.getDeclarations() ?? []),
    ];
    const isType = decls.some(
      (d) => ts.isInterfaceDeclaration(d) || ts.isTypeAliasDeclaration(d),
    );
    const isValue = decls.some(
      (d) =>
        ts.isClassDeclaration(d) ||
        ts.isFunctionDeclaration(d) ||
        ts.isVariableDeclaration(d) ||
        ts.isEnumDeclaration(d),
    );
    // Values (classes, functions, consts) are behaviour, not wire shapes.
    if (!isType || isValue) continue;

    const name = sym.getName();
    if (emitter.defs.has(name)) continue;
    if (EXCLUDE.has(name)) continue;
    if (behavioral.has(name)) continue;
    const where = (decls[0]?.getSourceFile().fileName ?? 'unknown').replace(
      REPO_ROOT + '/',
      '',
    );
    unaccounted.push(`${name} (${where})`);
  }

  if (unaccounted.length > 0) {
    throw new Error(
      'public-surface gap: these types are exported from ' +
        'packages/engine/src/index.ts but are neither generated into ' +
        '_generated/models.py nor listed in EXCLUDE, so nothing accounts ' +
        'for their absence:\n' +
        unaccounted.map((u) => `  - ${u}`).join('\n') +
        '\nMove the type into packages/engine/src/types/ to have it ' +
        'generated, or add it to EXCLUDE with the reason it is TS-only.',
    );
  }
}

function emit(stamp: boolean): { source: string; classCount: number; excludedCount: number } {
  const reg = buildRegistry();
  const emitter = new Emitter(reg);

  // Walk declarations in file order (files sorted, declarations in source order)
  // for deterministic first-encounter lifting; topoSort fixes final layout.
  const fileOrder = [...reg.decls.entries()].sort((a, b) => {
    const fa = a[1].getSourceFile().fileName;
    const fb = b[1].getSourceFile().fileName;
    if (fa !== fb) return fa < fb ? -1 : 1;
    return a[1].pos - b[1].pos;
  });
  for (const [name, decl] of fileOrder) {
    if (EXCLUDE.has(name)) continue;
    if (ts.isInterfaceDeclaration(decl) && hasBehavioralMembers(decl)) {
      if (!emitter.excludedBehavioral.includes(name)) emitter.excludedBehavioral.push(name);
      continue;
    }
    emitter.emitDecl(name);
  }

  selfCheck(emitter.defs);
  auditPublicSurface(emitter);
  return {
    source: render(emitter, stamp),
    classCount: [...emitter.defs.values()].filter((d) => d.kind === 'class').length,
    excludedCount: emitter.excludedBehavioral.length + EXCLUDE.size,
  };
}

function main(): void {
  // canonical.py / chain.py are stable committed outputs — verified
  // present, never rewritten by this script.
  for (const stable of ['canonical.py', 'chain.py']) {
    const p = join(PY_GENERATED_DIR, stable);
    if (!existsSync(p)) {
      throw new Error(`expected stable generated file missing: ${p}`);
    }
  }
  const stamp = process.argv.includes('--stamp');
  const { source, classCount, excludedCount } = emit(stamp);
  writeFileSync(OUT_FILE, source, 'utf-8');

  // Byte-for-byte copy: the two SDKs must agree on the catalog digest.
  if (!existsSync(KNOWN_MODELS_SRC)) {
    throw new Error(`known-models seed catalog missing: ${KNOWN_MODELS_SRC}`);
  }
  writeFileSync(KNOWN_MODELS_DST, readFileSync(KNOWN_MODELS_SRC));
  console.log(`[codegen-python] synced ${KNOWN_MODELS_DST}`);

  writeFileSync(TSA_AUTHORITIES_DST, tsaAuthoritiesJson(), 'utf-8');
  console.log(`[codegen-python] wrote ${TSA_AUTHORITIES_DST}`);

  console.log(
    `[codegen-python] wrote ${OUT_FILE}: ${classCount} classes (+aliases), ${excludedCount} excluded (audited in footer)${stamp ? ' [stamped]' : ''}`,
  );
}

main();

export { readJsdocTag, CANONICAL_SORT_TAG, HASHED_FIELDS_TAG, OMIT_WHEN_UNSET_TAG };
