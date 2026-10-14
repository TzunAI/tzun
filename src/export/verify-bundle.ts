/**
 * `verifyBundle()`: a `b1` proof bundle verified with nothing but the bundle
 * and the auditor's own inputs (Bundle §3, §4, §7.3, §7.7; Verification §3.1;
 * tzun-anchor/1 §10), reported in the shape of Verification §6.1:
 *
 *   { reportVersion: 'tzun-verify-report/1', bundleVersion, subject,
 *     inputs, checks: [{ id, outcome, reason?, facts? }], summary, checkedAt }
 *
 * Every check has one of the four outcomes of Verification §2.1. A check whose
 * prerequisite was not decided reports `not-checked`, `blocked_by:<id>`, and a
 * failure is reported once, at the check that decided it. Nothing the bundle
 * says about itself is an input: `exporter.*` is never read, and every fact is
 * re-derived. The function never throws.
 *
 * THE CHECKS, in report order:
 *
 *   bundle                 `bundleVersion` is `b1` (otherwise abstain on the
 *                          whole bundle, `unsupported_bundle_version`), the
 *                          profile is `record` (`chain` is not implemented
 *                          here: abstain, `unsupported_bundle_profile`), and
 *                          every member is readable (`malformed_bundle`):
 *                          among others, every checkpoint body parses and sits
 *                          under the key of its own origin, once, and no
 *                          member name a row id can carry (of the bundle, of
 *                          `extensions`, of `envelope.nonRepudiation`, of
 *                          `anchoring`) holds a lone surrogate (Bundle §4
 *                          step 9). When it is not `checked-correct`, it is
 *                          the only check.
 *   subject                `subject` names the envelope's evidence id and
 *                          stored digest (`subject_mismatch`).
 *   record.digest          The payload recomputed under its schema's rules
 *                          equals `integrity.canonicalDigest` (`digest_mismatch`,
 *                          `payload_unserializable`; an unknown schema version
 *                          abstains, `unsupported_schema_version`). An
 *                          envelope whose `envelopeVersion` is not `e1`
 *                          (another tag, `null`, or none) abstains,
 *                          `unsupported_envelope_version`: its tag says how
 *                          its members are read, and this verifier reads
 *                          `e1` alone (Verification §4.3).
 *   record.chainLink       `integrity.chainLink` is SHA-256(predecessor digest ‖
 *                          digest) over `chain.predecessor`, which sits at the
 *                          previous sequence (`chain_link_mismatch`,
 *                          `chain_link_missing`, `predecessor_mismatch`,
 *                          `not_in_bundle:predecessor`). A genesis record with
 *                          no link and no predecessor holds.
 *   custody.ledger         The ledger rows against each other and the
 *                          envelope's `custodyChain` (`verifyCustodyLedger`;
 *                          its failure reasons), `not_in_bundle:custody_entries`,
 *                          `not_applicable` when there is nothing to measure.
 *                          It proves the rows consistent, not complete: the
 *                          ledger is committed nowhere a bundle can check, so
 *                          a last row removed with its hashed mirror entry
 *                          leaves no trace.
 *   ts.record.token        The record's RFC 3161 token, tzun-anchor/1 §10.5
 *   ts.record.trust        steps 1 to 4 over the record's digest: a DER
 *                          token, its imprint, its signature, the
 *                          signingCertificate(V2) that binds its signer and
 *                          the signer's critical timestamping-only EKU, then
 *                          a valid path to a supplied root (`malformed_token`,
 *                          `imprint_mismatch`, `verification_failed`,
 *                          `missing_dependency`, `no_matching_trust_anchor`).
 *                          A key whose algorithm or curve this verifier does
 *                          not implement is `missing_dependency` on the check
 *                          whose step needs it (step 5). Only roots the
 *                          caller supplies count.
 *   signoff.expectation    The record's sign-off material against its hashed
 *                          `payload.signoffExpectation`, by every check that
 *                          needs no key (the engine's `checkSignoffExpectation`;
 *                          Verification §5). Its `false` answers are
 *                          checked-wrong with the engine's reason: a session
 *                          sign-off stripped (`signoff_stripped`), moved onto
 *                          a record that does not name it
 *                          (`session_signoff_not_expected`), of another slot
 *                          or statement (`session_seq_mismatch`,
 *                          `statement_digest_mismatch`), a sign-off block that
 *                          does not bind (`signoff_unbound`), a value of
 *                          neither form (`malformed_signoff_expectation`). A
 *                          policy record with no signature is not checked,
 *                          `signature_missing`: still to come, or stripped.
 *                          `blocked_by:record.digest` unless the digest holds;
 *                          `not_applicable` under a schema that does not hash
 *                          the field.
 *   signoff.key            `blocked_by:signoff.expectation` when that failed.
 *                          A record that owes a signature and carries no
 *                          assertion: `signature_missing`. A WebAuthn
 *                          assertion needs its credential, which this bundle
 *                          version carries in no slot yet:
 *                          `not_in_bundle:credential`. No WebAuthn signature
 *                          is verified here (Verification §4.5).
 *   decider, decider.freshness, contributions, contributions.binding,
 *   contributions.pipeline, links, links[<i>], links[<i>].edge,
 *   mandate.issuance, mandate.scope, mandate.limits, mandate.key,
 *   mandate.assertionTimestamp
 *                          The record rules (Verification §4.9 to §4.12), in
 *                          that order, by the engine's checks
 *                          (`record-rule-rows.ts`): read from the record
 *                          alone, `blocked_by:record.digest` unless its
 *                          digest holds. A bundle holds no link target, and
 *                          no edge is proven in this version: each
 *                          `links[<i>].edge` abstains, `unsupported_link_edge`.
 *                          `decider.freshness` reads the auditor's header
 *                          source for the reference's chain.
 *   anchor, anchor.*       The envelope's `nonRepudiation.anchor` by
 *                          `verifyAnchor` (tzun-anchor/1 §10.3 to §10.7), over
 *                          the recomputed digest, with the record's sequence
 *                          number, the bundle's chain id and the heavy
 *                          material every carried anchor checkpoint's
 *                          publications hold. With neither `anchor` nor
 *                          `blockchainAnchor`, `anchor` and its step checks
 *                          are `absent` whatever `record.digest` says
 *                          (Verification §4.6).
 *   anchor.newer           The subject's anchor into the newest carried anchor
 *                          checkpoint (tzun-anchor/1 §10.8; Bundle §7.5),
 *                          composed from the evidence-log checkpoint that
 *                          carries `logPath`, `anchorLeafIndex`, `anchorSize`
 *                          and `anchorPath`, and the anchor checkpoint at
 *                          `anchorSize` with its publications.
 *   anchor.consistency[<origin>]
 *                          For every origin the bundle carries or the anchors
 *                          name: every carried body is one that `anchor` or
 *                          `anchor.newer` authenticated (otherwise
 *                          `blocked_by:anchor`, or `blocked_by:anchor.newer`
 *                          once the anchor holds), and two authenticated
 *                          bodies are consistent (tzun-anchor/1 §10.8):
 *                          `split_view`, `log_inconsistent_with_anchor`,
 *                          `not_in_bundle:consistency_proof`.
 *   anchor.pending         The `anchorPending` slot: `not_yet_published`.
 *   extension[<key>]       An extension this verifier does not implement, with
 *                          a value: abstain, `unsupported_extension`.
 *   relatedRecords, policy A frozen slot this verifier does not read yet,
 *                          filled: abstain, `unsupported_slot`.
 *   payload.<name>         A payload member outside the format's twelve names,
 *                          in byte order: abstain, `unsupported_member`.
 *   member[<key>]          A top-level member a record bundle does not have:
 *                          abstain, `unsupported_member`.
 *   ts.assertion.token,    Each member of `nonRepudiation` with a value that
 *   nonRepudiation.<name>  no check above reads, in byte order of its name
 *                          (Verification §4.7): `assertionTimestamp` is
 *                          `ts.assertion.token`, a `blockchainAnchor` beside
 *                          an `anchor` abstains `legacy_blockchain_anchor`,
 *                          and any other is `nonRepudiation.<name>`; each
 *                          abstains, `unsupported_artifact` but for the
 *                          legacy anchor.
 *
 * The report restates the bundle's `bundleVersion` and `subject` as they
 * stand (Verification §6.1). `bundleExitCode()` turns a report into its exit
 * code (Verification §6.6).
 */
import { createHash } from 'node:crypto';
import {
  canonicalSerialize,
  checkSignoffExpectation,
  earlierFieldSet,
  EvidenceChain,
  recordDigestCheck,
  SchemaRegistry,
  verifyCustodyLedger,
  type EvidenceEnvelope,
  type EvmFinality,
} from '@tzun/engine';
import { ANCHOR_SPEC, verifyAnchor, type AnchorVerification, type AnchorVerifyOptions } from '../attestation/anchor-verify';
import type { EvmHeaderSource, EvmNetwork, PublisherManifest } from '../attestation/blockchain';
import { ANCHOR_LOG_KIND, parseCheckpoint, parseOrigin } from '../attestation/checkpoint';
import { MERKLE_SPEC, verifyConsistencyProof } from '../attestation/merkle';
import { readTrustAnchors } from '../attestation/rfc3161-verify';
import { UnreadableTrustAnchorError, verifyRfc3161Steps, type Rfc3161Certificate } from '../attestation/rfc3161-token';
import { BUNDLE_VERSION } from './bundle-types';
import { recordRuleChecks, unhashedPayloadRows } from './record-rule-rows';

/** The report version of Verification §6.1. */
export const BUNDLE_REPORT_VERSION = 'tzun-verify-report/1' as const;

/** The four outcomes of Verification §2.1. */
export type BundleCheckOutcome = 'checked-correct' | 'checked-wrong' | 'not-checked' | 'abstain';

/** One check of the report. `facts` are re-derived, never read from the bundle's claims. */
export interface BundleCheck {
  id: string;
  outcome: BundleCheckOutcome;
  reason?: string;
  facts?: Record<string, unknown>;
}

/** The earliest proven time the subject's digest existed by, and the check that proved it. */
export interface BundleExistedBy {
  /** ISO 8601. */
  at: string;
  /** An EVM publication or RFC 3161 token of an anchor, or the record's own RFC 3161 timestamp. */
  source: 'evm-calldata' | 'rfc3161' | 'record-timestamp';
  check: 'anchor' | 'anchor.newer' | 'ts.record.trust';
}

/**
 * The report's summary, derived from the checks and never an input
 * (Verification §6.4). The sign-off members are null, and `rungs` empty, until
 * sign-off verification is implemented here.
 */
export interface BundleReportSummary {
  mode: null;
  coverage: null;
  manifestEnforced: null;
  rungs: string[];
  keyKind: null;
  keyAssurance: null;
  uv: null;
  actorBound: null;
  existedBy: BundleExistedBy | null;
  /** From the subject's anchor when it holds, otherwise from `anchor.newer` when that holds. */
  anchorNetwork: EvmNetwork | null;
  anchorNamespace: 'production' | 'test' | null;
  anchorOriginAuthenticated: boolean;
  outcomes: Record<BundleCheckOutcome, number>;
}

/**
 * What the verifier was given, as far as a reader of the report needs to know
 * it: fingerprints and digests, never the inputs themselves.
 */
export interface BundleReportInputs {
  /** SHA-256 of each supplied RFC 3161 root certificate's DER, lowercase hex, sorted. */
  trustAnchors: string[];
  /** The chains the caller supplied header sources for, and the finality each declares. Sorted by chain. */
  evmHeaderSources: Array<{ chain: string; finality: EvmFinality | null }>;
  /** SHA-256 of the publisher manifest in DEO canonical form; null when none was supplied. */
  publisherManifest: string | null;
  /** Sign-off inputs this verifier does not read yet. */
  frameOrigins: null;
  vkeys: null;
  mdsRoots: null;
}

/** The report of Verification §6.1. Compare two reports without `checkedAt`. */
export interface BundleVerificationReport {
  reportVersion: typeof BUNDLE_REPORT_VERSION;
  /** The bundle's `bundleVersion` as it stands; `null` when the bundle is not an object or has none (Verification §6.1). */
  bundleVersion: unknown;
  /** The bundle's `subject` as it stands, whatever it holds; `null` when the bundle is not an object or has none (Verification §6.1). */
  subject: unknown;
  inputs: BundleReportInputs;
  checks: BundleCheck[];
  summary: BundleReportSummary;
  checkedAt: string;
}

/** The auditor's own inputs. None comes from the bundle; each one omitted leaves what it decides undecided. */
export interface VerifyBundleOptions {
  /** Which wallets may publish for which anchor origin (tzun-anchor/1 §9). */
  publisherManifest?: PublisherManifest;
  /** Header sources keyed by CAIP-2 chain. Without one, no EVM publication is `true`. */
  evmHeaderSources?: Record<string, EvmHeaderSource>;
  evmNetworks?: Record<string, EvmNetwork>;
  /** One deadline for every header-source call of one anchor verification. Default 30 s. */
  evmTimeoutMs?: number;
  /**
   * RFC 3161 roots, for the record's timestamp and for `rfc3161/1`
   * publications. Every one must read as a certificate with a key this
   * verifier implements: `verifyBundle` rejects with
   * `UnreadableTrustAnchorError` otherwise, and reports nothing
   * (Verification §3.1, §6.6).
   */
  trustAnchorsPem?: string[];
  /** Timestamp authorities to trust, by registry key or URL. A name the registry does not know is refused the same way. */
  authorities?: string[];
  /** The schemas digests are recomputed under. Default: the engine's. */
  registry?: SchemaRegistry;
}

/** The auditor's regime for `bundleExitCode` (Verification §3.2: `--require`, `--require-rung`, `--allow-unchecked`). */
export interface BundleExitOptions {
  /** Check ids that must be `checked-correct`. */
  require?: string[];
  /** Rungs the summary must report. */
  requireRung?: string[];
  /**
   * `true`: present artifacts left not checked or abstained on do not make the
   * exit code 4. A list of reasons (an allowance scoped more narrowly than the
   * switch of Verification §3.2; for example `['unsupported_link_edge']`): only
   * rows whose reason is in the list stop counting toward 4, and every other
   * unchecked row still does. An empty list allows nothing.
   */
  allowUnchecked?: boolean | readonly string[];
}

export type BundleExitCode = 0 | 1 | 2 | 3 | 4;

// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Json {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isIndex(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function check(id: string, outcome: BundleCheckOutcome, reason?: string, facts?: Record<string, unknown>): BundleCheck {
  return { id, outcome, ...(reason !== undefined && { reason }), ...(facts !== undefined && { facts }) };
}

const correct = (c: BundleCheck | undefined): boolean => c?.outcome === 'checked-correct';

/** The step checks of tzun-anchor/1 §10.3, in order. */
const ANCHOR_STEPS = ['anchor.spec', 'anchor.checkpoint', 'anchor.origin', 'anchor.leafIndex', 'anchor.inclusion', 'anchor.anchorInclusion'] as const;

/** The anchor reasons that are abstentions (tzun-anchor/1 §10.1): a construction this verifier does not implement. */
function isAbstention(reason: string | undefined): boolean {
  return typeof reason === 'string' && (reason.startsWith('unsupported_') || reason.startsWith('legacy_'));
}

const bytewise = (a: string, b: string): number => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

/** A UTF-16 surrogate with no partner: a string that has no UTF-8 form (Record §3.1). */
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

// ---- Inputs ----------------------------------------------------------------

/** Whether the caller supplied RFC 3161 trust, as `verifyAnchor` decides it: options or the environment. */
function tsaTrustSupplied(options: VerifyBundleOptions): boolean {
  const listed = (value: unknown) => Array.isArray(value) && value.length > 0;
  const configured = (name: string) => {
    const value = process.env[name];
    return typeof value === 'string' && value.trim().length > 0;
  };
  return listed(options.trustAnchorsPem) || listed(options.authorities) || configured('TZUN_TSA_TRUST_ANCHORS') || configured('TZUN_TSA_AUTHORITIES');
}

/**
 * The RFC 3161 roots the caller supplied, read, or none when it supplied
 * none. A root that cannot be read, or an authority the registry does not
 * know, is an auditor input that cannot be read: it throws, and no report is
 * made (Verification §3.1, §6.6).
 *
 * @throws UnreadableTrustAnchorError
 */
function suppliedRoots(options: VerifyBundleOptions): Rfc3161Certificate[] {
  const { trustAnchorsPem, authorities } = options;
  const given = (value: unknown) => value !== undefined && !(Array.isArray(value) && value.length === 0);
  if (!tsaTrustSupplied(options) && !given(trustAnchorsPem) && !given(authorities)) return [];
  return readTrustAnchors({
    ...(given(trustAnchorsPem) && { trustAnchorsPem }),
    ...(given(authorities) && { authorities }),
  });
}

function reportInputs(options: VerifyBundleOptions, roots: Rfc3161Certificate[]): BundleReportInputs {
  const trustAnchors = [...new Set(roots.map((r) => createHash('sha256').update(r.der).digest('hex')))].sort();
  const sources = isRecord(options.evmHeaderSources) ? options.evmHeaderSources : {};
  const evmHeaderSources = Object.keys(sources)
    .sort(bytewise)
    .map((chain) => {
      const finality = (sources[chain] as EvmHeaderSource | undefined)?.finality;
      return { chain, finality: finality === undefined ? null : (JSON.parse(JSON.stringify(finality)) as EvmFinality) };
    });
  let publisherManifest: string | null = null;
  if (isRecord(options.publisherManifest)) {
    try {
      const manifest = options.publisherManifest as unknown as Json;
      publisherManifest = sha256Hex(canonicalSerialize(manifest, Object.keys(manifest)));
    } catch {
      publisherManifest = null;
    }
  }
  return { trustAnchors, evmHeaderSources, publisherManifest, frameOrigins: null, vkeys: null, mdsRoots: null };
}

// ---- Reading the bundle ------------------------------------------------------

interface ReadEntry {
  body: unknown;
  publications?: unknown;
  logPath?: unknown;
  anchorLeafIndex?: unknown;
  anchorSize?: unknown;
  anchorPath?: unknown;
}

interface ReadLog {
  origin: string;
  checkpoints: ReadEntry[];
  consistency: Json[];
}

interface ReadBundle {
  subject: Json;
  envelope: EvidenceEnvelope;
  chain: { chainId: unknown; predecessor: Json | null };
  custodyEntries: unknown[] | null;
  credentials: unknown;
  relatedRecords: unknown;
  policy: unknown;
  /** Top-level members a `record` bundle does not have, sorted. */
  unknownMembers: string[];
  logs: ReadLog[];
  anchorPending: Json | null;
  extensions: Json;
}

const REQUIRED_MEMBERS = [
  'subject',
  'envelope',
  'chain',
  'custody',
  'credentials',
  'relatedRecords',
  'anchoring',
  'anchorPending',
  'policy',
  'extensions',
  'exporter',
] as const;

/** Every top-level member of a `record` bundle (Bundle §3.1). */
const RECORD_MEMBERS = new Set<string>(['bundleVersion', 'profile', ...REQUIRED_MEMBERS]);

const COMPOSED_MEMBERS = ['logPath', 'anchorLeafIndex', 'anchorSize', 'anchorPath'] as const;

/**
 * The `bundle` check: the version, the profile and the members' shapes. A
 * member's content is left to the check that reads it; only what the
 * verifier needs to find its way is held here: objects, arrays and strings,
 * custody entries that are objects, and checkpoint bodies that parse, each
 * under the key of its own origin, each once per log, with the subject's
 * anchor into the newest checkpoint stated once and on a checkpoint that is
 * not the anchor log's. A key that is not its bodies' origin would let the
 * bundle label, and so group, the checkpoints a consistency check compares.
 * No member name a row id can carry (of the bundle, of `extensions`, of
 * `envelope.nonRepudiation`, of `anchoring`) holds a lone surrogate, since a
 * report that holds one cannot be written (Bundle §4 step 9).
 */
function readBundle(bundle: unknown): { check: BundleCheck; read?: ReadBundle } {
  const malformed = { check: check('bundle', 'checked-wrong', 'malformed_bundle') };
  if (!isRecord(bundle)) return malformed;
  if (bundle.bundleVersion !== BUNDLE_VERSION) return { check: check('bundle', 'abstain', 'unsupported_bundle_version') };
  if (typeof bundle.profile !== 'string') return malformed;
  if (bundle.profile !== 'record') return { check: check('bundle', 'abstain', 'unsupported_bundle_profile') };
  if (!REQUIRED_MEMBERS.every((m) => m in bundle)) return malformed;

  const { subject, envelope, chain, custody, anchoring, anchorPending, extensions } = bundle;
  if (!isRecord(subject) || !isRecord(envelope) || !isRecord(chain) || !isRecord(custody) || !isRecord(anchoring) || !isRecord(extensions)) {
    return malformed;
  }
  for (const slot of ['credentials', 'relatedRecords', 'policy'] as const) {
    if (bundle[slot] !== null && !isRecord(bundle[slot])) return malformed;
  }
  if (!('chainId' in chain) || (chain.chainId !== null && typeof chain.chainId !== 'string')) return malformed;
  const predecessor = chain.predecessor ?? null;
  if (predecessor !== null) {
    if (!isRecord(predecessor) || typeof predecessor.canonicalDigest !== 'string' || !isIndex(predecessor.sequenceNumber)) return malformed;
  }
  const entries = custody.entries ?? null;
  if (entries !== null && (!Array.isArray(entries) || !entries.every(isRecord))) return malformed;
  if (anchorPending !== null) {
    if (!isRecord(anchorPending) || typeof anchorPending.origin !== 'string' || !isIndex(anchorPending.leafIndex) || typeof anchorPending.since !== 'string') {
      return malformed;
    }
  }

  const logs: ReadLog[] = [];
  let composed = 0;
  for (const origin of Object.keys(anchoring).sort(bytewise)) {
    const material = anchoring[origin];
    if (!isRecord(material) || !Array.isArray(material.checkpoints) || !Array.isArray(material.consistency)) return malformed;
    // A record bundle carries at most two checkpoints per log (Bundle §7.3).
    if (material.checkpoints.length > 2 || !material.checkpoints.every(isRecord) || !material.consistency.every(isRecord)) return malformed;
    const checkpoints = material.checkpoints as unknown as ReadEntry[];
    const bodies = new Set<string>();
    for (const cp of material.checkpoints as Json[]) {
      if (typeof cp.body !== 'string' || !Array.isArray(cp.signatures) || bodies.has(cp.body)) return malformed;
      bodies.add(cp.body);
      const parsed = parseCheckpoint(cp.body);
      if (!parsed.ok || parsed.checkpoint.origin !== origin) return malformed;
      if (COMPOSED_MEMBERS.some((m) => m in cp)) {
        composed += 1;
        const kind = parseOrigin(origin)?.kind;
        if (kind === undefined || kind === ANCHOR_LOG_KIND) return malformed;
      }
    }
    logs.push({ origin, checkpoints, consistency: material.consistency as Json[] });
  }
  // The subject's anchor into the newest checkpoint is stated once.
  if (composed > 1) return malformed;
  const nonRepudiation = envelope.nonRepudiation;
  const named = [bundle, extensions, anchoring, ...(isRecord(nonRepudiation) ? [nonRepudiation] : [])];
  if (named.some((object) => Object.keys(object).some((name) => LONE_SURROGATE.test(name)))) return malformed;

  return {
    check: check('bundle', 'checked-correct'),
    read: {
      subject,
      envelope: envelope as unknown as EvidenceEnvelope,
      chain: { chainId: chain.chainId, predecessor: predecessor as Json | null },
      custodyEntries: entries as unknown[] | null,
      credentials: bundle.credentials,
      relatedRecords: bundle.relatedRecords,
      policy: bundle.policy,
      unknownMembers: Object.keys(bundle).filter((m) => !RECORD_MEMBERS.has(m)).sort(bytewise),
      logs,
      anchorPending: anchorPending as Json | null,
      extensions,
    },
  };
}

// ---- Record checks ------------------------------------------------------------

function subjectCheck(read: ReadBundle): BundleCheck {
  const { subject, envelope } = read;
  const holds =
    typeof subject.evidenceId === 'string' &&
    typeof subject.canonicalDigest === 'string' &&
    subject.evidenceId === envelope.payload?.evidenceId &&
    subject.canonicalDigest === envelope.integrity?.canonicalDigest;
  return holds ? check('subject', 'checked-correct') : check('subject', 'checked-wrong', 'subject_mismatch');
}

/** The one envelope version this verifier reads. */
const ENVELOPE_VERSION: EvidenceEnvelope['envelopeVersion'] = 'e1';

function digestCheck(envelope: EvidenceEnvelope, registry: SchemaRegistry): { check: BundleCheck; digest: string } {
  // An unknown tag abstains on the part it governs (Verification §2.2, §4.3).
  // Everything that takes the digest as input is then blocked by this check.
  if ((envelope as { envelopeVersion?: unknown }).envelopeVersion !== ENVELOPE_VERSION) {
    return { check: check('record.digest', 'abstain', 'unsupported_envelope_version'), digest: '' };
  }
  const result = recordDigestCheck(envelope, registry);
  if (result.status === 'valid') return { check: check('record.digest', 'checked-correct'), digest: result.recomputed };
  if (result.reason === 'unknown_schema_version') return { check: check('record.digest', 'abstain', 'unsupported_schema_version'), digest: '' };
  const reason = result.reason ?? 'digest_mismatch';
  // An earlier hashed field set that reproduces the stored digest explains the
  // mismatch and never excuses it (Verification §4.3 step 4).
  const fieldSet = reason === 'digest_mismatch' ? earlierFieldSet(envelope.payload, envelope.integrity?.canonicalDigest) : null;
  return { check: check('record.digest', 'checked-wrong', reason, fieldSet !== null ? { fieldSet } : undefined), digest: result.recomputed };
}

function chainLinkCheck(read: ReadBundle): BundleCheck {
  const id = 'record.chainLink';
  const seq = read.envelope.payload?.sequenceNumber;
  const link = read.envelope.integrity?.chainLink ?? null;
  const stored = read.envelope.integrity?.canonicalDigest;
  const predecessor = read.chain.predecessor;
  if (predecessor === null) {
    if (seq === 1 && link === null) return check(id, 'checked-correct');
    if (link === null) return check(id, 'checked-wrong', 'chain_link_missing');
    return check(id, 'not-checked', 'not_in_bundle:predecessor');
  }
  // Sequences start at 1: a genesis record has no predecessor.
  if (!isIndex(seq) || seq < 2 || predecessor.sequenceNumber !== seq - 1) return check(id, 'checked-wrong', 'predecessor_mismatch');
  if (link === null) return check(id, 'checked-wrong', 'chain_link_missing');
  const chain = new EvidenceChain();
  chain.restore(predecessor.canonicalDigest as string);
  const expected = typeof stored === 'string' ? chain.computeLink(stored) : null;
  return expected !== null && expected === link ? check(id, 'checked-correct') : check(id, 'checked-wrong', 'chain_link_mismatch');
}

function custodyCheck(read: ReadBundle): BundleCheck {
  const id = 'custody.ledger';
  if (read.custodyEntries === null) return check(id, 'not-checked', 'not_in_bundle:custody_entries');
  const evidenceId = read.envelope.payload?.evidenceId;
  const ledger = verifyCustodyLedger(typeof evidenceId === 'string' ? evidenceId : '', read.envelope, undefined, read.custodyEntries as never);
  if (!ledger.valid) return check(id, 'checked-wrong', ledger.failures[0]?.reason ?? 'custody_ledger_invalid');
  if (ledger.rows === 0 && ledger.hashedEntries === 0) return check(id, 'not-checked', 'not_applicable');
  return check(id, 'checked-correct');
}

/**
 * The record's RFC 3161 timestamp by tzun-anchor/1 §10.5, steps in order:
 * `ts.record.token` is steps 1 to 3 (parse, the imprint over the recomputed
 * digest, the signature and its signer), and `ts.record.trust` is step 4, the
 * path to a root the caller supplied. The first step that does not hold
 * decides, and the check after it is blocked by it. A path that reaches a
 * supplied root and holds on none is `verification_failed`; one that reaches
 * none is not checked, `no_matching_trust_anchor`; one that would hold but for
 * a signature under a key or algorithm this verifier does not implement is not
 * checked, `missing_dependency` (tzun-anchor/1 §10.5 step 5).
 */
function recordTimestampChecks(
  envelope: EvidenceEnvelope,
  digest: BundleCheck,
  recomputed: string,
  roots: Rfc3161Certificate[],
): { checks: [BundleCheck, BundleCheck]; genTime?: string } {
  const token = (envelope.nonRepudiation as Json | undefined)?.rfc3161Token;
  const TOKEN = 'ts.record.token';
  const TRUST = 'ts.record.trust';
  const after = (first: BundleCheck): [BundleCheck, BundleCheck] => [first, check(TRUST, 'not-checked', `blocked_by:${TOKEN}`)];
  if (token === undefined || token === null) return { checks: [check(TOKEN, 'not-checked', 'absent'), check(TRUST, 'not-checked', 'absent')] };
  if (!correct(digest)) {
    return { checks: [check(TOKEN, 'not-checked', 'blocked_by:record.digest'), check(TRUST, 'not-checked', 'blocked_by:record.digest')] };
  }
  const verdict = verifyRfc3161Steps(token, recomputed, roots);
  switch (verdict.token) {
    case 'malformed':
      return { checks: after(check(TOKEN, 'checked-wrong', 'malformed_token')) };
    case 'missing_dependency':
      return { checks: after(check(TOKEN, 'not-checked', 'missing_dependency')) };
    case 'imprint_mismatch':
    case 'verification_failed':
      return { checks: after(check(TOKEN, 'checked-wrong', verdict.token)) };
  }
  const tokenCheck = check(TOKEN, 'checked-correct');
  if (verdict.trust === 'reached') return { checks: [tokenCheck, check(TRUST, 'checked-wrong', 'verification_failed')] };
  if (verdict.trust === 'missing_dependency') return { checks: [tokenCheck, check(TRUST, 'not-checked', 'missing_dependency')] };
  if (verdict.trust !== 'valid') return { checks: [tokenCheck, check(TRUST, 'not-checked', 'no_matching_trust_anchor')] };
  const genTime = verdict.genTime instanceof Date && !Number.isNaN(verdict.genTime.getTime()) ? verdict.genTime.toISOString() : undefined;
  // `authority` is always a fact of a trust check that holds, the empty string included (tzun-anchor/1 §10.5 step 4).
  return {
    checks: [tokenCheck, check(TRUST, 'checked-correct', undefined, { ...(genTime && { genTime }), authority: verdict.authority ?? '' })],
    ...(genTime && { genTime }),
  };
}

/** Whether the record's schema hashes `signoffExpectation`, so that its value there is the record's own. */
function hashesExpectation(envelope: EvidenceEnvelope, registry: SchemaRegistry): boolean {
  const schemaVersion = (envelope.payload as unknown as Json | undefined)?.schemaVersion;
  return typeof schemaVersion === 'string' && registry.get(schemaVersion)?.hashedFieldSet.includes('signoffExpectation') === true;
}

/**
 * `signoff.expectation`: the record's sign-off material against its hashed
 * `payload.signoffExpectation` (Verification §5), by the engine's
 * `checkSignoffExpectation`, which needs no key. `true` is checked-correct,
 * `false` checked-wrong with the engine's reason, and `null` (a policy record
 * with no signature, which may still be coming or was stripped) not checked,
 * `signature_missing`. The value is read only when the digest recomputed over
 * it holds; under a schema that does not hash it, a value there is not the
 * record's own and says nothing (`not_applicable`).
 */
function expectationCheck(envelope: EvidenceEnvelope, digest: BundleCheck, registry: SchemaRegistry): BundleCheck {
  const id = 'signoff.expectation';
  if (!correct(digest)) return check(id, 'not-checked', 'blocked_by:record.digest');
  if (!hashesExpectation(envelope, registry)) return check(id, 'not-checked', 'not_applicable');
  const result = checkSignoffExpectation(envelope);
  if (result.valid === true) return check(id, 'checked-correct');
  if (result.valid === false) return check(id, 'checked-wrong', result.reason ?? 'malformed_signoff_expectation');
  return check(id, 'not-checked', result.reason ?? 'signature_missing');
}

/**
 * `signoff.key`. Blocked when `signoff.expectation` failed: the record does
 * not carry the sign-off its expectation names, so there is no key to look
 * for. A record that owes a signature and carries no WebAuthn assertion is
 * not checked, `signature_missing`, as `signoff.expectation` says: it never
 * reads as an absent artifact. Otherwise a carried assertion needs its
 * credential, which no slot of this version carries.
 */
function signoffCheck(read: ReadBundle, expectation: BundleCheck): BundleCheck {
  if (expectation.outcome === 'checked-wrong') return check('signoff.key', 'not-checked', `blocked_by:${expectation.id}`);
  const assertion = (read.envelope.nonRepudiation as Json | undefined)?.webauthnAssertion;
  const carried = assertion !== undefined && assertion !== null;
  if (!carried && expectation.reason === 'signature_missing') return check('signoff.key', 'not-checked', 'signature_missing');
  if (read.credentials !== null) return check('signoff.key', 'abstain', 'unsupported_signoff');
  if (!carried) return check('signoff.key', 'not-checked', 'absent');
  return check('signoff.key', 'not-checked', 'not_in_bundle:credential');
}

// ---- Anchor checks --------------------------------------------------------------

/** The `anchor` row of tzun-anchor/1 §10.7 for a verdict: correct, wrong, abstain or not-checked as `anchorValid` and its reason say. */
function wholeAnchorCheck(id: 'anchor' | 'anchor.newer', verdict: AnchorVerification, facts?: Record<string, unknown>): BundleCheck {
  if (verdict.anchorValid === true) return check(id, 'checked-correct', undefined, facts);
  const reason = verdict.anchorPresent ? (verdict.anchorReason ?? 'anchor_verifier_error') : 'absent';
  if (verdict.anchorValid === false) return check(id, 'checked-wrong', reason);
  return check(id, isAbstention(reason) ? 'abstain' : 'not-checked', reason);
}

/**
 * The report's rows for one anchor verdict after its `anchor` row: the step
 * checks, then each publication's dispatch and its kind's checks, suffixed with
 * its index, each with the facts the catalogue names. They are
 * `verifyAnchor`'s own catalogue, in its report order (tzun-anchor/1 §10.3
 * step 6, §10.7).
 */
function anchorRows(verdict: AnchorVerification): BundleCheck[] {
  return verdict.checks
    .filter((c) => c.id !== 'anchor')
    .map((c) => check(c.id, c.outcome, c.reason as string | undefined, c.facts));
}

/** Every publication the bundle carries under an anchor checkpoint: the heavy material `verifyAnchor` joins. */
function carriedPublications(logs: ReadLog[]): unknown[] {
  const out: unknown[] = [];
  for (const log of logs) for (const cp of log.checkpoints) if (Array.isArray(cp.publications)) out.push(...cp.publications);
  return out;
}

/**
 * The subject's anchor into the newest carried anchor checkpoint, composed from
 * the evidence-log checkpoint that states it (tzun-anchor/1 §10.8): its body
 * and paths, and the anchor checkpoint of its domain at `anchorSize` with its
 * publications. Members the bundle does not supply are left out, and
 * `verifyAnchor` refuses the artifact for them.
 */
function composedAnchor(logs: ReadLog[], sequenceNumber: unknown): Json | null {
  for (const log of logs) {
    const entry = log.checkpoints.find((cp) => COMPOSED_MEMBERS.some((m) => m in cp));
    if (!entry) continue;
    const body = parseCheckpoint(entry.body);
    const origin = body.ok ? parseOrigin(body.checkpoint.origin) : null;
    const anchorOrigin = origin ? `${origin.domainPrefix}/${ANCHOR_LOG_KIND}` : null;
    const anchorLog = anchorOrigin === null ? undefined : logs.find((l) => l.origin === anchorOrigin);
    const anchorEntry = anchorLog?.checkpoints.find((cp) => {
      const parsed = parseCheckpoint(cp.body);
      return parsed.ok && parsed.checkpoint.size === entry.anchorSize;
    });
    return {
      anchorSpec: ANCHOR_SPEC,
      merkleSpec: MERKLE_SPEC,
      ...(isIndex(sequenceNumber) && sequenceNumber >= 1 && { leafIndex: sequenceNumber - 1 }),
      logCheckpoint: entry.body,
      ...(entry.logPath !== undefined && { logPath: entry.logPath }),
      ...(entry.anchorLeafIndex !== undefined && { anchorLeafIndex: entry.anchorLeafIndex }),
      ...(anchorEntry && { anchorCheckpoint: anchorEntry.body }),
      ...(entry.anchorPath !== undefined && { anchorPath: entry.anchorPath }),
      ...(anchorEntry && anchorEntry.publications !== undefined && { publications: anchorEntry.publications }),
    };
  }
  return null;
}

/**
 * `anchor.consistency[<origin>]` (tzun-anchor/1 §10.8), for every origin
 * whose checkpoints the bundle carries or the anchors name. A body is
 * authenticated by the check whose artifact names it: the envelope's anchor
 * (`anchor`), or the composed one (`anchor.newer`), each one body per origin.
 * Every body the bundle carries must be one of those, whatever the count: a
 * carried body neither authenticates is not checked, `blocked_by:anchor`
 * while the record's anchor does not hold and `blocked_by:anchor.newer` once
 * it does. When every carried body is authenticated and an origin has two
 * authenticated bodies, they are compared, whether the bundle carries them or
 * not: leaving the record's own checkpoint out of `anchoring` does not keep
 * it from being compared with a newer one. Origins, sizes and roots come from
 * the parsed bodies, so two bodies are compared only within one origin.
 */
function consistencyChecks(
  logs: ReadLog[],
  anchorCheck: BundleCheck,
  artifact: unknown,
  newerCheck: BundleCheck | undefined,
  composed: Json | null,
): BundleCheck[] {
  type Parsed = { size: number; root: string };
  const carried = new Map<string, Map<string, Parsed>>();
  const authenticated = new Map<string, Map<string, Parsed>>();
  const hold = (into: Map<string, Map<string, Parsed>>, body: unknown): void => {
    const parsed = parseCheckpoint(body);
    if (!parsed.ok) return;
    const bodies = into.get(parsed.checkpoint.origin) ?? new Map<string, Parsed>();
    bodies.set(body as string, { size: parsed.checkpoint.size, root: parsed.checkpoint.root });
    into.set(parsed.checkpoint.origin, bodies);
  };
  for (const log of logs) for (const cp of log.checkpoints) hold(carried, cp.body);
  if (isRecord(artifact) && correct(anchorCheck)) for (const body of [artifact.logCheckpoint, artifact.anchorCheckpoint]) hold(authenticated, body);
  if (composed && correct(newerCheck)) for (const body of [composed.logCheckpoint, composed.anchorCheckpoint]) hold(authenticated, body);

  const rows: BundleCheck[] = [];
  for (const origin of [...new Set([...carried.keys(), ...authenticated.keys()])].sort(bytewise)) {
    const id = `anchor.consistency[${origin}]`;
    const authentic = authenticated.get(origin) ?? new Map<string, Parsed>();
    if ([...(carried.get(origin)?.keys() ?? [])].some((body) => !authentic.has(body))) {
      rows.push(check(id, 'not-checked', correct(anchorCheck) ? 'blocked_by:anchor.newer' : 'blocked_by:anchor'));
      continue;
    }
    if (authentic.size < 2) continue;
    const [a, b] = [...authentic.values()];
    const [first, second] = a.size <= b.size ? [a, b] : [b, a];
    if (first.size === second.size) {
      rows.push(first.root === second.root ? check(id, 'checked-correct', undefined, { fromSize: first.size, toSize: second.size }) : check(id, 'checked-wrong', 'split_view'));
      continue;
    }
    const proofs = logs.find((l) => l.origin === origin)?.consistency ?? [];
    const proof = proofs.find((p) => p.fromSize === first.size && p.toSize === second.size);
    if (!proof) {
      rows.push(check(id, 'not-checked', 'not_in_bundle:consistency_proof'));
      continue;
    }
    const verified = verifyConsistencyProof(first.size, second.size, proof.path as string[], first.root, second.root);
    rows.push(
      verified.valid
        ? check(id, 'checked-correct', undefined, { fromSize: first.size, toSize: second.size })
        : check(id, 'checked-wrong', 'log_inconsistent_with_anchor'),
    );
  }
  return rows;
}

// ---- The report ------------------------------------------------------------------

function countOutcomes(checks: BundleCheck[]): Record<BundleCheckOutcome, number> {
  const outcomes: Record<BundleCheckOutcome, number> = { 'checked-correct': 0, 'checked-wrong': 0, 'not-checked': 0, abstain: 0 };
  for (const c of checks) outcomes[c.outcome] += 1;
  return outcomes;
}

function summaryOf(
  checks: BundleCheck[],
  own: AnchorVerification | null,
  newer: AnchorVerification | null,
  existedBy: BundleExistedBy[],
): BundleReportSummary {
  const holding = own?.anchorValid === true ? own : newer?.anchorValid === true ? newer : null;
  const shown = holding ?? (own?.anchorPresent ? own : newer);
  existedBy.sort((x, y) => Date.parse(x.at) - Date.parse(y.at));
  return {
    mode: null,
    coverage: null,
    manifestEnforced: null,
    rungs: [],
    keyKind: null,
    keyAssurance: null,
    uv: null,
    actorBound: null,
    existedBy: existedBy[0] ?? null,
    anchorNetwork: holding?.anchorNetwork ?? null,
    anchorNamespace: shown?.anchorNamespace ?? null,
    anchorOriginAuthenticated: holding?.anchorOriginAuthenticated === true,
    outcomes: countOutcomes(checks),
  };
}

/** Thrown by `jsonCopy` for a value it does not copy. */
const NOT_JSON = Symbol('not JSON');

/**
 * A copy of a JSON value, in this module's realm: primitives as they are,
 * arrays and plain objects (prototype `Object.prototype` or none) member by
 * member, strings with their lone surrogates. Anything else, a cycle
 * included, throws `NOT_JSON`.
 */
function jsonCopy(value: unknown, path: Set<object>): unknown {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') throw NOT_JSON;
    return value;
  }
  if (path.has(value)) throw NOT_JSON;
  path.add(value);
  try {
    if (Array.isArray(value)) return Array.from(value, (item) => jsonCopy(item, path));
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw NOT_JSON;
    const out: Record<string, unknown> = proto === null ? Object.create(null) : {};
    for (const key of Object.keys(value)) {
      // defineProperty, so a member named __proto__ stays a member.
      Object.defineProperty(out, key, { value: jsonCopy((value as Record<string, unknown>)[key], path), enumerable: true, writable: true, configurable: true });
    }
    return out;
  } finally {
    path.delete(value);
  }
}

/**
 * A member of the bundle as it stands, or `null` when the bundle is not an
 * object or lacks it (Verification §6.1). It is a copy, so a caller that edits
 * the report leaves its bundle as it was; a lone surrogate survives the copy. A
 * value that is not JSON (a function, a class instance, a cycle) is restated as
 * it is, and the report then has no canonical form (Verification §6.5).
 */
function restated(bundle: unknown, member: 'bundleVersion' | 'subject'): unknown {
  if (!isRecord(bundle) || !Object.prototype.hasOwnProperty.call(bundle, member)) return null;
  const value = bundle[member];
  if (value === undefined) return null;
  try {
    return jsonCopy(value, new Set());
  } catch {
    return value;
  }
}

function report(bundle: unknown, inputs: BundleReportInputs, checks: BundleCheck[], summary: BundleReportSummary): BundleVerificationReport {
  return {
    reportVersion: BUNDLE_REPORT_VERSION,
    bundleVersion: restated(bundle, 'bundleVersion'),
    subject: restated(bundle, 'subject'),
    inputs,
    checks,
    summary,
    checkedAt: new Date().toISOString(),
  };
}

const emptySummary = (checks: BundleCheck[]): BundleReportSummary => summaryOf(checks, null, null, []);

/**
 * Verify a `b1` proof bundle. Never throws on the bundle: it is a file someone
 * hands the verifier, and every member may be hostile JSON.
 *
 * The auditor's own inputs are another matter. RFC 3161 roots that cannot be
 * read (`trustAnchorsPem`, `authorities`, or the environment) are refused
 * before the bundle is read: the promise rejects with
 * `UnreadableTrustAnchorError` and there is no report, as a command-line
 * verifier refuses such an input with a code outside 0 to 4 (Verification
 * §3.1, §6.6). A root it dropped would read as a token that chains to none.
 */
export async function verifyBundle(bundle: unknown, options: VerifyBundleOptions = {}): Promise<BundleVerificationReport> {
  const opts: VerifyBundleOptions = isRecord(options) ? options : {};
  const roots = suppliedRoots(opts);
  const inputs = reportInputs(opts, roots);
  try {
    return await decide(bundle, opts, inputs, roots);
  } catch (err) {
    if (err instanceof UnreadableTrustAnchorError) throw err;
    // Every expected failure is a check. This keeps an unforeseen one a
    // verifier failure to report, never a verdict on the bundle.
    const checks = [check('bundle', 'not-checked', 'bundle_verifier_error')];
    return report(bundle, inputs, checks, emptySummary(checks));
  }
}

async function decide(bundle: unknown, options: VerifyBundleOptions, inputs: BundleReportInputs, roots: Rfc3161Certificate[]): Promise<BundleVerificationReport> {
  const { check: bundleCheck, read } = readBundle(bundle);
  if (!read) return report(bundle, inputs, [bundleCheck], emptySummary([bundleCheck]));
  const registry = options.registry instanceof SchemaRegistry ? options.registry : new SchemaRegistry();
  const checks: BundleCheck[] = [bundleCheck, subjectCheck(read)];
  const existedBy: BundleExistedBy[] = [];

  const { check: digest, digest: recomputed } = digestCheck(read.envelope, registry);
  checks.push(digest, chainLinkCheck(read), custodyCheck(read));

  const ts = recordTimestampChecks(read.envelope, digest, recomputed, roots);
  checks.push(...ts.checks);
  if (ts.genTime) existedBy.push({ at: ts.genTime, source: 'record-timestamp', check: 'ts.record.trust' });

  const expectation = expectationCheck(read.envelope, digest, registry);
  checks.push(expectation, signoffCheck(read, expectation));
  checks.push(
    ...(await recordRuleChecks({
      envelope: read.envelope,
      digest,
      registry,
      credentialsFilled: read.credentials !== null,
      ...(isRecord(options.evmHeaderSources) && { evmHeaderSources: options.evmHeaderSources }),
      ...(options.evmTimeoutMs !== undefined && { evmTimeoutMs: options.evmTimeoutMs }),
    })),
  );

  // The anchor checks take the record's digest as their input, so they wait
  // for it to be decided.
  const sequenceNumber = read.envelope.payload?.sequenceNumber;
  const chainId = typeof read.chain.chainId === 'string' ? read.chain.chainId : undefined;
  const anchorOptions: AnchorVerifyOptions = {
    ...(isIndex(sequenceNumber) && { sequenceNumber }),
    ...(chainId !== undefined && { chainId }),
    ...(options.publisherManifest !== undefined && { publisherManifest: options.publisherManifest }),
    ...(options.evmHeaderSources !== undefined && { evmHeaderSources: options.evmHeaderSources }),
    ...(options.evmNetworks !== undefined && { evmNetworks: options.evmNetworks }),
    ...(options.evmTimeoutMs !== undefined && { evmTimeoutMs: options.evmTimeoutMs }),
    ...(options.trustAnchorsPem !== undefined && { trustAnchorsPem: options.trustAnchorsPem }),
    ...(options.authorities !== undefined && { authorities: options.authorities }),
    publicationMaterial: carriedPublications(read.logs),
  };
  const artifacts = read.envelope.nonRepudiation;
  const artifact = isRecord(artifacts) ? artifacts.anchor : undefined;
  const composed = composedAnchor(read.logs, sequenceNumber);

  let own: AnchorVerification | null = null;
  let newer: AnchorVerification | null = null;
  let anchorCheck: BundleCheck;
  let newerCheck: BundleCheck | undefined;
  // Only an artifact that is there can wait for the digest: with neither
  // `anchor` nor `blockchainAnchor`, the anchor rows report it absent
  // whatever record.digest says (Verification §4.3, §4.6; Bundle §7.8).
  const present = (value: unknown) => value !== undefined && value !== null;
  const hasArtifact = isRecord(artifacts) && (present(artifacts.anchor) || present(artifacts.blockchainAnchor));
  if (!correct(digest)) {
    const reason = hasArtifact ? 'blocked_by:record.digest' : 'absent';
    anchorCheck = check('anchor', 'not-checked', reason);
    checks.push(anchorCheck, ...ANCHOR_STEPS.map((id) => check(id, 'not-checked', reason)));
    if (composed) {
      newerCheck = check('anchor.newer', 'not-checked', 'blocked_by:record.digest');
      checks.push(newerCheck);
    }
  } else {
    own = await verifyAnchor(artifacts, recomputed, anchorOptions);
    anchorCheck = wholeAnchorCheck('anchor', own);
    checks.push(anchorCheck, ...anchorRows(own));
    if (own.anchorValid === true && own.existedBy) existedBy.push({ ...own.existedBy, check: 'anchor' });
    if (composed) {
      newer = await verifyAnchor({ anchor: composed }, recomputed, anchorOptions);
      const logBody = parseCheckpoint(composed.logCheckpoint);
      const anchorBody = parseCheckpoint(composed.anchorCheckpoint);
      newerCheck = wholeAnchorCheck(
        'anchor.newer',
        newer,
        logBody.ok && anchorBody.ok ? { treeSize: logBody.checkpoint.size, anchorSize: anchorBody.checkpoint.size } : undefined,
      );
      checks.push(newerCheck);
      if (newer.anchorValid === true && newer.existedBy) existedBy.push({ ...newer.existedBy, check: 'anchor.newer' });
    }
  }
  checks.push(...consistencyChecks(read.logs, anchorCheck, artifact, newerCheck, composed));
  if (read.anchorPending !== null) checks.push(check('anchor.pending', 'not-checked', 'not_yet_published'));

  for (const key of Object.keys(read.extensions).sort(bytewise)) {
    if (read.extensions[key] !== null) checks.push(check(`extension[${key}]`, 'abstain', 'unsupported_extension'));
  }
  // The frozen slots this verifier does not read yet, when filled (Bundle §8),
  // and members a record bundle does not have: what they carry is not examined,
  // so they are never a pass.
  if (read.relatedRecords !== null) checks.push(check('relatedRecords', 'abstain', 'unsupported_slot'));
  if (read.policy !== null) checks.push(check('policy', 'abstain', 'unsupported_slot'));
  checks.push(...unhashedPayloadRows(read.envelope));
  for (const key of read.unknownMembers) checks.push(check(`member[${key}]`, 'abstain', 'unsupported_member'));
  checks.push(...unreadArtifactChecks(artifacts));

  return report(bundle, inputs, checks, summaryOf(checks, own, newer, existedBy));
}

/**
 * The members of `nonRepudiation` a check above reads, or that are never read
 * (Verification §4.7): the `mandate`, `mandateIssuance` and `confirmation`
 * members are read by the record-rule rows (Verification §4.12, §5).
 */
const READ_ARTIFACTS = new Set(['anchor', 'rfc3161Token', 'rfc3161Metadata', 'webauthnAssertion', 'signoff', 'mandate', 'mandateIssuance', 'confirmation']);

/**
 * A row for each member of `nonRepudiation` with a value that no check reads,
 * in byte order of its name, so that none is passed over in silence
 * (Verification §4.7): `assertionTimestamp` is `ts.assertion.token`, a
 * `blockchainAnchor` beside an `anchor` is `nonRepudiation.blockchainAnchor`
 * (`legacy_blockchain_anchor`; alone it is the anchor rows' abstention), and
 * any other member is `nonRepudiation.<name>`. Each abstains.
 */
function unreadArtifactChecks(artifacts: unknown): BundleCheck[] {
  if (!isRecord(artifacts)) return [];
  const rows: BundleCheck[] = [];
  for (const name of Object.keys(artifacts).sort(bytewise)) {
    const value = artifacts[name];
    if (value === null || value === undefined || READ_ARTIFACTS.has(name)) continue;
    if (name === 'assertionTimestamp') rows.push(check('ts.assertion.token', 'abstain', 'unsupported_artifact'));
    else if (name === 'blockchainAnchor') {
      const anchor = artifacts.anchor;
      if (anchor !== undefined && anchor !== null) rows.push(check('nonRepudiation.blockchainAnchor', 'abstain', 'legacy_blockchain_anchor'));
    } else rows.push(check(`nonRepudiation.${name}`, 'abstain', 'unsupported_artifact'));
  }
  return rows;
}

/**
 * The exit code of Verification §6.6 for a report, under the auditor's regime.
 * Precedence: 2, then 1, then 3, then 4, then 0.
 *
 *   2  the bundle was abstained on or could not be read (`bundle` is not
 *      `checked-correct`);
 *   1  a check is `checked-wrong`;
 *   3  a required check is not `checked-correct`, or a required rung is missing;
 *   4  a check is abstained on or `not-checked` for a reason other than
 *      `not_applicable` or `absent`, unless `allowUnchecked` is `true` or
 *      lists that reason;
 *   0  otherwise.
 *
 * Verification §6.6 also exempts `blocked_by` a check that failed from 4. A
 * report with a failed check is 1 before 4 is considered, so that exemption
 * needs no code.
 *
 * An absent artifact is not an unchecked one, so 0 does not say the record is
 * anchored: a bundle with no anchor and no `anchorPending` reads as a record
 * of a store that does not anchor. A regime that needs the record anchored
 * requires `anchor`, or `anchor.newer` for a record exported before its
 * artifact was filled. Nor does 0 say the record is signed: an assertion
 * stripped from a record whose `signoffExpectation` is `null`, or a stripped
 * `rfc3161Token`, reads as absent. A record captured with
 * `signoffExpectation: { policyDigest }` reads a stripped signature as
 * `signature_missing`, which exits 4.
 *
 * A report that cannot be written in canonical form (`comparableReport`
 * throws, as for a `subject` that holds a lone surrogate) is 2, whatever its
 * rows say (Verification §6.5).
 */
export function bundleExitCode(report: BundleVerificationReport, options: BundleExitOptions = {}): BundleExitCode {
  const checks = Array.isArray(report?.checks) ? report.checks : [];
  const bundle = checks.find((c) => c.id === 'bundle');
  if (!bundle || bundle.outcome !== 'checked-correct') return 2;
  try {
    comparableReport(report);
  } catch {
    return 2;
  }
  if (checks.some((c) => c.outcome === 'checked-wrong')) return 1;
  const required = Array.isArray(options.require) ? options.require : [];
  if (required.some((id) => !checks.some((c) => c.id === id && c.outcome === 'checked-correct'))) return 3;
  const rungs = Array.isArray(options.requireRung) ? options.requireRung : [];
  const reported = new Set(report.summary?.rungs ?? []);
  if (rungs.some((r) => !reported.has(r))) return 3;
  if (options.allowUnchecked !== true) {
    const allowed = new Set<string>(Array.isArray(options.allowUnchecked) ? options.allowUnchecked.filter((r) => typeof r === 'string') : []);
    const unchecked = checks.some(
      (c) =>
        (c.outcome === 'abstain' || (c.outcome === 'not-checked' && c.reason !== 'not_applicable' && c.reason !== 'absent')) &&
        !(typeof c.reason === 'string' && allowed.has(c.reason)),
    );
    if (unchecked) return 4;
  }
  return 0;
}

/** The report without `checkedAt`, in DEO canonical form: what two verifiers' reports are compared by (Verification §6.5). */
export function comparableReport(report: BundleVerificationReport): string {
  const { checkedAt: _checkedAt, ...rest } = report;
  return canonicalSerialize(rest as unknown as Json, Object.keys(rest));
}
