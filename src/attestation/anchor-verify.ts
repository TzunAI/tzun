import { createHash } from 'crypto';
import { keccak256 } from 'ethers';
import { MERKLE_SPEC, verifyMerkleProof } from './merkle';
import { checkOriginBinding, isPlatformNamespace, isTestNamespace, parseCheckpoint, parseOrigin } from './checkpoint';
import type { Checkpoint } from './checkpoint';
import {
  DEFAULT_EVM_TIMEOUT_MS,
  verifyEvmPublication,
  type EvmCalldataPublication,
  type EvmCheckOutcome,
  type EvmCheckResult,
  type EvmFinality,
  type EvmHeaderSource,
  type EvmNetwork,
  type EvmPublicationFacts,
  type PublisherManifest,
} from './blockchain';
import { extractTSTInfo, parseTimestampResponse, readTrustAnchors, verifyTimestampToken } from './rfc3161-verify';
import { UnreadableTrustAnchorError } from './rfc3161-token';
import type { AttestationAnchorReason } from './verify-attestation';
import type { AnchorExistedBy, Rfc3161AnchorPublication } from '@tzun/engine';

/**
 * `verifyAnchor`: a record's `nonRepudiation.anchor` checked under
 * tzun-anchor/1 §10.3, §10.6.
 *
 * The artifact places the record's digest in its chain's evidence log, and
 * that log's checkpoint in the domain's anchor log. The anchor log's own
 * checkpoint hashes to P, and each publication commits to P:
 *
 *   1. the tags are known (`tzun-anchor/1`, `rfc6962`), or the verifier abstains;
 *   2. the members are exactly those of tzun-anchor/1 §8.1 with their types,
 *      and `publications` is a non-empty array (`malformed_anchor`); both
 *      checkpoint bodies parse under the exact form (`malformed_checkpoint`);
 *      both paths are arrays of hashes (`malformed_merkle_path`);
 *   2b. the log origin is in the anchor origin's domain, and is not itself an
 *       anchor origin; a store source log of any kind other than evidence
 *       never holds a record, whether or not a chain id is supplied; and,
 *       when a chain id is supplied, the log is that chain's evidence log (a
 *       platform origin is opaque, so neither its kind nor its chain is
 *       checked);
 *   3. `leafIndex` is `sequenceNumber − 1`, when a sequence number is supplied;
 *   4. the digest is in the log checkpoint (RFC 6962 inclusion);
 *   5. `SHA-256(logCheckpoint)` is in the anchor checkpoint;
 *   6. each publication, on its own, against P = `SHA-256(anchorCheckpoint)`.
 *
 * Steps 1 to 5 run in order and stop at the first that fails; the checks after
 * it report `blocked_by`. The Merkle functions are the engine's.
 *
 * The verdict carries the check catalogue of tzun-anchor/1 §10.7, the ids the
 * TS SDK, the Python SDK and `tzun-verify` share: `anchor` (the anchor as a
 * whole), one check per step, and per publication the dispatch
 * `anchor.publication[i]` and its kind's checks, each suffixed with the
 * publication's index.
 */

/** The `anchorSpec` tag this verifier implements. */
export const ANCHOR_SPEC = 'tzun-anchor/1' as const;

/**
 * `nonRepudiation.anchor` (tzun-anchor/1 §8) and its `rfc3161/1` entry. The
 * declarations are the engine's (`AttestationArtifacts.anchor`); an EVM entry
 * there is `EvmAnchorPublication`.
 */
export type { AnchorArtifact, Rfc3161AnchorPublication } from '@tzun/engine';

/**
 * One publication of P as `verifyAnchor` reads it: an envelope entry, or an
 * EVM entry completed with the export bundle's material (see
 * `publicationMaterial`). A kind this verifier does not implement is
 * abstained on.
 */
export type AnchorPublication = EvmCalldataPublication | Rfc3161AnchorPublication;

/**
 * The verifier's own inputs. None of them comes from the artifact. Each one
 * omitted leaves what it would decide undecided, never passed.
 */
export interface AnchorVerifyOptions {
  /** The record's `payload.sequenceNumber` (hashed). Omitted: step 3 is not checked. */
  sequenceNumber?: number | null;
  /**
   * The chain the record belongs to. Supplied, the log must be its evidence
   * log, except under the platform's opaque origins. Omitted: the chain is
   * not checked.
   */
  chainId?: string | null;
  /** Which wallets may publish for which anchor origin (tzun-anchor/1 §9). Omitted: no EVM publication can be `true`. */
  publisherManifest?: PublisherManifest;
  /** The verifier's header sources, keyed by CAIP-2 chain. Omitted: no EVM publication can be `true`. */
  evmHeaderSources?: Record<string, EvmHeaderSource>;
  /** Overrides or extends the CAIP-2 → network registry. */
  evmNetworks?: Record<string, EvmNetwork>;
  /** One deadline for every header-source call this verification makes. Default 30 s. */
  evmTimeoutMs?: number;
  /**
   * The export bundle's publications for the anchor checkpoint (Bundle §7.4:
   * `anchoring[<anchor origin>].checkpoints[].publications`). An EVM entry
   * supplies the fields the envelope leaves out (`rawTransaction`,
   * `blockHeader`, `txIndex`, `txProof`); where both carry a field, the
   * envelope's value is used. The entry joined to an envelope that carries
   * `transactionId` is the one whose `keccak256(rawTransaction)` is that id
   * (and whose `blockHash`, when both carry one, is the envelope's), so two
   * publications mined in one block are never confused. An envelope with no
   * `transactionId` is joined by `blockHash`, and only when exactly one entry
   * has it.
   */
  publicationMaterial?: unknown[];
  /**
   * Trust anchors for `rfc3161/1` publications, as for record timestamps.
   * With neither this nor `authorities` (nor `TZUN_TSA_TRUST_ANCHORS` or
   * `TZUN_TSA_AUTHORITIES` in the environment), no RFC 3161 publication can
   * be `true`: the SDK's built-in default roots are not a trust input. One
   * that cannot be read is refused: `verifyAnchor` throws
   * `UnreadableTrustAnchorError`.
   */
  trustAnchorsPem?: string[];
  /** Timestamp authorities to trust, by registry key or URL, as for record timestamps. */
  authorities?: string[];
}

/** The checks of steps 1 to 5 (tzun-anchor/1 §10.7), in step order. */
type AnchorStepCheckId =
  | 'anchor.spec'
  | 'anchor.checkpoint'
  | 'anchor.origin'
  | 'anchor.leafIndex'
  | 'anchor.inclusion'
  | 'anchor.anchorInclusion';

/**
 * The tzun-anchor/1 §10.7 checks of a record's anchor that are not a
 * publication's: `anchor`, the anchor as a whole (its outcome follows
 * `anchorValid`, its reason is `anchorReason`), and the checks of steps 1 to 5.
 */
export type AnchorCheckId = 'anchor' | AnchorStepCheckId;

/**
 * The tzun-anchor/1 §10.7 checks of the publication at index `i` of
 * `publications` (tzun-anchor/1 §10.3 step 6), each suffixed with that index:
 * `anchor.publication[i]` (the dispatch), then `anchor.evm.tx[i]` and
 * `anchor.evm.canonical[i]` for `evm-calldata/1`, or `anchor.tsa.token[i]` and
 * `anchor.tsa.trust[i]` for `rfc3161/1`.
 */
export type AnchorPublicationCheckId =
  | `anchor.publication[${number}]`
  | `anchor.evm.tx[${number}]`
  | `anchor.evm.canonical[${number}]`
  | `anchor.tsa.token[${number}]`
  | `anchor.tsa.trust[${number}]`;

/** Why an anchor check was `not-checked`. */
export type AnchorNotCheckedReason =
  /** No anchor artifact is attached. */
  | 'absent'
  /** No sequence number was supplied, so `leafIndex` could not be compared. */
  | 'input_not_supplied:sequence_number'
  /**
   * An earlier check failed, abstained or was not checked, and this one
   * depends on it. A publication's check names the suffixed id
   * (`blocked_by:anchor.evm.tx[0]`).
   */
  | `blocked_by:${AnchorStepCheckId | AnchorPublicationCheckId}`
  /**
   * `anchor.tsa.token` or `anchor.tsa.trust`: the RFC 3161 verifier could not
   * carry out that check's step for want of a cryptographic dependency: an
   * algorithm, or a key's algorithm or curve, it does not implement
   * (tzun-anchor/1 §10.5 step 5).
   */
  | 'missing_dependency'
  /**
   * `anchor.tsa.trust`: the token's certificate path does not validate to a
   * supplied root (tzun-anchor/1 §10.5 step 4): no roots were supplied, no
   * path finds an issuer among them, or a path finds a root and then fails on
   * it. The publication is `null`, `publication_not_checked`.
   */
  | 'no_matching_trust_anchor';

/**
 * One check of the tzun-anchor/1 §10.7 catalogue, with one of the four
 * outcomes of tzun-anchor/1 §10.1. `id`, `outcome`, `reason` and `facts` are
 * what a report carries.
 */
export interface AnchorCheckResult {
  id: AnchorCheckId | AnchorPublicationCheckId;
  outcome: EvmCheckOutcome;
  /** `true` for checked-correct, `false` for checked-wrong, `null` otherwise. */
  value: boolean | null;
  reason?: AttestationAnchorReason | AnchorNotCheckedReason | EvmCheckResult['reason'];
  /**
   * The facts tzun-anchor/1 §10.7 names for the check, re-derived by this
   * verification:
   *
   * - `anchor.origin`, whenever it is checked-correct: `originAuthenticated`,
   *   `namespace` and `chainChecked`, the values of `anchorOriginAuthenticated`,
   *   `anchorNamespace` and `anchorPosition.chainChecked`;
   * - `anchor.leafIndex`: `leafIndexChecked`, `true` when a supplied sequence
   *   number was compared (whether or not it matched), `false` when none was
   *   supplied;
   * - `anchor.evm.tx[i]`, on every outcome once the transaction parses:
   *   `transactionId`, `txType`, `sender` and `signedChainId`;
   * - `anchor.evm.canonical[i]`: `finality` on every outcome once the header
   *   source's chain id matched (absent when the source declares none), and,
   *   when it is checked-correct, `chain`, `namespace`, `network`, `blockTime`
   *   and `inclusion`;
   * - `anchor.tsa.trust[i]`, when it is checked-correct: `genTime` and
   *   `authority` (`authorityOf` the signer certificate: its first
   *   commonName as encoded, or the empty string).
   */
  facts?: Record<string, unknown>;
}

/** One publication's verdict, in the order the artifact lists them. */
export interface AnchorPublicationVerdict {
  index: number;
  /** The kind the artifact states, when it is a string. */
  kind: string | null;
  valid: boolean | null;
  /** Present whenever `valid` is not `true`. */
  reason?: AttestationAnchorReason;
  /**
   * This publication's slice of the tzun-anchor/1 §10.7 catalogue in `checks`:
   * the dispatch `anchor.publication[i]`, then, only when it is
   * checked-correct, its kind's two checks, each suffixed `[i]`.
   */
  checks: AnchorCheckResult[];
  /**
   * `evm-calldata/1`: everything {@link verifyEvmPublication} established,
   * including the block number and hash as the publication claims them. The
   * catalogue's EVM facts are on the checks as well.
   */
  evm?: EvmPublicationFacts;
  /** `rfc3161/1`: read from the token. `genTime` counts as proven only when `valid` is `true`. */
  rfc3161?: { genTime?: string; tsaSubject?: string };
}

/** Where the record sits, as far as `leafIndexChecked`, `chainChecked` and `authenticated` say. */
export interface AnchorPosition {
  /** The evidence log's origin. */
  origin: string;
  leafIndex: number;
  /** The evidence log's size at its anchored checkpoint. */
  treeSize: number;
  anchorOrigin: string;
  anchorLeafIndex: number;
  /** The anchor log's size at the published checkpoint. */
  anchorSize: number;
  /** Whether `leafIndex` was compared with a supplied sequence number. */
  leafIndexChecked: boolean;
  /** Whether the chain segment was compared with a supplied chain id. */
  chainChecked: boolean;
  /** Whether the anchor origin is authenticated: `anchorOriginAuthenticated`. */
  authenticated: boolean;
}

// `AnchorExistedBy` (the earliest proven time P existed by, and what proved
// it) is declared in @tzun/engine, where `VerificationResult.existedBy` uses it.
export type { AnchorExistedBy };

/** The tzun-anchor/1 §10.6 verdict on one record's anchor. */
export interface AnchorVerification {
  /** Whether the artifacts carry an anchor at all, the new artifact or a legacy `blockchainAnchor`. */
  anchorPresent: boolean;
  /**
   * `false` when a step from 2 to 5 fails, or any publication is `false` (an
   * artifact that lies about one publication is a finding). `true` when steps
   * 2 to 5 hold and at least one publication is `true`. `null` otherwise:
   * absent, abstained on, or no publication decided.
   */
  anchorValid: boolean | null;
  /** Present whenever `anchorValid` is not `true` and an anchor is attached. */
  anchorReason?: AttestationAnchorReason;
  /** Steps 4 and 5 together: `null` when they did not run. */
  merkleProofValid: boolean | null;
  /** The strongest publication that is `true`. `null` whenever `anchorValid` is not `true`. */
  anchorPublication: 'evm-calldata' | 'rfc3161' | null;
  /**
   * `true` only when an `evm-calldata/1` publication is `true`: a publisher
   * the verifier's manifest lists for this origin signed P, and the verifier's
   * own header source confirmed the block. An RFC 3161 token authenticates
   * the TSA, not the requester, so an RFC 3161-only anchor proves existed-by
   * and nothing about who named the origin.
   */
  anchorOriginAuthenticated: boolean;
  /** Reported once steps 2 to 5 hold and no publication is `false`. */
  anchorPosition: AnchorPosition | null;
  /** From the manifest entry's CAIP-2 chain through the verifier's registry, never from the artifact. */
  anchorNetwork: EvmNetwork | null;
  /**
   * What the header source counted as final when it confirmed the true EVM
   * publications (its `finality`, see `EvmHeaderSource`): the chain's
   * `finalized` block, or a confirmation depth the verifier chose, which with
   * `acceptNonFinal` may not be final at all. `null` unless an EVM
   * publication is `true`, when the sources behind them disagree, and when
   * the source declares none.
   */
  anchorFinality: EvmFinality | null;
  /**
   * `'test'` whenever the anchor checkpoint parses and its origin begins with
   * `test.`, whatever the manifest says and whatever the verdict (tzun-anchor/1
   * §10.6): labelling yourself test is never an escalation. Otherwise the
   * manifest entry's namespace when the origin is authenticated (`null` when
   * the entries behind the true EVM publications disagree), and `null` when
   * it is not, or when `anchorValid` is `false`. So `'production'` needs an
   * authenticated origin that is not a test origin.
   */
  anchorNamespace: 'production' | 'test' | null;
  /** The earliest time a `true` publication proves P existed by. */
  existedBy: AnchorExistedBy | null;
  /** P, `SHA-256(anchorCheckpoint)` in hex, once the anchor checkpoint parses. */
  p: string | null;
  /**
   * The tzun-anchor/1 §10.7 catalogue for this anchor, in report order:
   * `anchor`, the six step checks (`anchor.spec` to `anchor.anchorInclusion`),
   * then each publication's checks in array order (`anchor.publication[i]`,
   * followed by its kind's checks when the dispatch is checked-correct). The
   * publications are dispatched only once steps 1 to 5 hold, so no
   * publication check is reported before that.
   */
  checks: AnchorCheckResult[];
  /** One verdict per publication; empty unless steps 1 to 5 hold. */
  publications: AnchorPublicationVerdict[];
}

const STEP_CHECKS: readonly AnchorStepCheckId[] = [
  'anchor.spec',
  'anchor.checkpoint',
  'anchor.origin',
  'anchor.leafIndex',
  'anchor.inclusion',
  'anchor.anchorInclusion',
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isPresent(value: unknown): boolean {
  return value !== undefined && value !== null;
}

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** The members of `nonRepudiation.anchor` (tzun-anchor/1 §8.1), and no others. */
const ANCHOR_MEMBERS: ReadonlySet<string> = new Set([
  'anchorSpec',
  'merkleSpec',
  'leafIndex',
  'logCheckpoint',
  'logPath',
  'anchorLeafIndex',
  'anchorCheckpoint',
  'anchorPath',
  'publications',
]);

/** A JSON integer in [0, 2^53 − 1] (tzun-anchor/1 notation). */
function isIndex(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** A hash under Tree §4: a string of exactly 64 hex digits, in either case. */
function isHash(value: unknown): boolean {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Step 2's shape (tzun-anchor/1 §8.1, §10.3): exactly the nine members, the two
 * indices JSON integers in [0, 2^53 − 1], and `publications` a non-empty array.
 * The bodies and the paths are left to the rest of step 2, which gives them
 * their own reasons; a member that is absent is a shape failure all the same.
 */
function anchorShapeHolds(a: Record<string, unknown>): boolean {
  // A member whose value is `undefined` is absent, as it is once serialised.
  const keys = Object.keys(a).filter((k) => a[k] !== undefined);
  if (keys.length !== ANCHOR_MEMBERS.size || !keys.every((k) => ANCHOR_MEMBERS.has(k))) return false;
  if (!isIndex(a.leafIndex) || !isIndex(a.anchorLeafIndex)) return false;
  return Array.isArray(a.publications) && a.publications.length > 0;
}

function check(
  id: AnchorCheckId | AnchorPublicationCheckId,
  outcome: EvmCheckOutcome,
  reason?: AnchorCheckResult['reason'],
  facts?: Record<string, unknown>,
): AnchorCheckResult {
  const value = outcome === 'checked-correct' ? true : outcome === 'checked-wrong' ? false : null;
  return {
    id,
    outcome,
    value,
    ...(reason !== undefined && { reason }),
    ...(facts !== undefined && { facts }),
  };
}

/** Every step check after `id` reports that it was blocked by `id`. */
function blockedAfter(id: AnchorStepCheckId): AnchorCheckResult[] {
  return STEP_CHECKS.slice(STEP_CHECKS.indexOf(id) + 1).map((later) =>
    check(later, 'not-checked', `blocked_by:${id}`),
  );
}

/** The tzun-anchor/1 §10.1 abstentions: a construction or version this verifier does not implement. */
const ABSTENTIONS: ReadonlySet<string> = new Set([
  'unsupported_anchor_spec',
  'unsupported_merkle_spec',
  'legacy_blockchain_anchor',
  'unsupported_publication_kind',
  'unsupported_evm_tx_type',
]);

/**
 * Check `anchor` (tzun-anchor/1 §10.7), from the anchor fields: checked-correct
 * when `anchorValid` is `true`, checked-wrong when it is `false`, and otherwise
 * abstain or not-checked as `anchorReason` is or is not an abstention, with
 * `anchorReason` as its reason. With nothing attached it is not-checked,
 * `absent`.
 */
function anchorCheck(v: AnchorVerification): AnchorCheckResult {
  if (v.anchorValid === true) return check('anchor', 'checked-correct');
  if (v.anchorValid === false) return check('anchor', 'checked-wrong', v.anchorReason);
  if (!v.anchorPresent) return check('anchor', 'not-checked', 'absent');
  return check('anchor', ABSTENTIONS.has(v.anchorReason as string) ? 'abstain' : 'not-checked', v.anchorReason);
}

/**
 * The verdict with its whole tzun-anchor/1 §10.7 catalogue: `checks` arrives
 * holding the step checks, and leaves with `anchor` before them and each
 * publication's checks after them.
 */
function withCatalogue(v: AnchorVerification): AnchorVerification {
  return { ...v, checks: [anchorCheck(v), ...v.checks, ...v.publications.flatMap((pub) => pub.checks)] };
}

function verdict(fields: Partial<AnchorVerification> & Pick<AnchorVerification, 'anchorPresent' | 'anchorValid' | 'checks'>): AnchorVerification {
  return {
    merkleProofValid: null,
    anchorPublication: null,
    anchorOriginAuthenticated: false,
    anchorPosition: null,
    anchorNetwork: null,
    anchorFinality: null,
    anchorNamespace: null,
    existedBy: null,
    p: null,
    publications: [],
    ...fields,
  };
}

/**
 * Verify a record's anchor (tzun-anchor/1 §10.3). Never throws on the artifact.
 *
 * The RFC 3161 trust anchors the caller supplies (`trustAnchorsPem`,
 * `authorities`, or the environment) are read first, whatever the artifact
 * holds: one that cannot be read is refused, and the call throws
 * `UnreadableTrustAnchorError` (Verification §3.1).
 *
 * @param artifacts - the record's `nonRepudiation`. `anchor` is read from it;
 *   a legacy `blockchainAnchor` alone is abstained on
 *   (`legacy_blockchain_anchor`).
 * @param digest - the record's `integrity.canonicalDigest`.
 */
export async function verifyAnchor(
  artifacts: unknown,
  digest: string,
  options: AnchorVerifyOptions = {},
): Promise<AnchorVerification> {
  const opts = isRecord(options) ? (options as AnchorVerifyOptions) : {};
  const given = (value: unknown) => value !== undefined && !(Array.isArray(value) && value.length === 0);
  if (tsaTrustSupplied(opts) || given(opts.trustAnchorsPem) || given(opts.authorities)) {
    readTrustAnchors({
      ...(given(opts.trustAnchorsPem) && { trustAnchorsPem: opts.trustAnchorsPem }),
      ...(given(opts.authorities) && { authorities: opts.authorities }),
    });
  }
  let present = false;
  try {
    const bag = isRecord(artifacts) ? artifacts : {};
    present = isPresent(bag.anchor) || isPresent(bag.blockchainAnchor);
    return withCatalogue(await decide(bag, digest, opts));
  } catch (err) {
    if (err instanceof UnreadableTrustAnchorError) throw err;
    // Every expected failure returns a verdict. This keeps an unforeseen one
    // undecided rather than an exception or a verdict.
    return withCatalogue(
      verdict({
        anchorPresent: present,
        anchorValid: null,
        ...(present && { anchorReason: 'anchor_verifier_error' as const }),
        checks: STEP_CHECKS.map((id) => check(id, 'not-checked', present ? 'anchor_verifier_error' : 'absent')),
      }),
    );
  }
}

async function decide(
  bag: Record<string, unknown>,
  digest: string,
  options: AnchorVerifyOptions,
): Promise<AnchorVerification> {
  // ---- Step 1: the tags ------------------------------------------------------
  if (!isPresent(bag.anchor)) {
    if (isPresent(bag.blockchainAnchor)) {
      return verdict({
        anchorPresent: true,
        anchorValid: null,
        anchorReason: 'legacy_blockchain_anchor',
        checks: [check('anchor.spec', 'abstain', 'legacy_blockchain_anchor'), ...blockedAfter('anchor.spec')],
      });
    }
    return verdict({
      anchorPresent: false,
      anchorValid: null,
      checks: STEP_CHECKS.map((id) => check(id, 'not-checked', 'absent')),
    });
  }

  // A non-object carries no `anchorSpec`, and an absent tag is abstained on.
  const a = isRecord(bag.anchor) ? bag.anchor : {};
  const abstain = (reason: AttestationAnchorReason) =>
    verdict({
      anchorPresent: true,
      anchorValid: null,
      anchorReason: reason,
      checks: [check('anchor.spec', 'abstain', reason), ...blockedAfter('anchor.spec')],
    });
  if (a.anchorSpec !== ANCHOR_SPEC) return abstain('unsupported_anchor_spec');
  if (a.merkleSpec !== MERKLE_SPEC) return abstain('unsupported_merkle_spec');

  const checks: AnchorCheckResult[] = [check('anchor.spec', 'checked-correct')];
  // tzun-anchor/1 §10.6: a test origin is 'test' whatever the verdict, so a
  // failure after the anchor checkpoint parsed reports it too.
  let testOrigin = false;
  const fail = (
    id: AnchorStepCheckId,
    reason: AttestationAnchorReason,
    extra: Partial<AnchorVerification> = {},
    facts?: Record<string, unknown>,
  ) =>
    verdict({
      anchorPresent: true,
      anchorValid: false,
      anchorReason: reason,
      checks: [...checks, check(id, 'checked-wrong', reason, facts), ...blockedAfter(id)],
      anchorNamespace: testOrigin ? 'test' : null,
      ...extra,
    });

  // ---- Step 2: shape, both checkpoints, both paths ---------------------------
  if (!anchorShapeHolds(a)) return fail('anchor.checkpoint', 'malformed_anchor');
  const logParsed = parseCheckpoint(a.logCheckpoint);
  const anchorParsed = parseCheckpoint(a.anchorCheckpoint);
  testOrigin = anchorParsed.ok && isTestNamespace(anchorParsed.checkpoint.origin);
  if (!logParsed.ok || !anchorParsed.ok) return fail('anchor.checkpoint', 'malformed_checkpoint');
  const log: Checkpoint = logParsed.checkpoint;
  const anchor: Checkpoint = anchorParsed.checkpoint;
  const pathsHold = [a.logPath, a.anchorPath].every((path) => Array.isArray(path) && path.every(isHash));
  if (!pathsHold) return fail('anchor.checkpoint', 'malformed_merkle_path');
  const p = sha256Hex(anchor.body);
  checks.push(check('anchor.checkpoint', 'checked-correct'));

  // ---- Step 2b: origin binding -----------------------------------------------
  // A log checkpoint that names the anchor origin itself is refused here: the
  // log origin's rest must not be `anchors`.
  const binding = checkOriginBinding(anchor.origin, log.origin, options.chainId);
  if (!binding.ok) return fail('anchor.origin', binding.reason, { p });
  // A store source log of another kind (`custody`, say) never holds a record:
  // a record has a leaf in its own chain's evidence log and nowhere else. The
  // rule holds without a chain id. A platform log's name is an opaque key, so
  // its kind cannot be read; the leaf preimage rule keeps its other kinds'
  // leaves out of the record domain. The shared checkOriginBinding stays as it
  // is, since a source log of any kind is in its domain.
  const logOrigin = parseOrigin(log.origin);
  if (logOrigin?.kind === 'log' && !isPlatformNamespace(logOrigin.namespace)) {
    return fail('anchor.origin', 'chain_id_mismatch', { p });
  }
  // The origin's facts as they stand if a later step fails: nothing is
  // authenticated, and the namespace is known only for a test origin. They
  // are restated below once the publications have been decided.
  const originCheckAt = checks.length;
  checks.push(
    check('anchor.origin', 'checked-correct', undefined, {
      originAuthenticated: false,
      namespace: testOrigin ? 'test' : null,
      chainChecked: binding.chainChecked,
    }),
  );

  // ---- Step 3: leafIndex = sequenceNumber − 1 --------------------------------
  // Not checked blocks nothing: no later step depends on it.
  const leafIndex = a.leafIndex;
  const seq = options.sequenceNumber;
  const leafIndexChecked = isPresent(seq);
  if (leafIndexChecked) {
    const matches = Number.isSafeInteger(seq) && (seq as number) >= 1 && leafIndex === (seq as number) - 1;
    if (!matches) return fail('anchor.leafIndex', 'leaf_index_mismatch', { p }, { leafIndexChecked: true });
    checks.push(check('anchor.leafIndex', 'checked-correct', undefined, { leafIndexChecked: true }));
  } else {
    checks.push(check('anchor.leafIndex', 'not-checked', 'input_not_supplied:sequence_number', { leafIndexChecked: false }));
  }

  // ---- Step 4: the digest is in the log checkpoint ----------------------------
  // Step 2 held the index and the path to their types, so what fails here is
  // the proof: an index outside the tree, or a path that does not lead to the
  // root.
  if (!verifyMerkleProof(digest, leafIndex as number, log.size, a.logPath as string[], log.root)) {
    return fail('anchor.inclusion', 'merkle_proof_invalid', { p, merkleProofValid: false });
  }
  checks.push(check('anchor.inclusion', 'checked-correct'));

  // ---- Step 5: the log checkpoint is in the anchor checkpoint -----------------
  const logLeaf = sha256Hex(log.body);
  if (!verifyMerkleProof(logLeaf, a.anchorLeafIndex as number, anchor.size, a.anchorPath as string[], anchor.root)) {
    return fail('anchor.anchorInclusion', 'anchor_proof_invalid', { p, merkleProofValid: false });
  }
  checks.push(check('anchor.anchorInclusion', 'checked-correct'));

  // ---- Step 6: each publication against P ------------------------------------
  const pubs = await verifyPublications(a.publications as unknown[], p, anchor.origin, options);

  // tzun-anchor/1 §10.6: `false` when any publication is; `true` when one is;
  // otherwise `null`, with `publication_not_checked` when any publication was
  // not checked, and otherwise the first publication's abstention.
  const firstFalse = pubs.find((v) => v.valid === false);
  const anyTrue = pubs.some((v) => v.valid === true);
  let anchorValid: boolean | null;
  let anchorReason: AttestationAnchorReason | undefined;
  if (firstFalse) {
    anchorValid = false;
    anchorReason = firstFalse.reason;
  } else if (anyTrue) {
    anchorValid = true;
  } else {
    anchorValid = null;
    const undecided = pubs.filter((v) => v.valid === null);
    anchorReason = undecided.some((v) => !PUBLICATION_ABSTENTIONS.has(v.reason as string))
      ? 'publication_not_checked'
      : undecided[0]?.reason;
  }

  // Facts come only from publications that are `true`, and none are reported
  // for an artifact that lies about a publication.
  const trusted = anchorValid === false ? [] : pubs.filter((v) => v.valid === true);
  const evmTrue = trusted.filter((v) => v.kind === 'evm-calldata/1' && v.evm);
  const tsaTrue = trusted.filter((v) => v.kind === 'rfc3161/1' && v.rfc3161?.genTime);
  const authenticated = evmTrue.length > 0;

  const single = <T>(values: T[]): T | null => {
    const distinct = [...new Set(values)];
    return distinct.length === 1 ? distinct[0] : null;
  };
  // tzun-anchor/1 §10.6: a test origin is 'test' whatever the manifest says and
  // whatever the verdict (labelling yourself test is never an escalation);
  // otherwise an authenticated origin takes its manifest entry's namespace.
  let anchorNamespace: 'production' | 'test' | null;
  if (testOrigin) {
    anchorNamespace = 'test';
  } else if (anchorValid === false) {
    anchorNamespace = null;
  } else if (authenticated) {
    anchorNamespace = single(evmTrue.map((v) => v.evm!.namespace ?? null));
  } else {
    anchorNamespace = null;
  }
  const anchorNetwork = authenticated ? single(evmTrue.map((v) => v.evm!.network ?? null)) : null;
  // Compared by value: two sources that both count 64 confirmations agree.
  const finalities = evmTrue.map((v) => v.evm!.finality ?? null);
  const agreed = single(finalities.map((f) => JSON.stringify(f)));
  const anchorFinality: EvmFinality | null = authenticated && agreed !== null ? (JSON.parse(agreed) as EvmFinality | null) : null;

  const bounds: AnchorExistedBy[] = [
    ...evmTrue
      .filter((v) => typeof v.evm!.blockTime === 'string')
      .map((v) => ({ at: v.evm!.blockTime as string, source: 'evm-calldata' as const })),
    ...tsaTrue.map((v) => ({ at: v.rfc3161!.genTime as string, source: 'rfc3161' as const })),
  ];
  // Earliest first; on a tie the EVM publication, which also authenticates the origin.
  bounds.sort((x, y) => Date.parse(x.at) - Date.parse(y.at) || (x.source === 'evm-calldata' ? -1 : 1));
  const existedBy = bounds[0] ?? null;

  checks[originCheckAt] = check('anchor.origin', 'checked-correct', undefined, {
    originAuthenticated: authenticated,
    namespace: anchorNamespace,
    chainChecked: binding.chainChecked,
  });

  const anchorPosition: AnchorPosition | null =
    anchorValid === false
      ? null
      : {
          origin: log.origin,
          leafIndex: leafIndex as number,
          treeSize: log.size,
          anchorOrigin: anchor.origin,
          anchorLeafIndex: a.anchorLeafIndex as number,
          anchorSize: anchor.size,
          leafIndexChecked,
          chainChecked: binding.chainChecked,
          authenticated,
        };

  return {
    anchorPresent: true,
    anchorValid,
    ...(anchorValid !== true && anchorReason !== undefined && { anchorReason }),
    merkleProofValid: true,
    anchorPublication: anchorValid !== true ? null : authenticated ? 'evm-calldata' : tsaTrue.length > 0 ? 'rfc3161' : null,
    anchorOriginAuthenticated: anchorValid !== false && authenticated,
    anchorPosition,
    anchorNetwork: anchorValid === false ? null : anchorNetwork,
    anchorFinality: anchorValid === false ? null : anchorFinality,
    anchorNamespace,
    existedBy: anchorValid === false ? null : existedBy,
    p,
    checks,
    publications: pubs,
  };
}

/** The publication-level abstentions (tzun-anchor/1 §10.1): a construction this verifier does not implement. */
const PUBLICATION_ABSTENTIONS: ReadonlySet<string> = new Set(['unsupported_publication_kind', 'unsupported_evm_tx_type']);

/** Check `id` of the publication at `index`: the id suffixed `[index]` (tzun-anchor/1 §10.3 step 6). */
function at(id: 'anchor.publication' | 'anchor.evm.tx' | 'anchor.evm.canonical' | 'anchor.tsa.token' | 'anchor.tsa.trust', index: number): AnchorPublicationCheckId {
  return `${id}[${index}]`;
}

/**
 * Each publication's verdict, in array order (tzun-anchor/1 §10.3 step 6). Step
 * 2 made `publications` a non-empty array. The dispatch is check
 * `anchor.publication[i]`: an element that is not an object is `false`,
 * `malformed_publication`; an absent, non-string or unknown kind abstains,
 * `unsupported_publication_kind`; in both cases no other check of the element
 * is reported. A kind this verifier implements passes it, and its own checks
 * follow.
 */
async function verifyPublications(
  publications: unknown[],
  p: string,
  anchorOrigin: string,
  options: AnchorVerifyOptions,
): Promise<AnchorPublicationVerdict[]> {
  const requested = options.evmTimeoutMs;
  const timeoutMs =
    typeof requested === 'number' && Number.isFinite(requested) && requested > 0 ? requested : DEFAULT_EVM_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;

  const out: AnchorPublicationVerdict[] = [];
  for (let index = 0; index < publications.length; index++) {
    const pub = publications[index];
    const dispatch = at('anchor.publication', index);
    if (!isRecord(pub)) {
      out.push({
        index,
        kind: null,
        valid: false,
        reason: 'malformed_publication',
        checks: [check(dispatch, 'checked-wrong', 'malformed_publication')],
      });
      continue;
    }
    const kind = typeof pub.kind === 'string' ? pub.kind : null;
    let decided: AnchorPublicationVerdict;
    if (kind === 'evm-calldata/1') {
      decided = await verifyEvm(index, pub, p, anchorOrigin, options, deadline);
    } else if (kind === 'rfc3161/1') {
      decided = await verifyRfc3161(index, pub, p, options);
    } else {
      out.push({
        index,
        kind,
        valid: null,
        reason: 'unsupported_publication_kind',
        checks: [check(dispatch, 'abstain', 'unsupported_publication_kind')],
      });
      continue;
    }
    out.push({ ...decided, checks: [check(dispatch, 'checked-correct'), ...decided.checks] });
  }
  return out;
}

/** `keccak256` of a `0x`-hex raw transaction, lowercase; `null` for anything else. */
function rawTransactionId(raw: unknown): string | null {
  if (typeof raw !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(raw)) return null;
  return keccak256(raw).toLowerCase();
}

/**
 * The envelope's EVM publication, completed from the bundle's material for
 * the same transaction (see `publicationMaterial`). The envelope's own fields
 * are kept. With no matching entry, the envelope is returned as it is.
 *
 * The result is built from entries, not by assignment: a `__proto__` member,
 * which JSON.parse keeps as an own property, stays an ordinary key and never
 * becomes the result's prototype, as in the Python SDK.
 */
function withMaterial(pub: Record<string, unknown>, material: unknown): Record<string, unknown> {
  if (!Array.isArray(material)) return pub;
  const entries = material.filter(
    (m): m is Record<string, unknown> => isRecord(m) && m.kind === 'evm-calldata/1',
  );
  const inBlock = (m: Record<string, unknown>) =>
    typeof pub.blockHash === 'string' &&
    typeof m.blockHash === 'string' &&
    m.blockHash.toLowerCase() === pub.blockHash.toLowerCase();

  let entry: Record<string, unknown> | undefined;
  if (typeof pub.transactionId === 'string') {
    const id = pub.transactionId.toLowerCase();
    entry = entries.find(
      (m) =>
        rawTransactionId(m.rawTransaction) === id &&
        (!isPresent(m.blockHash) || !isPresent(pub.blockHash) || inBlock(m)),
    );
  } else {
    const candidates = entries.filter(inBlock);
    entry = candidates.length === 1 ? candidates[0] : undefined;
  }
  if (!entry) return pub;
  return Object.fromEntries([
    ...Object.entries(entry),
    ...Object.entries(pub).filter(([, value]) => isPresent(value)),
  ]);
}

async function verifyEvm(
  index: number,
  pub: Record<string, unknown>,
  p: string,
  anchorOrigin: string,
  options: AnchorVerifyOptions,
  deadline: number,
): Promise<AnchorPublicationVerdict> {
  const result = await verifyEvmPublication({
    publication: withMaterial(pub, options.publicationMaterial) as unknown as EvmCalldataPublication,
    p,
    anchorOrigin,
    manifest: options.publisherManifest as PublisherManifest,
    headerSources: options.evmHeaderSources,
    networks: options.evmNetworks,
    timeoutMs: Math.max(1, deadline - Date.now()),
  });
  const f = result.facts;
  // tzun-anchor/1 §10.7: the offline facts once the transaction parsed,
  // whatever the outcome.
  const txFacts =
    f.sender !== undefined
      ? pick(f, ['transactionId', 'txType', 'sender', 'signedChainId'])
      : undefined;
  // tzun-anchor/1 §10.4 item 14: `finality` on every outcome once the source's
  // chain id matched; the rest only when the chain confirmed the block.
  const canonicalFacts = {
    ...(f.finality !== undefined && { finality: f.finality }),
    ...(result.checks.canonical.outcome === 'checked-correct' && pick(f, ['chain', 'namespace', 'network', 'blockTime', 'inclusion'])),
  };
  const suffixed = (reason: EvmCheckResult['reason']) =>
    reason === 'blocked_by:anchor.evm.tx' ? (`blocked_by:${at('anchor.evm.tx', index)}` as const) : reason;
  return {
    index,
    kind: 'evm-calldata/1',
    valid: result.valid,
    ...(result.valid !== true && result.reason !== undefined && { reason: result.reason }),
    checks: [
      check(at('anchor.evm.tx', index), result.checks.tx.outcome, suffixed(result.checks.tx.reason), txFacts),
      check(
        at('anchor.evm.canonical', index),
        result.checks.canonical.outcome,
        suffixed(result.checks.canonical.reason),
        Object.keys(canonicalFacts).length > 0 ? canonicalFacts : undefined,
      ),
    ],
    evm: f,
  };
}

/** The members of `facts` named in `keys` that are present, in that order. */
function pick(facts: EvmPublicationFacts, keys: ReadonlyArray<keyof EvmPublicationFacts>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of keys) if (facts[key] !== undefined) out[key] = facts[key];
  return out;
}

/** How `extractTSTInfo` names the SHA-256 imprint algorithm (OID 2.16.840.1.101.3.4.2.1). */
const SHA256_IMPRINT = 'SHA-256';

/**
 * Whether the verifier was given TSA trust anchors of its own: `trustAnchorsPem`
 * or `authorities` in the options, or `TZUN_TSA_TRUST_ANCHORS` or
 * `TZUN_TSA_AUTHORITIES` in the environment. The roots this SDK ships as its
 * default trust store never count, because an RFC 3161 publication is `true`
 * only under a root the caller supplied (tzun-anchor/1 §10.5 step 4).
 */
function tsaTrustSupplied(options: AnchorVerifyOptions): boolean {
  const listed = (value: unknown) => Array.isArray(value) && value.length > 0;
  const configured = (name: string) => {
    const value = process.env[name];
    return typeof value === 'string' && value.trim().length > 0;
  };
  return (
    listed(options.trustAnchorsPem) ||
    listed(options.authorities) ||
    configured('TZUN_TSA_TRUST_ANCHORS') ||
    configured('TZUN_TSA_AUTHORITIES')
  );
}

function isoTime(value: unknown): string | undefined {
  return value instanceof Date && !Number.isNaN(value.getTime()) ? value.toISOString() : undefined;
}

/**
 * An `rfc3161/1` publication (tzun-anchor/1 §10.5), at index `index`:
 * its checks are `anchor.tsa.token[index]` and `anchor.tsa.trust[index]`.
 *
 * - `true` when the token's certificate path reaches a root the caller
 *   supplied, its imprint is `{SHA-256, P}`, its CMS signature verifies, a
 *   signingCertificate(V2) binds its signer certificate, and that certificate
 *   has a critical extendedKeyUsage whose only purpose is timestamping
 *   (`verifyTimestampToken`, tzun-anchor/1 §10.5 steps 1 to 4).
 * - `false` for an unreadable token (with trust anchors supplied, one that is
 *   not DER is unreadable), and for a token whose path to a supplied root
 *   validates in full and whose imprint (algorithm or value), CMS signature,
 *   signer binding or extendedKeyUsage then fails.
 * - `null`, `publication_not_checked`, when a step needs an algorithm this
 *   verifier does not implement (tzun-anchor/1 §10.5 step 5), with
 *   `missing_dependency` on the check of that step: `anchor.tsa.token[i]` for
 *   the signer's key or the token's signature, and `anchor.tsa.trust[i]`,
 *   the token check correct, for the key of a certificate that issues
 *   another on the path to a supplied root.
 * - `null`, `publication_not_checked`, with `no_matching_trust_anchor` on
 *   `anchor.tsa.trust[i]` (tzun-anchor/1 §10.1), when the caller supplied no
 *   trust anchors (no path can reach a supplied root) and for every other
 *   path failure. That covers a path that finds no issuer among the supplied
 *   roots, and also one that finds a root and then fails on it: a certificate outside
 *   its validity window at genTime, or a certificate that names a supplied
 *   root as issuer but whose signature does not verify under that root's key.
 *   The chain result `verifyTimestampToken` returns does not say which link
 *   failed, so those cases cannot yet be told apart and reported as `false`.
 */
async function verifyRfc3161(
  index: number,
  pub: Record<string, unknown>,
  p: string,
  options: AnchorVerifyOptions,
): Promise<AnchorPublicationVerdict> {
  const base = { index, kind: 'rfc3161/1' as const };
  const TOKEN = at('anchor.tsa.token', index);
  const TRUST = at('anchor.tsa.trust', index);
  const unreadable = (): AnchorPublicationVerdict => ({
    ...base,
    valid: false,
    reason: 'malformed_publication',
    checks: [
      check(TOKEN, 'checked-wrong', 'malformed_publication'),
      check(TRUST, 'not-checked', `blocked_by:${TOKEN}`),
    ],
  });
  if (typeof pub.token !== 'string' || pub.token.length === 0) return unreadable();

  let imprintAlgorithm: string;
  let tokenGenTime: string | undefined;
  try {
    const tstInfo = extractTSTInfo(parseTimestampResponse(pub.token));
    imprintAlgorithm = tstInfo.messageImprint.hashAlgorithm;
    tokenGenTime = isoTime(tstInfo.genTime);
  } catch {
    return unreadable();
  }

  if (!tsaTrustSupplied(options)) {
    return {
      ...base,
      valid: null,
      reason: 'publication_not_checked',
      checks: [
        check(TOKEN, 'not-checked', `blocked_by:${TRUST}`),
        check(TRUST, 'not-checked', 'no_matching_trust_anchor'),
      ],
      rfc3161: tokenGenTime !== undefined ? { genTime: tokenGenTime } : {},
    };
  }

  const result = await verifyTimestampToken(pub.token, p, {
    ...(options.trustAnchorsPem ? { trustAnchorsPem: options.trustAnchorsPem } : {}),
    ...(options.authorities ? { authorities: options.authorities } : {}),
  });
  if (result.reason === 'unparseable_token') return unreadable();

  const genTime = isoTime(result.genTime);
  const facts = {
    ...(genTime !== undefined && { genTime }),
    ...(result.tsaSubject !== undefined && { tsaSubject: result.tsaSubject }),
  };
  if (result.reason === 'missing_dependency') {
    // tzun-anchor/1 §10.5 step 5: on the check whose step needs what this
    // verifier lacks. Steps 1 to 3 held when only the path's signatures
    // could not be checked.
    const trustStep = result.signatureValid === true && result.digestMatch === true;
    return {
      ...base,
      valid: null,
      reason: 'publication_not_checked',
      checks: trustStep
        ? [check(TOKEN, 'checked-correct'), check(TRUST, 'not-checked', 'missing_dependency')]
        : [check(TOKEN, 'not-checked', 'missing_dependency'), check(TRUST, 'not-checked', `blocked_by:${TOKEN}`)],
      rfc3161: facts,
    };
  }
  if (result.certificateChainValid !== true) {
    return {
      ...base,
      valid: null,
      reason: 'publication_not_checked',
      checks: [
        check(TOKEN, 'not-checked', `blocked_by:${TRUST}`),
        check(TRUST, 'not-checked', 'no_matching_trust_anchor'),
      ],
      rfc3161: facts,
    };
  }
  // tzun-anchor/1 §10.7: the trust check's facts, when it holds. `authority` is
  // always one of them, the empty string included.
  const trust = check(TRUST, 'checked-correct', undefined, {
    ...(genTime !== undefined && { genTime }),
    authority: result.tsaSubject ?? '',
  });
  // tzun-anchor/1 §7.3, §10.5 step 2: the imprint is {sha256, P}. The same 32
  // bytes under another algorithm's OID is not a timestamp of P.
  const imprintMatches = result.digestMatch === true && imprintAlgorithm === SHA256_IMPRINT;
  if (result.valid === true && imprintMatches) {
    return { ...base, valid: true, checks: [check(TOKEN, 'checked-correct'), trust], rfc3161: facts };
  }
  const reason: AttestationAnchorReason = !imprintMatches ? 'rfc3161_imprint_mismatch' : 'rfc3161_signature_invalid';
  return {
    ...base,
    valid: false,
    reason,
    checks: [check(TOKEN, 'checked-wrong', reason), trust],
    rfc3161: facts,
  };
}
