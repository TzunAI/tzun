import { stepModelDigests } from '../sdk/step-models';
import { StorageAdapter } from '@tzun/engine';
import { MonitoringEventBus } from './event-bus';
import { SchemaRegistry } from '@tzun/engine';
import { canonicalSerialize } from '@tzun/engine';
import { computeDigest } from '@tzun/engine';
import { verifyChainCompleteness, ChainCompletenessResult } from '@tzun/engine';
import { verifyCustodyTrail, verifyCustodyLedger, toCustodyLedgerEntry } from '@tzun/engine';
import type {
  CustodyLedgerFailure,
  CustodyRelinkFailure,
  CustodyTrailFailure,
  RelinkRecord,
  StoredCustodyEntry,
} from '@tzun/engine';
import { verifyEnvelope, VerifyEnvelopeOptions } from '@tzun/engine';
import { AttestationPresenceCounts, AttestationValidityCounts, ScannerConfig, ScannerState, ScanSummary } from '@tzun/engine';
import { EvidenceEnvelope } from '@tzun/engine';
import type { AttestationArtifacts, EvmFinality } from '@tzun/engine';
import {
  verifyAttestation,
  webauthnChallengeForDigest,
  AttestationVerifyOptions,
} from '../attestation/verify-attestation';
import { verifyAnchor, type AnchorVerification, type AnchorVerifyOptions } from '../attestation/anchor-verify';
import { readTrustAnchors } from '../attestation/rfc3161-verify';
import { UnreadableTrustAnchorError } from '../attestation/rfc3161-token';
import { CredentialStore } from '../attestation/credential-store';
import type { EvmHeaderSource } from '../attestation/blockchain';
import { ChainScope, chainUpperBound, resolveChainScopes } from '../storage/chain-bounds';
import { computeRelinkDigest } from './recovery-manager';
import { rpcErrorText } from '../anchoring/evm-chain';
import {
  StoreLogs,
  checkAnchoredLogs,
  newPassReads,
  passHeaderSource,
  publicationMaterial,
  readOnce,
  scannerChainFinality,
  sharedPassReads,
  type AnchorScanCache,
  type EvmPublicationMaterial,
  type PassReads,
  type ScannerAnchoringDeps,
  type ScannerEvmTransaction,
  type SignedTransaction,
} from './anchor-log-checks';
import { transplantedFrom } from '../sdk/anchor-state';
import { expireEndedMandates, type MandateListingStore } from '../sdk/mandates/expiry';
import { evidenceLogOrigin, logStoreFor } from '../storage/log-store';
import { checkMandateConsumption, earlierFieldSet, type MandateEventRow } from '@tzun/engine';

export { runAnchorScanPass } from './anchor-log-checks';
export type {
  AnchorScanCache,
  AnchorScanCarry,
  ScannerAnchoringDeps,
  ScannerEvmChain,
  ScannerEvmTransaction,
  ScannerLogScope,
} from './anchor-log-checks';

/** Anything a `custody_trail_invalid` event carries: the three custody checks' findings. */
type CustodyFailure = CustodyTrailFailure | CustodyLedgerFailure | CustodyRelinkFailure;

/** A finding's identity — what it is and where it is — so one is reported once. */
function custodyFailureKey(f: CustodyFailure): string {
  const at = f as { index?: number; rowId?: string };
  return `${f.reason}|${at.index ?? ''}|${at.rowId ?? ''}`;
}

/** What one phase-1 worker (and the phase as a whole) reports back. */
interface Phase1Result {
  recordsChecked: number;
  issues: number;
  /** `custody_trail_invalid` events emitted — at most one per record. */
  custodyTrailInvalid: number;
  /** `record_rule_violated` events emitted. */
  recordRuleViolations: number;
  attestationPresence: AttestationPresenceCounts;
}

/** What the chain phase reports back for one chain. */
interface Phase2Result {
  /** `chain_break` events emitted. */
  chainBreaks: number;
  /** `sequence_gap` events emitted — one per missing run, not per record. */
  sequenceGaps: number;
  /** `duplicate_sequence` events emitted. */
  duplicateSequences: number;
  /** `digest_superseded` events emitted. */
  digestSuperseded: number;
  /** `captured_at_regression` events emitted. */
  timeRegressions: number;
  /**
   * `digest_differs_from_logged_leaf`, `anchor_stripped` and
   * `anchor_transplanted` events emitted: one per record.
   */
  logFindings: number;
  /** The rows the walk judged, in the order it walked them. */
  envelopes: EvidenceEnvelope[];
  /** The walk's whole answer. */
  completeness: ChainCompletenessResult;
}

/**
 * `storage`, except that every row `listBySequence()` returns is also kept in
 * `records`, and every capture digest `getCaptureDigests()` returns in
 * `captureDigests`.
 *
 * The chain phase hands this to `verifyChainCompleteness()` and builds its
 * events from what it kept, so an event describes the very row — and the very
 * capture digest — the walk judged, not a second read that could have changed
 * in between, and the chain is read once per pass rather than twice. Every
 * other member is the adapter's own, bound to the adapter; a member the
 * adapter does not have stays absent.
 */
function recordingReads(storage: StorageAdapter): {
  storage: StorageAdapter;
  records: EvidenceEnvelope[];
  captureDigests: Record<string, string>;
} {
  const records: EvidenceEnvelope[] = [];
  const captureDigests: Record<string, string> = {};
  const view = new Proxy(storage, {
    get(target, prop) {
      if (prop === 'listBySequence') {
        return async (fromSequence?: number, toSequence?: number, chainId?: string) => {
          const rows = await target.listBySequence(fromSequence, toSequence, chainId);
          records.push(...rows);
          return rows;
        };
      }
      if (prop === 'getCaptureDigests' && typeof target.getCaptureDigests === 'function') {
        return async (evidenceIds: string[]) => {
          const digests = await target.getCaptureDigests(evidenceIds);
          Object.assign(captureDigests, digests);
          return digests;
        };
      }
      const value: unknown = Reflect.get(target, prop, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  return { storage: view, records, captureDigests };
}

/**
 * Fold ascending sequence numbers into runs of consecutive ones:
 * `[3, 4, 7]` → `[{ from: 3, to: 4 }, { from: 7, to: 7 }]`.
 */
function consecutiveRuns(sorted: number[]): Array<{ from: number; to: number }> {
  const runs: Array<{ from: number; to: number }> = [];
  for (const n of sorted) {
    const last = runs[runs.length - 1];
    if (last && n === last.to + 1) {
      last.to = n;
    } else {
      runs.push({ from: n, to: n });
    }
  }
  return runs;
}

/** What the attestation check reports back for one batch of records. */
interface AttestationCheckResult {
  /** `attestation_invalid` events emitted — what the pass counts as failures. */
  issues: number;
  /**
   * `attestation_unverifiable` events emitted — artifacts that are PRESENT but
   * which this build cannot check. Kept apart from `issues` because "checked
   * and failed" and "could not check" are different findings with different
   * remedies, and conflating them is what a distinct event type exists to stop.
   */
  unverifiable: number;
  /**
   * Records whose artifact the verifier reported `true` for, per component.
   * Raw counts: a component the scanner is not equipped to verify is simply
   * never `true` here and reads 0. `runFullPass` turns that into `null` via
   * `verifiedAttestationComponents()` so 0 keeps meaning "none valid".
   */
  valid: AttestationPresenceCounts;
}

/**
 * The anchor abstentions the attestation check raises as `attestation_invalid`
 * (tzun-anchor/1 §10.10): an anchor under a tag this build does not read, or a
 * `blockchainAnchor`. Each verdict is an abstention, and stored evidence whose
 * whole anchor has become unverifiable is a finding.
 */
const ESCALATED_ANCHOR_REASONS: ReadonlySet<string> = new Set([
  'unsupported_anchor_spec',
  'unsupported_merkle_spec',
  'legacy_blockchain_anchor',
]);

/**
 * The anchor abstentions the attestation check reports as
 * `attestation_unverifiable`: an anchor whose publications this build does not
 * implement, and a failure of the verifier itself. An anchor that lists no
 * publication is `malformed_anchor` (tzun-anchor/1 §10.3 step 2), a `false`
 * verdict, so it is `attestation_invalid`.
 *
 * Neither list holds `publication_not_checked` or `no_matching_trust_anchor`
 * (tzun-anchor/1 §10.10): they are the normal state of an anchor whose
 * publications the scanner has no header source or trust roots to check, and
 * raising them would be noise on every record forever.
 */
const UNVERIFIABLE_ANCHOR_REASONS: ReadonlySet<string> = new Set([
  'unsupported_publication_kind',
  'unsupported_evm_tx_type',
  'anchor_verifier_error',
]);

/**
 * Which attestation artifacts an envelope CARRIES. Presence only — a non-empty
 * token is not a valid timestamp — and the single definition of "present"
 * shared by the attestation check (which then verifies what is present) and
 * the per-pass coverage count `GET /v1/integrity/status` reports.
 *
 * An anchor is present when `nonRepudiation.anchor` or a `blockchainAnchor`
 * is attached, as `verifyAnchor` counts one: the verifier abstains on a
 * `blockchainAnchor`, and the attestation check reports that as unverifiable
 * rather than missing.
 */
function attestationPresenceOf(
  envelope: EvidenceEnvelope,
): { timestamp: boolean; signature: boolean; anchor: boolean } {
  const nr = (envelope.nonRepudiation ?? {}) as EvidenceEnvelope['nonRepudiation'] & { blockchainAnchor?: unknown };
  return {
    timestamp: !!nr.rfc3161Token,
    signature: !!(nr.webauthnAssertion && nr.webauthnAssertion.signature),
    anchor: (nr.anchor !== undefined && nr.anchor !== null) || (nr.blockchainAnchor !== undefined && nr.blockchainAnchor !== null),
  };
}

/**
 * The record's artifacts without its anchor: what the timestamp and signature
 * checks read. The anchor is verified apart, on another digest.
 * Anything that is not an object is handed on as it is, for the verifier to
 * read as no artifacts.
 */
function withoutAnchor(artifacts: EvidenceEnvelope['nonRepudiation']): AttestationArtifacts {
  if (artifacts === null || typeof artifacts !== 'object' || Array.isArray(artifacts)) return artifacts;
  const rest: Record<string, unknown> = { ...artifacts };
  delete rest.anchor;
  delete rest.blockchainAnchor;
  return rest as AttestationArtifacts;
}

/**
 * What the header sources that took part in an anchor verdict counted as
 * final: the `finality` fact of its EVM publications (tzun-anchor/1 §10.4
 * item 14), which a source that declares a mode reports once its chain id
 * matched, whatever the outcome. `undefined` when no such fact was reported;
 * `null` when the facts disagree.
 */
function finalityJudgedUnder(verdict: AnchorVerification): EvmFinality | null | undefined {
  const modes = new Map<string, EvmFinality>();
  for (const publication of verdict.publications) {
    const finality = publication.evm?.finality;
    if (finality !== undefined) modes.set(JSON.stringify(finality), finality);
  }
  if (modes.size === 0) return undefined;
  return modes.size === 1 ? [...modes.values()][0] : null;
}

/** A copy of a map of what each chain counts as final: a copy handed out cannot change the scanner's own. */
function copyFinality(finality: Record<string, EvmFinality | null>): Record<string, EvmFinality | null> {
  return Object.fromEntries(
    Object.entries(finality).map(([chain, mode]) => [chain, mode !== null && typeof mode === 'object' ? { ...mode } : mode]),
  );
}

/**
 * What the scanner needs in order to do more than a presence check on
 * attestation artifacts.
 *
 * Every field is optional and every one of them is a *trust anchor the scanner
 * cannot invent*: a public key to verify a WebAuthn assertion against, a
 * decision about which TSA roots count, the chains an anchor was published on
 * and who may publish there. Absent, the corresponding component degrades to
 * a presence check — never to a silent `true`.
 * An anchor's proofs need no trust anchor and are always checked; its EVM
 * publication is checked only with `anchoring`.
 */
export interface ScannerAttestationDeps {
  /**
   * Registered WebAuthn credentials. Supplying it upgrades the signature
   * component from "a non-empty string is present" to full cryptographic
   * verification.
   */
  credentialStore?: CredentialStore;
  /** Origins a WebAuthn ceremony is allowed to have run on. */
  allowedOrigins?: string[];
  /** Relying Party ID assertions must be scoped to. */
  rpId?: string;
  /**
   * The challenge a record's assertion was required to sign, binding it to
   * that record.
   *
   * Supply this only if you run your own binding scheme. Left unset, the
   * scanner derives the expectation itself with
   * `webauthnChallengeForDigest(envelope.integrity.canonicalDigest)` — the
   * binding is a pure function of the digest, so the check costs a SHA-256 and
   * needs no configuration, and leaving it off by default meant the scanner
   * walked past the one artifact that claims a human approved the decision.
   *
   * The two modes report a mismatch differently and deliberately. A challenge
   * YOU supply is an assertion about what this record's ceremony was told to
   * sign, so a mismatch is a finding: `challenge_mismatch`, an
   * `attestation_invalid` event. The derived default cannot know whether the
   * ceremony ever intended to bind — a record captured before 0.3.16 signed a
   * login nonce — so a mismatch is `assertion_not_bound_to_digest` and does
   * NOT raise an event. Neither counts as a valid signature.
   *
   * Returning `undefined` from your own function falls back to the derived
   * default for that record.
   */
  expectedChallengeFor?: (envelope: EvidenceEnvelope) => string | undefined;
  /**
   * How far to take RFC 3161 verification. Defaults to `'structural'` — read
   * the token as tzun-anchor/1 §10.5 step 1 does (a DER TimeStampResp that
   * carries its signer's certificate) and require its imprint to be SHA-256
   * over this record's digest — because
   * `'trust-chain'` pins the bundled FreeTSA root and would report every
   * genuine token from any other TSA as invalid.
   */
  timestampVerification?: 'trust-chain' | 'structural';
  /**
   * The publisher manifest and the chains a store anchors on
   * (tzun-anchor/1 §9, §10.4). With them, a record's EVM publication is
   * checked end to end, check b re-derives each anchored root from the
   * published P, and check g accounts for the publisher wallet's nonces.
   * Supplying it says the deployment anchors, which turns on `anchor_overdue`
   * (check e).
   */
  anchoring?: ScannerAnchoringDeps;
}

/**
 * The store's material for the record's EVM publications, by the transaction
 * ids its anchor names: the signed transaction, the header and the trie proof
 * the scheduler stored when the block was final (tzun-anchor/1 §7.2 rule 4).
 * None of it is trusted: the verifier recovers the sender, hashes the header
 * and walks the proof.
 */
function materialFor(
  artifacts: EvidenceEnvelope['nonRepudiation'],
  material: Map<string, EvmPublicationMaterial>,
): EvmPublicationMaterial[] {
  const anchor = (artifacts as { anchor?: { publications?: unknown } } | undefined)?.anchor;
  const publications = Array.isArray(anchor?.publications) ? (anchor.publications as unknown[]) : [];
  const out: EvmPublicationMaterial[] = [];
  for (const p of publications) {
    const id = (p as { transactionId?: unknown } | null)?.transactionId;
    const m = typeof id === 'string' ? material.get(id.toLowerCase()) : undefined;
    if (m) out.push(m);
  }
  return out;
}

/**
 * ScheduledScanner — two-phase parallel verification of the evidence chain.
 *
 * Phase 1: Parallel digest verification. Partitions the chain into segments,
 * runs Promise-based workers concurrently. Each worker calls
 * `storage.listBySequence(from, to)`, recomputes digests, and checks each
 * record's custody trail.
 *
 * Phase 2: the chain walk. `verifyChainCompleteness()` over each chain in
 * turn, its findings emitted as monitoring events. The chain rules are the
 * walk's; the scanner does not keep a second copy of them. On a store with
 * evidence logs the walk also compares every record with its logged leaf
 * (check a of `anchor-log-checks.ts`) and with the fill (check h).
 *
 * Then the store's logs and anchoring tables (`checkAnchoredLogs`, checks b
 * to g): each log against what was anchored, and each publisher wallet's
 * nonces against what the store holds.
 *
 * `ScannerAnchoringDeps.scope` divides that work between one domain scan,
 * which walks no chain, and a chain scan per chain, and
 * `ScannerAnchoringDeps.sharedCache`, the cache `runAnchorScanPass` gives a
 * pass, lets the scanners of that pass read the chain and the anchor log once
 * between them.
 */
export class ScheduledScanner {
  private state: ScannerState;
  private stopRequested = false;
  /**
   * The one chain this scanner is responsible for, or `undefined` — the
   * default — for every chain in the store.
   *
   * A store holds one chain until someone forks it. After `recovery.fork()`
   * the store holds a sealed chain numbered 1..N and a live chain restarting
   * at 1, and a single unscoped walk would read that as ONE chain: every
   * sequence number the two chains share a `duplicate_sequence`, every
   * boundary between them a `chain_break` — tamper incidents on an untampered
   * store.
   *
   * So `undefined` means one bounded pass per chain — see `resolveScopes()` —
   * which avoids that false-incident flood WITHOUT dropping the sealed chain,
   * so the default needs no wiring from the SDK and gets none.
   *
   * Scoping is per-scanner, not per-pass, so a caller that owns one scanner per
   * chain (the platform's scanner worker) can divide the store between them
   * instead of having each scanner redo all of it.
   */
  private chainScope: string | undefined;
  /** The running scan loop, if `start()` has been called and not stopped. */
  private loop: Promise<void> | null = null;
  /** Serialises passes; see `runFullPass()`. Never rejects. */
  private passChain: Promise<unknown> = Promise.resolve();
  private sleepTimer: ReturnType<typeof setTimeout> | null = null;
  private wake: (() => void) | null = null;
  /**
   * Custody-check reads that failed in THIS pass, so the rest of the pass does
   * not retry them record by record; reset when a pass starts, so a transient
   * failure costs one pass, not the life of the scanner. Each is logged once
   * per scanner.
   */
  private custodyLedgerUnreadable = false;
  private relinksUnreadable = false;
  private custodyLedgerFailureLogged = false;
  private relinkFailureLogged = false;
  /** Relink records read in this pass, by id; `null` for one the store does not hold. */
  private relinkCache = new Map<string, RelinkRecord | null>();
  /**
   * The store's evidence logs and anchoring tables, read once per pass;
   * `null` for a store that keeps none. Reset when a pass starts.
   */
  private passLogs: Promise<StoreLogs | null> | null = null;
  /** The mined EVM publications' material for this pass's anchor verifications, by transaction id. */
  private passMaterial: Promise<Map<string, EvmPublicationMaterial>> | null = null;
  /** This pass's view of each chain as a header source: one answer per question per pass. */
  private passHeaderSources: Record<string, EvmHeaderSource> | null = null;
  /**
   * What this pass reads once: the reads it shares with the other scanners of
   * the pass (`ScannerAnchoringDeps.sharedCache`), or its own. Reset when a
   * pass starts.
   */
  private passReads: PassReads | null = null;
  /**
   * The pass caches this scanner has read through. A pass handed one of them
   * again reads on its own: a scanner's second pass is another pass.
   */
  private readonly passCaches = new WeakSet<AnchorScanCache>();
  /**
   * What each chain the scanner reads counts as final, checked and copied when
   * it was built (`scannerChainFinality`): what every pass reports as
   * `evmFinality`, and what its header sources declare.
   */
  private readonly evmFinality: Record<string, EvmFinality | null>;
  /**
   * Transactions checks b and g have read in finalized blocks, by id. A
   * transaction's sender, nonce and calldata are fixed by its id, so a later
   * pass does not read it again. A pass that reads through a `sharedCache`
   * uses the maps its pass carries instead.
   */
  private readonly minedTransactions = new Map<string, ScannerEvmTransaction>();
  /** Stored raw transactions check g has recovered the signer of, by hash. */
  private readonly signedTransactions = new Map<string, SignedTransaction>();
  /** Log checks that could not run, each logged once per scanner. */
  private readonly notCheckedLogged = new Set<string>();
  private logReadFailureLogged = false;
  /** The store as this pass's record-rule checks read it, with its link-target cache (`recordRuleStorage`). */
  private passRuleStorage: StorageAdapter | null = null;
  /** This pass's evidence-log origins, once read (`passEvidenceLogOrigin`); `undefined` until then. */
  private passOrigin: ((chainId: string) => string) | null | undefined = undefined;

  constructor(
    private readonly storage: StorageAdapter,
    private readonly bus: MonitoringEventBus,
    private readonly registry: SchemaRegistry,
    private readonly config: ScannerConfig,
    private readonly attestationDeps: ScannerAttestationDeps = {},
  ) {
    // `runPhase1` advances its cursor by `config.workers`
    // (`for (let i = 0; i < segments.length; i += this.config.workers)`), so a
    // zero or negative worker count is not a slow scan — it is a loop that
    // never advances, awaiting `Promise.all([])` forever. Timers, signals and
    // I/O are all starved behind that microtask loop, so the process pins a
    // core and cannot even run its SIGTERM handler. Refuse the value at
    // construction rather than wedging at scan time.
    if (!Number.isFinite(config.workers) || config.workers < 1) {
      throw new RangeError(
        `ScannerConfig.workers must be a finite integer >= 1 (received ${String(config.workers)}). ` +
          'A non-positive worker count makes the phase-1 segment loop never advance.',
      );
    }
    if (!Number.isFinite(config.batchSize) || config.batchSize < 1) {
      throw new RangeError(
        `ScannerConfig.batchSize must be a finite integer >= 1 (received ${String(config.batchSize)}).`,
      );
    }
    // The verifier's rule for a header source's finality: a
    // depth below 64 confirmations confirms anchors that may be reorganised
    // away, and is refused here unless the chain says it accepts that.
    this.evmFinality = scannerChainFinality(attestationDeps.anchoring?.evmChains);

    this.state = {
      currentPassStartedAt: null,
      lastCompletedPassAt: null,
      lastCompletedPass: null,
      totalPasses: 0,
      highWaterMark: 0,
      segmentsInProgress: [],
    };
  }

  /**
   * Scope every subsequent pass to one chain. Pass `undefined` to go back to
   * scanning the whole store. Takes effect on the next pass; a pass already
   * running keeps the scope it started with.
   */
  setChainScope(chainId: string | undefined): void {
    this.chainScope = chainId;
  }

  /** The chain this scanner is currently scoped to, if any. */
  getChainScope(): string | undefined {
    return this.chainScope;
  }

  /** Returns a snapshot copy of the current scanner state. */
  getState(): ScannerState {
    const last = this.state.lastCompletedPass;
    return {
      ...this.state,
      segmentsInProgress: [...this.state.segmentsInProgress],
      lastCompletedPass: last
        ? {
            ...last,
            attestationPresence: last.attestationPresence
              ? { ...last.attestationPresence }
              : undefined,
            attestationValid: last.attestationValid
              ? { ...last.attestationValid }
              : undefined,
            evmFinality: last.evmFinality ? copyFinality(last.evmFinality) : undefined,
          }
        : null,
    };
  }

  /**
   * Which attestation components a pass under this configuration VERIFIES,
   * as opposed to merely checks for presence. Decided from configuration,
   * not from verdicts: a component the verifier is not equipped for comes
   * back `null` on every record, which is indistinguishable from "no record
   * had one" if you only count `true`s. See `AttestationValidityCounts`.
   */
  private verifiedAttestationComponents(): { timestamp: boolean; signature: boolean; anchor: boolean } {
    if (!this.config.verifyAttestation) {
      return { timestamp: false, signature: false, anchor: false };
    }
    return {
      // Structural verification (parse + imprint over this digest) always
      // runs; trust-chain mode is stricter, not a different kind of check.
      timestamp: true,
      // `signatureValid: true` needs a public key to verify against AND a
      // challenge derived from this record's digest to bind it to. The
      // challenge is always available — derived from the digest when the
      // caller supplies no scheme of its own — so the credential store
      // is the only remaining precondition.
      signature: !!this.attestationDeps.credentialStore,
      // `anchorValid: true` needs an EVM publication checked against a
      // header source and a publisher manifest (the scanner holds no TSA roots
      // for an RFC 3161 one).
      anchor: this.anchorPublicationsChecked(),
    };
  }

  /** Whether an EVM publication can be `true` under this scanner's inputs. */
  private anchorPublicationsChecked(): boolean {
    const anchoring = this.attestationDeps.anchoring;
    return !!anchoring?.publisherManifest && Object.keys(anchoring.evmChains ?? {}).length > 0;
  }

  /** The store's logs for this pass, read on first use; null for a store without them. */
  private storeLogs(): Promise<StoreLogs | null> {
    if (!this.passLogs) {
      this.passLogs = StoreLogs.open(this.storage).catch((err) => {
        this.logReadFailure(err);
        return null;
      });
    }
    return this.passLogs;
  }

  private logReadFailure(err: unknown): void {
    if (this.logReadFailureLogged) return;
    this.logReadFailureLogged = true;
    // The checks read the chain too: the text names no URL, which can carry an API key.
    console.error(
      '[ScheduledScanner] The store\'s evidence logs could not be read; the checks against them ' +
        'did not run on this pass:',
      rpcErrorText(err),
    );
  }

  /**
   * What this pass reads once: its pass's shared reads when it was handed a
   * cache whose pass is running and that it has not read through before, else
   * its own. A cache it does not read is logged once.
   */
  private reads(): PassReads {
    if (!this.passReads) {
      const cache = this.attestationDeps.anchoring?.sharedCache;
      const shared = cache && !this.passCaches.has(cache) ? sharedPassReads(cache) : null;
      if (cache && shared) {
        this.passCaches.add(cache);
      } else if (cache) {
        const note =
          'the sharedCache this scanner was handed is not a running pass\'s (its pass has ended, this scanner has ' +
          'already made a pass with it, or runAnchorScanPass did not make it): this pass read the chain and the ' +
          'anchor log on its own. Hand the scanners of each pass the cache runAnchorScanPass gives that pass';
        if (!this.notCheckedLogged.has(note)) {
          this.notCheckedLogged.add(note);
          console.warn(`[ScheduledScanner] ${note}.`);
        }
      }
      this.passReads = shared ?? newPassReads(this.minedTransactions, this.signedTransactions);
    }
    return this.passReads;
  }

  /** The EVM publications' material for this pass, read on first use, once for the scanners that share a cache. */
  private publicationMaterial(): Promise<Map<string, EvmPublicationMaterial>> {
    if (!this.passMaterial) {
      const reads = this.reads();
      this.passMaterial = this.storeLogs()
        .then(async (logs) => {
          const anchors = logs?.anchors;
          if (!logs || !anchors || !logs.anchorLog) return new Map<string, EvmPublicationMaterial>();
          return readOnce(reads.publicationMaterial, logs.anchorOrigin, async () =>
            publicationMaterial(await anchors.listAnchorPublications({ kind: 'evm-calldata/1' })),
          );
        })
        .catch((err) => {
          this.logReadFailure(err);
          return new Map<string, EvmPublicationMaterial>();
        });
    }
    return this.passMaterial;
  }

  /** This pass's header sources: each chain, answering each question once for the scanners that share a cache. */
  private headerSources(): Record<string, EvmHeaderSource> {
    if (!this.passHeaderSources) {
      const reads = this.reads();
      const chains = this.attestationDeps.anchoring?.evmChains ?? {};
      this.passHeaderSources = Object.fromEntries(
        Object.entries(chains).map(([k, c]) => [k, passHeaderSource(reads, c, this.evmFinality[k] ?? null)]),
      );
    }
    return this.passHeaderSources;
  }

  /**
   * Run a single full verification pass over all records.
   * Phase 1: parallel digest verification.
   * Phase 2: the chain walk, `verifyChainCompleteness()` (if configured).
   * Emits scan_completed when done.
   */
  /**
   * With `verifyAttestation` on, the RFC 3161 trust anchors this pass's
   * verifiers read, read once before any record: the environment's
   * (`TZUN_TSA_TRUST_ANCHORS`, `TZUN_TSA_AUTHORITIES`), or, under
   * `timestampVerification: 'trust-chain'` with none configured, the default
   * roots. One that cannot be read throws `UnreadableTrustAnchorError` and
   * the pass fails with it, where every record would otherwise throw it
   * (Verification §3.1). A scheduled loop logs the failed pass.
   */
  private refuseUnreadableTrustAnchors(): void {
    if (!this.config.verifyAttestation) return;
    const configured = ['TZUN_TSA_TRUST_ANCHORS', 'TZUN_TSA_AUTHORITIES'].some((name) => (process.env[name] ?? '').trim().length > 0);
    if (configured || this.attestationDeps.timestampVerification === 'trust-chain') readTrustAnchors({});
  }

  /**
   * Run one full pass. Passes never overlap: a call made while another is in
   * flight — the scheduled loop and a manual `Tzun.runScan()`, say — waits for
   * it, because a pass writes the scanner's shared state as it goes.
   */
  runFullPass(): Promise<void> {
    const run = this.passChain.then(() => this.runFullPassExclusive());
    this.passChain = run.catch(() => undefined);
    return run;
  }

  private async runFullPassExclusive(): Promise<void> {
    const startTime = Date.now();
    this.state.currentPassStartedAt = new Date().toISOString();
    this.custodyLedgerUnreadable = false;
    this.relinksUnreadable = false;
    this.relinkCache = new Map();
    this.passLogs = null;
    this.passMaterial = null;
    this.passHeaderSources = null;
    this.passReads = null;
    this.passRuleStorage = null;
    this.passOrigin = undefined;

    try {
      // The domain scan walks no chain: its checks are the domain's log
      // checks alone (`ScannerAnchoringDeps.scope`).
      const domainScan = this.attestationDeps.anchoring?.scope === 'domain';
      if (!domainScan) this.refuseUnreadableTrustAnchors();
      // The fallback bound for a store whose chains cannot be enumerated, or a
      // scope naming a chain it does not know: this scanner's own chain, or
      // 'default' when it has no scope. The per-chain rotation
      // below carries each chain's own bound.
      const lastSequence = domainScan ? 0 : await this.storage.getLastSequence(this.chainScope);

      let totalRecordsChecked = 0;
      let digestMismatches = 0;
      let chainBreaks = 0;
      let sequenceGaps = 0;
      let duplicateSequences = 0;
      let digestSuperseded = 0;
      let timeRegressions = 0;
      let custodyTrailInvalid = 0;
      let recordRuleViolations = 0;
      let mandateFindings = 0;
      let attestationUnverifiable = 0;
      let attestationFailures = 0;
      let logFindings = 0;
      let anchorOverdue = 0;
      // The records each chain's pass read, for the log checks below.
      const recordsByChain = new Map<string, EvidenceEnvelope[]>();
      const attestationPresence: AttestationPresenceCounts = {
        timestamp: 0,
        signature: 0,
        anchor: 0,
      };
      const attestationValidRaw: AttestationPresenceCounts = {
        timestamp: 0,
        signature: 0,
        anchor: 0,
      };
      const addValid = (v: AttestationPresenceCounts): void => {
        attestationValidRaw.timestamp += v.timestamp;
        attestationValidRaw.signature += v.signature;
        attestationValidRaw.anchor += v.anchor;
      };

      // One pass PER CHAIN, never one pass over the union of them.
      //
      // Sequence numbers restart at 1 after `recovery.fork()`, so a store that
      // has forked holds two records numbered 1, two numbered 2, and so on.
      // One `listBySequence(1, lastSequence)` walk with no chain filter would
      // sort both chains into one sequence order, then read the collisions as
      // mid-chain insertions and every crossing of the chain boundary as a
      // broken link: on an untampered three-then-two fork, FIVE fabricated
      // incidents — 2 duplicate_sequence and 3 chain_break — each one paging
      // an operator about a chain nobody had touched. Each chain is also
      // walked to its own upper bound, so a sealed chain's later records are
      // scanned too.
      //
      // Sealed chains stay in the rotation. A sealed chain is the read-only
      // remainder of a fork and is exactly where an insider would tamper;
      // dropping it would trade a false alarm for a missed one.
      const scopes = domainScan ? [] : await this.resolveScopes(lastSequence);
      // The highest sequence any chain in this pass is known to have reached.
      const passHighWaterMark = scopes.reduce((max, s) => Math.max(max, s.upperBound ?? 0), 0);

      for (const scope of scopes) {
        const to = scope.upperBound ?? 0;
        if (to <= 0) continue;

        const phase1Result = await this.runPhase1(1, to, scope.chainId);
        totalRecordsChecked += phase1Result.recordsChecked;
        digestMismatches += phase1Result.issues;
        custodyTrailInvalid += phase1Result.custodyTrailInvalid;
        recordRuleViolations += phase1Result.recordRuleViolations;
        attestationPresence.timestamp += phase1Result.attestationPresence.timestamp;
        attestationPresence.signature += phase1Result.attestationPresence.signature;
        attestationPresence.anchor += phase1Result.attestationPresence.anchor;

        if (this.config.verifyChainCompleteness) {
          const phase2Result = await this.runPhase2(1, to, scope.chainId);
          chainBreaks += phase2Result.chainBreaks;
          sequenceGaps += phase2Result.sequenceGaps;
          duplicateSequences += phase2Result.duplicateSequences;
          digestSuperseded += phase2Result.digestSuperseded;
          timeRegressions += phase2Result.timeRegressions;
          logFindings += phase2Result.logFindings;
          if (scope.chainId !== undefined) recordsByChain.set(scope.chainId, phase2Result.envelopes);

          // Phase 1.5: Attestation checking (reuses Phase 2 records)
          if (this.config.verifyAttestation) {
            const checked = await this.runAttestationCheckOnRecords(phase2Result.envelopes, scope.chainId);
            attestationFailures += checked.issues;
            attestationUnverifiable += checked.unverifiable;
            addValid(checked.valid);
          }
        } else if (this.config.verifyAttestation) {
          // No Phase 2, but attestation still needed — must fetch records
          const envelopes = await this.storage.listBySequence(1, to, scope.chainId);
          if (scope.chainId !== undefined) recordsByChain.set(scope.chainId, envelopes);
          const checked = await this.runAttestationCheckOnRecords(envelopes, scope.chainId);
          attestationFailures += checked.issues;
          attestationUnverifiable += checked.unverifiable;
          addValid(checked.valid);
        }

        // Continuity when Phase 2 is switched off. Phase 2 is the precise
        // detector — it knows WHICH sequence numbers are gone — so this coarse
        // count check only runs when Phase 2 did not, otherwise the same missing
        // records would be reported twice. Without it, a scanner configured with
        // verifyChainCompleteness: false has no continuity check at all: it would
        // scan the three rows that survive a five-record chain and call the pass
        // clean. Counted per chain, because `to` is a per-chain bound.
        if (!this.config.verifyChainCompleteness && phase1Result.recordsChecked < to) {
          this.bus.emit({
            type: 'sequence_gap',
            expectedSequence: phase1Result.recordsChecked + 1,
            foundSequence: to + 1,
          });
          sequenceGaps++;
        }
      }

      // The store's logs and anchoring (checks b to g), once per
      // pass over every chain this pass walked.
      const logged = await this.runLogChecks(scopes, recordsByChain);
      logFindings += logged.logFindings;
      anchorOverdue += logged.anchorOverdue;

      // The store's mandates (Record §9.10), once per pass. A
      // domain scan walks no chain and reads no mandate.
      if (!domainScan) mandateFindings += await this.runMandateChecks();

      // Every finding except `timeRegressions` and `anchorOverdue`, which are
      // reported but — like `verifyChainCompleteness().valid` — do not decide
      // whether the pass was clean: a regression is suspicious, not proof, and
      // an anchoring delay says nothing about the evidence.
      const totalIssues =
        digestMismatches +
        chainBreaks +
        sequenceGaps +
        duplicateSequences +
        digestSuperseded +
        custodyTrailInvalid +
        recordRuleViolations +
        mandateFindings +
        attestationFailures +
        logFindings;
      const durationMs = Date.now() - startTime;
      const completedAt = new Date().toISOString();

      // Validity is reported only for the components this pass verified;
      // the rest are null, not 0 — see `AttestationValidityCounts`.
      const verifies = this.verifiedAttestationComponents();
      const attestationValid: AttestationValidityCounts = {
        timestamp: verifies.timestamp ? attestationValidRaw.timestamp : null,
        signature: verifies.signature ? attestationValidRaw.signature : null,
        anchor: verifies.anchor ? attestationValidRaw.anchor : null,
      };

      // The pass is complete: record what it measured BEFORE announcing it, so
      // a `scan_completed` subscriber that reads `getState()` sees this pass —
      // its number, its timestamp, its summary — not the previous one.
      //
      // `lastCompletedPass` is the only source `GET /v1/integrity/status` has
      // for the pass duration and coverage, and it is what distinguishes a
      // store that has never been scanned from one that has been scanned and
      // found clean.
      const summary: ScanSummary = {
        passNumber: this.state.totalPasses + 1,
        startedAt: this.state.currentPassStartedAt ?? completedAt,
        completedAt,
        durationMs,
        recordsChecked: totalRecordsChecked,
        issuesFound: totalIssues,
        digestMismatches,
        chainBreaks,
        sequenceGaps,
        duplicateSequences,
        digestSuperseded,
        timeRegressions,
        custodyTrailInvalid,
        recordRuleViolations,
        mandateFindings,
        attestationFailures,
        attestationUnverifiable,
        logFindings,
        anchorOverdue,
        attestationPresence: { ...attestationPresence },
        attestationValid: { ...attestationValid },
        evmFinality: copyFinality(this.evmFinality),
      };
      this.state.totalPasses += 1;
      this.state.lastCompletedPassAt = completedAt;
      this.state.lastCompletedPass = summary;

      // Emit scan_completed
      this.bus.emit({
        type: 'scan_completed',
        recordsChecked: totalRecordsChecked,
        issuesFound: totalIssues,
        durationMs,
        digestMismatches,
        chainBreaks,
        sequenceGaps,
        duplicateSequences,
        digestSuperseded,
        timeRegressions,
        custodyTrailInvalid,
        recordRuleViolations,
        mandateFindings,
        attestationFailures,
        attestationUnverifiable,
        logFindings,
        anchorOverdue,
        attestationPresence: { ...attestationPresence },
        attestationValid: { ...attestationValid },
        evmFinality: copyFinality(this.evmFinality),
      });
      // highWaterMark is only ever raised, and deliberately so. Comparing this
      // pass's high-water mark against a previous pass's to catch a shrinking
      // chain would (a) be a no-op in production, where the platform's scanner
      // worker constructs a fresh ScheduledScanner per chain per pass so the mark
      // starts at 0 every time, and (b) require a per-chain mark to mean
      // anything on a store with several chains, since a chain's numbering says
      // nothing about another's. The shrinkage that matters is caught inside a
      // single pass instead, by comparing the fetched records against `to`.
      if (passHighWaterMark > this.state.highWaterMark) {
        this.state.highWaterMark = passHighWaterMark;
      }
    } finally {
      // Never leave the scanner looking mid-pass. Anything that escapes the
      // body above — a storage error, an adapter that throws — would otherwise
      // strand `currentPassStartedAt` and `segmentsInProgress`;
      // computeIntegrityStatus reads those to decide `scannerRunning`, so a
      // single failed pass would make the dashboard report a scan in progress
      // forever.
      this.state.currentPassStartedAt = null;
      this.state.segmentsInProgress = [];
      this.passLogs = null;
      this.passMaterial = null;
      this.passHeaderSources = null;
      this.passReads = null;
      this.passRuleStorage = null;
      this.passOrigin = undefined;
    }
  }

  /**
   * Checks b to g of `anchor-log-checks.ts` over the store's logs, its
   * anchoring tables and the chains it publishes on (`checkAnchoredLogs`),
   * emitted as monitoring events. A store read that fails is logged once and
   * the pass goes on: the other phases' findings stand.
   */
  private async runLogChecks(
    scopes: ChainScope[],
    recordsByChain: Map<string, EvidenceEnvelope[]>,
  ): Promise<{ logFindings: number; anchorOverdue: number }> {
    const counts = { logFindings: 0, anchorOverdue: 0 };
    const store = await this.storeLogs();
    if (!store) return counts;
    try {
      const result = await checkAnchoredLogs({
        store,
        chainIds: scopes.map((s) => s.chainId).filter((id): id is string => typeof id === 'string'),
        // Read when the log is judged, not when the pass started: an epoch the
        // scheduler cuts mid-pass anchors records captured after the scopes
        // were read.
        chainHead: async (chainId) => (await chainUpperBound(this.storage, chainId)) ?? 0,
        records: recordsByChain,
        deps: this.attestationDeps.anchoring,
        reads: this.reads(),
      });
      for (const event of result.events) {
        this.bus.emit(event);
        if (event.type === 'anchor_overdue') counts.anchorOverdue++;
        else counts.logFindings++;
      }
      for (const note of result.notChecked) {
        if (this.notCheckedLogged.has(note)) continue;
        this.notCheckedLogged.add(note);
        console.warn(`[ScheduledScanner] ${note}.`);
      }
    } catch (err) {
      this.logReadFailure(err);
    }
    return counts;
  }

  /**
   * The chains this pass will walk, each with its own sequence upper bound.
   *
   * Every chain by default, sealed ones included. Narrowed to exactly one when
   * `setChainScope()` has named a chain.
   *
   * Falls back to a single scope when the adapter cannot enumerate chains —
   * the HTTP transport refuses `listChains()` / `listForksForChain()` outright.
   * There it is one walk bounded by the chain-state high-water mark. A store
   * reached over that transport cannot fork through this SDK anyway, so there
   * is no second chain for the unscoped walk to collide with.
   */
  private async resolveScopes(lastSequence: number): Promise<ChainScope[]> {
    try {
      const all = await resolveChainScopes(this.storage);

      // An explicit `setChainScope()` NARROWS the rotation to one chain; it
      // does not change how any chain is walked. Two requirements compose in
      // exactly one order:
      //
      //   - the rotation must default to EVERY chain, sealed ones included,
      //     because a sealed chain is the read-only remainder of a fork and
      //     is precisely where an insider would tamper; and
      //   - a caller that owns one scanner per chain (the platform's scanner
      //     worker) must be able to say which chain this one is responsible
      //     for, so N scanners do not each redo all N chains.
      //
      // Putting the scope on the leaf `listBySequence` calls instead would
      // silently override the per-chain loop's own `chainId` on every
      // iteration, so the loop would walk the SAME chain once per chain in the
      // store: N passes over the active chain and zero over the sealed one.
      // That reads as a working scan (no false incidents, plausible record
      // counts) while covering strictly less.
      if (this.chainScope === undefined) return all;

      const scoped = all.find((s) => s.chainId === this.chainScope);
      // A scope naming a chain the store cannot enumerate still has to scan
      // something; bound it by the live counter rather than returning [] and
      // reporting a clean pass over nothing.
      return scoped ? [scoped] : [{ chainId: this.chainScope, upperBound: lastSequence }];
    } catch {
      // The adapter cannot enumerate chains (the HTTP transport refuses
      // `listChains()` / `listForksForChain()` outright). Fall back to a single
      // walk bounded by the chain-state high-water mark — and still honour an
      // explicit scope, which is the only chain information available here.
      // With no scope set this is one unscoped walk, which is safe here: a
      // store reached over that transport cannot fork through this SDK, so
      // there is no second chain for the walk to collide with.
      return [
        { chainId: this.chainScope as unknown as string, upperBound: lastSequence },
      ];
    }
  }

  /**
   * Whether this config names a schedule: `continuous`, or `interval` with a
   * positive `intervalMs`. Without one, passes run only on request.
   */
  isScheduled(): boolean {
    return (
      this.config.mode === 'continuous' ||
      (this.config.mode === 'interval' && (this.config.intervalMs ?? 0) > 0)
    );
  }

  /**
   * Start the scan loop, or return the one already running.
   *
   * 'interval' mode waits `intervalMs` between passes; 'continuous' runs them
   * back to back, yielding to the event loop between each. An 'interval' config
   * without a positive `intervalMs` has no schedule and runs a single pass.
   *
   * The loop never holds the process open — its wait timer is unref'd — and a
   * pass that throws is logged and does not end it. `stop()` ends it.
   */
  start(): Promise<void> {
    if (this.loop) return this.loop;
    this.stopRequested = false;
    this.loop = (async () => {
      while (!this.stopRequested) {
        try {
          await this.runFullPass();
        } catch (err) {
          // One failed pass must not end scheduled scanning: a transient
          // storage error would otherwise leave the store unmonitored for the
          // life of the process, with nothing saying so.
          console.error('[Tzun] Scheduled scan pass failed:', err);
        }
        if (this.stopRequested) break;
        if (this.config.mode === 'interval' && !((this.config.intervalMs ?? 0) > 0)) break;
        await this.sleep(this.config.mode === 'interval' ? this.config.intervalMs! : 0);
      }
    })().finally(() => {
      this.loop = null;
    });
    return this.loop;
  }

  /**
   * Stop the loop and resolve once it has exited — including a pass already in
   * flight, and any pass started through `runFullPass()` directly. A caller
   * about to close the store must await this, or the store closes under a
   * running pass.
   */
  async stop(): Promise<void> {
    this.stopRequested = true;
    if (this.sleepTimer) {
      clearTimeout(this.sleepTimer);
      this.sleepTimer = null;
    }
    this.wake?.();
    this.wake = null;
    await this.loop;
    await this.passChain;
  }

  /** An unref'd wait that `stop()` can cut short. */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      this.wake = resolve;
      this.sleepTimer = setTimeout(() => {
        this.sleepTimer = null;
        this.wake = null;
        resolve();
      }, ms);
      this.sleepTimer.unref?.();
    });
  }

  // ---------------------------------------------------------------------------
  // Phase 1: Parallel digest verification
  // ---------------------------------------------------------------------------

  /**
   * Partition the range [from, to] into segments and verify digests in
   * parallel using the configured number of workers.
   */
  async runPhase1(
    from: number,
    to: number,
    chainId?: string,
  ): Promise<Phase1Result> {
    const segments = this.partitionIntoSegments(from, to);
    this.state.segmentsInProgress = segments.map((s) => ({ from: s.from, to: s.to }));

    // Run workers in parallel, limited to config.workers concurrency
    const results: Phase1Result[] = [];
    for (let i = 0; i < segments.length; i += this.config.workers) {
      const batch = segments.slice(i, i + this.config.workers);
      const batchResults = await Promise.all(
        batch.map((seg) => this.verifyDigestsInRange(seg.from, seg.to, chainId)),
      );
      results.push(...batchResults);
    }

    let totalRecords = 0;
    let totalIssues = 0;
    let totalCustodyTrailInvalid = 0;
    let totalRecordRuleViolations = 0;
    const attestationPresence: AttestationPresenceCounts = {
      timestamp: 0,
      signature: 0,
      anchor: 0,
    };
    for (const r of results) {
      totalRecords += r.recordsChecked;
      totalIssues += r.issues;
      totalCustodyTrailInvalid += r.custodyTrailInvalid;
      totalRecordRuleViolations += r.recordRuleViolations;
      attestationPresence.timestamp += r.attestationPresence.timestamp;
      attestationPresence.signature += r.attestationPresence.signature;
      attestationPresence.anchor += r.attestationPresence.anchor;
    }

    return {
      recordsChecked: totalRecords,
      issues: totalIssues,
      custodyTrailInvalid: totalCustodyTrailInvalid,
      recordRuleViolations: totalRecordRuleViolations,
      attestationPresence,
    };
  }

  /**
   * Verify digests for all records in the sequence range [from, to].
   * Emits record_verified for each clean record, digest_mismatch for tampered,
   * and custody_trail_invalid for a record whose custody trail fails
   * (`checkCustodyTrail`).
   *
   * When `config.scannerVerifyDescriptors !== false` (default true), each envelope
   * with `aiBom !== null` is additionally passed through `verifyEnvelope`
   * with the storage adapter + `walkLineage: true`, and any descriptor /
   * parent-descriptor tamper incidents are re-emitted onto the event bus.
   */
  async verifyDigestsInRange(
    from: number,
    to: number,
    chainId?: string,
  ): Promise<Phase1Result> {
    const envelopes = await this.storage.listBySequence(from, to, chainId);
    let issues = 0;
    let custodyTrailInvalid = 0;
    let recordRuleViolations = 0;
    // Attestation presence is counted here, not in the attestation check,
    // because this is the one place every configuration of the scanner reads
    // every record: the attestation check only runs when `verifyAttestation`
    // is on, and only looks at records claiming 'complete', 'partial' or
    // 'pending'.
    const attestationPresence: AttestationPresenceCounts = {
      timestamp: 0,
      signature: 0,
      anchor: 0,
    };

    for (const envelope of envelopes) {
      const present = attestationPresenceOf(envelope);
      if (present.timestamp) attestationPresence.timestamp++;
      if (present.signature) attestationPresence.signature++;
      if (present.anchor) attestationPresence.anchor++;

      const recomputedDigest = this.recomputeDigest(envelope);

      const digestHolds = recomputedDigest === envelope.integrity.canonicalDigest;
      if (!digestHolds) {
        // An earlier hashed field set that reproduces the stored digest
        // explains the mismatch and keeps its severity (Verification §4.3).
        const fieldSet = earlierFieldSet(envelope.payload, envelope.integrity.canonicalDigest);
        this.bus.emit({
          type: 'digest_mismatch',
          evidenceId: envelope.payload.evidenceId,
          stored: envelope.integrity.canonicalDigest,
          recomputed: recomputedDigest,
          ...(fieldSet !== null && { fieldSet }),
        });
        issues++;
      } else {
        this.bus.emit({
          type: 'record_verified',
          evidenceId: envelope.payload.evidenceId,
        });
      }

      // Descriptor verification. Only meaningful when the envelope carries an
      // AI-BOM. The verifier's contract: when `options.storage` is supplied
      // AND `aiBom !== null`, resolve the descriptor and (when
      // `walkLineage: true`) walk the parent DAG. To skip the path entirely
      // when `scannerVerifyDescriptors: false`, we simply omit `storage` from the
      // options — `verifyEnvelope` then short-circuits descriptor work even
      // for envelopes with `aiBom !== null`.
      // A throw from descriptor verification would otherwise propagate
      // straight out of runFullPass, killing the entire scheduled scan on one
      // bad record — so a single unverifiable envelope would blind the monitor
      // to every record after it. Count the record as an issue and keep
      // scanning.
      try {
        issues += await this.verifyDescriptorPath(envelope);
      } catch (error) {
        issues += 1;
        console.error(
          `[ScheduledScanner] Descriptor verification threw for evidence ` +
          `"${envelope.payload.evidenceId}"; counted as an issue and scanning ` +
          `continued:`,
          error instanceof Error ? error.message : String(error),
        );
        this.bus.emit({
          type: 'descriptor_resolution_failure',
          evidenceId: envelope.payload.evidenceId,
          modelDescriptorDigest: stepModelDigests(envelope)[0] ?? '(unresolved)',
        });
      }

      custodyTrailInvalid += await this.checkCustodyTrail(envelope);

      // The record rules run only where the digest holds: a record whose
      // bytes were altered is a digest_mismatch, not a rule finding.
      if (digestHolds) {
        try {
          recordRuleViolations += await this.checkRecordRules(envelope);
        } catch (error) {
          recordRuleViolations += 1;
          console.error(
            `[ScheduledScanner] The record-rule check threw for evidence "${envelope.payload.evidenceId}"; ` +
              'counted as a finding and scanning continued:',
            error instanceof Error ? error.message : String(error),
          );
          this.bus.emit({ type: 'record_rule_violated', evidenceId: envelope.payload.evidenceId, rule: 'record', reason: 'check_failed' });
        }
      }
    }

    return { recordsChecked: envelopes.length, issues, custodyTrailInvalid, recordRuleViolations, attestationPresence };
  }

  // ---------------------------------------------------------------------------
  // Phase 1: record rules
  // ---------------------------------------------------------------------------

  /**
   * The record rules of one record whose digest holds, by the engine's
   * store-level `verifyEnvelope`: one `record_rule_violated { rule, reason }`
   * for each structure failure a conforming writer would have refused. The
   * `decider`, `contributions` and `links` rows that are checked-wrong; each
   * `links[<i>]` row that is checked-wrong, as `links.target` when the store
   * holds its target (the target no longer agrees with the link, or its rule
   * fails) and `links` otherwise; and `payload.members` for payload members
   * outside the format's names. The `contributions.binding` outcomes never
   * raise it: capture accepts a flawed process on purpose. Link targets are
   * resolved through this pass's cache; descriptors are the descriptor
   * path's. Returns the number of events emitted.
   */
  private async checkRecordRules(envelope: EvidenceEnvelope): Promise<number> {
    const options: VerifyEnvelopeOptions = { storage: this.recordRuleStorage() };
    const origin = await this.passEvidenceLogOrigin();
    if (origin !== null) options.evidenceLogOrigin = origin;
    const result = await verifyEnvelope(envelope, undefined, this.registry, options);
    const evidenceId = envelope.payload.evidenceId;
    const found: Array<{ rule: string; reason: string }> = [];
    for (const rule of ['decider', 'contributions', 'links'] as const) {
      const row = result[rule];
      if (row?.outcome === 'checked-wrong') found.push({ rule, reason: row.reason ?? 'checked-wrong' });
    }
    for (const relation of result.links?.relations ?? []) {
      if (relation.outcome !== 'checked-wrong') continue;
      found.push({ rule: relation.targetHeld ? 'links.target' : 'links', reason: relation.reason ?? 'checked-wrong' });
    }
    if ((result.unhashedPayloadMembers ?? []).length > 0) found.push({ rule: 'payload.members', reason: 'unsupported_member' });
    for (const f of found) this.bus.emit({ type: 'record_rule_violated', evidenceId, rule: f.rule, reason: f.reason });
    return found.length;
  }

  /**
   * The store as the record-rule check reads it: without the descriptor
   * catalog (the descriptor path resolves step models), and with this pass's
   * cache of link targets read by digest.
   */
  private recordRuleStorage(): StorageAdapter {
    if (this.passRuleStorage) return this.passRuleStorage;
    const storage = this.storage;
    const targets = new Map<string, Promise<EvidenceEnvelope | null>>();
    const byDigest = storage.retrieveByDigest?.bind(storage);
    const view = Object.create(storage, {
      getModelDescriptor: { value: undefined },
      ...(byDigest && {
        retrieveByDigest: {
          value: (digest: string): Promise<EvidenceEnvelope | null> => {
            let read = targets.get(digest);
            if (!read) {
              read = byDigest(digest);
              targets.set(digest, read);
            }
            return read;
          },
        },
      }),
    }) as StorageAdapter;
    this.passRuleStorage = view;
    return view;
  }

  /** This store's evidence-log origins, for comparing a link's locator with its held target; read once a pass. */
  private async passEvidenceLogOrigin(): Promise<((chainId: string) => string) | null> {
    if (this.passOrigin !== undefined) return this.passOrigin;
    const logs = logStoreFor(this.storage);
    let origin: ((chainId: string) => string) | null = null;
    if (logs) {
      try {
        const identity = await logs.getStoreIdentity();
        // The engine reads the store's own origin prefix as the origin of the
        // empty chain id, which names no log: answered with the prefix itself.
        origin = (chainId: string) =>
          chainId === '' ? evidenceLogOrigin(identity.ns, identity.storeId, 'x').slice(0, -2) : evidenceLogOrigin(identity.ns, identity.storeId, chainId);
      } catch {
        origin = null;
      }
    }
    this.passOrigin = origin;
    return origin;
  }

  // ---------------------------------------------------------------------------
  // Mandates (Record §9.10)
  // ---------------------------------------------------------------------------

  /**
   * Once a pass, on a store with the mandate tables and the link index: every
   * open mandate past its window is moved to `expired` with its event, then
   * the records of each mandate (the records that link its issuance record
   * with `mandate`) are checked for a slot held twice
   * (`mandate_slot_duplicate`), slots held by no record (`mandate_slot_gap`)
   * and running totals that do not step by each record's own value
   * (`mandate_totals_unexplained`). A mandate whose check cannot be read is
   * logged and skipped. Returns the number of events emitted.
   */
  private async runMandateChecks(): Promise<number> {
    const s = this.storage;
    if (
      typeof s.listMandates !== 'function' ||
      typeof s.getMandate !== 'function' ||
      typeof s.getMandateTotals !== 'function' ||
      typeof s.listMandateEvents !== 'function' ||
      typeof s.expireMandate !== 'function'
    ) {
      return 0;
    }
    const store: MandateListingStore = {
      getMandate: (key) => s.getMandate!(key),
      getMandateTotals: (id) => s.getMandateTotals!(id),
      listMandateEvents: (id) => s.listMandateEvents!(id),
      expireMandate: (expiry) => s.expireMandate!(expiry),
      listMandates: (filter) => s.listMandates!(filter),
    };
    const pass = await expireEndedMandates(store, new Date().toISOString());
    for (const failed of pass.failed) {
      console.error(`[ScheduledScanner] Mandate "${failed.mandateId}" past its window could not be moved to expired (${failed.errorName}).`);
    }
    if (typeof s.listLinksTo !== 'function' || typeof s.retrieve !== 'function') return 0;

    let emitted = 0;
    let cursor: string | null = null;
    do {
      const page: { rows: Awaited<ReturnType<NonNullable<StorageAdapter['listMandates']>>>['rows']; cursor: string | null } =
        await s.listMandates({ limit: 100, cursor });
      for (const mandate of page.rows) {
        try {
          emitted += await this.checkMandateConsumption(mandate.mandateId, mandate.mandateDigest, mandate.documentBytes, mandate.issuanceDigest);
        } catch (error) {
          console.error(
            `[ScheduledScanner] The consumption check of mandate "${mandate.mandateId}" could not run; the pass goes on:`,
            error instanceof Error ? error.message : String(error),
          );
        }
      }
      cursor = page.cursor;
    } while (cursor !== null);
    return emitted;
  }

  /** The consumption check of one mandate over the records that link its issuance record (`mandate`). */
  private async checkMandateConsumption(mandateId: string, mandateDigest: string, documentBytes: string, issuanceDigest: string): Promise<number> {
    const s = this.storage;
    const records: EvidenceEnvelope[] = [];
    let cursor: string | undefined;
    do {
      const page = await s.listLinksTo!(issuanceDigest, { rels: ['mandate'], limit: 200, ...(cursor !== undefined && { cursor }) });
      for (const row of page.rows) {
        const envelope = await s.retrieve(row.evidenceId);
        if (envelope) records.push(envelope);
      }
      cursor = page.cursor ?? undefined;
    } while (cursor !== undefined);
    const events: MandateEventRow[] = await s.listMandateEvents!(mandateId);
    const terminal = [...events].reverse().find((e) => e.body.event !== 'issued');
    const result = checkMandateConsumption(JSON.parse(documentBytes) as unknown, records, terminal ? { lastEvent: terminal.body } : {});
    let emitted = 0;
    for (const slot of result.duplicateSlots) {
      const evidenceIds = records
        .filter((r) => (r.payload.signoffExpectation as { mandateSeq?: unknown } | null)?.mandateSeq === slot)
        .map((r) => r.payload.evidenceId);
      this.bus.emit({ type: 'mandate_slot_duplicate', mandateDigest, slot, evidenceIds });
      emitted++;
    }
    for (const gap of result.gaps) {
      this.bus.emit({ type: 'mandate_slot_gap', mandateDigest, from: gap.from, to: gap.to, unexplained: gap.unexplained });
      emitted++;
    }
    for (const step of result.unexplainedSteps) {
      this.bus.emit({ type: 'mandate_totals_unexplained', mandateDigest, slot: step.slot, cap: step.cap, expected: step.expected, actual: step.actual });
      emitted++;
    }
    return emitted;
  }

  // ---------------------------------------------------------------------------
  // Phase 1: custody trail
  // ---------------------------------------------------------------------------

  /**
   * Check one record's custody trail — the hashed entries recording who
   * relinked, forked or reviewed it — and emit one `custody_trail_invalid`
   * naming every failure, or nothing. Returns the number of events emitted.
   *
   * Three checks, because `custodyChain` sits outside the hashed field set and
   * no digest or chain link covers it:
   *
   * - the trail as the envelope carries it (`verifyCustodyTrail`, the check
   *   behind `verifyEnvelope().custodyTrailValid`);
   * - the trail against the store's `custody_entries` ledger
   *   (`verifyCustodyLedger`). This is what catches the deletion of the LAST
   *   hashed entry, which leaves the envelope a shorter trail that is
   *   internally consistent;
   * - each 'relinked' entry's `relinkDigest` against the relink record it
   *   names (`computeRelinkDigest`, the rule `RecoveryManager.relink()` wrote
   *   it with). A relink record altered after the relink — its range widened,
   *   its `modifiedLinks` rewritten — no longer has that digest.
   *
   * A store that cannot read its ledger or its relink records (the platform's
   * chain-scoped scanner view stubs both) gets the checks it can do; the first
   * failed read of each kind is logged, once per scanner.
   */
  private async checkCustodyTrail(envelope: EvidenceEnvelope): Promise<number> {
    const evidenceId = envelope?.payload?.evidenceId;
    const found: CustodyFailure[] = [];

    const offline = verifyCustodyTrail(envelope);
    if (offline.valid === false) found.push(...offline.failures);

    const rows = await this.readCustodyLedger(evidenceId);
    if (rows !== null) {
      const ledger = verifyCustodyLedger(
        evidenceId,
        envelope,
        undefined,
        rows.map(toCustodyLedgerEntry),
      );
      found.push(...ledger.failures);
    }

    found.push(...(await this.relinkDigestFailures(envelope)));

    // `unhashed_after_hashed` is the one finding the envelope check and the
    // ledger check both make, about the same entry; the event names it once.
    const seen = new Set<string>();
    const failures = found.filter((f) => {
      const key = custodyFailureKey(f);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    if (failures.length === 0) return 0;
    this.bus.emit({ type: 'custody_trail_invalid', evidenceId, failures });
    return 1;
  }

  /** The record's `custody_entries` rows, or null when the store cannot say. */
  private async readCustodyLedger(evidenceId: unknown): Promise<StoredCustodyEntry[] | null> {
    if (this.custodyLedgerUnreadable || typeof evidenceId !== 'string') return null;
    if (typeof this.storage.listCustodyEntries !== 'function') return null;
    try {
      return await this.storage.listCustodyEntries(evidenceId);
    } catch (err) {
      this.custodyLedgerUnreadable = true;
      if (this.custodyLedgerFailureLogged) return null;
      this.custodyLedgerFailureLogged = true;
      console.error(
        '[ScheduledScanner] The store cannot read its custody_entries ledger; custody trails are ' +
          'checked from the envelope alone, which cannot see a deleted last entry:',
        err instanceof Error ? err.message : err,
      );
      return null;
    }
  }

  /** `relink_record_missing` / `relink_digest_mismatch` for the record's 'relinked' entries. */
  private async relinkDigestFailures(envelope: EvidenceEnvelope): Promise<CustodyRelinkFailure[]> {
    const failures: CustodyRelinkFailure[] = [];
    const chain = Array.isArray(envelope?.custodyChain) ? envelope.custodyChain : [];
    for (let index = 0; index < chain.length; index++) {
      const entry = chain[index] as { action?: unknown; metadata?: unknown } | null;
      if (entry?.action !== 'relinked') continue;
      const metadata = entry.metadata as { relinkId?: unknown; relinkDigest?: unknown } | null | undefined;
      const relinkId = metadata?.relinkId;
      const recorded = metadata?.relinkDigest;
      // An entry written before relinks carried a digest has nothing to check.
      if (typeof relinkId !== 'string' || typeof recorded !== 'string') continue;

      const relink = await this.readRelink(relinkId);
      if (relink === undefined) continue; // the store cannot say
      if (relink === null) {
        failures.push({ reason: 'relink_record_missing', index });
      } else if (computeRelinkDigest(relink) !== recorded) {
        failures.push({ reason: 'relink_digest_mismatch', index });
      }
    }
    return failures;
  }

  /**
   * The relink record, `null` when the store does not hold it, or `undefined`
   * when the store cannot say. Read once per record id per pass: one relink
   * names every record it rewrote.
   */
  private async readRelink(relinkId: string): Promise<RelinkRecord | null | undefined> {
    if (this.relinkCache.has(relinkId)) return this.relinkCache.get(relinkId);
    if (this.relinksUnreadable || typeof this.storage.getRelink !== 'function') return undefined;
    try {
      const relink = await this.storage.getRelink(relinkId);
      this.relinkCache.set(relinkId, relink);
      return relink;
    } catch (err) {
      this.relinksUnreadable = true;
      if (this.relinkFailureLogged) return undefined;
      this.relinkFailureLogged = true;
      console.error(
        "[ScheduledScanner] The store cannot read relink records; 'relinked' custody entries' " +
          'relinkDigest is not checked:',
        err instanceof Error ? err.message : err,
      );
      return undefined;
    }
  }

  /**
   * Descriptor-verification helper. Returns the number of descriptor /
   * parent-descriptor tamper incidents emitted for this envelope (0 when
   * the path is skipped or no contribution step records a model).
   */
  private async verifyDescriptorPath(envelope: EvidenceEnvelope): Promise<number> {
    // A model's bill of materials lives only in a contribution step: a
    // record whose steps name no model has no descriptor to resolve.
    if (stepModelDigests(envelope).length === 0) {
      return 0;
    }
    if (this.config.scannerVerifyDescriptors === false) {
      // Caller opted out — pass no storage so the verifier short-circuits.
      return 0;
    }

    const options: VerifyEnvelopeOptions = {
      storage: this.storage,
      walkLineage: true,
    };
    const result = await verifyEnvelope(envelope, undefined, this.registry, options);

    const incidents = result.tamperIncidents ?? [];
    for (const incident of incidents) {
      this.bus.emit(incident);
    }
    return incidents.length;
  }

  // ---------------------------------------------------------------------------
  // Phase 1.5: Attestation checking
  // ---------------------------------------------------------------------------

  /**
   * Check attestation artifacts for records claiming 'complete', 'partial' or
   * 'pending' attestation status.
   *
   * Presence alone proves nothing: a truthy string is not a timestamp. A stored
   * token can be whatever an endpoint returned on an HTTP 200 (a captive-portal
   * login page, an HTML 503 from a proxy), or a `SIMULATED_...` placeholder —
   * so a presence-only check (`!!nr.rfc3161Token` and friends) would report
   * `attestationFailures: 0` on every pass over a store with no usable
   * timestamps anywhere, while the public event type calls that counter a
   * count of "attestation verification failures".
   *
   * So every present component is verified: the timestamp and the signature by
   * `verifyAttestation` over the stored digest, which the token's imprint and
   * the assertion's challenge bind; the anchor by `verifyAnchor` over the
   * digest recomputed from the payload, as `verify()` and `get()` judge it. The
   * presence rules run on top of the verdicts rather than instead of them:
   *
   * - a component that verifies `false` is a failure, whatever the status;
   * - status 'complete' additionally requires all three components present;
   * - status 'partial' additionally requires at least one present;
   * - status 'pending' has no presence rule. It means a component the writer
   *   obtains for every record has not arrived yet (the engine's
   *   `determineAttestationStatus`) — a timestamp in hand and an anchor still
   *   to come, say. What it carries is verified like any other record's;
   *   what it is still waiting for is neither a failure nor a finding.
   *
   * A component that comes back `null` is *unchecked*, not passed — it has no
   * artifact, or the scanner was not given the trust anchor needed to check it
   * (see `ScannerAttestationDeps`). Unchecked never counts as a failure on its
   * own; the presence rules above are what catch a missing artifact.
   *
   * Trust anchors the verifiers cannot read are not a record's verdict:
   * `UnreadableTrustAnchorError` is rethrown, and the pass fails with it.
   *
   * Alongside the failure count, this returns how many records the verifier
   * reported `true` for, per component — the numerator of
   * `attestationCoverage`. Only `true` counts: `null` is unchecked and `false`
   * is a failure, and neither is a valid artifact.
   */
  async runAttestationCheckOnRecords(envelopes: EvidenceEnvelope[], chainId?: string): Promise<AttestationCheckResult> {
    let issues = 0;
    let unverifiable = 0;
    const valid: AttestationPresenceCounts = { timestamp: 0, signature: 0, anchor: 0 };
    const anchoring = this.attestationDeps.anchoring;
    const checksPublications = this.anchorPublicationsChecked();
    const material = checksPublications ? await this.publicationMaterial() : new Map<string, EvmPublicationMaterial>();

    for (const envelope of envelopes) {
      const status = envelope.attestationStatus;
      if (status !== 'complete' && status !== 'partial' && status !== 'pending') continue;

      const nr = envelope.nonRepudiation ?? {};
      const evidenceId = envelope.payload.evidenceId;

      const {
        timestamp: hasTimestamp,
        signature: hasSignature,
        anchor: hasAnchor,
      } = attestationPresenceOf(envelope);

      const emit = (
        component: 'timestamp' | 'signature' | 'anchor',
        reason: string,
        facts: { capturedAtSkewMs?: number; anchorFinality?: EvmFinality | null } = {},
      ) => {
        this.bus.emit({
          type: 'attestation_invalid',
          evidenceId,
          component,
          reason,
          ...(facts.capturedAtSkewMs !== undefined && { capturedAtSkewMs: facts.capturedAtSkewMs }),
          ...(facts.anchorFinality !== undefined && { anchorFinality: facts.anchorFinality }),
        });
        issues++;
      };

      /**
       * The artifact is there; this build cannot read it. Separate event,
       * separate counter — see AttestationUnverifiableEvent. Still reported,
       * because evidence nobody can verify is what an unattended scan is for.
       */
      const emitUnverifiable = (
        component: 'timestamp' | 'signature' | 'anchor',
        reason: string,
      ) => {
        this.bus.emit({ type: 'attestation_unverifiable', evidenceId, component, reason });
        unverifiable++;
      };

      // --- what the artifacts themselves say when actually verified ----------
      // The timestamp and the signature are judged on the STORED digest: the
      // token's imprint and the assertion's challenge bind the digest the
      // record was captured with, and whether the payload still hashes to it
      // is phase 1's question (`digest_mismatch`).
      const options: AttestationVerifyOptions = {
        timestampVerification: this.attestationDeps.timestampVerification ?? 'structural',
      };
      if (this.attestationDeps.allowedOrigins) {
        options.allowedOrigins = this.attestationDeps.allowedOrigins;
      }
      if (this.attestationDeps.rpId) {
        options.rpId = this.attestationDeps.rpId;
      }
      // Binding check, on by default. A caller-supplied
      // expectation is an assertion about this record and a mismatch is a
      // finding; the derived fallback is the verifier's own guess at what the
      // ceremony should have signed, and a mismatch there is
      // `assertion_not_bound_to_digest` — true of a pre-0.3.16 record and of a
      // replayed assertion alike, and not something to raise an incident over.
      const supplied = this.attestationDeps.expectedChallengeFor?.(envelope);
      if (supplied !== undefined) {
        options.expectedChallenge = supplied;
      } else {
        options.expectedChallenge = webauthnChallengeForDigest(envelope.integrity.canonicalDigest);
        options.expectedChallengeSource = 'derived-from-digest';
      }

      // The anchor end to end (tzun-anchor/1 §10.3): the record's position
      // and chain, and, with the scanner's own manifest and chains, its EVM
      // publication, joined with the material the store kept for it.
      const anchorOptions: AnchorVerifyOptions = {};
      if (typeof envelope.payload?.sequenceNumber === 'number') anchorOptions.sequenceNumber = envelope.payload.sequenceNumber;
      if (chainId !== undefined) anchorOptions.chainId = chainId;
      if (checksPublications && anchoring) {
        anchorOptions.publisherManifest = anchoring.publisherManifest;
        anchorOptions.evmHeaderSources = this.headerSources();
        if (anchoring.evmNetworks) anchorOptions.evmNetworks = anchoring.evmNetworks;
        if (anchoring.evmTimeoutMs !== undefined) anchorOptions.evmTimeoutMs = anchoring.evmTimeoutMs;
        const joined = materialFor(nr, material);
        if (joined.length > 0) anchorOptions.publicationMaterial = joined;
      }

      let verdict: Awaited<ReturnType<typeof verifyAttestation>> | null = null;
      let anchorVerdict: AnchorVerification | null = null;
      try {
        verdict = await verifyAttestation(
          withoutAnchor(nr),
          envelope.integrity.canonicalDigest,
          this.attestationDeps.credentialStore,
          // capturedAt comes from the HASHED payload, which is the copy worth
          // checking — the token commits to it, so a mismatch against genTime
          // means the clock that minted it was wrong at capture time.
          { ...options, capturedAt: envelope.payload?.capturedAt },
        );
      } catch (err) {
        // Trust anchors that cannot be read are a configuration the whole
        // pass depends on, not this record's verdict: the pass fails.
        if (err instanceof UnreadableTrustAnchorError) throw err;
        // The verifier itself failed. Fall through to the presence rules
        // rather than inventing a verdict in either direction.
        verdict = null;
      }
      if (hasAnchor) {
        // The anchor is judged on the digest RECOMPUTED from the payload, as
        // `verify()` and `get()` judge it: an anchor that holds
        // only for the stored digest does not hold for a record whose payload
        // was altered under it. A payload that cannot be hashed has no digest
        // (''), and no proof holds for it.
        try {
          anchorVerdict = await verifyAnchor(nr, this.recomputeDigest(envelope), anchorOptions);
        } catch (err) {
          if (err instanceof UnreadableTrustAnchorError) throw err;
          // `verifyAnchor` reports its own failures as `anchor_verifier_error`;
          // anything that still escapes goes to the presence rules, as above.
          anchorVerdict = null;
        }
      }

      let timestampFailed = false;
      let signatureFailed = false;
      let anchorFailed = false;

      if (verdict) {
        if (verdict.timestampValid === false) {
          emit('timestamp', verdict.timestampReason ?? 'verification_failed');
          timestampFailed = true;
        } else if (verdict.timestampValid === true) {
          valid.timestamp++;
        }
        if (verdict.signatureValid === false) {
          emit('signature', verdict.signatureReason ?? 'verification_failed');
          signatureFailed = true;
        } else if (verdict.signatureValid === true) {
          valid.signature++;
        }
        // A capturedAt later than the genTime that notarised it is not a
        // degraded attestation, it is an internally inconsistent record: the
        // token is over a digest committing to capturedAt, so capturedAt
        // cannot postdate the stamp. Reported on the timestamp component,
        // because it is the timestamp's relationship to the record that broke.
        // The skew goes with it: its size is what separates a clock that
        // drifted ahead from one that was far off.
        if (verdict.capturedAtValid === false && verdict.capturedAtReason !== undefined) {
          emit('timestamp', verdict.capturedAtReason, { capturedAtSkewMs: verdict.capturedAtSkewMs });
          timestampFailed = true;
        }
      }
      if (anchorVerdict) {
        // The finality the chain was read under goes with a failure it took
        // part in: a block the chain no longer holds at 2
        // confirmations is a different incident from one it no longer holds
        // at its finalized block.
        const anchorFinality = finalityJudgedUnder(anchorVerdict);
        if (anchorVerdict.anchorValid === false) {
          emit('anchor', anchorVerdict.anchorReason ?? 'verification_failed', { anchorFinality });
          anchorFailed = true;
        } else if (anchorVerdict.anchorValid === true) {
          valid.anchor++;
        } else if (anchorVerdict.anchorReason !== undefined && ESCALATED_ANCHOR_REASONS.has(anchorVerdict.anchorReason)) {
          // The verifier ABSTAINS here (null, not false): the anchor names a
          // construction or version this build does not read, or it is a
          // `blockchainAnchor`, which tzun-anchor/1 does not read at all. The
          // scanner is a different question with a different answer
          // (tzun-anchor/1 §10.10): stored evidence whose anchor has become
          // unverifiable is a finding, `attestation_invalid`, and staying
          // silent would let a rewritten tag turn a failing anchor into a pass.
          emit('anchor', anchorVerdict.anchorReason);
          anchorFailed = true;
        } else if (anchorVerdict.anchorReason !== undefined && UNVERIFIABLE_ANCHOR_REASONS.has(anchorVerdict.anchorReason)) {
          // An anchor this build cannot check for another reason: its
          // publications are of kinds it does not implement, it lists none, or
          // the verifier itself failed. Reported, as "could not check".
          emitUnverifiable('anchor', anchorVerdict.anchorReason);
          // Still "not usable" for the presence rule below: an anchor we cannot
          // read does not satisfy the requirement that a 'partial' record carry
          // at least one artifact that actually holds up.
          anchorFailed = true;
        }
      }

      // --- presence, on top of the verdicts ---------------------------------
      // None for 'pending': what it lacks has not arrived yet.
      if (status === 'complete') {
        // All three must be present for complete attestation.
        if (!hasTimestamp) emit('timestamp', 'missing');
        if (!hasSignature) emit('signature', 'missing');
        if (!hasAnchor) emit('anchor', 'missing');
      } else if (status === 'partial') {
        // 'partial' — at least one artifact must be present, and one that is
        // present but demonstrably bad does not satisfy the requirement.
        const usableTimestamp = hasTimestamp && !timestampFailed;
        const usableSignature = hasSignature && !signatureFailed;
        const usableAnchor = hasAnchor && !anchorFailed;
        if (!usableTimestamp && !usableSignature && !usableAnchor) {
          // Do not double-count: if a component already failed verification, the
          // failure has been reported and the record is already counted.
          if (!timestampFailed && !signatureFailed && !anchorFailed) {
            emit('timestamp', 'missing');
          }
        }
      }
    }

    return { issues, unverifiable, valid };
  }

  // ---------------------------------------------------------------------------
  // Phase 2: the chain walk
  // ---------------------------------------------------------------------------

  /**
   * Walk one chain with `verifyChainCompleteness()` and emit what it finds.
   *
   * The walk owns the chain rules: duplicate and backwards sequence numbers,
   * every link — the genesis record's included — sequence continuity against
   * `to`, whether each record is still the one that was captured, and whether
   * `capturedAt` runs backwards. `to` is the chain's high-water mark from chain
   * state, a counter that survives DELETEs of evidence rows, and comparing
   * against it is what makes a deleted TAIL — or a chain with no rows left at
   * all — visible: with no survivor after the missing records, nothing else
   * would notice them. This phase translates the walk's answer into the
   * scanner's event vocabulary:
   *
   *   sequenceGaps       → one `sequence_gap` per run of consecutive numbers
   *   duplicateSequences → one `duplicate_sequence` per extra record
   *   brokenLinks        → one `chain_break` per record
   *   digestSuperseded   → one `digest_superseded` per record
   *   timeRegressions    → one `captured_at_regression` per record
   *   digestDiffersFromLoggedLeaf
   *                      → one `digest_differs_from_logged_leaf` per record
   *   anchorStripped     → one `anchor_stripped` per record
   *
   * The last two come from the chain's evidence log (checks a and h of
   * `anchor-log-checks.ts`), which the walk is given on a store that keeps
   * one. Against the same log, each record whose position holds a leaf is
   * checked for an anchor made for another leaf (`transplantedFrom`, the rule
   * `get()` reports by): one `anchor_transplanted` per record.
   *
   * `digestMismatches` is not emitted here: Phase 1 recomputes every digest
   * and has already reported each mismatch, with both digests.
   *
   * Returns per-category event counts and the rows the walk judged, so
   * callers can reuse them without a second storage read.
   */
  async runPhase2(from: number, to: number, chainId?: string): Promise<Phase2Result> {
    const read = recordingReads(this.storage);
    const store = chainId !== undefined ? await this.storeLogs() : null;
    const evidenceLog = chainId !== undefined ? (store?.chainEvidenceLog(chainId) ?? null) : null;
    // Every leaf the walk reads, so an event names the very digest it judged.
    const loggedDigests = new Map<number, string>();
    const completeness = await verifyChainCompleteness(read.storage, this.registry, {
      fromSequence: from,
      toSequence: to,
      chainId,
      ...(evidenceLog && {
        evidenceLog: {
          leaves: async (fromIndex: number, toIndex: number) => {
            const leaves = await evidenceLog.reader.leaves(fromIndex, toIndex);
            for (const l of leaves) loggedDigests.set(l.leafIndex, l.leafDigest);
            return leaves;
          },
          anchorFillDone: evidenceLog.reader.anchorFillDone,
        },
      }),
    });
    const envelopes = read.records;

    // --- sequence_gap ------------------------------------------------------
    // The walk lists every missing number; the event names a missing range,
    // which TamperDetector turns into one incident spanning
    // [expectedSequence, foundSequence - 1] — one incident per destroyed
    // run, not one per deleted row.
    let sequenceGaps = 0;
    for (const run of consecutiveRuns(completeness.sequenceGaps)) {
      this.bus.emit({ type: 'sequence_gap', expectedSequence: run.from, foundSequence: run.to + 1 });
      sequenceGaps++;
    }

    // --- duplicate_sequence ------------------------------------------------
    // The walk names a duplicate by its sequence number; the event names the
    // record. Rows come back in sequence order (the listBySequence contract),
    // so rows sharing a number sit together and the walk flags each one after
    // the first: for a number it lists k times, the event goes to the last k
    // rows carrying that number.
    const timesListed = new Map<number, number>();
    for (const n of completeness.duplicateSequences) {
      timesListed.set(n, (timesListed.get(n) ?? 0) + 1);
    }
    const rowsCarrying = new Map<number, number[]>();
    envelopes.forEach((envelope, i) => {
      const n = envelope?.payload?.sequenceNumber;
      if (!timesListed.has(n)) return;
      const rows = rowsCarrying.get(n) ?? [];
      rows.push(i);
      rowsCarrying.set(n, rows);
    });
    const duplicateRows: number[] = [];
    for (const [n, k] of timesListed) {
      duplicateRows.push(...(rowsCarrying.get(n) ?? []).slice(-k));
    }
    let duplicateSequences = 0;
    for (const i of duplicateRows.sort((a, b) => a - b)) {
      const { evidenceId, sequenceNumber } = envelopes[i].payload;
      this.bus.emit({
        type: 'duplicate_sequence',
        evidenceId,
        sequenceNumber,
        previousSequence: envelopes[i - 1]?.payload?.sequenceNumber ?? sequenceNumber,
      });
      duplicateSequences++;
    }

    // The remaining findings name records by evidence ID.
    const rowOf = new Map<string, number>();
    envelopes.forEach((envelope, i) => {
      const id = envelope?.payload?.evidenceId;
      if (!rowOf.has(id)) rowOf.set(id, i);
    });
    const row = (evidenceId: string): EvidenceEnvelope | undefined => {
      const i = rowOf.get(evidenceId);
      return i === undefined ? undefined : envelopes[i];
    };

    // --- chain_break -------------------------------------------------------
    // The event also carries the record's sequence number and the digest of
    // the row before it, which is what the link should have been computed
    // onto — '' for a first row, which has no predecessor.
    let chainBreaks = 0;
    for (const evidenceId of completeness.brokenLinks) {
      const i = rowOf.get(evidenceId);
      const previous = i !== undefined && i > 0 ? envelopes[i - 1] : undefined;
      this.bus.emit({
        type: 'chain_break',
        evidenceId,
        sequenceNumber: row(evidenceId)?.payload?.sequenceNumber ?? 0,
        expectedPrevDigest: previous?.integrity?.canonicalDigest ?? '',
      });
      chainBreaks++;
    }

    // --- digest_superseded -------------------------------------------------
    // Both digests: the one the capture revision recorded, as the walk read
    // it, and the one the record carries now.
    let digestSuperseded = 0;
    for (const evidenceId of completeness.digestSuperseded) {
      const envelope = row(evidenceId);
      this.bus.emit({
        type: 'digest_superseded',
        evidenceId,
        sequenceNumber: envelope?.payload?.sequenceNumber ?? 0,
        capturedDigest: read.captureDigests[evidenceId] ?? '',
        currentDigest: envelope?.integrity?.canonicalDigest ?? '',
      });
      digestSuperseded++;
    }

    // --- captured_at_regression --------------------------------------------
    let timeRegressions = 0;
    for (const evidenceId of completeness.timeRegressions) {
      const envelope = row(evidenceId);
      this.bus.emit({
        type: 'captured_at_regression',
        evidenceId,
        sequenceNumber: envelope?.payload?.sequenceNumber ?? 0,
        capturedAt: envelope?.payload?.capturedAt ?? '',
      });
      timeRegressions++;
    }

    // --- digest_differs_from_logged_leaf (check a) -------------------------
    let logFindings = 0;
    for (const evidenceId of completeness.digestDiffersFromLoggedLeaf ?? []) {
      const envelope = row(evidenceId);
      const sequenceNumber = envelope?.payload?.sequenceNumber ?? 0;
      this.bus.emit({
        type: 'digest_differs_from_logged_leaf',
        evidenceId,
        sequenceNumber,
        origin: evidenceLog?.log.origin ?? '',
        loggedDigest: loggedDigests.get(sequenceNumber - 1) ?? '',
        currentDigest: envelope?.integrity?.canonicalDigest ?? '',
      });
      logFindings++;
    }

    // --- anchor_stripped (check h) -----------------------------------------
    for (const evidenceId of completeness.anchorStripped ?? []) {
      this.bus.emit({
        type: 'anchor_stripped',
        evidenceId,
        sequenceNumber: row(evidenceId)?.payload?.sequenceNumber ?? 0,
        origin: evidenceLog?.log.origin ?? '',
      });
      logFindings++;
    }

    // --- anchor_transplanted -------------------------------------------------
    // A record's artifact against its own log and leaf. With an opaque log
    // origin the verifier leaves the chain unchecked, and this is what ties
    // the anchor to the record's chain. A record is judged at the position
    // its hashed sequence number names, as the walk judges it, and only where
    // the log holds a leaf, as `get()` reports only a record its store
    // logged. Reported once per record.
    if (evidenceLog) {
      const reported = new Set<string>();
      for (const envelope of envelopes) {
        const sequenceNumber: unknown = envelope?.payload?.sequenceNumber;
        const evidenceId: unknown = envelope?.payload?.evidenceId;
        if (typeof evidenceId !== 'string' || reported.has(evidenceId)) continue;
        if (typeof sequenceNumber !== 'number' || !Number.isSafeInteger(sequenceNumber) || sequenceNumber < 1) continue;
        const leafIndex = sequenceNumber - 1;
        if (!loggedDigests.has(leafIndex)) continue;
        const named = transplantedFrom(envelope, { origin: evidenceLog.log.origin, leafIndex });
        if (!named) continue;
        reported.add(evidenceId);
        this.bus.emit({
          type: 'anchor_transplanted',
          evidenceId,
          sequenceNumber,
          origin: evidenceLog.log.origin,
          artifactOrigin: named.origin,
          artifactLeafIndex: named.leafIndex,
        });
        logFindings++;
      }
    }

    return {
      chainBreaks,
      sequenceGaps,
      duplicateSequences,
      digestSuperseded,
      timeRegressions,
      logFindings,
      envelopes,
      completeness,
    };
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Partition the range [from, to] into segments of batchSize.
   */
  private partitionIntoSegments(
    from: number,
    to: number,
  ): Array<{ from: number; to: number }> {
    const segments: Array<{ from: number; to: number }> = [];
    let cursor = from;
    while (cursor <= to) {
      const segEnd = Math.min(cursor + this.config.batchSize - 1, to);
      segments.push({ from: cursor, to: segEnd });
      cursor = segEnd + 1;
    }
    return segments;
  }

  /**
   * Recompute the canonical digest for an envelope using the schema registry.
   */
  private recomputeDigest(envelope: EvidenceEnvelope): string {
    const schema = this.registry.get(envelope.payload.schemaVersion);
    if (!schema) {
      // An unknown schemaVersion is tampering, not an unverifiable record.
      //
      // schemaVersion is NOT in v1.0's hashedFieldSet, so an attacker with
      // UPDATE on the evidence table can flip it without disturbing the digest.
      // The registry only ever contains v1.0, so any other value is
      // unambiguous evidence of modification.
      //
      // Throwing here would propagate out of verifyDigestsInRange →
      // Promise.all → runPhase1 → runFullPass, so a single doctored row would
      // kill the whole pass: no digest_mismatch for the record, no
      // scan_completed, no Phase 2 chain and gap checks, and scanner state left
      // mid-pass so /v1/integrity/status reports scannerRunning: true forever.
      // Every subsequent pass would die the same way, leaving the entire chain
      // unmonitored while chainStatus stayed 'healthy'. One row could switch
      // off monitoring for a whole chain.
      //
      // Returning '' makes the comparison in verifyDigestsInRange fail, so the
      // record is reported as a digest_mismatch with recomputed='' and the pass
      // carries on.
      return '';
    }
    // Same blast radius, same answer, one layer down.
    // canonicalSerialize throws by design on a payload it cannot render
    // injectively — a lone UTF-16 surrogate (which JSON.stringify preserves as
    // \ud800 straight through every adapter into the store), nesting past
    // MAX_DEPTH, a non-finite number. Uncaught, that throw would propagate as
    // described above: one such row would kill the whole pass and leave the
    // chain unmonitored while chainStatus stayed 'healthy'. A payload this
    // implementation cannot canonicalize has no recomputable digest, so '' is
    // the answer and the record is reported as a mismatch.
    try {
      return computeDigest(
        canonicalSerialize(
          envelope.payload as unknown as Record<string, unknown>,
          schema.hashedFieldSet,
        ),
      );
    } catch {
      return '';
    }
  }
}
