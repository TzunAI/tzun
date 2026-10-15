/**
 * The anchor scheduler: one domain, one leader (tzun-anchor/1 §5, §6, §7.2,
 * §8.4, §11).
 *
 * Each pass, run by the leader only:
 *
 *   1. Lease. Take or renew `anchor_lease`; a replica that does not hold it
 *      does nothing (every replica keeps writing leaves). The lease is renewed
 *      again before every signature, every broadcast and every fill chunk,
 *      and a pass that finds it taken stops where it is.
 *   2. Wallet. Read the dedicated publisher's enrolment, or its `nonce_base`
 *      when it is not enrolled yet. It is enrolled, once, by the first
 *      transaction its signer returns that passes the check, before that
 *      transaction is stored: a signer whose stated address is not the one
 *      that signs enrols nothing.
 *   3. Confirm what is in flight, in publication order:
 *        prepared   sign, persist the raw transaction, then broadcast (the outbox);
 *        submitted  look up a receipt for every attempt; without one, rebroadcast
 *                   the latest attempt's stored bytes, and replace a stuck
 *                   attempt (same nonce, same calldata, +12.5%, at most 5,
 *                   clamped to the hard cap). A publication another wallet
 *                   signed is rebroadcast only, never replaced, with the
 *                   `anchor_publication_other_wallet` alarm;
 *        included   a vanished receipt or a moved block is a reorg; a block at
 *                   or below the node's `finalized` tag, still canonical, is
 *                   final: the header, transaction index and trie proof are
 *                   stored with the publication.
 *   4. Fill every finalized publication's records (fill-only, chunked), after
 *      the history check (below) when there is anything to fill.
 *   5. When an epoch is due (cadence, governor) and no publication is unmined:
 *      check the past (the last finalized transaction still carries P from
 *      the publisher in a canonical block, and the anchor log still rebuilds
 *      its root), cut the epoch in one transaction, and publish it. The
 *      epoch's transaction checks, under the lease row's lock, that this
 *      instance still holds the lease and that nothing was published since
 *      the epoch was planned (`EpochGuard`).
 *
 * There is at most one unmined publication at a time, so a nonce is never
 * signed past one the chain has not taken. A mined publication awaiting
 * finality does not block the next epoch.
 *
 * Nothing the scheduler signs, sends, fills or plans rests on a row because it
 * is stored (explain.ts). Every publication row is authenticated at the start
 * of each pass by its signed transactions, each read as tzun-anchor/1 §10.4
 * item 2 reads one, and a sender the configuration or the manifest names,
 * inside that sender's window. What a publisher returns is read the same way
 * before it is stored (§7.2 rule 3). Every broadcast, a stored transaction sent
 * again included, reads the bytes about to be sent the same way first, and
 * sends a publication's only at the nonce and over the P it was signed or
 * authenticated with this pass (`unsendableAs`, §7.2 rule 3). A first signature
 * is given only to an epoch this process planned, or to a prepared one the
 * anchor log re-derives above the published size B, when the cadence calls it
 * due (the sign gate). An epoch is planned only on the anchor log explained
 * above B, each leaf the digest of a source checkpoint of a kind the scheduler
 * anchors (`sourceLogKinds`) that its log's leaves rebuild. Finality and the
 * published size's block count only when the node confirms them; until it does,
 * the pass defers what builds on them (`anchor_history_unverified`). A fill
 * writes only under a publication the node confirms, over a range it explains,
 * onto records that match their leaves.
 *
 * `anchor_history_mismatch`, `anchor_nonce_consumed_externally`,
 * `anchor_log_leaf_unexplained`, `anchor_publication_unexplained` and
 * `anchor_wallet_tx_unexplained` stop the scheduler: every later pass does
 * nothing until it is recreated. A new instance repeats every check before
 * it fills or extends anything. An unexplained anchor leaf stays in the
 * insert-only anchor log, so the domain moves to a new store identity.
 *
 * Passes and the wallet operations (`sweep`, `handover`,
 * `rebroadcastAccountedTransaction`) run one at a time, and a wallet
 * operation needs the lease too.
 */
import { randomBytes } from 'node:crypto';
import type { AttestationExpectation } from '@tzun/engine';
import { anchorLogOrigin, checkpointDigest, parseOrigin } from '../attestation/checkpoint';
import { readEvmTransaction, verifyEvmTransactionProof, type EvmItemTwoRule, type PublisherManifest } from '../attestation/blockchain';
import {
  ANCHOR_LEASE_HOLDER_PREFIX,
  ANCHOR_LOG_KIND,
  AnchorEpochFenceError,
  InvalidLogNamespaceError,
  LogNamespaceMismatchError,
  anchorStoreFor,
  assertLogNamespace,
  assertWalletTx,
  logStoreFor,
  type AnchorBroadcastOutcome,
  type AnchorPublication,
  type AnchorPublicationAttempt,
  type AnchorStore,
  type AnchorWallet,
  type AnchorWalletTx,
  type LogLeaf,
  type LogRecord,
  type LogStore,
} from '../storage/log-store';
import { AttestationRetryScheduler } from '../sdk/attestation-retry-scheduler';
import { sdkLog, type LogSink } from '../sdk/log';
import { resolveAnchoringConfig, type AnchoringConfig, type ResolvedAnchoringConfig } from './config';
import {
  ALARM_SEVERITY,
  AnchorActivationError,
  AnchoringConfigError,
  AnchorForceRateLimitedError,
  AnchorNotLeaderError,
  AnchorSignerError,
  AnchorSignerUnavailableError,
  AnchorWalletError,
  STOPPING_ALARMS,
  itemTwoRefusal,
  type AnchorAlarm,
  type AnchorAlarmCode,
} from './errors';
import { EvmBlockMaterialError, publisherFor, type EvmBroadcastResult, type EvmPublisher, type EvmReceipt } from './evm-chain';
import { expectedOrigin, planEpoch } from './epoch';
import {
  AnchorLogTrust,
  AnchorTrustError,
  DEFAULT_SOURCE_LOG_KINDS,
  PublicationTrust,
  allowedPublishers,
  senderAllowed,
  type ExplainedRange,
} from './explain';
import { fillDoneHolds, fillPublication, readFillProgress } from './fill';
import {
  ANCHOR_PUBLICATION_GAS_LIMIT,
  DAY_MS,
  MAX_REPLACEMENTS,
  RUNWAY_CRITICAL_DAYS,
  RUNWAY_WARNING_DAYS,
  cadenceDecision,
  feeDecision,
  governorView,
  gweiToWei,
  minPriorityFeeWei,
  publicationFees,
  replacementFees,
  withPriorityFeeFloor,
  type GovernorView,
} from './governor';
import { buildTxTrie } from './tx-trie';

/** The scheduler's own tunables. They are not the deployment's cadence, which is configuration. */
export interface AnchorSchedulerTuning {
  /** Wait between passes. Default 60 s. */
  tickMs: number;
  /** Ceiling on the backed-off wait while passes fail. Default 15 min. */
  maxBackoffMs: number;
  /** How long a lease lasts without renewal. Default 5 min. */
  leaseTtlMs: number;
  /** An unmined attempt older than this, and priced under the base fee or unknown to the node, is stuck. Default 10 min. */
  stuckAfterMs: number;
  /** Records per fill transaction. Default 500. */
  fillChunkSize: number;
  /**
   * How long the node may leave a publication unconfirmed whose finality or
   * block carries trust (the last finalized, the published size's, one
   * awaiting its fill) before `anchor_history_unverified` turns critical. The
   * pass defers what depends on it from the first unconfirmed read. Default
   * one hour.
   */
  unverifiedEscalateMs: number;
  /**
   * How far ahead of the scheduler's clock a publication's `created_at`, or
   * an attempt's `sentAt`, may be: a later time does not authenticate (the
   * cadence, the force window and the stuck test read them). Default 5 min.
   */
  maxClockSkewMs: number;
}

export const DEFAULT_ANCHOR_TUNING: Readonly<AnchorSchedulerTuning> = Object.freeze({
  tickMs: 60_000,
  maxBackoffMs: 15 * 60_000,
  leaseTtlMs: 5 * 60_000,
  stuckAfterMs: 10 * 60_000,
  fillChunkSize: 500,
  unverifiedEscalateMs: 60 * 60_000,
  maxClockSkewMs: 5 * 60_000,
});

/** @internal Test seams: where a crash would do the most harm. */
export interface AnchorSchedulerTestHooks {
  /** After a signed attempt is persisted, before it is broadcast. */
  afterPersistAttempt?: (publication: AnchorPublication) => void | Promise<void>;
  /** After a broadcast returned, before its outcome is recorded. */
  afterBroadcast?: (publication: AnchorPublication, result: EvmBroadcastResult) => void | Promise<void>;
}

export interface AnchorSchedulerOptions {
  /** A SQLite or Postgres adapter: its `logStore()` and `anchorStore()` are used. */
  storage?: unknown;
  /** The stores, when not taken from `storage`. */
  logStore?: LogStore;
  anchorStore?: AnchorStore;
  config: AnchoringConfig;
  /**
   * The publisher. Default: built from `config.publishers.evm` (its
   * `privateKey`, or its external `signer`), over JSON-RPC on its `rpcUrl`.
   * What a publisher passed here returns is sent as it is, once the
   * scheduler has read it (`EvmPublisher`).
   */
  publisher?: EvmPublisher;
  /** Epoch milliseconds. Default `Date.now`. */
  clock?: () => number;
  /** This instance's lease holder id. Default: random. */
  holderId?: string;
  /**
   * What the store's writers expect every record to carry (`timestamp`,
   * `anchor`): the expectation `determineAttestationStatus` is given when a
   * fill recomputes a record's status. Required, because a default would
   * speak for the writers. Unless it says `timestamp: false`, a fill leaves a
   * `pending` record that has no timestamp `pending`, for the
   * pending-attestation retry. `Tzun.init()` passes its own expectation, so a
   * `Tzun` that obtains no timestamp says `timestamp: false`.
   *
   * A record does not say what its writer expected, so this one expectation
   * is applied to every record a fill writes: every writer of an anchored
   * store must expect the same timestamp. The fill records the expectation it
   * used in the publication's `fill_progress`, and an instance whose own
   * differs raises `anchor_expectation_mismatch` on its next pass.
   */
  expectation: AttestationExpectation;
  /**
   * A verifier's publisher manifest (tzun-anchor/1 §9). An entry naming this
   * publisher in the `production` namespace makes it a production publisher,
   * which the activation guard refuses without `production: true`. Default:
   * `config.publisherManifest`.
   */
  publisherManifest?: PublisherManifest;
  /**
   * Whether a waiting leaf of a non-evidence log is an `anchor_fill` revision
   * leaf, which rides along and starts an epoch only at T_max. Evidence leaves
   * always start one. Default: none rides along.
   */
  isRideAlongLeaf?: (log: LogRecord, leaf: LogLeaf) => boolean;
  /**
   * The kinds of source log the scheduler anchors (tzun-anchor/1 §11 item 4). A
   * kind belongs here only when the store binds every leaf of its logs to a
   * stored row, as the SQL stores bind each evidence leaf to its record, and
   * its leaves' preimages can never be a record's canonical bytes. A log of
   * another kind is not anchored, and is logged once (`anchor_log_ignored`).
   * Remove a kind only while no epoch is in flight: an unpublished epoch that
   * holds a leaf of a removed kind stops the scheduler. Default `['evidence']`.
   */
  sourceLogKinds?: readonly string[];
  /**
   * The least priority fee a publication is signed with, in gwei. Default:
   * `DEFAULT_MIN_PRIORITY_FEE_GWEI` for the chain (0.1 gwei on Ethereum
   * mainnet, none elsewhere); 0 turns it off.
   */
  minPriorityFeeGwei?: number;
  tuning?: Partial<AnchorSchedulerTuning>;
  onLog?: LogSink;
  onAlarm?: (alarm: AnchorAlarm) => void;
  /** @internal */
  testHooks?: AnchorSchedulerTestHooks;
}

/** A publication as `getAnchorState()` reports it. */
export interface AnchorPublicationSummary {
  id: number;
  epochId: number;
  anchorSize: number;
  p: string;
  state: AnchorPublication['state'];
  forced: boolean;
  nonce: number | null;
  attempts: number;
  transactionId: string | null;
  blockNumber: number | null;
  createdAt: string;
}

/** What one pass did. */
export interface AnchorPassReport {
  /** This instance held the lease. */
  leader: boolean;
  /** Anchoring is stopped by an alarm (see `halted` in the state). */
  halted: boolean;
  /** The epoch this pass cut, if any. */
  epoch: { epochId: number; anchorSize: number; p: string; publicationId: number; members: number; forced: boolean } | null;
  /**
   * Why a due epoch or a signing was put off, if it was: a governor or
   * cadence reason, `not_leader`, `lease_lost` (another instance took the
   * lease during the pass), or an `AnchorEpochFenceError` reason
   * (`lease_not_held`, `publication_unmined`, `published_size_moved`).
   */
  deferred: string | null;
  /** Publication state changes, in order. */
  transitions: Array<{ publicationId: number; from: AnchorPublication['state']; to: AnchorPublication['state'] }>;
  /** Broadcasts this pass made. */
  broadcasts: Array<{ publicationId: number; txHash: string; outcome: AnchorBroadcastOutcome; reason: string }>;
  /** Records filled. */
  filled: number;
  /** A mined publication is waiting for its block to be final. */
  awaitingFinality: boolean;
  /** A broadcast publication is waiting to be mined, and the node has it. */
  awaitingInclusion: boolean;
  /** Alarms raised in this pass. */
  alarms: AnchorAlarm[];
  /** A forced epoch refused by the rolling limit; `anchorNow` throws it. */
  forceRefused?: AnchorForceRateLimitedError;
}

/** What `getAnchorState()` returns. */
export interface AnchorState {
  domainPrefix: string;
  anchorOrigin: string;
  /** `test` for a `test.` origin; otherwise `production`. */
  namespace: 'test' | 'production';
  production: boolean;
  chain: string;
  publisher: string;
  lease: { holder: string; expiresAt: string; self: boolean } | null;
  halted: AnchorAlarm | null;
  nextEpochDueAt: string | null;
  lastPublished: AnchorPublicationSummary | null;
  lastFinalized: AnchorPublicationSummary | null;
  inFlight: AnchorPublicationSummary[];
  wallet: {
    enrolled: boolean;
    nonceBase: number | null;
    /** Wei, as of the last pass. */
    balanceWei: string | null;
    /** Days, as of the last pass. */
    runwayDays: number | null;
  };
  fees: {
    baseFeePerGasWei: string | null;
    maxPriorityFeePerGasWei: string | null;
    softMaxFeeGwei: number;
    hardFeeCapGwei: number;
  };
  intervalMs: number | null;
  overBudget: boolean | null;
  /** Wei spent on finalized publications, from their receipts. */
  spentWei: string;
  force: { usedInLast24h: number; limit: number };
  /** Records of finalized publications not filled yet. */
  fillBacklog: number;
  stalledPasses: number;
  lastPassAt: string | null;
  lastError: string | null;
  alarms: AnchorAlarm[];
}

/** Nonce accounting for the publisher wallet. */
export interface NonceAccounting {
  address: string;
  chain: string;
  nonceBase: number;
  /** The wallet's mined transaction count. */
  transactionCount: number;
  accounted: Array<{ nonce: number; kind: 'publication' | 'sweep' | 'handover'; txHash: string }>;
  /** Nonces in [nonceBase, transactionCount) that map to nothing this store holds: `anchor_wallet_nonce_unaccounted`. */
  unaccounted: number[];
}

/** What `sweep`, `handover` and `rebroadcastAccountedTransaction` did. */
export interface AccountedTransactionResult {
  /** The accounted transaction, as stored before it was sent. */
  tx: AnchorWalletTx;
  /** What the node said to the broadcast; null when the transaction was already mined and nothing was sent. */
  broadcast: EvmBroadcastResult | null;
  /**
   * The wallet is retired for this domain: the broadcast was accepted or had
   * no answer, or the transaction is mined. A refused broadcast leaves the
   * wallet enrolled, and the stored transaction is sent again with
   * `rebroadcastAccountedTransaction()`.
   */
  retired: boolean;
}

export interface AnchorScheduler {
  /** Run one pass now, after any pass in flight. */
  runPass(): Promise<AnchorPassReport>;
  /**
   * Run a pass now. With `force`, an epoch is cut even when the cadence says it
   * is not due, minInterval included; the hard cap, the soft maximum, the 3×
   * balance refusal and the rolling limit still hold.
   *
   * @throws {AnchorForceRateLimitedError} the seventh forced publication in 24 h (by default).
   */
  anchorNow(options?: { force?: boolean }): Promise<AnchorPassReport>;
  getAnchorState(): Promise<AnchorState>;
  /**
   * The interval the cadence cuts epochs at: the governor's, as of the last
   * pass that read the wallet and the fees, or `targetIntervalMs` before one
   * has. A leaf logged at `t` is due in an epoch by `t` plus it (the store's
   * `get()` reports that as `anchorState.dueBy`).
   */
  intervalMs(): number;
  /** Nonce accounting for the publisher wallet (tzun-anchor/1 §7.2 rule 2). */
  accountNonces(): Promise<NonceAccounting>;
  /**
   * Return the wallet's balance to `to` and retire the wallet. The signed
   * transaction is stored as an accounted `sweep` before it is sent.
   *
   * Refused while any publication is not finalized and filled (retiring the
   * wallet would strand it), while an accounted transaction of the wallet is
   * stored and not mined, and on an instance that does not hold the lease
   * (`AnchorNotLeaderError`).
   */
  sweep(to: string): Promise<AccountedTransactionResult>;
  /**
   * The last transaction of this domain's wallet, when it passes to another
   * domain after a wipe (Anchor §4.3.2): a zero-value self-transaction whose
   * calldata is the new anchor origin's bytes, stored as an accounted
   * `handover` before it is sent. The wallet is retired for this domain.
   * Refused as `sweep` is, and for an origin that is not another domain's
   * anchor log origin (`<ns>/<id>/anchors`).
   */
  handover(newAnchorOrigin: string): Promise<AccountedTransactionResult>;
  /**
   * Send the wallet's latest accounted transaction again, from its stored
   * bytes, and retire the wallet once it is accepted or mined. For a sweep or
   * handover whose broadcast was refused or lost.
   */
  rebroadcastAccountedTransaction(): Promise<AccountedTransactionResult>;
  /** Run passes every `tickMs`. */
  start(): Promise<void>;
  /** Stop the schedule, wait for a pass in flight, release the lease. */
  stop(): Promise<void>;
  /**
   * `stop()`, then close a chain connection the scheduler opened. Final: from
   * the moment it is called, `runPass`, `anchorNow`, `getAnchorState` and the
   * wallet operations throw, so no pass starts on a store about to close.
   */
  close(): Promise<void>;
}

const EVM = 'evm-calldata/1' as const;

/** A pass found the lease taken by another instance: it stops where it is. */
class LeaseLost extends Error {
  constructor(readonly holder: string) {
    super(`the anchor lease is held by ${holder}`);
    this.name = 'LeaseLost';
  }
}
const UNMINED: ReadonlyArray<AnchorPublication['state']> = ['prepared', 'submitted'];
const IN_FLIGHT: ReadonlyArray<AnchorPublication['state']> = ['prepared', 'submitted', 'included'];

function summary(p: AnchorPublication): AnchorPublicationSummary {
  return {
    id: p.id,
    epochId: p.epochId,
    anchorSize: p.anchorSize,
    p: p.p,
    state: p.state,
    forced: p.forced,
    nonce: p.nonce,
    attempts: p.attempts.length,
    transactionId: p.minedTxHash,
    blockNumber: p.blockNumber,
    createdAt: p.createdAt,
  };
}

/**
 * Why a signed transaction is not sent: `why`, said of the transaction, and
 * the field it fails, or the rule of tzun-anchor/1 §10.4 item 2 it breaks
 * (then `rule` too).
 */
interface Unsendable {
  field: string;
  why: string;
  rule?: EvmItemTwoRule;
}

/** A publication as the scheduler signed it, or authenticated it at the start of the pass. */
interface HeldPublication {
  p: string;
  anchorSize: number;
  nonce: number | null;
  fromAddress: string | null;
}

/** The attempt a rebroadcast sends: the latest one the node did not refuse. */
function liveAttempt(p: AnchorPublication): { attempt: AnchorPublicationAttempt; index: number } {
  for (let i = p.attempts.length - 1; i >= 0; i--) {
    if (p.attempts[i].broadcast !== 'rejected') return { attempt: p.attempts[i], index: i };
  }
  return { attempt: p.attempts[p.attempts.length - 1], index: p.attempts.length - 1 };
}

/**
 * Create a scheduler for the store's domain. Reads the store's identity and
 * applies the activation guard; touches no chain.
 *
 * @throws {AnchoringConfigError} for a configuration it cannot use.
 * @throws {LogNamespaceMismatchError} when `config.namespace` is not the store's.
 * @throws {AnchorActivationError} when the store would publish production anchors without `production: true`.
 */
export async function createAnchorScheduler(options: AnchorSchedulerOptions): Promise<AnchorScheduler> {
  const config: ResolvedAnchoringConfig = resolveAnchoringConfig(options.config);
  if (options.expectation === null || typeof options.expectation !== 'object') {
    throw new AnchoringConfigError(
      'createAnchorScheduler needs `expectation`: what the store\'s writers expect records to carry ({ timestamp?, anchor? }), ' +
        'for the status a fill recomputes.',
    );
  }
  const logs = options.logStore ?? logStoreFor(options.storage);
  const anchors = options.anchorStore ?? anchorStoreFor(options.storage);
  if (!logs || !anchors) {
    throw new Error('Anchoring needs a SQLite or Postgres store: the adapter given has no log store or anchor store.');
  }
  const identity = await logs.getStoreIdentity();
  if (config.namespace !== undefined && config.namespace !== identity.ns) {
    throw new LogNamespaceMismatchError(identity.ns, config.namespace);
  }
  const domainPrefix = `${identity.ns}/${identity.storeId}`;
  const anchorOrigin = anchorLogOrigin(domainPrefix);
  // tzun-anchor/1 §4.3.4: an origin is a test origin iff it begins with `test.`.
  const isTest = anchorOrigin.startsWith('test.');

  const ownsPublisher = options.publisher === undefined;
  const publisher = options.publisher ?? (await publisherFor(config.evm));
  if (publisher.chain !== config.evm.chain) {
    throw new AnchorWalletError('anchor_wallet_chain_mismatch', `The publisher signs for ${publisher.chain}; anchoring.publishers.evm.chain is ${config.evm.chain}.`);
  }

  // The activation guard.
  if (!config.production) {
    if (!isTest) {
      if (ownsPublisher) publisher.client.close();
      throw new AnchorActivationError(anchorOrigin, 'its namespace is not a test. namespace');
    }
    const manifest = options.publisherManifest ?? config.publisherManifest;
    const listed = Object.values(manifest?.publishers ?? {}).some((entries) =>
      Array.isArray(entries) &&
      entries.some((e) => e?.namespace === 'production' && typeof e.address === 'string' && e.address.toLowerCase() === publisher.address),
    );
    if (listed) {
      if (ownsPublisher) publisher.client.close();
      throw new AnchorActivationError(anchorOrigin, `the publisher ${publisher.address} is a production publisher in the manifest`);
    }
  }

  const tuning: AnchorSchedulerTuning = { ...DEFAULT_ANCHOR_TUNING, ...(options.tuning ?? {}) };
  const clock = options.clock ?? Date.now;
  const holderId = options.holderId ?? `anchor-${randomBytes(8).toString('hex')}`;
  // The lease is taken as a tzun-anchor/2 scheduler: the SDK's stores refuse
  // any other holder, so a scheduler of an earlier release cannot lead.
  const holder = `${ANCHOR_LEASE_HOLDER_PREFIX}${holderId}`;
  const expectation = options.expectation;
  const chain = publisher.client;
  const hooks = options.testHooks ?? {};
  const isRideAlong = options.isRideAlongLeaf ?? (() => false);
  const closeOwned = (): void => {
    if (ownsPublisher) publisher.client.close();
  };
  const refuse = (message: string): never => {
    closeOwned();
    throw new AnchoringConfigError(message);
  };

  const sourceLogKinds = options.sourceLogKinds ?? DEFAULT_SOURCE_LOG_KINDS;
  if (!Array.isArray(sourceLogKinds) || sourceLogKinds.length === 0 || !sourceLogKinds.every((k) => typeof k === 'string' && /^[a-z][a-z0-9]*$/.test(k) && k !== ANCHOR_LOG_KIND)) {
    refuse('sourceLogKinds must be a non-empty list of log kinds (lowercase letters and digits), the anchor log\'s own kind aside.');
  }
  const minTipGwei = options.minPriorityFeeGwei;
  if (minTipGwei !== undefined && !(typeof minTipGwei === 'number' && Number.isFinite(minTipGwei) && minTipGwei >= 0)) {
    refuse('minPriorityFeeGwei must be a number of gwei at or above 0.');
  }
  const tipFloorWei = minPriorityFeeWei(publisher.chain, minTipGwei);
  // A floor at the hard cap would defer every epoch for good (the base fee
  // comes on top), and one above the soft maximum every epoch until it is stale.
  if (tipFloorWei > 0n && tipFloorWei >= gweiToWei(config.budget.hardFeeCapGwei)) {
    refuse(
      `The minimum priority fee (${Number(tipFloorWei) / 1e9} gwei) is at or above anchoring.budget.hardFeeCapGwei ` +
        `(${config.budget.hardFeeCapGwei} gwei): no publication could be signed. Lower minPriorityFeeGwei or raise the cap.`,
    );
  }
  if (holder.length > 200) refuse('holderId must be at most 185 characters.');

  // A chain change needs a new domain: the scheduler accepts only its
  // configured chain's publications, so a store that published on another chain
  // would stop on its first pass.
  const elsewhere = (await anchors.listAnchorPublications({ kind: EVM })).find((p) => p.chain !== publisher.chain);
  if (elsewhere) {
    refuse(
      `The store has published on ${String(elsewhere.chain)} (publication ${elsewhere.id}), and anchoring.publishers.evm.chain is ${publisher.chain}. ` +
        'A store anchors on one chain: start a new store (a new domain) to anchor on another.',
    );
  }

  // The publishers the scheduler accepts as its own: its configured publisher
  // and the manifest's entries for its anchor origin, never an address read
  // from the database (tzun-anchor/1 §11 item 5).
  let allowed: ReturnType<typeof allowedPublishers>;
  try {
    allowed = allowedPublishers({
      publisherAddress: publisher.address,
      chain: publisher.chain,
      anchorOrigin,
      isTest,
      manifest: options.publisherManifest ?? config.publisherManifest,
    });
  } catch (err) {
    closeOwned();
    throw err;
  }
  // The configured publisher signs only inside its own window: a manifest
  // that lists it on this chain with every window closed makes each of its
  // publications one verifiers refuse (evm_sender_mismatch).
  const own = allowed.filter((e) => e.address === publisher.address);
  if (own.length > 0 && own.every((e) => e.lastSecond !== null && e.lastSecond < Math.floor(clock() / 1000))) {
    refuse(
      `The publisher manifest lists the configured publisher ${publisher.address} for ${anchorOrigin} on ${publisher.chain} ` +
        `with every validity window closed (the last ended ${new Date(Math.max(...own.map((e) => e.lastSecond as number)) * 1000).toISOString()}): ` +
        'verifiers would refuse every publication it sends. Configure the key the manifest names now, or extend its window.',
    );
  }
  const trust = new PublicationTrust({
    allowed,
    chain: publisher.chain,
    chainId: publisher.chainId,
    anchorOrigin,
    client: chain,
    maxClockSkewSeconds: Math.floor(tuning.maxClockSkewMs / 1000),
  });
  let logTrust: AnchorLogTrust | null = null;

  let halted: AnchorAlarm | null = null;
  const isHalted = (): boolean => halted !== null;
  const alarms = new Map<string, AnchorAlarm>();
  let wallet: AnchorWallet | null = null;
  /** The publisher's wallet before it is enrolled (see `ensureWallet`, `enrolSigned`). */
  let unenrolled: AnchorWallet | null = null;
  let lastView: GovernorView | null = null;
  let lastBalance: bigint | null = null;
  let lastFees: { baseFeePerGas: bigint; maxPriorityFeePerGas: bigint } | null = null;
  let nextDueAt: number | null = null;
  let anchorLogId: number | null = null;

  const log = (event: string, fields: Record<string, unknown>): void => {
    if (options.onLog) sdkLog(options.onLog, event, fields);
  };
  if (tipFloorWei > gweiToWei(config.budget.softMaxFeeGwei)) {
    log('anchor_priority_fee_floor_above_soft_max', {
      minPriorityFeeGwei: Number(tipFloorWei) / 1e9,
      softMaxFeeGwei: config.budget.softMaxFeeGwei,
      chain: publisher.chain,
    });
  }

  // A warning, before the first pass, when the stored history names a sender
  // the scheduler does not accept: its first pass would stop.
  for (const p of await anchors.listAnchorPublications({ kind: EVM })) {
    const sender = p.attempts.length > 0 ? trust.decode(p.attempts[0].rawTx)?.from : undefined;
    if (sender !== undefined && !senderAllowed(allowed, sender, null)) {
      log('anchor_history_sender_not_allowed', { publicationId: p.id, sender, anchorOrigin });
    }
  }

  const raise = (report: AnchorPassReport | null, code: AnchorAlarmCode, message: string, subject?: string, severity = ALARM_SEVERITY[code]): AnchorAlarm => {
    const alarm: AnchorAlarm = { code, severity, message, raisedAt: new Date(clock()).toISOString(), ...(subject !== undefined && { subject }) };
    alarms.set(`${code}:${subject ?? ''}`, alarm);
    if (STOPPING_ALARMS.has(code)) halted = alarm;
    report?.alarms.push(alarm);
    log('anchor_alarm', { code, severity: alarm.severity, message, subject });
    options.onAlarm?.(alarm);
    return alarm;
  };
  const clear = (code: AnchorAlarmCode, subject?: string): void => {
    alarms.delete(`${code}:${subject ?? ''}`);
  };

  /** Since when each publication has gone unconfirmed, by id: `anchor_history_unverified` turns critical after `unverifiedEscalateMs`. */
  const unverifiedSince = new Map<string, number>();
  const unverified = (report: AnchorPassReport, subject: string, message: string): void => {
    const since = unverifiedSince.get(subject) ?? clock();
    unverifiedSince.set(subject, since);
    const severity = clock() - since >= tuning.unverifiedEscalateMs ? 'critical' : 'warning';
    raise(report, 'anchor_history_unverified', message, subject, severity);
    report.deferred ??= 'history_unverified';
  };
  const verified = (subject: string): void => {
    unverifiedSince.delete(subject);
    clear('anchor_history_unverified', subject);
  };
  /** Raise a trust failure's alarm, which stops anchoring. */
  const raiseTrust = (report: AnchorPassReport, err: AnchorTrustError): void => {
    raise(report, err.code, err.message, err.subject);
  };
  const getLogTrust = async (): Promise<AnchorLogTrust> => {
    if (logTrust === null) {
      logTrust = new AnchorLogTrust({
        logs,
        anchors,
        anchorLogId: await getAnchorLogId(),
        anchorOrigin,
        sourceLogKinds,
        expectedOrigin: (l) => expectedOrigin(l, domainPrefix),
        onIgnoredLog: (l) => log('anchor_log_ignored', { origin: l.origin, kind: l.kind }),
      });
    }
    return logTrust;
  };
  /** The epochs this process persisted and has not signed yet, by publication id: the only rows the sign gate takes without re-deriving them. */
  const planned = new Map<number, { p: string; anchorSize: number; createdAt: string; forced: boolean }>();
  /**
   * What each row that passed the offline checks this pass held, by id: a
   * replacement signs only that P, at that nonce, for a row that still holds
   * it and still passes the checks when it is signed.
   */
  const authenticated = new Map<number, HeldPublication>();
  /** Finalized publications whose stored `done` was shown to hold, by id and progress. */
  const doneHolds = new Set<string>();

  const newReport = (): AnchorPassReport => ({
    leader: false,
    halted: false,
    epoch: null,
    deferred: null,
    transitions: [],
    broadcasts: [],
    filled: 0,
    awaitingFinality: false,
    awaitingInclusion: false,
    alarms: [],
  });

  /**
   * Renew the lease, or throw `LeaseLost` when another instance holds it.
   * Called before every signature, broadcast and fill chunk, so a pass that
   * outlives its lease stops before it writes or sends anything more.
   */
  const holdLease = async (): Promise<void> => {
    const lease = await anchors.acquireAnchorLease(domainPrefix, holder, tuning.leaseTtlMs);
    if (lease.holder !== holder) throw new LeaseLost(lease.holder);
  };

  // Passes and wallet operations run one at a time on this instance; the
  // lease keeps them apart across instances.
  let tail: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(work: () => Promise<T>): Promise<T> => {
    const run = tail.then(work, work);
    tail = run.catch(() => undefined);
    return run;
  };

  const getAnchorLogId = async (): Promise<number> => {
    if (anchorLogId === null) anchorLogId = (await anchors.ensureStoreLog(ANCHOR_LOG_KIND)).logId;
    return anchorLogId;
  };

  const evmPublications = async (): Promise<AnchorPublication[]> => anchors.listAnchorPublications({ kind: EVM });

  const move = async (
    report: AnchorPassReport,
    publication: AnchorPublication,
    patch: Parameters<AnchorStore['updateAnchorPublication']>[1],
  ): Promise<AnchorPublication> => {
    const next = await anchors.updateAnchorPublication(publication.id, patch);
    if (next.state !== publication.state) {
      report.transitions.push({ publicationId: publication.id, from: publication.state, to: next.state });
      log('anchor_publication_state', { publicationId: publication.id, from: publication.state, to: next.state });
    }
    return next;
  };

  // ── Wallet ──────────────────────────────────────────────────────────────

  const checkHeld = (held: AnchorWallet): AnchorWallet => {
    if (held.domain !== domainPrefix) {
      throw new AnchorWalletError('anchor_wallet_not_dedicated', `The wallet ${held.address} is enrolled for ${held.domain}, not ${domainPrefix}.`);
    }
    if (held.retiredAt !== null) {
      throw new AnchorWalletError('anchor_wallet_retired', `The wallet ${held.address} was retired at ${held.retiredAt}.`);
    }
    wallet = held;
    return held;
  };

  /**
   * The publisher's wallet: its enrolment, or, before it is enrolled, the
   * enrolment it would get (`nonceBase` read from the node now), held in
   * `unenrolled` until `enrolSigned` writes it.
   */
  const ensureWallet = async (): Promise<AnchorWallet> => {
    if (wallet && wallet.retiredAt === null) return wallet;
    const held = await anchors.getAnchorWallet(publisher.address, publisher.chain);
    if (held) {
      unenrolled = null;
      return checkHeld(held);
    }
    const nodeChainId = await chain.chainId();
    if (nodeChainId !== publisher.chainId) {
      throw new AnchorWalletError(
        'anchor_wallet_chain_mismatch',
        `The node at anchoring.publishers.evm.rpcUrl is on chain ${nodeChainId}, not ${publisher.chainId}.`,
      );
    }
    const nonceBase = await chain.transactionCount(publisher.address, 'latest');
    unenrolled = { address: publisher.address, chain: publisher.chain, domain: domainPrefix, nonceBase, enrolledAt: '', retiredAt: null };
    return unenrolled;
  };

  /**
   * Enrol the wallet if it is not enrolled yet. Called only once a
   * transaction the publisher returned has passed the scheduler's own check
   * of it (`answerRefusal`), which reads it as tzun-anchor/1 §10.4 item 2
   * reads a transaction and recovers the publisher's address from it (§7.2
   * rule 3). So the enrolled address is one the publisher has shown it signs
   * for: an address a publisher only claims is never written to the
   * INSERT-only table.
   */
  const enrolSigned = async (): Promise<void> => {
    if (!unenrolled) return;
    const { address, chain: walletChain, nonceBase } = unenrolled;
    const held = await anchors.enrolAnchorWallet({ address, chain: walletChain, domain: domainPrefix, nonceBase });
    unenrolled = null;
    log('anchor_wallet_enrolled', { address: held.address, chain: held.chain, nonceBase: held.nonceBase });
    checkHeld(held);
  };

  /**
   * A wallet's accounted transactions, each checked to be the signed
   * transaction its row says (`assertAnchorWalletTx`) as it is read: one that
   * is not raises `anchor_wallet_tx_unexplained`, which stops anchoring, and
   * null is returned.
   */
  const checkedWalletTxs = async (report: AnchorPassReport | null, w: Pick<AnchorWallet, 'address' | 'chain'>): Promise<AnchorWalletTx[] | null> => {
    const txs = await anchors.listAnchorWalletTxs(w.address, w.chain);
    for (const tx of txs) {
      try {
        assertWalletTx(tx);
      } catch (err) {
        raise(
          report,
          'anchor_wallet_tx_unexplained',
          `The accounted transaction of ${tx.address} at nonce ${tx.nonce} is not the transaction it claims to be (${(err as Error).message}). Anchoring is stopped.`,
          `${tx.address}@${tx.nonce}`,
        );
        return null;
      }
    }
    return txs;
  };

  /**
   * The next nonce: one past every nonce this store holds for the wallet,
   * from `nonce_base`, checked against the node's pending count. `null` when
   * it cannot be used yet (the node lags) or must never be (someone else took
   * nonces: a stopping alarm).
   */
  const nextNonce = async (report: AnchorPassReport, w: AnchorWallet, superseding?: number): Promise<number | null> => {
    // Every publication row passed the offline checks at the start of the
    // pass, or the pass stopped there: their nonces are the wallet's own.
    const held = (await evmPublications())
      .filter((p) => p.state !== 'superseded' && p.id !== superseding && p.fromAddress === w.address && p.nonce !== null)
      .map((p) => p.nonce as number);
    const txs = await checkedWalletTxs(report, w);
    if (txs === null) return null;
    const accounted = txs.map((t) => t.nonce);
    const next = Math.max(w.nonceBase - 1, ...held, ...accounted) + 1;
    const pending = await chain.transactionCount(w.address, 'pending');
    if (pending === next) return next;
    if (pending > next) {
      raise(
        report,
        'anchor_nonce_consumed_externally',
        `The wallet's pending transaction count is ${pending}, but this store has used nonces only up to ${next - 1}: ` +
          'another party is sending from the dedicated publisher wallet.',
        `${w.address}@${next}`,
      );
      return null;
    }
    report.deferred = 'nonce_behind_node';
    return null;
  };

  // ── The history check ───────────────────────────────────────────────────

  /**
   * The last finalized publication is the scheduler's own, at a block the node
   * confirms: `verifyEvmPublication`, with the node as header source and the
   * accepted senders as manifest, says `valid === true`, and the anchor log's
   * leaves still rebuild the root its P commits to. Every finalized row's nonce
   * is at or above its wallet's enrolment. True when it holds; false when it
   * fails (`anchor_history_mismatch`, which stops anchoring); 'defer' when the
   * node could not confirm it, and nothing that builds on it runs this pass.
   */
  const checkHistory = async (report: AnchorPassReport): Promise<boolean | 'defer'> => {
    const finalized = (await evmPublications()).filter((p) => p.state === 'finalized');
    const last = finalized.reduce<AnchorPublication | null>((a, p) => (!a || p.anchorSize > a.anchorSize ? p : a), null);
    if (!last) return true;
    const subject = String(last.id);
    const mismatch = (why: string): boolean => {
      raise(report, 'anchor_history_mismatch', `The last published anchor (publication ${last.id}) no longer matches: ${why}. Anchoring is stopped.`, subject);
      return false;
    };
    const wallets = new Map<string, AnchorWallet | null>();
    for (const p of finalized) {
      const key = `${p.fromAddress as string} ${p.chain as string}`;
      if (!wallets.has(key)) wallets.set(key, await anchors.getAnchorWallet(p.fromAddress as string, p.chain as string));
      const enrolled = wallets.get(key);
      if (enrolled && (p.nonce as number) < enrolled.nonceBase) {
        return mismatch(`publication ${p.id} holds nonce ${String(p.nonce)}, below its wallet's enrolment at ${enrolled.nonceBase}`);
      }
    }
    const confirmation = await trust.confirmed(last, { fresh: true });
    if (confirmation.status === 'invalid') return mismatch(`its transaction is not a publication the scheduler accepts (${confirmation.why})`);
    if (confirmation.status === 'unconfirmed') {
      unverified(report, subject, `The node could not confirm publication ${last.id} (${confirmation.why}); nothing that builds on it runs until it does.`);
      return 'defer';
    }
    verified(subject);
    try {
      const lt = await getLogTrust();
      await lt.leavesBelow(await lt.base(last.anchorSize, last.p, 'anchor_history_mismatch', subject), { fresh: true });
    } catch (err) {
      if (!(err instanceof AnchorTrustError)) throw err;
      return mismatch(err.message);
    }
    return true;
  };

  // ── Broadcasting ────────────────────────────────────────────────────────

  /**
   * Record what the node said. An `accepted` answer is recorded; `rejected`
   * only for a first broadcast, so an attempt that may already have
   * propagated is never later called rejected (and superseded).
   */
  const recordBroadcast = async (
    report: AnchorPassReport,
    publication: AnchorPublication,
    index: number,
    result: EvmBroadcastResult,
    first: boolean,
  ): Promise<AnchorPublication> => {
    report.broadcasts.push({ publicationId: publication.id, txHash: publication.attempts[index].txHash, outcome: result.outcome, reason: result.reason });
    const current = publication.attempts[index].broadcast;
    let next = current;
    if (result.outcome === 'accepted') next = 'accepted';
    else if (result.outcome === 'rejected' && first && result.reason !== 'nonce_too_low') next = 'rejected';
    if (next === current) return publication;
    const attempts = publication.attempts.map((a, i) => (i === index ? { ...a, broadcast: next } : a));
    return anchors.updateAnchorPublication(publication.id, { attempts });
  };

  /**
   * Why the signed transaction `raw` must not be sent, or null when it may
   * be. Every broadcast reads the bytes about to be sent as tzun-anchor/1
   * §10.4 item 2 reads a transaction, a stored one sent again included (§7.2
   * rule 3, §11 item 6): they must meet every rule of that item (so they are
   * of type 0, 1 or 2), sign the publisher's chain id, and recover `sender`.
   * A record that they were checked before is not enough: whoever can write
   * the store can replace a stored transaction with its twin, with n − s and
   * the recovery parity flipped, which needs no key, recovers the same
   * sender and which every verifier refuses. Bytes that fail are never
   * lowered or otherwise repaired here: a stored attempt is append-only, and
   * changing it would hide the tampering and change its id.
   */
  const unsendable = (raw: string, sender: string | null): Unsendable | null => {
    const reading = readEvmTransaction(raw);
    if (!reading.ok) {
      const why = itemTwoRefusal(reading.rule);
      return reading.rule === null ? { field: 'encoding', why } : { field: reading.rule, why, rule: reading.rule };
    }
    const { chainId, sender: signer } = reading.transaction;
    if (chainId !== publisher.chainId) return { field: 'chainId', why: `it is signed for chain id ${chainId}, not ${publisher.chainId}` };
    if (sender === null) return { field: 'sender', why: 'no sender of it was authenticated this pass' };
    if (signer !== sender) return { field: 'sender', why: `it is signed by ${signer}, not ${sender}` };
    return null;
  };

  /**
   * Why `raw` must not be sent as a transaction of the publication `held`
   * describes, or null when it may be: it passes `unsendable` with `held`'s
   * sender, and the same bytes carry `held`'s nonce and the calldata
   * 0x ‖ P. `held` is the publication as the scheduler signed it this pass or
   * authenticated it at the start of the pass, never the columns of a row
   * read since: the write that replaces a stored attempt can rewrite those
   * too. A transaction the same key signed at another nonce, or over other
   * calldata, is not this publication's.
   */
  const unsendableAs = (raw: string, held: HeldPublication | undefined): Unsendable | null => {
    const refused = unsendable(raw, held?.fromAddress ?? null);
    if (refused !== null || held === undefined) return refused;
    const tx = trust.decode(raw);
    if (tx === null) return { field: 'nonce', why: 'its nonce, value or fees cannot be read' };
    if (tx.nonce !== held.nonce) return { field: 'nonce', why: `it is signed at nonce ${tx.nonce}, not ${String(held.nonce)}` };
    if (tx.data !== `0x${held.p}`) return { field: 'data', why: 'its calldata is not 0x ‖ P' };
    return null;
  };

  /**
   * The transaction a publisher returned is read before it is stored or
   * enrols the wallet: for a publication, it must pass `unsendableAs` as the
   * publication asked for, and make a row the publication checks accept at
   * the start of every later pass; for an accounted transaction, it must pass
   * `unsendable` with the wallet as sender, and be the row it is stored as
   * (`assertWalletTx`). One that fails is refused as a signer's answer is,
   * with this `AnchorSignerError`: nothing is stored or sent, and the
   * operation can be retried. The SDK's own publishers have read it already
   * (`checkSignedTransaction`), lowering a high `s`. A publisher passed as
   * `AnchorSchedulerOptions.publisher` returns the bytes that are sent, and
   * nothing it returns is lowered (tzun-anchor/1 §7.2 rule 3).
   */
  const answerRefusal = (refused: Unsendable | null): AnchorSignerError | null => {
    if (refused === null) return null;
    return refused.rule === undefined
      ? new AnchorSignerError(refused.field, refused.why)
      : new AnchorSignerError(refused.rule, 'what the publisher returns is sent as it is, so it must meet the rule itself', refused.rule);
  };

  /**
   * Broadcast `raw` as a transaction of `publication` when `unsendableAs`
   * finds nothing against it, with the publication as the scheduler signed
   * it this pass or authenticated it at the start of the pass. Otherwise
   * nothing is sent, null is returned, and `anchor_publication_unexplained`
   * stops anchoring.
   */
  const broadcastPublication = async (report: AnchorPassReport, publication: AnchorPublication, raw: string): Promise<EvmBroadcastResult | null> => {
    const refused = unsendableAs(raw, authenticated.get(publication.id));
    if (refused !== null) {
      raise(
        report,
        'anchor_publication_unexplained',
        `A transaction of publication ${publication.id} (nonce ${String(publication.nonce)}) is not sent: ${refused.why}. Anchoring is stopped.`,
        String(publication.id),
      );
      return null;
    }
    return chain.broadcast(raw);
  };

  /**
   * Whether the configured publisher's window contains now: outside it,
   * verifiers refuse what it sends, so nothing is signed and the pass defers
   * (`anchor_publisher_outside_window`).
   */
  const publisherInWindow = (report: AnchorPassReport, what: string): boolean => {
    if (senderAllowed(trust.allowed, publisher.address, Math.floor(clock() / 1000))) {
      clear('anchor_publisher_outside_window', publisher.address);
      return true;
    }
    raise(
      report,
      'anchor_publisher_outside_window',
      `The configured publisher ${publisher.address} is outside its validity window in the publisher manifest now, so ${what}: verifiers would refuse it.`,
      publisher.address,
    );
    report.deferred = 'publisher_outside_window';
    return false;
  };

  /** Sign, persist, then broadcast: the outbox. */
  const sendAttempt = async (
    report: AnchorPassReport,
    publication: AnchorPublication,
    nonce: number,
    fees: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint },
  ): Promise<AnchorPublication> => {
    if (publication.fromAddress !== null && publication.fromAddress !== publisher.address) {
      throw new Error(`Publication ${publication.id} was signed by ${publication.fromAddress}; ${publisher.address} does not sign for it.`);
    }
    const nowSeconds = Math.floor(clock() / 1000);
    if (!publisherInWindow(report, `publication ${publication.id} is not signed`)) return publication;
    // The sign gate (tzun-anchor/1 §11 item 4): a first signature only of a P
    // this process planned, or re-derived from the anchor log this pass; a
    // replacement only of the P, nonce and sender authenticated at the start of
    // the pass, on a row that still holds them and still passes the offline
    // checks now. What is signed is that P, never the row's own.
    let signable: { p: string; anchorSize: number } | undefined;
    if (publication.attempts.length === 0) {
      const plan = planned.get(publication.id);
      if (plan !== undefined && plan.p === publication.p && plan.anchorSize === publication.anchorSize) signable = plan;
    } else {
      const held = authenticated.get(publication.id);
      if (
        held !== undefined &&
        held.p === publication.p &&
        held.anchorSize === publication.anchorSize &&
        held.nonce === nonce &&
        held.fromAddress === publication.fromAddress &&
        trust.offline(publication, nowSeconds) === null
      ) {
        signable = held;
      }
    }
    if (!signable) {
      raise(
        report,
        'anchor_publication_unexplained',
        `Publication ${publication.id} (anchor size ${publication.anchorSize}) is not one the scheduler derived or authenticated, so it is not signed. Anchoring is stopped.`,
        String(publication.id),
      );
      return publication;
    }
    await holdLease();
    let signed: { raw: string; hash: string };
    try {
      signed = await publisher.signPublication(signable.p, { nonce, ...fees, gasLimit: ANCHOR_PUBLICATION_GAS_LIMIT });
    } catch (err) {
      // Nothing the signer returned is stored or sent; the pass fails and is retried.
      if (err instanceof AnchorSignerError) raise(report, 'anchor_signer_mismatch', err.message, publisher.address);
      if (err instanceof AnchorSignerUnavailableError) raise(report, 'anchor_signer_unavailable', err.message, publisher.address);
      throw err;
    }
    clear('anchor_signer_unavailable', publisher.address);
    const attempt: AnchorPublicationAttempt = {
      txHash: signed.hash,
      rawTx: signed.raw,
      maxFeePerGas: fees.maxFeePerGas.toString(),
      maxPriorityFeePerGas: fees.maxPriorityFeePerGas.toString(),
      sentAt: new Date(clock()).toISOString(),
      broadcast: 'unknown',
    };
    // What the publisher returned is read before it is stored or enrols the
    // wallet (`answerRefusal`).
    const asked: HeldPublication = { p: signable.p, anchorSize: signable.anchorSize, nonce, fromAddress: publisher.address };
    const next = { state: 'submitted' as const, fromAddress: publisher.address, nonce, attempts: [...publication.attempts, attempt] };
    const rowRefusal = (): Unsendable | null => {
      const why = trust.offline({ ...publication, ...next }, Math.floor(clock() / 1000));
      return why === null ? null : { field: 'transaction', why: `the publication checks refuse the row it makes (${why})` };
    };
    const refused = answerRefusal(unsendableAs(signed.raw, asked) ?? rowRefusal());
    if (refused !== null) {
      raise(report, 'anchor_signer_mismatch', refused.message, publisher.address);
      throw refused;
    }
    clear('anchor_signer_mismatch', publisher.address);
    await enrolSigned();
    let current = await move(report, publication, next);
    planned.delete(publication.id);
    authenticated.set(current.id, asked);
    await hooks.afterPersistAttempt?.(current);
    await holdLease();
    const result = await broadcastPublication(report, current, signed.raw);
    if (result === null) return current;
    await hooks.afterBroadcast?.(current, result);
    current = await recordBroadcast(report, current, current.attempts.length - 1, result, true);
    if (result.reason === 'nonce_too_low') current = await afterNonceTooLow(report, current);
    return current;
  };

  /** Receipt lookup for every attempt, newest first. */
  const findMined = async (publication: AnchorPublication): Promise<{ receipt: EvmReceipt; attempt: AnchorPublicationAttempt } | null> => {
    for (let i = publication.attempts.length - 1; i >= 0; i--) {
      const receipt = await chain.receipt(publication.attempts[i].txHash);
      if (receipt) return { receipt, attempt: publication.attempts[i] };
    }
    return null;
  };

  const markIncluded = async (
    report: AnchorPassReport,
    publication: AnchorPublication,
    mined: { receipt: EvmReceipt; attempt: AnchorPublicationAttempt },
  ): Promise<AnchorPublication> =>
    move(report, publication, {
      state: 'included',
      minedTxHash: mined.receipt.transactionHash,
      blockNumber: mined.receipt.blockNumber,
      blockHash: mined.receipt.blockHash,
      txIndex: mined.receipt.transactionIndex,
      gasUsed: mined.receipt.gasUsed.toString(),
      effectiveGasPrice: mined.receipt.effectiveGasPrice.toString(),
    });

  /**
   * The node says the nonce is used. Look up a receipt for every attempt
   * first (a restart after the transaction mined records it, no alarm); only
   * when none was mined, and no accounted transaction holds the nonce, is it
   * someone else's transaction.
   */
  const afterNonceTooLow = async (report: AnchorPassReport, publication: AnchorPublication): Promise<AnchorPublication> => {
    const mined = await findMined(publication);
    if (mined) return markIncluded(report, publication, mined);
    const txs = await checkedWalletTxs(report, { address: publication.fromAddress as string, chain: publication.chain as string });
    if (txs === null) return publication;
    const accounted = txs.some((t) => t.nonce === publication.nonce);
    if (!accounted) {
      raise(
        report,
        'anchor_nonce_consumed_externally',
        `Nonce ${publication.nonce} of the publisher wallet was used by a transaction this store never made ` +
          `(publication ${publication.id}'s attempts are not mined). Another party is sending from the dedicated wallet.`,
        `${publication.fromAddress}@${publication.nonce}`,
      );
    }
    return publication;
  };

  // ── Fees and balance ────────────────────────────────────────────────────

  /** The node's fees, with the tip raised to the chain's floor (`minPriorityFeeGwei`). */
  const marketFees = async (): Promise<{ baseFeePerGas: bigint; maxPriorityFeePerGas: bigint }> => withPriorityFeeFloor(await chain.fees(), tipFloorWei);

  const readMarket = async (report: AnchorPassReport, w: AnchorWallet): Promise<GovernorView> => {
    const fees = await marketFees();
    const balance = await chain.balance(w.address);
    lastFees = fees;
    lastBalance = balance;
    const view = governorView({ balanceWei: balance, priceWei: fees.baseFeePerGas + fees.maxPriorityFeePerGas, cadence: config.cadence, budget: config.budget });
    lastView = view;
    if (balance < view.minimumBalanceWei) {
      raise(
        report,
        'anchor_wallet_insufficient_funds',
        `The publisher's balance (${balance} wei) is under 3x one publication at the hard cap (${view.minimumBalanceWei} wei); nothing is submitted.`,
        w.address,
      );
    } else {
      clear('anchor_wallet_insufficient_funds', w.address);
    }
    if (view.runwayDays < RUNWAY_CRITICAL_DAYS) {
      raise(report, 'anchor_runway_critical', `The projected runway is ${view.runwayDays.toFixed(1)} days (under ${RUNWAY_CRITICAL_DAYS}).`, w.address);
      clear('anchor_runway_low', w.address);
    } else if (view.runwayDays < RUNWAY_WARNING_DAYS) {
      raise(report, 'anchor_runway_low', `The projected runway is ${view.runwayDays.toFixed(1)} days (under ${RUNWAY_WARNING_DAYS}).`, w.address);
      clear('anchor_runway_critical', w.address);
    } else {
      clear('anchor_runway_low', w.address);
      clear('anchor_runway_critical', w.address);
    }
    return view;
  };

  /**
   * Whether a publication may be signed now: the 3× balance refusal, then the
   * fee caps. Returns the fees to sign with, or null with the reason in
   * `report.deferred`.
   */
  const clearToSign = async (
    report: AnchorPassReport,
    w: AnchorWallet,
    stale: boolean,
    read?: GovernorView,
  ): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | null> => {
    const view = read ?? (await readMarket(report, w));
    if ((lastBalance as bigint) < view.minimumBalanceWei) {
      report.deferred = 'anchor_wallet_insufficient_funds';
      return null;
    }
    const fees = lastFees as { baseFeePerGas: bigint; maxPriorityFeePerGas: bigint };
    const decision = feeDecision(fees.baseFeePerGas + fees.maxPriorityFeePerGas, config.budget, stale);
    if (!decision.ok) {
      report.deferred = decision.reason;
      if (decision.reason === 'fee_above_hard_cap' && stale) {
        raise(report, 'anchor_fee_above_hard_cap', `The fee is above the hard cap (${config.budget.hardFeeCapGwei} gwei) and a leaf has waited T_max.`, anchorOrigin);
      }
      return null;
    }
    clear('anchor_fee_above_hard_cap', anchorOrigin);
    const signing = publicationFees(fees.baseFeePerGas, fees.maxPriorityFeePerGas, config.budget);
    if (!signing) {
      report.deferred = 'fee_above_hard_cap';
      return null;
    }
    return signing;
  };

  // ── Confirming what is in flight ────────────────────────────────────────

  /**
   * A prepared publication found at the start of a pass. One this process
   * planned is signed as planned. Any other is a persisted epoch that was never
   * signed (a crash between persisting and signing) or a row someone else
   * wrote: it is signed only once the anchor log re-derives its P above the
   * published size, and only when the cadence calls its epoch due, as an epoch
   * that is not forced. Anything else raises `anchor_publication_unexplained`
   * and stops. The row's own `forced` is never read: only an operator's
   * `anchorNow({ force: true })` signs a re-derived epoch the cadence does not
   * call due, under the rolling force limit, and it counts as forced.
   */
  const publishPrepared = async (report: AnchorPassReport, publication: AnchorPublication, rows: AnchorPublication[], force: boolean): Promise<void> => {
    const w = await ensureWallet();
    if ((await checkHistory(report)) !== true) return;
    let stale: boolean;
    const plan = planned.get(publication.id);
    if (plan !== undefined) {
      stale = clock() - Date.parse(plan.createdAt) >= config.cadence.maxStalenessMs;
    } else {
      const state = await publishedState(report, rows, null);
      if (!state) return;
      const { explained } = state;
      const unexplained = (why: string): void => {
        raise(
          report,
          'anchor_publication_unexplained',
          `Publication ${publication.id} (anchor size ${publication.anchorSize}) cannot be re-derived from the anchor log: ${why}. Nothing is signed; anchoring is stopped.`,
          String(publication.id),
        );
      };
      if (publication.anchorSize !== explained.size || !(explained.size > explained.base.size)) {
        return unexplained(`the anchor log's size is ${explained.size}, above the published size ${explained.base.size} only by an epoch at that size`);
      }
      if (explained.anchorCheckpoint?.bodyDigest !== publication.p) return unexplained('its P is not the digest of the anchor checkpoint the leaves rebuild');
      // Due by the cadence over the leaves its epoch covers (waiting() sees
      // none of them), from authenticated rows; never signed as forced.
      const covered = await coveredLeaves(explained);
      const view = await readMarket(report, w);
      const input = {
        now: clock(),
        lastEpochAt: lastEpochAtOf(rows.filter((r) => r.id !== publication.id)),
        oldestTriggeringLeafAt: covered.triggering,
        oldestRideAlongLeafAt: covered.rideAlong,
        waitingLeaves: covered.count,
        intervalMs: view.intervalMs,
        cadence: config.cadence,
      };
      const natural = cadenceDecision({ ...input, force: false });
      const forced = force && !natural.due;
      const decision = forced ? cadenceDecision({ ...input, force: true }) : natural;
      if (!decision.due) {
        report.deferred = decision.why;
        nextDueAt = natural.due ? null : natural.dueAt;
        return;
      }
      if (forced) {
        const refusal = await forceRefusal();
        if (refusal) {
          report.forceRefused = refusal;
          report.deferred = refusal.code;
          return;
        }
      }
      stale = decision.stale;
      planned.set(publication.id, { p: publication.p, anchorSize: publication.anchorSize, createdAt: publication.createdAt, forced });
      if (!forced) rederived.add(publication.id);
      log('anchor_epoch_rederived', { publicationId: publication.id, anchorSize: publication.anchorSize, p: publication.p });
    }
    const fees = await clearToSign(report, w, stale);
    if (!fees) return;
    const nonce = await nextNonce(report, w);
    if (nonce === null) return;
    await sendAttempt(report, publication, nonce, fees);
  };

  const confirmSubmitted = async (report: AnchorPassReport, publication: AnchorPublication): Promise<void> => {
    const mined = await findMined(publication);
    if (mined) {
      const included = await markIncluded(report, publication, mined);
      await confirmIncluded(report, included);
      return;
    }
    // No receipt: send the stored bytes again, as they are, once they pass
    // `unsendableAs` now: signed by the sender, at the nonce and over the P
    // authenticated for the row at the start of the pass. A transaction a node
    // never propagated, or evicted, goes out unchanged; one that fails is not
    // sent, and anchoring stops.
    const { attempt, index } = liveAttempt(publication);
    const latest = publication.attempts[publication.attempts.length - 1];
    await holdLease();
    const result = await broadcastPublication(report, publication, attempt.rawTx);
    if (result === null) return;
    let current = await recordBroadcast(report, publication, index, result, false);
    if (result.reason === 'nonce_too_low') {
      await afterNonceTooLow(report, current);
      return;
    }
    if (result.outcome === 'unknown') {
      report.deferred = 'node_unreachable';
      return;
    }
    // Signed by another wallet (the publisher key was changed while it was in
    // flight): this key cannot replace it, since a replacement is the same
    // nonce of the same sender. The stored bytes go out every pass until it is
    // mined, and no epoch is cut before then.
    if (current.fromAddress !== publisher.address) {
      raise(
        report,
        'anchor_publication_other_wallet',
        `Publication ${current.id} (nonce ${current.nonce}) was signed by ${current.fromAddress}, not the configured ` +
          `publisher ${publisher.address}. Its stored transaction is rebroadcast every pass and never replaced, and no ` +
          `epoch is cut until it is mined. To replace it, configure the key of ${current.fromAddress} again.`,
        String(current.id),
      );
      if ((await chain.transaction(attempt.txHash)) !== null) report.awaitingInclusion = true;
      return;
    }
    // Stuck: the latest attempt is old enough, and priced under the base fee,
    // or the node does not know the attempt it was just sent. A replacement
    // bumps the latest attempt's fees, whatever the node said to it.
    const known = await chain.transaction(attempt.txHash);
    if (clock() - Date.parse(latest.sentAt) < tuning.stuckAfterMs) {
      if (known !== null) report.awaitingInclusion = true;
      return;
    }
    // The fees the latest attempt was signed with, read from its signed
    // bytes: the stored fee columns are not part of what was authenticated.
    const signedLatest = trust.decode(latest.rawTx);
    const latestFees = {
      maxFeePerGas: signedLatest?.maxFeePerGas ?? BigInt(latest.maxFeePerGas),
      maxPriorityFeePerGas: signedLatest?.maxPriorityFeePerGas ?? BigInt(latest.maxPriorityFeePerGas),
    };
    const fees = await chain.fees();
    if (fees.baseFeePerGas <= latestFees.maxFeePerGas && known !== null) {
      report.awaitingInclusion = true;
      return;
    }
    const replacements = current.attempts.length - 1;
    const bumped = replacementFees(latestFees, config.budget);
    if (replacements >= MAX_REPLACEMENTS || bumped === null) {
      raise(
        report,
        'anchor_tx_stuck',
        `Publication ${current.id} (nonce ${current.nonce}) is unmined after ${replacements} replacement(s) and cannot be ` +
          `replaced again within the hard cap (${config.budget.hardFeeCapGwei} gwei); its latest attempt is rebroadcast every pass.`,
        String(current.id),
      );
      return;
    }
    current = await sendAttempt(report, current, current.nonce as number, bumped);
    log('anchor_attempt_replaced', { publicationId: current.id, nonce: current.nonce, attempts: current.attempts.length });
  };

  const confirmIncluded = async (report: AnchorPassReport, publication: AnchorPublication): Promise<void> => {
    const mined = await findMined(publication);
    if (!mined) {
      // Reorg: the receipt is gone. Back to submitted, and rebroadcast.
      const back = await move(report, publication, {
        state: 'submitted',
        minedTxHash: null,
        blockNumber: null,
        blockHash: null,
        txIndex: null,
        gasUsed: null,
        effectiveGasPrice: null,
      });
      await confirmSubmitted(report, back);
      return;
    }
    let current = publication;
    if (mined.receipt.blockHash !== current.blockHash || mined.receipt.transactionHash !== current.minedTxHash) {
      current = await markIncluded(report, current, mined);
    }
    const finalized = await chain.finalizedBlockNumber();
    if (mined.receipt.blockNumber > finalized) {
      report.awaitingFinality = true;
      return;
    }
    const canonical = await chain.canonicalBlock(mined.receipt.blockNumber);
    if (!canonical || canonical.hash !== mined.receipt.blockHash) {
      report.awaitingFinality = true;
      return;
    }
    // Final. Store the header, the index and the trie proof now: they are never
    // fetched later from an endpoint that may be gone (tzun-anchor/1 §7.2
    // rule 4). A block whose material cannot be read or rebuilt (a header field
    // a later fork adds, a node that returns other bytes) pages: the
    // publication cannot become final until the SDK reads it.
    const unreadable = (err: EvmBlockMaterialError): never => {
      raise(
        report,
        'anchor_block_material_unreadable',
        `Publication ${current.id} is mined in block ${mined.receipt.blockNumber}, whose material cannot be stored: ${err.message}`,
        String(current.id),
      );
      throw err;
    };
    let material: Awaited<ReturnType<typeof chain.blockMaterial>>;
    try {
      material = await chain.blockMaterial(mined.receipt.blockNumber);
    } catch (err) {
      if (err instanceof EvmBlockMaterialError) unreadable(err);
      throw err;
    }
    if (material.hash !== mined.receipt.blockHash) {
      report.awaitingFinality = true;
      return;
    }
    const trie = buildTxTrie(material.rawTransactions);
    if (trie.root !== material.transactionsRoot) {
      unreadable(new EvmBlockMaterialError(`block ${material.number}'s transactions do not rebuild its transactions root, so its proof is not stored`));
    }
    const proof = trie.proof(mined.receipt.transactionIndex);
    const walked = verifyEvmTransactionProof(material.transactionsRoot, mined.receipt.transactionIndex, proof);
    if (walked === null || walked.toLowerCase() !== mined.attempt.rawTx) {
      unreadable(new EvmBlockMaterialError(`the transaction-trie proof for ${mined.receipt.transactionHash} does not walk to its raw transaction`));
    }
    clear('anchor_block_material_unreadable', String(current.id));
    await move(report, current, {
      state: 'finalized',
      blockHeader: material.headerRlp,
      txIndex: mined.receipt.transactionIndex,
      txTrieProof: proof,
    });
    clear('anchor_tx_stuck', String(current.id));
    clear('anchor_publication_other_wallet', String(current.id));
  };

  // ── Waiting leaves and the cadence ──────────────────────────────────────

  const waiting = async (): Promise<{ triggering: number | null; rideAlong: number | null; count: number }> => {
    let triggering: number | null = null;
    let rideAlong: number | null = null;
    let count = 0;
    const lt = await getLogTrust();
    for (const logRecord of await logs.listLogs()) {
      // A log of a kind the scheduler does not anchor never makes an epoch due.
      if (!lt.anchors(logRecord)) continue;
      const { size } = await logs.getLogSize(logRecord.logId);
      const m = (await anchors.getLastAnchoredCheckpoint(logRecord.logId))?.treeSize ?? 0;
      if (size <= m) continue;
      if (logRecord.kind === 'evidence') {
        const [first] = await logs.listLogLeaves(logRecord.logId, m, m + 1);
        if (!first) continue;
        const at = Date.parse(first.loggedAt);
        triggering = triggering === null ? at : Math.min(triggering, at);
        count += size - m;
        continue;
      }
      for (const leaf of await logs.listLogLeaves(logRecord.logId, m, size)) {
        const at = Date.parse(leaf.loggedAt);
        if (isRideAlong(logRecord, leaf)) rideAlong = rideAlong === null ? at : Math.min(rideAlong, at);
        else {
          triggering = triggering === null ? at : Math.min(triggering, at);
          count += 1;
        }
      }
    }
    return { triggering, rideAlong, count };
  };

  /** The leaves an explained, unpublished epoch covers, as `waiting()` reads leaves: the crash path's cadence input. */
  const coveredLeaves = async (range: ExplainedRange): Promise<{ triggering: number | null; rideAlong: number | null; count: number }> => {
    let triggering: number | null = null;
    let rideAlong: number | null = null;
    let count = 0;
    for (const cp of range.checkpoints.values()) {
      const logRecord = range.logs.get(cp.logId) as LogRecord;
      const m = cp.prevAnchoredSize ?? 0;
      if (logRecord.kind === 'evidence') {
        const [first] = await logs.listLogLeaves(cp.logId, m, m + 1);
        if (!first) continue;
        const at = Date.parse(first.loggedAt);
        triggering = triggering === null ? at : Math.min(triggering, at);
        count += cp.treeSize - m;
        continue;
      }
      for (const leaf of await logs.listLogLeaves(cp.logId, m, cp.treeSize)) {
        const at = Date.parse(leaf.loggedAt);
        if (isRideAlong(logRecord, leaf)) rideAlong = rideAlong === null ? at : Math.min(rideAlong, at);
        else {
          triggering = triggering === null ? at : Math.min(triggering, at);
          count += 1;
        }
      }
    }
    return { triggering, rideAlong, count };
  };

  /**
   * The publications the cadence and the force limit count: those with an
   * attempt (every one authenticated at the start of the pass, which stops
   * otherwise), and the epochs this process persisted. A prepared row this
   * process did not persist counts for nothing until it is signed. The times
   * are the database's (`created_at`, assigned on insert).
   */
  const countedRows = (rows: AnchorPublication[]): Array<{ createdAt: string; forced: boolean }> => [
    ...rows.filter((p) => p.attempts.length > 0 && !planned.has(p.id)).map((p) => ({ createdAt: p.createdAt, forced: p.forced && !rederived.has(p.id) })),
    ...[...planned.values()],
  ];
  /** Re-derived epochs this process signed on the cadence: never counted as forced, whatever their row says. */
  const rederived = new Set<number>();
  const lastEpochAtOf = (rows: AnchorPublication[]): number | null => {
    const counted = countedRows(rows);
    return counted.length > 0 ? Math.max(...counted.map((p) => Date.parse(p.createdAt))) : null;
  };

  const forcedInWindow = async (): Promise<Array<{ createdAt: string }>> => {
    const since = clock() - DAY_MS;
    return countedRows(await evmPublications()).filter((p) => p.forced && Date.parse(p.createdAt) > since);
  };

  /** The rolling force limit: the refusal, or null when a forced epoch is allowed. */
  const forceRefusal = async (): Promise<AnchorForceRateLimitedError | null> => {
    const used = await forcedInWindow();
    if (used.length < config.budget.forcePerDay) return null;
    const oldest = Math.min(...used.map((p) => Date.parse(p.createdAt)));
    return new AnchorForceRateLimitedError(config.budget.forcePerDay, new Date(oldest + DAY_MS).toISOString());
  };

  /** The unmined EVM publications, and the one a new epoch may supersede: the only one, every broadcast of it refused. */
  const unminedOf = (publications: AnchorPublication[]): { unmined: AnchorPublication[]; supersedable: AnchorPublication | null } => {
    const unmined = publications.filter((p) => UNMINED.includes(p.state));
    const only = unmined.length === 1 ? unmined[0] : null;
    const supersedable = only && only.state === 'submitted' && only.attempts.every((a) => a.broadcast === 'rejected') ? only : null;
    return { unmined, supersedable };
  };

  /**
   * Whether the node knows none of a publication's attempts: no receipt and
   * no transaction for any. A stored broadcast outcome is a hint, so a new
   * epoch takes a rejected publication's nonce only on this answer (R8). No
   * answer is not this answer.
   */
  const unknownToNode = async (publication: AnchorPublication): Promise<boolean> => {
    try {
      for (const a of publication.attempts) {
        if ((await chain.receipt(a.txHash)) !== null || (await chain.transaction(a.txHash)) !== null) return false;
      }
      return true;
    } catch {
      return false;
    }
  };

  /**
   * Every row passes the offline checks, or the pass stops: the last finalized
   * row with `anchor_history_mismatch`, any other with
   * `anchor_publication_unexplained`.
   */
  const authenticateRows = (report: AnchorPassReport, rows: AnchorPublication[]): boolean => {
    const nowSeconds = Math.floor(clock() / 1000);
    const lastFinalized = rows.filter((p) => p.state === 'finalized').reduce<AnchorPublication | null>((a, p) => (!a || p.anchorSize > a.anchorSize ? p : a), null);
    for (const row of rows) {
      const why = trust.offline(row, nowSeconds);
      if (why === null) {
        if (row.attempts.length > 0) authenticated.set(row.id, { p: row.p, anchorSize: row.anchorSize, nonce: row.nonce, fromAddress: row.fromAddress });
        continue;
      }
      if (row === lastFinalized) {
        raise(report, 'anchor_history_mismatch', `The last published anchor (publication ${row.id}) no longer matches: ${why}. Anchoring is stopped.`, String(row.id));
      } else {
        raise(report, 'anchor_publication_unexplained', `Publication ${row.id} (${row.state}, anchor size ${row.anchorSize}) is not one the scheduler made: ${why}. Anchoring is stopped.`, String(row.id));
      }
      return false;
    }
    return true;
  };

  /**
   * B, the published size: the largest anchor size among the broadcast
   * publications, the one `supersedes` names aside, with that row authenticated
   * at a time the node confirms (now for a submitted row, its receipt's block
   * for an included one, `valid === true` for a finalized one); and the anchor
   * log explained above it. Null when the pass defers (the node could not
   * confirm) or stops.
   */
  const publishedState = async (
    report: AnchorPassReport,
    rows: AnchorPublication[],
    supersedes: number | null,
  ): Promise<{ published: number | null; explained: ExplainedRange; trust: AnchorLogTrust } | null> => {
    const row = rows
      .filter((p) => (p.state === 'submitted' || p.state === 'included' || p.state === 'finalized') && p.id !== supersedes)
      .reduce<AnchorPublication | null>((a, p) => (!a || p.anchorSize > a.anchorSize ? p : a), null);
    if (row && row.state !== 'submitted') {
      const confirmation = await trust.confirmed(row);
      if (confirmation.status === 'invalid') {
        raise(report, 'anchor_publication_unexplained', `Publication ${row.id}, at the published size ${row.anchorSize}, is not one the scheduler accepts: ${confirmation.why}. Anchoring is stopped.`, String(row.id));
        return null;
      }
      if (confirmation.status === 'unconfirmed') {
        unverified(report, String(row.id), `The node could not confirm publication ${row.id} at the published size (${confirmation.why}); no epoch is planned until it does.`);
        return null;
      }
      verified(String(row.id));
    }
    try {
      const lt = await getLogTrust();
      const base = await lt.base(row?.anchorSize ?? 0, row?.p ?? null, 'anchor_publication_unexplained', row ? String(row.id) : 'size 0');
      return { published: row?.anchorSize ?? null, explained: await lt.explain(base), trust: lt };
    } catch (err) {
      if (!(err instanceof AnchorTrustError)) throw err;
      raiseTrust(report, err);
      return null;
    }
  };

  const maybeEpoch = async (report: AnchorPassReport, force: boolean): Promise<void> => {
    const before = await evmPublications();
    const first = unminedOf(before);
    if (first.unmined.length > 0 && !first.supersedable) {
      if (force) report.deferred = 'publication_in_flight';
      return;
    }
    const w = await ensureWallet();
    const now = clock();
    const view = await readMarket(report, w);
    const wait = await waiting();
    const lastEpochAt = lastEpochAtOf(before);
    const input = {
      now,
      lastEpochAt,
      oldestTriggeringLeafAt: wait.triggering,
      oldestRideAlongLeafAt: wait.rideAlong,
      waitingLeaves: wait.count,
      intervalMs: view.intervalMs,
      cadence: config.cadence,
    };
    const natural = cadenceDecision({ ...input, force: false });
    nextDueAt = natural.due ? now : natural.dueAt;
    // A forced epoch is one the cadence would not have cut now: only those
    // count toward the rolling limit.
    const forced = force && !natural.due;
    const decision = forced ? cadenceDecision({ ...input, force: true }) : natural;
    if (!decision.due) {
      if (force) report.deferred = decision.why;
      return;
    }
    if (forced) {
      const refusal = await forceRefusal();
      if (refusal) {
        report.forceRefused = refusal;
        report.deferred = refusal.code;
        return;
      }
    }
    if (!publisherInWindow(report, 'no epoch is cut')) return;
    const fees = await clearToSign(report, w, decision.stale, view);
    if (!fees) return;
    if ((await checkHistory(report)) !== true) return;
    // A stored broadcast outcome is a hint: the publication a new epoch
    // supersedes gives its nonce up only once the node knows none of its
    // attempts.
    if (first.supersedable && !(await unknownToNode(first.supersedable))) {
      report.deferred = 'publication_in_flight';
      return;
    }
    // The nonce is settled before the epoch is written, so a nonce problem
    // leaves no epoch behind. A publication the epoch supersedes gives its nonce up.
    const nonce = await nextNonce(report, w, first.supersedable?.id);
    if (nonce === null) return;

    // The publications as they stand after the chain reads: the epoch is
    // planned on these, and its transaction refuses to write unless they
    // still stand and this instance still holds the lease (EpochGuard).
    await holdLease();
    const publications = await evmPublications();
    const { unmined, supersedable } = unminedOf(publications);
    if ((unmined.length > 0 && !supersedable) || supersedable?.id !== first.supersedable?.id) {
      report.deferred = 'publication_in_flight';
      return;
    }
    if (!authenticateRows(report, publications)) return;
    const state = await publishedState(report, publications, supersedable?.id ?? null);
    if (!state) return;
    const published = state.published;
    let planning: Awaited<ReturnType<typeof planEpoch>>;
    try {
      planning = await planEpoch({
        logs,
        anchors,
        domainPrefix,
        anchorOrigin,
        chain: publisher.chain,
        forced,
        publishedAnchorSize: published,
        explained: state.explained,
        trust: state.trust,
      });
    } catch (err) {
      if (!(err instanceof AnchorTrustError)) throw err;
      raiseTrust(report, err);
      return;
    }
    const { plan, refused } = planning;
    for (const r of refused) {
      if (r.reason === 'log_inconsistent_with_anchor') {
        raise(report, 'log_inconsistent_with_anchor', `The log ${r.origin} is refused: ${r.detail}. Other logs continue.`, r.origin);
      } else {
        log('anchor_log_refused', { origin: r.origin, reason: r.reason, detail: r.detail });
      }
    }
    if (!plan) {
      if (force) report.deferred = 'nothing_to_anchor';
      return;
    }
    let publication: AnchorPublication;
    try {
      [publication] = await anchors.persistEpoch({
        ...plan.write,
        guard: { domain: domainPrefix, holder, publishedAnchorSize: published, supersedes: supersedable?.id ?? null },
      });
    } catch (err) {
      if (!(err instanceof AnchorEpochFenceError)) throw err;
      report.deferred = err.reason;
      log('anchor_epoch_fenced', { reason: err.reason, message: err.message });
      return;
    }
    planned.set(publication.id, { p: plan.p, anchorSize: plan.anchorSize, createdAt: publication.createdAt, forced });
    if (supersedable) {
      report.transitions.push({ publicationId: supersedable.id, from: supersedable.state, to: 'superseded' });
      log('anchor_publication_state', { publicationId: supersedable.id, from: supersedable.state, to: 'superseded' });
    }
    report.epoch = {
      epochId: plan.epochId,
      anchorSize: plan.anchorSize,
      p: plan.p,
      publicationId: publication.id,
      members: plan.members.length,
      forced,
    };
    log('anchor_epoch', { epochId: plan.epochId, anchorSize: plan.anchorSize, p: plan.p, members: plan.members.length, forced });
    await sendAttempt(report, publication, nonce, fees);
  };

  // ── The fill ────────────────────────────────────────────────────────────

  /**
   * Fill every finalized publication whose stored `done` is not shown to
   * hold, in anchor-size order, each from the previous finalized size, after
   * the history check. A publication is filled only once the node confirms
   * it (`valid === true`); one it cannot confirm waits, and the ones after it
   * are filled from its size. A record that does not match its leaf is
   * skipped and reported (`anchor_fill_conflict`).
   */
  const fillFinalized = async (report: AnchorPassReport): Promise<void> => {
    const finalized = (await evmPublications()).filter((p) => p.state === 'finalized').sort((a, b) => a.anchorSize - b.anchorSize);
    const doneKey = (p: AnchorPublication): string => `${p.id}:${JSON.stringify(p.fillProgress)}`;
    if (finalized.every((p) => doneHolds.has(doneKey(p)))) return;
    // Nothing is filled from a history that no longer holds: the check runs
    // before any fill, so an instance started after a stopping alarm repeats
    // it before it writes a record.
    if (!authenticateRows(report, finalized)) return;
    if ((await checkHistory(report)) !== true) return;
    const lt = await getLogTrust();
    const ctx = { logs, anchors, anchorLogId: await getAnchorLogId(), expectation, chunkSize: tuning.fillChunkSize, trust: lt, beforeChunk: holdLease };
    let previous: { anchorSize: number; p: string } | null = null;
    for (const publication of finalized) {
      const authority = { previous, sender: trust.senderOf(publication) as string };
      previous = { anchorSize: publication.anchorSize, p: publication.p };
      if (doneHolds.has(doneKey(publication))) continue;
      const subject = String(publication.id);
      try {
        if (readFillProgress(publication)?.done && (await fillDoneHolds(ctx, publication, authority))) {
          doneHolds.add(doneKey(publication));
          continue;
        }
        const confirmation = await trust.confirmed(publication);
        if (confirmation.status === 'invalid') {
          raise(report, 'anchor_publication_unexplained', `Publication ${publication.id} is not one the scheduler accepts: ${confirmation.why}. Nothing is filled; anchoring is stopped.`, subject);
          return;
        }
        if (confirmation.status === 'unconfirmed') {
          unverified(report, subject, `The node could not confirm publication ${publication.id} (${confirmation.why}); its records are filled once it does.`);
          continue;
        }
        verified(subject);
        // Wall time, not the scheduler's clock: the duration of the fill itself.
        const started = Date.now();
        const outcome = await fillPublication(ctx, publication, authority);
        report.filled += outcome.filled;
        log('anchor_fill', {
          publicationId: publication.id,
          epochId: publication.epochId,
          filled: outcome.filled,
          alreadyAnchored: outcome.alreadyAnchored,
          missing: outcome.missing.length,
          conflicts: outcome.conflicts.length,
          done: outcome.done,
          durationMs: Date.now() - started,
        });
        if (outcome.hintRefused) log('anchor_fill_progress_refused', { publicationId: publication.id });
        if (outcome.missing.length > 0) log('anchor_fill_missing_records', { publicationId: publication.id, missing: outcome.missing.length });
        if (outcome.conflicts.length > 0) {
          raise(
            report,
            'anchor_fill_conflict',
            `Publication ${publication.id}: ${outcome.conflicts.length} record(s) do not match their evidence leaf and were not filled ` +
              `(${outcome.conflicts.slice(0, 5).join(', ')}${outcome.conflicts.length > 5 ? ', ...' : ''}).`,
            subject,
          );
        }
        if (outcome.done) {
          const after = await anchors.getAnchorPublication(publication.id);
          if (after) doneHolds.add(doneKey(after));
        }
      } catch (err) {
        if (!(err instanceof AnchorTrustError)) throw err;
        raiseTrust(report, err);
        return;
      }
    }
  };

  // ── The pass ────────────────────────────────────────────────────────────

  /**
   * Compare this instance's timestamp expectation with the one the store's
   * latest fill used (`fill_progress.timestampExpected`), and raise or clear
   * `anchor_expectation_mismatch`. Run by every instance, leader or not: the
   * one whose records a mismatched fill would move is usually not the leader.
   */
  const checkExpectation = async (report: AnchorPassReport): Promise<void> => {
    const own = expectation.timestamp !== false;
    const filled = (await evmPublications())
      .map((p) => ({ p, progress: readFillProgress(p) }))
      .filter((x) => x.progress?.timestampExpected !== undefined)
      .sort((a, b) => b.p.anchorSize - a.p.anchorSize)[0];
    if (!filled || filled.progress!.timestampExpected === own) {
      clear('anchor_expectation_mismatch', anchorOrigin);
      return;
    }
    const says = (t: boolean): string => (t ? 'a timestamp' : 'no timestamp');
    raise(
      report,
      'anchor_expectation_mismatch',
      `Publication ${filled.p.id} was filled by a writer whose records expect ${says(filled.progress!.timestampExpected!)}; ` +
        `this instance's records expect ${says(own)}. Every writer of an anchored store must expect the same timestamp ` +
        '(attestation.require and attestation.deferrable): a fill recomputes every record\'s status with the leader\'s ' +
        'expectation, so a record waiting for a timestamp can leave the retry\'s queue, or one waiting only for its anchor can stay pending.',
      anchorOrigin,
    );
  };

  const pass = async (force: boolean): Promise<AnchorPassReport> => {
    const report = newReport();
    if (halted) {
      report.halted = true;
      if (force) report.deferred = 'halted';
      return report;
    }
    await checkExpectation(report);
    const lease = await anchors.acquireAnchorLease(domainPrefix, holder, tuning.leaseTtlMs);
    if (lease.holder !== holder) {
      if (force) report.deferred = 'not_leader';
      return report;
    }
    report.leader = true;
    try {
      await leaderPass(report, force);
    } catch (err) {
      if (!(err instanceof LeaseLost)) throw err;
      report.deferred = 'lease_lost';
      log('anchor_lease_lost', { holder: err.holder });
    }
    report.halted = isHalted();
    return report;
  };

  const leaderPass = async (report: AnchorPassReport, force: boolean): Promise<void> => {
    await ensureWallet();

    // Every publication row is authenticated before anything reads it
    // (tzun-anchor/1 §11 item 5): a row the scheduler did not make stops the
    // pass.
    authenticated.clear();
    const rows = await evmPublications();
    if (!authenticateRows(report, rows)) return;
    for (const publication of rows) {
      if (isHalted()) break;
      if (publication.state === 'prepared') {
        await publishPrepared(report, publication, rows, force);
      } else if (publication.state === 'submitted') {
        await confirmSubmitted(report, publication);
      } else if (publication.state === 'included') {
        await confirmIncluded(report, publication);
      }
    }
    if (isHalted()) return;
    await fillFinalized(report);
    if (isHalted()) return;
    await maybeEpoch(report, force);
  };

  // The anchor pass runs on its own AttestationRetryScheduler: it serialises
  // passes, backs off 2, 4, 8, then 15 minutes while they fail, and waits for a
  // pass in flight on stop(). The retry scheduler hands its pass a record
  // limit; the anchor pass has none, so the value says whether the pass was
  // forced.
  const FORCED_PASS = -1;
  const NOT_LEADING: ReadonlySet<string> = new Set(['not_leader', 'lease_lost', 'lease_not_held']);
  const runner = new AttestationRetryScheduler<{ attempted: number; succeeded: number; failed: number; report: AnchorPassReport }>(
    async (limit) => {
      const report = await exclusive(() => pass(limit === FORCED_PASS));
      // Any state change is progress, and so is waiting inside the expected
      // mining or finality window.
      const moved = report.transitions.length > 0 || report.filled > 0 || report.epoch !== null;
      const waitingOnChain = report.awaitingFinality || report.awaitingInclusion;
      const busy =
        moved || waitingOnChain || (report.deferred !== null && !NOT_LEADING.has(report.deferred) && report.forceRefused === undefined);
      return {
        result: { attempted: busy ? 1 : 0, succeeded: moved ? 1 : 0, failed: report.deferred === 'node_unreachable' ? 1 : 0, report },
        requested: busy ? 1 : 0,
        progressed: moved || waitingOnChain,
      };
    },
    {
      intervalMs: tuning.tickMs,
      maxBackoffMs: Math.max(tuning.maxBackoffMs, tuning.tickMs),
      onLog: options.onLog ? (event, fields) => options.onLog!(event.replace(/^attestation_retry/, 'anchor'), fields) : () => undefined,
    },
  );

  const fillBacklog = async (): Promise<number> => {
    let backlog = 0;
    for (const p of await evmPublications()) {
      if (p.state !== 'finalized') continue;
      const progress = readFillProgress(p);
      if (!progress) backlog += 1;
      else if (!progress.done) backlog += Math.max(0, progress.total - progress.filled);
    }
    return backlog;
  };

  let closed = false;
  const refuseClosed = (what: string): void => {
    if (closed) throw new Error(`The anchor scheduler for ${anchorOrigin} is closed: ${what} runs nothing.`);
  };

  const scheduler: AnchorScheduler = {
    async runPass() {
      refuseClosed('runPass()');
      return (await runner.runPass(0)).report;
    },

    async anchorNow(opts = {}) {
      refuseClosed('anchorNow()');
      const { report } = await runner.runPass(opts.force === true ? FORCED_PASS : 0);
      if (report.forceRefused) throw report.forceRefused;
      return report;
    },

    async getAnchorState() {
      refuseClosed('getAnchorState()');
      const publications = await evmPublications();
      const broadcast = publications.filter((p) => ['submitted', 'included', 'finalized'].includes(p.state));
      const latest = (list: AnchorPublication[]): AnchorPublication | null =>
        list.reduce<AnchorPublication | null>((a, p) => (!a || p.anchorSize > a.anchorSize ? p : a), null);
      const lastPublished = latest(broadcast);
      const lastFinalized = latest(publications.filter((p) => p.state === 'finalized'));
      const spent = publications
        .filter((p) => p.state === 'finalized' && p.gasUsed !== null && p.effectiveGasPrice !== null)
        .reduce((sum, p) => sum + BigInt(p.gasUsed as string) * BigInt(p.effectiveGasPrice as string), 0n);
      const held = await anchors.getAnchorWallet(publisher.address, publisher.chain);
      const lease = (await anchors.getAnchorLease(domainPrefix)) ?? null;
      const retry = runner.getState();
      return {
        domainPrefix,
        anchorOrigin,
        namespace: isTest ? 'test' : 'production',
        production: config.production,
        chain: publisher.chain,
        publisher: publisher.address,
        lease: lease ? { holder: lease.holder, expiresAt: lease.expiresAt, self: lease.holder === holder } : null,
        halted,
        nextEpochDueAt: nextDueAt === null ? null : new Date(nextDueAt).toISOString(),
        lastPublished: lastPublished ? summary(lastPublished) : null,
        lastFinalized: lastFinalized ? summary(lastFinalized) : null,
        inFlight: publications.filter((p) => IN_FLIGHT.includes(p.state)).map(summary),
        wallet: {
          enrolled: held !== null,
          nonceBase: held?.nonceBase ?? null,
          balanceWei: lastBalance === null ? null : lastBalance.toString(),
          runwayDays: lastView?.runwayDays ?? null,
        },
        fees: {
          baseFeePerGasWei: lastFees ? lastFees.baseFeePerGas.toString() : null,
          maxPriorityFeePerGasWei: lastFees ? lastFees.maxPriorityFeePerGas.toString() : null,
          softMaxFeeGwei: config.budget.softMaxFeeGwei,
          hardFeeCapGwei: config.budget.hardFeeCapGwei,
        },
        intervalMs: lastView?.intervalMs ?? null,
        overBudget: lastView?.overBudget ?? null,
        spentWei: spent.toString(),
        force: { usedInLast24h: (await forcedInWindow()).length, limit: config.budget.forcePerDay },
        fillBacklog: await fillBacklog(),
        stalledPasses: retry.stalledPasses,
        lastPassAt: retry.lastPassAt,
        lastError: retry.lastError,
        alarms: [...alarms.values()],
      } satisfies AnchorState;
    },

    intervalMs() {
      return lastView?.intervalMs ?? config.cadence.targetIntervalMs;
    },

    async accountNonces() {
      refuseClosed('accountNonces()');
      const w = await ensureWallet().catch(async () => {
        const held = await anchors.getAnchorWallet(publisher.address, publisher.chain);
        if (!held) throw new Error(`The wallet ${publisher.address} is not enrolled.`);
        return held;
      });
      const count = await chain.transactionCount(w.address, 'latest');
      const publications = (await evmPublications()).filter((p) => p.fromAddress === w.address && p.nonce !== null);
      const txs = await checkedWalletTxs(null, w);
      if (txs === null) throw new Error(`An accounted transaction of ${w.address} is not the transaction it claims to be: anchor_wallet_tx_unexplained.`);
      const logId = await getAnchorLogId();
      const accounted: NonceAccounting['accounted'] = [];
      const unaccounted: number[] = [];
      for (let nonce = w.nonceBase; nonce < count; nonce++) {
        let found: NonceAccounting['accounted'][number] | null = null;
        for (const p of publications.filter((x) => x.nonce === nonce)) {
          const cp = await anchors.getLogCheckpoint(logId, p.anchorSize);
          if (!cp || checkpointDigest(cp.body) !== p.p) continue;
          for (const a of p.attempts) {
            const tx = await chain.transaction(a.txHash);
            if (tx && tx.blockHash !== null && tx.from === w.address && tx.nonce === nonce && tx.data === `0x${p.p}`) {
              found = { nonce, kind: 'publication', txHash: a.txHash };
              break;
            }
          }
          if (found) break;
        }
        if (!found) {
          for (const t of txs.filter((x) => x.nonce === nonce)) {
            const tx = await chain.transaction(t.txHash);
            if (tx && tx.blockHash !== null && tx.from === w.address && tx.nonce === nonce) {
              found = { nonce, kind: t.kind, txHash: t.txHash };
              break;
            }
          }
        }
        if (found) accounted.push(found);
        else unaccounted.push(nonce);
      }
      return { address: w.address, chain: w.chain, nonceBase: w.nonceBase, transactionCount: count, accounted, unaccounted };
    },

    async sweep(to) {
      refuseClosed('sweep()');
      return accountedTransaction('sweep', async (w, fees, nonce) => {
        const gasLimit = 21_000n;
        const balance = await chain.balance(w.address);
        const value = balance - gasLimit * fees.maxFeePerGas;
        if (value <= 0n) throw new Error(`The wallet's balance (${balance} wei) does not cover a sweep's fee.`);
        return publisher.signTransfer(to, value, '0x', { nonce, ...fees, gasLimit });
      });
    },

    async handover(newAnchorOrigin) {
      refuseClosed('handover()');
      assertHandoverOrigin(newAnchorOrigin);
      return accountedTransaction('handover', async (w, fees, nonce) =>
        publisher.signTransfer(w.address, 0n, `0x${Buffer.from(newAnchorOrigin, 'utf8').toString('hex')}`, {
          nonce,
          ...fees,
          gasLimit: 60_000n,
        }),
      );
    },

    async rebroadcastAccountedTransaction() {
      refuseClosed('rebroadcastAccountedTransaction()');
      return exclusive(async () => {
        await walletLease();
        const held = await anchors.getAnchorWallet(publisher.address, publisher.chain);
        if (!held) throw new Error(`The wallet ${publisher.address} is not enrolled.`);
        const txs = await checkedWalletTxs(null, held);
        if (txs === null) throw new Error(`An accounted transaction of ${held.address} is not the transaction it claims to be: anchor_wallet_tx_unexplained.`);
        const tx = txs[txs.length - 1];
        if (!tx) throw new Error(`The wallet ${held.address} has no accounted transaction to send again.`);
        if (await chain.receipt(tx.txHash)) {
          const retired = await retire(held);
          log('anchor_wallet_accounted_tx', { kind: tx.kind, nonce: tx.nonce, txHash: tx.txHash, outcome: 'mined' });
          return { tx, broadcast: null, retired };
        }
        return sendAccounted(held, tx);
      });
    },

    start() {
      try {
        refuseClosed('start()');
      } catch (err) {
        return Promise.reject(err);
      }
      return runner.start();
    },

    async stop() {
      await runner.stop();
      await anchors.releaseAnchorLease(domainPrefix, holder).catch(() => undefined);
    },

    async close() {
      if (closed) return;
      closed = true;
      await scheduler.stop();
      if (ownsPublisher) publisher.client.close();
    },
  };

  /** The lease, for a wallet operation: `AnchorNotLeaderError` when another instance holds it. */
  const walletLease = async (): Promise<void> => {
    try {
      await holdLease();
    } catch (err) {
      if (err instanceof LeaseLost) throw new AnchorNotLeaderError(err.holder);
      throw err;
    }
  };

  /** Retire the wallet, once; true when it is retired afterwards. */
  const retire = async (w: AnchorWallet): Promise<boolean> => {
    if (w.retiredAt === null) {
      const current = await anchors.getAnchorWallet(w.address, w.chain);
      if (current?.retiredAt === null) await anchors.retireAnchorWallet(w.address, w.chain);
    }
    wallet = null;
    return true;
  };

  /**
   * Broadcast a stored accounted transaction; the wallet is retired only when
   * the node did not refuse it. Its bytes pass `unsendable` first, with the
   * wallet as sender, as tzun-anchor/1 §7.2 rule 3 asks of the publisher
   * key's accounting transactions too: bytes that fail are not sent, and
   * `anchor_wallet_tx_unexplained` stops anchoring.
   */
  const sendAccounted = async (w: AnchorWallet, tx: AnchorWalletTx): Promise<AccountedTransactionResult> => {
    await walletLease();
    const why = unsendable(tx.rawTx, w.address)?.why ?? null;
    if (why !== null) {
      raise(
        null,
        'anchor_wallet_tx_unexplained',
        `The accounted transaction of ${tx.address} at nonce ${tx.nonce} is not sent: ${why}. Anchoring is stopped.`,
        `${tx.address}@${tx.nonce}`,
      );
      throw new Error(`The accounted transaction of ${tx.address} at nonce ${tx.nonce} is not sent (${why}): anchor_wallet_tx_unexplained.`);
    }
    const broadcast = await chain.broadcast(tx.rawTx);
    const retired = broadcast.outcome === 'rejected' ? false : await retire(w);
    log('anchor_wallet_accounted_tx', { kind: tx.kind, nonce: tx.nonce, txHash: tx.txHash, outcome: broadcast.outcome, retired });
    return { tx, broadcast, retired };
  };

  /**
   * The first publication that still needs the wallet: one not superseded and
   * not finalized, or a finalized one whose stored `done` no record bears out
   * (`fillDoneHolds`: the last record of its range carries its artifact). A
   * stored `done` alone retires nothing.
   */
  const openPublication = async (): Promise<AnchorPublication | null> => {
    const publications = await evmPublications();
    const unsettled = publications.find((p) => p.state !== 'superseded' && p.state !== 'finalized');
    if (unsettled) return unsettled;
    const ctx = { logs, anchors, anchorLogId: await getAnchorLogId(), expectation, chunkSize: tuning.fillChunkSize, trust: await getLogTrust() };
    let previous: { anchorSize: number; p: string } | null = null;
    for (const p of publications.filter((x) => x.state === 'finalized').sort((a, b) => a.anchorSize - b.anchorSize)) {
      const authority = { previous, sender: trust.senderOf(p) ?? '' };
      previous = { anchorSize: p.anchorSize, p: p.p };
      if (!(await fillDoneHolds(ctx, p, authority))) return p;
    }
    return null;
  };

  /**
   * An accounted transaction: stored before it is sent; the wallet is retired
   * for this domain once the node takes it. It runs between passes, under the
   * lease, and only when nothing needs the wallet again: every publication is
   * superseded, or finalized and filled, and no accounted transaction is
   * waiting to be mined.
   */
  const accountedTransaction = (
    kind: 'sweep' | 'handover',
    sign: (w: AnchorWallet, fees: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }, nonce: number) => Promise<{ raw: string; hash: string }>,
  ): Promise<AccountedTransactionResult> =>
    exclusive(async () => {
      await walletLease();
      const w = await ensureWallet();
      const open = await openPublication();
      if (open) {
        throw new Error(
          `Publication ${open.id} is ${open.state === 'finalized' ? 'finalized but not filled' : open.state}: a ${kind} retires ` +
            'the wallet, so every publication must be finalized and filled first.',
        );
      }
      const mined = await chain.transactionCount(w.address, 'latest');
      const accountedTxs = await checkedWalletTxs(null, w);
      if (accountedTxs === null) throw new Error(`An accounted transaction of ${w.address} is not the transaction it claims to be: anchor_wallet_tx_unexplained.`);
      const waitingTx = accountedTxs.find((t) => t.nonce >= mined);
      if (waitingTx) {
        throw new Error(
          `The ${waitingTx.kind} at nonce ${waitingTx.nonce} is stored and not mined: send it again with ` +
            'rebroadcastAccountedTransaction() instead of signing another.',
        );
      }
      const report = newReport();
      const market = await marketFees();
      const fees = publicationFees(market.baseFeePerGas, market.maxPriorityFeePerGas, config.budget);
      if (!fees) throw new Error(`The fee is above the hard cap; the ${kind} is not sent.`);
      const nonce = await nextNonce(report, w);
      if (nonce === null) throw new Error(`The ${kind} cannot take a nonce now (${report.deferred ?? report.alarms[0]?.code ?? 'unknown'}).`);
      await walletLease();
      const signed = await sign(w, fees, nonce);
      const row = { address: w.address, chain: w.chain, nonce, txHash: signed.hash, kind, rawTx: signed.raw };
      const rowRefusal = (): Unsendable | null => {
        try {
          assertWalletTx(row);
          return null;
        } catch (err) {
          return { field: 'transaction', why: (err as Error).message };
        }
      };
      const refused = answerRefusal(unsendable(signed.raw, w.address) ?? rowRefusal());
      if (refused !== null) throw refused;
      await enrolSigned();
      const tx = await anchors.insertAnchorWalletTx(row);
      return sendAccounted(w, tx);
    });

  /** `handover`'s target: another domain's anchor log origin, `<ns>/<id>/anchors`, with a valid namespace. */
  const assertHandoverOrigin = (origin: unknown): void => {
    const parsed = parseOrigin(origin);
    const refuse = (why: string): never => {
      throw new Error(`handover needs another domain's anchor origin, <ns>/<id>/anchors: ${why}.`);
    };
    if (!parsed || parsed.kind !== 'anchors') refuse(`${JSON.stringify(origin)} is not an anchor log origin`);
    if (parsed!.domainPrefix === domainPrefix) refuse('it is this domain\'s own anchor origin');
    try {
      assertLogNamespace(parsed!.namespace);
    } catch (err) {
      if (err instanceof InvalidLogNamespaceError) refuse(err.message);
      throw err;
    }
  };

  return scheduler;
}
