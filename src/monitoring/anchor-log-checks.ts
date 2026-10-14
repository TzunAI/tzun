/**
 * What the scanner checks in a store's evidence logs and anchoring tables
 * (tzun-anchor/1 §10.8, §10.10). The letters below name the checks here and
 * in the scanner.
 *
 * Per record, through the chain walk (`verifyChainCompleteness` with the
 * chain's evidence log, `StoreLogs.chainEvidenceLog`):
 *
 *   a  a record's digest is not the leaf logged at its position
 *      (`digest_differs_from_logged_leaf`);
 *   h  a record carries no anchor in an epoch whose fill has finished
 *      (`anchor_stripped`).
 *
 * Per log and per publisher wallet (`checkAnchoredLogs`):
 *
 *   b  a log's leaves no longer rebuild a root that was anchored
 *      (`log_rewritten_below_anchor`). The anchored root comes from the
 *      published P, never from `anchor_publications`: P is the calldata of the
 *      publisher's own transaction, read over RPC, with its sender and nonce
 *      checked. A body is authenticated when it hashes to a P sent by a
 *      publisher the scanner's manifest lists (the anchor log's checkpoint),
 *      or when an inclusion path places its digest under an authenticated
 *      anchor checkpoint (a source log's checkpoint). The authenticated
 *      bodies come from the store's checkpoints and from the anchors filled
 *      into records. When the manifest lists no publisher for the store, the
 *      store's own wallet rows say who publishes, and what they vouch for is
 *      unauthenticated. Without a chain to read, the store's own checkpoints
 *      are the reference. Either way the finding says so
 *      (`authenticated: false`);
 *   c  a log, or an evidence log's chain head, is below an anchored size
 *      (`log_truncated_below_anchor`). The head is read after the log's
 *      checkpoints, so an epoch cut while the pass runs is never above it;
 *   d  the store's checkpoints of a log are not one growing log: a stored
 *      consistency proof fails, a predecessor is gone, an anchored checkpoint
 *      is not proved from the one before it, or a body does not state its own
 *      row (`log_inconsistent_with_anchor`); two authenticated bodies state
 *      one size with two roots (`split_view`, tzun-anchor/1 §10.8);
 *   e  a chain's oldest leaf without a filled anchor was logged more than
 *      T_max ago (`anchor_overdue`), when the deployment anchors;
 *   g  a nonce of a publisher wallet, from its floor to its transaction
 *      count, maps to neither a stored publication whose anchor checkpoint
 *      hashes to the transaction's calldata nor a stored accounted
 *      transaction with its hash (`anchor_wallet_nonce_unaccounted`). A wallet
 *      the manifest lists is accounted from the scanner's own floor
 *      (`ScannerAnchoringDeps.nonceBases`), whether or not the store still
 *      holds its row; any other wallet a publication names, from its stored
 *      `nonce_base`.
 *
 * A chain read that fails or answers nothing leaves what it would decide
 * undecided, and the result says what was not checked: an empty answer is
 * never a statement (tzun-anchor/1 §10.4).
 *
 * The checks split into what is about the domain and what is about a chain
 * (`ScannerAnchoringDeps.scope`). The domain's: the publications, the anchor
 * log (b, c, d), the source logs that belong to no chain (b, c, d), their
 * split views, and the publisher wallets (g). A chain's: the records (a, h,
 * `anchor_transplanted`) and the chain's evidence log (b, c, d, its split
 * view, e). A deployment with many chains makes one domain scan and one
 * chain scan per chain, and the scans of one pass share their chain reads
 * and the anchor log's published sizes (`runAnchorScanPass`), so the pass
 * reads each transaction once, not once per chain.
 */
import { createHash } from 'node:crypto';
import { Transaction, keccak256 } from 'ethers';
import {
  extendCompactRange,
  verifyConsistencyProof,
  verifyMerkleProof,
  type ChainEvidenceLog,
  type CompactRange,
  type EvidenceEnvelope,
  type EvmFinality,
  type LogInconsistencyReason,
  type MonitoringEvent,
  type StorageAdapter,
} from '@tzun/engine';
import { ANCHOR_SPEC } from '../attestation/anchor-verify';
import { checkedFinality, type EvmHeaderSource, type EvmNetwork, type PublisherManifest } from '../attestation/blockchain';
import { anchorLogOrigin, parseCheckpoint, type Checkpoint } from '../attestation/checkpoint';
import { DEFAULT_ANCHOR_CADENCE } from '../anchoring/config';
import { rpcErrorText } from '../anchoring/evm-chain';
import {
  ANCHOR_LOG_KIND,
  EVIDENCE_LOG_KIND,
  anchorStoreFor,
  logStoreFor,
  type AnchorPublication,
  type AnchorStore,
  type AnchorWallet,
  type LeafAnchorProgress,
  type LogCheckpoint,
  type LogLeaf,
  type LogRecord,
  type LogStore,
} from '../storage/log-store';

/** A transaction as a chain the scanner reads reports it. */
export interface ScannerEvmTransaction {
  /** The sender, `0x` and 40 hex. */
  from: string;
  nonce: number;
  /** Calldata, `0x` hex. */
  data: string;
  /** The block that includes it, or `null` while it is not mined. */
  blockHash: string | null;
  blockNumber: number | null;
}

/**
 * One EVM chain, as the scanner reads it: the verifier's header source for
 * the chain (canonicality and finality of an anchor's block), plus the reads
 * checks b and g make. `JsonRpcEvmChain` (src/anchoring) is one.
 *
 * Its `finality` says what `finalizedBlockNumber()` counts as final, and every
 * pass reports it (`ScanSummary.evmFinality`, and `anchorFinality` on an
 * anchor's `attestation_invalid`). It is held to the verifier's rule when the
 * scanner is built (`scannerChainFinality`): `'finalized'`, or a confirmation
 * depth of at least `EVM_MIN_FINAL_CONFIRMATIONS` (64) unless it sets
 * `acceptNonFinal: true`. A chain that declares none is taken at its word,
 * and reported as declaring none.
 */
export interface ScannerEvmChain extends EvmHeaderSource {
  /** The number of transactions `address` has had mined. */
  transactionCount(address: string, tag: 'latest'): Promise<number>;
  transaction(transactionId: string): Promise<ScannerEvmTransaction | null>;
}

/**
 * What the scanner needs to check anchored evidence against what was
 * published. Every field is the scanner's own input, never the store's: the
 * store is what is being checked.
 *
 * Supplying this object says the deployment anchors, which turns on check e
 * (`anchor_overdue`).
 */
export interface ScannerAnchoringDeps {
  /**
   * Which wallets may publish P for which anchor origin (tzun-anchor/1 §9).
   * With `evmChains`, a record's EVM publication is checked end to end. When
   * it lists EVM publishers for the store's anchor origin, they are the only
   * publishers checks b and g accept; otherwise the store's own wallet rows
   * stand in, and what they vouch for is unauthenticated.
   */
  publisherManifest?: PublisherManifest;
  /**
   * Where check g starts accounting each publisher wallet the manifest lists
   * for the store's anchor origin, keyed by CAIP-10 account
   * (`eip155:11155111:0x…`, the address in any case). A wallet absent here
   * starts at 0: dedicated to the domain from its first transaction. Give its
   * enrolment nonce when it had sent transactions before it was enrolled (a
   * wallet handed over from another domain, for one).
   *
   * The floor is the scanner's input, not the store's `nonce_base`, because
   * the store is what is being checked: a database owner who deleted the
   * wallet's publications and its row would otherwise let the scheduler
   * enrol the wallet again above the nonces that were hidden.
   */
  nonceBases?: Record<string, number>;
  /**
   * The chains the store publishes on, keyed by CAIP-2 chain
   * (`eip155:11155111`). Each is the header source for its chain, and the
   * source of P (a transaction's calldata) for check b and of the wallet's
   * transaction count for check g. Without one, those checks fall back to the
   * store's own checkpoints (b) or do not run (g).
   */
  evmChains?: Record<string, ScannerEvmChain>;
  /** Overrides or extends the CAIP-2 → network registry. */
  evmNetworks?: Record<string, EvmNetwork>;
  /** One deadline for the header-source calls of one record's anchor verification. Default 30 s. */
  evmTimeoutMs?: number;
  /** T_max: how long a leaf may wait for its anchor. Default 24 h. */
  maxStalenessMs?: number;
  /**
   * The clock checks e and g read: e for how long a leaf has waited, g for
   * whether a manifest entry's `validUntil` has passed. Default `Date.now`.
   */
  now?: () => number;
  /**
   * Which part of the checks this scanner makes. Default `'all'`.
   *
   *   - `'all'`: every check, over the chains the scanner walks and every
   *     log of the store.
   *   - `'domain'`: the domain scan. The scanner walks no chain and checks no
   *     record. It re-derives each publication's P from the chain (b), judges
   *     the anchor log (b, c, d) and the source logs that belong to no chain
   *     (b, c, d), reports their split views, and accounts for the publisher
   *     wallets (g). Run over a view of the store that holds every log of the
   *     domain.
   *   - `'sourceLogs'`: a chain scan. The scanner walks its chains and checks
   *     their records (a, h, `anchor_transplanted`, the attestation check)
   *     and their evidence logs (b, c, d, their split views, e). It still
   *     reads the anchor log's published sizes, to tell which of a chain's
   *     checkpoints a publication vouches for, and reports nothing about the
   *     anchor log, the other source logs or the wallets.
   *
   * One domain scan and a chain scan for every chain make the checks `'all'`
   * makes over the whole store. Two things differ. The domain scan judges
   * the anchor log against the anchor checkpoints the records carry only
   * when it runs after the chain scans of its pass and shares their
   * `sharedCache`; run first, it judges it against the publications alone.
   * And a chain scan tells which of its chain's checkpoints the anchor log
   * vouches for by the anchor log as its own records show it, where `'all'`
   * reads every chain's records first.
   */
  scope?: ScannerLogScope;
  /**
   * What the scanners of one pass share: the cache `runAnchorScanPass` hands
   * the pass, given to its domain scanner and every chain scanner. They then
   * read each transaction, block and finalized height once for the pass, the
   * store's publications once, and the anchor log's published sizes once. A
   * chain scan leaves in it the anchor checkpoints its records carry, for the
   * domain scan.
   *
   * The scanners that share one must share the anchoring inputs (the
   * manifest, the floors, the same `evmChains` readers) and scan one domain,
   * or views of it. A cache is read only while its pass runs: a scanner handed
   * one whose pass has ended, one it has already made a pass with, or an
   * object `runAnchorScanPass` did not make reads on its own for that pass and
   * logs that it did. Without one, a scanner keeps its reads to itself.
   */
  sharedCache?: AnchorScanCache;
}

/** The part of the log checks a scanner makes: `ScannerAnchoringDeps.scope`. */
export type ScannerLogScope = 'all' | 'domain' | 'sourceLogs';

declare const anchorScanPassBrand: unique symbol;

/**
 * What the scanners of one pass share (`ScannerAnchoringDeps.sharedCache`).
 * Only `runAnchorScanPass` makes one, for the pass it runs, and its reads
 * end when that pass does.
 */
export interface AnchorScanCache {
  readonly [anchorScanPassBrand]: true;
}

/**
 * What stays true from one pass to the next (`runAnchorScanPass`): a
 * transaction read in a finalized block is fixed by its id, and the signer
 * recovered from stored bytes is fixed by their hash.
 */
export interface AnchorScanCarry {
  /** Transactions read in finalized blocks, by lowercase id. */
  minedTransactions?: Map<string, ScannerEvmTransaction>;
  /** Stored raw transactions whose signer was recovered, by lowercase hash. */
  signedTransactions?: Map<string, SignedTransaction>;
}

/** @internal What one pass reads once, whether one scanner makes the pass or several share it. */
export interface PassReads {
  /** Transactions read in finalized blocks, by id: kept by the scanner, or carried from pass to pass. */
  minedTransactions: Map<string, ScannerEvmTransaction>;
  /** Signers recovered from stored raw transactions, by hash. */
  signedTransactions: Map<string, SignedTransaction>;
  /** Transactions read on this pass, by id. A read that fails is dropped, so the next question asks again. */
  transactions: Map<string, Promise<ScannerEvmTransaction | null>>;
  /** Each chain's finalized height, read once this pass. */
  finalizedHeights: Map<ScannerEvmChain, Promise<number>>;
  /** Each chain as the verifier's header source, by what the scanner counts as final there. */
  headerSources: Map<ScannerEvmChain, Map<string, EvmHeaderSource>>;
  /** Stored wallet rows, by domain, address and chain. */
  wallets: Map<string, Promise<AnchorWallet | null>>;
  /** The anchor log's published sizes, by anchor origin: read once for the pass's chain scans. */
  anchorBases: Map<string, Promise<AnchorBasis>>;
  /** Anchor checkpoints the chain scans found in their records, by origin: the domain scan judges the anchor log against them. */
  recordAnchorRefs: Refs;
  /** The mined EVM publications' material for the attestation check, by anchor origin. */
  publicationMaterial: Map<string, Promise<Map<string, EvmPublicationMaterial>>>;
}

/** @internal A pass's reads, empty, over the maps of what stays true across passes. */
export function newPassReads(minedTransactions: Map<string, ScannerEvmTransaction>, signedTransactions: Map<string, SignedTransaction>): PassReads {
  return {
    minedTransactions,
    signedTransactions,
    transactions: new Map(),
    finalizedHeights: new Map(),
    headerSources: new Map(),
    wallets: new Map(),
    anchorBases: new Map(),
    recordAnchorRefs: new Refs(),
    publicationMaterial: new Map(),
  };
}

/** Each cache `runAnchorScanPass` made, with its pass's reads while the pass runs, and null once it has ended. */
const sharedPasses = new WeakMap<AnchorScanCache, { reads: PassReads | null }>();

/**
 * Runs one pass of a deployment's scans over one `AnchorScanCache`: `run`
 * hands the cache to every scanner of the pass (the chain scans, then the
 * domain scan) and settles when they have finished. Everything `run` scans is
 * one pass. The cache's reads end when `run` settles, so a scan made after
 * that never reads them, whichever chain it names and whatever order it runs
 * in.
 *
 * `carry` keeps what stays true from one pass to the next. Hand every pass
 * the same maps and a later pass does not read those transactions and
 * signers again. Without them the pass keeps its own.
 */
export async function runAnchorScanPass<T>(run: (cache: AnchorScanCache) => Promise<T> | T, carry: AnchorScanCarry = {}): Promise<T> {
  const cache = Object.freeze({}) as unknown as AnchorScanCache;
  const pass = { reads: newPassReads(carry.minedTransactions ?? new Map(), carry.signedTransactions ?? new Map()) as PassReads | null };
  sharedPasses.set(cache, pass);
  try {
    return await run(cache);
  } finally {
    pass.reads = null;
  }
}

/**
 * @internal The reads `cache` holds for its pass while `runAnchorScanPass`
 * runs it; null once the pass has ended, and for an object it did not make.
 */
export function sharedPassReads(cache: AnchorScanCache): PassReads | null {
  return sharedPasses.get(cache)?.reads ?? null;
}

/** @internal `read()` once per key for the pass; a read that fails is dropped, so the next caller asks again. */
export function readOnce<T>(cache: Map<string, Promise<T>>, key: string, read: () => Promise<T>): Promise<T> {
  let pending = cache.get(key);
  if (!pending) {
    pending = read();
    cache.set(key, pending);
    pending.catch(() => cache.delete(key));
  }
  return pending;
}

/** @internal `chain` as the pass's header source (`memoizedHeaderSource`), one per chain and finality for the pass. */
export function passHeaderSource(reads: PassReads, chain: ScannerEvmChain, finality: EvmFinality | null): EvmHeaderSource {
  let byFinality = reads.headerSources.get(chain);
  if (!byFinality) reads.headerSources.set(chain, (byFinality = new Map()));
  const key = JSON.stringify(finality);
  let source = byFinality.get(key);
  if (!source) byFinality.set(key, (source = memoizedHeaderSource(chain, finality)));
  return source;
}

/** The export-bundle material of one mined EVM publication, as `verifyAnchor` joins it (tzun-anchor/1 §8.2). */
export interface EvmPublicationMaterial {
  kind: 'evm-calldata/1';
  rawTransaction: string;
  blockNumber: number;
  blockHash: string;
  blockHeader?: string;
  txIndex?: number;
  txProof?: string[];
}

/**
 * What each of `chains` counts as final, keyed as they are: its declared
 * `finality` checked as `RpcEvmHeaderSource` checks one (`checkedFinality`),
 * or `null` for a chain that declares none. Read once, into fresh values, so
 * a declaration changed later changes no pass.
 *
 * @throws naming the chain, when a declaration is not an `EvmFinality`, or is
 *   a depth below `EVM_MIN_FINAL_CONFIRMATIONS` without `acceptNonFinal: true`.
 */
export function scannerChainFinality(chains: Record<string, ScannerEvmChain> | undefined): Record<string, EvmFinality | null> {
  const out: Record<string, EvmFinality | null> = {};
  for (const [key, chain] of Object.entries(chains ?? {})) {
    const declared = chain.finality;
    out[key] = declared === undefined ? null : checkedFinality(declared, `The scanner's chain ${key}:`);
  }
  return out;
}

/**
 * `chain` as a header source that asks each question once: every record of an
 * epoch names the same block and transaction, so one pass asks the node about
 * each epoch, not about each record. A failed call is not kept, so the next
 * record asks again. It declares `finality`, the chain's as the scanner
 * checked it when it was built (`scannerChainFinality`), so the verifier
 * reports the finality each verdict was judged under; `null` declares none.
 */
export function memoizedHeaderSource(chain: ScannerEvmChain, finality: EvmFinality | null): EvmHeaderSource {
  const chainIds = new Map<string, Promise<bigint>>();
  const finalized = new Map<string, Promise<number>>();
  const blocks = new Map<string, Promise<{ hash: string; timestamp: number } | null>>();
  const transactions = new Map<string, Promise<ScannerEvmTransaction | null>>();
  return {
    ...(finality !== null && { finality }),
    chainId: () => readOnce(chainIds, '', () => chain.chainId()),
    finalizedBlockNumber: () => readOnce(finalized, '', () => chain.finalizedBlockNumber()),
    canonicalBlock: (n) => readOnce(blocks, String(n), () => chain.canonicalBlock(n)),
    transaction: (id) => readOnce(transactions, id.toLowerCase(), () => chain.transaction(id)),
  };
}

/** The adapter behind the verifying proxy, or `storage` itself: the log stores are read from the adapter. */
function underlying(storage: StorageAdapter): StorageAdapter {
  const proxy = storage as StorageAdapter & { unwrap?: () => StorageAdapter };
  return typeof proxy.unwrap === 'function' ? proxy.unwrap() : storage;
}

const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
const HEX_P = /^0x[0-9a-f]{64}$/;
const lower = (v: unknown): string | null => (typeof v === 'string' ? v.toLowerCase() : null);

/** A checkpoint body parsed, with its digest; `null` for one that does not parse. */
function readBody(body: unknown): (Checkpoint & { digest: string }) | null {
  const parsed = parseCheckpoint(body);
  return parsed.ok ? { ...parsed.checkpoint, digest: sha256(parsed.checkpoint.body) } : null;
}

/** Whether the fill of the epoch `progress` describes has finished: its deciding publication is final and its `fill_progress` done. */
function fillDone(progress: LeafAnchorProgress | null): boolean {
  const pubs = progress?.publications ?? [];
  const primary = pubs.find((p) => p.kind === 'evm-calldata/1') ?? pubs.find((p) => p.kind === 'rfc3161/1');
  return !!primary && (primary.state === 'finalized' || primary.state === 'obtained') && primary.fillProgress?.done === true;
}

/**
 * The store's logs, read once per pass: its identity, its logs, each log's
 * checkpoints and the fill of each epoch.
 */
export class StoreLogs {
  private readonly checkpointCache = new Map<number, Promise<LogCheckpoint[]>>();
  private readonly anchoredCache = new Map<number, Promise<LogCheckpoint[]>>();
  private readonly fillCache = new Map<string, Promise<boolean>>();

  private constructor(
    readonly logs: LogStore,
    readonly anchors: AnchorStore | undefined,
    readonly domainPrefix: string,
    readonly anchorOrigin: string,
    readonly logList: LogRecord[],
  ) {}

  /** The store's logs, or null for a store that keeps none (the cloud transport, a custom adapter). */
  static async open(storage: StorageAdapter): Promise<StoreLogs | null> {
    const base = underlying(storage);
    const logs = logStoreFor(base);
    if (!logs) return null;
    const identity = await logs.getStoreIdentity();
    const domainPrefix = `${identity.ns}/${identity.storeId}`;
    return new StoreLogs(logs, anchorStoreFor(base), domainPrefix, anchorLogOrigin(domainPrefix), await logs.listLogs());
  }

  get anchorLog(): LogRecord | undefined {
    return this.logList.find((l) => l.kind === ANCHOR_LOG_KIND && l.chainId === null);
  }

  evidenceLog(chainId: string): LogRecord | undefined {
    return this.logList.find((l) => l.kind === EVIDENCE_LOG_KIND && l.chainId === chainId);
  }

  /** A log's checkpoints in size order; none on a store without anchoring tables. */
  checkpoints(logId: number): Promise<LogCheckpoint[]> {
    let read = this.checkpointCache.get(logId);
    if (!read) {
      read = this.anchors ? this.anchors.listLogCheckpoints(logId) : Promise.resolve([]);
      this.checkpointCache.set(logId, read);
    }
    return read;
  }

  /** A log's checkpoints that sit in the anchor log, in size order. */
  anchoredCheckpoints(logId: number): Promise<LogCheckpoint[]> {
    let read = this.anchoredCache.get(logId);
    if (!read) {
      read = this.checkpoints(logId).then((all) => all.filter((c) => c.anchorLeafIndex !== null));
      this.anchoredCache.set(logId, read);
    }
    return read;
  }

  /**
   * Whether the fill of the epoch that anchors leaf `leafIndex` of `log` has
   * finished: the rule `get()` reports `anchor_stripped` by
   * (`AnchorStore.getLeafAnchorProgress`), asked once per anchored checkpoint.
   */
  async anchorFillDone(log: LogRecord, leafIndex: number): Promise<boolean> {
    if (!this.anchors) return false;
    const anchored = await this.anchoredCheckpoints(log.logId);
    // The first anchored checkpoint past the leaf: the epoch that anchors it.
    let lo = 0;
    let hi = anchored.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (anchored[mid].treeSize > leafIndex) hi = mid;
      else lo = mid + 1;
    }
    const covering = anchored[lo];
    if (!covering) return false;
    const key = `${log.logId}:${covering.treeSize}`;
    let done = this.fillCache.get(key);
    if (!done) {
      const anchors = this.anchors;
      done = anchors.getLeafAnchorProgress(log.logId, covering.treeSize - 1).then(fillDone);
      this.fillCache.set(key, done);
    }
    return done;
  }

  /** The chain's evidence log for the walk (checks a and h), or null before the chain's first record. */
  chainEvidenceLog(chainId: string): { log: LogRecord; reader: ChainEvidenceLog } | null {
    const log = this.evidenceLog(chainId);
    if (!log) return null;
    return {
      log,
      reader: {
        leaves: async (from, to) =>
          (await this.logs.listLogLeaves(log.logId, from, to)).map((l) => ({ leafIndex: l.leafIndex, leafDigest: l.leafDigest })),
        anchorFillDone: (leafIndex) => this.anchorFillDone(log, leafIndex),
      },
    };
  }
}

/** What check b and split_view compare the logs against: one root a log had at one size. */
interface RootRef {
  root: string;
  /** From a published P (directly or through an inclusion path), or only from the store's own checkpoint. */
  authenticated: boolean;
}

/** Roots per origin, per size. */
class Refs {
  readonly byOrigin = new Map<string, Map<number, RootRef[]>>();

  add(origin: string, size: number, root: string, authenticated: boolean): void {
    let sizes = this.byOrigin.get(origin);
    if (!sizes) this.byOrigin.set(origin, (sizes = new Map()));
    const refs = sizes.get(size) ?? [];
    const same = refs.find((r) => r.root === root);
    if (same) same.authenticated ||= authenticated;
    else refs.push({ root, authenticated });
    sizes.set(size, refs);
  }

  of(origin: string): Map<number, RootRef[]> {
    return this.byOrigin.get(origin) ?? new Map();
  }
}

/** The roots `refs` holds for `origin`, copied out: what a later `add` does to `refs` does not change them. */
function anchorRefsIn(refs: Refs, origin: string): AnchorRef[] {
  const out: AnchorRef[] = [];
  for (const [size, list] of refs.of(origin)) for (const r of list) out.push({ size, root: r.root, authenticated: r.authenticated });
  return out;
}

/** The largest of `first` and `rest`. */
function largest(first: number, rest: Iterable<number>): number {
  let max = first;
  for (const n of rest) if (n > max) max = n;
  return max;
}

/** Leaves appended to a compact range at a time: bounds the inclusion paths `extendCompactRange` returns alongside. */
const REBUILD_CHUNK = 4096;

/**
 * @internal MTH of `leaves[0, n)` for each `n` in `sizes`, built
 * incrementally; `null` for a size the leaves do not reach densely, and for
 * any size from the first the engine refuses to build (a digest that is not
 * 64 hex, or one repeated within a chunk). A root built over a leaf rewritten
 * to repeat another is still a root, and it is not the anchored one.
 */
export function rootsAt(leaves: LogLeaf[], sizes: number[]): Map<number, string | null> {
  const digests: string[] = [];
  for (const l of leaves) {
    if (l.leafIndex !== digests.length) break;
    digests.push(l.leafDigest);
  }
  const out = new Map<number, string | null>();
  let range: CompactRange = { size: 0, hashes: [] };
  let broken = false;
  for (const n of [...new Set(sizes)].sort((a, b) => a - b)) {
    if (broken || n > digests.length) {
      out.set(n, null);
      continue;
    }
    try {
      let root = '';
      while (range.size < n) {
        const ext = extendCompactRange(range, digests.slice(range.size, Math.min(n, range.size + REBUILD_CHUNK)));
        range = ext.range;
        root = ext.root;
      }
      out.set(n, root);
    } catch {
      broken = true;
      out.set(n, null);
    }
  }
  return out;
}

/** The inputs of one pass's log checks. */
export interface AnchoredLogScanInput {
  store: StoreLogs;
  /** The chains this pass walks. */
  chainIds: string[];
  /**
   * A chain's head (`last_sequence`) now. Asked about an evidence log after
   * its checkpoints are read: in an honest store the head only grows, so a
   * head read later covers every size anchored before it.
   */
  chainHead(chainId: string): Promise<number>;
  /** The records this pass read, by chain: their filled anchors authenticate bodies and name rewritten records. */
  records: Map<string, EvidenceEnvelope[]>;
  deps: ScannerAnchoringDeps | undefined;
  /**
   * What the pass reads once: the scanner's own, or its pass's shared ones
   * (`sharedPassReads`). Its transactions read in finalized blocks and its
   * recovered signers are kept from earlier passes:
   * a transaction's sender, nonce and calldata are fixed by its id, a
   * finalized block stays, and what signed bytes say is fixed by their hash.
   * Filled by this call.
   */
  reads: PassReads;
}

/** A root the anchor log had at one size, and whether a published P vouches for it. */
interface AnchorRef {
  size: number;
  root: string;
  authenticated: boolean;
}

/**
 * @internal What the store and the chain say the anchor log published,
 * before any record is read: the publications with each one's P re-derived
 * from the chain (b), the anchor log's stored checkpoints, and its leaves.
 * Read once for all the chain scans of a pass; the domain scan and `'all'`
 * read their own.
 */
export interface AnchorBasis {
  publications: AnchorPublication[];
  /** The roots the anchor log's stored checkpoints and the publications' P state, in the order they were read. */
  refs: AnchorRef[];
  /** What the publications' check found. */
  events: MonitoringEvent[];
  /** Publications whose transaction the node did not confirm on this pass, by chain. */
  unconfirmed: Map<string, number[]>;
  /** Chains a publication names that the scanner has no reader for. */
  missingReaders: Set<string>;
  /** The anchor log's size and leaves, read after its checkpoints and the publications. */
  anchorSize: number;
  anchorLeaves: LogLeaf[];
}

/** What a signed transaction's bytes say: the sender recovered from its signature, its nonce and its calldata. */
export interface SignedTransaction {
  from: string;
  nonce: number;
  data: string;
}

/**
 * Who vouches for a publisher: `manifest` when the scanner's manifest lists
 * it, `store` when the manifest lists no publisher for the store and the
 * store's own wallet row names it. Only `manifest` authenticates.
 */
type PublisherTrust = 'manifest' | 'store';

/** One publisher wallet check g accounts for. */
interface WalletAccount {
  address: string;
  chain: string;
  /** The first nonce accounted. */
  nonceBase: number;
  /** The manifest listed the wallet for this store's anchor origin until a time that has passed. */
  listingEnded: boolean;
}

/** `nonceBases`, keyed `<chain>:<lowercase address>`; an entry that is not a CAIP-10 account and a non-negative integer is dropped. */
function nonceFloors(nonceBases: Record<string, number> | undefined): Map<string, number> {
  const out = new Map<string, number>();
  for (const [account, base] of Object.entries(nonceBases ?? {})) {
    const at = account.lastIndexOf(':');
    if (at <= 0 || !Number.isSafeInteger(base) || base < 0) continue;
    out.set(`${account.slice(0, at)}:${account.slice(at + 1).toLowerCase()}`, base);
  }
  return out;
}

const plural = (n: number, noun: string): string => (n === 1 ? noun : `${noun}s`);
/** Up to five numbers, then how many more. */
const preview = (ns: number[]): string => (ns.length <= 5 ? ns.join(', ') : `${ns.slice(0, 5).join(', ')} and ${ns.length - 5} more`);

/** What one pass's log checks found. */
export interface AnchoredLogScanResult {
  events: MonitoringEvent[];
  /** Why part of the checks did not run on this pass, for the operator. */
  notChecked: string[];
}

/** The mined EVM publications' material, by transaction id, for `verifyAnchor` (tzun-anchor/1 §8.2). */
export function publicationMaterial(publications: AnchorPublication[]): Map<string, EvmPublicationMaterial> {
  const out = new Map<string, EvmPublicationMaterial>();
  for (const p of publications) {
    if (p.kind !== 'evm-calldata/1' || !p.minedTxHash || p.blockNumber === null || !p.blockHash) continue;
    const attempt = p.attempts.find((a) => a.txHash === p.minedTxHash);
    if (!attempt) continue;
    out.set(p.minedTxHash, {
      kind: 'evm-calldata/1',
      rawTransaction: attempt.rawTx,
      blockNumber: p.blockNumber,
      blockHash: p.blockHash,
      ...(p.blockHeader !== null && { blockHeader: p.blockHeader }),
      ...(p.txIndex !== null && p.txTrieProof !== null && { txIndex: p.txIndex, txProof: p.txTrieProof }),
    });
  }
  return out;
}

/**
 * The chains the scanner was given, read through the pass's reads. A
 * transaction in a block at or below the chain's finalized height is kept
 * for later passes; any other is read again next pass. A read that fails is
 * not kept, so the next question asks again. Both a failure and an empty
 * answer come back as null, and null decides nothing.
 */
class ChainReads {
  constructor(
    private readonly chains: Record<string, ScannerEvmChain>,
    private readonly reads: PassReads,
  ) {}

  /** Whether the scanner was given any chain. */
  get any(): boolean {
    return Object.keys(this.chains).length > 0;
  }

  readerFor(chain: string | null | undefined): ScannerEvmChain | undefined {
    return typeof chain === 'string' ? this.chains[chain] : undefined;
  }

  finalizedHeight(reader: ScannerEvmChain): Promise<number> {
    let read = this.reads.finalizedHeights.get(reader);
    if (!read) {
      read = reader.finalizedBlockNumber().catch(() => -1);
      this.reads.finalizedHeights.set(reader, read);
    }
    return read;
  }

  transaction(reader: ScannerEvmChain, id: string): Promise<ScannerEvmTransaction | null> {
    const key = id.toLowerCase();
    const known = this.reads.minedTransactions.get(key);
    if (known) return Promise.resolve(known);
    const read = readOnce(this.reads.transactions, key, () =>
      reader.transaction(key).then(async (tx) => {
        if (!tx) return null;
        const view: ScannerEvmTransaction = {
          from: String(tx.from).toLowerCase(),
          nonce: Number(tx.nonce),
          data: String(tx.data).toLowerCase(),
          blockHash: tx.blockHash ? String(tx.blockHash).toLowerCase() : null,
          blockNumber: typeof tx.blockNumber === 'number' ? tx.blockNumber : null,
        };
        if (view.blockHash !== null && view.blockNumber !== null && view.blockNumber <= (await this.finalizedHeight(reader))) {
          this.reads.minedTransactions.set(key, view);
        }
        return view;
      }),
    );
    return read.catch(() => null);
  }
}

/** Who publishes for the store: the manifest's publishers for its anchor origin, or else its own wallet rows. */
class Publishers {
  readonly entries: Array<{ address: string; chain: string; validUntil: string | null }>;
  /** With publishers listed, the manifest alone says who publishes. Without them the store's wallet rows do, and the database owner can write those. */
  readonly byManifest: boolean;

  constructor(
    private readonly store: StoreLogs,
    private readonly anchors: AnchorStore,
    deps: ScannerAnchoringDeps | undefined,
    private readonly reads: PassReads,
  ) {
    const listed: unknown = deps?.publisherManifest?.publishers?.[store.anchorOrigin];
    this.entries = (Array.isArray(listed) ? listed : [])
      .filter(
        (e): e is { address: string; chain: string; validUntil?: unknown } =>
          typeof e?.address === 'string' && typeof e?.chain === 'string' && e.chain.startsWith('eip155:'),
      )
      .map((e) => ({ address: e.address.toLowerCase(), chain: e.chain, validUntil: typeof e.validUntil === 'string' ? e.validUntil : null }));
    this.byManifest = this.entries.length > 0;
  }

  /** The store's row for a wallet, when it enrolled it for this domain. */
  walletOf(address: string, chain: string): Promise<AnchorWallet | null> {
    const domain = this.store.domainPrefix;
    return readOnce(this.reads.wallets, `${domain}|${address}@${chain}`, () =>
      this.anchors.getAnchorWallet(address, chain).then((w) => (w && w.domain === domain ? w : null)),
    );
  }

  async trust(address: string, chain: string): Promise<PublisherTrust | null> {
    if (this.byManifest) return this.entries.some((e) => e.address === address && e.chain === chain) ? 'manifest' : null;
    return (await this.walletOf(address, chain)) !== null ? 'store' : null;
  }

  /** P and who vouches for it, when `tx` is a mined transaction of a publisher of this store carrying 32 bytes of calldata. */
  async publishedP(tx: ScannerEvmTransaction | null, chain: string): Promise<{ p: string; trust: PublisherTrust } | null> {
    if (!tx || tx.blockHash === null || !HEX_P.test(tx.data)) return null;
    const trust = await this.trust(tx.from, chain);
    return trust ? { p: tx.data.slice(2), trust } : null;
  }
}

/**
 * The anchor log's published sizes, before any record is read (b): the roots
 * its stored checkpoints state, and each publication's P re-derived from the
 * chain, with its sender and nonce checked, then the anchor log's leaves.
 */
async function readAnchorBasis(store: StoreLogs, anchors: AnchorStore, chains: ChainReads, publishers: Publishers): Promise<AnchorBasis> {
  const events: MonitoringEvent[] = [];
  const refs: AnchorRef[] = [];
  const unconfirmed = new Map<string, number[]>();
  const missingReaders = new Set<string>();
  const anchorLog = store.anchorLog;
  // Read whether or not the anchor log's row is still there: a publication
  // with no anchor log to reproduce it is a finding, not a store to skip.
  const publications = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
  const anchorCheckpoints = anchorLog ? await store.checkpoints(anchorLog.logId) : [];
  const anchorCpAt = new Map(anchorCheckpoints.map((c) => [c.treeSize, c]));

  const rewritten = (e: Omit<Extract<MonitoringEvent, { type: 'log_rewritten_below_anchor' }>, 'type'>): void => {
    events.push({ type: 'log_rewritten_below_anchor', ...e });
  };

  for (const cp of anchorCheckpoints) {
    const body = readBody(cp.body);
    if (body) refs.push({ size: cp.treeSize, root: body.root, authenticated: false });
  }
  for (const p of publications) {
    if (!p.minedTxHash || (p.state !== 'included' && p.state !== 'finalized')) continue;
    const cp = anchorCpAt.get(p.anchorSize);
    const base = {
      origin: store.anchorOrigin,
      chainId: null,
      anchoredSize: p.anchorSize,
      evidenceIds: [],
      publicationId: p.id,
      transactionId: p.minedTxHash,
    };
    const reader = chains.readerFor(p.chain);
    const tx = reader ? await chains.transaction(reader, p.minedTxHash) : null;
    if (!reader || !tx || tx.blockHash === null) {
      // No chain, or the node said nothing: P is not re-derived. The store
      // still contradicts itself when it holds no checkpoint at a size it
      // says it published.
      if (!reader) missingReaders.add(p.chain ?? '(none)');
      else unconfirmed.set(p.chain as string, [...(unconfirmed.get(p.chain as string) ?? []), p.id]);
      if (!cp) rewritten({ ...base, reason: 'checkpoint_missing', authenticated: false });
      continue;
    }
    const trust = await publishers.trust(tx.from, p.chain as string);
    if (!trust) {
      rewritten({ ...base, reason: 'publication_not_from_publisher', authenticated: publishers.byManifest });
      continue;
    }
    const authenticated = trust === 'manifest';
    if (!HEX_P.test(tx.data)) {
      rewritten({ ...base, reason: 'publication_calldata_not_p', authenticated });
      continue;
    }
    if (tx.nonce !== p.nonce) rewritten({ ...base, reason: 'publication_nonce_mismatch', authenticated });
    const pOnChain = tx.data.slice(2);
    const body = cp ? readBody(cp.body) : null;
    if (!cp) {
      rewritten({ ...base, reason: 'checkpoint_missing', authenticated });
    } else if (!body || body.digest !== pOnChain || body.origin !== store.anchorOrigin || body.size !== p.anchorSize) {
      rewritten({ ...base, reason: 'checkpoint_rewritten', authenticated });
    } else {
      refs.push({ size: p.anchorSize, root: body.root, authenticated });
    }
  }

  let anchorSize = 0;
  let anchorLeaves: LogLeaf[] = [];
  if (anchorLog) {
    anchorSize = (await store.logs.getLogSize(anchorLog.logId)).size;
    anchorLeaves = await store.logs.listLogLeaves(anchorLog.logId, 0, largest(anchorSize, refs.map((r) => r.size)));
  }
  return { publications, refs, events, unconfirmed, missingReaders, anchorSize, anchorLeaves };
}

/**
 * The checks of `input.deps.scope` (`ScannerAnchoringDeps.scope`, default
 * all of them) over the store's logs, its anchoring tables and the chains it
 * publishes on: b, c, d, e and g, and split_view. Never throws for what it
 * finds; a store read that fails throws, as every scanner read does.
 */
export async function checkAnchoredLogs(input: AnchoredLogScanInput): Promise<AnchoredLogScanResult> {
  const { store, deps, reads } = input;
  const scope: ScannerLogScope = deps?.scope ?? 'all';
  const events: MonitoringEvent[] = [];
  const notChecked: string[] = [];
  const anchors = store.anchors;
  if (!anchors) return { events, notChecked };
  // Whether this scan reports on the domain: the anchor log, the source logs
  // that belong to no chain, the publisher wallets.
  const domainFindings = scope !== 'sourceLogs';

  const chains = new ChainReads(deps?.evmChains ?? {}, reads);
  const publishers = new Publishers(store, anchors, deps, reads);
  if (domainFindings && !publishers.byManifest && chains.any) {
    notChecked.push(
      `the publisher manifest lists no EVM publisher for ${store.anchorOrigin}: the store's own wallet rows say who ` +
        'publishes there, so nothing is authenticated against the chain and split views are not looked for',
    );
  }

  // ── The anchor log's published sizes: P from the chain (b) ───────────
  // The domain scan also takes the anchor checkpoints the pass's chain scans
  // found in their records. It takes them before it reads the anchor log, so
  // the log it reads is past every one of them.
  const fromChainScans = scope === 'domain' ? anchorRefsIn(reads.recordAnchorRefs, store.anchorOrigin) : [];
  const readBasis = (): Promise<AnchorBasis> => readAnchorBasis(store, anchors, chains, publishers);
  const basis = scope === 'sourceLogs' ? await readOnce(reads.anchorBases, store.anchorOrigin, readBasis) : await readBasis();
  if (scope === 'domain' && !reads.anchorBases.has(store.anchorOrigin)) reads.anchorBases.set(store.anchorOrigin, Promise.resolve(basis));
  if (domainFindings) events.push(...basis.events);

  const refs = new Refs();
  for (const r of [...basis.refs, ...fromChainScans]) refs.add(store.anchorOrigin, r.size, r.root, r.authenticated);

  const rewritten = (e: Omit<Extract<MonitoringEvent, { type: 'log_rewritten_below_anchor' }>, 'type'>): void => {
    events.push({ type: 'log_rewritten_below_anchor', ...e });
  };

  // ── Anchors filled into records: more bodies, authenticated by P ──────
  const embedded: Array<{ record: EvidenceEnvelope; anchor: FilledAnchor; logBody: Checkpoint }> = [];
  for (const records of input.records.values()) {
    for (const record of records) {
      const anchor = filledAnchor(record);
      if (!anchor) continue;
      const logBody = readBody(anchor.logCheckpoint);
      const anchorBody = readBody(anchor.anchorCheckpoint);
      if (!logBody || !anchorBody || anchorBody.origin !== store.anchorOrigin) continue;
      let trust: PublisherTrust | null = null;
      for (const pub of anchor.publications) {
        const reader = chains.readerFor(pub.chain);
        if (!reader) continue;
        const published = await publishers.publishedP(await chains.transaction(reader, pub.transactionId), pub.chain);
        if (published?.p !== anchorBody.digest) continue;
        trust = published.trust;
        if (trust === 'manifest') break;
      }
      if (trust) {
        const vouched = trust === 'manifest';
        refs.add(store.anchorOrigin, anchorBody.size, anchorBody.root, vouched);
        // Left for the pass's domain scan, which reads no record.
        reads.recordAnchorRefs.add(store.anchorOrigin, anchorBody.size, anchorBody.root, vouched);
        if (verifyMerkleProof(logBody.digest, anchor.anchorLeafIndex, anchorBody.size, anchor.anchorPath, anchorBody.root)) {
          refs.add(logBody.origin, logBody.size, logBody.root, vouched);
        }
      }
      embedded.push({ record, anchor, logBody });
    }
  }

  // ── The anchor log's leaves (b, c) and which of them are authenticated ─
  // A chain scan judges it only to learn which leaves are authenticated.
  const anchorLog = store.anchorLog;
  let authenticatedAnchorLeaves: LogLeaf[] = [];
  if (anchorLog) {
    const judged = judgeLog(store.anchorOrigin, null, refs.of(store.anchorOrigin), basis.anchorLeaves, basis.anchorSize, null, domainFindings ? events : []);
    authenticatedAnchorLeaves = basis.anchorLeaves.slice(0, judged.authenticatedThrough);
  }

  // ── Source logs: their stored checkpoints under the authenticated anchor log ─
  // The evidence logs of the chains this scan walked, unless it is the domain
  // scan; the logs of no chain, unless it is a chain scan.
  const inScope = new Set(input.chainIds);
  const sourceLogs = store.logList.filter((l) => {
    if (l.kind === ANCHOR_LOG_KIND) return false;
    if (l.kind === EVIDENCE_LOG_KIND) return scope !== 'domain' && l.chainId !== null && inScope.has(l.chainId);
    return domainFindings;
  });
  for (const log of sourceLogs) {
    for (const cp of await store.checkpoints(log.logId)) {
      const body = readBody(cp.body);
      if (!body) continue;
      const i = cp.anchorLeafIndex;
      if (i !== null && i < authenticatedAnchorLeaves.length) {
        if (authenticatedAnchorLeaves[i].leafDigest === body.digest) {
          refs.add(log.origin, cp.treeSize, body.root, true);
        } else {
          rewritten({
            origin: log.origin,
            chainId: log.chainId,
            anchoredSize: cp.treeSize,
            reason: 'checkpoint_rewritten',
            authenticated: true,
            evidenceIds: [],
          });
        }
      } else {
        refs.add(log.origin, cp.treeSize, body.root, false);
      }
    }
  }

  // ── split_view (d): two authenticated roots at one size ───────────────
  // Of the logs this scan reports on.
  const reportsOn = (log: LogRecord): boolean =>
    scope === 'all' || (log.kind === ANCHOR_LOG_KIND ? domainFindings : sourceLogs.includes(log));
  for (const [origin, sizes] of refs.byOrigin) {
    const log = store.logList.find((l) => l.origin === origin);
    if (!log || !reportsOn(log)) continue;
    for (const [size, list] of sizes) {
      const roots = list.filter((r) => r.authenticated).map((r) => r.root);
      if (roots.length > 1) events.push({ type: 'split_view', origin, chainId: log.chainId, size, roots: [...roots].sort() });
    }
  }

  // ── Source logs: leaves against the roots (b, c), stored proofs (d) ──
  for (const log of sourceLogs) {
    const { size } = await store.logs.getLogSize(log.logId);
    const sizes = refs.of(log.origin);
    const top = largest(size, sizes.keys());
    const leaves = top > 0 ? await store.logs.listLogLeaves(log.logId, 0, top) : [];
    // Read now, after the log's checkpoints: an epoch the scheduler cut while
    // this pass ran is below the head it moved.
    const lastSequence = log.kind === EVIDENCE_LOG_KIND && log.chainId !== null ? await input.chainHead(log.chainId) : null;
    const judged = judgeLog(log.origin, log.chainId, sizes, leaves, size, lastSequence, events);
    if (judged.rewrite) {
      // Name the records whose own leaf no longer sits under their anchored root.
      const leafAt = new Map(leaves.map((l) => [l.leafIndex, l.leafDigest]));
      const named: string[] = [];
      for (const e of embedded) {
        if (e.logBody.origin !== log.origin) continue;
        const genuine = sizes.get(e.logBody.size)?.some((r) => r.root === e.logBody.root) ?? false;
        if (!genuine) continue;
        const leaf = leafAt.get(e.anchor.leafIndex);
        if (leaf === undefined || !verifyMerkleProof(leaf, e.anchor.leafIndex, e.logBody.size, e.anchor.logPath, e.logBody.root)) {
          named.push(e.record.payload.evidenceId);
        }
      }
      judged.rewrite.evidenceIds = [...new Set(named)].sort();
    }
  }
  for (const log of [...(domainFindings && anchorLog ? [anchorLog] : []), ...sourceLogs]) {
    checkStoredProofs(log, await store.checkpoints(log.logId), log === anchorLog ? basis.publications : null, events);
  }

  // ── e: anchor_overdue, when the deployment anchors ────────────────────
  const now = (deps?.now ?? Date.now)();
  if (deps) {
    const maxStalenessMs = deps.maxStalenessMs ?? DEFAULT_ANCHOR_CADENCE.maxStalenessMs;
    for (const log of sourceLogs) {
      if (log.kind !== EVIDENCE_LOG_KIND || log.chainId === null) continue;
      const overdue = await overdueLeaf(store, log, maxStalenessMs, now);
      if (overdue) events.push({ ...overdue, maxStalenessMs });
    }
  }

  if (!domainFindings) return { events, notChecked };

  // ── g: nonce accounting for each publisher wallet ─────────────────────
  // A wallet the manifest lists is accounted from the scanner's own floor,
  // whatever the store's row for it says, and whether or not the row is still
  // there. Any other wallet a publication names is accounted from its stored
  // enrolment, when the store enrolled it for this domain.
  const missingReader = new Set(basis.missingReaders);
  const floors = nonceFloors(deps?.nonceBases);
  const accounts = new Map<string, WalletAccount>();
  for (const e of publishers.entries) {
    const until = e.validUntil === null ? Number.NaN : Date.parse(e.validUntil);
    accounts.set(`${e.address}@${e.chain}`, {
      address: e.address,
      chain: e.chain,
      nonceBase: floors.get(`${e.chain}:${e.address}`) ?? 0,
      listingEnded: Number.isFinite(until) && until <= now,
    });
  }
  for (const p of basis.publications) {
    if (!p.fromAddress || !p.chain || accounts.has(`${p.fromAddress}@${p.chain}`)) continue;
    const wallet = await publishers.walletOf(p.fromAddress, p.chain);
    if (wallet) {
      accounts.set(`${wallet.address}@${wallet.chain}`, { address: wallet.address, chain: wallet.chain, nonceBase: wallet.nonceBase, listingEnded: false });
    }
  }
  for (const account of accounts.values()) {
    const reader = chains.readerFor(account.chain);
    if (!reader) {
      missingReader.add(account.chain);
      continue;
    }
    events.push(
      ...(await accountNonces({
        anchors,
        store,
        account,
        reader,
        readTransaction: (r, id) => chains.transaction(r, id),
        walletOf: (address, chain) => publishers.walletOf(address, chain),
        signed: reads.signedTransactions,
        notChecked,
      })),
    );
  }

  for (const [chain, ids] of basis.unconfirmed) {
    notChecked.push(
      `on ${chain}, the node did not confirm the transaction of ${plural(ids.length, 'publication')} ${preview(ids)}: ` +
        'P was not re-derived from it on this pass',
    );
  }
  for (const chain of missingReader) {
    notChecked.push(`no chain was given for ${chain}: P is not re-derived from calldata there, and its wallets' nonces are not accounted`);
  }
  return { events, notChecked };
}

/** A record's filled `tzun-anchor/1` artifact, read defensively, or null. */
interface FilledAnchor {
  leafIndex: number;
  logCheckpoint: string;
  logPath: string[];
  anchorLeafIndex: number;
  anchorCheckpoint: string;
  anchorPath: string[];
  publications: Array<{ chain: string; transactionId: string }>;
}

function filledAnchor(record: EvidenceEnvelope): FilledAnchor | null {
  const a = (record?.nonRepudiation as { anchor?: unknown } | null | undefined)?.anchor as Record<string, unknown> | null | undefined;
  if (!a || typeof a !== 'object' || a.anchorSpec !== ANCHOR_SPEC) return null;
  const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
  const isPath = (v: unknown): v is string[] => Array.isArray(v) && v.every((h) => typeof h === 'string');
  if (!isInt(a.leafIndex) || !isInt(a.anchorLeafIndex) || !isPath(a.logPath) || !isPath(a.anchorPath)) return null;
  if (typeof a.logCheckpoint !== 'string' || typeof a.anchorCheckpoint !== 'string' || !Array.isArray(a.publications)) return null;
  const publications: FilledAnchor['publications'] = [];
  for (const p of a.publications as unknown[]) {
    const e = p as Record<string, unknown> | null;
    const id = lower(e?.transactionId);
    if (e?.kind === 'evm-calldata/1' && typeof e.chain === 'string' && id !== null && /^0x[0-9a-f]{64}$/.test(id)) {
      publications.push({ chain: e.chain, transactionId: id });
    }
  }
  return {
    leafIndex: a.leafIndex,
    logCheckpoint: a.logCheckpoint,
    logPath: a.logPath,
    anchorLeafIndex: a.anchorLeafIndex,
    anchorCheckpoint: a.anchorCheckpoint,
    anchorPath: a.anchorPath,
    publications,
  };
}

/**
 * Checks b and c for one log: its leaves against every root it had at an
 * anchored size, its size and chain head against the largest. Pushes at most
 * one truncation and one rewrite finding, and returns the rewrite finding so
 * its records can be named, and how many leaves an authenticated root vouches
 * for.
 */
function judgeLog(
  origin: string,
  chainId: string | null,
  sizes: Map<number, RootRef[]>,
  leaves: LogLeaf[],
  logSize: number,
  lastSequence: number | null,
  events: MonitoringEvent[],
): { rewrite: Extract<MonitoringEvent, { type: 'log_rewritten_below_anchor' }> | null; authenticatedThrough: number } {
  const anchoredSizes = [...sizes.keys()].sort((a, b) => a - b);
  if (anchoredSizes.length === 0) return { rewrite: null, authenticatedThrough: 0 };
  const anchoredSize = anchoredSizes[anchoredSizes.length - 1];
  const reached = lastSequence === null ? logSize : Math.min(logSize, lastSequence);
  if (reached < anchoredSize) {
    events.push({ type: 'log_truncated_below_anchor', origin, chainId, anchoredSize, logSize, lastSequence });
  }

  // Sizes the log still reaches; a size past its end is the truncation above.
  const judged = anchoredSizes.filter((n) => n <= logSize);
  const rebuilt = rootsAt(leaves, judged);
  let authenticatedThrough = 0;
  let lastGood = 0;
  let failure: { size: number; authenticated: boolean; from: number } | null = null;
  for (const n of judged) {
    const root = rebuilt.get(n) ?? null;
    const list = sizes.get(n) ?? [];
    const authenticatedRoots = list.filter((r) => r.authenticated);
    // The store's own root counts only where no published one exists.
    const expected = authenticatedRoots.length > 0 ? authenticatedRoots : list;
    const holds = root !== null && expected.every((r) => r.root === root);
    if (holds) {
      lastGood = n;
      if (authenticatedRoots.length > 0) authenticatedThrough = n;
      continue;
    }
    const authenticated = authenticatedRoots.length > 0;
    if (!failure || (authenticated && !failure.authenticated)) failure = { size: n, authenticated, from: lastGood };
  }
  if (!failure) return { rewrite: null, authenticatedThrough };
  const rewrite: Extract<MonitoringEvent, { type: 'log_rewritten_below_anchor' }> = {
    type: 'log_rewritten_below_anchor',
    origin,
    chainId,
    anchoredSize: failure.size,
    reason: 'leaves_do_not_rebuild_root',
    authenticated: failure.authenticated,
    leafRange: { from: failure.from, to: failure.size },
    evidenceIds: [],
  };
  events.push(rewrite);
  return { rewrite, authenticatedThrough };
}

/**
 * Check d from the store alone: every stored checkpoint states its own row,
 * every stored consistency proof verifies between the two bodies it joins,
 * and every anchored checkpoint after the first is proved from the one before
 * it. For the anchor log, the anchored checkpoints are those of the
 * publications that were not superseded.
 */
function checkStoredProofs(
  log: LogRecord,
  checkpoints: LogCheckpoint[],
  publications: AnchorPublication[] | null,
  events: MonitoringEvent[],
): void {
  const inconsistent = (fromSize: number | null, toSize: number, reason: LogInconsistencyReason): void => {
    events.push({ type: 'log_inconsistent_with_anchor', origin: log.origin, chainId: log.chainId, fromSize, toSize, reason });
  };
  const bySize = new Map(checkpoints.map((c) => [c.treeSize, c]));
  const rootOf = new Map<number, string>();
  for (const cp of checkpoints) {
    const body = readBody(cp.body);
    if (!body || body.origin !== log.origin || body.size !== cp.treeSize || body.root !== cp.root) {
      inconsistent(null, cp.treeSize, 'checkpoint_body_mismatch');
    } else {
      rootOf.set(cp.treeSize, body.root);
    }
  }
  for (const cp of checkpoints) {
    const m = cp.prevAnchoredSize;
    if (m === null) continue;
    if (!bySize.has(m)) {
      inconsistent(m, cp.treeSize, 'predecessor_missing');
      continue;
    }
    const first = rootOf.get(m);
    const second = rootOf.get(cp.treeSize);
    if (first === undefined || second === undefined) continue; // the body finding above
    if (!verifyConsistencyProof(m, cp.treeSize, cp.consistencyProof ?? [], first, second).valid) {
      inconsistent(m, cp.treeSize, 'consistency_proof_invalid');
    }
  }
  const anchoredSizes =
    publications === null
      ? checkpoints.filter((c) => c.anchorLeafIndex !== null).map((c) => c.treeSize)
      : [...new Set(publications.filter((p) => p.state !== 'superseded').map((p) => p.anchorSize))].filter((n) => bySize.has(n));
  anchoredSizes.sort((a, b) => a - b);
  for (let i = 1; i < anchoredSizes.length; i++) {
    const cp = bySize.get(anchoredSizes[i]) as LogCheckpoint;
    if (cp.prevAnchoredSize !== anchoredSizes[i - 1] && (cp.prevAnchoredSize === null || bySize.has(cp.prevAnchoredSize))) {
      inconsistent(anchoredSizes[i - 1], cp.treeSize, 'proof_chain_broken');
    }
  }
}

/**
 * Check e for one evidence log: the oldest leaf whose epoch's fill has not
 * finished, when it was logged more than `maxStalenessMs` before `now`. Fills
 * finish in epoch order, so the oldest such leaf is the first past the newest
 * anchored checkpoint whose fill is done.
 */
async function overdueLeaf(
  store: StoreLogs,
  log: LogRecord,
  maxStalenessMs: number,
  now: number,
): Promise<Omit<Extract<MonitoringEvent, { type: 'anchor_overdue' }>, 'maxStalenessMs'> | null> {
  const { size } = await store.logs.getLogSize(log.logId);
  const anchored = await store.anchoredCheckpoints(log.logId);
  let filledThrough = 0;
  for (let i = anchored.length - 1; i >= 0; i--) {
    if (await store.anchorFillDone(log, anchored[i].treeSize - 1)) {
      filledThrough = anchored[i].treeSize;
      break;
    }
  }
  if (filledThrough >= size) return null;
  const [leaf] = await store.logs.listLogLeaves(log.logId, filledThrough, filledThrough + 1);
  if (!leaf) return null;
  const loggedAt = Date.parse(leaf.loggedAt);
  if (!Number.isFinite(loggedAt) || now - loggedAt <= maxStalenessMs) return null;

  const progress = store.anchors ? await store.anchors.getLeafAnchorProgress(log.logId, leaf.leafIndex) : null;
  const pubs = progress?.publications ?? [];
  const primary = pubs.find((p) => p.kind === 'evm-calldata/1') ?? pubs.find((p) => p.kind === 'rfc3161/1');
  let reason: 'not_published' | 'finality_stalled' | 'not_filled' = 'not_published';
  if (primary?.state === 'included') reason = 'finality_stalled';
  else if (primary?.state === 'finalized' || primary?.state === 'obtained') reason = 'not_filled';
  return {
    type: 'anchor_overdue',
    origin: log.origin,
    chainId: log.chainId as string,
    reason,
    leafIndex: leaf.leafIndex,
    evidenceId: leaf.sourceRef,
    loggedAt: new Date(loggedAt).toISOString(),
  };
}

/**
 * Whether `rawTx` is what the store says it is: bytes that hash to `txHash`,
 * signed by `address`, at `nonce`, carrying `data` (any calldata when `data`
 * is null). A database owner without the wallet's key can make no such bytes.
 * A signature is recovered once per hash: the bytes that hash to it are fixed.
 */
function signedAs(
  signed: Map<string, SignedTransaction>,
  rawTx: unknown,
  txHash: unknown,
  address: string,
  nonce: number,
  data: string | null,
): boolean {
  if (typeof rawTx !== 'string' || typeof txHash !== 'string') return false;
  try {
    const hash = txHash.toLowerCase();
    if (keccak256(rawTx) !== hash) return false;
    let view = signed.get(hash);
    if (!view) {
      const tx = Transaction.from(rawTx);
      if (!tx.from) return false;
      view = { from: tx.from.toLowerCase(), nonce: tx.nonce, data: tx.data.toLowerCase() };
      signed.set(hash, view);
    }
    return view.from === address && view.nonce === nonce && (data === null || view.data === data);
  } catch {
    return false;
  }
}

/**
 * Check g for one publisher wallet (tzun-anchor/1 §7.2 rule 2): every nonce
 * from `account.nonceBase` to its mined transaction count − 1 maps to a
 * stored publication whose anchor checkpoint hashes to the transaction's
 * calldata, or to a stored accounted transaction with the transaction's hash.
 * A wallet the store retired, whose manifest listing for this origin has
 * ended, is accounted up to the accounted transaction that retired it: what
 * it sends later is not this origin's. Any other wallet is accounted to its
 * count, retired or not.
 *
 * A nonce is unaccounted only on a definite answer. Its candidates are the
 * stored transactions for it that are what they claim to be (`signedAs`):
 * signed by the wallet at that nonce, with the calldata of the publication's
 * anchor checkpoint. With none, the nonce is unaccounted. Otherwise the chain
 * is asked about each, and one mined as stored accounts for the nonce. When
 * none is, and some read failed or answered nothing or an unmined
 * transaction, the nonce is undecided on this pass and reported as not
 * checked; when every answer was a mined transaction other than the one
 * stored, it is unaccounted.
 *
 * The count is read before the store's rows: a transaction is stored before
 * it is sent, so every nonce the count covers has its row by then.
 */
async function accountNonces(ctx: {
  anchors: AnchorStore;
  store: StoreLogs;
  account: WalletAccount;
  reader: ScannerEvmChain;
  readTransaction: (reader: ScannerEvmChain, id: string) => Promise<ScannerEvmTransaction | null>;
  walletOf: (address: string, chain: string) => Promise<AnchorWallet | null>;
  signed: Map<string, SignedTransaction>;
  notChecked: string[];
}): Promise<MonitoringEvent[]> {
  const { anchors, store, account, reader, readTransaction, walletOf, signed, notChecked } = ctx;
  const { address, chain } = account;
  let count: number;
  try {
    count = await reader.transactionCount(address, 'latest');
  } catch (err) {
    // The reader's text without its URL: a node's URL can carry an API key.
    notChecked.push(
      `the transaction count of the publisher wallet ${address} on ${chain} could not be read ` +
        `(${rpcErrorText(err)}): its nonces are not accounted on this pass`,
    );
    return [];
  }
  const publications = (await anchors.listAnchorPublications({ kind: 'evm-calldata/1' })).filter(
    (p) => p.fromAddress === address && p.chain === chain && p.nonce !== null,
  );
  const accountedTxs = await anchors.listAnchorWalletTxs(address, chain);
  // An epoch cut after this pass read the anchor log is read now, not missed.
  const anchorLog = store.anchorLog ?? (await store.logs.listLogs()).find((l) => l.kind === ANCHOR_LOG_KIND && l.chainId === null);
  const anchorCpAt = new Map((store.anchorLog ? await store.checkpoints(store.anchorLog.logId) : []).map((c) => [c.treeSize, c]));
  const anchorBodyAt = async (size: number): Promise<string | undefined> => {
    const cached = anchorCpAt.get(size);
    if (cached) return cached.body;
    return anchorLog ? (await anchors.getLogCheckpoint(anchorLog.logId, size))?.body : undefined;
  };

  let bound = count;
  if (account.listingEnded && accountedTxs.length > 0 && (await walletOf(address, chain))?.retiredAt) {
    bound = Math.min(count, Math.max(...accountedTxs.map((t) => t.nonce)) + 1);
  }
  const events: MonitoringEvent[] = [];
  const undecided: number[] = [];
  for (let nonce = account.nonceBase; nonce < bound; nonce++) {
    const holders = publications.filter((p) => p.nonce === nonce);
    const candidates: Array<{ txHash: string; data: string | null }> = [];
    for (const p of holders) {
      const body = readBody(await anchorBodyAt(p.anchorSize));
      if (!body) continue;
      const data = `0x${body.digest}`;
      for (const a of p.attempts) {
        if (signedAs(signed, a.rawTx, a.txHash, address, nonce, data)) candidates.push({ txHash: a.txHash, data });
      }
    }
    for (const t of accountedTxs) {
      if (t.nonce === nonce && signedAs(signed, t.rawTx, t.txHash, address, nonce, null)) candidates.push({ txHash: t.txHash, data: null });
    }

    let verdict: 'accounted' | 'unaccounted' | 'undecided' = 'unaccounted';
    for (const c of candidates) {
      const tx = await readTransaction(reader, c.txHash);
      if (!tx || tx.blockHash === null) {
        verdict = 'undecided';
        continue;
      }
      if (tx.from === address && tx.nonce === nonce && (c.data === null || tx.data === c.data)) {
        verdict = 'accounted';
        break;
      }
    }
    if (verdict === 'accounted') continue;
    if (verdict === 'undecided') {
      undecided.push(nonce);
      continue;
    }
    const holder = holders.find((p) => p.state !== 'superseded') ?? holders[0] ?? null;
    events.push({
      type: 'anchor_wallet_nonce_unaccounted',
      address,
      chain,
      nonce,
      nonceBase: account.nonceBase,
      epochId: holder?.epochId ?? null,
      publicationId: holder?.id ?? null,
    });
  }
  if (undecided.length > 0) {
    notChecked.push(
      `${plural(undecided.length, 'nonce')} ${preview(undecided)} of the publisher wallet ${address} on ${chain} ` +
        `${undecided.length === 1 ? 'is' : 'are'} not accounted on this pass: the node confirmed none of the transactions the store holds for ` +
        `${undecided.length === 1 ? 'it' : 'them'} (a read failed, or it answered nothing or an unmined transaction)`,
    );
  }
  return events;
}
