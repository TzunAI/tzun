/**
 * What the anchor scheduler trusts, and why (tzun-anchor/1 §11 items 4 and 5).
 *
 * The scheduler signs only a P it has re-derived from the anchor log, and
 * accepts an earlier publication as its own only from outside its store: by
 * the signed transaction, a sender its configuration or its manifest names,
 * inside that sender's validity window at a time the node confirms. Nothing
 * here trusts a column because it is stored:
 *
 *   - `allowedPublishers`: the senders the scheduler accepts, from its
 *     configured publisher and the manifest, never from the database.
 *   - `PublicationTrust.offline`: every check of a publication row that needs
 *     no node: each attempt's hash, signature, sender, chain, nonce and
 *     calldata, the row's sender and mined hash, and the sender's window at
 *     the times the row can show offline. Sender recovery, the costly step,
 *     is memoized by the raw transaction's bytes; every comparison with the
 *     row's columns runs on every read, so a row rewritten after it was read
 *     fails the next read.
 *   - `PublicationTrust.confirmed`: the node-confirmed checks of a row whose
 *     finality, or whose block, carries trust: `verifyEvmPublication` with
 *     the node as header source must say `valid === true` for a finalized
 *     row; an included row's receipt must place it where it says, at a block
 *     time inside its sender's window. `null` from the node defers.
 *   - `AnchorLogTrust`: the anchor log, explained. Its base is the
 *     checkpoint at a size the scheduler authenticated a publication for:
 *     the body hashes to that publication's P, parses as the anchor
 *     origin's checkpoint at that size, and its compact range folds to the
 *     body's root. Every anchor leaf below the base must be the digest of
 *     exactly one stored checkpoint, whose body names the origin and size
 *     the anchor log committed to; every anchor leaf above it must be the
 *     digest of exactly one source checkpoint, of a kind the scheduler
 *     anchors, that its log's leaves rebuild from the predecessor the anchor
 *     log last committed to for its origin (rules a to g of
 *     `AnchorLogTrust.explain`).
 *
 * Every failure is an `AnchorTrustError`: the scheduler raises its alarm and
 * stops, signing, filling and planning nothing more.
 */
import { createHash } from 'node:crypto';
import { Transaction, keccak256 } from 'ethers';
import {
  checkOriginBinding,
  formatCheckpoint,
  parseCheckpoint,
} from '../attestation/checkpoint';
import { compactRangeOf, compactRangeRoot, extendCompactRange, verifyConsistencyProof } from '../attestation/merkle';
import {
  parseEvmBlockHeader,
  publisherValidAt,
  readEvmPublisherWindows,
  verifyEvmPublication,
  type EvmHeaderSource,
  type EvmPublisherWindow,
  type PublisherManifest,
} from '../attestation/blockchain';
import {
  ANCHOR_LOG_KIND,
  EVIDENCE_LOG_KIND,
  type AnchorPublication,
  type AnchorPublicationAttempt,
  type AnchorStore,
  type LogCheckpoint,
  type LogLeaf,
  type LogRecord,
  type LogStore,
} from '../storage/log-store';
import { AnchoringConfigError, type AnchorAlarmCode } from './errors';
import type { EvmChainClient } from './evm-chain';

/** The kinds of source log the scheduler anchors unless told otherwise: those whose leaves the store binds to stored rows. */
export const DEFAULT_SOURCE_LOG_KINDS: readonly string[] = Object.freeze([EVIDENCE_LOG_KIND]);

/** A check the scheduler's trust rests on failed. `code` is the alarm it raises; every one stops anchoring. */
export class AnchorTrustError extends Error {
  constructor(
    readonly code: Extract<AnchorAlarmCode, 'anchor_log_leaf_unexplained' | 'anchor_publication_unexplained' | 'anchor_wallet_tx_unexplained' | 'anchor_history_mismatch'>,
    readonly subject: string,
    message: string,
  ) {
    super(message);
    this.name = 'AnchorTrustError';
  }
}

const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
const popcount = (n: number): number => {
  let count = 0;
  for (let v = n; v > 0; v = Math.floor(v / 2)) count += v % 2;
  return count;
};
const bytewise = (a: string, b: string): number => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

/** The root a compact range of `size` folds to, or null when it is malformed (or empty). */
function foldedRoot(size: number, hashes: unknown): string | null {
  if (!Array.isArray(hashes) || size < 1 || hashes.length !== popcount(size)) return null;
  try {
    return compactRangeRoot({ size, hashes: hashes as string[] });
  } catch {
    return null;
  }
}

/** The root of `digests` as one log, or null when it is empty or a digest is malformed or repeated. */
function rootOf(digests: string[]): string | null {
  if (digests.length === 0) return null;
  try {
    return compactRangeRoot(compactRangeOf(digests));
  } catch {
    return null;
  }
}

// ── The senders the scheduler accepts ──────────────────────────────────────

/** A sender the scheduler accepts, with its window in whole unix seconds (inclusive; null when unbounded). */
export type AllowedPublisher = EvmPublisherWindow;

/**
 * The publishers the scheduler accepts for `anchorOrigin` on `chain`: every
 * manifest entry for the origin on that chain, with its window, and the
 * configured publisher, within its own entries' windows when the manifest
 * lists it and unbounded otherwise. Never read from the database.
 *
 * @throws {AnchoringConfigError} when the manifest's entries for the origin are unreadable.
 */
export function allowedPublishers(input: {
  publisherAddress: string;
  chain: string;
  anchorOrigin: string;
  isTest: boolean;
  manifest: PublisherManifest | undefined;
}): AllowedPublisher[] {
  const entries = input.manifest === undefined ? [] : readEvmPublisherWindows(input.manifest, input.anchorOrigin);
  if (entries === undefined) {
    throw new AnchoringConfigError(
      `The publisher manifest's entries for ${input.anchorOrigin} cannot be read (an entry is malformed), so the publishers the scheduler accepts are unknown.`,
    );
  }
  const onChain = entries.filter((e) => e.chain === input.chain);
  const configured = input.publisherAddress.toLowerCase();
  const out = [...onChain];
  if (!onChain.some((e) => e.address === configured)) {
    out.push({ address: configured, chain: input.chain, namespace: input.isTest ? 'test' : 'production', firstSecond: null, lastSecond: null });
  }
  return out;
}

/** Whether `sender` is an allowed publisher at `unixSeconds`, or at any time when `unixSeconds` is null. */
export function senderAllowed(allowed: readonly AllowedPublisher[], sender: string, unixSeconds: number | null): boolean {
  return allowed.some((e) => e.address === sender && (unixSeconds === null || publisherValidAt(e, unixSeconds)));
}

/** A manifest that names exactly `allowed`, for `verifyEvmPublication`. */
export function manifestOf(anchorOrigin: string, allowed: readonly AllowedPublisher[]): PublisherManifest {
  const iso = (s: number | null): string | undefined => (s === null ? undefined : new Date(s * 1000).toISOString());
  return {
    publishers: {
      [anchorOrigin]: allowed.map((e) => ({
        address: e.address,
        chain: e.chain,
        namespace: e.namespace,
        ...(e.firstSecond !== null && { validFrom: iso(e.firstSecond) }),
        ...(e.lastSecond !== null && { validUntil: iso(e.lastSecond) }),
      })),
    },
  } as PublisherManifest;
}

/** The scheduler's chain client as a verifier's header source. */
export function headerSourceOf(chain: EvmChainClient): EvmHeaderSource {
  return {
    finality: 'finalized',
    chainId: () => chain.chainId(),
    finalizedBlockNumber: () => chain.finalizedBlockNumber(),
    canonicalBlock: (n) => chain.canonicalBlock(n),
    transaction: async (id) => {
      const t = await chain.transaction(id);
      return t ? { from: t.from, blockHash: t.blockHash, blockNumber: t.blockNumber } : null;
    },
  };
}

// ── Publication rows ────────────────────────────────────────────────────────

/** A signed transaction, decoded. */
interface Decoded {
  hash: string;
  from: string;
  chainId: bigint;
  nonce: number;
  data: string;
  value: bigint;
  /** The signed fee caps: what a replacement bumps, never the row's own columns. */
  maxFeePerGas: bigint | null;
  maxPriorityFeePerGas: bigint | null;
}

/** The outcome of a node-confirmed check. */
export type Confirmation = { status: 'valid'; blockTime: number } | { status: 'invalid'; why: string } | { status: 'unconfirmed'; why: string };

/** Columns a prepared publication has none of: it has never been sent. */
const UNSENT_COLUMNS = [
  'fromAddress',
  'nonce',
  'minedTxHash',
  'blockNumber',
  'blockHash',
  'blockHeader',
  'txIndex',
  'txTrieProof',
  'gasUsed',
  'effectiveGasPrice',
  'token',
  'genTime',
] as const;

/**
 * The publication checks of one scheduler, with their memos. One per
 * scheduler process: the memos hold only what was derived from bytes, keyed
 * by those bytes.
 */
export class PublicationTrust {
  private readonly decoded = new Map<string, Decoded | null>();
  private readonly confirmedMemo = new Map<string, Confirmation>();
  /** How many sender recoveries were made: the memo's cost, for the scheduler's tests. */
  recoveries = 0;

  constructor(
    private readonly ctx: {
      allowed: readonly AllowedPublisher[];
      chain: string;
      chainId: bigint;
      anchorOrigin: string;
      client: EvmChainClient;
      /** How far ahead of the scheduler's clock a row's times may be, in seconds. Default 300. */
      maxClockSkewSeconds?: number;
    },
  ) {}

  get allowed(): readonly AllowedPublisher[] {
    return this.ctx.allowed;
  }

  /** `rawTx` decoded, its sender recovered once per process; null when it is not a signed transaction. */
  decode(rawTx: string): Decoded | null {
    if (this.decoded.has(rawTx)) return this.decoded.get(rawTx)!;
    let out: Decoded | null = null;
    try {
      const tx = Transaction.from(rawTx);
      this.recoveries += 1;
      if (tx.isSigned() && tx.from) {
        out = {
          hash: keccak256(rawTx).toLowerCase(),
          from: tx.from.toLowerCase(),
          chainId: tx.chainId,
          nonce: tx.nonce,
          data: tx.data.toLowerCase(),
          value: tx.value,
          maxFeePerGas: tx.maxFeePerGas,
          maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
        };
      }
    } catch {
      out = null;
    }
    this.decoded.set(rawTx, out);
    return out;
  }

  /**
   * The offline checks of `row`: null when they hold, otherwise why
   * not. `nowSeconds` is the time an unmined attempt's window must contain,
   * and the latest a row's `created_at` or an attempt's `sentAt` may name,
   * give or take the clock skew: the cadence, the force window and the stuck
   * test read those times, so one in the future would stop epochs or
   * replacements without a word. The sender, once checked, is in `senderOf`.
   */
  offline(row: AnchorPublication, nowSeconds: number): string | null {
    if (row.kind !== 'evm-calldata/1') return `it is a ${row.kind} publication, which the scheduler does not write`;
    if (row.chain !== this.ctx.chain) return `it is on ${String(row.chain)}, not the configured chain ${this.ctx.chain}`;
    const latest = nowSeconds + (this.ctx.maxClockSkewSeconds ?? 300);
    if (!(Date.parse(row.createdAt) / 1000 <= latest)) return `its created_at ${String(row.createdAt)} is not a time at or before now`;
    if (row.state === 'prepared') {
      if (row.attempts.length > 0) return 'a prepared publication carries attempts';
      const set = UNSENT_COLUMNS.find((c) => row[c] !== null);
      return set ? `a prepared publication has ${set} set` : null;
    }
    if (row.attempts.length === 0) return `a ${row.state} publication has no attempt`;
    if (row.state === 'obtained') return 'an EVM publication cannot be obtained';
    let sender: string | null = null;
    for (const [i, a] of row.attempts.entries()) {
      const why = this.attemptProblem(row, a);
      if (why) return `attempt ${i}: ${why}`;
      if (!(Date.parse(a.sentAt) / 1000 <= latest)) return `attempt ${i}: its sentAt ${String(a.sentAt)} is not a time at or before now`;
      const from = this.decode(a.rawTx)!.from;
      if (sender !== null && from !== sender) return `attempt ${i} is signed by ${from}, another sender than attempt 0's`;
      sender = from;
    }
    if (row.fromAddress !== sender) return `its sender column says ${String(row.fromAddress)}; its transactions are signed by ${sender}`;
    if (!senderAllowed(this.ctx.allowed, sender as string, null)) {
      return `its transactions are signed by ${sender}, which neither the configured publisher nor the manifest names for ${this.ctx.anchorOrigin}`;
    }
    if (row.state === 'included' || row.state === 'finalized') {
      if (!row.attempts.some((a) => a.txHash === row.minedTxHash)) return `its mined transaction ${String(row.minedTxHash)} is none of its attempts`;
    }
    if (row.state === 'submitted' && !senderAllowed(this.ctx.allowed, sender as string, nowSeconds)) {
      return `its sender ${sender} is outside its validity window now`;
    }
    if (row.state === 'finalized') {
      // The stored header's time can make the row fail, never pass: the
      // node-confirmed check decides it.
      const header = row.blockHeader === null ? null : parseEvmBlockHeader(row.blockHeader);
      if (!header) return 'a finalized publication has no readable block header';
      if (!senderAllowed(this.ctx.allowed, sender as string, header.timestamp)) {
        return `its sender ${sender} was outside its validity window at its block's time`;
      }
    }
    return null;
  }

  /** The sender of a row that passed `offline`, or null for one never sent. */
  senderOf(row: AnchorPublication): string | null {
    return row.attempts.length === 0 ? null : (this.decode(row.attempts[0].rawTx)?.from ?? null);
  }

  /** Why attempt `a` of `row` is not a publication of `row.p` the row's nonce carries, or null. */
  private attemptProblem(row: AnchorPublication, a: AnchorPublicationAttempt): string | null {
    if (typeof a.rawTx !== 'string' || !/^0x([0-9a-f]{2})+$/.test(a.rawTx)) return 'its raw transaction is not 0x lowercase hex';
    const tx = this.decode(a.rawTx);
    if (!tx) return 'its raw transaction is not a signed transaction';
    if (tx.hash !== a.txHash) return 'its txHash is not keccak256 of its raw transaction';
    if (tx.chainId !== this.ctx.chainId) return `it is signed for chain ${tx.chainId}, not ${this.ctx.chainId}`;
    if (tx.nonce !== row.nonce) return `it is signed at nonce ${tx.nonce}, not the row's ${String(row.nonce)}`;
    if (tx.data !== `0x${row.p}`) return 'its calldata is not 0x ‖ P';
    if (tx.value !== 0n) return 'it carries value';
    return null;
  }

  /**
   * The node-confirmed check of a finalized or included row, memoized by
   * every column it reads while it holds; `fresh` asks the node again (the
   * history check does, every time). A finalized row needs
   * `verifyEvmPublication` with the node as header source to say `true`. An
   * included row needs the node's receipt to place its mined transaction in
   * the row's block, and its sender's window to contain that block's time.
   */
  async confirmed(row: AnchorPublication, options: { fresh?: boolean } = {}): Promise<Confirmation> {
    const key = createHash('sha256')
      .update(JSON.stringify([row.id, row.state, row.p, row.chain, row.fromAddress, row.nonce, row.attempts.map((a) => [a.txHash, a.rawTx]), row.minedTxHash, row.blockNumber, row.blockHash, row.blockHeader, row.txIndex, row.txTrieProof]))
      .digest('hex');
    const held = options.fresh ? undefined : this.confirmedMemo.get(key);
    if (held) return held;
    const result = row.state === 'finalized' ? await this.confirmFinalized(row) : await this.confirmIncluded(row);
    if (result.status === 'valid') this.confirmedMemo.set(key, result);
    else this.confirmedMemo.delete(key);
    return result;
  }

  private async confirmFinalized(row: AnchorPublication): Promise<Confirmation> {
    const mined = row.attempts.find((a) => a.txHash === row.minedTxHash);
    if (!mined) return { status: 'invalid', why: 'its mined transaction is none of its attempts' };
    const verdict = await verifyEvmPublication({
      publication: {
        kind: 'evm-calldata/1',
        transactionId: row.minedTxHash as string,
        rawTransaction: mined.rawTx,
        blockNumber: row.blockNumber as number,
        blockHash: row.blockHash as string,
        ...(row.blockHeader !== null && { blockHeader: row.blockHeader }),
        ...(row.txIndex !== null && row.txTrieProof !== null && { txIndex: row.txIndex, txProof: row.txTrieProof }),
      },
      p: row.p,
      anchorOrigin: this.ctx.anchorOrigin,
      manifest: manifestOf(this.ctx.anchorOrigin, this.ctx.allowed),
      headerSources: { [this.ctx.chain]: headerSourceOf(this.ctx.client) },
    });
    if (verdict.valid === true) return { status: 'valid', blockTime: Date.parse(verdict.facts.blockTime as string) / 1000 };
    const why = `${verdict.reason ?? 'not decided'}${verdict.checks.canonical.reason ? ` (${verdict.checks.canonical.reason})` : verdict.checks.tx.reason ? ` (${verdict.checks.tx.reason})` : ''}`;
    return verdict.valid === false ? { status: 'invalid', why } : { status: 'unconfirmed', why };
  }

  private async confirmIncluded(row: AnchorPublication): Promise<Confirmation> {
    const receipt = await this.ctx.client.receipt(row.minedTxHash as string);
    if (!receipt) return { status: 'unconfirmed', why: `the node has no receipt for ${String(row.minedTxHash)}` };
    if (receipt.blockNumber !== row.blockNumber || receipt.blockHash !== row.blockHash) {
      return { status: 'unconfirmed', why: `the node places ${String(row.minedTxHash)} in block ${receipt.blockNumber}, not the row's ${String(row.blockNumber)}` };
    }
    const block = await this.ctx.client.canonicalBlock(receipt.blockNumber);
    if (!block || block.hash !== receipt.blockHash) return { status: 'unconfirmed', why: `the node does not call block ${receipt.blockNumber} canonical` };
    const sender = this.senderOf(row) as string;
    if (!senderAllowed(this.ctx.allowed, sender, block.timestamp)) {
      return { status: 'invalid', why: `its sender ${sender} was outside its validity window at block ${receipt.blockNumber}'s time` };
    }
    return { status: 'valid', blockTime: block.timestamp };
  }
}

// ── The anchor log ──────────────────────────────────────────────────────────

/** An authenticated anchor-log state: its size, root and compact range, and the epoch id of its checkpoint. */
export interface AnchorBase {
  size: number;
  /** Null for the empty log, which has no root. */
  root: string | null;
  range: string[];
  /** The epoch id the checkpoint at `size` names (0 for the empty log). */
  epochId: number;
}

/** The anchor log above a base, explained. */
export interface ExplainedRange {
  base: AnchorBase;
  /** The anchor log's size: every leaf in [base.size, size) is explained. */
  size: number;
  /** The anchor log's state at `size`, rebuilt from the base's range and the explained leaves (root null when empty). */
  root: string | null;
  range: string[];
  /** The anchor leaves of [base.size, size), in index order. */
  leaves: LogLeaf[];
  /** The source checkpoint behind each anchor leaf of [base.size, size), by anchor leaf index. */
  checkpoints: Map<number, LogCheckpoint>;
  /** The logs of those checkpoints, by log id. */
  logs: Map<number, LogRecord>;
  /** The anchor log's own checkpoint at `size`, or null when `size` is the base's. */
  anchorCheckpoint: LogCheckpoint | null;
  /** The epoch id of the last explained epoch: the base's when nothing lies above it. */
  lastEpochId: number;
}

/**
 * The explained anchor log of one scheduler. It keeps the anchor leaves it
 * has checked against an authenticated root, and which origin and size each
 * one commits to, and trusts those values in memory whatever later happens
 * to their rows.
 */
export class AnchorLogTrust {
  /** Anchor leaves [0, verified.length), each checked against an authenticated root. */
  private verified: string[] = [];
  /** The compact range of `verified`, so the next check extends it rather than rebuilding it. */
  private verifiedRange: { size: number; hashes: string[] } = { size: 0, hashes: [] };
  /**
   * For each source origin, the anchor leaves of [0, indexed) whose
   * checkpoint is that origin's, in anchor-leaf order, read from checkpoint
   * bodies that hash to the verified leaves: which checkpoint of a log the
   * anchor log last committed to below a size never depends on what the
   * store's rows say it was.
   */
  private readonly anchoredBelow = new Map<string, Array<{ k: number; treeSize: number }>>();
  private indexed = 0;
  /** Explanations made, by base, size and the leaves and anchor checkpoint they explained. */
  private readonly explainedMemo = new Map<string, ExplainedRange>();
  private readonly ignoredLogs = new Set<number>();

  constructor(
    private readonly ctx: {
      logs: LogStore;
      anchors: AnchorStore;
      anchorLogId: number;
      anchorOrigin: string;
      sourceLogKinds: readonly string[];
      /** The origin a source log must carry (`expectedOrigin` of epoch.ts). */
      expectedOrigin: (log: LogRecord) => string;
      /** Logged once per log of a kind the scheduler does not anchor. */
      onIgnoredLog?: (log: LogRecord) => void;
    },
  ) {}

  /** Whether the scheduler anchors logs of `log`'s kind; a log of another kind is reported once. */
  anchors(log: LogRecord): boolean {
    if (log.kind === ANCHOR_LOG_KIND) return false;
    if (this.ctx.sourceLogKinds.includes(log.kind)) return true;
    if (!this.ignoredLogs.has(log.logId)) {
      this.ignoredLogs.add(log.logId);
      this.ctx.onIgnoredLog?.(log);
    }
    return false;
  }

  /**
   * The anchor log's state at `size`, authenticated by `p`, the P of a
   * publication the scheduler authenticated: the checkpoint's body hashes to
   * P, parses as the anchor origin's checkpoint at `size` with the row's
   * root, and its compact range folds to that root. Size 0 is the empty log.
   */
  async base(size: number, p: string | null, failAs: AnchorTrustError['code'] = 'anchor_publication_unexplained', subject = `size ${size}`): Promise<AnchorBase> {
    if (size === 0) return { size: 0, root: null, range: [], epochId: 0 };
    const fail = (why: string): never => {
      throw new AnchorTrustError(failAs, subject, `The anchor checkpoint at size ${size} is not the one its publication published: ${why}.`);
    };
    const cp = await this.ctx.anchors.getLogCheckpoint(this.ctx.anchorLogId, size);
    if (!cp) return fail('the anchor log has no checkpoint there');
    if (sha256Hex(cp.body) !== p || cp.bodyDigest !== p) return fail('its body does not hash to P');
    const parsed = parseCheckpoint(cp.body);
    if (!parsed.ok || parsed.checkpoint.origin !== this.ctx.anchorOrigin || parsed.checkpoint.size !== size || parsed.checkpoint.root !== cp.root) {
      return fail('its body is not the anchor origin\'s checkpoint at that size with its root');
    }
    if (foldedRoot(size, cp.compactRange) !== cp.root) return fail('its compact range does not fold to its root');
    return { size, root: cp.root, range: [...cp.compactRange], epochId: cp.epochId ?? 0 };
  }

  /**
   * The anchor leaves [0, base.size), checked against the base's root. Values
   * checked once stay trusted in memory; with `fresh`, the stored rows are
   * read and checked again (the history check's re-read).
   */
  async leavesBelow(base: AnchorBase, options: { fresh?: boolean } = {}): Promise<string[]> {
    if (base.size === 0) return [];
    if (options.fresh) {
      const stored = (await this.ctx.logs.listLogLeaves(this.ctx.anchorLogId, 0, base.size)).map((l) => l.leafDigest);
      if (stored.length !== base.size || rootOf(stored) !== base.root) {
        throw new AnchorTrustError('anchor_log_leaf_unexplained', `size ${base.size}`, `The anchor log's leaves below size ${base.size} no longer rebuild its published root.`);
      }
      return stored;
    }
    if (base.size === this.verified.length) {
      if (foldedRoot(this.verifiedRange.size, this.verifiedRange.hashes) !== base.root) {
        throw new AnchorTrustError('anchor_log_leaf_unexplained', `size ${base.size}`, `The anchor log below size ${base.size} is not consistent with the leaves verified before it.`);
      }
      return this.verified;
    }
    if (base.size < this.verified.length) {
      const prefix = this.verified.slice(0, base.size);
      if (rootOf(prefix) !== base.root) {
        throw new AnchorTrustError('anchor_log_leaf_unexplained', `size ${base.size}`, `The anchor log below size ${base.size} is not consistent with the leaves verified before it.`);
      }
      return prefix;
    }
    // Extend what is verified by the leaves after it, from its compact range:
    // the values below are already pinned by an authenticated root.
    const more = (await this.ctx.logs.listLogLeaves(this.ctx.anchorLogId, this.verified.length, base.size)).map((l) => l.leafDigest);
    let extended: { root: string; range: { size: number; hashes: string[] } } | null = null;
    try {
      extended = more.length === base.size - this.verified.length ? extendCompactRange(this.verifiedRange, more) : null;
    } catch {
      extended = null;
    }
    if (!extended || extended.root !== base.root) {
      throw new AnchorTrustError('anchor_log_leaf_unexplained', `size ${base.size}`, `The anchor log's leaves below size ${base.size} do not rebuild its published root.`);
    }
    this.verified = [...this.verified, ...more];
    this.verifiedRange = extended.range;
    return this.verified;
  }

  /**
   * Index the source checkpoints of the verified anchor leaves not indexed
   * yet: each leaf `k` must have exactly one checkpoint row claiming it, whose
   * body hashes to the leaf and parses. The body names the checkpoint's
   * origin and size, so the index holds only what the anchor log committed
   * to.
   *
   * @throws {AnchorTrustError} `anchor_log_leaf_unexplained` when a leaf has no such checkpoint.
   */
  private async indexBelow(): Promise<void> {
    const to = this.verified.length;
    if (this.indexed >= to) return;
    const byLeaf = new Map<number, LogCheckpoint[]>();
    for (const cp of await this.ctx.anchors.listCheckpointsByAnchorLeaf(this.indexed, to)) {
      const k = cp.anchorLeafIndex as number;
      byLeaf.set(k, [...(byLeaf.get(k) ?? []), cp]);
    }
    const added: Array<[string, { k: number; treeSize: number }]> = [];
    for (let k = this.indexed; k < to; k++) {
      const found = byLeaf.get(k) ?? [];
      const parsed = found.length === 1 && sha256Hex(found[0].body) === this.verified[k] ? parseCheckpoint(found[0].body) : null;
      if (!parsed?.ok) {
        throw new AnchorTrustError(
          'anchor_log_leaf_unexplained',
          `anchor leaf ${k} (rule a)`,
          `Anchor leaf ${k}, below the published size, is not the digest of exactly one stored source checkpoint (${found.length} claim it). Anchoring is stopped.`,
        );
      }
      added.push([parsed.checkpoint.origin, { k, treeSize: parsed.checkpoint.size }]);
    }
    for (const [origin, entry] of added) this.anchoredBelow.set(origin, [...(this.anchoredBelow.get(origin) ?? []), entry]);
    this.indexed = to;
  }

  /** The last anchor leaf below `limit` whose checkpoint is `origin`'s, from the index, or null. */
  private lastBelow(origin: string, limit: number): { k: number; treeSize: number } | null {
    const entries = this.anchoredBelow.get(origin) ?? [];
    for (let i = entries.length - 1; i >= 0; i--) if (entries[i].k < limit) return entries[i];
    return null;
  }

  /**
   * Whether `p`, a source checkpoint the anchor log commits to below `base`,
   * is the one it commits to: its body hashes to the verified anchor leaf at
   * its index, parses as its log's checkpoint at its size with its root, and
   * its compact range folds to that root. Its root and range are not
   * committed, so they are checked here.
   */
  private async authenticBelow(p: LogCheckpoint, log: LogRecord, below: string[]): Promise<string | null> {
    const k = p.anchorLeafIndex as number;
    if (!(k >= 0 && k < below.length)) return `its anchor leaf ${k} is not below the base`;
    if (sha256Hex(p.body) !== p.bodyDigest || p.bodyDigest !== below[k]) return `its body does not hash to anchor leaf ${k}`;
    const parsed = parseCheckpoint(p.body);
    if (!parsed.ok || parsed.checkpoint.origin !== log.origin || parsed.checkpoint.size !== p.treeSize || parsed.checkpoint.root !== p.root) {
      return 'its body is not its log\'s checkpoint at its size with its root';
    }
    if (foldedRoot(p.treeSize, p.compactRange) !== p.root) return 'its compact range does not fold to its root';
    return null;
  }

  /**
   * Explain every anchor leaf of [base.size, size) (rules a to g), and the
   * anchor log's checkpoint at `size`. `size` defaults to the anchor log's
   * size.
   */
  async explain(base: AnchorBase, size?: number): Promise<ExplainedRange> {
    const N = size ?? (await this.ctx.logs.getLogSize(this.ctx.anchorLogId)).size;
    const below = await this.leavesBelow(base);
    await this.indexBelow();
    const fail = (k: number, rule: string, why: string): never => {
      throw new AnchorTrustError('anchor_log_leaf_unexplained', `anchor leaf ${k} (rule ${rule})`, `Anchor leaf ${k} is unexplained (rule ${rule}): ${why}. Anchoring is stopped.`);
    };
    const leaves = N > base.size ? await this.ctx.logs.listLogLeaves(this.ctx.anchorLogId, base.size, N) : [];
    // A range explained before, over the same leaves and the same anchor
    // checkpoint, is the same explanation: its checkpoints are kept in
    // memory, and every reader compares what it reads with them.
    const atN = N > base.size ? await this.ctx.anchors.getLogCheckpoint(this.ctx.anchorLogId, N) : null;
    const memoKey = createHash('sha256')
      .update(JSON.stringify([base.size, base.root, N, leaves.map((l) => [l.leafIndex, l.leafDigest, l.sourceRef]), atN && [atN.root, atN.body, atN.bodyDigest, atN.epochId]]))
      .digest('hex');
    const memo = this.explainedMemo.get(memoKey);
    if (memo) return memo;
    if (leaves.length !== N - base.size || leaves.some((l, i) => l.leafIndex !== base.size + i)) {
      fail(base.size, 'a', `the anchor log is not dense above size ${base.size}`);
    }
    const byLeaf = new Map<number, LogCheckpoint[]>();
    if (N > base.size) {
      for (const cp of await this.ctx.anchors.listCheckpointsByAnchorLeaf(base.size, N)) {
        const k = cp.anchorLeafIndex as number;
        byLeaf.set(k, [...(byLeaf.get(k) ?? []), cp]);
      }
    }
    const logsById = new Map<number, LogRecord>();
    const logOf = async (logId: number): Promise<LogRecord | null> => {
      if (!logsById.has(logId)) {
        const log = await this.ctx.logs.getLog(logId);
        if (!log) return null;
        logsById.set(logId, log);
      }
      return logsById.get(logId)!;
    };
    const explained = new Map<number, LogCheckpoint>();
    /** The last checkpoint this walk explained, by origin: rule e's predecessor above the base. */
    const walkLast = new Map<string, LogCheckpoint>();
    let lastEpochId = base.epochId;
    let epochStart = -1;
    let epochOrigins: string[] = [];

    for (const leaf of leaves) {
      const k = leaf.leafIndex;
      // a. exactly one source checkpoint holds the leaf's digest at its index.
      const found = byLeaf.get(k) ?? [];
      if (found.length !== 1) fail(k, 'a', found.length === 0 ? 'no source checkpoint is behind it' : `${found.length} checkpoints claim it`);
      const c = found[0];
      const log = await logOf(c.logId);
      // d. its log is a source log of a kind the scheduler anchors, in the domain, under the origin the store names.
      if (!log) return fail(k, 'd', `its checkpoint names log ${c.logId}, which does not exist`);
      if (log.kind === ANCHOR_LOG_KIND) fail(k, 'd', 'its checkpoint is the anchor log\'s own');
      if (!this.ctx.sourceLogKinds.includes(log.kind)) fail(k, 'd', `its checkpoint is of a ${log.kind} log, a kind the scheduler does not anchor`);
      const binding = checkOriginBinding(this.ctx.anchorOrigin, log.origin, log.kind === EVIDENCE_LOG_KIND ? log.chainId : undefined);
      if (!binding.ok || this.ctx.expectedOrigin(log) !== log.origin) fail(k, 'd', `its log's origin ${log.origin} is not in the domain`);
      // b. the checkpoint's body is its digest and the leaf, and names its log, size and root.
      if (sha256Hex(c.body) !== c.bodyDigest || c.bodyDigest !== leaf.leafDigest) fail(k, 'b', 'its checkpoint\'s body does not hash to the leaf');
      const parsed = parseCheckpoint(c.body);
      if (!parsed.ok || parsed.checkpoint.origin !== log.origin || parsed.checkpoint.size !== c.treeSize || parsed.checkpoint.root !== c.root) {
        fail(k, 'b', 'its checkpoint\'s body is not its log\'s checkpoint at its size with its root');
      }
      // c. the leaf names the checkpoint's origin and size, as the planner writes it.
      if (leaf.sourceRef !== `${log.origin}\n${c.treeSize}`) fail(k, 'c', 'its source reference is not its checkpoint\'s origin and size');
      // e. the predecessor the checkpoint builds on is the one the anchor log
      // committed to last for its origin: the last one this walk explained,
      // or else the last one below the base, from the index. The store's own
      // answer must agree, and a predecessor below the base must be authentic.
      const inWalk = walkLast.get(log.origin) ?? null;
      const committed = inWalk ? null : this.lastBelow(log.origin, base.size);
      const prevSize = inWalk?.treeSize ?? committed?.treeSize ?? null;
      const prevLeaf = (inWalk?.anchorLeafIndex as number | undefined) ?? committed?.k ?? null;
      if (c.prevAnchoredSize !== prevSize || !(c.treeSize > (prevSize ?? 0))) {
        fail(k, 'e', `its checkpoint follows size ${String(c.prevAnchoredSize)}, but the anchor log last committed to its log at ${String(prevSize)}`);
      }
      const stored = await this.ctx.anchors.getLastAnchoredCheckpointBelow(c.logId, k);
      if ((stored?.anchorLeafIndex ?? null) !== prevLeaf || (stored !== null && stored.treeSize !== prevSize)) {
        fail(k, 'e', `the store says its log was last anchored at size ${String(stored?.treeSize ?? null)}, but the anchor log committed to size ${String(prevSize)}`);
      }
      let p: LogCheckpoint | null = null;
      if (inWalk) {
        if (stored!.bodyDigest !== inWalk.bodyDigest || stored!.root !== inWalk.root || JSON.stringify(stored!.compactRange) !== JSON.stringify(inWalk.compactRange)) {
          fail(k, 'e', `its predecessor at size ${inWalk.treeSize} is not the one this walk explained`);
        }
        p = inWalk;
      } else if (committed) {
        const why = await this.authenticBelow(stored as LogCheckpoint, log, below);
        if (why) fail(k, 'e', `its predecessor at size ${committed.treeSize}: ${why}`);
        p = stored;
      }
      // f. its log's leaves rebuild it from the predecessor, consistently.
      const m = p?.treeSize ?? 0;
      const sourceLeaves = await this.ctx.logs.listLogLeaves(c.logId, m, c.treeSize);
      if (sourceLeaves.length !== c.treeSize - m) fail(k, 'f', `its log has ${sourceLeaves.length} leaves in [${m}, ${c.treeSize})`);
      let ext: { root: string; range: { hashes: string[] } } | null = null;
      try {
        ext = extendCompactRange({ size: m, hashes: p?.compactRange ?? [] }, sourceLeaves.map((l) => l.leafDigest));
      } catch {
        ext = null;
      }
      if (!ext || ext.root !== c.root || JSON.stringify(ext.range.hashes) !== JSON.stringify(c.compactRange)) {
        fail(k, 'f', `its log's leaves do not rebuild its root and range at size ${c.treeSize}`);
      }
      if ((p === null) !== (c.consistencyProof === null)) fail(k, 'f', 'its consistency proof is not there exactly when a predecessor is');
      if (p && !verifyConsistencyProof(m, c.treeSize, c.consistencyProof as string[], p.root, c.root).valid) {
        fail(k, 'f', `its consistency proof from size ${m} does not verify`);
      }
      // g. an epoch's leaves are contiguous, in bytewise origin order, one per log; epoch ids rise.
      if (c.epochId === null) fail(k, 'g', 'its checkpoint names no epoch');
      if (epochStart === -1 || c.epochId !== lastEpochId) {
        if (!((c.epochId as number) > lastEpochId)) fail(k, 'g', `its epoch ${String(c.epochId)} does not follow epoch ${lastEpochId}`);
        lastEpochId = c.epochId as number;
        epochStart = k;
        epochOrigins = [];
      }
      if (epochOrigins.length > 0 && !(bytewise(epochOrigins[epochOrigins.length - 1], log.origin) < 0)) {
        fail(k, 'g', `its epoch is not in ascending bytewise origin order, one checkpoint per log`);
      }
      epochOrigins.push(log.origin);
      explained.set(k, c);
      walkLast.set(log.origin, c);
    }

    // The anchor log's checkpoint at N rebuilds from the base and the explained leaves.
    let root = base.root;
    let range = base.range;
    let anchorCheckpoint: LogCheckpoint | null = null;
    if (N > base.size) {
      const ext = extendCompactRange({ size: base.size, hashes: base.range }, leaves.map((l) => l.leafDigest));
      root = ext.root;
      range = ext.range.hashes;
      anchorCheckpoint = await this.ctx.anchors.getLogCheckpoint(this.ctx.anchorLogId, N);
      const body = formatCheckpoint(this.ctx.anchorOrigin, N, ext.root);
      if (!anchorCheckpoint || anchorCheckpoint.root !== ext.root || anchorCheckpoint.body !== body || anchorCheckpoint.bodyDigest !== sha256Hex(body)) {
        throw new AnchorTrustError(
          'anchor_log_leaf_unexplained',
          `anchor checkpoint ${N}`,
          `The anchor log's checkpoint at size ${N} is not the one its leaves rebuild. Anchoring is stopped.`,
        );
      }
      if (anchorCheckpoint.epochId !== lastEpochId) {
        throw new AnchorTrustError(
          'anchor_log_leaf_unexplained',
          `anchor checkpoint ${N}`,
          `The anchor log's checkpoint at size ${N} names epoch ${String(anchorCheckpoint.epochId)}, not the last explained epoch ${lastEpochId}. Anchoring is stopped.`,
        );
      }
    }
    const result: ExplainedRange = { base, size: N, root, range, leaves, checkpoints: explained, logs: logsById, anchorCheckpoint, lastEpochId };
    if (N > base.size) {
      if (this.explainedMemo.size >= 64) this.explainedMemo.clear();
      this.explainedMemo.set(memoKey, result);
    }
    return result;
  }

  /**
   * A source log's last anchored checkpoint, authenticated (rule e): the
   * last one of its origin that `range` explained, or else the last one of
   * its origin below the base, by the index, whose body is the verified
   * anchor leaf at its index. Null when the anchor log never committed to the
   * log. The store's own answer must be that checkpoint.
   */
  async lastAnchored(log: LogRecord, range: ExplainedRange): Promise<LogCheckpoint | null> {
    const fail = (why: string): never => {
      throw new AnchorTrustError('anchor_log_leaf_unexplained', `log ${log.origin}`, `The last anchored checkpoint of ${log.origin}: ${why}. Anchoring is stopped.`);
    };
    const below = await this.leavesBelow(range.base);
    await this.indexBelow();
    let inRange: [number, LogCheckpoint] | null = null;
    for (const [k, c] of range.checkpoints) {
      if (range.logs.get(c.logId)?.origin === log.origin && (inRange === null || k > inRange[0])) inRange = [k, c];
    }
    const committed = inRange ? null : this.lastBelow(log.origin, range.base.size);
    const stored = await this.ctx.anchors.getLastAnchoredCheckpoint(log.logId);
    if (!inRange && !committed) {
      if (stored) fail(`the store names size ${stored.treeSize} at anchor leaf ${String(stored.anchorLeafIndex)}, and the anchor log never committed to the log`);
      return null;
    }
    const k = inRange ? inRange[0] : (committed as { k: number }).k;
    if (!stored || stored.anchorLeafIndex !== k) {
      fail(`the store names ${stored ? `size ${stored.treeSize} at anchor leaf ${String(stored.anchorLeafIndex)}` : 'none'}, and the anchor log committed to anchor leaf ${k}`);
    }
    const cp = stored as LogCheckpoint;
    if (inRange) {
      const seen = inRange[1];
      if (seen.logId !== cp.logId || seen.treeSize !== cp.treeSize || seen.bodyDigest !== cp.bodyDigest || seen.root !== cp.root || JSON.stringify(seen.compactRange) !== JSON.stringify(cp.compactRange)) {
        fail(`it is not the one the anchor log explains at leaf ${k}`);
      }
      return cp;
    }
    const why = await this.authenticBelow(cp, log, below);
    if (why) fail(`size ${cp.treeSize}: ${why}`);
    return cp;
  }
}
