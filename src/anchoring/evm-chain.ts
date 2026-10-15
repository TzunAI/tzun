/**
 * The EVM side of the anchor scheduler: what it reads from a chain, how it
 * broadcasts, and the dedicated publisher that signs (tzun-anchor/1 §7.2).
 *
 * FINALITY. The scheduler treats a block as final only when it is at or below
 * the node's `finalized` tag, never after a number of confirmations. On
 * Ethereum's public networks (measured on Sepolia, Hoodi and mainnet) the tag
 * trails the head by 64 to 96 blocks, about 13 to 19 minutes. anvil computes
 * its `finalized` tag as the head minus twice `--slots-in-an-epoch` (32 by
 * default), with no consensus behind it, and anvil can revert below it; a test
 * on anvil exercises the scheduler's handling of the tag, not finality itself.
 *
 * THE KEY. A publisher signs through an `AnchorTransactionSigner`: an
 * external signer the caller supplies (an ethers `Signer`, a KMS or HSM
 * signer), which keeps the key where the caller keeps it, or an ethers
 * `Wallet` built from a private key the caller passes in, held in a closure.
 * Either way the publisher exposes only the address and a signing function,
 * and it checks every transaction the signer returns before anything stores
 * or sends it: against the one it asked for, and against every rule of
 * tzun-anchor/1 §10.4 item 2, read by the verifier's own reader (§7.2 rule 3,
 * §11 item 6). A signature whose `s` is above (n − 1) / 2, which some KMS and
 * HSM signers return, is replaced by the equivalent one with n − s; anything
 * else that breaks a rule is refused. Every call to the signer has a deadline
 * (`signTimeoutMs`). Nothing here reads the environment or logs.
 *
 * THE URL. A node's URL often carries an API key in its path (Infura,
 * Alchemy). ethers writes the request URL into the message of every HTTP
 * failure, so `JsonRpcEvmChain` rethrows every failure as an
 * {@link EvmRpcError}, whose message and fields name no URL.
 */
import { FetchRequest, JsonRpcProvider, Network, Transaction, Wallet, encodeRlp, getBytes, keccak256, toBeHex } from 'ethers';
import type { AnchorTransactionRequest, AnchorTransactionSigner, EvmFinality } from '@tzun/engine';
import { decodeEvmRlp, evmRlpForm, readEvmTransaction, type EvmItemTwoRule } from '../attestation/blockchain';
import type { AnchorBroadcastOutcome } from '../storage/log-store';
import { DEFAULT_SIGN_TIMEOUT_MS, type ResolvedEvmPublisher } from './config';
import { AnchorSignerError, AnchorSignerUnavailableError } from './errors';
import { blockHeaderRlp, type JsonRpcBlock } from './tx-trie';

/** The fee market as the latest block shows it. */
export interface EvmFees {
  baseFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

/**
 * Why a broadcast came back as it did.
 *
 *   ok, already_known   the node has the transaction (accepted)
 *   nonce_too_low       the nonce is used; which transaction used it is looked up before anything is concluded
 *   insufficient_funds, underpriced, rejected
 *                       the node refused the transaction, and said why: `rejected` is any other definite
 *                       refusal (an invalid sender, chain or signature, too little gas, a full pool)
 *   rate_limited        the provider refused to serve the request: unknown
 *   unreachable         no answer (timeout, connection, 5xx): unknown
 *   unrecognized        an error that says none of the above: unknown
 *
 * `unknown` counts as accepted: the node may hold the transaction, so it is
 * never superseded at its nonce.
 */
export type EvmBroadcastReason =
  | 'ok'
  | 'already_known'
  | 'nonce_too_low'
  | 'insufficient_funds'
  | 'underpriced'
  | 'rejected'
  | 'rate_limited'
  | 'unreachable'
  | 'unrecognized';

export interface EvmBroadcastResult {
  outcome: AnchorBroadcastOutcome;
  reason: EvmBroadcastReason;
  /** The node's message, for the operator. Never key material: a raw transaction is public. */
  detail?: string;
}

export interface EvmReceipt {
  transactionHash: string;
  blockNumber: number;
  blockHash: string;
  transactionIndex: number;
  gasUsed: bigint;
  effectiveGasPrice: bigint;
}

/** A transaction as the node reports it. */
export interface EvmTransactionView {
  hash: string;
  from: string;
  nonce: number;
  /** Calldata, `0x` hex, lowercase. */
  data: string;
  blockHash: string | null;
  blockNumber: number | null;
}

/** A block's header and transactions, as the node reports them. */
export interface EvmBlockMaterial {
  number: number;
  hash: string;
  timestamp: number;
  /** The header's RLP, whose keccak256 is `hash`. */
  headerRlp: string;
  transactionsRoot: string;
  /** The block's signed transactions, in block order. */
  rawTransactions: string[];
}

/** What the scheduler reads from, and sends to, one EVM chain. */
export interface EvmChainClient {
  chainId(): Promise<bigint>;
  transactionCount(address: string, tag: 'latest' | 'pending'): Promise<number>;
  balance(address: string): Promise<bigint>;
  fees(): Promise<EvmFees>;
  broadcast(rawTransaction: string): Promise<EvmBroadcastResult>;
  receipt(transactionHash: string): Promise<EvmReceipt | null>;
  transaction(transactionHash: string): Promise<EvmTransactionView | null>;
  /** The height of the node's `finalized` block. */
  finalizedBlockNumber(): Promise<number>;
  /** The canonical block at `blockNumber`, or `null`. */
  canonicalBlock(blockNumber: number): Promise<{ hash: string; timestamp: number } | null>;
  /**
   * A block's header RLP and transactions, each checked against the block
   * hash and the transactions root. Material that does not check throws
   * {@link EvmBlockMaterialError}.
   */
  blockMaterial(blockNumber: number): Promise<EvmBlockMaterial>;
  /** Release the connection. */
  close(): void;
}

const lower = (v: string): string => v.toLowerCase();
const quantity = (v: unknown): number => Number(BigInt(v as string));

/** A URL in running text: a scheme, `://`, and everything up to whitespace, a quote or a bracket. */
const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'`<>()]+/gi;

const withoutUrls = (text: string): string => text.replace(URL_IN_TEXT, '<url>');

/**
 * An RPC failure's text with no URL in it: ethers' `shortMessage` when there
 * is one (it leaves out the request, whose URL can hold an API key), with
 * the node's own JSON-RPC error message after it, otherwise the message.
 * Any URL left in the text becomes `<url>`, for a client that is not ethers.
 */
export function rpcErrorText(err: unknown): string {
  const e = err as { shortMessage?: unknown; message?: unknown; error?: { message?: unknown }; info?: { error?: { message?: unknown } } } | null;
  const base = typeof e?.shortMessage === 'string' ? e.shortMessage : typeof e?.message === 'string' ? e.message : String(err);
  const node = e?.error?.message ?? e?.info?.error?.message;
  return withoutUrls(typeof node === 'string' && typeof e?.shortMessage === 'string' && !base.includes(node) ? `${base}: ${node}` : base);
}

/** A node's JSON-RPC error object, its message without URLs. */
function rpcErrorObject(value: unknown): { code?: unknown; message?: string } | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const v = value as { code?: unknown; message?: unknown };
  return { ...(v.code !== undefined && { code: v.code }), ...(typeof v.message === 'string' && { message: withoutUrls(v.message) }) };
}

/**
 * A block's material cannot be stored: its header does not rebuild to its
 * hash (a header field the SDK does not know, as a later fork adds one), or
 * its transactions are not the ones its header commits to. The scheduler
 * raises `anchor_block_material_unreadable` for it.
 */
export class EvmBlockMaterialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EvmBlockMaterialError';
    Object.setPrototypeOf(this, EvmBlockMaterialError.prototype);
  }
}

/**
 * A JSON-RPC request that failed, as {@link JsonRpcEvmChain} throws it: the
 * text of {@link rpcErrorText}, and of the original error only what says
 * why (ethers' `code`, the HTTP `status`, the node's JSON-RPC `error`). The
 * request, the response and ethers' `info`, which name the URL, are dropped.
 */
export class EvmRpcError extends Error {
  /** ethers' error code (`SERVER_ERROR`, `TIMEOUT`, `NETWORK_ERROR`, ...), when there is one. */
  readonly code?: string;
  /** The HTTP status of a failed request, when the node answered one. */
  readonly status?: number;
  readonly shortMessage: string;
  /** The node's JSON-RPC error, when it sent one. */
  readonly error?: { code?: unknown; message?: string };
  /** ethers' `info`, reduced to the node's JSON-RPC error. */
  readonly info?: { error: { code?: unknown; message?: string } };

  constructor(err: unknown) {
    const text = rpcErrorText(err);
    super(text);
    this.name = 'EvmRpcError';
    this.shortMessage = text;
    const e = err as { code?: unknown; response?: { statusCode?: unknown }; error?: unknown; info?: { error?: unknown } } | null;
    if (typeof e?.code === 'string') this.code = e.code;
    if (typeof e?.response?.statusCode === 'number') this.status = e.response.statusCode;
    const error = rpcErrorObject(e?.error);
    if (error) this.error = error;
    const infoError = rpcErrorObject(e?.info?.error);
    if (infoError) this.info = { error: infoError };
  }
}

/**
 * Sort a node's answer to a broadcast into an outcome. Messages differ
 * between clients (geth: "already known", anvil: "transaction already
 * imported"), so the match is on the phrases every client uses. Only a
 * definite refusal of the transaction is `rejected`. A rate limit, an
 * internal error, no answer and anything unrecognised are `unknown`: the node
 * may have taken the transaction, and an `unknown` attempt is never
 * superseded at its nonce.
 */
export function classifyBroadcastError(err: unknown): EvmBroadcastResult {
  const e = err as { code?: unknown; error?: { message?: unknown; code?: unknown }; info?: { error?: { message?: unknown } }; shortMessage?: unknown; message?: unknown };
  const texts = [e?.error?.message, e?.info?.error?.message, e?.shortMessage, e?.message]
    .filter((t): t is string => typeof t === 'string')
    .map(lower);
  const text = texts.join(' | ');
  const detail = texts[0]?.slice(0, 200);
  const has = (...phrases: string[]): boolean => phrases.some((p) => text.includes(p));
  if (has('already known', 'already imported', 'known transaction', 'alreadyknown')) {
    return { outcome: 'accepted', reason: 'already_known', detail };
  }
  if (has('nonce too low', 'nonce is too low', 'nonce has already been used', 'nonce_expired') || e?.code === 'NONCE_EXPIRED') {
    return { outcome: 'rejected', reason: 'nonce_too_low', detail };
  }
  if (has('insufficient funds') || e?.code === 'INSUFFICIENT_FUNDS') {
    return { outcome: 'rejected', reason: 'insufficient_funds', detail };
  }
  if (has('underpriced', 'less than block base fee', 'fee cap less than', 'max fee per gas less than', 'fee too low') || e?.code === 'REPLACEMENT_UNDERPRICED') {
    return { outcome: 'rejected', reason: 'underpriced', detail };
  }
  if (
    has(
      'invalid sender',
      'invalid signature',
      'invalid chain id',
      'invalid chainid',
      'incorrect chain id',
      'chain id mismatch',
      'only replay-protected',
      'intrinsic gas too low',
      'exceeds block gas limit',
      'gas limit reached',
      'txpool is full',
      'transaction pool is full',
      'oversized data',
      'transaction type not supported',
      'tx type not supported',
      'tip higher than fee cap',
      'max priority fee per gas higher than max fee per gas',
    )
  ) {
    return { outcome: 'rejected', reason: 'rejected', detail };
  }
  const code = e?.error?.code;
  if (code === -32005 || code === 429 || has('rate limit', 'rate-limit', 'too many requests', 'request count exceeded', 'exceeded the request limit')) {
    return { outcome: 'unknown', reason: 'rate_limited', detail };
  }
  const transport =
    e?.code === 'TIMEOUT' ||
    e?.code === 'NETWORK_ERROR' ||
    e?.code === 'SERVER_ERROR' ||
    has('econnrefused', 'econnreset', 'etimedout', 'socket hang up', 'fetch failed', 'timeout', 'bad response');
  if (transport || (e?.error === undefined && e?.info?.error === undefined)) {
    return { outcome: 'unknown', reason: 'unreachable', detail };
  }
  return { outcome: 'unknown', reason: 'unrecognized', detail };
}

/** How many recent blocks `JsonRpcEvmChain.fees()` reads the paid tips of. */
export const FEE_HISTORY_BLOCKS = 20;

/** The anchor scheduler's chain client over JSON-RPC. */
export class JsonRpcEvmChain implements EvmChainClient {
  /**
   * What this client counts as final: the node's `finalized` tag, which
   * `finalizedBlockNumber()` reads. Declared for a reader of the chain that
   * reports it, as a `ScheduledScanner` does with every anchor verdict
   * (`EvmHeaderSource.finality`).
   */
  readonly finality: EvmFinality = 'finalized';
  private readonly provider: JsonRpcProvider;

  /**
   * @param rpcUrl - the node. The chain id is pinned, so an unreachable node
   *   is a failed request rather than an endless network detection.
   * @param expectedChainId - the chain the publisher signs for.
   */
  constructor(rpcUrl: string, expectedChainId: bigint, options: { timeoutMs?: number } = {}) {
    const request = new FetchRequest(rpcUrl);
    request.timeout = options.timeoutMs ?? 30_000;
    const network = Network.from(expectedChainId);
    // No request cache: two reads of a nonce or a receipt a moment apart must
    // both reach the node (ethers otherwise answers repeats for 250 ms).
    this.provider = new JsonRpcProvider(request, network, { staticNetwork: network, batchMaxCount: 1, cacheTimeout: -1 });
  }

  /** One request. A failure is rethrown as an {@link EvmRpcError}, which names no URL. */
  private async send<T>(method: string, params: unknown[]): Promise<T> {
    try {
      return (await this.provider.send(method, params)) as T;
    } catch (err) {
      throw new EvmRpcError(err);
    }
  }

  async chainId(): Promise<bigint> {
    return BigInt(await this.send<string>('eth_chainId', []));
  }

  async transactionCount(address: string, tag: 'latest' | 'pending'): Promise<number> {
    return quantity(await this.send<string>('eth_getTransactionCount', [address, tag]));
  }

  async balance(address: string): Promise<bigint> {
    return BigInt(await this.send<string>('eth_getBalance', [address, 'latest']));
  }

  /**
   * The latest block's base fee, and a tip: the larger of the node's
   * `eth_maxPriorityFeePerGas` and the median tip the last
   * {@link FEE_HISTORY_BLOCKS} blocks paid (`eth_feeHistory`, 50th
   * percentile). A node's suggestion alone can be nothing on mainnet. Either
   * read may fail: without the suggestion the tip is 1 gwei, and without the
   * history the suggestion stands. The scheduler raises the result to the
   * chain's floor (`minPriorityFeeWei`).
   */
  async fees(): Promise<EvmFees> {
    const block = await this.send<{ baseFeePerGas?: string } | null>('eth_getBlockByNumber', ['latest', false]);
    if (!block || typeof block.baseFeePerGas !== 'string') throw new Error('The node reports no base fee: the chain is not EIP-1559.');
    let tip: bigint;
    try {
      tip = BigInt(await this.send<string>('eth_maxPriorityFeePerGas', []));
    } catch {
      tip = 1_000_000_000n;
    }
    const paid = await this.medianPaidTip().catch(() => null);
    if (paid !== null && paid > tip) tip = paid;
    return { baseFeePerGas: BigInt(block.baseFeePerGas), maxPriorityFeePerGas: tip };
  }

  /** The median of the per-block median tips over the last blocks, or null when the node reports none. */
  private async medianPaidTip(): Promise<bigint | null> {
    const history = await this.send<{ reward?: unknown } | null>('eth_feeHistory', [toBeHex(FEE_HISTORY_BLOCKS), 'latest', [50]]);
    const rewards = Array.isArray(history?.reward) ? history.reward : [];
    const tips = rewards
      .map((r) => (Array.isArray(r) && typeof r[0] === 'string' && /^0x[0-9a-fA-F]+$/.test(r[0]) ? BigInt(r[0]) : null))
      .filter((t): t is bigint => t !== null)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return tips.length === 0 ? null : tips[Math.floor(tips.length / 2)];
  }

  async broadcast(rawTransaction: string): Promise<EvmBroadcastResult> {
    try {
      await this.send<string>('eth_sendRawTransaction', [rawTransaction]);
      return { outcome: 'accepted', reason: 'ok' };
    } catch (err) {
      return classifyBroadcastError(err);
    }
  }

  async receipt(transactionHash: string): Promise<EvmReceipt | null> {
    const r = await this.send<Record<string, string> | null>('eth_getTransactionReceipt', [transactionHash]);
    if (!r || typeof r.blockHash !== 'string' || typeof r.blockNumber !== 'string') return null;
    return {
      transactionHash: lower(r.transactionHash),
      blockNumber: quantity(r.blockNumber),
      blockHash: lower(r.blockHash),
      transactionIndex: quantity(r.transactionIndex),
      gasUsed: BigInt(r.gasUsed),
      effectiveGasPrice: BigInt(r.effectiveGasPrice ?? '0x0'),
    };
  }

  async transaction(transactionHash: string): Promise<EvmTransactionView | null> {
    const t = await this.send<Record<string, string | null> | null>('eth_getTransactionByHash', [transactionHash]);
    if (!t) return null;
    return {
      hash: lower(t.hash as string),
      from: lower(t.from as string),
      nonce: quantity(t.nonce),
      data: lower((t.input ?? t.data ?? '0x') as string),
      blockHash: t.blockHash ? lower(t.blockHash) : null,
      blockNumber: t.blockNumber ? quantity(t.blockNumber) : null,
    };
  }

  async finalizedBlockNumber(): Promise<number> {
    const block = await this.send<{ number?: string } | null>('eth_getBlockByNumber', ['finalized', false]);
    if (!block || typeof block.number !== 'string') throw new Error('The node reports no finalized block.');
    return quantity(block.number);
  }

  async canonicalBlock(blockNumber: number): Promise<{ hash: string; timestamp: number } | null> {
    const block = await this.send<{ hash?: string; timestamp?: string } | null>('eth_getBlockByNumber', [toBeHex(blockNumber), false]);
    if (!block || typeof block.hash !== 'string' || typeof block.timestamp !== 'string') return null;
    return { hash: lower(block.hash), timestamp: quantity(block.timestamp) };
  }

  async blockMaterial(blockNumber: number): Promise<EvmBlockMaterial> {
    const block = await this.send<(JsonRpcBlock & { transactions: Array<Record<string, unknown>>; timestamp: string }) | null>(
      'eth_getBlockByNumber',
      [toBeHex(blockNumber), true],
    );
    if (!block) throw new Error(`The node has no block ${blockNumber}.`);
    const headerRlp = blockHeaderRlp(block);
    if (headerRlp === null) throw new EvmBlockMaterialError(`block ${blockNumber}'s header does not rebuild to its hash, so its material is not stored`);
    const rawTransactions: string[] = [];
    for (const t of block.transactions) {
      const hash = lower(String(t.hash));
      let raw = reassembleTransaction(t);
      if (raw === null || keccak256(raw) !== hash) {
        raw = lower(await this.send<string>('eth_getRawTransactionByHash', [hash]));
        if (keccak256(raw) !== hash) throw new EvmBlockMaterialError(`the node's raw transaction ${hash} does not hash to its id`);
      }
      rawTransactions.push(raw);
    }
    return {
      number: quantity(block.number),
      hash: lower(block.hash),
      timestamp: quantity(block.timestamp),
      headerRlp,
      transactionsRoot: lower(block.transactionsRoot),
      rawTransactions,
    };
  }

  close(): void {
    this.provider.destroy();
  }
}

/**
 * @internal A transaction's signed envelope as it sits in its block's
 * transactions trie, reassembled from the node's JSON, or null for a shape
 * ethers cannot rebuild (the caller then asks the node for the raw bytes).
 * Types 0 to 4: a blob transaction (type 3) is its consensus form, without
 * the blobs, and a set-code transaction (type 4) carries its authorizations.
 */
export function reassembleTransaction(t: Record<string, unknown>): string | null {
  try {
    const q = (v: unknown): bigint | undefined => (typeof v === 'string' ? BigInt(v) : undefined);
    const type = Number(q(t.type) ?? 0n);
    const authorizations = Array.isArray(t.authorizationList)
      ? (t.authorizationList as Array<Record<string, unknown>>).map((a) => ({
          chainId: q(a.chainId) as bigint,
          address: a.address as string,
          nonce: q(a.nonce) as bigint,
          signature: { r: a.r as string, s: a.s as string, yParity: Number(q(a.yParity ?? a.v)) as 0 | 1 },
        }))
      : undefined;
    return lower(
      Transaction.from({
        type,
        to: (t.to as string | null) ?? null,
        nonce: Number(q(t.nonce)),
        gasLimit: q(t.gas),
        gasPrice: type >= 2 ? undefined : q(t.gasPrice),
        maxPriorityFeePerGas: q(t.maxPriorityFeePerGas),
        maxFeePerGas: q(t.maxFeePerGas),
        maxFeePerBlobGas: q(t.maxFeePerBlobGas),
        blobVersionedHashes: Array.isArray(t.blobVersionedHashes) ? (t.blobVersionedHashes as string[]) : undefined,
        authorizationList: authorizations as never,
        data: (t.input as string) ?? '0x',
        value: q(t.value),
        chainId: q(t.chainId),
        accessList: (t.accessList as never) ?? undefined,
        signature: { r: t.r as string, s: t.s as string, v: Number(q(t.v)), yParity: t.yParity === undefined ? undefined : (Number(q(t.yParity)) as 0 | 1) } as never,
      }).serialized,
    );
  } catch {
    return null;
  }
}

/** A signed transaction, ready to persist and then broadcast. */
export interface SignedTransaction {
  raw: string;
  hash: string;
}

/** What a publication or an accounted transaction is signed with. */
export interface EvmTransactionFields {
  nonce: number;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  gasLimit: bigint;
}

/**
 * The dedicated publisher of one domain on one chain (tzun-anchor/1 §7.2
 * rule 2): an address, a chain, and a signer. The key is not reachable from
 * this object.
 */
export interface EvmPublisher {
  /** `0x` and 40 lowercase hex. */
  readonly address: string;
  /** CAIP-2. */
  readonly chain: string;
  readonly chainId: bigint;
  readonly client: EvmChainClient;
  /**
   * A publication: a zero-value transaction to the publisher's own address
   * whose calldata is exactly `0x ‖ hex(P)` (EIP-1559, chain id signed).
   */
  signPublication(p: string, fields: EvmTransactionFields): Promise<SignedTransaction>;
  /** An accounted transaction (`sweep`, `handover`): any recipient, value and calldata. */
  signTransfer(to: string, value: bigint, data: string, fields: EvmTransactionFields): Promise<SignedTransaction>;
}

const P_HEX = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** The EIP-155 chain id of a CAIP-2 `eip155:<id>` chain; throws for anything else. */
export function eip155ChainId(chain: string): bigint {
  const match = /^eip155:([1-9][0-9]*)$/.exec(chain);
  if (!match) throw new Error(`The publisher's chain must be eip155:<id> (got ${JSON.stringify(chain)}).`);
  return BigInt(match[1]);
}

/** The order n of the secp256k1 group (tzun-anchor/1 §10.4 item 2). */
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/** ⌊n/2⌋, which is (n − 1) / 2 because n is odd: the largest `s` EIP-2 allows. */
const SECP256K1_HALF_N = SECP256K1_N / 2n;

/** How many fields each transaction type's signed list has. */
const SIGNED_FIELD_COUNT: Readonly<Record<0 | 1 | 2, number>> = { 0: 9, 1: 11, 2: 12 };

/** An integer as RLP writes it: no leading zero byte, and 0 as the empty string. */
const rlpInteger = (n: bigint): string => (n === 0n ? '0x' : toBeHex(n));

/**
 * `raw` with its signature's `s` replaced by n − s and its recovery parity
 * flipped (tzun-anchor/1 §7.2 rule 3): a typed `yParity` of 0 becomes 1 and 1
 * becomes 0, and a legacy `v` becomes the other of its pair, 27 and 28, or
 * c × 2 + 35 and c × 2 + 36 for a chain id c. The hash a transaction's
 * signature signs covers none of `v`, `yParity`, `r` and `s`, so the result is
 * an equivalent signature by the same key over the same hash, and the same
 * sender recovers from it. The other fields keep their bytes.
 *
 * `null` unless `raw` is the canonical RLP of a signed type 0, 1 or 2
 * transaction whose `s` is above (n − 1) / 2 and below n, whose `r` is from 1
 * to n − 1, and whose typed `yParity` is 0 or 1 (a legacy `v`, 27 or above).
 * The result is not checked against the other rules of item 2:
 * {@link transactionToBroadcast} reads it again. Never throws.
 */
export function withLowS(raw: string): string | null {
  try {
    if (!/^0x([0-9a-fA-F]{2})+$/.test(raw)) return null;
    const first = parseInt(raw.slice(2, 4), 16);
    const type = first >= 0xc0 ? 0 : first === 1 || first === 2 ? first : null;
    if (type === null) return null;
    const payload = type === 0 ? raw : `0x${raw.slice(4)}`;
    if (evmRlpForm(getBytes(payload)) !== 'canonical') return null;
    const fields = decodeEvmRlp(payload);
    if (!Array.isArray(fields) || fields.length !== SIGNED_FIELD_COUNT[type]) return null;
    const [parityItem, rItem, sItem] = fields.slice(-3);
    const integers = [parityItem, rItem, sItem].map((item) =>
      typeof item === 'string' && !item.startsWith('0x00') ? (item === '0x' ? 0n : BigInt(item)) : null,
    );
    if (integers.some((n) => n === null)) return null;
    const [parity, r, s] = integers as bigint[];
    if (r < 1n || r >= SECP256K1_N || s <= SECP256K1_HALF_N || s >= SECP256K1_N) return null;
    let flipped: bigint;
    if (type === 0) {
      // 27 and c × 2 + 35 are odd, 28 and c × 2 + 36 even: each moves to the other of its pair.
      if (parity < 27n) return null;
      flipped = parity % 2n === 1n ? parity + 1n : parity - 1n;
    } else {
      if (parity !== 0n && parity !== 1n) return null;
      flipped = 1n - parity;
    }
    const body = encodeRlp([...fields.slice(0, -3), rlpInteger(flipped), rlpInteger(r), rlpInteger(SECP256K1_N - s)]);
    return type === 0 ? body : `0x0${type}${body.slice(2)}`;
  } catch {
    return null;
  }
}

/**
 * What the publisher may broadcast for the signed transaction `raw`, as
 * tzun-anchor/1 §7.2 rule 3 and §11 item 6 require of a writer: a transaction
 * that meets every rule of §10.4 item 2, read by the verifier's own reader
 * (`readEvmTransaction`).
 *
 * - When `raw` meets every rule: `raw` itself, its bytes unchanged.
 * - When the only rule it breaks is an `s` above (n − 1) / 2 (EIP-2), which
 *   some KMS and HSM signers return and a development chain such as anvil
 *   mines: {@link withLowS}(raw), which meets every rule and recovers the
 *   same sender (`lowered: true`). It is another transaction id.
 * - Otherwise: the rule it breaks, by the vectors' id, or `null` when it is
 *   no signed transaction of type 0, 1 or 2. When a high `s` is not the only
 *   rule broken, the rule is the one still broken with `s` lowered.
 *
 * Never throws.
 */
export function transactionToBroadcast(
  raw: string,
): { ok: true; raw: string; lowered: boolean } | { ok: false; rule: EvmItemTwoRule | null } {
  const reading = readEvmTransaction(raw);
  if (reading.ok) return { ok: true, raw, lowered: false };
  if (reading.rule !== 'signature-values') return { ok: false, rule: reading.rule };
  const lowered = withLowS(raw);
  if (lowered === null) return { ok: false, rule: 'signature-values' };
  const again = readEvmTransaction(lowered);
  return again.ok ? { ok: true, raw: lowered, lowered: true } : { ok: false, rule: again.rule };
}

/** What each rule of tzun-anchor/1 §10.4 item 2 refuses, for an {@link AnchorSignerError}'s message. */
const ITEM_TWO_BREACH: Readonly<Record<EvmItemTwoRule, string>> = {
  'chain-id': 'a typed transaction signed for chain id 0',
  'legacy-v': 'a legacy v other than 27, 28, or chainId * 2 + 35 or + 36 for a chain id of 1 or more',
  'signature-values': 'r is not from 1 to n - 1, s is 0 or n or more, or yParity is not 0 or 1',
  fees: 'maxPriorityFeePerGas above maxFeePerGas',
  recovery: 'no public key recovers from the signature',
  encoding: 'not the canonical RLP of its fields',
  'field-sizes': 'a nonce or gasLimit above 2^64 - 1, or a chain id, amount or fee above 2^256 - 1',
};

/**
 * The signed transaction `raw`, checked against `request` and the publisher's
 * `address`, as the bytes the publisher stores and broadcasts. First it must
 * meet every rule of tzun-anchor/1 §10.4 item 2 ({@link transactionToBroadcast}):
 * a signature whose only fault is an `s` above (n − 1) / 2 is replaced by the
 * equivalent one with n − s, and a transaction that breaks any other rule is
 * an {@link AnchorSignerError} whose `rule` names it. Then: it is signed, the
 * recovered sender is the publisher, every field is the one requested, it
 * carries no access list, and its bytes are ethers' canonical serialisation of
 * it (so its hash is the one a node will report). Anything else is an
 * {@link AnchorSignerError}, and nothing is stored or sent. A transaction that
 * meets every rule is returned with its bytes unchanged.
 */
export function checkSignedTransaction(raw: unknown, request: AnchorTransactionRequest, address: string): SignedTransaction {
  if (typeof raw !== 'string' || !/^0x([0-9a-fA-F]{2})+$/.test(raw)) {
    throw new AnchorSignerError('encoding', 'not 0x hex bytes');
  }
  const ready = transactionToBroadcast(raw);
  if (!ready.ok) {
    if (ready.rule !== null) throw new AnchorSignerError(ready.rule, ITEM_TWO_BREACH[ready.rule], ready.rule);
    if (isUnsignedTransaction(raw)) throw new AnchorSignerError('signature', 'unsigned, or no sender recovers from it');
    throw new AnchorSignerError('encoding', 'not a signed transaction');
  }
  const bytes = ready.raw;
  let tx: Transaction;
  try {
    tx = Transaction.from(bytes);
  } catch {
    throw new AnchorSignerError('encoding', 'not a signed transaction');
  }
  let from: string | null;
  let serialized: string;
  try {
    from = tx.isSigned() ? tx.from : null;
    serialized = tx.serialized;
  } catch (err) {
    throw new AnchorSignerError('signature', `not a canonical signature (${shortReason(err)})`);
  }
  if (!from) throw new AnchorSignerError('signature', 'unsigned, or no sender recovers from it');
  if (serialized.toLowerCase() !== bytes.toLowerCase()) throw new AnchorSignerError('encoding', 'not the canonical serialisation');
  if (lower(from) !== address) throw new AnchorSignerError('sender', `signed by ${lower(from)}, not the publisher ${address}`);
  const expected: Array<[string, unknown, unknown]> = [
    ['type', tx.type, request.type],
    ['chainId', tx.chainId, request.chainId],
    ['nonce', tx.nonce, request.nonce],
    ['to', tx.to === null ? null : lower(tx.to), lower(request.to)],
    ['value', tx.value, request.value],
    ['data', lower(tx.data), lower(request.data)],
    ['gasLimit', tx.gasLimit, request.gasLimit],
    ['maxFeePerGas', tx.maxFeePerGas, request.maxFeePerGas],
    ['maxPriorityFeePerGas', tx.maxPriorityFeePerGas, request.maxPriorityFeePerGas],
  ];
  for (const [field, got, want] of expected) {
    if (got !== want) throw new AnchorSignerError(field, `${String(got)} where ${String(want)} was asked for`);
  }
  if ((tx.accessList ?? []).length > 0) throw new AnchorSignerError('accessList', 'an access list was added');
  const signed = lower(bytes);
  return { raw: signed, hash: keccak256(signed) };
}

/** Whether ethers reads `raw` as a transaction that carries no signature. */
function isUnsignedTransaction(raw: string): boolean {
  try {
    return !Transaction.from(raw).isSigned();
  } catch {
    return false;
  }
}

/** An error's message up to ethers' parenthesised detail, for a refusal that names what went wrong. */
function shortReason(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return message.split(' (')[0].slice(0, 120);
}

/**
 * Ask the signer, within `timeoutMs`. A call that throws, returns a rejected
 * promise, or has not settled at the deadline is an
 * {@link AnchorSignerUnavailableError}; whatever it settles to later is
 * dropped. The timer does not hold the process open.
 */
async function askSigner<T>(step: 'getAddress' | 'signTransaction', timeoutMs: number, call: () => Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new AnchorSignerUnavailableError(step, `no answer within ${timeoutMs} ms`)), timeoutMs);
    timer.unref?.();
  });
  try {
    return await Promise.race([
      Promise.resolve()
        .then(call)
        .catch((err: unknown) => {
          throw new AnchorSignerUnavailableError(step, `it failed: ${shortReason(err)}`);
        }),
      deadline,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** A publisher over `signer`, whose address is `address`. */
function signerPublisher(
  signer: AnchorTransactionSigner,
  address: string,
  chain: string,
  client: EvmChainClient,
  signTimeoutMs: number,
): EvmPublisher {
  const chainId = eip155ChainId(chain);
  const sign = async (to: string, value: bigint, data: string, fields: EvmTransactionFields): Promise<SignedTransaction> => {
    const request: AnchorTransactionRequest = {
      type: 2,
      chainId,
      nonce: fields.nonce,
      to,
      value,
      data,
      gasLimit: fields.gasLimit,
      maxFeePerGas: fields.maxFeePerGas,
      maxPriorityFeePerGas: fields.maxPriorityFeePerGas,
    };
    // A copy, so a signer that edits its argument edits nothing the check reads.
    const raw = await askSigner('signTransaction', signTimeoutMs, () => signer.signTransaction({ ...request }));
    return checkSignedTransaction(raw, request, address);
  };
  return {
    address,
    chain,
    chainId,
    client,
    signPublication(p, fields) {
      if (!P_HEX.test(p)) return Promise.reject(new Error('P must be 64 lowercase hex digits.'));
      return sign(address, 0n, `0x${p}`, fields);
    },
    signTransfer(to, value, data, fields) {
      return sign(lower(to), value, data, fields);
    },
  };
}

/** The chain client for a publisher: the one given, or JSON-RPC on `rpcUrl`. */
function clientFor(chain: string, rpcUrl: string | undefined, client: EvmChainClient | undefined): EvmChainClient {
  const found = client ?? (rpcUrl ? new JsonRpcEvmChain(rpcUrl, eip155ChainId(chain)) : undefined);
  if (!found) throw new Error('The publisher needs an rpcUrl or a chain client.');
  return found;
}

/**
 * A publisher from a caller-supplied private key, held in an ethers `Wallet`
 * in a closure. `client` defaults to a JSON-RPC client on `rpcUrl`.
 */
export function createEvmPublisher(options: {
  privateKey: string;
  chain: string;
  rpcUrl?: string;
  client?: EvmChainClient;
  signTimeoutMs?: number;
}): EvmPublisher {
  eip155ChainId(options.chain);
  const wallet = new Wallet(options.privateKey);
  return signerPublisher(
    wallet,
    lower(wallet.address),
    options.chain,
    clientFor(options.chain, options.rpcUrl, options.client),
    options.signTimeoutMs ?? DEFAULT_SIGN_TIMEOUT_MS,
  );
}

/**
 * A publisher over an external signer: an ethers
 * `Signer`, or a KMS or HSM signer built on `AbstractSigner`. The key stays
 * with the signer; the publisher reads its address once, here, and checks
 * every transaction it returns. The address is taken as the signer states
 * it: the scheduler enrols the wallet only once a transaction the signer
 * returned has recovered to it. Each call to the signer has to settle within
 * `signTimeoutMs` (default 60 s). `client` defaults to a JSON-RPC client on
 * `rpcUrl`.
 *
 * @throws {AnchorSignerError} when the signer's address is not `0x` and 40 hex.
 * @throws {AnchorSignerUnavailableError} when `getAddress()` throws or does not settle in time.
 */
export async function createSignerPublisher(options: {
  signer: AnchorTransactionSigner;
  chain: string;
  rpcUrl?: string;
  client?: EvmChainClient;
  signTimeoutMs?: number;
}): Promise<EvmPublisher> {
  eip155ChainId(options.chain);
  const signTimeoutMs = options.signTimeoutMs ?? DEFAULT_SIGN_TIMEOUT_MS;
  const address = await askSigner('getAddress', signTimeoutMs, () => options.signer.getAddress());
  if (typeof address !== 'string' || !ADDRESS.test(address)) {
    throw new AnchorSignerError('address', 'getAddress() did not return 0x and 40 hex digits');
  }
  return signerPublisher(options.signer, lower(address), options.chain, clientFor(options.chain, options.rpcUrl, options.client), signTimeoutMs);
}

/**
 * The publisher `evm` configures, over `client` when one is given (the
 * scheduler's tests), otherwise over JSON-RPC on `evm.rpcUrl`.
 */
export async function publisherFor(evm: ResolvedEvmPublisher, client?: EvmChainClient): Promise<EvmPublisher> {
  const common = { chain: evm.chain, rpcUrl: evm.rpcUrl, client, signTimeoutMs: evm.signTimeoutMs };
  if (evm.signer) return createSignerPublisher({ signer: evm.signer, ...common });
  return createEvmPublisher({ privateKey: evm.privateKey as string, ...common });
}
