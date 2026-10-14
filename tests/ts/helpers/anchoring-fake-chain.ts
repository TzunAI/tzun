/**
 * An in-memory EVM chain for the anchor scheduler's unit tests: balances,
 * nonces, a mempool, blocks mined on demand, a `finalized` tag a fixed depth
 * below the head, reorgs, and an outage switch. Blocks carry a real
 * transactions trie and a header that commits to it, so the material the
 * scheduler stores verifies with the SDK's own EVM verifier.
 *
 * It models the rules the scheduler depends on, not a whole node: a
 * transaction is valid when it parses, is signed for this chain, carries the
 * sender's next nonce (or a later one, queued), can be paid for, and a
 * same-nonce replacement bumps both fees by at least 10%. The anvil suite
 * (tests/anvil/) runs the same scheduler against a real node.
 */
import { Transaction, Wallet, keccak256, type BaseWallet } from 'ethers';
import {
  classifyBroadcastError,
  type EvmBlockMaterial,
  type EvmBroadcastResult,
  type EvmChainClient,
  type EvmFees,
  type EvmReceipt,
  type EvmTransactionView,
} from '../../../src/anchoring/evm-chain';
import { buildTxTrie } from '../../../src/anchoring/tx-trie';
import { buildHeader } from './evm-fixtures';

interface Block {
  number: number;
  hash: string;
  timestamp: number;
  header: string;
  transactionsRoot: string;
  raws: string[];
}

interface Mined {
  blockNumber: number;
  index: number;
  gasUsed: bigint;
  effectiveGasPrice: bigint;
}

const lower = (v: string): string => v.toLowerCase();

export class FakeEvmChain implements EvmChainClient {
  baseFeePerGas = 1_000_000_000n;
  maxPriorityFeePerGas = 100_000_000n;
  /** How far below the head the `finalized` tag sits. */
  finalizedDepth = 2;
  /** When true, every call fails as an unreachable node does. */
  outage = false;
  /** When set, the next broadcast is refused with this node message. */
  refuseNext: string | null = null;
  /** When set, every broadcast it returns a message for is refused with that message. */
  refuse: ((rawTransaction: string) => string | null) | null = null;
  /**
   * When set, the next broadcast fails with this JSON-RPC error, classified
   * as `JsonRpcEvmChain` classifies it. With `accept`, the node took the
   * transaction all the same (an internal error after the pool accepted it).
   */
  errorNext: { error: unknown; accept: boolean } | null = null;
  readonly blocks: Block[] = [];
  readonly balances = new Map<string, bigint>();
  private readonly mined = new Map<string, Mined>();
  private readonly minedRaw = new Map<string, string>();
  private readonly pool = new Map<string, string>();
  private readonly counts = new Map<string, number>();
  /** Every raw transaction ever broadcast, in order: what left the scheduler. */
  readonly broadcasts: string[] = [];
  private time = 1_790_000_000;

  constructor(readonly chainIdValue = 31337n) {
    this.pushBlock([]);
  }

  private guard(): void {
    if (this.outage) {
      const err = new Error('connect ECONNREFUSED 127.0.0.1:8545') as Error & { code: string };
      err.code = 'NETWORK_ERROR';
      throw err;
    }
  }

  fund(address: string, wei: bigint): void {
    this.balances.set(lower(address), (this.balances.get(lower(address)) ?? 0n) + wei);
  }

  head(): number {
    return this.blocks[this.blocks.length - 1].number;
  }

  private pushBlock(raws: string[]): Block {
    const number = this.blocks.length;
    const parent = this.blocks[number - 1];
    const trie = buildTxTrie(raws);
    this.time += 12;
    const { rlp, hash } = buildHeader({ number, timestamp: this.time, transactionsRoot: trie.root, parentHash: parent?.hash });
    const block = { number, hash: lower(hash), timestamp: this.time, header: rlp, transactionsRoot: lower(trie.root), raws };
    this.blocks.push(block);
    return block;
  }

  private parse(raw: string): Transaction {
    return Transaction.from(raw);
  }

  /** Mine one block from the pool: each sender's next nonces, paying at least the base fee. */
  mine(count = 1): void {
    for (let c = 0; c < count; c++) {
      const include: string[] = [];
      let progress = true;
      while (progress) {
        progress = false;
        for (const [hash, raw] of [...this.pool.entries()]) {
          const tx = this.parse(raw);
          const from = lower(tx.from as string);
          if (tx.nonce !== (this.counts.get(from) ?? 0)) continue;
          if ((tx.maxFeePerGas ?? tx.gasPrice ?? 0n) < this.baseFeePerGas) continue;
          const price = tx.maxFeePerGas !== null
            ? (tx.maxFeePerGas < this.baseFeePerGas + (tx.maxPriorityFeePerGas ?? 0n) ? tx.maxFeePerGas : this.baseFeePerGas + (tx.maxPriorityFeePerGas ?? 0n))
            : (tx.gasPrice as bigint);
          const gasUsed = tx.data === '0x' ? 21_000n : 22_280n;
          this.balances.set(from, (this.balances.get(from) ?? 0n) - gasUsed * price - tx.value);
          if (tx.to) this.fund(tx.to, tx.value);
          this.counts.set(from, tx.nonce + 1);
          this.pool.delete(hash);
          include.push(raw);
          this.mined.set(hash, { blockNumber: this.blocks.length, index: include.length - 1, gasUsed, effectiveGasPrice: price });
          this.minedRaw.set(hash, raw);
          progress = true;
        }
      }
      this.pushBlock(include);
    }
  }

  /**
   * Drop the last `depth` blocks. Their transactions return to the pool when
   * `requeue` is true (geth), and are forgotten otherwise (anvil's revert).
   */
  reorg(depth: number, requeue = false): void {
    for (let i = 0; i < depth; i++) {
      const block = this.blocks.pop()!;
      for (const raw of [...block.raws].reverse()) {
        const hash = keccak256(raw);
        const tx = this.parse(raw);
        const from = lower(tx.from as string);
        this.counts.set(from, tx.nonce);
        const m = this.mined.get(hash)!;
        this.balances.set(from, (this.balances.get(from) ?? 0n) + m.gasUsed * m.effectiveGasPrice + tx.value);
        this.mined.delete(hash);
        this.minedRaw.delete(hash);
        if (requeue) this.pool.set(hash, raw);
      }
    }
  }

  /** Remove a pending transaction, as a node that evicts it does. */
  evict(hash: string): void {
    this.pool.delete(lower(hash));
  }

  poolSize(): number {
    return this.pool.size;
  }

  /** Sign and include a transaction from `wallet` at its next nonce, outside the scheduler. */
  async sendExternal(wallet: BaseWallet, data = '0x'): Promise<string> {
    const raw = await wallet.signTransaction({
      type: 2,
      chainId: this.chainIdValue,
      nonce: await this.transactionCount(wallet.address, 'pending'),
      to: wallet.address,
      value: 0n,
      data,
      gasLimit: 30_000n,
      maxFeePerGas: this.baseFeePerGas * 3n,
      maxPriorityFeePerGas: this.maxPriorityFeePerGas,
    });
    const result = await this.broadcast(raw);
    if (result.outcome !== 'accepted') throw new Error(`external transaction refused: ${result.reason}`);
    return keccak256(raw);
  }

  // ── EvmChainClient ────────────────────────────────────────────────────────

  async chainId(): Promise<bigint> {
    this.guard();
    return this.chainIdValue;
  }

  async transactionCount(address: string, tag: 'latest' | 'pending'): Promise<number> {
    this.guard();
    const from = lower(address);
    let n = this.counts.get(from) ?? 0;
    if (tag === 'pending') {
      const pending = new Set([...this.pool.values()].map((r) => this.parse(r)).filter((t) => lower(t.from as string) === from).map((t) => t.nonce));
      while (pending.has(n)) n++;
    }
    return n;
  }

  async balance(address: string): Promise<bigint> {
    this.guard();
    return this.balances.get(lower(address)) ?? 0n;
  }

  async fees(): Promise<EvmFees> {
    this.guard();
    return { baseFeePerGas: this.baseFeePerGas, maxPriorityFeePerGas: this.maxPriorityFeePerGas };
  }

  async broadcast(rawTransaction: string): Promise<EvmBroadcastResult> {
    this.guard();
    if (this.errorNext) {
      const { error, accept } = this.errorNext;
      this.errorNext = null;
      if (accept) await this.broadcast(rawTransaction);
      else this.broadcasts.push(rawTransaction);
      return classifyBroadcastError(error);
    }
    this.broadcasts.push(rawTransaction);
    const refused = this.refuse?.(rawTransaction) ?? null;
    if (this.refuseNext || refused) {
      const detail = (this.refuseNext ?? refused) as string;
      this.refuseNext = null;
      return detail.includes('insufficient funds')
        ? { outcome: 'rejected', reason: 'insufficient_funds', detail }
        : { outcome: 'rejected', reason: 'rejected', detail };
    }
    const tx = this.parse(rawTransaction);
    const hash = keccak256(rawTransaction);
    if (tx.chainId !== this.chainIdValue) return { outcome: 'rejected', reason: 'rejected', detail: 'invalid chain id' };
    if (this.pool.has(hash)) return { outcome: 'accepted', reason: 'already_known' };
    const from = lower(tx.from as string);
    if (tx.nonce < (this.counts.get(from) ?? 0)) return { outcome: 'rejected', reason: 'nonce_too_low', detail: 'nonce too low' };
    const cost = tx.gasLimit * (tx.maxFeePerGas ?? tx.gasPrice ?? 0n) + tx.value;
    if (cost > (this.balances.get(from) ?? 0n)) {
      return { outcome: 'rejected', reason: 'insufficient_funds', detail: 'insufficient funds for gas * price + value' };
    }
    for (const [otherHash, otherRaw] of this.pool) {
      const other = this.parse(otherRaw);
      if (lower(other.from as string) !== from || other.nonce !== tx.nonce) continue;
      const enough = (a: bigint | null, b: bigint | null): boolean => (a ?? 0n) * 100n >= (b ?? 0n) * 110n;
      if (!enough(tx.maxFeePerGas, other.maxFeePerGas) || !enough(tx.maxPriorityFeePerGas, other.maxPriorityFeePerGas)) {
        return { outcome: 'rejected', reason: 'underpriced', detail: 'replacement transaction underpriced' };
      }
      this.pool.delete(otherHash);
    }
    this.pool.set(hash, rawTransaction);
    return { outcome: 'accepted', reason: 'ok' };
  }

  async receipt(transactionHash: string): Promise<EvmReceipt | null> {
    this.guard();
    const m = this.mined.get(lower(transactionHash));
    if (!m) return null;
    return {
      transactionHash: lower(transactionHash),
      blockNumber: m.blockNumber,
      blockHash: this.blocks[m.blockNumber].hash,
      transactionIndex: m.index,
      gasUsed: m.gasUsed,
      effectiveGasPrice: m.effectiveGasPrice,
    };
  }

  async transaction(transactionHash: string): Promise<EvmTransactionView | null> {
    this.guard();
    const hash = lower(transactionHash);
    const raw = this.minedRaw.get(hash) ?? this.pool.get(hash);
    if (!raw) return null;
    const tx = this.parse(raw);
    const m = this.mined.get(hash);
    return {
      hash,
      from: lower(tx.from as string),
      nonce: tx.nonce,
      data: lower(tx.data),
      blockHash: m ? this.blocks[m.blockNumber].hash : null,
      blockNumber: m ? m.blockNumber : null,
    };
  }

  async finalizedBlockNumber(): Promise<number> {
    this.guard();
    return Math.max(0, this.head() - this.finalizedDepth);
  }

  async canonicalBlock(blockNumber: number): Promise<{ hash: string; timestamp: number } | null> {
    this.guard();
    const block = this.blocks[blockNumber];
    return block ? { hash: block.hash, timestamp: block.timestamp } : null;
  }

  async blockMaterial(blockNumber: number): Promise<EvmBlockMaterial> {
    this.guard();
    const block = this.blocks[blockNumber];
    if (!block) throw new Error(`no block ${blockNumber}`);
    return {
      number: block.number,
      hash: block.hash,
      timestamp: block.timestamp,
      headerRlp: block.header,
      transactionsRoot: block.transactionsRoot,
      rawTransactions: [...block.raws],
    };
  }

  close(): void {
    /* nothing to release */
  }
}

/** A throwaway publisher key, and its wallet. Never a real key. */
export function throwawayWallet(): Wallet {
  return Wallet.createRandom() as unknown as Wallet;
}
