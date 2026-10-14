/**
 * A minimal EVM JSON-RPC node on loopback, for driving real ethers
 * (`JsonRpcProvider`, `Wallet.sendTransaction`) with no mocks and no network.
 *
 * It auto-mines: every accepted raw transaction goes into a new block of its
 * own. Blocks are real in the sense that matters here: each header is the RLP
 * of its fields with `transactionsRoot` computed over the block's
 * transactions, and the block hash is keccak256 of that header. The
 * `finalized` tag trails the head by `finalityLag` blocks.
 *
 * It answers only the methods ethers uses to send a transaction, wait for it,
 * and read it back. It does not execute anything: balances, gas and state are
 * not modelled.
 */
import * as http from 'http';
import type { AddressInfo } from 'net';
import { JsonRpcProvider, Transaction, Wallet, keccak256, toQuantity } from 'ethers';
import { buildHeader, buildTxTrie } from './evm-fixtures';

interface Block {
  number: number;
  hash: string;
  parentHash: string;
  timestamp: number;
  raws: string[];
  transactionsRoot: string;
}

const Z32 = '0x' + '00'.repeat(32);

export class FakeEvmNode {
  readonly chainId: bigint;
  finalityLag: number;
  /** When set, requests are read and never answered. */
  hang = false;
  /** When set, every request is answered 429 Too Many Requests, `Retry-After: 100`. */
  throttle = false;
  /** Every HTTP request received, answered or not. */
  requests = 0;
  private blocks: Block[] = [];
  private byHash = new Map<string, { block: Block; index: number }>();
  private server?: http.Server;

  constructor(opts: { chainId: bigint; finalityLag?: number; genesisTime?: number }) {
    this.chainId = opts.chainId;
    this.finalityLag = opts.finalityLag ?? 64;
    this.push([], opts.genesisTime ?? 1_790_000_000);
  }

  get head(): number {
    return this.blocks.length - 1;
  }

  /** Mine `n` empty blocks. */
  mineEmpty(n: number): void {
    for (let i = 0; i < n; i++) this.push([]);
  }

  /** Mine a block containing these raw transactions, in order. */
  mine(raws: string[]): Block {
    return this.push(raws);
  }

  async start(): Promise<string> {
    this.server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        this.requests++;
        if (this.hang) return;
        if (this.throttle) {
          res.statusCode = 429;
          // ethers reads an integer Retry-After as the delay in milliseconds.
          res.setHeader('retry-after', '100');
          res.end('rate limited');
          return;
        }
        const payload = JSON.parse(body);
        const answer = Array.isArray(payload) ? payload.map((p) => this.answer(p)) : this.answer(payload);
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(answer));
      });
    });
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}`;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
  }

  private push(raws: string[], timestamp?: number): Block {
    const prev = this.blocks[this.blocks.length - 1];
    const number = this.blocks.length;
    const trie = buildTxTrie(raws);
    const ts = timestamp ?? prev.timestamp + 12;
    const header = buildHeader({ number, timestamp: ts, transactionsRoot: trie.root, parentHash: prev?.hash ?? Z32 });
    const block: Block = { number, hash: header.hash, parentHash: prev?.hash ?? Z32, timestamp: ts, raws, transactionsRoot: trie.root };
    this.blocks.push(block);
    raws.forEach((raw, index) => this.byHash.set(keccak256(raw), { block, index }));
    return block;
  }

  private blockAt(tag: unknown): Block | undefined {
    if (tag === 'latest' || tag === 'pending') return this.blocks[this.head];
    if (tag === 'finalized' || tag === 'safe') return this.blocks[Math.max(0, this.head - this.finalityLag)];
    if (tag === 'earliest') return this.blocks[0];
    if (typeof tag === 'string' && tag.startsWith('0x')) return this.blocks[Number(BigInt(tag))];
    return undefined;
  }

  private blockJson(b: Block) {
    return {
      number: toQuantity(b.number),
      hash: b.hash,
      parentHash: b.parentHash,
      timestamp: toQuantity(b.timestamp),
      nonce: '0x0000000000000000',
      difficulty: '0x0',
      gasLimit: toQuantity(30_000_000),
      gasUsed: toQuantity(21_000 * b.raws.length),
      miner: '0x' + '22'.repeat(20),
      extraData: '0x',
      baseFeePerGas: '0x7',
      stateRoot: '0x' + '33'.repeat(32),
      receiptsRoot: '0x' + '44'.repeat(32),
      transactionsRoot: b.transactionsRoot,
      mixHash: Z32,
      transactions: b.raws.map((r) => keccak256(r)),
    };
  }

  private txJson(hash: string) {
    const at = this.byHash.get(hash);
    if (!at) return null;
    const t = Transaction.from(at.block.raws[at.index]);
    const sig = t.signature!;
    return {
      hash,
      type: toQuantity(t.type!),
      blockHash: at.block.hash,
      blockNumber: toQuantity(at.block.number),
      transactionIndex: toQuantity(at.index),
      from: t.from,
      to: t.to,
      nonce: toQuantity(t.nonce),
      gas: toQuantity(t.gasLimit),
      gasPrice: toQuantity(t.gasPrice ?? t.maxFeePerGas ?? 0n),
      ...(t.type === 2
        ? { maxFeePerGas: toQuantity(t.maxFeePerGas!), maxPriorityFeePerGas: toQuantity(t.maxPriorityFeePerGas!) }
        : {}),
      ...(t.type === 1 || t.type === 2 ? { accessList: [], yParity: toQuantity(sig.yParity) } : {}),
      input: t.data,
      value: toQuantity(t.value),
      chainId: toQuantity(t.chainId),
      v: toQuantity(t.type === 0 ? sig.networkV ?? sig.v : sig.yParity),
      r: sig.r,
      s: sig.s,
    };
  }

  private receiptJson(hash: string) {
    const at = this.byHash.get(hash);
    if (!at) return null;
    const t = Transaction.from(at.block.raws[at.index]);
    return {
      transactionHash: hash,
      transactionIndex: toQuantity(at.index),
      blockHash: at.block.hash,
      blockNumber: toQuantity(at.block.number),
      from: t.from,
      to: t.to,
      contractAddress: null,
      cumulativeGasUsed: toQuantity(21_000 * (at.index + 1)),
      gasUsed: toQuantity(21_000),
      effectiveGasPrice: toQuantity(t.gasPrice ?? t.maxFeePerGas ?? 0n),
      logs: [],
      logsBloom: '0x' + '00'.repeat(256),
      status: '0x1',
      type: toQuantity(t.type!),
    };
  }

  private answer(req: { id: number; method: string; params: unknown[] }) {
    const ok = (result: unknown) => ({ jsonrpc: '2.0', id: req.id, result });
    const p = req.params ?? [];
    switch (req.method) {
      case 'eth_chainId':
        return ok(toQuantity(this.chainId));
      case 'net_version':
        return ok(this.chainId.toString());
      case 'eth_blockNumber':
        return ok(toQuantity(this.head));
      case 'eth_getBlockByNumber': {
        const b = this.blockAt(p[0]);
        return ok(b ? this.blockJson(b) : null);
      }
      case 'eth_getBlockByHash': {
        const b = this.blocks.find((x) => x.hash === p[0]);
        return ok(b ? this.blockJson(b) : null);
      }
      case 'eth_getTransactionCount': {
        const who = String(p[0]).toLowerCase();
        let n = 0;
        for (const b of this.blocks) for (const r of b.raws) if (Transaction.from(r).from!.toLowerCase() === who) n++;
        return ok(toQuantity(n));
      }
      case 'eth_estimateGas':
        return ok(toQuantity(22_280));
      case 'eth_gasPrice':
        return ok(toQuantity(2_000_000_000));
      case 'eth_maxPriorityFeePerGas':
        return ok(toQuantity(1_000_000_000));
      case 'eth_sendRawTransaction': {
        const raw = String(p[0]);
        const t = Transaction.from(raw);
        if (t.chainId !== this.chainId) {
          return { jsonrpc: '2.0', id: req.id, error: { code: -32000, message: 'invalid chain id' } };
        }
        this.mine([raw]);
        return ok(keccak256(raw));
      }
      case 'eth_getTransactionByHash':
        return ok(this.txJson(String(p[0])));
      case 'eth_getTransactionReceipt':
        return ok(this.receiptJson(String(p[0])));
      default:
        return { jsonrpc: '2.0', id: req.id, error: { code: -32601, message: `method ${req.method} not supported` } };
    }
  }
}


/**
 * Publish P the way a publisher does (tzun-anchor/1 §7.2): a zero-value
 * transaction from `privateKey` to its own address whose calldata is exactly
 * `0x ‖ P`, sent over JSON-RPC to `rpcUrl` and waited for. Returns its hash.
 */
export async function publishOverRpc(privateKey: string, rpcUrl: string, p: string): Promise<string> {
  const provider = new JsonRpcProvider(rpcUrl);
  try {
    const wallet = new Wallet(privateKey, provider);
    const tx = await wallet.sendTransaction({ to: wallet.address, value: 0, data: '0x' + p.replace(/^0x/, '') });
    await tx.wait(1);
    return tx.hash;
  } finally {
    provider.destroy();
  }
}
