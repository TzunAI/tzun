/**
 * Offline EVM fixtures: real signed transactions, a transaction trie, block
 * headers and the proof that ties them together.
 *
 * Nothing here talks to a node. Transactions are signed by throwaway keys from
 * `Wallet.createRandom()`, and blocks are fabricated: a header is only the RLP
 * of its fields, so a test can mint one with any number, timestamp or
 * transactions root it likes. That is the point of the fabricated-header cases
 * in blockchain-evm-publication.test.ts: offline, everything but the sender's
 * signature is whatever the bundle says.
 *
 * The trie builder (src/anchoring/tx-trie.ts) is written independently of the
 * verifier's proof walker in src/attestation/blockchain.ts, so a bug in one
 * cannot certify the other. The Sepolia vector in
 * blockchain-evm-publication.test.ts checks the builder against a real block's
 * `transactionsRoot`.
 */
import {
  Wallet,
  type BaseWallet,
  encodeRlp,
  hexlify,
  keccak256,
  toBeHex,
  type RlpStructuredData,
} from 'ethers';

export const SEPOLIA = 11155111n;
export const MAINNET = 1n;

/** A random 32-byte value in 0x-prefixed hex, standing in for P. */
export function randomP(): string {
  return hexlify(Wallet.createRandom().privateKey).toLowerCase();
}

export interface AnchorTxOptions {
  type?: 0 | 1 | 2;
  chainId?: bigint;
  nonce?: number;
  /** Defaults to the signer's own address: the publisher's zero-value self-transaction. */
  to?: string | null;
  data: string;
}

/** Sign an anchor-shaped transaction offline and return its raw envelope. */
export async function signAnchorTx(wallet: BaseWallet, opts: AnchorTxOptions): Promise<string> {
  const type = opts.type ?? 2;
  const base = {
    type,
    chainId: opts.chainId ?? SEPOLIA,
    nonce: opts.nonce ?? 0,
    to: opts.to === undefined ? wallet.address : opts.to,
    value: 0n,
    data: opts.data,
    gasLimit: 30_000n,
  };
  if (type === 2) {
    return wallet.signTransaction({ ...base, maxFeePerGas: 3_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n });
  }
  if (type === 1) {
    return wallet.signTransaction({ ...base, gasPrice: 2_000_000_000n, accessList: [] });
  }
  return wallet.signTransaction({ ...base, gasPrice: 2_000_000_000n });
}

// ─── The transactions trie ─────────────────────────────────────────────────

// The builder lives with the anchor scheduler, which stores the proofs it
// builds (src/anchoring/tx-trie.ts). It shares no code with the verifier's
// proof walker in src/attestation/blockchain.ts.
export { buildTxTrie, txKey, type BuiltTrie } from '../../../src/anchoring/tx-trie';
import { buildTxTrie, type BuiltTrie } from '../../../src/anchoring/tx-trie';

// ─── Block headers ─────────────────────────────────────────────────────────

const q = (n: bigint | number): string => (BigInt(n) === 0n ? '0x' : toBeHex(BigInt(n)));

export interface HeaderFields {
  parentHash?: string;
  number: number;
  timestamp: number;
  transactionsRoot: string;
}

/**
 * A post-Prague header: the fifteen original fields, then base fee,
 * withdrawals root, blob gas used, excess blob gas, parent beacon root and
 * requests hash. The block hash is keccak256 of this RLP.
 */
export function buildHeader(f: HeaderFields): { rlp: string; hash: string } {
  const z32 = '0x' + '00'.repeat(32);
  const fields: RlpStructuredData[] = [
    f.parentHash ?? '0x' + '11'.repeat(32),
    '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347',
    '0x' + '22'.repeat(20),
    '0x' + '33'.repeat(32),
    f.transactionsRoot,
    '0x' + '44'.repeat(32),
    '0x' + '00'.repeat(256),
    q(0),
    q(f.number),
    q(30_000_000),
    q(21_000),
    q(f.timestamp),
    '0x',
    z32,
    '0x' + '00'.repeat(8),
    q(7),
    z32,
    q(0),
    q(0),
    z32,
    z32,
  ];
  const rlp = encodeRlp(fields);
  return { rlp, hash: keccak256(rlp) };
}

// ─── A whole publication ───────────────────────────────────────────────────

export interface FabricatedBlock {
  number: number;
  timestamp: number;
  hash: string;
  header: string;
  raws: string[];
  trie: BuiltTrie;
}

/** A block containing `raws` in order, with a header that commits to them. */
export function fabricateBlock(raws: string[], number = 7_123_456, timestamp = 1_790_000_000): FabricatedBlock {
  const trie = buildTxTrie(raws);
  const { rlp, hash } = buildHeader({ number, timestamp, transactionsRoot: trie.root });
  return { number, timestamp, hash, header: rlp, raws, trie };
}

/** The §9 bundle form of the publication of `raws[index]` in `block`. */
export function publicationFrom(block: FabricatedBlock, index: number) {
  const raw = block.raws[index];
  return {
    kind: 'evm-calldata/1' as const,
    transactionId: keccak256(raw),
    rawTransaction: raw,
    blockNumber: block.number,
    blockHash: block.hash,
    blockHeader: block.header,
    txIndex: index,
    txProof: block.trie.proof(index),
  };
}
