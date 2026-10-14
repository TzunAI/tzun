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
  N,
  Signature,
  SigningKey,
  Wallet,
  type BaseWallet,
  computeAddress,
  decodeRlp,
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

// ─── Signatures at the edges of tzun-anchor/1 §10.4 item 2 ─────────────────

/** ⌊n/2⌋ for the secp256k1 order n: the largest s EIP-2 allows. */
export const HALF_N = N / 2n;
export { N as SECP256K1_N };

/** The field prime of secp256k1. */
const P_FIELD = 2n ** 256n - 2n ** 32n - 977n;

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
  }
  return result;
}

/** Whether some point of secp256k1 has this x: x^3 + 7 is a square mod p. */
export function isXCoordinate(x: bigint): boolean {
  return modPow((x ** 3n + 7n) % P_FIELD, (P_FIELD - 1n) / 2n, P_FIELD) === 1n;
}

/** An envelope's type and its RLP fields. */
export function envelopeFields(raw: string): { type: 0 | 1 | 2; fields: RlpStructuredData[] } {
  const first = parseInt(raw.slice(2, 4), 16);
  const type = first >= 0xc0 ? 0 : (first as 1 | 2);
  return { type, fields: decodeRlp(type === 0 ? raw : '0x' + raw.slice(4)) as RlpStructuredData[] };
}

/** The envelope of these fields: `type ‖ rlp(fields)`, or `rlp(fields)` for legacy. */
export function encodeEnvelope(type: 0 | 1 | 2, fields: RlpStructuredData[]): string {
  const body = encodeRlp(fields);
  return type === 0 ? body : `0x0${type}${body.slice(2)}`;
}

/** `raw` carrying another signature, which no key need have made: `v` is a legacy v or a typed yParity. */
export function withSignature(raw: string, sig: { v: bigint; r: bigint; s: bigint }): string {
  const { type, fields } = envelopeFields(raw);
  const n = fields.length;
  return encodeEnvelope(type, [...fields.slice(0, n - 3), q(sig.v), q(sig.r), q(sig.s)]);
}

/** A signed envelope's own signature: legacy v or typed yParity, r and s. */
export function signatureOf(raw: string): { v: bigint; r: bigint; s: bigint } {
  const { fields } = envelopeFields(raw);
  const [v, r, s] = fields.slice(fields.length - 3).map((f) => BigInt(f === '0x' ? 0 : (f as string)));
  return { v, r, s };
}

/** The same signature with s above n/2: n - s with the other parity, which recovers the same key. */
export function highS(raw: string): string {
  const { type } = envelopeFields(raw);
  const { v, r, s } = signatureOf(raw);
  // Legacy: v 27 ↔ 28, and an EIP-155 v ↔ its partner (odd ↔ even).
  const flipped = type !== 0 ? v ^ 1n : v === 27n || v === 28n ? 55n - v : v % 2n === 1n ? v + 1n : v - 1n;
  return withSignature(raw, { v: flipped, r, s: N - s });
}

/**
 * The smallest r from which a public key recovers with this s and parity over
 * `digest`, and the address it recovers: a valid signature that no key was
 * asked to make, so s can sit anywhere in [1, n/2].
 */
export function firstRecoverableR(digest: string, s: bigint, yParity: 0 | 1): { r: bigint; sender: string } {
  let r = 1n;
  while (!isXCoordinate(r)) r++;
  const sig = Signature.from({ r: toBeHex(r, 32), s: toBeHex(s, 32), yParity });
  return { r, sender: computeAddress(SigningKey.recoverPublicKey(digest, sig)).toLowerCase() };
}

/** The smallest r that is no point's x-coordinate: no public key recovers from it. */
export function firstUnrecoverableR(): bigint {
  let r = 1n;
  while (isXCoordinate(r)) r++;
  return r;
}

/**
 * A signature over `digest` from which public-key recovery gives the point at
 * infinity: with R = (z / s) G and r = x(R), r^-1 (s R - z G) = O.
 */
export function infinitySignature(digest: string, s = 1n): { yParity: 0 | 1; r: bigint; s: bigint } {
  const z = BigInt(digest) % N;
  const k = (z * modPow(s, N - 2n, N)) % N;
  const point = SigningKey.computePublicKey(toBeHex(k, 32), false);
  const r = BigInt('0x' + point.slice(4, 68));
  const yParity = (BigInt('0x' + point.slice(68)) & 1n) === 1n ? 1 : 0;
  return { yParity, r, s };
}

/**
 * A legacy transaction `key` signs: EIP-155 for `chainId` when `eip155` (so
 * chain id 0 signs v 35 or 36), unprotected (v 27 or 28) otherwise, at the
 * first nonce from `nonce` whose signature has parity `yParity`.
 */
export function signLegacy(
  key: SigningKey,
  opts: { data: string; chainId?: bigint; eip155: boolean; yParity: 0 | 1; nonce?: number; to?: string },
): string {
  const chainId = opts.chainId ?? 0n;
  for (let nonce = opts.nonce ?? 0; nonce < (opts.nonce ?? 0) + 64; nonce++) {
    const body: RlpStructuredData[] = [q(nonce), q(2_000_000_000), q(30_000), opts.to ?? computeAddress(key.publicKey), '0x', opts.data];
    const unsigned = opts.eip155 ? [...body, q(chainId), '0x', '0x'] : body;
    const sig = key.sign(keccak256(encodeRlp(unsigned)));
    if (sig.yParity !== opts.yParity) continue;
    const v = opts.eip155 ? chainId * 2n + 35n + BigInt(sig.yParity) : 27n + BigInt(sig.yParity);
    return encodeRlp([...body, q(v), q(BigInt(sig.r)), q(BigInt(sig.s))]);
  }
  throw new Error('no nonce in 64 gives this parity');
}
