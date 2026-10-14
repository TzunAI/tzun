/**
 * The heavy EVM material a publication stores when it is final (tzun-anchor/1
 * §7.2 rule 4, §11 item 3): the block header's RLP and the transaction's
 * proof in the block's transactions trie.
 *
 * Both are built here from what a JSON-RPC node returns, and neither is
 * trusted by its builder: the header's keccak256 must be the block hash the
 * node reported, and the trie's root must be the header's `transactionsRoot`.
 * The stored proof is then walked by the verifier's own implementation
 * (`verifyEvmTransactionProof` in src/attestation/blockchain.ts), which shares
 * no code with the builder below, so a bug in one cannot certify the other.
 */
import { encodeRlp, getBytes, hexlify, keccak256, toBeHex, type RlpStructuredData } from 'ethers';

function nibblesOf(hex: string): number[] {
  const out: number[] = [];
  for (const b of getBytes(hex)) out.push(b >> 4, b & 0x0f);
  return out;
}

/** Hex-prefix encoding (Yellow Paper appendix C). */
function hexPrefix(nibbles: number[], leaf: boolean): string {
  const flag = (leaf ? 2 : 0) + (nibbles.length % 2);
  const all = nibbles.length % 2 === 1 ? [flag, ...nibbles] : [flag, 0, ...nibbles];
  const bytes = new Uint8Array(all.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = (all[2 * i] << 4) | all[2 * i + 1];
  return hexlify(bytes);
}

function hexPrefixDecode(hp: string): { nibbles: number[]; leaf: boolean } {
  const n = nibblesOf(hp);
  const leaf = n[0] >= 2;
  return { nibbles: n[0] % 2 === 1 ? n.slice(1) : n.slice(2), leaf };
}

/** The trie key of transaction `index`: `rlp(index)`. */
export function txKey(index: number): string {
  return encodeRlp(index === 0 ? '0x' : toBeHex(index));
}

export interface BuiltTrie {
  root: string;
  /** Proof nodes, root first, for the transaction at `index`. */
  proof(index: number): string[];
}

/**
 * Build the transactions trie of a block whose transactions are `raws`, in
 * block order. The value at key rlp(i) is the i-th transaction's envelope:
 * `type ‖ rlp(payload)` for a typed transaction, `rlp(tx)` for a legacy one,
 * which is exactly the raw signed transaction either way.
 */
export function buildTxTrie(raws: string[]): BuiltTrie {
  const db = new Map<string, RlpStructuredData>();
  const ref = (node: RlpStructuredData): RlpStructuredData => {
    const enc = encodeRlp(node);
    if (getBytes(enc).length < 32) return node;
    const h = keccak256(enc);
    db.set(h, node);
    return h;
  };
  type Entry = { k: number[]; v: string };
  const build = (entries: Entry[], depth: number): RlpStructuredData => {
    if (entries.length === 1) return [hexPrefix(entries[0].k.slice(depth), true), entries[0].v];
    let len = 0;
    for (;;) {
      const at = depth + len;
      if (entries.some((e) => e.k.length <= at)) break;
      const nib = entries[0].k[at];
      if (!entries.every((e) => e.k[at] === nib)) break;
      len++;
    }
    if (len > 0) {
      return [hexPrefix(entries[0].k.slice(depth, depth + len), false), ref(build(entries, depth + len))];
    }
    const branch: RlpStructuredData[] = new Array(17).fill('0x');
    for (let nib = 0; nib < 16; nib++) {
      const group = entries.filter((e) => e.k.length > depth && e.k[depth] === nib);
      if (group.length > 0) branch[nib] = ref(build(group, depth + 1));
    }
    const terminal = entries.find((e) => e.k.length === depth);
    if (terminal) branch[16] = terminal.v;
    return branch;
  };

  const entries = raws.map((v, i) => ({ k: nibblesOf(txKey(i)), v: v.toLowerCase() }));
  if (entries.length === 0) {
    // The empty trie's root is keccak256(rlp('')), and it proves nothing.
    return { root: keccak256(encodeRlp('0x')), proof: () => [] };
  }
  const rootNode = build(entries, 0);
  const root = keccak256(encodeRlp(rootNode));

  return {
    root,
    proof(index: number): string[] {
      const key = nibblesOf(txKey(index));
      const out = [encodeRlp(rootNode)];
      let node = rootNode as RlpStructuredData[];
      let d = 0;
      const follow = (child: RlpStructuredData): RlpStructuredData[] | null => {
        if (typeof child === 'string') {
          if (child === '0x') return null;
          const next = db.get(child)!;
          out.push(encodeRlp(next));
          return next as RlpStructuredData[];
        }
        return child as RlpStructuredData[];
      };
      for (;;) {
        if (node.length === 17) {
          if (d === key.length) break;
          const next = follow(node[key[d]]);
          d++;
          if (!next) break;
          node = next;
        } else {
          const { nibbles, leaf } = hexPrefixDecode(node[0] as string);
          if (leaf) break;
          d += nibbles.length;
          const next = follow(node[1]);
          if (!next) break;
          node = next;
        }
      }
      return out;
    },
  };
}

/** A block as `eth_getBlockByNumber` returns it: hex quantities and data. */
export type JsonRpcBlock = Record<string, unknown> & { hash: string; number: string; transactionsRoot: string };

/**
 * The header fields, in RLP order. The optional ones are appended by later
 * forks: `baseFeePerGas` (London), `withdrawalsRoot` (Shanghai),
 * `blobGasUsed`, `excessBlobGas` and `parentBeaconBlockRoot` (Cancun),
 * `requestsHash` (Prague), `blockAccessListHash` (EIP-7928) and `slotNumber`
 * (EIP-7843), both Amsterdam (Glamsterdam). A block carries a prefix of them.
 */
const HEADER_FIELDS: Array<{ name: string; quantity: boolean; optional: boolean }> = [
  { name: 'parentHash', quantity: false, optional: false },
  { name: 'sha3Uncles', quantity: false, optional: false },
  { name: 'miner', quantity: false, optional: false },
  { name: 'stateRoot', quantity: false, optional: false },
  { name: 'transactionsRoot', quantity: false, optional: false },
  { name: 'receiptsRoot', quantity: false, optional: false },
  { name: 'logsBloom', quantity: false, optional: false },
  { name: 'difficulty', quantity: true, optional: false },
  { name: 'number', quantity: true, optional: false },
  { name: 'gasLimit', quantity: true, optional: false },
  { name: 'gasUsed', quantity: true, optional: false },
  { name: 'timestamp', quantity: true, optional: false },
  { name: 'extraData', quantity: false, optional: false },
  { name: 'mixHash', quantity: false, optional: false },
  { name: 'nonce', quantity: false, optional: false },
  { name: 'baseFeePerGas', quantity: true, optional: true },
  { name: 'withdrawalsRoot', quantity: false, optional: true },
  { name: 'blobGasUsed', quantity: true, optional: true },
  { name: 'excessBlobGas', quantity: true, optional: true },
  { name: 'parentBeaconBlockRoot', quantity: false, optional: true },
  { name: 'requestsHash', quantity: false, optional: true },
  { name: 'blockAccessListHash', quantity: false, optional: true },
  { name: 'slotNumber', quantity: true, optional: true },
];

/**
 * The RLP of a block's header, rebuilt from the node's JSON, or `null` when
 * the rebuild does not hash to the block hash the node reported (a field this
 * code does not know, or a node that reports a field it should not). An
 * optional field is included while every one before it is present.
 */
export function blockHeaderRlp(block: JsonRpcBlock): string | null {
  const fields: RlpStructuredData[] = [];
  for (const f of HEADER_FIELDS) {
    const value = block[f.name];
    if (value === undefined || value === null) {
      if (f.optional) break;
      return null;
    }
    if (typeof value !== 'string') return null;
    fields.push(f.quantity ? (BigInt(value) === 0n ? '0x' : toBeHex(BigInt(value))) : value);
  }
  const rlp = encodeRlp(fields);
  return keccak256(rlp) === block.hash.toLowerCase() ? rlp : null;
}
