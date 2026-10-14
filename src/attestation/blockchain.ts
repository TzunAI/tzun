import {
  FetchRequest,
  JsonRpcProvider,
  Network,
  Transaction,
  decodeRlp,
  encodeRlp,
  getBytes,
  keccak256,
  toBeHex,
  type AccessList,
  type RlpStructuredData,
  type Signature,
} from 'ethers';
import type { EvmFinality, PublisherManifest, PublisherManifestEntry } from '@tzun/engine';

// ─── EVM publication verification ──────────────────────────────────────────
//
// An `evm-calldata/1` publication is a transaction whose calldata is exactly
// `0x ‖ P`, where P is the 32-byte value the anchor commits to. This module
// treats P as opaque: it never assumes how P was derived.
//
// A calldata anchor is a statement by the transaction's SIGNER. The verifier
// therefore recovers the sender from the raw signed transaction and checks it
// against the publishers the verifier's own manifest lists for the anchor
// origin. The recipient (`to`) is not checked: anyone can send a transaction to
// any address, so `to` says nothing about who published.
//
// Offline, everything in a publication except the sender's signature comes
// from the bundle: the raw transaction, the header, the trie proof, the block
// hash, the block time and the chain. Those facts alone prove only that the
// publisher key signed a transaction carrying P. A publication is `true` only
// once the verifier's own header source confirms the block is canonical at
// finalized depth; until then it is `null`, `publication_not_checked`.

/**
 * Why an `evm-calldata/1` publication came out the way it did.
 *
 * `false` reasons: the publication was decided and fails.
 * `null` reasons: the verifier could not decide (`publication_not_checked`), or
 * the publication names a construction it does not implement (`unsupported_*`).
 */
export type EvmPublicationReason =
  /** The transaction's calldata is not exactly `0x ‖ P`. */
  | 'evm_calldata_mismatch'
  /**
   * The recovered sender is not a publisher the manifest lists for this anchor
   * origin, or it was not one at the block time.
   */
  | 'evm_sender_mismatch'
  /**
   * The chain id the sender signed is not the manifest entry's CAIP-2 chain.
   * A pre-EIP-155 legacy transaction signs no chain id and always fails here.
   */
  | 'evm_chain_mismatch'
  /**
   * The bundle's transaction material does not hold together: `keccak(raw)` is
   * not the transaction id, the header does not hash to the block hash or names
   * another block number, or the trie proof does not place this transaction
   * under the header's `transactionsRoot`.
   */
  | 'evm_tx_proof_invalid'
  /** The verifier's header source says the block, or the transaction's place in it, is not canonical. */
  | 'anchor_not_found_on_chain'
  /** The publication is present but unreadable: a field is missing, mistyped, or the raw transaction does not parse or is unsigned. */
  | 'malformed_publication'
  /** Not decided. `checks` names what was missing: see {@link EvmNotCheckedReason}. */
  | 'publication_not_checked'
  /** The publication's `kind` is not `evm-calldata/1`. */
  | 'unsupported_publication_kind'
  /** The transaction is not legacy (EIP-155), EIP-2930 or EIP-1559. */
  | 'unsupported_evm_tx_type';

/** Why a check was `not-checked`. Detail under a `publication_not_checked` verdict. */
export type EvmNotCheckedReason =
  /** No header source was supplied for the manifest entry's chain. */
  | 'input_not_supplied:evm_header_source'
  /** A manifest entry for this origin is malformed, so the manifest cannot be read. */
  | 'input_not_supplied:publisher_manifest'
  /** P is not 32 bytes of hex. */
  | 'input_not_supplied:p'
  /** The manifest lists no publisher for this anchor origin. */
  | 'no_expectation:publisher'
  /** The publication carries no raw signed transaction, so no sender can be recovered. */
  | 'not_in_bundle:raw_transaction'
  /**
   * Nothing places the transaction in the block: the bundle carries no trie
   * proof, and the header source cannot look the transaction up.
   */
  | 'not_in_bundle:tx_proof'
  /**
   * The bundle carries no block header, so a trie proof it carries cannot be
   * walked, and a publisher's validity window has no block time until the
   * header source confirms one.
   */
  | 'not_in_bundle:block_header'
  /** The header source's own chain id is not the manifest entry's chain. */
  | 'evm_header_source_chain_mismatch'
  /** The header source failed or answered with something unusable. */
  | 'evm_header_source_unavailable'
  /** The header source did not answer before the verification's deadline (`timeoutMs`). */
  | 'evm_header_source_timeout'
  /** The block is above the header source's finalized height. */
  | 'evm_block_not_finalized'
  /**
   * The header source contradicts itself or the signed transaction: it reports
   * another sender, no block for a finalized height, another timestamp for a
   * block whose header hashes to it, or a transaction in a block it does not
   * call canonical.
   */
  | 'evm_header_source_inconsistent'
  /** An earlier check failed and this one depends on it. */
  | 'blocked_by:anchor.evm.tx'
  /** An unforeseen failure inside the verifier. A bug to report, never a verdict on the publication. */
  | 'evm_verifier_error';

/** The four outcomes of Verification §2.1, per check. */
export type EvmCheckOutcome = 'checked-correct' | 'checked-wrong' | 'not-checked' | 'abstain';

export interface EvmCheckResult {
  id: 'anchor.evm.tx' | 'anchor.evm.canonical';
  outcome: EvmCheckOutcome;
  /** `true` for checked-correct, `false` for checked-wrong, `null` otherwise. */
  value: boolean | null;
  reason?: EvmPublicationReason | EvmNotCheckedReason;
}

// The publisher manifest (tzun-anchor/1 §9) is declared in @tzun/engine,
// where the anchoring config's activation guard reads it too.
export type { PublisherManifest, PublisherManifestEntry };

/**
 * An `evm-calldata/1` publication: the record's publication entry
 * (tzun-anchor/1 §8.2) joined with the heavy material the export bundle
 * carries (Bundle §7.4).
 *
 * `rawTransaction`, `blockNumber` and `blockHash` are required to decide
 * anything. `blockHeader`, `txIndex` and `txProof` together place the
 * transaction in the block offline; a proof is walked only under the header.
 * Without them, only a header source that can look the transaction up can
 * place it. `null` reads as absent for every optional field.
 */
export interface EvmCalldataPublication {
  kind: 'evm-calldata/1';
  /** When present, must equal `keccak256(rawTransaction)`. */
  transactionId?: string;
  /** The signed transaction envelope, `0x` hex: `type ‖ rlp(payload)`, or `rlp(tx)` for legacy. */
  rawTransaction?: string;
  blockNumber: number;
  blockHash: string;
  /** The block header's RLP, `0x` hex. Its keccak256 must be `blockHash`. */
  blockHeader?: string;
  /** The transaction's index in the block: its trie key is `rlp(txIndex)`. */
  txIndex?: number;
  /** Transactions-trie proof nodes, root first, each `0x` hex RLP. */
  txProof?: string[];
  /** Display only; never trusted. The chain comes from the manifest. */
  chain?: string;
  /** Display only; never trusted. The sender is recovered from the signature. */
  publisher?: string;
}

/** A transaction as a header source's node reports it. */
export interface EvmSourceTransaction {
  from: string;
  blockHash: string | null;
  blockNumber: number | null;
  /** The signed envelope, when the source could reassemble it. */
  rawTransaction?: string;
}

/**
 * The verifier's own view of a chain. Supplied by the auditor, never by the
 * artifact. {@link RpcEvmHeaderSource} reads one over JSON-RPC.
 */
export interface EvmHeaderSource {
  /**
   * What this source counts as final (see {@link EvmFinality}), when it says.
   * Reported with every verdict the source took part in (the fact `finality`,
   * and `anchorFinality` on a record's anchor), so a result judged under a
   * confirmation depth is never read as one judged at the chain's
   * `finalized` block. {@link RpcEvmHeaderSource} always says.
   */
  readonly finality?: EvmFinality;
  /** The EIP-155 chain id of the network this source reads. */
  chainId(): Promise<bigint>;
  /** The height of the newest block this source considers final. */
  finalizedBlockNumber(): Promise<number>;
  /** The canonical block at `blockNumber`, or `null` when the source has none there. */
  canonicalBlock(blockNumber: number): Promise<{ hash: string; timestamp: number } | null>;
  /** Optional: the transaction as the source's node sees it, for a cross-check and for inclusion. */
  transaction?(transactionId: string): Promise<EvmSourceTransaction | null>;
}

export type EvmNetwork = 'mainnet' | 'testnet';

/**
 * The verifier's registry from CAIP-2 chain to network (tzun-anchor/1 §9):
 * Ethereum mainnet, and the Sepolia and Hoodi test networks. Other chains
 * report `network: null` unless the caller's `networks` names them; a chain
 * added here later reads as `null` to a verifier released before it, which
 * under-claims.
 */
export const DEFAULT_EVM_NETWORKS: Readonly<Record<string, EvmNetwork>> = Object.freeze({
  'eip155:1': 'mainnet',
  'eip155:11155111': 'testnet',
  'eip155:560048': 'testnet',
});

export interface EvmPublicationInput {
  /** Untrusted: validated field by field. */
  publication: EvmCalldataPublication;
  /** The 32 bytes the publication must carry, as hex with or without `0x`. */
  p: string;
  /** The anchor origin whose manifest entries may publish P. */
  anchorOrigin: string;
  manifest: PublisherManifest;
  /** Header sources keyed by canonical CAIP-2 chain (`eip155:11155111`). */
  headerSources?: Record<string, EvmHeaderSource>;
  /** Overrides or extends {@link DEFAULT_EVM_NETWORKS}. */
  networks?: Record<string, EvmNetwork>;
  /**
   * One deadline for every header-source call this verification makes, in
   * milliseconds. Default {@link DEFAULT_EVM_TIMEOUT_MS}. A call still
   * pending at the deadline makes the publication `null`,
   * `evm_header_source_timeout`.
   */
  timeoutMs?: number;
}

/** The default deadline for one verification's header-source calls. */
export const DEFAULT_EVM_TIMEOUT_MS = 30_000;

export interface EvmPublicationFacts {
  /** `keccak256(rawTransaction)`. */
  transactionId?: string;
  txType?: number;
  /** Recovered from the signature. Reported whatever the verdict. */
  sender?: string;
  /** The chain id the sender signed, in decimal; `'0'` for a pre-EIP-155 transaction. */
  signedChainId?: string;
  /** As the publication claims it. Confirmed only when `valid` is `true`. */
  blockNumber?: number;
  /** As the publication claims it. Confirmed only when `valid` is `true`. */
  blockHash?: string;
  /** What placed the transaction in the block: a verified trie proof, or the header source's own lookup. */
  inclusion?: 'tx_proof' | 'header_source';
  /** Set only when `valid` is `true`: the manifest entry's CAIP-2 chain. */
  chain?: string;
  /** Set only when `valid` is `true`: the manifest entry's namespace, or `null` if matching entries disagree. */
  namespace?: 'production' | 'test' | null;
  /** Set only when `valid` is `true`: from the manifest entry's chain through the verifier's registry. */
  network?: EvmNetwork | null;
  /** Set only when `valid` is `true`: the block time the header source confirmed, ISO 8601. */
  blockTime?: string;
  /**
   * What the header source counts as final, as it declares it: set once the
   * source has been asked for its finalized height, whatever the verdict, so
   * `evm_block_not_finalized` can be read against it. Absent when the source
   * declares nothing.
   */
  finality?: EvmFinality;
}

export interface EvmPublicationVerdict {
  /** `true`: decided and holds. `false`: decided and fails. `null`: not decided, or abstained. */
  valid: boolean | null;
  reason?: EvmPublicationReason;
  checks: { tx: EvmCheckResult; canonical: EvmCheckResult };
  facts: EvmPublicationFacts;
}

const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const EIP155 = /^eip155:([1-9][0-9]{0,30})$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/;

/**
 * A manifest's RFC 3339 timestamp (tzun-anchor/1 §9) at full precision, or
 * `undefined`: the instant is `seconds`, in unix seconds, plus a fraction of a
 * second that is non-zero exactly when `fractional` is true. An offset is
 * whole minutes, so it never moves the fraction. Every field is range-checked,
 * so an impossible date (`2026-09-31`, `T24:00:00Z`, a second of 60) is
 * refused rather than rolled over. The fraction's digits are only tested for
 * zero, never converted to a number of milliseconds: `Date.parse` reads
 * `.0005` as `.000`, and in V8 reads `.0001234567` as 1 ms. The Python SDK's
 * `rfc3339_seconds` reads the same value.
 */
function rfc3339Seconds(value: string): { seconds: number; fractional: boolean } | undefined {
  const m = RFC3339.exec(value);
  if (!m) return undefined;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const daysIn = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > daysIn[month - 1]) return undefined;
  if (hour > 23 || minute > 59 || second > 59) return undefined;
  let offsetSeconds = 0;
  if (m[9] !== undefined) {
    const offsetHour = Number(m[9]);
    const offsetMinute = Number(m[10]);
    if (offsetHour > 23 || offsetMinute > 59) return undefined;
    offsetSeconds = (m[8][0] === '+' ? 1 : -1) * (offsetHour * 60 + offsetMinute) * 60;
  }
  // setUTCFullYear, not Date.UTC, which reads a year below 100 as 1900 + year.
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  return { seconds: date.getTime() / 1000 - offsetSeconds, fractional: /[1-9]/.test(m[7] ?? '') };
}

/**
 * A copy of the finality a header source declares, or `undefined` when it
 * declares none or something that is not an {@link EvmFinality}. Never throws:
 * the source is the verifier's own input, but a copy keeps a caller's later
 * edit out of a result already returned.
 */
function declaredFinality(source: EvmHeaderSource): EvmFinality | undefined {
  try {
    const f = source.finality;
    if (f === 'finalized') return 'finalized';
    if (f !== null && typeof f === 'object' && Number.isSafeInteger(f.confirmations) && f.confirmations >= 1) {
      return f.acceptNonFinal === true ? { confirmations: f.confirmations, acceptNonFinal: true } : { confirmations: f.confirmations };
    }
  } catch {
    // A getter that throws declares nothing.
  }
  return undefined;
}

/** Raised by {@link withDeadline} when the deadline passes first. */
class DeadlineExceeded extends Error {
  constructor() {
    super('deadline exceeded');
  }
}

/** The longest delay `setTimeout` honours: Node runs a longer one after 1 ms. */
const MAX_TIMER_DELAY_MS = 2_147_483_647;

/**
 * `work`, or a {@link DeadlineExceeded} rejection at `deadline` (epoch ms),
 * whichever comes first. A deadline further off than `setTimeout` can wait is
 * reached in steps of at most {@link MAX_TIMER_DELAY_MS}. The timer is cleared
 * either way and never holds a process open.
 */
function withDeadline<T>(work: () => Promise<T> | T, deadline: number): Promise<T> {
  if (deadline - Date.now() <= 0) return Promise.reject(new DeadlineExceeded());
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expiry = new Promise<never>((_resolve, reject) => {
    const arm = () => {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        reject(new DeadlineExceeded());
        return;
      }
      timer = setTimeout(arm, Math.min(remaining, MAX_TIMER_DELAY_MS));
      (timer as { unref?: () => void }).unref?.();
    };
    arm();
  });
  return Promise.race([Promise.resolve().then(work), expiry]).finally(() => clearTimeout(timer));
}

function isHex(value: unknown): value is string {
  return typeof value === 'string' && /^0x([0-9a-fA-F]{2})*$/.test(value);
}

/** The chain id of an `eip155:<id>` CAIP-2 chain, or `null` for anything else. */
function eip155ChainId(caip2: unknown): bigint | null {
  if (typeof caip2 !== 'string') return null;
  const m = EIP155.exec(caip2);
  return m ? BigInt(m[1]) : null;
}

/**
 * The most lists an RLP item may sit inside, its own included: a top-level list
 * is at depth 1. No header, transactions-trie node or transaction the verifier
 * reads comes near it. `MAX_RLP_DEPTH` in the Python SDK's `evm_rlp` is the
 * same number.
 */
export const MAX_RLP_DEPTH = 64;

/**
 * Whether no list in `data` sits more than `MAX_RLP_DEPTH` lists deep, read
 * without recursion. It follows the prefixes of a well-formed item exactly; on
 * a malformed one it only has to stop, because `decodeRlp` refuses that anyway.
 */
function rlpDepthWithinLimit(data: Uint8Array): boolean {
  const ends: number[] = [];
  let pos = 0;
  while (pos < data.length) {
    while (ends.length > 0 && pos >= ends[ends.length - 1]) ends.pop();
    const prefix = data[pos];
    if (prefix < 0x80) {
      pos += 1;
      continue;
    }
    const long = prefix >= 0xf8 || (prefix >= 0xb8 && prefix < 0xc0);
    const lengthLength = long ? prefix - (prefix >= 0xc0 ? 0xf7 : 0xb7) : 0;
    let length = long ? 0 : prefix - (prefix >= 0xc0 ? 0xc0 : 0x80);
    for (let i = 1; i <= lengthLength; i++) length = length * 256 + (data[pos + i] ?? 0);
    const start = pos + 1 + lengthLength;
    if (prefix < 0xc0) {
      pos = start + length;
      continue;
    }
    if (ends.length >= MAX_RLP_DEPTH) return false;
    if (length > 0) ends.push(start + length);
    pos = start;
  }
  return true;
}

/**
 * ethers' `decodeRlp`, refusing first an item nested more than
 * {@link MAX_RLP_DEPTH} lists deep. `decodeRlp` recurses once per level, so
 * without the limit the depth at which it gives up would be the host's stack
 * size. Throws what `decodeRlp` throws, or an `Error` for the depth.
 */
export function decodeEvmRlp(hex: string): RlpStructuredData {
  if (!rlpDepthWithinLimit(getBytes(hex))) throw new Error('RLP lists nested too deep');
  return decodeRlp(hex);
}

/** An RLP scalar as a safe integer: `0x` is 0, and a leading zero byte is not canonical. */
function rlpSafeInt(item: RlpStructuredData): number | null {
  if (typeof item !== 'string' || !isHex(item)) return null;
  if (item === '0x') return 0;
  if (item.startsWith('0x00')) return null;
  const n = BigInt(item);
  return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : null;
}

export interface EvmBlockHeader {
  /** keccak256 of the header RLP. */
  hash: string;
  number: number;
  /** Unix seconds. */
  timestamp: number;
  transactionsRoot: string;
}

/**
 * Read the fields a publication check needs from a block header's RLP:
 * `transactionsRoot` (field 4), `number` (8) and `timestamp` (11). Returns
 * `null` for anything that is not an RLP list of at least the fifteen original
 * header fields, or whose three read fields are not byte strings of the right
 * form. Other fields are not read, whatever their shape. Never throws.
 */
export function parseEvmBlockHeader(rlp: string): EvmBlockHeader | null {
  try {
    if (!isHex(rlp)) return null;
    const fields = decodeEvmRlp(rlp);
    if (!Array.isArray(fields) || fields.length < 15) return null;
    const transactionsRoot = fields[4];
    if (typeof transactionsRoot !== 'string' || !HEX32.test(transactionsRoot)) return null;
    const number = rlpSafeInt(fields[8]);
    const timestamp = rlpSafeInt(fields[11]);
    if (number === null || timestamp === null) return null;
    return { hash: keccak256(rlp), number, timestamp, transactionsRoot: transactionsRoot.toLowerCase() };
  } catch {
    return null;
  }
}

function nibblesOf(bytes: Uint8Array): number[] {
  const out: number[] = [];
  for (const b of bytes) out.push(b >> 4, b & 0x0f);
  return out;
}

/** Hex-prefix decoding (Yellow Paper appendix C). */
function decodeHexPrefix(path: string): { leaf: boolean; nibbles: number[] } | null {
  const n = nibblesOf(getBytes(path));
  if (n.length === 0 || n[0] > 3) return null;
  const odd = (n[0] & 1) === 1;
  if (!odd && n[1] !== 0) return null;
  return { leaf: n[0] >= 2, nibbles: n.slice(odd ? 1 : 2) };
}

function sameNibbles(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/**
 * Walk a Merkle-Patricia proof for transaction `txIndex` (key `rlp(txIndex)`)
 * from `transactionsRoot`, and return the value it proves: the transaction's
 * signed envelope. Returns `null` when the proof is broken, proves the key
 * absent, or carries nodes it never uses. Never throws.
 */
export function verifyEvmTransactionProof(
  transactionsRoot: string,
  txIndex: number,
  proof: readonly string[],
): string | null {
  try {
    if (!HEX32.test(transactionsRoot) || !Number.isSafeInteger(txIndex) || txIndex < 0) return null;
    if (!Array.isArray(proof) || proof.length === 0 || !proof.every(isHex)) return null;

    const key = nibblesOf(getBytes(encodeRlp(txIndex === 0 ? '0x' : toBeHex(txIndex))));
    let expected = transactionsRoot.toLowerCase();
    let pos = 0;
    let used = 0;
    let node: RlpStructuredData | null = null;

    for (;;) {
      if (node === null) {
        if (used >= proof.length) return null;
        const encoded = proof[used++];
        if (keccak256(encoded) !== expected) return null;
        node = decodeEvmRlp(encoded);
      }
      if (!Array.isArray(node)) return null;

      let next: RlpStructuredData;
      if (node.length === 17) {
        if (pos === key.length) {
          const value = node[16];
          return typeof value === 'string' && value !== '0x' && used === proof.length ? value : null;
        }
        next = node[key[pos++]];
      } else if (node.length === 2) {
        if (typeof node[0] !== 'string') return null;
        const hp = decodeHexPrefix(node[0]);
        if (!hp) return null;
        if (hp.leaf) {
          if (!sameNibbles(key.slice(pos), hp.nibbles)) return null;
          const value = node[1];
          return typeof value === 'string' && used === proof.length ? value : null;
        }
        if (hp.nibbles.length === 0 || !sameNibbles(key.slice(pos, pos + hp.nibbles.length), hp.nibbles)) {
          return null;
        }
        pos += hp.nibbles.length;
        next = node[1];
      } else {
        return null;
      }

      if (Array.isArray(next)) {
        node = next; // an embedded node, under 32 bytes, carried inside its parent
        continue;
      }
      if (typeof next !== 'string' || !HEX32.test(next)) return null;
      expected = next.toLowerCase();
      node = null;
    }
  } catch {
    return null;
  }
}

interface ParsedEntry {
  address: string;
  chainId: bigint;
  chain: string;
  namespace: 'production' | 'test';
  /** The first whole unix second the entry is valid at: `validFrom` rounded up. `null` when unbounded. */
  firstSecond: number | null;
  /** The last whole unix second the entry is valid at: `validUntil` rounded down. `null` when unbounded. */
  lastSecond: number | null;
}

/**
 * The EVM entries for one origin, normalised. `undefined` when an EVM entry is
 * malformed; entries in other CAIP-2 namespaces are skipped.
 */
function evmEntriesFor(manifest: unknown, origin: unknown): ParsedEntry[] | undefined {
  if (typeof origin !== 'string' || !manifest || typeof manifest !== 'object') return [];
  const publishers = (manifest as PublisherManifest).publishers;
  if (!publishers || typeof publishers !== 'object') return [];
  const entries = Object.prototype.hasOwnProperty.call(publishers, origin) ? publishers[origin] : undefined;
  if (entries === undefined) return [];
  if (!Array.isArray(entries)) return undefined;

  const out: ParsedEntry[] = [];
  for (const e of entries) {
    if (!e || typeof e !== 'object') return undefined;
    if (typeof e.chain !== 'string') return undefined;
    if (!e.chain.startsWith('eip155:')) continue;
    const chainId = eip155ChainId(e.chain);
    if (chainId === null) return undefined;
    if (typeof e.address !== 'string' || !ADDRESS.test(e.address)) return undefined;
    if (e.namespace !== 'production' && e.namespace !== 'test') return undefined;
    const bound = (v: unknown) => {
      if (v === undefined || v === null) return null;
      return typeof v === 'string' ? rfc3339Seconds(v) : undefined;
    };
    const from = bound(e.validFrom);
    const until = bound(e.validUntil);
    if (from === undefined || until === undefined) return undefined;
    // Both ends are inclusive and compared at full precision (tzun-anchor/1
    // §9). A block time is a whole second, so that is validFrom rounded up and
    // validUntil rounded down to the whole second.
    out.push({
      address: e.address.toLowerCase(),
      chainId,
      chain: `eip155:${chainId}`,
      namespace: e.namespace,
      firstSecond: from === null ? null : from.seconds + (from.fractional ? 1 : 0),
      lastSecond: until === null ? null : until.seconds,
    });
  }
  return out;
}

function validAt(entry: ParsedEntry, unixSeconds: number): boolean {
  return (
    (entry.firstSecond === null || entry.firstSecond <= unixSeconds) &&
    (entry.lastSecond === null || unixSeconds <= entry.lastSecond)
  );
}

/**
 * A manifest's EVM publisher entry for one anchor origin, read as the
 * verifier reads it (tzun-anchor/1 §9): the address lowercased, the chain in
 * canonical CAIP-2, and the validity window as whole unix seconds, both ends
 * inclusive (`validFrom` rounded up, `validUntil` rounded down; `null` when
 * unbounded).
 */
export interface EvmPublisherWindow {
  address: string;
  chain: string;
  namespace: 'production' | 'test';
  firstSecond: number | null;
  lastSecond: number | null;
}

/**
 * The EVM entries `manifest` lists for `anchorOrigin`, exactly as
 * `verifyEvmPublication` reads them, or `undefined` when an EVM entry for the
 * origin is malformed (the verifier's `input_not_supplied:publisher_manifest`).
 * Entries in other CAIP-2 namespaces are skipped. The anchor scheduler takes
 * the publishers it accepts from here.
 */
export function readEvmPublisherWindows(manifest: unknown, anchorOrigin: string): EvmPublisherWindow[] | undefined {
  return evmEntriesFor(manifest, anchorOrigin)?.map(({ address, chain, namespace, firstSecond, lastSecond }) => ({
    address,
    chain,
    namespace,
    firstSecond,
    lastSecond,
  }));
}

/** Whether `entry`'s validity window contains `unixSeconds`, both ends inclusive. */
export function publisherValidAt(entry: Pick<EvmPublisherWindow, 'firstSecond' | 'lastSecond'>, unixSeconds: number): boolean {
  return validAt(entry as ParsedEntry, unixSeconds);
}

const TX_CHECK = 'anchor.evm.tx' as const;
const CANONICAL_CHECK = 'anchor.evm.canonical' as const;

function check(
  id: EvmCheckResult['id'],
  outcome: EvmCheckOutcome,
  reason?: EvmPublicationReason | EvmNotCheckedReason,
): EvmCheckResult {
  const value = outcome === 'checked-correct' ? true : outcome === 'checked-wrong' ? false : null;
  return reason === undefined ? { id, outcome, value } : { id, outcome, value, reason };
}

/**
 * Verify one `evm-calldata/1` publication against P (tzun-anchor/1 §10.3
 * step 6, §10.4).
 *
 * `true` needs every offline fact (the transaction id, calldata `0x ‖ P`, a
 * recovered sender that the manifest lists for `anchorOrigin` at the block
 * time, the signed chain id equal to that entry's CAIP-2 chain, and, when the
 * bundle carries them, the header hash and the trie proof) AND the header
 * source for that chain confirming the block canonical at finalized depth,
 * with the transaction placed in it by a verified trie proof or by the
 * source's own lookup. Offline facts that fail give `false`; anything short of
 * the header source's confirmation gives `null`, `publication_not_checked`.
 *
 * Never throws.
 */
export async function verifyEvmPublication(input: EvmPublicationInput): Promise<EvmPublicationVerdict> {
  const requested = input?.timeoutMs;
  const timeoutMs =
    typeof requested === 'number' && Number.isFinite(requested) && requested > 0 ? requested : DEFAULT_EVM_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;
  const facts: EvmPublicationFacts = {};
  const blocked = check(CANONICAL_CHECK, 'not-checked', 'blocked_by:anchor.evm.tx');
  const txFailed = (reason: EvmPublicationReason): EvmPublicationVerdict => ({
    valid: false,
    reason,
    checks: { tx: check(TX_CHECK, 'checked-wrong', reason), canonical: blocked },
    facts,
  });
  const txAbstained = (reason: EvmPublicationReason): EvmPublicationVerdict => ({
    valid: null,
    reason,
    checks: { tx: check(TX_CHECK, 'abstain', reason), canonical: blocked },
    facts,
  });
  const txNotChecked = (reason: EvmNotCheckedReason): EvmPublicationVerdict => ({
    valid: null,
    reason: 'publication_not_checked',
    checks: { tx: check(TX_CHECK, 'not-checked', reason), canonical: blocked },
    facts,
  });

  try {
    const pub = (input ?? ({} as EvmPublicationInput)).publication as unknown as Record<string, unknown>;
    if (!pub || typeof pub !== 'object' || Array.isArray(pub)) return txFailed('malformed_publication');
    if (pub.kind !== 'evm-calldata/1') return txAbstained('unsupported_publication_kind');

    // P is the caller's input, not the artifact's.
    const pHex = typeof input.p === 'string' ? (input.p.startsWith('0x') ? input.p : '0x' + input.p) : '';
    if (!HEX32.test(pHex)) return txNotChecked('input_not_supplied:p');

    if (pub.rawTransaction === undefined || pub.rawTransaction === null) {
      return txNotChecked('not_in_bundle:raw_transaction');
    }
    // JSON from nullable columns or other languages writes an absent field as null.
    const optional = (v: unknown) => (v === null ? undefined : v);
    const { rawTransaction, blockNumber, blockHash } = pub;
    const transactionId = optional(pub.transactionId);
    const blockHeader = optional(pub.blockHeader);
    const txIndex = optional(pub.txIndex);
    const txProof = optional(pub.txProof);
    if (!isHex(rawTransaction) || rawTransaction === '0x') return txFailed('malformed_publication');
    if (transactionId !== undefined && !(typeof transactionId === 'string' && HEX32.test(transactionId))) {
      return txFailed('malformed_publication');
    }
    if (typeof blockHash !== 'string' || !HEX32.test(blockHash)) return txFailed('malformed_publication');
    if (typeof blockNumber !== 'number' || !Number.isSafeInteger(blockNumber) || blockNumber < 0) {
      return txFailed('malformed_publication');
    }
    if (blockHeader !== undefined && !isHex(blockHeader)) return txFailed('malformed_publication');
    const hasProof = txIndex !== undefined || txProof !== undefined;
    if (hasProof) {
      if (typeof txIndex !== 'number' || !Number.isSafeInteger(txIndex) || txIndex < 0) {
        return txFailed('malformed_publication');
      }
      if (!Array.isArray(txProof) || txProof.length === 0 || !txProof.every(isHex)) {
        return txFailed('malformed_publication');
      }
    }
    const claimedHash = blockHash.toLowerCase();
    facts.blockNumber = blockNumber;
    facts.blockHash = claimedHash;

    // EIP-2718: a legacy transaction is an RLP list (first byte 0xc0 or
    // above); a typed one starts with its type, 0x00 to 0x7f. Only types this
    // verifier reads go on to be parsed, so an unknown type abstains instead
    // of failing to parse.
    const firstByte = parseInt(rawTransaction.slice(2, 4), 16);
    if (firstByte < 0xc0) {
      if (firstByte >= 0x80) return txFailed('malformed_publication');
      if (firstByte !== 1 && firstByte !== 2) {
        facts.txType = firstByte;
        return txAbstained('unsupported_evm_tx_type');
      }
    }

    let tx: Transaction;
    let sender: string;
    try {
      tx = Transaction.from(rawTransaction);
      // Recovering the sender can fail on a signature that parses but is not a point.
      if (!tx.isSigned() || !tx.from) return txFailed('malformed_publication');
      sender = tx.from.toLowerCase();
    } catch {
      return txFailed('malformed_publication');
    }

    const computedId = keccak256(rawTransaction);
    facts.transactionId = computedId;
    if (tx.type !== null) facts.txType = tx.type;
    facts.sender = sender;
    facts.signedChainId = tx.chainId.toString();

    if (transactionId !== undefined && (transactionId as string).toLowerCase() !== computedId) {
      return txFailed('evm_tx_proof_invalid');
    }
    if (tx.data.toLowerCase() !== pHex.toLowerCase()) return txFailed('evm_calldata_mismatch');

    const entries = evmEntriesFor(input.manifest, input.anchorOrigin);
    if (entries === undefined) return txNotChecked('input_not_supplied:publisher_manifest');
    if (entries.length === 0) return txNotChecked('no_expectation:publisher');
    const bySender = entries.filter((e) => e.address === sender);
    if (bySender.length === 0) return txFailed('evm_sender_mismatch');
    // A pre-EIP-155 transaction signs chain id 0, which matches no entry.
    const byChain = bySender.filter((e) => e.chainId === tx.chainId);
    if (byChain.length === 0) return txFailed('evm_chain_mismatch');

    // The header and the trie proof, when the bundle carries them.
    let headerTime: number | null = null;
    let proofVerified = false;
    if (blockHeader !== undefined) {
      if (keccak256(blockHeader).toLowerCase() !== claimedHash) return txFailed('evm_tx_proof_invalid');
      const header = parseEvmBlockHeader(blockHeader);
      if (!header || header.number !== blockNumber) return txFailed('evm_tx_proof_invalid');
      headerTime = header.timestamp;
      if (hasProof) {
        const proven = verifyEvmTransactionProof(header.transactionsRoot, txIndex as number, txProof as string[]);
        if (proven === null || proven.toLowerCase() !== rawTransaction.toLowerCase()) {
          return txFailed('evm_tx_proof_invalid');
        }
        proofVerified = true;
      }
    }

    // The bundle's block time decides the validity window offline. It is the
    // artifact's own claim, so it can make the publication fail but never pass.
    let candidates = byChain;
    if (headerTime !== null) {
      candidates = byChain.filter((e) => validAt(e, headerTime as number));
      if (candidates.length === 0) return txFailed('evm_sender_mismatch');
    }
    // Without a header, a bounded window waits for the block time the header
    // source confirms, and the sender check is not complete until then.
    const windowPending =
      headerTime === null && byChain.some((e) => e.firstSecond !== null || e.lastSecond !== null);
    const txCheck = windowPending
      ? check(TX_CHECK, 'not-checked', 'not_in_bundle:block_header')
      : check(TX_CHECK, 'checked-correct');
    const chain = byChain[0].chain;
    const noInclusion: EvmNotCheckedReason =
      hasProof && blockHeader === undefined ? 'not_in_bundle:block_header' : 'not_in_bundle:tx_proof';

    const notCanonical = (reason: EvmNotCheckedReason): EvmPublicationVerdict => ({
      valid: null,
      reason: 'publication_not_checked',
      checks: { tx: txCheck, canonical: check(CANONICAL_CHECK, 'not-checked', reason) },
      facts,
    });
    const offChain = (): EvmPublicationVerdict => ({
      valid: false,
      reason: 'anchor_not_found_on_chain',
      checks: { tx: txCheck, canonical: check(CANONICAL_CHECK, 'checked-wrong', 'anchor_not_found_on_chain') },
      facts,
    });

    const sources = input.headerSources;
    const source =
      sources && typeof sources === 'object' && Object.prototype.hasOwnProperty.call(sources, chain)
        ? sources[chain]
        : undefined;
    if (!source) return notCanonical('input_not_supplied:evm_header_source');

    let blockTime: number;
    let inclusion: 'tx_proof' | 'header_source' | null = proofVerified ? 'tx_proof' : null;
    const ask = <T>(call: () => Promise<T>) => withDeadline(call, deadline);
    const failed = (err: unknown) =>
      notCanonical(err instanceof DeadlineExceeded ? 'evm_header_source_timeout' : 'evm_header_source_unavailable');
    try {
      const sourceChainId = await ask(() => source.chainId());
      if (typeof sourceChainId !== 'bigint') return notCanonical('evm_header_source_unavailable');
      if (sourceChainId !== tx.chainId) return notCanonical('evm_header_source_chain_mismatch');

      const declared = declaredFinality(source);
      if (declared !== undefined) facts.finality = declared;
      const finalized = await ask(() => source.finalizedBlockNumber());
      if (typeof finalized !== 'number' || !Number.isSafeInteger(finalized)) {
        return notCanonical('evm_header_source_unavailable');
      }
      if (blockNumber > finalized) return notCanonical('evm_block_not_finalized');

      // A source that calls this height final must have a block there.
      const block = await ask(() => source.canonicalBlock(blockNumber));
      if (block === null) return notCanonical('evm_header_source_inconsistent');
      if (
        typeof block !== 'object' ||
        typeof block.hash !== 'string' ||
        !HEX32.test(block.hash) ||
        typeof block.timestamp !== 'number' ||
        !Number.isSafeInteger(block.timestamp)
      ) {
        return notCanonical('evm_header_source_unavailable');
      }
      if (block.hash.toLowerCase() !== claimedHash) return offChain();
      // The header hashed to this canonical block, so its timestamp is the
      // block's; a source that reports another one is not answering straight.
      if (headerTime !== null && block.timestamp !== headerTime) {
        return notCanonical('evm_header_source_inconsistent');
      }
      blockTime = block.timestamp;

      const lookup = source.transaction;
      if (typeof lookup === 'function') {
        // A lookup that fails, times out or knows nothing (an expired lookup
        // index, say) contradicts nothing when the trie proof already placed
        // the transaction in the confirmed block.
        let seen: EvmSourceTransaction | null = null;
        try {
          seen = await ask(() => lookup.call(source, computedId));
        } catch (err) {
          if (!proofVerified) return failed(err);
        }
        if (seen) {
          if (typeof seen.blockHash !== 'string' || typeof seen.from !== 'string') {
            return notCanonical('evm_header_source_inconsistent');
          }
          const seenHash = seen.blockHash.toLowerCase();
          if (seenHash !== claimedHash) {
            // With a verified proof, the source has confirmed the very block
            // that holds the transaction, so it is contradicting itself.
            if (proofVerified) return notCanonical('evm_header_source_inconsistent');
            // Without one, the lookup decides only if the source also calls
            // the block it names canonical at that block's height. A stale
            // lookup index, or a backend behind a load balancer that has not
            // caught up, names a block it no longer calls canonical.
            const at = seen.blockNumber;
            if (typeof at !== 'number' || !Number.isSafeInteger(at) || at < 0) {
              return notCanonical('evm_header_source_inconsistent');
            }
            const named = await ask(() => source.canonicalBlock(at));
            if (!named || typeof named.hash !== 'string' || named.hash.toLowerCase() !== seenHash) {
              return notCanonical('evm_header_source_inconsistent');
            }
            return offChain();
          }
          if (seen.from.toLowerCase() !== sender) return notCanonical('evm_header_source_inconsistent');
          inclusion = inclusion ?? 'header_source';
        }
      }
    } catch (err) {
      return failed(err);
    }
    if (inclusion === null) return notCanonical(noInclusion);
    facts.inclusion = inclusion;

    // The validity window, at the block time the header source confirmed.
    const valid = candidates.filter((e) => validAt(e, blockTime));
    if (valid.length === 0) {
      return {
        valid: false,
        reason: 'evm_sender_mismatch',
        checks: { tx: check(TX_CHECK, 'checked-wrong', 'evm_sender_mismatch'), canonical: blocked },
        facts,
      };
    }

    const namespaces = new Set(valid.map((e) => e.namespace));
    const networks = { ...DEFAULT_EVM_NETWORKS, ...(input.networks ?? {}) };
    facts.chain = chain;
    facts.namespace = namespaces.size === 1 ? valid[0].namespace : null;
    facts.network = Object.prototype.hasOwnProperty.call(networks, chain) ? networks[chain] : null;
    facts.blockTime = new Date(blockTime * 1000).toISOString();
    return {
      valid: true,
      checks: { tx: check(TX_CHECK, 'checked-correct'), canonical: check(CANONICAL_CHECK, 'checked-correct') },
      facts,
    };
  } catch {
    // Every expected failure returns above. This keeps an unforeseen one
    // undecided rather than an exception or a verdict.
    return txNotChecked('evm_verifier_error');
  }
}

// ─── Header source over JSON-RPC ───────────────────────────────────────────

/**
 * A transaction as a JSON-RPC node reports it: ethers' `TransactionResponse`
 * satisfies this. The signed fields are what {@link RpcEvmHeaderSource}
 * reassembles the raw envelope from.
 */
export interface AnchorTransaction {
  hash: string;
  from: string;
  blockHash: string | null;
  blockNumber: number | null;
  type: number;
  to: string | null;
  nonce: number;
  gasLimit: bigint;
  gasPrice?: bigint | null;
  maxPriorityFeePerGas?: bigint | null;
  maxFeePerGas?: bigint | null;
  data: string;
  value: bigint;
  chainId: bigint;
  signature: unknown;
  accessList?: unknown;
}

/**
 * The part of a JSON-RPC provider the verifier reads. An ethers
 * `JsonRpcProvider` satisfies it; tests supply a fake.
 */
export interface AnchorTransactionProvider {
  getTransaction(hash: string): Promise<AnchorTransaction | null>;
  getBlock(block: number | 'finalized'): Promise<{ number: number; hash: string | null; timestamp: number } | null>;
  getBlockNumber(): Promise<number>;
  getNetwork(): Promise<{ chainId: bigint }>;
  /** When present, the chain id is read with `eth_chainId` rather than the provider's cached network. */
  send?(method: string, params: unknown[]): Promise<unknown>;
}

/**
 * The fewest confirmations a confirmation depth may count as final without
 * `acceptNonFinal`: 64 blocks, two Ethereum epochs of 32 slots, the least
 * distance at which the node's `finalized` block can trail the newest one.
 * On Ethereum's public networks the finalized block was measured 64 to 96
 * blocks behind the newest (Sepolia, Hoodi and mainnet). A depth is not
 * finality even at the floor: the chain can stall finalization and reorganise
 * deeper, which is why the result states the depth it was judged under.
 */
export const EVM_MIN_FINAL_CONFIRMATIONS = 64;

// `EvmFinality` (what counts as final: `'finalized'`, or a confirmation
// depth of at least EVM_MIN_FINAL_CONFIRMATIONS unless `acceptNonFinal`) is
// declared in @tzun/engine, where `VerificationResult.anchorFinality` uses it.
export type { EvmFinality };

/**
 * `finality` checked and normalised, or a thrown `Error` naming what is
 * wrong. The result is a fresh value, so a caller's object mutated later does
 * not change it. `undefined` is `'finalized'`. The rule for
 * {@link RpcEvmHeaderSource}, {@link EthereumAnchorVerifier} and the chains a
 * `ScheduledScanner` reads.
 */
export function checkedFinality(finality: EvmFinality | undefined, who: string): EvmFinality {
  if (finality === undefined || finality === 'finalized') return 'finalized';
  if (finality === null || typeof finality !== 'object') {
    throw new Error(`${who} \`finality\` must be 'finalized' or { confirmations: n }.`);
  }
  const n = finality.confirmations;
  if (!Number.isSafeInteger(n) || n < 1) {
    throw new Error(`${who} \`finality.confirmations\` must be a positive integer.`);
  }
  if (finality.acceptNonFinal === true) return { confirmations: n, acceptNonFinal: true };
  if (n < EVM_MIN_FINAL_CONFIRMATIONS) {
    throw new Error(
      `${who} \`finality.confirmations\` of ${n} is below ${EVM_MIN_FINAL_CONFIRMATIONS}, so an anchor it confirms may not be final. ` +
        "Use 'finalized' (the default), at least " +
        `${EVM_MIN_FINAL_CONFIRMATIONS} confirmations, or set \`acceptNonFinal: true\` to accept anchors that may be reorganised away.`,
    );
  }
  return { confirmations: n };
}

/** {@link EvmHeaderSource} backed by a JSON-RPC node the verifier chooses. */
export class RpcEvmHeaderSource implements EvmHeaderSource {
  /** What this source counts as final; see {@link EvmFinality}. */
  readonly finality: EvmFinality;

  /**
   * @throws when `options.finality` is not an {@link EvmFinality}: a depth
   *   that is not a positive integer, or one below
   *   {@link EVM_MIN_FINAL_CONFIRMATIONS} without `acceptNonFinal: true`.
   */
  constructor(
    private readonly provider: AnchorTransactionProvider,
    options: { finality?: EvmFinality } = {},
  ) {
    this.finality = checkedFinality(options.finality, 'RpcEvmHeaderSource');
  }

  async chainId(): Promise<bigint> {
    if (typeof this.provider.send === 'function') {
      return BigInt((await this.provider.send('eth_chainId', [])) as string);
    }
    return (await this.provider.getNetwork()).chainId;
  }

  async finalizedBlockNumber(): Promise<number> {
    if (this.finality === 'finalized') {
      const block = await this.provider.getBlock('finalized');
      if (!block) throw new Error('The node reports no finalized block.');
      return block.number;
    }
    return (await this.provider.getBlockNumber()) - (this.finality.confirmations - 1);
  }

  async canonicalBlock(blockNumber: number): Promise<{ hash: string; timestamp: number } | null> {
    const block = await this.provider.getBlock(blockNumber);
    if (!block || !block.hash) return null;
    return { hash: block.hash, timestamp: block.timestamp };
  }

  /**
   * The node's copy of the transaction. `rawTransaction` is reassembled from
   * the signed fields the node returns, and is set only when it hashes back to
   * `transactionId`.
   */
  async transaction(transactionId: string): Promise<EvmSourceTransaction | null> {
    const t = await this.provider.getTransaction(transactionId);
    if (!t) return null;
    let rawTransaction: string | undefined;
    try {
      const raw = Transaction.from({
        type: t.type,
        to: t.to,
        nonce: t.nonce,
        gasLimit: t.gasLimit,
        gasPrice: t.gasPrice,
        maxPriorityFeePerGas: t.maxPriorityFeePerGas,
        maxFeePerGas: t.maxFeePerGas,
        data: t.data,
        value: t.value,
        chainId: t.chainId,
        signature: t.signature as Signature,
        accessList: t.accessList as AccessList | null | undefined,
      }).serialized;
      rawTransaction = keccak256(raw) === transactionId.toLowerCase() ? raw : undefined;
    } catch {
      rawTransaction = undefined;
    }
    return { from: t.from, blockHash: t.blockHash, blockNumber: t.blockNumber, rawTransaction };
  }
}

// ─── EthereumAnchorVerifier: one published value, read back from a node ────

export interface EthereumAnchorVerifierConfig {
  /** JSON-RPC endpoint per chain label, e.g. `{ 'ethereum-sepolia': 'https://…' }`. */
  rpcUrls: Record<string, string>;
  /**
   * The wallets allowed to publish, each on its CAIP-2 chain. A transaction
   * counts only when its recovered SENDER is one of these, on the chain it
   * signed for, at the block time. Required: the constructor throws when it
   * is missing, empty, malformed, or names no EVM chain.
   */
  publishers: PublisherManifestEntry[];
  /**
   * CAIP-2 chain per chain label. Defaults: `ethereum-mainnet` →
   * `eip155:1`, `ethereum-sepolia` → `eip155:11155111`, `ethereum-hoodi` →
   * `eip155:560048`.
   */
  chains?: Record<string, string>;
  /**
   * What counts as final. Default: the node's `finalized` tag. A confirmation
   * depth below {@link EVM_MIN_FINAL_CONFIRMATIONS} is refused unless it
   * carries `acceptNonFinal: true`. Every result states the finality it was
   * judged under.
   */
  finality?: EvmFinality;
  /** Overrides or extends {@link DEFAULT_EVM_NETWORKS}. */
  networks?: Record<string, EvmNetwork>;
  /**
   * One deadline for everything a `verifyAnchor` call asks the node, in
   * milliseconds. Default {@link DEFAULT_EVM_TIMEOUT_MS}. The default
   * provider also times out each request at this value.
   */
  timeoutMs?: number;
  /**
   * Provider factory override, for tests. The default is an ethers
   * `JsonRpcProvider` pinned to the label's chain, built per call and
   * destroyed when the call ends. A provider from this factory is the
   * caller's, and is not destroyed.
   */
  providerFor?: (rpcUrl: string) => AnchorTransactionProvider;
}

/**
 * Thrown by {@link EthereumAnchorVerifier} when the publication was not
 * decided: unknown, neither confirmed nor refused. `verdict` is the
 * publication's verdict, and `finality` the finality it was judged under
 * (`evm_block_not_finalized` is relative to it).
 */
export class EvmPublicationNotCheckedError extends Error {
  constructor(
    readonly verdict: EvmPublicationVerdict,
    readonly finality?: EvmFinality,
  ) {
    const { tx, canonical } = verdict.checks;
    const detail = tx.outcome === 'checked-correct' ? canonical.reason : tx.reason;
    super(`The anchor transaction was not decided: ${verdict.reason} (${detail}).`);
    this.name = 'EvmPublicationNotCheckedError';
  }
}

/** What {@link EthereumAnchorVerifier.verifyAnchor} returns when it decides. */
export interface EthereumAnchorVerification {
  /** `true`: a configured publisher published the root in a block that is final under `finality`. */
  confirmed: boolean;
  /**
   * Set when `confirmed` is `false`: the publication's own reason, one of
   * `evm_calldata_mismatch`, `evm_sender_mismatch` (a sender that is not a
   * publisher, or not one at the block time) and `evm_chain_mismatch`. The
   * verifier never reports `anchor_not_found_on_chain`: the block comes from
   * the node's own lookup, so a node that then calls another block canonical
   * contradicts itself, and a node that does not know the transaction cannot
   * tell "never mined" from "no longer indexed". Both throw.
   */
  reason?: EvmPublicationReason;
  /** The full verdict of {@link verifyEvmPublication}. */
  publication: EvmPublicationVerdict;
  /**
   * The finality the verdict was judged under. A display of a confirmed
   * anchor should say which: `{ confirmations: 2, acceptNonFinal: true }` is
   * "2 confirmations, not final", not "anchored".
   */
  finality: EvmFinality;
}

/**
 * The `false` reasons that come from the signed transaction itself. Under
 * {@link EthereumAnchorVerifier} the raw transaction is reassembled from the
 * node's answer and hashes to the claimed id, so these are facts about what
 * was signed. Any other `false` there can only come from the node's own
 * fields (its block number or hash), and is the node answering unusably.
 */
const SIGNED_TRANSACTION_REFUSALS: ReadonlySet<EvmPublicationReason> = new Set<EvmPublicationReason>([
  'evm_calldata_mismatch',
  'evm_sender_mismatch',
  'evm_chain_mismatch',
]);

const DEFAULT_ANCHOR_CHAINS: Readonly<Record<string, string>> = Object.freeze({
  'ethereum-sepolia': 'eip155:11155111',
  'ethereum-hoodi': 'eip155:560048',
  'ethereum-mainnet': 'eip155:1',
});

/** The manifest key the configured publishers are kept under. */
const CONFIGURED_PUBLISHERS = 'configured-publishers';

/**
 * Confirms that a 32-byte value P (tzun-anchor/1 §6) was published on an EVM
 * chain, by the configured publishers, in a block that is final (by default,
 * at or below the node's `finalized` block; see {@link EvmFinality}).
 *
 * It reads the transaction from the configured node, reassembles the signed
 * envelope, and runs {@link verifyEvmPublication} with the value as P and the
 * same node as the header source. The result is an
 * {@link EthereumAnchorVerification}: `true` → `confirmed: true`; `false` →
 * `confirmed: false` with the publication's own reason
 * (`evm_calldata_mismatch`, `evm_sender_mismatch`, `evm_chain_mismatch`).
 * Either way the result states the `finality` it was judged under. Not
 * decided (not final yet, not known to the node, the node unreachable, past
 * the deadline, or answering with a block it cannot have) → throws. The full
 * verdict rides along as `publication`, or on the thrown
 * {@link EvmPublicationNotCheckedError}. `verifyAttestation` does not call
 * it: a record's `nonRepudiation.anchor` is checked by `verifyAnchor`.
 *
 * The block a transaction is in comes from the node's own lookup here, not
 * from an artifact. So when the node then calls another block canonical at
 * that height, it is contradicting itself (a stale index, a load-balanced
 * backend, a reorg between two reads), and the result is undecided
 * (`evm_header_source_inconsistent`), never `false`.
 */
export class EthereumAnchorVerifier {
  private readonly rpcUrls: Record<string, string>;
  private readonly publishers: PublisherManifestEntry[];
  private readonly chains: Record<string, string>;
  private readonly finality: EvmFinality;
  private readonly networks?: Record<string, EvmNetwork>;
  private readonly timeoutMs: number;
  private readonly providerFor?: (rpcUrl: string) => AnchorTransactionProvider;

  constructor(config: EthereumAnchorVerifierConfig) {
    const publishers = config?.publishers;
    if (!Array.isArray(publishers) || publishers.length === 0) {
      throw new Error('EthereumAnchorVerifier needs `publishers`: at least one wallet allowed to publish.');
    }
    const parsed = evmEntriesFor({ publishers: { [CONFIGURED_PUBLISHERS]: publishers } }, CONFIGURED_PUBLISHERS);
    if (parsed === undefined) {
      throw new Error('EthereumAnchorVerifier `publishers` has a malformed entry (address, CAIP-2 chain, namespace or RFC 3339 dates).');
    }
    if (parsed.length === 0) {
      throw new Error('EthereumAnchorVerifier `publishers` names no EVM (eip155) chain.');
    }
    const timeoutMs = config.timeoutMs;
    if (timeoutMs !== undefined && !(typeof timeoutMs === 'number' && Number.isFinite(timeoutMs) && timeoutMs > 0)) {
      throw new Error('EthereumAnchorVerifier `timeoutMs` must be a positive number of milliseconds.');
    }
    this.rpcUrls = config.rpcUrls;
    this.publishers = publishers;
    this.chains = { ...DEFAULT_ANCHOR_CHAINS, ...(config.chains ?? {}) };
    this.finality = checkedFinality(config.finality, 'EthereumAnchorVerifier');
    this.networks = config.networks;
    this.timeoutMs = timeoutMs ?? DEFAULT_EVM_TIMEOUT_MS;
    this.providerFor = config.providerFor;
  }

  /**
   * @param anchor - `chain`: a configured chain label; `transactionId`: the
   *   transaction that should carry P; `p`: the 32 bytes as hex, with or
   *   without `0x`.
   */
  async verifyAnchor(anchor: { chain: string; transactionId: string; p: string }): Promise<EthereumAnchorVerification> {
    const rpcUrl = Object.prototype.hasOwnProperty.call(this.rpcUrls, anchor.chain) ? this.rpcUrls[anchor.chain] : undefined;
    if (!rpcUrl) {
      // No endpoint configured for this chain: unknown, not absent, so it
      // throws rather than answering `confirmed: false`.
      throw new Error(`No RPC URL configured for chain "${anchor.chain}". Cannot confirm the anchor.`);
    }
    const chainId = eip155ChainId(this.chains[anchor.chain]);
    if (chainId === null) {
      throw new Error(`No CAIP-2 chain configured for "${anchor.chain}". Cannot confirm the anchor.`);
    }

    const deadline = Date.now() + this.timeoutMs;
    // A static network keeps an unreachable URL a failed request rather than
    // an endless network-detection retry; the chain id is still read from the
    // node with eth_chainId and checked. Each request also times out on its
    // own, so an abandoned one does not linger past the deadline.
    let owned: JsonRpcProvider | undefined;
    let provider: AnchorTransactionProvider;
    if (this.providerFor) {
      provider = this.providerFor(rpcUrl);
    } else {
      const network = Network.from(chainId);
      const request = new FetchRequest(rpcUrl);
      request.timeout = this.timeoutMs;
      owned = new JsonRpcProvider(request, network, { staticNetwork: network });
      provider = owned as unknown as AnchorTransactionProvider;
    }
    try {
      return await this.decide(anchor, provider, chainId, deadline);
    } finally {
      owned?.destroy();
    }
  }

  private async decide(
    anchor: { chain: string; transactionId: string; p: string },
    provider: AnchorTransactionProvider,
    chainId: bigint,
    deadline: number,
  ): Promise<EthereumAnchorVerification> {
    const node = new RpcEvmHeaderSource(provider, { finality: this.finality });

    let seen: EvmSourceTransaction | null;
    try {
      seen = await withDeadline(() => node.transaction(anchor.transactionId), deadline);
    } catch (err) {
      if (err instanceof DeadlineExceeded) {
        throw new Error(
          `The node did not return transaction ${anchor.transactionId} within ${this.timeoutMs} ms. Cannot confirm the anchor.`,
        );
      }
      throw err;
    }
    if (!seen) {
      // A node that does not know the hash cannot tell "never mined" from "no
      // longer indexed" (lookup indexes expire), so the anchor is unknown.
      throw new Error(`The node does not know transaction ${anchor.transactionId}. Cannot confirm the anchor.`);
    }
    if (seen.blockHash === null || seen.blockNumber === null) {
      throw new Error(`Transaction ${anchor.transactionId} is not in a block yet. Cannot confirm the anchor.`);
    }
    if (!seen.rawTransaction) {
      throw new Error(`The node's copy of ${anchor.transactionId} could not be reassembled into a signed transaction.`);
    }

    const source: EvmHeaderSource = {
      finality: node.finality,
      chainId: () => node.chainId(),
      finalizedBlockNumber: () => node.finalizedBlockNumber(),
      canonicalBlock: (n) => node.canonicalBlock(n),
      transaction: async () => seen,
    };
    const publication = await verifyEvmPublication({
      publication: {
        kind: 'evm-calldata/1',
        transactionId: anchor.transactionId,
        rawTransaction: seen.rawTransaction,
        blockNumber: seen.blockNumber,
        blockHash: seen.blockHash,
      },
      p: anchor.p,
      anchorOrigin: CONFIGURED_PUBLISHERS,
      manifest: { publishers: { [CONFIGURED_PUBLISHERS]: this.publishers } },
      headerSources: { [`eip155:${chainId}`]: source },
      networks: this.networks,
      timeoutMs: Math.max(1, deadline - Date.now()),
    });

    // A copy per result, so a caller that edits one cannot change the verifier.
    const finality: EvmFinality = typeof this.finality === 'string' ? this.finality : { ...this.finality };
    if (publication.valid === true) return { confirmed: true, publication, finality };
    if (publication.valid === false && publication.reason !== undefined && SIGNED_TRANSACTION_REFUSALS.has(publication.reason)) {
      return { confirmed: false, reason: publication.reason, publication, finality };
    }
    if (publication.valid === false) {
      // The block claim came from this node's own lookup, so a node that now
      // calls another block canonical is contradicting itself. Any other
      // `false` can only come from the block number or hash the node reported
      // for the transaction, which is the node answering unusably.
      const checks =
        publication.reason === 'anchor_not_found_on_chain'
          ? { tx: publication.checks.tx, canonical: check(CANONICAL_CHECK, 'not-checked', 'evm_header_source_inconsistent') }
          : {
              tx: check(TX_CHECK, 'not-checked', 'evm_header_source_unavailable'),
              canonical: check(CANONICAL_CHECK, 'not-checked', 'blocked_by:anchor.evm.tx'),
            };
      throw new EvmPublicationNotCheckedError(
        { valid: null, reason: 'publication_not_checked', checks, facts: publication.facts },
        finality,
      );
    }
    throw new EvmPublicationNotCheckedError(publication, finality);
  }
}
