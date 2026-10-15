/**
 * Cross-SDK harness for the anchor verifier (tzun-anchor/1 §4, §10.3 to §10.6):
 * the Node side. tests/cross-sdk/test_anchor_verify_parity.py drives it and
 * compares every answer with tzun_sdk.attestation (checkpoint, evm_rlp,
 * evm_transaction, evm_publication, anchor_verify).
 *
 * Reads one JSON command from stdin, runs it against the in-repo TypeScript
 * (never a published version), writes one JSON result to stdout.
 * Run it with TZ=UTC: asn1js reads a zoned GeneralizedTime in the host's zone.
 *
 *   { action: "corpus", bodies, segments, origins, bindings, formats, rlp,
 *     transactions, headers, proofs, base64, generalizedTimes, utcTimes }
 *     → the TypeScript answer for each input of each list (see `corpus`).
 *
 *   { action: "transactions" }
 *     → { cases: [{ name, raw }] }: ethers-signed transactions of every type
 *     the verifier reads, mutations of them, and transactions at the edges of
 *     each rule of tzun-anchor/1 §10.4 item 2, for the "corpus" command, which
 *     reads each with `readEvmTransaction`: the transaction and its sender, or
 *     `{ refused: <rule> }` (null when no rule applies: not a transaction).
 *
 *   { action: "evm-scenarios" }
 *     → { cases: [{ name, input, sources, verdict }] }: publications, blocks
 *     and header sources built with ethers and the fabricated-block helpers,
 *     each with `verifyEvmPublication`'s verdict. `sources` maps a CAIP-2 chain
 *     to a scripted header source (`scripted` below), or is null.
 *
 *   { action: "verify-evm", cases: [{ input, sources }] } → { verdicts }
 *
 *   { action: "anchor-scenarios" }
 *     → { cases: [{ name, artifacts, digest, options, verdict }] }: anchored
 *     records with EVM and RFC 3161 publications (tokens from a throwaway TSA),
 *     each with `verifyAnchor`'s verdict. `options.evmHeaderSources` holds
 *     scripted sources.
 *
 *   { action: "networks" } → { networks }: `DEFAULT_EVM_NETWORKS`, the CAIP-2
 *     chains the verifier knows and the network each one is.
 *
 *   { action: "verify-anchor", cases: [{ artifacts, digest, options }] } → { verdicts }
 *     A case whose trust anchors cannot be read gets `{ refused: <message> }`
 *     in place of a verdict: `verifyAnchor` throws `UnreadableTrustAnchorError`.
 *     A case's `env`, when present, sets `TZUN_TSA_TRUST_ANCHORS` and
 *     `TZUN_TSA_AUTHORITIES` for that case alone (a name it leaves out is
 *     unset).
 */
import { Transaction, Wallet, decodeRlp, encodeRlp, keccak256, toBeHex, type RlpStructuredData } from 'ethers';
import * as asn1js from 'asn1js';
import { verifyAnchor, type AnchorVerifyOptions } from '../../../src/attestation/anchor-verify';
import { UnreadableTrustAnchorError } from '../../../src/attestation/rfc3161-token';
import {
  DEFAULT_EVM_NETWORKS,
  decodeEvmRlp,
  parseEvmBlockHeader,
  readEvmTransaction,
  verifyEvmPublication,
  verifyEvmTransactionProof,
  type EvmHeaderSource,
  type EvmPublicationInput,
} from '../../../src/attestation/blockchain';
import {
  chainIdFromSegment,
  checkOriginBinding,
  formatCheckpoint,
  parseCheckpoint,
  parseOrigin,
} from '../../../src/attestation/checkpoint';
import {
  HALF_N,
  MAINNET,
  SECP256K1_N,
  SEPOLIA,
  buildTxTrie,
  encodeEnvelope,
  envelopeFields,
  fabricateBlock,
  firstRecoverableR,
  firstUnrecoverableR,
  highS,
  infinitySignature,
  publicationFrom,
  randomP,
  signAnchorTx,
  signLegacy,
  signTypedFields,
  signatureOf,
  withSignature,
  type FabricatedBlock,
} from '../../ts/helpers/evm-fixtures';
import { PLATFORM_PREFIX, TEST_PREFIX, anchoredRecord, sha256 } from '../../ts/helpers/anchor-fixtures';
import { makeTsaFixture } from '../../ts/rfc3161-fixture';

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
  });
}

const hasOwn = (o: unknown, k: string): boolean =>
  o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);

// ─── Scripted header sources ───────────────────────────────────────────────

/**
 * A header source the JSON describes, so both SDKs ask the same questions of
 * the same answers. tests/cross-sdk/test_anchor_verify_parity.py builds its
 * Python twin from the same JSON.
 *
 *   chainId: decimal string (a bigint), or chainIdRaw: any JSON, returned as it is
 *   finalized: any JSON, returned as it is
 *   blocks: { "<height>": any JSON }, a missing height answering null
 *   transactions: { "<id>": any JSON }: present, the source has a lookup
 *   finality: present, the source declares it as it is
 *   fail: { <method>: "throw" | "hang" }
 *   delayMs: every call answers after this long
 */
export interface SourceSpec {
  chainId?: string;
  chainIdRaw?: Json;
  finalized?: Json;
  blocks?: Record<string, Json>;
  transactions?: Record<string, Json>;
  finality?: Json;
  fail?: Record<string, 'throw' | 'hang'>;
  delayMs?: number;
}

function scripted(spec: SourceSpec): EvmHeaderSource {
  const act = async <T>(method: string, answer: () => T): Promise<T> => {
    const failure = spec.fail?.[method];
    if (failure === 'throw') throw new Error(`${method} failed`);
    if (failure === 'hang') await new Promise(() => undefined);
    if (spec.delayMs) await new Promise((r) => setTimeout(r, spec.delayMs));
    return answer();
  };
  const source: Record<string, unknown> = {
    chainId: () => act('chainId', () => (hasOwn(spec, 'chainIdRaw') ? spec.chainIdRaw : BigInt(spec.chainId!))),
    finalizedBlockNumber: () => act('finalizedBlockNumber', () => spec.finalized),
    canonicalBlock: (n: number) =>
      act('canonicalBlock', () => (hasOwn(spec.blocks, String(n)) ? spec.blocks![String(n)] : null)),
  };
  if (spec.transactions) {
    source.transaction = (id: string) =>
      act('transaction', () => (hasOwn(spec.transactions, id) ? spec.transactions![id] : null));
  }
  if (hasOwn(spec, 'finality')) source.finality = spec.finality;
  return source as unknown as EvmHeaderSource;
}

function scriptedSources(sources: Record<string, SourceSpec> | null | undefined): Record<string, EvmHeaderSource> | undefined {
  if (!sources) return undefined;
  return Object.fromEntries(Object.entries(sources).map(([chain, spec]) => [chain, scripted(spec)]));
}

/** What a node that has seen `block` reports: its chain, a finalized height 64 above it, the block and its transactions. */
function sourceOf(block: FabricatedBlock, opts: { finalizedDepth?: number; lookups?: boolean; chainId?: bigint } = {}): SourceSpec {
  const spec: SourceSpec = {
    chainId: String(opts.chainId ?? SEPOLIA),
    finalized: block.number + (opts.finalizedDepth ?? 64),
    blocks: { [String(block.number)]: { hash: block.hash, timestamp: block.timestamp } },
  };
  if (opts.lookups !== false) {
    spec.transactions = {};
    for (const raw of block.raws) {
      const t = Transaction.from(raw);
      spec.transactions[t.hash!] = { from: t.from!, blockHash: block.hash, blockNumber: block.number };
    }
  }
  return spec;
}

// ─── The corpus ────────────────────────────────────────────────────────────

function errorOr<T>(f: () => T): T | { error: true } {
  try {
    return f();
  } catch {
    return { error: true };
  }
}

interface Corpus {
  bodies?: unknown[];
  segments?: unknown[];
  origins?: unknown[];
  bindings?: Array<{ anchorOrigin: unknown; logOrigin: unknown; chainId?: unknown }>;
  formats?: Array<{ origin: unknown; size: unknown; root: unknown }>;
  rlp?: string[];
  transactions?: string[];
  headers?: unknown[];
  proofs?: Array<{ root: unknown; index: unknown; proof: unknown }>;
  base64?: string[];
  generalizedTimes?: string[];
  utcTimes?: string[];
}

function isoOrNull(d: Date): string | null {
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/**
 * A time as the token reader meets it: its DER element read by asn1js
 * `fromBER`, which parses after the constructor has set the fields a parse
 * does not (a GeneralizedTime's millisecond among them), then `toDate`.
 */
function timeFromBer(tag: number, text: string) {
  return errorOr(() => {
    const bytes = Buffer.from(text, 'latin1');
    const parsed = asn1js.fromBER(Buffer.concat([Buffer.from([tag, bytes.length]), bytes]));
    if (parsed.offset === -1) throw new Error(parsed.result.error);
    return { iso: isoOrNull((parsed.result as asn1js.UTCTime).toDate()) };
  });
}

function corpus(c: Corpus): Record<string, unknown[]> {
  return {
    bodies: (c.bodies ?? []).map((b) => parseCheckpoint(b)),
    segments: (c.segments ?? []).map((s) => chainIdFromSegment(s)),
    origins: (c.origins ?? []).map((o) => parseOrigin(o)),
    bindings: (c.bindings ?? []).map((b) => checkOriginBinding(b.anchorOrigin, b.logOrigin, b.chainId)),
    formats: (c.formats ?? []).map((f) => errorOr(() => ({ body: formatCheckpoint(f.origin as string, f.size as number, f.root as string) }))),
    rlp: (c.rlp ?? []).map((hex) => errorOr(() => ({ value: decodeEvmRlp(hex) }))),
    transactions: (c.transactions ?? []).map((raw) => {
      const reading = readEvmTransaction(raw);
      if (!reading.ok) return { refused: reading.rule };
      const tx = reading.transaction;
      return { type: tx.type, chainId: tx.chainId.toString(), data: tx.data, sender: tx.sender };
    }),
    headers: (c.headers ?? []).map((h) => parseEvmBlockHeader(h as string)),
    proofs: (c.proofs ?? []).map((p) => verifyEvmTransactionProof(p.root as string, p.index as number, p.proof as string[])),
    base64: (c.base64 ?? []).map((s) => Buffer.from(s, 'base64').toString('hex')),
    generalizedTimes: (c.generalizedTimes ?? []).map((s) => timeFromBer(0x18, s)),
    utcTimes: (c.utcTimes ?? []).map((s) => timeFromBer(0x17, s)),
  };
}

// ─── Transactions ──────────────────────────────────────────────────────────

const q = (n: bigint | number): string => (BigInt(n) === 0n ? '0x' : toBeHex(BigInt(n)));
const enc = (x: RlpStructuredData): string => encodeRlp(x).slice(2);

/** An RLP list of items already encoded (hex without 0x), so an item can use a non-canonical form. */
function listOfEncoded(items: string[]): string {
  const payload = items.join('');
  const len = payload.length / 2;
  if (len <= 55) return (0xc0 + len).toString(16) + payload;
  let l = len.toString(16);
  if (l.length % 2) l = '0' + l;
  return (0xf7 + l.length / 2).toString(16) + l + payload;
}

async function transactions(): Promise<Array<{ name: string; raw: string }>> {
  const wallet = Wallet.createRandom();
  const p = randomP();
  const out: Array<{ name: string; raw: string }> = [];
  const add = (name: string, raw: string) => out.push({ name, raw });

  const t2 = await signAnchorTx(wallet, { data: p, type: 2 });
  const t1 = await signAnchorTx(wallet, { data: p, type: 1 });
  const t0 = await signAnchorTx(wallet, { data: p, type: 0 });
  add('EIP-1559', t2);
  add('EIP-2930', t1);
  add('legacy EIP-155', t0);
  add('EIP-1559 on mainnet', await signAnchorTx(wallet, { data: p, type: 2, chainId: MAINNET }));
  add('EIP-1559 contract creation', await signAnchorTx(wallet, { data: p, type: 2, to: null }));
  add('EIP-1559 with an access list', await wallet.signTransaction({
    type: 2, chainId: SEPOLIA, nonce: 3, to: wallet.address, value: 5n, data: p, gasLimit: 90_000n,
    maxFeePerGas: 3_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n,
    accessList: [{ address: wallet.address, storageKeys: ['0x' + '01'.repeat(32), '0x' + 'ab'.repeat(32)] }],
  }));
  const pre = Transaction.from({ type: 0, nonce: 0, to: wallet.address, gasLimit: 30_000n, gasPrice: 2_000_000_000n, data: p, value: 0n });
  pre.signature = wallet.signingKey.sign(pre.unsignedHash);
  add('legacy pre-EIP-155', pre.serialized);

  // Field-level mutations of the signed EIP-1559 transaction, re-encoded.
  const fields = decodeRlp('0x' + t2.slice(4)) as RlpStructuredData[];
  const typed = (f: RlpStructuredData[]) => '0x02' + encodeRlp(f).slice(2);
  const withField = (i: number, v: RlpStructuredData) => typed(fields.map((x, j) => (j === i ? v : x)));
  add('unsigned (9 fields)', typed(fields.slice(0, 9)));
  add('10 fields', typed(fields.slice(0, 10)));
  add('yParity 2', withField(9, '0x02'));
  add('yParity with a leading zero byte', withField(9, fields[9] === '0x' ? '0x00' : '0x0001'));
  add('yParity behind a string prefix', '0x02' + listOfEncoded(fields.map((f, j) => (j === 9 ? (f === '0x' ? '8100' : '8101') : enc(f)))));
  add('yParity flipped', withField(9, fields[9] === '0x' ? '0x01' : '0x'));
  add('yParity as a list', withField(9, []));
  add('r of 33 bytes', withField(10, '0x00' + (fields[10] as string).slice(2).padStart(64, '0')));
  add('r zero-padded to 32 bytes', withField(10, '0x' + (fields[10] as string).slice(2).padStart(64, '0')));
  add('r = 0', withField(10, '0x'));
  add('s = n', withField(11, '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'));
  add('s above n', withField(11, '0x' + 'ff'.repeat(32)));
  const s = BigInt(fields[11] as string);
  const n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  add('high s, same parity', withField(11, q(n - s)));
  add('high s, other parity', typed(fields.map((x, j) => (j === 11 ? q(n - s) : j === 9 ? (fields[9] === '0x' ? '0x01' : '0x') : x))));
  add('a tip above the fee cap', withField(2, '0x' + 'ff'.repeat(8)));
  add('a nonce above 2^53 - 1', withField(1, q(2n ** 53n)));
  add('a nonce of 2^53 - 1', withField(1, q(2n ** 53n - 1n)));
  add('a nonce with a leading zero', withField(1, '0x0000'));
  add('a value above 2^256 - 1', withField(6, '0x01' + '00'.repeat(32)));
  add('a value of 33 bytes that fits', withField(6, '0x00' + 'ff'.repeat(32)));
  add('a recipient of 19 bytes', withField(5, '0x' + '35'.repeat(19)));
  add('calldata as a list', withField(7, []));
  add('an access list that is a string', withField(8, '0x78'));
  add('an access-list entry of three items', withField(8, [[wallet.address.toLowerCase(), [], '0x']]));
  add('an access-list address of 19 bytes', withField(8, [['0x' + '35'.repeat(19), []]]));
  add('an access-list key of 31 bytes', withField(8, [[wallet.address.toLowerCase(), ['0x' + '01'.repeat(31)]]]));
  add('access-list keys as a string', withField(8, [[wallet.address.toLowerCase(), '0x' + '01'.repeat(32)]]));
  add('a chain id of 2^256 - 1', withField(0, '0x' + 'ff'.repeat(32)));
  add('trailing bytes', t2 + '00');
  add('an empty typed payload', '0x02');
  add('a typed payload that is a string', '0x02' + encodeRlp('0x616263').slice(2));
  // Non-canonical RLP forms ethers reads by value.
  add('calldata in the long string form', '0x02' + listOfEncoded(fields.map((f, j) => (j === 7 ? 'b820' + (f as string).slice(2) : enc(f)))));
  add('a list in the long form', '0x02f8' + (enc(fields).length / 2 - 2).toString(16).padStart(2, '0') + enc(fields).slice(4));
  add('a length with a leading zero byte', '0x02' + listOfEncoded(fields.map((f, j) => (j === 7 ? 'b90020' + (f as string).slice(2) : enc(f)))));

  // Legacy mutations.
  const legacy = decodeRlp(t0) as RlpStructuredData[];
  const legacyWith = (i: number, v: RlpStructuredData) => encodeRlp(legacy.map((x, j) => (j === i ? v : x)));
  add('legacy unsigned (6 fields)', encodeRlp(legacy.slice(0, 6)));
  add('legacy 7 fields', encodeRlp(legacy.slice(0, 7)));
  add('legacy v = 0', legacyWith(6, '0x'));
  add('legacy v = 1', legacyWith(6, '0x01'));
  add('legacy v = 35', legacyWith(6, '0x23'));
  add('legacy v = 36', legacyWith(6, '0x24'));
  add('legacy v = 26', legacyWith(6, '0x1a'));
  add('legacy r = s = 0', encodeRlp([...legacy.slice(0, 7), '0x', '0x']));
  add('legacy v of another chain', legacyWith(6, q(BigInt(legacy[6] as string) + 2n)));
  add('legacy huge v', legacyWith(6, '0x' + 'ff'.repeat(32)));
  add('legacy r of 33 bytes', legacyWith(7, '0x00' + (legacy[7] as string).slice(2).padStart(64, '0')));

  // The edges of tzun-anchor/1 §10.4 item 2.
  add('EIP-1559 on chain id 0', await signAnchorTx(wallet, { data: p, type: 2, chainId: 0n }));
  add('EIP-2930 on chain id 0', await signAnchorTx(wallet, { data: p, type: 1, chainId: 0n }));
  add('EIP-2930 on chain id 1', await signAnchorTx(wallet, { data: p, type: 1, chainId: MAINNET }));
  for (const yParity of [0, 1] as const) {
    add(`legacy v ${35 + yParity}, signed for chain id 0`, signLegacy(wallet.signingKey, { data: p, eip155: true, chainId: 0n, yParity }));
    add(`legacy v ${37 + yParity}, signed for chain id 1`, signLegacy(wallet.signingKey, { data: p, eip155: true, chainId: MAINNET, yParity }));
    add(`legacy v ${27 + yParity}, unprotected`, signLegacy(wallet.signingKey, { data: p, eip155: false, yParity }));
  }
  add('legacy high s', highS(t0));
  add('EIP-2930 high s', highS(t1));
  const digest = Transaction.from(t2).unsignedHash;
  const half = firstRecoverableR(digest, HALF_N, 0);
  add('s exactly n/2', withSignature(t2, { v: 0n, r: half.r, s: HALF_N }));
  add('s = n/2 + 1, the other parity', withSignature(t2, { v: 1n, r: half.r, s: HALF_N + 1n }));
  add('s = 1', withSignature(t2, { v: 1n, r: firstRecoverableR(digest, 1n, 1).r, s: 1n }));
  add('s = 0', withSignature(t2, { ...signatureOf(t2), s: 0n }));
  add('r = n', withSignature(t2, { ...signatureOf(t2), r: SECP256K1_N }));
  add('yParity 27', withSignature(t2, { ...signatureOf(t2), v: 27n }));
  add('an r that is no x-coordinate', withSignature(t2, { v: 0n, r: firstUnrecoverableR(), s: 1n }));
  const infinity = infinitySignature(digest);
  add('a signature that recovers the point at infinity', withSignature(t2, { v: BigInt(infinity.yParity), r: infinity.r, s: infinity.s }));
  const fees = { type: 2, chainId: SEPOLIA, nonce: 0, to: wallet.address, value: 0n, data: p, gasLimit: 30_000n } as const;
  const atCap = await wallet.signTransaction({ ...fees, maxFeePerGas: 7n, maxPriorityFeePerGas: 7n });
  add('a tip equal to the fee cap', atCap);
  const aboveCap = envelopeFields(atCap).fields.slice(0, 9);
  aboveCap[2] = '0x08';
  const aboveSig = wallet.signingKey.sign(keccak256(encodeEnvelope(2, aboveCap)));
  add('a tip one wei above the fee cap, signed', withSignature(encodeEnvelope(2, [...aboveCap, '0x', '0x', '0x']), {
    v: BigInt(aboveSig.yParity),
    r: BigInt(aboveSig.r),
    s: BigInt(aboveSig.s),
  }));

  // Encoding: the canonical RLP of the fields. The publisher's EIP-1559
  // transaction with its values written in other bytes.
  const wrote = (i: number, bytes: string) => '0x02' + listOfEncoded(fields.map((f, j) => (j === i ? bytes : enc(f))));
  add('a chain id with a leading zero byte', withField(0, '0x00' + (fields[0] as string).slice(2)));
  add('a gas limit with a leading zero byte', withField(4, '0x00' + (fields[4] as string).slice(2)));
  add('a nonce of 0 written 0x8100', wrote(1, '8100'));
  add('a nonce of 5 written 0x8105', wrote(1, '8105'));
  add('a list length with a leading zero byte', '0x02f900' + t2.slice(6));
  add('two bytes after the list', t2 + '0000');
  add('legacy gas price with a leading zero byte', legacyWith(1, '0x00' + (legacy[1] as string).slice(2)));
  add('legacy trailing byte', t0 + '00');
  // An access-list entry of an address and one key is 55 bytes, the longest
  // item the short form holds: read as 0xf7, refused as 0xf837.
  const entry55 = [wallet.address.toLowerCase(), ['0x' + '01'.repeat(32)]];
  const listed55 = signTypedFields(wallet.signingKey, 2, [
    q(SEPOLIA), q(0n), q(1_000_000_000n), q(3_000_000_000n), q(30_000n), wallet.address.toLowerCase(), q(0n), p, [entry55],
  ]);
  const fields55 = decodeRlp('0x' + listed55.slice(4)) as RlpStructuredData[];
  add('an access-list entry of 55 bytes', listed55);
  add('an access-list entry of 55 bytes in the long form',
    '0x02' + listOfEncoded(fields55.map((f, j) => (j === 8 ? listOfEncoded(['f837' + enc(entry55).slice(2)]) : enc(f)))));

  // Field sizes, each signed by the publisher over its own values: nonce and
  // gasLimit up to 2^64 - 1, the chain id, value and fees up to 2^256 - 1, a
  // legacy v up to 2 * (2^256 - 1) + 36.
  const signed2 = (over: Partial<Record<'chainId' | 'nonce' | 'tip' | 'cap' | 'gasLimit' | 'value', bigint>>) =>
    signTypedFields(wallet.signingKey, 2, [
      q(over.chainId ?? SEPOLIA), q(over.nonce ?? 0n), q(over.tip ?? 1_000_000_000n), q(over.cap ?? 3_000_000_000n),
      q(over.gasLimit ?? 30_000n), wallet.address.toLowerCase(), q(over.value ?? 0n), p, [],
    ]);
  add('signed: nonce 2^53', signed2({ nonce: 2n ** 53n }));
  add('signed: nonce 2^53 + 1', signed2({ nonce: 2n ** 53n + 1n }));
  add('signed: nonce 2^64 - 1', signed2({ nonce: 2n ** 64n - 1n }));
  add('signed: nonce 2^64', signed2({ nonce: 2n ** 64n }));
  add('signed: gasLimit 2^64 - 1', signed2({ gasLimit: 2n ** 64n - 1n }));
  add('signed: gasLimit 2^64', signed2({ gasLimit: 2n ** 64n }));
  add('signed: value 2^256 - 1', signed2({ value: 2n ** 256n - 1n }));
  add('signed: value 2^256', signed2({ value: 2n ** 256n }));
  add('signed: maxFeePerGas 2^256', signed2({ cap: 2n ** 256n }));
  add('signed: maxPriorityFeePerGas 2^256 above a fee cap of 7', signed2({ tip: 2n ** 256n, cap: 7n }));
  add('signed: chain id 2^64', signed2({ chainId: 2n ** 64n }));
  add('signed: chain id 2^256 - 1', signed2({ chainId: 2n ** 256n - 1n }));
  add('signed: chain id 2^256', signed2({ chainId: 2n ** 256n }));
  add('legacy chain id 2^255', signLegacy(wallet.signingKey, { data: p, eip155: true, chainId: 2n ** 255n, yParity: 0 }));
  add('legacy v 2 * (2^256 - 1) + 36', signLegacy(wallet.signingKey, { data: p, eip155: true, chainId: 2n ** 256n - 1n, yParity: 1 }));
  add('legacy chain id 2^256', signLegacy(wallet.signingKey, { data: p, eip155: true, chainId: 2n ** 256n, yParity: 0 }));
  add('legacy gas price 2^256', legacyWith(1, q(2n ** 256n)));

  // Types the verifier does not parse are refused here too.
  add('type 3 header only', '0x03c0');
  add('EIP-2930 unsigned', '0x01' + encodeRlp((decodeRlp('0x' + t1.slice(4)) as RlpStructuredData[]).slice(0, 8)).slice(2));
  add('garbage', '0xc3010203');
  return out;
}

// ─── EVM publication scenarios ─────────────────────────────────────────────

const ORIGIN = 'local.invalid/3f2a9c0e5b7d4e1f8a6c2b9d0e4f7a1c/anchors';
const SEPOLIA_CHAIN = 'eip155:11155111';

interface EvmCase {
  name: string;
  input: Record<string, unknown>;
  /** Scripted sources by chain, null for none, or any other JSON passed as `headerSources` as it is. */
  sources: Record<string, SourceSpec> | Json;
}

function entry(address: string, extra: Record<string, unknown> = {}) {
  return { address, chain: SEPOLIA_CHAIN, namespace: 'test', ...extra };
}
const manifestOf = (...entries: unknown[]) => ({ publishers: { [ORIGIN]: entries } });

async function fillers(n = 3): Promise<string[]> {
  const out: string[] = [];
  for (let i = 0; i < n; i++) out.push(await signAnchorTx(Wallet.createRandom(), { data: randomP(), nonce: i }));
  return out;
}

async function honest(opts: { type?: 0 | 1 | 2; index?: number } = {}) {
  const p = randomP();
  const publisher = Wallet.createRandom();
  const raw = await signAnchorTx(publisher, { data: p, type: opts.type });
  const raws = await fillers();
  const index = opts.index ?? 2;
  raws.splice(index, 0, raw);
  const block = fabricateBlock(raws);
  const publication = publicationFrom(block, index) as Record<string, unknown>;
  const source = sourceOf(block);
  const input = { publication, p, anchorOrigin: ORIGIN, manifest: manifestOf(entry(publisher.address)) };
  return { p, publisher, block, publication, source, input, index };
}

const bare = (pub: Record<string, unknown>) => {
  const { blockHeader, txIndex, txProof, ...rest } = pub;
  void blockHeader;
  void txIndex;
  void txProof;
  return rest;
};

const iso = (unix: number) => new Date(unix * 1000).toISOString();

async function evmScenarios(): Promise<EvmCase[]> {
  const cases: EvmCase[] = [];
  const add = (name: string, input: Record<string, unknown>, sources: Record<string, SourceSpec> | Json) =>
    cases.push({ name, input, sources });
  const S = (spec: SourceSpec) => ({ [SEPOLIA_CHAIN]: spec });

  for (const type of [0, 1, 2] as const) {
    const s = await honest({ type });
    add(`type ${type}: true`, s.input, S(s.source));
    add(`type ${type}: no header source`, s.input, null);
    const forged = await signAnchorTx(Wallet.createRandom(), { data: s.p, type, to: s.publisher.address });
    const block = fabricateBlock([forged]);
    add(`type ${type}: a foreign sender`, { ...s.input, publication: publicationFrom(block, 0) }, S(sourceOf(block)));
  }

  const s = await honest();
  const src = s.source;
  const blockKey = String(s.block.number);
  const txId = keccak256(s.block.raws[2]);
  add('an unknown kind', { ...s.input, publication: { ...s.publication, kind: 'evm-calldata/2' } }, S(src));
  add('a missing kind', { ...s.input, publication: { ...s.publication, kind: null } }, S(src));
  add('another origin\'s publisher', { ...s.input, manifest: { publishers: { [ORIGIN]: [entry(Wallet.createRandom().address)], 'local.invalid/ffff/anchors': [entry(s.publisher.address)] } } }, S(src));
  add('no publisher for the origin', { ...s.input, manifest: { publishers: {} } }, S(src));
  add('the publication\'s own publisher field', { ...s.input, publication: { ...s.publication, publisher: Wallet.createRandom().address, chain: 'eip155:1' } }, S(src));
  add('P without 0x', { ...s.input, p: s.p.slice(2) }, S(src));
  add('P in upper case', { ...s.input, p: '0x' + s.p.slice(2).toUpperCase() }, S(src));
  add('P with 0X', { ...s.input, p: '0X' + s.p.slice(2) }, S(src));
  add('another P', { ...s.input, p: randomP() }, S(src));
  add('P of 31 bytes', { ...s.input, p: s.p.slice(0, 64) }, S(src));
  add('P not a string', { ...s.input, p: 7 }, S(src));
  for (const [label, mutate] of [
    ['one byte appended', (p: string) => p + '00'],
    ['a selector in front', (p: string) => '0xdeadbeef' + p.slice(2)],
    ['truncated by a byte', (p: string) => p.slice(0, -2)],
  ] as const) {
    const raw = await signAnchorTx(s.publisher, { data: mutate(s.p) });
    const block = fabricateBlock([raw]);
    add(`calldata with ${label}`, { ...s.input, publication: publicationFrom(block, 0) }, S(sourceOf(block)));
  }

  // Validity windows.
  const t = s.block.timestamp;
  const windowed = (bound: Record<string, unknown>) => ({ ...s.input, manifest: manifestOf(entry(s.publisher.address, bound)) });
  add('validUntil a second before the block', windowed({ validUntil: iso(t - 1) }), S(src));
  add('validUntil exactly at the block', windowed({ validUntil: iso(t) }), S(src));
  add('validUntil a second after the block', windowed({ validUntil: iso(t + 1) }), S(src));
  add('validFrom a minute after the block', windowed({ validFrom: iso(t + 60) }), S(src));
  add('validFrom exactly at the block', windowed({ validFrom: iso(t) }), S(src));
  add('validFrom half a millisecond after the block', windowed({ validFrom: iso(t).replace('.000Z', '.0005Z') }), S(src));
  add('validFrom a second after the block, offset form', windowed({ validFrom: new Date((t + 1) * 1000 + 5.5 * 3600_000).toISOString().replace('Z', '+05:30').replace('.000', '') }), S(src));
  add('a bounded window, no header, no source', { ...windowed({ validFrom: iso(t - 60) }), publication: bare(s.publication) }, null);
  add('a bounded window, no header, with a source', { ...windowed({ validFrom: iso(t - 60) }), publication: bare(s.publication) }, S(src));
  add('a window closed before the confirmed time, no header', { ...windowed({ validUntil: iso(t - 1) }), publication: bare(s.publication) }, S(src));
  add('a window closed before the header time, offline', windowed({ validUntil: iso(t - 1) }), null);
  for (const date of [
    '2026-09-31T00:00:00Z', '2026-02-30T00:00:00Z', '2026-02-29T00:00:00Z', '2100-02-29T00:00:00Z', '2026-13-01T00:00:00Z',
    '2026-00-10T00:00:00Z', '2026-09-00T00:00:00Z', '2026-09-23T24:00:00Z', '2026-09-23T23:60:00Z', '2026-09-23T23:59:60Z',
    '2026-09-23T12:00:00+24:00', '2026-09-23T12:00:00+05:60', '2026-09-23t12:00:00Z', '2026-09-23T12:00:00z',
    '2026-09-23T12:00:00', '2026-09-23T12:00:00.Z', '2026-09-23 12:00:00Z', '+002026-09-23T12:00:00Z', 'soon', '',
    '2028-02-29T00:00:00Z', '2000-02-29T00:00:00Z', '2026-09-30T23:59:59.999Z', '2026-09-23T12:00:00-07:00',
    '0000-01-01T00:00:00Z', '9999-12-31T23:59:59.9999999Z', '2026-09-23T12:00:00-00:00',
  ]) {
    add(`validFrom ${JSON.stringify(date)}`, windowed({ validFrom: date }), S(src));
    add(`validUntil ${JSON.stringify(date)}`, windowed({ validUntil: date }), S(src));
  }
  add('validFrom a number', windowed({ validFrom: 1790000000 }), S(src));
  add('validFrom null', windowed({ validFrom: null }), S(src));

  // The chain the sender signed.
  const mainnet = await signAnchorTx(s.publisher, { data: s.p, chainId: MAINNET });
  const mainnetBlock = fabricateBlock([mainnet]);
  add('a mainnet transaction under a Sepolia entry', { ...s.input, publication: publicationFrom(mainnetBlock, 0) }, {
    'eip155:1': sourceOf(mainnetBlock, { chainId: MAINNET }),
    [SEPOLIA_CHAIN]: sourceOf(mainnetBlock),
  });
  const pre = Transaction.from({ type: 0, nonce: 0, to: s.publisher.address, gasLimit: 30_000n, gasPrice: 2_000_000_000n, data: s.p, value: 0n });
  pre.signature = s.publisher.signingKey.sign(pre.unsignedHash);
  const preBlock = fabricateBlock([pre.serialized]);
  add('a pre-EIP-155 transaction', { ...s.input, publication: publicationFrom(preBlock, 0) }, S(sourceOf(preBlock)));
  add('a source on another chain', s.input, S({ ...src, chainId: String(MAINNET) }));
  add('a source filed under another chain', s.input, { 'eip155:1': src });
  add('a network override', { ...s.input, networks: { [SEPOLIA_CHAIN]: 'mainnet' } }, S(src));
  add('a network override that is not a network', { ...s.input, networks: { [SEPOLIA_CHAIN]: { weird: true } } }, S(src));
  add('networks that are not an object', { ...s.input, networks: 'eip155' }, S(src));

  // Finality and canonicality.
  add('a block above the finalized height', s.input, S({ ...src, finalized: s.block.number - 1 }));
  add('a block exactly at the finalized height', s.input, S({ ...src, finalized: s.block.number }));
  add('a negative finalized height', s.input, S({ ...src, finalized: -5 }));
  add('a fractional finalized height', s.input, S({ ...src, finalized: 5.5 }));
  add('a string finalized height', s.input, S({ ...src, finalized: String(s.block.number + 64) }));
  const backdated = fabricateBlock(s.block.raws, s.block.number, s.block.timestamp - 86_400 * 365);
  add('a back-dated header the chain never saw', { ...s.input, publication: publicationFrom(backdated, 2) }, S(src));
  add('a header for another block number', { ...s.input, publication: { ...s.publication, blockNumber: s.block.number + 1 } }, S(src));
  const next = String(s.block.number + 1);
  const other = { hash: '0x' + 'ee'.repeat(32), timestamp: s.block.timestamp + 12 };
  const seen = src.transactions![txId] as Record<string, Json>;
  add('no proof: a lookup in another canonical block', { ...s.input, publication: bare(s.publication) },
    S({ ...src, blocks: { ...src.blocks, [next]: other }, transactions: { ...src.transactions, [txId]: { ...seen, blockHash: other.hash, blockNumber: s.block.number + 1 } } }));
  add('no proof: a stale lookup', { ...s.input, publication: bare(s.publication) },
    S({ ...src, blocks: { ...src.blocks, [next]: { hash: '0x' + 'dd'.repeat(32), timestamp: 1 } }, transactions: { ...src.transactions, [txId]: { ...seen, blockHash: other.hash, blockNumber: s.block.number + 1 } } }));
  add('no proof: a lookup with no block number', { ...s.input, publication: bare(s.publication) },
    S({ ...src, transactions: { ...src.transactions, [txId]: { ...seen, blockHash: other.hash, blockNumber: null } } }));
  add('no proof: a lookup naming a height with no block', { ...s.input, publication: bare(s.publication) },
    S({ ...src, transactions: { ...src.transactions, [txId]: { ...seen, blockHash: other.hash, blockNumber: s.block.number + 7 } } }));
  add('another timestamp for the block', s.input, S({ ...src, blocks: { [blockKey]: { hash: s.block.hash, timestamp: s.block.timestamp + 1 } } }));
  add('with a proof: a lookup naming another block', s.input, S({ ...src, transactions: { ...src.transactions, [txId]: { ...seen, blockHash: other.hash } } }));
  add('with a proof: a failing lookup', s.input, S({ ...src, fail: { transaction: 'throw' } }));
  add('no proof: a failing lookup', { ...s.input, publication: bare(s.publication) }, S({ ...src, fail: { transaction: 'throw' } }));
  add('another sender in the lookup', s.input, S({ ...src, transactions: { ...src.transactions, [txId]: { ...seen, from: Wallet.createRandom().address } } }));
  add('a lookup with no sender', s.input, S({ ...src, transactions: { ...src.transactions, [txId]: { blockHash: s.block.hash, blockNumber: s.block.number } } }));
  add('a lookup that is an empty object', s.input, S({ ...src, transactions: { ...src.transactions, [txId]: {} } }));
  add('a lookup that is a string', s.input, S({ ...src, transactions: { ...src.transactions, [txId]: 'seen' } }));
  add('a lookup that is 0', s.input, S({ ...src, transactions: { ...src.transactions, [txId]: 0 } }));
  add('a lookup that is false', s.input, S({ ...src, transactions: { ...src.transactions, [txId]: false } }));
  add('a failing canonical block', s.input, S({ ...src, fail: { canonicalBlock: 'throw' } }));
  add('a failing chain id', s.input, S({ ...src, fail: { chainId: 'throw' } }));
  add('a chain id that is a string', s.input, S({ ...src, chainIdRaw: '11155111' }));
  add('a chain id that is null', s.input, S({ ...src, chainIdRaw: null }));
  add('no block at a final height', s.input, S({ ...src, blocks: {} }));
  add('a block that is junk', s.input, S({ ...src, blocks: { [blockKey]: { hash: 'nope', timestamp: 1 } } }));
  add('a block that is a list', s.input, S({ ...src, blocks: { [blockKey]: [] } }));
  add('a block with a fractional timestamp', s.input, S({ ...src, blocks: { [blockKey]: { hash: s.block.hash, timestamp: 1.5 } } }));
  add('a block whose hash is in upper case', s.input, S({ ...src, blocks: { [blockKey]: { hash: '0x' + s.block.hash.slice(2).toUpperCase(), timestamp: s.block.timestamp } } }));
  add('a source that has forgotten the transaction', s.input, S({ ...src, transactions: {} }));
  add('a headers-only source', s.input, S({ ...src, transactions: undefined }));
  add('no header and proof, by lookup', { ...s.input, publication: bare(s.publication) }, S(src));
  add('no header and proof, headers only', { ...s.input, publication: bare(s.publication) }, S({ ...src, transactions: undefined }));
  const { blockHeader: _h, ...noHeader } = s.publication;
  void _h;
  add('a proof without its header, by lookup', { ...s.input, publication: { ...noHeader, txProof: ['0xdead'] } }, S(src));
  add('a proof without its header, headers only', { ...s.input, publication: { ...noHeader, txProof: ['0xdead'] } }, S({ ...src, transactions: undefined }));

  // Declared finality.
  for (const finality of ['finalized', { confirmations: 64 }, { confirmations: 2, acceptNonFinal: true }, { confirmations: 64, acceptNonFinal: false },
    { confirmations: 0 }, { confirmations: 1.5 }, { confirmations: '64' }, 'latest', 7, null, [], { confirmations: 64.0 }]) {
    add(`declared finality ${JSON.stringify(finality)}`, s.input, S({ ...src, finality: finality as Json }));
    add(`declared finality ${JSON.stringify(finality)}, not final`, s.input, S({ ...src, finality: finality as Json, finalized: s.block.number - 1 }));
  }
  add('declared finality, refused offline', { ...s.input, p: randomP() }, S({ ...src, finality: 'finalized' }));

  // Deadlines.
  add('a source that never answers', { ...s.input, timeoutMs: 50 }, S({ ...src, fail: { canonicalBlock: 'hang' } }));
  add('a lookup that never answers, with a proof', { ...s.input, timeoutMs: 1000 }, S({ ...src, fail: { transaction: 'hang' } }));
  add('a lookup that never answers, no proof', { ...s.input, publication: bare(s.publication), timeoutMs: 50 }, S({ ...src, fail: { transaction: 'hang' } }));
  add('slow calls within the deadline', { ...s.input, publication: bare(s.publication), timeoutMs: 5000 }, S({ ...src, delayMs: 40 }));
  add('slow calls past the deadline', { ...s.input, publication: bare(s.publication), timeoutMs: 100 }, S({ ...src, delayMs: 40 }));
  for (const timeoutMs of [0, -1, '30', null, true]) add(`timeoutMs ${JSON.stringify(timeoutMs)}`, { ...s.input, timeoutMs }, S(src));

  // Placing the transaction.
  for (const index of [0, 1, 2, 3]) {
    const h = await honest({ index });
    add(`trie proof at index ${index}`, h.input, S({ ...h.source, transactions: undefined }));
  }
  {
    const p = randomP();
    const publisher = Wallet.createRandom();
    const filler = await signAnchorTx(Wallet.createRandom(), { data: randomP() });
    const raws = Array.from({ length: 200 }, () => filler);
    raws.push(await signAnchorTx(publisher, { data: p }));
    const block = fabricateBlock(raws);
    add('trie proof at index 200', { publication: publicationFrom(block, 200), p, anchorOrigin: ORIGIN, manifest: manifestOf(entry(publisher.address)) }, S({ ...sourceOf(block, { lookups: false }) }));
  }
  add('a transaction id that is another\'s', { ...s.input, publication: { ...s.publication, transactionId: keccak256(s.block.raws[0]) } }, S(src));
  add('a header that does not hash to the block hash', { ...s.input, publication: { ...s.publication, blockHeader: fabricateBlock(s.block.raws, s.block.number, s.block.timestamp + 12).header } }, S(src));
  {
    const proof = [...(s.publication.txProof as string[])];
    const last = proof.length - 1;
    const at = proof[last].length - 10;
    proof[last] = proof[last].slice(0, at) + (proof[last][at] === '0' ? '1' : '0') + proof[last].slice(at + 1);
    add('a tampered trie node', { ...s.input, publication: { ...s.publication, txProof: proof } }, S(src));
  }
  add('another transaction\'s proof', { ...s.input, publication: { ...s.publication, txIndex: 1, txProof: s.block.trie.proof(1) } }, S(src));
  add('an unused node appended', { ...s.input, publication: { ...s.publication, txProof: [...(s.publication.txProof as string[]), (s.publication.txProof as string[])[0]] } }, S(src));

  // Malformed publications.
  const P = s.publication;
  const junk: Array<[string, unknown]> = [
    ['a null publication', null], ['a string publication', 'evm-calldata/1'], ['an array publication', []],
    ['raw that is not hex', { ...P, rawTransaction: 'not hex' }], ['raw of odd length', { ...P, rawTransaction: '0x02f' }],
    ['raw truncated', { ...P, rawTransaction: s.block.raws[2].slice(0, 40) }],
    ['raw unsigned', { ...P, rawTransaction: Transaction.from(s.block.raws[2]).unsignedSerialized }],
    ['raw of 0x', { ...P, rawTransaction: '0x' }], ['raw with 0x90 first', { ...P, rawTransaction: '0x90' + s.block.raws[2].slice(4) }],
    ['raw of type 5', { ...P, rawTransaction: '0x05' + s.block.raws[2].slice(4) }], ['raw of type 0x00', { ...P, rawTransaction: '0x00' }],
    ['raw of type 0x7f', { ...P, rawTransaction: '0x7fc0' }], ['raw in upper case', { ...P, rawTransaction: '0x' + (P.rawTransaction as string).slice(2).toUpperCase() }],
    ['raw with 0X', { ...P, rawTransaction: '0X' + (P.rawTransaction as string).slice(2) }],
    ['a short block hash', { ...P, blockHash: '0x1234' }], ['a negative block number', { ...P, blockNumber: -1 }],
    ['a string block number', { ...P, blockNumber: String(P.blockNumber) }], ['a fractional block number', { ...P, blockNumber: 1.5 }],
    ['an integral float block number', { ...P, blockNumber: Number(P.blockNumber) + 0.0 }], ['a boolean block number', { ...P, blockNumber: true }],
    ['a proof that is not an array', { ...P, txProof: 'nodes' }], ['a proof of non-hex nodes', { ...P, txProof: ['zz'] }],
    ['an empty proof', { ...P, txProof: [] }], ['a proof with no index', { ...P, txIndex: undefined }],
    ['an index with no proof', { ...P, txProof: undefined }], ['a negative index', { ...P, txIndex: -1 }],
    ['a header of 0xdeadbeef', { ...P, blockHeader: '0xdeadbeef' }], ['a header that is not hex', { ...P, blockHeader: 'header' }],
    ['a transaction id that is a number', { ...P, transactionId: 42 }], ['a transaction id in upper case', { ...P, transactionId: '0x' + (P.transactionId as string).slice(2).toUpperCase() }],
    ['nulls for every optional field', { ...P, transactionId: null, blockHeader: null, txIndex: null, txProof: null, chain: null, publisher: null }],
    ['no raw transaction', bare({ ...P, rawTransaction: undefined })], ['a null raw transaction', { ...P, rawTransaction: null }],
    ['raw of 0xzz', { ...P, rawTransaction: '0xzz' }],
  ];
  for (const [label, pub] of junk) add(label, { ...s.input, publication: pub }, S(src));
  for (const junkHeader of ['0xdeadbeef', encodeRlp(['0x01', '0x02']), encodeRlp(new Array(15).fill(['0x01'])), encodeRlp(new Array(15).fill('0x'))]) {
    add(`a header that hashes to the block hash but is not one: ${junkHeader.slice(0, 12)}`, { ...s.input, publication: { ...P, blockHeader: junkHeader, blockHash: keccak256(junkHeader) } }, S(src));
  }
  const good = '0x' + '11'.repeat(20);
  for (const [label, manifest] of [
    ['a null manifest', null], ['a manifest that is an array', []], ['publishers that is a string', { publishers: 'x' }],
    ['publishers that is an array', { publishers: [] }], ['entries that are a string', { publishers: { [ORIGIN]: 'x' } }],
    ['entries that are null', { publishers: { [ORIGIN]: null } }], ['an entry that is null', { publishers: { [ORIGIN]: [null] } }],
    ['an entry that is an array', { publishers: { [ORIGIN]: [[]] } }],
    ['a bad address', { publishers: { [ORIGIN]: [{ address: '0x12', chain: SEPOLIA_CHAIN, namespace: 'test' }] } }],
    ['a bad namespace', { publishers: { [ORIGIN]: [{ address: good, chain: SEPOLIA_CHAIN, namespace: 'prod' }] } }],
    ['a bad date', { publishers: { [ORIGIN]: [{ address: good, chain: SEPOLIA_CHAIN, namespace: 'test', validUntil: 'soon' }] } }],
    ['a leading-zero chain id', { publishers: { [ORIGIN]: [{ address: good, chain: 'eip155:011155111', namespace: 'test' }] } }],
    ['a chain that is not a string', { publishers: { [ORIGIN]: [{ address: good, chain: 11155111, namespace: 'test' }] } }],
    ['a non-EVM entry beside the publisher', manifestOf({ address: 'x', chain: 'bip122:000000000019d6689c085ae165831e93', namespace: 'test' }, entry(s.publisher.address))],
    ['only non-EVM entries', manifestOf({ address: 'x', chain: 'bip122:000000000019d6689c085ae165831e93', namespace: 'test' })],
    ['two matching entries that disagree on the namespace', manifestOf(entry(s.publisher.address), entry(s.publisher.address, { namespace: 'production' }))],
    ['a checksummed address', manifestOf(entry(s.publisher.address))],
    ['an upper-case address', manifestOf(entry('0x' + s.publisher.address.slice(2).toUpperCase()))],
  ] as const) {
    add(`manifest: ${label}`, { ...s.input, manifest }, S(src));
  }
  add('the anchor origin is not a string', { ...s.input, anchorOrigin: 7 }, S(src));
  add('the anchor origin is "length" with publishers an array', { ...s.input, anchorOrigin: 'length', manifest: { publishers: [] } }, S(src));
  add('the anchor origin is "0" with publishers an array', { ...s.input, anchorOrigin: '0', manifest: { publishers: [[entry(s.publisher.address)]] } }, S(src));
  add('header sources that are a string', s.input, 'eip155:11155111');
  add('header sources that are a list', s.input, [src as unknown as Json]);
  return cases;
}

async function verifyEvmCase(c: { input: Record<string, unknown>; sources: unknown }) {
  const input = { ...c.input } as unknown as EvmPublicationInput;
  const scriptedByChain = c.sources !== null && typeof c.sources === 'object' && !Array.isArray(c.sources);
  const sources = scriptedByChain ? scriptedSources(c.sources as Record<string, SourceSpec>) : c.sources;
  return verifyEvmPublication({ ...input, ...(sources !== null && sources !== undefined && { headerSources: sources as never }) });
}

// ─── Anchor scenarios ──────────────────────────────────────────────────────

interface AnchorCase {
  name: string;
  artifacts: unknown;
  digest: unknown;
  options: Record<string, unknown>;
  /** For a token with a flipped bit: the byte it is in. */
  flipAt?: number;
  /** The TSA trust environment for this case alone. */
  env?: Record<string, string>;
}

const TSA_ENV = ['TZUN_TSA_TRUST_ANCHORS', 'TZUN_TSA_AUTHORITIES'] as const;

/** Run `f` with the TSA trust environment `env` names, then put the process's back. */
async function withTsaEnv<T>(env: Record<string, string> | undefined, f: () => Promise<T>): Promise<T> {
  if (env === undefined) return f();
  const saved = TSA_ENV.map((name) => [name, process.env[name]] as const);
  for (const name of TSA_ENV) {
    if (typeof env[name] === 'string') process.env[name] = env[name];
    else delete process.env[name];
  }
  try {
    return await f();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

function withTsa(token: string) {
  return { kind: 'rfc3161/1', token };
}

function derMutations(token: string): Array<[string, string, number?]> {
  const der = Buffer.from(token, 'base64');
  const out: Array<[string, string, number?]> = [];
  for (const cut of [1, 2, 5, 20, der.length >> 1, der.length - 40, der.length - 1]) {
    out.push([`truncated to ${cut} bytes`, der.subarray(0, cut).toString('base64')]);
  }
  const status = Buffer.from(der);
  // TimeStampResp ::= SEQUENCE { status SEQUENCE { INTEGER ... } ... }: find the status INTEGER.
  const seq = status.indexOf(Buffer.from([0x30, 0x03, 0x02, 0x01]));
  if (seq >= 0) {
    for (const v of [1, 2, 3, 0xff]) {
      const copy = Buffer.from(der);
      copy[seq + 4] = v;
      out.push([`status ${v}`, copy.toString('base64')]);
    }
  }
  for (let at = 0; at < der.length; at++) {
    for (const mask of at % 2 === 0 ? [0x01, 0x80] : [0x20]) {
      const copy = Buffer.from(der);
      copy[at] ^= mask;
      out.push([`byte ${at} xor ${mask}`, copy.toString('base64'), at]);
    }
  }
  out.push(['with trailing bytes', Buffer.concat([der, Buffer.from([0, 1, 2])]).toString('base64')]);
  out.push(['base64url', token.replace(/\+/g, '-').replace(/\//g, '_')]);
  out.push(['base64 with whitespace', token.replace(/(.{60})/g, '$1\n ')]);
  out.push(['base64 without padding', token.replace(/=+$/, '')]);
  out.push(['base64 with a stray =', token.slice(0, 40) + '=' + token.slice(40)]);
  out.push(['base64 with junk characters', '@@' + token + '!!']);
  out.push(['not base64', 'not a real token']);
  out.push(['x', 'x']);
  out.push(['a non-ASCII character', token.slice(0, 10) + 'é' + token.slice(10)]);
  return out;
}

async function anchorScenarios(): Promise<AnchorCase[]> {
  const cases: AnchorCase[] = [];
  const add = (name: string, artifacts: unknown, digest: unknown, options: Record<string, unknown>) =>
    cases.push({ name, artifacts, digest, options });

  // An EVM publication for a record, with its bundle material and a source that saw it.
  const evmFor = async (p: string, opts: { chainId?: bigint; timestamp?: number } = {}) => {
    const publisher = Wallet.createRandom();
    const raw = await signAnchorTx(publisher, { data: '0x' + p, chainId: opts.chainId });
    const block = fabricateBlock([...(await fillers(2)), raw], 7_000_000 + Math.floor(Math.random() * 1000), opts.timestamp ?? 1_790_000_000);
    const full = publicationFrom(block, 2);
    const envelope = { kind: 'evm-calldata/1', chain: SEPOLIA_CHAIN, transactionId: full.transactionId, blockNumber: full.blockNumber, blockHash: full.blockHash, publisher: publisher.address };
    return { publisher, block, full, envelope, source: sourceOf(block, { chainId: opts.chainId }) };
  };

  const r = anchoredRecord();
  const e = await evmFor(r.p);
  const manifest = { publishers: { [r.anchorOrigin]: [{ address: e.publisher.address, chain: SEPOLIA_CHAIN, namespace: 'production' }] } };
  const base = { sequenceNumber: r.sequenceNumber, chainId: r.chainId, publisherManifest: manifest, publicationMaterial: [e.full] };
  const withPubs = (rec: typeof r, pubs: unknown[]) => ({ anchor: { ...rec.anchor, publications: pubs } });
  const S = (spec: SourceSpec) => ({ [SEPOLIA_CHAIN]: spec });

  add('EVM: true', withPubs(r, [e.envelope]), r.digest, { ...base, evmHeaderSources: S(e.source) });
  add('EVM: bundle only', withPubs(r, [e.envelope]), r.digest, base);
  add('EVM: envelope only', withPubs(r, [e.envelope]), r.digest, { ...base, publicationMaterial: undefined, evmHeaderSources: S(e.source) });
  add('EVM: the full form in the envelope', withPubs(r, [e.full]), r.digest, { ...base, publicationMaterial: undefined, evmHeaderSources: S(e.source) });
  add('EVM: no sequence number, no chain id', withPubs(r, [e.envelope]), r.digest, { ...base, sequenceNumber: undefined, chainId: undefined, evmHeaderSources: S(e.source) });
  add('EVM: a finality depth', withPubs(r, [e.envelope]), r.digest, { ...base, evmHeaderSources: S({ ...e.source, finality: { confirmations: 64 } }) });
  add('EVM: networks override', withPubs(r, [e.envelope]), r.digest, { ...base, evmNetworks: { [SEPOLIA_CHAIN]: 'mainnet' }, evmHeaderSources: S(e.source) });
  add('EVM: material joined by block hash', withPubs(r, [{ ...e.envelope, transactionId: undefined }]), r.digest, { ...base, evmHeaderSources: S(e.source) });
  add('EVM: material in another block', withPubs(r, [e.envelope]), r.digest, { ...base, publicationMaterial: [{ ...e.full, blockHash: '0x' + '99'.repeat(32) }], evmHeaderSources: S(e.source) });
  add('EVM: material that is not a list', withPubs(r, [e.envelope]), r.digest, { ...base, publicationMaterial: e.full, evmHeaderSources: S(e.source) });
  add('EVM: material of junk entries', withPubs(r, [e.envelope]), r.digest, { ...base, publicationMaterial: [null, 'x', { kind: 'rfc3161/1', token: 'x' }, e.full], evmHeaderSources: S(e.source) });
  {
    // Two publications mined in one block: each envelope joins its own material.
    const other = Wallet.createRandom();
    const raw2 = await signAnchorTx(other, { data: '0x' + r.p });
    const block = fabricateBlock([e.block.raws[2], raw2], e.block.number, e.block.timestamp);
    const f0 = publicationFrom(block, 0);
    const f1 = publicationFrom(block, 1);
    const env1 = { kind: 'evm-calldata/1', chain: SEPOLIA_CHAIN, transactionId: f1.transactionId, blockNumber: f1.blockNumber, blockHash: f1.blockHash, publisher: other.address };
    const m2 = { publishers: { [r.anchorOrigin]: [{ address: e.publisher.address, chain: SEPOLIA_CHAIN, namespace: 'production' }, { address: other.address, chain: SEPOLIA_CHAIN, namespace: 'test' }] } };
    add('EVM: two in one block, joined by id', withPubs(r, [env1]), r.digest, { ...base, publisherManifest: m2, publicationMaterial: [f0, f1], evmHeaderSources: S(sourceOf(block)) });
    add('EVM: two in one block, by block hash is ambiguous', withPubs(r, [{ ...env1, transactionId: undefined }]), r.digest, { ...base, publisherManifest: m2, publicationMaterial: [f0, f1], evmHeaderSources: S(sourceOf(block)) });
    add('EVM: two true publications that disagree on the namespace', withPubs(r, [{ ...env1, transactionId: f0.transactionId, publisher: e.publisher.address }, env1]), r.digest, { ...base, publisherManifest: m2, publicationMaterial: [f0, f1], evmHeaderSources: S(sourceOf(block)) });
  }
  {
    const e2 = await evmFor(r.p, { timestamp: 1_780_000_000 });
    const m2 = { publishers: { [r.anchorOrigin]: [{ address: e.publisher.address, chain: SEPOLIA_CHAIN, namespace: 'production' }, { address: e2.publisher.address, chain: SEPOLIA_CHAIN, namespace: 'production' }] } };
    const sources = { ...e.source, blocks: { ...e.source.blocks, ...e2.source.blocks }, transactions: { ...e.source.transactions, ...e2.source.transactions } };
    add('EVM: two true publications, the earlier one first in time', withPubs(r, [e.envelope, e2.envelope]), r.digest, { ...base, publisherManifest: m2, publicationMaterial: [e.full, e2.full], evmHeaderSources: S({ ...sources, finalized: e.block.number + 64 }) });
    add('EVM: two true publications that disagree on finality', withPubs(r, [e.envelope, e2.envelope]), r.digest, { ...base, publisherManifest: m2, publicationMaterial: [e.full, e2.full], evmHeaderSources: S({ ...sources, finalized: e.block.number + 64, finality: 'finalized' }) });
    add('EVM: one true, one false', withPubs(r, [e.envelope, e2.envelope]), r.digest, { ...base, publicationMaterial: [e.full, e2.full], evmHeaderSources: S({ ...sources, finalized: e.block.number + 64 }) });
  }
  {
    // A legacy publication signed before EIP-155 (v 27): it signs no chain id, so item 5
    // refuses it, and anchor.evm.tx reports signedChainId null (tzun-anchor/1 §10.7).
    const legacy = signLegacy(e.publisher.signingKey, { data: '0x' + r.p, eip155: false, yParity: 0 });
    const block = fabricateBlock([...(await fillers(2)), legacy], e.block.number + 1, e.block.timestamp + 12);
    const full = publicationFrom(block, 2);
    const envelope = { kind: 'evm-calldata/1', chain: SEPOLIA_CHAIN, transactionId: full.transactionId, blockNumber: full.blockNumber, blockHash: full.blockHash, publisher: e.publisher.address };
    add('EVM: a legacy publication signed before EIP-155', withPubs(r, [envelope]), r.digest, { ...base, publicationMaterial: [full], evmHeaderSources: S(sourceOf(block)) });
  }
  add('EVM: [null, true]', withPubs(r, [null, e.envelope]), r.digest, { ...base, evmHeaderSources: S(e.source) });
  add('EVM: [no kind, true]', withPubs(r, [{ token: 'x' }, e.envelope]), r.digest, { ...base, evmHeaderSources: S(e.source) });
  add('EVM: [unknown kind, not checked]', withPubs(r, [{ kind: 'witness/1' }, e.envelope]), r.digest, base);
  add('EVM: [unknown kind]', withPubs(r, [{ kind: 'witness/1' }]), r.digest, base);
  add('EVM: [unsupported tx type, unknown kind]', withPubs(r, [{ ...e.full, rawTransaction: '0x05c0' }, { kind: 'witness/1' }]), r.digest, { ...base, publicationMaterial: undefined });
  add('EVM: a kind that is a number', withPubs(r, [{ kind: 7 }]), r.digest, base);

  // Test and platform origins.
  const t = anchoredRecord({ domainPrefix: TEST_PREFIX });
  const et = await evmFor(t.p);
  const tm = (ns: string) => ({ publishers: { [t.anchorOrigin]: [{ address: et.publisher.address, chain: SEPOLIA_CHAIN, namespace: ns }] } });
  add('a test origin under a production entry', withPubs(t, [et.envelope]), t.digest, { sequenceNumber: t.sequenceNumber, chainId: t.chainId, publisherManifest: tm('production'), publicationMaterial: [et.full], evmHeaderSources: S(et.source) });
  add('a test origin, a false publication', withPubs(t, [et.envelope]), t.digest, { sequenceNumber: t.sequenceNumber, chainId: t.chainId, publisherManifest: tm('test'), publicationMaterial: [{ ...et.full, rawTransaction: e.full.rawTransaction }], evmHeaderSources: S(et.source) });
  const pl = anchoredRecord({ domainPrefix: PLATFORM_PREFIX, logOrigin: `${PLATFORM_PREFIX}/${sha256('opaque').slice(0, 32)}` });
  const ep = await evmFor(pl.p);
  add('a platform origin', withPubs(pl, [ep.envelope]), pl.digest, { sequenceNumber: pl.sequenceNumber, chainId: 'user-abc', publisherManifest: { publishers: { [pl.anchorOrigin]: [{ address: ep.publisher.address, chain: SEPOLIA_CHAIN, namespace: 'production' }] } }, publicationMaterial: [ep.full], evmHeaderSources: S(ep.source) });

  // RFC 3161.
  const tsa = await makeTsaFixture({ digestHex: r.p, genTime: new Date('2026-09-20T12:00:00Z') });
  const tsaMs = await makeTsaFixture({ digestHex: r.p, genTime: new Date('2026-09-20T12:00:00.123Z') });
  const other = await makeTsaFixture({ digestHex: sha256('another P'), genTime: new Date('2026-09-20T12:00:00Z') });
  add('RFC 3161: no trust supplied', withPubs(r, [withTsa(tsa.tokenBase64)]), r.digest, base);
  add('RFC 3161: a genTime with milliseconds', withPubs(r, [withTsa(tsaMs.tokenBase64)]), r.digest, base);
  add('RFC 3161: another P, no trust supplied', withPubs(r, [withTsa(other.tokenBase64)]), r.digest, base);
  add('RFC 3161: beside a true EVM publication', withPubs(r, [withTsa(tsa.tokenBase64), e.envelope]), r.digest, { ...base, evmHeaderSources: S(e.source) });
  add('RFC 3161: an empty token', withPubs(r, [withTsa('')]), r.digest, base);
  add('RFC 3161: a token that is a number', withPubs(r, [{ kind: 'rfc3161/1', token: 7 }]), r.digest, base);
  for (const [label, token, flipAt] of derMutations(tsa.tokenBase64)) {
    add(`RFC 3161: ${label}`, withPubs(r, [withTsa(token)]), r.digest, base);
    if (flipAt !== undefined) cases[cases.length - 1].flipAt = flipAt;
  }
  // Trust supplied: the Python SDK cannot run the CMS check; the parity test expects that here.
  add('RFC 3161 (trust supplied): a valid token', withPubs(r, [withTsa(tsa.tokenBase64)]), r.digest, { ...base, trustAnchorsPem: [tsa.caPem] });
  add('RFC 3161 (trust supplied): an unreadable token', withPubs(r, [withTsa('x')]), r.digest, { ...base, trustAnchorsPem: [tsa.caPem] });
  add('RFC 3161 (trust supplied by authority): a valid token', withPubs(r, [withTsa(tsa.tokenBase64)]), r.digest, { ...base, authorities: ['freetsa'] });

  // Steps 1 to 5 around real publications.
  add('legacy blockchainAnchor', { blockchainAnchor: { txHash: '0x' }, anchor: null }, r.digest, base);
  add('no anchor', {}, r.digest, base);
  add('artifacts that are null', null, r.digest, base);
  add('artifacts that are a list', [r.anchor], r.digest, base);
  add('an anchor that is a string', { anchor: 'x' }, r.digest, base);
  add('an extra member', { anchor: { ...r.anchor, extra: 1 } }, r.digest, base);
  add('a member that is null', { anchor: { ...r.anchor, logPath: null } }, r.digest, base);
  add('a float leaf index', { anchor: { ...r.anchor, leafIndex: r.anchor.leafIndex + 0.5 } }, r.digest, base);
  add('a leaf index as a string', { anchor: { ...r.anchor, leafIndex: String(r.anchor.leafIndex) } }, r.digest, base);
  add('a boolean anchor leaf index', { anchor: { ...r.anchor, anchorLeafIndex: true } }, r.digest, base);
  add('an upper-case path element', { anchor: { ...r.anchor, logPath: r.anchor.logPath.map((h) => h.toUpperCase()) } }, r.digest, base);
  add('a digest in upper case', withPubs(r, [e.envelope]), r.digest.toUpperCase(), { ...base, evmHeaderSources: S(e.source) });
  add('a digest that is not a string', withPubs(r, [e.envelope]), 7, base);
  add('a sequence number of 0', withPubs(r, [e.envelope]), r.digest, { ...base, sequenceNumber: 0 });
  add('a fractional sequence number', withPubs(r, [e.envelope]), r.digest, { ...base, sequenceNumber: 3.5 });
  add('a sequence number that is a string', withPubs(r, [e.envelope]), r.digest, { ...base, sequenceNumber: '3' });
  add('a chain id that is a number', withPubs(r, [e.envelope]), r.digest, { ...base, chainId: 7 });
  add('an evmTimeoutMs that is nonsense', withPubs(r, [e.envelope]), r.digest, { ...base, evmTimeoutMs: -5, evmHeaderSources: S(e.source) });
  return cases;
}

function anchorOptions(o: Record<string, unknown>): AnchorVerifyOptions {
  const { evmHeaderSources, ...rest } = o;
  const sources = scriptedSources(evmHeaderSources as Record<string, SourceSpec> | undefined);
  return { ...(rest as AnchorVerifyOptions), ...(sources && { evmHeaderSources: sources }) };
}

async function main(): Promise<void> {
  const cmd = JSON.parse(await readStdin()) as { action: string } & Record<string, unknown>;
  // stdout carries the answer: anything the SDK logs goes to stderr.
  console.log = (...args: unknown[]) => process.stderr.write(`${args.map(String).join(' ')}\n`);
  let out: unknown;
  switch (cmd.action) {
    case 'corpus':
      out = corpus(cmd as Corpus);
      break;
    case 'transactions':
      out = { cases: await transactions() };
      break;
    // One case at a time: some cases time header sources out.
    case 'evm-scenarios': {
      const cases = [];
      for (const c of await evmScenarios()) cases.push({ ...c, verdict: await verifyEvmCase(c) });
      out = { cases };
      break;
    }
    case 'verify-evm': {
      const verdicts = [];
      for (const c of cmd.cases as EvmCase[]) verdicts.push(await verifyEvmCase(c));
      out = { verdicts };
      break;
    }
    case 'anchor-scenarios': {
      const cases = [];
      for (const c of await anchorScenarios()) {
        cases.push({ ...c, verdict: await verifyAnchor(c.artifacts, c.digest as string, anchorOptions(c.options)) });
      }
      out = { cases };
      break;
    }
    case 'verify-anchor': {
      const verdicts: unknown[] = [];
      for (const c of cmd.cases as AnchorCase[]) {
        try {
          verdicts.push(await withTsaEnv(c.env, () => verifyAnchor(c.artifacts, c.digest as string, anchorOptions(c.options))));
        } catch (err) {
          if (!(err instanceof UnreadableTrustAnchorError)) throw err;
          verdicts.push({ refused: err.message });
        }
      }
      out = { verdicts };
      break;
    }
    case 'networks':
      out = { networks: DEFAULT_EVM_NETWORKS };
      break;
    case 'trie':
      out = (() => {
        const values = cmd.values as string[];
        const trie = buildTxTrie(values);
        return { root: trie.root, proofs: values.map((_v, i) => trie.proof(i)) };
      })();
      break;
    default:
      throw new Error(`unknown action ${cmd.action}`);
  }
  process.stdout.write(JSON.stringify(out, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)));
}

// The verifier's deadline timer does not hold the process open, so a case whose
// header source never answers would otherwise let Node exit before it times out.
const keepAlive = setInterval(() => undefined, 1_000);
main()
  .catch((err) => {
    process.stderr.write(`${(err as Error).stack ?? err}\n`);
    process.exitCode = 1;
  })
  .finally(() => clearInterval(keepAlive));
