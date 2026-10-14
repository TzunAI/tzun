/**
 * Generate vectors/evm-anchor-vectors.json (tzun-anchor/1 §13): the
 * publisher-manifest validity cases of §9, each a manifest entry whose
 * `validFrom` or `validUntil` sits at, just inside or just outside the time of
 * a block that carries a real publication, and the verdict §10.4 states for
 * it; and the transaction cases of §10.4 item 2, signed transactions at each
 * edge of what item 2 refuses, each with the verdict §10.4 states for it.
 *
 *   pnpm exec tsx scripts/generate-evm-anchor-vectors.ts > vectors/evm-anchor-vectors.json
 *
 * The publication is not made here. It is epoch 0's of
 * vectors/anchor-e2e-vectors.json, signed and mined on anvil, copied byte for
 * byte with the canonical block that run's node reported; the Go gate's evm/
 * module checks that material with go-ethereum. The header source's
 * transaction lookup states what the trie proof already proves: the
 * transaction is in that block, sent by the publisher.
 *
 * NOTHING HERE CALLS THE SDK. Each bound is read by a transcription of §9
 * written for this script: the grammar, the range checks, and a comparison at
 * full precision, the fraction's digits kept as a string, the calendar in
 * BigInt. Each case's verdicts are then stated from §10.4 for three ways of
 * presenting the same publication (see `format.modes` in the output). The
 * TypeScript and Python suites hold their verifiers to the file.
 *
 * The transaction cases are signed here, deterministically (RFC 6979), by a
 * well-known throwaway key, or carry a signature built so that it recovers a
 * chosen way; ethers supplies keccak-256, RLP, signing and public-key
 * recovery. Whether item 2 refuses each one is read by a transcription of its
 * rules written for this script, checked against what the case was built to
 * be, and the verdict is stated from §10.4.
 * `pnpm run regenerate:vectors -- --anvil` rewrites it right after
 * anchor-e2e-vectors.json, whose epoch 0 it copies.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { N, Signature, SigningKey, computeAddress, encodeRlp, keccak256, toBeHex, type RlpStructuredData } from 'ethers';

const E2E = JSON.parse(readFileSync(join(__dirname, '..', 'vectors', 'anchor-e2e-vectors.json'), 'utf8')) as {
  chain: string;
  anchorOrigin: string;
  manifest: { publishers: Record<string, Array<{ address: string; chain: string; namespace: string }>> };
  headerSource: { chainId: number; finalizedBlockNumber: number; finality: string };
  epochs: Array<{
    p: string;
    publication: Record<string, unknown> & { transactionId: string; blockNumber: number; blockHash: string; publisher: string };
    canonicalBlock: { number: number; hash: string; timestamp: number };
  }>;
};

// ---- §9, transcribed ----------------------------------------------------------------------

/** YYYY-MM-DD "T" hh:mm:ss [ "." 1*DIGIT ] ( "Z" / ( "+" / "-" ) hh:mm ), T and Z uppercase only. */
const GRAMMAR = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$/;

/** An instant: whole unix seconds, and the fraction's digits exactly as written ('' for none). */
interface Instant {
  seconds: bigint;
  fraction: string;
}

function isLeapYear(y: bigint): boolean {
  return (y % 4n === 0n && y % 100n !== 0n) || y % 400n === 0n;
}

function daysInMonth(y: bigint, m: bigint): bigint {
  if (m === 2n) return isLeapYear(y) ? 29n : 28n;
  return [4n, 6n, 9n, 11n].includes(m) ? 30n : 31n;
}

/** Days from 1970-01-01 to y-m-d in the proleptic Gregorian calendar, counted month by month. */
function daysSinceEpoch(y: bigint, m: bigint, d: bigint): bigint {
  let days = 0n;
  if (y >= 1970n) for (let year = 1970n; year < y; year++) days += isLeapYear(year) ? 366n : 365n;
  else for (let year = y; year < 1970n; year++) days -= isLeapYear(year) ? 366n : 365n;
  for (let month = 1n; month < m; month++) days += daysInMonth(y, month);
  return days + d - 1n;
}

/** A bound as §9 reads it: `null` for absent or null (unbounded), 'malformed' for anything else it refuses. */
function readBound(value: unknown): Instant | null | 'malformed' {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') return 'malformed';
  const g = GRAMMAR.exec(value);
  if (!g) return 'malformed';
  const [year, month, day, hour, minute, second] = g.slice(1, 7).map((s) => BigInt(s));
  if (month < 1n || month > 12n || day < 1n || day > daysInMonth(year, month)) return 'malformed';
  if (hour > 23n || minute > 59n || second > 59n) return 'malformed';
  let offset = 0n;
  if (g[8] !== undefined) {
    const [oh, om] = [BigInt(g[9]), BigInt(g[10])];
    if (oh > 23n || om > 59n) return 'malformed';
    offset = (g[8] === '+' ? 1n : -1n) * (oh * 3600n + om * 60n);
  }
  const seconds = daysSinceEpoch(year, month, day) * 86400n + hour * 3600n + minute * 60n + second - offset;
  return { seconds, fraction: g[7] ?? '' };
}

/** The sign of (instant − t) for a whole second t, at full precision. */
function compare(i: Instant, t: bigint): -1 | 0 | 1 {
  if (i.seconds !== t) return i.seconds < t ? -1 : 1;
  return /[1-9]/.test(i.fraction) ? 1 : 0;
}

type Window = 'admits' | 'excludes' | 'malformed';

/** Whether an entry with these bounds is valid at block time t: both ends inclusive (§9). */
function windowAt(bounds: Record<string, unknown>, t: bigint): Window {
  const from = readBound(bounds.validFrom);
  const until = readBound(bounds.validUntil);
  if (from === 'malformed' || until === 'malformed') return 'malformed';
  if (from !== null && compare(from, t) > 0) return 'excludes';
  if (until !== null && compare(until, t) < 0) return 'excludes';
  return 'admits';
}

// ---- §10.4, transcribed -------------------------------------------------------------------

type Mode = 'header' | 'noHeader' | 'offline';
interface Check {
  outcome: 'checked-correct' | 'checked-wrong' | 'not-checked';
  reason?: string;
}
interface Expect {
  valid: boolean | null;
  reason?: string;
  tx: Check;
  canonical: Check;
  inclusion?: 'tx_proof' | 'header_source';
}

function expectFor(window: Window, mode: Mode): Expect {
  const blocked: Check = { outcome: 'not-checked', reason: 'blocked_by:anchor.evm.tx' };
  // Item 5: an EVM entry that breaks a rule of §9 makes the entries unreadable.
  if (window === 'malformed') {
    return { valid: null, reason: 'publication_not_checked', tx: { outcome: 'not-checked', reason: 'input_not_supplied:publisher_manifest' }, canonical: blocked };
  }
  // Item 6 (the bundle's header) or item 13 (the block time the source
  // confirmed): no matching entry valid at the block time. Reported on
  // anchor.evm.tx, once.
  if (window === 'excludes') {
    return { valid: false, reason: 'evm_sender_mismatch', tx: { outcome: 'checked-wrong', reason: 'evm_sender_mismatch' }, canonical: blocked };
  }
  // Offline, the header can make the publication fail but never pass.
  if (mode === 'offline') {
    return {
      valid: null,
      reason: 'publication_not_checked',
      tx: { outcome: 'checked-correct' },
      canonical: { outcome: 'not-checked', reason: 'input_not_supplied:evm_header_source' },
    };
  }
  return {
    valid: true,
    tx: { outcome: 'checked-correct' },
    canonical: { outcome: 'checked-correct' },
    inclusion: mode === 'header' ? 'tx_proof' : 'header_source',
  };
}

// ---- The cases ----------------------------------------------------------------------------

const epoch = E2E.epochs[0];
const pub = epoch.publication;
const block = epoch.canonicalBlock;
const T = block.timestamp;
const entry = E2E.manifest.publishers[E2E.anchorOrigin][0];

/** Unix second s as YYYY-MM-DDThh:mm:ss in UTC. */
const utc = (s: number) => new Date(s * 1000).toISOString().slice(0, 19);
/** Unix second s as YYYY-MM-DDThh:mm:ss local time at an offset of `sign` hh:mm. */
const at = (s: number, sign: '+' | '-', hh: number, mm: number) => utc(s + (sign === '+' ? 1 : -1) * (hh * 3600 + mm * 60));
const off = (sign: '+' | '-', hh: number, mm: number) => `${sign}${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}`;
const localWithFraction = (s: number, fraction: string, sign: '+' | '-', hh: number, mm: number) =>
  `${at(s, sign, hh, mm)}${fraction}${off(sign, hh, mm)}`;

/** The block's own date and minute, with another second: a leap second at the block's minute. */
const blockMinute = utc(T).slice(0, 17);
const blockDate = utc(T).slice(0, 10);

const cases: Array<{ name: string; bounds: Record<string, unknown> }> = [
  // validFrom: inclusive, and a fraction past the block's second puts it after the block.
  { name: 'validFrom exactly at the block time', bounds: { validFrom: `${utc(T)}Z` } },
  { name: 'validFrom at the block time, a zero fraction', bounds: { validFrom: `${utc(T)}.000Z` } },
  { name: 'validFrom at the block time, twelve zero digits', bounds: { validFrom: `${utc(T)}.000000000000Z` } },
  { name: 'validFrom half a millisecond after the block time (§9, §13)', bounds: { validFrom: `${utc(T)}.0005Z` } },
  { name: 'validFrom a tenth of a nanosecond after the block time', bounds: { validFrom: `${utc(T)}.0000000001Z` } },
  { name: 'validFrom a millisecond after the block time', bounds: { validFrom: `${utc(T)}.001Z` } },
  { name: 'validFrom sixteen nines past the block time', bounds: { validFrom: `${utc(T)}.9999999999999999Z` } },
  { name: 'validFrom a second after the block time', bounds: { validFrom: `${utc(T + 1)}Z` } },
  { name: 'validFrom a second before the block time', bounds: { validFrom: `${utc(T - 1)}Z` } },
  { name: 'validFrom half a millisecond into the second before the block (§13: a block at the next second holds)', bounds: { validFrom: `${utc(T - 1)}.0005Z` } },
  { name: 'validFrom 10^-16 s before the block time', bounds: { validFrom: `${utc(T - 1)}.9999999999999999Z` } },
  { name: 'validFrom half a millisecond after the block time, written at +05:30', bounds: { validFrom: localWithFraction(T, '.0005', '+', 5, 30) } },
  { name: 'validFrom exactly at the block time, written at -07:00', bounds: { validFrom: localWithFraction(T, '', '-', 7, 0) } },
  { name: 'validFrom exactly at the block time, written at -00:00', bounds: { validFrom: `${utc(T)}-00:00` } },
  { name: 'validFrom half a millisecond before the block time, written at +23:59', bounds: { validFrom: localWithFraction(T - 1, '.9995', '+', 23, 59) } },

  // validUntil: inclusive, and a fraction past the block's second still admits it.
  { name: 'validUntil exactly at the block time (§13: the window\'s end at the block time holds)', bounds: { validUntil: `${utc(T)}Z` } },
  { name: 'validUntil at the block time, a zero fraction', bounds: { validUntil: `${utc(T)}.000Z` } },
  { name: 'validUntil half a millisecond after the block time', bounds: { validUntil: `${utc(T)}.0005Z` } },
  { name: 'validUntil sixteen nines past the block time', bounds: { validUntil: `${utc(T)}.9999999999999999Z` } },
  { name: 'validUntil a tenth of a nanosecond before the block time', bounds: { validUntil: `${utc(T - 1)}.9999999999Z` } },
  { name: 'validUntil half a millisecond before the block time', bounds: { validUntil: `${utc(T - 1)}.9995Z` } },
  { name: 'validUntil a second before the block time (§13: a sender outside its window)', bounds: { validUntil: `${utc(T - 1)}Z` } },
  { name: 'validUntil a second after the block time', bounds: { validUntil: `${utc(T + 1)}Z` } },
  { name: 'validUntil half a millisecond before the block time, written at -09:30', bounds: { validUntil: localWithFraction(T - 1, '.9995', '-', 9, 30) } },
  { name: 'validUntil exactly at the block time, written at +05:45', bounds: { validUntil: localWithFraction(T, '', '+', 5, 45) } },

  // Both ends.
  { name: 'a window of one instant, the block time', bounds: { validFrom: `${utc(T)}Z`, validUntil: `${utc(T)}Z` } },
  { name: 'a window inside the block\'s second that holds no whole second', bounds: { validFrom: `${utc(T)}.0000000001Z`, validUntil: `${utc(T)}.9999999999Z` } },
  { name: 'a window two tenths of a nanosecond wide around the block time', bounds: { validFrom: `${utc(T - 1)}.9999999999Z`, validUntil: `${utc(T)}.0000000001Z` } },
  { name: 'a window that ends before it starts', bounds: { validFrom: `${utc(T + 1)}Z`, validUntil: `${utc(T - 1)}Z` } },
  { name: 'both bounds null: unbounded', bounds: { validFrom: null, validUntil: null } },
  { name: 'no bounds: unbounded', bounds: {} },

  // Leap days are dates; a leap second is not a second of §9.
  { name: 'validFrom on a leap day after the block (2028-02-29)', bounds: { validFrom: '2028-02-29T00:00:00Z' } },
  { name: 'validUntil on a leap day after the block (2028-02-29)', bounds: { validUntil: '2028-02-29T00:00:00Z' } },
  { name: 'validFrom on a leap day of a year divisible by 400 (2000-02-29)', bounds: { validFrom: '2000-02-29T00:00:00Z' } },
  { name: 'validFrom on the leap day of year 0000', bounds: { validFrom: '0000-02-29T00:00:00Z' } },
  { name: 'validUntil at the last instant of a leap day before the block (2024-02-29)', bounds: { validUntil: '2024-02-29T23:59:59.9999999999Z' } },
  { name: 'validUntil at the last instant of year 9999', bounds: { validUntil: '9999-12-31T23:59:59.9999999999Z' } },
  { name: 'validFrom on a leap day at +02:00 that is February 28 in UTC (2028-02-29T01:00:00+02:00)', bounds: { validFrom: '2028-02-29T01:00:00+02:00' } },
];

/** Values §9 refuses, each tried as validFrom and as validUntil. */
const malformed: Array<[string, unknown]> = [
  ['a leap second at the block\'s minute', `${blockMinute}60Z`],
  ['a leap second UTC inserted (2016-12-31T23:59:60Z)', '2016-12-31T23:59:60Z'],
  ['February 29 in a common year', '2026-02-29T00:00:00Z'],
  ['February 29 in a century year that is not a leap year', '2100-02-29T00:00:00Z'],
  ['a day past the end of the month (2026-09-31)', '2026-09-31T00:00:00Z'],
  ['hour 24 (T24:00:00)', `${blockDate}T24:00:00Z`],
  ['minute 60', `${blockDate}T23:60:00Z`],
  ['a lowercase t', `${utc(T).replace('T', 't')}Z`],
  ['a lowercase z', `${utc(T)}z`],
  ['a point with no digits', `${utc(T)}.Z`],
  ['no offset', utc(T)],
  ['an offset of +24:00', `${utc(T)}+24:00`],
  ['an offset minute of 60', `${utc(T)}+05:60`],
  ['a space for the T', `${utc(T).replace('T', ' ')}Z`],
  ['a fraction digit that is not ASCII (U+0665)', `${utc(T)}.000٥Z`],
  ['a six-digit year', `+00${utc(T)}Z`],
  ['a number of unix seconds', T],
];
for (const [label, value] of malformed) {
  cases.push({ name: `validFrom: ${label}`, bounds: { validFrom: value } });
  cases.push({ name: `validUntil: ${label}`, bounds: { validUntil: value } });
}

const names = new Set(cases.map((c) => c.name));
if (names.size !== cases.length) throw new Error('two cases share a name');

const MODES: Mode[] = ['header', 'noHeader', 'offline'];
const validityBounds = cases.map((c) => {
  const window = windowAt(c.bounds, BigInt(T));
  return { name: c.name, bounds: c.bounds, window, expect: Object.fromEntries(MODES.map((m) => [m, expectFor(window, m)])) };
});
// Each outcome is reached, and each bound on each side of the block.
for (const w of ['admits', 'excludes', 'malformed'] as const) {
  if (!validityBounds.some((c) => c.window === w)) throw new Error(`no case ${w}`);
}

// ---- §10.4 item 2, transcribed ----------------------------------------------------------

/** ⌊n/2⌋ for the secp256k1 order n: the largest s EIP-2 allows. */
const HALF_N = N / 2n;
/** The field prime of secp256k1. */
const FIELD_P = 2n ** 256n - 2n ** 32n - 977n;

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
const isXCoordinate = (x: bigint) => modPow((x ** 3n + 7n) % FIELD_P, (FIELD_P - 1n) / 2n, FIELD_P) === 1n;

/** A scalar as RLP writes it: no leading zero, and 0 as the empty string. */
const scalar = (n: bigint | number): string => (BigInt(n) === 0n ? '0x' : toBeHex(BigInt(n)));
/** An RLP scalar's value. */
const num = (item: RlpStructuredData): bigint => (item === '0x' ? 0n : BigInt(item as string));

type TxType = 0 | 1 | 2;
interface Built {
  type: TxType;
  /** The unsigned fields, in signing order, without the EIP-155 chain fields. */
  body: RlpStructuredData[];
  /** v for legacy, yParity for typed. */
  v: bigint;
  r: bigint;
  s: bigint;
}

/** Which rule of item 2 a transaction breaks, or null when item 2 reads it and a key recovers. */
type Rule = 'typed-chain-id' | 'legacy-v' | 'signature-scalars' | 'fee-cap' | 'public-key-recovery';

/** The digest a signature over these fields signs; a legacy v at or above 35 signs EIP-155's chain fields. */
function signingDigest(type: TxType, body: RlpStructuredData[], v: bigint): string {
  if (type !== 0) return keccak256(`0x0${type}${encodeRlp(body).slice(2)}`);
  if (v === 27n || v === 28n) return keccak256(encodeRlp(body));
  return keccak256(encodeRlp([...body, scalar((v - 35n) / 2n), '0x', '0x']));
}

/**
 * The rules of §10.4 item 2 a signed transaction can break, read from its
 * fields: a typed chain id of 0; a legacy v other than 27, 28 or 37 and above
 * (chainId * 2 + 35 or + 36 for a chain id of 1 or more); r outside [1, n - 1],
 * s outside [1, n/2] or a typed yParity other than 0 or 1; an EIP-1559 tip above
 * its fee cap; and a signature from which no public key recovers.
 */
function breaks(t: Built): Rule | null {
  if (t.type !== 0 && num(t.body[0]) < 1n) return 'typed-chain-id';
  if (t.type === 0 && t.v !== 27n && t.v !== 28n && t.v < 37n) return 'legacy-v';
  if (t.r < 1n || t.r >= N || t.s < 1n || t.s > HALF_N) return 'signature-scalars';
  if (t.type !== 0 && t.v !== 0n && t.v !== 1n) return 'signature-scalars';
  if (t.type === 2 && num(t.body[2]) > num(t.body[3])) return 'fee-cap';
  return recovered(t) === null ? 'public-key-recovery' : null;
}

/** The address the signature recovers over the transaction's digest, or null when no public key recovers. */
function recovered(t: Built): string | null {
  if (!isXCoordinate(t.r)) return null;
  const yParity = t.type !== 0 ? Number(t.v) : t.v === 27n || t.v === 28n ? Number(t.v - 27n) : Number((t.v - 35n) % 2n);
  try {
    const sig = Signature.from({ r: toBeHex(t.r, 32), s: toBeHex(t.s, 32), yParity: yParity as 0 | 1 });
    return computeAddress(SigningKey.recoverPublicKey(signingDigest(t.type, t.body, t.v), sig)).toLowerCase();
  } catch {
    // The point at infinity.
    return null;
  }
}

/** The signed envelope: `type ‖ rlp(fields)`, or `rlp(fields)` for legacy. */
function envelope(t: Built): string {
  const fields = encodeRlp([...t.body, scalar(t.v), scalar(t.r), scalar(t.s)]);
  return t.type === 0 ? fields : `0x0${t.type}${fields.slice(2)}`;
}

/** The chain id the fields sign: a typed transaction's first field, a legacy EIP-155 v's, 0 for v 27 or 28. */
function signedChainId(t: Built): bigint {
  if (t.type !== 0) return num(t.body[0]);
  return t.v >= 35n ? (t.v - 35n) / 2n : 0n;
}

// ---- The transaction cases ----------------------------------------------------------------

/** The throwaway key of EIP-155's worked example, 0x46 repeated: never a publisher anywhere real. */
const KEY = new SigningKey('0x' + '46'.repeat(32));
const KEY_ADDRESS = computeAddress(KEY.publicKey).toLowerCase();
const TX_CHAIN = 1n;
const TX_P = '0x' + epoch.p;

function typedBody(type: 1 | 2, opts: { chainId?: bigint; nonce?: number; tip?: bigint; cap?: bigint } = {}): RlpStructuredData[] {
  const head = [scalar(opts.chainId ?? TX_CHAIN), scalar(opts.nonce ?? 0)];
  const fees = type === 2 ? [scalar(opts.tip ?? 1_000_000_000n), scalar(opts.cap ?? 3_000_000_000n)] : [scalar(2_000_000_000n)];
  return [...head, ...fees, scalar(30_000), KEY_ADDRESS, '0x', TX_P, []];
}

/** The key's signature over a typed body. */
function signedTyped(type: 1 | 2, body: RlpStructuredData[]): Built {
  const sig = KEY.sign(signingDigest(type, body, 0n));
  return { type, body, v: BigInt(sig.yParity), r: BigInt(sig.r), s: BigInt(sig.s) };
}

/** The key's legacy signature: EIP-155 for chainId when it is not null, else unprotected; at the first nonce with this parity. */
function signedLegacy(chainId: bigint | null, yParity: 0 | 1): Built {
  for (let nonce = 0; nonce < 64; nonce++) {
    const body: RlpStructuredData[] = [scalar(nonce), scalar(2_000_000_000n), scalar(30_000), KEY_ADDRESS, '0x', TX_P];
    const v = chainId === null ? 27n + BigInt(yParity) : chainId * 2n + 35n + BigInt(yParity);
    const sig = KEY.sign(signingDigest(0, body, v));
    if (sig.yParity === yParity) return { type: 0, body, v, r: BigInt(sig.r), s: BigInt(sig.s) };
  }
  throw new Error('no nonce below 64 gives this parity');
}

/** The same signature with s above n/2: n - s and the other parity, which recovers the same key. */
function highS(t: Built): Built {
  const v = t.type !== 0 ? t.v ^ 1n : t.v === 27n || t.v === 28n ? 55n - t.v : t.v % 2n === 1n ? t.v + 1n : t.v - 1n;
  return { ...t, v, s: N - t.s };
}

/** The smallest r that is (or is not) a point's x-coordinate: a public key recovers from (r, s) for any s in [1, n/2] exactly when it is. */
function firstR(xCoordinate: boolean): bigint {
  let r = 1n;
  while (isXCoordinate(r) !== xCoordinate) r++;
  return r;
}

const base2 = signedTyped(2, typedBody(2));
const atHalf: Built = { ...base2, v: 0n, r: firstR(true), s: HALF_N };
const aboveCap = signedTyped(2, typedBody(2, { tip: 3_000_000_001n, cap: 3_000_000_000n }));
// With R = (z / s) G and r = x(R), recovery gives r^-1 (s R - z G), the point at infinity.
const z = BigInt(signingDigest(2, base2.body, 0n)) % N;
const infinityPoint = SigningKey.computePublicKey(toBeHex(z, 32), false);
const atInfinity: Built = {
  ...base2,
  v: (BigInt('0x' + infinityPoint.slice(68)) & 1n) === 1n ? 1n : 0n,
  r: BigInt('0x' + infinityPoint.slice(4, 68)),
  s: 1n,
};

const transactionSpecs: Array<{ id: string; name: string; built: Built; rule: Rule | null; signer: 'key' | 'recovered' }> = [
  // A typed transaction signs a chain id of 1 or more.
  { id: 'type2-chain-id-0', name: 'EIP-1559 signed by the publisher for chain id 0', built: signedTyped(2, typedBody(2, { chainId: 0n })), rule: 'typed-chain-id', signer: 'key' },
  { id: 'type1-chain-id-0', name: 'EIP-2930 signed by the publisher for chain id 0', built: signedTyped(1, typedBody(1, { chainId: 0n })), rule: 'typed-chain-id', signer: 'key' },
  { id: 'type2-chain-id-1', name: 'EIP-1559 signed by the publisher for chain id 1', built: base2, rule: null, signer: 'key' },
  { id: 'type1-chain-id-1', name: 'EIP-2930 signed by the publisher for chain id 1', built: signedTyped(1, typedBody(1)), rule: null, signer: 'key' },

  // A legacy v is 27, 28, or chainId * 2 + 35 or + 36 for a chain id of 1 or more.
  { id: 'legacy-v-35', name: 'legacy v 35: an EIP-155 signature by the publisher for chain id 0', built: signedLegacy(0n, 0), rule: 'legacy-v', signer: 'key' },
  { id: 'legacy-v-36', name: 'legacy v 36: an EIP-155 signature by the publisher for chain id 0', built: signedLegacy(0n, 1), rule: 'legacy-v', signer: 'key' },
  { id: 'legacy-v-34', name: 'legacy v 34: the publisher\'s v-27 signature with v one below 35', built: { ...signedLegacy(null, 0), v: 34n }, rule: 'legacy-v', signer: 'key' },
  { id: 'legacy-v-37', name: 'legacy v 37: an EIP-155 signature by the publisher for chain id 1', built: signedLegacy(TX_CHAIN, 0), rule: null, signer: 'key' },
  { id: 'legacy-v-38', name: 'legacy v 38: an EIP-155 signature by the publisher for chain id 1', built: signedLegacy(TX_CHAIN, 1), rule: null, signer: 'key' },
  { id: 'legacy-v-27', name: 'legacy v 27: unprotected, signed by the publisher, so it names no chain (item 5)', built: signedLegacy(null, 0), rule: null, signer: 'key' },
  { id: 'legacy-v-28', name: 'legacy v 28: unprotected, signed by the publisher, so it names no chain (item 5)', built: signedLegacy(null, 1), rule: null, signer: 'key' },

  // r in [1, n - 1], s in [1, n/2] (EIP-2), a typed yParity of 0 or 1.
  { id: 'type2-high-s', name: 'EIP-1559 with the publisher\'s signature as n - s and the other parity, which recovers the same key', built: highS(base2), rule: 'signature-scalars', signer: 'key' },
  { id: 'legacy-high-s', name: 'legacy v 37 with the publisher\'s signature as n - s and v 38, which recovers the same key', built: highS(signedLegacy(TX_CHAIN, 0)), rule: 'signature-scalars', signer: 'key' },
  { id: 'type2-s-half-n', name: 'EIP-1559 with s exactly n/2 (floor), the smallest r that recovers, yParity 0', built: atHalf, rule: null, signer: 'recovered' },
  { id: 'type2-s-half-n-plus-1', name: 'EIP-1559 with s = n/2 + 1, the same r and yParity 1, which recovers the same key as the n/2 case', built: { ...atHalf, v: 1n, s: HALF_N + 1n }, rule: 'signature-scalars', signer: 'recovered' },
  { id: 'type2-s-1', name: 'EIP-1559 with s = 1, the smallest r that recovers, yParity 0', built: { ...base2, v: 0n, r: firstR(true), s: 1n }, rule: null, signer: 'recovered' },
  { id: 'type2-r-0', name: 'EIP-1559 with r = 0', built: { ...base2, r: 0n }, rule: 'signature-scalars', signer: 'key' },
  { id: 'type2-s-0', name: 'EIP-1559 with s = 0', built: { ...base2, s: 0n }, rule: 'signature-scalars', signer: 'key' },
  { id: 'type2-r-n', name: 'EIP-1559 with r = n', built: { ...base2, r: N }, rule: 'signature-scalars', signer: 'key' },
  { id: 'type2-s-n', name: 'EIP-1559 with s = n', built: { ...base2, s: N }, rule: 'signature-scalars', signer: 'key' },
  { id: 'type2-y-parity-2', name: 'EIP-1559 with the publisher\'s r and s and yParity 2', built: { ...base2, v: 2n }, rule: 'signature-scalars', signer: 'key' },

  // An EIP-1559 tip is at most its fee cap.
  { id: 'type2-tip-equals-cap', name: 'EIP-1559 signed by the publisher with maxPriorityFeePerGas equal to maxFeePerGas', built: signedTyped(2, typedBody(2, { tip: 3_000_000_000n, cap: 3_000_000_000n })), rule: null, signer: 'key' },
  { id: 'type2-tip-above-cap', name: 'EIP-1559 signed by the publisher with maxPriorityFeePerGas one wei above maxFeePerGas', built: aboveCap, rule: 'fee-cap', signer: 'key' },

  // A public key recovers from the signature.
  { id: 'type2-r-not-x-coordinate', name: 'EIP-1559 with an r that is no point\'s x-coordinate', built: { ...base2, v: 0n, r: firstR(false), s: 1n }, rule: 'public-key-recovery', signer: 'key' },
  { id: 'type2-recovers-infinity', name: 'EIP-1559 with a signature from which recovery gives the point at infinity', built: atInfinity, rule: 'public-key-recovery', signer: 'key' },
];

/** What every transaction case's publication claims for its block: offline, nothing checks it. */
const TX_BLOCK = { blockNumber: 1, blockHash: keccak256(new TextEncoder().encode('tzun-anchor/1 §10.4 item 2')) };
const blockedCheck: Check = { outcome: 'not-checked', reason: 'blocked_by:anchor.evm.tx' };
const transactionCases = transactionSpecs.map(({ id, name, built, rule, signer }) => {
  const found = breaks(built);
  if (found !== rule) throw new Error(`${id}: built to break ${rule ?? 'nothing'}, but breaks ${found ?? 'nothing'}`);
  const raw = envelope(built);
  const sender = rule === null ? recovered(built) : null;
  if (rule === null && signer === 'key' && sender !== KEY_ADDRESS) throw new Error(`${id}: does not recover the key`);
  // The manifest names the key, or for a signature no key made, the address it recovers.
  const publisher = signer === 'key' ? KEY_ADDRESS : (recovered(rule === null ? built : { ...built, v: built.v ^ 1n, s: N - built.s }) as string);
  let expect: Expect;
  if (rule !== null) {
    // Item 2: the transaction does not yield a sender.
    expect = { valid: false, reason: 'malformed_publication', tx: { outcome: 'checked-wrong', reason: 'malformed_publication' }, canonical: blockedCheck };
  } else if (signedChainId(built) !== TX_CHAIN) {
    // Item 5: no entry for the sender on the chain it signed.
    expect = { valid: false, reason: 'evm_chain_mismatch', tx: { outcome: 'checked-wrong', reason: 'evm_chain_mismatch' }, canonical: blockedCheck };
  } else {
    // Offline: every offline fact holds, and no header source decides.
    expect = {
      valid: null,
      reason: 'publication_not_checked',
      tx: { outcome: 'checked-correct' },
      canonical: { outcome: 'not-checked', reason: 'input_not_supplied:evm_header_source' },
    };
  }
  return { id, name, rule, item2: rule === null ? 'reads' : 'refuses', rawTransaction: raw, transactionId: keccak256(raw), publisher, sender, expect };
});
const ids = new Set(transactionCases.map((c) => c.id));
if (ids.size !== transactionCases.length) throw new Error('two transaction cases share an id');
// Every rule is broken by some case, and some cases break none.
for (const rule of ['typed-chain-id', 'legacy-v', 'signature-scalars', 'fee-cap', 'public-key-recovery', null] as const) {
  if (!transactionCases.some((c) => c.rule === rule)) throw new Error(`no case breaks ${rule ?? 'nothing'}`);
}

const out = {
  description:
    'The publisher-manifest validity cases of tzun-anchor/1 §9 and §13: a manifest entry for the real publisher whose validFrom or validUntil sits at, just inside or just outside the time of the block that holds the publication, the leap days the format allows and the leap second it refuses, and the verdict of tzun-anchor/1 §10.4 for each, presented three ways. Both ends of a window are inclusive and compared at full precision: a block time is a whole second, so a validFrom with any non-zero fraction admits only a block at a later second, and a validUntil with one still admits a block at its own second. ' +
    'Then the transaction cases of §10.4 item 2: signed transactions at each edge of what item 2 refuses because no block on any chain a manifest can name holds such a transaction (a typed transaction on chain id 0; a legacy v of 35 or 36, or any other below 37 but 27 and 28; r outside [1, n - 1], s outside [1, n/2] or a typed yParity other than 0 or 1; an EIP-1559 tip above its fee cap; a signature from which no public key recovers), each with the transaction just inside the edge, and the verdict of §10.4 for each, offline. A refused transaction is false, malformed_publication, whatever an Ethereum library would recover from it. The header-source cases §13 also lists for this file are not in it.',
  source:
    'Generated by scripts/generate-evm-anchor-vectors.ts, which reads each bound by its own transcription of §9 (full precision, the fraction kept as digits) and states each verdict from §10.4, calling no SDK code. The publication, its block and the publisher are epoch 0 of anchor-e2e-vectors.json, byte for byte: signed and mined on anvil, and checked there by the Go gate with go-ethereum. The transaction cases are signed by the script with the throwaway key of the EIP-155 example (0x46 repeated, RFC 6979 signatures), or carry a signature built to recover a chosen way, and the script reads each against its own transcription of §10.4 item 2. scripts/regenerate-vectors.ts --anvil rewrites this file right after anchor-e2e-vectors.json.',
  format: {
    publication:
      'The evm-calldata/1 publication with its heavy material, as anchor-e2e-vectors.json epochs[0].publication; p is its P, sender the address its signature recovers to, blockTime the unix seconds of its block (headerSource.blocks[0].timestamp).',
    headerSource:
      'The header source the header and noHeader modes use: its chain id, its finality, its finalized height, the canonical block at each height it lists (none at any other), and the transactions it looks up by transactionId (none other).',
    manifestEntry: 'The entry every case starts from, for anchorOrigin: the publisher on the file\'s chain. A case\'s bounds are set on it, and its manifest is { "publishers": { anchorOrigin: [ entry ] } }.',
    validityBounds:
      'name; bounds, the members set on manifestEntry (an absent member is left absent, null is set to null); window, whether §9 makes the entry valid at blockTime (admits, excludes) or unreadable (malformed); expect, per mode, the verdict of verifyEvmPublication: valid, reason (absent when valid is true), the anchor.evm.tx and anchor.evm.canonical checks, each with outcome and reason (absent when checked-correct), and inclusion when valid is true.',
    modes:
      'header: the publication as given (blockHeader, txIndex and txProof carried), with headerSource, so the window is judged at the header\'s time (§10.4 item 6) and again at the time the source confirms (item 13). noHeader: the publication without blockHeader, txIndex and txProof, with headerSource, so the window is judged only at the time the source confirms, and the source\'s lookup places the transaction (item 12). offline: the publication as given and no header source, so the header can make the publication fail but never pass.',
    transactionCases:
      'chain, blockNumber and blockHash: what every case\'s publication claims (no header, no trie proof, no header source: offline). A case is { "kind": "evm-calldata/1", "chain": chain, "transactionId": transactionId, "rawTransaction": rawTransaction, "blockNumber": blockNumber, "blockHash": blockHash }, verified for P = p of this file and anchorOrigin, with the manifest { "publishers": { anchorOrigin: [ { "address": publisher, "chain": chain, "namespace": "test" } ] } }. Each case: id; name; rule, the rule of item 2 it breaks (typed-chain-id, legacy-v, signature-scalars, fee-cap, public-key-recovery), or null when item 2 reads it; item2, refuses or reads; rawTransaction and transactionId (its keccak-256); publisher, the address the signing key has, or for a signature no key made, the address it recovers (for a high s, read as n - s with the other parity); sender, the address item 2 recovers (null when it refuses); expect, the verdict of verifyEvmPublication, as for validityBounds.',
  },
  chain: E2E.chain,
  anchorOrigin: E2E.anchorOrigin,
  p: epoch.p,
  sender: pub.publisher,
  blockTime: T,
  publication: pub,
  headerSource: {
    chainId: E2E.headerSource.chainId,
    finality: E2E.headerSource.finality,
    finalizedBlockNumber: E2E.headerSource.finalizedBlockNumber,
    blocks: [{ number: block.number, hash: block.hash, timestamp: block.timestamp }],
    transactions: [{ transactionId: pub.transactionId, blockHash: pub.blockHash, blockNumber: pub.blockNumber, from: pub.publisher }],
  },
  manifestEntry: { address: entry.address, chain: entry.chain, namespace: entry.namespace },
  validityBounds,
  transactionCases: {
    chain: `eip155:${TX_CHAIN}`,
    blockNumber: TX_BLOCK.blockNumber,
    blockHash: TX_BLOCK.blockHash,
    cases: transactionCases,
  },
};

process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
