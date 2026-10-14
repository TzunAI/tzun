/**
 * Generate vectors/evm-anchor-vectors.json (tzun-anchor/1 §13): the
 * publisher-manifest validity cases of §9, each a manifest entry whose
 * `validFrom` or `validUntil` sits at, just inside or just outside the time of
 * a block that carries a real publication, and the verdict §10.4 states for
 * it.
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
 * `pnpm run regenerate:vectors -- --anvil` rewrites it right after
 * anchor-e2e-vectors.json, whose epoch 0 it copies.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

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

const out = {
  description:
    'The publisher-manifest validity cases of tzun-anchor/1 §9 and §13: a manifest entry for the real publisher whose validFrom or validUntil sits at, just inside or just outside the time of the block that holds the publication, the leap days the format allows and the leap second it refuses, and the verdict of tzun-anchor/1 §10.4 for each, presented three ways. Both ends of a window are inclusive and compared at full precision: a block time is a whole second, so a validFrom with any non-zero fraction admits only a block at a later second, and a validUntil with one still admits a block at its own second. This file holds only these cases; the transaction and header-source cases §13 also lists for it are not in it.',
  source:
    'Generated by scripts/generate-evm-anchor-vectors.ts, which reads each bound by its own transcription of §9 (full precision, the fraction kept as digits) and states each verdict from §10.4, calling no SDK code. The publication, its block and the publisher are epoch 0 of anchor-e2e-vectors.json, byte for byte: signed and mined on anvil, and checked there by the Go gate with go-ethereum. scripts/regenerate-vectors.ts --anvil rewrites this file right after anchor-e2e-vectors.json.',
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
};

process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
