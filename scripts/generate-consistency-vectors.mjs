// Generate vectors/merkle-consistency-vectors.json.
//
// INDEPENDENT PIN. This script imports nothing but node:crypto. It is a
// from-scratch transcription of two RFC texts, written recursively exactly as
// RFC 6962 states them:
//
//   MTH({d(0)})  = SHA-256(0x00 || d(0))
//   MTH(D[n])    = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//                  where k is the largest power of two STRICTLY less than n
//
//   PROOF(m, D[n])              = SUBPROOF(m, D[n], true)          (RFC 6962 §2.1.2,
//   SUBPROOF(m, D[m], true)     = {}                                 RFC 9162 §2.1.4.1)
//   SUBPROOF(m, D[m], false)    = {MTH(D[m])}
//   SUBPROOF(m, D[n], b), m ≤ k = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
//   SUBPROOF(m, D[n], b), m > k = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])
//
// The engine's generator (packages/engine/src/merkle.ts) is iterative: it
// walks node indices up from the largest perfect subtree ending at m. The two
// must agree byte for byte, and the vectors are derived without running the
// code they hold honest.
//
// Every proof written here is first checked by a separate transcription of the
// RFC 9162 §2.1.4.2 verifier (below), with the edge rules of Tree §3.5:
// 0 < first ≤ second, and first == second holds only with an empty proof and
// equal roots.
//
// scripts/regenerate-vectors.ts does not and must not rewrite this file.
//
// Run: node scripts/generate-consistency-vectors.mjs > vectors/merkle-consistency-vectors.json
import { createHash } from 'node:crypto';

const sha256 = (buf) => createHash('sha256').update(buf).digest();
const hex = (b) => b.toString('hex');

/** RFC 6962 §2.1 leaf hash over the digest's RAW 32 bytes. */
const leafHash = (digestHex) => sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(digestHex, 'hex')]));

/** RFC 6962 §2.1 internal node over raw 32-byte children. */
const nodeHash = (left, right) => sha256(Buffer.concat([Buffer.from([0x01]), left, right]));

/** Largest power of two strictly less than n. Defined for n >= 2. */
function splitPoint(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH(D[n]), recursive per RFC 6962 §2.1. */
function mth(digests) {
  if (digests.length === 0) return sha256(Buffer.alloc(0));
  if (digests.length === 1) return leafHash(digests[0]);
  const k = splitPoint(digests.length);
  return nodeHash(mth(digests.slice(0, k)), mth(digests.slice(k)));
}

/** SUBPROOF(m, D[n], b), recursive per RFC 6962 §2.1.2. Returns raw Buffers. */
function subproof(m, digests, b) {
  const n = digests.length;
  if (m === n) return b ? [] : [mth(digests)];
  const k = splitPoint(n);
  if (m <= k) return [...subproof(m, digests.slice(0, k), b), mth(digests.slice(k))];
  return [...subproof(m - k, digests.slice(k), false), mth(digests.slice(0, k))];
}

/** PROOF(m, D[n]). Tzun defines it for 0 < m ≤ n; m == n is the empty proof. */
function consistencyProof(m, digests) {
  return subproof(m, digests, true);
}

/** PATH(m, D[n]), RFC 6962 §2.1.1, leaf-first. Used only for the size exhibits. */
function auditPath(m, digests) {
  const n = digests.length;
  if (n <= 1) return [];
  const k = splitPoint(n);
  return m < k
    ? [...auditPath(m, digests.slice(0, k)), mth(digests.slice(k))]
    : [...auditPath(m - k, digests.slice(k)), mth(digests.slice(0, k))];
}

const isPowerOfTwo = (x) => x > 0 && (x & (x - 1)) === 0;
const lsbSet = (x) => (x & 1) === 1;

/**
 * The encoding rule for every hash a verifier reads: a string of exactly 64
 * hex digits, in either case, matched against the WHOLE string (JavaScript's
 * `$` without the m flag matches only at the end of input). Returns the
 * lowercase form, or null.
 */
const parseHash = (v) => (typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v) ? v.toLowerCase() : null);

/**
 * RFC 9162 §2.1.4.2, step by step, plus the Tzun edge rules and the encoding
 * rule above. Boolean out. Sizes stay well inside 2^31 here, so the bit
 * operators are exact.
 */
function verifyConsistency(first, second, proof, firstRootIn, secondRootIn) {
  if (!(Number.isInteger(first) && Number.isInteger(second))) return false;
  if (!(first > 0 && first <= second)) return false;
  const firstRootHex = parseHash(firstRootIn);
  const secondRootHex = parseHash(secondRootIn);
  if (firstRootHex === null || secondRootHex === null || !Array.isArray(proof)) return false;
  const pathHex = proof.map(parseHash);
  if (pathHex.includes(null)) return false;
  if (first === second) return pathHex.length === 0 && firstRootHex === secondRootHex;
  // Step 1.
  if (pathHex.length === 0) return false;
  let path = pathHex.map((h) => Buffer.from(h, 'hex'));
  // Step 2.
  if (isPowerOfTwo(first)) path = [Buffer.from(firstRootHex, 'hex'), ...path];
  // Step 3.
  let fn = first - 1;
  let sn = second - 1;
  // Step 4.
  while (lsbSet(fn)) {
    fn >>= 1;
    sn >>= 1;
  }
  // Step 5.
  let fr = path[0];
  let sr = path[0];
  // Step 6.
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (lsbSet(fn) || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (!lsbSet(fn)) {
        while (!lsbSet(fn) && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  // Step 7.
  return hex(fr) === firstRootHex && hex(sr) === secondRootHex && sn === 0;
}

/** RFC 9162 §2.1.3.2 inclusion verification. Used only for the size exhibits. */
function verifyInclusion(leafDigestHex, leafIndex, treeSize, pathHex, rootHex) {
  if (leafIndex >= treeSize) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash(leafDigestHex);
  for (const p of pathHex) {
    if (sn === 0) return false;
    const c = Buffer.from(p, 'hex');
    if (lsbSet(fn) || fn === sn) {
      r = nodeHash(c, r);
      if (!lsbSet(fn)) {
        while (!lsbSet(fn) && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = nodeHash(r, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && hex(r) === rootHex;
}

// The same leaves as vectors/merkle-rfc6962-vectors.json, extended to 64.
const D = (i) => createHash('sha256').update(`tzun-merkle-vector-${i}`, 'utf8').digest('hex');
const LEAVES = Array.from({ length: 64 }, (_, i) => D(i));
const ROOT = (n) => hex(mth(LEAVES.slice(0, n)));

/** Flip the lowest bit of the first byte of a 64-hex value. */
const flipBit = (h) => ((parseInt(h.slice(0, 2), 16) ^ 0x01).toString(16).padStart(2, '0')) + h.slice(2);

// ---- Honest proofs -------------------------------------------------------

const pairs = [];
for (let n = 1; n <= 16; n++) for (let m = 1; m <= n; m++) pairs.push([m, n]);
// Selected pairs up to 64: each side of every power-of-two boundary, and odd
// sizes whose proofs are long.
const SELECTED_SECOND = [17, 31, 32, 33, 47, 63, 64];
const SELECTED_FIRST = [1, 2, 3, 5, 7, 8, 11, 15, 16, 17, 21, 31, 32, 33, 47, 48, 62, 63, 64];
for (const n of SELECTED_SECOND) {
  for (const m of SELECTED_FIRST) if (m <= n) pairs.push([m, n]);
}

const valid = pairs.map(([m, n]) => {
  const proof = consistencyProof(m, LEAVES.slice(0, n)).map(hex);
  const entry = { first: m, second: n, firstRoot: ROOT(m), secondRoot: ROOT(n), proof };
  if (!verifyConsistency(entry.first, entry.second, entry.proof, entry.firstRoot, entry.secondRoot)) {
    throw new Error(`self-check failed: honest proof for m=${m} n=${n} does not verify`);
  }
  return entry;
});

// ---- Negative cases -------------------------------------------------------

const invalid = [];
const refuse = (mutation, derivedFrom, c) => {
  if (verifyConsistency(c.first, c.second, c.proof, c.firstRoot, c.secondRoot)) {
    throw new Error(`self-check failed: negative "${mutation}" from ${JSON.stringify(derivedFrom)} verifies`);
  }
  invalid.push({ mutation, derivedFrom, ...c });
};

// Every mutation below is applied to every honest pair with second ≤ 8, and to
// these larger pairs. The file stays small enough to review; a harness that
// wants every pair can apply the same mutations to `valid` itself.
const NEGATIVE_BASES_BEYOND_8 = [
  [3, 11], [7, 12], [5, 16], [9, 16], [13, 16], [1, 64], [17, 63], [21, 47], [31, 33], [33, 64], [62, 64],
];
const EQUAL_SIZE_BASES = [1, 2, 3, 4, 7, 8, 16, 64];
const isNegativeBase = (m, n) =>
  m === n ? EQUAL_SIZE_BASES.includes(n) : n <= 8 || NEGATIVE_BASES_BEYOND_8.some(([a, b]) => a === m && b === n);

for (const v of valid) {
  if (!isNegativeBase(v.first, v.second)) continue;
  const from = { first: v.first, second: v.second };
  const base = { first: v.first, second: v.second, firstRoot: v.firstRoot, secondRoot: v.secondRoot, proof: v.proof };

  if (v.first === v.second) {
    // m == n: only the empty proof and equal roots hold.
    refuse('equal sizes with a non-empty proof', from, { ...base, proof: [v.firstRoot] });
    if (v.second > 1) refuse('equal sizes with different roots', from, { ...base, firstRoot: ROOT(v.first - 1) });
    continue;
  }

  // Single-bit tamper of each proof element and of each root.
  v.proof.forEach((_, i) => {
    const proof = [...v.proof];
    proof[i] = flipBit(proof[i]);
    refuse(`proof[${i}] bit-flipped`, from, { ...base, proof });
  });
  refuse('firstRoot bit-flipped', from, { ...base, firstRoot: flipBit(v.firstRoot) });
  refuse('secondRoot bit-flipped', from, { ...base, secondRoot: flipBit(v.secondRoot) });

  refuse('first and second swapped', from, {
    first: v.second, second: v.first, firstRoot: v.secondRoot, secondRoot: v.firstRoot, proof: v.proof,
  });
  refuse('proof truncated (last element dropped)', from, { ...base, proof: v.proof.slice(0, -1) });
  if (v.proof.length > 1) refuse('proof truncated (first element dropped)', from, { ...base, proof: v.proof.slice(1) });
  refuse('proof extended (secondRoot appended)', from, { ...base, proof: [...v.proof, v.secondRoot] });
  refuse('proof extended (last element repeated)', from, { ...base, proof: [...v.proof, v.proof[v.proof.length - 1]] });
}

// m = 0. Tzun never publishes an empty log and refuses every proof from size
// 0. transparency-dev/merkle v0.0.2 accepts five of these negatives: the four
// "first = 0 with an empty proof" and "first = 0 and second = 0". Its main
// branch (v0.0.3-0.20260921095310-fbbcd741c3d1, the version the Go gate pins)
// refuses all of them.
const EMPTY_ROOT = hex(sha256(Buffer.alloc(0)));
for (const n of [1, 2, 7, 16]) {
  refuse('first = 0 with an empty proof', { first: 0, second: n }, {
    first: 0, second: n, firstRoot: EMPTY_ROOT, secondRoot: ROOT(n), proof: [],
  });
}
refuse('first = 0 with a non-empty proof', { first: 0, second: 5 }, {
  first: 0, second: 5, firstRoot: EMPTY_ROOT, secondRoot: ROOT(5), proof: consistencyProof(1, LEAVES.slice(0, 5)).map(hex),
});
refuse('first = 0 and second = 0', { first: 0, second: 0 }, {
  first: 0, second: 0, firstRoot: EMPTY_ROOT, secondRoot: EMPTY_ROOT, proof: [],
});
// m > n without a swap: the honest proof for (m, n) presented as (n + 1, n).
for (const [m, n] of [[3, 7], [8, 16], [5, 6]]) {
  const v = valid.find((e) => e.first === m && e.second === n);
  refuse('first greater than second', { first: m, second: n }, {
    first: n + 1, second: n, firstRoot: ROOT(n + 1), secondRoot: v.secondRoot, proof: v.proof,
  });
}

// ---- Encoding cases ---------------------------------------------------------

// Every hash is read under parseHash's rule. These cases pin it: case is
// normalised, and anything but exactly 64 hex digits in a string is refused.
// The base is the honest proof for (3, 7).
const encoding = [];
const encodingCase = (name, verifies, c) => {
  if (verifyConsistency(c.first, c.second, c.proof, c.firstRoot, c.secondRoot) !== verifies) {
    throw new Error(`self-check failed: encoding case "${name}" does not give ${verifies}`);
  }
  encoding.push({ case: name, verifies, ...c });
};
{
  const v = valid.find((e) => e.first === 3 && e.second === 7);
  const base = { first: 3, second: 7, firstRoot: v.firstRoot, secondRoot: v.secondRoot, proof: v.proof };
  const withProof0 = (x) => ({ ...base, proof: [x, ...v.proof.slice(1)] });
  const upper = (h) => h.toUpperCase();
  const mixed = (h) => [...h].map((ch, i) => (i % 2 ? ch.toUpperCase() : ch)).join('');

  encodingCase('proof[0] in uppercase', true, withProof0(upper(v.proof[0])));
  encodingCase('every proof element in uppercase', true, { ...base, proof: v.proof.map(upper) });
  encodingCase('proof[0] in mixed case', true, withProof0(mixed(v.proof[0])));
  encodingCase('firstRoot in uppercase', true, { ...base, firstRoot: upper(v.firstRoot) });
  encodingCase('secondRoot in uppercase', true, { ...base, secondRoot: upper(v.secondRoot) });
  const five = valid.find((e) => e.first === 5 && e.second === 5);
  encodingCase('equal sizes, roots equal once case is normalised', true, {
    first: 5, second: 5, firstRoot: five.firstRoot, secondRoot: upper(five.secondRoot), proof: [],
  });

  encodingCase('proof[0] with a trailing newline', false, withProof0(`${v.proof[0]}\n`));
  encodingCase('proof[0] with 63 hex digits', false, withProof0(v.proof[0].slice(0, 63)));
  encodingCase('proof[0] with 65 hex digits', false, withProof0(`${v.proof[0]}0`));
  encodingCase('proof[0] with a 0x prefix', false, withProof0(`0x${v.proof[0]}`));
  encodingCase('proof[0] with a leading space', false, withProof0(` ${v.proof[0]}`));
  encodingCase('proof[0] is a number', false, withProof0(7));
  encodingCase('proof[0] is null', false, withProof0(null));
  encodingCase('firstRoot with a trailing newline', false, { ...base, firstRoot: `${v.firstRoot}\n` });
  encodingCase('secondRoot with a 0x prefix', false, { ...base, secondRoot: `0x${v.secondRoot}` });
  encodingCase('firstRoot with 63 hex digits', false, { ...base, firstRoot: v.firstRoot.slice(0, 63) });
  encodingCase('proof is null', false, { ...base, proof: null });
}

// ---- Size malleability exhibits (F11) ------------------------------------

// A proof does not authenticate the size it was made for. These honest proofs
// also verify under a DIFFERENT claimed size, under any RFC-correct verifier,
// with every hash unchanged. The size must come from an authenticated source
// (a checkpoint); the proof alone cannot pin it.
const inclusionExhibits = [];
for (const [m, n] of [[0, 5], [1, 3], [21, 24], [40, 48]]) {
  const leaves = LEAVES.slice(0, n);
  const path = auditPath(m, leaves).map(hex);
  const root = ROOT(n);
  if (!verifyInclusion(LEAVES[m], m, n, path, root)) throw new Error(`self-check failed: inclusion m=${m} n=${n}`);
  const acceptedSizes = [];
  for (let s = m + 1; s <= 64; s++) if (s !== n && verifyInclusion(LEAVES[m], m, s, path, root)) acceptedSizes.push(s);
  if (acceptedSizes.length === 0) throw new Error(`exhibit m=${m} n=${n} is not malleable`);
  inclusionExhibits.push({ leafIndex: m, leafDigest: LEAVES[m], treeSize: n, root, auditPath: path, alsoVerifiesUnderTreeSize: acceptedSizes });
}

const consistencyExhibits = [];
for (const [m, n] of [[1, 3], [3, 5], [4, 6], [9, 13], [16, 20]]) {
  const v = { firstRoot: ROOT(m), secondRoot: ROOT(n), proof: consistencyProof(m, LEAVES.slice(0, n)).map(hex) };
  if (!verifyConsistency(m, n, v.proof, v.firstRoot, v.secondRoot)) throw new Error(`self-check failed: exhibit m=${m} n=${n}`);
  const acceptedSeconds = [];
  for (let s = m; s <= 64; s++) {
    if (s !== n && verifyConsistency(m, s, v.proof, v.firstRoot, v.secondRoot)) acceptedSeconds.push(s);
  }
  if (acceptedSeconds.length === 0) throw new Error(`exhibit m=${m} n=${n} is not malleable`);
  consistencyExhibits.push({
    first: m, second: n, firstRoot: v.firstRoot, secondRoot: v.secondRoot, proof: v.proof,
    alsoVerifiesUnderSecond: acceptedSeconds,
  });
}

// The census behind F11, measured with the verifiers above.
let inclusionMalleable = 0;
let inclusionTotal = 0;
for (let n = 1; n <= 64; n++) {
  const leaves = LEAVES.slice(0, n);
  const root = ROOT(n);
  for (let m = 0; m < n; m++) {
    inclusionTotal++;
    const path = auditPath(m, leaves).map(hex);
    for (let s = m + 1; s <= 64; s++) {
      if (s !== n && verifyInclusion(LEAVES[m], m, s, path, root)) {
        inclusionMalleable++;
        break;
      }
    }
  }
}
let consistencyMalleable = 0;
let consistencyFirstMalleable = 0;
let consistencyTotal = 0;
for (let n = 2; n <= 64; n++) {
  const leaves = LEAVES.slice(0, n);
  const secondRoot = ROOT(n);
  for (let m = 1; m < n; m++) {
    consistencyTotal++;
    const proof = consistencyProof(m, leaves).map(hex);
    const firstRoot = ROOT(m);
    for (let s = m; s <= 64; s++) {
      if (s !== n && verifyConsistency(m, s, proof, firstRoot, secondRoot)) {
        consistencyMalleable++;
        break;
      }
    }
    for (let f = 1; f <= n; f++) {
      if (f !== m && verifyConsistency(f, n, proof, firstRoot, secondRoot)) {
        consistencyFirstMalleable++;
        break;
      }
    }
  }
}

const out = {
  description:
    'RFC 6962 §2.1.2 consistency-proof vectors for Tzun growing logs. Tree math is the RFC 6962 tree profile (Tree): leaves are the RAW 32 bytes of a digest, leafHash = SHA-256(0x00 || d), node = SHA-256(0x01 || left || right), MTH splits at the largest power of two strictly less than n. A proof is PROOF(m, D[n]) = SUBPROOF(m, D[n], true), as bare lowercase hex, innermost element first. Verification is RFC 9162 §2.1.4.2 with the edge rules of Tree §3.5.',
  source:
    'Computed by scripts/generate-consistency-vectors.mjs, a from-scratch RECURSIVE transcription of RFC 6962 §2.1.2 SUBPROOF that imports nothing but node:crypto. Every valid entry was verified, every invalid entry refused, and every encoding entry given its stated outcome by the script\'s own transcription of RFC 9162 §2.1.4.2 before being written. The engine implementation these vectors pin (packages/engine/src/merkle.ts) is iterative and walks node indices. scripts/regenerate-vectors.ts does not and must not rewrite this file.',
  format: {
    leafDigests: 'The 64 leaf digests of one log. A tree of size n is leafDigests[0:n]. leafDigests[i] = sha256(utf8("tzun-merkle-vector-" + i)), the same leaves as merkle-rfc6962-vectors.json.',
    valid: 'Each entry is a verifier input {first, second, firstRoot, secondRoot, proof} that MUST verify. proof is exactly PROOF(first, leafDigests[0:second]); a generator MUST reproduce it byte for byte. Every pair 0 < first <= second <= 16, plus selected pairs up to 64.',
    invalid: 'Each entry is a verifier input {first, second, firstRoot, secondRoot, proof} that MUST NOT verify. mutation says what was changed; derivedFrom names the honest (first, second) it came from. The mutations are applied to every valid pair with second <= 8 and to a listed set of larger pairs, and first = 0 and first > second are added on their own.',
    encoding: 'Each entry is a verifier input {first, second, firstRoot, secondRoot, proof} with its expected outcome in verifies. They pin the encoding rule in edgeRules; the math around them is the honest (3, 7) proof or (5, 5). proof elements here may be any JSON value, not only strings.',
    sizeMalleability: 'Documentation, not conformance. Honest proofs that ALSO verify under a different claimed size, under any RFC-correct verifier. See its note.',
  },
  edgeRules: [
    'first must satisfy 0 < first <= second. first = 0 is refused, including with an empty proof and including first = second = 0: Tzun never publishes an empty log. transparency-dev/merkle v0.0.2 accepts exactly those cases (five entries in invalid: the four "first = 0 with an empty proof" and "first = 0 and second = 0"); its main branch (v0.0.3-0.20260921095310-fbbcd741c3d1) refuses every entry in invalid.',
    'first == second verifies only with an empty proof and firstRoot == secondRoot.',
    'first < second with an empty proof is refused.',
    'Every hash (each proof element, firstRoot and secondRoot) is a JSON string of exactly 64 hexadecimal digits, matched against the whole string. Uppercase and mixed case are accepted and normalised to lowercase before hashing and comparison. Anything else is refused: a trailing newline, surrounding whitespace, 63 or 65 digits, a 0x prefix, or a non-string. A regular expression must be anchored to the whole string: in Python use re.fullmatch, because re.match with $ also matches before a trailing newline.',
  ],
  leafDigests: LEAVES,
  valid,
  invalid,
  encoding,
  sizeMalleability: {
    note:
      'Neither an inclusion proof nor a consistency proof authenticates the tree size it was made for. A verifier recomputes a root from the path and the claimed size; when a different size gives the same sequence of left and right steps, the computation is identical and the proof verifies. No verifier can reject those sizes from the proof alone. So every verifier takes the size as an explicit input, and the size must come from an authenticated checkpoint. The census counts, over every honest proof with second size <= 64, the proofs that also verify under at least one other claimed second size <= 64 (inclusion: leafIndex fixed; consistency: first fixed, both roots unchanged), and the consistency proofs that verify under another claimed FIRST size (second and both roots unchanged).',
    census: {
      inclusion: { proofs: inclusionTotal, verifyUnderAnotherTreeSize: inclusionMalleable },
      consistency: {
        proofs: consistencyTotal,
        verifyUnderAnotherSecondSize: consistencyMalleable,
        verifyUnderAnotherFirstSize: consistencyFirstMalleable,
      },
    },
    inclusion: inclusionExhibits,
    consistency: consistencyExhibits,
  },
};

// Standard two-space JSON, except that an array of hashes or sizes sits on one
// line, so each case reads as one block.
const json = JSON.stringify(out, null, 2).replace(
  /\[\n\s+((?:"[0-9a-f]{64}"|\d+)(?:,\n\s+(?:"[0-9a-f]{64}"|\d+))*)\n\s+\]/g,
  (_, items) => `[${items.split(/,\n\s+/).join(', ')}]`,
);
process.stdout.write(json + '\n');
