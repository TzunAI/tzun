// Generate vectors/merkle-rfc6962-vectors.json.
//
// INDEPENDENT PIN. This script is a from-scratch transcription of RFC 6962
// §2.1, written recursively, exactly as the RFC states it:
//
//   MTH({})       = SHA-256()
//   MTH({d(0)})   = SHA-256(0x00 || d(0))
//   MTH(D[n])     = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//                   where k is the largest power of two STRICTLY less than n
//
// The SDK's src/attestation/merkle.ts is iterative (level-by-level, promoting
// an odd trailing node). The two agree — that equivalence is the whole reason
// the SDK can stay iterative — but they are different code, and that is the
// point: these vectors must be derivable without running the implementation
// they are used to hold honest.
//
// Per the convention set by vectors/custody-entry-hash-vectors.json,
// scripts/regenerate-vectors.ts does NOT and MUST NOT rewrite this file.
//
// Run: node scripts/generate-merkle-vectors.mjs > vectors/merkle-rfc6962-vectors.json
import { createHash } from 'crypto';

const sha256 = (buf) => createHash('sha256').update(buf).digest();

/** RFC 6962 §2.1 leaf hash: SHA-256(0x00 || the leaf's RAW 32 bytes). */
const leafHash = (digestHex) =>
  sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(digestHex, 'hex')]));

/** RFC 6962 §2.1 internal node: SHA-256(0x01 || left || right), raw 32-byte children. */
const nodeHash = (left, right) =>
  sha256(Buffer.concat([Buffer.from([0x01]), left, right]));

/** Largest power of two strictly less than n. Defined for n >= 2. */
function splitPoint(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH(D[n]) — the Merkle Tree Hash, recursive per the RFC. */
function mth(digests) {
  if (digests.length === 0) return sha256(Buffer.alloc(0));
  if (digests.length === 1) return leafHash(digests[0]);
  const k = splitPoint(digests.length);
  return nodeHash(mth(digests.slice(0, k)), mth(digests.slice(k)));
}

/**
 * PATH(m, D[n]) — the RFC 6962 §2.1.1 audit path for the leaf at index m,
 * ordered leaf-first, root-last. Returns an array of raw 32-byte Buffers.
 */
function auditPath(m, digests) {
  const n = digests.length;
  if (n <= 1) return []; // PATH(0, {d0}) is empty
  const k = splitPoint(n);
  return m < k
    ? [...auditPath(m, digests.slice(0, k)), mth(digests.slice(k))]
    : [...auditPath(m - k, digests.slice(k)), mth(digests.slice(0, k))];
}

/**
 * Verify an audit path using the algorithm RFC 6962 §2.1.2 actually specifies.
 *
 * The path is ordered leaf-first, so verification walks UP the tree; each
 * step's side is derived from (leafIndex, treeSize) rather than read from a
 * stored label, which is precisely the property that lets a stock CT verifier
 * check these proofs. An earlier draft of this function descended from the
 * root instead and mis-ordered the very first concatenation at n=3 — the
 * self-check below caught it, which is why it is here.
 */
function verifyAuditPath(leafDigestHex, leafIndex, treeSize, pathHexes, rootHex) {
  if (leafIndex >= treeSize) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash(leafDigestHex);

  for (const stepHex of pathHexes) {
    if (sn === 0) return false; // more path than the tree can justify
    const step = Buffer.from(stepHex, 'hex');
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(step, r); // this subtree is the RIGHT child
      while (fn !== 0 && fn % 2 === 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = nodeHash(r, step); // this subtree is the LEFT child
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && r.toString('hex') === rootHex;
}

// Deterministic, reproducible leaf digests. Anyone can regenerate these:
// sha256(utf8("tzun-merkle-vector-" + i)).
const D = (i) => createHash('sha256').update(`tzun-merkle-vector-${i}`, 'utf8').digest('hex');

const hex = (b) => b.toString('hex');

const trees = [];
// n = 1..9 covers: the degenerate single leaf, both powers of two and the
// unbalanced sizes where duplicate-last and promote-odd disagree (n >= 3),
// plus n = 16 as a fully balanced control.
for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 9, 16]) {
  const digests = Array.from({ length: n }, (_, i) => D(i));
  const root = hex(mth(digests));
  const proofs = digests.map((d, m) => {
    const path = auditPath(m, digests).map(hex);
    const holds = verifyAuditPath(d, m, n, path, root);
    if (!holds) throw new Error(`self-check failed: n=${n} m=${m}`);
    return { leafIndex: m, leafDigest: d, auditPath: path };
  });
  trees.push({ treeSize: n, leafDigests: digests, root, leafHashes: digests.map((d) => hex(leafHash(d))), proofs });
}

// The ambiguity the old construction had, pinned as a NEGATIVE: under
// duplicate-last these two roots were byte-identical, which let a proof for a
// phantom 4th leaf verify against a 3-leaf root. Under RFC 6962 they differ.
const three = [D(0), D(1), D(2)];
const threeWithRepeat = [D(0), D(1), D(2), D(2)];

const out = {
  description:
    'RFC 6962 §2.1 Merkle Tree Hash vectors for Tzun batch anchoring. Leaves are the RAW 32 bytes of a record\'s canonicalDigest (hex-decoded, NOT the 64 ASCII hex characters). leafHash = SHA-256(0x00 || d). internalNode = SHA-256(0x01 || left || right) over raw 32-byte children. An odd trailing node is PROMOTED, never duplicated — equivalently, MTH(D[n]) splits at the largest power of two strictly less than n. auditPath is RFC 6962 §2.1.1 PATH(m, D[n]), ordered leaf-first/root-last, as bare lowercase hex with no position label: the side of each step is derived from (leafIndex, treeSize), which is what lets a stock Certificate Transparency verifier check these proofs unmodified.',
  source:
    'Computed by scripts/generate-merkle-vectors.mjs, a from-scratch RECURSIVE transcription of RFC 6962 §2.1/§2.1.1. The SDK implementation it pins (src/attestation/merkle.ts) is ITERATIVE and level-by-level; the two are independent code paths that must agree. This is an independent pin in the sense of vectors/custody-entry-hash-vectors.json: scripts/regenerate-vectors.ts does not and must not rewrite this file. emptyTreeRoot is the universally published RFC 6962 constant (SHA-256 of the empty string) and can be checked against any CT implementation without reference to Tzun.',
  emptyTreeRoot: {
    note:
      'MTH({}) per the RFC. Tzun never anchors an empty batch — buildMerkleTree refuses empty input — but the constant is pinned because it is the one value every CT implementation agrees on, so it independently confirms the hash function and encoding before any Tzun-specific value is trusted.',
    root: hex(sha256(Buffer.alloc(0))),
  },
  leafDigestDerivation: 'leafDigests[i] = sha256(utf8("tzun-merkle-vector-" + i))',
  trees,
  distinctnessVectors: [
    {
      name: 'a 3-leaf tree and the same leaves with the last repeated must NOT share a root (CVE-2012-2459 shape)',
      why:
        'Under the previous duplicate-last construction these two roots were byte-identical, so an audit path for a phantom 4th leaf verified against the 3-leaf root. Promotion makes tree shape a function of treeSize, which closes it in the hash rather than beside it.',
      a: { leafDigests: three, treeSize: 3, root: hex(mth(three)) },
      b: { leafDigests: threeWithRepeat, treeSize: 4, root: hex(mth(threeWithRepeat)) },
      rootsEqual: hex(mth(three)) === hex(mth(threeWithRepeat)),
    },
  ],
};

if (out.distinctnessVectors[0].rootsEqual) {
  throw new Error('generator is wrong: the duplicate-leaf roots collided under RFC 6962');
}

process.stdout.write(JSON.stringify(out, null, 2) + '\n');
