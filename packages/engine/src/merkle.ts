import { createHash } from 'crypto';

/**
 * RFC 6962 §2.1 Merkle trees over evidence digests: the tree hash, inclusion
 * proofs, consistency proofs and compact ranges.
 *
 * Specification: Tree §3 (tree math, inclusion proofs).
 * Consistency proofs and compact ranges: Tree §3.5, §5.3 and §5.5.
 * Vectors: vectors/merkle-rfc6962-vectors.json and
 *   vectors/merkle-consistency-vectors.json
 *
 * Two rules carry the whole construction:
 *
 *  - A leaf is the RAW 32 bytes of a digest (hex-decoded), never its 64 ASCII
 *    characters, so a stock Certificate Transparency library reproduces every
 *    root and verifies every proof.
 *  - An odd trailing node is PROMOTED to the next layer, never duplicated.
 *    Tree shape is then a function of the tree size, which rules out the
 *    CVE-2012-2459 ambiguity: root([a,b,c]) differs from root([a,b,c,c]).
 *
 * Everything here is ITERATIVE: layers, node indices and arithmetic on
 * sizes. The RFC states the construction recursively, and both vector files
 * are written by recursive transcriptions (scripts/generate-merkle-vectors.mjs,
 * scripts/generate-consistency-vectors.mjs), so this file is never its own
 * witness.
 *
 * Size arithmetic uses division rather than 32-bit bit operators, so it is
 * exact for every safe integer.
 */

/** The `merkleSpec` wire tag. A verifier that does not recognise the tag on an
 *  artifact must report an unsupported spec, never fall back to another rule. */
export const MERKLE_SPEC = 'rfc6962' as const;

/**
 * Internal representation of a Merkle tree.
 * `layers[0]` = leaf-hash layer, `layers[layers.length - 1]` = root layer.
 * Each layer holds 64-char lowercase hex hashes.
 */
export interface MerkleTree {
  layers: string[][];
  leafCount: number;
}

const HEX_64 = /^[0-9a-f]{64}$/;

/**
 * The encoding rule for every hash this module reads: a string of exactly 64
 * hex digits, matched against the whole string, in either case. Returns the
 * lowercase form, or null for anything else (a trailing newline, whitespace,
 * 63 or 65 digits, a 0x prefix, a non-string). Never throws.
 */
function asDigest(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const lower = value.toLowerCase();
  return HEX_64.test(lower) ? lower : null;
}

/**
 * RFC 6962 leaf hash: SHA-256(0x00 || the digest's RAW 32 bytes).
 *
 * The hex-DECODE is the whole point. Hashing the 64 ASCII characters instead
 * gives roots no CT tool reproduces.
 */
export function merkleLeafHash(digestHex: string): string {
  const d = asDigest(digestHex);
  if (d === null) {
    throw new Error('Merkle leaf must be a 64-character hex SHA-256 digest.');
  }
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(d, 'hex')]))
    .digest('hex');
}

/** RFC 6962 internal node: SHA-256(0x01 || left || right) over raw 32-byte children. */
function nodeHash(leftHex: string, rightHex: string): string {
  return createHash('sha256')
    .update(Buffer.concat([
      Buffer.from([0x01]),
      Buffer.from(leftHex, 'hex'),
      Buffer.from(rightHex, 'hex'),
    ]))
    .digest('hex');
}

/**
 * Build a Merkle tree over evidence digests, in batch insertion order.
 *
 * Order is load-bearing and the list is never sorted. An odd trailing node is
 * PROMOTED unchanged to the next layer, never duplicated.
 *
 * @throws if the batch is empty, if any entry is not a 64-char hex digest, or
 *         if a digest repeats (Tree §5.4 — evidence digests are unique by
 *         construction, so this refuses nothing honest and removes the
 *         reader's ambiguity about what a root covers).
 */
export function buildMerkleTree(digests: string[]): MerkleTree {
  if (!Array.isArray(digests) || digests.length === 0) {
    throw new Error('Cannot build Merkle tree: at least one digest is required.');
  }

  const normalised = digests.map((d, i) => {
    const v = asDigest(d);
    if (v === null) {
      throw new Error(`Cannot build Merkle tree: entry ${i} is not a 64-character hex digest.`);
    }
    return v;
  });

  const seen = new Set<string>();
  for (let i = 0; i < normalised.length; i++) {
    if (seen.has(normalised[i])) {
      throw new Error(
        `Cannot build Merkle tree: duplicate digest at index ${i} makes the root ambiguous (CVE-2012-2459).`
      );
    }
    seen.add(normalised[i]);
  }

  const layers: string[][] = [normalised.map(merkleLeafHash)];

  let current = layers[0];
  while (current.length > 1) {
    const next: string[] = [];
    let i = 0;
    for (; i + 1 < current.length; i += 2) {
      next.push(nodeHash(current[i], current[i + 1]));
    }
    // Odd trailing node: promote it unchanged. Duplicating it here would
    // reopen CVE-2012-2459.
    if (i < current.length) {
      next.push(current[i]);
    }
    layers.push(next);
    current = next;
  }

  return { layers, leafCount: normalised.length };
}

/** The Merkle root of a built tree. */
export function getMerkleRoot(tree: MerkleTree): string {
  const layers = tree?.layers;
  if (!Array.isArray(layers) || layers.length === 0) {
    throw new Error('Cannot read Merkle root: the tree has no layers.');
  }
  return layers[layers.length - 1][0];
}

/**
 * RFC 6962 §2.1.1 audit path for the leaf at `leafIndex`, ordered leaf-first
 * and root-last, as bare lowercase hex.
 *
 * There is deliberately NO left/right label. The side of each step is derived
 * from (leafIndex, treeSize) at verification time, which is what lets a stock
 * CT verifier check these proofs unmodified.
 *
 * A single-leaf tree yields an empty path — a valid anchor and a worthless
 * inclusion proof (Tree §5.4). Callers must not present it as evidence of batching.
 */
export function getMerkleProof(tree: MerkleTree, leafIndex: number): string[] {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= tree.leafCount) {
    throw new Error(
      `Leaf index ${leafIndex} is out of bounds (tree has ${tree.leafCount} leaves).`
    );
  }

  const proof: string[] = [];
  let idx = leafIndex;

  for (let layer = 0; layer < tree.layers.length - 1; layer++) {
    const current = tree.layers[layer];
    const siblingIdx = idx % 2 === 1 ? idx - 1 : idx + 1;

    if (siblingIdx < current.length) {
      proof.push(current[siblingIdx]);
      idx = Math.floor(idx / 2);
    } else {
      // No sibling: this node was promoted to the next layer unchanged, so it
      // contributes no step and keeps its position there.
      idx = Math.floor(idx / 2);
    }
  }

  return proof;
}

/**
 * Verify an RFC 6962 §2.1.2 inclusion proof.
 *
 * Never throws. Every argument here is client-supplied JSON on a server that
 * verifies what a client sent: `leaf` is a record's
 * canonicalDigest and the root and path come out of
 * `nonRepudiation.anchor`. A malformed proof is `false`, which is a
 * reportable verdict; an exception would take down the caller instead.
 *
 * WHAT A `true` HERE DOES NOT MEAN. It proves only that `leaf` was among the
 * `treeSize` digests that produced `expectedRoot`. It does NOT prove the root
 * was ever published — `expectedRoot` arrives inside the very artifact under
 * examination. Only a checked publication of the anchor checkpoint can
 * establish that, which is why `anchorValid` is reported separately from
 * `merkleProofValid` (Tree §6).
 *
 * THE SIZE IS AN INPUT, NOT A FINDING. The fold is steered by
 * (leafIndex, treeSize), so a proof fails under every wrong `treeSize` that
 * changes any step. No verifier can reject a wrong size whose steps are the
 * same, because the computation is then identical, and most proofs have one:
 * over trees of 1 to 64 leaves, 1,984 of the 2,080 audit paths also verify
 * under another size. Only the last leaf's path, and the second-to-last leaf's
 * in an even-sized tree, fail under every other size. `treeSize` therefore has
 * to come from an authenticated source, such as a checkpoint; the proof cannot
 * vouch for it.
 */
export function verifyMerkleProof(
  leaf: string,
  leafIndex: number,
  treeSize: number,
  proof: string[],
  expectedRoot: string
): boolean {
  const leafDigest = asDigest(leaf);
  const root = asDigest(expectedRoot);
  if (leafDigest === null || root === null) return false;
  if (!Array.isArray(proof)) return false;
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) return false;
  if (leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize) return false;

  const steps: string[] = [];
  for (const entry of proof) {
    // A legacy "<left|right>:<hash>" element fails here, which is the intended
    // outcome: re-reading an old path under the new rule would silently verify
    // it against the wrong tree (Tree §8).
    const step = asDigest(entry);
    if (step === null) return false;
    steps.push(step);
  }

  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = merkleLeafHash(leafDigest);

  for (const step of steps) {
    // More path than the tree can justify.
    if (sn === 0) return false;

    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(step, r);
      while (fn !== 0 && fn % 2 === 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = nodeHash(r, step);
    }

    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  // `sn === 0` is required, not incidental: it rejects a truncated path that
  // happens to fold to the right value.
  return sn === 0 && r === root;
}

// ---- Shared node arithmetic ------------------------------------------------

const half = (x: number): number => Math.floor(x / 2);
const isOdd = (x: number): boolean => x % 2 === 1;

function isPowerOfTwo(x: number): boolean {
  if (x < 1) return false;
  let v = x;
  while (v % 2 === 0) v /= 2;
  return v === 1;
}

function popcount(x: number): number {
  let count = 0;
  for (let v = x; v > 0; v = half(v)) if (isOdd(v)) count++;
  return count;
}

/** Number of binary digits of x (0 for 0): the height of a tree of x + 1
 *  leaves is bitLength(x). */
function bitLength(x: number): number {
  let bits = 0;
  for (let v = x; v > 0; v = half(v)) bits++;
  return bits;
}

/** Hash of node `index` on `level` of a tree of fixed size: the MTH of leaves
 *  [index·2^level, min((index + 1)·2^level, size)). */
type NodeSource = (level: number, index: number) => string;

/** MTH of perfect subtrees that tile a range left to right: RFC 6962 splits at
 *  the largest power of two, so the fold runs right to left. */
function foldRight(pieces: string[]): string {
  let h = pieces[pieces.length - 1];
  for (let i = pieces.length - 2; i >= 0; i--) h = nodeHash(pieces[i], h);
  return h;
}

/**
 * The hashes a verifier needs to climb from node (level, index) to the root of
 * a tree of `size` leaves: the sibling of each ancestor, bottom up. A level
 * where the node is the promoted last one contributes nothing.
 */
function pathFromNode(level: number, index: number, size: number, nodeAt: NodeSource): string[] {
  const path: string[] = [];
  let lvl = level;
  let idx = index;
  let width = Math.ceil(size / 2 ** lvl);
  while (width > 1) {
    const sibling = isOdd(idx) ? idx - 1 : idx + 1;
    if (sibling < width) path.push(nodeAt(lvl, sibling));
    idx = half(idx);
    lvl += 1;
    width = Math.ceil(width / 2);
  }
  return path;
}

/**
 * PROOF(first, D[second]) by node indices, as in transparency-dev/merkle: the
 * largest perfect subtree that ends at `first`, then its audit path in the
 * tree of `second` leaves. When `first` is a power of two that subtree is the
 * whole first tree, which the verifier already holds as `firstRoot`, so it is
 * left out. Requires 0 < first ≤ second.
 */
function consistencyPath(first: number, second: number, nodeAt: NodeSource): string[] {
  if (first === second) return [];
  let level = 0;
  let odd = first;
  while (odd % 2 === 0) {
    odd /= 2;
    level += 1;
  }
  // first = odd · 2^level, so the subtree [first − 2^level, first) is node
  // (level, odd − 1), and index 0 means first is a power of two.
  const index = odd - 1;
  const path = index === 0 ? [] : [nodeAt(level, index)];
  return path.concat(pathFromNode(level, index, second, nodeAt));
}

// ---- Consistency proofs ------------------------------------------------------

/**
 * Why a consistency proof could not be generated or did not verify.
 *
 * - `malformed_tree`: the generator's tree is not one `buildMerkleTree` makes.
 * - `malformed_size`: a size is not a non-negative safe integer.
 * - `size_out_of_range`: the sizes break 0 < first ≤ second (and, for the
 *   generator, second ≤ the tree's leaf count). Tzun never publishes an empty
 *   log, so first = 0 is always out of range.
 * - `malformed_root`, `malformed_proof`: not 64-char hex, or not an array of it.
 * - `proof_length_mismatch`: the proof has more or fewer elements than the
 *   two sizes call for; equal sizes call for none.
 * - `first_root_mismatch`, `second_root_mismatch`: the proof does not
 *   reconstruct that root. Equal sizes with different roots report the second.
 */
export type ConsistencyProofReason =
  | 'malformed_tree'
  | 'malformed_size'
  | 'size_out_of_range'
  | 'malformed_root'
  | 'malformed_proof'
  | 'proof_length_mismatch'
  | 'first_root_mismatch'
  | 'second_root_mismatch';

export type ConsistencyProofResult =
  | { ok: true; proof: string[] }
  | { ok: false; reason: ConsistencyProofReason };

export interface ConsistencyVerification {
  valid: boolean;
  /** `null` exactly when `valid` is true. */
  reason: ConsistencyProofReason | null;
}

/** Thrown inside the generator on a tree node it cannot use; never escapes. */
class MalformedTree extends Error {}

/** The width of every layer `buildMerkleTree` produces for `leafCount` leaves. */
function expectedLayerWidths(leafCount: number): number[] {
  const widths = [leafCount];
  while (widths[widths.length - 1] > 1) widths.push(Math.ceil(widths[widths.length - 1] / 2));
  return widths;
}

function isWellShapedTree(tree: unknown): tree is MerkleTree {
  if (typeof tree !== 'object' || tree === null) return false;
  const { layers, leafCount } = tree as { layers?: unknown; leafCount?: unknown };
  if (!Number.isSafeInteger(leafCount) || (leafCount as number) < 1 || !Array.isArray(layers)) return false;
  const widths = expectedLayerWidths(leafCount as number);
  return (
    layers.length === widths.length &&
    widths.every((w, i) => Array.isArray(layers[i]) && (layers[i] as unknown[]).length === w)
  );
}

/**
 * Nodes of the tree of the first `size` leaves, read from a tree of
 * `tree.leafCount ≥ size` leaves. A perfect subtree is the same node in both
 * trees; a node on the right edge of the smaller tree is folded from the
 * perfect subtrees that tile it.
 */
function treeNodeSource(tree: MerkleTree, size: number): NodeSource {
  const stored = (level: number, index: number): string => {
    const value = tree.layers[level][index];
    if (typeof value !== 'string' || !HEX_64.test(value)) throw new MalformedTree();
    return value;
  };
  return (level, index) => {
    const span = 2 ** level;
    const lo = index * span;
    const hi = Math.min(lo + span, size);
    if (hi - lo === span) return stored(level, index);
    const pieces: string[] = [];
    let at = lo;
    for (let b = level - 1; b >= 0; b--) {
      const w = 2 ** b;
      if (at + w <= hi) {
        pieces.push(stored(b, at / w));
        at += w;
      }
    }
    return foldRight(pieces);
  };
}

/**
 * RFC 6962 §2.1.2 consistency proof PROOF(first, D[second]) from a built tree,
 * as bare lowercase hex. `second` defaults to the tree's leaf count; a smaller
 * `second` gives the proof between two earlier sizes of the same log.
 *
 * Never throws. A tree `buildMerkleTree` did not make, or sizes outside
 * 0 < first ≤ second ≤ leafCount, give `{ ok: false, reason }`. Equal sizes
 * give the empty proof.
 */
export function getConsistencyProof(tree: MerkleTree, first: number, second?: number): ConsistencyProofResult {
  if (!isWellShapedTree(tree)) return { ok: false, reason: 'malformed_tree' };
  const to = second === undefined ? tree.leafCount : second;
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(to)) return { ok: false, reason: 'malformed_size' };
  if (!(first > 0 && first <= to && to <= tree.leafCount)) return { ok: false, reason: 'size_out_of_range' };
  try {
    return { ok: true, proof: consistencyPath(first, to, treeNodeSource(tree, to)) };
  } catch (err) {
    if (err instanceof MalformedTree) return { ok: false, reason: 'malformed_tree' };
    throw err;
  }
}

/**
 * Verify an RFC 6962 consistency proof: RFC 9162 §2.1.4.2, with the Tzun edge
 * rules of Tree §3.5. `firstRoot` and `secondRoot`
 * are the roots of the log at sizes `first` and `second`.
 *
 * - 0 < first ≤ second, or `size_out_of_range`. Tzun never publishes an empty
 *   log, so a proof from size 0 is refused even when it is empty.
 * - first == second holds only with an empty proof and equal roots.
 * - Otherwise the proof must be non-empty and reconstruct both roots, with
 *   nothing left over and nothing missing.
 *
 * Never throws: every argument may be client-supplied JSON, and a malformed
 * one is `{ valid: false, reason }`. Hashes may be upper or lower case and are
 * compared after lowercasing; any other spelling is `malformed_root` or
 * `malformed_proof` (vectors/merkle-consistency-vectors.json, `encoding`).
 *
 * THE SECOND SIZE IS AN INPUT, NOT A FINDING. As for inclusion proofs, a wrong
 * `second` fails whenever it changes a step of the fold and cannot fail when
 * it does not. Over logs of up to 64 leaves, 1,984 of the 2,016 proofs with
 * first < second also verify under another `second`, both roots unchanged;
 * only an odd-sized log grown by exactly one leaf pins it. A wrong `first`
 * always changed a step in the same range. Both sizes must come from
 * authenticated checkpoints.
 */
export function verifyConsistencyProof(
  first: number,
  second: number,
  proof: string[],
  firstRoot: string,
  secondRoot: string
): ConsistencyVerification {
  const fail = (reason: ConsistencyProofReason): ConsistencyVerification => ({ valid: false, reason });

  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second)) return fail('malformed_size');
  if (!(first > 0 && first <= second)) return fail('size_out_of_range');
  const r1 = asDigest(firstRoot);
  const r2 = asDigest(secondRoot);
  if (r1 === null || r2 === null) return fail('malformed_root');
  if (!Array.isArray(proof)) return fail('malformed_proof');
  // A proof holds at most the first tree's last subtree plus one sibling per
  // level of the second tree: ceil(log2(second)) + 1 elements. A longer array
  // is refused on its length, before any element is read.
  if (proof.length > bitLength(second - 1) + 1) return fail('proof_length_mismatch');
  const path: string[] = [];
  for (const entry of proof) {
    const step = asDigest(entry);
    if (step === null) return fail('malformed_proof');
    path.push(step);
  }

  if (first === second) {
    if (path.length !== 0) return fail('proof_length_mismatch');
    return r1 === r2 ? { valid: true, reason: null } : fail('second_root_mismatch');
  }
  if (path.length === 0) return fail('proof_length_mismatch');

  // The verifier holds the whole first tree as `firstRoot`; when `first` is a
  // power of two the proof leaves that subtree out.
  if (isPowerOfTwo(first)) path.unshift(r1);

  let fn = first - 1;
  let sn = second - 1;
  while (isOdd(fn)) {
    fn = half(fn);
    sn = half(sn);
  }

  let fr = path[0];
  let sr = path[0];
  for (let i = 1; i < path.length; i++) {
    // More proof than the two sizes can justify.
    if (sn === 0) return fail('proof_length_mismatch');
    const c = path[i];
    if (isOdd(fn) || fn === sn) {
      // c is a left sibling: part of both trees.
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn !== 0 && !isOdd(fn)) {
        fn = half(fn);
        sn = half(sn);
      }
    } else {
      // c is a right sibling: only in the second tree.
      sr = nodeHash(sr, c);
    }
    fn = half(fn);
    sn = half(sn);
  }

  // `sn === 0` rejects a truncated proof, as for inclusion proofs.
  if (sn !== 0) return fail('proof_length_mismatch');
  if (fr !== r1) return fail('first_root_mismatch');
  if (sr !== r2) return fail('second_root_mismatch');
  return { valid: true, reason: null };
}

// ---- Compact ranges ------------------------------------------------------------

/**
 * The compact range of a log of `size` leaves: the roots of the perfect
 * subtrees that tile [0, size), largest (leftmost) first, one per set bit of
 * `size`. It is all a log writer keeps between epochs: the next root, the
 * consistency proof from `size`, and the inclusion proof of every leaf
 * appended after it follow from it and the new leaves alone.
 */
export interface CompactRange {
  size: number;
  hashes: string[];
}

/** What appending leaves to a compact range yields (see `extendCompactRange`). */
export interface CompactRangeExtension {
  /** The compact range of the extended log. */
  range: CompactRange;
  /** MTH of the extended log. */
  root: string;
  /** PROOF(old size, D[new size]); `[]` when nothing was appended, and `null`
   *  from an empty log, which has no root to be consistent with. */
  consistencyProof: string[] | null;
  /** PATH(j, D[new size]) for each appended leaf j, in append order. */
  inclusionProofs: string[][];
}

function checkedRange(range: unknown): CompactRange {
  if (typeof range !== 'object' || range === null) {
    throw new Error('Malformed compact range: expected { size, hashes }.');
  }
  const { size, hashes } = range as { size?: unknown; hashes?: unknown };
  if (!Number.isSafeInteger(size) || (size as number) < 0) {
    throw new Error('Malformed compact range: size must be a non-negative safe integer.');
  }
  if (!Array.isArray(hashes) || hashes.length !== popcount(size as number)) {
    throw new Error(`Malformed compact range: a size of ${size} needs ${popcount(size as number)} hashes.`);
  }
  const normalised = hashes.map((h, i) => {
    const v = asDigest(h);
    if (v === null) throw new Error(`Malformed compact range: hash ${i} is not a 64-character hex digest.`);
    return v;
  });
  return { size: size as number, hashes: normalised };
}

/**
 * Validate appended digests. The range cannot see the leaves behind it, so
 * distinctness against them is the log writer's to enforce; within the batch
 * a repeat is refused, as `buildMerkleTree` refuses one.
 */
function checkedDigests(digests: unknown): string[] {
  if (!Array.isArray(digests)) throw new Error('Cannot add to a compact range: digests must be an array.');
  const seen = new Set<string>();
  return digests.map((d, i) => {
    const v = asDigest(d);
    if (v === null) throw new Error(`Cannot add to a compact range: entry ${i} is not a 64-character hex digest.`);
    if (seen.has(v)) {
      throw new Error(`Cannot add to a compact range: duplicate digest at index ${i} makes the root ambiguous (CVE-2012-2459).`);
    }
    seen.add(v);
    return v;
  });
}

/** The (level, index) of each compact-range subtree of `size`, largest first. */
function rangeNodes(size: number): Array<{ level: number; index: number }> {
  const nodes: Array<{ level: number; index: number }> = [];
  let level = 0;
  while (2 ** (level + 1) <= size) level += 1;
  let start = 0;
  for (; level >= 0; level--) {
    const span = 2 ** level;
    if (start + span <= size) {
      nodes.push({ level, index: start / span });
      start += span;
    }
  }
  return nodes;
}

interface Grown {
  size: number;
  nodeAt: NodeSource;
}

/**
 * The tree of `range.size + leaves.length` leaves, held as the old compact
 * range plus, on every level, the nodes that reach into the appended leaves.
 * Any other node of the new tree lies inside an old compact-range subtree and
 * is never needed.
 */
function grow(range: CompactRange, leaves: string[]): Grown {
  const m = range.size;
  const n = m + leaves.length;
  const old = new Map<string, string>();
  rangeNodes(m).forEach(({ level, index }, i) => old.set(`${level}:${index}`, range.hashes[i]));

  // rows[level][k] is node (level, base[level] + k), for every node on that
  // level whose leaves reach past m.
  const rows: string[][] = [leaves.map(merkleLeafHash)];
  const base: number[] = [m];
  const at = (level: number, index: number): string => {
    if (level < rows.length && index >= base[level]) return rows[level][index - base[level]];
    const h = old.get(`${level}:${index}`);
    if (h === undefined) throw new Error(`Compact range has no node (${level}, ${index}).`);
    return h;
  };

  if (m < n) {
    for (let level = 0; Math.ceil(n / 2 ** level) > 1; level++) {
      const width = Math.ceil(n / 2 ** level);
      const from = Math.floor(m / 2 ** (level + 1));
      const to = Math.ceil(n / 2 ** (level + 1));
      const next: string[] = [];
      for (let i = from; i < to; i++) {
        const left = at(level, 2 * i);
        // No right child: the node is promoted unchanged.
        next.push(2 * i + 1 < width ? nodeHash(left, at(level, 2 * i + 1)) : left);
      }
      rows.push(next);
      base.push(from);
    }
  }
  return { size: n, nodeAt: at };
}

/**
 * The compact range of a log whose leaves are `digests`, in order. An empty
 * list gives the range of the empty log.
 *
 * @throws on a digest that is not 64-char hex, or on a repeated digest.
 */
export function compactRangeOf(digests: string[]): CompactRange {
  return extendRange({ size: 0, hashes: [] }, checkedDigests(digests)).range;
}

/**
 * MTH of the log a compact range describes.
 *
 * @throws on a malformed range, and on the empty log, which has no root.
 */
export function compactRangeRoot(range: CompactRange): string {
  const r = checkedRange(range);
  if (r.size === 0) throw new Error('Cannot compute a root: the compact range describes an empty log.');
  return foldRight(r.hashes);
}

function extendRange(range: CompactRange, leaves: string[]): { range: CompactRange; grown: Grown } {
  const grown = grow(range, leaves);
  const hashes = rangeNodes(grown.size).map(({ level, index }) => grown.nodeAt(level, index));
  return { range: { size: grown.size, hashes }, grown };
}

/**
 * Append `digests` to the log a compact range describes, using only that range
 * and the new leaves: O(new leaves + log n) hashes for the root, the new range
 * and the consistency proof, plus O(log n) per inclusion proof.
 *
 * Every output equals a recomputation over the whole log (Tree §5.5, §9, tested
 * for every 0 ≤ m ≤ n ≤ 64).
 *
 * @throws on a malformed range, a digest that is not 64-char hex, a digest
 *         repeated within `digests`, an empty log with nothing appended, or
 *         a log that would pass Number.MAX_SAFE_INTEGER leaves.
 */
export function extendCompactRange(range: CompactRange, digests: string[]): CompactRangeExtension {
  const before = checkedRange(range);
  const leaves = checkedDigests(digests);
  // Past 2^53 − 1 a leaf index is no longer an exact number, so neither the
  // node arithmetic nor the index of any appended leaf would mean anything.
  if (leaves.length > Number.MAX_SAFE_INTEGER - before.size) {
    throw new Error(
      `Malformed compact range: a log of ${before.size} leaves cannot take ${leaves.length} more ` +
        'without passing Number.MAX_SAFE_INTEGER.'
    );
  }
  if (before.size === 0 && leaves.length === 0) {
    throw new Error('Cannot extend a compact range: an empty log with nothing appended has no root.');
  }
  const { range: after, grown } = extendRange(before, leaves);
  const m = before.size;
  const n = after.size;
  const inclusionProofs: string[][] = [];
  for (let j = m; j < n; j++) inclusionProofs.push(pathFromNode(0, j, n, grown.nodeAt));
  return {
    range: after,
    root: foldRight(after.hashes),
    consistencyProof: m === 0 ? null : consistencyPath(m, n, grown.nodeAt),
    inclusionProofs,
  };
}

// ---- Proofs from a compact range, leaves streamed -------------------------------

/** What a {@link CompactRangeProver} yields once it holds every leaf. */
export interface CompactRangeProofs {
  /** The compact range of the log of `size` leaves. */
  range: CompactRange;
  /** MTH of the log of `size` leaves. */
  root: string;
  /** PATH(leafIndex, D[size]); null when no leaf was asked for. */
  inclusionProof: string[] | null;
  /** PROOF(fromSize, D[size]); null when no size was asked for. */
  consistencyProof: string[] | null;
}

interface RangeNode {
  level: number;
  index: number;
  hash: string;
}

/**
 * One inclusion proof and one consistency proof in a log of `size` leaves,
 * from the compact range of an earlier size and the leaves after it, fed in
 * as many `append` calls as the caller likes. It keeps only the compact range
 * of the leaves so far and the O(log n) nodes the two proofs need, so a caller
 * can read the leaves a page at a time: O(new leaves) hashes in all, O(log n)
 * state, whatever the log's growth. `extendCompactRange` gives every appended
 * leaf's inclusion proof instead, and holds them all.
 *
 * The leaves are the log's own. Their distinctness was the log writer's to
 * enforce when it appended them, so it is not checked here.
 */
export class CompactRangeProver {
  private readonly size: number;
  private readonly leafIndex: number | null;
  private readonly fromSize: number | null;
  /** The nodes of the starting compact range, by level and index. */
  private readonly old = new Map<string, string>();
  /** wanted[level] holds the indices, on that level, of the nodes the proofs read. */
  private readonly wanted: Array<Set<number>> = [];
  private readonly found = new Map<string, string>();
  /** The compact range of the leaves appended so far, largest subtree first. */
  private readonly stack: RangeNode[];
  private appended: number;

  /**
   * @param range     the compact range of the log's first `range.size` leaves
   * @param size      the size the proofs are in, at least `range.size`
   * @param want      `leafIndex`: the leaf whose PATH(leafIndex, D[size]) to
   *                  give, with `range.size ≤ leafIndex < size`; `fromSize`:
   *                  the size whose PROOF(fromSize, D[size]) to give, with
   *                  `range.size ≤ fromSize ≤ size` and `fromSize ≥ 1`
   * @throws on a malformed range, a size or a request outside those bounds,
   *         and an empty log, which has no root
   */
  constructor(range: CompactRange, size: number, want: { leafIndex?: number; fromSize?: number } = {}) {
    const before = checkedRange(range);
    if (!Number.isSafeInteger(size) || size < before.size) {
      throw new Error(`Cannot prove from a compact range of ${before.size} leaves: size must be a safe integer of at least ${before.size}.`);
    }
    if (size === 0) throw new Error('Cannot prove from a compact range: an empty log has no root.');
    const { leafIndex, fromSize } = want;
    if (leafIndex !== undefined && (!Number.isSafeInteger(leafIndex) || leafIndex < before.size || leafIndex >= size)) {
      throw new Error(`Cannot prove the inclusion of leaf ${leafIndex}: it must be at least ${before.size} and below ${size}.`);
    }
    if (fromSize !== undefined && (!Number.isSafeInteger(fromSize) || fromSize < Math.max(before.size, 1) || fromSize > size)) {
      throw new Error(`Cannot prove consistency from size ${fromSize}: it must be at least ${Math.max(before.size, 1)} and at most ${size}.`);
    }
    this.size = size;
    this.leafIndex = leafIndex ?? null;
    this.fromSize = fromSize ?? null;
    this.appended = before.size;
    this.stack = rangeNodes(before.size).map(({ level, index }, i) => ({ level, index, hash: before.hashes[i] }));
    for (const node of this.stack) this.old.set(`${node.level}:${node.index}`, node.hash);

    // The nodes the proofs read, found by running them over a source that
    // only records what it is asked for.
    const record: NodeSource = (level, index) => {
      (this.wanted[level] ??= new Set<number>()).add(index);
      return '';
    };
    if (this.leafIndex !== null) pathFromNode(0, this.leafIndex, size, record);
    if (this.fromSize !== null) consistencyPath(this.fromSize, size, record);
  }

  /** The index of the next leaf `append` takes. */
  get next(): number {
    return this.appended;
  }

  /**
   * Append the next leaves of the log, in order.
   *
   * @throws on a digest that is not 64-char hex, and on more leaves than the
   *         log's size leaves room for
   */
  append(digests: string[]): void {
    if (!Array.isArray(digests)) throw new Error('Cannot append to a compact range: digests must be an array.');
    if (digests.length > this.size - this.appended) {
      throw new Error(`Cannot append ${digests.length} leaves at ${this.appended}: the log has ${this.size}.`);
    }
    for (let i = 0; i < digests.length; i++) {
      const digest = asDigest(digests[i]);
      if (digest === null) throw new Error(`Cannot append to a compact range: entry ${i} is not a 64-character hex digest.`);
      let node: RangeNode = { level: 0, index: this.appended, hash: merkleLeafHash(digest) };
      this.keep(node);
      // The range's subtrees have strictly decreasing levels, so the only
      // one the new node can join is the last, when it is on the same level.
      while (this.stack.length > 0 && this.stack[this.stack.length - 1].level === node.level) {
        const left = this.stack.pop() as RangeNode;
        node = { level: node.level + 1, index: half(node.index), hash: nodeHash(left.hash, node.hash) };
        this.keep(node);
      }
      this.stack.push(node);
      this.appended += 1;
    }
  }

  /**
   * The root, the compact range and the proofs asked for.
   *
   * @throws unless every leaf up to the log's size was appended
   */
  finish(): CompactRangeProofs {
    if (this.appended !== this.size) {
      throw new Error(`Cannot finish: ${this.appended} of the log's ${this.size} leaves were appended.`);
    }
    const nodeAt: NodeSource = (level, index) => {
      const key = `${level}:${index}`;
      const hash = this.found.get(key) ?? this.old.get(key);
      if (hash !== undefined) return hash;
      // A node on the right edge of the tree: the fold of the range's
      // subtrees that tile it.
      const lo = index * 2 ** level;
      if (lo < this.size && lo + 2 ** level > this.size) {
        return foldRight(this.stack.filter((n) => n.index * 2 ** n.level >= lo).map((n) => n.hash));
      }
      throw new Error(`Compact range has no node (${level}, ${index}).`);
    };
    const hashes = this.stack.map((n) => n.hash);
    return {
      range: { size: this.size, hashes },
      root: foldRight(hashes),
      inclusionProof: this.leafIndex === null ? null : pathFromNode(0, this.leafIndex, this.size, nodeAt),
      consistencyProof: this.fromSize === null ? null : consistencyPath(this.fromSize, this.size, nodeAt),
    };
  }

  private keep(node: RangeNode): void {
    if (this.wanted[node.level]?.has(node.index)) this.found.set(`${node.level}:${node.index}`, node.hash);
  }
}
