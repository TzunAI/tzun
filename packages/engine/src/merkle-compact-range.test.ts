/**
 * Compact ranges: Tree §5.5, §9.
 *
 * A checkpoint row keeps the compact range of its size: the popcount(n) roots
 * of the perfect subtrees that tile [0, n), largest first. An epoch then needs
 * only that range plus the leaves appended since. These tests require every
 * root, compact range, consistency proof and inclusion proof computed that way
 * to equal a recomputation over the whole log, for every 0 ≤ m ≤ n ≤ 64.
 */
import { createHash } from 'crypto';

import {
  buildMerkleTree,
  compactRangeOf,
  compactRangeRoot,
  extendCompactRange,
  getConsistencyProof,
  getMerkleProof,
  getMerkleRoot,
  merkleLeafHash,
  verifyConsistencyProof,
  verifyMerkleProof,
} from './merkle';
import type { CompactRange, MerkleTree } from './merkle';

const LEAVES = Array.from({ length: 64 }, (_, i) =>
  createHash('sha256').update(`tzun-merkle-vector-${i}`, 'utf8').digest('hex'),
);

const trees = new Map<number, MerkleTree>();
const treeOf = (n: number): MerkleTree => {
  let t = trees.get(n);
  if (!t) {
    t = buildMerkleTree(LEAVES.slice(0, n));
    trees.set(n, t);
  }
  return t;
};

const popcount = (n: number): number => n.toString(2).split('').filter((b) => b === '1').length;

describe('Tree §5.5, §9: the compact range of a size', () => {
  it('holds popcount(n) subtree roots, and folds to the root of the whole log', () => {
    for (let n = 1; n <= 64; n++) {
      const range = compactRangeOf(LEAVES.slice(0, n));
      expect(range.size).toBe(n);
      expect(range.hashes).toHaveLength(popcount(n));
      expect(compactRangeRoot(range)).toBe(getMerkleRoot(treeOf(n)));
    }
  });

  it('is the leaf hash for one leaf, and empty for none', () => {
    expect(compactRangeOf([LEAVES[0]])).toEqual({ size: 1, hashes: [merkleLeafHash(LEAVES[0])] });
    expect(compactRangeOf([])).toEqual({ size: 0, hashes: [] });
  });

  it('holds the perfect subtrees that tile [0, n), largest first', () => {
    // 13 = 8 + 4 + 1: subtrees [0, 8), [8, 12) and [12, 13).
    const range = compactRangeOf(LEAVES.slice(0, 13));
    expect(range.hashes).toEqual([
      getMerkleRoot(buildMerkleTree(LEAVES.slice(0, 8))),
      getMerkleRoot(buildMerkleTree(LEAVES.slice(8, 12))),
      merkleLeafHash(LEAVES[12]),
    ]);
  });
});

describe('Tree §5.5, §9: extending a compact range equals a full recomputation, for every 0 ≤ m ≤ n ≤ 64', () => {
  it('reproduces the root, the new compact range, the consistency proof and every new leaf\'s inclusion proof', () => {
    const failures: string[] = [];
    let pairs = 0;
    let inclusionProofs = 0;
    for (let m = 0; m <= 64; m++) {
      const before = compactRangeOf(LEAVES.slice(0, m));
      for (let n = Math.max(m, 1); n <= 64; n++) {
        pairs++;
        const full = treeOf(n);
        const root = getMerkleRoot(full);
        const ext = extendCompactRange(before, LEAVES.slice(m, n));

        if (ext.root !== root) failures.push(`root ${m}/${n}`);
        if (JSON.stringify(ext.range) !== JSON.stringify(compactRangeOf(LEAVES.slice(0, n)))) failures.push(`range ${m}/${n}`);

        if (m === 0) {
          if (ext.consistencyProof !== null) failures.push(`a proof from the empty log ${m}/${n}`);
        } else {
          const direct = getConsistencyProof(full, m);
          if (!direct.ok || JSON.stringify(ext.consistencyProof) !== JSON.stringify(direct.proof)) {
            failures.push(`consistency ${m}/${n}`);
          }
          const firstRoot = compactRangeRoot(before);
          if (!verifyConsistencyProof(m, n, ext.consistencyProof as string[], firstRoot, ext.root).valid) {
            failures.push(`consistency verifies ${m}/${n}`);
          }
        }

        if (ext.inclusionProofs.length !== n - m) failures.push(`inclusion count ${m}/${n}`);
        for (let j = m; j < n; j++) {
          inclusionProofs++;
          const path = ext.inclusionProofs[j - m];
          if (JSON.stringify(path) !== JSON.stringify(getMerkleProof(full, j))) failures.push(`inclusion ${j} ${m}/${n}`);
          if (!verifyMerkleProof(LEAVES[j], j, n, path, root)) failures.push(`inclusion verifies ${j} ${m}/${n}`);
        }
      }
    }
    expect(failures).toEqual([]);
    // 0 ≤ m ≤ n ≤ 64 with n ≥ 1, and one inclusion proof per appended leaf.
    expect(pairs).toBe(2144);
    expect(inclusionProofs).toBe(45760);
  }, 60_000);

  it('carries a log through irregular epochs, each proven consistent with the last', () => {
    const batches = [1, 2, 3, 5, 8, 1, 1, 13, 4, 26];
    let range: CompactRange = compactRangeOf([]);
    let previousRoot: string | null = null;
    let size = 0;
    for (const count of batches) {
      const ext = extendCompactRange(range, LEAVES.slice(size, size + count));
      const newSize = size + count;
      expect(ext.range.size).toBe(newSize);
      expect(ext.root).toBe(getMerkleRoot(treeOf(newSize)));
      if (previousRoot === null) {
        expect(ext.consistencyProof).toBeNull();
      } else {
        expect(verifyConsistencyProof(size, newSize, ext.consistencyProof as string[], previousRoot, ext.root)).toEqual({
          valid: true,
          reason: null,
        });
      }
      range = ext.range;
      previousRoot = ext.root;
      size = newSize;
    }
    expect(size).toBe(64);
  });

  it('with nothing appended, keeps the range and gives the empty proof', () => {
    const range = compactRangeOf(LEAVES.slice(0, 11));
    const ext = extendCompactRange(range, []);
    expect(ext.range).toEqual(range);
    expect(ext.root).toBe(getMerkleRoot(treeOf(11)));
    expect(ext.consistencyProof).toEqual([]);
    expect(ext.inclusionProofs).toEqual([]);
  });
});

describe('compact-range inputs are checked', () => {
  const good = () => compactRangeOf(LEAVES.slice(0, 5));

  it.each<[string, () => unknown]>([
    ['a range with too few hashes', () => ({ size: 5, hashes: good().hashes.slice(0, 1) })],
    ['a range with too many hashes', () => ({ size: 4, hashes: good().hashes })],
    ['a range with a non-hex hash', () => ({ size: 5, hashes: ['zz'.repeat(32), good().hashes[1]] })],
    ['a negative size', () => ({ size: -1, hashes: [] })],
    ['a fractional size', () => ({ size: 1.5, hashes: [good().hashes[0]] })],
    ['a missing hashes array', () => ({ size: 5 })],
    ['a null range', () => null],
  ])('extendCompactRange refuses %s', (_name, range) => {
    expect(() => extendCompactRange(range() as CompactRange, [LEAVES[5]])).toThrow(/compact range/i);
  });

  it('refuses a malformed or repeated appended digest', () => {
    expect(() => extendCompactRange(good(), ['nope'])).toThrow(/64-character hex/);
    expect(() => extendCompactRange(good(), [LEAVES[5], LEAVES[5]])).toThrow(/duplicate/i);
    expect(() => compactRangeOf([LEAVES[0], LEAVES[0]])).toThrow(/duplicate/i);
  });

  it('gives an empty log no root', () => {
    expect(() => compactRangeRoot(compactRangeOf([]))).toThrow(/empty/i);
  });
});

describe('a log never grows past Number.MAX_SAFE_INTEGER leaves', () => {
  // A full compact range of 2^53 − 1 leaves: one subtree per set bit, 53 of them.
  const top: CompactRange = { size: Number.MAX_SAFE_INTEGER, hashes: LEAVES.slice(0, 53) };

  it.each([1, 2, 3])('refuses to append %i leaf/leaves to a log of 2^53 − 1', (count) => {
    expect(() => extendCompactRange(top, LEAVES.slice(53, 53 + count))).toThrow(
      /Malformed compact range: .*Number\.MAX_SAFE_INTEGER/,
    );
  });

  it('still grows a log to exactly 2^53 − 1, with proofs that verify', () => {
    // 2^53 − 2 has every bit but the lowest set: 52 subtrees.
    const before: CompactRange = { size: Number.MAX_SAFE_INTEGER - 1, hashes: LEAVES.slice(0, 52) };
    const leaf = LEAVES[60];
    const ext = extendCompactRange(before, [leaf]);
    expect(ext.range.size).toBe(Number.MAX_SAFE_INTEGER);
    expect(ext.range.hashes).toHaveLength(53);
    expect(ext.root).toBe(compactRangeRoot(ext.range));
    expect(ext.inclusionProofs).toHaveLength(1);
    expect(verifyMerkleProof(leaf, Number.MAX_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER, ext.inclusionProofs[0], ext.root)).toBe(true);
    expect(
      verifyConsistencyProof(
        Number.MAX_SAFE_INTEGER - 1,
        Number.MAX_SAFE_INTEGER,
        ext.consistencyProof as string[],
        compactRangeRoot(before),
        ext.root,
      ),
    ).toEqual({ valid: true, reason: null });
  });
});
