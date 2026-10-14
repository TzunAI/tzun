/**
 * RFC 6962 §2.1.2 consistency proofs: Tree §3.5, §5.3, §9.
 *
 * The vectors are an INDEPENDENT pin. scripts/generate-consistency-vectors.mjs
 * transcribes SUBPROOF recursively and imports nothing but node:crypto; the
 * generator under test walks node indices, and the verifier under test is the
 * Tree §3.5 algorithm. Regenerating the vectors from this module would defeat the
 * point.
 *
 * The last block measures size binding (Tree §3.6). A verifier
 * recomputes a root from the path and the size it is given, so it rejects
 * every wrong size whose fold differs and cannot reject a wrong size whose fold
 * is identical. The tests derive "identical fold" from the RFC recursion over
 * sizes alone, with no hashing, and require the verifiers to match it exactly.
 */
import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';

import {
  buildMerkleTree,
  compactRangeOf,
  compactRangeRoot,
  extendCompactRange,
  getConsistencyProof,
  getMerkleProof,
  getMerkleRoot,
  verifyConsistencyProof,
  verifyMerkleProof,
} from './merkle';
import type { ConsistencyProofReason, MerkleTree } from './merkle';

interface Case {
  first: number;
  second: number;
  firstRoot: string;
  secondRoot: string;
  proof: string[];
}
interface Vectors {
  leafDigests: string[];
  valid: Case[];
  invalid: Array<Case & { mutation: string; derivedFrom: { first: number; second: number } }>;
  encoding: Array<{
    case: string;
    verifies: boolean;
    first: number;
    second: number;
    firstRoot: unknown;
    secondRoot: unknown;
    proof: unknown;
  }>;
  sizeMalleability: {
    census: {
      inclusion: { proofs: number; verifyUnderAnotherTreeSize: number };
      consistency: { proofs: number; verifyUnderAnotherSecondSize: number; verifyUnderAnotherFirstSize: number };
    };
    inclusion: Array<{
      leafIndex: number;
      leafDigest: string;
      treeSize: number;
      root: string;
      auditPath: string[];
      alsoVerifiesUnderTreeSize: number[];
    }>;
    consistency: Array<Case & { alsoVerifiesUnderSecond: number[] }>;
  };
}

const V: Vectors = JSON.parse(
  readFileSync(join(__dirname, '..', '..', '..', 'vectors', 'merkle-consistency-vectors.json'), 'utf-8'),
);
const LEAVES = V.leafDigests;

const trees = new Map<number, MerkleTree>();
const treeOf = (n: number): MerkleTree => {
  let t = trees.get(n);
  if (!t) {
    t = buildMerkleTree(LEAVES.slice(0, n));
    trees.set(n, t);
  }
  return t;
};
const rootOf = (n: number): string => getMerkleRoot(treeOf(n));

/** Flip the lowest bit of the first byte. */
const flip = (h: string): string => (parseInt(h.slice(0, 2), 16) ^ 1).toString(16).padStart(2, '0') + h.slice(2);

const proofOf = (tree: MerkleTree, first: number, second?: number): string[] => {
  const r = getConsistencyProof(tree, first, second);
  if (!r.ok) throw new Error(`generator refused (${first}, ${second ?? tree.leafCount}): ${r.reason}`);
  return r.proof;
};

describe('Tree §9: the independent consistency vectors', () => {
  it('derive their leaves as documented', () => {
    expect(LEAVES).toHaveLength(64);
    LEAVES.forEach((d, i) => {
      expect(d).toBe(createHash('sha256').update(`tzun-merkle-vector-${i}`, 'utf8').digest('hex'));
    });
  });

  it('cover every pair 0 < first ≤ second ≤ 16, and pairs up to 64', () => {
    const have = new Set(V.valid.map((c) => `${c.first}/${c.second}`));
    for (let n = 1; n <= 16; n++) for (let m = 1; m <= n; m++) expect(have.has(`${m}/${n}`)).toBe(true);
    expect(Math.max(...V.valid.map((c) => c.second))).toBe(64);
    expect(V.valid.length).toBe(have.size);
  });

  it.each(V.valid.map((c) => [c.first, c.second, c] as const))(
    'PROOF(%i, D[%i]): the generator reproduces it byte for byte and the verifier accepts it',
    (first, second, c) => {
      expect(rootOf(first)).toBe(c.firstRoot);
      expect(rootOf(second)).toBe(c.secondRoot);
      expect(getConsistencyProof(treeOf(second), first)).toEqual({ ok: true, proof: c.proof });
      // The same proof from a log that has since grown to 64 leaves.
      expect(getConsistencyProof(treeOf(64), first, second)).toEqual({ ok: true, proof: c.proof });
      expect(verifyConsistencyProof(first, second, c.proof, c.firstRoot, c.secondRoot)).toEqual({
        valid: true,
        reason: null,
      });
    },
  );

  it.each(V.invalid.map((c) => [c.mutation, JSON.stringify(c.derivedFrom), c] as const))(
    'refuses "%s" (from %s)',
    (_mutation, _from, c) => {
      const verdict = verifyConsistencyProof(c.first, c.second, c.proof, c.firstRoot, c.secondRoot);
      expect(verdict.valid).toBe(false);
      expect(verdict.reason).not.toBeNull();
    },
  );

  it.each(V.encoding.map((c) => [c.case, c] as const))('encoding: %s', (_name, c) => {
    const verdict = (verifyConsistencyProof as (...a: unknown[]) => { valid: boolean; reason: string | null })(
      c.first,
      c.second,
      c.proof,
      c.firstRoot,
      c.secondRoot,
    );
    expect(verdict.valid).toBe(c.verifies);
    if (!c.verifies) expect(['malformed_root', 'malformed_proof']).toContain(verdict.reason);
  });

  it('pin case normalisation and each refused spelling', () => {
    const names = V.encoding.map((c) => `${c.verifies ? 'accept' : 'refuse'}: ${c.case}`);
    for (const expected of [
      'accept: every proof element in uppercase',
      'accept: equal sizes, roots equal once case is normalised',
      'refuse: proof[0] with a trailing newline',
      'refuse: proof[0] with 63 hex digits',
      'refuse: proof[0] with 65 hex digits',
      'refuse: proof[0] with a 0x prefix',
      'refuse: proof[0] is a number',
    ]) {
      expect(names).toContain(expected);
    }
  });

  it('accepts every size-malleability exhibit under every size it lists (the math, not this verifier)', () => {
    for (const e of V.sizeMalleability.consistency) {
      for (const s of [e.second, ...e.alsoVerifiesUnderSecond]) {
        expect(verifyConsistencyProof(e.first, s, e.proof, e.firstRoot, e.secondRoot).valid).toBe(true);
      }
    }
    for (const e of V.sizeMalleability.inclusion) {
      for (const s of [e.treeSize, ...e.alsoVerifiesUnderTreeSize]) {
        expect(verifyMerkleProof(e.leafDigest, e.leafIndex, s, e.auditPath, e.root)).toBe(true);
      }
    }
  });
});

describe('Tree §3.5, §5.3: the separate verifier checks the generator, exhaustively for second ≤ 64', () => {
  it('accepts every generated proof and refuses every single-bit tamper of a proof element or a root', () => {
    const failures: string[] = [];
    let tampers = 0;
    for (let n = 1; n <= 64; n++) {
      const secondRoot = rootOf(n);
      for (let m = 1; m <= n; m++) {
        const firstRoot = rootOf(m);
        const proof = proofOf(treeOf(n), m);
        if (JSON.stringify(proofOf(treeOf(64), m, n)) !== JSON.stringify(proof)) failures.push(`grown tree ${m}/${n}`);
        if (!verifyConsistencyProof(m, n, proof, firstRoot, secondRoot).valid) failures.push(`honest ${m}/${n}`);
        proof.forEach((_, i) => {
          const bad = [...proof];
          bad[i] = flip(bad[i]);
          tampers++;
          if (verifyConsistencyProof(m, n, bad, firstRoot, secondRoot).valid) failures.push(`proof[${i}] ${m}/${n}`);
        });
        tampers += 2;
        if (verifyConsistencyProof(m, n, proof, flip(firstRoot), secondRoot).valid) failures.push(`firstRoot ${m}/${n}`);
        if (verifyConsistencyProof(m, n, proof, firstRoot, flip(secondRoot)).valid) failures.push(`secondRoot ${m}/${n}`);
      }
    }
    expect(failures).toEqual([]);
    expect(tampers).toBeGreaterThan(10_000);
  }, 60_000);

  it('gives the empty proof for equal sizes, and refuses it for distinct ones', () => {
    expect(proofOf(treeOf(5), 5)).toEqual([]);
    expect(verifyConsistencyProof(5, 5, [], rootOf(5), rootOf(5))).toEqual({ valid: true, reason: null });
    expect(verifyConsistencyProof(5, 6, [], rootOf(5), rootOf(6))).toEqual({
      valid: false,
      reason: 'proof_length_mismatch',
    });
  });

  it('names what failed', () => {
    const proof = proofOf(treeOf(7), 3);
    const [r3, r7] = [rootOf(3), rootOf(7)];
    expect(verifyConsistencyProof(3, 7, proof, flip(r3), r7).reason).toBe('first_root_mismatch');
    expect(verifyConsistencyProof(3, 7, proof, r3, flip(r7)).reason).toBe('second_root_mismatch');
    expect(verifyConsistencyProof(3, 7, proof.slice(0, -1), r3, r7).reason).toBe('proof_length_mismatch');
    expect(verifyConsistencyProof(3, 7, [...proof, r7], r3, r7).reason).toBe('proof_length_mismatch');
    expect(verifyConsistencyProof(4, 4, [r3], rootOf(4), rootOf(4)).reason).toBe('proof_length_mismatch');
    expect(verifyConsistencyProof(4, 4, [], rootOf(4), r7).reason).toBe('second_root_mismatch');
    expect(verifyConsistencyProof(7, 3, proof, r7, r3).reason).toBe('size_out_of_range');
    expect(verifyConsistencyProof(0, 7, [], rootOf(1), r7).reason).toBe('size_out_of_range');
  });
});

describe('the verifier caps the proof length by the second size', () => {
  it('refuses an over-long proof by its length alone, before reading an element', () => {
    // A proof holds at most one element per tree level plus the first tree's
    // subtree: ceil(log2(second)) + 1. A million unreadable elements for a log
    // of 7 is refused on length, without a pass over the array.
    const verdict = verifyConsistencyProof(3, 7, Array(1_000_000).fill('zz'), rootOf(3), rootOf(7));
    expect(verdict).toEqual({ valid: false, reason: 'proof_length_mismatch' });
  });

  it('admits every honest proof: the bound holds for every 1 ≤ m ≤ n ≤ 1024 and is reached', () => {
    const bitLength = (x: number): number => (x === 0 ? 0 : Math.floor(Math.log2(x)) + 1);
    const over: string[] = [];
    let reached = 0;
    for (let n = 1; n <= 1024; n++) {
      const bound = bitLength(n - 1) + 1;
      let longest = 0;
      for (let m = 1; m <= n; m++) longest = Math.max(longest, subproofSteps(m, n, true).length);
      if (longest > bound) over.push(`${n}: ${longest} > ${bound}`);
      if (longest === bound) reached++;
    }
    expect(over).toEqual([]);
    expect(reached).toBeGreaterThan(900);
  });

  it('verifies every honest proof into logs of 100 to 1,025 leaves', () => {
    const leaves = Array.from({ length: 1025 }, (_, i) =>
      createHash('sha256').update(`tzun-merkle-cap-${i}`, 'utf8').digest('hex'),
    );
    // Root of every prefix, from one running compact range.
    const roots: string[] = [''];
    let range = compactRangeOf([]);
    for (const leaf of leaves) {
      range = extendCompactRange(range, [leaf]).range;
      roots.push(compactRangeRoot(range));
    }
    const failures: string[] = [];
    for (const n of [100, 255, 256, 257, 1000, 1023, 1024, 1025]) {
      const tree = buildMerkleTree(leaves.slice(0, n));
      expect(roots[n]).toBe(getMerkleRoot(tree));
      for (let m = 1; m <= n; m++) {
        const verdict = verifyConsistencyProof(m, n, proofOf(tree, m), roots[m], roots[n]);
        if (!verdict.valid) failures.push(`${m}/${n}: ${verdict.reason}`);
      }
    }
    expect(failures).toEqual([]);
  }, 60_000);
});

describe('Tree §3.5, §5.3: neither function throws', () => {
  const r3 = () => rootOf(3);
  const r7 = () => rootOf(7);
  const honest = () => proofOf(treeOf(7), 3);

  it.each<[string, () => unknown[], ConsistencyProofReason]>([
    ['a non-integer first size', () => [2.5, 7, honest(), r3(), r7()], 'malformed_size'],
    ['a string size', () => ['3', 7, honest(), r3(), r7()], 'malformed_size'],
    ['a NaN size', () => [3, NaN, honest(), r3(), r7()], 'malformed_size'],
    ['an infinite size', () => [3, Infinity, honest(), r3(), r7()], 'malformed_size'],
    ['a size beyond 2^53', () => [3, 2 ** 53 + 2, honest(), r3(), r7()], 'malformed_size'],
    ['a negative size', () => [-1, 7, honest(), r3(), r7()], 'size_out_of_range'],
    ['first = 0', () => [0, 7, [], r3(), r7()], 'size_out_of_range'],
    ['first = second = 0', () => [0, 0, [], r3(), r3()], 'size_out_of_range'],
    ['first > second', () => [7, 3, honest(), r7(), r3()], 'size_out_of_range'],
    ['a non-string root', () => [3, 7, honest(), 42, r7()], 'malformed_root'],
    ['a short root', () => [3, 7, honest(), r3(), r7().slice(2)], 'malformed_root'],
    ['a non-hex root', () => [3, 7, honest(), 'zz'.repeat(32), r7()], 'malformed_root'],
    ['a null proof', () => [3, 7, null, r3(), r7()], 'malformed_proof'],
    ['a string proof', () => [3, 7, 'nope', r3(), r7()], 'malformed_proof'],
    ['a non-string proof element', () => [3, 7, [7], r3(), r7()], 'malformed_proof'],
    ['a legacy "position:hash" element', () => [3, 7, [`left:${honest()[0]}`], r3(), r7()], 'malformed_proof'],
    ['a non-hex proof element', () => [3, 7, ['zz'.repeat(32)], r3(), r7()], 'malformed_proof'],
  ])('the verifier returns a reason for %s', (_name, args, reason) => {
    const call = () => (verifyConsistencyProof as (...a: unknown[]) => unknown)(...args());
    expect(call).not.toThrow();
    expect(call()).toEqual({ valid: false, reason });
  });

  it('the verifier does its size arithmetic past 2^32 without wrapping', () => {
    // The honest 1→2 proof, claimed for a log of 2^32 + 2 leaves. Under 32-bit
    // operators that size wraps to 2 and the proof would verify.
    const proof = proofOf(treeOf(2), 1);
    expect(verifyConsistencyProof(1, 2, proof, rootOf(1), rootOf(2)).valid).toBe(true);
    expect(verifyConsistencyProof(1, 2 ** 32 + 2, proof, rootOf(1), rootOf(2))).toEqual({
      valid: false,
      reason: 'proof_length_mismatch',
    });
  });

  it.each<[string, () => [unknown, unknown, unknown?], ConsistencyProofReason]>([
    ['a null tree', () => [null, 1], 'malformed_tree'],
    ['a tree without layers', () => [{ leafCount: 3 }, 1], 'malformed_tree'],
    ['a tree whose leafCount disagrees with its leaves', () => [{ ...treeOf(7), leafCount: 9 }, 3], 'malformed_tree'],
    ['a tree with a missing layer', () => [{ ...treeOf(7), layers: treeOf(7).layers.slice(0, -1) }, 3], 'malformed_tree'],
    [
      'a tree with a non-hex node',
      () => [{ leafCount: 7, layers: treeOf(7).layers.map((l, i) => (i === 1 ? l.map(() => 'zz') : l)) }, 3],
      'malformed_tree',
    ],
    [
      'a tree with a non-string node',
      () => [{ leafCount: 7, layers: treeOf(7).layers.map((l, i) => (i === 0 ? l.map(() => 7) : l)) }, 3],
      'malformed_tree',
    ],
    ['a first size of 0', () => [treeOf(7), 0], 'size_out_of_range'],
    ['a first size above the second', () => [treeOf(7), 5, 4], 'size_out_of_range'],
    ['a second size beyond the tree', () => [treeOf(7), 3, 8], 'size_out_of_range'],
    ['a fractional size', () => [treeOf(7), 1.5], 'malformed_size'],
    ['a string size', () => [treeOf(7), '3'], 'malformed_size'],
  ])('the generator returns a reason for %s', (_name, args, reason) => {
    const call = () => (getConsistencyProof as (...a: unknown[]) => unknown)(...args());
    expect(call).not.toThrow();
    expect(call()).toEqual({ ok: false, reason });
  });
});

// ---- Size binding (Tree §3.6) ----------------------------------------------
//
// The step pattern of a proof is a function of the sizes alone. These two
// oracles transcribe the RFC recursions (PATH and SUBPROOF) over sizes, with no
// hashing: 'R' is a sibling to the right, 'L' a sibling to the left, 'T' the
// terminal subtree SUBPROOF emits when b is false.

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
function pathSteps(m: number, n: number): string {
  if (n === 1) return '';
  const k = split(n);
  return m < k ? pathSteps(m, k) + 'R' : pathSteps(m - k, n - k) + 'L';
}
function subproofSteps(m: number, n: number, b: boolean): string {
  if (m === n) return b ? '' : 'T';
  const k = split(n);
  return m <= k ? subproofSteps(m, k, b) + 'R' : subproofSteps(m - k, n - k, false) + 'L';
}

describe('every verifier binds to the size it is given, wherever RFC 6962 math can tell (Tree §3.6)', () => {
  it('an inclusion proof fails under every wrong tree size whose step pattern differs, and only those', () => {
    const disagreements: string[] = [];
    let malleable = 0;
    let proofs = 0;
    const alwaysDetected: string[] = [];
    for (let n = 1; n <= 64; n++) {
      const tree = treeOf(n);
      for (let m = 0; m < n; m++) {
        proofs++;
        const path = getMerkleProof(tree, m);
        let acceptedElsewhere = false;
        for (let s = 1; s <= 64; s++) {
          if (s === n) continue;
          const accepted = verifyMerkleProof(LEAVES[m], m, s, path, rootOf(n));
          const undetectable = m < s && pathSteps(m, s) === pathSteps(m, n);
          if (accepted !== undetectable) disagreements.push(`leaf ${m} of ${n} claimed as ${s}`);
          if (accepted) acceptedElsewhere = true;
        }
        if (acceptedElsewhere) malleable++;
        else alwaysDetected.push(`${m}/${n}`);
      }
    }
    expect(disagreements).toEqual([]);
    // The census the vectors file records, reproduced by the shipped verifier.
    expect({ proofs, malleable }).toEqual({
      proofs: V.sizeMalleability.census.inclusion.proofs,
      malleable: V.sizeMalleability.census.inclusion.verifyUnderAnotherTreeSize,
    });
    expect({ proofs, malleable }).toEqual({ proofs: 2080, malleable: 1984 });
    // Every wrong size is caught only for the last leaf, and for the
    // second-to-last leaf of an even-sized tree (its sibling is the last leaf).
    const expected: string[] = [];
    for (let n = 1; n <= 64; n++) {
      for (let m = 0; m < n; m++) if (m === n - 1 || (n % 2 === 0 && m === n - 2)) expected.push(`${m}/${n}`);
    }
    expect(alwaysDetected).toEqual(expected);
  }, 60_000);

  it('a consistency proof fails under every wrong second size whose step pattern differs, and only those', () => {
    const disagreements: string[] = [];
    let malleable = 0;
    let proofs = 0;
    const alwaysDetected: string[] = [];
    for (let n = 1; n <= 64; n++) {
      for (let m = 1; m <= n; m++) {
        const proof = proofOf(treeOf(n), m);
        let acceptedElsewhere = false;
        for (let s = 1; s <= 64; s++) {
          if (s === n) continue;
          const accepted = verifyConsistencyProof(m, s, proof, rootOf(m), rootOf(n)).valid;
          const undetectable = m <= s && subproofSteps(m, s, true) === subproofSteps(m, n, true);
          if (accepted !== undetectable) disagreements.push(`${m}→${n} claimed as ${m}→${s}`);
          if (accepted) acceptedElsewhere = true;
        }
        if (m < n) {
          proofs++;
          if (acceptedElsewhere) malleable++;
          else alwaysDetected.push(`${m}/${n}`);
        } else {
          // Equal sizes carry the empty proof, which no other second size accepts.
          expect(acceptedElsewhere).toBe(false);
        }
      }
    }
    expect(disagreements).toEqual([]);
    expect({ proofs, malleable }).toEqual({
      proofs: V.sizeMalleability.census.consistency.proofs,
      malleable: V.sizeMalleability.census.consistency.verifyUnderAnotherSecondSize,
    });
    expect({ proofs, malleable }).toEqual({ proofs: 2016, malleable: 1984 });
    // Every wrong second size is caught only when an odd-sized log grew by one leaf.
    const expected: string[] = [];
    for (let n = 2; n <= 64; n++) for (let m = 1; m < n; m++) if (m % 2 === 1 && n === m + 1) expected.push(`${m}/${n}`);
    expect(alwaysDetected).toEqual(expected);
  }, 60_000);

  it('a consistency proof fails under every wrong first size (both roots unchanged)', () => {
    const sameSteps: string[] = [];
    const accepted: string[] = [];
    for (let n = 1; n <= 64; n++) {
      for (let m = 1; m <= n; m++) {
        const proof = proofOf(treeOf(n), m);
        for (let f = 1; f <= 64; f++) {
          if (f === m) continue;
          if (f <= n && subproofSteps(f, n, true) === subproofSteps(m, n, true)) sameSteps.push(`${m}/${f}/${n}`);
          if (verifyConsistencyProof(f, n, proof, rootOf(m), rootOf(n)).valid) accepted.push(`${m}→${n} as ${f}→${n}`);
        }
      }
    }
    // No two first sizes share a step pattern, so the math can always tell.
    expect(sameSteps).toEqual([]);
    expect(accepted).toEqual([]);
    expect(V.sizeMalleability.census.consistency.verifyUnderAnotherFirstSize).toBe(0);
  }, 60_000);
});
