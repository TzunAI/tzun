/**
 * CompactRangeProver: one inclusion proof and one consistency proof from a
 * compact range and the leaves after it, fed in pages (Tree §3.5, §5.5;
 * Bundle §7.3). Every output must equal a recomputation over the whole
 * log, for every starting size, leaf and size up to 40 leaves, however the
 * leaves are paged.
 */
import { createHash } from 'crypto';

import {
  buildMerkleTree,
  compactRangeOf,
  CompactRangeProver,
  extendCompactRange,
  getConsistencyProof,
  getMerkleProof,
  getMerkleRoot,
} from './merkle';
import type { MerkleTree } from './merkle';

const LEAVES = Array.from({ length: 64 }, (_, i) =>
  createHash('sha256').update(`tzun-merkle-vector-${i}`, 'utf8').digest('hex'),
);
const N = 40;

const trees = new Map<number, MerkleTree>();
const treeOf = (n: number): MerkleTree => {
  let t = trees.get(n);
  if (!t) {
    t = buildMerkleTree(LEAVES.slice(0, n));
    trees.set(n, t);
  }
  return t;
};

const proofs = new Map<string, string>();
/** getMerkleProof, as JSON, computed once per (j, n). */
function inclusion(j: number, n: number): string {
  const key = `i${j}:${n}`;
  let p = proofs.get(key);
  if (p === undefined) {
    p = JSON.stringify(getMerkleProof(treeOf(n), j));
    proofs.set(key, p);
  }
  return p;
}
/** getConsistencyProof, as JSON, computed once per (m, n). */
function consistency(m: number, n: number): string {
  const key = `c${m}:${n}`;
  let p = proofs.get(key);
  if (p === undefined) {
    const r = getConsistencyProof(treeOf(n), m, n);
    if (!r.ok) throw new Error(r.reason);
    p = JSON.stringify(r.proof);
    proofs.set(key, p);
  }
  return p;
}

/** The prover from the range of `start` leaves to `n`, fed `page` leaves at a time. */
function prove(start: number, n: number, want: { leafIndex?: number; fromSize?: number }, page = n) {
  const prover = new CompactRangeProver(compactRangeOf(LEAVES.slice(0, start)), n, want);
  for (let at = start; at < n; at += page) {
    if (prover.next !== at) throw new Error(`next is ${prover.next}, not ${at}`);
    prover.append(LEAVES.slice(at, Math.min(at + page, n)));
  }
  return prover.finish();
}

describe('CompactRangeProver: equal to a full recomputation', () => {
  it(`gives every leaf's inclusion proof and every size's consistency proof, from every starting size, for n ≤ ${N}`, () => {
    const failures: string[] = [];
    let runs = 0;
    for (let n = 1; n <= N; n++) {
      const root = getMerkleRoot(treeOf(n));
      const range = compactRangeOf(LEAVES.slice(0, n));
      for (let start = 0; start <= n; start++) {
        for (let j = start; j < n; j++) {
          runs++;
          const out = prove(start, n, { leafIndex: j });
          if (out.root !== root || JSON.stringify(out.range) !== JSON.stringify(range)) failures.push(`root/range start=${start} n=${n}`);
          if (JSON.stringify(out.inclusionProof) !== inclusion(j, n) || out.consistencyProof !== null) {
            failures.push(`inclusion start=${start} j=${j} n=${n}`);
          }
        }
        for (let m = Math.max(start, 1); m <= n; m++) {
          runs++;
          const out = prove(start, n, { fromSize: m });
          if (out.root !== root) failures.push(`root start=${start} m=${m} n=${n}`);
          if (JSON.stringify(out.consistencyProof) !== consistency(m, n) || out.inclusionProof !== null) {
            failures.push(`consistency start=${start} m=${m} n=${n}`);
          }
        }
      }
    }
    expect(failures).toEqual([]);
    expect(runs).toBeGreaterThan(20_000);
  });

  it('gives both proofs from one pass, however the leaves are paged', () => {
    const failures: string[] = [];
    for (const n of [1, 2, 3, 7, 8, 9, 13, 16, 17, 31, 33]) {
      for (let start = 0; start <= n; start++) {
        for (let j = start; j < n; j++) {
          for (const m of [...new Set([Math.max(start, 1), j + 1, n])]) {
            for (const page of [1, 3, 1024]) {
              const out = prove(start, n, { leafIndex: j, fromSize: m }, page);
              if (JSON.stringify(out.inclusionProof) !== inclusion(j, n) || JSON.stringify(out.consistencyProof) !== consistency(m, n)) {
                failures.push(`start=${start} j=${j} m=${m} n=${n} page=${page}`);
              }
            }
          }
        }
      }
    }
    expect(failures).toEqual([]);
  });

  it('agrees with extendCompactRange, which holds every appended leaf\'s proof', () => {
    const ext = extendCompactRange(compactRangeOf(LEAVES.slice(0, 5)), LEAVES.slice(5, 64));
    for (let j = 5; j < 64; j++) {
      const out = prove(5, 64, { leafIndex: j, fromSize: 5 }, 7);
      expect(out.inclusionProof).toEqual(ext.inclusionProofs[j - 5]);
      expect(out.consistencyProof).toEqual(ext.consistencyProof);
      expect(out.range).toEqual(ext.range);
      expect(out.root).toBe(ext.root);
    }
  });

  it('gives the root and range alone when no proof is asked for, and nothing appended from a non-empty range', () => {
    expect(prove(0, 13, {}, 4)).toEqual({ range: compactRangeOf(LEAVES.slice(0, 13)), root: getMerkleRoot(treeOf(13)), inclusionProof: null, consistencyProof: null });
    expect(prove(13, 13, { fromSize: 13 })).toEqual({ range: compactRangeOf(LEAVES.slice(0, 13)), root: getMerkleRoot(treeOf(13)), inclusionProof: null, consistencyProof: [] });
  });
});

describe('CompactRangeProver: refusals', () => {
  const range = compactRangeOf(LEAVES.slice(0, 4));

  it('refuses a size below the range, an empty log, and requests outside the log', () => {
    expect(() => new CompactRangeProver(range, 3)).toThrow(/at least 4/);
    expect(() => new CompactRangeProver(compactRangeOf([]), 0)).toThrow(/empty log/);
    expect(() => new CompactRangeProver(range, 8, { leafIndex: 3 })).toThrow(/leaf 3/);
    expect(() => new CompactRangeProver(range, 8, { leafIndex: 8 })).toThrow(/leaf 8/);
    expect(() => new CompactRangeProver(range, 8, { fromSize: 3 })).toThrow(/size 3/);
    expect(() => new CompactRangeProver(range, 8, { fromSize: 9 })).toThrow(/size 9/);
    expect(() => new CompactRangeProver(compactRangeOf([]), 8, { fromSize: 0 })).toThrow(/size 0/);
    expect(() => new CompactRangeProver({ size: 4, hashes: [] }, 8)).toThrow(/Malformed compact range/);
  });

  it('refuses a digest that is not hex, more leaves than the log has, and finishing early', () => {
    const prover = new CompactRangeProver(range, 6, { leafIndex: 5 });
    expect(() => prover.append(['zz'])).toThrow(/entry 0/);
    expect(() => prover.append(LEAVES.slice(4, 7))).toThrow(/the log has 6/);
    prover.append(LEAVES.slice(4, 5));
    expect(() => prover.finish()).toThrow(/5 of the log's 6/);
    prover.append(LEAVES.slice(5, 6));
    expect(prover.finish().inclusionProof).toEqual(getMerkleProof(treeOf(6), 5));
  });

  it('holds O(log n) state: 2^18 leaves in pages keep no per-leaf proof', () => {
    const n = 1 << 18;
    const digest = (i: number) => createHash('sha256').update(String(i)).digest('hex');
    const prover = new CompactRangeProver(compactRangeOf([digest(0)]), n, { leafIndex: 1, fromSize: 1 });
    const internals = prover as unknown as { stack: unknown[]; found: Map<string, string> };
    for (let at = 1; at < n; at += 4096) {
      const page: string[] = [];
      for (let i = at; i < Math.min(at + 4096, n); i++) page.push(digest(i));
      prover.append(page);
      expect(internals.stack.length).toBeLessThanOrEqual(19);
      expect(internals.found.size).toBeLessThanOrEqual(36);
    }
    const out = prover.finish();
    expect(out.inclusionProof).toHaveLength(18);
    expect(out.consistencyProof).toHaveLength(18);
  });
});
