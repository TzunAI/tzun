/**
 * The Merkle module lives in `@tzun/engine`, and `src/attestation/merkle`
 * re-exports it.
 *
 * These imports resolve `@tzun/engine` through the workspace link to the
 * engine's built entry point, which is what a consumer of the published
 * package imports. A consumer that reaches this module through the SDK's
 * build output (`dist/src/attestation/merkle`) gets the same members,
 * re-exported from the engine.
 */
import * as fs from 'fs';
import * as path from 'path';

import * as engine from '@tzun/engine';
import {
  MERKLE_SPEC,
  buildMerkleTree,
  getConsistencyProof,
  getMerkleProof,
  getMerkleRoot,
  merkleLeafHash,
  verifyConsistencyProof,
  verifyMerkleProof,
} from '@tzun/engine';
import * as sdkMerkle from '../../src/attestation/merkle';
import * as attestation from '../../src/attestation';

const SURFACE = [
  'CompactRangeProver',
  'MERKLE_SPEC',
  'buildMerkleTree',
  'compactRangeOf',
  'compactRangeRoot',
  'extendCompactRange',
  'getConsistencyProof',
  'getMerkleProof',
  'getMerkleRoot',
  'merkleLeafHash',
  'verifyConsistencyProof',
  'verifyMerkleProof',
] as const;

const read = (file: string) =>
  JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'vectors', file), 'utf-8'));

describe('the engine entry point carries the Merkle surface', () => {
  it.each(SURFACE)('exports %s', (name) => {
    expect((engine as Record<string, unknown>)[name]).toBeDefined();
  });

  it('src/attestation/merkle re-exports the engine members themselves, not copies', () => {
    expect(Object.keys(sdkMerkle).sort()).toEqual([...SURFACE].sort());
    for (const name of SURFACE) {
      expect((sdkMerkle as Record<string, unknown>)[name]).toBe((engine as Record<string, unknown>)[name]);
    }
  });

  it('the attestation barrel hands out the engine\'s inclusion functions', () => {
    expect(attestation.buildMerkleTree).toBe(engine.buildMerkleTree);
    expect(attestation.verifyMerkleProof).toBe(engine.verifyMerkleProof);
    expect(attestation.MERKLE_SPEC).toBe('rfc6962');
  });
});

describe('through the engine entry point, inclusion proofs reproduce the frozen vectors', () => {
  const inclusion = read('merkle-rfc6962-vectors.json') as {
    trees: Array<{
      treeSize: number;
      leafDigests: string[];
      root: string;
      leafHashes: string[];
      proofs: Array<{ leafIndex: number; leafDigest: string; auditPath: string[] }>;
    }>;
  };

  it.each(inclusion.trees.map((t) => [t.treeSize, t] as const))(
    'the frozen %i-leaf vector reproduces byte for byte',
    (_n, t) => {
      const tree = buildMerkleTree(t.leafDigests);
      expect(getMerkleRoot(tree)).toBe(t.root);
      t.leafDigests.forEach((d, i) => expect(merkleLeafHash(d)).toBe(t.leafHashes[i]));
      for (const p of t.proofs) {
        expect(getMerkleProof(tree, p.leafIndex)).toEqual(p.auditPath);
        expect(verifyMerkleProof(p.leafDigest, p.leafIndex, t.treeSize, p.auditPath, t.root)).toBe(true);
      }
    },
  );

  it('and the consistency vectors pass through it too', () => {
    const consistency = read('merkle-consistency-vectors.json') as {
      leafDigests: string[];
      valid: Array<{ first: number; second: number; firstRoot: string; secondRoot: string; proof: string[] }>;
    };
    const full = buildMerkleTree(consistency.leafDigests);
    for (const c of consistency.valid) {
      expect(getConsistencyProof(full, c.first, c.second)).toEqual({ ok: true, proof: c.proof });
      expect(verifyConsistencyProof(c.first, c.second, c.proof, c.firstRoot, c.secondRoot).valid).toBe(true);
    }
    expect(MERKLE_SPEC).toBe('rfc6962');
  });
});
