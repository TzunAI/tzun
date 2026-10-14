/**
 * Conformance to the tree profile (Tree §9).
 *
 * These assertions are driven entirely by vectors/merkle-rfc6962-vectors.json,
 * which is an INDEPENDENT pin: it is produced by a recursive transcription of
 * RFC 6962 (scripts/generate-merkle-vectors.mjs), while the implementation
 * under test is iterative and level-by-level. Regenerating the vectors from
 * the implementation would defeat the entire purpose and is forbidden by the
 * vectors file's own `source` field.
 *
 * Two properties carry most of the weight:
 *   - leaves hash the 32 raw digest bytes, not the 64 ASCII hex characters, so
 *     a stock CT verifier reproduces a Tzun root at every n;
 *   - an odd trailing node is promoted, not duplicated, so root([a,b,c]) and
 *     root([a,b,c,c]) differ and an audit path for a phantom 4th leaf does not
 *     verify against a 3-leaf root.
 */
import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';

import {
  buildMerkleTree,
  getMerkleRoot,
  getMerkleProof,
  verifyMerkleProof,
  merkleLeafHash,
  MERKLE_SPEC,
} from '../../src/attestation/merkle';

interface Proof {
  leafIndex: number;
  leafDigest: string;
  auditPath: string[];
}
interface Tree {
  treeSize: number;
  leafDigests: string[];
  root: string;
  leafHashes: string[];
  proofs: Proof[];
}
interface Vectors {
  emptyTreeRoot: { root: string };
  trees: Tree[];
  distinctnessVectors: Array<{
    name: string;
    a: { leafDigests: string[]; root: string };
    b: { leafDigests: string[]; root: string };
  }>;
}

const VECTORS: Vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'vectors', 'merkle-rfc6962-vectors.json'), 'utf-8')
);

describe('the spec tag is the literal the wire format requires', () => {
  it('is "rfc6962"', () => {
    expect(MERKLE_SPEC).toBe('rfc6962');
  });
});

describe('Tree §9 item 6 — the empty tree hash matches every CT implementation', () => {
  it('is SHA-256 of the empty string', () => {
    // Not produced by buildMerkleTree — an empty batch is never anchored — but
    // pinned because it independently confirms the hash and the encoding
    // before any Tzun-specific value is trusted.
    expect(VECTORS.emptyTreeRoot.root).toBe(createHash('sha256').update(Buffer.alloc(0)).digest('hex'));
  });
});

describe('Tree §9 items 1 and 2 — roots and leaf hashes match the vectors', () => {
  it.each(VECTORS.trees.map((t) => [t.treeSize, t] as const))(
    'a %i-leaf tree reproduces the pinned root and every leaf hash',
    (_size, tree) => {
      expect(getMerkleRoot(buildMerkleTree(tree.leafDigests))).toBe(tree.root);
      tree.leafDigests.forEach((d, i) => {
        expect(merkleLeafHash(d)).toBe(tree.leafHashes[i]);
      });
    }
  );
});

describe('Tree §9 items 3 and 4 — audit paths match, and verification accepts them', () => {
  it.each(VECTORS.trees.map((t) => [t.treeSize, t] as const))(
    'every leaf of a %i-leaf tree proves its own membership',
    (_size, tree) => {
      const built = buildMerkleTree(tree.leafDigests);
      for (const p of tree.proofs) {
        expect(getMerkleProof(built, p.leafIndex)).toEqual(p.auditPath);
        expect(verifyMerkleProof(p.leafDigest, p.leafIndex, tree.treeSize, p.auditPath, tree.root)).toBe(true);
      }
    }
  );

  it('an unbalanced tree gives its trailing leaf a shorter path than the rest', () => {
    // The visible signature of promotion. Under duplicate-last every path in a
    // tree is the same length, so this fails if the builder duplicates an odd
    // trailing node.
    const three = VECTORS.trees.find((t) => t.treeSize === 3)!;
    expect(three.proofs.map((p) => p.auditPath.length)).toEqual([2, 2, 1]);
  });
});

describe('Tree §9 item 4 — verification rejects anything altered', () => {
  const tree = VECTORS.trees.find((t) => t.treeSize === 5)!;
  const p = tree.proofs[2];
  const flipFirstNibble = (h: string) => (h[0] === '0' ? '1' : '0') + h.slice(1);

  it('rejects a altered leaf digest', () => {
    expect(verifyMerkleProof(flipFirstNibble(p.leafDigest), p.leafIndex, tree.treeSize, p.auditPath, tree.root)).toBe(false);
  });

  it('rejects an altered root', () => {
    expect(verifyMerkleProof(p.leafDigest, p.leafIndex, tree.treeSize, p.auditPath, flipFirstNibble(tree.root))).toBe(false);
  });

  it('rejects an altered path element', () => {
    const tampered = [...p.auditPath];
    tampered[0] = flipFirstNibble(tampered[0]);
    expect(verifyMerkleProof(p.leafDigest, p.leafIndex, tree.treeSize, tampered, tree.root)).toBe(false);
  });

  it('rejects a truncated path even when the remainder folds cleanly', () => {
    // The `sn === 0` terminal check in Tree §3.4 exists for exactly this.
    expect(verifyMerkleProof(p.leafDigest, p.leafIndex, tree.treeSize, p.auditPath.slice(0, -1), tree.root)).toBe(false);
  });

  it('rejects a leafIndex outside the tree', () => {
    expect(verifyMerkleProof(p.leafDigest, tree.treeSize, tree.treeSize, p.auditPath, tree.root)).toBe(false);
  });

  it('rejects a proof replayed against a different position', () => {
    const other = p.leafIndex === 0 ? 1 : 0;
    expect(verifyMerkleProof(p.leafDigest, other, tree.treeSize, p.auditPath, tree.root)).toBe(false);
  });
});

describe('Tree §9 item 5 — the duplicate-leaf ambiguity is closed in the hash', () => {
  // The two halves are checked at different levels on purpose (Tree §9 item
  // 5). Root distinctness belongs to MTH and is pinned by the vectors; refusing
  // to BUILD such a batch belongs to buildMerkleTree (Tree §5.4 item 1). An
  // implementation must not grow a bypass that builds a tree over repeated
  // leaves just to satisfy this.
  it.each(VECTORS.distinctnessVectors.map((d) => [d.name, d] as const))(
    'the hash rule separates them: %s',
    (_name, d) => {
      expect(getMerkleRoot(buildMerkleTree(d.a.leafDigests))).toBe(d.a.root);
      // Under duplicate-last these two roots would be byte-identical.
      expect(d.a.root).not.toBe(d.b.root);
    }
  );

  it.each(VECTORS.distinctnessVectors.map((d) => [d.name, d] as const))(
    'and the builder refuses the repeated-leaf batch outright: %s',
    (_name, d) => {
      expect(() => buildMerkleTree(d.b.leafDigests)).toThrow(/duplicate/i);
    }
  );

  it('refuses to build a tree over a repeated digest at all', () => {
    // Tree §5.4 item 1. Evidence digests are unique by construction, so this
    // refuses nothing honest — it removes the reader's ambiguity at the source.
    const d = VECTORS.trees[0].leafDigests[0];
    expect(() => buildMerkleTree([d, d])).toThrow(/duplicate/i);
  });
});

describe('Tree §5.4 items 2 and 3 — batch-formation limits', () => {
  it('refuses an empty batch', () => {
    expect(() => buildMerkleTree([])).toThrow(/at least one digest/i);
  });

  it('gives a single-leaf tree an empty path, and says so by construction', () => {
    const one = VECTORS.trees.find((t) => t.treeSize === 1)!;
    const built = buildMerkleTree(one.leafDigests);
    expect(getMerkleProof(built, 0)).toEqual([]);
    expect(getMerkleRoot(built)).toBe(merkleLeafHash(one.leafDigests[0]));
    // …and therefore proves nothing beyond itself: the empty path is satisfied
    // by whatever digest the root was built from. Callers must not present a
    // treeSize-1 proof as evidence of batching (Tree §5.4 item 3, §6).
    expect(verifyMerkleProof(one.leafDigests[0], 0, 1, [], getMerkleRoot(built))).toBe(true);
  });
});

describe('the verifier never throws on untrusted input', () => {
  const tree = VECTORS.trees.find((t) => t.treeSize === 4)!;
  const p = tree.proofs[0];

  it.each([
    ['a non-string leaf', 123 as unknown as string, p.auditPath],
    ['a non-array path', p.leafDigest, 'nope' as unknown as string[]],
    ['a non-string path element', p.leafDigest, [7] as unknown as string[]],
    ['a legacy "position:hash" element', p.leafDigest, [`left:${p.auditPath[0]}`]],
    ['a non-hex path element', p.leafDigest, ['zz'.repeat(32)]],
  ])('returns false for %s rather than throwing', (_name, leaf, proof) => {
    expect(() => verifyMerkleProof(leaf, p.leafIndex, tree.treeSize, proof, tree.root)).not.toThrow();
    expect(verifyMerkleProof(leaf, p.leafIndex, tree.treeSize, proof, tree.root)).toBe(false);
  });
});
