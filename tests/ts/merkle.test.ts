/**
 * Behavioural properties of the Merkle primitive.
 *
 * The known-answer coverage — roots, leaf hashes and audit paths for tree
 * sizes 1..9 and 16 — lives in tests/ts/merkle-rfc6962-conformance.test.ts,
 * driven by vectors/merkle-rfc6962-vectors.json. This file deliberately does
 * NOT restate those. It pins the properties that a vector cannot express: that
 * domain separation actually separates, that the construction is deterministic,
 * that hostile shapes are refused, and that the odd-layer rule is promotion.
 *
 * Written for the RFC 6962 construction (Tree §3; the odd-layer rule is
 * Tree §3.2). Duplicating an odd trailing leaf is the CVE-2012-2459 shape,
 * so the odd-layer test below asserts promotion and that no leaf repeats.
 */
import {
  buildMerkleTree,
  getMerkleRoot,
  getMerkleProof,
  verifyMerkleProof,
  merkleLeafHash,
} from '../../src/attestation/merkle';
import { createHash } from 'crypto';

const sha256 = (data: string): string => createHash('sha256').update(data, 'utf8').digest('hex');

describe('Merkle Tree', () => {
  const digests = [
    sha256('record-1'),
    sha256('record-2'),
    sha256('record-3'),
    sha256('record-4'),
    sha256('record-5'),
    sha256('record-6'),
    sha256('record-7'),
  ];

  describe('buildMerkleTree', () => {
    it('throws on empty input', () => {
      expect(() => buildMerkleTree([])).toThrow('at least one digest');
    });

    it('returns a single-element tree for one digest', () => {
      const tree = buildMerkleTree([digests[0]]);
      expect(tree.leafCount).toBe(1);
      expect(tree.layers).toHaveLength(1);
      expect(getMerkleRoot(tree)).toBe(merkleLeafHash(digests[0]));
    });

    it('produces a deterministic root for the same inputs', () => {
      expect(getMerkleRoot(buildMerkleTree(digests))).toBe(getMerkleRoot(buildMerkleTree(digests)));
    });

    it('produces a different root when inputs change', () => {
      const other = [...digests.slice(0, 6), sha256('record-8')];
      expect(getMerkleRoot(buildMerkleTree(digests))).not.toBe(getMerkleRoot(buildMerkleTree(other)));
    });

    it('produces a different root when only the ORDER changes', () => {
      // Leaf order is load-bearing and the list is never sorted (Tree §3.1).
      const swapped = [digests[1], digests[0], ...digests.slice(2)];
      expect(getMerkleRoot(buildMerkleTree(digests))).not.toBe(getMerkleRoot(buildMerkleTree(swapped)));
    });

    // Duplicating the trailing leaf would make root([a,b,c]) === root([a,b,c,c]).
    it('promotes an odd trailing node instead of duplicating it', () => {
      const tree = buildMerkleTree(digests.slice(0, 3));
      // Promotion: the 3-leaf layer reduces to 2 (one pair + the promoted
      // trailing leaf), and the promoted node appears unchanged one layer up.
      expect(tree.layers[0]).toHaveLength(3);
      expect(tree.layers[1]).toHaveLength(2);
      expect(tree.layers[1][1]).toBe(tree.layers[0][2]);
      // Duplication would produce a 4-wide leaf layer with a repeated tail.
      expect(tree.layers[0][2]).not.toBe(tree.layers[0][1]);
    });

    it('refuses a repeated digest, which would make the root ambiguous', () => {
      expect(() => buildMerkleTree([digests[0], digests[1], digests[0]])).toThrow(/duplicate/i);
    });

    it('refuses input that is not a 64-character hex digest', () => {
      expect(() => buildMerkleTree(['not-hex'])).toThrow(/hex digest/i);
      expect(() => buildMerkleTree([digests[0].slice(0, 63)])).toThrow(/hex digest/i);
    });
  });

  describe('merkleLeafHash', () => {
    it('hashes the digest\'s RAW bytes, not its hex characters', () => {
      // Hashing the raw bytes is what lets a stock Certificate Transparency
      // verifier reproduce a Tzun root. Hashing the 64 ASCII characters yields
      // a different value, and this asserts the leaf hash is not that one.
      const raw = createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(digests[0], 'hex')]))
        .digest('hex');
      const asAscii = createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(digests[0], 'utf8')]))
        .digest('hex');

      expect(merkleLeafHash(digests[0])).toBe(raw);
      expect(merkleLeafHash(digests[0])).not.toBe(asAscii);
    });

    it('is case-insensitive about the input hex', () => {
      expect(merkleLeafHash(digests[0].toUpperCase())).toBe(merkleLeafHash(digests[0]));
    });
  });

  describe('getMerkleProof', () => {
    it('returns an empty proof for a single-element tree', () => {
      expect(getMerkleProof(buildMerkleTree([digests[0]]), 0)).toEqual([]);
    });

    it('returns log2(n) steps for a balanced tree', () => {
      const tree = buildMerkleTree(digests.slice(0, 4));
      expect(getMerkleProof(tree, 0)).toHaveLength(2);
    });

    it('returns bare hex with no position label', () => {
      // No label, on purpose: the side of each step is derived from
      // (leafIndex, treeSize) at verification, which is what makes the proof
      // checkable by a verifier we did not write.
      for (const step of getMerkleProof(buildMerkleTree(digests.slice(0, 4)), 1)) {
        expect(step).toMatch(/^[0-9a-f]{64}$/);
      }
    });

    it('throws for an out-of-bounds leaf index', () => {
      const tree = buildMerkleTree(digests.slice(0, 4));
      expect(() => getMerkleProof(tree, 4)).toThrow('out of bounds');
      expect(() => getMerkleProof(tree, -1)).toThrow('out of bounds');
    });
  });

  describe('verifyMerkleProof', () => {
    const tree = buildMerkleTree(digests.slice(0, 4));
    const root = getMerkleRoot(tree);

    it('verifies a valid proof for the first leaf', () => {
      expect(verifyMerkleProof(digests[0], 0, 4, getMerkleProof(tree, 0), root)).toBe(true);
    });

    it('verifies a valid proof for the last leaf', () => {
      expect(verifyMerkleProof(digests[3], 3, 4, getMerkleProof(tree, 3), root)).toBe(true);
    });

    it('rejects a proof with a wrong leaf', () => {
      expect(verifyMerkleProof(digests[1], 0, 4, getMerkleProof(tree, 0), root)).toBe(false);
    });

    it('rejects a proof with a wrong root', () => {
      const otherRoot = getMerkleRoot(buildMerkleTree(digests.slice(2, 6)));
      expect(verifyMerkleProof(digests[0], 0, 4, getMerkleProof(tree, 0), otherRoot)).toBe(false);
    });

    it('rejects a valid proof presented at the wrong leaf index', () => {
      // The side of each step is derived from the leaf index rather than
      // carried as data, so a proof is bound to a position and cannot be
      // replayed at another.
      expect(verifyMerkleProof(digests[0], 1, 4, getMerkleProof(tree, 0), root)).toBe(false);
    });

    it('rejects a valid proof presented against the wrong tree size', () => {
      expect(verifyMerkleProof(digests[0], 0, 8, getMerkleProof(tree, 0), root)).toBe(false);
    });

    it('round-trips every leaf position, across odd and even layer widths', () => {
      const seven = buildMerkleTree(digests);
      const sevenRoot = getMerkleRoot(seven);
      for (let i = 0; i < digests.length; i++) {
        expect(verifyMerkleProof(digests[i], i, digests.length, getMerkleProof(seven, i), sevenRoot)).toBe(true);
      }
    });
  });

  describe('domain separation (RFC 6962)', () => {
    it('a single-leaf root is the LEAF HASH, never the raw digest', () => {
      const root = getMerkleRoot(buildMerkleTree([digests[0]]));
      expect(root).not.toBe(digests[0]);
      expect(root).toBe(merkleLeafHash(digests[0]));
    });

    it('defeats the second-preimage attack: an internal node cannot pose as a leaf', () => {
      // The 0x00/0x01 prefixes exist for this. An attacker who knows an
      // internal node's hash tries to present it as a leaf with an empty
      // proof; because verification re-applies the 0x00 leaf prefix, the value
      // it folds to can never equal the 0x01-prefixed node the tree built.
      const tree = buildMerkleTree(digests.slice(0, 4));
      const root = getMerkleRoot(tree);
      const internalNode = tree.layers[1][0];
      expect(verifyMerkleProof(internalNode, 0, 1, [], root)).toBe(false);
      expect(verifyMerkleProof(internalNode, 0, 4, [], root)).toBe(false);
    });
  });
});
