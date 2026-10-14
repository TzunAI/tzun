/**
 * The engine's entry point exports the Merkle surface, so a
 * consumer imports it from `@tzun/engine` instead of a path inside the SDK's
 * build output.
 *
 * The type imports are part of the test: ts-jest type-checks this file, so a
 * type dropped from the index fails the suite at compile time.
 */
import {
  MERKLE_SPEC,
  CompactRangeProver,
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
} from './index';
import type {
  CompactRange,
  CompactRangeExtension,
  CompactRangeProofs,
  ConsistencyProofReason,
  ConsistencyProofResult,
  ConsistencyVerification,
  MerkleTree,
} from './index';
import * as merkle from './merkle';

describe('the Merkle surface on the engine entry point', () => {
  it('exports every runtime member of the module, and nothing else of it is missing', () => {
    const fromIndex: Record<string, unknown> = {
      MERKLE_SPEC,
      CompactRangeProver,
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
    };
    expect(Object.keys(merkle).sort()).toEqual(Object.keys(fromIndex).sort());
    for (const [name, value] of Object.entries(fromIndex)) {
      expect(value).toBe((merkle as Record<string, unknown>)[name]);
    }
    expect(MERKLE_SPEC).toBe('rfc6962');
  });

  it('names the types a verifier and a log writer need', () => {
    const d = 'a'.repeat(64);
    const tree: MerkleTree = buildMerkleTree([d]);
    const range: CompactRange = compactRangeOf([d]);
    const ext: CompactRangeExtension = extendCompactRange(range, ['b'.repeat(64)]);
    const generated: ConsistencyProofResult = getConsistencyProof(tree, 1);
    const verdict: ConsistencyVerification = verifyConsistencyProof(1, 2, ext.consistencyProof ?? [], getMerkleRoot(tree), ext.root);
    const reason: ConsistencyProofReason | null = verdict.reason;
    const prover = new CompactRangeProver(range, 2, { leafIndex: 1, fromSize: 1 });
    prover.append(['b'.repeat(64)]);
    const proofs: CompactRangeProofs = prover.finish();
    expect(proofs).toEqual({ range: ext.range, root: ext.root, inclusionProof: ext.inclusionProofs[0], consistencyProof: ext.consistencyProof });
    expect(generated).toEqual({ ok: true, proof: [] });
    expect(verdict).toEqual({ valid: true, reason: null });
    expect(reason).toBeNull();
  });
});
