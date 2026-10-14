/**
 * RFC 6962 Merkle trees: inclusion proofs, consistency proofs and compact
 * ranges. The module lives in `@tzun/engine` (packages/engine/src/merkle.ts),
 * because the status rules that consume Merkle facts are engine code; this
 * path re-exports it for the SDK's own call sites.
 */
export {
  MERKLE_SPEC,
  merkleLeafHash,
  buildMerkleTree,
  getMerkleRoot,
  getMerkleProof,
  verifyMerkleProof,
  getConsistencyProof,
  verifyConsistencyProof,
  compactRangeOf,
  compactRangeRoot,
  extendCompactRange,
  CompactRangeProver,
} from '@tzun/engine';
export type {
  MerkleTree,
  ConsistencyProofReason,
  ConsistencyProofResult,
  ConsistencyVerification,
  CompactRange,
  CompactRangeExtension,
  CompactRangeProofs,
} from '@tzun/engine';
