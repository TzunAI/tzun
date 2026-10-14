/**
 * The anchoring verification surface is importable from the package entry
 * (Anchor §4, §10.3, §10.4, §10.6), so a holder
 * of an envelope or an export bundle needs no deep import into `dist/`.
 */
import {
  verifyAnchor,
  ANCHOR_SPEC,
  parseCheckpoint,
  formatCheckpoint,
  checkpointDigest,
  parseOrigin,
  chainSegment,
  chainIdFromSegment,
  anchorLogOrigin,
  evidenceLogOrigin,
  isTestNamespace,
  checkOriginBinding,
  MERKLE_SPEC,
  merkleLeafHash,
  verifyMerkleProof,
  verifyConsistencyProof,
  verifyEvmPublication,
  verifyEvmTransactionProof,
  parseEvmBlockHeader,
  RpcEvmHeaderSource,
  EthereumAnchorVerifier,
  EvmPublicationNotCheckedError,
  DEFAULT_EVM_NETWORKS,
  DEFAULT_EVM_TIMEOUT_MS,
  verifyAttestation,
} from '../../src/sdk/index';
import type {
  AnchorArtifact,
  AnchorVerification,
  AnchorVerifyOptions,
  AttestationAnchorReason,
  AttestationTimestampReason,
  AttestationActorReason,
  AttestationCapturedAtReason,
  Checkpoint,
  PublisherManifest,
  PublisherManifestEntry,
  EvmHeaderSource,
  EvmPublicationReason,
  EvmPublicationVerdict,
  EvmNetwork,
} from '../../src/sdk/index';
import * as attestation from '../../src/attestation/index';

describe('the anchoring verification surface is exported from the package entry', () => {
  it('exports every value', () => {
    for (const fn of [
      verifyAnchor,
      parseCheckpoint,
      formatCheckpoint,
      checkpointDigest,
      parseOrigin,
      chainSegment,
      chainIdFromSegment,
      anchorLogOrigin,
      evidenceLogOrigin,
      isTestNamespace,
      checkOriginBinding,
      merkleLeafHash,
      verifyMerkleProof,
      verifyConsistencyProof,
      verifyEvmPublication,
      verifyEvmTransactionProof,
      parseEvmBlockHeader,
      RpcEvmHeaderSource,
      EthereumAnchorVerifier,
      EvmPublicationNotCheckedError,
      verifyAttestation,
    ]) {
      expect(typeof fn).toBe('function');
    }
    expect(ANCHOR_SPEC).toBe('tzun-anchor/1');
    expect(MERKLE_SPEC).toBe('rfc6962');
    expect(DEFAULT_EVM_NETWORKS['eip155:11155111']).toBe('testnet');
    expect(DEFAULT_EVM_TIMEOUT_MS).toBeGreaterThan(0);
  });

  it('exports the types (a missing one fails tsc)', () => {
    const reason: AttestationAnchorReason = 'evm_sender_mismatch';
    const evmReason: EvmPublicationReason = reason as EvmPublicationReason;
    const others: [AttestationTimestampReason, AttestationActorReason, AttestationCapturedAtReason] = [
      'untrusted_chain',
      'actor_mismatch',
      'captured_after_timestamp',
    ];
    const entry: PublisherManifestEntry = { address: '0x' + '00'.repeat(20), chain: 'eip155:11155111', namespace: 'test' };
    const manifest: PublisherManifest = { publishers: { o: [entry] } };
    const options: AnchorVerifyOptions = { publisherManifest: manifest };
    const network: EvmNetwork = 'testnet';
    const unused: Array<
      | AnchorArtifact
      | AnchorVerification
      | Checkpoint
      | EvmHeaderSource
      | EvmPublicationVerdict
      | undefined
    > = [undefined];
    expect([evmReason, others, options, network, unused]).toHaveLength(5);
  });

  it('src/attestation re-exports the same functions', () => {
    expect(attestation.verifyAnchor).toBe(verifyAnchor);
    expect(attestation.parseCheckpoint).toBe(parseCheckpoint);
    expect(attestation.verifyEvmPublication).toBe(verifyEvmPublication);
    expect(attestation.RpcEvmHeaderSource).toBe(RpcEvmHeaderSource);
    expect(attestation.verifyConsistencyProof).toBe(verifyConsistencyProof);
    expect(attestation.PLATFORM_NAMESPACE).toBe('log.tzun.ai');
  });
});
