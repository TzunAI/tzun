/**
 * The auditor's path: a record's anchor must be confirmable from the record's
 * own inclusion proof and the transaction alone, by someone holding only the
 * transaction hash, their own node and the publisher list.
 *
 * The SDK holds no per-capture anchor client, and capture does not anchor
 * (tests/ts/capture-decoupling.test.ts), so the transaction here
 * is sent the way a publisher sends one: to itself, zero value, calldata P.
 * No mocks of ethers and no network: it is really signed and broadcast over
 * JSON-RPC to a loopback node (tests/ts/helpers/evm-fake-node.ts).
 */
import { Wallet } from 'ethers';
import { EthereumAnchorVerifier } from '../../src/attestation/blockchain';
import {
  buildMerkleTree,
  getMerkleProof,
  getMerkleRoot,
  verifyMerkleProof,
} from '../../src/attestation/merkle';
import { FakeEvmNode, publishOverRpc } from './helpers/evm-fake-node';
import { SEPOLIA } from './helpers/evm-fixtures';
import { createHash } from 'crypto';

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

describe('an auditor can confirm a batch anchor from a record and the transaction alone', () => {
  let node: FakeEvmNode;
  let url: string;

  beforeEach(async () => {
    node = new FakeEvmNode({ chainId: SEPOLIA, finalityLag: 8 });
    url = await node.start();
  });
  afterEach(() => node.stop());

  it('round-trips: each record proves into the root the publisher broadcast, and the verifier reads that root back', async () => {
    // The auditor's position exactly: a record's digest and inclusion proof, a
    // transaction hash, their own node and the publisher list. Not our
    // database, our config, or our word for it.
    const publisher = Wallet.createRandom();
    const digests = [sha256('decision-1'), sha256('decision-2'), sha256('decision-3')];
    const tree = buildMerkleTree(digests);
    const batchMerkleRoot = getMerkleRoot(tree);

    const transactionId = await publishOverRpc(publisher.privateKey, url, batchMerkleRoot);
    node.mineEmpty(8);

    // Every record in the batch proves into the one root the transaction
    // carries, at its own position.
    digests.forEach((digest, leafIndex) => {
      expect(
        verifyMerkleProof(digest, leafIndex, digests.length, getMerkleProof(tree, leafIndex), batchMerkleRoot),
      ).toBe(true);
    });

    const verifier = new EthereumAnchorVerifier({
      rpcUrls: { 'ethereum-sepolia': url },
      publishers: [{ address: publisher.address, chain: 'eip155:11155111', namespace: 'test' }],
    });
    const claim = { chain: 'ethereum-sepolia', transactionId, p: batchMerkleRoot };

    const confirmed = await verifier.verifyAnchor(claim);
    expect(confirmed.confirmed).toBe(true);
    expect(confirmed.publication).toMatchObject({
      valid: true,
      facts: { sender: publisher.address.toLowerCase(), signedChainId: '11155111' },
    });

    // The negative controls. A root the transaction does not carry is refused,
    // so "confirmed" is a statement about the chain, not about the artifact
    // that asserted it; and a record that is not in the batch does not prove
    // into the root that was confirmed.
    const other = await verifier.verifyAnchor({ ...claim, p: sha256('a-root-that-was-never-broadcast') });
    expect(other.confirmed).toBe(false);
    expect(other.reason).toBe('evm_calldata_mismatch');
    expect(other.publication!.reason).toBe('evm_calldata_mismatch');

    expect(
      verifyMerkleProof(sha256('decision-never-captured'), 0, digests.length, getMerkleProof(tree, 0), batchMerkleRoot),
    ).toBe(false);
  }, 20_000);
});
