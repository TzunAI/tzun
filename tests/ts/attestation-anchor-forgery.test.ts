/**
 * The anchor check in `src/attestation/verify-attestation.ts` never decides an
 * anchor verdict against a Merkle root supplied inside the artifact being
 * verified.
 *
 * tzun-anchor/1 makes that its first rule. Every root in
 * `nonRepudiation.anchor` — the evidence log's and the anchor log's — arrives
 * inside the artifact, so anyone holding a digest can mint a self-consistent
 * one: an evidence log whose leaf is the digest, an anchor log whose leaf is
 * that log's checkpoint digest, and the P they hash to. Its proofs hold. What
 * it cannot mint is a publication of P that a verifier checks against its own
 * inputs: a header source and a publisher manifest for `evm-calldata/1`, TSA
 * roots it supplied for `rfc3161/1` (tzun-anchor/1 §10.4, §10.5). Without one,
 * `anchorValid` is `null`, never `true`, and the record's verdict does not
 * move.
 *
 * The hand-rolled hashing below needs no Tzun code and no capability beyond a
 * SHA-256 implementation and the digest already in hand, which is the point.
 */
import { createHash } from 'crypto';
import { verifyAttestation } from '../../src/attestation/verify-attestation';
import type { AttestationArtifacts } from '@tzun/engine';
import { makeTsaFixture } from './rfc3161-fixture';

const sha256 = (bytes: Buffer | string): string => createHash('sha256').update(bytes).digest('hex');

/** RFC 6962 leaf hash: SHA-256(0x00 || the digest's raw 32 bytes). */
const leafHash = (digestHex: string): string => sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(digestHex, 'hex')]));

/** RFC 6962 interior node: SHA-256(0x01 || left || right). */
const node = (left: string, right: string): string =>
  sha256(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'hex'), Buffer.from(right, 'hex')]));

/** A C2SP checkpoint body: origin, size, base64 root. */
const body = (origin: string, size: number, rootHex: string): string =>
  `${origin}\n${size}\n${Buffer.from(rootHex, 'hex').toString('base64')}\n`;

const STORE = 'local.invalid/' + 'ab'.repeat(16);
const LOG_ORIGIN = `${STORE}/evidence/${Buffer.from('default', 'utf8').toString('hex')}`;
const ANCHOR_ORIGIN = `${STORE}/anchors`;

const digest = sha256('a-decision-that-was-never-anchored');

/** An `evm-calldata/1` entry in its envelope form, claiming a mainnet transaction. */
const evmClaim = {
  kind: 'evm-calldata/1',
  chain: 'eip155:1',
  transactionId: '0x' + 'ff'.repeat(32),
  blockNumber: 21_000_000,
  blockHash: '0x' + 'ee'.repeat(32),
  publisher: '0x' + '11'.repeat(20),
};

/**
 * The forgery. A one-leaf evidence log holding the digest, and a two-leaf
 * anchor log holding that log's checkpoint digest beside a made-up one. Every
 * byte is derived from the digest and public rules. `publications` must be
 * non-empty (tzun-anchor/1 §10.3 step 2); by default it claims an EVM
 * publication the verifier has nothing to check against.
 */
function forgedAnchor(publications: unknown[] = [evmClaim]) {
  const logCheckpoint = body(LOG_ORIGIN, 1, leafHash(digest));
  const logLeaf = sha256(logCheckpoint);
  const other = sha256('some other checkpoint');
  const anchorCheckpoint = body(ANCHOR_ORIGIN, 2, node(leafHash(logLeaf), leafHash(other)));
  return {
    anchor: {
      anchorSpec: 'tzun-anchor/1',
      merkleSpec: 'rfc6962',
      leafIndex: 0,
      logCheckpoint,
      logPath: [],
      anchorLeafIndex: 0,
      anchorCheckpoint,
      anchorPath: [leafHash(other)],
      publications,
    },
    p: sha256(anchorCheckpoint),
  };
}

describe('an artifact cannot attest to its own anchoring', () => {
  it('sanity: the forged anchor is internally consistent — its proofs hold', async () => {
    const result = await verifyAttestation({ anchor: forgedAnchor().anchor } as never, digest, undefined, {
      sequenceNumber: 1,
      chainId: 'default',
    });
    expect(result.merkleProofValid).toBe(true);
    expect(result.anchorPosition).toMatchObject({ leafIndex: 0, leafIndexChecked: true, chainChecked: true });
  });

  it('does not report a self-consistent anchor whose publication nothing checks as anchored', async () => {
    const result = await verifyAttestation({ anchor: forgedAnchor().anchor } as never, digest);
    expect(result.merkleProofValid).toBe(true);
    expect(result.anchorValid).toBeNull();
    expect(result.anchorPublication).toBeNull();
    expect(result.existedBy).toBeNull();
  });

  it('does not let a forged anchor promote a record out of "none"', async () => {
    const result = await verifyAttestation({ anchor: forgedAnchor([evmClaim]).anchor } as never, digest);
    expect(result.anchorValid).not.toBe(true);
    expect(result.attestationVerdict).toBe('none');
  });

  it('a claimed EVM publication is undecided without the verifier\'s own header source and manifest', async () => {
    const result = await verifyAttestation({ anchor: forgedAnchor([evmClaim]).anchor } as never, digest);
    expect(result.anchorValid).toBeNull();
    expect(result.anchorReason).toBe('publication_not_checked');
    expect(result.anchorOriginAuthenticated).toBe(false);
  });

  it("a genuine token over P from the forger's own TSA counts for nothing unless the verifier trusts its root", async () => {
    const forged = forgedAnchor();
    const tsa = await makeTsaFixture({ digestHex: forged.p, genTime: new Date('2026-09-20T12:00:00Z') });
    const artifacts = { anchor: { ...forged.anchor, publications: [{ kind: 'rfc3161/1', token: tsa.tokenBase64 }] } };

    const untrusted = await verifyAttestation(artifacts as never, digest, undefined, {
      trustAnchorsPem: [(await makeTsaFixture({ digestHex: forged.p, caCN: 'Some Other Root', signerCN: 'Some Other TSA' })).caPem],
    });
    expect(untrusted.anchorValid).toBeNull();
    expect(untrusted.anchorReason).toBe('publication_not_checked');
    expect(untrusted.existedBy).toBeNull();

    // Only the verifier's own input makes it count, and then only as
    // existed-by: an RFC 3161 token authenticates the TSA, not the origin.
    const trusted = await verifyAttestation(artifacts as never, digest, undefined, { trustAnchorsPem: [tsa.caPem] });
    expect(trusted.anchorValid).toBe(true);
    expect(trusted.anchorPublication).toBe('rfc3161');
    expect(trusted.anchorOriginAuthenticated).toBe(false);
  });

  it('rejects a genuine audit path replayed at the wrong leafIndex', async () => {
    // The same bytes, one position over: the side of the anchor-log step is
    // derived from the index, so the fold changes and the proof fails.
    const { anchor } = forgedAnchor();
    const result = await verifyAttestation({ anchor: { ...anchor, anchorLeafIndex: 1 } } as never, digest);
    expect(result.anchorValid).toBe(false);
    expect(result.anchorReason).toBe('anchor_proof_invalid');
    expect(result.merkleProofValid).toBe(false);
  });

  it('a self-attesting legacy blockchainAnchor is abstained on and counts for nothing', async () => {
    const result = await verifyAttestation(
      {
        blockchainAnchor: {
          chain: 'ethereum-mainnet',
          transactionId: '0x' + 'ff'.repeat(32),
          batchMerkleRoot: leafHash(digest),
          merklePath: [],
          leafIndex: 0,
          treeSize: 1,
          merkleSpec: 'rfc6962',
        },
      } as unknown as AttestationArtifacts,
      digest,
    );
    expect(result.anchorValid).toBeNull();
    expect(result.anchorReason).toBe('legacy_blockchain_anchor');
    expect(result.merkleProofValid).toBeNull();
    expect(result.attestationVerdict).toBe('none');
  });

  it('never lets an unknown tag count toward attestationVerdict', async () => {
    for (const change of [{ anchorSpec: 'tzun-anchor/2' }, { merkleSpec: 'rfc6962-but-sorted' }]) {
      const result = await verifyAttestation({ anchor: { ...forgedAnchor([evmClaim]).anchor, ...change } } as never, digest);
      expect(result.anchorValid).toBeNull();
      expect(result.merkleProofValid).toBeNull();
      expect(result.attestationVerdict).toBe('none');
    }
  });
});
