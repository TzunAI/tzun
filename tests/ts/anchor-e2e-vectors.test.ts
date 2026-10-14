/**
 * tzun-anchor/1 §13: the SDK's verifier gives every record in
 * vectors/anchor-e2e-vectors.json its stated verdicts. The file holds records
 * the anchor scheduler anchored on anvil, through `Tzun.init({ anchoring })`,
 * with each epoch's publication and its heavy material
 * (scripts/generate-anchor-e2e-vectors.ts). The header source here is the one
 * the file states: the canonical block it reported and its finalized height.
 *
 * The Go gate (tests/cross-impl/go and its evm module) checks the same file
 * with transparency-dev and go-ethereum, and
 * tests/cross-sdk/test_anchor_e2e_vectors.py with the Python SDK.
 */
import { SchemaRegistry, verifyEnvelope, type EvidenceEnvelope } from '@tzun/engine';
import { verifyAnchor, type AnchorVerifyOptions } from '../../src/attestation/anchor-verify';
import type { EvmHeaderSource, PublisherManifest } from '../../src/attestation/blockchain';
import vectors from '../../vectors/anchor-e2e-vectors.json';

interface Epoch {
  anchorCheckpoint: string;
  p: string;
  publication: Record<string, unknown> & { blockNumber: number; blockHash: string; txProof: string[]; blockHeader: string };
  canonicalBlock: { number: number; hash: string; timestamp: number };
}

const epochs = vectors.epochs as unknown as Epoch[];
const manifest = vectors.manifest as unknown as PublisherManifest;
const CHAIN = vectors.chain;

/** The header source the file states: its chain, its finalized height, the canonical blocks it reported. */
function statedSource(overrides: Partial<{ hash: string; finalized: number }> = {}): EvmHeaderSource {
  return {
    finality: 'finalized',
    chainId: async () => BigInt(vectors.headerSource.chainId),
    finalizedBlockNumber: async () => overrides.finalized ?? vectors.headerSource.finalizedBlockNumber,
    canonicalBlock: async (n) => {
      const block = epochs.find((e) => e.canonicalBlock.number === n)?.canonicalBlock;
      return block ? { hash: overrides.hash ?? block.hash, timestamp: block.timestamp } : null;
    },
  };
}

type Case = (typeof vectors.records)[number];
const records = vectors.records.map((r) => [r.case, r] as const);

function inputsFor(r: Case, material: Record<string, unknown> = epochs[r.epoch].publication): AnchorVerifyOptions {
  return {
    sequenceNumber: r.envelope.payload.sequenceNumber,
    chainId: r.chainId,
    publisherManifest: manifest,
    publicationMaterial: [material],
  };
}

describe('vectors/anchor-e2e-vectors.json (Anchor §13)', () => {
  it('holds records of two epochs, on three chains, under a test origin', () => {
    expect(epochs).toHaveLength(2);
    expect(new Set(vectors.records.map((r) => r.chainId))).toEqual(new Set(['alpha', 'beta', 'gamma']));
    expect(vectors.anchorOrigin.startsWith('test.')).toBe(true);
    // Each publication shares its block with other transactions, so each trie proof walks more than one node.
    for (const e of epochs) expect(e.publication.txProof.length).toBeGreaterThan(1);
  });

  it.each(records)('%s: the envelope is intact (its digest recomputes)', (_name, r) => {
    const result = verifyEnvelope(r.envelope as unknown as EvidenceEnvelope, undefined, new SchemaRegistry());
    expect(result.storedDigest).toBe(result.recomputedDigest);
  });

  it.each(records)('%s: from the envelope and the bundle alone, the transaction holds and the publication is not checked', async (_name, r) => {
    const v = await verifyAnchor(r.envelope.nonRepudiation, r.envelope.integrity.canonicalDigest, inputsFor(r));
    const e = r.expect.bundleOnly;
    expect(v).toMatchObject({ anchorValid: e.anchorValid, anchorReason: e.anchorReason, merkleProofValid: e.merkleProofValid });
    const outcomeOrReason = (id: string) => {
      const c = v.checks.find((x) => x.id === id);
      return c?.outcome === 'checked-correct' ? c.outcome : c?.reason;
    };
    expect([outcomeOrReason('anchor.evm.tx[0]'), outcomeOrReason('anchor.evm.canonical[0]')]).toEqual([e.evmTx, e.evmCanonical]);
  });

  it.each(records)('%s: with the manifest and the stated header source, anchored (§10.6)', async (_name, r) => {
    const v = await verifyAnchor(r.envelope.nonRepudiation, r.envelope.integrity.canonicalDigest, {
      ...inputsFor(r),
      evmHeaderSources: { [CHAIN]: statedSource() },
    });
    const { inclusion, ...fields } = r.expect.withHeaderSource;
    expect(v).toMatchObject(fields);
    expect(v).not.toHaveProperty('anchorReason');
    expect(v.p).toBe(epochs[r.epoch].p);
    expect(v.publications[0].evm?.inclusion).toBe(inclusion);
  });

  describe('what the vectors refuse, changed', () => {
    const r = vectors.records[vectors.records.length - 1];
    const pub = epochs[r.epoch].publication;
    const flip = (hex: string, at = hex.length - 1): string => hex.slice(0, at) + (hex[at] === '0' ? '1' : '0') + hex.slice(at + 1);
    const verdict = (material: Record<string, unknown>, source = statedSource(), m: PublisherManifest = manifest) =>
      verifyAnchor(r.envelope.nonRepudiation, r.envelope.integrity.canonicalDigest, {
        ...inputsFor(r, material),
        publisherManifest: m,
        evmHeaderSources: { [CHAIN]: source },
      });

    it('a trie node changed: evm_tx_proof_invalid', async () => {
      const txProof = [...pub.txProof];
      txProof[1] = flip(txProof[1]);
      expect(await verdict({ ...pub, txProof })).toMatchObject({ anchorValid: false, anchorReason: 'evm_tx_proof_invalid' });
    });

    it('a header that does not hash to the block hash: evm_tx_proof_invalid', async () => {
      expect(await verdict({ ...pub, blockHeader: flip(pub.blockHeader, 20) })).toMatchObject({ anchorValid: false, anchorReason: 'evm_tx_proof_invalid' });
    });

    it('a header source that reports another block at that height: anchor_not_found_on_chain', async () => {
      expect(await verdict(pub, statedSource({ hash: flip(pub.blockHash) }))).toMatchObject({ anchorValid: false, anchorReason: 'anchor_not_found_on_chain' });
    });

    it('a header source whose finalized height is below the block: not checked', async () => {
      const v = await verdict(pub, statedSource({ finalized: pub.blockNumber - 1 }));
      expect(v).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
      expect(v.checks.find((c) => c.id === 'anchor.evm.canonical[0]')).toMatchObject({ reason: 'evm_block_not_finalized' });
    });

    it('a manifest that names another publisher: evm_sender_mismatch', async () => {
      const other = { publishers: { [vectors.anchorOrigin]: [{ address: '0x' + '42'.repeat(20), chain: CHAIN, namespace: 'test' as const }] } };
      expect(await verdict(pub, statedSource(), other)).toMatchObject({ anchorValid: false, anchorReason: 'evm_sender_mismatch' });
    });

    it('another record\'s digest: merkle_proof_invalid', async () => {
      const other = vectors.records[0].envelope.integrity.canonicalDigest;
      const v = await verifyAnchor(r.envelope.nonRepudiation, other, inputsFor(r));
      expect(v).toMatchObject({ anchorValid: false, anchorReason: 'merkle_proof_invalid' });
    });
  });
});
