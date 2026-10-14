/**
 * tzun-anchor/1 §13: `verifyEvmPublication` gives every case of
 * vectors/evm-anchor-vectors.json its stated verdict, in each of the three
 * modes the file states. The cases are §9's validity bounds, compared at full
 * precision: a validFrom any fraction past the block's second
 * excludes the block, a validUntil any fraction past it still admits it, and
 * a date §9 refuses (a leap second, an impossible day, a lowercase `t`) makes
 * the manifest unreadable.
 *
 * The file's publication is epoch 0 of vectors/anchor-e2e-vectors.json, byte
 * for byte, which the Go gate checks with go-ethereum; the first test holds it
 * to that. tests/cross-sdk/test_evm_anchor_vectors.py holds the Python SDK to
 * the same file, and tests/cross-sdk/test_anchor_verify_parity.py requires
 * both SDKs to give every case the same whole verdict.
 */
import { verifyEvmPublication, type EvmHeaderSource, type EvmPublicationInput } from '../../src/attestation/blockchain';
import e2e from '../../vectors/anchor-e2e-vectors.json';
import vectors from '../../vectors/evm-anchor-vectors.json';

type Mode = 'header' | 'noHeader' | 'offline';
const MODES: Mode[] = ['header', 'noHeader', 'offline'];

interface Check {
  outcome: string;
  reason?: string;
}
interface Expect {
  valid: boolean | null;
  reason?: string;
  tx: Check;
  canonical: Check;
  inclusion?: string;
}
interface Case {
  name: string;
  bounds: Record<string, unknown>;
  window: 'admits' | 'excludes' | 'malformed';
  expect: Record<Mode, Expect>;
}

const cases = vectors.validityBounds as unknown as Case[];
const spec = vectors.headerSource;

/** The header source the file states: its chain, finality, finalized height, blocks and transaction lookups. */
function statedSource(): EvmHeaderSource {
  return {
    finality: spec.finality as EvmHeaderSource['finality'],
    chainId: async () => BigInt(spec.chainId),
    finalizedBlockNumber: async () => spec.finalizedBlockNumber,
    canonicalBlock: async (n) => {
      const b = spec.blocks.find((x) => x.number === n);
      return b ? { hash: b.hash, timestamp: b.timestamp } : null;
    },
    transaction: async (id) => {
      const t = spec.transactions.find((x) => x.transactionId === id);
      return t ? { blockHash: t.blockHash, blockNumber: t.blockNumber, from: t.from } : null;
    },
  };
}

function inputFor(c: Case, mode: Mode): EvmPublicationInput {
  const { blockHeader, txIndex, txProof, ...bare } = vectors.publication;
  return {
    publication: (mode === 'noHeader' ? bare : vectors.publication) as unknown as EvmPublicationInput['publication'],
    p: vectors.p,
    anchorOrigin: vectors.anchorOrigin,
    manifest: { publishers: { [vectors.anchorOrigin]: [{ ...vectors.manifestEntry, ...c.bounds }] } } as unknown as EvmPublicationInput['manifest'],
    headerSources: mode === 'offline' ? undefined : { [vectors.chain]: statedSource() },
  };
}

const withoutUndefined = (c: { outcome: string; reason?: string }): Check =>
  c.reason === undefined ? { outcome: c.outcome } : { outcome: c.outcome, reason: c.reason };

describe('vectors/evm-anchor-vectors.json (tzun-anchor/1 §9, §13)', () => {
  it('carries epoch 0 of anchor-e2e-vectors.json, byte for byte', () => {
    const epoch = e2e.epochs[0];
    expect(vectors.publication).toEqual(epoch.publication);
    expect(vectors.p).toBe(epoch.p);
    expect(vectors.chain).toBe(e2e.chain);
    expect(vectors.anchorOrigin).toBe(e2e.anchorOrigin);
    expect(vectors.blockTime).toBe(epoch.canonicalBlock.timestamp);
    expect(vectors.headerSource.blocks).toEqual([epoch.canonicalBlock]);
    expect(vectors.headerSource).toMatchObject(e2e.headerSource);
    expect(vectors.manifestEntry).toEqual(e2e.manifest.publishers[e2e.anchorOrigin as keyof typeof e2e.manifest.publishers][0]);
    expect(vectors.sender).toBe(vectors.manifestEntry.address);
    expect(vectors.headerSource.transactions).toEqual([
      { transactionId: epoch.publication.transactionId, blockHash: epoch.publication.blockHash, blockNumber: epoch.publication.blockNumber, from: vectors.sender },
    ]);
  });

  it('reaches every window on both sides of the block, including below the millisecond', () => {
    const windows = new Set(cases.map((c) => c.window));
    expect(windows).toEqual(new Set(['admits', 'excludes', 'malformed']));
    const second = new Date(vectors.blockTime * 1000).toISOString().slice(0, 19);
    expect(cases.find((c) => c.bounds.validFrom === `${second}.0005Z` && c.bounds.validUntil === undefined)?.window).toBe('excludes');
    expect(cases.find((c) => c.bounds.validUntil === `${second}.0005Z` && c.bounds.validFrom === undefined)?.window).toBe('admits');
  });

  describe.each(MODES)('%s', (mode) => {
    it.each(cases.map((c) => [c.name, c] as const))('%s', async (_name, c) => {
      const v = await verifyEvmPublication(inputFor(c, mode));
      const e = c.expect[mode];
      expect({
        valid: v.valid,
        reason: v.reason,
        tx: withoutUndefined(v.checks.tx),
        canonical: withoutUndefined(v.checks.canonical),
        inclusion: v.valid === true ? v.facts.inclusion : undefined,
      }).toEqual({
        valid: e.valid,
        reason: e.reason,
        tx: e.tx,
        canonical: e.canonical,
        inclusion: e.inclusion,
      });
    });
  });
});
