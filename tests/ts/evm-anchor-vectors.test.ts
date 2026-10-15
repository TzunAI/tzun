/**
 * tzun-anchor/1 §13: `verifyEvmPublication` gives every case of
 * vectors/evm-anchor-vectors.json its stated verdict, in each of the three
 * modes the file states. The cases are §9's validity bounds, compared at full
 * precision: a validFrom any fraction past the block's second
 * excludes the block, a validUntil any fraction past it still admits it, and
 * a date §9 refuses (a leap second, an impossible day, a lowercase `t`) makes
 * the manifest unreadable. Then §10.4 item 2's transaction cases, offline: a
 * transaction that breaks one of the rules item 2 states (a typed chain id of
 * 0, a legacy v of 35 or 36, a high s, a tip above the fee cap, a signature no
 * key recovers from, bytes that are not the canonical RLP of the fields, a
 * field above its size) is false, malformed_publication, and the one just
 * inside each edge is read, with the sender the file states.
 * `readEvmTransaction` must report the very rule each refused case breaks.
 *
 * The file's publication is epoch 0 of vectors/anchor-e2e-vectors.json, byte
 * for byte, which the Go gate checks with go-ethereum; the first test holds it
 * to that. tests/cross-sdk/test_evm_anchor_vectors.py holds the Python SDK to
 * the same file, and tests/cross-sdk/test_anchor_verify_parity.py requires
 * both SDKs to give every case the same whole verdict.
 */
import {
  readEvmTransaction,
  verifyEvmPublication,
  type EvmHeaderSource,
  type EvmPublicationInput,
} from '../../src/attestation/blockchain';
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

interface TransactionCase {
  id: string;
  name: string;
  rule: string | null;
  item2: 'reads' | 'refuses';
  rawTransaction: string;
  transactionId: string;
  publisher: string;
  sender: string | null;
  signedChainId: string | null;
  expect: Expect;
}

const tx = vectors.transactionCases;
const txCases = tx.cases as unknown as TransactionCase[];

function transactionInput(c: TransactionCase): EvmPublicationInput {
  return {
    publication: {
      kind: 'evm-calldata/1',
      chain: tx.chain,
      transactionId: c.transactionId,
      rawTransaction: c.rawTransaction,
      blockNumber: tx.blockNumber,
      blockHash: tx.blockHash,
    },
    p: vectors.p,
    anchorOrigin: vectors.anchorOrigin,
    manifest: { publishers: { [vectors.anchorOrigin]: [{ address: c.publisher, chain: tx.chain, namespace: 'test' }] } },
  };
}

describe('vectors/evm-anchor-vectors.json: the transaction cases of tzun-anchor/1 §10.4 item 2', () => {
  it('breaks each rule of item 2, and meets each at its edge', () => {
    expect(new Set(txCases.map((c) => c.rule))).toEqual(
      new Set(['chain-id', 'legacy-v', 'signature-values', 'fees', 'recovery', 'encoding', 'field-sizes', null]),
    );
    expect(new Set(txCases.map((c) => c.id)).size).toBe(txCases.length);
    for (const c of txCases) expect(c.item2).toBe(c.rule === null ? 'reads' : 'refuses');
  });

  it.each(txCases.map((c) => [c.id, c] as const))('%s', async (_id, c) => {
    const v = await verifyEvmPublication(transactionInput(c));
    expect({
      valid: v.valid,
      reason: v.reason,
      tx: withoutUndefined(v.checks.tx),
      canonical: withoutUndefined(v.checks.canonical),
      sender: v.facts.sender ?? null,
    }).toEqual({ ...c.expect, sender: c.sender });
    // tzun-anchor/1 §10.7: the signed chain id once the transaction decodes, null for v 27 or
    // 28; no facts at all when item 2 refuses it.
    if (c.rule === null) expect(v.facts).toHaveProperty('signedChainId', c.signedChainId);
    else expect(v.facts).not.toHaveProperty('signedChainId');
  });

  it('states the signed chain id of each transaction item 2 reads, and null for v 27 and 28', () => {
    const read = txCases.filter((c) => c.rule === null);
    expect(txCases.filter((c) => c.rule !== null).every((c) => c.signedChainId === null)).toBe(true);
    expect(read.filter((c) => c.signedChainId === null).map((c) => c.id).sort()).toEqual(['legacy-v-27', 'legacy-v-28']);
    expect(read.every((c) => c.signedChainId === null || /^[1-9][0-9]*$/.test(c.signedChainId))).toBe(true);
  });

  it.each(txCases.map((c) => [c.id, c] as const))('%s: readEvmTransaction reports the rule it breaks', (_id, c) => {
    const reading = readEvmTransaction(c.rawTransaction);
    expect(reading.ok ? { sender: reading.transaction.sender } : { rule: reading.rule }).toEqual(
      c.rule === null ? { sender: c.sender } : { rule: c.rule },
    );
  });
});

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
