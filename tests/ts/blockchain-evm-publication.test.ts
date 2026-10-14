/**
 * Anchor §10.4: the `evm-calldata/1` publication verifier (Anchor §10.3 step 6).
 *
 * No mocks of ethers and no network. Every transaction is really signed by a
 * throwaway key, every block is fabricated (a header is only the RLP of its
 * fields), and the header source is a fake the test controls. That is the
 * point: offline, everything but the sender's signature is whatever the
 * bundle says, so only the sender check and the verifier's own header source
 * can tell a real publication from a manufactured one.
 */
import { Wallet, Transaction, decodeRlp, encodeRlp, keccak256, type RlpStructuredData } from 'ethers';
import {
  verifyEvmPublication,
  verifyEvmTransactionProof,
  parseEvmBlockHeader,
  decodeEvmRlp,
  RpcEvmHeaderSource,
  EVM_MIN_FINAL_CONFIRMATIONS,
  MAX_RLP_DEPTH,
  type AnchorTransactionProvider,
  type EvmFinality,
  type EvmHeaderSource,
  type EvmPublicationInput,
  type EvmSourceTransaction,
  type PublisherManifest,
  type PublisherManifestEntry,
} from '../../src/attestation/blockchain';
import {
  MAINNET,
  SEPOLIA,
  buildTxTrie,
  fabricateBlock,
  publicationFrom,
  randomP,
  signAnchorTx,
  type FabricatedBlock,
} from './helpers/evm-fixtures';
import sepoliaVector from './fixtures/evm-sepolia-block.json';
import sepoliaSelfTx from './fixtures/evm-sepolia-self-tx.json';

const ORIGIN = 'local.invalid/3f2a9c0e5b7d4e1f8a6c2b9d0e4f7a1c/anchors';

const decodeRlpList = (hex: string) => decodeRlp(hex) as RlpStructuredData[];
const SEPOLIA_CHAIN = 'eip155:11155111';

/** A header source the test controls: the auditor's own view of the chain. */
class FakeHeaderSource implements EvmHeaderSource {
  chain = SEPOLIA;
  finalized: number;
  blocks = new Map<number, { hash: string; timestamp: number }>();
  txs = new Map<string, EvmSourceTransaction>();
  calls = 0;

  constructor(block?: FabricatedBlock, opts: { finalizedDepth?: number; lookups?: boolean } = {}) {
    this.finalized = block ? block.number + (opts.finalizedDepth ?? 64) : 0;
    if (block) {
      this.blocks.set(block.number, { hash: block.hash, timestamp: block.timestamp });
      if (opts.lookups !== false) {
        for (const raw of block.raws) {
          const t = Transaction.from(raw);
          this.txs.set(t.hash!, { from: t.from!, blockHash: block.hash, blockNumber: block.number, rawTransaction: raw });
        }
      }
    }
  }
  async chainId() {
    this.calls++;
    return this.chain;
  }
  async finalizedBlockNumber() {
    return this.finalized;
  }
  async canonicalBlock(n: number) {
    return this.blocks.get(n) ?? null;
  }
  async transaction(id: string) {
    return this.txs.get(id) ?? null;
  }
}

/** The same source without a transaction lookup: headers only, like a light client. */
function headersOnly(src: FakeHeaderSource): EvmHeaderSource {
  return {
    chainId: () => src.chainId(),
    finalizedBlockNumber: () => src.finalizedBlockNumber(),
    canonicalBlock: (n) => src.canonicalBlock(n),
  };
}

function entry(wallet: { address: string }, extra: Partial<PublisherManifestEntry> = {}): PublisherManifestEntry {
  return { address: wallet.address, chain: SEPOLIA_CHAIN, namespace: 'test', ...extra };
}

function manifestOf(...entries: PublisherManifestEntry[]): PublisherManifest {
  return { publishers: { [ORIGIN]: entries } };
}

/** Three unrelated transactions from strangers, so the trie has branches and an extension. */
async function fillers(n = 3): Promise<string[]> {
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    out.push(await signAnchorTx(Wallet.createRandom(), { data: randomP(), nonce: i }));
  }
  return out;
}

interface Scenario {
  p: string;
  publisher: ReturnType<typeof Wallet.createRandom>;
  block: FabricatedBlock;
  input: EvmPublicationInput;
  source: FakeHeaderSource;
}

/** The publisher's anchor for P at index 2 of a four-transaction block, and a source that has seen it. */
async function honest(opts: { type?: 0 | 1 | 2; index?: number } = {}): Promise<Scenario> {
  const p = randomP();
  const publisher = Wallet.createRandom();
  const raw = await signAnchorTx(publisher, { data: p, type: opts.type });
  const others = await fillers();
  const index = opts.index ?? 2;
  const raws = [...others];
  raws.splice(index, 0, raw);
  const block = fabricateBlock(raws);
  const source = new FakeHeaderSource(block);
  return {
    p,
    publisher,
    block,
    source,
    input: {
      publication: publicationFrom(block, index),
      p,
      anchorOrigin: ORIGIN,
      manifest: manifestOf(entry(publisher)),
      headerSources: { [SEPOLIA_CHAIN]: source },
    },
  };
}

describe('the evm-calldata/1 checks (Anchor §10.4)', () => {
  it('a transaction from another sender with the right calldata → false, evm_sender_mismatch', async () => {
    const s = await honest();
    const attacker = Wallet.createRandom();
    // Right calldata, and sent TO the publisher's address, so a check on
    // `tx.to` would pass it.
    const forged = await signAnchorTx(attacker, { data: s.p, to: s.publisher.address });
    const block = fabricateBlock([...(await fillers()), forged]);
    const source = new FakeHeaderSource(block);
    const input = { ...s.input, publication: publicationFrom(block, 3), headerSources: { [SEPOLIA_CHAIN]: source } };

    const withSource = await verifyEvmPublication(input);
    expect(withSource.valid).toBe(false);
    expect(withSource.reason).toBe('evm_sender_mismatch');
    expect(withSource.checks.tx).toMatchObject({ outcome: 'checked-wrong', reason: 'evm_sender_mismatch' });
    expect(withSource.checks.canonical).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:anchor.evm.tx' });
    expect(withSource.facts.sender).toBe(attacker.address.toLowerCase());
    // The failure is decided offline: the header source is never consulted.
    expect(source.calls).toBe(0);

    const offline = await verifyEvmPublication({ ...input, headerSources: undefined });
    expect(offline).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
  });

  it('a valid transaction with a fabricated header and no header source → null, publication_not_checked', async () => {
    const s = await honest();
    // Everything checks offline: the publisher really signed it, the header
    // hashes to the block hash, the trie proof holds. None of it was ever
    // mined, and the timestamp is back-dated by a year.
    const backdated = fabricateBlock(s.block.raws, 5_000_000, 1_758_000_000);
    const input = { ...s.input, publication: publicationFrom(backdated, 2), headerSources: undefined };

    const v = await verifyEvmPublication(input);
    expect(v.valid).toBeNull();
    expect(v.reason).toBe('publication_not_checked');
    expect(v.checks.tx.outcome).toBe('checked-correct');
    expect(v.checks.canonical).toMatchObject({
      outcome: 'not-checked',
      value: null,
      reason: 'input_not_supplied:evm_header_source',
    });
    // An unconfirmed header dates nothing and names no network.
    expect(v.facts.blockTime).toBeUndefined();
    expect(v.facts.network).toBeUndefined();
    expect(v.facts.namespace).toBeUndefined();
  });
});

describe('the four outcomes', () => {
  it('true: offline facts hold and the header source confirms the block final', async () => {
    const s = await honest();
    const v = await verifyEvmPublication(s.input);
    expect(v.valid).toBe(true);
    expect(v.reason).toBeUndefined();
    expect(v.checks.tx).toEqual({ id: 'anchor.evm.tx', outcome: 'checked-correct', value: true });
    expect(v.checks.canonical).toEqual({ id: 'anchor.evm.canonical', outcome: 'checked-correct', value: true });
    expect(v.facts).toMatchObject({
      sender: s.publisher.address.toLowerCase(),
      signedChainId: '11155111',
      chain: SEPOLIA_CHAIN,
      namespace: 'test',
      network: 'testnet',
      blockTime: new Date(s.block.timestamp * 1000).toISOString(),
      inclusion: 'tx_proof',
      transactionId: keccak256(s.block.raws[2]),
    });
  });

  it('false: decided and fails', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, p: randomP() });
    expect(v).toMatchObject({ valid: false, reason: 'evm_calldata_mismatch' });
    expect(v.checks.tx.value).toBe(false);
  });

  it('null, not-checked: no header source', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, headerSources: {} });
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.outcome).toBe('not-checked');
  });

  it('null, abstain: a publication kind this verifier does not implement', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({
      ...s.input,
      publication: { ...s.input.publication, kind: 'evm-calldata/2' as 'evm-calldata/1' },
    });
    expect(v).toMatchObject({ valid: null, reason: 'unsupported_publication_kind' });
    expect(v.checks.tx).toMatchObject({ outcome: 'abstain', value: null });
  });

  it('null, abstain: a transaction type this verifier does not implement (EIP-7702)', async () => {
    const s = await honest();
    const w = s.publisher;
    const raw = await w.signTransaction({
      type: 4,
      chainId: SEPOLIA,
      nonce: 0,
      to: w.address,
      value: 0n,
      data: s.p,
      gasLimit: 60_000n,
      maxFeePerGas: 3_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      authorizationList: [await w.authorize({ address: w.address, nonce: 1, chainId: SEPOLIA })],
    });
    const block = fabricateBlock([raw]);
    const v = await verifyEvmPublication({
      ...s.input,
      publication: publicationFrom(block, 0),
      headerSources: { [SEPOLIA_CHAIN]: new FakeHeaderSource(block) },
    });
    expect(v).toMatchObject({ valid: null, reason: 'unsupported_evm_tx_type' });
    expect(v.checks.tx.outcome).toBe('abstain');
  });
});

describe('the sender, not the recipient', () => {
  it('does not check tx.to: a publisher transaction to any address verifies', async () => {
    const p = randomP();
    const publisher = Wallet.createRandom();
    const raw = await signAnchorTx(publisher, { data: p, to: Wallet.createRandom().address });
    const block = fabricateBlock([raw]);
    const v = await verifyEvmPublication({
      publication: publicationFrom(block, 0),
      p,
      anchorOrigin: ORIGIN,
      manifest: manifestOf(entry(publisher)),
      headerSources: { [SEPOLIA_CHAIN]: new FakeHeaderSource(block) },
    });
    expect(v.valid).toBe(true);
  });

  it("another origin's publisher does not count for this origin", async () => {
    const s = await honest();
    const other = Wallet.createRandom();
    const v = await verifyEvmPublication({
      ...s.input,
      manifest: {
        publishers: {
          [ORIGIN]: [entry(other)],
          'local.invalid/ffff/anchors': [entry(s.publisher)],
        },
      },
    });
    expect(v).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
  });

  it('abstains when the manifest names no publisher for the origin', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, manifest: { publishers: {} } });
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.tx).toMatchObject({ outcome: 'not-checked', reason: 'no_expectation:publisher' });
  });

  it('never trusts the publication\'s own `publisher` or `chain` fields', async () => {
    const s = await honest();
    const attacker = Wallet.createRandom();
    const forged = await signAnchorTx(attacker, { data: s.p });
    const block = fabricateBlock([forged]);
    const v = await verifyEvmPublication({
      ...s.input,
      publication: { ...publicationFrom(block, 0), publisher: s.publisher.address, chain: SEPOLIA_CHAIN },
      headerSources: { [SEPOLIA_CHAIN]: new FakeHeaderSource(block) },
    });
    expect(v).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
  });

  describe('Anchor §9: validity windows, judged at the block time', () => {
    it('a rotated-out publisher after its validUntil → evm_sender_mismatch', async () => {
      const s = await honest();
      const until = new Date((s.block.timestamp - 1) * 1000).toISOString();
      const v = await verifyEvmPublication({ ...s.input, manifest: manifestOf(entry(s.publisher, { validUntil: until })) });
      expect(v).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
    });

    it('the same publisher before its validUntil → true', async () => {
      const s = await honest();
      const until = new Date((s.block.timestamp + 1) * 1000).toISOString();
      const v = await verifyEvmPublication({ ...s.input, manifest: manifestOf(entry(s.publisher, { validUntil: until })) });
      expect(v.valid).toBe(true);
    });

    it('a publisher before its validFrom → evm_sender_mismatch', async () => {
      const s = await honest();
      const from = new Date((s.block.timestamp + 60) * 1000).toISOString();
      const v = await verifyEvmPublication({ ...s.input, manifest: manifestOf(entry(s.publisher, { validFrom: from })) });
      expect(v).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
    });

    it('without a header or a header source, a bounded window leaves the sender check not-checked', async () => {
      const s = await honest();
      const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
      const from = new Date((s.block.timestamp - 60) * 1000).toISOString();
      const v = await verifyEvmPublication({
        ...s.input,
        publication: bare,
        manifest: manifestOf(entry(s.publisher, { validFrom: from })),
        headerSources: undefined,
      });
      expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
      expect(v.checks.tx).toMatchObject({ outcome: 'not-checked', reason: 'not_in_bundle:block_header' });

      const confirmed = await verifyEvmPublication({
        ...s.input,
        publication: bare,
        manifest: manifestOf(entry(s.publisher, { validFrom: from })),
      });
      expect(confirmed.valid).toBe(true);
      expect(confirmed.checks.tx.outcome).toBe('checked-correct');
    });

    it('without a header in the bundle, the window is judged at the time the header source confirms', async () => {
      const s = await honest();
      const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
      const until = new Date((s.block.timestamp - 1) * 1000).toISOString();
      const v = await verifyEvmPublication({
        ...s.input,
        publication: bare,
        manifest: manifestOf(entry(s.publisher, { validUntil: until })),
      });
      expect(v).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
      // A failure is reported once, at the check that decided it (Anchor §10.1).
      expect(v.checks.tx).toMatchObject({ outcome: 'checked-wrong', reason: 'evm_sender_mismatch' });
      expect(v.checks.canonical).toMatchObject({ outcome: 'not-checked', reason: 'blocked_by:anchor.evm.tx' });
    });

    it('offline, a window that excludes the header\'s time → false, with no header source at all', async () => {
      const s = await honest();
      const until = new Date((s.block.timestamp - 1) * 1000).toISOString();
      const v = await verifyEvmPublication({
        ...s.input,
        manifest: manifestOf(entry(s.publisher, { validUntil: until })),
        headerSources: undefined,
      });
      expect(v).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
      expect(v.checks.canonical.reason).toBe('blocked_by:anchor.evm.tx');
    });

    it.each([
      ['a day past the end of the month', '2026-09-31T00:00:00Z'],
      ['February 30', '2026-02-30T00:00:00Z'],
      ['February 29 in a common year', '2026-02-29T00:00:00Z'],
      ['February 29 in a century that is not a leap year', '2100-02-29T00:00:00Z'],
      ['month 13', '2026-13-01T00:00:00Z'],
      ['month 00', '2026-00-10T00:00:00Z'],
      ['day 00', '2026-09-00T00:00:00Z'],
      ['hour 24', '2026-09-23T24:00:00Z'],
      ['minute 60', '2026-09-23T23:60:00Z'],
      ['second 60', '2026-09-23T23:59:60Z'],
      ['an offset of +24:00', '2026-09-23T12:00:00+24:00'],
      ['an offset minute of 60', '2026-09-23T12:00:00+05:60'],
    ])('refuses a manifest date with %s instead of rolling it over (%s)', async (_label, date) => {
      const s = await honest();
      for (const bound of [{ validFrom: date }, { validUntil: date }]) {
        const v = await verifyEvmPublication({ ...s.input, manifest: manifestOf(entry(s.publisher, bound)) });
        expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
        expect(v.checks.tx.reason).toBe('input_not_supplied:publisher_manifest');
      }
    });

    it('compares a bound at full precision, below the millisecond (tzun-anchor/1 §9)', async () => {
      // Anchor §9 compares at full precision: Date.parse would read '.0005' as '.000',
      // but a validFrom any fraction past the block's second excludes the block.
      const s = await honest();
      const second = new Date(s.block.timestamp * 1000).toISOString().slice(0, 19);
      const earlier = new Date((s.block.timestamp - 1) * 1000).toISOString().slice(0, 19);
      for (const [bound, valid] of [
        [{ validFrom: `${second}Z` }, true],
        [{ validFrom: `${second}.000000000Z` }, true],
        [{ validFrom: `${second}.0005Z` }, false],
        [{ validFrom: `${second}.0001234567Z` }, false],
        [{ validFrom: `${second}.0000000000001Z` }, false],
        [{ validFrom: `${earlier}.0005Z` }, true],
        [{ validFrom: `${earlier}.9999999999999Z` }, true],
        [{ validUntil: `${second}Z` }, true],
        [{ validUntil: `${second}.9999999999Z` }, true],
        [{ validUntil: `${earlier}.9999999999Z` }, false],
      ] as const) {
        const v = await verifyEvmPublication({ ...s.input, manifest: manifestOf(entry(s.publisher, bound)) });
        expect([bound, v.valid, v.reason]).toEqual([bound, valid, valid ? undefined : 'evm_sender_mismatch']);
      }
    });

    it.each([
      ['February 29 in a leap year', '2028-02-29T00:00:00Z'],
      ['February 29 in a year divisible by 400', '2000-02-29T00:00:00Z'],
      ['the last second of a day', '2026-09-30T23:59:59.999Z'],
      ['an offset', '2026-09-23T12:00:00-07:00'],
    ])('accepts a real date: %s (%s)', async (_label, date) => {
      const s = await honest();
      const v = await verifyEvmPublication({ ...s.input, manifest: manifestOf(entry(s.publisher, { validFrom: date })) });
      expect(v.valid).not.toBeNull();
    });
  });
});

describe('the chain the sender signed', () => {
  it('a signed chain id other than the manifest entry\'s CAIP-2 chain → evm_chain_mismatch', async () => {
    const s = await honest();
    const mainnet = await signAnchorTx(s.publisher, { data: s.p, chainId: MAINNET });
    const block = fabricateBlock([mainnet]);
    const v = await verifyEvmPublication({
      ...s.input,
      publication: publicationFrom(block, 0),
      headerSources: { 'eip155:1': new FakeHeaderSource(block), [SEPOLIA_CHAIN]: new FakeHeaderSource(block) },
    });
    expect(v).toMatchObject({ valid: false, reason: 'evm_chain_mismatch' });
    expect(v.facts.signedChainId).toBe('1');
  });

  it('a pre-EIP-155 legacy transaction binds no chain → evm_chain_mismatch', async () => {
    const s = await honest();
    const unsigned = Transaction.from({
      type: 0,
      nonce: 0,
      to: s.publisher.address,
      gasLimit: 30_000n,
      gasPrice: 2_000_000_000n,
      data: s.p,
      value: 0n,
    });
    unsigned.signature = s.publisher.signingKey.sign(unsigned.unsignedHash);
    const raw = unsigned.serialized;
    expect(Transaction.from(raw).chainId).toBe(0n);
    const block = fabricateBlock([raw]);
    const v = await verifyEvmPublication({
      ...s.input,
      publication: publicationFrom(block, 0),
      headerSources: { [SEPOLIA_CHAIN]: new FakeHeaderSource(block) },
    });
    expect(v).toMatchObject({ valid: false, reason: 'evm_chain_mismatch' });
    expect(v.facts.signedChainId).toBe('0');
  });

  it('the header source is chosen by the manifest entry\'s chain, and must itself be on that chain', async () => {
    const s = await honest();
    s.source.chain = MAINNET;
    const v = await verifyEvmPublication(s.input);
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_header_source_chain_mismatch');
  });

  it('reports the network from the verifier\'s registry, never from the artifact', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, networks: { [SEPOLIA_CHAIN]: 'mainnet' } });
    expect(v.facts.network).toBe('mainnet');
  });
});

describe('calldata is exactly 0x ‖ P, with P opaque', () => {
  it('accepts P with or without 0x, in either case', async () => {
    const s = await honest();
    for (const p of [s.p, s.p.slice(2), s.p.toUpperCase().replace('0X', '0x'), s.p.slice(2).toUpperCase()]) {
      expect((await verifyEvmPublication({ ...s.input, p })).valid).toBe(true);
    }
  });

  it.each([
    ['one byte appended', (p: string) => p + '00'],
    ['a four-byte selector in front', (p: string) => '0xdeadbeef' + p.slice(2)],
    ['truncated by a byte', (p: string) => p.slice(0, -2)],
  ])('rejects calldata with %s', async (_label, mutate) => {
    const s = await honest();
    const raw = await signAnchorTx(s.publisher, { data: mutate(s.p) });
    const block = fabricateBlock([raw]);
    const v = await verifyEvmPublication({
      ...s.input,
      publication: publicationFrom(block, 0),
      headerSources: { [SEPOLIA_CHAIN]: new FakeHeaderSource(block) },
    });
    expect(v).toMatchObject({ valid: false, reason: 'evm_calldata_mismatch' });
  });

  it('does not decide when P itself is not 32 bytes', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, p: s.p.slice(0, 40) });
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.tx.reason).toBe('input_not_supplied:p');
  });
});

describe('finality comes only from the header source', () => {
  it('a block above the finalized height → null, evm_block_not_finalized', async () => {
    const s = await honest();
    s.source.finalized = s.block.number - 1;
    const v = await verifyEvmPublication(s.input);
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_block_not_finalized');
    expect(v.facts.blockTime).toBeUndefined();
  });

  it('a block exactly at the finalized height → true', async () => {
    const s = await honest();
    s.source.finalized = s.block.number;
    expect((await verifyEvmPublication(s.input)).valid).toBe(true);
  });

  it('a fabricated, back-dated header the chain never saw → false, anchor_not_found_on_chain', async () => {
    const s = await honest();
    const backdated = fabricateBlock(s.block.raws, s.block.number, s.block.timestamp - 86_400 * 365);
    const v = await verifyEvmPublication({ ...s.input, publication: publicationFrom(backdated, 2) });
    expect(v).toMatchObject({ valid: false, reason: 'anchor_not_found_on_chain' });
    expect(v.checks.tx.outcome).toBe('checked-correct');
    expect(v.checks.canonical).toMatchObject({ outcome: 'checked-wrong', reason: 'anchor_not_found_on_chain' });
  });

  it("with no trie proof, a lookup placing the transaction in another block the source calls canonical → anchor_not_found_on_chain", async () => {
    const s = await honest();
    const id = keccak256(s.block.raws[2]);
    const other = { hash: '0x' + 'ee'.repeat(32), timestamp: s.block.timestamp + 12 };
    s.source.blocks.set(s.block.number + 1, other);
    s.source.txs.set(id, { ...s.source.txs.get(id)!, blockHash: other.hash, blockNumber: s.block.number + 1 });
    const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
    const v = await verifyEvmPublication({ ...s.input, publication: bare });
    expect(v).toMatchObject({ valid: false, reason: 'anchor_not_found_on_chain' });
  });

  it('with no trie proof, a lookup naming a block the source does not call canonical is a stale index → null', async () => {
    const s = await honest();
    const id = keccak256(s.block.raws[2]);
    // The lookup names block N+1 by a hash the source's canonical chain does
    // not have there (a stale index, or a backend that has not caught up).
    s.source.blocks.set(s.block.number + 1, { hash: '0x' + 'dd'.repeat(32), timestamp: s.block.timestamp + 12 });
    s.source.txs.set(id, { ...s.source.txs.get(id)!, blockHash: '0x' + 'ee'.repeat(32), blockNumber: s.block.number + 1 });
    const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
    const v = await verifyEvmPublication({ ...s.input, publication: bare });
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_header_source_inconsistent');

    // The same with no block number at all in the lookup.
    s.source.txs.set(id, { ...s.source.txs.get(id)!, blockNumber: null });
    const w = await verifyEvmPublication({ ...s.input, publication: bare });
    expect(w.checks.canonical.reason).toBe('evm_header_source_inconsistent');
  });

  it("a header source reporting another timestamp for the block the header hashes to is inconsistent", async () => {
    const s = await honest();
    s.source.blocks.set(s.block.number, { hash: s.block.hash, timestamp: s.block.timestamp + 1 });
    const v = await verifyEvmPublication(s.input);
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_header_source_inconsistent');
  });

  it('with a verified trie proof, a lookup naming another block is the source contradicting itself → null', async () => {
    const s = await honest();
    const id = keccak256(s.block.raws[2]);
    s.source.txs.set(id, { ...s.source.txs.get(id)!, blockHash: '0x' + 'ee'.repeat(32) });
    const v = await verifyEvmPublication(s.input);
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_header_source_inconsistent');
  });

  it('a lookup that fails does not undo a verified trie proof; without one it leaves the publication undecided', async () => {
    const s = await honest();
    s.source.transaction = async () => {
      throw new Error('transaction indexing is in progress');
    };
    expect((await verifyEvmPublication(s.input)).valid).toBe(true);

    const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
    const v = await verifyEvmPublication({ ...s.input, publication: bare });
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_header_source_unavailable');
  });

  it('a header source filed under another chain is not used', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, headerSources: { 'eip155:1': s.source } });
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('input_not_supplied:evm_header_source');
  });

  it('a header source that reports another sender for the same hash is not believed either way', async () => {
    const s = await honest();
    const id = keccak256(s.block.raws[2]);
    s.source.txs.set(id, { ...s.source.txs.get(id)!, from: Wallet.createRandom().address });
    const v = await verifyEvmPublication(s.input);
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_header_source_inconsistent');
  });

  it('a header source that fails → null, evm_header_source_unavailable', async () => {
    const s = await honest();
    s.source.canonicalBlock = async () => {
      throw new Error('ECONNREFUSED');
    };
    const v = await verifyEvmPublication(s.input);
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_header_source_unavailable');
  });

  it('a header source with no block at a height it calls final is inconsistent', async () => {
    const s = await honest();
    s.source.blocks.clear();
    const v = await verifyEvmPublication(s.input);
    expect(v.checks.canonical.reason).toBe('evm_header_source_inconsistent');
    expect(v.valid).toBeNull();
  });

  it('a source that no longer knows the transaction contradicts nothing when the trie proof placed it', async () => {
    const s = await honest();
    s.source.txs.clear();
    const v = await verifyEvmPublication(s.input);
    expect(v.valid).toBe(true);
    expect(v.facts.inclusion).toBe('tx_proof');
  });
});

// The finality a header source counts by is reported with the verdict it took
// part in: a result judged at a confirmation depth must never read as one
// judged at the finalized block.
describe('the finality the header source declares is reported with the verdict', () => {
  it('a true publication carries the source\'s finality as a fact, as a copy', async () => {
    const s = await honest();
    const declared: EvmFinality = { confirmations: 64 };
    const source = Object.assign(s.source, { finality: declared });
    const v = await verifyEvmPublication({ ...s.input, headerSources: { [SEPOLIA_CHAIN]: source } });
    expect(v.valid).toBe(true);
    expect(v.facts.finality).toEqual({ confirmations: 64 });
    declared.confirmations = 2;
    expect(v.facts.finality).toEqual({ confirmations: 64 });
  });

  it('a block above the finalized height is not checked, and the result says what "finalized" meant', async () => {
    const s = await honest();
    s.source.finalized = s.input.publication.blockNumber - 1;
    const source = Object.assign(s.source, { finality: { confirmations: 2, acceptNonFinal: true } as EvmFinality });
    const v = await verifyEvmPublication({ ...s.input, headerSources: { [SEPOLIA_CHAIN]: source } });
    expect(v).toMatchObject({ valid: null, checks: { canonical: { reason: 'evm_block_not_finalized' } } });
    expect(v.facts.finality).toEqual({ confirmations: 2, acceptNonFinal: true });
  });

  it('RpcEvmHeaderSource declares its finality; a source that declares nothing, or nonsense, reports none', async () => {
    const s = await honest();
    const plain = await verifyEvmPublication(s.input);
    expect(plain.valid).toBe(true);
    expect(plain.facts).not.toHaveProperty('finality');
    for (const nonsense of [{ confirmations: 0 }, { confirmations: 1.5 }, 'latest', 7]) {
      const v = await verifyEvmPublication({
        ...s.input,
        headerSources: { [SEPOLIA_CHAIN]: Object.assign(s.source, { finality: nonsense as unknown as EvmFinality }) },
      });
      expect(v.valid).toBe(true);
      expect(v.facts).not.toHaveProperty('finality');
    }
    expect(new RpcEvmHeaderSource({} as never).finality).toBe('finalized');
  });

  it('a publication refused offline never consults the source, so it reports no finality', async () => {
    const s = await honest();
    const source = Object.assign(s.source, { finality: 'finalized' as EvmFinality });
    const v = await verifyEvmPublication({ ...s.input, p: randomP(), headerSources: { [SEPOLIA_CHAIN]: source } });
    expect(v).toMatchObject({ valid: false, reason: 'evm_calldata_mismatch' });
    expect(v.facts).not.toHaveProperty('finality');
  });
});

describe('one deadline for every header-source call', () => {
  const never = <T>() => new Promise<T>(() => {});
  const after = <T>(ms: number, value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(value), ms));

  it('a source that never answers → null, evm_header_source_timeout, at the deadline', async () => {
    const s = await honest();
    s.source.canonicalBlock = () => never();
    const started = Date.now();
    const v = await verifyEvmPublication({ ...s.input, timeoutMs: 50 });
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('evm_header_source_timeout');
  });

  it('is one deadline for the whole verification: calls each under it can sum past it', async () => {
    const s = await honest();
    const slow: EvmHeaderSource = {
      chainId: () => after(40, SEPOLIA),
      finalizedBlockNumber: () => after(40, s.source.finalized),
      canonicalBlock: (n) => after(40, s.source.blocks.get(n) ?? null),
      transaction: (id) => after(40, s.source.txs.get(id) ?? null),
    };
    const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
    const input = { ...s.input, publication: bare, headerSources: { [SEPOLIA_CHAIN]: slow } };
    expect((await verifyEvmPublication({ ...input, timeoutMs: 5_000 })).valid).toBe(true);
    const v = await verifyEvmPublication({ ...input, timeoutMs: 100 });
    expect(v.checks.canonical.reason).toBe('evm_header_source_timeout');
    expect(v.valid).toBeNull();
  });

  it('a lookup that times out never undoes a verified trie proof', async () => {
    const s = await honest();
    s.source.transaction = () => never();
    expect((await verifyEvmPublication({ ...s.input, timeoutMs: 50 })).valid).toBe(true);

    const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
    const v = await verifyEvmPublication({ ...s.input, publication: bare, timeoutMs: 50 });
    expect(v.checks.canonical.reason).toBe('evm_header_source_timeout');
  });

  it('a timeoutMs beyond what setTimeout can wait still waits for the answer', async () => {
    // Node runs a setTimeout longer than 2^31 - 1 ms after 1 ms.
    const s = await honest();
    const slow: EvmHeaderSource = {
      chainId: () => after(30, SEPOLIA),
      finalizedBlockNumber: () => after(30, s.source.finalized),
      canonicalBlock: (n) => after(30, s.source.blocks.get(n) ?? null),
      transaction: (id) => after(30, s.source.txs.get(id) ?? null),
    };
    for (const timeoutMs of [2 ** 31 - 1, 2 ** 31, Number.MAX_SAFE_INTEGER, 1e308]) {
      const v = await verifyEvmPublication({ ...s.input, headerSources: { [SEPOLIA_CHAIN]: slow }, timeoutMs });
      expect(v.valid).toBe(true);
    }
  });

  it('a nonsense timeoutMs falls back to the default rather than throwing', async () => {
    const s = await honest();
    for (const timeoutMs of [0, -1, NaN, Infinity, '30' as never]) {
      expect((await verifyEvmPublication({ ...s.input, timeoutMs })).valid).toBe(true);
    }
  });
});

describe('placing the transaction in the block', () => {
  it.each([0, 1, 2, 3])('verifies the trie proof at index %i of a four-transaction block', async (index) => {
    const s = await honest({ index });
    const v = await verifyEvmPublication({ ...s.input, headerSources: { [SEPOLIA_CHAIN]: headersOnly(s.source) } });
    expect(v.valid).toBe(true);
    expect(v.facts.inclusion).toBe('tx_proof');
  });

  it('verifies at index 200, where the trie key is two bytes', async () => {
    const p = randomP();
    const publisher = Wallet.createRandom();
    const filler = await signAnchorTx(Wallet.createRandom(), { data: randomP() });
    const raws = Array.from({ length: 200 }, () => filler);
    raws.push(await signAnchorTx(publisher, { data: p }));
    const block = fabricateBlock(raws);
    const v = await verifyEvmPublication({
      publication: publicationFrom(block, 200),
      p,
      anchorOrigin: ORIGIN,
      manifest: manifestOf(entry(publisher)),
      headerSources: { [SEPOLIA_CHAIN]: headersOnly(new FakeHeaderSource(block)) },
    });
    expect(v.valid).toBe(true);
  });

  it('without header and proof, the header source\'s own lookup places it', async () => {
    const s = await honest();
    const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
    const v = await verifyEvmPublication({ ...s.input, publication: bare });
    expect(v.valid).toBe(true);
    expect(v.facts.inclusion).toBe('header_source');
  });

  it('without header and proof, a headers-only source cannot place it → null, not_in_bundle:tx_proof', async () => {
    const s = await honest();
    const { blockHeader, txIndex, txProof, ...bare } = s.input.publication;
    const v = await verifyEvmPublication({
      ...s.input,
      publication: bare,
      headerSources: { [SEPOLIA_CHAIN]: headersOnly(s.source) },
    });
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.canonical.reason).toBe('not_in_bundle:tx_proof');
  });

  it('a proof without its header is not walked: only the header source can place the transaction', async () => {
    const s = await honest();
    const { blockHeader, ...noHeader } = s.input.publication;
    const withJunkProof = { ...noHeader, txProof: ['0xdead'] };
    const byLookup = await verifyEvmPublication({ ...s.input, publication: withJunkProof });
    expect(byLookup.valid).toBe(true);
    expect(byLookup.facts.inclusion).toBe('header_source');

    const headersOnlyVerdict = await verifyEvmPublication({
      ...s.input,
      publication: withJunkProof,
      headerSources: { [SEPOLIA_CHAIN]: headersOnly(s.source) },
    });
    expect(headersOnlyVerdict).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(headersOnlyVerdict.checks.canonical.reason).toBe('not_in_bundle:block_header');
  });

  it('binds the proof to its index at a leaf: proof(1) does not prove index 2 in a two-transaction block', () => {
    const values = ['0x' + 'aa'.repeat(40), '0x' + 'bb'.repeat(40)];
    const trie = buildTxTrie(values);
    expect(verifyEvmTransactionProof(trie.root, 1, trie.proof(1))).toBe(values[1]);
    expect(verifyEvmTransactionProof(trie.root, 2, trie.proof(1))).toBeNull();
    expect(verifyEvmTransactionProof(trie.root, 0, trie.proof(1))).toBeNull();
  });

  it('binds the proof to its index through an extension node (a 300-transaction block)', () => {
    // Keys 256..299 are rlp(i) = 0x82 0x01 0x00..0x2b, so under nibbles 8, 2
    // they share the extension [0, 1]. Key 512 is 0x82 0x02 0x00: it
    // diverges inside that extension.
    const values = Array.from({ length: 300 }, (_v, i) => '0x' + i.toString(16).padStart(4, '0') + 'cc'.repeat(38));
    const trie = buildTxTrie(values);
    const proof = trie.proof(256);
    const nodes = proof.map((n) => decodeRlp(n) as RlpStructuredData[]);
    const extension = nodes.find((n) => n.length === 2 && parseInt((n[0] as string).slice(2, 3), 16) < 2);
    expect(extension).toBeDefined();
    expect(verifyEvmTransactionProof(trie.root, 256, proof)).toBe(values[256]);
    expect(verifyEvmTransactionProof(trie.root, 512, proof)).toBeNull();
    expect(verifyEvmTransactionProof(trie.root, 257, proof)).toBeNull();
  });

  it('walks nodes embedded in their parent (a trie of values under 32 bytes)', () => {
    // Transaction values are never this small, so this only reaches the
    // embedded-node branch of the walker through the proof function itself.
    const values = Array.from({ length: 20 }, (_v, i) => '0x' + (i + 1).toString(16).padStart(2, '0'));
    const trie = buildTxTrie(values);
    values.forEach((value, i) => {
      const proof = trie.proof(i);
      expect(verifyEvmTransactionProof(trie.root, i, proof)).toBe(value);
      expect(verifyEvmTransactionProof(trie.root, i === 0 ? 1 : 0, proof)).not.toBe(value);
    });
    // At least one proof is shorter than the path it walks, so nodes were embedded.
    expect(values.some((_v, i) => trie.proof(i).length < 3)).toBe(true);
  });

  it('a transaction id that is not keccak256(raw) → evm_tx_proof_invalid', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({
      ...s.input,
      publication: { ...s.input.publication, transactionId: keccak256(s.block.raws[0]) },
    });
    expect(v).toMatchObject({ valid: false, reason: 'evm_tx_proof_invalid' });
  });

  it('a header that does not hash to the block hash → evm_tx_proof_invalid', async () => {
    const s = await honest();
    const other = fabricateBlock(s.block.raws, s.block.number, s.block.timestamp + 12);
    const v = await verifyEvmPublication({ ...s.input, publication: { ...s.input.publication, blockHeader: other.header } });
    expect(v).toMatchObject({ valid: false, reason: 'evm_tx_proof_invalid' });
  });

  it('a header for another block number → evm_tx_proof_invalid', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, publication: { ...s.input.publication, blockNumber: s.block.number + 1 } });
    expect(v).toMatchObject({ valid: false, reason: 'evm_tx_proof_invalid' });
  });

  it('a tampered trie node → evm_tx_proof_invalid', async () => {
    const s = await honest();
    const proof = [...s.input.publication.txProof!];
    const last = proof.length - 1;
    // Flip one nibble inside the last node.
    const at = proof[last].length - 10;
    proof[last] = proof[last].slice(0, at) + (proof[last][at] === '0' ? '1' : '0') + proof[last].slice(at + 1);
    const v = await verifyEvmPublication({ ...s.input, publication: { ...s.input.publication, txProof: proof } });
    expect(v).toMatchObject({ valid: false, reason: 'evm_tx_proof_invalid' });
  });

  it("another transaction's proof → evm_tx_proof_invalid", async () => {
    const s = await honest();
    const v = await verifyEvmPublication({
      ...s.input,
      publication: { ...s.input.publication, txIndex: 1, txProof: s.block.trie.proof(1) },
    });
    expect(v).toMatchObject({ valid: false, reason: 'evm_tx_proof_invalid' });
  });

  it('a proof with an unused node appended → evm_tx_proof_invalid', async () => {
    const s = await honest();
    const proof = [...s.input.publication.txProof!, s.input.publication.txProof![0]];
    const v = await verifyEvmPublication({ ...s.input, publication: { ...s.input.publication, txProof: proof } });
    expect(v).toMatchObject({ valid: false, reason: 'evm_tx_proof_invalid' });
  });
});

describe('transaction types', () => {
  it.each([
    [0, 'legacy with EIP-155'],
    [1, 'EIP-2930'],
    [2, 'EIP-1559'],
  ] as const)('type %i (%s) verifies end to end', async (type, _label) => {
    const s = await honest({ type });
    const v = await verifyEvmPublication(s.input);
    expect(v.valid).toBe(true);
    expect(v.facts.txType).toBe(type);
    expect(v.facts.sender).toBe(s.publisher.address.toLowerCase());
  });

  it.each([0, 1, 2] as const)('type %i from a foreign sender → evm_sender_mismatch', async (type) => {
    const s = await honest();
    const forged = await signAnchorTx(Wallet.createRandom(), { data: s.p, type, to: s.publisher.address });
    const block = fabricateBlock([forged]);
    const v = await verifyEvmPublication({
      ...s.input,
      publication: publicationFrom(block, 0),
      headerSources: { [SEPOLIA_CHAIN]: new FakeHeaderSource(block) },
    });
    expect(v).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
  });
});

describe('never throws on malformed input', () => {
  const MALFORMED = [false, 'malformed_publication'] as const;
  const garbage: Array<[string, (s: Scenario) => unknown, boolean | null, string]> = [
    ['a null publication', () => null, ...MALFORMED],
    ['a string publication', () => 'evm-calldata/1', ...MALFORMED],
    ['an array publication', () => [], ...MALFORMED],
    ['a missing kind', (s) => ({ ...s.input.publication, kind: undefined }), null, 'unsupported_publication_kind'],
    ['raw that is not hex', (s) => ({ ...s.input.publication, rawTransaction: 'not hex' }), ...MALFORMED],
    ['raw that is odd-length hex', (s) => ({ ...s.input.publication, rawTransaction: '0x02f' }), ...MALFORMED],
    ['raw that is truncated', (s) => ({ ...s.input.publication, rawTransaction: s.block.raws[2].slice(0, 40) }), ...MALFORMED],
    ['raw that is an unsigned transaction', (s) => ({
      ...s.input.publication,
      rawTransaction: Transaction.from(s.block.raws[2]).unsignedSerialized,
    }), ...MALFORMED],
    ['raw of 0x', (s) => ({ ...s.input.publication, rawTransaction: '0x' }), ...MALFORMED],
    ['raw whose first byte is neither a type nor a list', (s) => ({ ...s.input.publication, rawTransaction: '0x90' + s.block.raws[2].slice(4) }), ...MALFORMED],
    ['raw of a transaction type no one defines yet', (s) => ({ ...s.input.publication, rawTransaction: '0x05' + s.block.raws[2].slice(4) }), null, 'unsupported_evm_tx_type'],
    ['a short block hash', (s) => ({ ...s.input.publication, blockHash: '0x1234' }), ...MALFORMED],
    ['a negative block number', (s) => ({ ...s.input.publication, blockNumber: -1 }), ...MALFORMED],
    ['a string block number', (s) => ({ ...s.input.publication, blockNumber: '7123456' }), ...MALFORMED],
    ['a fractional block number', (s) => ({ ...s.input.publication, blockNumber: 1.5 }), ...MALFORMED],
    ['a proof that is not an array', (s) => ({ ...s.input.publication, txProof: 'nodes' }), ...MALFORMED],
    ['a proof of non-hex nodes', (s) => ({ ...s.input.publication, txProof: ['zz'] }), ...MALFORMED],
    ['an empty proof', (s) => ({ ...s.input.publication, txProof: [] }), ...MALFORMED],
    ['a proof with no index', (s) => ({ ...s.input.publication, txIndex: undefined }), ...MALFORMED],
    ['a header that does not hash to the block hash', (s) => ({ ...s.input.publication, blockHeader: '0xdeadbeef' }), false, 'evm_tx_proof_invalid'],
    ['a transaction id that is not hex', (s) => ({ ...s.input.publication, transactionId: 42 }), ...MALFORMED],
  ];

  it.each(garbage)('%s → %s, %s', async (_label, make, valid, reason) => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, publication: make(s) as never });
    expect(v.valid).toBe(valid);
    expect(v.reason).toBe(reason);
  });

  it('a header that hashes to the block hash but is not a header → evm_tx_proof_invalid', async () => {
    const s = await honest();
    for (const junk of ['0xdeadbeef', encodeRlp(['0x01', '0x02']), encodeRlp(new Array(15).fill(['0x01']))]) {
      const v = await verifyEvmPublication({
        ...s.input,
        publication: { ...s.input.publication, blockHeader: junk, blockHash: keccak256(junk) },
      });
      expect(v).toMatchObject({ valid: false, reason: 'evm_tx_proof_invalid' });
    }
  });

  it('null reads as absent for every optional field', async () => {
    const s = await honest();
    const nulls = { transactionId: null, blockHeader: null, txIndex: null, txProof: null, chain: null, publisher: null };
    const v = await verifyEvmPublication({ ...s.input, publication: { ...s.input.publication, ...nulls } as never });
    expect(v.valid).toBe(true);
    expect(v.facts.inclusion).toBe('header_source');
  });

  it('an unreadable publication is checked-wrong, never pending', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, publication: { ...s.input.publication, rawTransaction: '0xzz' } });
    expect(v).toMatchObject({ valid: false, reason: 'malformed_publication' });
  });

  it('a publication with no raw transaction is not checked', async () => {
    const s = await honest();
    const { rawTransaction, ...rest } = s.input.publication;
    const v = await verifyEvmPublication({ ...s.input, publication: rest });
    expect(v).toMatchObject({ valid: null, reason: 'publication_not_checked' });
    expect(v.checks.tx.reason).toBe('not_in_bundle:raw_transaction');
  });

  it.each([
    ['a null manifest', null],
    ['publishers that is not an object', { publishers: 'x' }],
    ['entries that are not an array', { publishers: { [ORIGIN]: 'x' } }],
    ['an entry with a bad address', { publishers: { [ORIGIN]: [{ address: '0x12', chain: SEPOLIA_CHAIN, namespace: 'test' }] } }],
    ['an entry with a bad namespace', { publishers: { [ORIGIN]: [{ address: '0x' + '11'.repeat(20), chain: SEPOLIA_CHAIN, namespace: 'prod' }] } }],
    ['an entry with a bad date', { publishers: { [ORIGIN]: [{ address: '0x' + '11'.repeat(20), chain: SEPOLIA_CHAIN, namespace: 'test', validUntil: 'soon' }] } }],
    ['an entry with a leading-zero chain id', { publishers: { [ORIGIN]: [{ address: '0x' + '11'.repeat(20), chain: 'eip155:011155111', namespace: 'test' }] } }],
  ])('%s → null, never true, never a throw', async (_label, manifest) => {
    const s = await honest();
    const v = await verifyEvmPublication({ ...s.input, manifest: manifest as never });
    expect(v.valid).toBeNull();
  });

  it('skips entries for non-EVM chains rather than failing the manifest', async () => {
    const s = await honest();
    const v = await verifyEvmPublication({
      ...s.input,
      manifest: manifestOf({ address: 'x', chain: 'bip122:000000000019d6689c085ae165831e93', namespace: 'test' }, entry(s.publisher)),
    });
    expect(v.valid).toBe(true);
  });

  it('a header source returning junk is unavailable, not a verdict', async () => {
    const s = await honest();
    s.source.canonicalBlock = async () => ({ hash: 'nope', timestamp: NaN }) as never;
    const v = await verifyEvmPublication(s.input);
    expect(v.valid).toBeNull();
    expect(v.checks.canonical.reason).toBe('evm_header_source_unavailable');
  });

  it('survives an undefined input', async () => {
    await expect(verifyEvmPublication(undefined as never)).resolves.toMatchObject({ valid: false });
  });
});

/** `depth` lists, each holding the next, the innermost empty, built without recursion. */
function nestedLists(depth: number): Uint8Array {
  const prefixes: number[][] = [];
  let length = 1;
  for (let d = 1; d < depth; d++) {
    const prefix = length <= 55 ? [0xc0 + length] : [0xf7 + byteLength(length), ...bigEndian(length)];
    prefixes.push(prefix);
    length += prefix.length;
  }
  return Uint8Array.from([...prefixes.reverse().flat(), 0xc0]);
}

function byteLength(n: number): number {
  return bigEndian(n).length;
}

function bigEndian(n: number): number[] {
  const out: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
  return out;
}

/** An RLP list of items already encoded. */
function listOf(items: Uint8Array[]): string {
  const payload = Buffer.concat(items);
  const n = payload.length;
  const prefix = n <= 55 ? [0xc0 + n] : [0xf7 + byteLength(n), ...bigEndian(n)];
  return '0x' + Buffer.concat([Buffer.from(prefix), payload]).toString('hex');
}

describe('RLP nests at most MAX_RLP_DEPTH lists deep, whatever the stack', () => {
  // ethers' decodeRlp recurses once per level, so on its own it gives up where
  // the host's stack runs out: about 3,000 levels in Node, sooner in a browser.
  const hex = (b: Uint8Array) => '0x' + Buffer.from(b).toString('hex');

  it('decodes MAX_RLP_DEPTH lists and refuses one more, at any depth', () => {
    expect(MAX_RLP_DEPTH).toBe(64);
    expect(() => decodeEvmRlp(hex(nestedLists(MAX_RLP_DEPTH)))).not.toThrow();
    for (const depth of [MAX_RLP_DEPTH + 1, 1_000, 3_000, 20_000]) {
      expect(() => decodeEvmRlp(hex(nestedLists(depth)))).toThrow('RLP lists nested too deep');
    }
  });

  it('a header whose unread first field nests too deep is not a header', () => {
    const fields = (decodeRlp(sepoliaVector.header) as string[]).map((f) => getBytesOf(encodeRlp(f)));
    const withFirst = (first: Uint8Array) => listOf([first, ...fields.slice(1)]);
    // The header's own list is one level: its first field may nest 63 more.
    expect(parseEvmBlockHeader(withFirst(nestedLists(MAX_RLP_DEPTH - 1)))).not.toBeNull();
    for (const depth of [MAX_RLP_DEPTH, 1_000, 3_000, 20_000]) {
      expect(parseEvmBlockHeader(withFirst(nestedLists(depth)))).toBeNull();
    }
  });

  it("a trie node that nests too deep off the key's path proves nothing", () => {
    // A branch node whose slot 8 holds an embedded leaf for key rlp(0) = 0x80
    // (nibbles 8, 0) and whose slot 3 holds nested lists the walk never reads.
    const leaf = getBytesOf(encodeRlp(['0x30', '0xabcd']));
    const branch = (junk: Uint8Array) => {
      const slots = Array.from({ length: 17 }, () => getBytesOf(encodeRlp('0x')));
      slots[3] = junk;
      slots[8] = leaf;
      return listOf(slots);
    };
    const shallow = branch(nestedLists(MAX_RLP_DEPTH - 1));
    expect(verifyEvmTransactionProof(keccak256(shallow), 0, [shallow])).toBe('0xabcd');
    for (const depth of [MAX_RLP_DEPTH, 1_000, 3_000]) {
      const deep = branch(nestedLists(depth));
      expect(verifyEvmTransactionProof(keccak256(deep), 0, [deep])).toBeNull();
    }
  });
});

function getBytesOf(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex.slice(2), 'hex'));
}

describe('a real Sepolia block (tests/ts/fixtures/evm-sepolia-block.json)', () => {
  // Fetched once from a public node; see the fixture's `source`. It pins the
  // header layout and the trie walk against real chain data, and the trie
  // builder in src/anchoring/tx-trie.ts reproduced this block's
  // transactionsRoot from all of its transactions.
  const v = sepoliaVector;

  it('reads the header: hash, number, timestamp, transactionsRoot', () => {
    expect(parseEvmBlockHeader(v.header)).toEqual({
      hash: v.blockHash,
      number: v.blockNumber,
      timestamp: v.timestamp,
      transactionsRoot: v.transactionsRoot,
    });
  });

  it.each(v.transactions.map((t) => [t.index, t.type, t]))(
    'proves transaction %i (type %i) under transactionsRoot, and recovers its sender',
    (_i, _type, t) => {
      const tx = t as (typeof v.transactions)[number];
      expect(verifyEvmTransactionProof(v.transactionsRoot, tx.index, tx.proof)).toBe(tx.raw);
      expect(verifyEvmTransactionProof(v.transactionsRoot, tx.index + 1, tx.proof)).toBeNull();
      const parsed = Transaction.from(tx.raw);
      expect(parsed.from).toBe(tx.sender);
      expect(parsed.chainId).toBe(SEPOLIA);
    },
  );

  it('verifies a real anchor-shaped Sepolia transaction end to end (evm-sepolia-self-tx.json)', async () => {
    // A zero-value self-transaction whose calldata is exactly 32 bytes, at
    // index 175 of a 222-transaction block: the shape a Tzun anchor takes.
    // Its sender stands in for a manifest publisher; the fake header source
    // stands in for the auditor's node, confirming the real block hash.
    const w = sepoliaSelfTx;
    const tx = w.transactions[0];
    const parsed = Transaction.from(tx.raw);
    expect(parsed.to).toBe(parsed.from);
    expect(parsed.value).toBe(0n);
    const source = new FakeHeaderSource();
    source.finalized = w.blockNumber + 64;
    source.blocks.set(w.blockNumber, { hash: w.blockHash, timestamp: w.timestamp });
    const input: EvmPublicationInput = {
      publication: {
        kind: 'evm-calldata/1',
        transactionId: parsed.hash!,
        rawTransaction: tx.raw,
        blockNumber: w.blockNumber,
        blockHash: w.blockHash,
        blockHeader: w.header,
        txIndex: tx.index,
        txProof: tx.proof,
      },
      p: parsed.data,
      anchorOrigin: ORIGIN,
      manifest: manifestOf({ address: tx.sender, chain: SEPOLIA_CHAIN, namespace: 'test' }),
      headerSources: { [SEPOLIA_CHAIN]: headersOnly(source) },
    };

    const v = await verifyEvmPublication(input);
    expect(v.valid).toBe(true);
    expect(v.facts).toMatchObject({
      inclusion: 'tx_proof',
      network: 'testnet',
      blockTime: new Date(w.timestamp * 1000).toISOString(),
      sender: tx.sender.toLowerCase(),
    });

    // The same real transaction, with a stranger as the manifest's publisher.
    const stranger = await verifyEvmPublication({ ...input, manifest: manifestOf(entry(Wallet.createRandom())) });
    expect(stranger).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
    // And offline, with no header source.
    const offline = await verifyEvmPublication({ ...input, headerSources: undefined });
    expect(offline).toMatchObject({ valid: null, reason: 'publication_not_checked' });
  });

  it('verifies a real legacy EIP-155 transaction up to the calldata check', async () => {
    const tx = v.transactions.find((t) => t.type === 0)!;
    const pub = {
      kind: 'evm-calldata/1' as const,
      rawTransaction: tx.raw,
      blockNumber: v.blockNumber,
      blockHash: v.blockHash,
      blockHeader: v.header,
      txIndex: tx.index,
      txProof: tx.proof,
    };
    // Its calldata is not a 32-byte P, so this ends at the calldata check,
    // after the transaction parsed and before anything else could pass.
    const verdict = await verifyEvmPublication({
      publication: pub,
      p: randomP(),
      anchorOrigin: ORIGIN,
      manifest: manifestOf({ address: tx.sender, chain: SEPOLIA_CHAIN, namespace: 'test' }),
    });
    expect(verdict).toMatchObject({ valid: false, reason: 'evm_calldata_mismatch' });
    expect(verdict.facts.sender).toBe(tx.sender.toLowerCase());
  });

  it('reads only fields 4, 8 and 11, whatever shape the others take', () => {
    const fields = decodeRlpList(v.header);
    const withList = [...fields];
    withList[20] = ['0x01', '0x02']; // a field a later fork might make a list
    expect(parseEvmBlockHeader(encodeRlp(withList))).toMatchObject({
      number: v.blockNumber,
      timestamp: v.timestamp,
      transactionsRoot: v.transactionsRoot,
    });
    const badRoot = [...fields];
    badRoot[4] = [fields[4] as string];
    expect(parseEvmBlockHeader(encodeRlp(badRoot))).toBeNull();
    const paddedNumber = [...fields];
    paddedNumber[8] = '0x00' + (fields[8] as string).slice(2);
    expect(parseEvmBlockHeader(encodeRlp(paddedNumber))).toBeNull();
    expect(parseEvmBlockHeader(encodeRlp(fields.slice(0, 14)))).toBeNull();
    expect(parseEvmBlockHeader('0x')).toBeNull();
  });
});

describe('RpcEvmHeaderSource', () => {
  async function node(opts: { head: number; finalized: number; withSend?: boolean; type?: 0 | 1 | 2 }) {
    const publisher = Wallet.createRandom();
    const raw = await signAnchorTx(publisher, { data: randomP(), type: opts.type });
    const t = Transaction.from(raw);
    const block = fabricateBlock([raw], opts.head - 10);
    const provider: AnchorTransactionProvider = {
      async getNetwork() {
        return { chainId: SEPOLIA };
      },
      async getBlockNumber() {
        return opts.head;
      },
      async getBlock(tag) {
        if (tag === 'finalized') return { number: opts.finalized, hash: '0x' + 'ab'.repeat(32), timestamp: 0 };
        return tag === block.number ? { number: block.number, hash: block.hash, timestamp: block.timestamp } : null;
      },
      async getTransaction(hash) {
        if (hash !== t.hash) return null;
        return {
          hash: t.hash!,
          from: t.from!,
          blockHash: block.hash,
          blockNumber: block.number,
          type: t.type!,
          to: t.to,
          nonce: t.nonce,
          gasLimit: t.gasLimit,
          // For EIP-1559 a node reports the effective price, not a signed field.
          gasPrice: t.type === 2 ? 2_500_000_000n : t.gasPrice,
          maxPriorityFeePerGas: t.maxPriorityFeePerGas,
          maxFeePerGas: t.maxFeePerGas,
          data: t.data,
          value: t.value,
          chainId: t.chainId,
          signature: t.signature,
          accessList: t.accessList,
        };
      },
    };
    if (opts.withSend) provider.send = async (method) => (method === 'eth_chainId' ? '0x1' : null);
    return { provider, raw, t, block };
  }

  it("uses the node's finalized tag by default", async () => {
    const { provider } = await node({ head: 1000, finalized: 936 });
    expect(await new RpcEvmHeaderSource(provider).finalizedBlockNumber()).toBe(936);
  });

  it('or a confirmation depth, counting the block itself', async () => {
    const { provider } = await node({ head: 1000, finalized: 936 });
    const deep = new RpcEvmHeaderSource(provider, { finality: { confirmations: 64 } });
    expect(deep.finality).toEqual({ confirmations: 64 });
    expect(await deep.finalizedBlockNumber()).toBe(937);
    const shallow = new RpcEvmHeaderSource(provider, { finality: { confirmations: 12, acceptNonFinal: true } });
    expect(shallow.finality).toEqual({ confirmations: 12, acceptNonFinal: true });
    expect(await shallow.finalizedBlockNumber()).toBe(989);
    expect(new RpcEvmHeaderSource(provider).finality).toBe('finalized');
  });

  it(`refuses a depth below ${EVM_MIN_FINAL_CONFIRMATIONS} unless it accepts a non-final block, and a depth that is not a positive integer`, async () => {
    const { provider } = await node({ head: 1000, finalized: 936 });
    expect(() => new RpcEvmHeaderSource(provider, { finality: { confirmations: 12 } })).toThrow(/acceptNonFinal/);
    expect(() => new RpcEvmHeaderSource(provider, { finality: { confirmations: 63 } })).toThrow(/below 64/);
    for (const confirmations of [0, -3, 2.5]) {
      expect(() => new RpcEvmHeaderSource(provider, { finality: { confirmations, acceptNonFinal: true } })).toThrow(/positive integer/);
    }
    expect(() => new RpcEvmHeaderSource(provider, { finality: 'latest' as never })).toThrow(/finality/);
  });

  it('keeps the finality it was built with when the caller changes its object', async () => {
    const { provider } = await node({ head: 1000, finalized: 936 });
    const finality = { confirmations: 64 };
    const source = new RpcEvmHeaderSource(provider, { finality });
    finality.confirmations = 1;
    expect(await source.finalizedBlockNumber()).toBe(937);
  });

  it.each([0, 1, 2] as const)('reassembles a type %i signed envelope from what the node reports', async (type) => {
    const { provider, raw, t } = await node({ head: 1000, finalized: 936, type });
    const seen = await new RpcEvmHeaderSource(provider).transaction(t.hash!);
    expect(seen).toMatchObject({ from: t.from, rawTransaction: raw });
    expect(await new RpcEvmHeaderSource(provider).transaction('0x' + '00'.repeat(32))).toBeNull();
  });

  it('asks the node for its chain id with eth_chainId when it can', async () => {
    const { provider } = await node({ head: 1000, finalized: 936, withSend: true });
    expect(await new RpcEvmHeaderSource(provider).chainId()).toBe(1n);
  });

  it('drives the verifier: final → true; not yet final → null', async () => {
    const final = await node({ head: 1000, finalized: 995 });
    const p = final.t.data;
    const input = (source: EvmHeaderSource): EvmPublicationInput => ({
      publication: publicationFrom(final.block, 0),
      p,
      anchorOrigin: ORIGIN,
      manifest: manifestOf(entry({ address: final.t.from! })),
      headerSources: { [SEPOLIA_CHAIN]: source },
    });
    expect((await verifyEvmPublication(input(new RpcEvmHeaderSource(final.provider)))).valid).toBe(true);

    const early = new RpcEvmHeaderSource(final.provider, { finality: { confirmations: 64 } });
    const v = await verifyEvmPublication(input(early));
    expect(v.valid).toBeNull();
    expect(v.checks.canonical.reason).toBe('evm_block_not_finalized');
  });
});
