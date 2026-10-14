/**
 * `EthereumAnchorVerifier`: confirms a 32-byte value was published, by a
 * configured publisher, in a finalized block (Anchor §10.4).
 *
 * No mocks of ethers and no network. Transactions are really signed by
 * throwaway keys; the node is either a fake `AnchorTransactionProvider` or,
 * for the round trip, a loopback JSON-RPC node that real ethers talks to.
 */
import { Transaction, Wallet } from 'ethers';
import {
  EthereumAnchorVerifier,
  EvmPublicationNotCheckedError,
  EVM_MIN_FINAL_CONFIRMATIONS,
  type AnchorTransactionProvider,
  type EthereumAnchorVerifierConfig,
  type EvmPublicationReason,
} from '../../src/attestation/blockchain';
import { merkleLeafHash } from '../../src/attestation/merkle';
import { FakeEvmNode, publishOverRpc } from './helpers/evm-fake-node';
import { SEPOLIA, fabricateBlock, randomP, signAnchorTx, type FabricatedBlock } from './helpers/evm-fixtures';

const rpcUrls = { 'ethereum-sepolia': 'https://rpc.example' };

/**
 * A node that has mined `raws` into one block and reports `finalized` as its
 * finalized height. `getTransaction` answers the way ethers'
 * `TransactionResponse` does: signed fields plus `from`, `hash` and the block.
 */
function nodeWith(
  raws: string[],
  opts: {
    finalizedDepth?: number;
    chainId?: bigint;
    pending?: boolean;
    canonicalHash?: string;
    /** What the node reports as the transaction's block hash, in place of the block's. */
    reportedBlockHash?: string;
  } = {},
) {
  const block: FabricatedBlock = fabricateBlock(raws);
  const provider: AnchorTransactionProvider = {
    async getNetwork() {
      return { chainId: opts.chainId ?? SEPOLIA };
    },
    async getBlockNumber() {
      return block.number + 100;
    },
    async getBlock(tag) {
      if (tag === 'finalized') return { number: block.number + (opts.finalizedDepth ?? 36), hash: '0x' + 'ab'.repeat(32), timestamp: 0 };
      return tag === block.number ? { number: block.number, hash: opts.canonicalHash ?? block.hash, timestamp: block.timestamp } : null;
    },
    async getTransaction(hash) {
      const raw = raws.find((r) => Transaction.from(r).hash === hash);
      if (!raw) return null;
      const t = Transaction.from(raw);
      return {
        hash: t.hash!,
        from: t.from!,
        blockHash: opts.pending ? null : (opts.reportedBlockHash ?? block.hash),
        blockNumber: opts.pending ? null : block.number,
        type: t.type!,
        to: t.to,
        nonce: t.nonce,
        gasLimit: t.gasLimit,
        gasPrice: t.gasPrice ?? t.maxFeePerGas,
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
  return { block, provider };
}

function verifierFor(
  publisher: { address: string },
  provider: AnchorTransactionProvider,
  extra: Partial<EthereumAnchorVerifierConfig> = {},
) {
  return new EthereumAnchorVerifier({
    rpcUrls,
    publishers: [{ address: publisher.address, chain: 'eip155:11155111', namespace: 'test' }],
    providerFor: () => provider,
    ...extra,
  });
}

describe('a foreign sender to the publisher address', () => {
  it('rejects a transaction from a foreign sender sent TO the publisher address with the right calldata', async () => {
    // The attacker signs a transaction TO the publisher's address carrying the
    // root. A check on `tx.to` confirms it; only the recovered sender tells
    // the two apart.
    const publisher = Wallet.createRandom();
    const attacker = Wallet.createRandom();
    const p = randomP();
    const forged = await signAnchorTx(attacker, { to: publisher.address, data: p });
    const { provider } = nodeWith([forged]);

    const res = await verifierFor(publisher, provider).verifyAnchor({
      chain: 'ethereum-sepolia',
      transactionId: Transaction.from(forged).hash!,
      p: p.slice(2),
    });

    expect(res.confirmed).toBe(false);
    expect(res.reason).toBe('evm_sender_mismatch');
    expect(res.publication).toMatchObject({ valid: false, reason: 'evm_sender_mismatch' });
    expect(res.publication!.facts.sender).toBe(attacker.address.toLowerCase());
  });
});

describe('EthereumAnchorVerifier reads the root back off the chain', () => {
  let publisher: ReturnType<typeof Wallet.createRandom>;
  let p: string;
  let raw: string;
  let txId: string;

  beforeEach(async () => {
    publisher = Wallet.createRandom();
    p = randomP();
    raw = await signAnchorTx(publisher, { data: p });
    txId = Transaction.from(raw).hash!;
  });

  it("confirms the publisher's transaction carrying the root once it is final", async () => {
    const { provider } = nodeWith([raw]);
    const res = await verifierFor(publisher, provider).verifyAnchor({
      chain: 'ethereum-sepolia',
      transactionId: txId,
      p: p.slice(2),
    });
    expect(res.confirmed).toBe(true);
    expect(res.reason).toBeUndefined();
    expect(res.publication).toMatchObject({
      valid: true,
      facts: { chain: 'eip155:11155111', network: 'testnet', namespace: 'test', inclusion: 'header_source' },
    });
  });

  it('rejects a transaction carrying a different root', async () => {
    const { provider } = nodeWith([raw]);
    const res = await verifierFor(publisher, provider).verifyAnchor({
      chain: 'ethereum-sepolia',
      transactionId: txId,
      p: randomP().slice(2),
    });
    expect(res.confirmed).toBe(false);
    expect(res.reason).toBe('evm_calldata_mismatch');
    expect(res.publication!.reason).toBe('evm_calldata_mismatch');
  });

  it('does not decide a transaction the node does not know: never mined and no longer indexed look the same', async () => {
    const { provider } = nodeWith([]);
    await expect(
      verifierFor(publisher, provider).verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) }),
    ).rejects.toThrow(/does not know transaction/);
  });

  it('rejects a transaction signed for another chain than the label names', async () => {
    const mainnet = await signAnchorTx(publisher, { data: p, chainId: 1n });
    const { provider } = nodeWith([mainnet]);
    const res = await verifierFor(publisher, provider).verifyAnchor({
      chain: 'ethereum-sepolia',
      transactionId: Transaction.from(mainnet).hash!,
      p: p.slice(2),
    });
    expect(res.confirmed).toBe(false);
    expect(res.publication!.reason).toBe('evm_chain_mismatch');
  });

  it('does not decide a block that is not final yet: throws, so the anchor reads unknown', async () => {
    const { provider } = nodeWith([raw], { finalizedDepth: -1 });
    const v = verifierFor(publisher, provider);
    const call = v.verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) });
    await expect(call).rejects.toBeInstanceOf(EvmPublicationNotCheckedError);
    await expect(
      v.verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) }),
    ).rejects.toMatchObject({
      verdict: { valid: null, reason: 'publication_not_checked', checks: { canonical: { reason: 'evm_block_not_finalized' } } },
    });
  });

  it('does not decide a transaction that is not in a block yet', async () => {
    const { provider } = nodeWith([raw], { pending: true });
    await expect(
      verifierFor(publisher, provider).verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) }),
    ).rejects.toThrow(/not in a block yet/);
  });

  it('does not decide against a node on another chain', async () => {
    const { provider } = nodeWith([raw], { chainId: 1n });
    await expect(
      verifierFor(publisher, provider).verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) }),
    ).rejects.toMatchObject({ verdict: { checks: { canonical: { reason: 'evm_header_source_chain_mismatch' } } } });
  });

  it.each([
    ['missing', undefined, /needs `publishers`/],
    ['empty', [], /needs `publishers`/],
    ['not an array', 'x', /needs `publishers`/],
    ['malformed', [{ address: '0x12', chain: 'eip155:11155111', namespace: 'test' }], /malformed entry/],
    ['an impossible date', [{ address: '0x' + '11'.repeat(20), chain: 'eip155:11155111', namespace: 'test', validUntil: '2026-09-31T00:00:00Z' }], /malformed entry/],
    ['no EVM chain', [{ address: 'x', chain: 'bip122:000000000019d6689c085ae165831e93', namespace: 'test' }], /no EVM/],
  ])('refuses publishers that are %s', (_label, publishers, message) => {
    const { provider } = nodeWith([raw]);
    expect(() => new EthereumAnchorVerifier({ rpcUrls, publishers: publishers as never, providerFor: () => provider })).toThrow(message);
  });

  it('refuses a timeoutMs that is not a positive number', () => {
    const { provider } = nodeWith([raw]);
    for (const timeoutMs of [0, -5, NaN]) {
      expect(() => verifierFor(publisher, provider, { timeoutMs })).toThrow(/timeoutMs/);
    }
  });

  it("does not decide when the node's lookup names a block the node does not call canonical", async () => {
    // A stale lookup index, a load-balanced backend, or a reorg between the
    // two reads. The block claim came from this node, not from an artifact.
    const { provider } = nodeWith([raw], { canonicalHash: '0x' + 'cd'.repeat(32) });
    const call = verifierFor(publisher, provider).verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) });
    await expect(call).rejects.toBeInstanceOf(EvmPublicationNotCheckedError);
    await expect(
      verifierFor(publisher, provider).verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) }),
    ).rejects.toMatchObject({
      verdict: { valid: null, reason: 'publication_not_checked', checks: { canonical: { reason: 'evm_header_source_inconsistent' } } },
    });
  });

  it('with a confirmation depth too, a node contradicting itself is undecided, not false', async () => {
    const { provider } = nodeWith([raw], { canonicalHash: '0x' + 'cd'.repeat(32) });
    await expect(
      verifierFor(publisher, provider, { finality: { confirmations: 1, acceptNonFinal: true } }).verifyAnchor({
        chain: 'ethereum-sepolia',
        transactionId: txId,
        p: p.slice(2),
      }),
    ).rejects.toBeInstanceOf(EvmPublicationNotCheckedError);
  });

  describe('deadline', () => {
    const never = <T>() => new Promise<T>(() => {});

    it('a node that never answers getBlock → throws at the deadline, undecided', async () => {
      const { provider } = nodeWith([raw]);
      provider.getBlock = () => never();
      const started = Date.now();
      await expect(
        verifierFor(publisher, provider, { timeoutMs: 100 }).verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) }),
      ).rejects.toMatchObject({ verdict: { checks: { canonical: { reason: 'evm_header_source_timeout' } } } });
      expect(Date.now() - started).toBeLessThan(1_000);
    });

    it('a node that never answers getTransaction → throws at the deadline', async () => {
      const { provider } = nodeWith([raw]);
      provider.getTransaction = () => never();
      await expect(
        verifierFor(publisher, provider, { timeoutMs: 100 }).verifyAnchor({ chain: 'ethereum-sepolia', transactionId: txId, p: p.slice(2) }),
      ).rejects.toThrow(/within 100 ms/);
    });
  });

  it('throws for an unconfigured chain so the result reads "unavailable", not "not anchored"', async () => {
    const { provider } = nodeWith([raw]);
    await expect(
      verifierFor(publisher, provider).verifyAnchor({ chain: 'ethereum-mainnet', transactionId: txId, p: p.slice(2) }),
    ).rejects.toThrow(/No RPC URL configured/);
  });

  it('throws for a chain label with no CAIP-2 mapping', async () => {
    const { provider } = nodeWith([raw]);
    const v = verifierFor(publisher, provider, { rpcUrls: { 'my-l2': 'https://rpc.example' } });
    await expect(
      v.verifyAnchor({ chain: 'my-l2', transactionId: txId, p: p.slice(2) }),
    ).rejects.toThrow(/No CAIP-2 chain configured/);
  });
});

describe('the verdict names its refusal and the finality it was judged under', () => {
  let publisher: ReturnType<typeof Wallet.createRandom>;
  let p: string;

  beforeEach(() => {
    publisher = Wallet.createRandom();
    p = randomP();
  });

  const claimFor = (raw: string, root = p) => ({
    chain: 'ethereum-sepolia',
    transactionId: Transaction.from(raw).hash!,
    p: root.slice(2),
  });

  // Every refusal EthereumAnchorVerifier can decide comes from the signed
  // transaction the node returned, which hashes to the claimed id. Each case
  // signs a transaction for a claim of `root`.
  type Refusal = (root: string) => Promise<{ raw: string; extra?: Partial<EthereumAnchorVerifierConfig> }>;
  const refusals: Array<[string, EvmPublicationReason, Refusal]> = [
    ['calldata other than the root', 'evm_calldata_mismatch', async () => ({ raw: await signAnchorTx(publisher, { data: randomP() }) })],
    [
      'a foreign sender, to the publisher address',
      'evm_sender_mismatch',
      async (root) => ({ raw: await signAnchorTx(Wallet.createRandom(), { data: root, to: publisher.address }) }),
    ],
    [
      'the publisher, after its entry ended',
      'evm_sender_mismatch',
      async (root) => ({
        raw: await signAnchorTx(publisher, { data: root }),
        extra: { publishers: [{ address: publisher.address, chain: 'eip155:11155111', namespace: 'test', validUntil: '2026-01-01T00:00:00Z' }] },
      }),
    ],
    ['a transaction signed for another chain', 'evm_chain_mismatch', async (root) => ({ raw: await signAnchorTx(publisher, { data: root, chainId: 1n }) })],
  ];

  it.each(refusals)('%s: the top-level reason is %s, never anchor_not_found_on_chain', async (_name, reason, make) => {
    const { raw, extra } = await make(p);
    const { provider } = nodeWith([raw]);
    const res = await verifierFor(publisher, provider, extra).verifyAnchor(claimFor(raw));
    expect(res).toMatchObject({ confirmed: false, reason, finality: 'finalized' });
    expect(res.publication!.reason).toBe(reason);
  });

  it.each(refusals)('%s: a record root read as P is refused with %s, the verdict and finality beside it', async (_name, reason, make) => {
    // A one-leaf tree's root, in the unprefixed form a record's Merkle root is
    // stored in: the reason a caller switches on is the publication's own.
    const root = merkleLeafHash('cd'.repeat(32));
    const { raw, extra } = await make('0x' + root);
    const { provider } = nodeWith([raw]);
    const res = await verifierFor(publisher, provider, extra).verifyAnchor({
      chain: 'ethereum-sepolia',
      transactionId: Transaction.from(raw).hash!,
      p: root,
    });
    expect(res.confirmed).toBe(false);
    expect(res.reason).toBe(reason);
    expect(res.reason).not.toBe('anchor_not_found_on_chain');
    expect(res.publication).toMatchObject({ valid: false, reason });
    expect(res.finality).toBe('finalized');
  });

  it('a node that reports an unusable block for the transaction leaves the anchor undecided, not malformed', async () => {
    const raw = await signAnchorTx(publisher, { data: p });
    const { provider } = nodeWith([raw], { reportedBlockHash: '0x1234' });
    const call = verifierFor(publisher, provider).verifyAnchor(claimFor(raw));
    await expect(call).rejects.toBeInstanceOf(EvmPublicationNotCheckedError);
    await expect(verifierFor(publisher, provider).verifyAnchor(claimFor(raw))).rejects.toMatchObject({
      verdict: { valid: null, reason: 'publication_not_checked', checks: { tx: { reason: 'evm_header_source_unavailable' } } },
      finality: 'finalized',
    });
  });

  it("reports the node's finalized tag as the finality of a confirmed anchor by default", async () => {
    const raw = await signAnchorTx(publisher, { data: p });
    const { provider } = nodeWith([raw]);
    expect(await verifierFor(publisher, provider).verifyAnchor(claimFor(raw))).toMatchObject({
      confirmed: true,
      finality: 'finalized',
    });
  });

  it(`refuses a confirmation depth below ${EVM_MIN_FINAL_CONFIRMATIONS} unless the caller accepts a non-final anchor`, async () => {
    expect(EVM_MIN_FINAL_CONFIRMATIONS).toBe(64);
    const raw = await signAnchorTx(publisher, { data: p });
    const { provider } = nodeWith([raw]);
    for (const confirmations of [1, 2, 12, 63]) {
      expect(() => verifierFor(publisher, provider, { finality: { confirmations } })).toThrow(/acceptNonFinal/);
    }
    // Only `true` opts in.
    expect(() =>
      verifierFor(publisher, provider, { finality: { confirmations: 2, acceptNonFinal: 'yes' as unknown as true } }),
    ).toThrow(/acceptNonFinal/);
    for (const confirmations of [0, -1, 1.5, NaN, 2 ** 53]) {
      expect(() => verifierFor(publisher, provider, { finality: { confirmations, acceptNonFinal: true } })).toThrow(
        /positive integer/,
      );
    }
    for (const finality of ['latest', 'safe', null, 64, {}]) {
      expect(() => verifierFor(publisher, provider, { finality: finality as never })).toThrow(/finality/);
    }
  });

  it('a depth at the floor is accepted, and the result says it was judged by depth', async () => {
    const raw = await signAnchorTx(publisher, { data: p });
    const { provider } = nodeWith([raw], { finalizedDepth: 64 });
    const res = await verifierFor(publisher, provider, { finality: { confirmations: 64 } }).verifyAnchor(claimFor(raw));
    expect(res).toMatchObject({ confirmed: true, finality: { confirmations: 64 } });
    expect(res.finality).toEqual({ confirmations: 64 });
  });

  it('a depth below the floor, accepted as non-final, is confirmed early and says so', async () => {
    // The block is 99 below the head but above the node's finalized height:
    // the finalized tag leaves it undecided, two confirmations confirm it.
    const raw = await signAnchorTx(publisher, { data: p });
    const { provider } = nodeWith([raw], { finalizedDepth: -1 });
    await expect(verifierFor(publisher, provider).verifyAnchor(claimFor(raw))).rejects.toMatchObject({
      verdict: { checks: { canonical: { reason: 'evm_block_not_finalized' } } },
      finality: 'finalized',
    });
    const early = verifierFor(publisher, provider, { finality: { confirmations: 2, acceptNonFinal: true } });
    const res = await early.verifyAnchor(claimFor(raw));
    expect(res).toMatchObject({ confirmed: true });
    expect(res.finality).toEqual({ confirmations: 2, acceptNonFinal: true });
    // The publication's own facts say the same.
    expect(res.publication.facts.finality).toEqual({ confirmations: 2, acceptNonFinal: true });

    // Each result carries its own copy: editing one changes neither the verifier nor the next result.
    (res.finality as { confirmations: number }).confirmations = 64;
    expect((await early.verifyAnchor(claimFor(raw))).finality).toEqual({ confirmations: 2, acceptNonFinal: true });
  });

  it('a refusal under a confirmation depth names the depth too', async () => {
    const raw = await signAnchorTx(publisher, { data: p, chainId: 1n });
    const { provider } = nodeWith([raw]);
    const res = await verifierFor(publisher, provider, { finality: { confirmations: 100 } }).verifyAnchor(claimFor(raw));
    expect(res).toEqual(expect.objectContaining({ confirmed: false, reason: 'evm_chain_mismatch', finality: { confirmations: 100 } }));
  });
});

describe('round trip over JSON-RPC: what a publisher broadcast is what the verifier reads back', () => {
  let node: FakeEvmNode;
  let url: string;

  beforeEach(async () => {
    node = new FakeEvmNode({ chainId: SEPOLIA, finalityLag: 8 });
    url = await node.start();
  });
  afterEach(() => node.stop());

  it('confirms the root once the block is final, and not before', async () => {
    // The auditor's position: a transaction hash, their own node, and the
    // publisher list. Not our database, and not our word for it.
    const key = Wallet.createRandom();
    const root = randomP().slice(2);
    const transactionId = await publishOverRpc(key.privateKey, url, root);

    const verifier = new EthereumAnchorVerifier({
      rpcUrls: { 'ethereum-sepolia': url },
      publishers: [{ address: key.address, chain: 'eip155:11155111', namespace: 'test' }],
    });
    const claim = { chain: 'ethereum-sepolia', transactionId, p: root };

    await expect(verifier.verifyAnchor(claim)).rejects.toMatchObject({
      verdict: { checks: { canonical: { reason: 'evm_block_not_finalized' } } },
    });

    node.mineEmpty(8);
    const res = await verifier.verifyAnchor(claim);
    expect(res.confirmed).toBe(true);
    expect(res.publication!.facts.sender).toBe(key.address.toLowerCase());

    // And the negative controls: a root the transaction does not carry, and a
    // publisher list that does not name the sender.
    const other = await verifier.verifyAnchor({ ...claim, p: randomP().slice(2) });
    expect(other.confirmed).toBe(false);
    expect(other.publication!.reason).toBe('evm_calldata_mismatch');

    const stranger = new EthereumAnchorVerifier({
      rpcUrls: { 'ethereum-sepolia': url },
      publishers: [{ address: Wallet.createRandom().address, chain: 'eip155:11155111', namespace: 'test' }],
    });
    const wrong = await stranger.verifyAnchor(claim);
    expect(wrong.confirmed).toBe(false);
    expect(wrong.publication!.reason).toBe('evm_sender_mismatch');
  }, 20_000);

  it('gives up at the deadline on a node that accepts the request and never answers', async () => {
    const key = Wallet.createRandom();
    const verifier = new EthereumAnchorVerifier({
      rpcUrls: { 'ethereum-sepolia': url },
      publishers: [{ address: key.address, chain: 'eip155:11155111', namespace: 'test' }],
      timeoutMs: 300,
    });
    node.hang = true;
    const started = Date.now();
    await expect(
      verifier.verifyAnchor({ chain: 'ethereum-sepolia', transactionId: '0x' + '12'.repeat(32), p: randomP().slice(2) }),
    ).rejects.toThrow();
    expect(Date.now() - started).toBeLessThan(3_000);
  }, 10_000);

  it('stops asking a rate-limiting node once the deadline has passed', async () => {
    // ethers retries a 429 every Retry-After (100 ms here) for up to 12
    // attempts, until its request expires. It checks expiry before waiting
    // out the delay, so one retry already scheduled can land just after the
    // deadline; none follows it. Without the request timeout the retries
    // would run on for about a second after the call gave up.
    const key = Wallet.createRandom();
    const verifier = new EthereumAnchorVerifier({
      rpcUrls: { 'ethereum-sepolia': url },
      publishers: [{ address: key.address, chain: 'eip155:11155111', namespace: 'test' }],
      timeoutMs: 300,
    });
    node.throttle = true;
    await expect(
      verifier.verifyAnchor({ chain: 'ethereum-sepolia', transactionId: '0x' + '12'.repeat(32), p: randomP().slice(2) }),
    ).rejects.toThrow();
    await new Promise((resolve) => setTimeout(resolve, 250));
    const settled = node.requests;
    expect(settled).toBeGreaterThan(0);
    expect(settled).toBeLessThan(12);
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    expect(node.requests).toBe(settled);
  }, 10_000);
});
