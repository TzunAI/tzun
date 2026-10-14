/**
 * The EVM chains the SDK anchors to:
 *
 *   - the anchor writer rebuilds a Glamsterdam header (EIP-7928's
 *     `blockAccessListHash`, EIP-7843's `slotNumber`), pinned to a real block
 *     of the Platåberget testnet (tests/ts/fixtures/evm-glamsterdam-block.json).
 *     A rebuild that stopped at `requestsHash` would not hash to the block
 *     hash, `blockMaterial()` would throw, and no publication on a
 *     Glamsterdam block would ever be filled;
 *   - the verifiers' registry knows the Hoodi test network, `eip155:560048`;
 *   - the tip a publication is signed with has a floor where a node can
 *     suggest none (Ethereum mainnet), and the node's suggestion is raised to
 *     the median tip recent blocks paid.
 */
import { Wallet, decodeRlp, keccak256, toBeHex } from 'ethers';
import glamsterdam from './fixtures/evm-glamsterdam-block.json';
import { JsonRpcEvmChain } from '../../src/anchoring/evm-chain';
import { blockHeaderRlp, type JsonRpcBlock } from '../../src/anchoring/tx-trie';
import {
  DEFAULT_MIN_PRIORITY_FEE_GWEI,
  minPriorityFeeWei,
  publicationFees,
  withPriorityFeeFloor,
} from '../../src/anchoring/governor';
import { DEFAULT_ANCHOR_BUDGET } from '../../src/anchoring/config';
import {
  DEFAULT_EVM_NETWORKS,
  EthereumAnchorVerifier,
  parseEvmBlockHeader,
  verifyEvmPublication,
  type AnchorTransactionProvider,
} from '../../src/attestation/blockchain';
import { fabricateBlock, publicationFrom } from './helpers/evm-fixtures';

const block = glamsterdam.block as unknown as JsonRpcBlock;

describe('a Glamsterdam header (EIP-7928, EIP-7843), from a real Platåberget block', () => {
  it('rebuilds to the block hash, with blockAccessListHash and slotNumber after requestsHash', () => {
    const rlp = blockHeaderRlp(block);
    expect(rlp).not.toBeNull();
    expect(keccak256(rlp as string)).toBe(block.hash);
    // The fixture's header, which the Python SDK's test reads, is this RLP.
    expect(rlp).toBe(glamsterdam.header);
    const fields = decodeRlp(rlp as string) as string[];
    expect(fields).toHaveLength(23);
    expect(fields[21]).toBe(block.blockAccessListHash);
    expect(BigInt(fields[22])).toBe(BigInt(block.slotNumber as string));
  });

  it('does not rebuild without the two fields: a header that stops at requestsHash does not hash to the block', () => {
    const { blockAccessListHash: _a, slotNumber: _s, ...prague } = block as Record<string, unknown>;
    expect(blockHeaderRlp(prague as JsonRpcBlock)).toBeNull();
  });

  it('is read by the verifier, which takes any header of at least the fifteen original fields', () => {
    const rlp = blockHeaderRlp(block) as string;
    expect(parseEvmBlockHeader(rlp)).toEqual({
      hash: block.hash,
      number: Number(BigInt(block.number)),
      timestamp: Number(BigInt(block.timestamp as string)),
      transactionsRoot: (block.transactionsRoot as string).toLowerCase(),
    });
  });

  it("JsonRpcEvmChain.blockMaterial stores a Glamsterdam block's header", async () => {
    const chain = new JsonRpcEvmChain('http://127.0.0.1:9', 0x1a6a8cc6en);
    (chain as unknown as { provider: { send: (m: string, p: unknown[]) => Promise<unknown> } }).provider.send = async (method) => {
      if (method !== 'eth_getBlockByNumber') throw new Error(`unexpected ${method}`);
      return { ...block, transactions: [] };
    };
    const material = await chain.blockMaterial(Number(BigInt(block.number)));
    expect(material).toMatchObject({ hash: block.hash, headerRlp: blockHeaderRlp(block), rawTransactions: [] });
    chain.close();
  });
});

describe('the Hoodi test network (eip155:560048)', () => {
  it('is in the registry as a testnet, beside mainnet and Sepolia', () => {
    expect(DEFAULT_EVM_NETWORKS).toEqual({ 'eip155:1': 'mainnet', 'eip155:11155111': 'testnet', 'eip155:560048': 'testnet' });
  });

  it("a publication on Hoodi reports network 'testnet'; on an unknown chain, null", async () => {
    for (const [chainId, network] of [[560048n, 'testnet'], [17000n, null]] as const) {
      const wallet = Wallet.createRandom();
      const p = '0x' + 'ab'.repeat(32);
      const raw = await wallet.signTransaction({
        type: 2, chainId, nonce: 0, to: wallet.address, value: 0n, data: p, gasLimit: 30_000n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n,
      });
      const fabricated = fabricateBlock([raw]);
      const chain = `eip155:${chainId}`;
      const verdict = await verifyEvmPublication({
        publication: publicationFrom(fabricated, 0),
        p,
        anchorOrigin: 'test.tzun.dev/' + '0'.repeat(32) + '/anchors',
        manifest: { publishers: { ['test.tzun.dev/' + '0'.repeat(32) + '/anchors']: [{ address: wallet.address, chain, namespace: 'test' }] } },
        headerSources: {
          [chain]: {
            chainId: async () => chainId,
            finalizedBlockNumber: async () => fabricated.number + 64,
            canonicalBlock: async () => ({ hash: fabricated.hash, timestamp: fabricated.timestamp }),
          },
        },
      });
      expect(verdict).toMatchObject({ valid: true, facts: { chain, network } });
    }
  });

  it("the read-back verifier knows the chain label 'ethereum-hoodi'", async () => {
    const provider: AnchorTransactionProvider = {
      getTransaction: async () => null,
      getBlock: async () => null,
      getBlockNumber: async () => 0,
      getNetwork: async () => ({ chainId: 560048n }),
    };
    let asked: string | null = null;
    const verifier = new EthereumAnchorVerifier({
      rpcUrls: { 'ethereum-hoodi': 'https://rpc.example' },
      publishers: [{ address: Wallet.createRandom().address, chain: 'eip155:560048', namespace: 'test' }],
      providerFor: (label: string) => {
        asked = label;
        return provider;
      },
    } as never);
    // No transaction there: the label resolved to Hoodi, whose node was asked.
    await verifier.verifyAnchor({ chain: 'ethereum-hoodi', transactionId: '0x' + '1'.repeat(64), p: 'ab'.repeat(32) }).catch(() => undefined);
    expect(asked).not.toBeNull();
  });
});

describe('the tip floor', () => {
  it('is 0.1 gwei on Ethereum mainnet and nothing elsewhere, unless overridden', () => {
    expect(DEFAULT_MIN_PRIORITY_FEE_GWEI).toEqual({ 'eip155:1': 0.1 });
    expect(minPriorityFeeWei('eip155:1')).toBe(100_000_000n);
    expect(minPriorityFeeWei('eip155:560048')).toBe(0n);
    expect(minPriorityFeeWei('eip155:1', 0)).toBe(0n);
    expect(minPriorityFeeWei('eip155:560048', 1.5)).toBe(1_500_000_000n);
  });

  it('raises a tip below it, keeps one above it, and the fees stay within the hard cap', () => {
    expect(withPriorityFeeFloor({ baseFeePerGas: 10n, maxPriorityFeePerGas: 0n }, 100n)).toEqual({ baseFeePerGas: 10n, maxPriorityFeePerGas: 100n });
    expect(withPriorityFeeFloor({ baseFeePerGas: 10n, maxPriorityFeePerGas: 500n }, 100n)).toEqual({ baseFeePerGas: 10n, maxPriorityFeePerGas: 500n });
    const floored = withPriorityFeeFloor({ baseFeePerGas: 99_000_000n, maxPriorityFeePerGas: 0n }, minPriorityFeeWei('eip155:1'));
    expect(publicationFees(floored.baseFeePerGas, floored.maxPriorityFeePerGas, DEFAULT_ANCHOR_BUDGET)).toEqual({
      maxFeePerGas: 2n * 99_000_000n + 100_000_000n,
      maxPriorityFeePerGas: 100_000_000n,
    });
  });

  it("JsonRpcEvmChain.fees takes the larger of the node's suggestion and the median tip recent blocks paid", async () => {
    const chain = new JsonRpcEvmChain('http://127.0.0.1:9', 1n);
    const answers: Record<string, unknown> = {
      eth_getBlockByNumber: { baseFeePerGas: toBeHex(99_000_000n) },
      eth_maxPriorityFeePerGas: '0x0',
      eth_feeHistory: { reward: [[toBeHex(40_000_000n)], [toBeHex(50_000_000n)], [toBeHex(60_000_000n)]] },
    };
    const send = (chain as unknown as { provider: { send: (m: string, p: unknown[]) => Promise<unknown> } }).provider;
    send.send = async (method) => {
      if (answers[method] instanceof Error) throw answers[method];
      return answers[method];
    };
    expect(await chain.fees()).toEqual({ baseFeePerGas: 99_000_000n, maxPriorityFeePerGas: 50_000_000n });
    answers.eth_maxPriorityFeePerGas = toBeHex(70_000_000n);
    expect((await chain.fees()).maxPriorityFeePerGas).toBe(70_000_000n);
    answers.eth_feeHistory = new Error('method not found');
    answers.eth_maxPriorityFeePerGas = '0x0';
    expect((await chain.fees()).maxPriorityFeePerGas).toBe(0n);
    chain.close();
  });
});
