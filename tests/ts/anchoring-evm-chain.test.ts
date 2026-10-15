/**
 * The JSON-RPC edge of the anchor scheduler (src/anchoring/evm-chain.ts):
 * how a node's answer to a broadcast is sorted, and how a block's
 * transactions are rebuilt from the node's JSON for
 * the transactions trie the scheduler stores a proof from (Anchor §7.2, §11).
 */
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Transaction, Wallet, keccak256, toQuantity } from 'ethers';
import { JsonRpcEvmChain, classifyBroadcastError, reassembleTransaction } from '../../src/anchoring/evm-chain';
import { anvilAvailability } from '../anvil/harness';

/** An error as ethers' JsonRpcProvider.send rejects with it, for a JSON-RPC error reply. */
const rpcError = (code: number, message: string) => ({ code: 'UNKNOWN_ERROR', shortMessage: 'could not coalesce error', error: { code, message } });

describe('classifyBroadcastError: only a definite refusal is rejected', () => {
  it.each([
    ['already known', rpcError(-32000, 'already known'), 'accepted', 'already_known'],
    ['anvil: already imported', rpcError(-32003, 'transaction already imported'), 'accepted', 'already_known'],
    ['nonce too low', rpcError(-32000, 'nonce too low: next nonce 4, tx nonce 3'), 'rejected', 'nonce_too_low'],
    ['insufficient funds', rpcError(-32000, 'insufficient funds for gas * price + value'), 'rejected', 'insufficient_funds'],
    ['replacement underpriced', rpcError(-32000, 'replacement transaction underpriced'), 'rejected', 'underpriced'],
    ['fee cap below the base fee', rpcError(-32000, 'max fee per gas less than block base fee'), 'rejected', 'underpriced'],
    ['invalid sender', rpcError(-32000, 'invalid sender'), 'rejected', 'rejected'],
    ['wrong chain', rpcError(-32000, 'invalid chain id for signer'), 'rejected', 'rejected'],
    ['intrinsic gas', rpcError(-32000, 'intrinsic gas too low'), 'rejected', 'rejected'],
    ['a full pool', rpcError(-32000, 'txpool is full'), 'rejected', 'rejected'],
    ['Infura rate limit', rpcError(-32005, 'daily request count exceeded, request rate limited'), 'unknown', 'rate_limited'],
    ['a 429 reply', rpcError(429, 'Too Many Requests'), 'unknown', 'rate_limited'],
    ['an internal error', rpcError(-32603, 'internal error'), 'unknown', 'unrecognized'],
    ['an unknown message', rpcError(-32000, 'something the SDK has never seen'), 'unknown', 'unrecognized'],
    ['no answer', Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8545'), { code: 'NETWORK_ERROR' }), 'unknown', 'unreachable'],
    ['a timeout', Object.assign(new Error('request timeout'), { code: 'TIMEOUT' }), 'unknown', 'unreachable'],
  ])('%s', (_label, error, outcome, reason) => {
    expect(classifyBroadcastError(error)).toMatchObject({ outcome, reason });
  });
});

/** A transaction as `eth_getBlockByNumber(n, true)` reports it. */
function nodeJson(raw: string): Record<string, unknown> {
  const tx = Transaction.from(raw);
  const sig = tx.signature!;
  const out: Record<string, unknown> = {
    hash: keccak256(raw),
    type: toQuantity(tx.type ?? 0),
    chainId: toQuantity(tx.chainId),
    nonce: toQuantity(tx.nonce),
    to: tx.to?.toLowerCase() ?? null,
    gas: toQuantity(tx.gasLimit),
    value: toQuantity(tx.value),
    input: tx.data,
    maxFeePerGas: toQuantity(tx.maxFeePerGas ?? 0n),
    maxPriorityFeePerGas: toQuantity(tx.maxPriorityFeePerGas ?? 0n),
    accessList: tx.accessList ?? [],
    r: sig.r,
    s: sig.s,
    v: toQuantity(sig.yParity),
    yParity: toQuantity(sig.yParity),
  };
  if (tx.type === 3) {
    out.maxFeePerBlobGas = toQuantity(tx.maxFeePerBlobGas ?? 0n);
    out.blobVersionedHashes = tx.blobVersionedHashes;
  }
  if (tx.type === 4) {
    out.authorizationList = (tx.authorizationList ?? []).map((a) => ({
      chainId: toQuantity(a.chainId),
      address: a.address.toLowerCase(),
      nonce: toQuantity(a.nonce),
      yParity: toQuantity(a.signature.yParity),
      r: a.signature.r,
      s: a.signature.s,
    }));
  }
  return out;
}

describe('the writer sends only bytes it signed and checked: no node signs for it (tzun-anchor/1 §7.2 rule 3)', () => {
  it('broadcast() is one eth_sendRawTransaction of exactly the bytes it is given', async () => {
    const calls: Array<{ method: string; params: unknown[] }> = [];
    const server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        const message = JSON.parse(body) as { id: number; method: string; params: unknown[] };
        calls.push({ method: message.method, params: message.params });
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: keccak256(String(message.params[0])) }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const chain = new JsonRpcEvmChain(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, 31337n);
    try {
      const raw = await Wallet.createRandom().signTransaction({
        type: 2,
        chainId: 31337n,
        nonce: 0,
        to: '0x' + '11'.repeat(20),
        value: 0n,
        data: '0x' + 'ab'.repeat(32),
        gasLimit: 30_000n,
        maxFeePerGas: 2_000_000_000n,
        maxPriorityFeePerGas: 1_000_000_000n,
      });
      expect(await chain.broadcast(raw)).toEqual({ outcome: 'accepted', reason: 'ok' });
      expect(calls).toEqual([{ method: 'eth_sendRawTransaction', params: [raw] }]);
    } finally {
      chain.close();
      server.close();
    }
  });

  it('no source file asks a node to sign or to send a transaction it signs (eth_sendTransaction, eth_sign, personal_sign)', () => {
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        if (e.isDirectory()) walk(join(dir, e.name));
        else if (e.name.endsWith('.ts')) files.push(join(dir, e.name));
      }
    };
    walk(join(__dirname, '..', '..', 'src'));
    expect(files.length).toBeGreaterThan(50);
    const asking = files.filter((f) => /eth_sendTransaction|eth_sign|personal_sign|\.sendTransaction\(/.test(readFileSync(f, 'utf8')));
    expect(asking).toEqual([]);
  });
});

describe('JsonRpcEvmChain declares what it counts as final', () => {
  it("the node's finalized tag, so a scanner reading through it states the finality its anchor verdicts were judged under", () => {
    const chain = new JsonRpcEvmChain('http://127.0.0.1:9', 11155111n);
    try {
      expect(chain.finality).toBe('finalized');
    } finally {
      chain.close();
    }
  });
});

describe('reassembleTransaction: a block\'s transactions from the node\'s JSON (review: types 3 and 4)', () => {
  const chainId = 11_155_111n;
  const base = { chainId, value: 0n, data: '0x', maxFeePerGas: 3_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n };

  it('rebuilds an EIP-1559 publication', async () => {
    const w = Wallet.createRandom();
    const raw = (await w.signTransaction({ ...base, type: 2, nonce: 5, to: w.address, data: '0x' + 'ab'.repeat(32), gasLimit: 30_000n })).toLowerCase();
    expect(reassembleTransaction(nodeJson(raw))).toBe(raw);
  });

  it('rebuilds a blob transaction (type 3) in its consensus form, without the blobs', async () => {
    const w = Wallet.createRandom();
    const raw = (
      await w.signTransaction({
        ...base,
        type: 3,
        nonce: 7,
        to: '0x' + '11'.repeat(20),
        gasLimit: 21_000n,
        maxFeePerBlobGas: 5n,
        blobVersionedHashes: ['0x01' + 'ab'.repeat(31), '0x01' + 'cd'.repeat(31)],
      })
    ).toLowerCase();
    const json = nodeJson(raw);
    expect(reassembleTransaction(json)).toBe(raw);
    expect(keccak256(reassembleTransaction(json)!)).toBe(json.hash);
    // Without the blob fields the node's JSON does not rebuild the transaction.
    const { blobVersionedHashes: _h, maxFeePerBlobGas: _f, ...bare } = json;
    expect(reassembleTransaction(bare)).not.toBe(raw);
  });

  it('rebuilds a set-code transaction (type 4) with its authorizations', async () => {
    const w = Wallet.createRandom();
    const delegator = Wallet.createRandom();
    const authorization = await delegator.authorize({ address: '0x' + '22'.repeat(20), nonce: 3n, chainId });
    const raw = (
      await w.signTransaction({ ...base, type: 4, nonce: 8, to: '0x' + '33'.repeat(20), gasLimit: 60_000n, authorizationList: [authorization] })
    ).toLowerCase();
    const json = nodeJson(raw);
    expect(reassembleTransaction(json)).toBe(raw);
    const { authorizationList: _a, ...bare } = json;
    expect(reassembleTransaction(bare)).not.toBe(raw);
  });

  it('returns null for JSON it cannot rebuild, so the caller asks the node for the raw bytes', () => {
    expect(reassembleTransaction({ type: '0x7f', nonce: '0x0' })).toBeNull();
  });
});

describe('when the anvil suite runs (review: CI minutes)', () => {
  it('never with TZUN_SKIP_ANVIL=1, and under CI only when TZUN_ANVIL=1 asks for it', () => {
    expect(anvilAvailability({ TZUN_SKIP_ANVIL: '1', TZUN_ANVIL: '1' })).toEqual({ ok: false, reason: 'TZUN_SKIP_ANVIL=1' });
    expect(anvilAvailability({ CI: 'true' })).toMatchObject({ ok: false, reason: expect.stringMatching(/TZUN_ANVIL=1/) });
    // Asked for under CI, or outside CI: Docker decides.
    const docker = anvilAvailability({});
    expect(anvilAvailability({ CI: 'true', TZUN_ANVIL: '1' }).ok).toBe(docker.ok);
    expect(anvilAvailability({ CI: 'false' }).ok).toBe(docker.ok);
  });
});
