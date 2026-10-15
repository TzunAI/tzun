/**
 * The publisher's key given as an external signer: a customer may keep its
 * publisher key in its own tool or KMS, and Tzun never takes it. The publisher accepts an ethers `Signer` (or any
 * object with `getAddress()` and `signTransaction()`), checks every
 * transaction it returns against the one it asked for, and runs the same
 * outbox, nonce accounting, enrolment and replacement as with a private key.
 *
 * The chain is the in-memory one the scheduler's suite uses; the anvil suite
 * (tests/anvil/) runs both key kinds against a real node.
 */
import { N, Transaction, Wallet, concat, decodeRlp, encodeRlp, keccak256, toBeHex, type TransactionRequest } from 'ethers';
import type { AnchorTransactionRequest, AnchorTransactionSigner } from '@tzun/engine';
import {
  AnchorSignerError,
  AnchorSignerUnavailableError,
  checkSignedTransaction,
  createAnchorScheduler,
  createEvmPublisher,
  createSignerPublisher,
  type AnchorScheduler,
  type EvmPublisher,
} from '../../src/anchoring';
import { transactionToBroadcast, withLowS } from '../../src/anchoring/evm-chain';
import { readEvmTransaction } from '../../src/attestation/blockchain';
import { anchorStoreFor, logStoreFor, type AnchorPublication } from '../../src/storage/log-store';
import { makeEnvelope } from './storage-conformance/fixtures';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { ClosureSigner } from './helpers/closure-signer';
import { highSSigner, rewriteType2Field, signType2, toHighS } from './helpers/signer-faults';
import { signLegacy } from './helpers/evm-fixtures';
import { type LogBackend, type OpenedStore, logBackends } from './helpers/log-store-backends';

const CHAIN = 'eip155:31337';
const NS = 'test.signer.tzun';
const ETH = 10n ** 18n;
const MIN = 60_000;
const HOUR = 60 * MIN;

const REQUEST: AnchorTransactionRequest = {
  type: 2,
  chainId: 31337n,
  nonce: 7,
  to: '0x' + '11'.repeat(20),
  value: 0n,
  data: '0x' + 'ab'.repeat(32),
  gasLimit: 30_000n,
  maxFeePerGas: 2_100_000_000n,
  maxPriorityFeePerGas: 100_000_000n,
};

describe('checkSignedTransaction: what a signer returns is the transaction it was asked for', () => {
  const wallet = Wallet.createRandom();
  const address = wallet.address.toLowerCase();

  it('accepts the requested transaction, signed by the publisher, and hashes its bytes', async () => {
    const raw = await wallet.signTransaction(REQUEST);
    const signed = checkSignedTransaction(raw, REQUEST, address);
    expect(signed.raw).toBe(raw.toLowerCase());
    expect(signed.hash).toBe(Transaction.from(raw).hash);
  });

  it.each<[string, Partial<AnchorTransactionRequest> | { accessList: unknown }]>([
    ['nonce', { nonce: 8 }],
    ['chainId', { chainId: 1n }],
    ['to', { to: '0x' + '22'.repeat(20) }],
    ['value', { value: 1n }],
    ['data', { data: '0x' + 'cd'.repeat(32) }],
    ['gasLimit', { gasLimit: 31_000n }],
    ['maxFeePerGas', { maxFeePerGas: 2_200_000_000n }],
    ['maxPriorityFeePerGas', { maxPriorityFeePerGas: 200_000_000n }],
    ['accessList', { accessList: [{ address: '0x' + '33'.repeat(20), storageKeys: [] }] }],
  ])('refuses a transaction whose %s differs', async (field, change) => {
    const raw = await wallet.signTransaction({ ...REQUEST, ...change } as TransactionRequest);
    expect(() => checkSignedTransaction(raw, REQUEST, address)).toThrow(AnchorSignerError);
    try {
      checkSignedTransaction(raw, REQUEST, address);
    } catch (err) {
      expect(err).toMatchObject({ code: 'anchor_signer_mismatch', field });
    }
  });

  it('refuses a legacy or EIP-2930 transaction for the same fields', async () => {
    const legacy = await wallet.signTransaction({ ...REQUEST, type: 0, gasPrice: 2_100_000_000n, maxFeePerGas: undefined, maxPriorityFeePerGas: undefined });
    expect(() => checkSignedTransaction(legacy, REQUEST, address)).toThrow(/type/);
  });

  it('refuses a transaction another key signed, garbage, and an unsigned transaction', async () => {
    const other = await Wallet.createRandom().signTransaction(REQUEST);
    expect(() => checkSignedTransaction(other, REQUEST, address)).toThrow(/sender/);
    for (const junk of [undefined, 42, 'not hex', '0x', '0x1234']) {
      expect(() => checkSignedTransaction(junk, REQUEST, address)).toThrow(AnchorSignerError);
    }
    const unsigned = Transaction.from({ ...REQUEST }).unsignedSerialized;
    expect(() => checkSignedTransaction(unsigned, REQUEST, address)).toThrow(/signature/);
  });

  it('lowers a high s: the same transaction with n - s and the other yParity, the bytes the publisher signs with its key', async () => {
    const raw = await wallet.signTransaction(REQUEST);
    const highS = toHighS(raw);
    expect(readEvmTransaction(highS)).toEqual({ ok: false, rule: 'signature-values' });
    const signed = checkSignedTransaction(highS, REQUEST, address);
    expect(signed).toEqual({ raw: raw.toLowerCase(), hash: keccak256(raw) });
  });

  // Each is the publisher's own signature over the transaction it carries; item 2 refuses
  // it for the rule named, whatever the request asked for, and the refusal names that rule.
  it.each<[string, () => Promise<string>, string]>([
    ['a typed transaction signed for chain id 0', () => wallet.signTransaction({ ...REQUEST, chainId: 0n }), 'chain-id'],
    ['a tip above the fee cap', async () => signType2(wallet.signingKey, { ...REQUEST, maxPriorityFeePerGas: REQUEST.maxFeePerGas + 1n }), 'fees'],
    ['a high s and a tip above the fee cap', async () => toHighS(signType2(wallet.signingKey, { ...REQUEST, maxPriorityFeePerGas: REQUEST.maxFeePerGas + 1n })), 'fees'],
    ['a nonce written with a leading zero byte', async () => rewriteType2Field(await wallet.signTransaction(REQUEST), 1, '0x0007'), 'encoding'],
    ['a high s and a nonce written with a leading zero byte', async () => rewriteType2Field(toHighS(await wallet.signTransaction(REQUEST)), 1, '0x0007'), 'encoding'],
    ['a high s with yParity 2', async () => rewriteType2Field(toHighS(await wallet.signTransaction(REQUEST)), 9, '0x02'), 'signature-values'],
    ['s = n', async () => rewriteType2Field(await wallet.signTransaction(REQUEST), 11, toBeHex(N)), 'signature-values'],
  ])('refuses %s, naming the rule of item 2 it breaks', async (_name, make, rule) => {
    const raw = await make();
    expect(() => checkSignedTransaction(raw, REQUEST, address)).toThrow(AnchorSignerError);
    expect(() => checkSignedTransaction(raw, REQUEST, address)).toThrow(expect.objectContaining({ code: 'anchor_signer_mismatch', field: rule, rule }));
    expect(() => checkSignedTransaction(raw, REQUEST, address)).toThrow(/tzun-anchor\/1 §10\.4 item 2/);
  });

  it('never carries key material in its message', async () => {
    const raw = await Wallet.createRandom().signTransaction(REQUEST);
    try {
      checkSignedTransaction(raw, REQUEST, address);
    } catch (err) {
      expect((err as Error).message).not.toContain(wallet.privateKey.slice(2));
    }
  });
});

describe('withLowS and transactionToBroadcast: what the writer broadcasts meets every rule of tzun-anchor/1 §10.4 item 2', () => {
  const wallet = Wallet.createRandom();
  const address = wallet.address.toLowerCase();
  const p = '0x' + 'ab'.repeat(32);

  /** The signing hash of a signed transaction: ethers' unsignedHash, from the fields alone. */
  const signingHash = (raw: string): string => Transaction.from(raw).unsignedHash;

  it.each<[string, () => Promise<string>]>([
    ['EIP-1559', () => wallet.signTransaction(REQUEST)],
    ['EIP-2930', () => wallet.signTransaction({ ...REQUEST, type: 1, gasPrice: 2_100_000_000n, maxFeePerGas: undefined, maxPriorityFeePerGas: undefined })],
    ['legacy EIP-155, v 2c + 35', async () => signLegacy(wallet.signingKey, { data: p, eip155: true, chainId: 31337n, yParity: 0 })],
    ['legacy EIP-155, v 2c + 36', async () => signLegacy(wallet.signingKey, { data: p, eip155: true, chainId: 31337n, yParity: 1 })],
    ['legacy, v 27', async () => signLegacy(wallet.signingKey, { data: p, eip155: false, yParity: 0 })],
    ['legacy, v 28', async () => signLegacy(wallet.signingKey, { data: p, eip155: false, yParity: 1 })],
  ])('%s with a high s: lowered to the same key\'s signature over the same hash, which every rule reads', async (_name, sign) => {
    const low = (await sign()).toLowerCase();
    const high = toHighS(low);
    expect(high).not.toBe(low);
    expect(readEvmTransaction(high)).toEqual({ ok: false, rule: 'signature-values' });
    // The high s is the same key's signature over the same hash: ethers, which reads it,
    // recovers the publisher from it.
    const highFields = decodeRlp(high.startsWith('0x0') ? `0x${high.slice(4)}` : high) as string[];
    expect(BigInt(highFields[highFields.length - 1]) > N / 2n).toBe(true);
    expect(signingHash(high)).toBe(signingHash(low));
    expect(Transaction.from(high).from?.toLowerCase()).toBe(address);

    const lowered = withLowS(high);
    expect(lowered).toBe(low);
    expect(signingHash(lowered!)).toBe(signingHash(low));
    const reading = readEvmTransaction(lowered!);
    expect(reading.ok && reading.transaction.sender).toBe(address);
    expect(transactionToBroadcast(high)).toEqual({ ok: true, raw: low, lowered: true });
  });

  it('a transaction that meets every rule is broadcast byte for byte, and withLowS leaves it alone', async () => {
    const raw = await wallet.signTransaction(REQUEST);
    expect(transactionToBroadcast(raw)).toEqual({ ok: true, raw, lowered: false });
    expect(withLowS(raw)).toBeNull();
  });

  it('withLowS refuses what is not a high s alone: r or s out of range, a typed yParity other than 0 or 1, bytes that are no transaction', async () => {
    const raw = await wallet.signTransaction(REQUEST);
    const fields = decodeRlp(`0x${raw.slice(4)}`) as string[];
    const withSig = (parity: string, r: string, s: string) => concat(['0x02', encodeRlp([...fields.slice(0, -3), parity, r, s])]);
    const highS = toBeHex(N - BigInt(fields[11]));
    expect(withLowS(withSig(fields[9], fields[10], toBeHex(N)))).toBeNull();
    expect(withLowS(withSig(fields[9], '0x', highS))).toBeNull();
    expect(withLowS(withSig(fields[9], toBeHex(N), highS))).toBeNull();
    expect(withLowS(withSig('0x02', fields[10], highS))).toBeNull();
    expect(withLowS(withSig(fields[9], fields[10], '0x00' + highS.slice(2)))).toBeNull();
    for (const junk of ['0x', '0x1234', 'not hex', '0x05c0']) expect(withLowS(junk)).toBeNull();
  });

  it('names the rule still broken when a high s is not the only one', async () => {
    const raw = await wallet.signTransaction({ ...REQUEST, chainId: 0n });
    expect(transactionToBroadcast(toHighS(raw))).toEqual({ ok: false, rule: 'chain-id' });
    const junk = await wallet.signTransaction({ ...REQUEST, gasLimit: 2n ** 64n });
    expect(transactionToBroadcast(junk)).toEqual({ ok: false, rule: 'field-sizes' });
    expect(transactionToBroadcast(toHighS(junk))).toEqual({ ok: false, rule: 'field-sizes' });
    expect(transactionToBroadcast('0x1234')).toEqual({ ok: false, rule: null });
  });
});

describe('a publisher over an external signer that returns a high s', () => {
  const chain = new FakeEvmChain();
  const fields = { nonce: 3, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 100_000_000n, gasLimit: 30_000n };
  const p = 'ab'.repeat(32);

  it('signs the bytes a publisher holding the same key signs: the high s lowered, the same sender, the same signing hash', async () => {
    const wallet = Wallet.createRandom();
    const byKey = createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain });
    const signer = highSSigner(wallet);
    const bySigner = await createSignerPublisher({ signer, chain: CHAIN, client: chain });
    const expected = await byKey.signPublication(p, fields);
    const signed = await bySigner.signPublication(p, fields);
    expect(signed).toEqual(expected);
    expect(signer.returned).toHaveLength(1);
    expect(signed.raw).not.toBe(signer.returned[0]);
    expect(Transaction.from(signed.raw).unsignedHash).toBe(Transaction.from(signer.returned[0]).unsignedHash);
    const reading = readEvmTransaction(signed.raw);
    expect(reading.ok && reading.transaction.sender).toBe(wallet.address.toLowerCase());
    expect(signed.hash).toBe(keccak256(signed.raw));
    // An accounted transaction is held to the same rules.
    expect(await bySigner.signTransfer('0x' + '99'.repeat(20), 5n, '0x', fields)).toEqual(await byKey.signTransfer('0x' + '99'.repeat(20), 5n, '0x', fields));
  });

  it('refuses a high-s legacy EIP-155 transaction for its type: the writer asks for EIP-1559 only', async () => {
    const wallet = Wallet.createRandom();
    const legacy: AnchorTransactionSigner = {
      getAddress: async () => wallet.address,
      signTransaction: async (request) =>
        toHighS(await wallet.signTransaction({ ...request, type: 0, gasPrice: request.maxFeePerGas, maxFeePerGas: undefined, maxPriorityFeePerGas: undefined } as TransactionRequest)),
    };
    const publisher = await createSignerPublisher({ signer: legacy, chain: CHAIN, client: chain });
    await expect(publisher.signPublication(p, fields)).rejects.toMatchObject({ code: 'anchor_signer_mismatch', field: 'type' });
  });
});

describe('a publisher over an external signer', () => {
  const chain = new FakeEvmChain();

  it('signs the same bytes as a publisher holding the same key: one code path, either way the key is given', async () => {
    const wallet = Wallet.createRandom();
    const byKey = createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain });
    const bySigner = await createSignerPublisher({ signer: new ClosureSigner(wallet.privateKey), chain: CHAIN, client: chain });
    const byWallet = await createSignerPublisher({ signer: wallet, chain: CHAIN, client: chain });
    expect(bySigner.address).toBe(byKey.address);
    const fields = { nonce: 3, maxFeePerGas: 2_000_000_000n, maxPriorityFeePerGas: 100_000_000n, gasLimit: 30_000n };
    const p = 'ab'.repeat(32);
    const expected = await byKey.signPublication(p, fields);
    expect(await bySigner.signPublication(p, fields)).toEqual(expected);
    expect(await byWallet.signPublication(p, fields)).toEqual(expected);
    const tx = Transaction.from(expected.raw);
    expect(tx).toMatchObject({ type: 2, chainId: 31337n, nonce: 3, value: 0n, data: `0x${p}` });
    expect(tx.to?.toLowerCase()).toBe(byKey.address);
  });

  it('asks the signer for its address once, when it is created, and refuses an address that is not one', async () => {
    let asked = 0;
    const wallet = Wallet.createRandom();
    const counting: AnchorTransactionSigner = {
      getAddress: async () => {
        asked += 1;
        return wallet.address;
      },
      signTransaction: (request) => wallet.signTransaction(request),
    };
    const publisher = await createSignerPublisher({ signer: counting, chain: CHAIN, client: chain });
    await publisher.signPublication('ab'.repeat(32), { nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, gasLimit: 30_000n });
    expect(asked).toBe(1);
    await expect(createSignerPublisher({ signer: { ...counting, getAddress: async () => 'nobody' }, chain: CHAIN, client: chain })).rejects.toMatchObject({
      code: 'anchor_signer_mismatch',
      field: 'address',
    });
  });
});

describe('the signer has a deadline', () => {
  const chain = new FakeEvmChain();
  const wallet = Wallet.createRandom();
  const fields = { nonce: 0, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, gasLimit: 30_000n };
  const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

  it('a getAddress() that never settles, or throws, is AnchorSignerUnavailableError', async () => {
    const hanging: AnchorTransactionSigner = { getAddress: never, signTransaction: never };
    const started = Date.now();
    await expect(createSignerPublisher({ signer: hanging, chain: CHAIN, client: chain, signTimeoutMs: 50 })).rejects.toMatchObject({
      code: 'anchor_signer_unavailable',
      step: 'getAddress',
    });
    expect(Date.now() - started).toBeLessThan(2_000);
    const throwing: AnchorTransactionSigner = {
      getAddress: () => {
        throw new Error('the KMS said no');
      },
      signTransaction: never,
    };
    await expect(createSignerPublisher({ signer: throwing, chain: CHAIN, client: chain })).rejects.toThrow(/getAddress\(\) \(it failed: the KMS said no\)/);
  });

  it('a signTransaction() that never settles, or rejects, is AnchorSignerUnavailableError; a late answer is dropped', async () => {
    let answer: ((raw: string) => void) | undefined;
    const slow: AnchorTransactionSigner = {
      getAddress: async () => wallet.address,
      signTransaction: () => new Promise<string>((resolve) => (answer = resolve)),
    };
    const publisher = await createSignerPublisher({ signer: slow, chain: CHAIN, client: chain, signTimeoutMs: 50 });
    const refused = publisher.signPublication('ab'.repeat(32), fields);
    await expect(refused).rejects.toBeInstanceOf(AnchorSignerUnavailableError);
    await expect(refused).rejects.toMatchObject({ step: 'signTransaction' });
    answer!(await wallet.signTransaction({ ...REQUEST, nonce: 0 }));

    const rejecting: AnchorTransactionSigner = { getAddress: async () => wallet.address, signTransaction: async () => Promise.reject(new Error('HSM offline')) };
    const refusing = await createSignerPublisher({ signer: rejecting, chain: CHAIN, client: chain });
    await expect(refusing.signPublication('ab'.repeat(32), fields)).rejects.toThrow(/HSM offline/);
  });
});

/**
 * One scenario, run with each key kind on its own store and chain: a wallet
 * that has already sent 3 transactions, an epoch published at its nonce base,
 * a crash after the attempt is stored and before it is sent, the restart that
 * sends the stored bytes, two replacements while the base fee is high, the
 * fill, and a sweep. What the store and the chain hold afterwards, described
 * without the values that differ between two stores (P, hashes, times), must
 * be the same for both kinds.
 */
describe.each(logBackends('anchoring_signer').map((b) => [b.name, b] as const))('the outbox, enrolment, replacement and accounting with either key kind, on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(120_000);
  const opened: OpenedStore<unknown>[] = [];
  const schedulers: AnchorScheduler[] = [];

  afterEach(async () => {
    for (const s of schedulers.splice(0)) await s.stop().catch(() => undefined);
    for (const o of opened.splice(0)) await o.close();
  });
  afterAll(() => backend.dispose());

  async function scenario(kind: 'privateKey' | 'external signer'): Promise<Record<string, unknown>> {
    await backend.fresh();
    const store = await backend.open({ logNamespace: NS });
    opened.push(store);
    const chain = new FakeEvmChain();
    const wallet = Wallet.createRandom() as unknown as Wallet;
    chain.fund(wallet.address, ETH);
    for (let i = 0; i < 3; i++) await chain.sendExternal(wallet);
    chain.mine(1);
    const signer = new ClosureSigner(wallet.privateKey);
    let offset = 0;
    const clock = (): number => Date.now() + offset;
    const publisher = async (): Promise<EvmPublisher> =>
      kind === 'privateKey'
        ? createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain })
        : createSignerPublisher({ signer, chain: CHAIN, client: chain });
    const make = async (extra: Record<string, unknown> = {}): Promise<AnchorScheduler> => {
      const s = await createAnchorScheduler({
        storage: store.adapter,
        config: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, privateKey: '0x' + '01'.repeat(32) } } },
        publisher: await publisher(),
        clock,
        expectation: {},
        tuning: { stuckAfterMs: 5 * MIN, leaseTtlMs: 1_000 },
        ...extra,
      });
      schedulers.push(s);
      return s;
    };
    const adapter = store.adapter as unknown as { store(e: ReturnType<typeof makeEnvelope>, chainId?: string): Promise<void> };
    for (let i = 1; i <= 3; i++) await adapter.store(makeEnvelope({ evidenceId: `${kind}-${i}`, sequenceNumber: i, attestationStatus: 'partial' }), 'alpha');
    const publications = async (): Promise<AnchorPublication[]> => anchorStoreFor(store.adapter)!.listAnchorPublications({ kind: 'evm-calldata/1' });

    // A crash after the signed attempt is stored, before it is sent.
    const crashing = await make({ holderId: 'crashing', testHooks: { afterPersistAttempt: () => { throw new Error('killed after persist'); } } });
    offset += HOUR;
    await expect(crashing.runPass()).rejects.toThrow('killed after persist');
    await crashing.stop();
    expect(chain.broadcasts.slice(3)).toEqual([]);
    const signaturesBeforeRestart = signer.signed.length;

    // The restart sends the stored bytes, and asks for no new signature.
    await new Promise((r) => setTimeout(r, 1_100));
    const s = await make({ holderId: 'restarted' });
    await s.runPass();
    const [stored] = await publications();
    expect(chain.broadcasts[chain.broadcasts.length - 1]).toBe(stored.attempts[0].rawTx);
    expect(signer.signed.length).toBe(signaturesBeforeRestart);

    // The base fee jumps: two replacements at the same nonce, same calldata, +12.5%.
    chain.baseFeePerGas = 60_000_000_000n;
    chain.mine(1);
    for (let i = 0; i < 2; i++) {
      offset += 6 * MIN;
      await s.runPass();
    }
    chain.baseFeePerGas = 1_000_000_000n;
    for (let i = 0; i < 6; i++) {
      chain.mine(chain.finalizedDepth + 1);
      await s.runPass();
      const pubs = await publications();
      if (pubs.every((p) => p.state === 'finalized') && (await s.getAnchorState()).fillBacklog === 0) break;
    }
    const [done] = await publications();
    expect(done.state).toBe('finalized');

    const sweep = await s.sweep('0x' + '99'.repeat(20));
    const accounting = await s.accountNonces();
    const record = await (store.adapter as unknown as { retrieve(id: string): Promise<{ nonRepudiation: { anchor?: unknown } } | null> }).retrieve(`${kind}-2`);
    expect(logStoreFor(store.adapter)).toBeDefined();

    return {
      nonceBase: accounting.nonceBase,
      attempts: done.attempts.map((a) => {
        const tx = Transaction.from(a.rawTx);
        return { nonce: tx.nonce, from: tx.from!.toLowerCase() === wallet.address.toLowerCase(), maxFeePerGas: a.maxFeePerGas, tip: a.maxPriorityFeePerGas, dataIsP: tx.data === `0x${done.p}` };
      }),
      minedIsAnAttempt: done.attempts.some((a) => a.txHash === done.minedTxHash),
      filled: record?.nonRepudiation.anchor !== undefined,
      sweep: { kind: sweep.tx.kind, nonce: sweep.tx.nonce, retired: sweep.retired, broadcast: sweep.broadcast?.outcome },
      accounted: accounting.accounted.map((a) => [a.nonce, a.kind]),
      unaccounted: accounting.unaccounted,
    };
  }

  it('does the same with a private key and with an external signer', async () => {
    const byKey = await scenario('privateKey');
    const bySigner = await scenario('external signer');
    expect(byKey).toMatchObject({
      nonceBase: 3,
      minedIsAnAttempt: true,
      filled: true,
      sweep: { kind: 'sweep', nonce: 4, retired: true, broadcast: 'accepted' },
      unaccounted: [],
    });
    expect((byKey.attempts as unknown[]).length).toBe(3);
    expect((byKey.attempts as Array<{ nonce: number }>).every((a) => a.nonce === 3)).toBe(true);
    expect(bySigner).toEqual(byKey);
  });
});
