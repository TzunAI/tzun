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
import { randomBytes } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { N, Transaction, Wallet, concat, decodeRlp, encodeRlp, hexlify, keccak256, toBeHex, type TransactionRequest } from 'ethers';
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
import {
  highSSigner,
  rewriteType2Encoding,
  rewriteType2Field,
  signType2,
  toHighS,
  type2SigningHash,
  type2WithSignature,
} from './helpers/signer-faults';
import { HALF_N, SEPOLIA, firstRecoverableR, firstUnrecoverableR, signLegacy, signatureOf, withSignature } from './helpers/evm-fixtures';
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

/** A signed transaction with some of its signature values replaced, the others kept, each written as RLP writes an integer. */
function withSignedValues(raw: string, values: Partial<{ v: bigint; r: bigint; s: bigint }>): string {
  return withSignature(raw, { ...signatureOf(raw), ...values });
}

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
  ])('refuses a transaction whose %s differs, and its high-s twin once lowered', async (field, change) => {
    const raw = await wallet.signTransaction({ ...REQUEST, ...change } as TransactionRequest);
    // The comparison with the request runs on the bytes that would be sent: a
    // high s is lowered first, and the lowered transaction still differs.
    for (const returned of [raw, toHighS(raw)]) {
      expect(() => checkSignedTransaction(returned, REQUEST, address)).toThrow(expect.objectContaining({ code: 'anchor_signer_mismatch', field }));
    }
  });

  it('refuses a legacy or EIP-2930 transaction for its type, the high-s twin of each once lowered', async () => {
    const legacy = await wallet.signTransaction({ ...REQUEST, type: 0, gasPrice: 2_100_000_000n, maxFeePerGas: undefined, maxPriorityFeePerGas: undefined });
    const eip2930 = await wallet.signTransaction({ ...REQUEST, type: 1, gasPrice: 2_100_000_000n, maxFeePerGas: undefined, maxPriorityFeePerGas: undefined });
    for (const returned of [legacy, toHighS(legacy), eip2930, toHighS(eip2930)]) {
      expect(() => checkSignedTransaction(returned, REQUEST, address)).toThrow(expect.objectContaining({ code: 'anchor_signer_mismatch', field: 'type' }));
    }
  });

  it('refuses a transaction of a type item 2 does not read by its type, not as bytes that are no transaction', async () => {
    const blob = await wallet.signTransaction({ ...REQUEST, type: 3, maxFeePerBlobGas: 1n, blobVersionedHashes: ['0x01' + '00'.repeat(31)] } as TransactionRequest);
    const setCode = await wallet.signTransaction({ ...REQUEST, type: 4, authorizationList: [] } as TransactionRequest);
    for (const [returned, type] of [[blob, 3], [setCode, 4], ['0x7fc0', 127]] as const) {
      let refusal: unknown;
      try {
        checkSignedTransaction(returned, REQUEST, address);
      } catch (err) {
        refusal = err;
      }
      expect(refusal).toBeInstanceOf(AnchorSignerError);
      expect(refusal).toMatchObject({ code: 'anchor_signer_mismatch', field: 'type' });
      expect(refusal).not.toHaveProperty('rule');
      const message = (refusal as Error).message;
      expect(message).toContain(`a transaction of type ${type}, which tzun-anchor/1 §10.4 item 2 does not read, where 2 was asked for`);
      expect(message).not.toMatch(/encoding|not a signed transaction/);
    }
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
    ['s = 0', async () => withSignedValues(await wallet.signTransaction(REQUEST), { s: 0n }), 'signature-values'],
    ['s = 2^256 - 1', async () => withSignedValues(await wallet.signTransaction(REQUEST), { s: 2n ** 256n - 1n }), 'signature-values'],
    ['r = 0', async () => withSignedValues(await wallet.signTransaction(REQUEST), { r: 0n }), 'signature-values'],
    ['r = n', async () => withSignedValues(await wallet.signTransaction(REQUEST), { r: N }), 'signature-values'],
    ['r = 2^256 - 1', async () => withSignedValues(await wallet.signTransaction(REQUEST), { r: 2n ** 256n - 1n }), 'signature-values'],
    ['yParity 2', async () => withSignedValues(await wallet.signTransaction(REQUEST), { v: 2n }), 'signature-values'],
    ['an r that is no point\'s x-coordinate', async () => withSignature(await wallet.signTransaction(REQUEST), { v: 0n, r: firstUnrecoverableR(), s: 1n }), 'recovery'],
    ['a legacy transaction signed for chain id 0 (v 35 or 36)', async () => signLegacy(wallet.signingKey, { data: REQUEST.data, eip155: true, chainId: 0n, yParity: 0 }), 'legacy-v'],
    ['a gasLimit of 2^64', () => wallet.signTransaction({ ...REQUEST, gasLimit: 2n ** 64n }), 'field-sizes'],
    ['the nonce 7 written 0x81 0x07, a byte below 0x80 as a one-byte string', async () => rewriteType2Encoding(await wallet.signTransaction(REQUEST), 1, '0x8107'), 'encoding'],
    ['the data, 32 bytes, in the long form', async () => rewriteType2Encoding(await wallet.signTransaction(REQUEST), 7, concat(['0xb820', REQUEST.data])), 'encoding'],
    ['yParity 0 written 0x00', async () => rewriteType2Encoding(await wallet.signTransaction(REQUEST), 9, '0x00'), 'encoding'],
    ['yParity 0 written 0x81 0x00', async () => rewriteType2Encoding(await wallet.signTransaction(REQUEST), 9, '0x8100'), 'encoding'],
    ['a byte after the list', async () => `${await wallet.signTransaction(REQUEST)}00`, 'encoding'],
  ])('refuses %s, naming the rule of item 2 it breaks', async (_name, make, rule) => {
    const raw = await make();
    expect(() => checkSignedTransaction(raw, REQUEST, address)).toThrow(AnchorSignerError);
    expect(() => checkSignedTransaction(raw, REQUEST, address)).toThrow(expect.objectContaining({ code: 'anchor_signer_mismatch', field: rule, rule }));
    expect(() => checkSignedTransaction(raw, REQUEST, address)).toThrow(/tzun-anchor\/1 §10\.4 item 2/);
  });

  it('refuses s and n - s whose parity was not flipped with them: item 2 reads them, and another sender recovers (§7.2 rule 3)', async () => {
    const raw = await wallet.signTransaction(REQUEST);
    const { v, r, s } = signatureOf(raw);
    // A signer that lowered a high s itself, but kept its parity.
    const keptParity = withSignature(raw, { v: 1n - v, r, s });
    const misread = readEvmTransaction(keptParity);
    expect(misread.ok).toBe(true);
    expect(misread.ok && misread.transaction.sender).not.toBe(address);
    // The same mistake the other way round: n - s with the parity kept, which the writer lowers to it.
    const unflipped = withSignature(raw, { v, r, s: N - s });
    expect(transactionToBroadcast(unflipped)).toEqual({ ok: true, raw: keptParity, lowered: true });
    for (const returned of [keptParity, unflipped]) {
      expect(() => checkSignedTransaction(returned, REQUEST, address)).toThrow(expect.objectContaining({ code: 'anchor_signer_mismatch', field: 'sender' }));
    }
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

  it.each([0, 1] as const)('EIP-1559 whose high s has yParity %i: s becomes n - s and yParity the other, the same sender, another transaction id', async (highParity) => {
    // A Wallet's signature, low s, whose high-s twin has the parity asked for.
    let low: string | undefined;
    for (let nonce = 0; low === undefined; nonce++) {
      const raw = await wallet.signTransaction({ ...REQUEST, nonce });
      if (signatureOf(raw).v === BigInt(1 - highParity)) low = raw;
    }
    const request = { ...REQUEST, nonce: Transaction.from(low).nonce };
    const high = toHighS(low);
    const highSig = signatureOf(high);
    expect(highSig.v).toBe(BigInt(highParity));
    expect(highSig.s > HALF_N).toBe(true);
    const signed = checkSignedTransaction(high, request, address);
    expect(signatureOf(signed.raw)).toEqual({ v: BigInt(1 - highParity), r: highSig.r, s: N - highSig.s });
    expect(signed).toEqual({ raw: low, hash: keccak256(low) });
    expect(signed.hash).not.toBe(keccak256(high));
    const reading = readEvmTransaction(signed.raw);
    expect(reading.ok && reading.transaction.sender).toBe(address);
  });

  it.each([0, 1] as const)('legacy EIP-155 on chain id 11155111, yParity %i: v moves to the other of c × 2 + 35 and c × 2 + 36, never to v xor 1', async (yParity) => {
    const c = SEPOLIA;
    const low = signLegacy(wallet.signingKey, { data: p, eip155: true, chainId: c, yParity });
    const high = toHighS(low);
    const lowV = signatureOf(low).v;
    const highV = signatureOf(high).v;
    expect(lowV).toBe(c * 2n + 35n + BigInt(yParity));
    expect(highV).toBe(c * 2n + 36n - BigInt(yParity));
    const lowered = withLowS(high)!;
    // The decoded v, not only the sender: v xor 1 of c × 2 + 35 is c × 2 + 34, which signs another chain id.
    const v = signatureOf(lowered).v;
    expect(v).toBe(lowV);
    expect(v).not.toBe(highV ^ 1n);
    expect(lowered).toBe(low);
    const reading = readEvmTransaction(lowered);
    expect(reading.ok && [reading.transaction.chainId, reading.transaction.sender]).toEqual([c, address]);
  });

  it.each([0, 1] as const)('a legacy v of 27 or 28 (27 + %i) with a high s is never lowered: it signs no chain id, which §7.2 rule 3 requires', async (yParity) => {
    const low = signLegacy(wallet.signingKey, { data: p, eip155: false, yParity });
    const high = toHighS(low);
    expect(signatureOf(high).v).toBe(28n - BigInt(yParity));
    expect(readEvmTransaction(high)).toEqual({ ok: false, rule: 'signature-values' });
    expect(withLowS(high)).toBeNull();
    expect(transactionToBroadcast(high)).toEqual({ ok: false, rule: 'signature-values' });
  });

  it('n - s below 2^248 is written in fewer than 32 bytes with no leading zero, and yParity 0 as the empty string', async () => {
    // A Wallet's signature with yParity 0 and s below 2^248 (about 1 in 256): its
    // high-s twin has yParity 1 and n - s, which the writer lowers back.
    let low: string | undefined;
    for (let nonce = 0; low === undefined; nonce++) {
      const raw = await wallet.signTransaction({ ...REQUEST, nonce });
      const sig = signatureOf(raw);
      if (sig.v === 0n && sig.s < 2n ** 248n) low = raw;
    }
    const request = { ...REQUEST, nonce: Transaction.from(low).nonce };
    const high = toHighS(low);
    const signed = checkSignedTransaction(high, request, address);
    expect(signed.raw).toBe(low);
    const written = decodeRlp(`0x${signed.raw.slice(4)}`) as string[];
    expect(written[9]).toBe('0x');
    expect((written[11].length - 2) / 2).toBeLessThan(32);
    expect(written[11].startsWith('0x00')).toBe(false);
    expect(readEvmTransaction(signed.raw).ok).toBe(true);
    // The same values patched into the 32 bytes s had, or yParity 0 written as a
    // byte: not canonical RLP, so refused, never sent.
    const lowS = signatureOf(low).s;
    const patched = rewriteType2Field(rewriteType2Field(high, 9, '0x'), 11, toBeHex(lowS, 32));
    for (const returned of [patched, rewriteType2Encoding(low, 9, '0x00'), rewriteType2Encoding(low, 9, '0x8100')]) {
      expect(readEvmTransaction(returned)).toEqual({ ok: false, rule: 'encoding' });
      expect(() => checkSignedTransaction(returned, request, address)).toThrow(expect.objectContaining({ field: 'encoding', rule: 'encoding' }));
    }
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

describe('a signer whose s sits at an edge of EIP-2: a signature no key we hold made, from which a sender recovers', () => {
  const digest = type2SigningHash(REQUEST);

  it('s = (n - 1) / 2 is accepted unchanged, byte for byte', () => {
    for (const yParity of [0, 1] as const) {
      const { r, sender } = firstRecoverableR(digest, HALF_N, yParity);
      const raw = type2WithSignature(REQUEST, { yParity, r, s: HALF_N });
      expect(transactionToBroadcast(raw)).toEqual({ ok: true, raw, lowered: false });
      expect(checkSignedTransaction(raw, REQUEST, sender)).toEqual({ raw, hash: keccak256(raw) });
    }
  });

  // 2^255 - 1 is the largest s ethers' Signature takes, which firstRecoverableR uses to find the sender.
  it.each<[string, bigint]>([
    ['(n - 1) / 2 + 1', HALF_N + 1n],
    ['2^255 - 1', 2n ** 255n - 1n],
  ])('s = %s is lowered to n - s with the other parity, from which the same sender recovers', (_name, s) => {
    for (const yParity of [0, 1] as const) {
      const { r, sender } = firstRecoverableR(digest, s, yParity);
      const raw = type2WithSignature(REQUEST, { yParity, r, s });
      expect(readEvmTransaction(raw)).toEqual({ ok: false, rule: 'signature-values' });
      const signed = checkSignedTransaction(raw, REQUEST, sender);
      expect(signatureOf(signed.raw)).toEqual({ v: BigInt(1 - yParity), r, s: N - s });
      const reading = readEvmTransaction(signed.raw);
      expect(reading.ok && reading.transaction.sender).toBe(sender);
      expect(signed.hash).toBe(keccak256(signed.raw));
      expect(signed.hash).not.toBe(keccak256(raw));
    }
    // n − ((n − 1) / 2 + 1) is (n − 1) / 2 itself, the largest s EIP-2 allows.
    expect(N - (HALF_N + 1n)).toBe(HALF_N);
  });
});

describe('what a private key signs never needs the lowering', () => {
  it('over 300 random transactions a Wallet signs, item 2 reads every one with s at most (n - 1) / 2, and the writer sends an EIP-1559 one unchanged', async () => {
    // ethers signs with s at most (n - 1) / 2, so the lowering is reached only
    // through an external signer: in these tests, the mocks in signer-faults.ts.
    const wallets = [Wallet.createRandom(), Wallet.createRandom(), Wallet.createRandom()];
    const big = (bytes: number): bigint => BigInt(hexlify(randomBytes(bytes)));
    for (let i = 0; i < 300; i++) {
      const signer = wallets[i % wallets.length];
      const maxFeePerGas = big(8) + 1n;
      const request: AnchorTransactionRequest = {
        type: 2,
        chainId: big(4) + 1n,
        nonce: Number(big(4)),
        to: hexlify(randomBytes(20)),
        value: 0n,
        data: hexlify(randomBytes(32)),
        gasLimit: 21_000n + big(2),
        maxFeePerGas,
        maxPriorityFeePerGas: maxFeePerGas - big(4) % maxFeePerGas,
      };
      const type = i % 3;
      const raw =
        type === 2
          ? await signer.signTransaction(request)
          : await signer.signTransaction({ ...request, type, gasPrice: request.maxFeePerGas, maxFeePerGas: undefined, maxPriorityFeePerGas: undefined });
      expect(signatureOf(raw).s <= HALF_N).toBe(true);
      const reading = readEvmTransaction(raw);
      expect(reading.ok && reading.transaction.sender).toBe(signer.address.toLowerCase());
      expect(transactionToBroadcast(raw)).toEqual({ ok: true, raw, lowered: false });
      if (type === 2) expect(checkSignedTransaction(raw, request, signer.address.toLowerCase())).toEqual({ raw, hash: keccak256(raw) });
    }
  });
});

/**
 * The five distinct signed transactions in deo-vectors-1.0.tar.gz, the
 * conformance-vector archive published at spec.tzun.ai (sha256
 * 9a9cfad0684f6be5c0789006ac1830faffed7983a6ea3708bfb9d5002a8d2170): the
 * publications of its `anchor-e2e-vectors.json` and its b1 bundles, signed on
 * anvil by the development account 5.
 */
const DEO_VECTORS_1_0_RAW_TRANSACTIONS = [
  '0x02f88c827a6901843b9aca00848bcd4c46827530949965507d1a55bcc2695c58ba16fb37d819b0a4dc80a03108bcaaf98e468715d18c3324c60b0562024369bd2e146a80705edc3cbcff93c001a0d6662c44e2fa08b3da90dbff99ff24f45db16a1e04468ea820f68683a200deb2a03f02bd6618707c2837e65f72d6f16c491c793bd781cd5d821f7414e77d0cdf9e',
  '0x02f88c827a6901843b9aca00848bcd4c46827530949965507d1a55bcc2695c58ba16fb37d819b0a4dc80a03f7e698dfb8531a729cf806f2b933803c3cd5cb41f4bc91d42cc1a1d7d209f09c080a0206405501b59d2555ffe4d7debac171542fc5c0b976d04fd1af657a35858d006a0606759f94b4391ae4607c2a39fb47f5136a98001d8d88c4af2bbacd7372f0c88',
  '0x02f88c827a6903843b9aca00845fa239c2825708949965507d1a55bcc2695c58ba16fb37d819b0a4dc80a0e2bbbafa3619948d34be8b567096e7eb2a2f97f17e35fe937e3ce73640b53e8cc001a02df721a3dc26f2f19b1f252d5909b80b3cf9cde029dbeeb680bd9c1066d1abc9a07b292f40c0e473e4245070d0b4b00b6eaa0ee400226f988a5ddf5b8855e193eb',
  '0x02f88c827a6980843b9aca0084b2d05e00827530949965507d1a55bcc2695c58ba16fb37d819b0a4dc80a001a37cfc1a2e8a85feb11ec9bac3c26f2ccbf2b0dfe1fa026cce0d5bc909ccfec001a0c532769cb62bd7d805986a78ab38f0f2c6ece6638b4ca9c4c4806d9e7edfe9dda02a97138aff0f3102cae6ba0b3dcd60b5c1a57623c4c984bf23280d0a476bfe2a',
  '0x02f88c827a6980843b9aca0084b2d05e00827530949965507d1a55bcc2695c58ba16fb37d819b0a4dc80a0ce160e900de68182541b9ef62cd84523717d9c83796243536d842ca87c8b5f7dc001a071a3adee7b979cf83f7d262e35794c62d53e0916a84dcaf91621647dc1a056d7a00a11de0dc0fd9f7711fdfa5abd28c847dc4f3a2d1ff876caefec8bc60daa4d9e',
];

/** Every distinct `rawTransaction` member in a JSON value. */
function rawTransactionsIn(value: unknown, found = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    for (const v of value) rawTransactionsIn(v, found);
  } else if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (k === 'rawTransaction' && typeof v === 'string') found.add(v.toLowerCase());
      else rawTransactionsIn(v, found);
    }
  }
  return found;
}

/** The publications of this repository's anchor vectors: `anchor-e2e-vectors.json` and the b1 bundles. */
function repositoryVectorRawTransactions(): string[] {
  const vectors = join(__dirname, '..', '..', 'vectors');
  const found = rawTransactionsIn(JSON.parse(readFileSync(join(vectors, 'anchor-e2e-vectors.json'), 'utf8')));
  for (const dir of readdirSync(join(vectors, 'bundle-b1'), { withFileTypes: true })) {
    if (dir.isDirectory()) rawTransactionsIn(JSON.parse(readFileSync(join(vectors, 'bundle-b1', dir.name, 'bundle.json'), 'utf8')), found);
  }
  return [...found];
}

describe('the publications of the conformance vectors pass the writer\'s check unchanged', () => {
  it.each<[string, string[]]>([
    ['deo-vectors-1.0 (spec.tzun.ai)', DEO_VECTORS_1_0_RAW_TRANSACTIONS],
    ['vectors/ in this repository', repositoryVectorRawTransactions()],
  ])('%s: five transactions, each sent byte for byte', (_name, raws) => {
    expect(new Set(raws).size).toBe(5);
    for (const raw of raws) {
      const tx = Transaction.from(raw);
      const request: AnchorTransactionRequest = {
        type: 2,
        chainId: tx.chainId,
        nonce: tx.nonce,
        to: tx.to!,
        value: tx.value,
        data: tx.data,
        gasLimit: tx.gasLimit,
        maxFeePerGas: tx.maxFeePerGas!,
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas!,
      };
      const reading = readEvmTransaction(raw);
      expect(reading.ok).toBe(true);
      expect(transactionToBroadcast(raw)).toEqual({ ok: true, raw, lowered: false });
      expect(withLowS(raw)).toBeNull();
      expect(checkSignedTransaction(raw, request, reading.ok ? reading.transaction.sender : '')).toEqual({ raw, hash: keccak256(raw) });
    }
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
    // What the wrapped key signed, before the signer made its high-s twin.
    expect(signed.raw).toBe(signer.signed[0].toLowerCase());
    expect(signed.raw).not.toBe(signer.returned[0]);
    expect(signed.hash).not.toBe(keccak256(signer.returned[0]));
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

  it.each([0, 1] as const)('refuses a legacy v of 27 or 28 (27 + %i): low, for its type; high, unlowered, for its s', async (yParity) => {
    const wallet = Wallet.createRandom();
    const low = signLegacy(wallet.signingKey, { data: `0x${p}`, eip155: false, yParity, nonce: fields.nonce, to: wallet.address });
    for (const [returned, refusal] of [
      [low, { field: 'type' }],
      [toHighS(low), { field: 'signature-values', rule: 'signature-values' }],
    ] as const) {
      const publisher = await createSignerPublisher({ signer: { getAddress: async () => wallet.address, signTransaction: async () => returned }, chain: CHAIN, client: chain });
      await expect(publisher.signPublication(p, fields)).rejects.toMatchObject({ code: 'anchor_signer_mismatch', ...refusal });
    }
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
