/**
 * Transactions an external signer can return that a verifier refuses, for the
 * anchor writer's tests (tzun-anchor/1 §7.2 rule 3, §10.4 item 2): a high `s`,
 * as some KMS and HSM signers return, which the writer lowers before it
 * stores or sends the transaction, and fields ethers will not sign, which the
 * writer refuses. Never a real key.
 */
import { N, concat, decodeRlp, encodeRlp, keccak256, toBeHex, type SigningKey } from 'ethers';
import type { AnchorTransactionRequest, AnchorTransactionSigner } from '@tzun/engine';

/**
 * `raw`, a signed type 0, 1 or 2 transaction whose `s` is at most n/2, with
 * `s` as n − s and the other parity: a typed `yParity` 0 and 1 swap, and a
 * legacy `v` moves to the other of its pair (27 and 28, or c × 2 + 35 and
 * c × 2 + 36). It is the same key's signature over the same hash.
 */
export function toHighS(raw: string): string {
  const typed = parseInt(raw.slice(2, 4), 16) < 0xc0;
  const fields = decodeRlp(typed ? `0x${raw.slice(4)}` : raw) as string[];
  const [parity, , s] = fields.slice(-3).map((x) => (x === '0x' ? 0n : BigInt(x)));
  if (s > N / 2n) throw new Error('the signature already has a high s');
  const flipped = typed ? 1n - parity : parity % 2n === 1n ? parity + 1n : parity - 1n;
  fields[fields.length - 3] = flipped === 0n ? '0x' : toBeHex(flipped);
  fields[fields.length - 1] = toBeHex(N - s);
  const body = encodeRlp(fields);
  return typed ? concat([raw.slice(0, 4), body]) : body;
}

/** What {@link highSSigner} wraps: anything that states an address and signs offline. */
interface OfflineSigner {
  getAddress(): Promise<string>;
  signTransaction(request: AnchorTransactionRequest): Promise<string>;
}

/**
 * An external signer that signs with `signer` and returns each signature with
 * a high `s`, as a KMS or HSM signer can. `requests` holds every request,
 * `signed` every transaction `signer` signed for it, and `returned` the
 * high-`s` twin of each that it returned, in order. Over an ethers `Wallet`, which signs deterministically (RFC 6979),
 * it returns the same bytes every time it is asked for the same transaction.
 */
export function highSSigner(
  signer: OfflineSigner,
): AnchorTransactionSigner & { requests: AnchorTransactionRequest[]; signed: string[]; returned: string[] } {
  const requests: AnchorTransactionRequest[] = [];
  const signed: string[] = [];
  const returned: string[] = [];
  return {
    requests,
    signed,
    returned,
    getAddress: () => signer.getAddress(),
    async signTransaction(request) {
      requests.push(request);
      const low = await signer.signTransaction(request);
      signed.push(low);
      const raw = toHighS(low);
      returned.push(raw);
      return raw;
    },
  };
}

const rlpInteger = (n: bigint | number): string => (BigInt(n) === 0n ? '0x' : toBeHex(n));

/** The unsigned fields of the EIP-1559 transaction `request` describes, as RLP writes them. */
function type2Fields(request: AnchorTransactionRequest): Array<string | never[]> {
  return [
    rlpInteger(request.chainId),
    rlpInteger(request.nonce),
    rlpInteger(request.maxPriorityFeePerGas),
    rlpInteger(request.maxFeePerGas),
    rlpInteger(request.gasLimit),
    request.to,
    rlpInteger(request.value),
    request.data,
    [],
  ];
}

/** The hash an EIP-1559 signature over `request` signs: keccak256(0x02 ‖ rlp(unsigned fields)). */
export function type2SigningHash(request: AnchorTransactionRequest): string {
  return keccak256(concat(['0x02', encodeRlp(type2Fields(request))]));
}

/**
 * The EIP-1559 transaction `request` describes, carrying the signature
 * (`yParity`, `r`, `s`) as given: for a signature no key was asked to make,
 * such as one with `s` at an edge of EIP-2.
 */
export function type2WithSignature(request: AnchorTransactionRequest, sig: { yParity: number; r: bigint; s: bigint }): string {
  return concat(['0x02', encodeRlp([...type2Fields(request), rlpInteger(sig.yParity), rlpInteger(sig.r), rlpInteger(sig.s)])]);
}

/**
 * The EIP-1559 transaction `request` describes, signed by `key` over its
 * signing hash with no check on its values: a tip above the fee cap or a chain
 * id of 0, which ethers will not sign, are signed as given.
 */
export function signType2(key: SigningKey, request: AnchorTransactionRequest): string {
  const sig = key.sign(type2SigningHash(request));
  return type2WithSignature(request, { yParity: sig.yParity, r: BigInt(sig.r), s: BigInt(sig.s) });
}

/** A signed EIP-1559 transaction with its field at `index` written as the RLP string `value`, the signature kept. */
export function rewriteType2Field(raw: string, index: number, value: string): string {
  const fields = decodeRlp(`0x${raw.slice(4)}`) as string[];
  fields[index] = value;
  return concat(['0x02', encodeRlp(fields)]);
}

/**
 * A signed EIP-1559 transaction with its field at `index` written as the
 * bytes `encoded`, whatever RLP they are (`0x8105` for the byte 5, say), the
 * other fields and the signature kept, in a list with a minimal header.
 */
export function rewriteType2Encoding(raw: string, index: number, encoded: string): string {
  const fields = decodeRlp(`0x${raw.slice(4)}`) as Array<string | never[]>;
  const body = concat(fields.map((f, i) => (i === index ? encoded : encodeRlp(f))));
  const length = (body.length - 2) / 2;
  if (length > 0xffff) throw new Error('the list is too long for this helper');
  const header = length <= 55 ? toBeHex(0xc0 + length) : length <= 0xff ? concat(['0xf8', toBeHex(length, 1)]) : concat(['0xf9', toBeHex(length, 2)]);
  return concat(['0x02', header, body]);
}
