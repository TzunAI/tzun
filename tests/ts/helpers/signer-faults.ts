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
 * a high `s`, as a KMS or HSM signer can. `returned` holds every transaction
 * it returned, in order.
 */
export function highSSigner(signer: OfflineSigner): AnchorTransactionSigner & { returned: string[] } {
  const returned: string[] = [];
  return {
    returned,
    getAddress: () => signer.getAddress(),
    async signTransaction(request) {
      const raw = toHighS(await signer.signTransaction(request));
      returned.push(raw);
      return raw;
    },
  };
}

const rlpInteger = (n: bigint | number): string => (BigInt(n) === 0n ? '0x' : toBeHex(n));

/**
 * The EIP-1559 transaction `request` describes, signed by `key` over its
 * signing hash with no check on its values: a tip above the fee cap or a chain
 * id of 0, which ethers will not sign, are signed as given.
 */
export function signType2(key: SigningKey, request: AnchorTransactionRequest): string {
  const fields = [
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
  const sig = key.sign(keccak256(concat(['0x02', encodeRlp(fields)])));
  return concat(['0x02', encodeRlp([...fields, rlpInteger(sig.yParity), toBeHex(BigInt(sig.r)), toBeHex(BigInt(sig.s))])]);
}

/** A signed EIP-1559 transaction with its field at `index` written as the RLP string `value`, the signature kept. */
export function rewriteType2Field(raw: string, index: number, value: string): string {
  const fields = decodeRlp(`0x${raw.slice(4)}`) as string[];
  fields[index] = value;
  return concat(['0x02', encodeRlp(fields)]);
}
