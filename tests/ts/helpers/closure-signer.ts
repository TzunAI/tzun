/**
 * An ethers signer in the shape of a KMS or HSM signer, for the external-signer
 * tests: an `AbstractSigner` whose key lives in a
 * closure, reached only by a signing function. It answers `getAddress()` and
 * `signTransaction()`, and records what it was asked to sign. Never a real key.
 */
import { AbstractSigner, SigningKey, Transaction, computeAddress, type Provider, type TransactionRequest } from 'ethers';

export class ClosureSigner extends AbstractSigner {
  readonly signed: TransactionRequest[] = [];
  private readonly sign: (digest: string) => ReturnType<SigningKey['sign']>;
  private readonly address: string;

  constructor(privateKey: string, provider: Provider | null = null) {
    super(provider);
    const key = new SigningKey(privateKey);
    this.sign = (digest) => key.sign(digest);
    this.address = computeAddress(key.publicKey);
  }

  async getAddress(): Promise<string> {
    return this.address;
  }

  connect(provider: Provider | null): ClosureSigner {
    void provider;
    throw new Error('a closure signer does not reconnect');
  }

  async signTransaction(request: TransactionRequest): Promise<string> {
    this.signed.push(request);
    const tx = Transaction.from(request as Parameters<typeof Transaction.from>[0]);
    tx.signature = this.sign(tx.unsignedHash);
    return tx.serialized;
  }

  async signMessage(): Promise<string> {
    throw new Error('not a message signer');
  }

  async signTypedData(): Promise<string> {
    throw new Error('not a typed-data signer');
  }
}
