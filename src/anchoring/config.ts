/**
 * The anchoring configuration (publishers, cadence and budget) and its
 * validation. The types are declared in `@tzun/engine` beside `TzunConfig`,
 * whose `anchoring` member they are, and re-exported here.
 *
 * Members beyond the publishers, the cadence and the budget:
 *   - `namespace`: the store's `ns` (tzun-anchor/1 §4.3.2). It lives in the
 *     store's immutable identity: `Tzun.init()` mints a new store with it
 *     (as with `logNamespace`), and `createAnchorScheduler` only checks it
 *     against the stored one.
 *   - `publisherManifest`: the verifiers' publisher manifest, which the
 *     activation guard reads.
 *   - `autoStart`: whether `Tzun.init()` starts the schedule.
 * The scheduler's own tunables (tick, lease, stuck threshold, fill chunk) are
 * options of `createAnchorScheduler`, not configuration a deployment is
 * expected to change.
 *
 * The publisher's key is given in exactly one of two ways: `privateKey`, or
 * `signer`, an external signer (an ethers `Signer`, a KMS or HSM signer) that
 * keeps the key where the customer keeps it.
 *
 * Cadence and fee caps are per deployment, configurable per customer. They
 * are configuration, not wire format, and never freeze.
 */
import { Wallet } from 'ethers';
import type {
  AnchorBudget,
  AnchorCadence,
  AnchorTransactionSigner,
  AnchoringConfig,
  PublisherManifest,
} from '@tzun/engine';
import { assertLogNamespace } from '../storage/log-store';
import { AnchoringConfigError } from './errors';

export type {
  AnchorBudget,
  AnchorCadence,
  AnchorTransactionRequest,
  AnchorTransactionSigner,
  AnchoringConfig,
  EvmPublisherConfig,
  WriteOnceSink,
} from '@tzun/engine';

export const DEFAULT_ANCHOR_CADENCE: Readonly<AnchorCadence> = Object.freeze({
  targetIntervalMs: 60 * 60_000,
  minIntervalMs: 10 * 60_000,
  sizeTrigger: 10_000,
  maxStalenessMs: 24 * 60 * 60_000,
});

export const DEFAULT_ANCHOR_BUDGET: Readonly<AnchorBudget> = Object.freeze({
  runwayDays: 180,
  softMaxFeeGwei: 20,
  hardFeeCapGwei: 50,
  forcePerDay: 6,
});

/** How long the SDK waits for the signer by default (`publishers.evm.signTimeoutMs`). */
export const DEFAULT_SIGN_TIMEOUT_MS = 60_000;

/** The EVM publisher, checked: `rpcUrl`, `chain`, exactly one of `privateKey` and `signer`, and the signing deadline. */
export interface ResolvedEvmPublisher {
  rpcUrl: string;
  chain: string;
  privateKey?: string;
  signer?: AnchorTransactionSigner;
  signTimeoutMs: number;
}

/** The configuration with every default applied. */
export interface ResolvedAnchoringConfig {
  evm: ResolvedEvmPublisher;
  cadence: AnchorCadence;
  budget: AnchorBudget;
  production: boolean;
  namespace: string | undefined;
  /** The verifiers' publisher manifest, for the activation guard and the scanner. */
  publisherManifest: PublisherManifest | undefined;
  /** The scanner's check-g floors, by CAIP-10 account. */
  nonceBases: Record<string, number> | undefined;
  /** `Tzun.init()` starts the schedule. */
  autoStart: boolean;
}

const PRIVATE_KEY = /^0x[0-9a-fA-F]{64}$/;
const EIP155 = /^eip155:[1-9][0-9]{0,30}$/;
const EIP155_ACCOUNT = /^eip155:[1-9][0-9]{0,30}:0x[0-9a-fA-F]{40}$/;

/** Whether `value` can be asked for an address and a signature. */
function isTransactionSigner(value: unknown): value is AnchorTransactionSigner {
  const s = value as Partial<AnchorTransactionSigner> | null;
  return typeof s === 'object' && s !== null && typeof s.getAddress === 'function' && typeof s.signTransaction === 'function';
}

function positiveInteger(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new AnchoringConfigError(`anchoring.${name} must be a positive integer (got ${String(value)}).`);
  }
  return value;
}

function positiveNumber(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new AnchoringConfigError(`anchoring.${name} must be a positive number (got ${String(value)}).`);
  }
  return value;
}

/**
 * Check `config` and apply the defaults. Every refusal names the field and
 * never echoes the private key.
 *
 * @throws {AnchoringConfigError}
 */
export function resolveAnchoringConfig(config: AnchoringConfig): ResolvedAnchoringConfig {
  if (typeof config !== 'object' || config === null) {
    throw new AnchoringConfigError('anchoring must be an object.');
  }
  const publishers = config.publishers;
  if (typeof publishers !== 'object' || publishers === null) {
    throw new AnchoringConfigError('anchoring.publishers is required.');
  }
  if (publishers.rfc3161 === true) {
    throw new AnchoringConfigError(
      'anchoring.publishers.rfc3161: the rfc3161/1 publication is not built yet. Publish through evm.',
    );
  }
  if (config.mirror !== undefined) {
    throw new AnchoringConfigError('anchoring.mirror: the write-once mirror arrives with the rfc3161/1 publisher and is not built yet.');
  }
  const evm = publishers.evm;
  if (evm === undefined) {
    throw new AnchoringConfigError('anchoring.publishers.evm is required: it is the only publication kind built so far.');
  }
  if (typeof evm.rpcUrl !== 'string' || !/^https?:\/\//.test(evm.rpcUrl)) {
    throw new AnchoringConfigError('anchoring.publishers.evm.rpcUrl must be an http(s) URL.');
  }
  const hasKey = evm.privateKey !== undefined;
  const hasSigner = evm.signer !== undefined;
  if (hasKey && hasSigner) {
    throw new AnchoringConfigError(
      'anchoring.publishers.evm takes privateKey or signer, not both: a signer holds the key itself.',
    );
  }
  if (!hasKey && !hasSigner) {
    throw new AnchoringConfigError(
      'anchoring.publishers.evm needs the publisher\'s key: privateKey, or signer (an ethers Signer, or a KMS or HSM signer, that keeps it).',
    );
  }
  if (hasKey && (typeof evm.privateKey !== 'string' || !PRIVATE_KEY.test(evm.privateKey))) {
    throw new AnchoringConfigError('anchoring.publishers.evm.privateKey must be 0x and 64 hex digits.');
  }
  if (hasKey) {
    // 64 hex digits can still be no key: zero, or not below the curve order.
    // The library's own message is replaced, and the key is never echoed.
    try {
      new Wallet(evm.privateKey as string);
    } catch {
      throw new AnchoringConfigError('anchoring.publishers.evm.privateKey is not a valid secp256k1 private key.');
    }
  }
  if (hasSigner && !isTransactionSigner(evm.signer)) {
    throw new AnchoringConfigError(
      'anchoring.publishers.evm.signer must have getAddress() and signTransaction(): an ethers Signer, or a signer built on ethers AbstractSigner.',
    );
  }
  if (typeof evm.chain !== 'string' || !EIP155.test(evm.chain)) {
    throw new AnchoringConfigError('anchoring.publishers.evm.chain must be a CAIP-2 EVM chain, eip155:<decimal chain id>.');
  }
  const signTimeoutMs = evm.signTimeoutMs === undefined ? DEFAULT_SIGN_TIMEOUT_MS : positiveInteger(evm.signTimeoutMs, 'publishers.evm.signTimeoutMs');
  if (config.production !== undefined && typeof config.production !== 'boolean') {
    throw new AnchoringConfigError('anchoring.production must be a boolean.');
  }
  if (config.autoStart !== undefined && typeof config.autoStart !== 'boolean') {
    throw new AnchoringConfigError('anchoring.autoStart must be a boolean.');
  }
  const manifest = config.publisherManifest as unknown;
  if (
    manifest !== undefined &&
    (typeof manifest !== 'object' || manifest === null || typeof (manifest as { publishers?: unknown }).publishers !== 'object' || (manifest as { publishers?: unknown }).publishers === null)
  ) {
    throw new AnchoringConfigError('anchoring.publisherManifest must be a publisher manifest: { publishers: { <anchor origin>: [entries] } }.');
  }
  const nonceBases = config.nonceBases as unknown;
  if (nonceBases !== undefined) {
    if (typeof nonceBases !== 'object' || nonceBases === null || Array.isArray(nonceBases)) {
      throw new AnchoringConfigError('anchoring.nonceBases must be an object: { <CAIP-10 account>: <nonce> }.');
    }
    for (const [account, base] of Object.entries(nonceBases)) {
      if (!EIP155_ACCOUNT.test(account)) {
        throw new AnchoringConfigError(`anchoring.nonceBases: ${JSON.stringify(account)} is not a CAIP-10 EVM account, eip155:<chain id>:0x<40 hex>.`);
      }
      if (typeof base !== 'number' || !Number.isSafeInteger(base) || base < 0) {
        throw new AnchoringConfigError(`anchoring.nonceBases[${JSON.stringify(account)}] must be a non-negative integer (got ${String(base)}).`);
      }
    }
  }
  let namespace: string | undefined;
  if (config.namespace !== undefined) {
    try {
      namespace = assertLogNamespace(config.namespace);
    } catch (err) {
      throw new AnchoringConfigError(`anchoring.namespace: ${(err as Error).message}`);
    }
  }

  const cadence: AnchorCadence = { ...DEFAULT_ANCHOR_CADENCE, ...(config.cadence ?? {}) };
  positiveInteger(cadence.targetIntervalMs, 'cadence.targetIntervalMs');
  positiveInteger(cadence.minIntervalMs, 'cadence.minIntervalMs');
  positiveInteger(cadence.sizeTrigger, 'cadence.sizeTrigger');
  positiveInteger(cadence.maxStalenessMs, 'cadence.maxStalenessMs');
  if (cadence.minIntervalMs > cadence.targetIntervalMs || cadence.targetIntervalMs > cadence.maxStalenessMs) {
    throw new AnchoringConfigError(
      'anchoring.cadence must satisfy minIntervalMs <= targetIntervalMs <= maxStalenessMs.',
    );
  }

  const budget: AnchorBudget = { ...DEFAULT_ANCHOR_BUDGET, ...(config.budget ?? {}) };
  positiveNumber(budget.runwayDays, 'budget.runwayDays');
  positiveNumber(budget.softMaxFeeGwei, 'budget.softMaxFeeGwei');
  positiveNumber(budget.hardFeeCapGwei, 'budget.hardFeeCapGwei');
  positiveInteger(budget.forcePerDay, 'budget.forcePerDay');
  if (budget.softMaxFeeGwei > budget.hardFeeCapGwei) {
    throw new AnchoringConfigError('anchoring.budget.softMaxFeeGwei must not exceed hardFeeCapGwei.');
  }

  return {
    evm: hasKey
      ? { rpcUrl: evm.rpcUrl, chain: evm.chain, privateKey: evm.privateKey as string, signTimeoutMs }
      : { rpcUrl: evm.rpcUrl, chain: evm.chain, signer: evm.signer as AnchorTransactionSigner, signTimeoutMs },
    cadence,
    budget,
    production: config.production === true,
    namespace,
    publisherManifest: manifest as PublisherManifest | undefined,
    nonceBases: nonceBases === undefined ? undefined : { ...(nonceBases as Record<string, number>) },
    autoStart: config.autoStart !== false,
  };
}
