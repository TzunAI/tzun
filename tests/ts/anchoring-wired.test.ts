/**
 * Anchoring wired into `Tzun`: `Tzun.init({ anchoring, logNamespace })` runs
 * the anchor scheduler on its store, starts and stops it with the instance,
 * and answers `getAnchorState()` and `anchorNow()`; a record expects an
 * anchor from its capture; `get()` reports when its epoch is due; `verify()`
 * decides its anchor. The publisher's key is a private key or an external
 * signer the SDK only asks for an address and signatures.
 *
 * The chain is the in-memory one the scheduler's own suite uses
 * (tests/ts/helpers/anchoring-fake-chain.ts), handed to `Tzun.init` through
 * its internal test seam; the anvil suite (tests/anvil/) runs the same wiring
 * against a real node. On SQLite always, and on Postgres when its legs run.
 */
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SigningKey, Transaction, Wallet, computeAddress, keccak256 } from 'ethers';
import type { AnchorTransactionRequest, AnchorTransactionSigner, CaptureInput, TzunConfig } from '@tzun/engine';
import {
  Tzun,
  AnchorActivationError,
  AnchorForceRateLimitedError,
  AnchoringConfigError,
  InvalidLogNamespaceError,
  LogNamespaceMismatchError,
  verifyAnchor,
} from '../../src/sdk/index';
import { AttestationRetryScheduler } from '../../src/sdk/attestation-retry-scheduler';
import { anchorStoreFor, logStoreFor } from '../../src/storage/log-store';
import { readEvmTransaction, type EvmHeaderSource } from '../../src/attestation/blockchain';
import { withLowS } from '../../src/anchoring/evm-chain';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { highSSigner, rewriteType2Field, signType2 } from './helpers/signer-faults';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const CHAIN = 'eip155:31337';
const NS = 'test.wired.tzun';
const ETH = 10n ** 18n;
const HOUR = 60 * 60_000;

const decision = (i: number): CaptureInput => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', i },
  action: 'approved',
  reason: `record ${i}`,
});

/** The fake chain as a verifier's own header source. */
function headerSource(chain: FakeEvmChain): EvmHeaderSource {
  return {
    finality: 'finalized',
    chainId: () => chain.chainId(),
    finalizedBlockNumber: () => chain.finalizedBlockNumber(),
    canonicalBlock: (n) => chain.canonicalBlock(n),
    transaction: async (id) => {
      const t = await chain.transaction(id);
      return t ? { from: t.from, blockHash: t.blockHash, blockNumber: t.blockNumber } : null;
    },
  };
}

/**
 * A signer in the shape of a KMS or HSM signer: the key lives in a closure no
 * caller can reach, and the object answers `getAddress()` and
 * `signTransaction()` and nothing else. Every property the SDK reads on it is
 * recorded, so a test can show the SDK asks for nothing but an address and
 * signatures.
 */
function closureSigner(privateKey: string): { signer: AnchorTransactionSigner; reads: string[]; requests: AnchorTransactionRequest[] } {
  const key = new SigningKey(privateKey);
  const address = computeAddress(key.publicKey);
  const reads: string[] = [];
  const requests: AnchorTransactionRequest[] = [];
  const target: AnchorTransactionSigner = {
    async getAddress() {
      return address;
    },
    async signTransaction(request) {
      requests.push(request);
      const tx = Transaction.from(request);
      tx.signature = key.sign(tx.unsignedHash);
      return tx.serialized;
    },
  };
  const signer = new Proxy(target, {
    get(t, prop, receiver) {
      if (typeof prop === 'string') reads.push(prop);
      return Reflect.get(t, prop, receiver);
    },
  });
  return { signer, reads, requests };
}

interface Backend {
  name: 'sqlite' | 'postgres';
  /** The config keys that open a fresh, empty store for one case. */
  fresh(): Promise<Record<string, unknown>>;
  /** The config keys that open the store `fresh()` last opened. */
  same(): Record<string, unknown>;
  dispose(): void;
}

function sqliteBackend(): Backend {
  let dir: string | undefined;
  let file = '';
  return {
    name: 'sqlite',
    async fresh() {
      if (dir) rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), 'tzun-test-anchoring-wired-'));
      file = join(dir, 'store.db');
      return { dbPath: file };
    },
    same: () => ({ dbPath: file }),
    dispose() {
      if (dir) rmSync(dir, { recursive: true, force: true });
    },
  };
}

function postgresBackend(): Backend | undefined {
  const schema = pgSuiteSchema('anchoring_wired');
  if (!PG_TESTS_ENABLED) return undefined;
  return {
    name: 'postgres',
    async fresh() {
      await schema.reset();
      return { dbUrl: schema.url };
    },
    same: () => ({ dbUrl: schema.url }),
    dispose: () => undefined,
  };
}

const backends = [sqliteBackend(), postgresBackend()].filter((b): b is Backend => b !== undefined);

type KeyKind = 'privateKey' | 'external signer';

describe.each(backends.map((b) => [b.name, b] as const))('Tzun with anchoring on %s', (_name, backend: Backend) => {
  jest.setTimeout(60_000);
  let chain: FakeEvmChain;
  let wallet: Wallet;
  const open: Tzun[] = [];

  beforeEach(() => {
    chain = new FakeEvmChain();
    wallet = Wallet.createRandom() as unknown as Wallet;
    chain.fund(wallet.address, ETH);
  });

  afterEach(async () => {
    for (const t of open.splice(0)) await t.close();
  });

  afterAll(() => backend.dispose());

  function publisherConfig(kind: KeyKind): TzunConfig['anchoring'] & object {
    const evm =
      kind === 'privateKey'
        ? { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, privateKey: wallet.privateKey }
        : { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer: closureSigner(wallet.privateKey).signer };
    return { publishers: { evm }, autoStart: false };
  }

  async function init(storeKeys: Record<string, unknown>, extra: Partial<TzunConfig> = {}): Promise<Tzun> {
    const tzun = await Tzun.init({
      mode: 'dev',
      ...storeKeys,
      logNamespace: NS,
      anchoring: publisherConfig('privateKey'),
      _anchorChainClient: chain,
      ...extra,
    } as TzunConfig);
    open.push(tzun);
    return tzun;
  }

  /** Mine and pass until the epoch's publication is final and its records filled. */
  async function settle(tzun: Tzun): Promise<void> {
    for (let i = 0; i < 10; i++) {
      chain.mine(3);
      await tzun.anchorNow();
      const state = (await tzun.getAnchorState())!;
      if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) return;
    }
    throw new Error('the publication did not settle');
  }

  describe.each<[KeyKind]>([['privateKey'], ['external signer']])('publishing with a %s', (kind) => {
    it('captures expect an anchor; an epoch is published, finalized and filled; get() and verify() follow it (Anchor §10.9)', async () => {
      const tzun = await init(await backend.fresh(), { anchoring: publisherConfig(kind) });
      const captured = await tzun.capture(decision(1));
      await tzun.capture(decision(2));
      const id = captured.envelope.payload.evidenceId;
      // No timestamp is configured in dev mode; the anchor is expected, and absent.
      expect(captured.envelope.attestationStatus).toBe('pending');
      expect(captured.logPosition?.origin).toMatch(new RegExp(`^${NS.replace(/\./g, '\\.')}/[0-9a-f]{32}/evidence/`));

      // Before any epoch: awaiting it, with when it is due.
      const waiting = (await tzun.get(id))!;
      expect(waiting.anchorState).toMatchObject({ state: 'awaiting_epoch', anchorValid: null, anchorReason: 'anchor_not_yet_published' });
      const [leaf] = await logStoreFor(tzun.getStorage())!.listLogLeaves(
        (await logStoreFor(tzun.getStorage())!.getEvidenceLogPosition(id))!.logId,
        0,
        1,
      );
      expect(Date.parse(waiting.anchorState!.dueBy!)).toBe(Date.parse(leaf.loggedAt) + HOUR);
      expect(await tzun.verify(id)).toMatchObject({ anchorValid: null, anchorReason: 'anchor_not_yet_published' });

      const state0 = (await tzun.getAnchorState())!;
      expect(state0).toMatchObject({ namespace: 'test', production: false, chain: CHAIN, publisher: wallet.address.toLowerCase() });
      expect(state0.anchorOrigin).toMatch(new RegExp(`^${NS.replace(/\./g, '\\.')}/[0-9a-f]{32}/anchors$`));

      // A forced epoch: one transaction from the publisher, calldata P.
      const report = await tzun.anchorNow({ force: true });
      expect(report.epoch).toMatchObject({ members: 1, forced: true });
      expect(chain.broadcasts).toHaveLength(1);
      const tx = Transaction.from(chain.broadcasts[0]);
      expect(tx.from?.toLowerCase()).toBe(wallet.address.toLowerCase());
      expect(tx.data).toBe(`0x${report.epoch!.p}`);

      const published = (await tzun.get(id))!;
      expect(published.anchorState).toMatchObject({ state: 'awaiting_finality', anchorReason: 'anchor_not_yet_published' });
      expect(published.anchorState).not.toHaveProperty('dueBy');

      await settle(tzun);
      const anchored = (await tzun.get(id))!;
      expect(anchored.anchorState).toMatchObject({ state: 'anchored', anchorValid: null, anchorReason: 'publication_not_checked' });
      // Filled: nothing expected is missing any more.
      expect(anchored.envelope.attestationStatus).toBe('partial');
      expect(anchored.envelope.nonRepudiation.anchor?.publications[0]).toMatchObject({ kind: 'evm-calldata/1', publisher: wallet.address.toLowerCase() });

      // verify() decides the anchor: undecided with no header source; true
      // with the verifier's own manifest and header source, the heavy material
      // joined in from the store.
      // The verdict's namespace, finality and existed-by ride along, so a
      // display can say "test" or "not final" rather than "anchored".
      expect(await tzun.verify(id)).toMatchObject({
        verified: true,
        anchorValid: null,
        anchorReason: 'publication_not_checked',
        anchorNamespace: 'test',
        anchorFinality: null,
        existedBy: null,
      });
      const manifest = { publishers: { [state0.anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' as const }] } };
      const checked = await tzun.verify(id, undefined, { anchor: { publisherManifest: manifest, evmHeaderSources: { [CHAIN]: headerSource(chain) } } });
      expect(checked).toMatchObject({
        verified: true,
        anchorValid: true,
        anchorNamespace: 'test',
        anchorFinality: 'finalized',
        existedBy: { at: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/), source: 'evm-calldata' },
      });
      expect(checked).not.toHaveProperty('anchorReason');
      // A depth the caller accepts as not final is named, not hidden.
      const shallow: EvmHeaderSource = { ...headerSource(chain), finality: { confirmations: 2, acceptNonFinal: true } };
      expect(await tzun.verify(id, undefined, { anchor: { publisherManifest: manifest, evmHeaderSources: { [CHAIN]: shallow } } })).toMatchObject({
        anchorValid: true,
        anchorFinality: { confirmations: 2, acceptNonFinal: true },
      });
      // A record with no anchor carries none of them.
      const unanchoredId = (await tzun.capture(decision(3))).envelope.payload.evidenceId;
      const unanchored = await tzun.verify(unanchoredId);
      for (const field of ['anchorNamespace', 'anchorFinality', 'existedBy']) expect(unanchored).not.toHaveProperty(field);
      // The envelope alone carries no raw transaction: what made verify() true
      // is the material the store holds for the publication, joined in.
      const direct = await verifyAnchor(anchored.envelope.nonRepudiation, anchored.envelope.integrity.canonicalDigest, {
        sequenceNumber: anchored.envelope.payload.sequenceNumber,
        publisherManifest: manifest,
        evmHeaderSources: { [CHAIN]: headerSource(chain) },
      });
      expect(direct).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked', anchorNamespace: 'test' });
      expect(direct.checks.find((c) => c.id === 'anchor.evm.tx[0]')).toMatchObject({ reason: 'not_in_bundle:raw_transaction' });
    });

    it('enrols a wallet that already sent 3 transactions at nonce_base 3, and publishes at nonce 3 (Anchor §7.2)', async () => {
      for (let i = 0; i < 3; i++) await chain.sendExternal(wallet);
      chain.mine(1);
      const tzun = await init(await backend.fresh(), { anchoring: publisherConfig(kind) });
      await tzun.capture(decision(1));
      await tzun.anchorNow({ force: true });
      const state = (await tzun.getAnchorState())!;
      expect(state.wallet).toMatchObject({ enrolled: true, nonceBase: 3 });
      expect(state.inFlight).toEqual([expect.objectContaining({ nonce: 3, attempts: 1 })]);
      expect(Transaction.from(chain.broadcasts[chain.broadcasts.length - 1]).nonce).toBe(3);
    });
  });

  it('an external signer is asked for its address and for signatures, and for nothing else', async () => {
    const { signer, reads, requests } = closureSigner(wallet.privateKey);
    const tzun = await init(await backend.fresh(), { anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer } }, autoStart: false } });
    await tzun.capture(decision(1));
    await tzun.anchorNow({ force: true });
    expect(new Set(reads)).toEqual(new Set(['getAddress', 'signTransaction']));
    expect(requests).toEqual([
      expect.objectContaining({ type: 2, chainId: 31337n, nonce: 0, to: wallet.address.toLowerCase(), value: 0n, gasLimit: 30_000n }),
    ]);
  });

  it('a signer that returns another transaction than the one asked for: nothing is stored or sent, and the alarm says why', async () => {
    const other = Wallet.createRandom();
    const tampering: AnchorTransactionSigner = {
      getAddress: async () => wallet.address,
      signTransaction: async (request) => wallet.signTransaction({ ...request, nonce: request.nonce + 1 }),
    };
    const foreign: AnchorTransactionSigner = {
      getAddress: async () => wallet.address,
      signTransaction: async (request) => other.signTransaction(request),
    };
    for (const signer of [tampering, foreign]) {
      chain = new FakeEvmChain();
      chain.fund(wallet.address, ETH);
      const tzun = await init(await backend.fresh(), { anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer } }, autoStart: false } });
      await tzun.capture(decision(1));
      await expect(tzun.anchorNow({ force: true })).rejects.toMatchObject({ code: 'anchor_signer_mismatch' });
      expect(chain.broadcasts).toEqual([]);
      const state = (await tzun.getAnchorState())!;
      expect(state.alarms).toEqual([expect.objectContaining({ code: 'anchor_signer_mismatch', severity: 'critical' })]);
      // The epoch is cut and waits, unsigned: the next pass signs it again.
      const [publication] = await anchorStoreFor(tzun.getStorage())!.listAnchorPublications({ kind: 'evm-calldata/1' });
      expect(publication).toMatchObject({ state: 'prepared', attempts: [] });
      await tzun.close();
    }
  });

  it('a signer that returns a high s: what is stored and broadcast is its signature with n - s, which every rule of tzun-anchor/1 §10.4 item 2 reads, and it verifies', async () => {
    const signer = highSSigner(wallet);
    const tzun = await init(await backend.fresh(), { anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer } }, autoStart: false } });
    const id = (await tzun.capture(decision(1))).envelope.payload.evidenceId;
    await tzun.anchorNow({ force: true });
    expect(signer.returned).toHaveLength(1);
    expect(chain.broadcasts).toHaveLength(1);
    const [sent] = chain.broadcasts;
    expect(sent).toBe(withLowS(signer.returned[0]));
    // The same key's signature over the same hash: the same sender, the same signing hash.
    expect(Transaction.from(sent).unsignedHash).toBe(Transaction.from(signer.returned[0]).unsignedHash);
    const reading = readEvmTransaction(sent);
    expect(reading.ok && reading.transaction.sender).toBe(wallet.address.toLowerCase());
    const [publication] = await anchorStoreFor(tzun.getStorage())!.listAnchorPublications({ kind: 'evm-calldata/1' });
    expect(publication.attempts).toEqual([expect.objectContaining({ rawTx: sent, txHash: keccak256(sent) })]);

    await settle(tzun);
    const state = (await tzun.getAnchorState())!;
    expect(state.alarms).toEqual([]);
    const manifest = { publishers: { [state.anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' as const }] } };
    expect(await tzun.verify(id, undefined, { anchor: { publisherManifest: manifest, evmHeaderSources: { [CHAIN]: headerSource(chain) } } })).toMatchObject({
      verified: true,
      anchorValid: true,
    });
  });

  it('a signer that returns a transaction that meets every rule: it is broadcast byte for byte', async () => {
    const returned: string[] = [];
    const signer: AnchorTransactionSigner = {
      getAddress: async () => wallet.address,
      signTransaction: async (request) => {
        returned.push(await wallet.signTransaction(request));
        return returned[returned.length - 1];
      },
    };
    const tzun = await init(await backend.fresh(), { anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer } }, autoStart: false } });
    await tzun.capture(decision(1));
    await tzun.anchorNow({ force: true });
    expect(chain.broadcasts).toEqual(returned);
  });

  it.each<[string, (key: SigningKey, request: AnchorTransactionRequest) => Promise<string>, string]>([
    ['chain id 0', async (key, request) => signType2(key, { ...request, chainId: 0n }), 'chain-id'],
    ['a tip above the fee cap', async (key, request) => signType2(key, { ...request, maxPriorityFeePerGas: request.maxFeePerGas + 1n }), 'fees'],
    ['RLP that is not canonical', async (key, request) => rewriteType2Field(signType2(key, request), 1, '0x0000'), 'encoding'],
  ])('a signer that returns a transaction with %s: nothing is stored or sent, and the error and the alarm name the rule', async (_name, make, rule) => {
    const signer: AnchorTransactionSigner = {
      getAddress: async () => wallet.address,
      signTransaction: (request) => make(wallet.signingKey, request),
    };
    const tzun = await init(await backend.fresh(), { anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer } }, autoStart: false } });
    await tzun.capture(decision(1));
    await expect(tzun.anchorNow({ force: true })).rejects.toMatchObject({ code: 'anchor_signer_mismatch', field: rule, rule });
    expect(chain.broadcasts).toEqual([]);
    const state = (await tzun.getAnchorState())!;
    expect(state.alarms).toEqual([expect.objectContaining({ code: 'anchor_signer_mismatch', severity: 'critical' })]);
    expect(state.alarms[0].message).toContain(`(${rule}: `);
    const [publication] = await anchorStoreFor(tzun.getStorage())!.listAnchorPublications({ kind: 'evm-calldata/1' });
    expect(publication).toMatchObject({ state: 'prepared', attempts: [] });
  });

  it('a signer that never answers fails the pass within signTimeoutMs, with an alarm, and close() still returns', async () => {
    let asked = 0;
    const hanging: AnchorTransactionSigner = {
      getAddress: async () => wallet.address,
      signTransaction: () => {
        asked += 1;
        return new Promise<string>(() => undefined);
      },
    };
    const tzun = await init(await backend.fresh(), {
      anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer: hanging, signTimeoutMs: 100 } }, autoStart: false },
    });
    await tzun.capture(decision(1));
    await expect(tzun.anchorNow({ force: true })).rejects.toMatchObject({ code: 'anchor_signer_unavailable', step: 'signTransaction' });
    expect(asked).toBe(1);
    expect(chain.broadcasts).toEqual([]);
    const state = (await tzun.getAnchorState())!;
    expect(state.alarms).toEqual([expect.objectContaining({ code: 'anchor_signer_unavailable', severity: 'warning' })]);
    expect(state.stalledPasses).toBe(1);
    const [publication] = await anchorStoreFor(tzun.getStorage())!.listAnchorPublications({ kind: 'evm-calldata/1' });
    expect(publication).toMatchObject({ state: 'prepared', attempts: [] });

    // A pass in flight on the hanging signer: close() waits for it, and the
    // deadline ends it.
    const inFlight = tzun.anchorNow().catch((err: Error) => err);
    for (let i = 0; i < 50 && asked < 2; i++) await new Promise((r) => setTimeout(r, 10));
    expect(asked).toBe(2);
    const closed = await Promise.race([tzun.close().then(() => 'closed'), new Promise((r) => setTimeout(() => r('hung'), 3_000))]);
    expect(closed).toBe('closed');
    open.splice(open.indexOf(tzun), 1);
    expect(await inFlight).toMatchObject({ code: 'anchor_signer_unavailable' });
  });

  it('a signer whose getAddress() never answers is refused at init, and the store is released', async () => {
    const hanging: AnchorTransactionSigner = { getAddress: () => new Promise<string>(() => undefined), signTransaction: async () => '0x' };
    const store = await backend.fresh();
    await expect(
      init(store, { anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer: hanging, signTimeoutMs: 50 } }, autoStart: false } }),
    ).rejects.toMatchObject({ code: 'anchor_signer_unavailable', step: 'getAddress' });
    // The store was closed on the refusal: the next instance opens it.
    const next = await init(backend.same());
    expect((await next.getAnchorState())!.wallet.enrolled).toBe(false);
  });

  it('a signer whose stated address is not the key that signs enrols nothing; fixed, it enrols and publishes', async () => {
    const claimed = Wallet.createRandom();
    chain.fund(claimed.address, ETH);
    const liar: AnchorTransactionSigner = {
      getAddress: async () => claimed.address,
      signTransaction: (request) => wallet.signTransaction(request),
    };
    const store = await backend.fresh();
    const lying = await init(store, { anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer: liar } }, autoStart: false } });
    await lying.capture(decision(1));
    await expect(lying.anchorNow({ force: true })).rejects.toMatchObject({ code: 'anchor_signer_mismatch', field: 'sender' });
    const anchors = anchorStoreFor(lying.getStorage())!;
    expect(await anchors.getAnchorWallet(claimed.address.toLowerCase(), CHAIN)).toBeNull();
    expect((await lying.getAnchorState())!.wallet).toMatchObject({ enrolled: false, nonceBase: null });
    expect(chain.broadcasts).toEqual([]);
    await lying.close();
    open.splice(open.indexOf(lying), 1);

    // The epoch the lying instance persisted was never signed: the next
    // instance re-derives it, and signs it once the cadence calls it due or,
    // as here, when the operator forces it.
    const fixed = await init(backend.same(), { anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, signer: closureSigner(wallet.privateKey).signer } }, autoStart: false } });
    expect((await fixed.anchorNow()).broadcasts).toEqual([]);
    expect((await fixed.anchorNow({ force: true })).broadcasts).toHaveLength(1);
    await settle(fixed);
    const fixedAnchors = anchorStoreFor(fixed.getStorage())!;
    expect(await fixedAnchors.getAnchorWallet(claimed.address.toLowerCase(), CHAIN)).toBeNull();
    expect(await fixedAnchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN)).toMatchObject({ nonceBase: 0, retiredAt: null });
    const [publication] = await fixedAnchors.listAnchorPublications({ kind: 'evm-calldata/1' });
    expect(publication).toMatchObject({ state: 'finalized', fromAddress: wallet.address.toLowerCase() });
  });

  it('two writers with different timestamp expectations: the one whose records the fill would move raises anchor_expectation_mismatch', async () => {
    const store = await backend.fresh();
    // The leader obtains no timestamp; the replica defers one to a TSA that is down.
    const leader = await init(store, { chainId: 'leader' });
    const savedFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      throw new Error('TSA unreachable');
    }) as unknown as typeof fetch;
    try {
      const replica = await init(backend.same(), {
        chainId: 'replica',
        attestation: { deferrable: ['timestamp'], timestamp: { rfc3161Url: 'https://tsa.invalid/tsr' } },
      } as Partial<TzunConfig>);
      await leader.capture(decision(1));
      await replica.capture(decision(2));
      expect((await leader.anchorNow({ force: true })).leader).toBe(true);
      await settle(leader);
      expect((await leader.getAnchorState())!.alarms).toEqual([]);

      const report = await replica.anchorNow();
      expect(report.leader).toBe(false);
      expect(report.alarms).toEqual([expect.objectContaining({ code: 'anchor_expectation_mismatch', severity: 'warning' })]);
      expect(report.alarms[0].message).toMatch(/expect no timestamp; this instance's records expect a timestamp/);
      expect((await replica.getAnchorState())!.alarms.map((a) => a.code)).toEqual(['anchor_expectation_mismatch']);

      // A replica configured like the leader raises nothing.
      const alike = await init(backend.same(), { chainId: 'alike' });
      expect((await alike.anchorNow()).alarms).toEqual([]);
    } finally {
      globalThis.fetch = savedFetch;
    }
  });

  it('getAnchorState() is null, and anchorNow() refuses, on an instance that does not anchor', async () => {
    const store = await backend.fresh();
    const plain = await Tzun.init({ mode: 'dev', ...store } as TzunConfig);
    open.push(plain);
    expect(await plain.getAnchorState()).toBeNull();
    await expect(plain.anchorNow()).rejects.toThrow(/this instance does not anchor/);
  });

  it('starts the schedule with the instance unless autoStart is false, and stops it and releases the lease on close()', async () => {
    const start = jest.spyOn(AttestationRetryScheduler.prototype, 'start');
    try {
      const store = await backend.fresh();
      const started = await init(store, { anchoring: { ...publisherConfig('privateKey'), autoStart: undefined } });
      expect(start).toHaveBeenCalledTimes(1);
      await started.anchorNow();
      expect((await started.getAnchorState())!.lease).toMatchObject({ self: true });
      await started.close();
      open.splice(open.indexOf(started), 1);

      start.mockClear();
      const next = await init(backend.same());
      expect(start).not.toHaveBeenCalled();
      // The lease was released on close(): the next instance leads at once.
      const report = await next.anchorNow();
      expect(report.leader).toBe(true);
    } finally {
      start.mockRestore();
    }
  });

  it('forced publications are limited per rolling 24 hours', async () => {
    const tzun = await init(await backend.fresh(), { anchoring: { ...publisherConfig('privateKey'), budget: { forcePerDay: 1 } } });
    await tzun.capture(decision(1));
    await tzun.anchorNow({ force: true });
    await settle(tzun);
    await tzun.capture(decision(2));
    await expect(tzun.anchorNow({ force: true })).rejects.toBeInstanceOf(AnchorForceRateLimitedError);
  });

  it("a pass that fails while the header follower is still reading rejects the caller's await, and nothing is left unhandled", async () => {
    const tzun = await init(await backend.fresh(), { anchoring: { ...publisherConfig('privateKey'), budget: { forcePerDay: 1 } } });
    await tzun.capture(decision(1));
    await tzun.anchorNow({ force: true });
    await settle(tzun);
    await tzun.capture(decision(2));
    // The follower's read of the node is held until the pass has failed. A
    // rejection with no handler attached would fail this case on its own
    // (jest reports it against the running test), and the caller's await
    // would not settle before the read does.
    let release!: () => void;
    const held = new Promise<null>((resolve) => {
      release = () => resolve(null);
    });
    const follower = (tzun as unknown as { headerFollower: { refresh(): Promise<unknown> } }).headerFollower;
    const read = jest.spyOn(follower, 'refresh').mockImplementation(() => held);
    try {
      const outcome = tzun.anchorNow({ force: true }).then(
        () => 'resolved',
        (error: unknown) => error,
      );
      let timer: NodeJS.Timeout | undefined;
      const waited = new Promise((resolve) => {
        timer = setTimeout(() => resolve('still waiting on the read'), 5_000);
      });
      const first = await Promise.race([outcome, waited]);
      clearTimeout(timer);
      expect(read).toHaveBeenCalledTimes(1);
      expect(first).toBeInstanceOf(AnchorForceRateLimitedError);
    } finally {
      release();
      read.mockRestore();
    }
  });

  it('a store in a namespace that is not test. is refused without production: true, and accepted with it', async () => {
    const store = await backend.fresh();
    await expect(init(store, { logNamespace: 'demo.tzun.ai' })).rejects.toBeInstanceOf(AnchorActivationError);
    const prod = await init(backend.same(), { logNamespace: 'demo.tzun.ai', anchoring: { ...publisherConfig('privateKey'), production: true } });
    expect(await prod.getAnchorState()).toMatchObject({ namespace: 'production', production: true });
    expect(chain.broadcasts).toEqual([]);
  });

  it('logNamespace mints a new store, and a different one on that store is refused loudly', async () => {
    const tzun = await init(await backend.fresh());
    expect((await logStoreFor(tzun.getStorage())!.getStoreIdentity()).ns).toBe(NS);
    await tzun.close();
    open.splice(open.indexOf(tzun), 1);
    await expect(init(backend.same(), { logNamespace: 'test.another.tzun' })).rejects.toBeInstanceOf(LogNamespaceMismatchError);
    // anchoring.namespace alone names the store too.
    const again = await init(backend.same(), { logNamespace: undefined, anchoring: { ...publisherConfig('privateKey'), namespace: NS } });
    expect((await again.getAnchorState())!.anchorOrigin.startsWith(`${NS}/`)).toBe(true);
  });

  it('anchoring.namespace alone mints a new store with it, the demo\'s first boot included', async () => {
    const tzun = await init(await backend.fresh(), { logNamespace: undefined, anchoring: { ...publisherConfig('privateKey'), namespace: 'test.alone.tzun' } });
    expect((await logStoreFor(tzun.getStorage())!.getStoreIdentity()).ns).toBe('test.alone.tzun');
    await tzun.close();
    open.splice(open.indexOf(tzun), 1);

    const demo = await init(await backend.fresh(), {
      logNamespace: undefined,
      anchoring: { ...publisherConfig('privateKey'), namespace: 'demo.tzun.ai', production: true },
    });
    expect((await logStoreFor(demo.getStorage())!.getStoreIdentity()).ns).toBe('demo.tzun.ai');
    expect(await demo.getAnchorState()).toMatchObject({ namespace: 'production', production: true });
  });

  it('a publisher the manifest lists in production is refused on a test. store without production: true', async () => {
    const entry = (namespace: 'production' | 'test') => ({ address: wallet.address, chain: CHAIN, namespace });
    const manifest = (namespace: 'production' | 'test') => ({ publishers: { 'demo.tzun.ai/0123456789abcdef0123456789abcdef/anchors': [entry(namespace)] } });
    const store = await backend.fresh();
    const refusal = init(store, { anchoring: { ...publisherConfig('privateKey'), publisherManifest: manifest('production') } });
    await expect(refusal).rejects.toBeInstanceOf(AnchorActivationError);
    await expect(refusal).rejects.toThrow(`the publisher ${wallet.address.toLowerCase()} is a production publisher in the manifest`);
    // The same key listed only as a test publisher, or with the explicit go.
    const asTest = await init(backend.same(), { anchoring: { ...publisherConfig('privateKey'), publisherManifest: manifest('test') } });
    expect(await asTest.getAnchorState()).toMatchObject({ namespace: 'test', production: false });
    await asTest.close();
    open.splice(open.indexOf(asTest), 1);
    const withGo = await init(backend.same(), { anchoring: { ...publisherConfig('privateKey'), publisherManifest: manifest('production'), production: true } });
    expect(await withGo.getAnchorState()).toMatchObject({ namespace: 'test', production: true });
    expect(chain.broadcasts).toEqual([]);
  });

  it('a closed instance refuses anchorNow() and getAnchorState(), also when called while close() runs', async () => {
    const tzun = await init(await backend.fresh());
    await tzun.capture(decision(1));
    const pass = tzun.anchorNow({ force: true });
    const closing = tzun.close();
    await expect(tzun.anchorNow()).rejects.toThrow('[Tzun] anchorNow(): this instance is closed.');
    await closing;
    open.splice(open.indexOf(tzun), 1);
    expect((await pass).epoch).not.toBeNull();
    await expect(tzun.anchorNow()).rejects.toThrow(/this instance is closed/);
    await expect(tzun.getAnchorState()).rejects.toThrow('[Tzun] getAnchorState(): this instance is closed.');
    // A closed instance that never anchored still answers null.
    const plain = await Tzun.init({ mode: 'dev', ...backend.same() } as TzunConfig);
    await plain.close();
    expect(await plain.getAnchorState()).toBeNull();
  });

  it('the anchor scheduler works through the verifying proxy, and without it', async () => {
    const proxied = await init(await backend.fresh());
    const storage = (proxied as unknown as { storage: unknown }).storage;
    expect(storage).not.toBe(proxied.getStorage());
    expect(logStoreFor(storage)).toBeDefined();
    expect(anchorStoreFor(storage)).toBeDefined();
    await proxied.capture(decision(1));
    expect((await proxied.anchorNow({ force: true })).epoch).not.toBeNull();

    // Another store needs another publisher: a wallet is dedicated to one
    // domain, and a second domain spending its nonces is an alarm.
    chain = new FakeEvmChain();
    wallet = Wallet.createRandom() as unknown as Wallet;
    chain.fund(wallet.address, ETH);
    const bare = await init(await backend.fresh(), { verifyReads: false, _anchorChainClient: chain });
    await bare.capture(decision(1));
    expect((await bare.anchorNow({ force: true })).epoch).not.toBeNull();
  });

  it('an instance that does not anchor still reads the anchor state its store holds, without dueBy', async () => {
    const anchoring = await init(await backend.fresh());
    const { envelope } = await anchoring.capture(decision(1));
    const reader = await Tzun.init({ mode: 'dev', ...backend.same() } as TzunConfig);
    open.push(reader);
    const read = (await reader.get(envelope.payload.evidenceId))!;
    expect(read.anchorState).toMatchObject({ state: 'awaiting_epoch', anchorReason: 'anchor_not_yet_published' });
    expect(read.anchorState).not.toHaveProperty('dueBy');
  });
});

describe('Tzun.init refuses anchoring configurations before it opens a store', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-anchoring-refused-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const key = '0x' + '5a'.repeat(32);
  const evm = { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN };

  it.each<[string, Record<string, unknown>, RegExp]>([
    ['privateKey and signer both', { publishers: { evm: { ...evm, privateKey: key, signer: new Wallet(key) } } }, /privateKey or signer, not both/],
    ['neither privateKey nor signer', { publishers: { evm } }, /needs the publisher's key: privateKey, or signer/],
    ['a signer without signTransaction', { publishers: { evm: { ...evm, signer: { getAddress: async () => '0x' } } } }, /signer must have getAddress\(\) and signTransaction\(\)/],
    ['a malformed private key', { publishers: { evm: { ...evm, privateKey: '0x1234' } } }, /privateKey must be 0x and 64 hex digits/],
    ['rfc3161, not built yet', { publishers: { evm: { ...evm, privateKey: key }, rfc3161: true } }, /rfc3161\/1 publication is not built yet/],
    ['autoStart that is not a boolean', { publishers: { evm: { ...evm, privateKey: key } }, autoStart: 'yes' }, /autoStart must be a boolean/],
    ['a private key of zero', { publishers: { evm: { ...evm, privateKey: '0x' + '00'.repeat(32) } } }, /privateKey is not a valid secp256k1 private key/],
    ['a private key not below the curve order', { publishers: { evm: { ...evm, privateKey: '0x' + 'ff'.repeat(32) } } }, /privateKey is not a valid secp256k1 private key/],
    ['a signTimeoutMs that is not a positive integer', { publishers: { evm: { ...evm, privateKey: key, signTimeoutMs: 0 } } }, /signTimeoutMs must be a positive integer/],
  ])('%s: AnchoringConfigError, and no file is created', async (_label, anchoring, message) => {
    const dbPath = join(dir, 'refused.db');
    const refusal = Tzun.init({ mode: 'dev', dbPath, logNamespace: NS, anchoring } as unknown as TzunConfig);
    await expect(refusal).rejects.toBeInstanceOf(AnchoringConfigError);
    await expect(refusal).rejects.toThrow(message);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('never echoes the private key in a refusal', async () => {
    const secret = '0x' + 'c3'.repeat(32);
    const message = await Tzun.init({
      mode: 'dev',
      dbPath: join(dir, 'secret.db'),
      logNamespace: NS,
      anchoring: { publishers: { evm: { rpcUrl: 'ftp://nowhere', chain: CHAIN, privateKey: secret } } },
    } as TzunConfig).then(
      () => 'not refused',
      (err: Error) => err.message,
    );
    expect(message).toMatch(/rpcUrl/);
    expect(message).not.toContain(secret.slice(2));
  });

  it('a namespace outside test. without production: true is refused before the store is opened', async () => {
    const dbPath = join(dir, 'production.db');
    await expect(
      Tzun.init({ mode: 'dev', dbPath, logNamespace: 'demo.tzun.ai', anchoring: { publishers: { evm: { ...evm, privateKey: key } } } } as TzunConfig),
    ).rejects.toBeInstanceOf(AnchorActivationError);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('anchoring with neither logNamespace nor anchoring.namespace is refused, and no file is created', async () => {
    for (const production of [false, true]) {
      const dbPath = join(dir, `no-namespace-${production}.db`);
      const refusal = Tzun.init({ mode: 'dev', dbPath, anchoring: { publishers: { evm: { ...evm, privateKey: key } }, production } } as TzunConfig);
      await expect(refusal).rejects.toBeInstanceOf(AnchoringConfigError);
      await expect(refusal).rejects.toThrow(/`anchoring` needs the store's namespace: set logNamespace/);
      expect(existsSync(dbPath)).toBe(false);
    }
  });

  it('a publisherManifest that is not a manifest is refused', async () => {
    const dbPath = join(dir, 'bad-manifest.db');
    await expect(
      Tzun.init({ mode: 'dev', dbPath, logNamespace: NS, anchoring: { publishers: { evm: { ...evm, privateKey: key } }, publisherManifest: [] as never } } as TzunConfig),
    ).rejects.toThrow(/anchoring.publisherManifest must be a publisher manifest/);
    expect(existsSync(dbPath)).toBe(false);
  });

  it.each([
    ['not an object', [] as never, /anchoring.nonceBases must be an object/],
    ['a key that is not a CAIP-10 EVM account', { '0x1111111111111111111111111111111111111111': 1 }, /is not a CAIP-10 EVM account/],
    ['a negative nonce', { 'eip155:31337:0x1111111111111111111111111111111111111111': -1 }, /must be a non-negative integer/],
    ['a fractional nonce', { 'eip155:31337:0x1111111111111111111111111111111111111111': 1.5 }, /must be a non-negative integer/],
  ])('anchoring.nonceBases that is %s is refused, and no file is created', async (_label, nonceBases, message) => {
    const dbPath = join(dir, 'bad-nonce-bases.db');
    const refusal = Tzun.init({ mode: 'dev', dbPath, logNamespace: NS, anchoring: { publishers: { evm: { ...evm, privateKey: key } }, nonceBases } } as TzunConfig);
    await expect(refusal).rejects.toBeInstanceOf(AnchoringConfigError);
    await expect(refusal).rejects.toThrow(message);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('anchoring.namespace and logNamespace that differ are refused', async () => {
    const dbPath = join(dir, 'two-namespaces.db');
    await expect(
      Tzun.init({ mode: 'dev', dbPath, logNamespace: NS, anchoring: { publishers: { evm: { ...evm, privateKey: key } }, namespace: 'test.other.tzun' } } as TzunConfig),
    ).rejects.toThrow(/name different namespaces/);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('a malformed logNamespace is refused, and no file is created', async () => {
    const dbPath = join(dir, 'bad-ns.db');
    await expect(Tzun.init({ mode: 'dev', dbPath, logNamespace: 'Not A Namespace' })).rejects.toBeInstanceOf(InvalidLogNamespaceError);
    expect(existsSync(dbPath)).toBe(false);
  });

  it('logNamespace on the cloud transport is refused, before any request', async () => {
    const fetchFn = jest.fn();
    await expect(Tzun.init({ apiKey: 'tzun_test_key', logNamespace: NS, _httpFetchFn: fetchFn } as TzunConfig)).rejects.toThrow(
      /`logNamespace` is refused on the cloud transport/,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('logNamespace names the memory adapter\'s origins too', async () => {
    const tzun = await Tzun.init({ mode: 'dev', logNamespace: 'test.memory.tzun' });
    const { logPosition } = await tzun.capture(decision(1));
    expect(logPosition?.origin.startsWith('test.memory.tzun/')).toBe(true);
    await tzun.close();
  });
});
