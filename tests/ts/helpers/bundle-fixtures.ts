/**
 * Anchored stores for the proof-bundle suites (Bundle §3, §4, §7.3, §7.7; Verification §3.1):
 * a `Tzun` that anchors on the in-memory EVM chain the scheduler's own suite
 * uses (./anchoring-fake-chain.ts), on SQLite always and on Postgres when its
 * legs run, with the verifier inputs an auditor would hold for it: the
 * publisher manifest and a header source that reads the same chain.
 *
 * Not a suite: jest's testMatch is `**\/tests/**\/*.test.ts`.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Wallet } from 'ethers';
import type { CaptureInput, TzunConfig } from '@tzun/engine';
import { Tzun } from '../../../src/sdk/index';
import type { EvmHeaderSource, PublisherManifest } from '../../../src/attestation/blockchain';
import { FakeEvmChain } from './anchoring-fake-chain';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './postgres-test-db';

export const BUNDLE_CHAIN = 'eip155:31337';
export const BUNDLE_NS = 'test.bundle.tzun';

export const decision = (i: number, chainId = 'default'): CaptureInput => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', chain: chainId, i },
  action: 'approved',
  reason: `bundle record ${i}`,
  aiSystemId: 'bundle-suite',
});

/** One store backend: SQLite in a temporary directory, or a Postgres schema. */
export interface BundleBackend {
  name: 'sqlite' | 'postgres';
  /** The config keys that open a fresh, empty store. */
  fresh(): Promise<Record<string, unknown>>;
  dispose(): void;
}

export function sqliteBundleBackend(): BundleBackend {
  const dirs: string[] = [];
  return {
    name: 'sqlite',
    async fresh() {
      const dir = mkdtempSync(join(tmpdir(), 'tzun-test-bundle-'));
      dirs.push(dir);
      return { dbPath: join(dir, 'store.db') };
    },
    dispose() {
      for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
    },
  };
}

/** Undefined unless the Postgres legs run. Call it at the top of a describe, where `pgSuiteSchema` registers its hooks. */
export function postgresBundleBackend(label: string): BundleBackend | undefined {
  const schema = pgSuiteSchema(label);
  if (!PG_TESTS_ENABLED) return undefined;
  return {
    name: 'postgres',
    async fresh() {
      await schema.reset();
      return { dbUrl: schema.url };
    },
    dispose: () => undefined,
  };
}

/** The fake chain as an auditor's own header source. */
export function fakeHeaderSource(chain: FakeEvmChain, finalized?: number): EvmHeaderSource {
  return {
    finality: 'finalized',
    chainId: () => chain.chainId(),
    finalizedBlockNumber: async () => finalized ?? (await chain.finalizedBlockNumber()),
    canonicalBlock: (n) => chain.canonicalBlock(n),
  };
}

/** An anchoring `Tzun` on a fake chain, with what an auditor of its bundles holds. */
export interface AnchoredStore {
  tzun: Tzun;
  chain: FakeEvmChain;
  publisher: Wallet;
  storeKeys: Record<string, unknown>;
  /** The domain's anchor origin. */
  anchorOrigin(): Promise<string>;
  /** The manifest that names the store's publisher for its anchor origin. */
  manifest(): Promise<PublisherManifest>;
  /** A `Tzun` on the same store, on another chain id, that does not anchor. */
  on(chainId: string): Promise<Tzun>;
  /** Capture `n` records on `t` (default: the anchoring instance) and return their evidence ids. */
  capture(n: number, t?: Tzun, chainId?: string): Promise<string[]>;
  /** Cut an epoch and mine until its publication is final and filled. */
  epoch(): Promise<void>;
  close(): Promise<void>;
}

let captureCounter = 0;

export async function anchoredStore(storeKeys: Record<string, unknown>, extra: Partial<TzunConfig> = {}): Promise<AnchoredStore> {
  const chain = new FakeEvmChain();
  const publisher = Wallet.createRandom() as unknown as Wallet;
  chain.fund(publisher.address, 10n ** 21n);
  const open: Tzun[] = [];
  const tzun = await Tzun.init({
    mode: 'dev',
    ...storeKeys,
    logNamespace: BUNDLE_NS,
    anchoring: {
      publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: BUNDLE_CHAIN, privateKey: publisher.privateKey } },
      autoStart: false,
      budget: { forcePerDay: 1_000_000 },
    },
    _anchorChainClient: chain,
    ...extra,
  } as TzunConfig);
  open.push(tzun);
  const anchorOrigin = async () => (await tzun.getAnchorState())!.anchorOrigin;
  const store: AnchoredStore = {
    tzun,
    chain,
    publisher,
    storeKeys,
    anchorOrigin,
    async manifest() {
      return { publishers: { [await anchorOrigin()]: [{ address: publisher.address.toLowerCase(), chain: BUNDLE_CHAIN, namespace: 'test' as const }] } };
    },
    async on(chainId) {
      const t = await Tzun.init({ mode: 'dev', ...storeKeys, chainId } as TzunConfig);
      open.push(t);
      return t;
    },
    async capture(n, t = tzun, chainId = 'default') {
      const ids: string[] = [];
      for (let i = 0; i < n; i++) {
        const r = await t.capture(decision(++captureCounter, chainId));
        if (!r.stored) throw new Error('capture was not stored');
        ids.push(r.envelope.payload.evidenceId);
      }
      return ids;
    },
    async epoch() {
      const report = await tzun.anchorNow({ force: true });
      if (!report.epoch) throw new Error('no epoch was cut');
      for (let i = 0; i < 20; i++) {
        chain.mine(3);
        await tzun.anchorNow();
        const state = (await tzun.getAnchorState())!;
        if (state.halted) throw new Error(`anchoring halted: ${state.halted.code}`);
        if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) return;
      }
      throw new Error('the publication did not settle');
    },
    async close() {
      for (const t of open.splice(0)) await t.close().catch(() => undefined);
    },
  };
  return store;
}
