/**
 * The scanner's anchoring checks against a real EVM node (anvil, one
 * container for the suite): the store anchored
 * by the anchor scheduler, records captured through `Tzun.capture()`, and the
 * scanner reading the chain over JSON-RPC (`JsonRpcEvmChain`) as its header
 * source, the source of P, and the publisher's transaction count.
 *
 *   - check g: a transaction sent from the publisher key outside the
 *     scheduler leaves its nonce unaccounted;
 *   - the operator's attack: a record rewritten, every trace of its epoch
 *     erased, and the log anchored again with the same key. The records the
 *     rewrite did not touch still carry the first epoch's anchor, published
 *     on chain, so the scanner sees two published histories (`split_view`)
 *     and a log that no longer rebuilds the first one; and the first epoch's
 *     nonce, whose publication the store no longer holds, is unaccounted;
 *   - the scanner of a `Tzun` that anchors, over the JSON-RPC client
 *     `Tzun.init` opens on the publisher's `rpcUrl`: every filled anchor
 *     verified end to end with the manifest, and check g.
 *
 * Every pass reports the node's `finalized` tag as what its anchor verdicts
 * were judged under: `JsonRpcEvmChain` declares it.
 *
 * Skipped, loudly, where Docker cannot run containers, when
 * TZUN_SKIP_ANVIL=1, and under CI unless TZUN_ANVIL=1 (harness.ts).
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Wallet } from 'ethers';
import {
  SchemaRegistry,
  canonicalSerialize,
  computeDigest,
  EvidenceChain,
  type EvidenceEnvelope,
  type MonitoringEvent,
} from '@tzun/engine';
import { Tzun } from '../../src/sdk';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { anchorStoreFor, logStoreFor } from '../../src/storage/log-store';
import { JsonRpcEvmChain, createAnchorScheduler, type AnchorScheduler } from '../../src/anchoring';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { ScheduledScanner, type ScannerAnchoringDeps } from '../../src/monitoring/scheduled-scanner';
import { rewriteStoredEnvelope } from '../ts/helpers/tamper-store';
import { ANVIL_CHAIN_ID, ANVIL_IMAGE, anvilAvailability, startAnvil, type AnvilNode } from './harness';

const CHAIN = `eip155:${ANVIL_CHAIN_ID}`;
const NS = 'test.anvil.tzun';
const HOUR = 60 * 60_000;
const registry = new SchemaRegistry();

const availability = anvilAvailability();
if (!availability.ok) {
  const bar = '!'.repeat(78);
  // eslint-disable-next-line no-console
  console.warn(
    `\n${bar}\n  ANVIL SUITE SKIPPED: ${availability.reason}.\n` +
      `  The scanner's check g and its rewrite-and-re-anchor case run on anvil (${ANVIL_IMAGE}).\n` +
      `  Run tests/anvil/ where Docker works before calling the scanner's anchoring checks tested.\n${bar}\n`,
  );
}
const suite = availability.ok ? describe : describe.skip;

suite('the scanner\'s anchoring checks on anvil', () => {
  jest.setTimeout(300_000);
  let node: AnvilNode;
  let dir: string;
  let offset = 0;
  const clock = (): number => Date.now() + offset;
  const open: Array<{ close(): Promise<void> | void }> = [];
  const schedulers: AnchorScheduler[] = [];

  beforeAll(async () => {
    node = await startAnvil();
  }, 300_000);

  afterAll(async () => {
    await node?.stop();
  });

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-anvil-scan-'));
    offset = 0;
  });

  afterEach(async () => {
    for (const s of schedulers.splice(0)) await s.close().catch(() => undefined);
    for (const o of open.splice(0)) await o.close();
    rmSync(dir, { recursive: true, force: true });
  });

  /** A store minted in the test namespace, with `n` records on `chainId` captured through Tzun.capture(). */
  async function storeWith(chainId: string, n: number): Promise<{ file: string; adapter: SqliteStorageAdapter }> {
    const file = join(dir, `store-${Date.now()}.db`);
    await new SqliteStorageAdapter(file, { logNamespace: NS }).close();
    const tzun = await Tzun.init({ mode: 'dev', dbPath: file, chainId });
    for (let i = 0; i < n; i++) {
      await tzun.capture({ decider: { kind: 'human', id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { chainId, i }, action: 'approved', reason: 'reviewed', aiSystemId: 'anvil-scanner-suite' });
    }
    await tzun.close();
    const adapter = new SqliteStorageAdapter(file);
    open.push(adapter);
    return { file, adapter };
  }

  async function scheduler(adapter: SqliteStorageAdapter, publisher: Wallet): Promise<AnchorScheduler> {
    const s = await createAnchorScheduler({
      storage: adapter,
      clock,
      expectation: {},
      config: { publishers: { evm: { rpcUrl: node.rpcUrl, privateKey: publisher.privateKey, chain: CHAIN } } },
    });
    schedulers.push(s);
    return s;
  }

  /** Cut an epoch, then mine and pass until it is finalized and filled. */
  async function anchorEpoch(s: AnchorScheduler, adapter: SqliteStorageAdapter): Promise<void> {
    offset += HOUR;
    await s.runPass();
    for (let i = 0; i < 10; i++) {
      await node.mine(3);
      await s.runPass();
      const pubs = await anchorStoreFor(adapter)!.listAnchorPublications({ kind: 'evm-calldata/1' });
      if (pubs.length > 0 && pubs.every((p) => p.state === 'finalized' || p.state === 'superseded') && (await s.getAnchorState()).fillBacklog === 0) return;
    }
    throw new Error('the epoch did not settle');
  }

  async function scan(adapter: SqliteStorageAdapter, publisher: Wallet): Promise<MonitoringEvent[]> {
    const identity = await logStoreFor(adapter)!.getStoreIdentity();
    const rpc = new JsonRpcEvmChain(node.rpcUrl, ANVIL_CHAIN_ID);
    open.push({ close: () => rpc.close() });
    const anchoring: ScannerAnchoringDeps = {
      publisherManifest: {
        publishers: { [`${identity.ns}/${identity.storeId}/anchors`]: [{ address: publisher.address, chain: CHAIN, namespace: 'test' }] },
      },
      evmChains: { [CHAIN]: rpc },
      now: clock,
    };
    const bus = new MonitoringEventBus();
    const events: MonitoringEvent[] = [];
    bus.subscribe((e) => events.push(e));
    const scanner = new ScheduledScanner(
      adapter,
      bus,
      registry,
      { batchSize: 100, workers: 2, mode: 'interval', intervalMs: 0, verifyAttestation: true, verifyChainCompleteness: true },
      { anchoring },
    );
    await scanner.runFullPass();
    return events;
  }

  const ofType = <T extends MonitoringEvent['type']>(events: MonitoringEvent[], type: T): Array<Extract<MonitoringEvent, { type: T }>> =>
    events.filter((e): e is Extract<MonitoringEvent, { type: T }> => e.type === type);

  it('a clean anchored store: every filled anchor verifies against the node, and nothing is found', async () => {
    const { adapter } = await storeWith('alpha', 6);
    const publisher = await node.fundedWallet();
    await anchorEpoch(await scheduler(adapter, publisher), adapter);
    const events = await scan(adapter, publisher);
    expect(events.filter((e) => e.type.startsWith('log_') || e.type.startsWith('anchor_') || e.type === 'split_view' || e.type.startsWith('attestation_'))).toEqual([]);
    const done = events.find((e) => e.type === 'scan_completed');
    // Judged at the node's finalized tag, which JsonRpcEvmChain declares.
    expect(done).toMatchObject({ issuesFound: 0, attestationValid: { anchor: 6 }, evmFinality: { [CHAIN]: 'finalized' } });
  });

  it('a payload altered under its stored digest, as in the Sepolia dry run: its anchor is judged on the recomputed digest', async () => {
    const { adapter } = await storeWith('alpha', 4);
    const publisher = await node.fundedWallet();
    await anchorEpoch(await scheduler(adapter, publisher), adapter);
    const [victim] = ((await adapter.list({ chainId: 'alpha' })) as EvidenceEnvelope[]).filter((r) => r.payload.sequenceNumber === 2);
    await rewriteStoredEnvelope(adapter, victim.payload.evidenceId, (e) => {
      e.payload.reason = 'altered under its digest';
    });
    const events = await scan(adapter, publisher);
    expect(ofType(events, 'digest_mismatch').map((e) => e.evidenceId)).toEqual([victim.payload.evidenceId]);
    expect(ofType(events, 'attestation_invalid')).toEqual([
      { type: 'attestation_invalid', evidenceId: victim.payload.evidenceId, component: 'anchor', reason: 'merkle_proof_invalid' },
    ]);
    expect(events.find((e) => e.type === 'scan_completed')).toMatchObject({ attestationValid: { anchor: 3 }, evmFinality: { [CHAIN]: 'finalized' } });
  });

  it('check g: a transaction sent from the publisher key outside the scheduler is an unaccounted nonce', async () => {
    const { adapter } = await storeWith('alpha', 3);
    const publisher = await node.fundedWallet();
    await anchorEpoch(await scheduler(adapter, publisher), adapter);
    expect(ofType(await scan(adapter, publisher), 'anchor_wallet_nonce_unaccounted')).toEqual([]);

    const foreign = await publisher.connect(node.provider).sendTransaction({ to: publisher.address, value: 0n, data: '0xdead' });
    await foreign.wait();
    const events = await scan(adapter, publisher);
    expect(ofType(events, 'anchor_wallet_nonce_unaccounted')).toEqual([
      {
        type: 'anchor_wallet_nonce_unaccounted',
        address: publisher.address.toLowerCase(),
        chain: CHAIN,
        nonce: 1,
        nonceBase: 0,
        epochId: null,
        publicationId: null,
      },
    ]);
  });

  it('a record rewritten and the log anchored again with the same key: split_view, and the log no longer rebuilds what was first published', async () => {
    const { adapter } = await storeWith('alpha', 5);
    const publisher = await node.fundedWallet();
    await anchorEpoch(await scheduler(adapter, publisher), adapter);
    const logs = logStoreFor(adapter)!;
    const log = (await logs.getEvidenceLog('alpha'))!;
    const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
    const records = (await adapter.list({ chainId: 'alpha' })) as EvidenceEnvelope[];
    const victim = records.find((r) => r.payload.sequenceNumber === 3)!;
    const before = records.find((r) => r.payload.sequenceNumber === 2)!;

    // The operator: rewrite record 3 and reseat it, strip its anchor so the
    // fill writes a new one, move its leaf, and erase the epoch.
    const rewritten = await rewriteStoredEnvelope(adapter, victim.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten after the fact';
      e.integrity.canonicalDigest = computeDigest(canonicalSerialize(e.payload as unknown as Record<string, unknown>, registry.get('v1.0')!.hashedFieldSet));
      const link = new EvidenceChain();
      link.restore(before.integrity.canonicalDigest);
      e.integrity.chainLink = link.computeLink(e.integrity.canonicalDigest) as string;
      delete (e.nonRepudiation as Record<string, unknown>).anchor;
    });
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    db.transaction(() => {
      const triggers = db.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'").all() as Array<{ name: string; sql: string }>;
      for (const t of triggers) db.exec(`DROP TRIGGER "${t.name}"`);
      db.prepare('UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 2').run(rewritten.integrity.canonicalDigest, log.logId);
      db.prepare('DELETE FROM log_checkpoints').run();
      db.prepare('DELETE FROM log_leaves WHERE log_id = ?').run(anchorLog.logId);
      db.prepare('DELETE FROM anchor_publications').run();
      db.prepare('DELETE FROM anchor_wallets').run();
      for (const t of triggers) db.exec(t.sql);
    })();
    for (const s of schedulers.splice(0)) await s.close();
    await anchorEpoch(await scheduler(adapter, publisher), adapter);
    const [republished] = await anchorStoreFor(adapter)!.listAnchorPublications({ kind: 'evm-calldata/1' });
    expect(republished).toMatchObject({ nonce: 1, anchorSize: 1, state: 'finalized' });

    const events = await scan(adapter, publisher);
    const views = ofType(events, 'split_view');
    expect(views.map((v) => [v.origin, v.size]).sort()).toEqual(
      [
        [anchorLog.origin, 1],
        [log.origin, 5],
      ].sort(),
    );
    expect(ofType(events, 'log_rewritten_below_anchor')).toContainEqual(
      expect.objectContaining({ origin: log.origin, anchoredSize: 5, authenticated: true, reason: 'leaves_do_not_rebuild_root' }),
    );
    // The first epoch's nonce: the scheduler enrolled the wallet again at 1, and the scanner still accounts from 0.
    expect(ofType(events, 'anchor_wallet_nonce_unaccounted').map((e) => [e.nonce, e.nonceBase, e.publicationId])).toEqual([[0, 0, null]]);
  });

  it("Tzun.init({ anchoring, monitoring }) gives its own scanner the chain: anchors verified end to end, and check g", async () => {
    const publisher = await node.fundedWallet();
    const file = join(dir, 'tzun-test-wired-scanner.db');
    const boot = async (anchoring: Record<string, unknown> = {}): Promise<Tzun> => {
      const t = await Tzun.init({
        mode: 'dev',
        dbPath: file,
        chainId: 'wired',
        logNamespace: NS,
        anchoring: { publishers: { evm: { rpcUrl: node.rpcUrl, chain: CHAIN, privateKey: publisher.privateKey } }, autoStart: false, ...anchoring },
        monitoring: {
          enabled: true,
          scanner: { batchSize: 100, workers: 2, mode: 'interval', intervalMs: 0, verifyAttestation: true, verifyChainCompleteness: true, autoStart: false },
        },
      });
      open.push(t);
      return t;
    };
    const eventsOf = (t: Tzun): MonitoringEvent[] => {
      const events: MonitoringEvent[] = [];
      (t as unknown as { eventBus: MonitoringEventBus }).eventBus.subscribe((e) => events.push(e));
      return events;
    };

    const first = await boot();
    for (let i = 0; i < 3; i++) await first.capture({ decider: { kind: 'human', id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: 'wired', aiSystemId: 'anvil-scanner-suite' });
    await first.anchorNow({ force: true });
    for (let i = 0; i < 10; i++) {
      await node.mine(3);
      await first.anchorNow();
      const state = (await first.getAnchorState())!;
      if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) break;
    }
    const { anchorOrigin, fillBacklog } = (await first.getAnchorState())!;
    expect(fillBacklog).toBe(0);
    await first.close();

    const manifest = { publishers: { [anchorOrigin]: [{ address: publisher.address, chain: CHAIN, namespace: 'test' as const }] } };
    const tzun = await boot({ publisherManifest: manifest });
    const events = eventsOf(tzun);
    await tzun.runScan();
    expect(tzun.getScannerState()!.lastCompletedPass).toMatchObject({
      issuesFound: 0,
      attestationValid: { anchor: 3 },
      evmFinality: { [CHAIN]: 'finalized' },
    });

    const foreign = await publisher.connect(node.provider).sendTransaction({ to: publisher.address, value: 0n, data: '0xdead' });
    await foreign.wait();
    await tzun.runScan();
    expect(ofType(events, 'anchor_wallet_nonce_unaccounted')).toEqual([
      expect.objectContaining({ address: publisher.address.toLowerCase(), chain: CHAIN, nonce: 1, nonceBase: 0, publicationId: null }),
    ]);
  });
});
