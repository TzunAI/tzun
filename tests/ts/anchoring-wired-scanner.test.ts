/**
 * The scanner and the chain walk of a `Tzun` that anchors:
 * `Tzun.init({ anchoring, monitoring: { scanner } })` hands its own scanner
 * the anchoring inputs (the chain as header source, source of P and of the
 * publisher's transaction count; the publisher manifest; the cadence's T_max;
 * the check-g floors), so checks e and g, check b against the published P and
 * the end-to-end EVM check run in the SDK's scanner; and
 * `tzun.verifyChainCompleteness()` gives the walk the chain's evidence log, so
 * it reports checks a and h.
 *
 * The chain is the in-memory one the scheduler's suite uses, handed to
 * `Tzun.init` through its internal test seam; tests/anvil/ runs check g
 * against a real node. On SQLite always, and on Postgres when its legs run.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Wallet } from 'ethers';
import {
  EvidenceChain,
  SchemaRegistry,
  canonicalSerialize,
  computeDigest,
  type CaptureInput,
  type EvidenceEnvelope,
  type MonitoringEvent,
  type TzunConfig,
} from '@tzun/engine';
import { Tzun } from '../../src/sdk/index';
import type { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { logStoreFor } from '../../src/storage/log-store';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { rewriteStoredEnvelope } from './helpers/tamper-store';

const CHAIN = 'eip155:31337';
const NS = 'test.wired.tzun';
const ETH = 10n ** 18n;
const hashed = new SchemaRegistry().get('v1.0')!.hashedFieldSet;

const decision = (i: number): CaptureInput => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', i },
  action: 'approved',
  reason: `record ${i}`,
});

const scannerConfig = {
  batchSize: 100,
  workers: 2,
  mode: 'interval' as const,
  intervalMs: 0,
  verifyAttestation: true,
  verifyChainCompleteness: true,
  autoStart: false,
};

interface Backend {
  name: 'sqlite' | 'postgres';
  fresh(): Promise<Record<string, unknown>>;
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
      dir = mkdtempSync(join(tmpdir(), 'tzun-test-wired-scanner-'));
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
  const schema = pgSuiteSchema('anchoring_wired_scanner');
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

describe.each(backends.map((b) => [b.name, b] as const))("a Tzun that anchors gives its own scanner and walk the store's logs and the chain, on %s", (_name, backend) => {
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

  async function init(storeKeys: Record<string, unknown>, anchoring: Record<string, unknown> = {}, extra: Partial<TzunConfig> = {}): Promise<Tzun> {
    const tzun = await Tzun.init({
      mode: 'dev',
      ...storeKeys,
      logNamespace: NS,
      anchoring: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', chain: CHAIN, privateKey: wallet.privateKey } }, autoStart: false, ...anchoring },
      _anchorChainClient: chain,
      monitoring: { enabled: true, scanner: scannerConfig },
      ...extra,
    } as TzunConfig);
    open.push(tzun);
    return tzun;
  }

  /** Every monitoring event the instance's scanner emits. */
  function eventsOf(tzun: Tzun): MonitoringEvent[] {
    const events: MonitoringEvent[] = [];
    (tzun as unknown as { eventBus: MonitoringEventBus }).eventBus.subscribe((e) => events.push(e));
    return events;
  }

  const ofType = <T extends MonitoringEvent['type']>(events: MonitoringEvent[], type: T): Array<Extract<MonitoringEvent, { type: T }>> =>
    events.filter((e): e is Extract<MonitoringEvent, { type: T }> => e.type === type);

  /** Force an epoch, then mine and pass until it is finalized and filled. */
  async function anchorAll(tzun: Tzun): Promise<void> {
    await tzun.anchorNow({ force: true });
    for (let i = 0; i < 10; i++) {
      chain.mine(chain.finalizedDepth + 1);
      await tzun.anchorNow();
      const state = (await tzun.getAnchorState())!;
      if (state.lastFinalized && state.inFlight.length === 0 && state.fillBacklog === 0) return;
    }
    throw new Error('the publication did not settle');
  }

  /** Change rows as a database owner can: around the triggers. */
  async function asOwner(tzun: Tzun, statements: Array<[string, unknown[]]>): Promise<void> {
    const storage = tzun.getStorage() as ReturnType<Tzun['getStorage']> & { unwrap?: () => unknown };
    const adapter = typeof storage.unwrap === 'function' ? storage.unwrap() : storage;
    if (adapter instanceof SqliteStorageAdapter) {
      const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
      db.transaction(() => {
        const triggers = db.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'").all() as Array<{ name: string; sql: string }>;
        for (const t of triggers) db.exec(`DROP TRIGGER "${t.name}"`);
        for (const [sql, params] of statements) db.prepare(sql).run(...params);
        for (const t of triggers) db.exec(t.sql);
      })();
      return;
    }
    const pool = (adapter as PostgresStorageAdapter as unknown as { pool: import('pg').Pool }).pool;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL session_replication_role = 'replica'");
      for (const [sql, params] of statements) {
        let n = 0;
        await client.query(sql.replace(/\?/g, () => `$${++n}`), params);
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /** Rewrite a record's payload and reseat it: a new digest, its own link repaired onto its predecessor. */
  function reseat(tzun: Tzun, record: EvidenceEnvelope, previous: EvidenceEnvelope | undefined): Promise<EvidenceEnvelope> {
    return rewriteStoredEnvelope(tzun.getStorage(), record.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten';
      e.integrity.canonicalDigest = computeDigest(canonicalSerialize(e.payload as unknown as Record<string, unknown>, hashed));
      if (previous) {
        const link = new EvidenceChain();
        link.restore(previous.integrity.canonicalDigest);
        e.integrity.chainLink = link.computeLink(e.integrity.canonicalDigest) as string;
      }
    });
  }

  it("with the verifiers' manifest, every filled anchor is verified end to end by the SDK's own scanner", async () => {
    const storeKeys = await backend.fresh();
    const first = await init(storeKeys);
    for (let i = 1; i <= 3; i++) await first.capture(decision(i));
    await anchorAll(first);
    const { anchorOrigin } = (await first.getAnchorState())!;
    await first.close();

    const manifest = { publishers: { [anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' as const }] } };
    const tzun = await init(backend.same(), { publisherManifest: manifest });
    const events = eventsOf(tzun);
    await tzun.runScan();
    const pass = tzun.getScannerState()!.lastCompletedPass!;
    expect(pass).toMatchObject({ issuesFound: 0, logFindings: 0, anchorOverdue: 0 });
    // The header source and the manifest reached the scanner: the EVM publication is checked, so validity is measured.
    expect(pass.attestationValid).toMatchObject({ anchor: 3 });
    expect(events.filter((e) => e.type === 'attestation_invalid' || e.type === 'attestation_unverifiable')).toEqual([]);
  });

  it("a payload altered under its stored digest: the scanner's anchor verdict is the one verify() and get() give", async () => {
    const storeKeys = await backend.fresh();
    const first = await init(storeKeys);
    const captured = [];
    for (let i = 1; i <= 3; i++) captured.push((await first.capture(decision(i))).envelope);
    await anchorAll(first);
    const { anchorOrigin } = (await first.getAnchorState())!;
    await first.close();

    const victim = captured[1];
    const manifest = { publishers: { [anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' as const }] } };
    const tzun = await init(backend.same(), { publisherManifest: manifest });
    await rewriteStoredEnvelope(tzun.getStorage(), victim.payload.evidenceId, (e) => {
      e.payload.reason = 'altered under its digest';
    });
    const events = eventsOf(tzun);
    await tzun.runScan();
    // The pass's events: the reads below go through the verifying proxy, which reports what it finds on the same bus.
    const scanned = [...events];

    const verified = await tzun.verify(victim.payload.evidenceId);
    expect(verified).toMatchObject({ anchorValid: false, anchorReason: 'merkle_proof_invalid' });
    const read = (await tzun.get(victim.payload.evidenceId))!;
    expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: false });
    expect(ofType(scanned, 'digest_mismatch').map((e) => e.evidenceId)).toEqual([victim.payload.evidenceId]);
    expect(ofType(scanned, 'attestation_invalid')).toEqual([
      { type: 'attestation_invalid', evidenceId: victim.payload.evidenceId, component: 'anchor', reason: 'merkle_proof_invalid' },
    ]);
    expect(tzun.getScannerState()!.lastCompletedPass!.attestationValid).toMatchObject({ anchor: 2 });
  });

  it("check g runs in the SDK's own scanner: a transaction the publisher key sent outside the scheduler is an unaccounted nonce", async () => {
    const tzun = await init(await backend.fresh());
    await tzun.capture(decision(1));
    await anchorAll(tzun);
    const events = eventsOf(tzun);
    await tzun.runScan();
    expect(ofType(events, 'anchor_wallet_nonce_unaccounted')).toEqual([]);

    await chain.sendExternal(wallet);
    chain.mine(chain.finalizedDepth + 1);
    const incidents: string[] = [];
    tzun.on('tamper', (incident) => incidents.push(incident.type));
    await tzun.runScan();
    expect(ofType(events, 'anchor_wallet_nonce_unaccounted')).toEqual([
      expect.objectContaining({ address: wallet.address.toLowerCase(), chain: CHAIN, nonce: 1, nonceBase: 0, publicationId: null }),
    ]);
    expect(incidents).toContain('anchor_wallet_nonce_unaccounted');
  });

  it("check g accounts a wallet the manifest lists from anchoring.nonceBases, the scanner's own floor", async () => {
    // The wallet sent 3 transactions before it was enrolled for this store.
    for (let i = 0; i < 3; i++) await chain.sendExternal(wallet);
    chain.mine(1);
    const storeKeys = await backend.fresh();
    const first = await init(storeKeys);
    await first.capture(decision(1));
    await anchorAll(first);
    const { anchorOrigin } = (await first.getAnchorState())!;
    await first.close();
    const manifest = { publishers: { [anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' as const }] } };

    // With the manifest and no floor, the three earlier nonces are unaccounted: the floor is 0.
    const unfloored = await init(backend.same(), { publisherManifest: manifest });
    const before = eventsOf(unfloored);
    await unfloored.runScan();
    expect(ofType(before, 'anchor_wallet_nonce_unaccounted').map((e) => e.nonce)).toEqual([0, 1, 2]);
    await unfloored.close();

    const floored = await init(backend.same(), { publisherManifest: manifest, nonceBases: { [`${CHAIN}:${wallet.address}`]: 3 } });
    const after = eventsOf(floored);
    await floored.runScan();
    expect(ofType(after, 'anchor_wallet_nonce_unaccounted')).toEqual([]);
  });

  it("check e runs in the SDK's own scanner, with the cadence's T_max", async () => {
    const tzun = await init(await backend.fresh(), { cadence: { minIntervalMs: 10, targetIntervalMs: 20, maxStalenessMs: 30 } });
    await tzun.capture(decision(1));
    await new Promise((resolve) => setTimeout(resolve, 60));
    const events = eventsOf(tzun);
    await tzun.runScan();
    expect(ofType(events, 'anchor_overdue')).toEqual([expect.objectContaining({ chainId: 'default', reason: 'not_published', maxStalenessMs: 30 })]);
    expect(tzun.getScannerState()!.lastCompletedPass!.anchorOverdue).toBe(1);
  });

  it("check b runs against the published P in the SDK's own scanner: a rewritten leaf is raised as authenticated", async () => {
    const first = await init(await backend.fresh());
    const records: EvidenceEnvelope[] = [];
    for (let i = 1; i <= 4; i++) records.push((await first.capture(decision(i))).envelope);
    await anchorAll(first);
    const { anchorOrigin } = (await first.getAnchorState())!;
    await first.close();
    // With the manifest, P read from the publisher's own transaction authenticates the anchored root.
    const manifest = { publishers: { [anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' as const }] } };
    const tzun = await init(backend.same(), { publisherManifest: manifest });
    const logs = logStoreFor(tzun.getStorage())!;
    const log = (await logs.getEvidenceLog('default'))!;
    const rewritten = await reseat(tzun, records[2], records[1]);
    await asOwner(tzun, [['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = ?', [rewritten.integrity.canonicalDigest, log.logId, 2]]]);

    const events = eventsOf(tzun);
    await tzun.runScan();
    expect(ofType(events, 'log_rewritten_below_anchor')).toEqual([
      expect.objectContaining({ origin: log.origin, chainId: 'default', anchoredSize: 4, reason: 'leaves_do_not_rebuild_root', authenticated: true }),
    ]);
  });

  it('verifyChainCompleteness() reports checks a and h from the evidence log', async () => {
    const tzun = await init(await backend.fresh());
    const records: EvidenceEnvelope[] = [];
    for (let i = 1; i <= 4; i++) records.push((await tzun.capture(decision(i))).envelope);
    await anchorAll(tzun);
    const clean = await tzun.verifyChainCompleteness();
    expect(clean).toMatchObject({ valid: true, digestDiffersFromLoggedLeaf: [], anchorStripped: [] });

    await rewriteStoredEnvelope(tzun.getStorage(), records[0].payload.evidenceId, (e) => {
      delete (e.nonRepudiation as Record<string, unknown>).anchor;
    });
    // The tail rewritten and reseated: its digest and link agree with each other, not with its logged leaf.
    await reseat(tzun, records[3], records[2]);
    const walked = await tzun.verifyChainCompleteness();
    expect(walked.digestDiffersFromLoggedLeaf).toEqual([records[3].payload.evidenceId]);
    expect(walked.anchorStripped).toEqual([records[0].payload.evidenceId]);
    expect(walked).toMatchObject({ valid: false, brokenLinks: [], digestMismatches: [] });
    const all = await tzun.verifyAllChains();
    expect(all.valid).toBe(false);
    expect(all.active.digestDiffersFromLoggedLeaf).toEqual([records[3].payload.evidenceId]);
  });

  it('verifyChainCompleteness() reports check a on a store that does not anchor', async () => {
    const tzun = await Tzun.init({ mode: 'dev', ...(await backend.fresh()) });
    open.push(tzun);
    const records: EvidenceEnvelope[] = [];
    for (let i = 1; i <= 3; i++) records.push((await tzun.capture(decision(i))).envelope);
    expect(await tzun.verifyChainCompleteness()).toMatchObject({ valid: true, digestDiffersFromLoggedLeaf: [], anchorStripped: [] });
    await reseat(tzun, records[2], records[1]);
    expect(await tzun.verifyChainCompleteness()).toMatchObject({ valid: false, digestDiffersFromLoggedLeaf: [records[2].payload.evidenceId] });
  });
});
