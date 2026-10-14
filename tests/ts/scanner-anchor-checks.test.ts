import { testEvidenceId } from './helpers/evidence-id';
/**
 * The scanner's checks of a store's evidence logs and anchoring
 * (the scanner's checks a to h; tzun-anchor/1 §10.8, §10.10), on stores the anchor scheduler really anchored: records
 * chained as `capture()` chains them, epochs cut, published to an in-memory
 * chain (tests/ts/helpers/anchoring-fake-chain.ts), finalized and filled. The
 * anvil suite (tests/anvil/scanner-anvil.test.ts) runs checks g and the
 * rewrite-and-re-anchor case against a real node.
 *
 * Also the attestation check's anchor verdicts: judged on the digest
 * recomputed from the payload, as `verify()` and `get()` judge them, and
 * stating the finality the chain reads were judged under.
 *
 * Every tamper is made the way the database owner can make it: around the
 * append-only triggers. On SQLite always, and on Postgres when its legs run.
 */
import { createHash } from 'node:crypto';
import { Wallet } from 'ethers';
import {
  SchemaRegistry,
  assembleEnvelope,
  canonicalSerialize,
  computeDigest,
  compactRangeOf,
  compactRangeRoot,
  EvidenceChain,
  webauthnChallengeForDigest,
  type EvidenceEnvelope,
  type EvmFinality,
  type MonitoringEvent,
  type ScannerConfig,
  type StorageAdapter,
  type TamperIncident,
} from '@tzun/engine';
import { makeGenuineAssertion, storeWith, ORIGIN, RP_ID } from './attestation-assertion-helpers';
import { signedTimestampToken } from './rfc3161-fixture';
import { createAnchorScheduler, createEvmPublisher, type AnchorScheduler } from '../../src/anchoring';
import { checkpointDigest, formatCheckpoint } from '../../src/attestation/checkpoint';
import { StoreLogs, rootsAt } from '../../src/monitoring/anchor-log-checks';
import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import {
  ScheduledScanner,
  runAnchorScanPass,
  type AnchorScanCache,
  type AnchorScanCarry,
  type ScannerAnchoringDeps,
  type ScannerEvmChain,
  type ScannerLogScope,
} from '../../src/monitoring/scheduled-scanner';
import { TamperDetector } from '../../src/monitoring/tamper-detector';
import { anchorStoreFor, logStoreFor, type AnchorStore, type LogStore } from '../../src/storage/log-store';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { logBackends, type LogBackend, type OpenedStore, type RawDb } from './helpers/log-store-backends';
import { rewriteStoredEnvelope } from './helpers/tamper-store';

const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;
const ETH = 10n ** 18n;
const CHAIN = 'eip155:31337';
const NS = 'test.tzun.dev';
const registry = new SchemaRegistry();
const hashed = registry.get('v1.0')!.hashedFieldSet;

const ANCHOR_FINDINGS = new Set<MonitoringEvent['type']>([
  'digest_differs_from_logged_leaf',
  'log_rewritten_below_anchor',
  'log_truncated_below_anchor',
  'log_inconsistent_with_anchor',
  'split_view',
  'anchor_overdue',
  'anchor_wallet_nonce_unaccounted',
  'anchor_stripped',
  'anchor_transplanted',
]);

type Adapter = StorageAdapter & {
  store(e: EvidenceEnvelope, chainId?: string): Promise<void>;
  retrieve(id: string): Promise<EvidenceEnvelope | null>;
};

const linkOnto = (previous: string, digest: string): string => {
  const chain = new EvidenceChain();
  chain.restore(previous);
  return chain.computeLink(digest) as string;
};

describe.each(logBackends('scanner_anchor_checks').map((b) => [b.name, b] as const))('the scanner\'s anchor checks on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(120_000);
  let store: OpenedStore<StorageAdapter>;
  let adapter: Adapter;
  let logs: LogStore;
  let anchors: AnchorStore;
  let raw: RawDb;
  let chain: FakeEvmChain;
  let wallet: Wallet;
  let offset: number;
  let schedulers: AnchorScheduler[];
  /** Each chain's last digest, so the next record links onto it. */
  let heads: Map<string, { seq: number; digest: string }>;
  const clock = (): number => Date.now() + offset;
  const advance = (ms: number): void => {
    offset += ms;
  };

  beforeEach(async () => {
    await backend.fresh();
    store = (await backend.open({ logNamespace: NS })) as unknown as OpenedStore<StorageAdapter>;
    adapter = store.adapter as unknown as Adapter;
    logs = logStoreFor(store.adapter)!;
    anchors = anchorStoreFor(store.adapter)!;
    raw = store.raw;
    chain = new FakeEvmChain();
    wallet = Wallet.createRandom() as unknown as Wallet;
    chain.fund(wallet.address, ETH);
    offset = 0;
    schedulers = [];
    heads = new Map();
  });

  afterEach(async () => {
    for (const s of schedulers) await s.stop().catch(() => undefined);
    await store.close();
  });

  afterAll(async () => {
    await backend.dispose();
  });

  let counter = 0;
  /** Store `n` records on `chainId`, chained as `capture()` chains them. */
  async function capture(chainId: string, n: number): Promise<EvidenceEnvelope[]> {
    const out: EvidenceEnvelope[] = [];
    for (let i = 0; i < n; i++) {
      counter += 1;
      const head = heads.get(chainId);
      const seq = (head?.seq ?? 0) + 1;
      const e = assembleEnvelope({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiSystemId: 'scanner-anchor-suite', aiOutput: { chainId, i: counter }, action: 'approved', reason: `record ${counter}` }, { previousDigest: head?.digest, sequenceNumber: seq, signoffExpectation: null, evidenceId: testEvidenceId(`rec-${counter}`) });
      await adapter.store(e, chainId);
      heads.set(chainId, { seq, digest: e.integrity.canonicalDigest });
      out.push(e);
    }
    return out;
  }

  async function scheduler(): Promise<AnchorScheduler> {
    const s = await createAnchorScheduler({
      storage: store.adapter,
      config: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: wallet.privateKey, chain: CHAIN } } },
      publisher: createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }),
      clock,
      expectation: {},
    });
    schedulers.push(s);
    return s;
  }

  /** Cut an epoch now, then mine and pass until it is finalized and filled. */
  async function anchorNow(s: AnchorScheduler): Promise<void> {
    advance(HOUR);
    await s.runPass();
    for (let i = 0; i < 8; i++) {
      chain.mine(chain.finalizedDepth + 1);
      await s.runPass();
      const pubs = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
      if (pubs.every((p) => p.state === 'finalized' || p.state === 'superseded') && (await s.getAnchorState()).fillBacklog === 0) return;
    }
    throw new Error('the epoch did not settle');
  }

  async function anchorOrigin(): Promise<string> {
    const id = await logs.getStoreIdentity();
    return `${id.ns}/${id.storeId}/anchors`;
  }

  async function deps(extra: Partial<ScannerAnchoringDeps> = {}): Promise<ScannerAnchoringDeps> {
    return {
      publisherManifest: { publishers: { [await anchorOrigin()]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' }] } },
      evmChains: { [CHAIN]: chain },
      now: clock,
      ...extra,
    };
  }

  const config: ScannerConfig = { batchSize: 100, workers: 2, mode: 'interval', intervalMs: 0, verifyAttestation: true, verifyChainCompleteness: true };

  /** One scanner pass; the events it emitted, and its summary. */
  async function scan(anchoring?: ScannerAnchoringDeps, bus = new MonitoringEventBus()): Promise<{ events: MonitoringEvent[]; scanner: ScheduledScanner }> {
    const events: MonitoringEvent[] = [];
    bus.subscribe((e) => events.push(e));
    const scanner = new ScheduledScanner(store.adapter, bus, registry, config, anchoring ? { anchoring } : {});
    await scanner.runFullPass();
    return { events, scanner };
  }

  const findings = (events: MonitoringEvent[]): MonitoringEvent[] => events.filter((e) => ANCHOR_FINDINGS.has(e.type));
  const ofType = <T extends MonitoringEvent['type']>(events: MonitoringEvent[], type: T): Array<Extract<MonitoringEvent, { type: T }>> =>
    events.filter((e): e is Extract<MonitoringEvent, { type: T }> => e.type === type);

  /** Change rows the way a database owner can: around the triggers. */
  async function asOwner(statements: Array<[string, unknown[]?]>): Promise<void> {
    if (backend.name === 'sqlite') {
      const db = raw.sqlite!;
      db.transaction(() => {
        const triggers = db.prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'").all() as Array<{ name: string; sql: string }>;
        for (const t of triggers) db.exec(`DROP TRIGGER "${t.name}"`);
        for (const [sql, params = []] of statements) db.prepare(sql).run(...params);
        for (const t of triggers) db.exec(t.sql);
      })();
    } else {
      await raw.run('BEGIN');
      await raw.run("SET LOCAL session_replication_role = 'replica'");
      for (const [sql, params = []] of statements) await raw.run(sql, params);
      await raw.run('COMMIT');
    }
  }

  /** What the scanner logged as not checked while `run` ran. */
  async function notesDuring(run: () => Promise<unknown>): Promise<string> {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      await run();
      return warn.mock.calls.flat().join('\n');
    } finally {
      warn.mockRestore();
    }
  }

  /** `chain` with some of its reads replaced. */
  function chainWith(overrides: Partial<ScannerEvmChain>): ScannerEvmChain {
    return {
      chainId: () => chain.chainId(),
      finalizedBlockNumber: () => chain.finalizedBlockNumber(),
      canonicalBlock: (n) => chain.canonicalBlock(n),
      transactionCount: (address, tag) => chain.transactionCount(address, tag),
      transaction: (id) => chain.transaction(id),
      ...overrides,
    };
  }

  /** Rewrite a record's payload and reseat it: a new digest, its own link repaired onto its predecessor. */
  async function rewriteAndReseat(record: EvidenceEnvelope, previous: EvidenceEnvelope | undefined, keepAnchor = true): Promise<EvidenceEnvelope> {
    return rewriteStoredEnvelope(store.adapter, record.payload.evidenceId, (e) => {
      e.payload.reason = 'rewritten';
      e.integrity.canonicalDigest = computeDigest(canonicalSerialize(e.payload as unknown as Record<string, unknown>, hashed));
      e.integrity.chainLink = previous ? linkOnto(previous.integrity.canonicalDigest, e.integrity.canonicalDigest) : null;
      if (!keepAnchor) delete (e.nonRepudiation as Record<string, unknown>).anchor;
    });
  }

  it('an anchored store scans clean, and every filled anchor verifies end to end', async () => {
    await capture('alpha', 5);
    await capture('beta', 3);
    await anchorNow(await scheduler());

    const { events, scanner } = await scan(await deps());
    expect(findings(events)).toEqual([]);
    expect(events.filter((e) => e.type === 'attestation_invalid' || e.type === 'attestation_unverifiable')).toEqual([]);
    const pass = scanner.getState().lastCompletedPass!;
    expect(pass).toMatchObject({ issuesFound: 0, logFindings: 0, anchorOverdue: 0 });
    // A manifest and a chain: the EVM publication is checked, so validity is measured.
    expect(pass.attestationValid).toMatchObject({ anchor: 8 });
  });

  it('without a manifest and a chain, the anchor is not counted valid, and nothing is raised', async () => {
    await capture('alpha', 3);
    await anchorNow(await scheduler());
    const { events, scanner } = await scan();
    expect(findings(events)).toEqual([]);
    // publication_not_checked is the normal state here, never escalated (tzun-anchor/1 §10.10).
    expect(events.filter((e) => e.type === 'attestation_invalid' || e.type === 'attestation_unverifiable')).toEqual([]);
    expect(scanner.getState().lastCompletedPass!.attestationValid).toMatchObject({ anchor: null });
  });

  describe('the anchor is judged on the digest recomputed from the payload, as verify() and get() judge it', () => {
    it("a payload altered under its stored digest: digest_mismatch, and attestation_invalid on the anchor; the timestamp and the signature stay on the stored digest", async () => {
      const records = await capture('alpha', 4);
      await anchorNow(await scheduler());
      const victim = records[1];
      const stored = victim.integrity.canonicalDigest;
      // A timestamp and a signature over the digest the record was captured
      // with, then its payload altered and that digest kept.
      const credentialId = 'cred-altered';
      const { publicKeyBase64, assertion } = makeGenuineAssertion({ challenge: webauthnChallengeForDigest(stored), credentialId });
      const token = await signedTimestampToken(stored);
      const altered = await rewriteStoredEnvelope(store.adapter, victim.payload.evidenceId, (e) => {
        e.nonRepudiation = { ...e.nonRepudiation, rfc3161Token: token, webauthnAssertion: assertion };
        e.payload.reason = 'altered under its digest';
      });
      expect(altered.integrity.canonicalDigest).toBe(stored);
      const recomputed = computeDigest(canonicalSerialize(altered.payload as unknown as Record<string, unknown>, hashed));

      const bus = new MonitoringEventBus();
      const events: MonitoringEvent[] = [];
      bus.subscribe((e) => events.push(e));
      const scanner = new ScheduledScanner(store.adapter, bus, registry, config, {
        anchoring: await deps(),
        credentialStore: storeWith(credentialId, publicKeyBase64),
        rpId: RP_ID,
        allowedOrigins: [ORIGIN],
      });
      await scanner.runFullPass();

      expect(ofType(events, 'digest_mismatch')).toEqual([
        { type: 'digest_mismatch', evidenceId: victim.payload.evidenceId, stored, recomputed },
      ]);
      // The anchor's inclusion proof is over the digest the record was logged
      // with; the record as it is now hashes to another one.
      expect(ofType(events, 'attestation_invalid')).toEqual([
        { type: 'attestation_invalid', evidenceId: victim.payload.evidenceId, component: 'anchor', reason: 'merkle_proof_invalid' },
      ]);
      const pass = scanner.getState().lastCompletedPass!;
      // The token's imprint and the assertion's challenge bind the stored
      // digest, which is unchanged: both still verify. Three anchors of four.
      expect(pass.attestationValid).toEqual({ timestamp: 1, signature: 1, anchor: 3 });
      expect(pass).toMatchObject({ digestMismatches: 1, attestationFailures: 1 });
    });

    it('a payload the registry cannot hash: the anchor is judged on no digest, and fails', async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      await rewriteStoredEnvelope(store.adapter, records[2].payload.evidenceId, (e) => {
        (e.payload as { schemaVersion: string }).schemaVersion = 'v9.9';
      });
      const { events, scanner } = await scan(await deps());
      expect(ofType(events, 'digest_mismatch').map((e) => [e.evidenceId, e.recomputed])).toEqual([[records[2].payload.evidenceId, '']]);
      expect(ofType(events, 'attestation_invalid')).toEqual([
        { type: 'attestation_invalid', evidenceId: records[2].payload.evidenceId, component: 'anchor', reason: 'merkle_proof_invalid' },
      ]);
      expect(scanner.getState().lastCompletedPass!.attestationValid).toMatchObject({ anchor: 2 });
    });
  });

  describe('the finality the chain reads were judged under', () => {
    it("every pass states what each chain it read counted as final: the chain's declaration, null when it declares none", async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());

      const declared = await scan(await deps({ evmChains: { [CHAIN]: chainWith({ finality: 'finalized' }) } }));
      expect(declared.scanner.getState().lastCompletedPass!.evmFinality).toEqual({ [CHAIN]: 'finalized' });
      expect(ofType(declared.events, 'scan_completed').map((e) => e.evmFinality)).toEqual([{ [CHAIN]: 'finalized' }]);
      expect(declared.scanner.getState().lastCompletedPass!.attestationValid).toMatchObject({ anchor: 2 });

      const deep = await scan(await deps({ evmChains: { [CHAIN]: chainWith({ finality: { confirmations: 96 } }) } }));
      expect(deep.scanner.getState().lastCompletedPass!.evmFinality).toEqual({ [CHAIN]: { confirmations: 96 } });

      // The in-memory chain declares nothing: the scanner does not guess.
      const silent = await scan(await deps());
      expect(silent.scanner.getState().lastCompletedPass!.evmFinality).toEqual({ [CHAIN]: null });

      // No chain was read.
      const none = await scan();
      expect(none.scanner.getState().lastCompletedPass!.evmFinality).toEqual({});
    });

    it('the declaration is read once, when the scanner is built: a later edit does not reach a pass or its state', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const reader = chainWith({ finality: 'finalized' }) as ScannerEvmChain & { finality: EvmFinality };
      const bus = new MonitoringEventBus();
      const scanner = new ScheduledScanner(store.adapter, bus, registry, config, { anchoring: await deps({ evmChains: { [CHAIN]: reader } }) });
      reader.finality = { confirmations: 2 };
      await scanner.runFullPass();
      const state = scanner.getState();
      expect(state.lastCompletedPass!.evmFinality).toEqual({ [CHAIN]: 'finalized' });
      (state.lastCompletedPass!.evmFinality as Record<string, unknown>)[CHAIN] = 'edited';
      expect(scanner.getState().lastCompletedPass!.evmFinality).toEqual({ [CHAIN]: 'finalized' });
    });

    it.each<[string, unknown]>([
      ['a depth below 64 confirmations', { confirmations: 2 }],
      ['a depth of 63', { confirmations: 63 }],
      ['a depth of zero', { confirmations: 0 }],
      ['a fractional depth', { confirmations: 64.5 }],
      ['a word other than finalized', 'safe'],
      ['null', null],
    ])('refuses, when it is built, a chain whose finality is %s (the verifier\'s rule)', async (_label, finality) => {
      const reader = chainWith({ finality: finality as EvmFinality });
      expect(
        () => new ScheduledScanner(store.adapter, new MonitoringEventBus(), registry, config, { anchoring: { evmChains: { [CHAIN]: reader } } }),
      ).toThrow(new RegExp(`${CHAIN}.*finality`));
    });

    it('names the floor when it refuses a shallow depth, and accepts one that says it accepts anchors that may not be final', async () => {
      const shallow = chainWith({ finality: { confirmations: 2 } });
      expect(
        () => new ScheduledScanner(store.adapter, new MonitoringEventBus(), registry, config, { anchoring: { evmChains: { [CHAIN]: shallow } } }),
      ).toThrow(/below 64.*acceptNonFinal/s);

      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const accepting = chainWith({ finality: { confirmations: 2, acceptNonFinal: true } });
      const { scanner } = await scan(await deps({ evmChains: { [CHAIN]: accepting } }));
      expect(scanner.getState().lastCompletedPass!.evmFinality).toEqual({ [CHAIN]: { confirmations: 2, acceptNonFinal: true } });
      expect(scanner.getState().lastCompletedPass!.attestationValid).toMatchObject({ anchor: 2 });
    });

    it('an anchor the chain contradicts carries the finality it was judged under; one its own proofs fail carries none', async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      await rewriteStoredEnvelope(store.adapter, records[0].payload.evidenceId, (e) => {
        e.payload.reason = 'altered under its digest';
      });
      // The chain now holds another block where the anchor's was.
      const reorged = chainWith({
        finality: { confirmations: 64 },
        canonicalBlock: async (n) => {
          const block = await chain.canonicalBlock(n);
          return block && { ...block, hash: `0x${'ab'.repeat(32)}` };
        },
      });
      const { events } = await scan(await deps({ evmChains: { [CHAIN]: reorged } }));
      const invalid = ofType(events, 'attestation_invalid');
      expect(invalid).toEqual([
        { type: 'attestation_invalid', evidenceId: records[0].payload.evidenceId, component: 'anchor', reason: 'merkle_proof_invalid' },
        ...records.slice(1).map((r) => ({
          type: 'attestation_invalid',
          evidenceId: r.payload.evidenceId,
          component: 'anchor',
          reason: 'anchor_not_found_on_chain',
          anchorFinality: { confirmations: 64 },
        })),
      ]);
    });

    it("the incident says what the chain counted as final", async () => {
      const bus = new MonitoringEventBus();
      const detector = new TamperDetector(bus, store.adapter);
      const raised: TamperIncident[] = [];
      detector.onIncident((i) => raised.push(i));
      bus.emit({ type: 'attestation_invalid', evidenceId: 'ev-final', component: 'anchor', reason: 'anchor_not_found_on_chain', anchorFinality: 'finalized' });
      bus.emit({
        type: 'attestation_invalid',
        evidenceId: 'ev-shallow',
        component: 'anchor',
        reason: 'anchor_not_found_on_chain',
        anchorFinality: { confirmations: 2, acceptNonFinal: true },
      });
      bus.emit({ type: 'attestation_invalid', evidenceId: 'ev-deep', component: 'anchor', reason: 'anchor_not_found_on_chain', anchorFinality: { confirmations: 96 } });
      bus.emit({ type: 'attestation_invalid', evidenceId: 'ev-split', component: 'anchor', reason: 'anchor_not_found_on_chain', anchorFinality: null });
      bus.emit({ type: 'attestation_invalid', evidenceId: 'ev-proof', component: 'anchor', reason: 'merkle_proof_invalid' });
      await detector.settle();
      expect(raised.map((i) => i.details)).toEqual([
        'Attestation component "anchor" failed verification for evidence record "ev-final": anchor_not_found_on_chain ' +
          "(judged at the chain's finalized block)",
        'Attestation component "anchor" failed verification for evidence record "ev-shallow": anchor_not_found_on_chain ' +
          '(judged at 2 confirmations, which may not be final)',
        'Attestation component "anchor" failed verification for evidence record "ev-deep": anchor_not_found_on_chain ' +
          '(judged at 96 confirmations)',
        'Attestation component "anchor" failed verification for evidence record "ev-split": anchor_not_found_on_chain ' +
          '(judged by chains that count different blocks as final)',
        'Attestation component "anchor" failed verification for evidence record "ev-proof": merkle_proof_invalid',
      ]);
    });
  });

  describe('check a: a record rewritten after it was logged', () => {
    it('names the record, with the digest the log holds and the one it carries', async () => {
      const records = await capture('alpha', 4);
      await anchorNow(await scheduler());
      const rewritten = await rewriteAndReseat(records[2], records[1]);

      const { events } = await scan(await deps());
      expect(ofType(events, 'digest_differs_from_logged_leaf')).toEqual([
        {
          type: 'digest_differs_from_logged_leaf',
          evidenceId: records[2].payload.evidenceId,
          sequenceNumber: 3,
          origin: (await logs.getEvidenceLog('alpha'))!.origin,
          loggedDigest: records[2].integrity.canonicalDigest,
          currentDigest: rewritten.integrity.canonicalDigest,
        },
      ]);
      // The leaves were not touched: nothing below the anchor was rewritten.
      expect(ofType(events, 'log_rewritten_below_anchor')).toEqual([]);
    });

    it('runs on a store that does not anchor', async () => {
      const records = await capture('alpha', 3);
      await rewriteAndReseat(records[1], records[0]);
      const { events } = await scan();
      expect(ofType(events, 'digest_differs_from_logged_leaf').map((e) => e.evidenceId)).toEqual([records[1].payload.evidenceId]);
    });
  });

  describe('check b: a log rewritten below its anchored size', () => {
    it('the leaf rewritten too: raised against the published P, and the record named through its embedded path', async () => {
      const records = await capture('alpha', 6);
      await anchorNow(await scheduler());
      const log = (await logs.getEvidenceLog('alpha'))!;
      const rewritten = await rewriteAndReseat(records[3], records[2]);
      await asOwner([['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = ?', [rewritten.integrity.canonicalDigest, log.logId, 3]]]);

      const { events } = await scan(await deps());
      // The record now matches its leaf: check a sees nothing.
      expect(ofType(events, 'digest_differs_from_logged_leaf')).toEqual([]);
      expect(ofType(events, 'log_rewritten_below_anchor')).toEqual([
        expect.objectContaining({
          origin: log.origin,
          chainId: 'alpha',
          anchoredSize: 6,
          reason: 'leaves_do_not_rebuild_root',
          authenticated: true,
          evidenceIds: [records[3].payload.evidenceId],
          leafRange: { from: 0, to: 6 },
        }),
      ]);
    });

    it('editing anchor_publications.p and every stored checkpoint to match does not hide it', async () => {
      const records = await capture('alpha', 4);
      await anchorNow(await scheduler());
      const log = (await logs.getEvidenceLog('alpha'))!;
      const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
      const rewritten = await rewriteAndReseat(records[1], records[0]);

      // Rebuild everything the store holds from the rewritten leaves: the
      // evidence checkpoint, the anchor log's leaf, the anchor checkpoint, P.
      const leaves = (await logs.listLogLeaves(log.logId, 0, 4)).map((l) => l.leafDigest);
      leaves[1] = rewritten.integrity.canonicalDigest;
      const range = compactRangeOf(leaves);
      const body = formatCheckpoint(log.origin, 4, compactRangeRoot(range));
      const anchorRange = compactRangeOf([checkpointDigest(body)]);
      const anchorBody = formatCheckpoint(anchorLog.origin, 1, compactRangeRoot(anchorRange));
      const p = checkpointDigest(anchorBody);
      await asOwner([
        ['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 1', [leaves[1], log.logId]],
        [
          'UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ?, compact_range = ? WHERE log_id = ? AND tree_size = 4',
          [compactRangeRoot(range), body, checkpointDigest(body), JSON.stringify(range.hashes), log.logId],
        ],
        ['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 0', [checkpointDigest(body), anchorLog.logId]],
        [
          'UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ?, compact_range = ? WHERE log_id = ? AND tree_size = 1',
          [compactRangeRoot(anchorRange), anchorBody, p, JSON.stringify(anchorRange.hashes), anchorLog.logId],
        ],
        ['UPDATE anchor_publications SET p = ?', [p]],
      ]);

      // The store now agrees with itself: with no chain to read, nothing is found.
      const local = await scan();
      expect(ofType(local.events, 'log_rewritten_below_anchor')).toEqual([]);

      // With the chain, P is the transaction's calldata, and the store no longer reproduces it.
      const { events } = await scan(await deps());
      const found = ofType(events, 'log_rewritten_below_anchor');
      expect(found).toContainEqual(expect.objectContaining({ origin: anchorLog.origin, reason: 'checkpoint_rewritten', authenticated: true }));
      // The records' own filled anchors carry the evidence checkpoint that was published: the record is named.
      expect(found).toContainEqual(
        expect.objectContaining({ origin: log.origin, authenticated: true, evidenceIds: [records[1].payload.evidenceId] }),
      );
      // Only one history was published: the store's rewritten bodies authenticate nothing.
      expect(ofType(events, 'split_view')).toEqual([]);
      // Check g: the store no longer holds a publication whose checkpoint hashes to the calldata at nonce 0.
      const [pub] = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
      expect(ofType(events, 'anchor_wallet_nonce_unaccounted')).toEqual([
        expect.objectContaining({ nonce: 0, publicationId: pub.id, epochId: pub.epochId }),
      ]);
    });

    it('a publication pointed at another sender\'s transaction is raised', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const stranger = Wallet.createRandom() as unknown as Wallet;
      chain.fund(stranger.address, ETH);
      const foreign = await chain.sendExternal(stranger, `0x${'ab'.repeat(32)}`);
      chain.mine(1);
      await asOwner([['UPDATE anchor_publications SET mined_tx_hash = ?', [foreign]]]);

      const { events } = await scan(await deps());
      expect(ofType(events, 'log_rewritten_below_anchor')).toContainEqual(
        expect.objectContaining({ reason: 'publication_not_from_publisher', transactionId: foreign, authenticated: true }),
      );
    });

    it('with a manifest, a wallet the store enrolled is not a publisher unless the manifest lists it', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const [pub] = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
      // The database owner enrols a wallet of their own and points the
      // publication at its transaction, which carries the very same P.
      const intruder = Wallet.createRandom() as unknown as Wallet;
      chain.fund(intruder.address, ETH);
      const copy = await chain.sendExternal(intruder, `0x${pub.p}`);
      chain.mine(chain.finalizedDepth + 1);
      const id = await logs.getStoreIdentity();
      await asOwner([
        [
          "INSERT INTO anchor_wallets (address, chain, domain, nonce_base, enrolled_at) VALUES (?, ?, ?, 0, '2026-01-01T00:00:00Z')",
          [intruder.address.toLowerCase(), CHAIN, `${id.ns}/${id.storeId}`],
        ],
        ['UPDATE anchor_publications SET mined_tx_hash = ?, from_address = ?', [copy, intruder.address.toLowerCase()]],
      ]);
      const { events } = await scan(await deps());
      expect(ofType(events, 'log_rewritten_below_anchor')).toContainEqual(
        expect.objectContaining({ reason: 'publication_not_from_publisher', transactionId: copy, authenticated: true }),
      );
    });

    it('when the manifest lists no publisher for the store, its wallet rows stand in: nothing is authenticated, and the scanner says so', async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      const log = (await logs.getEvidenceLog('alpha'))!;
      await asOwner([['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 1', ['cd'.repeat(32), log.logId]]]);
      let events: MonitoringEvent[] = [];
      const notes = await notesDuring(async () => {
        ({ events } = await scan(await deps({ publisherManifest: { publishers: {} } })));
      });
      expect(ofType(events, 'log_rewritten_below_anchor')).toEqual([
        expect.objectContaining({ origin: log.origin, authenticated: false, evidenceIds: [records[1].payload.evidenceId] }),
      ]);
      expect(notes).toMatch(/the publisher manifest lists no EVM publisher for \S+\/anchors: the store's own wallet rows say who publishes/);
    });

    it('a publication\'s nonce edited: its transaction is raised, and the nonce it really used is unaccounted', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const [pub] = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
      await asOwner([['UPDATE anchor_publications SET nonce = 7 WHERE id = ?', [pub.id]]]);
      const { events } = await scan(await deps());
      expect(ofType(events, 'log_rewritten_below_anchor')).toContainEqual(
        expect.objectContaining({ reason: 'publication_nonce_mismatch', publicationId: pub.id, authenticated: true }),
      );
      expect(ofType(events, 'anchor_wallet_nonce_unaccounted').map((e) => e.nonce)).toEqual([0]);
    });

    it('the anchor checkpoint at a published size deleted: checkpoint_missing', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
      await asOwner([['DELETE FROM log_checkpoints WHERE log_id = ?', [anchorLog.logId]]]);
      const { events } = await scan(await deps());
      expect(ofType(events, 'log_rewritten_below_anchor')).toContainEqual(
        expect.objectContaining({ origin: anchorLog.origin, reason: 'checkpoint_missing', anchoredSize: 1, authenticated: true }),
      );
    });

    it('an evidence checkpoint rewritten to another root, its leaves untouched: checkpoint_rewritten under the published anchor log', async () => {
      await capture('alpha', 3);
      await anchorNow(await scheduler());
      const log = (await logs.getEvidenceLog('alpha'))!;
      const forged = formatCheckpoint(log.origin, 3, 'ee'.repeat(32));
      await asOwner([
        ['UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ? WHERE log_id = ? AND tree_size = 3', ['ee'.repeat(32), forged, checkpointDigest(forged), log.logId]],
      ]);
      const { events } = await scan(await deps());
      expect(ofType(events, 'log_rewritten_below_anchor')).toContainEqual(
        expect.objectContaining({ origin: log.origin, reason: 'checkpoint_rewritten', anchoredSize: 3, authenticated: true }),
      );
      // The leaves still rebuild the root that was published.
      expect(ofType(events, 'log_rewritten_below_anchor').filter((e) => e.origin === log.origin && e.reason === 'leaves_do_not_rebuild_root')).toEqual([]);
    });

    it('without a chain, a leaf rewritten below the store\'s own anchored checkpoint is still raised, as unauthenticated', async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      const log = (await logs.getEvidenceLog('alpha'))!;
      await asOwner([['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 2', ['cd'.repeat(32), log.logId]]]);
      const { events } = await scan();
      expect(ofType(events, 'log_rewritten_below_anchor')).toEqual([
        expect.objectContaining({ origin: log.origin, authenticated: false, evidenceIds: [records[2].payload.evidenceId] }),
      ]);
    });
  });

  describe('check c: a log truncated below its anchored size', () => {
    it('an epoch the scheduler cuts while a pass runs is not a truncation: the chain head is read after the checkpoints', async () => {
      await capture('alpha', 3);
      const s = await scheduler();
      await anchorNow(s);
      const bus = new MonitoringEventBus();
      const events: MonitoringEvent[] = [];
      bus.subscribe((e) => events.push(e));
      const scanner = new ScheduledScanner(store.adapter, bus, registry, config, { anchoring: await deps() });
      // Two records captured and anchored between the pass's scope read (its
      // start) and its log checks (its end).
      const inner = scanner as unknown as { runLogChecks: (...args: unknown[]) => Promise<unknown> };
      const runLogChecks = inner.runLogChecks.bind(scanner);
      inner.runLogChecks = async (...args: unknown[]) => {
        await capture('alpha', 2);
        await anchorNow(s);
        return runLogChecks(...args);
      };
      await scanner.runFullPass();
      expect((await anchors.listAnchorPublications({ kind: 'evm-calldata/1' })).map((p) => p.anchorSize)).toEqual([1, 2]);
      expect(findings(events)).toEqual([]);
    });

    it('the tail of the log deleted', async () => {
      await capture('alpha', 5);
      await anchorNow(await scheduler());
      const log = (await logs.getEvidenceLog('alpha'))!;
      await asOwner([['DELETE FROM log_leaves WHERE log_id = ? AND leaf_index >= 3', [log.logId]]]);
      const { events } = await scan(await deps());
      expect(ofType(events, 'log_truncated_below_anchor')).toEqual([
        { type: 'log_truncated_below_anchor', origin: log.origin, chainId: 'alpha', anchoredSize: 5, logSize: 3, lastSequence: 5 },
      ]);
    });

    it('the chain head moved below the anchored size', async () => {
      await capture('alpha', 4);
      await anchorNow(await scheduler());
      await asOwner([["UPDATE chain_state SET last_sequence = 2 WHERE chain_id = 'alpha'"]]);
      const { events } = await scan(await deps());
      expect(ofType(events, 'log_truncated_below_anchor')).toContainEqual(
        expect.objectContaining({ chainId: 'alpha', anchoredSize: 4, logSize: 4, lastSequence: 2 }),
      );
    });
  });

  describe('check d: inconsistent anchored checkpoints, and split views', () => {
    async function twoEpochs(): Promise<{ logId: number; origin: string }> {
      await capture('alpha', 3);
      const s = await scheduler();
      await anchorNow(s);
      await capture('alpha', 2);
      await anchorNow(s);
      const log = (await logs.getEvidenceLog('alpha'))!;
      return { logId: log.logId, origin: log.origin };
    }

    it('a stored consistency proof that does not verify', async () => {
      const { logId, origin } = await twoEpochs();
      await asOwner([['UPDATE log_checkpoints SET consistency_proof = ? WHERE log_id = ? AND tree_size = 5', [JSON.stringify(['00'.repeat(32)]), logId]]]);
      const { events } = await scan(await deps());
      expect(ofType(events, 'log_inconsistent_with_anchor')).toEqual([
        { type: 'log_inconsistent_with_anchor', origin, chainId: 'alpha', fromSize: 3, toSize: 5, reason: 'consistency_proof_invalid' },
      ]);
    });

    it('a predecessor deleted, and an anchored checkpoint no longer proved from the one before it', async () => {
      const { logId, origin } = await twoEpochs();
      await asOwner([['UPDATE log_checkpoints SET prev_anchored_size = NULL, consistency_proof = NULL WHERE log_id = ? AND tree_size = 5', [logId]]]);
      const broken = await scan(await deps());
      expect(ofType(broken.events, 'log_inconsistent_with_anchor')).toEqual([
        { type: 'log_inconsistent_with_anchor', origin, chainId: 'alpha', fromSize: 3, toSize: 5, reason: 'proof_chain_broken' },
      ]);
    });

    it('a checkpoint whose predecessor is gone', async () => {
      const { logId, origin } = await twoEpochs();
      await asOwner([['DELETE FROM log_checkpoints WHERE log_id = ? AND tree_size = 3', [logId]]]);
      const { events } = await scan(await deps());
      expect(ofType(events, 'log_inconsistent_with_anchor')).toContainEqual(
        expect.objectContaining({ origin, fromSize: 3, toSize: 5, reason: 'predecessor_missing' }),
      );
    });

    it('the log rewritten and anchored again with the publisher\'s key: split_view against the records\' published anchors', async () => {
      const records = await capture('alpha', 4);
      await anchorNow(await scheduler());
      const log = (await logs.getEvidenceLog('alpha'))!;
      const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
      // The operator holds the database and the key: rewrite a record and its
      // leaf, erase every trace of the epoch, and anchor the log again.
      const rewritten = await rewriteAndReseat(records[2], records[1], false);
      await asOwner([
        ['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 2', [rewritten.integrity.canonicalDigest, log.logId]],
        ['DELETE FROM log_checkpoints'],
        ['DELETE FROM log_leaves WHERE log_id = ?', [anchorLog.logId]],
        ['DELETE FROM anchor_publications'],
        ['DELETE FROM anchor_wallets'],
      ]);
      for (const s of schedulers.splice(0)) await s.stop();
      await anchorNow(await scheduler());
      const pubs = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
      expect(pubs.map((p) => [p.nonce, p.anchorSize])).toEqual([[1, 1]]);

      const { events } = await scan(await deps());
      const views = ofType(events, 'split_view');
      expect(views.map((v) => [v.origin, v.size])).toEqual(
        expect.arrayContaining([
          [anchorLog.origin, 1],
          [log.origin, 4],
        ]),
      );
      expect(views.every((v) => v.roots.length === 2)).toBe(true);
      // The leaves rebuild the new root, not the one the untouched records carry.
      expect(ofType(events, 'log_rewritten_below_anchor')).toContainEqual(
        expect.objectContaining({ origin: log.origin, anchoredSize: 4, authenticated: true, reason: 'leaves_do_not_rebuild_root' }),
      );
      // The first epoch's nonce: the store no longer holds its publication.
      expect(ofType(events, 'anchor_wallet_nonce_unaccounted').map((e) => [e.nonce, e.publicationId])).toEqual([[0, null]]);
    });
  });

  describe('check e: anchor_overdue', () => {
    it('leaves no epoch has taken, older than T_max: not_published', async () => {
      const records = await capture('alpha', 2);
      const early = await scan(await deps());
      expect(ofType(early.events, 'anchor_overdue')).toEqual([]);
      advance(DAY + HOUR);
      const { events, scanner } = await scan(await deps());
      expect(ofType(events, 'anchor_overdue')).toEqual([
        expect.objectContaining({
          chainId: 'alpha',
          reason: 'not_published',
          leafIndex: 0,
          evidenceId: records[0].payload.evidenceId,
          maxStalenessMs: DAY,
        }),
      ]);
      // Reported, not counted as an issue: an anchoring delay says nothing about the evidence.
      expect(scanner.getState().lastCompletedPass).toMatchObject({ anchorOverdue: 1, issuesFound: 0 });
    });

    it('a publication mined and never final: finality_stalled', async () => {
      await capture('alpha', 2);
      chain.finalizedDepth = 10_000;
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      chain.mine(1);
      await s.runPass();
      expect((await anchors.listAnchorPublications({ kind: 'evm-calldata/1' }))[0].state).toBe('included');
      advance(DAY);
      const { events } = await scan(await deps());
      expect(ofType(events, 'anchor_overdue').map((e) => e.reason)).toEqual(['finality_stalled']);
    });

    it('final and not filled: not_filled; and nothing without the anchoring inputs', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      await asOwner([['UPDATE anchor_publications SET fill_progress = NULL']]);
      advance(DAY + HOUR);
      const { events } = await scan(await deps());
      expect(ofType(events, 'anchor_overdue').map((e) => e.reason)).toEqual(['not_filled']);
      expect(ofType((await scan()).events, 'anchor_overdue')).toEqual([]);
    });
  });

  describe('check g: publisher nonce accounting', () => {
    it('a foreign transaction from the publisher wallet leaves its nonce unaccounted', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      await chain.sendExternal(wallet);
      chain.mine(1);
      const { events } = await scan(await deps());
      expect(ofType(events, 'anchor_wallet_nonce_unaccounted')).toEqual([
        { type: 'anchor_wallet_nonce_unaccounted', address: wallet.address.toLowerCase(), chain: CHAIN, nonce: 1, nonceBase: 0, epochId: null, publicationId: null },
      ]);
    });

    it('the scanner\'s floor, not the store\'s: transactions from before enrolment are not counted when it is given, and are without it', async () => {
      for (let i = 0; i < 3; i++) await chain.sendExternal(wallet);
      chain.mine(1);
      await capture('alpha', 2);
      const s = await scheduler();
      await anchorNow(s);
      expect((await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN))!.nonceBase).toBe(3);
      const floor = { nonceBases: { [`${CHAIN}:${wallet.address}`]: 3 } };
      expect(findings((await scan(await deps(floor))).events)).toEqual([]);
      // Without the floor the scanner starts at 0, whatever nonce_base says.
      const unfloored = await scan(await deps());
      expect(ofType(unfloored.events, 'anchor_wallet_nonce_unaccounted').map((e) => [e.nonce, e.nonceBase])).toEqual([
        [0, 0],
        [1, 0],
        [2, 0],
      ]);
      await capture('alpha', 1);
      await anchorNow(s);
      await asOwner([['DELETE FROM anchor_publications WHERE nonce = 4']]);
      const { events } = await scan(await deps(floor));
      expect(ofType(events, 'anchor_wallet_nonce_unaccounted').map((e) => [e.nonce, e.nonceBase])).toEqual([[4, 3]]);
    });

    it('the database owner deletes the anchoring rows instead of editing them: the published nonce stays unaccounted, before and after the scheduler enrols the wallet again', async () => {
      const records = await capture('alpha', 4);
      await anchorNow(await scheduler());
      const log = (await logs.getEvidenceLog('alpha'))!;
      const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
      // Rewrite record 3 and its leaf, strip every anchor so no record keeps
      // the first epoch, and delete (rather than edit) everything the store
      // kept about what was published, the wallet's row included.
      const rewritten = await rewriteAndReseat(records[2], records[1], false);
      for (const r of [records[0], records[1], records[3]]) {
        await rewriteStoredEnvelope(store.adapter, r.payload.evidenceId, (e) => {
          delete (e.nonRepudiation as Record<string, unknown>).anchor;
          if (r === records[3]) e.integrity.chainLink = linkOnto(rewritten.integrity.canonicalDigest, e.integrity.canonicalDigest);
        });
      }
      await asOwner([
        ['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 2', [rewritten.integrity.canonicalDigest, log.logId]],
        ['DELETE FROM log_checkpoints'],
        ['DELETE FROM log_leaves WHERE log_id = ?', [anchorLog.logId]],
        ['DELETE FROM anchor_publications'],
        ['DELETE FROM anchor_wallets'],
      ]);
      const wiped = await scan(await deps());
      expect(ofType(wiped.events, 'anchor_wallet_nonce_unaccounted').map((e) => [e.nonce, e.nonceBase, e.publicationId])).toEqual([[0, 0, null]]);

      // The operator's own scheduler, which holds the key, enrols the wallet
      // again at its current count and anchors the rewritten log.
      for (const s of schedulers.splice(0)) await s.stop();
      await anchorNow(await scheduler());
      expect((await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN))!.nonceBase).toBe(1);
      const reanchored = await scan(await deps());
      expect(ofType(reanchored.events, 'anchor_wallet_nonce_unaccounted').map((e) => [e.nonce, e.nonceBase, e.publicationId])).toEqual([[0, 0, null]]);
    });

    it('a stored transaction hash edited to one the node does not know leaves its nonce unaccounted: the stored bytes do not hash to it', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const [pub] = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
      const unknown = `0x${'77'.repeat(32)}`;
      await asOwner([
        [
          'UPDATE anchor_publications SET attempts = ?, mined_tx_hash = ? WHERE id = ?',
          [JSON.stringify(pub.attempts.map((a) => ({ ...a, txHash: unknown }))), unknown, pub.id],
        ],
      ]);
      let events: MonitoringEvent[] = [];
      const notes = await notesDuring(async () => {
        ({ events } = await scan(await deps()));
      });
      expect(ofType(events, 'anchor_wallet_nonce_unaccounted')).toEqual([expect.objectContaining({ nonce: 0, publicationId: pub.id })]);
      // What the node does not know decides nothing about P, and the scanner says so.
      expect(notes).toMatch(new RegExp(`the node did not confirm the transaction of publication ${pub.id}: P was not re-derived`));
    });

    it.each([
      ['fails', async (): Promise<null> => {
        throw new Error('429 Too Many Requests');
      }],
      ['answers nothing', async (): Promise<null> => null],
    ])('a transaction read that %s leaves the nonce undecided, never unaccounted, and the scanner says so', async (_what, transaction) => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      let events: MonitoringEvent[] = [];
      const notes = await notesDuring(async () => {
        ({ events } = await scan(await deps({ evmChains: { [CHAIN]: chainWith({ transaction }) } })));
      });
      expect(findings(events)).toEqual([]);
      expect(notes).toMatch(/nonce 0 of the publisher wallet 0x[0-9a-f]{40} on eip155:31337 is not accounted on this pass/);
    });

    it('a read that fails is asked again later in the pass, not kept', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      let calls = 0;
      const once = chainWith({
        transaction: async (id) => {
          calls += 1;
          if (calls === 1) throw new Error('timeout');
          return chain.transaction(id);
        },
      });
      const bus = new MonitoringEventBus();
      const events: MonitoringEvent[] = [];
      bus.subscribe((e) => events.push(e));
      // No attestation check: check b makes the first read and check g the second.
      const scanner = new ScheduledScanner(store.adapter, bus, registry, { ...config, verifyAttestation: false }, {
        anchoring: await deps({ evmChains: { [CHAIN]: once } }),
      });
      const notes = await notesDuring(() => scanner.runFullPass());
      expect(findings(events)).toEqual([]);
      expect(calls).toBe(2);
      expect(notes).toMatch(/did not confirm the transaction of publication/);
      expect(notes).not.toMatch(/is not accounted on this pass/);
    });

    it('a transaction count that cannot be read is reported as not checked', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const failing = chainWith({
        transactionCount: async () => {
          throw new Error('503 Service Unavailable');
        },
      });
      let events: MonitoringEvent[] = [];
      const notes = await notesDuring(async () => {
        ({ events } = await scan(await deps({ evmChains: { [CHAIN]: failing } })));
      });
      expect(findings(events)).toEqual([]);
      expect(notes).toMatch(/the transaction count of the publisher wallet 0x[0-9a-f]{40} on eip155:31337 could not be read \(503 Service Unavailable\)/);
    });

    it("a reader's failure that names its URL is reported without it: an API key sits in the path", async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      const key = 'SECRET_PROJECT_KEY_abc123';
      const failing = chainWith({
        transactionCount: async () => {
          // As ethers words an HTTP failure, when the reader is not the SDK's JsonRpcEvmChain.
          throw new Error(
            `server response 401 Unauthorized (request={  }, response={  }, error=null, info={ "requestUrl": "https://sepolia.infura.io/v3/${key}" }, code=SERVER_ERROR, version=6.15.0)`,
          );
        },
      });
      const notes = await notesDuring(async () => {
        await scan(await deps({ evmChains: { [CHAIN]: failing } }));
      });
      expect(notes).toMatch(/the transaction count of the publisher wallet 0x[0-9a-f]{40} on eip155:31337 could not be read \(server response 401 Unauthorized/);
      expect(notes).not.toContain(key);
      expect(notes).not.toContain('sepolia.infura.io');
    });

    it('a retired wallet is accounted to its count while the manifest lists it, and to its retirement once the listing has ended', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await anchorNow(s);
      await s.sweep(Wallet.createRandom().address);
      chain.mine(chain.finalizedDepth + 1);
      await s.runPass().catch(() => undefined);
      expect((await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN))!.retiredAt).not.toBeNull();
      // The old key, funded again, sends a 32-byte value of its own.
      chain.fund(wallet.address, ETH);
      await chain.sendExternal(wallet, `0x${'ab'.repeat(32)}`);
      chain.mine(chain.finalizedDepth + 1);

      const listed = await scan(await deps());
      expect(ofType(listed.events, 'anchor_wallet_nonce_unaccounted').map((e) => e.nonce)).toEqual([2]);
      const ended = new Date(clock() - HOUR).toISOString();
      const rotated = { publishers: { [await anchorOrigin()]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' as const, validUntil: ended }] } };
      expect(ofType((await scan(await deps({ publisherManifest: rotated }))).events, 'anchor_wallet_nonce_unaccounted')).toEqual([]);
    });

    it('without a chain the nonces are not accounted, and the scanner says so once', async () => {
      await capture('alpha', 2);
      await anchorNow(await scheduler());
      await chain.sendExternal(wallet);
      chain.mine(1);
      const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
      try {
        const { events } = await scan({ ...(await deps()), evmChains: {} });
        expect(ofType(events, 'anchor_wallet_nonce_unaccounted')).toEqual([]);
        expect(warn.mock.calls.flat().join('\n')).toMatch(/no chain was given for eip155:31337/);
      } finally {
        warn.mockRestore();
      }
    });
  });

  describe('check h: anchor_stripped', () => {
    it('a filled anchor removed is named; a record whose epoch is not filled yet is not', async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      const waiting = await capture('alpha', 2);
      await rewriteStoredEnvelope(store.adapter, records[1].payload.evidenceId, (e) => {
        delete (e.nonRepudiation as Record<string, unknown>).anchor;
      });
      const { events } = await scan(await deps());
      expect(ofType(events, 'anchor_stripped')).toEqual([
        { type: 'anchor_stripped', evidenceId: records[1].payload.evidenceId, sequenceNumber: 2, origin: (await logs.getEvidenceLog('alpha'))!.origin },
      ]);
      expect(ofType(events, 'anchor_stripped').map((e) => e.evidenceId)).not.toContain(waiting[0].payload.evidenceId);
    });

    it('a record the walk read before the fill\'s last chunk committed is not reported stripped', async () => {
      const records = await capture('alpha', 3);
      const s = await scheduler();
      await anchorNow(s);
      // The store as it is just before the last fill chunk commits: the
      // publication final, its fill not done, the records without anchors.
      for (const r of records) {
        await rewriteStoredEnvelope(store.adapter, r.payload.evidenceId, (e) => {
          delete (e.nonRepudiation as Record<string, unknown>).anchor;
        });
      }
      await asOwner([['UPDATE anchor_publications SET fill_progress = NULL']]);
      // The fill commits after the walk read the records and before it asks
      // whether the epoch is filled.
      const proto = StoreLogs.prototype as unknown as { anchorFillDone: (...args: unknown[]) => Promise<boolean> };
      const anchorFillDone = proto.anchorFillDone;
      let filled = false;
      proto.anchorFillDone = async function (this: unknown, ...args: unknown[]) {
        if (!filled) {
          filled = true;
          await s.runPass();
        }
        return anchorFillDone.apply(this, args);
      };
      try {
        const { events } = await scan(await deps());
        expect(filled).toBe(true);
        expect(ofType(events, 'anchor_stripped')).toEqual([]);
      } finally {
        proto.anchorFillDone = anchorFillDone;
      }
      const after = await Promise.all(records.map((r) => adapter.retrieve(r.payload.evidenceId)));
      expect(after.every((e) => !!(e?.nonRepudiation as { anchor?: unknown } | undefined)?.anchor)).toBe(true);
    });
  });

  describe('anchor_transplanted: a record carrying an anchor made for another leaf', () => {
    /** Put `donor`'s filled anchor, as the store holds it, on `record`. */
    async function transplant(record: EvidenceEnvelope, donor: EvidenceEnvelope, edit: (anchor: Record<string, unknown>) => void = () => undefined): Promise<void> {
      const stored = await adapter.retrieve(donor.payload.evidenceId);
      const anchor = { ...((stored!.nonRepudiation as unknown as { anchor: Record<string, unknown> }).anchor) };
      edit(anchor);
      await rewriteStoredEnvelope(store.adapter, record.payload.evidenceId, (e) => {
        (e.nonRepudiation as Record<string, unknown>).anchor = anchor;
      });
    }

    it("another record's anchor on the same chain: named with the leaf it was made for, beside the verifier's own verdict", async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      await transplant(records[0], records[2]);

      const { events, scanner } = await scan(await deps());
      const origin = (await logs.getEvidenceLog('alpha'))!.origin;
      expect(ofType(events, 'anchor_transplanted')).toEqual([
        { type: 'anchor_transplanted', evidenceId: records[0].payload.evidenceId, sequenceNumber: 1, origin, artifactOrigin: origin, artifactLeafIndex: 2 },
      ]);
      expect(ofType(events, 'attestation_invalid')).toContainEqual(
        expect.objectContaining({ evidenceId: records[0].payload.evidenceId, component: 'anchor', reason: 'leaf_index_mismatch' }),
      );
      // One per record, folded into the pass's log findings.
      expect(scanner.getState().lastCompletedPass).toMatchObject({ logFindings: 1 });
    });

    it("another chain's anchor at the record's own leaf index: named with the log it was made for", async () => {
      const alpha = await capture('alpha', 2);
      const beta = await capture('beta', 2);
      await anchorNow(await scheduler());
      await transplant(alpha[1], beta[1]);

      const { events } = await scan(await deps());
      expect(ofType(events, 'anchor_transplanted')).toEqual([
        {
          type: 'anchor_transplanted',
          evidenceId: alpha[1].payload.evidenceId,
          sequenceNumber: 2,
          origin: (await logs.getEvidenceLog('alpha'))!.origin,
          artifactOrigin: (await logs.getEvidenceLog('beta'))!.origin,
          artifactLeafIndex: 1,
        },
      ]);
    });

    it('an artifact that names no leaf is not a transplant: its log checkpoint does not parse, or its leafIndex is not an integer', async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      await transplant(records[0], records[2], (a) => {
        a.logCheckpoint = 'not a body';
      });
      await transplant(records[1], records[2], (a) => {
        a.leafIndex = '1';
      });
      const { events } = await scan(await deps());
      expect(ofType(events, 'anchor_transplanted')).toEqual([]);
    });

    it('runs without the anchoring inputs, and on a record the log holds no leaf for it judges nothing', async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      await transplant(records[0], records[2]);
      const log = (await logs.getEvidenceLog('alpha'))!;
      expect(ofType((await scan()).events, 'anchor_transplanted').map((e) => e.evidenceId)).toEqual([records[0].payload.evidenceId]);

      await asOwner([['DELETE FROM log_leaves WHERE log_id = ? AND leaf_index = 0', [log.logId]]]);
      expect(ofType((await scan()).events, 'anchor_transplanted')).toEqual([]);
    });

    it("with opaque log origins, which name no chain, another chain's artifact at the record's own leaf index is still told apart", async () => {
      // A store whose evidence logs are named as the platform names them,
      // `<ns>/<deploymentId>/<32-hex key>`: nothing in the origin says which
      // chain a log is, so the verifier leaves the chain unchecked.
      const alpha = await capture('alpha', 2);
      await capture('beta', 2);
      const { ns, storeId } = await logs.getStoreIdentity();
      const opaque = new Map([
        ['alpha', `${ns}/${storeId}/${'1a'.repeat(16)}`],
        ['beta', `${ns}/${storeId}/${'2b'.repeat(16)}`],
      ]);
      const opaqueLogs = new Proxy(logs, {
        get(target, prop) {
          if (prop === 'listLogs') {
            return async () => (await target.listLogs()).map((l) => (l.kind === 'evidence' ? { ...l, origin: opaque.get(l.chainId as string)! } : l));
          }
          const value: unknown = Reflect.get(target, prop, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      const platformLike = new Proxy(store.adapter, {
        get(target, prop) {
          if (prop === 'logStore') return () => opaqueLogs;
          if (prop === 'anchorStore') return () => undefined;
          const value: unknown = Reflect.get(target, prop, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      const artifact = (origin: string, leafIndex: number) => ({
        anchorSpec: 'tzun-anchor/1',
        leafIndex,
        logCheckpoint: formatCheckpoint(origin, 2, 'ab'.repeat(32)),
        logPath: [],
        anchorLeafIndex: 0,
        anchorCheckpoint: formatCheckpoint(`${ns}/${storeId}/anchors`, 1, 'cd'.repeat(32)),
        anchorPath: [],
        publications: [],
      });
      await rewriteStoredEnvelope(store.adapter, alpha[0].payload.evidenceId, (e) => {
        (e.nonRepudiation as Record<string, unknown>).anchor = artifact(opaque.get('alpha')!, 0);
      });
      await rewriteStoredEnvelope(store.adapter, alpha[1].payload.evidenceId, (e) => {
        (e.nonRepudiation as Record<string, unknown>).anchor = artifact(opaque.get('beta')!, 1);
      });

      const events: MonitoringEvent[] = [];
      const bus = new MonitoringEventBus();
      bus.subscribe((e) => events.push(e));
      await new ScheduledScanner(platformLike, bus, registry, config).runFullPass();
      expect(ofType(events, 'anchor_transplanted')).toEqual([
        {
          type: 'anchor_transplanted',
          evidenceId: alpha[1].payload.evidenceId,
          sequenceNumber: 2,
          origin: opaque.get('alpha'),
          artifactOrigin: opaque.get('beta'),
          artifactLeafIndex: 1,
        },
      ]);
    });

    it('is raised once, as a warning: a second pass records it again and raises nothing', async () => {
      const records = await capture('alpha', 3);
      await anchorNow(await scheduler());
      await transplant(records[1], records[0]);
      const bus = new MonitoringEventBus();
      const detector = new TamperDetector(bus, store.adapter);
      const raised: TamperIncident[] = [];
      detector.onIncident((i) => raised.push(i));
      await scan(await deps(), bus);
      await scan(await deps(), bus);
      await detector.settle();
      expect(raised.filter((i) => i.type === 'anchor_transplanted').map((i) => [i.severity, i.affectedRecords])).toEqual([
        ['warning', [records[1].payload.evidenceId]],
      ]);
    });
  });


  describe('one domain scan and a chain scan per chain (ScannerAnchoringDeps.scope, sharedCache)', () => {
    /** Findings as comparable strings: every event but the per-record and per-pass notices. */
    const findingKeys = (events: MonitoringEvent[]): string[] =>
      events.filter((e) => e.type !== 'record_verified' && e.type !== 'scan_completed').map((e) => JSON.stringify(e)).sort();

    /** Events about the domain: its anchor log, its publications, its wallets. */
    const aboutDomain = (e: MonitoringEvent, anchorOrigin: string): boolean =>
      e.type === 'anchor_wallet_nonce_unaccounted' || ('origin' in e && e.origin === anchorOrigin && 'chainId' in e && e.chainId === null);

    async function scanAs(
      anchoring: ScannerAnchoringDeps,
      scope: ScannerLogScope | undefined,
      chainId?: string,
      storage: StorageAdapter = store.adapter,
    ): Promise<{ events: MonitoringEvent[]; scanner: ScheduledScanner }> {
      const events: MonitoringEvent[] = [];
      const bus = new MonitoringEventBus();
      bus.subscribe((e) => events.push(e));
      const scanner = new ScheduledScanner(storage, bus, registry, config, { anchoring: { ...anchoring, ...(scope && { scope }) } });
      if (chainId !== undefined) scanner.setChainScope(chainId);
      await scanner.runFullPass();
      return { events, scanner };
    }

    interface SplitResult {
      domain: MonitoringEvent[];
      byChain: Map<string, MonitoringEvent[]>;
      all: MonitoringEvent[];
    }

    /** The scans of one pass over `cache` (or none): a chain scan per chain, and the domain scan. */
    async function splitScans(anchoring: ScannerAnchoringDeps, chains: string[], cache: AnchorScanCache | undefined, domainFirst = false): Promise<SplitResult> {
      const withCache: ScannerAnchoringDeps = { ...anchoring, ...(cache && { sharedCache: cache }) };
      const byChain = new Map<string, MonitoringEvent[]>();
      let domain: MonitoringEvent[] = [];
      if (domainFirst) domain = (await scanAs(withCache, 'domain')).events;
      for (const c of chains) byChain.set(c, (await scanAs(withCache, 'sourceLogs', c)).events);
      if (!domainFirst) domain = (await scanAs(withCache, 'domain')).events;
      return { domain, byChain, all: [...domain, ...[...byChain.values()].flat()] };
    }

    /**
     * One pass made the split way: a chain scan per chain and a domain scan,
     * sharing the cache `runAnchorScanPass` gives the pass, or none when
     * `shared` is false.
     */
    async function splitPass(
      anchoring: ScannerAnchoringDeps,
      chains: string[],
      options: { domainFirst?: boolean; shared?: boolean; carry?: AnchorScanCarry } = {},
    ): Promise<SplitResult> {
      if (options.shared === false) return splitScans(anchoring, chains, undefined, options.domainFirst);
      return runAnchorScanPass((cache) => splitScans(anchoring, chains, cache, options.domainFirst), options.carry);
    }

    /** `target` with `overrides` in place of some of its members, and its other methods bound to it. */
    function viewOf<T extends object>(target: T, overrides: Record<string, unknown>): T {
      return new Proxy(target, {
        get(t, prop) {
          if (typeof prop === 'string' && Object.prototype.hasOwnProperty.call(overrides, prop)) return overrides[prop];
          if (prop === 'unwrap') return undefined;
          const value: unknown = Reflect.get(t, prop, t);
          return typeof value === 'function' ? value.bind(t) : value;
        },
      });
    }

    /**
     * The store as the platform's scanner sees one (account, env) scope
     *: its chains under the scope's own chain ids, which
     * are unique only within the scope (`chains`: the scope's id → the
     * store's), their evidence logs under those ids, and the domain's anchor
     * log. The anchoring tables are read only.
     */
    function scopeView(chains: Record<string, string>): StorageAdapter {
      const toStore = (id: string | undefined): string => (id !== undefined && chains[id]) || `(not in this scope) ${String(id)}`;
      const toScope = new Map(Object.entries(chains).map(([scopeId, storeId]) => [storeId, scopeId]));
      const inScope = <R extends { chainId: string }>(rows: R[]): R[] =>
        rows.filter((r) => toScope.has(r.chainId)).map((r) => ({ ...r, chainId: toScope.get(r.chainId)! }));
      const scopedLogs = viewOf(logs, {
        listLogs: async () =>
          (await logs.listLogs())
            .filter((l) => l.kind === 'anchors' || (l.chainId !== null && toScope.has(l.chainId)))
            .map((l) => (l.chainId === null ? l : { ...l, chainId: toScope.get(l.chainId)! })),
      });
      const readOnlyAnchors = new Proxy(anchors, {
        get(t, prop) {
          const value: unknown = Reflect.get(t, prop, t);
          if (typeof value !== 'function') return value;
          if (typeof prop === 'string' && (prop.startsWith('get') || prop.startsWith('list'))) return value.bind(t);
          return () => Promise.reject(new Error(`the scope view's anchor store is read only: ${String(prop)}`));
        },
      });
      return viewOf(store.adapter, {
        getLastSequence: (id?: string) => store.adapter.getLastSequence(toStore(id)),
        listBySequence: (from?: number, to?: number, id?: string) => store.adapter.listBySequence(from, to, toStore(id)),
        listForksForChain: async (id: string) =>
          (await store.adapter.listForksForChain(toStore(id))).map((f) => ({
            ...f,
            oldChainId: toScope.get(f.oldChainId) ?? f.oldChainId,
            newChainId: toScope.get(f.newChainId) ?? f.newChainId,
          })),
        listChains: async () => inScope(await store.adapter.listChains()),
        listRecordChainIds: async () => (await store.adapter.listRecordChainIds()).filter((id) => toScope.has(id)).map((id) => toScope.get(id)!),
        logStore: () => scopedLogs,
        anchorStore: () => readOnlyAnchors,
      });
    }

    /** The store as the platform's anchor worker sees it: every log of the domain, and no chain named. */
    function deploymentView(): StorageAdapter {
      const deploymentLogs = viewOf(logs, {
        listLogs: async () => (await logs.listLogs()).map((l) => (l.kind === 'evidence' ? { ...l, chainId: null } : l)),
      });
      return viewOf(store.adapter, { logStore: () => deploymentLogs, anchorStore: () => anchors });
    }

    /** `chain` as a reader that counts its calls, by method and argument. */
    function countingChain(): { reader: ScannerEvmChain; calls: Map<string, number> } {
      const calls = new Map<string, number>();
      const count = (key: string): void => {
        calls.set(key, (calls.get(key) ?? 0) + 1);
      };
      return {
        calls,
        reader: chainWith({
          chainId: () => (count('chainId'), chain.chainId()),
          finalizedBlockNumber: () => (count('finalizedBlockNumber'), chain.finalizedBlockNumber()),
          canonicalBlock: (n) => (count(`canonicalBlock:${n}`), chain.canonicalBlock(n)),
          transactionCount: (address, tag) => (count(`transactionCount:${address.toLowerCase()}`), chain.transactionCount(address, tag)),
          transaction: (id) => (count(`transaction:${id.toLowerCase()}`), chain.transaction(id)),
        }),
      };
    }

    /** Two chains, anchored in one epoch; `tamper` then changes the store. Returns the chains to scan. */
    const scenarios: Array<[string, () => Promise<string[]>]> = [
      ['a clean store', async () => {
        await capture('alpha', 3);
        await capture('beta', 2);
        await anchorNow(await scheduler());
        return ['alpha', 'beta'];
      }],
      ['a record rewritten after it was logged (a)', async () => {
        const records = await capture('alpha', 4);
        await capture('beta', 2);
        await anchorNow(await scheduler());
        await rewriteAndReseat(records[2], records[1]);
        return ['alpha', 'beta'];
      }],
      ['a leaf rewritten below its anchor, the record with it (b)', async () => {
        const records = await capture('alpha', 5);
        await capture('beta', 2);
        await anchorNow(await scheduler());
        const log = (await logs.getEvidenceLog('alpha'))!;
        const rewritten = await rewriteAndReseat(records[3], records[2]);
        await asOwner([['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = ?', [rewritten.integrity.canonicalDigest, log.logId, 3]]]);
        return ['alpha', 'beta'];
      }],
      ["a publication pointed at another sender's transaction (b, the domain)", async () => {
        await capture('alpha', 2);
        await capture('beta', 2);
        await anchorNow(await scheduler());
        const stranger = Wallet.createRandom() as unknown as Wallet;
        chain.fund(stranger.address, ETH);
        const foreign = await chain.sendExternal(stranger, `0x${'ab'.repeat(32)}`);
        chain.mine(1);
        await asOwner([['UPDATE anchor_publications SET mined_tx_hash = ?', [foreign]]]);
        return ['alpha', 'beta'];
      }],
      ["a publication's nonce edited (b and g)", async () => {
        await capture('alpha', 2);
        await capture('beta', 2);
        await anchorNow(await scheduler());
        await asOwner([['UPDATE anchor_publications SET nonce = 7']]);
        return ['alpha', 'beta'];
      }],
      ['the anchor checkpoint at a published size deleted (b, the domain)', async () => {
        await capture('alpha', 2);
        await capture('beta', 2);
        await anchorNow(await scheduler());
        const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
        await asOwner([['DELETE FROM log_checkpoints WHERE log_id = ?', [anchorLog.logId]]]);
        return ['alpha', 'beta'];
      }],
      ['an evidence checkpoint rewritten to another root (b, the chain)', async () => {
        await capture('alpha', 3);
        await capture('beta', 2);
        await anchorNow(await scheduler());
        const log = (await logs.getEvidenceLog('alpha'))!;
        const forged = formatCheckpoint(log.origin, 3, 'ee'.repeat(32));
        await asOwner([
          ['UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ? WHERE log_id = ? AND tree_size = 3', ['ee'.repeat(32), forged, checkpointDigest(forged), log.logId]],
        ]);
        return ['alpha', 'beta'];
      }],
      ["one log's tail deleted, and another chain's head moved below its anchor (c)", async () => {
        await capture('alpha', 5);
        await capture('beta', 4);
        await anchorNow(await scheduler());
        const log = (await logs.getEvidenceLog('alpha'))!;
        await asOwner([
          ['DELETE FROM log_leaves WHERE log_id = ? AND leaf_index >= 3', [log.logId]],
          ["UPDATE chain_state SET last_sequence = 2 WHERE chain_id = 'beta'"],
        ]);
        return ['alpha', 'beta'];
      }],
      ['a stored consistency proof that does not verify (d)', async () => {
        await capture('alpha', 3);
        await capture('beta', 2);
        const s = await scheduler();
        await anchorNow(s);
        await capture('alpha', 2);
        await anchorNow(s);
        const log = (await logs.getEvidenceLog('alpha'))!;
        await asOwner([['UPDATE log_checkpoints SET consistency_proof = ? WHERE log_id = ? AND tree_size = 5', [JSON.stringify(['00'.repeat(32)]), log.logId]]]);
        return ['alpha', 'beta'];
      }],
      ['leaves waiting past T_max (e)', async () => {
        await capture('alpha', 2);
        await capture('beta', 1);
        await anchorNow(await scheduler());
        await capture('beta', 2);
        advance(DAY + HOUR);
        return ['alpha', 'beta'];
      }],
      ['a foreign transaction from the publisher wallet (g)', async () => {
        await capture('alpha', 2);
        await capture('beta', 2);
        await anchorNow(await scheduler());
        await chain.sendExternal(wallet);
        chain.mine(1);
        return ['alpha', 'beta'];
      }],
      ['an anchor stripped (h) and an anchor transplanted', async () => {
        const alpha = await capture('alpha', 3);
        const beta = await capture('beta', 3);
        await anchorNow(await scheduler());
        await rewriteStoredEnvelope(store.adapter, alpha[1].payload.evidenceId, (e) => {
          delete (e.nonRepudiation as Record<string, unknown>).anchor;
        });
        const donor = await adapter.retrieve(alpha[0].payload.evidenceId);
        await rewriteStoredEnvelope(store.adapter, beta[0].payload.evidenceId, (e) => {
          (e.nonRepudiation as Record<string, unknown>).anchor = (donor!.nonRepudiation as unknown as { anchor: unknown }).anchor;
        });
        return ['alpha', 'beta'];
      }],
      ["the log rewritten and anchored again with the publisher's key (split views)", async () => {
        const records = await capture('alpha', 4);
        await anchorNow(await scheduler());
        const log = (await logs.getEvidenceLog('alpha'))!;
        const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
        const rewritten = await rewriteAndReseat(records[2], records[1], false);
        await asOwner([
          ['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 2', [rewritten.integrity.canonicalDigest, log.logId]],
          ['DELETE FROM log_checkpoints'],
          ['DELETE FROM log_leaves WHERE log_id = ?', [anchorLog.logId]],
          ['DELETE FROM anchor_publications'],
          ['DELETE FROM anchor_wallets'],
        ]);
        for (const s of schedulers.splice(0)) await s.stop();
        await anchorNow(await scheduler());
        return ['alpha'];
      }],
    ];

    it.each(scenarios)('%s: the split finds what one scan of the whole store finds, each finding in the scan it belongs to', async (_name, tamper) => {
      const chains = await tamper();
      const anchoring = await deps();
      const whole = await scanAs(anchoring, undefined);
      // `'all'` is the default.
      expect(findingKeys((await scanAs(anchoring, 'all')).events)).toEqual(findingKeys(whole.events));

      const split = await splitPass(anchoring, chains);
      expect(findingKeys(split.all)).toEqual(findingKeys(whole.events));

      const anchorOrigin = `${(await logs.getStoreIdentity()).ns}/${(await logs.getStoreIdentity()).storeId}/anchors`;
      // The domain scan walks no chain: it says nothing about a record or an evidence log.
      expect(split.domain.filter((e) => e.type !== 'scan_completed' && !aboutDomain(e, anchorOrigin))).toEqual([]);
      // A chain scan says nothing about the domain, and nothing about another chain.
      for (const [chainId, events] of split.byChain) {
        expect(events.filter((e) => aboutDomain(e, anchorOrigin))).toEqual([]);
        expect(events.filter((e) => 'chainId' in e && typeof e.chainId === 'string' && e.chainId !== chainId)).toEqual([]);
      }
    });

    it('the domain scan walks no chain: no record is read, and its pass counts only its findings', async () => {
      await capture('alpha', 3);
      await anchorNow(await scheduler());
      await chain.sendExternal(wallet);
      chain.mine(1);
      const { events, scanner } = await scanAs(await deps(), 'domain');
      expect(events.filter((e) => e.type === 'record_verified')).toEqual([]);
      expect(ofType(events, 'anchor_wallet_nonce_unaccounted').map((e) => e.nonce)).toEqual([1]);
      expect(scanner.getState().lastCompletedPass).toMatchObject({ recordsChecked: 0, logFindings: 1, issuesFound: 1, anchorOverdue: 0 });
    });

    it('a chain scan reports no domain finding it sees, and the domain scan reports each once', async () => {
      await capture('alpha', 2);
      await capture('beta', 2);
      await anchorNow(await scheduler());
      await asOwner([['UPDATE anchor_publications SET nonce = 7']]);
      const split = await splitPass(await deps(), ['alpha', 'beta']);
      for (const events of split.byChain.values()) expect(findings(events)).toEqual([]);
      expect(ofType(split.domain, 'log_rewritten_below_anchor').map((e) => e.reason)).toEqual(['publication_nonce_mismatch']);
      expect(ofType(split.domain, 'anchor_wallet_nonce_unaccounted').map((e) => e.nonce)).toEqual([0]);
    });

    it("the domain scan judges the anchor log against the records' anchor checkpoints when it runs after the chain scans of its pass", async () => {
      await scenarios[scenarios.length - 1][1]();
      const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
      const anchorSplit = (events: MonitoringEvent[]) => ofType(events, 'split_view').filter((e) => e.origin === anchorLog.origin);
      const last = await splitPass(await deps(), ['alpha']);
      expect(anchorSplit(last.domain).map((e) => e.size)).toEqual([1]);
      // Run first, it has only the publications, which state one history.
      const first = await splitPass(await deps(), ['alpha'], { domainFirst: true });
      expect(anchorSplit(first.domain)).toEqual([]);
      // The chain's own findings do not depend on the order.
      expect(findingKeys(first.byChain.get('alpha')!)).toEqual(findingKeys(last.byChain.get('alpha')!));
    });

    it('the scans of one pass read the chain once between them: three chains cost what one does', async () => {
      for (const c of ['alpha', 'beta', 'gamma']) await capture(c, 2);
      await anchorNow(await scheduler());
      const [pub] = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
      const measure = async (chains: string[], shared = true): Promise<Record<string, number>> => {
        const { reader, calls } = countingChain();
        await splitPass(await deps({ evmChains: { [CHAIN]: reader } }), chains, { shared });
        return Object.fromEntries(calls);
      };
      const one = await measure(['alpha']);
      const three = await measure(['alpha', 'beta', 'gamma']);
      expect(three).toEqual(one);
      expect(three[`transaction:${pub.minedTxHash}`]).toBeGreaterThan(0);
      expect(three[`transactionCount:${wallet.address.toLowerCase()}`]).toBe(1);
      // Without a shared cache every chain scan reads the chain again.
      const unshared = await measure(['alpha', 'beta', 'gamma'], false);
      expect(unshared[`transaction:${pub.minedTxHash}`]).toBeGreaterThan(three[`transaction:${pub.minedTxHash}`]);
    });

    it("the platform's layout: chain scans over scope views whose chain ids repeat across scopes, then the domain scan over the deployment view", async () => {
      // The anchor log re-anchored with the publisher's key: only the records'
      // anchor checkpoints show its split view, so the domain scan finds it
      // only with the chain scans' reads of the same pass.
      await scenarios[scenarios.length - 1][1]();
      // Another scope's chain, which the platform may give the same id: its
      // records wait for their epoch.
      await capture('beta', 2);
      const anchorLog = (await logs.listLogs()).find((l) => l.kind === 'anchors')!;
      const anchorOrigin = anchorLog.origin;
      const whole = await scanAs(await deps(), undefined);
      expect(ofType(whole.events, 'split_view').filter((e) => e.origin === anchorOrigin).map((e) => e.size)).toEqual([1]);

      /** A pass over `scans` ([a scope view, the chain id it scans]), then the domain scan over the deployment view. */
      const platformPass = async (scans: Array<[StorageAdapter, string]>) => {
        const { reader, calls } = countingChain();
        const anchoring = await deps({ evmChains: { [CHAIN]: reader } });
        const result = await runAnchorScanPass(async (sharedCache) => {
          const byScope: MonitoringEvent[][] = [];
          for (const [view, chainId] of scans) byScope.push((await scanAs({ ...anchoring, sharedCache }, 'sourceLogs', chainId, view)).events);
          const domain = (await scanAs({ ...anchoring, sharedCache }, 'domain', undefined, deploymentView())).events;
          return { byScope, domain };
        });
        return { ...result, calls: Object.fromEntries(calls) };
      };
      const one = await platformPass([[scopeView({ alpha: 'alpha' }), 'alpha']]);
      // Three scopes, each with a chain it calls 'alpha'. The second's records
      // are the first's again, so its anchors name the same transactions and
      // blocks. The third's are other records, anchored in no epoch yet.
      const three = await platformPass([
        [scopeView({ alpha: 'alpha' }), 'alpha'],
        [scopeView({ alpha: 'alpha' }), 'alpha'],
        [scopeView({ alpha: 'beta' }), 'alpha'],
      ]);
      // The other scopes' chains cost no read of the chain: the pass shares them.
      expect(three.calls).toEqual(one.calls);
      expect(three.calls.finalizedBlockNumber).toBeGreaterThan(0);
      // The deployment view names no chain, and the domain scan, run last,
      // finds the anchor log's split view through the first scopes' records.
      expect(ofType(three.domain, 'split_view').map((e) => [e.origin, e.size])).toEqual([[anchorOrigin, 1]]);
      expect(findingKeys(three.domain)).toEqual(findingKeys(whole.events.filter((e) => aboutDomain(e, anchorOrigin))));
      // The first and third scopes and the domain scan find what one scan of the whole store finds.
      expect(findingKeys([...three.domain, ...three.byScope[0], ...three.byScope[2]])).toEqual(findingKeys(whole.events));
      // The second scope's 'alpha' finds what the first's does, and the third's
      // walks its own two records and has nothing to report.
      expect(findingKeys(three.byScope[1])).toEqual(findingKeys(three.byScope[0]));
      expect(ofType(three.byScope[2], 'scan_completed').map((e) => e.recordsChecked)).toEqual([2]);
      expect(findings(three.byScope[2])).toEqual([]);
    });

    it('a cache is read only while its pass runs: a new chain scanned first in a later pass is judged on what that pass reads', async () => {
      await capture('alpha', 3);
      const s = await scheduler();
      await anchorNow(s);
      const anchoring = await deps();
      let ended: AnchorScanCache | undefined;
      const first = await runAnchorScanPass(async (cache) => {
        ended = cache;
        return splitScans(anchoring, ['alpha'], cache);
      });
      expect(findings(first.all)).toEqual([]);

      // A new chain, anchored in a second epoch, then its checkpoint rewritten:
      // only the anchor log as it is now vouches for that checkpoint. Judged on
      // the first pass's reads, the forged body would be the store's own.
      await capture('beta', 2);
      await anchorNow(s);
      const log = (await logs.getEvidenceLog('beta'))!;
      const forged = formatCheckpoint(log.origin, 2, 'ee'.repeat(32));
      await asOwner([
        ['UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ? WHERE log_id = ? AND tree_size = 2', ['ee'.repeat(32), forged, checkpointDigest(forged), log.logId]],
      ]);
      const expected = [expect.objectContaining({ origin: log.origin, anchoredSize: 2, reason: 'checkpoint_rewritten', authenticated: true })];

      // The next pass, with the new chain first.
      const next = await splitPass(anchoring, ['beta', 'alpha']);
      expect(ofType(next.byChain.get('beta')!, 'log_rewritten_below_anchor')).toEqual(expected);
      expect(findingKeys(next.all)).toEqual(findingKeys((await scanAs(anchoring, undefined)).events));

      // The first pass's cache handed to the scanners anyway: each reads on its own, and says so.
      let stale: SplitResult | undefined;
      const notes = await notesDuring(async () => {
        stale = await splitScans(anchoring, ['beta', 'alpha'], ended);
      });
      expect(ofType(stale!.byChain.get('beta')!, 'log_rewritten_below_anchor')).toEqual(expected);
      expect(findingKeys(stale!.all)).toEqual(findingKeys(next.all));
      expect(notes).toContain("the sharedCache this scanner was handed is not a running pass's (its pass has ended");
    });

    it("a scanner handed one pass's cache for two of its passes reads the second on its own", async () => {
      await capture('alpha', 3);
      const s = await scheduler();
      await anchorNow(s);
      const anchoring = await deps();
      await runAnchorScanPass(async (sharedCache) => {
        const events: MonitoringEvent[] = [];
        const bus = new MonitoringEventBus();
        bus.subscribe((e) => events.push(e));
        const long = new ScheduledScanner(store.adapter, bus, registry, config, { anchoring: { ...anchoring, scope: 'sourceLogs', sharedCache } });
        long.setChainScope('alpha');
        await long.runFullPass();
        expect(findings(events)).toEqual([]);

        await capture('alpha', 2);
        await anchorNow(s);
        const log = (await logs.getEvidenceLog('alpha'))!;
        const forged = formatCheckpoint(log.origin, 5, 'ee'.repeat(32));
        await asOwner([
          ['UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ? WHERE log_id = ? AND tree_size = 5', ['ee'.repeat(32), forged, checkpointDigest(forged), log.logId]],
        ]);
        events.length = 0;
        const notes = await notesDuring(() => long.runFullPass());
        expect(ofType(events, 'log_rewritten_below_anchor')).toEqual([
          expect.objectContaining({ origin: log.origin, anchoredSize: 5, reason: 'checkpoint_rewritten', authenticated: true }),
        ]);
        expect(notes).toContain("the sharedCache this scanner was handed is not a running pass's");
      });
    });

    it('a transaction read in a finalized block is not read again by a later pass handed the same maps', async () => {
      await capture('alpha', 2);
      await capture('beta', 2);
      await anchorNow(await scheduler());
      const [pub] = await anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
      const { reader, calls } = countingChain();
      const anchoring = await deps({ evmChains: { [CHAIN]: reader } });
      const carry = { minedTransactions: new Map(), signedTransactions: new Map() };
      await splitPass(anchoring, ['alpha', 'beta'], { carry });
      const firstPass = calls.get(`transaction:${pub.minedTxHash}`) ?? 0;
      expect(carry.minedTransactions.has(pub.minedTxHash!)).toBe(true);
      calls.clear();
      await splitPass(anchoring, ['alpha', 'beta'], { carry });
      expect(calls.get(`transaction:${pub.minedTxHash}`) ?? 0).toBeLessThan(firstPass);
    });
  });

  it('each finding is raised once: a second pass records it again and raises nothing', async () => {
    await capture('alpha', 3);
    await capture('beta', 3);
    await anchorNow(await scheduler());
    const alpha = (await logs.getEvidenceLog('alpha'))!;
    const beta = (await logs.getEvidenceLog('beta'))!;
    // The same truncation on two chains: two findings, never merged.
    await asOwner([['DELETE FROM log_leaves WHERE log_id IN (?, ?) AND leaf_index >= 2', [alpha.logId, beta.logId]]]);
    await chain.sendExternal(wallet);
    chain.mine(1);

    const bus = new MonitoringEventBus();
    const detector = new TamperDetector(bus, store.adapter);
    const raised: TamperIncident[] = [];
    detector.onIncident((i) => raised.push(i));
    await scan(await deps(), bus);
    await detector.settle();
    const first = raised.filter((i) => ANCHOR_FINDINGS.has(i.type));
    expect(first.map((i) => [i.type, i.severity]).sort()).toEqual([
      ['anchor_wallet_nonce_unaccounted', 'critical'],
      ['log_truncated_below_anchor', 'critical'],
      ['log_truncated_below_anchor', 'critical'],
    ]);
    await scan(await deps(), bus);
    await detector.settle();
    expect(raised.filter((i) => ANCHOR_FINDINGS.has(i.type))).toHaveLength(first.length);
  });

  it('a finding stays one incident when what it says changes between passes: the chain unreachable on the second', async () => {
    const records = await capture('alpha', 4);
    await anchorNow(await scheduler());
    const log = (await logs.getEvidenceLog('alpha'))!;
    // No record keeps an anchor, so the finding names no record.
    for (const r of records) {
      await rewriteStoredEnvelope(store.adapter, r.payload.evidenceId, (e) => {
        delete (e.nonRepudiation as Record<string, unknown>).anchor;
      });
    }
    await asOwner([['UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 1', ['cd'.repeat(32), log.logId]]]);

    const bus = new MonitoringEventBus();
    const detector = new TamperDetector(bus, store.adapter);
    const raised: TamperIncident[] = [];
    detector.onIncident((i) => raised.push(i));
    // Both passes emit on one bus, so the first pass's events are taken before the second runs.
    const first = [...(await scan(await deps(), bus)).events];
    await detector.settle();
    chain.outage = true;
    const offline = await deps();
    let second: MonitoringEvent[] = [];
    await notesDuring(async () => {
      ({ events: second } = await scan(offline, bus));
    });
    await detector.settle();
    chain.outage = false;
    // The first pass read the root from the chain; the second could not.
    expect(ofType(first, 'log_rewritten_below_anchor').map((e) => [e.authenticated, e.evidenceIds])).toEqual([[true, []]]);
    expect(ofType(second, 'log_rewritten_below_anchor').map((e) => [e.authenticated, e.evidenceIds])).toEqual([[false, []]]);
    const rewrites = raised.filter((i) => i.type === 'log_rewritten_below_anchor');
    expect(rewrites).toHaveLength(1);
    expect(rewrites[0].details.split('\n')[0]).toBe(
      `The evidence log ${log.origin} (chain "alpha") no longer reproduces what was anchored at size 4 (leaves_do_not_rebuild_root).`,
    );
  });
});

describe('rebuilding a log\'s roots at its anchored sizes', () => {
  const leaf = (i: number): string => createHash('sha256').update(`leaf-${i}`).digest('hex');
  const leaves = Array.from({ length: 9000 }, (_, i) => ({ logId: 1, leafIndex: i, leafDigest: leaf(i), sourceRef: `r${i}`, source: 'capture' as const, loggedAt: '' }));

  it('matches a rebuild from scratch at every size, across the chunks it appends in', () => {
    const sizes = [1, 2, 3, 4095, 4096, 4097, 8191, 8192, 8193, 9000];
    const roots = rootsAt(leaves, [...sizes].reverse());
    for (const n of sizes) {
      expect(roots.get(n)).toBe(compactRangeRoot(compactRangeOf(leaves.slice(0, n).map((l) => l.leafDigest))));
    }
  });

  it('gives no root past a missing leaf, or past the log\'s end', () => {
    const holed = leaves.slice(0, 10).filter((l) => l.leafIndex !== 6);
    const roots = rootsAt(holed, [5, 6, 7, 12]);
    expect(roots.get(5)).toBe(compactRangeRoot(compactRangeOf(holed.slice(0, 5).map((l) => l.leafDigest))));
    expect(roots.get(6)).toBe(compactRangeRoot(compactRangeOf(holed.slice(0, 6).map((l) => l.leafDigest))));
    expect(roots.get(7)).toBeNull();
    expect(roots.get(12)).toBeNull();
  });

  it('gives no root from a leaf the engine refuses to build on', () => {
    const malformed = leaves.slice(0, 4).map((l, i) => (i === 2 ? { ...l, leafDigest: 'not a digest' } : l));
    const roots = rootsAt(malformed, [2, 3, 4]);
    expect(roots.get(2)).not.toBeNull();
    expect(roots.get(3)).toBeNull();
    expect(roots.get(4)).toBeNull();
  });
});
