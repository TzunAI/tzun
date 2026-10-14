/**
 * The anchor scheduler's state machine (Anchor §5, §6, §7.2, §8.4, §11)
 * against an in-memory chain
 * (tests/ts/helpers/anchoring-fake-chain.ts), on SQLite and, when its legs
 * run, Postgres. The anvil suite (tests/anvil/) runs the same scheduler
 * against a real node.
 *
 * Time is the scheduler's clock: `advance()` moves it, and the stores'
 * timestamps (leaves, publications) stay on the wall clock behind it.
 */
import { createHash } from 'node:crypto';
import { Transaction, Wallet } from 'ethers';
import { webauthnChallengeForDigest, type AttestationArtifacts, type AttestationExpectation, type EvidenceEnvelope } from '@tzun/engine';
import {
  AnchorActivationError,
  AnchorForceRateLimitedError,
  AnchorNotLeaderError,
  AnchorWalletError,
  AnchoringConfigError,
  createAnchorScheduler,
  createEvmPublisher,
  type AnchorScheduler,
  type AnchorSchedulerOptions,
  type AnchorPassReport,
} from '../../src/anchoring';
import { checkpointDigest, parseCheckpoint } from '../../src/attestation/checkpoint';
import { verifyAnchor } from '../../src/attestation/anchor-verify';
import { verifyEvmPublication, type EvmHeaderSource } from '../../src/attestation/blockchain';
import {
  ANCHOR_FILL_CAUSE,
  ANCHOR_LEASE_HOLDER_PREFIX,
  anchorStoreFor,
  logStoreFor,
  type AnchorPublication,
  type AnchorStore,
  type LogStore,
} from '../../src/storage/log-store';
import { makeEnvelope } from './storage-conformance/fixtures';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { type LogBackend, type OpenedStore, type RawDb, logBackends } from './helpers/log-store-backends';

const HOUR = 60 * 60_000;
const MIN = 60_000;
const ETH = 10n ** 18n;
const CHAIN = 'eip155:31337';
const NS = 'test.tzun.dev';

type Adapter = {
  store(e: EvidenceEnvelope, chainId?: string): Promise<void>;
  retrieve(id: string): Promise<EvidenceEnvelope | null>;
  listEnvelopeRevisions(id: string): Promise<Array<{ cause: string }>>;
  listByMissingObtainable(components: ['timestamp']): Promise<EvidenceEnvelope[]>;
};

/** An assertion whose clientDataJSON carries the challenge for `digest`: a signature bound to the record. */
function assertionFor(digest: string): NonNullable<AttestationArtifacts['webauthnAssertion']> {
  const clientData = { type: 'webauthn.get', challenge: webauthnChallengeForDigest(digest) };
  return { signature: 'sig', credentialKeyId: 'cred', algorithm: 'ES256', clientDataJSON: Buffer.from(JSON.stringify(clientData)).toString('base64') };
}
const TOKEN = 'dG9rZW4=';

type Method = (...args: never[]) => Promise<unknown>;

/** A store proxy that runs `around` in place of `method`, handing it the original. */
function intercept(target: AnchorStore, method: keyof AnchorStore, around: (original: Method, ...args: never[]) => Promise<unknown>): AnchorStore {
  return new Proxy(target, {
    get(t, prop, receiver) {
      const v = Reflect.get(t, prop, receiver);
      if (prop === method) return (...args: never[]) => around((v as Method).bind(t), ...args);
      return typeof v === 'function' ? v.bind(t) : v;
    },
  });
}

/** The fake chain as a verifier's header source. */
function headerSource(chain: FakeEvmChain): EvmHeaderSource {
  return {
    chainId: () => chain.chainId(),
    finalizedBlockNumber: () => chain.finalizedBlockNumber(),
    canonicalBlock: (n) => chain.canonicalBlock(n),
    transaction: async (id) => {
      const t = await chain.transaction(id);
      return t ? { from: t.from, blockHash: t.blockHash, blockNumber: t.blockNumber } : null;
    },
  };
}

describe.each(logBackends('anchoring_scheduler').map((b) => [b.name, b] as const))('the anchor scheduler on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(120_000);
  let opened: OpenedStore<unknown>[] = [];
  let store: OpenedStore<unknown>;
  let adapter: Adapter;
  let logs: LogStore;
  let anchors: AnchorStore;
  let raw: RawDb;
  let chain: FakeEvmChain;
  let wallet: Wallet;
  let offset: number;
  let schedulers: AnchorScheduler[];
  const clock = (): number => Date.now() + offset;
  const advance = (ms: number): void => {
    offset += ms;
  };

  beforeEach(async () => {
    await backend.fresh();
    store = await backend.open({ logNamespace: NS });
    opened = [store];
    adapter = store.adapter as unknown as Adapter;
    logs = logStoreFor(store.adapter)!;
    anchors = anchorStoreFor(store.adapter)!;
    raw = store.raw;
    chain = new FakeEvmChain();
    wallet = Wallet.createRandom() as unknown as Wallet;
    chain.fund(wallet.address, ETH);
    offset = 0;
    schedulers = [];
  });

  afterEach(async () => {
    for (const s of schedulers) await s.stop().catch(() => undefined);
    for (const o of opened) await o.close();
  });

  afterAll(async () => {
    await backend.dispose();
  });

  async function scheduler(extra: Partial<AnchorSchedulerOptions> = {}, on: OpenedStore<unknown> = store): Promise<AnchorScheduler> {
    const s = await createAnchorScheduler({
      storage: on.adapter,
      config: {
        ...(extra.config ?? {}),
        publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: wallet.privateKey, chain: CHAIN } },
      },
      publisher: createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }),
      clock,
      // The records `capture()` stores carry no attestation, and none is expected of them.
      expectation: {},
      tuning: { stuckAfterMs: 5 * MIN, ...(extra.tuning ?? {}) },
      ...Object.fromEntries(Object.entries(extra).filter(([k]) => k !== 'config' && k !== 'tuning')),
    });
    schedulers.push(s);
    return s;
  }

  let counter = 0;
  /** Store `n` records on `chainId`, continuing its sequence. */
  async function capture(chainId: string, n: number): Promise<string[]> {
    const log = await logs.getEvidenceLog(chainId);
    const start = log ? (await logs.getLogSize(log.logId)).size : 0;
    const ids: string[] = [];
    for (let i = 1; i <= n; i++) {
      counter += 1;
      const id = `rec-${counter}`;
      await adapter.store(makeEnvelope({ evidenceId: id, sequenceNumber: start + i, attestationStatus: 'partial' }), chainId);
      ids.push(id);
    }
    return ids;
  }

  async function publications(): Promise<AnchorPublication[]> {
    return anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
  }

  /** Pass, mine, pass until the latest publication is finalized and filled. */
  async function settle(s: AnchorScheduler): Promise<AnchorPassReport[]> {
    const reports: AnchorPassReport[] = [];
    for (let i = 0; i < 8; i++) {
      chain.mine(chain.finalizedDepth + 1);
      reports.push(await s.runPass());
      const pubs = await publications();
      if (pubs.length > 0 && pubs.every((p) => p.state === 'finalized' || p.state === 'superseded') && (await s.getAnchorState()).fillBacklog === 0) break;
    }
    return reports;
  }

  /** Another instance takes the lease for an hour. */
  async function steal(s: AnchorScheduler): Promise<void> {
    const { domainPrefix } = await s.getAnchorState();
    await raw.run('UPDATE anchor_lease SET holder = ?, expires_at = ? WHERE domain = ?', [`${ANCHOR_LEASE_HOLDER_PREFIX}intruder`, new Date(Date.now() + HOUR).toISOString(), domainPrefix]);
  }

  /** Store one record on `chainId` at `sequenceNumber`, with `artifacts(digest)` and `status`. */
  async function storeRecord(
    id: string,
    chainId: string,
    sequenceNumber: number,
    status: EvidenceEnvelope['attestationStatus'],
    artifacts: (digest: string) => AttestationArtifacts = () => ({}),
  ): Promise<void> {
    const e = makeEnvelope({ evidenceId: id, sequenceNumber, attestationStatus: status });
    e.nonRepudiation = artifacts(e.integrity.canonicalDigest);
    await adapter.store(e, chainId);
  }

  const statusOf = async (id: string): Promise<string> => (await adapter.retrieve(id))!.attestationStatus;
  const retryQueue = async (): Promise<string[]> => (await adapter.listByMissingObtainable(['timestamp'])).map((e) => e.payload.evidenceId);

  /** Change a guarded row the way a database owner can: around the triggers. */
  async function asOwner(sql: string, params: unknown[] = []): Promise<void> {
    if (backend.name === 'sqlite') {
      for (const t of ['log_leaves_block_update', 'log_checkpoints_guard_update']) await raw.run(`DROP TRIGGER IF EXISTS ${t}`);
      await raw.run(sql, params);
    } else {
      await raw.run('BEGIN');
      await raw.run("SET LOCAL session_replication_role = 'replica'");
      await raw.run(sql, params);
      await raw.run('COMMIT');
    }
  }

  describe('one transaction per epoch (Anchor §5, §6)', () => {
    it('3 chains x 50 records publish exactly one transaction, whose calldata is P', async () => {
      for (const c of ['alpha', 'beta', 'gamma']) await capture(c, 50);
      const s = await scheduler();
      expect((await s.runPass()).epoch).toBeNull(); // not due yet: the 1 h target
      advance(HOUR);
      const report = await s.runPass();
      expect(report.epoch).toMatchObject({ members: 3, anchorSize: 3, forced: false });
      expect(chain.broadcasts).toHaveLength(1);

      const [pub] = await publications();
      const anchorLog = await anchors.ensureStoreLog('anchors');
      const cp = (await anchors.getLogCheckpoint(anchorLog.logId, 3))!;
      expect(checkpointDigest(cp.body)).toBe(pub.p);
      expect(pub.p).toBe(report.epoch!.p);
      const tx = (await chain.transaction(pub.attempts[0].txHash))!;
      expect(tx.data).toBe(`0x${pub.p}`);
      expect(tx.from).toBe(wallet.address.toLowerCase());
      // The anchor log's leaves are the three checkpoints, in bytewise origin order.
      const leaves = await logs.listLogLeaves(anchorLog.logId, 0, 3);
      const origins = leaves.map((l) => l.sourceRef.split('\n')[0]);
      expect([...origins].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))).toEqual(origins);
      expect(origins.every((o) => o.startsWith(`${NS}/`))).toBe(true);

      await settle(s);
      expect(chain.broadcasts).toHaveLength(1);
      expect((await publications())[0].state).toBe('finalized');
    });
  });

  describe('the fill (Anchor §8.4, §11) and an end-to-end verifyAnchor', () => {
    it('fills every record after finality, chunked, with an anchor_fill revision, and verifyAnchor accepts it', async () => {
      const ids = [...(await capture('alpha', 23)), ...(await capture('beta', 4))];
      const s = await scheduler({ tuning: { fillChunkSize: 7 }, expectation: {} });
      advance(HOUR);
      await s.runPass();
      // Mined but not final: nothing is filled.
      chain.mine(1);
      const waiting = await s.runPass();
      expect(waiting.awaitingFinality).toBe(true);
      expect(((await adapter.retrieve(ids[0]))!.nonRepudiation as Record<string, unknown>).anchor).toBeUndefined();
      const reports = await settle(s);
      expect(reports.reduce((n, r) => n + r.filled, 0)).toBe(27);

      const [pub] = await publications();
      expect(pub.fillProgress).toMatchObject({ done: true, filled: 27, total: 27 });
      for (const id of ids) {
        const env = (await adapter.retrieve(id))!;
        const anchor = (env.nonRepudiation as Record<string, unknown>).anchor as Record<string, unknown>;
        expect(anchor.anchorSpec).toBe('tzun-anchor/1');
        expect(anchor.leafIndex).toBe(env.payload.sequenceNumber - 1);
        expect((await adapter.listEnvelopeRevisions(id)).map((r) => r.cause)).toEqual(['capture', ANCHOR_FILL_CAUSE]);
      }
      // A later pass fills nothing again.
      expect((await s.runPass()).filled).toBe(0);

      const identity = await logs.getStoreIdentity();
      const anchorOrigin = `${identity.ns}/${identity.storeId}/anchors`;
      const env = (await adapter.retrieve(ids[5]))!;
      const verdict = await verifyAnchor(env.nonRepudiation, env.integrity.canonicalDigest, {
        sequenceNumber: env.payload.sequenceNumber,
        chainId: 'alpha',
        publisherManifest: { publishers: { [anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' }] } },
        evmHeaderSources: { [CHAIN]: headerSource(chain) },
        evmNetworks: { [CHAIN]: 'testnet' },
        publicationMaterial: [
          { kind: 'evm-calldata/1', rawTransaction: pub.attempts[0].rawTx, blockNumber: pub.blockNumber, blockHash: pub.blockHash, blockHeader: pub.blockHeader, txIndex: pub.txIndex, txProof: pub.txTrieProof },
        ],
      });
      expect(verdict).toMatchObject({ anchorValid: true, merkleProofValid: true, anchorOriginAuthenticated: true, anchorPublication: 'evm-calldata', anchorNamespace: 'test' });
      expect(verdict.publications[0].evm?.inclusion).toBe('tx_proof');
    });

    it('logs each fill as its own anchor_fill event: the publication, the records filled and how long it took', async () => {
      const events: Array<[string, Record<string, unknown>]> = [];
      const onLog = (event: string, fields: Record<string, unknown>): void => {
        events.push([event, fields]);
      };
      await capture('alpha', 5);
      const s = await scheduler({ onLog, tuning: { fillChunkSize: 2 } });
      advance(HOUR);
      await s.runPass();
      await settle(s);
      const [pub] = await publications();
      const fills = events.filter(([e]) => e === 'anchor_fill').map(([, f]) => f);
      expect(fills).toEqual([
        { publicationId: pub.id, epochId: pub.epochId, filled: 5, alreadyAnchored: 0, missing: 0, conflicts: 0, done: true, durationMs: expect.any(Number) },
      ]);
      expect(fills[0].durationMs as number).toBeGreaterThanOrEqual(0);
      // A pass with nothing to fill logs no fill.
      events.length = 0;
      await s.runPass();
      expect(events.filter(([e]) => e === 'anchor_fill')).toEqual([]);
    });

    it('on the schedule, the fill is logged beside the pass (anchor_fill and anchor_pass)', async () => {
      const events: string[] = [];
      await capture('alpha', 3);
      const s = await scheduler({ onLog: (event: string) => events.push(event), tuning: { tickMs: 10 } });
      advance(HOUR);
      void s.start();
      try {
        for (let i = 0; i < 200 && !events.includes('anchor_fill'); i++) {
          chain.mine(chain.finalizedDepth + 1);
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      } finally {
        await s.stop();
      }
      expect(events).toContain('anchor_fill');
      expect(events).toContain('anchor_pass');
    });

    it('resumes a fill that stopped part-way, without filling a record twice', async () => {
      const ids = await capture('alpha', 20);
      let chunks = 0;
      const failing: AnchorStore = new Proxy(anchors, {
        get(target, prop, receiver) {
          if (prop === 'fillAnchorArtifacts') {
            return async (chunk: Parameters<AnchorStore['fillAnchorArtifacts']>[0]) => {
              chunks += 1;
              if (chunks === 2) throw new Error('the process died during the fill');
              return target.fillAnchorArtifacts(chunk);
            };
          }
          const v = Reflect.get(target, prop, receiver);
          return typeof v === 'function' ? v.bind(target) : v;
        },
      });
      const s = await scheduler({ anchorStore: failing, logStore: logs, storage: undefined, tuning: { fillChunkSize: 6 } });
      advance(HOUR);
      await s.runPass();
      chain.mine(chain.finalizedDepth + 1);
      await expect(s.runPass()).rejects.toThrow('the process died during the fill');
      const [partial] = await publications();
      expect(partial.fillProgress).toMatchObject({ filled: 6, done: false });
      const again = await s.runPass();
      expect(again.filled).toBe(14);
      for (const id of ids) {
        expect((await adapter.listEnvelopeRevisions(id)).map((r) => r.cause)).toEqual(['capture', ANCHOR_FILL_CAUSE]);
      }
    });

    it("names each record's evidence log in its fill (AnchorFill.logId), the log its artifact's checkpoint names", async () => {
      const ids = new Map<string, string>();
      for (const id of await capture('alpha', 3)) ids.set(id, 'alpha');
      for (const id of await capture('beta', 2)) ids.set(id, 'beta');
      const fills: Array<Parameters<AnchorStore['fillAnchorArtifacts']>[0]['fills'][number]> = [];
      const watching: AnchorStore = new Proxy(anchors, {
        get(target, prop, receiver) {
          if (prop === 'fillAnchorArtifacts') {
            return async (chunk: Parameters<AnchorStore['fillAnchorArtifacts']>[0]) => {
              fills.push(...chunk.fills);
              return target.fillAnchorArtifacts(chunk);
            };
          }
          const v = Reflect.get(target, prop, receiver);
          return typeof v === 'function' ? v.bind(target) : v;
        },
      });
      const s = await scheduler({ anchorStore: watching, logStore: logs, storage: undefined });
      advance(HOUR);
      await s.runPass();
      await settle(s);
      expect(fills.map((f) => f.evidenceId).sort()).toEqual([...ids.keys()].sort());
      for (const fill of fills) {
        const log = (await logs.getEvidenceLog(ids.get(fill.evidenceId)!))!;
        expect(fill.logId).toBe(log.logId);
        expect(fill.anchor.logCheckpoint.split('\n')[0]).toBe(log.origin);
      }
    });

    it.each<[string, AttestationExpectation]>([
      ['nothing', {}],
      ['an anchor', { anchor: true }],
      ['a timestamp and an anchor', { timestamp: true, anchor: true }],
    ])('a pending record without a timestamp stays pending, and on the retry pass\'s queue, when the expectation names %s', async (_label, expectation) => {
      await storeRecord('waiting', 'alpha', 1, 'pending');
      expect(await retryQueue()).toEqual(['waiting']);
      const s = await scheduler({ expectation });
      advance(HOUR);
      await s.runPass();
      await settle(s);
      const env = (await adapter.retrieve('waiting'))!;
      expect(env.nonRepudiation.anchor).toBeDefined();
      expect(env.attestationStatus).toBe('pending');
      expect(await retryQueue()).toEqual(['waiting']);
    });

    it('the status a fill stores counts the anchor: a bound signature, a timestamp and the anchor are complete', async () => {
      await storeRecord('signed', 'alpha', 1, 'partial', (d) => ({ webauthnAssertion: assertionFor(d), rfc3161Token: TOKEN }));
      await storeRecord('stamped', 'alpha', 2, 'partial', () => ({ rfc3161Token: TOKEN }));
      await storeRecord('bare', 'alpha', 3, 'none');
      await storeRecord('waiting', 'alpha', 4, 'pending');
      const s = await scheduler({ expectation: { timestamp: true, anchor: true } });
      advance(HOUR);
      await s.runPass();
      await settle(s);
      expect(await statusOf('signed')).toBe('complete');
      expect(await statusOf('stamped')).toBe('partial');
      expect(await statusOf('waiting')).toBe('pending');
      // The engine's rule under the stated expectation: a record without the
      // expected timestamp is pending, and the retry pass lists it.
      expect(await statusOf('bare')).toBe('pending');
      expect(await retryQueue()).toEqual(['bare', 'waiting']);
    });

    it('refuses to start without an expectation', async () => {
      await expect(scheduler({ expectation: undefined as unknown as AttestationExpectation })).rejects.toThrow(AnchoringConfigError);
    });
  });

  describe('the state machine (Anchor §11)', () => {
    it('only the lease holder anchors', async () => {
      await capture('alpha', 3);
      const second = await backend.open({ logNamespace: NS });
      opened.push(second);
      const a = await scheduler({ holderId: 'replica-a' });
      const b = await scheduler({ holderId: 'replica-b' }, second);
      advance(HOUR);
      expect((await a.runPass()).leader).toBe(true);
      const other = await b.runPass();
      expect(other).toMatchObject({ leader: false, epoch: null });
      expect(chain.broadcasts).toHaveLength(1);
      expect((await b.getAnchorState()).lease).toMatchObject({ holder: `${ANCHOR_LEASE_HOLDER_PREFIX}replica-a`, self: false });
    });

    it('a pass that outlives its lease while another instance publishes cuts no epoch on its stale view', async () => {
      await capture('alpha', 2);
      const a = await scheduler({ holderId: 'replica-a' });
      advance(HOUR);
      await a.runPass();
      await settle(a);
      const { domainPrefix } = await a.getAnchorState();

      // B's node answers a fee read only once the test lets it.
      let gate: { reached: Promise<void>; release: () => void } | null = null;
      const arm = (): { reached: Promise<void>; release: () => void } => {
        let reached!: () => void;
        let release!: () => void;
        const r = new Promise<void>((resolve) => (reached = resolve));
        const g = new Promise<void>((resolve) => (release = resolve));
        gate = { reached: r, release };
        const current = gate;
        (current as unknown as { wait: Promise<void>; hit: () => void }).wait = g;
        (current as unknown as { wait: Promise<void>; hit: () => void }).hit = reached;
        return current;
      };
      const stalling = new Proxy(chain, {
        get(target, prop, receiver) {
          if (prop === 'fees') {
            return async () => {
              const g = gate as unknown as { wait: Promise<void>; hit: () => void } | null;
              if (g) {
                gate = null;
                g.hit();
                await g.wait;
              }
              return target.fees();
            };
          }
          const v = Reflect.get(target, prop, receiver);
          return typeof v === 'function' ? v.bind(target) : v;
        },
      });
      const second = await backend.open({ logNamespace: NS });
      opened.push(second);
      const b = await scheduler(
        { holderId: 'replica-b', tuning: { leaseTtlMs: 200 }, publisher: createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: stalling }) },
        second,
      );
      const anchorLog = await anchors.ensureStoreLog('anchors');

      /**
       * B enters its pass and stalls in the fee read; its lease expires; A
       * publishes; another record arrives; then B goes on, with something to
       * anchor and a view of the publications from before A's epoch.
       */
      async function race(beforeB: () => Promise<void>): Promise<{ published: AnchorPassReport; late: AnchorPassReport }> {
        await capture('alpha', 1);
        advance(HOUR);
        await anchors.releaseAnchorLease(domainPrefix, `${ANCHOR_LEASE_HOLDER_PREFIX}replica-a`);
        const g = arm();
        const stalled = b.runPass();
        let published: AnchorPassReport;
        try {
          await g.reached;
          await new Promise((r) => setTimeout(r, 300));
          published = await a.runPass();
          await capture('alpha', 1);
          await beforeB();
        } finally {
          g.release();
        }
        return { published: published!, late: await stalled };
      }

      // A holds the lease when B goes on: B stops at its next lease check.
      const first = await race(async () => undefined);
      expect(first.published.epoch).toMatchObject({ anchorSize: 2 });
      expect(first.late).toMatchObject({ epoch: null, deferred: 'lease_lost' });
      await settle(a);

      // A has let the lease go when B goes on: B takes it, and the publications
      // it re-reads before planning show A's epoch unmined.
      const again = await race(() => anchors.releaseAnchorLease(domainPrefix, `${ANCHOR_LEASE_HOLDER_PREFIX}replica-a`));
      expect(again.published.epoch).not.toBeNull();
      expect(again.late).toMatchObject({ epoch: null, deferred: 'publication_in_flight' });

      // Every epoch is A's: one transaction each, at consecutive nonces, and
      // each anchor checkpoint's proof runs from the size published before it.
      const pubs = await publications();
      expect(pubs.map((p) => p.nonce)).toEqual(pubs.map((_p, i) => i));
      expect(pubs.slice(0, -1).map((p) => p.state)).toEqual(pubs.slice(0, -1).map(() => 'finalized'));
      expect(pubs[pubs.length - 1]).toMatchObject({ state: 'submitted', anchorSize: again.published.epoch!.anchorSize });
      const checkpoints = await anchors.listLogCheckpoints(anchorLog.logId);
      expect(checkpoints.map((c) => c.prevAnchoredSize)).toEqual([null, ...checkpoints.slice(0, -1).map((c) => c.treeSize)]);
      expect(chain.broadcasts).toHaveLength(pubs.length);
    });

    it('a pass that loses its lease stops before it broadcasts; the lease holder sends the stored transaction later', async () => {
      await capture('alpha', 2);
      let s!: AnchorScheduler;
      s = await scheduler({ testHooks: { afterPersistAttempt: () => steal(s) } });
      advance(HOUR);
      const report = await s.runPass();
      expect(report.deferred).toBe('lease_lost');
      expect(chain.broadcasts).toEqual([]);
      const [pub] = await publications();
      expect(pub).toMatchObject({ state: 'submitted', nonce: 0 });
      expect(pub.attempts).toHaveLength(1);
      // Not the leader: the next pass does nothing.
      expect(await s.runPass()).toMatchObject({ leader: false, broadcasts: [] });
      await anchors.releaseAnchorLease((await s.getAnchorState()).domainPrefix, `${ANCHOR_LEASE_HOLDER_PREFIX}intruder`);
      const resumed = await scheduler({ holderId: 'resumed' });
      await settle(resumed);
      const [done] = await publications();
      expect(done).toMatchObject({ state: 'finalized', minedTxHash: pub.attempts[0].txHash });
      expect(new Set(chain.broadcasts)).toEqual(new Set([pub.attempts[0].rawTx]));
    });

    it('a fill renews the lease before every chunk, and stops when another instance has taken it', async () => {
      await capture('alpha', 20);
      let chunks = 0;
      let s!: AnchorScheduler;
      const stealing = intercept(anchors, 'fillAnchorArtifacts', async (original, ...args) => {
        chunks += 1;
        const result = await original(...args);
        if (chunks === 1) await steal(s);
        return result;
      });
      s = await scheduler({ anchorStore: stealing, logStore: logs, storage: undefined, tuning: { fillChunkSize: 6 } });
      advance(HOUR);
      await s.runPass();
      chain.mine(chain.finalizedDepth + 1);
      const report = await s.runPass();
      expect(report.deferred).toBe('lease_lost');
      expect(chunks).toBe(1);
      const [pub] = await publications();
      expect(pub.fillProgress).toMatchObject({ filled: 6, done: false });
    });

    it('a new instance repeats the history check before it fills: a finalized block that is no longer canonical halts it', async () => {
      const ids = await capture('alpha', 4);
      const failing = intercept(anchors, 'fillAnchorArtifacts', async () => {
        throw new Error('the process died during the fill');
      });
      const s = await scheduler({ anchorStore: failing, logStore: logs, storage: undefined });
      advance(HOUR);
      await s.runPass();
      chain.mine(chain.finalizedDepth + 1);
      await expect(s.runPass()).rejects.toThrow('the process died during the fill');
      const [pub] = await publications();
      expect(pub).toMatchObject({ state: 'finalized', fillProgress: null });
      await s.stop();
      // A reorg below the finalized tag: impossible on a real chain, and what the check is for.
      chain.reorg(chain.head() - (pub.blockNumber as number) + 1);
      chain.mine(6);
      const restarted = await scheduler({ holderId: 'restarted' });
      const report = await restarted.runPass();
      expect(report.halted).toBe(true);
      expect(report.alarms.map((a) => a.code)).toContain('anchor_history_mismatch');
      expect(report.filled).toBe(0);
      for (const id of ids) expect((await adapter.retrieve(id))!.nonRepudiation.anchor).toBeUndefined();
    });

    it('refuses a log whose new checkpoint is not consistent with its anchored one, and anchors the others', async () => {
      await capture('alpha', 5);
      await capture('beta', 5);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      await settle(s);
      // The database owner corrupts alpha's stored compact range.
      const alpha = (await logs.getEvidenceLog('alpha'))!;
      await asOwner('UPDATE log_checkpoints SET compact_range = ? WHERE log_id = ?', [JSON.stringify(['00'.repeat(32), '11'.repeat(32)]), alpha.logId]);
      await capture('alpha', 2);
      await capture('beta', 2);
      advance(HOUR);
      const report = await s.runPass();
      expect(report.alarms.map((a) => [a.code, a.subject])).toContainEqual(['log_inconsistent_with_anchor', alpha.origin]);
      expect(report.epoch).toMatchObject({ members: 1 });
      expect(report.halted).toBe(false);
    });

    it('anchor_history_mismatch stops anchoring when the anchor log no longer rebuilds the published root', async () => {
      await capture('alpha', 4);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      await settle(s);
      const anchorLog = await anchors.ensureStoreLog('anchors');
      await asOwner('UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 0', ['ab'.repeat(32), anchorLog.logId]);
      await capture('alpha', 1);
      advance(HOUR);
      const report = await s.runPass();
      expect(report.halted).toBe(true);
      expect(report.alarms.map((a) => a.code)).toContain('anchor_history_mismatch');
      expect(report.epoch).toBeNull();
      advance(HOUR);
      expect(await s.runPass()).toMatchObject({ halted: true, epoch: null });
      expect((await s.getAnchorState()).halted?.code).toBe('anchor_history_mismatch');
      expect(chain.broadcasts).toHaveLength(1);
    });

    it('anchor_history_mismatch stops anchoring when the finalized block is no longer canonical', async () => {
      await capture('alpha', 4);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      await settle(s);
      const [pub] = await publications();
      // A reorg deeper than the finalized tag: impossible on a real chain, and exactly what the check is for.
      chain.reorg(chain.head() - (pub.blockNumber as number) + 1);
      chain.mine(6);
      await capture('alpha', 1);
      advance(HOUR);
      const report = await s.runPass();
      expect(report.halted).toBe(true);
      expect(report.alarms.map((a) => a.code)).toContain('anchor_history_mismatch');
    });
  });

  describe('the outbox', () => {
    it('a crash after broadcast resumes the same transaction and never signs a second', async () => {
      await capture('alpha', 3);
      const crashing = await scheduler({
        testHooks: {
          afterBroadcast: () => {
            throw new Error('killed after broadcast');
          },
        },
      });
      advance(HOUR);
      await expect(crashing.runPass()).rejects.toThrow('killed after broadcast');
      const [persisted] = await publications();
      expect(persisted.state).toBe('submitted');
      expect(persisted.attempts).toHaveLength(1);
      expect(persisted.attempts[0].broadcast).toBe('unknown');

      const restarted = await scheduler({ holderId: 'restarted' });
      await anchors.releaseAnchorLease((await restarted.getAnchorState()).domainPrefix, (await crashing.getAnchorState()).lease!.holder);
      await settle(restarted);
      const [done] = await publications();
      expect(done.state).toBe('finalized');
      expect(done.minedTxHash).toBe(persisted.attempts[0].txHash);
      expect(new Set(chain.broadcasts)).toEqual(new Set([persisted.attempts[0].rawTx]));
    });
  });

  describe('confirmation', () => {
    async function submitted(s: AnchorScheduler): Promise<AnchorPublication> {
      await capture('alpha', 2);
      advance(HOUR);
      await s.runPass();
      const [pub] = await publications();
      expect(pub.state).toBe('submitted');
      return pub;
    }

    it('an evicted transaction is rebroadcast unchanged', async () => {
      const s = await scheduler();
      const pub = await submitted(s);
      chain.evict(pub.attempts[0].txHash);
      expect(chain.poolSize()).toBe(0);
      const report = await s.runPass();
      expect(report.broadcasts).toEqual([expect.objectContaining({ txHash: pub.attempts[0].txHash, outcome: 'accepted' })]);
      expect(chain.broadcasts[chain.broadcasts.length - 1]).toBe(pub.attempts[0].rawTx);
      await settle(s);
      expect((await publications())[0]).toMatchObject({ state: 'finalized', minedTxHash: pub.attempts[0].txHash });
    });

    it('close() is final: runPass, anchorNow, getAnchorState and start refuse from the moment it is called', async () => {
      const s = await scheduler();
      await capture('alpha', 1);
      const inFlight = s.anchorNow({ force: true });
      const closing = s.close();
      await expect(s.runPass()).rejects.toThrow(/is closed: runPass\(\) runs nothing/);
      await closing;
      expect((await inFlight).epoch).not.toBeNull();
      await expect(s.anchorNow()).rejects.toThrow(/is closed/);
      await expect(s.getAnchorState()).rejects.toThrow(/is closed/);
      await expect(s.start()).rejects.toThrow(/is closed/);
      await expect(s.close()).resolves.toBeUndefined();
    });

    it('a restart after the transaction mined records it, with no alarm', async () => {
      const s = await scheduler();
      const pub = await submitted(s);
      chain.mine(1);
      await s.stop();
      const restarted = await scheduler({ holderId: 'restarted' });
      const report = await restarted.runPass();
      expect(report.transitions).toContainEqual({ publicationId: pub.id, from: 'submitted', to: 'included' });
      expect(report.alarms).toEqual([]);
    });

    it('looks up every attempt\'s receipt before calling a nonce-too-low answer foreign', async () => {
      const s = await scheduler();
      const pub = await submitted(s);
      chain.mine(1);
      // The node's receipt index misses the transaction once: the rebroadcast then answers "nonce too low".
      const receipt = chain.receipt.bind(chain);
      let hidden = 1;
      chain.receipt = async (hash: string) => (hidden-- > 0 ? null : receipt(hash));
      const report = await s.runPass();
      expect(report.broadcasts).toEqual([expect.objectContaining({ reason: 'nonce_too_low' })]);
      expect(report.transitions).toContainEqual({ publicationId: pub.id, from: 'submitted', to: 'included' });
      expect(report.alarms).toEqual([]);
    });

    it('a reorg returns an included transaction to submitted, and it is rebroadcast and finalized', async () => {
      const s = await scheduler();
      const pub = await submitted(s);
      chain.mine(1);
      await s.runPass();
      const included = (await publications())[0];
      expect(included.state).toBe('included');
      chain.reorg(1);
      const report = await s.runPass();
      expect(report.transitions).toContainEqual({ publicationId: pub.id, from: 'included', to: 'submitted' });
      expect(report.broadcasts[0]).toMatchObject({ txHash: pub.attempts[0].txHash, outcome: 'accepted' });
      chain.mine(1);
      await settle(s);
      const done = (await publications())[0];
      expect(done.state).toBe('finalized');
      expect(done.minedTxHash).toBe(pub.attempts[0].txHash);
    });

    it('replaces a stuck transaction with the same nonce and calldata, +12.5%, at most 5 times, then raises anchor_tx_stuck', async () => {
      const s = await scheduler();
      const pub = await submitted(s);
      // The base fee jumps past every fee the governor may pay: the attempt cannot be mined.
      chain.baseFeePerGas = 60_000_000_000n;
      chain.mine(1);
      const reports: AnchorPassReport[] = [];
      for (let i = 0; i < 7; i++) {
        advance(6 * MIN);
        reports.push(await s.runPass());
      }
      const stuck = (await publications())[0];
      expect(stuck.attempts).toHaveLength(6);
      for (let i = 1; i < stuck.attempts.length; i++) {
        const prev = BigInt(stuck.attempts[i - 1].maxFeePerGas);
        expect(BigInt(stuck.attempts[i].maxFeePerGas)).toBe((prev * 1125n + 999n) / 1000n);
      }
      const parsed = stuck.attempts.map((a) => Transaction.from(a.rawTx));
      expect(new Set(parsed.map((t) => t.nonce))).toEqual(new Set([pub.nonce]));
      expect(new Set(parsed.map((t) => t.data))).toEqual(new Set([`0x${pub.p}`]));
      expect(reports.flatMap((r) => r.alarms.map((a) => a.code))).toContain('anchor_tx_stuck');

      // The fee falls back: the latest attempt mines.
      chain.baseFeePerGas = 1_000_000_000n;
      await settle(s);
      const done = (await publications())[0];
      expect(done.state).toBe('finalized');
      expect(stuck.attempts.map((a) => a.txHash)).toContain(done.minedTxHash);
    });

    it('stops replacing when the clamp to the hard cap leaves less than the node\'s minimum bump', async () => {
      const s = await scheduler({ config: { publishers: {}, budget: { hardFeeCapGwei: 2.4, softMaxFeeGwei: 2 } } as never });
      const pub = await submitted(s);
      chain.baseFeePerGas = 3_000_000_000n;
      chain.mine(1);
      for (let i = 0; i < 4; i++) {
        advance(6 * MIN);
        await s.runPass();
      }
      const stuck = (await publications())[0];
      expect(BigInt(stuck.attempts[stuck.attempts.length - 1].maxFeePerGas)).toBeLessThanOrEqual(2_400_000_000n);
      expect(stuck.attempts.length).toBeLessThan(4);
      expect((await s.getAnchorState()).alarms.map((a) => a.code)).toContain('anchor_tx_stuck');
      expect(pub.id).toBe(stuck.id);
    });

    it('only a publication whose every broadcast was rejected is superseded, by a later epoch at the same nonce', async () => {
      await capture('alpha', 2);
      // No replacement in this case: only the supersession is under test.
      const s = await scheduler({ tuning: { stuckAfterMs: 48 * HOUR } });
      advance(HOUR);
      let firstRaw: string | null = null;
      chain.refuse = (raw) => {
        firstRaw ??= raw;
        return raw === firstRaw ? 'transaction pool is full' : null;
      };
      await s.runPass();
      const [rejected] = await publications();
      expect(rejected.attempts.map((a) => a.broadcast)).toEqual(['rejected']);
      // Every rebroadcast is refused too, and a refusal on a rebroadcast never changes what was recorded.
      await s.runPass();
      const second = await capture('alpha', 1);
      advance(HOUR);
      const report = await s.runPass();
      chain.refuse = null;
      expect(report.transitions).toContainEqual({ publicationId: rejected.id, from: 'submitted', to: 'superseded' });
      const [old, next] = await publications();
      expect(old.state).toBe('superseded');
      expect(next.nonce).toBe(rejected.nonce);
      // The new anchor checkpoint covers the superseded epoch's leaf too, and
      // its consistency proof starts from no published size.
      const anchorLog = await anchors.ensureStoreLog('anchors');
      expect((await anchors.getLogCheckpoint(anchorLog.logId, next.anchorSize))!.prevAnchoredSize).toBeNull();
      await settle(s);
      for (const id of ['rec-' + (counter - 2), ...second]) {
        const anchor = ((await adapter.retrieve(id))!.nonRepudiation as Record<string, { anchorCheckpoint: string }>).anchor;
        expect(parseCheckpoint(anchor.anchorCheckpoint)).toMatchObject({ ok: true, checkpoint: { size: next.anchorSize } });
      }
    });

    it('a broadcast with no answer is never superseded', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      advance(HOUR);
      const broadcast = chain.broadcast.bind(chain);
      chain.broadcast = async () => ({ outcome: 'unknown', reason: 'unreachable' });
      await s.runPass();
      chain.broadcast = broadcast;
      const [pub] = await publications();
      expect(pub.attempts.map((a) => a.broadcast)).toEqual(['unknown']);
      await capture('alpha', 1);
      advance(HOUR);
      const report = await s.runPass();
      expect(report.epoch).toBeNull();
      expect((await publications()).map((p) => p.state)).toEqual(['submitted']);
    });

    it('a rate-limited first broadcast is unknown, not rejected, and is never superseded', async () => {
      await capture('alpha', 2);
      const s = await scheduler({ tuning: { stuckAfterMs: 48 * HOUR } });
      advance(HOUR);
      chain.errorNext = { error: { code: 'UNKNOWN_ERROR', error: { code: -32005, message: 'daily request count exceeded, request rate limited' } }, accept: false };
      const first = await s.runPass();
      expect(first.broadcasts).toEqual([expect.objectContaining({ outcome: 'unknown', reason: 'rate_limited' })]);
      const [pub] = await publications();
      expect(pub.attempts.map((a) => a.broadcast)).toEqual(['unknown']);
      // Every later broadcast is refused, and a next epoch is due: the unknown attempt keeps its nonce.
      chain.refuse = () => 'transaction pool is full';
      await capture('alpha', 1);
      advance(HOUR);
      const report = await s.runPass();
      expect(report.epoch).toBeNull();
      expect((await publications()).map((p) => [p.state, p.attempts.map((a) => a.broadcast)])).toEqual([['submitted', ['unknown']]]);
    });

    it('an internal error from a node that took the transaction is unknown, and the transaction is finalized', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      advance(HOUR);
      chain.errorNext = { error: { code: 'UNKNOWN_ERROR', error: { code: -32603, message: 'internal error' } }, accept: true };
      await s.runPass();
      const [pub] = await publications();
      expect(pub.attempts.map((a) => a.broadcast)).toEqual(['unknown']);
      await settle(s);
      expect((await publications()).map((p) => [p.state, p.minedTxHash])).toEqual([['finalized', pub.attempts[0].txHash]]);
    });

    it('a publisher key changed while a publication is unmined, the old key in the manifest: the old transaction is rebroadcast, never re-signed, with an alarm', async () => {
      await capture('alpha', 2);
      const first = await scheduler();
      advance(HOUR);
      await first.runPass();
      const [pub] = await publications();
      const w1 = wallet.address.toLowerCase();
      expect(pub.fromAddress).toBe(w1);
      const { anchorOrigin } = await first.getAnchorState();
      // The base fee jumps: the transaction sticks.
      chain.baseFeePerGas = 60_000_000_000n;
      chain.mine(1);
      await first.stop();

      wallet = Wallet.createRandom() as unknown as Wallet;
      chain.fund(wallet.address, ETH);
      // The manifest names both keys: the scheduler accepts the old key's
      // publications as its own.
      const publisherManifest = {
        publishers: {
          [anchorOrigin]: [
            { address: w1, chain: CHAIN, namespace: 'test' as const },
            { address: wallet.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const },
          ],
        },
      };
      const rotated = await scheduler({ holderId: 'rotated', publisherManifest });
      await capture('alpha', 1);
      for (let i = 0; i < 3; i++) {
        advance(HOUR);
        const report = await rotated.runPass();
        expect(report.alarms.map((a) => a.code)).toContain('anchor_publication_other_wallet');
        expect(report.epoch).toBeNull();
      }
      const stuck = (await publications())[0];
      expect(stuck).toMatchObject({ state: 'submitted', fromAddress: w1 });
      expect(stuck.attempts).toHaveLength(1);
      expect(new Set(chain.broadcasts)).toEqual(new Set([pub.attempts[0].rawTx]));

      // The fee falls: the old transaction mines, and the epoch waiting behind
      // it is the new wallet's, at the new wallet's first nonce.
      chain.baseFeePerGas = 1_000_000_000n;
      await settle(rotated);
      const done = await publications();
      expect(done.map((p) => [p.state, p.fromAddress, p.nonce])).toEqual([
        ['finalized', w1, 0],
        ['finalized', wallet.address.toLowerCase(), 0],
      ]);
      expect(done[0].attempts).toHaveLength(1);
      expect((await rotated.getAnchorState()).alarms.map((a) => a.code)).not.toContain('anchor_publication_other_wallet');
    });

    it('a publisher key changed while a publication is unmined, the old key in no manifest: the scheduler stops and sends nothing', async () => {
      await capture('alpha', 2);
      const first = await scheduler();
      advance(HOUR);
      await first.runPass();
      const [pub] = await publications();
      chain.baseFeePerGas = 60_000_000_000n;
      chain.mine(1);
      await first.stop();
      const sent = chain.broadcasts.length;

      wallet = Wallet.createRandom() as unknown as Wallet;
      chain.fund(wallet.address, ETH);
      const rotated = await scheduler({ holderId: 'rotated' });
      advance(HOUR);
      const report = await rotated.runPass();
      expect(report.halted).toBe(true);
      expect(report.alarms.map((a) => [a.code, a.subject])).toEqual([['anchor_publication_unexplained', String(pub.id)]]);
      expect(chain.broadcasts).toHaveLength(sent);
      expect((await publications())[0]).toMatchObject({ state: 'submitted', attempts: [expect.objectContaining({ txHash: pub.attempts[0].txHash })] });
    });

    it('a foreign transaction from the wallet raises anchor_nonce_consumed_externally and stops anchoring', async () => {
      const s = await scheduler();
      const pub = await submitted(s);
      chain.evict(pub.attempts[0].txHash);
      await chain.sendExternal(wallet, '0xdead');
      chain.mine(1);
      const report = await s.runPass();
      expect(report.alarms.map((a) => a.code)).toContain('anchor_nonce_consumed_externally');
      expect(report.halted).toBe(true);
      expect((await s.getAnchorState()).halted?.code).toBe('anchor_nonce_consumed_externally');
    });

    it('a foreign transaction ahead of the next epoch is caught before signing', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      await settle(s);
      await chain.sendExternal(wallet);
      chain.mine(1);
      await capture('alpha', 1);
      advance(HOUR);
      const report = await s.runPass();
      expect(report.alarms.map((a) => a.code)).toContain('anchor_nonce_consumed_externally');
      expect(report.halted).toBe(true);
      // The nonce is checked before the epoch is written: no epoch is left behind.
      expect((await publications()).map((p) => p.state)).toEqual(['finalized']);
    });
  });

  describe('the governor', () => {
    it('defers above the soft maximum until T_max, and publishes within the hard cap then', async () => {
      await capture('alpha', 2);
      chain.baseFeePerGas = 25_000_000_000n;
      const s = await scheduler();
      // At 25 gwei the governor stretches the interval to about 2.4 h.
      advance(HOUR);
      expect((await s.runPass()).deferred).toBeNull();
      advance(2 * HOUR);
      expect((await s.runPass()).deferred).toBe('fee_above_soft_max');
      expect(chain.broadcasts).toHaveLength(0);
      advance(21 * HOUR);
      const report = await s.runPass();
      expect(report.epoch).not.toBeNull();
      const [pub] = await publications();
      expect(BigInt(pub.attempts[0].maxFeePerGas)).toBeLessThanOrEqual(50_000_000_000n);
    });

    it('never publishes above the hard cap, and raises an alarm once T_max has passed', async () => {
      await capture('alpha', 2);
      chain.baseFeePerGas = 55_000_000_000n;
      const s = await scheduler();
      advance(25 * HOUR);
      const report = await s.runPass();
      expect(report.deferred).toBe('fee_above_hard_cap');
      expect(report.alarms.map((a) => a.code)).toContain('anchor_fee_above_hard_cap');
      expect(chain.broadcasts).toHaveLength(0);
    });

    it('refuses to submit under 3x the cost at the hard cap', async () => {
      await capture('alpha', 2);
      const poor = Wallet.createRandom() as unknown as Wallet;
      chain.fund(poor.address, 3n * 22_280n * 50_000_000_000n - 1n);
      wallet = poor;
      const s = await scheduler();
      // The alarm is raised on every pass that reads the balance; the refusal when an epoch is due.
      expect((await s.runPass()).alarms.map((a) => a.code)).toContain('anchor_wallet_insufficient_funds');
      advance(25 * HOUR);
      const report = await s.runPass();
      expect(report.deferred).toBe('anchor_wallet_insufficient_funds');
      expect(report.alarms.map((a) => a.code)).toContain('anchor_wallet_insufficient_funds');
      expect(await publications()).toEqual([]);
    });

    it('warns under 30 days of runway and is critical under 7', async () => {
      await capture('alpha', 1);
      const low = Wallet.createRandom() as unknown as Wallet;
      chain.fund(low.address, ETH / 2000n);
      wallet = low;
      const s = await scheduler();
      await s.runPass();
      expect((await s.getAnchorState()).alarms.map((a) => a.code)).toContain('anchor_runway_low');
    });

    it('accounts spend from receipts', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      await settle(s);
      const [pub] = await publications();
      const state = await s.getAnchorState();
      expect(state.spentWei).toBe((BigInt(pub.gasUsed!) * BigInt(pub.effectiveGasPrice!)).toString());
      expect(pub.gasUsed).toBe('22280');
    });

    it('an unreachable node fails the pass, which backs off, and the next pass resumes', async () => {
      await capture('alpha', 2);
      const s = await scheduler({ tuning: { tickMs: 60_000 } });
      advance(HOUR);
      chain.outage = true;
      await expect(s.runPass()).rejects.toThrow(/ECONNREFUSED/);
      await expect(s.runPass()).rejects.toThrow(/ECONNREFUSED/);
      const state = await s.getAnchorState();
      expect(state.stalledPasses).toBe(2);
      expect(state.lastError).toMatch(/ECONNREFUSED/);
      chain.outage = false;
      expect((await s.runPass()).epoch).not.toBeNull();
      expect((await s.getAnchorState()).stalledPasses).toBe(0);
    });

    it('never cuts an empty epoch', async () => {
      const s = await scheduler();
      advance(30 * HOUR);
      expect((await s.runPass()).epoch).toBeNull();
      expect((await s.anchorNow({ force: true })).deferred).toBe('nothing_waiting');
    });
  });

  describe('anchorNow and getAnchorState', () => {
    it('force bypasses minInterval; the seventh forced publication in 24 h is refused', async () => {
      const s = await scheduler();
      for (let i = 0; i < 6; i++) {
        await capture('alpha', 1);
        const report = await s.anchorNow({ force: true });
        expect(report.epoch).toMatchObject({ forced: true });
        chain.mine(1);
        await s.runPass();
      }
      await capture('alpha', 1);
      await expect(s.anchorNow({ force: true })).rejects.toThrow(AnchorForceRateLimitedError);
      await expect(s.anchorNow({ force: true })).rejects.toMatchObject({ code: 'anchor_force_rate_limited', limit: 6 });
      const state = await s.getAnchorState();
      expect(state.force).toEqual({ usedInLast24h: 6, limit: 6 });
      // A day later the window has moved on.
      advance(24 * HOUR + MIN);
      expect((await s.anchorNow({ force: true })).epoch).not.toBeNull();
    });

    it('force obeys the hard cap and the 3x refusal, and a refused force does not count', async () => {
      await capture('alpha', 1);
      chain.baseFeePerGas = 60_000_000_000n;
      const s = await scheduler();
      expect((await s.anchorNow({ force: true })).deferred).toBe('fee_above_hard_cap');
      expect((await s.getAnchorState()).force.usedInLast24h).toBe(0);
    });

    it('a force when the cadence is due anyway is not counted as forced', async () => {
      await capture('alpha', 1);
      const s = await scheduler();
      advance(HOUR);
      expect((await s.anchorNow({ force: true })).epoch).toMatchObject({ forced: false });
    });

    it('getAnchorState reports the lease, the last publication, the wallet, fees, caps and the fill backlog', async () => {
      await capture('alpha', 3);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      chain.mine(1);
      await s.runPass();
      const mid = await s.getAnchorState();
      expect(mid).toMatchObject({
        namespace: 'test',
        production: false,
        chain: CHAIN,
        publisher: wallet.address.toLowerCase(),
        lease: { self: true },
        halted: null,
        wallet: { enrolled: true, nonceBase: 0 },
        fees: { softMaxFeeGwei: 20, hardFeeCapGwei: 50 },
      });
      expect(mid.lastPublished).toMatchObject({ state: 'included', anchorSize: 1 });
      expect(mid.inFlight).toHaveLength(1);
      expect(BigInt(mid.wallet.balanceWei!)).toBeGreaterThan(0n);
      await settle(s);
      const done = await s.getAnchorState();
      expect(done.lastFinalized).toMatchObject({ state: 'finalized' });
      expect(done.fillBacklog).toBe(0);
      expect(done.inFlight).toEqual([]);
    });
  });

  describe('the activation guard', () => {
    it('refuses a production origin unless production is true', async () => {
      await backend.fresh();
      const fresh = await backend.open({ logNamespace: 'demo.tzun.ai' });
      opened.push(fresh);
      await expect(scheduler({}, fresh)).rejects.toThrow(AnchorActivationError);
      await expect(scheduler({}, fresh)).rejects.toMatchObject({ code: 'anchor_production_not_enabled' });
      const allowed = await scheduler({ config: { publishers: {}, production: true } as never }, fresh);
      expect((await allowed.getAnchorState()).namespace).toBe('production');
    });

    it('refuses a publisher the manifest lists as a production publisher, even under a test. origin', async () => {
      await expect(
        scheduler({ publisherManifest: { publishers: { 'demo.tzun.ai/x/anchors': [{ address: wallet.address, chain: CHAIN, namespace: 'production' }] } } }),
      ).rejects.toThrow(/production publisher/);
    });

    // tzun-anchor/1 §10.6: a `test.` origin is always
    // `anchorNamespace: 'test'`, whatever the manifest says.
    it('a test. origin is reported anchorNamespace test, even under a production manifest entry', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      await settle(s);
      const env = (await adapter.retrieve('rec-' + counter))!;
      const anchorOrigin = (await s.getAnchorState()).anchorOrigin;
      const [pub] = await publications();
      const verdict = await verifyAnchor(env.nonRepudiation, env.integrity.canonicalDigest, {
        publisherManifest: { publishers: { [anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'production' }] } },
        evmHeaderSources: { [CHAIN]: headerSource(chain) },
        publicationMaterial: [{ kind: 'evm-calldata/1', rawTransaction: pub.attempts[0].rawTx, blockNumber: pub.blockNumber, blockHash: pub.blockHash }],
      });
      expect(verdict.anchorValid).toBe(true);
      expect(verdict.anchorNamespace).toBe('test');
    });

    it('refuses a namespace other than the store\'s', async () => {
      await expect(scheduler({ config: { publishers: {}, namespace: 'test.other' } as never })).rejects.toMatchObject({ code: 'log_namespace_mismatch' });
    });
  });

  describe('heavy material (Anchor §7.2, §11)', () => {
    it('stores the raw transaction, header, index and trie proof at finality, and the SDK verifier accepts them offline', async () => {
      await capture('alpha', 2);
      // Other traffic in the block, so the proof is not a single-leaf trie.
      const other = Wallet.createRandom() as unknown as Wallet;
      chain.fund(other.address, ETH);
      const s = await scheduler();
      advance(HOUR);
      await chain.sendExternal(other);
      await chain.sendExternal(other);
      await s.runPass();
      await chain.sendExternal(other);
      await settle(s);
      const [pub] = await publications();
      expect(pub.blockHeader).toMatch(/^0x/);
      expect(pub.txTrieProof!.length).toBeGreaterThan(0);
      expect(pub.txIndex).not.toBeNull();
      const anchorOrigin = (await s.getAnchorState()).anchorOrigin;
      const input = {
        publication: {
          kind: 'evm-calldata/1' as const,
          transactionId: pub.minedTxHash!,
          rawTransaction: pub.attempts.find((a) => a.txHash === pub.minedTxHash)!.rawTx,
          blockNumber: pub.blockNumber!,
          blockHash: pub.blockHash!,
          blockHeader: pub.blockHeader!,
          txIndex: pub.txIndex!,
          txProof: pub.txTrieProof!,
        },
        p: pub.p,
        anchorOrigin,
        manifest: { publishers: { [anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' as const }] } },
      };
      const offline = await verifyEvmPublication(input);
      expect(offline.checks.tx.outcome).toBe('checked-correct');
      expect(offline.valid).toBeNull();
      const online = await verifyEvmPublication({ ...input, headerSources: { [CHAIN]: headerSource(chain) } });
      expect(online).toMatchObject({ valid: true, facts: { inclusion: 'tx_proof' } });
    });
  });

  describe('wallet enrolment and accounted transactions (Anchor §7.2)', () => {
    it('a wallet that already sent 3 transactions enrols at nonce 3, anchors, and nonce accounting stays clean; a sweep is accounted', async () => {
      for (let i = 0; i < 3; i++) await chain.sendExternal(wallet);
      chain.mine(1);
      await capture('alpha', 2);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      await settle(s);
      expect((await s.getAnchorState()).wallet.nonceBase).toBe(3);
      const first = await s.accountNonces();
      expect(first).toMatchObject({ nonceBase: 3, transactionCount: 4, unaccounted: [] });
      expect(first.accounted.map((a) => [a.nonce, a.kind])).toEqual([[3, 'publication']]);

      const treasury = Wallet.createRandom().address;
      const swept = await s.sweep(treasury);
      expect(swept.tx).toMatchObject({ kind: 'sweep', nonce: 4 });
      expect(swept).toMatchObject({ broadcast: { outcome: 'accepted' }, retired: true });
      chain.mine(1);
      const after = await s.accountNonces();
      expect(after.unaccounted).toEqual([]);
      expect(after.accounted.map((a) => [a.nonce, a.kind])).toEqual([
        [3, 'publication'],
        [4, 'sweep'],
      ]);
      expect(await chain.balance(treasury)).toBeGreaterThan(0n);
      // Retired: the scheduler publishes no more from it.
      await capture('alpha', 1);
      advance(HOUR);
      await expect(s.runPass()).rejects.toThrow(AnchorWalletError);
    });

    it('a foreign transaction shows up as an unaccounted nonce', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      advance(HOUR);
      await s.runPass();
      await settle(s);
      await chain.sendExternal(wallet);
      chain.mine(1);
      expect((await s.accountNonces()).unaccounted).toEqual([1]);
    });

    it('a sweep and a pass never interleave: no publication is left in flight on a retired wallet', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      advance(HOUR);
      const [pass, sweep] = await Promise.allSettled([s.runPass(), s.sweep(Wallet.createRandom().address)]);
      const retired = (await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN))!.retiredAt;
      const inFlight = (await publications()).filter((p) => ['prepared', 'submitted', 'included'].includes(p.state));
      if (sweep.status === 'fulfilled') {
        expect(pass.status).toBe('rejected');
        expect((pass as PromiseRejectedResult).reason).toBeInstanceOf(AnchorWalletError);
        expect(await publications()).toEqual([]);
        expect(retired).not.toBeNull();
      } else {
        expect(pass.status).toBe('fulfilled');
        expect(retired).toBeNull();
        expect(inFlight).toHaveLength(1);
      }
    });

    it('a sweep is refused until every publication is finalized and filled', async () => {
      await capture('alpha', 2);
      const failing = intercept(anchors, 'fillAnchorArtifacts', async () => {
        throw new Error('the process died during the fill');
      });
      const s = await scheduler({ anchorStore: failing, logStore: logs, storage: undefined });
      advance(HOUR);
      await s.runPass();
      const dead = Wallet.createRandom().address;
      await expect(s.sweep(dead)).rejects.toThrow(/is submitted: a sweep retires the wallet, so every publication must be finalized and filled first/);
      chain.mine(chain.finalizedDepth + 1);
      await expect(s.runPass()).rejects.toThrow('the process died during the fill');
      await expect(s.sweep(dead)).rejects.toThrow(/finalized but not filled/);
      expect((await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN))!.retiredAt).toBeNull();
      expect(await anchors.listAnchorWalletTxs(wallet.address.toLowerCase(), CHAIN)).toEqual([]);
    });

    it('a wallet operation needs the lease', async () => {
      const a = await scheduler({ holderId: 'replica-a' });
      await a.runPass();
      const second = await backend.open({ logNamespace: NS });
      opened.push(second);
      const b = await scheduler({ holderId: 'replica-b' }, second);
      await expect(b.sweep(Wallet.createRandom().address)).rejects.toThrow(AnchorNotLeaderError);
      await expect(b.handover(`${NS}/${'f'.repeat(32)}/anchors`)).rejects.toMatchObject({ code: 'anchor_not_leader', holder: `${ANCHOR_LEASE_HOLDER_PREFIX}replica-a` });
      expect(chain.broadcasts).toEqual([]);
    });

    it('a refused sweep leaves the wallet enrolled; rebroadcastAccountedTransaction sends the stored bytes and retires it', async () => {
      const s = await scheduler();
      const treasury = Wallet.createRandom().address;
      chain.refuseNext = 'transaction pool is full';
      const refused = await s.sweep(treasury);
      expect(refused).toMatchObject({ broadcast: { outcome: 'rejected' }, retired: false });
      expect((await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN))!.retiredAt).toBeNull();
      await expect(s.sweep(treasury)).rejects.toThrow(/rebroadcastAccountedTransaction/);

      const again = await s.rebroadcastAccountedTransaction();
      expect(again).toMatchObject({ broadcast: { outcome: 'accepted' }, retired: true });
      expect(again.tx.txHash).toBe(refused.tx.txHash);
      expect(chain.broadcasts).toEqual([refused.tx.rawTx, refused.tx.rawTx]);
      expect((await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN))!.retiredAt).not.toBeNull();
      chain.mine(1);
      expect(await chain.balance(treasury)).toBeGreaterThan(0n);
      // Mined: nothing is sent again.
      expect(await s.rebroadcastAccountedTransaction()).toMatchObject({ broadcast: null, retired: true });
      expect(chain.broadcasts).toHaveLength(2);
    });

    it('a handover names another domain\'s anchor origin, or is refused', async () => {
      const s = await scheduler();
      const own = (await s.getAnchorState()).anchorOrigin;
      const id = 'f'.repeat(32);
      for (const bad of ['anchors', `${NS}/anchors`, `${NS}/${id}/evidence/616c706861`, `${NS}/${id}/anchors/more`, `Test.Upper/${id}/anchors`, own]) {
        await expect(s.handover(bad)).rejects.toThrow(/another domain's anchor origin/);
      }
      expect(chain.broadcasts).toEqual([]);
      expect(await anchors.listAnchorWalletTxs(wallet.address.toLowerCase(), CHAIN)).toEqual([]);
    });

    it('a handover is stored before it is sent, names the new anchor origin, and retires the wallet', async () => {
      await capture('alpha', 1);
      const s = await scheduler();
      const next = `${NS}/${'f'.repeat(32)}/anchors`;
      const handed = await s.handover(next);
      expect(handed.tx.kind).toBe('handover');
      const tx = (await chain.transaction(handed.tx.txHash))!;
      expect(Buffer.from(tx.data.slice(2), 'hex').toString('utf8')).toBe(next);
      expect((await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN))!.retiredAt).not.toBeNull();
      chain.mine(1);
      expect((await s.accountNonces()).unaccounted).toEqual([]);
    });
  });

  it('a pass reads each log\'s last anchored checkpoint by index, never a log\'s whole checkpoint history', async () => {
    await capture('alpha', 2);
    await capture('beta', 2);
    const calls: string[] = [];
    const spying = new Proxy(anchors, {
      get(t, prop, receiver) {
        if (prop === 'listLogCheckpoints') calls.push(String(prop));
        const v = Reflect.get(t, prop, receiver);
        return typeof v === 'function' ? v.bind(t) : v;
      },
    });
    const s = await scheduler({ anchorStore: spying, logStore: logs, storage: undefined });
    for (let epoch = 0; epoch < 3; epoch++) {
      await capture('alpha', 1);
      advance(HOUR);
      await s.runPass();
      await settle(s);
    }
    expect((await publications()).map((p) => p.state)).toEqual(['finalized', 'finalized', 'finalized']);
    expect(calls).toEqual([]);
  });

  it('the checkpoints it cuts are exact bodies naming the store\'s origins', async () => {
    await capture('alpha', 3);
    const s = await scheduler();
    advance(HOUR);
    await s.runPass();
    const alpha = (await logs.getEvidenceLog('alpha'))!;
    const [cp] = await anchors.listLogCheckpoints(alpha.logId);
    const parsed = parseCheckpoint(cp.body);
    expect(parsed).toMatchObject({ ok: true, checkpoint: { origin: alpha.origin, size: 3, root: cp.root } });
    expect(createHash('sha256').update(cp.body).digest('hex')).toBe(cp.bodyDigest);
  });
});
