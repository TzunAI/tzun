/**
 * Anchoring trust, the scheduler's part: it signs only a P it re-derives from
 * the anchor log, accepts an earlier publication as its own only by its signed
 * transaction and a sender its configuration or manifest names (inside its
 * window, at a time the node confirms), and fills only under a publication
 * the node confirms, over a range it explains, onto records that match their
 * leaves.
 *
 * Every forged row is written on the store's own database, outside the
 * adapter: with every trigger enabled where a writer the triggers hold could
 * write it (W1), around them where only the owner could (W2, `asOwner`). A
 * publisher or a store passed to the scheduler can also return anything, and
 * is given what it returns here.
 *
 * Before these checks, the sign-gate and source-log cases failed: the
 * dedicated wallet signed and broadcast the forged prepared publication, and
 * the custody log was anchored.
 */
import { createHash } from 'node:crypto';
import { Transaction, Wallet, decodeRlp, keccak256, type TransactionLike } from 'ethers';
import type { EvidenceEnvelope } from '@tzun/engine';
import {
  AnchoringConfigError,
  createAnchorScheduler,
  createEvmPublisher,
  type AnchorPassReport,
  type AnchorScheduler,
  type AnchorSchedulerOptions,
  type EvmPublisher,
  type EvmTransactionFields,
  type SignedTransaction,
} from '../../src/anchoring';
import { checkpointDigest, formatCheckpoint } from '../../src/attestation/checkpoint';
import { verifyAnchor } from '../../src/attestation/anchor-verify';
import { extendCompactRange } from '../../src/attestation/merkle';
import { readEvmTransaction, type EvmHeaderSource, type EvmItemTwoRule } from '../../src/attestation/blockchain';
import { anchorStoreFor, assertWalletTx, logStoreFor, type AnchorPublication, type AnchorStore, type AnchorWalletTx, type LogStore } from '../../src/storage/log-store';
import { makeEnvelope } from './storage-conformance/fixtures';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { buildHeader, buildTxTrie } from './helpers/evm-fixtures';
import { rewriteType2Field, toHighS } from './helpers/signer-faults';
import { type LogBackend, type OpenedStore, type RawDb, logBackends } from './helpers/log-store-backends';

const HOUR = 60 * 60_000;
const ETH = 10n ** 18n;
const CHAIN = 'eip155:31337';
const NS = 'test.tzun.dev';

const leafHash = (hex: string): string => createHash('sha256').update(Buffer.concat([Buffer.from([0]), Buffer.from(hex, 'hex')])).digest('hex');
const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

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

/**
 * Twins of a signed EIP-1559 transaction that anyone who can write the store
 * can make without the key: the same signer's signature over the same hash,
 * from which a lenient reader (ethers) recovers the same sender, and which
 * tzun-anchor/1 §10.4 item 2 refuses by the rule named.
 */
const TWINS: Array<[string, (raw: string) => string, EvmItemTwoRule]> = [
  ['its high-s twin (n - s, the parity flipped)', (raw) => toHighS(raw).toLowerCase(), 'signature-values'],
  [
    'its values in RLP that is not canonical (gasLimit with a leading zero byte)',
    (raw) => rewriteType2Field(raw, 4, `0x00${(decodeRlp(`0x${raw.slice(4)}`) as string[])[4].slice(2)}`).toLowerCase(),
    'encoding',
  ],
];

type Adapter = {
  store(e: EvidenceEnvelope, chainId?: string): Promise<void>;
  retrieve(id: string): Promise<EvidenceEnvelope | null>;
};

describe.each(logBackends('anchoring_trust').map((b) => [b.name, b] as const))('anchoring trust in the scheduler, on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(120_000);
  let opened: OpenedStore<unknown>[] = [];
  let store: OpenedStore<unknown>;
  let adapter: Adapter;
  let logs: LogStore;
  let anchors: AnchorStore;
  let raw: RawDb;
  let chain: FakeEvmChain;
  let wallet: Wallet;
  let offset = 0;
  let schedulers: AnchorScheduler[] = [];
  const clock = (): number => Date.now() + offset;
  const sqlite = backend.name === 'sqlite';
  /** The SQL a raw insert writes for an insert time: the statement's own on SQLite, which refuses any other. */
  const NOW = sqlite ? "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')" : 'now()';

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
  afterAll(async () => backend.dispose());

  async function scheduler(extra: Partial<AnchorSchedulerOptions> = {}, signerWallet: Wallet = wallet, on: OpenedStore<unknown> = store): Promise<AnchorScheduler> {
    const s = await createAnchorScheduler({
      storage: on.adapter,
      config: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: signerWallet.privateKey, chain: CHAIN } } },
      publisher: createEvmPublisher({ privateKey: signerWallet.privateKey, chain: CHAIN, client: chain }),
      clock,
      expectation: {},
      ...extra,
    });
    schedulers.push(s);
    return s;
  }

  let counter = 0;
  async function capture(chainId: string, n: number): Promise<string[]> {
    const log = await logs.getEvidenceLog(chainId);
    const start = log ? (await logs.getLogSize(log.logId)).size : 0;
    const ids: string[] = [];
    for (let i = 1; i <= n; i++) {
      counter += 1;
      const id = `rec-${counter}`;
      await adapter.store(makeEnvelope({ evidenceId: id, sequenceNumber: start + i }), chainId);
      ids.push(id);
    }
    return ids;
  }
  const publications = (): Promise<AnchorPublication[]> => anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
  const pass = (s: AnchorScheduler): Promise<AnchorPassReport> => s.runPass();
  async function settle(s: AnchorScheduler): Promise<void> {
    for (let i = 0; i < 8; i++) {
      chain.mine(chain.finalizedDepth + 1);
      await s.runPass();
      const pubs = await publications();
      if (pubs.length > 0 && pubs.every((p) => p.state === 'finalized' || p.state === 'superseded') && (await s.getAnchorState()).fillBacklog === 0) return;
    }
  }
  /** One epoch over what waits, published, finalized and filled. */
  async function epoch(s: AnchorScheduler): Promise<void> {
    offset += HOUR;
    await s.runPass();
    await settle(s);
  }
  const codes = (r: AnchorPassReport): string[] => r.alarms.map((a) => a.code);

  /** Change rows the way the store's owner can: around the triggers (W2). */
  async function asOwner(sql: string, params: unknown[] = []): Promise<void> {
    if (sqlite) {
      const triggers = await raw.all<{ name: string; tbl_name: string; sql: string }>("SELECT name, tbl_name, sql FROM sqlite_schema WHERE type = 'trigger'");
      const table = /^\s*(?:UPDATE|INSERT INTO|DELETE FROM)\s+(\w+)/i.exec(sql)?.[1];
      const held = triggers.filter((t) => t.tbl_name === table);
      for (const t of held) await raw.run(`DROP TRIGGER ${t.name}`);
      try {
        await raw.run(sql, params);
      } finally {
        for (const t of held) await raw.run(t.sql);
      }
    } else {
      await raw.run('BEGIN');
      await raw.run("SET LOCAL session_replication_role = 'replica'");
      await raw.run(sql, params);
      await raw.run('COMMIT');
    }
  }

  describe('the sign gate', () => {
    it("two plain INSERTs, an anchor checkpoint at a free size and a prepared publication of it, are never signed, and a fabricated record never verifies", async () => {
      await capture('alpha', 3);
      await capture('beta', 2);
      const s = await scheduler();
      await epoch(s);
      const identity = await logs.getStoreIdentity();
      const anchorOrigin = `${identity.ns}/${identity.storeId}/anchors`;
      const alphaOrigin = (await logs.getEvidenceLog('alpha'))!.origin;
      const anchorLog = await anchors.ensureStoreLog('anchors');
      expect((await logs.getLogSize(anchorLog.logId)).size).toBe(2);
      const sent = chain.broadcasts.length;

      // A fabricated record, never stored: alpha, sequence 1, another id.
      const forged = makeEnvelope({ evidenceId: 'fabricated', sequenceNumber: 1 });
      const d = forged.integrity.canonicalDigest;
      const logBody = formatCheckpoint(alphaOrigin, 1, leafHash(d));
      const anchorRoot = leafHash(checkpointDigest(logBody));
      const anchorBody = formatCheckpoint(anchorOrigin, 1, anchorRoot);
      const p = checkpointDigest(anchorBody);
      await raw.run(
        `INSERT INTO log_checkpoints (log_id, tree_size, root, body, body_digest, compact_range, prev_anchored_size, consistency_proof, anchor_leaf_index, epoch_id, signatures, created_at)
         VALUES (?, 1, ?, ?, ?, '[]', NULL, NULL, NULL, NULL, '[]', ${NOW})`,
        [anchorLog.logId, anchorRoot, anchorBody, p],
      );
      await raw.run(
        `INSERT INTO anchor_publications (epoch_id, anchor_size, p, kind, state, chain, created_at, updated_at) VALUES (99, 1, ?, 'evm-calldata/1', 'prepared', ?, ${NOW}, ${NOW})`,
        [p, CHAIN],
      );
      const report = await pass(s).catch((e: Error) => e);
      expect(chain.broadcasts).toHaveLength(sent);
      expect(report).toMatchObject({ halted: true });
      expect(codes(report as AnchorPassReport)).toContain('anchor_publication_unexplained');
      const planted = (await publications()).find((x) => x.anchorSize === 1)!;
      expect(planted).toMatchObject({ state: 'prepared', attempts: [], fromAddress: null });
      for (let i = 0; i < 3; i++) {
        chain.mine(chain.finalizedDepth + 1);
        offset += HOUR;
        expect(await pass(s)).toMatchObject({ halted: true, broadcasts: [] });
      }

      // Never published, so never verifies as origin-authenticated.
      const verdict = await verifyAnchor(
        {
          anchor: {
            anchorSpec: 'tzun-anchor/1',
            merkleSpec: 'rfc6962',
            leafIndex: 0,
            logCheckpoint: logBody,
            logPath: [],
            anchorLeafIndex: 0,
            anchorCheckpoint: anchorBody,
            anchorPath: [],
            publications: [{ kind: 'evm-calldata/1', chain: CHAIN, transactionId: `0x${'0'.repeat(64)}`, blockNumber: 1, blockHash: `0x${'0'.repeat(64)}`, publisher: wallet.address.toLowerCase() }],
          },
        } as never,
        d,
        {
          sequenceNumber: 1,
          chainId: 'alpha',
          publisherManifest: { publishers: { [anchorOrigin]: [{ address: wallet.address, chain: CHAIN, namespace: 'test' }] } },
          evmHeaderSources: { [CHAIN]: headerSource(chain) },
        },
      );
      expect(verdict.anchorOriginAuthenticated).not.toBe(true);
      expect(verdict.anchorValid).not.toBe(true);
    });

    it('an anchor leaf no source checkpoint is behind, under a prepared publication at the right size, stops the scheduler unsigned', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await epoch(s);
      const identity = await logs.getStoreIdentity();
      const anchorOrigin = `${identity.ns}/${identity.storeId}/anchors`;
      const anchorLog = await anchors.ensureStoreLog('anchors');
      const leaves = await logs.listLogLeaves(anchorLog.logId, 0, 10);
      const phantom = hex('a checkpoint nobody cut');
      await raw.run(
        `INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, ?, ?, ?, 'scheduler', ${NOW})`,
        [anchorLog.logId, leaves.length, phantom, `${anchorOrigin}-nothing\n1`],
      );
      const ext = extendCompactRange({ size: 0, hashes: [] }, [...leaves.map((l) => l.leafDigest), phantom]);
      const body = formatCheckpoint(anchorOrigin, leaves.length + 1, ext.root);
      await raw.run(
        `INSERT INTO log_checkpoints (log_id, tree_size, root, body, body_digest, compact_range, signatures, created_at) VALUES (?, ?, ?, ?, ?, ?, '[]', ${NOW})`,
        [anchorLog.logId, leaves.length + 1, ext.root, body, checkpointDigest(body), JSON.stringify(ext.range.hashes)],
      );
      await raw.run(
        `INSERT INTO anchor_publications (epoch_id, anchor_size, p, kind, state, chain, created_at, updated_at) VALUES (99, ?, ?, 'evm-calldata/1', 'prepared', ?, ${NOW}, ${NOW})`,
        [leaves.length + 1, checkpointDigest(body), CHAIN],
      );
      const sent = chain.broadcasts.length;
      offset += HOUR;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_log_leaf_unexplained');
      expect(chain.broadcasts).toHaveLength(sent);
    });

    it('a persisted epoch that was never signed is re-derived and signed when the cadence calls it due, never as forced, whatever its row says', async () => {
      await capture('alpha', 2);
      // A first instance cuts a forced epoch and dies before it signs.
      let failing = true;
      const dying = await scheduler({
        publisher: {
          ...createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }),
          signPublication: async (...args) => {
            if (failing) throw new Error('the process died before it signed');
            return createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }).signPublication(...args);
          },
        },
      });
      await expect(dying.anchorNow({ force: true })).rejects.toThrow('the process died before it signed');
      await dying.stop();
      failing = false;
      const [prepared] = await publications();
      expect(prepared).toMatchObject({ state: 'prepared', forced: true });

      // A new instance: the leaves the epoch covers are minutes old, so it is not due.
      const s = await scheduler({ holderId: 'restarted' });
      const early = await pass(s);
      expect(early.broadcasts).toEqual([]);
      expect(early.halted).toBe(false);
      expect((await publications())[0]).toMatchObject({ state: 'prepared', attempts: [] });
      // Due an hour later: signed, and not counted as forced.
      offset += HOUR;
      const due = await pass(s);
      expect(due.broadcasts).toHaveLength(1);
      expect((await publications())[0]).toMatchObject({ state: 'submitted', p: prepared.p });
      expect((await s.getAnchorState()).force.usedInLast24h).toBe(0);
      await settle(s);
      expect((await publications())[0].state).toBe('finalized');
    });

    it('a superseded publication with no attempt, which only the owner can write, stops the scheduler instead of moving its clock', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await epoch(s);
      const identity = await logs.getStoreIdentity();
      const anchorLog = await anchors.ensureStoreLog('anchors');
      const size = (await logs.getLogSize(anchorLog.logId)).size;
      const cp = (await anchors.getLogCheckpoint(anchorLog.logId, size))!;
      await asOwner(
        `INSERT INTO anchor_publications (epoch_id, anchor_size, p, kind, state, chain, created_at, updated_at) VALUES (7, ?, ?, 'rfc3161/1', 'prepared', NULL, ?, ?)`,
        [size, cp.bodyDigest, '2099-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z'],
      );
      await asOwner(
        `INSERT INTO anchor_publications (epoch_id, anchor_size, p, kind, state, chain, created_at, updated_at) VALUES (8, ?, ?, 'evm-calldata/1', 'superseded', ?, ?, ?)`,
        [size + 1, hex('nothing'), CHAIN, '2099-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z'],
      );
      void identity;
      await capture('alpha', 1);
      offset += HOUR;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_publication_unexplained');
    });
  });

  describe('the kinds of source log anchored', () => {
    it('a custody log written with plain INSERTs is not anchored; listed in sourceLogKinds it is', async () => {
      await capture('alpha', 1);
      const identity = await logs.getStoreIdentity();
      const custodyOrigin = `${identity.ns}/${identity.storeId}/custody`;
      const forged = makeEnvelope({ evidenceId: 'fabricated', sequenceNumber: 1 });
      await raw.run(`INSERT INTO logs (origin, kind, chain_id, created_at) VALUES (?, 'custody', NULL, ${NOW})`, [custodyOrigin]);
      const custody = (await logs.listLogs()).find((l) => l.kind === 'custody')!;
      await raw.run(
        `INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, 0, ?, 'x', 'scheduler', ${NOW})`,
        [custody.logId, forged.integrity.canonicalDigest],
      );
      const events: Array<[string, Record<string, unknown>]> = [];
      const s = await scheduler({ onLog: (event, fields) => events.push([event, fields]) });
      offset += HOUR;
      const report = await pass(s);
      expect(report.epoch).toMatchObject({ members: 1 });
      expect(await anchors.getLastAnchoredCheckpoint(custody.logId)).toBeNull();
      expect(events.filter(([e]) => e === 'anchor_log_ignored').map(([, f]) => f)).toEqual([{ origin: custodyOrigin, kind: 'custody' }]);
      await settle(s);

      // A deployment that binds its custody leaves anchors them.
      await capture('alpha', 1);
      const both = await scheduler({ holderId: 'both', sourceLogKinds: ['evidence', 'custody'] });
      await s.stop();
      offset += HOUR;
      expect((await pass(both)).epoch).toMatchObject({ members: 2 });
      expect(await anchors.getLastAnchoredCheckpoint(custody.logId)).not.toBeNull();
    });

    it('refuses sourceLogKinds that are not log kinds, or that name the anchor log', async () => {
      for (const kinds of [[], ['Evidence'], ['anchors'], ['evidence', 'a b']]) {
        await expect(scheduler({ sourceLogKinds: kinds })).rejects.toBeInstanceOf(AnchoringConfigError);
      }
    });
  });

  describe('the publication history', () => {
    it("a finalized publication whose transaction a stranger signed stops the scheduler: anchor_history_mismatch", async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await epoch(s);
      const [pub] = await publications();
      const stranger = Wallet.createRandom();
      const forgedRaw = await stranger.signTransaction({
        type: 2, chainId: 31337n, nonce: pub.nonce as number, to: stranger.address, value: 0n, data: `0x${pub.p}`,
        gasLimit: 30_000n, maxFeePerGas: 3_000_000_000n, maxPriorityFeePerGas: 1_000_000n,
      });
      const attempts = [{ ...pub.attempts[0], rawTx: forgedRaw.toLowerCase(), txHash: keccak256(forgedRaw) }];
      await asOwner('UPDATE anchor_publications SET attempts = ?, mined_tx_hash = ?, from_address = ? WHERE id = ?', [
        JSON.stringify(attempts),
        keccak256(forgedRaw),
        stranger.address.toLowerCase(),
        pub.id,
      ]);
      await capture('alpha', 1);
      offset += HOUR;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_history_mismatch');
      expect(report.epoch).toBeNull();
    });

    it('forged finality, a block above the finalized tag with a fabricated header, defers the fill and the epoch, then pages', async () => {
      await capture('alpha', 2);
      const s = await scheduler({ tuning: { unverifiedEscalateMs: 2 * HOUR } });
      offset += HOUR;
      await pass(s);
      const [pub] = await publications();
      expect(pub.state).toBe('submitted');
      // The owner moves it to finalized, in a block that does not exist yet.
      const futureBlock = chain.head() + 1_000;
      const trie = buildTxTrie([pub.attempts[0].rawTx]);
      const header = buildHeader({ number: futureBlock, timestamp: 1_800_000_000, transactionsRoot: trie.root });
      await asOwner(
        `UPDATE anchor_publications SET state = 'finalized', mined_tx_hash = ?, block_number = ?, block_hash = ?, block_header = ?, tx_index = 0, tx_trie_proof = ? WHERE id = ?`,
        [pub.attempts[0].txHash, futureBlock, header.hash, header.rlp, JSON.stringify(trie.proof(0)), pub.id],
      );
      offset += HOUR;
      const first = await pass(s);
      expect(first.halted).toBe(false);
      expect(first.filled).toBe(0);
      expect(first.epoch).toBeNull();
      expect(first.alarms).toContainEqual(expect.objectContaining({ code: 'anchor_history_unverified', severity: 'warning', subject: String(pub.id) }));
      offset += 3 * HOUR;
      const later = await pass(s);
      expect(later.alarms).toContainEqual(expect.objectContaining({ code: 'anchor_history_unverified', severity: 'critical' }));
      expect(later.filled).toBe(0);
      const [record] = await logs.listLogLeaves((await logs.getEvidenceLog('alpha'))!.logId, 0, 1);
      expect((await adapter.retrieve(record.sourceRef))!.nonRepudiation.anchor).toBeUndefined();
    });

    it("an included publication whose sender's window closed before its block moves no published size", async () => {
      // The manifest names the publisher from a date after the fake chain's
      // block times and before now: its transactions sign, and are refused at
      // the block time the node confirms.
      const identity = await logs.getStoreIdentity();
      const anchorOrigin = `${identity.ns}/${identity.storeId}/anchors`;
      const publisherManifest = {
        publishers: { [anchorOrigin]: [{ address: wallet.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const, validFrom: '2026-09-25T00:00:00Z' }] },
      };
      await capture('alpha', 2);
      const s = await scheduler({ publisherManifest });
      offset += HOUR;
      await pass(s);
      chain.mine(1);
      await pass(s);
      expect((await publications())[0].state).toBe('included');
      await capture('alpha', 1);
      offset += HOUR;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_publication_unexplained');
      expect(report.epoch).toBeNull();
    });

    it("a key change: the last finalized publication's sender, named nowhere, stops the new key's scheduler", async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await epoch(s);
      await s.stop();
      const next = Wallet.createRandom() as unknown as Wallet;
      chain.fund(next.address, ETH);
      const rotated = await scheduler({ holderId: 'rotated' }, next);
      await capture('alpha', 1);
      offset += HOUR;
      const report = await pass(rotated);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_history_mismatch');
      expect(report.broadcasts).toEqual([]);
    });
  });

  describe('nonces and wallet transactions', () => {
    it('an accounted transaction that is not the transaction it claims to be stops the scheduler', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await epoch(s);
      await raw.run(
        `INSERT INTO anchor_wallet_txs (address, chain, nonce, tx_hash, kind, raw_tx, created_at) VALUES (?, ?, 5, ?, 'sweep', '0xc0', ${NOW})`,
        [wallet.address.toLowerCase(), CHAIN, `0x${hex('a sweep nobody signed')}`],
      ).catch(async () =>
        asOwner(`INSERT INTO anchor_wallet_txs (address, chain, nonce, tx_hash, kind, raw_tx, created_at) VALUES (?, ?, 5, ?, 'sweep', '0xc0', ?)`, [
          wallet.address.toLowerCase(),
          CHAIN,
          `0x${hex('a sweep nobody signed')}`,
          new Date().toISOString(),
        ]),
      );
      await capture('alpha', 1);
      offset += HOUR;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_wallet_tx_unexplained');
      expect(report.broadcasts).toEqual([]);
    });

    it('a broadcast outcome rewritten to rejected while the node still holds the transaction supersedes nothing', async () => {
      await capture('alpha', 2);
      const s = await scheduler({ tuning: { stuckAfterMs: 100 * HOUR } });
      offset += HOUR;
      await pass(s);
      const [pub] = await publications();
      // The base fee rises past the transaction's cap: it waits in the pool,
      // and the node refuses its rebroadcast, which records nothing.
      chain.baseFeePerGas = 5_000_000_000n;
      chain.mine(1);
      chain.refuse = () => 'txpool is full';
      await asOwner('UPDATE anchor_publications SET attempts = ? WHERE id = ?', [
        JSON.stringify(pub.attempts.map((a) => ({ ...a, broadcast: 'rejected' }))),
        pub.id,
      ]);
      await capture('alpha', 1);
      offset += HOUR;
      const report = await pass(s);
      expect(report.epoch).toBeNull();
      expect(report.deferred).toBe('publication_in_flight');
      const after = await publications();
      expect(after).toHaveLength(1);
      expect(after[0].state).toBe('submitted');
    });
  });

  describe('what the scheduler sends again (tzun-anchor/1 §7.2 rule 3, §11 item 6)', () => {
    /** A submitted publication whose transaction the node has dropped, so the next pass sends it again. */
    async function evictedSubmission(): Promise<{ s: AnchorScheduler; pub: AnchorPublication }> {
      await capture('alpha', 2);
      const s = await scheduler({ tuning: { stuckAfterMs: 100 * HOUR } });
      offset += HOUR;
      await pass(s);
      const [pub] = await publications();
      expect(pub.state).toBe('submitted');
      chain.evict(pub.attempts[0].txHash);
      return { s, pub };
    }
    const twinOf = (pub: AnchorPublication, make: (raw: string) => string, rule: EvmItemTwoRule): string => {
      const twin = make(pub.attempts[0].rawTx);
      expect(readEvmTransaction(twin)).toEqual({ ok: false, rule });
      expect(Transaction.from(twin).from).toBe(wallet.address);
      return twin;
    };

    it.each(TWINS)('a stored attempt replaced by %s is not the scheduler\'s: anchoring stops, and nothing is sent', async (_what, make, rule) => {
      const { s, pub } = await evictedSubmission();
      const twin = twinOf(pub, make, rule);
      await asOwner('UPDATE anchor_publications SET attempts = ? WHERE id = ?', [
        JSON.stringify([{ ...pub.attempts[0], rawTx: twin, txHash: keccak256(twin) }]),
        pub.id,
      ]);
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(report.alarms).toContainEqual(
        expect.objectContaining({ code: 'anchor_publication_unexplained', message: expect.stringMatching(new RegExp(`is not one the scheduler made: .*\\(${rule}\\)`)) }),
      );
      expect(chain.broadcasts.slice(sent)).toEqual([]);
    });

    it.each(TWINS)('%s, appended as a new attempt as the triggers allow, is not sent', async (_what, make, rule) => {
      const { s, pub } = await evictedSubmission();
      const twin = twinOf(pub, make, rule);
      await raw.run('UPDATE anchor_publications SET attempts = ? WHERE id = ?', [
        JSON.stringify([...pub.attempts, { ...pub.attempts[0], rawTx: twin, txHash: keccak256(twin), broadcast: 'unknown' }]),
        pub.id,
      ]);
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(report.alarms).toContainEqual(
        expect.objectContaining({ code: 'anchor_publication_unexplained', message: expect.stringMatching(new RegExp(`is not one the scheduler made: .*\\(${rule}\\)`)) }),
      );
      expect(chain.broadcasts.slice(sent)).toEqual([]);
    });

    /**
     * An included publication whose block a reorg drops, so that the next
     * pass moves its row back to submitted, reads the row again and sends its
     * attempt. While that pass runs, after the row was authenticated, the
     * attempt is replaced (around the triggers) by `make(pub)`, and the row's
     * nonce column by `nonce` when it is given: the pass's report and what it
     * broadcast.
     */
    async function rewrittenDuringPass(
      make: (pub: AnchorPublication) => Promise<string> | string,
      nonce: number | null = null,
    ): Promise<{ report: AnchorPassReport; sent: string[]; substitute: string }> {
      await capture('alpha', 2);
      const s = await scheduler({ tuning: { stuckAfterMs: 100 * HOUR } });
      offset += HOUR;
      await pass(s);
      chain.mine(1);
      await pass(s);
      const [pub] = await publications();
      expect(pub.state).toBe('included');
      chain.reorg(1);
      const substitute = (await make(pub)).toLowerCase();
      const receipt = chain.receipt.bind(chain);
      let rewritten = false;
      chain.receipt = async (hash) => {
        if (!rewritten) {
          rewritten = true;
          await asOwner('UPDATE anchor_publications SET attempts = ?, nonce = ? WHERE id = ?', [
            JSON.stringify([{ ...pub.attempts[0], rawTx: substitute, txHash: keccak256(substitute) }]),
            nonce ?? pub.nonce,
            pub.id,
          ]);
        }
        return receipt(hash);
      };
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      expect(rewritten).toBe(true);
      return { report, sent: chain.broadcasts.slice(sent), substitute };
    }
    /** The fields of `pub`'s attempt with `change` applied, signed by `signer`. */
    const resigned = (pub: AnchorPublication, signer: Wallet, change: TransactionLike = {}): Promise<string> => {
      const tx = Transaction.from(pub.attempts[0].rawTx);
      const { chainId, nonce, maxFeePerGas, maxPriorityFeePerGas, gasLimit, to, value, data } = tx;
      return signer.signTransaction({ type: 2, chainId, nonce, maxFeePerGas, maxPriorityFeePerGas, gasLimit, to, value, data, ...change });
    };
    /** `raw`, an EIP-1559 transaction, with its `yParity` flipped and nothing else: item 2 reads it, and another sender recovers. */
    const parityFlipped = (raw: string): string => {
      const yParity = (decodeRlp(`0x${raw.slice(4)}`) as string[])[9];
      return rewriteType2Field(raw, 9, yParity === '0x' ? '0x01' : '0x');
    };

    it('a stored attempt rewritten during the pass, after its row was authenticated, is read again before it is sent, and is not sent', async () => {
      const { report, sent } = await rewrittenDuringPass((pub) => twinOf(pub, TWINS[0][1], 'signature-values'));
      expect(report.halted).toBe(true);
      expect(report.alarms).toContainEqual(
        expect.objectContaining({ code: 'anchor_publication_unexplained', message: expect.stringContaining('is not sent: it breaks the Signature values rule') }),
      );
      expect(sent).toEqual([]);
    });

    it.each<[string, (pub: AnchorPublication) => Promise<string> | string, RegExp, number | null]>([
      ['the same fields signed by another key', (pub) => resigned(pub, Wallet.createRandom() as unknown as Wallet), /is not sent: it is signed by 0x[0-9a-f]{40}, not 0x[0-9a-f]{40}\./, null],
      ['its yParity flipped alone', (pub) => parityFlipped(pub.attempts[0].rawTx), /is not sent: it is signed by 0x[0-9a-f]{40}, not 0x[0-9a-f]{40}\./, null],
      ['the same fields signed by the publisher key for chain id 1', (pub) => resigned(pub, wallet, { chainId: 1n }), /is not sent: it is signed for chain id 1, not 31337\./, null],
      ['a transaction of the publisher key at another nonce', (pub) => resigned(pub, wallet, { nonce: 7 }), /is not sent: it is signed at nonce 7, not 0\./, null],
      // The row's nonce column rewritten with it: the nonce sent is the one authenticated, not the row's.
      ['a transaction of the publisher key at another nonce, the row\'s nonce with it', (pub) => resigned(pub, wallet, { nonce: 7 }), /is not sent: it is signed at nonce 7, not 0\./, 7],
      ['a transaction of the publisher key over other calldata', (pub) => resigned(pub, wallet, { data: `0x${hex('another P')}` }), /is not sent: its calldata is not 0x ‖ P\./, null],
    ])('a stored attempt rewritten during the pass to %s, which item 2 reads, is not sent', async (_what, make, why, nonce) => {
      const { report, sent, substitute } = await rewrittenDuringPass(make, nonce);
      const reading = readEvmTransaction(substitute);
      expect(reading.ok).toBe(true);
      expect(report.halted).toBe(true);
      expect(report.alarms).toContainEqual(expect.objectContaining({ code: 'anchor_publication_unexplained', message: expect.stringMatching(why) }));
      expect(sent).toEqual([]);
    });

    it.each(TWINS)('a stored sweep replaced by %s is not sent again', async (_what, make, rule) => {
      await capture('alpha', 2);
      const seen: string[] = [];
      const s = await scheduler({ onAlarm: (a) => seen.push(`${a.code}: ${a.message}`) });
      await epoch(s);
      const swept = await s.sweep(Wallet.createRandom().address);
      expect(swept.broadcast).toMatchObject({ outcome: 'accepted' });
      chain.evict(swept.tx.txHash);
      const twin = make(swept.tx.rawTx);
      expect(readEvmTransaction(twin)).toEqual({ ok: false, rule });
      expect(Transaction.from(twin).from).toBe(wallet.address);
      // The id a lenient reader gives it: ethers hashes RLP it has made
      // canonical, which is the original's id; a high s it refuses to hash.
      const id = rule === 'encoding' ? swept.tx.txHash : keccak256(twin);
      expect(() => assertWalletTx({ ...swept.tx, rawTx: twin, txHash: id })).toThrow(`rawTx breaks the ${rule} rule of tzun-anchor/1 §10.4 item 2`);
      await asOwner('UPDATE anchor_wallet_txs SET raw_tx = ?, tx_hash = ? WHERE address = ? AND chain = ? AND nonce = ?', [
        twin,
        id,
        swept.tx.address,
        CHAIN,
        swept.tx.nonce,
      ]);
      const sent = chain.broadcasts.length;
      await expect(s.rebroadcastAccountedTransaction()).rejects.toThrow(/anchor_wallet_tx_unexplained/);
      expect(chain.broadcasts.slice(sent)).toEqual([]);
      expect(seen).toContainEqual(expect.stringMatching(new RegExp(`^anchor_wallet_tx_unexplained: .*breaks the ${rule} rule of tzun-anchor/1 §10\\.4 item 2`)));
    });

    /** A sweep `signer` signed for `chainId`, as the row of `address` on `chain`. */
    async function sweepRow(signer: Wallet, chainId: bigint, address: string, rowChain: string): Promise<AnchorWalletTx> {
      const rawTx = (
        await signer.signTransaction({ type: 2, chainId, nonce: 5, maxFeePerGas: 10n ** 9n, maxPriorityFeePerGas: 10n ** 9n, gasLimit: 21_000n, to: signer.address, value: 0 })
      ).toLowerCase();
      return { address: address.toLowerCase(), chain: rowChain, nonce: 5, txHash: keccak256(rawTx), kind: 'sweep', rawTx, createdAt: new Date().toISOString() };
    }

    it.each<[string, () => Promise<AnchorWalletTx>, RegExp]>([
      [
        'a sweep of another address, signed by that address',
        () => {
          const other = Wallet.createRandom() as unknown as Wallet;
          return sweepRow(other, 31337n, other.address, CHAIN);
        },
        /is not sent: it is signed by 0x[0-9a-f]{40}, not 0x[0-9a-f]{40}\./,
      ],
      ['a sweep of the wallet on eip155:1, signed for chain id 1', () => sweepRow(wallet, 1n, wallet.address, 'eip155:1'), /is not sent: it is signed for chain id 1, not 31337\./],
    ])('an accounted transaction that a store passed to the scheduler lists, %s, is not sent, and anchoring stops', async (_what, row, why) => {
      await capture('alpha', 2);
      const first = await scheduler();
      await epoch(first);
      await first.stop();
      // The row is one `assertWalletTx` accepts: the signed transaction is the row's.
      const extra = await row();
      expect(() => assertWalletTx(extra)).not.toThrow();
      const listing = new Proxy(anchors, {
        get(t, prop, receiver) {
          const v = Reflect.get(t, prop, receiver);
          if (prop === 'listAnchorWalletTxs') return async (...args: Parameters<AnchorStore['listAnchorWalletTxs']>) => [...(await t.listAnchorWalletTxs(...args)), extra];
          return typeof v === 'function' ? v.bind(t) : v;
        },
      });
      const seen: string[] = [];
      const s = await scheduler({ holderId: 'listing', anchorStore: listing, logStore: logs, storage: undefined, onAlarm: (a) => seen.push(`${a.code}: ${a.message}`) });
      const sent = chain.broadcasts.length;
      await expect(s.rebroadcastAccountedTransaction()).rejects.toThrow(/anchor_wallet_tx_unexplained/);
      expect(chain.broadcasts.slice(sent)).toEqual([]);
      expect(seen).toContainEqual(expect.stringMatching(new RegExp(`^anchor_wallet_tx_unexplained: .*${why.source}`)));
      await capture('alpha', 1);
      offset += HOUR;
      expect(await pass(s)).toMatchObject({ halted: true, broadcasts: [] });
      expect(chain.broadcasts.slice(sent)).toEqual([]);
    });
  });

  describe('what a publisher passed to the scheduler returns (tzun-anchor/1 §7.2 rule 3)', () => {
    type Change<A extends unknown[]> = (signed: SignedTransaction, ...args: A) => Promise<SignedTransaction> | SignedTransaction;
    /**
     * The SDK's publisher over `wallet`, with what it returns replaced by
     * `publication` or `transfer` of it while `faulty.on`.
     */
    function returning(changes: {
      publication?: Change<[p: string, fields: EvmTransactionFields]>;
      transfer?: Change<[request: { to: string; value: bigint; data: string } & EvmTransactionFields]>;
    }): { publisher: EvmPublisher; faulty: { on: boolean } } {
      const base = createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain });
      const faulty = { on: true };
      const publisher: EvmPublisher = {
        address: base.address,
        chain: base.chain,
        chainId: base.chainId,
        client: base.client,
        async signPublication(p, fields) {
          const signed = await base.signPublication(p, fields);
          return faulty.on && changes.publication ? changes.publication(signed, p, fields) : signed;
        },
        async signTransfer(to, value, data, fields) {
          const signed = await base.signTransfer(to, value, data, fields);
          return faulty.on && changes.transfer ? changes.transfer(signed, { to, value, data, ...fields }) : signed;
        },
      };
      return { publisher, faulty };
    }
    const answer = (raw: string): SignedTransaction => ({ raw: raw.toLowerCase(), hash: keccak256(raw.toLowerCase()) });

    it.each<[string, Change<[p: string, fields: EvmTransactionFields]>, string, RegExp]>([
      ['a high s', (signed) => answer(toHighS(signed.raw)), 'signature-values', /breaks the Signature values rule of tzun-anchor\/1 §10\.4 item 2 \(signature-values: /],
      [
        "another key's publication",
        async (_signed, p, fields) => createEvmPublisher({ privateKey: Wallet.createRandom().privateKey, chain: CHAIN, client: chain }).signPublication(p, fields),
        'sender',
        /\(sender: it is signed by 0x[0-9a-f]{40}, not 0x[0-9a-f]{40}\)/,
      ],
      [
        "the publisher key's publication for chain id 1",
        async (_signed, p, fields) => createEvmPublisher({ privateKey: wallet.privateKey, chain: 'eip155:1', client: chain }).signPublication(p, fields),
        'chainId',
        /\(chainId: it is signed for chain id 1, not 31337\)/,
      ],
      [
        'an unprotected legacy publication (v 27 or 28), which signs no chain id',
        async (_signed, p, fields) =>
          answer(await wallet.signTransaction({ type: 0, chainId: 0, nonce: fields.nonce, gasPrice: fields.maxFeePerGas, gasLimit: fields.gasLimit, to: wallet.address, value: 0, data: `0x${p}` })),
        'chainId',
        /\(chainId: it is signed for chain id 0, not 31337\)/,
      ],
      [
        'the publication at another nonce',
        async (_signed, p, fields) => createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }).signPublication(p, { ...fields, nonce: fields.nonce + 1 }),
        'nonce',
        /\(nonce: it is signed at nonce 1, not 0\)/,
      ],
      [
        'another P',
        async (_signed, _p, fields) => createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }).signPublication(hex('another P'), fields),
        'data',
        /\(data: its calldata is not 0x ‖ P\)/,
      ],
      ['a hash that is not keccak-256 of its bytes', (signed) => ({ raw: signed.raw, hash: `0x${hex('another hash')}` }), 'transaction', /its txHash is not keccak256 of its raw transaction/],
      [
        'a value of 1 wei',
        async (signed, p, fields) => {
          const tx = Transaction.from(signed.raw);
          return answer(await wallet.signTransaction({ type: 2, chainId: 31337, nonce: fields.nonce, maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas, gasLimit: fields.gasLimit, to: wallet.address, value: 1, data: `0x${p}` }));
        },
        'transaction',
        /it carries value/,
      ],
      ['its hex in capitals', (signed) => ({ raw: `0x${signed.raw.slice(2).toUpperCase()}`, hash: signed.hash }), 'transaction', /its raw transaction is not 0x lowercase hex/],
    ])('a publication it returns with %s is neither stored nor sent, enrols no wallet, and the next pass sends a compliant one at the same nonce', async (_what, change, field, why) => {
      await capture('alpha', 2);
      const { publisher, faulty } = returning({ publication: change });
      const s = await scheduler({ publisher });
      offset += HOUR;
      await expect(pass(s)).rejects.toMatchObject({ code: 'anchor_signer_mismatch', field, message: expect.stringMatching(why) });
      expect(chain.broadcasts).toEqual([]);
      expect(await publications()).toEqual([expect.objectContaining({ state: 'prepared', attempts: [], nonce: null, fromAddress: null })]);
      expect(await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN)).toBeNull();
      expect((await s.getAnchorState()).alarms).toEqual([expect.objectContaining({ code: 'anchor_signer_mismatch', message: expect.stringMatching(why) })]);

      faulty.on = false;
      const report = await pass(s);
      expect(report.halted).toBe(false);
      expect(chain.broadcasts).toHaveLength(1);
      expect(Transaction.from(chain.broadcasts[0]).nonce).toBe(0);
      expect((await s.getAnchorState()).alarms).toEqual([]);
    });

    it.each<[string, Change<[request: { to: string; value: bigint; data: string } & EvmTransactionFields]>, string, RegExp]>([
      ['a high s', (signed) => answer(toHighS(signed.raw)), 'signature-values', /breaks the Signature values rule of tzun-anchor\/1 §10\.4 item 2 \(signature-values: /],
      [
        "another key's transfer",
        async (_signed, { to, value, data, nonce, maxFeePerGas, maxPriorityFeePerGas, gasLimit }) =>
          answer(await Wallet.createRandom().signTransaction({ type: 2, chainId: 31337, nonce, maxFeePerGas, maxPriorityFeePerGas, gasLimit, to, value, data })),
        'sender',
        /\(sender: it is signed by 0x[0-9a-f]{40}, not 0x[0-9a-f]{40}\)/,
      ],
      ['a hash that is not keccak-256 of its bytes', (signed) => ({ raw: signed.raw, hash: `0x${hex('another hash')}` }), 'transaction', /txHash is not keccak256\(rawTx\)/],
    ])('a sweep it returns with %s is neither stored nor sent, and enrols no wallet', async (_what, change, field, why) => {
      const { publisher, faulty } = returning({ transfer: change });
      const s = await scheduler({ publisher });
      const to = Wallet.createRandom().address;
      await expect(s.sweep(to)).rejects.toMatchObject({ code: 'anchor_signer_mismatch', field, message: expect.stringMatching(why) });
      expect(chain.broadcasts).toEqual([]);
      expect(await anchors.listAnchorWalletTxs(wallet.address.toLowerCase(), CHAIN)).toEqual([]);
      expect(await anchors.getAnchorWallet(wallet.address.toLowerCase(), CHAIN)).toBeNull();

      faulty.on = false;
      expect((await s.sweep(to)).broadcast).toMatchObject({ outcome: 'accepted' });
      expect(chain.broadcasts).toHaveLength(1);
    });
  });

  describe('the fill', () => {
    async function finalizedUnfilled(n: number): Promise<{ s: AnchorScheduler; ids: string[]; pub: AnchorPublication }> {
      const ids = await capture('alpha', n);
      let fail = true;
      const failing = new Proxy(anchors, {
        get(t, prop, receiver) {
          const v = Reflect.get(t, prop, receiver);
          if (prop === 'fillAnchorArtifacts') {
            return async (...args: unknown[]) => {
              if (fail) throw new Error('the process died during the fill');
              return (v as (...a: unknown[]) => unknown).apply(t, args);
            };
          }
          return typeof v === 'function' ? v.bind(t) : v;
        },
      });
      const first = await scheduler({ anchorStore: failing, logStore: logs, storage: undefined });
      offset += HOUR;
      await pass(first);
      chain.mine(chain.finalizedDepth + 1);
      await expect(pass(first)).rejects.toThrow('the process died during the fill');
      await first.stop();
      fail = false;
      const [pub] = await publications();
      expect(pub).toMatchObject({ state: 'finalized', fillProgress: null });
      const s = await scheduler({ holderId: 'restarted' });
      return { s, ids, pub };
    }
    const anchorOf = async (id: string): Promise<unknown> => (await adapter.retrieve(id))!.nonRepudiation.anchor;

    it('a stored done that no record bears out is not taken: the fill runs', async () => {
      const { s, ids, pub } = await finalizedUnfilled(4);
      await anchors.updateAnchorPublication(pub.id, { fillProgress: { from: 0, anchorLeaf: pub.anchorSize, leafIndex: null, filled: 4, total: 4, done: true } });
      const report = await pass(s);
      expect(report.filled).toBe(4);
      for (const id of ids) expect(await anchorOf(id)).toBeDefined();
    });

    it("a stored cursor past records that carry no anchor, and a stored from, are not taken: every record is filled once", async () => {
      const { s, ids, pub } = await finalizedUnfilled(6);
      await anchors.updateAnchorPublication(pub.id, { fillProgress: { from: 5, anchorLeaf: 0, leafIndex: 4, filled: 4, total: 6, done: false } });
      const report = await pass(s);
      expect(report.filled).toBe(6);
      for (const id of ids) expect(await anchorOf(id)).toBeDefined();
      expect((await s.getAnchorState()).fillBacklog).toBe(0);
    });

    it('a record whose digest field is not its leaf is skipped and reported, and the others are filled', async () => {
      const { s, ids } = await finalizedUnfilled(3);
      const rewritten = (await adapter.retrieve(ids[1]))!;
      rewritten.integrity = { ...rewritten.integrity, canonicalDigest: hex('a digest the leaf never held') };
      await asOwner('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?', [JSON.stringify(rewritten), ids[1]]);
      const report = await pass(s);
      expect(report.halted).toBe(false);
      expect(report.alarms).toContainEqual(expect.objectContaining({ code: 'anchor_fill_conflict', severity: 'critical' }));
      expect(await anchorOf(ids[1])).toBeUndefined();
      expect(await anchorOf(ids[0])).toBeDefined();
      expect(await anchorOf(ids[2])).toBeDefined();
    });

    it('a finalized range whose anchor leaf has no source checkpoint stops the fill before it writes', async () => {
      const { s, ids } = await finalizedUnfilled(2);
      const alpha = (await logs.getEvidenceLog('alpha'))!;
      await asOwner('DELETE FROM log_checkpoints WHERE log_id = ?', [alpha.logId]);
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_log_leaf_unexplained');
      for (const id of ids) expect(await anchorOf(id)).toBeUndefined();
    });
  });

  describe('what the scheduler keeps in memory, and what it reads again', () => {
    it("an idle pass recovers no sender again; a row rewritten after it was read fails the next read", async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await epoch(s);
      await capture('alpha', 2);
      await epoch(s);
      const recover = jest.spyOn(Transaction, 'from');
      try {
        await pass(s);
        // The history check decodes the last finalized transaction for the node; nothing else is decoded again.
        expect(recover.mock.calls.length).toBeLessThanOrEqual(2);
      } finally {
        recover.mockRestore();
      }
      const [first] = await publications();
      await asOwner('UPDATE anchor_publications SET nonce = ? WHERE id = ?', [(first.nonce as number) + 40, first.id]);
      await capture('alpha', 1);
      offset += HOUR;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_publication_unexplained');
    });
  });

  it('a store that published on another chain refuses a scheduler for this one', async () => {
    await capture('alpha', 2);
    await epoch(await scheduler());
    const hoodi = new FakeEvmChain(560048n);
    const other = Wallet.createRandom();
    await expect(
      createAnchorScheduler({
        storage: store.adapter,
        config: { publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: other.privateKey, chain: 'eip155:560048' } } },
        publisher: createEvmPublisher({ privateKey: other.privateKey, chain: 'eip155:560048', client: hoodi }),
        clock,
        expectation: {},
      }),
    ).rejects.toThrow(/has published on eip155:31337.*a new store/);
  });

  it('signs with at least the chain\'s minimum tip when the node suggests none', async () => {
    const mainnet = new FakeEvmChain(1n);
    mainnet.maxPriorityFeePerGas = 0n;
    mainnet.fund(wallet.address, ETH);
    await capture('alpha', 1);
    const s = await createAnchorScheduler({
      storage: store.adapter,
      config: { production: true, publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: wallet.privateKey, chain: 'eip155:1' } } },
      publisher: createEvmPublisher({ privateKey: wallet.privateKey, chain: 'eip155:1', client: mainnet }),
      clock,
      expectation: {},
    });
    schedulers.push(s);
    offset += HOUR;
    await s.runPass();
    const [pub] = await publications();
    expect(Transaction.from(pub.attempts[0].rawTx).maxPriorityFeePerGas).toBe(100_000_000n);

    const none = await createAnchorScheduler({
      storage: store.adapter,
      config: { production: true, publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: wallet.privateKey, chain: 'eip155:1' } } },
      publisher: createEvmPublisher({ privateKey: wallet.privateKey, chain: 'eip155:1', client: mainnet }),
      clock,
      expectation: {},
      minPriorityFeeGwei: 0,
      holderId: 'none',
    });
    schedulers.push(none);
    await expect(createAnchorScheduler({
      storage: store.adapter,
      config: { production: true, publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: wallet.privateKey, chain: 'eip155:1' } } },
      publisher: createEvmPublisher({ privateKey: wallet.privateKey, chain: 'eip155:1', client: mainnet }),
      clock,
      expectation: {},
      minPriorityFeeGwei: -1,
    })).rejects.toBeInstanceOf(AnchoringConfigError);
  });
});
