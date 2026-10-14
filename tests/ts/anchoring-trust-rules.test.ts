/**
 * Anchoring trust, rule by rule: each check the scheduler's trust rests on
 * has a case here that fails when that check alone is deleted.
 *
 * Each case starts from a store the scheduler made, changes one thing the
 * way the store's owner can (around the triggers, `asOwner`), and checks
 * that nothing is signed or filled, with the alarm and, for the anchor log,
 * the rule that names the failure. A case that only checks the alarm code
 * would pass when another rule further down catches the same row.
 */
import { createHash } from 'node:crypto';
import { Transaction, Wallet, keccak256 } from 'ethers';
import type { EvidenceEnvelope } from '@tzun/engine';
import {
  AnchorForceRateLimitedError,
  AnchoringConfigError,
  EvmBlockMaterialError,
  createAnchorScheduler,
  createEvmPublisher,
  type AnchorPassReport,
  type AnchorScheduler,
  type AnchorSchedulerOptions,
} from '../../src/anchoring';
import { AnchorLogTrust, AnchorTrustError } from '../../src/anchoring/explain';
import { fillPublication } from '../../src/anchoring/fill';
import { checkpointDigest, formatCheckpoint } from '../../src/attestation/checkpoint';
import { extendCompactRange } from '../../src/attestation/merkle';
import {
  anchorStoreFor,
  logStoreFor,
  type AnchorPublication,
  type AnchorStore,
  type LogCheckpoint,
  type LogRecord,
  type LogStore,
} from '../../src/storage/log-store';
import { makeEnvelope } from './storage-conformance/fixtures';
import { FakeEvmChain } from './helpers/anchoring-fake-chain';
import { buildHeader, buildTxTrie } from './helpers/evm-fixtures';
import { type LogBackend, type OpenedStore, type RawDb, logBackends } from './helpers/log-store-backends';

const HOUR = 60 * 60_000;
const ETH = 10n ** 18n;
const CHAIN = 'eip155:31337';
const NS = 'test.tzun.dev';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

type Adapter = {
  store(e: EvidenceEnvelope, chainId?: string): Promise<void>;
  retrieve(id: string): Promise<EvidenceEnvelope | null>;
};

describe.each(logBackends('anchoring_trust_rules').map((b) => [b.name, b] as const))('anchoring trust, rule by rule, on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(180_000);
  let opened: OpenedStore<unknown>[] = [];
  let store: OpenedStore<unknown>;
  let adapter: Adapter;
  let logs: LogStore;
  let anchors: AnchorStore;
  let raw: RawDb;
  let chain: FakeEvmChain;
  let wallet: Wallet;
  /** A second key the manifest names beside the publisher. */
  let second: Wallet;
  /** A key nothing names. */
  let stranger: Wallet;
  let offset = 0;
  let schedulers: AnchorScheduler[] = [];
  const clock = (): number => Date.now() + offset;
  const sqlite = backend.name === 'sqlite';

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
    second = Wallet.createRandom() as unknown as Wallet;
    stranger = Wallet.createRandom() as unknown as Wallet;
    chain.fund(wallet.address, ETH);
    offset = 0;
    schedulers = [];
  });
  afterEach(async () => {
    for (const s of schedulers) await s.stop().catch(() => undefined);
    for (const o of opened) await o.close();
  });
  afterAll(async () => backend.dispose());

  async function anchorOrigin(): Promise<string> {
    const identity = await logs.getStoreIdentity();
    return `${identity.ns}/${identity.storeId}/anchors`;
  }

  /** The manifest naming the publisher and `second` for this store's anchor origin. */
  async function bothKeys(): Promise<NonNullable<AnchorSchedulerOptions['publisherManifest']>> {
    const origin = await anchorOrigin();
    return {
      publishers: {
        [origin]: [
          { address: wallet.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const },
          { address: second.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const },
        ],
      },
    };
  }

  async function scheduler(extra: Partial<AnchorSchedulerOptions> = {}, signerWallet: Wallet = wallet, budget?: Record<string, number>): Promise<AnchorScheduler> {
    const s = await createAnchorScheduler({
      storage: store.adapter,
      config: {
        publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: signerWallet.privateKey, chain: CHAIN } },
        ...(budget && { budget: budget as never }),
      },
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
  const alarm = (r: AnchorPassReport, code: string) => r.alarms.find((a) => a.code === code);

  /** Change rows the way the store's owner can: around the triggers. */
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
  const json = (v: unknown): string => JSON.stringify(v);

  /** `raw` signed again by `signer`, with `patch` applied. */
  function resign(rawTx: string, patch: { chainId?: bigint; data?: string; value?: bigint }, signer: Wallet = wallet): string {
    const t = Transaction.from(rawTx);
    const u = Transaction.from({
      type: 2,
      chainId: patch.chainId ?? t.chainId,
      nonce: t.nonce,
      to: t.to,
      data: patch.data ?? t.data,
      value: patch.value ?? t.value,
      gasLimit: t.gasLimit,
      maxFeePerGas: t.maxFeePerGas,
      maxPriorityFeePerGas: t.maxPriorityFeePerGas,
    });
    u.signature = signer.signingKey.sign(u.unsignedHash);
    return u.serialized.toLowerCase();
  }

  /** The anchor log, the store's evidence logs, and their checkpoints. */
  async function anchorLog(): Promise<LogRecord> {
    return anchors.ensureStoreLog('anchors');
  }
  async function cp(log: LogRecord, size: number): Promise<LogCheckpoint> {
    return (await anchors.getLogCheckpoint(log.logId, size))!;
  }

  // ── The anchor log above B, explained on a cold start ───────────────────

  /**
   * Epoch 1 (alpha@2, beta@2; anchor size 2) published, final and filled;
   * then epoch 2 (alpha@4, beta@4: anchor leaves 2 and 3, anchor size 4)
   * persisted by an instance that dies before it signs. A new instance
   * re-derives it on the crash path before it signs anything.
   */
  async function unsignedEpoch(extra: Partial<AnchorSchedulerOptions> = {}): Promise<{ prepared: AnchorPublication; alpha: LogRecord; beta: LogRecord; anchors: LogRecord }> {
    await capture('alpha', 2);
    await capture('beta', 2);
    const first = await scheduler(extra);
    await epoch(first);
    await first.stop();
    await capture('alpha', 2);
    await capture('beta', 2);
    const dying = await scheduler({
      ...extra,
      holderId: 'dying',
      publisher: {
        ...createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }),
        signPublication: async () => {
          throw new Error('the process died before it signed');
        },
      },
    });
    await expect(dying.anchorNow({ force: true })).rejects.toThrow('the process died before it signed');
    await dying.stop();
    const prepared = (await publications()).find((p) => p.state === 'prepared')!;
    expect(prepared).toMatchObject({ anchorSize: 4, attempts: [] });
    return { prepared, alpha: (await logs.getEvidenceLog('alpha'))!, beta: (await logs.getEvidenceLog('beta'))!, anchors: await anchorLog() };
  }

  /** A new instance's pass, once the re-derived epoch is due. */
  async function restartedPass(extra: Partial<AnchorSchedulerOptions> = {}): Promise<AnchorPassReport> {
    const s = await scheduler({ holderId: 'restarted', ...extra });
    offset += HOUR;
    return pass(s);
  }

  /** Nothing was signed, the scheduler stopped on `code`, and its subject names `subject`. */
  function refused(report: AnchorPassReport, sent: number, code: string, subject: RegExp): void {
    expect(chain.broadcasts).toHaveLength(sent);
    expect(report.halted).toBe(true);
    expect(codes(report)).toContain(code);
    expect(alarm(report, code)!.subject).toMatch(subject);
  }

  describe('the anchor log above B, rule by rule, on the crash path', () => {
    it('control: the epoch as the dead instance persisted it is re-derived and signed', async () => {
      await unsignedEpoch();
      const report = await restartedPass();
      expect(report.halted).toBe(false);
      expect(report.broadcasts).toHaveLength(1);
    });

    it("rule b: a source checkpoint whose body names another root than the one its digest commits to", async () => {
      const { alpha } = await unsignedEpoch();
      const forged = hex('another root');
      await asOwner('UPDATE log_checkpoints SET body = ?, root = ? WHERE log_id = ? AND tree_size = 4', [formatCheckpoint(alpha.origin, 4, forged), forged, alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule b\)/);
    });

    it("rule b: a source checkpoint whose root column is not its body's root line", async () => {
      const { alpha } = await unsignedEpoch();
      await asOwner('UPDATE log_checkpoints SET root = ? WHERE log_id = ? AND tree_size = 4', [hex('another root'), alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule b\)/);
    });

    it("rule c: an anchor leaf whose source reference is not its checkpoint's origin and size", async () => {
      const { anchors: anchorLogRecord, alpha } = await unsignedEpoch();
      await asOwner('UPDATE log_leaves SET source_ref = ? WHERE log_id = ? AND leaf_index = 2', [`${alpha.origin}\n3`, anchorLogRecord.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule c\)/);
    });

    it('rule d: a leaf of a kind the scheduler no longer anchors (a removed kind, in flight)', async () => {
      const identity = await logs.getStoreIdentity();
      const custodyOrigin = `${identity.ns}/${identity.storeId}/custody`;
      const NOW = sqlite ? "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')" : 'now()';
      await raw.run(`INSERT INTO logs (origin, kind, chain_id, created_at) VALUES (?, 'custody', NULL, ${NOW})`, [custodyOrigin]);
      const custody = (await logs.listLogs()).find((l) => l.kind === 'custody')!;
      const kinds = { sourceLogKinds: ['evidence', 'custody'] };
      await capture('alpha', 2);
      const first = await scheduler(kinds);
      await epoch(first);
      await first.stop();
      await capture('alpha', 1);
      await raw.run(`INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, 0, ?, 'custody-0', 'scheduler', ${NOW})`, [custody.logId, hex('custody leaf')]);
      const dying = await scheduler({
        ...kinds,
        holderId: 'dying',
        publisher: {
          ...createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }),
          signPublication: async () => {
            throw new Error('the process died before it signed');
          },
        },
      });
      await expect(dying.anchorNow({ force: true })).rejects.toThrow('the process died before it signed');
      await dying.stop();
      // custody sorts before evidence: anchor leaf 1 is the custody checkpoint.
      expect((await anchors.listCheckpointsByAnchorLeaf(1, 2))[0].logId).toBe(custody.logId);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 1 \(rule d\)/);
    });

    it("rule d: a source log whose origin is another domain's", async () => {
      const { alpha } = await unsignedEpoch();
      const identity = await logs.getStoreIdentity();
      await asOwner('UPDATE logs SET origin = ? WHERE log_id = ?', [alpha.origin.replace(identity.storeId, 'f'.repeat(identity.storeId.length)), alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf \d \(rule d\)/);
    });

    it('rule e: a source checkpoint that names another predecessor size than the anchor log committed to', async () => {
      const { alpha } = await unsignedEpoch();
      await asOwner('UPDATE log_checkpoints SET prev_anchored_size = 1 WHERE log_id = ? AND tree_size = 4', [alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule e\)/);
    });

    it('rule e: a predecessor under B whose root and compact range are rewritten consistently', async () => {
      const { alpha } = await unsignedEpoch();
      const forged = hex('a root alpha never had');
      // Size 2 is one subtree: its compact range is its root.
      await asOwner('UPDATE log_checkpoints SET root = ?, compact_range = ? WHERE log_id = ? AND tree_size = 2', [forged, json([forged]), alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule e\)/);
    });

    it("rule e: a predecessor under B whose compact range alone no longer folds to its root", async () => {
      const { alpha } = await unsignedEpoch();
      await asOwner('UPDATE log_checkpoints SET compact_range = ? WHERE log_id = ? AND tree_size = 2', [json([hex('not the range')]), alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule e\)/);
    });

    it("rule f: a source checkpoint its log's leaves do not rebuild", async () => {
      const { alpha } = await unsignedEpoch();
      await asOwner('UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 3', [hex('a leaf alpha never logged'), alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule f\)/);
    });

    it('rule f: a source checkpoint whose compact range is not the one its leaves rebuild', async () => {
      const { alpha } = await unsignedEpoch();
      await asOwner('UPDATE log_checkpoints SET compact_range = ? WHERE log_id = ? AND tree_size = 4', [json([hex('not the range')]), alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule f\)/);
    });

    it('rule f: a source checkpoint whose consistency proof does not verify', async () => {
      const { alpha } = await unsignedEpoch();
      await asOwner('UPDATE log_checkpoints SET consistency_proof = ? WHERE log_id = ? AND tree_size = 4', [json([hex('not a proof')]), alpha.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule f\)/);
    });

    it('rule g: an epoch whose id does not follow the published one', async () => {
      const { alpha, beta, anchors: anchorLogRecord } = await unsignedEpoch();
      for (const log of [alpha, beta]) await asOwner('UPDATE log_checkpoints SET epoch_id = 1 WHERE log_id = ? AND tree_size = 4', [log.logId]);
      await asOwner('UPDATE log_checkpoints SET epoch_id = 1 WHERE log_id = ? AND tree_size = 4', [anchorLogRecord.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 2 \(rule g\)/);
    });

    it('rule g: an epoch whose leaves are not in bytewise origin order, its anchor checkpoint and P rebuilt to match', async () => {
      const { alpha, beta, anchors: anchorLogRecord, prepared } = await unsignedEpoch();
      const [l2, l3] = await logs.listLogLeaves(anchorLogRecord.logId, 2, 4);
      // Swap the two leaves (through a free value: digest and reference are each unique) and their checkpoints' positions.
      const free = [hex('a free digest'), 'a free reference'];
      await asOwner('UPDATE log_leaves SET leaf_digest = ?, source_ref = ? WHERE log_id = ? AND leaf_index = 2', [...free, anchorLogRecord.logId]);
      await asOwner('UPDATE log_leaves SET leaf_digest = ?, source_ref = ? WHERE log_id = ? AND leaf_index = 3', [l2.leafDigest, l2.sourceRef, anchorLogRecord.logId]);
      await asOwner('UPDATE log_leaves SET leaf_digest = ?, source_ref = ? WHERE log_id = ? AND leaf_index = 2', [l3.leafDigest, l3.sourceRef, anchorLogRecord.logId]);
      await asOwner('UPDATE log_checkpoints SET anchor_leaf_index = 2 WHERE log_id = ? AND tree_size = 4', [beta.logId]);
      await asOwner('UPDATE log_checkpoints SET anchor_leaf_index = 3 WHERE log_id = ? AND tree_size = 4', [alpha.logId]);
      // The anchor checkpoint and P, rebuilt over the swapped leaves.
      const base = await cp(anchorLogRecord, 2);
      const ext = extendCompactRange({ size: 2, hashes: base.compactRange }, [l3.leafDigest, l2.leafDigest]);
      const body = formatCheckpoint(await anchorOrigin(), 4, ext.root);
      await asOwner('UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ?, compact_range = ? WHERE log_id = ? AND tree_size = 4', [
        ext.root, body, checkpointDigest(body), json(ext.range.hashes), anchorLogRecord.logId,
      ]);
      await asOwner('UPDATE anchor_publications SET p = ? WHERE id = ?', [checkpointDigest(body), prepared.id]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor leaf 3 \(rule g\)/);
    });

    it('the anchor checkpoint at N names another epoch than the last explained one', async () => {
      const { anchors: anchorLogRecord } = await unsignedEpoch();
      await asOwner('UPDATE log_checkpoints SET epoch_id = 7 WHERE log_id = ? AND tree_size = 4', [anchorLogRecord.logId]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor checkpoint 4/);
    });

    it('the anchor checkpoint at N, and P with it, rewritten to a root its leaves do not rebuild', async () => {
      const { anchors: anchorLogRecord, prepared } = await unsignedEpoch();
      const forged = hex('a forged anchor root');
      const body = formatCheckpoint(await anchorOrigin(), 4, forged);
      await asOwner('UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ?, compact_range = ? WHERE log_id = ? AND tree_size = 4', [
        forged, body, checkpointDigest(body), json([forged]), anchorLogRecord.logId,
      ]);
      await asOwner('UPDATE anchor_publications SET p = ? WHERE id = ?', [checkpointDigest(body), prepared.id]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_log_leaf_unexplained', /anchor checkpoint 4/);
    });
  });

  describe('the crash path (the sign gate)', () => {
    it("a prepared row whose P is not the anchor checkpoint's the leaves rebuild is not signed", async () => {
      const { prepared } = await unsignedEpoch();
      await asOwner('UPDATE anchor_publications SET p = ? WHERE id = ?', [hex('a P nobody derived'), prepared.id]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_publication_unexplained', new RegExp(`^${prepared.id}$`));
    });

    it("a prepared row whose anchor size is not the anchor log's is not signed, though its P is", async () => {
      const { prepared } = await unsignedEpoch();
      await asOwner('UPDATE anchor_publications SET anchor_size = 3 WHERE id = ?', [prepared.id]);
      const sent = chain.broadcasts.length;
      refused(await restartedPass(), sent, 'anchor_publication_unexplained', new RegExp(`^${prepared.id}$`));
    });

    it('a prepared row with a nonce set is not signed (a prepared row has never been sent)', async () => {
      const { prepared } = await unsignedEpoch();
      await asOwner('UPDATE anchor_publications SET nonce = 5 WHERE id = ?', [prepared.id]);
      const sent = chain.broadcasts.length;
      const report = await restartedPass();
      refused(report, sent, 'anchor_publication_unexplained', new RegExp(`^${prepared.id}$`));
      expect(alarm(report, 'anchor_publication_unexplained')!.message).toMatch(/prepared publication has nonce set/);
    });

    it("an operator's force on a re-derived epoch the cadence does not call due is refused past the rolling limit", async () => {
      // A forced epoch, counted; then an epoch persisted by an instance that dies before it signs.
      await capture('alpha', 2);
      const first = await scheduler({}, wallet, { forcePerDay: 1 });
      await first.anchorNow({ force: true });
      await settle(first);
      await first.stop();
      await capture('alpha', 2);
      const dying = await scheduler({
        holderId: 'dying',
        publisher: {
          ...createEvmPublisher({ privateKey: wallet.privateKey, chain: CHAIN, client: chain }),
          signPublication: async () => {
            throw new Error('the process died before it signed');
          },
        },
      });
      await expect(dying.anchorNow({ force: true })).rejects.toThrow('the process died before it signed');
      await dying.stop();
      // Not due by the cadence (the last epoch is minutes old), and the force is used up:
      // by the signed forced epoch only, since a row nobody signed counts for nothing.
      const s = await scheduler({ holderId: 'restarted' }, wallet, { forcePerDay: 1 });
      expect((await publications()).map((p) => [p.state, p.forced])).toEqual([['finalized', true], ['prepared', true]]);
      expect((await s.getAnchorState()).force.usedInLast24h).toBe(1);
      const sent = chain.broadcasts.length;
      await expect(s.anchorNow({ force: true })).rejects.toBeInstanceOf(AnchorForceRateLimitedError);
      expect(chain.broadcasts).toHaveLength(sent);
      expect((await publications()).find((p) => p.state === 'prepared')).toBeDefined();
    });

    it('a planned epoch the store returns with another P is not signed (the first-signature gate)', async () => {
      await capture('alpha', 2);
      const forgedP = hex('a P the store returned');
      const lying = new Proxy(anchors, {
        get(t, prop, receiver) {
          const v = Reflect.get(t, prop, receiver);
          if (prop === 'persistEpoch') {
            return async (...args: unknown[]) => {
              const rows = (await (v as (...a: unknown[]) => Promise<AnchorPublication[]>).apply(t, args));
              return rows.map((r, i) => (i === 0 ? { ...r, p: forgedP } : r));
            };
          }
          return typeof v === 'function' ? v.bind(t) : v;
        },
      });
      const s = await scheduler({ anchorStore: lying, logStore: logs, storage: undefined });
      offset += HOUR;
      const report = await pass(s);
      expect(chain.broadcasts).toHaveLength(0);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_publication_unexplained');
    });
  });

  describe('a replacement signs the P it authenticated', () => {
    it('a P rewritten between the start of the pass and a replacement is never signed', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      // The first broadcast: the node errors and keeps nothing (outcome unknown).
      chain.errorNext = { error: new Error('socket hang up'), accept: false };
      offset += HOUR;
      await pass(s);
      const [pub] = await publications();
      expect(pub.state).toBe('submitted');
      expect(pub.attempts[0].broadcast).toBe('unknown');
      const forgedP = hex('a P the scheduler never derived');
      // The owner rewrites p while the next pass rebroadcasts, and the base fee rises past the attempt's cap.
      const realBroadcast = chain.broadcast.bind(chain);
      let armed = true;
      chain.broadcast = async (rawTx: string) => {
        const result = await realBroadcast(rawTx);
        if (armed) {
          armed = false;
          await asOwner('UPDATE anchor_publications SET p = ? WHERE id = ?', [forgedP, pub.id]);
          chain.baseFeePerGas = 10_000_000_000n;
        }
        return result;
      };
      offset += HOUR;
      const report = await pass(s);
      const signedForged = chain.broadcasts.map((r) => Transaction.from(r)).filter((t) => t.data.toLowerCase() === `0x${forgedP}`);
      expect(signedForged).toHaveLength(0);
      expect(report.halted).toBe(true);
      expect(codes(report)).toContain('anchor_publication_unexplained');
    });
  });

  // ── Publication rows ────────────────────────────────────────────────────

  /** Two epochs, each published, final and filled, by a scheduler that accepts the publisher and `second`. */
  async function twoFinalized(): Promise<{ s: AnchorScheduler; rows: AnchorPublication[] }> {
    await capture('alpha', 2);
    const s = await scheduler({ publisherManifest: await bothKeys() });
    await epoch(s);
    await capture('alpha', 2);
    await epoch(s);
    const rows = await publications();
    expect(rows.map((r) => r.state)).toEqual(['finalized', 'finalized']);
    return { s, rows };
  }

  /** A superseded publication (its one broadcast refused), then one that took its nonce, final and filled. */
  async function superseded(): Promise<{ s: AnchorScheduler; rows: AnchorPublication[] }> {
    await capture('alpha', 2);
    const s = await scheduler({ publisherManifest: await bothKeys(), tuning: { stuckAfterMs: 48 * HOUR } });
    offset += HOUR;
    let firstRaw: string | null = null;
    chain.refuse = (r) => {
      firstRaw ??= r;
      return r === firstRaw ? 'transaction pool is full' : null;
    };
    await pass(s);
    await pass(s);
    await capture('alpha', 1);
    offset += HOUR;
    await pass(s);
    chain.refuse = null;
    await settle(s);
    const rows = await publications();
    expect(rows.map((r) => r.state)).toEqual(['superseded', 'finalized']);
    return { s, rows };
  }

  type Forged = { attempts: unknown[]; minedTxHash: string | null; fromAddress: string | null };
  const resigned = (row: AnchorPublication, patch: Parameters<typeof resign>[1], signer: Wallet = wallet): Forged => {
    const rawTx = resign(row.attempts[0].rawTx, patch, signer);
    const txHash = keccak256(rawTx);
    return {
      attempts: [{ ...row.attempts[0], rawTx, txHash }, ...row.attempts.slice(1)],
      minedTxHash: row.minedTxHash === null ? null : txHash,
      fromAddress: row.fromAddress,
    };
  };
  const PUBLICATION_FORGERIES: Array<[string, RegExp, (row: AnchorPublication) => Forged]> = [
    ['a txHash that is not its raw transaction\'s', /txHash is not keccak256/, (row) => {
      const txHash = `0x${hex('another hash')}`;
      return { attempts: [{ ...row.attempts[0], txHash }, ...row.attempts.slice(1)], minedTxHash: row.minedTxHash === null ? null : txHash, fromAddress: row.fromAddress };
    }],
    ['a transaction signed for another chain', /signed for chain 31338/, (row) => resigned(row, { chainId: 31338n })],
    ['calldata that is not 0x ‖ P', /calldata is not/, (row) => resigned(row, { data: `0x${hex('another P')}` })],
    ['a transaction that carries value', /carries value/, (row) => resigned(row, { value: 1n })],
    ['a second attempt by another allowed key', /another sender than attempt 0's/, (row) => {
      const rawTx = resign(row.attempts[0].rawTx, {}, second);
      return { attempts: [...row.attempts, { ...row.attempts[0], rawTx, txHash: keccak256(rawTx) }], minedTxHash: row.minedTxHash, fromAddress: second.address.toLowerCase() };
    }],
    ['a sender column that is not the signer', /its sender column says/, (row) => ({ attempts: row.attempts, minedTxHash: row.minedTxHash, fromAddress: second.address.toLowerCase() })],
    ['a signer nobody names', /neither the configured publisher nor the manifest/, (row) => ({ ...resigned(row, {}, stranger), fromAddress: stranger.address.toLowerCase() })],
  ];

  describe('publication rows, field by field, on a finalized publication below the last', () => {
    it.each([
      ...PUBLICATION_FORGERIES,
      ['a mined hash that is none of its attempts', /mined transaction .* is none of its attempts/, (row: AnchorPublication): Forged => ({ attempts: row.attempts, minedTxHash: `0x${hex('mined elsewhere')}`, fromAddress: row.fromAddress })],
    ] as Array<[string, RegExp, (row: AnchorPublication) => Forged]>)('%s', async (_what, why, forge) => {
      const { s, rows } = await twoFinalized();
      const forged = forge(rows[0]);
      await asOwner('UPDATE anchor_publications SET attempts = ?, mined_tx_hash = ?, from_address = ? WHERE id = ?', [json(forged.attempts), forged.minedTxHash, forged.fromAddress, rows[0].id]);
      await capture('alpha', 1);
      const sent = chain.broadcasts.length;
      offset += HOUR;
      const report = await pass(s);
      refused(report, sent, 'anchor_publication_unexplained', new RegExp(`^${rows[0].id}$`));
      expect(alarm(report, 'anchor_publication_unexplained')!.message).toMatch(why);
    });
  });

  describe('publication rows, field by field, on a superseded publication', () => {
    it.each(PUBLICATION_FORGERIES.filter(([what]) => !/sender column/.test(what)))('%s', async (_what, why, forge) => {
      const { s, rows } = await superseded();
      const forged = forge(rows[0]);
      await asOwner('UPDATE anchor_publications SET attempts = ?, from_address = ? WHERE id = ?', [json(forged.attempts), forged.fromAddress, rows[0].id]);
      await capture('alpha', 1);
      const sent = chain.broadcasts.length;
      offset += HOUR;
      const report = await pass(s);
      refused(report, sent, 'anchor_publication_unexplained', new RegExp(`^${rows[0].id}$`));
      expect(alarm(report, 'anchor_publication_unexplained')!.message).toMatch(why);
    });
  });

  describe('validity windows', () => {
    it("a submitted publication whose sender's window has closed since it was sent stops the scheduler", async () => {
      const publisherManifest = {
        publishers: { [await anchorOrigin()]: [{ address: wallet.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const, validUntil: new Date(clock() + 3 * HOUR).toISOString() }] },
      };
      await capture('alpha', 2);
      const s = await scheduler({ publisherManifest });
      offset += HOUR;
      expect((await pass(s)).broadcasts).toHaveLength(1);
      offset += 4 * HOUR;
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      refused(report, sent, 'anchor_publication_unexplained', /^\d+$/);
      expect(alarm(report, 'anchor_publication_unexplained')!.message).toMatch(/outside its validity window now/);
    });

    it("a finalized publication below the last, sent before its sender's window opened, stops the scheduler", async () => {
      await capture('alpha', 2);
      const first = await scheduler();
      await epoch(first);
      await capture('alpha', 2);
      await epoch(first);
      await first.stop();
      const [one, two] = await publications();
      const blockTime = async (p: AnchorPublication): Promise<number> => (await chain.canonicalBlock(p.blockNumber as number))!.timestamp;
      expect(await blockTime(two)).toBeGreaterThan(await blockTime(one));
      const publisherManifest = {
        publishers: { [await anchorOrigin()]: [{ address: wallet.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const, validFrom: new Date(((await blockTime(one)) + 1) * 1000).toISOString() }] },
      };
      const s = await scheduler({ publisherManifest, holderId: 'windowed' });
      await capture('alpha', 1);
      offset += HOUR;
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      refused(report, sent, 'anchor_publication_unexplained', new RegExp(`^${one.id}$`));
      expect(alarm(report, 'anchor_publication_unexplained')!.message).toMatch(/outside its validity window at its block's time/);
    });
  });

  // ── Finality, confirmed by the node (valid === true) ────────────────────

  /** Epoch 1 final and filled; epoch 2 mined in a block that is not final yet: B's row is included. */
  async function includedAtB(): Promise<{ s: AnchorScheduler; rows: AnchorPublication[] }> {
    await capture('alpha', 2);
    const s = await scheduler();
    await epoch(s);
    await capture('alpha', 2);
    offset += HOUR;
    await pass(s);
    chain.mine(1);
    await pass(s);
    const rows = await publications();
    expect(rows.map((r) => r.state)).toEqual(['finalized', 'included']);
    return { s, rows };
  }

  describe("B's row, when it is included, counts only as the node confirms it", () => {
    it('the node does not call its block canonical: the epoch defers', async () => {
      const { s, rows } = await includedAtB();
      const real = chain.canonicalBlock.bind(chain);
      chain.canonicalBlock = async (n: number) => (n === rows[1].blockNumber ? null : real(n));
      await capture('alpha', 1);
      offset += HOUR;
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      expect(report.epoch).toBeNull();
      expect(report.halted).toBe(false);
      expect(report.deferred).toBe('history_unverified');
      expect(alarm(report, 'anchor_history_unverified')?.subject).toBe(String(rows[1].id));
      expect(chain.broadcasts).toHaveLength(sent);
    });

    it.each([
      ['has no receipt for it', (r: Awaited<ReturnType<FakeEvmChain['receipt']>>) => (r ? null : r)],
      // Another canonical block than the row's: the receipt's own block checks out, the row's does not.
      ['places it in another canonical block', (r: Awaited<ReturnType<FakeEvmChain['receipt']>>) => (r ? { ...r, blockNumber: r.blockNumber - 1, blockHash: chain.blocks[r.blockNumber - 1].hash } : r)],
    ])('the node %s once the pass has confirmed what is in flight: the epoch defers', async (_what, change) => {
      const { s, rows } = await includedAtB();
      const realReceipt = chain.receipt.bind(chain);
      const realFinalized = chain.finalizedBlockNumber.bind(chain);
      // Armed once the in-flight confirmation has read the finalized height, so
      // only the published size's own check sees the changed answer.
      let armed = false;
      chain.finalizedBlockNumber = async () => {
        armed = true;
        return realFinalized();
      };
      chain.receipt = async (h: string) => {
        const r = await realReceipt(h);
        return armed && h === rows[1].minedTxHash ? change(r) : r;
      };
      await capture('alpha', 1);
      offset += HOUR;
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      expect(report.epoch).toBeNull();
      expect(report.halted).toBe(false);
      expect(report.deferred).toBe('history_unverified');
      expect(chain.broadcasts).toHaveLength(sent);
    });

    it('a source checkpoint above B rewritten after the walk that explained it is not grown from', async () => {
      const { anchors: anchorLogRecord, alpha } = await unsignedEpoch();
      const [one] = await publications();
      const trust = new AnchorLogTrust({
        logs,
        anchors,
        anchorLogId: anchorLogRecord.logId,
        anchorOrigin: await anchorOrigin(),
        sourceLogKinds: ['evidence'],
        expectedOrigin: (l) => l.origin,
      });
      // The walk from B = 2 explains alpha@4 (anchor leaf 2); then the owner rewrites its root and range consistently.
      const range = await trust.explain(await trust.base(one.anchorSize, one.p));
      expect((await trust.lastAnchored(alpha, range))?.treeSize).toBe(4);
      const forged = hex('a root alpha never had');
      await asOwner('UPDATE log_checkpoints SET root = ?, compact_range = ? WHERE log_id = ? AND tree_size = 4', [forged, json([forged]), alpha.logId]);
      const err = await trust.lastAnchored(alpha, range).catch((e: Error) => e);
      expect(err).toBeInstanceOf(AnchorTrustError);
      expect((err as Error).message).toMatch(/not the one the anchor log explains at leaf 2/);
    });

    /** The walker over the store's anchor log, as the scheduler builds it. */
    async function walker(over: AnchorStore = anchors): Promise<AnchorLogTrust> {
      return new AnchorLogTrust({
        logs,
        anchors: over,
        anchorLogId: (await anchorLog()).logId,
        anchorOrigin: await anchorOrigin(),
        sourceLogKinds: ['evidence'],
        expectedOrigin: (l) => l.origin,
      });
    }

    it('a predecessor under B that the store stops naming after the anchor log was indexed stops the walk (rule e)', async () => {
      const { alpha } = await unsignedEpoch();
      const [one] = await publications();
      const trust = await walker();
      const base = await trust.base(one.anchorSize, one.p);
      await trust.explain(base);
      // The owner unlinks alpha@2 (anchor leaf 0) from the anchor log; a walk the scheduler has not made yet reads the store again.
      await asOwner('UPDATE log_checkpoints SET anchor_leaf_index = NULL, epoch_id = NULL WHERE log_id = ? AND tree_size = 2', [alpha.logId]);
      const err = await trust.explain(base, 3).catch((e: Error) => e);
      expect(err).toBeInstanceOf(AnchorTrustError);
      expect((err as AnchorTrustError).subject).toBe('anchor leaf 2 (rule e)');
    });

    it("a predecessor explained earlier in the same walk that the store answers differently for stops the walk (rule e)", async () => {
      const { alpha } = await unsignedEpoch();
      const forged = hex('a root alpha never had');
      // The store's answer for alpha's last anchored checkpoint changes while the walk reads it.
      const changing = new Proxy(anchors, {
        get(t, prop, receiver) {
          const v = Reflect.get(t, prop, receiver);
          if (prop === 'getLastAnchoredCheckpointBelow') {
            return async (logId: number, below: number) => {
              const row = await (v as AnchorStore['getLastAnchoredCheckpointBelow']).call(t, logId, below);
              return row && logId === alpha.logId ? { ...row, root: forged, compactRange: [forged] } : row;
            };
          }
          return typeof v === 'function' ? v.bind(t) : v;
        },
      });
      const trust = await walker(changing);
      // From the empty log: alpha@2 (leaf 0) is explained in this walk before alpha@4 (leaf 2) builds on it.
      const err = await trust.explain(await trust.base(0, null), 4).catch((e: Error) => e);
      expect(err).toBeInstanceOf(AnchorTrustError);
      expect((err as AnchorTrustError).subject).toBe('anchor leaf 2 (rule e)');
    });

    it("B's anchor checkpoint rewritten consistently to another root is refused by its P", async () => {
      const { s, rows } = await includedAtB();
      const anchorLogRecord = await anchorLog();
      const forged = hex('another anchor root');
      const body = formatCheckpoint(await anchorOrigin(), rows[1].anchorSize, forged);
      await asOwner('UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ?, compact_range = ? WHERE log_id = ? AND tree_size = ?', [
        forged, body, checkpointDigest(body), json([forged]), anchorLogRecord.logId, rows[1].anchorSize,
      ]);
      await capture('alpha', 1);
      offset += HOUR;
      const sent = chain.broadcasts.length;
      refused(await pass(s), sent, 'anchor_publication_unexplained', new RegExp(`^${rows[1].id}$`));
    });

    it("B's anchor checkpoint with a compact range that does not fold to its root is refused", async () => {
      const { s, rows } = await includedAtB();
      const anchorLogRecord = await anchorLog();
      await asOwner('UPDATE log_checkpoints SET compact_range = ? WHERE log_id = ? AND tree_size = ?', [json([hex('not the range')]), anchorLogRecord.logId, rows[1].anchorSize]);
      await capture('alpha', 1);
      offset += HOUR;
      const sent = chain.broadcasts.length;
      const report = await pass(s).catch((e: Error) => e);
      expect(chain.broadcasts).toHaveLength(sent);
      refused(report as AnchorPassReport, sent, 'anchor_publication_unexplained', new RegExp(`^${rows[1].id}$`));
    });
  });

  describe('a fill waits for the node (valid === true)', () => {
    /** Two final publications, the first one's fill progress cleared, and its finality material rewritten. */
    async function forgedFinality(height: 'future' | 'finalized'): Promise<{ s: AnchorScheduler; rows: AnchorPublication[]; fills: number[] }> {
      await capture('alpha', 2);
      const fills: number[] = [];
      const s = await scheduler({ onLog: (event, fields) => event === 'anchor_fill' && fills.push(fields.publicationId as number) });
      await epoch(s);
      await capture('alpha', 2);
      await epoch(s);
      const rows = await publications();
      const blockNumber = height === 'future' ? chain.head() + 1_000 : (rows[0].blockNumber as number);
      const trie = buildTxTrie([rows[0].attempts[0].rawTx]);
      const header = buildHeader({ number: blockNumber, timestamp: 1_790_000_100, transactionsRoot: trie.root });
      await asOwner(
        'UPDATE anchor_publications SET block_number = ?, block_hash = ?, block_header = ?, tx_index = 0, tx_trie_proof = ?, fill_progress = NULL WHERE id = ?',
        [blockNumber, header.hash, header.rlp, json(trie.proof(0)), rows[0].id],
      );
      fills.length = 0;
      return { s, rows, fills };
    }

    it('a publication below the last whose block the node has not finalized is not filled', async () => {
      const { s, rows, fills } = await forgedFinality('future');
      const report = await pass(s);
      expect(fills).not.toContain(rows[0].id);
      expect(report.halted).toBe(false);
      expect(alarm(report, 'anchor_history_unverified')?.subject).toBe(String(rows[0].id));
    });

    it('a publication below the last in a block the node does not have stops the scheduler unfilled', async () => {
      const { s, rows, fills } = await forgedFinality('finalized');
      const report = await pass(s);
      expect(fills).not.toContain(rows[0].id);
      expect(report.halted).toBe(true);
      expect(alarm(report, 'anchor_publication_unexplained')?.subject).toBe(String(rows[0].id));
    });
  });

  describe('the history check', () => {
    it("a finalized publication below its wallet's nonce base stops the scheduler", async () => {
      await capture('alpha', 2);
      const first = await scheduler();
      await epoch(first);
      await first.stop();
      await asOwner('UPDATE anchor_wallets SET nonce_base = 50 WHERE address = ?', [wallet.address.toLowerCase()]);
      const s = await scheduler({ holderId: 'later' });
      await capture('alpha', 1);
      offset += HOUR;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(alarm(report, 'anchor_history_mismatch')?.message).toMatch(/below its wallet's enrolment at 50/);
    });
  });

  // ── The predecessor the anchor log committed to ─────────────────────────

  describe("a source log's last anchored checkpoint is the one the anchor log committed to", () => {
    it('the owner hides an anchored checkpoint and rewrites leaves below it: nothing is signed over it', async () => {
      const ids = await capture('alpha', 3);
      const s = await scheduler();
      await epoch(s);
      const alpha = (await logs.getEvidenceLog('alpha'))!;
      expect((await anchors.getLastAnchoredCheckpoint(alpha.logId))?.treeSize).toBe(3);
      await capture('alpha', 2);
      const forged = makeEnvelope({ evidenceId: ids[1], sequenceNumber: 2 });
      const forgedDigest = hex('forged record digest');
      forged.integrity = { ...forged.integrity, canonicalDigest: forgedDigest };
      await asOwner('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?', [json(forged), ids[1]]);
      await asOwner('UPDATE log_leaves SET leaf_digest = ? WHERE log_id = ? AND leaf_index = 1', [forgedDigest, alpha.logId]);
      await asOwner('UPDATE log_checkpoints SET anchor_leaf_index = NULL, epoch_id = NULL WHERE log_id = ?', [alpha.logId]);
      for (const scheduled of [s, await scheduler({ holderId: 'fresh' })]) {
        if (scheduled !== s) await s.stop();
        offset += HOUR;
        const report = await pass(scheduled);
        expect(report.halted).toBe(true);
        expect(codes(report)).toContain('anchor_log_leaf_unexplained');
      }
      expect((await publications()).filter((p) => p.anchorSize > 1)).toEqual([]);
    });

    /** A warm scheduler with two epochs of alpha behind it, B = 2, its walk of the anchor log in memory. */
    async function warm(): Promise<{ s: AnchorScheduler; alpha: LogRecord; events: Array<[string, Record<string, unknown>]> }> {
      const events: Array<[string, Record<string, unknown>]> = [];
      await capture('alpha', 2);
      const s = await scheduler({ onLog: (event, fields) => events.push([event, fields]) });
      await epoch(s);
      await capture('alpha', 2);
      await epoch(s);
      await capture('alpha', 2);
      return { s, alpha: (await logs.getEvidenceLog('alpha'))!, events };
    }

    it("a predecessor under B rewritten consistently after the scheduler read the anchor log is not grown from", async () => {
      const { s, alpha } = await warm();
      // alpha@4, anchored at leaf 1, below B = 2.
      const forged = hex('a root alpha never had');
      await asOwner('UPDATE log_checkpoints SET root = ?, compact_range = ? WHERE log_id = ? AND tree_size = 4', [forged, json([forged]), alpha.logId]);
      offset += HOUR;
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      expect(chain.broadcasts).toHaveLength(sent);
      expect(report.epoch).toBeNull();
      expect(alarm(report, 'log_inconsistent_with_anchor')?.message).toMatch(/is not its log's checkpoint at its size with its root/);
    });

    it('a predecessor under B whose compact range no longer folds to its root is not grown from', async () => {
      const { s, alpha } = await warm();
      await asOwner('UPDATE log_checkpoints SET compact_range = ? WHERE log_id = ? AND tree_size = 4', [json([hex('not the range')]), alpha.logId]);
      offset += HOUR;
      const sent = chain.broadcasts.length;
      const report = await pass(s);
      expect(chain.broadcasts).toHaveLength(sent);
      expect(alarm(report, 'log_inconsistent_with_anchor')?.message).toMatch(/compact range does not fold to its root/);
    });

    it('a predecessor under B whose body is rewritten after the anchor log was indexed is not grown from', async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await epoch(s);
      await capture('alpha', 2);
      await epoch(s);
      const [, two] = await publications();
      const alpha = (await logs.getEvidenceLog('alpha'))!;
      const anchorLogRecord = await anchorLog();
      const trust = new AnchorLogTrust({
        logs,
        anchors,
        anchorLogId: anchorLogRecord.logId,
        anchorOrigin: await anchorOrigin(),
        sourceLogKinds: ['evidence'],
        expectedOrigin: (l) => l.origin,
      });
      // The walk from B = 2 indexes the anchor leaves below it; then the owner rewrites alpha@4 (anchor leaf 1).
      const range = await trust.explain(await trust.base(two.anchorSize, two.p));
      expect((await trust.lastAnchored(alpha, range))?.treeSize).toBe(4);
      const forged = hex('a root alpha never had');
      const body = formatCheckpoint(alpha.origin, 4, forged);
      await asOwner('UPDATE log_checkpoints SET root = ?, body = ?, body_digest = ?, compact_range = ? WHERE log_id = ? AND tree_size = 4', [
        forged, body, checkpointDigest(body), json([forged]), alpha.logId,
      ]);
      const err = await trust.lastAnchored(alpha, range).catch((e: Error) => e);
      expect(err).toBeInstanceOf(AnchorTrustError);
      expect((err as Error).message).toMatch(/does not hash to anchor leaf 1/);
      // A cold walk refuses it at the index: no checkpoint's body is that leaf.
      offset += HOUR;
      await capture('alpha', 1);
      const fresh = await scheduler({ holderId: 'fresh' });
      await s.stop();
      const report = await pass(fresh);
      expect(report.halted).toBe(true);
      expect(alarm(report, 'anchor_log_leaf_unexplained')?.subject).toBe('anchor leaf 1 (rule a)');
    });
  });

  // ── The fill ────────────────────────────────────────────────────────────

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
      return { s: await scheduler({ holderId: 'restarted' }), ids, pub };
    }
    const anchorOf = async (id: string): Promise<unknown> => (await adapter.retrieve(id))!.nonRepudiation.anchor;

    it.each([
      ['of another chain', async (id: string) => asOwner("UPDATE envelopes SET chain_id = 'another-chain' WHERE evidence_id = ?", [id])],
      ['at another position', async (id: string) => {
        const e = (await adapter.retrieve(id))!;
        (e.payload as { sequenceNumber: number }).sequenceNumber = 99;
        await asOwner('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?', [json(e), id]);
      }],
    ])('a record %s than its leaf is skipped and reported, and the others are filled', async (_what, change) => {
      const { s, ids } = await finalizedUnfilled(3);
      await change(ids[1]);
      const report = await pass(s);
      expect(report.halted).toBe(false);
      expect(alarm(report, 'anchor_fill_conflict')?.message).toContain(ids[1]);
      expect(await anchorOf(ids[1])).toBeUndefined();
      expect(await anchorOf(ids[0])).toBeDefined();
      expect(await anchorOf(ids[2])).toBeDefined();
    });

    it("fillPublication refuses a publication whose P is not the anchor checkpoint its range rebuilds, and writes nothing", async () => {
      const { ids, pub } = await finalizedUnfilled(2);
      const anchorLogRecord = await anchorLog();
      const trust = new AnchorLogTrust({
        logs,
        anchors,
        anchorLogId: anchorLogRecord.logId,
        anchorOrigin: await anchorOrigin(),
        sourceLogKinds: ['evidence'],
        expectedOrigin: (l) => l.origin,
      });
      const ctx = { logs, anchors, anchorLogId: anchorLogRecord.logId, expectation: {}, chunkSize: 500, trust };
      const err = await fillPublication(ctx, { ...pub, p: hex('another P') }, { previous: null, sender: wallet.address.toLowerCase() }).catch((e: Error) => e);
      expect(err).toBeInstanceOf(AnchorTrustError);
      expect((err as AnchorTrustError).code).toBe('anchor_publication_unexplained');
      for (const id of ids) expect(await anchorOf(id)).toBeUndefined();
    });

    it('a sweep is refused while a finalized publication carries a stored done that no record bears out', async () => {
      const { s, pub } = await finalizedUnfilled(2);
      await anchors.updateAnchorPublication(pub.id, { fillProgress: { from: 0, anchorLeaf: pub.anchorSize, leafIndex: null, filled: 2, total: 2, done: true } });
      await expect(s.sweep(stranger.address)).rejects.toThrow(/finalized but not filled/);
      expect(chain.broadcasts).toHaveLength(1);
    });
  });

  // ── Times the scheduler reads ───────────────────────────────────────────

  describe('times in the future do not authenticate', () => {
    it("a publication's created_at in the future stops the scheduler instead of stopping epochs", async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      await epoch(s);
      const [pub] = await publications();
      await asOwner('UPDATE anchor_publications SET created_at = ? WHERE id = ?', [sqlite ? '2099-01-01T00:00:00.000Z' : '2099-01-01T00:00:00Z', pub.id]);
      await capture('alpha', 2);
      offset += HOUR;
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(report.alarms.map((a) => a.message).join(' ')).toMatch(/created_at .* is not a time at or before now/);
    });

    it("an attempt's sentAt in the future stops the scheduler instead of holding off a replacement", async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      offset += HOUR;
      await pass(s);
      const [pub] = await publications();
      await asOwner('UPDATE anchor_publications SET attempts = ? WHERE id = ?', [json([{ ...pub.attempts[0], sentAt: '2099-01-01T00:00:00.000Z' }]), pub.id]);
      const report = await pass(s);
      expect(report.halted).toBe(true);
      expect(alarm(report, 'anchor_publication_unexplained')?.message).toMatch(/sentAt .* is not a time at or before now/);
    });

    it("a replacement bumps the fees the stuck attempt was signed with, not its stored fee columns", async () => {
      await capture('alpha', 2);
      const s = await scheduler();
      offset += HOUR;
      await pass(s);
      const [pub] = await publications();
      const signed = Transaction.from(pub.attempts[0].rawTx);
      await asOwner('UPDATE anchor_publications SET attempts = ? WHERE id = ?', [json([{ ...pub.attempts[0], maxFeePerGas: '1', maxPriorityFeePerGas: '1' }]), pub.id]);
      chain.baseFeePerGas = (signed.maxFeePerGas as bigint) + 1n;
      offset += HOUR;
      await pass(s);
      const [after] = await publications();
      expect(after.attempts).toHaveLength(2);
      const replacement = Transaction.from(after.attempts[1].rawTx);
      expect(replacement.maxFeePerGas! * 1000n).toBeGreaterThanOrEqual(signed.maxFeePerGas! * 1100n);
      expect(replacement.maxPriorityFeePerGas! * 1000n).toBeGreaterThanOrEqual(signed.maxPriorityFeePerGas! * 1100n);
    });
  });

  // ── The configured publisher's own window ───────────────────────────────

  describe("the configured publisher's window", () => {
    it('a manifest that has closed every window of the configured publisher refuses the scheduler', async () => {
      const publisherManifest = {
        publishers: { [await anchorOrigin()]: [{ address: wallet.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const, validUntil: '2020-01-01T00:00:00Z' }] },
      };
      await capture('alpha', 2);
      await expect(scheduler({ publisherManifest })).rejects.toThrow(AnchoringConfigError);
      await expect(scheduler({ publisherManifest })).rejects.toThrow(/every validity window closed/);
    });

    it('a window that closes after the scheduler starts: nothing is signed, the pass defers and pages', async () => {
      const publisherManifest = {
        publishers: { [await anchorOrigin()]: [{ address: wallet.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const, validUntil: new Date(clock() + 30 * 60_000).toISOString() }] },
      };
      await capture('alpha', 2);
      const s = await scheduler({ publisherManifest });
      offset += HOUR;
      const report = await pass(s);
      expect(chain.broadcasts).toHaveLength(0);
      expect(report.halted).toBe(false);
      expect(report.deferred).toBe('publisher_outside_window');
      expect(alarm(report, 'anchor_publisher_outside_window')).toMatchObject({ severity: 'critical' });
      expect(await publications()).toEqual([]);
    });

    it('a window that opens later: nothing is signed until it does', async () => {
      const publisherManifest = {
        publishers: { [await anchorOrigin()]: [{ address: wallet.address.toLowerCase(), chain: CHAIN, namespace: 'test' as const, validFrom: new Date(clock() + 3 * HOUR).toISOString() }] },
      };
      await capture('alpha', 2);
      const s = await scheduler({ publisherManifest });
      offset += HOUR;
      expect((await pass(s)).deferred).toBe('publisher_outside_window');
      offset += 3 * HOUR;
      expect((await pass(s)).broadcasts).toHaveLength(1);
      expect((await s.getAnchorState()).alarms.map((a) => a.code)).not.toContain('anchor_publisher_outside_window');
    });
  });

  // ── Block material and the tip floor ────────────────────────────────────

  it("a final block whose material cannot be read pages (anchor_block_material_unreadable)", async () => {
    await capture('alpha', 2);
    const s = await scheduler();
    offset += HOUR;
    await pass(s);
    chain.blockMaterial = async () => {
      throw new EvmBlockMaterialError('block 3\'s header does not rebuild to its hash, so its material is not stored');
    };
    chain.mine(chain.finalizedDepth + 1);
    await expect(pass(s)).rejects.toThrow(EvmBlockMaterialError);
    const state = await s.getAnchorState();
    expect(state.alarms).toContainEqual(expect.objectContaining({ code: 'anchor_block_material_unreadable', severity: 'critical' }));
    expect(state.halted).toBeNull();
  });

  it('a minimum priority fee at or above the hard cap is refused; one above the soft maximum is logged', async () => {
    await expect(scheduler({ minPriorityFeeGwei: 50 })).rejects.toThrow(/at or above anchoring\.budget\.hardFeeCapGwei/);
    const events: string[] = [];
    await scheduler({ minPriorityFeeGwei: 25, onLog: (event) => events.push(event) });
    expect(events).toContain('anchor_priority_fee_floor_above_soft_max');
  });

  it("with minPriorityFeeGwei: 0 on mainnet, the node's tip is signed as it is", async () => {
    const mainnet = new FakeEvmChain(1n);
    mainnet.maxPriorityFeePerGas = 7n;
    mainnet.fund(wallet.address, ETH);
    await capture('alpha', 1);
    const s = await createAnchorScheduler({
      storage: store.adapter,
      config: { production: true, publishers: { evm: { rpcUrl: 'http://127.0.0.1:9', privateKey: wallet.privateKey, chain: 'eip155:1' } } },
      publisher: createEvmPublisher({ privateKey: wallet.privateKey, chain: 'eip155:1', client: mainnet }),
      clock,
      expectation: {},
      minPriorityFeeGwei: 0,
    });
    schedulers.push(s);
    offset += HOUR;
    await s.runPass();
    const [pub] = await publications();
    expect(Transaction.from(pub.attempts[0].rawTx).maxPriorityFeePerGas).toBe(7n);
  });
});
