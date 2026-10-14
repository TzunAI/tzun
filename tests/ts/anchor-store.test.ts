/**
 * The anchoring tables the anchor scheduler writes: per-store logs,
 * `log_checkpoints` and `anchor_publications` (the checkpoints of Anchor §4
 * and the publications of Anchor §7), on SQLite and, when its legs run,
 * Postgres.
 *
 * Publication state moves forward only, held by a trigger.
 * The transition matrix below tries every state change from every state and
 * expects the tables to accept exactly the ones ANCHOR_PUBLICATION_TRANSITIONS
 * lists, so the table in code and the triggers in SQL cannot drift apart.
 */
import { createHash } from 'node:crypto';
import {
  ANCHOR_PUBLICATION_STATES_BY_KIND,
  ANCHOR_PUBLICATION_TRANSITIONS,
  AnchorPublication,
  AnchorPublicationPatch,
  AnchorPublicationState,
  AnchorStore,
  LogStore,
  NewLogCheckpoint,
  anchorStoreFor,
  isAllowedPublicationTransition,
  logStoreFor,
  storeLogOrigin,
} from '../../src/storage/log-store';
import { makeEnvelope } from './storage-conformance/fixtures';
import { LogBackend, OpenedStore, RawDb, logBackends, refusal } from './helpers/log-store-backends';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');

function checkpoint(logId: number, origin: string, treeSize: number, extra: Partial<NewLogCheckpoint> = {}): NewLogCheckpoint {
  const root = hex(`root-${origin}-${treeSize}`);
  const body = `${origin}\n${treeSize}\n${Buffer.from(root, 'hex').toString('base64')}\n`;
  return {
    logId,
    treeSize,
    root,
    body,
    bodyDigest: createHash('sha256').update(body).digest('hex'),
    compactRange: [root],
    prevAnchoredSize: null,
    consistencyProof: null,
    anchorLeafIndex: null,
    epochId: null,
    ...extra,
  };
}

const attempt = (n: number, broadcast: 'accepted' | 'rejected' | 'unknown' = 'accepted') => ({
  txHash: `0x${hex(`tx-${n}`)}`,
  rawTx: `0x02f8${hex(`raw-${n}`)}`,
  maxFeePerGas: '2000000000',
  maxPriorityFeePerGas: '1000000',
  sentAt: '2026-09-25T10:00:00.000Z',
  broadcast,
});

/** SQLite's anchoring tables take only the statement's own time as an insert time. */
const SQLITE_NOW_SQL = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";

/**
 * The columns each state requires, so a move is refused only by the
 * transition rule. Each publication takes its own nonce (its anchor size), and
 * a move to `superseded` records every broadcast as rejected.
 */
function fieldsFor(state: AnchorPublicationState, current: AnchorPublication): AnchorPublicationPatch {
  const patch: AnchorPublicationPatch = { state };
  if (['submitted', 'included', 'finalized'].includes(state)) {
    if (current.fromAddress === null) patch.fromAddress = '0x' + '1'.repeat(40);
    if (current.nonce === null) patch.nonce = current.anchorSize;
    // Of unknown outcome, which may still become accepted or rejected.
    if (current.attempts.length === 0) patch.attempts = [attempt(1, 'unknown')];
  }
  if (state === 'superseded' && current.attempts.length > 0) {
    patch.attempts = current.attempts.map((a) => ({ ...a, broadcast: 'rejected' as const }));
  }
  if (['included', 'finalized'].includes(state)) {
    if (current.minedTxHash === null) patch.minedTxHash = attempt(1).txHash;
    if (current.blockNumber === null) patch.blockNumber = 100;
    if (current.blockHash === null) patch.blockHash = `0x${hex('block-100')}`;
  }
  if (state === 'obtained') {
    if (current.token === null) patch.token = Buffer.from('token').toString('base64');
    if (current.genTime === null) patch.genTime = '2026-09-25T10:00:00Z';
  }
  return patch;
}

/** A path of allowed moves from `prepared` to `target`. */
const PATH_TO: Record<AnchorPublicationState, AnchorPublicationState[]> = {
  prepared: [],
  submitted: ['submitted'],
  included: ['submitted', 'included'],
  finalized: ['submitted', 'included', 'finalized'],
  obtained: ['obtained'],
  superseded: ['submitted', 'superseded'],
};

describe.each(logBackends('anchor_store').map((b) => [b.name, b] as const))('anchoring tables on %s', (_name, backend: LogBackend) => {
  jest.setTimeout(60_000);
  let store: OpenedStore<unknown>;
  let logs: LogStore;
  let anchors: AnchorStore;
  let raw: RawDb;
  let nextAnchorSize = 1;

  beforeEach(async () => {
    await backend.fresh();
    store = await backend.open();
    logs = logStoreFor(store.adapter)!;
    anchors = anchorStoreFor(store.adapter)!;
    raw = store.raw;
    nextAnchorSize = 1;
  });

  afterEach(async () => {
    await store.close();
  });

  afterAll(async () => {
    await backend.dispose();
  });

  /**
   * Grow the anchor log to `size` leaves and store its checkpoint at `size`:
   * a publication's P must be that checkpoint's digest. Returns the digest.
   */
  async function anchorCheckpoint(size: number): Promise<string> {
    const anchorLog = await anchors.ensureStoreLog('anchors');
    const { size: have } = await logs.getLogSize(anchorLog.logId);
    const leaves = [];
    for (let i = have; i < size; i++) leaves.push({ leafIndex: i, leafDigest: hex(`anchor-leaf-${i}`), sourceRef: `cp-${i}` });
    if (leaves.length > 0) await anchors.appendLogLeaves(anchorLog.logId, leaves);
    const existing = await anchors.getLogCheckpoint(anchorLog.logId, size);
    if (existing) return existing.bodyDigest;
    const cp = checkpoint(anchorLog.logId, anchorLog.origin, size);
    await anchors.insertLogCheckpoint(cp);
    return cp.bodyDigest;
  }

  async function publication(kind: 'evm-calldata/1' | 'rfc3161/1', state: AnchorPublicationState): Promise<AnchorPublication> {
    let p = await anchors.insertAnchorPublication({
      epochId: nextAnchorSize,
      anchorSize: nextAnchorSize,
      p: await anchorCheckpoint(nextAnchorSize),
      kind,
      chain: kind === 'evm-calldata/1' ? 'eip155:11155111' : null,
    });
    nextAnchorSize += 1;
    for (const step of PATH_TO[state]) p = await anchors.updateAnchorPublication(p.id, fieldsFor(step, p));
    expect(p.state).toBe(state);
    return p;
  }

  describe('per-store logs', () => {
    it('ensureStoreLog creates the log once, under the store\'s prefix', async () => {
      const identity = await logs.getStoreIdentity();
      const first = await anchors.ensureStoreLog('anchors');
      const again = await anchors.ensureStoreLog('anchors');
      expect(first).toEqual(again);
      expect(first.origin).toBe(storeLogOrigin(identity.ns, identity.storeId, 'anchors'));
      expect(first.chainId).toBeNull();
      await expect(anchors.ensureStoreLog('evidence')).rejects.toThrow(TypeError);
    });

    it('appendLogLeaves is dense and write-once, and only for per-store logs', async () => {
      const log = await anchors.ensureStoreLog('anchors');
      await anchors.appendLogLeaves(log.logId, [
        { leafIndex: 0, leafDigest: hex('a0'), sourceRef: 'cp-0' },
        { leafIndex: 1, leafDigest: hex('a1'), sourceRef: 'cp-1' },
      ]);
      expect(await logs.getLogSize(log.logId)).toEqual({ size: 2, leafCount: 2 });
      await refusal(anchors.appendLogLeaves(log.logId, [{ leafIndex: 3, leafDigest: hex('a3'), sourceRef: 'cp-3' }]), /log_gap/);
      await refusal(anchors.appendLogLeaves(log.logId, [{ leafIndex: 1, leafDigest: hex('other'), sourceRef: 'cp-x' }]));
      // One call is one transaction: a refusal part-way writes none of it.
      await refusal(anchors.appendLogLeaves(log.logId, [
        { leafIndex: 2, leafDigest: hex('a2'), sourceRef: 'cp-2' },
        { leafIndex: 4, leafDigest: hex('a4'), sourceRef: 'cp-4' },
      ]), /log_gap/);
      expect(await logs.getLogSize(log.logId)).toEqual({ size: 2, leafCount: 2 });

      // An evidence log takes leaves only from the capture trigger and the backfill.
      await (store.adapter as { store(e: unknown): Promise<void> }).store(makeEnvelope({ evidenceId: 'ev-1' }));
      const evidence = (await logs.getEvidenceLog('default'))!;
      await refusal(anchors.appendLogLeaves(evidence.logId, [{ leafIndex: 1, leafDigest: hex('x'), sourceRef: 'forged' }]), /evidence log takes capture and backfill leaves/);
    });
  });

  describe('log_checkpoints', () => {
    let logId: number;
    let origin: string;

    beforeEach(async () => {
      const log = await anchors.ensureStoreLog('anchors');
      logId = log.logId;
      origin = log.origin;
      await anchors.appendLogLeaves(logId, [0, 1, 2].map((i) => ({ leafIndex: i, leafDigest: hex(`l${i}`), sourceRef: `r${i}` })));
    });

    it('round-trips a checkpoint', async () => {
      const cp = checkpoint(logId, origin, 2);
      await anchors.insertLogCheckpoint(cp);
      const next = checkpoint(logId, origin, 3, { prevAnchoredSize: 2, consistencyProof: [hex('p')], epochId: 4 });
      await anchors.insertLogCheckpoint(next);
      const read = await anchors.getLogCheckpoint(logId, 3);
      expect(read).toMatchObject({ ...next, signatures: [] });
      expect((await anchors.listLogCheckpoints(logId)).map((c) => c.treeSize)).toEqual([2, 3]);
    });

    it('refuses a checkpoint of leaves the log does not have, a body that names another log or size, and a digest that is not the body\'s', async () => {
      await refusal(anchors.insertLogCheckpoint(checkpoint(logId, origin, 4)), /no leaf at tree_size - 1/);
      const wrongSize = checkpoint(logId, origin, 2);
      const body = wrongSize.body.replace('\n2\n', '\n3\n');
      await refusal(anchors.insertLogCheckpoint({
        ...wrongSize,
        body,
        bodyDigest: createHash('sha256').update(body).digest('hex'),
      }), /three lines naming this log/);
      const otherOrigin = checkpoint(logId, `${origin}x`, 2);
      await refusal(anchors.insertLogCheckpoint({ ...otherOrigin, logId }), /three lines naming this log/);
      await refusal(anchors.insertLogCheckpoint({ ...checkpoint(logId, origin, 2), bodyDigest: hex('not the body') }), /bodyDigest is not the SHA-256/);
      await refusal(anchors.insertLogCheckpoint(checkpoint(logId, origin, 2, { prevAnchoredSize: 1 })));
      expect(await anchors.listLogCheckpoints(logId)).toEqual([]);
    });

    it('refuses a body whose root line is not the root in base64', async () => {
      const cp = checkpoint(logId, origin, 2);
      const otherRoot = hex('another root');
      const body = `${origin}\n2\n${Buffer.from(otherRoot, 'hex').toString('base64')}\n`;
      await refusal(anchors.insertLogCheckpoint({
        ...cp,
        body,
        bodyDigest: createHash('sha256').update(body).digest('hex'),
      }), /root line is not the root in base64/);
      if (backend.name === 'postgres') {
        // Postgres checks the root line itself too, for a writer that is not the SDK.
        await refusal(raw.run(
          `INSERT INTO log_checkpoints (log_id, tree_size, root, body, body_digest, compact_range)
           VALUES (?, 2, ?, ?, ?, '[]'::jsonb)`,
          [logId, cp.root, body, createHash('sha256').update(body).digest('hex')],
        ), /root line is not the root in base64/);
      }
      expect(await anchors.listLogCheckpoints(logId)).toEqual([]);
    });

    it('anchor_leaf_index must name the anchor-log leaf holding the body\'s digest, and the anchor log\'s own checkpoints have none', async () => {
      // logId is the anchor log here; a source log to anchor, with two leaves.
      const custody = await anchors.ensureStoreLog('custody');
      await anchors.appendLogLeaves(custody.logId, [0, 1].map((i) => ({ leafIndex: i, leafDigest: hex(`s${i}`), sourceRef: `s${i}` })));
      const source = checkpoint(custody.logId, custody.origin, 2);
      const wrongLeaf = /anchor_leaf_index must name the anchor-log leaf/;
      // The anchor log's leaf 3 is not this body's digest yet: there is no leaf 3.
      await refusal(anchors.insertLogCheckpoint({ ...source, anchorLeafIndex: 3 }), wrongLeaf);
      // Leaf 1 exists but holds another digest.
      await refusal(anchors.insertLogCheckpoint({ ...source, anchorLeafIndex: 1 }), wrongLeaf);
      await anchors.appendLogLeaves(logId, [{ leafIndex: 3, leafDigest: source.bodyDigest, sourceRef: 'custody-2' }]);
      await anchors.insertLogCheckpoint({ ...source, anchorLeafIndex: 3 });
      expect((await anchors.getLogCheckpoint(custody.logId, 2))!.anchorLeafIndex).toBe(3);
      // The anchor log's own checkpoint names no leaf of itself.
      await refusal(anchors.insertLogCheckpoint({ ...checkpoint(logId, origin, 4), anchorLeafIndex: 3 }), wrongLeaf);
    });

    it('finds the largest checkpoint at or below a size, and the largest anchored below an anchor size, by index', async () => {
      // logId is the anchor log here; a source log with checkpoints at 1, 3 and 5,
      // the first two anchored at anchor leaves 3 and 4, the last not anchored.
      const source = await anchors.ensureStoreLog('custody');
      await anchors.appendLogLeaves(source.logId, [0, 1, 2, 3, 4].map((i) => ({ leafIndex: i, leafDigest: hex(`s${i}`), sourceRef: `s${i}` })));
      const at = (size: number, anchorLeafIndex: number | null) => checkpoint(source.logId, source.origin, size, { anchorLeafIndex });
      const one = at(1, 3);
      const three = at(3, 4);
      await anchors.appendLogLeaves(logId, [
        { leafIndex: 3, leafDigest: one.bodyDigest, sourceRef: 'custody-1' },
        { leafIndex: 4, leafDigest: three.bodyDigest, sourceRef: 'custody-3' },
      ]);
      for (const cp of [one, three, at(5, null)]) await anchors.insertLogCheckpoint(cp);

      const size = async (p: Promise<{ treeSize: number } | null>) => (await p)?.treeSize ?? null;
      expect(await size(anchors.getLogCheckpointAtOrBelow(source.logId, 0))).toBeNull();
      expect(await size(anchors.getLogCheckpointAtOrBelow(source.logId, 1))).toBe(1);
      expect(await size(anchors.getLogCheckpointAtOrBelow(source.logId, 2))).toBe(1);
      expect(await size(anchors.getLogCheckpointAtOrBelow(source.logId, 4))).toBe(3);
      expect(await size(anchors.getLogCheckpointAtOrBelow(source.logId, 99))).toBe(5);
      expect(await anchors.getLogCheckpointAtOrBelow(source.logId, 4)).toEqual(await anchors.getLogCheckpoint(source.logId, 3));

      // Anchor size n takes anchor leaves 0 to n - 1.
      expect(await size(anchors.getLastAnchoredCheckpointBelow(source.logId, 3))).toBeNull();
      expect(await size(anchors.getLastAnchoredCheckpointBelow(source.logId, 4))).toBe(1);
      expect(await size(anchors.getLastAnchoredCheckpointBelow(source.logId, 5))).toBe(3);
      expect(await size(anchors.getLastAnchoredCheckpointBelow(source.logId, 99))).toBe(3);
      expect(await anchors.getLastAnchoredCheckpointBelow(source.logId, 99)).toEqual(await anchors.getLastAnchoredCheckpoint(source.logId));
    });

    it('is insert-only; signatures are append-only', async () => {
      await anchors.insertLogCheckpoint(checkpoint(logId, origin, 2));
      await refusal(anchors.insertLogCheckpoint(checkpoint(logId, origin, 2)));
      await anchors.appendCheckpointSignatures(logId, 2, ['— tzun.ai/log Az3Dsig1']);
      await anchors.appendCheckpointSignatures(logId, 2, ['— witness.example Bq9sig2']);
      expect((await anchors.getLogCheckpoint(logId, 2))!.signatures).toEqual(['— tzun.ai/log Az3Dsig1', '— witness.example Bq9sig2']);

      await refusal(raw.run('UPDATE log_checkpoints SET root = ? WHERE log_id = ?', [hex('forged'), logId]), /immutable/);
      const rewritten = JSON.stringify(['forged', '— witness.example Bq9sig2']);
      await refusal(raw.run('UPDATE log_checkpoints SET signatures = ? WHERE log_id = ?', [rewritten, logId]), /append-only/);
      await refusal(raw.run('UPDATE log_checkpoints SET signatures = ? WHERE log_id = ?', ['[]', logId]), /append-only/);
      await refusal(raw.run('DELETE FROM log_checkpoints'), /insert-only/);
      if (backend.name === 'postgres') {
        await refusal(raw.run('TRUNCATE log_checkpoints'), /insert-only/);
      }
      expect((await anchors.getLogCheckpoint(logId, 2))!.signatures).toHaveLength(2);
    });
  });

  describe('anchor_publications', () => {
    it('a publication starts prepared, and its kind fixes its chain', async () => {
      const evm = await publication('evm-calldata/1', 'prepared');
      expect(evm).toMatchObject({ state: 'prepared', chain: 'eip155:11155111', attempts: [], nonce: null });
      const tsa = await publication('rfc3161/1', 'prepared');
      expect(tsa.chain).toBeNull();
      const p5 = await anchorCheckpoint(5);
      await refusal(anchors.insertAnchorPublication({ epochId: 5, anchorSize: 5, p: p5, kind: 'evm-calldata/1' }), /constraint/i);
      await refusal(anchors.insertAnchorPublication({ epochId: 5, anchorSize: 5, p: p5, kind: 'rfc3161/1', chain: 'eip155:1' }), /constraint/i);
      const at = backend.name === 'sqlite' ? SQLITE_NOW_SQL : "'2026-09-25T10:00:00Z'";
      await refusal(raw.run(
        `INSERT INTO anchor_publications (epoch_id, anchor_size, p, kind, state, chain, created_at, updated_at)
         VALUES (?, ?, ?, 'rfc3161/1', 'obtained', NULL, ${at}, ${at})`,
        [5, 5, p5],
      ), /starts prepared/);
      // One publication per kind and anchor size: refused by the key on
      // Postgres, and before it by anchor_publications_block_replace on SQLite.
      await refusal(
        anchors.insertAnchorPublication({ epochId: 1, anchorSize: evm.anchorSize, p: evm.p, kind: 'evm-calldata/1', chain: 'eip155:11155111' }),
        /constraint|INSERT over an existing row refused/i,
      );
    });

    it('P must be the digest of the anchor log\'s stored checkpoint at the anchor size', async () => {
      const p3 = await anchorCheckpoint(3);
      await anchorCheckpoint(4);
      const refusedP = /P is not the digest of the anchor log's stored checkpoint/;
      await refusal(anchors.insertAnchorPublication({ epochId: 1, anchorSize: 3, p: hex('not a checkpoint'), kind: 'rfc3161/1' }), refusedP);
      // The digest of the checkpoint at another size.
      await refusal(anchors.insertAnchorPublication({ epochId: 1, anchorSize: 4, p: p3, kind: 'rfc3161/1' }), refusedP);
      // A size the anchor log has no checkpoint for.
      await refusal(anchors.insertAnchorPublication({ epochId: 1, anchorSize: 2, p: p3, kind: 'rfc3161/1' }), refusedP);
      // A checkpoint of another log, even with the right size.
      const custody = await anchors.ensureStoreLog('custody');
      await anchors.appendLogLeaves(custody.logId, [0, 1, 2].map((i) => ({ leafIndex: i, leafDigest: hex(`c${i}`), sourceRef: `c${i}` })));
      const other = checkpoint(custody.logId, custody.origin, 3);
      await anchors.insertLogCheckpoint(other);
      await refusal(anchors.insertAnchorPublication({ epochId: 1, anchorSize: 3, p: other.bodyDigest, kind: 'rfc3161/1' }), refusedP);
      expect(await anchors.insertAnchorPublication({ epochId: 1, anchorSize: 3, p: p3, kind: 'rfc3161/1' })).toMatchObject({ p: p3 });
    });

    it('a sender and nonce belong to one publication at a time, until it is superseded; the sender is lowercase hex', async () => {
      const sender = '0x' + 'a'.repeat(40);
      const first = await publication('evm-calldata/1', 'prepared');
      const second = await publication('evm-calldata/1', 'prepared');
      await anchors.updateAnchorPublication(first.id, { state: 'submitted', fromAddress: sender, nonce: 3, attempts: [{ ...attempt(1), broadcast: 'rejected' }] });
      // The nonce index on Postgres; anchor_publications_block_nonce_replace,
      // before it, on SQLite.
      await refusal(
        anchors.updateAnchorPublication(second.id, { state: 'submitted', fromAddress: sender, nonce: 3, attempts: [attempt(2)] }),
        /unique|holds this sender and nonce/i,
      );
      await anchors.updateAnchorPublication(first.id, { state: 'superseded' });
      const took = await anchors.updateAnchorPublication(second.id, { state: 'submitted', fromAddress: sender, nonce: 3, attempts: [attempt(2)] });
      expect(took).toMatchObject({ state: 'submitted', nonce: 3 });
      // Another spelling of an address would make a second sender of it.
      const third = await publication('evm-calldata/1', 'prepared');
      await refusal(anchors.updateAnchorPublication(third.id, { fromAddress: '0x' + 'A'.repeat(40) }), /constraint/i);
      await refusal(anchors.updateAnchorPublication(third.id, { fromAddress: 'a'.repeat(40) }), /constraint/i);
    });

    it('supersedes only a publication whose every broadcast was rejected; a broadcast is accepted, rejected or unknown', async () => {
      // The rule of anchor_publications_guard_update, and its restatement in
      // anchor_publications_guard_transitions, whichever fires first.
      const onlySupersededIfRejected = /only a publication whose every broadcast was rejected may be superseded|only a publication with an attempt, every one rejected, may be superseded/;
      const accepted = await publication('evm-calldata/1', 'submitted');
      await anchors.updateAnchorPublication(accepted.id, { attempts: [attempt(1)] });
      await refusal(anchors.updateAnchorPublication(accepted.id, { state: 'superseded' }), onlySupersededIfRejected);
      const unknown = await publication('evm-calldata/1', 'submitted');
      expect(unknown.attempts.map((a) => a.broadcast)).toEqual(['unknown']);
      await refusal(anchors.updateAnchorPublication(unknown.id, { state: 'superseded' }), onlySupersededIfRejected);
      // One rejected attempt and one of unknown outcome: still not supersedable.
      const mixed = await anchors.updateAnchorPublication(unknown.id, {
        attempts: [{ ...attempt(1), broadcast: 'rejected' }, attempt(2, 'unknown')],
      });
      await refusal(anchors.updateAnchorPublication(mixed.id, { state: 'superseded' }), onlySupersededIfRejected);
      const rejected = await anchors.updateAnchorPublication(unknown.id, {
        attempts: [{ ...attempt(1), broadcast: 'rejected' }, { ...attempt(2), broadcast: 'rejected' }],
      });
      expect((await anchors.updateAnchorPublication(rejected.id, { state: 'superseded' })).state).toBe('superseded');
      // Never sent at all: a prepared publication has no attempt to have been
      // refused, and is not superseded.
      const prepared = await publication('evm-calldata/1', 'prepared');
      await refusal(anchors.updateAnchorPublication(prepared.id, { state: 'superseded' }), /moves forward only|only a publication with an attempt/);

      const other = await publication('evm-calldata/1', 'submitted');
      const badBroadcast = /broadcast is accepted, rejected, unknown/;
      await refusal(
        anchors.updateAnchorPublication(other.id, { attempts: [{ ...attempt(1), broadcast: 'lost' as 'unknown' }] }),
        badBroadcast,
      );
      const { broadcast: _dropped, ...withoutBroadcast } = attempt(1);
      await refusal(
        anchors.updateAnchorPublication(other.id, { attempts: [withoutBroadcast as ReturnType<typeof attempt>] }),
        badBroadcast,
      );
    });

    it('walks the EVM path forward, and back from included on a reorg', async () => {
      let p = await publication('evm-calldata/1', 'included');
      p = await anchors.updateAnchorPublication(p.id, { state: 'submitted', attempts: [...p.attempts, attempt(2)] });
      expect(p.state).toBe('submitted');
      p = await anchors.updateAnchorPublication(p.id, { state: 'included', minedTxHash: attempt(2).txHash, blockHash: `0x${hex('block-101')}`, blockNumber: 101 });
      p = await anchors.updateAnchorPublication(p.id, {
        state: 'finalized', blockHeader: '0xf90211', txTrieProof: ['0xf851'], gasUsed: '22280', effectiveGasPrice: '1100000000',
      });
      expect(p).toMatchObject({ state: 'finalized', blockNumber: 101, gasUsed: '22280', txTrieProof: ['0xf851'] });
      // Fill progress and an error note may still move.
      p = await anchors.updateAnchorPublication(p.id, { fillProgress: { through: 500 }, error: null });
      expect(p.fillProgress).toEqual({ through: 500 });
    });

    it('fixes the identity columns, writes sender, nonce, token and genTime once, and keeps attempts append-only', async () => {
      const p = await publication('evm-calldata/1', 'submitted');
      await refusal(raw.run('UPDATE anchor_publications SET p = ? WHERE id = ?', [hex('other P'), p.id]), /fixed/);
      await refusal(raw.run('UPDATE anchor_publications SET anchor_size = 99 WHERE id = ?', [p.id]), /fixed/);
      await refusal(anchors.updateAnchorPublication(p.id, { nonce: 8 }), /written once/);
      await refusal(anchors.updateAnchorPublication(p.id, { fromAddress: '0x' + '2'.repeat(40) }), /written once/);
      await refusal(anchors.updateAnchorPublication(p.id, { attempts: [] }), /append-only/);
      await refusal(anchors.updateAnchorPublication(p.id, { attempts: [{ ...attempt(1), rawTx: '0xdifferent' }] }), /append-only/);
      // The broadcast outcome of a stored attempt may be learned later; once
      // accepted, it stays accepted.
      const learned = await anchors.updateAnchorPublication(p.id, { attempts: [{ ...attempt(1), broadcast: 'accepted' }, attempt(2)] });
      expect(learned.attempts.map((a) => a.broadcast)).toEqual(['accepted', 'accepted']);
      await refusal(
        anchors.updateAnchorPublication(p.id, { attempts: [{ ...attempt(1), broadcast: 'rejected' }, attempt(2)] }),
        /a broadcast outcome moves only from unknown, or from rejected to accepted/,
      );

      const tsa = await publication('rfc3161/1', 'obtained');
      await refusal(anchors.updateAnchorPublication(tsa.id, { token: 'b3RoZXI=' }), /written once/);
      await refusal(raw.run('DELETE FROM anchor_publications'), /never deleted/);
      if (backend.name === 'postgres') await refusal(raw.run('TRUNCATE anchor_publications'), /never deleted/);
    });

    it('reads the largest anchor size with a final publication of a kind, ignoring the other kind and publications not final', async () => {
      expect(await anchors.getLastFinalAnchorSize('evm-calldata/1')).toBeNull();
      expect(await anchors.getLastFinalAnchorSize('rfc3161/1')).toBeNull();
      await publication('evm-calldata/1', 'finalized'); // 1
      await publication('evm-calldata/1', 'finalized'); // 2
      await publication('rfc3161/1', 'obtained'); // 3
      await publication('evm-calldata/1', 'included'); // 4
      await publication('evm-calldata/1', 'superseded'); // 5
      await publication('rfc3161/1', 'prepared'); // 6
      expect(await anchors.getLastFinalAnchorSize('evm-calldata/1')).toBe(2);
      expect(await anchors.getLastFinalAnchorSize('rfc3161/1')).toBe(3);
    });

    it('once finalized, the mined transaction and its proof material stay as they are; a null may still be filled', async () => {
      let p = await publication('evm-calldata/1', 'finalized');
      await refusal(anchors.updateAnchorPublication(p.id, { blockHash: `0x${hex('reorged')}` }), /finalized/);
      await refusal(anchors.updateAnchorPublication(p.id, { minedTxHash: attempt(9).txHash }), /finalized/);
      p = await anchors.updateAnchorPublication(p.id, { blockHeader: '0xf90211' });
      await refusal(anchors.updateAnchorPublication(p.id, { blockHeader: '0xf90212' }), /finalized/);
    });

    it('persistEpoch writes leaves, checkpoints and publications in one transaction', async () => {
      const anchorLog = await anchors.ensureStoreLog('anchors');
      const cp = checkpoint(anchorLog.logId, anchorLog.origin, 1);
      const created = await anchors.persistEpoch({
        leaves: [{ logId: anchorLog.logId, leaves: [{ leafIndex: 0, leafDigest: hex('e1'), sourceRef: 'epoch-1' }] }],
        checkpoints: [cp],
        publications: [
          { epochId: 1, anchorSize: 1, p: cp.bodyDigest, kind: 'evm-calldata/1', chain: 'eip155:11155111' },
          { epochId: 1, anchorSize: 1, p: cp.bodyDigest, kind: 'rfc3161/1' },
        ],
      });
      expect(created.map((c) => [c.kind, c.state])).toEqual([['evm-calldata/1', 'prepared'], ['rfc3161/1', 'prepared']]);

      // A refusal anywhere in the epoch leaves nothing of it behind.
      await refusal(anchors.persistEpoch({
        leaves: [{ logId: anchorLog.logId, leaves: [{ leafIndex: 1, leafDigest: hex('e2'), sourceRef: 'epoch-2' }] }],
        checkpoints: [checkpoint(anchorLog.logId, anchorLog.origin, 2)],
        publications: [{ epochId: 2, anchorSize: 1, p: hex('dup'), kind: 'rfc3161/1' }],
      }));
      expect(await logs.getLogSize(anchorLog.logId)).toEqual({ size: 1, leafCount: 1 });
      expect(await anchors.getLogCheckpoint(anchorLog.logId, 2)).toBeNull();
      expect(await anchors.listAnchorPublications()).toHaveLength(2);
      expect(await anchors.listAnchorPublications({ kind: 'rfc3161/1', states: ['prepared'] })).toHaveLength(1);
      expect(await anchors.listAnchorPublications({ states: [] })).toEqual([]);
    });

    // The tables accept exactly the transitions the table in code lists.
    for (const [kind, states] of Object.entries(ANCHOR_PUBLICATION_STATES_BY_KIND) as Array<['evm-calldata/1' | 'rfc3161/1', AnchorPublicationState[]]>) {
      it(`${kind}: every state change is accepted exactly when ANCHOR_PUBLICATION_TRANSITIONS allows it`, async () => {
        const verdicts: string[] = [];
        for (const from of states) {
          for (const to of states) {
            if (from === to) continue;
            const p = await publication(kind, from);
            const allowed = isAllowedPublicationTransition(from, to);
            const outcome = await anchors.updateAnchorPublication(p.id, fieldsFor(to, p)).then(
              () => 'accepted',
              // A move to superseded with no attempt is refused by the
              // transition rule and by its restatement.
              (err: Error) => (/moves forward only|only a publication with an attempt/.test(err.message) ? 'refused' : `error: ${err.message}`),
            );
            verdicts.push(`${from} -> ${to}: ${outcome}`);
            expect(outcome).toBe(allowed ? 'accepted' : 'refused');
          }
        }
        expect(verdicts.length).toBe(states.length * (states.length - 1));
        expect(Object.keys(ANCHOR_PUBLICATION_TRANSITIONS)).toEqual(expect.arrayContaining(states));
      });
    }
  });
});
