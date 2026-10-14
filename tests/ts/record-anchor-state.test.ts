/**
 * tzun-anchor/1 §10.9: a capture reports where its record sits in its chain's
 * evidence log, and `get()` reports how far the record's anchor has got and
 * what the store's logs show is wrong with it.
 *
 * The anchor stages are read from the store's own anchoring tables, which the
 * anchor scheduler writes. This suite writes those rows itself, through the
 * store's `AnchorStore`, the way an epoch does: the checkpoint of the record's
 * evidence log appended to the anchor log, the anchor checkpoint, and its
 * publications, each checkpoint over the log's real leaves. A genuine anchor is
 * the artifact the fill writes (`storeAnchor`): its anchor checkpoint is the
 * one the epoch persisted, whose digest is the publication's P. A
 * self-consistent anchor (`selfConsistentAnchor`) is built from the store's
 * real leaves and origins over an anchor log of its own, so its proofs hold
 * and its P is not the store's. On SQLite always, and on Postgres when its
 * legs run; the memory adapter has evidence logs and no anchoring tables.
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { Tzun } from '../../src/sdk/index';
import {
  MemoryLogStore,
  PostgresLogStore,
  SqliteLogStore,
  anchorStoreFor,
  logStoreFor,
  type AnchorPublication,
  type AnchorPublicationKind,
  type AnchorStore,
  type LogRecord,
  type LogStore,
  type NewLogCheckpoint,
} from '../../src/storage/log-store';
import { SchemaRegistry, canonicalSerialize, computeDigest } from '@tzun/engine';
import type { AnchorArtifact, CaptureInput, EvidenceEnvelope, EvmAnchorPublication } from '@tzun/engine';
import { buildMerkleTree, compactRangeOf, getMerkleProof, getMerkleRoot } from '../../src/attestation/merkle';
import { checkpointDigest, formatCheckpoint } from '../../src/attestation/checkpoint';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { anchoredRecord } from './helpers/anchor-fixtures';
import { rewriteStoredEnvelope } from './helpers/tamper-store';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');
const SEPOLIA = 'eip155:11155111';

const decision = (i: number): CaptureInput => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', i },
  action: 'approved',
  reason: `record ${i}`,
});

interface Backend {
  name: 'memory' | 'sqlite' | 'postgres';
  /** A fresh, empty store for one case: the config keys that open it. */
  fresh(): Promise<Record<string, unknown>>;
  dispose(): Promise<void>;
}

function memoryBackend(): Backend {
  return { name: 'memory', fresh: async () => ({}), dispose: async () => undefined };
}

function sqliteBackend(): Backend {
  let dir: string | undefined;
  return {
    name: 'sqlite',
    async fresh() {
      if (dir) rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), 'tzun-test-anchor-state-'));
      return { dbPath: join(dir, 'store.db') };
    },
    async dispose() {
      if (dir) rmSync(dir, { recursive: true, force: true });
    },
  };
}

function postgresBackend(): Backend | undefined {
  const schema = pgSuiteSchema('record_anchor_state');
  if (!PG_TESTS_ENABLED) return undefined;
  return {
    name: 'postgres',
    async fresh() {
      await schema.reset();
      return { dbUrl: schema.url };
    },
    dispose: async () => undefined,
  };
}

/** A Tzun on a fresh store of `backend`. */
async function init(backend: Backend, extra: Record<string, unknown> = {}): Promise<Tzun> {
  return Tzun.init({ mode: 'dev', ...(await backend.fresh()), ...extra });
}

const sqlBackends = [sqliteBackend(), postgresBackend()].filter((b): b is Backend => b !== undefined);
const allBackends = [memoryBackend(), ...sqlBackends];

/** The log store class `backend` reads through, to spy on. */
function logStoreProto(backend: Backend): SqliteLogStore | PostgresLogStore | MemoryLogStore {
  if (backend.name === 'memory') return MemoryLogStore.prototype;
  return backend.name === 'sqlite' ? SqliteLogStore.prototype : PostgresLogStore.prototype;
}

/** The anchor store class `backend` reads through, to spy on. */
function anchorStoreProto(backend: Backend): SqliteLogStore | PostgresLogStore {
  return backend.name === 'sqlite' ? SqliteLogStore.prototype : PostgresLogStore.prototype;
}

/** The checkpoint row of `log` over `leaves`, its first `leaves.length` leaves: body, root and compact range. */
function checkpointOver(log: LogRecord, leaves: string[], extra: Partial<NewLogCheckpoint> = {}): NewLogCheckpoint {
  const root = getMerkleRoot(buildMerkleTree(leaves));
  const body = formatCheckpoint(log.origin, leaves.length, root);
  return {
    logId: log.logId,
    treeSize: leaves.length,
    root,
    body,
    bodyDigest: checkpointDigest(body),
    compactRange: compactRangeOf(leaves).hashes,
    prevAnchoredSize: null,
    consistencyProof: null,
    anchorLeafIndex: null,
    epochId: null,
    ...extra,
  };
}

/** The digests of `logId`'s leaves [0, size). */
async function leafDigests(logs: LogStore, logId: number, size: number): Promise<string[]> {
  return (await logs.listLogLeaves(logId, 0, size)).map((l) => l.leafDigest);
}

// Of unknown outcome: an accepted broadcast is final, and a test that
// supersedes a publication first learns that every one was rejected.
const attempt = (n: number) => ({
  txHash: `0x${hex(`tx-${n}`)}`,
  rawTx: `0x02f8${hex(`raw-${n}`)}`,
  maxFeePerGas: '2000000000',
  maxPriorityFeePerGas: '1000000',
  sentAt: '2026-09-25T10:00:00.000Z',
  broadcast: 'unknown' as const,
});

/** The stores behind a Tzun, as the scheduler reaches them. */
function storesOf(tzun: Tzun): { logs: LogStore; anchors: AnchorStore } {
  return { logs: logStoreFor(tzun.getStorage())!, anchors: anchorStoreFor(tzun.getStorage())! };
}

/**
 * One epoch: the checkpoint of `chainId`'s evidence log at `size` appended to
 * the anchor log, the anchor checkpoint that results, and one publication of
 * each kind in `kinds`.
 */
async function cutEpoch(
  tzun: Tzun,
  chainId: string,
  size: number,
  epochId: number,
  kinds: AnchorPublicationKind[],
): Promise<AnchorPublication[]> {
  const { logs, anchors } = storesOf(tzun);
  const evidenceLog = (await logs.getEvidenceLog(chainId))!;
  const anchorLog = await anchors.ensureStoreLog('anchors');
  const { size: anchorSize } = await logs.getLogSize(anchorLog.logId);
  const cp = checkpointOver(evidenceLog, await leafDigests(logs, evidenceLog.logId, size), { anchorLeafIndex: anchorSize, epochId });
  const anchorLeaves = [...(await leafDigests(logs, anchorLog.logId, anchorSize)), cp.bodyDigest];
  const anchorCp = checkpointOver(anchorLog, anchorLeaves, { epochId });
  return anchors.persistEpoch({
    leaves: [{ logId: anchorLog.logId, leaves: [{ leafIndex: anchorSize, leafDigest: cp.bodyDigest, sourceRef: `cp-${size}-${epochId}` }] }],
    checkpoints: [cp, anchorCp],
    publications: kinds.map((kind) => ({
      epochId,
      anchorSize: anchorSize + 1,
      p: anchorCp.bodyDigest,
      kind,
      chain: kind === 'evm-calldata/1' ? SEPOLIA : null,
    })),
  });
}

async function submit(anchors: AnchorStore, p: AnchorPublication, n: number, nonce = p.anchorSize): Promise<AnchorPublication> {
  return anchors.updateAnchorPublication(p.id, {
    state: 'submitted',
    fromAddress: '0x' + '1'.repeat(40),
    nonce,
    attempts: [attempt(n)],
  });
}

async function include(anchors: AnchorStore, p: AnchorPublication, n: number, blockNumber: number): Promise<AnchorPublication> {
  return anchors.updateAnchorPublication(p.id, {
    state: 'included',
    minedTxHash: attempt(n).txHash,
    blockNumber,
    blockHash: `0x${hex(`block-${blockNumber}`)}`,
  });
}

/** Send, mine and finalize `p` in block `blockNumber`. */
async function finalize(anchors: AnchorStore, p: AnchorPublication, n: number, blockNumber: number): Promise<AnchorPublication> {
  const included = await include(anchors, await submit(anchors, p, n), n, blockNumber);
  return anchors.updateAnchorPublication(included.id, { state: 'finalized' });
}

/** The EVM entry the scheduler's fill writes for publication `n` mined in `blockNumber` (tzun-anchor/1 §8.2). */
const evmEntry = (n: number, blockNumber: number): EvmAnchorPublication => ({
  kind: 'evm-calldata/1',
  chain: SEPOLIA,
  transactionId: attempt(n).txHash,
  blockNumber,
  blockHash: `0x${hex(`block-${blockNumber}`)}`,
  publisher: '0x' + '1'.repeat(40),
});

/**
 * The `nonRepudiation.anchor` the scheduler's fill writes into `record` from
 * `publication` (src/anchoring/fill.ts): the first anchored checkpoint of the
 * record's evidence log past its leaf, the anchor checkpoint the epoch
 * persisted at the publication's anchor size (whose digest is its P), and the
 * paths through both, from the store's own leaves.
 */
async function storeAnchor(
  tzun: Tzun,
  record: EvidenceEnvelope,
  publication: AnchorPublication,
  publications: AnchorArtifact['publications'] = [evmEntry(1, 100)],
): Promise<AnchorArtifact> {
  const { logs, anchors } = storesOf(tzun);
  const position = (await logs.getEvidenceLogPosition(record.payload.evidenceId))!;
  const cp = (await anchors.listLogCheckpoints(position.logId)).find((c) => c.anchorLeafIndex !== null && c.treeSize > position.leafIndex)!;
  const anchorLog = await anchors.ensureStoreLog('anchors');
  const anchorCp = (await anchors.getLogCheckpoint(anchorLog.logId, publication.anchorSize))!;
  expect(anchorCp.bodyDigest).toBe(publication.p);
  expect(cp.anchorLeafIndex!).toBeLessThan(publication.anchorSize);
  return {
    anchorSpec: 'tzun-anchor/1',
    merkleSpec: 'rfc6962',
    leafIndex: position.leafIndex,
    logCheckpoint: cp.body,
    logPath: getMerkleProof(buildMerkleTree(await leafDigests(logs, position.logId, cp.treeSize)), position.leafIndex),
    anchorLeafIndex: cp.anchorLeafIndex!,
    anchorCheckpoint: anchorCp.body,
    anchorPath: getMerkleProof(buildMerkleTree(await leafDigests(logs, anchorLog.logId, publication.anchorSize)), cp.anchorLeafIndex!),
    publications,
  };
}

/**
 * A `nonRepudiation.anchor` for `records[leafIndex]` whose proofs hold and
 * that the store did not publish: its evidence log is the store's (origin
 * and, unless `digests` says otherwise, leaves) at size `size`, under an
 * anchor log of its own with `before` and `after` made-up leaves around the
 * log's checkpoint (default 2 and 1), so its P is not the store's.
 */
async function selfConsistentAnchor(
  tzun: Tzun,
  records: EvidenceEnvelope[],
  leafIndex: number,
  size: number,
  opts: { chainId?: string; publications?: AnchorArtifact['publications']; digests?: string[]; before?: number; after?: number } = {},
): Promise<AnchorArtifact> {
  const identity = await storesOf(tzun).logs.getStoreIdentity();
  return anchoredRecord({
    domainPrefix: `${identity.ns}/${identity.storeId}`,
    chainId: opts.chainId ?? 'default',
    digests: opts.digests ?? records.slice(0, size).map((r) => r.integrity.canonicalDigest),
    leafIndex,
    ...(opts.before !== undefined && { before: opts.before }),
    ...(opts.after !== undefined && { after: opts.after }),
    publications: opts.publications ?? [evmEntry(1, 100)],
  }).anchor;
}

async function attachAnchor(tzun: Tzun, record: EvidenceEnvelope, anchor: unknown): Promise<void> {
  await tzun.getStorage().updateAttestation(record.payload.evidenceId, { anchor } as never, 'partial');
}

describe.each(allBackends.map((b) => [b.name, b] as const))('CaptureResult.logPosition on %s', (_name, backend) => {
  jest.setTimeout(60_000);
  let tzun: Tzun | undefined;

  afterEach(async () => {
    jest.restoreAllMocks();
    await tzun?.close();
    tzun = undefined;
  });
  afterAll(() => backend.dispose());

  it("names the chain's evidence log and the record's leaf, sequenceNumber − 1", async () => {
    tzun = await init(backend);
    const first = await tzun.capture(decision(1));
    const second = await tzun.capture(decision(2));
    const logs = logStoreFor(tzun.getStorage())!;
    const identity = await logs.getStoreIdentity();

    expect(first.logPosition).toEqual({
      origin: `${identity.ns}/${identity.storeId}/evidence/${Buffer.from('default', 'utf8').toString('hex')}`,
      leafIndex: 0,
    });
    expect(second.logPosition).toEqual({ origin: first.logPosition!.origin, leafIndex: 1 });
    // The position the store's own log holds for the record.
    const held = await logs.getEvidenceLogPosition(second.envelope.payload.evidenceId);
    expect({ origin: held!.origin, leafIndex: held!.leafIndex }).toEqual(second.logPosition);
    expect(held!.leafDigest).toBe(second.envelope.integrity.canonicalDigest);
  });

  it("a named chain's records sit in that chain's log", async () => {
    tzun = await init(backend, { chainId: 'tenant-a' });
    const r = await tzun.capture(decision(1));
    expect(r.logPosition!.origin).toMatch(new RegExp(`/evidence/${Buffer.from('tenant-a', 'utf8').toString('hex')}$`));
    expect(r.logPosition!.leafIndex).toBe(r.envelope.payload.sequenceNumber - 1);
  });

  it("a replay reports the original record's position", async () => {
    tzun = await init(backend);
    const first = await tzun.capture(decision(1), { idempotencyKey: 'k-1' });
    await tzun.capture(decision(2));
    const again = await tzun.capture(decision(1), { idempotencyKey: 'k-1' });
    expect(again.replayed).toBe(true);
    expect(again.logPosition).toEqual(first.logPosition);
  });

  it('a capture that stores nothing reports no position', async () => {
    tzun = await init(backend);
    const refused = await tzun.capture({ ...decision(1), action: '' });
    expect(refused.stored).toBe(false);
    expect(refused).not.toHaveProperty('logPosition');
  });

  it('a failed read of the leaf leaves the capture stored, without a position, and is logged', async () => {
    const events: Array<[string, Record<string, unknown>]> = [];
    tzun = await init(backend, { onLog: (event: string, fields: Record<string, unknown>) => events.push([event, fields]) });
    jest.spyOn(logStoreProto(backend), 'getEvidenceLogPosition').mockRejectedValueOnce(new Error('log read failed'));

    const r = await tzun.capture(decision(1));
    expect(r.stored).toBe(true);
    expect(r).not.toHaveProperty('logPosition');
    expect(events).toContainEqual([
      'capture_log_position_unread',
      expect.objectContaining({ evidenceId: r.envelope.payload.evidenceId, errorMessage: 'log read failed' }),
    ]);
    expect(await tzun.get(r.envelope.payload.evidenceId)).not.toBeNull();
  });

  it('the position is read after the capture lock is released: a slow read holds up no other capture', async () => {
    tzun = await init(backend);
    const proto = logStoreProto(backend);
    const original = proto.getEvidenceLogPosition;
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    let reached!: () => void;
    const firstReadReached = new Promise<void>((resolve) => (reached = resolve));
    let calls = 0;
    jest.spyOn(proto, 'getEvidenceLogPosition').mockImplementation(async function (this: LogStore, evidenceId: string) {
      calls += 1;
      if (calls === 1) {
        reached();
        await held;
      }
      return original.call(this, evidenceId);
    });

    const first = tzun.capture(decision(1));
    await firstReadReached;
    // The first capture is stored and waiting on its position read. A second
    // capture must get the lock and finish meanwhile.
    const second = await Promise.race([
      tzun.capture(decision(2)),
      new Promise<'blocked'>((resolve) => setTimeout(() => resolve('blocked'), 5_000)),
    ]);
    expect(second).not.toBe('blocked');
    expect((second as Awaited<ReturnType<Tzun['capture']>>).logPosition).toMatchObject({ leafIndex: 1 });

    release();
    expect((await first).logPosition).toMatchObject({ leafIndex: 0 });
  });
});

describe.each(allBackends.map((b) => [b.name, b] as const))('get() reports the log position on %s', (_name, backend) => {
  jest.setTimeout(60_000);
  let tzun: Tzun | undefined;

  afterEach(async () => {
    await tzun?.close();
    tzun = undefined;
  });
  afterAll(() => backend.dispose());

  it('beside the envelope and the verdict, with no anchor state on a store that does not anchor', async () => {
    tzun = await init(backend);
    const r = await tzun.capture(decision(1));
    const read = await tzun.get(r.envelope.payload.evidenceId);
    expect(read!.logPosition).toEqual(r.logPosition);
    expect(read).not.toHaveProperty('anchorState');
    expect(read).not.toHaveProperty('logFindings');
  });

  it('with read verification off too', async () => {
    tzun = await init(backend, { verifyReads: false });
    const r = await tzun.capture(decision(1));
    expect((await tzun.get(r.envelope.payload.evidenceId))!.logPosition).toEqual(r.logPosition);
  });

  it('list() does not report it', async () => {
    tzun = await init(backend);
    await tzun.capture(decision(1));
    const [read] = await tzun.list();
    expect(read).not.toHaveProperty('logPosition');
    expect(read).not.toHaveProperty('anchorState');
  });

  it('a record rewritten after it was logged is a finding (digest_differs_from_logged_leaf)', async () => {
    tzun = await init(backend);
    const r = await tzun.capture(decision(1));
    const id = r.envelope.payload.evidenceId;
    const logs = logStoreFor(tzun.getStorage())!;
    const logged = (await logs.getEvidenceLogPosition(id))!;
    // What a consistent rewrite leaves: an envelope whose digest is not the leaf.
    jest.spyOn(logStoreProto(backend), 'getEvidenceLogPosition').mockResolvedValueOnce({
      ...logged,
      leafDigest: hex('the digest the record was logged with'),
    });
    const read = await tzun.get(id);
    expect(read!.logFindings).toEqual(['digest_differs_from_logged_leaf']);
    expect(read!.logPosition).toEqual(r.logPosition);
    jest.restoreAllMocks();
    expect(await tzun.get(id)).not.toHaveProperty('logFindings');
  });

  it("a record carrying another record's anchor is a transplant, on a store that anchors or not", async () => {
    tzun = await init(backend);
    const records: EvidenceEnvelope[] = [];
    for (let i = 1; i <= 3; i++) records.push((await tzun.capture(decision(i))).envelope);
    await attachAnchor(tzun, records[0], await selfConsistentAnchor(tzun, records, 1, 3));
    const read = await tzun.get(records[0].payload.evidenceId);
    expect(read!.logFindings).toEqual(['anchor_transplanted']);
    expect(read).not.toHaveProperty('anchorState');
    // Record 2's own anchor names its own log and leaf.
    await attachAnchor(tzun, records[1], await selfConsistentAnchor(tzun, records, 1, 3));
    expect(await tzun.get(records[1].payload.evidenceId)).not.toHaveProperty('logFindings');
    // An artifact whose log checkpoint does not parse names no log: nothing to compare.
    await attachAnchor(tzun, records[2], { ...(await selfConsistentAnchor(tzun, records, 1, 3)), logCheckpoint: 'not a body' });
    expect(await tzun.get(records[2].payload.evidenceId)).not.toHaveProperty('logFindings');
  });
});

describe.each(sqlBackends.map((b) => [b.name, b] as const))('get() reports the anchor stage on %s', (_name, backend) => {
  jest.setTimeout(60_000);
  let tzun: Tzun;
  let store: Record<string, unknown>;
  let records: EvidenceEnvelope[];
  let origin: string;

  beforeEach(async () => {
    store = await backend.fresh();
    tzun = await Tzun.init({ mode: 'dev', ...store });
    records = [];
    for (let i = 1; i <= 3; i++) records.push((await tzun.capture(decision(i))).envelope);
    origin = (await storesOf(tzun).logs.getEvidenceLog('default'))!.origin;
  });
  afterEach(() => tzun.close());
  afterAll(() => backend.dispose());

  const readOf = async (i: number) => (await tzun.get(records[i].payload.evidenceId))!;
  const stateOf = async (i: number) => (await readOf(i)).anchorState;
  const pending = (i: number) => ({
    origin,
    leafIndex: i,
    anchorValid: null,
    anchorReason: 'anchor_not_yet_published',
  });

  it('awaiting_epoch once the store anchors, for a record no epoch covers', async () => {
    await storesOf(tzun).anchors.ensureStoreLog('anchors');
    expect(await stateOf(0)).toEqual({ state: 'awaiting_epoch', ...pending(0) });
    expect((await readOf(0)).logPosition).toEqual({ origin, leafIndex: 0 });
  });

  it('awaiting_epoch while the epoch that covers the record has sent nothing', async () => {
    await cutEpoch(tzun, 'default', 2, 1, ['evm-calldata/1', 'rfc3161/1']);
    const publication = { kind: 'evm-calldata/1', chain: SEPOLIA };
    expect(await stateOf(0)).toEqual({ state: 'awaiting_epoch', ...pending(0), publication });
    expect(await stateOf(1)).toEqual({ state: 'awaiting_epoch', ...pending(1), publication });
    expect(await stateOf(2)).toEqual({ state: 'awaiting_epoch', ...pending(2) });
  });

  it('awaiting_finality with the transaction once it is signed, and with its block once mined', async () => {
    const { anchors } = storesOf(tzun);
    const [evm] = await cutEpoch(tzun, 'default', 2, 1, ['evm-calldata/1']);

    const submitted = await submit(anchors, evm, 1);
    expect(await stateOf(1)).toEqual({
      state: 'awaiting_finality',
      ...pending(1),
      publication: { kind: 'evm-calldata/1', chain: SEPOLIA, transactionId: attempt(1).txHash },
    });

    await include(anchors, submitted, 1, 11_781_565);
    expect(await stateOf(1)).toEqual({
      state: 'awaiting_finality',
      ...pending(1),
      publication: { kind: 'evm-calldata/1', chain: SEPOLIA, transactionId: attempt(1).txHash, blockNumber: 11_781_565 },
    });
  });

  it("awaiting_finality once the block is final and the record is not filled; anchored once it carries the anchor the fill writes", async () => {
    const { anchors } = storesOf(tzun);
    const [evm] = await cutEpoch(tzun, 'default', 2, 1, ['evm-calldata/1']);
    await finalize(anchors, evm, 1, 100);
    const publication = { kind: 'evm-calldata/1', chain: SEPOLIA, transactionId: attempt(1).txHash, blockNumber: 100 };

    expect(await stateOf(0)).toEqual({ state: 'awaiting_finality', ...pending(0), publication });

    await attachAnchor(tzun, records[0], await storeAnchor(tzun, records[0], evm));
    // The proofs hold and its anchor checkpoint is the one whose digest the
    // store published; the publication is not decided without a header source.
    expect(await stateOf(0)).toEqual({
      state: 'anchored',
      origin,
      leafIndex: 0,
      anchorValid: null,
      anchorReason: 'publication_not_checked',
      publication,
    });
    expect(await stateOf(1)).toEqual({ state: 'awaiting_finality', ...pending(1), publication });
  });

  it('the EVM publication decides while it is not final, whatever the token says', async () => {
    const { anchors } = storesOf(tzun);
    const [evm, tsa] = await cutEpoch(tzun, 'default', 2, 1, ['evm-calldata/1', 'rfc3161/1']);
    await anchors.updateAnchorPublication(tsa.id, { state: 'obtained', token: 'dG9rZW4=', genTime: '2026-09-25T10:00:00Z' });
    await submit(anchors, evm, 1);
    expect(await stateOf(0)).toMatchObject({ state: 'awaiting_finality', publication: { kind: 'evm-calldata/1' } });
  });

  it('a store that publishes only through RFC 3161: awaiting_finality once the token is obtained', async () => {
    const { anchors } = storesOf(tzun);
    const [tsa] = await cutEpoch(tzun, 'default', 3, 1, ['rfc3161/1']);
    expect(await stateOf(2)).toEqual({ state: 'awaiting_epoch', ...pending(2), publication: { kind: 'rfc3161/1' } });
    await anchors.updateAnchorPublication(tsa.id, { state: 'obtained', token: 'dG9rZW4=', genTime: '2026-09-25T10:00:00Z' });
    expect(await stateOf(2)).toEqual({ state: 'awaiting_finality', ...pending(2), publication: { kind: 'rfc3161/1' } });
  });

  it('a superseded publication covers nothing; a later epoch that covers the record decides', async () => {
    const { anchors } = storesOf(tzun);
    const [first] = await cutEpoch(tzun, 'default', 1, 1, ['evm-calldata/1']);
    const sent = await submit(anchors, first, 1, 7);
    await anchors.updateAnchorPublication(sent.id, {
      state: 'superseded',
      attempts: sent.attempts.map((a) => ({ ...a, broadcast: 'rejected' as const })),
    });
    // Record 1's checkpoint sits in the anchor log, and no live publication covers it.
    expect(await stateOf(0)).toEqual({ state: 'awaiting_epoch', ...pending(0) });

    // The next epoch's anchor checkpoint covers the whole anchor log, record 1's checkpoint included.
    const [second] = await cutEpoch(tzun, 'default', 3, 2, ['evm-calldata/1']);
    await submit(anchors, second, 2, 7);
    expect(await stateOf(0)).toEqual({
      state: 'awaiting_finality',
      ...pending(0),
      publication: { kind: 'evm-calldata/1', chain: SEPOLIA, transactionId: attempt(2).txHash },
    });
    expect(await stateOf(2)).toMatchObject({ state: 'awaiting_finality' });
  });

  it("another chain's epoch does not cover this chain's records", async () => {
    const other = await Tzun.init({ mode: 'dev', ...store, chainId: 'tenant-b' });
    try {
      await other.capture(decision(9));
      await cutEpoch(tzun, 'tenant-b', 1, 1, ['evm-calldata/1']);
      expect(await stateOf(0)).toEqual({ state: 'awaiting_epoch', ...pending(0) });
    } finally {
      await other.close();
    }
  });

  it('a failure to read the anchoring tables leaves the read without its log fields, and is logged', async () => {
    const events: Array<[string, Record<string, unknown>]> = [];
    const logged = await Tzun.init({ mode: 'dev', ...store, onLog: (event: string, fields: Record<string, unknown>) => events.push([event, fields]) });
    try {
      await storesOf(logged).anchors.ensureStoreLog('anchors');
      jest.spyOn(anchorStoreProto(backend), 'getLeafAnchorProgress').mockRejectedValueOnce(new Error('no such table: log_checkpoints'));
      const read = await logged.get(records[0].payload.evidenceId);
      expect(read!.envelope.payload.evidenceId).toBe(records[0].payload.evidenceId);
      expect(read).not.toHaveProperty('logPosition');
      expect(read).not.toHaveProperty('anchorState');
      expect(events).toContainEqual([
        'get_anchor_state_unread',
        expect.objectContaining({ evidenceId: records[0].payload.evidenceId, errorMessage: 'no such table: log_checkpoints' }),
      ]);
    } finally {
      jest.restoreAllMocks();
      await logged.close();
    }
  });
});

describe.each(sqlBackends.map((b) => [b.name, b] as const))("get() does not take the record's word for its anchor on %s", (_name, backend) => {
  jest.setTimeout(60_000);
  let tzun: Tzun;
  let records: EvidenceEnvelope[];
  let finalPublication: Record<string, unknown>;
  let evm: AnchorPublication;

  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev', ...(await backend.fresh()) });
    records = [];
    for (let i = 1; i <= 3; i++) records.push((await tzun.capture(decision(i))).envelope);
  });
  afterEach(() => tzun.close());
  afterAll(() => backend.dispose());

  /** Records 1 and 2 covered by an epoch whose EVM publication is final; record 3 covered by none. */
  async function finalEpoch(): Promise<void> {
    [evm] = await cutEpoch(tzun, 'default', 2, 1, ['evm-calldata/1']);
    evm = await finalize(storesOf(tzun).anchors, evm, 1, 100);
    finalPublication = { kind: 'evm-calldata/1', chain: SEPOLIA, transactionId: attempt(1).txHash, blockNumber: 100 };
  }
  const stateOf = async (i: number) => (await tzun.get(records[i].payload.evidenceId))!.anchorState;

  it.each([
    ['an empty object', {}],
    ['a string', 'garbage'],
    ['an unknown tag', { anchorSpec: 'tzun-anchor/9' }],
    ['false', false],
    ['zero', 0],
  ])('a forged anchor (%s) on a record whose epoch is final is anchor_invalid, not awaiting anything', async (_label, forged) => {
    await finalEpoch();
    await attachAnchor(tzun, records[0], forged);
    const read = await tzun.get(records[0].payload.evidenceId);
    expect(read!.anchorState).toMatchObject({
      state: 'anchor_invalid',
      anchorValid: null,
      anchorReason: 'unsupported_anchor_spec',
      publication: finalPublication,
    });
    await attachAnchor(tzun, records[2], forged);
    expect(await stateOf(2)).toMatchObject({ state: 'awaiting_epoch', anchorValid: null, anchorReason: 'unsupported_anchor_spec' });
  });

  it("another record's genuine anchor is not this record's: anchor_invalid, leaf_index_mismatch, and the transplant is a finding", async () => {
    await finalEpoch();
    await attachAnchor(tzun, records[0], await storeAnchor(tzun, records[1], evm));
    const read = (await tzun.get(records[0].payload.evidenceId))!;
    expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: false, anchorReason: 'leaf_index_mismatch' });
    // Its anchor checkpoint is the store's: the transplant is the only finding.
    expect(read.logFindings).toEqual(['anchor_transplanted']);
    expect(await tzun.verify(records[0].payload.evidenceId)).toMatchObject({ logFindings: ['anchor_transplanted'] });
  });

  it("an anchor from another log at the record's own position: anchor_invalid, merkle_proof_invalid, and no transplant finding", async () => {
    await finalEpoch();
    const elsewhere = await selfConsistentAnchor(tzun, records, 0, 2, { digests: [hex('another record'), hex('and another')] });
    await attachAnchor(tzun, records[0], elsewhere);
    const read = (await tzun.get(records[0].payload.evidenceId))!;
    expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: false, anchorReason: 'merkle_proof_invalid' });
    // It names the record's own log and leaf: a forged tree, not another
    // record's artifact, under an anchor checkpoint the store never published.
    expect(read.logFindings).toEqual(['anchor_checkpoint_not_published']);
  });

  it("an anchor from another chain's log: anchor_invalid, chain_id_mismatch, and the transplant is a finding", async () => {
    await finalEpoch();
    await attachAnchor(tzun, records[0], await selfConsistentAnchor(tzun, records, 0, 2, { chainId: 'tenant-b' }));
    const read = (await tzun.get(records[0].payload.evidenceId))!;
    expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: false, anchorReason: 'chain_id_mismatch' });
    expect(read.logFindings).toEqual(['anchor_transplanted', 'anchor_checkpoint_not_published']);
  });

  it('an anchor whose proofs hold is not anchored before its epoch is final', async () => {
    const [prepared] = await cutEpoch(tzun, 'default', 2, 1, ['evm-calldata/1']);
    await attachAnchor(tzun, records[0], await storeAnchor(tzun, records[0], prepared));
    expect(await stateOf(0)).toMatchObject({ state: 'awaiting_epoch', anchorValid: null, anchorReason: 'publication_not_checked' });
    await submit(storesOf(tzun).anchors, prepared, 1);
    expect(await stateOf(0)).toMatchObject({ state: 'awaiting_finality', anchorValid: null, anchorReason: 'publication_not_checked' });
  });

  it('an anchor whose proofs hold on a record no epoch covers is awaiting_epoch', async () => {
    await finalEpoch();
    await attachAnchor(tzun, records[2], await selfConsistentAnchor(tzun, records, 2, 3));
    expect(await stateOf(2)).toMatchObject({ state: 'awaiting_epoch', anchorValid: null, anchorReason: 'publication_not_checked' });
  });

  it('an anchor whose proofs hold and that lists an unreadable publication is not anchored', async () => {
    await finalEpoch();
    await attachAnchor(tzun, records[0], await storeAnchor(tzun, records[0], evm, [evmEntry(1, 100), null as never]));
    expect(await stateOf(0)).toMatchObject({ state: 'anchor_invalid', anchorValid: false, anchorReason: 'malformed_publication' });
    // verify() decides the record's own artifact: false, and `verified` untouched.
    expect(await tzun.verify(records[0].payload.evidenceId)).toMatchObject({ verified: true, anchorValid: false, anchorReason: 'malformed_publication' });
  });

  it('the verdict on the record is untouched', async () => {
    await finalEpoch();
    await attachAnchor(tzun, records[0], { anchorSpec: 'tzun-anchor/9' });
    const read = await tzun.get(records[0].payload.evidenceId);
    const [listed] = (await tzun.list()).filter((r) => r.envelope.payload.evidenceId === records[0].payload.evidenceId);
    expect(read!.verdict.status).toBe(listed.verdict.status);
  });
});

/** The digest of `envelope`'s payload under its schema's hashed field set, as the store computes it. */
function payloadDigest(envelope: EvidenceEnvelope): string {
  const schema = new SchemaRegistry().get(envelope.payload.schemaVersion)!;
  return computeDigest(canonicalSerialize(envelope.payload as unknown as Record<string, unknown>, schema.hashedFieldSet));
}

describe.each(sqlBackends.map((b) => [b.name, b] as const))(
  'a record whose epoch is final is anchored only as stored: an altered payload and a rewritten row, on %s',
  (_name, backend) => {
    jest.setTimeout(60_000);
    let tzun: Tzun;
    let store: Record<string, unknown>;
    let records: EvidenceEnvelope[];
    const finalPublication = { kind: 'evm-calldata/1', chain: SEPOLIA, transactionId: attempt(1).txHash, blockNumber: 100 };

    /** Records 1 and 2 covered by an epoch whose EVM publication is final and filled, each carrying its genuine anchor. */
    beforeEach(async () => {
      store = await backend.fresh();
      tzun = await Tzun.init({ mode: 'dev', ...store });
      records = [];
      for (let i = 1; i <= 3; i++) records.push((await tzun.capture(decision(i))).envelope);
      const [evm] = await cutEpoch(tzun, 'default', 2, 1, ['evm-calldata/1']);
      const final = await finalize(storesOf(tzun).anchors, evm, 1, 100);
      for (const i of [0, 1]) await attachAnchor(tzun, records[i], await storeAnchor(tzun, records[i], final));
      await storesOf(tzun).anchors.updateAnchorPublication(final.id, {
        fillProgress: { from: 0, anchorLeaf: 1, leafIndex: null, filled: 2, total: 2, done: true },
      });
    });
    afterEach(() => tzun.close());
    afterAll(() => backend.dispose());

    const id = (i: number): string => records[i].payload.evidenceId;

    it('an intact record with its genuine anchor is anchored, with no finding', async () => {
      const read = (await tzun.get(id(0)))!;
      expect(read.anchorState).toMatchObject({ state: 'anchored', anchorValid: null, anchorReason: 'publication_not_checked', publication: finalPublication });
      expect(read).not.toHaveProperty('logFindings');
    });

    it('the payload altered and the stored digest kept is anchor_invalid, its anchor checked against the digest recomputed from the payload', async () => {
      await rewriteStoredEnvelope(tzun.getStorage(), id(0), (e) => {
        e.payload.reason = 'altered after it was anchored';
      });
      const read = (await tzun.get(id(0)))!;
      // The read's own verdict already said so; the anchor stage said `anchored`.
      expect(read.verdict.digest).toMatchObject({ status: 'invalid', reason: 'digest_mismatch' });
      expect(read.anchorState).toEqual({
        state: 'anchor_invalid',
        origin: read.logPosition!.origin,
        leafIndex: 0,
        anchorValid: false,
        anchorReason: 'merkle_proof_invalid',
        publication: finalPublication,
      });
      // The stored digest is still the logged leaf: no logged-leaf finding.
      expect(read).not.toHaveProperty('logFindings');
      // verify() judges the anchor against the same digest.
      const verified = await tzun.verify(id(0));
      expect(verified).toMatchObject({ verified: false, anchorValid: false, anchorReason: 'merkle_proof_invalid' });
      expect(verified.recomputedDigest).not.toBe(verified.storedDigest);
      // The record beside it is untouched.
      expect((await tzun.get(id(1)))!.anchorState).toMatchObject({ state: 'anchored' });
    });

    it('the payload altered, with read verification off: the stage recomputes the digest itself', async () => {
      await rewriteStoredEnvelope(tzun.getStorage(), id(0), (e) => {
        e.payload.reason = 'altered after it was anchored';
      });
      const unverified = await Tzun.init({ mode: 'dev', ...store, verifyReads: false });
      try {
        const read = (await unverified.get(id(0)))!;
        expect(read.verdict.status).toBe('unmeasured');
        expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: false, anchorReason: 'merkle_proof_invalid' });
      } finally {
        await unverified.close();
      }
    });

    it('only the stored digest edited, the payload intact: anchor_invalid, and the logged-leaf finding', async () => {
      await rewriteStoredEnvelope(tzun.getStorage(), id(0), (e) => {
        e.integrity.canonicalDigest = hex('a digest the payload does not have');
      });
      const read = (await tzun.get(id(0)))!;
      expect(read.verdict.digest).toMatchObject({ status: 'invalid', reason: 'digest_mismatch' });
      expect(read.logFindings).toEqual(['digest_differs_from_logged_leaf']);
      // The anchor still holds for the payload's digest, and the record as stored is not what was anchored.
      expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: null, anchorReason: 'publication_not_checked' });
    });

    it('the payload and its digest rewritten (a self-consistent row) is anchor_invalid, merkle_proof_invalid, with the logged-leaf finding', async () => {
      await rewriteStoredEnvelope(tzun.getStorage(), id(0), (e) => {
        e.payload.reason = 'rewritten, digest and all';
        e.integrity.canonicalDigest = payloadDigest(e);
      });
      const read = (await tzun.get(id(0)))!;
      expect(read.verdict.digest.status).toBe('valid');
      expect(read.logFindings).toEqual(['digest_differs_from_logged_leaf']);
      expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: false, anchorReason: 'merkle_proof_invalid', publication: finalPublication });
    });

    it("a rewritten row: another store's artifact for the same chain and position is anchor_invalid, merkle_proof_invalid, and a transplant", async () => {
      const identity = await storesOf(tzun).logs.getStoreIdentity();
      const otherStore = anchoredRecord({
        domainPrefix: `${identity.ns}/${'ab'.repeat(16)}`,
        chainId: 'default',
        digests: [hex('store B record 1'), hex('store B record 2')],
        leafIndex: 0,
        publications: [evmEntry(1, 100)],
      }).anchor;
      // The fill writes an anchor only where there is none: the operator writes the row.
      await rewriteStoredEnvelope(tzun.getStorage(), id(0), (e) => {
        (e.nonRepudiation as Record<string, unknown>).anchor = otherStore;
      });
      const read = (await tzun.get(id(0)))!;
      expect(read.verdict.status).toBe('valid');
      expect(read.logFindings).toEqual(['anchor_transplanted', 'anchor_checkpoint_not_published']);
      expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: false, anchorReason: 'merkle_proof_invalid' });
      expect(await tzun.verify(id(0))).toMatchObject({
        verified: true,
        anchorValid: false,
        anchorReason: 'merkle_proof_invalid',
        logFindings: ['anchor_transplanted', 'anchor_checkpoint_not_published'],
      });
    });

    /**
     * The payload and its digest rewritten, and the artifact replaced by one
     * whose steps 1 to 5 hold for the rewritten record: the store's own
     * origins and the record's leaf, over made-up leaves. Nothing the
     * verifier checks without a header source binds it to what the store
     * published; the store's final P and its logged leaf do.
     */
    async function reseatWithForgedAnchor(shape: { before?: number; after?: number }): Promise<AnchorArtifact> {
      let digest = '';
      await rewriteStoredEnvelope(tzun.getStorage(), id(0), (e) => {
        e.payload.reason = 'forged after anchoring';
        e.integrity.canonicalDigest = digest = payloadDigest(e);
      });
      const forged = await selfConsistentAnchor(tzun, records, 0, 2, { digests: [digest, records[1].integrity.canonicalDigest], ...shape });
      await rewriteStoredEnvelope(tzun.getStorage(), id(0), (e) => {
        (e.nonRepudiation as Record<string, unknown>).anchor = forged;
      });
      return forged;
    }

    it.each([
      ['an anchor log of one leaf, the size of the store\'s (a forged-anchor probe)', { before: 0, after: 0 }],
      ['a larger anchor log of its own', {}],
    ])(
      'a rewritten row with a forged artifact (%s): anchor_invalid, never anchored, with the logged-leaf finding and the unpublished checkpoint',
      async (_label, shape) => {
        const forged = await reseatWithForgedAnchor(shape);
        const read = (await tzun.get(id(0)))!;
        expect(read.verdict.status).toBe('valid');
        // The verifier alone finds nothing wrong: its proofs hold for the rewritten record.
        expect(read.anchorState).toMatchObject({
          state: 'anchor_invalid',
          anchorValid: null,
          anchorReason: 'publication_not_checked',
          publication: finalPublication,
        });
        expect(read.logFindings).toEqual(['digest_differs_from_logged_leaf', 'anchor_checkpoint_not_published']);
        const published = await storesOf(tzun).anchors.listAnchorPublications({ kind: 'evm-calldata/1' });
        expect(published.map((p) => p.p)).not.toContain(checkpointDigest(forged.anchorCheckpoint));
        expect(await tzun.verify(id(0))).toMatchObject({
          verified: true,
          anchorValid: null,
          anchorReason: 'publication_not_checked',
          logFindings: ['digest_differs_from_logged_leaf', 'anchor_checkpoint_not_published'],
        });
        // The record beside it is untouched.
        expect((await tzun.get(id(1)))!.anchorState).toMatchObject({ state: 'anchored' });
      },
    );

    it("an intact record whose genuine anchor is swapped for a self-consistent one the store did not publish: anchor_invalid, and the unpublished checkpoint is the finding", async () => {
      const swapped = await selfConsistentAnchor(tzun, records, 0, 2, { digests: [records[0].integrity.canonicalDigest, hex('a made-up second leaf')] });
      await rewriteStoredEnvelope(tzun.getStorage(), id(0), (e) => {
        (e.nonRepudiation as Record<string, unknown>).anchor = swapped;
      });
      const read = (await tzun.get(id(0)))!;
      expect(read.verdict.status).toBe('valid');
      // The leaf is the record's, the proofs hold, and P is not the store's.
      expect(read.logFindings).toEqual(['anchor_checkpoint_not_published']);
      expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: null, anchorReason: 'publication_not_checked' });
    });

    it('a record the epoch does not cover keeps awaiting it, whatever its payload', async () => {
      await rewriteStoredEnvelope(tzun.getStorage(), id(2), (e) => {
        e.payload.reason = 'altered before any epoch';
      });
      expect((await tzun.get(id(2)))!.anchorState).toMatchObject({ state: 'awaiting_epoch', anchorReason: 'anchor_not_yet_published' });
    });
  },
);

describe.each(sqlBackends.map((b) => [b.name, b] as const))('a stripped anchor on %s', (_name, backend) => {
  jest.setTimeout(60_000);
  let tzun: Tzun;
  let records: EvidenceEnvelope[];
  let evm: AnchorPublication;

  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev', ...(await backend.fresh()) });
    records = [];
    for (let i = 1; i <= 2; i++) records.push((await tzun.capture(decision(i))).envelope);
    [evm] = await cutEpoch(tzun, 'default', 2, 1, ['evm-calldata/1']);
    evm = await finalize(storesOf(tzun).anchors, evm, 1, 100);
  });
  afterEach(() => tzun.close());
  afterAll(() => backend.dispose());

  const readOf = async (i: number) => (await tzun.get(records[i].payload.evidenceId))!;
  const fill = (done: boolean) =>
    storesOf(tzun).anchors.updateAnchorPublication(evm.id, {
      fillProgress: { from: 0, anchorLeaf: done ? 1 : 0, leafIndex: null, filled: done ? 2 : 1, total: 2, done },
    });

  it('a record the finished fill left without an anchor is a finding and anchor_invalid, never a pending state', async () => {
    await attachAnchor(tzun, records[1], await storeAnchor(tzun, records[1], evm));
    await fill(true);
    const read = await readOf(0);
    expect(read.logFindings).toEqual(['anchor_stripped']);
    expect(read.anchorState).toEqual({
      state: 'anchor_invalid',
      origin: read.logPosition!.origin,
      leafIndex: 0,
      anchorValid: null,
      anchorReason: 'absent',
      publication: { kind: 'evm-calldata/1', chain: SEPOLIA, transactionId: attempt(1).txHash, blockNumber: 100 },
    });
    const filled = await readOf(1);
    expect(filled.anchorState).toMatchObject({ state: 'anchored' });
    expect(filled).not.toHaveProperty('logFindings');

    // verify() reads the store the same way: no "not yet" for the stripped
    // record but a spec reason, `absent`, with the finding beside it, so a
    // reader of anchorValid and anchorReason alone can tell
    // it from an anchor that is not decided.
    const stripped = await tzun.verify(records[0].payload.evidenceId);
    expect(stripped).toMatchObject({ anchorValid: null, anchorReason: 'absent', logFindings: ['anchor_stripped'] });
    const kept = await tzun.verify(records[1].payload.evidenceId);
    expect(kept).toMatchObject({ anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(kept).not.toHaveProperty('logFindings');
  });

  it('while the fill is running, a record whose payload was altered is anchor_invalid: it can never be anchored as stored', async () => {
    await fill(false);
    await rewriteStoredEnvelope(tzun.getStorage(), records[0].payload.evidenceId, (e) => {
      e.payload.reason = 'altered before the fill reached it';
    });
    const read = await readOf(0);
    expect(read.verdict.digest).toMatchObject({ status: 'invalid', reason: 'digest_mismatch' });
    expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: null, anchorReason: 'anchor_not_yet_published' });
    // The record beside it waits for the fill.
    expect((await readOf(1)).anchorState).toMatchObject({ state: 'awaiting_finality', anchorReason: 'anchor_not_yet_published' });
  });

  it('while the fill is running, a record without an anchor is still awaiting it', async () => {
    await fill(false);
    const read = await readOf(0);
    expect(read).not.toHaveProperty('logFindings');
    expect(read.anchorState).toMatchObject({ state: 'awaiting_finality', anchorValid: null, anchorReason: 'anchor_not_yet_published' });
    // tzun-anchor/1 §10.9: a store-aware verify says the same.
    expect(await tzun.verify(records[0].payload.evidenceId)).toMatchObject({ anchorValid: null, anchorReason: 'anchor_not_yet_published' });
  });
});

describe.each(sqlBackends.map((b) => [b.name, b] as const))("get() binds a record's anchor to a P the store published, on %s", (_name, backend) => {
  jest.setTimeout(60_000);
  let tzun: Tzun;
  let records: EvidenceEnvelope[];
  let first: AnchorPublication;
  let second: AnchorPublication;

  /** Epoch 1 covers record 1; epoch 2 covers records 1 and 2 (its anchor checkpoint includes epoch 1's leaf). */
  beforeEach(async () => {
    tzun = await Tzun.init({ mode: 'dev', ...(await backend.fresh()) });
    records = [];
    for (let i = 1; i <= 3; i++) records.push((await tzun.capture(decision(i))).envelope);
    [first] = await cutEpoch(tzun, 'default', 1, 1, ['evm-calldata/1']);
    [second] = await cutEpoch(tzun, 'default', 2, 2, ['evm-calldata/1']);
  });
  afterEach(() => tzun.close());
  afterAll(() => backend.dispose());

  const readOf = async (i: number) => (await tzun.get(records[i].payload.evidenceId))!;

  it('a record filled from a later final publication than the earliest one covering it is anchored', async () => {
    const { anchors } = storesOf(tzun);
    // The scheduler fills epoch 2 while epoch 1 is not yet marked final, so
    // epoch 2's fill covers record 1 too; epoch 1 is final by the next read.
    second = await finalize(anchors, second, 2, 101);
    await attachAnchor(tzun, records[0], await storeAnchor(tzun, records[0], second, [evmEntry(2, 101)]));
    first = await finalize(anchors, first, 1, 100);

    const read = await readOf(0);
    // The earliest final publication decides the stage; the record's P is the other one's.
    expect(read.anchorState).toMatchObject({ state: 'anchored', publication: { transactionId: attempt(1).txHash, blockNumber: 100 } });
    expect(read).not.toHaveProperty('logFindings');
  });

  it("a P of the store's that is not final yet does not anchor a record: anchor_invalid, and the unpublished checkpoint is the finding", async () => {
    const { anchors } = storesOf(tzun);
    await finalize(anchors, first, 1, 100);
    await submit(anchors, second, 2);
    await attachAnchor(tzun, records[0], await storeAnchor(tzun, records[0], second, [evmEntry(2, 101)]));
    const read = await readOf(0);
    expect(read.anchorState).toMatchObject({ state: 'anchor_invalid', anchorValid: null, anchorReason: 'publication_not_checked' });
    expect(read.logFindings).toEqual(['anchor_checkpoint_not_published']);
  });

  it('AnchorStore.getAnchorPublicationAt reads the publication of a kind at an anchor size', async () => {
    const { anchors } = storesOf(tzun);
    expect(await anchors.getAnchorPublicationAt('evm-calldata/1', 1)).toMatchObject({ id: first.id, anchorSize: 1, p: first.p, state: 'prepared' });
    expect(await anchors.getAnchorPublicationAt('evm-calldata/1', 2)).toMatchObject({ id: second.id, anchorSize: 2, p: second.p });
    expect(await anchors.getAnchorPublicationAt('evm-calldata/1', 3)).toBeNull();
    expect(await anchors.getAnchorPublicationAt('rfc3161/1', 1)).toBeNull();
  });
});

describe.each(sqlBackends.map((b) => [b.name, b] as const))('AnchorStore.getLeafAnchorProgress on %s', (_name, backend) => {
  jest.setTimeout(120_000);
  let tzun: Tzun;
  let store: Record<string, unknown>;
  let logId: number;
  let ids: string[];

  beforeEach(async () => {
    store = await backend.fresh();
    tzun = await Tzun.init({ mode: 'dev', ...store });
    ids = [];
    for (let i = 1; i <= 4; i++) ids.push((await tzun.capture(decision(i))).envelope.payload.evidenceId);
    logId = (await storesOf(tzun).logs.getEvidenceLog('default'))!.logId;
  });
  afterEach(() => tzun.close());
  afterAll(() => backend.dispose());

  const progress = (leafIndex: number) => storesOf(tzun).anchors.getLeafAnchorProgress(logId, leafIndex);

  it('is null on a store with no anchor log, and names no epoch for a leaf none covers', async () => {
    expect(await progress(0)).toBeNull();
    await storesOf(tzun).anchors.ensureStoreLog('anchors');
    expect(await progress(0)).toEqual({ anchorLeafIndex: null, publications: [] });
  });

  it('per kind: the earliest final publication, else the furthest along; superseded ones never', async () => {
    const { anchors } = storesOf(tzun);
    const [e1] = await cutEpoch(tzun, 'default', 1, 1, ['evm-calldata/1']); // anchor leaf 0
    const [e2, t2] = await cutEpoch(tzun, 'default', 2, 2, ['evm-calldata/1', 'rfc3161/1']); // anchor leaf 1
    const [e3] = await cutEpoch(tzun, 'default', 3, 3, ['evm-calldata/1']); // anchor leaf 2

    // Leaf 0 is first committed at anchor leaf 0; every epoch covers it.
    expect(await progress(0)).toMatchObject({
      anchorLeafIndex: 0,
      publications: [
        { id: e1.id, kind: 'evm-calldata/1', state: 'prepared', anchorSize: 1 },
        { id: t2.id, kind: 'rfc3161/1', state: 'prepared', anchorSize: 2 },
      ],
    });

    const sent1 = await submit(anchors, e1, 1, 1);
    await include(anchors, await submit(anchors, e2, 2, 2), 2, 200);
    // Included beats submitted, whatever the epoch.
    expect((await progress(0))!.publications[0]).toMatchObject({ id: e2.id, state: 'included', transactionId: attempt(2).txHash, blockNumber: 200 });
    expect((await progress(0))!.publications[0]).not.toHaveProperty('attempts');

    await anchors.updateAnchorPublication(sent1.id, {
      state: 'superseded',
      attempts: sent1.attempts.map((a) => ({ ...a, broadcast: 'rejected' as const })),
    });
    await finalize(anchors, e3, 3, 300);
    await anchors.updateAnchorPublication(t2.id, { state: 'obtained', token: 'dG9rZW4=', genTime: '2026-09-25T10:00:00Z' });
    // The earliest final one: e3 is final, e2 only included.
    expect(await progress(0)).toMatchObject({
      anchorLeafIndex: 0,
      publications: [
        { id: e3.id, state: 'finalized', transactionId: attempt(3).txHash, blockNumber: 300 },
        { id: t2.id, kind: 'rfc3161/1', state: 'obtained', transactionId: null },
      ],
    });
    // Leaf 2 is first committed at anchor leaf 2: only e3 covers it.
    expect(await progress(2)).toMatchObject({ anchorLeafIndex: 2, publications: [{ id: e3.id }] });
    // Leaf 3 is in no checkpoint yet.
    expect(await progress(3)).toEqual({ anchorLeafIndex: null, publications: [] });
  });

  it('reads the fill progress', async () => {
    const { anchors } = storesOf(tzun);
    const [evm] = await cutEpoch(tzun, 'default', 1, 1, ['evm-calldata/1']);
    const final = await finalize(anchors, evm, 1, 100);
    await anchors.updateAnchorPublication(final.id, { fillProgress: { done: true, filled: 1, total: 1 } });
    expect((await progress(0))!.publications[0].fillProgress).toEqual({ done: true, filled: 1, total: 1 });
  });

  it('get() reads the anchoring tables through it alone, never by listing them', async () => {
    const { anchors } = storesOf(tzun);
    for (let e = 1; e <= 3; e++) {
      const [evm] = await cutEpoch(tzun, 'default', e, e, ['evm-calldata/1']);
      await finalize(anchors, evm, e, 100 + e);
    }
    const proto = anchorStoreProto(backend);
    const listings = [
      jest.spyOn(proto, 'listLogs'),
      jest.spyOn(proto, 'listLogCheckpoints'),
      jest.spyOn(proto, 'listAnchorPublications'),
      jest.spyOn(proto, 'listLogLeaves'),
    ];
    const reads = jest.spyOn(proto, 'getLeafAnchorProgress');
    try {
      expect((await tzun.get(ids[0]))!.anchorState).toMatchObject({ state: 'awaiting_finality' });
      for (const spy of listings) expect(spy).not.toHaveBeenCalled();
      expect(reads).toHaveBeenCalledTimes(1);
    } finally {
      jest.restoreAllMocks();
    }
  });

  if (backend.name === 'sqlite') {
    it('each publication branch searches the (kind, anchor_size) index; none scans the table', async () => {
      await storesOf(tzun).anchors.ensureStoreLog('anchors');
      const db = new Database(store.dbPath as string, { readonly: true });
      try {
        const sql = (db.prepare("SELECT sql FROM sqlite_master WHERE name = 'anchor_publications'").get() as { sql: string }).sql;
        expect(sql).toContain('UNIQUE (kind, anchor_size)');
        // The statement getLeafAnchorProgress prepares, captured from the store.
        const prepared: string[] = [];
        const realPrepare = Database.prototype.prepare;
        const spy = jest.spyOn(Database.prototype, 'prepare').mockImplementation(function (this: Database.Database, source: string) {
          prepared.push(source);
          return realPrepare.call(this, source);
        });
        try {
          await cutEpoch(tzun, 'default', 1, 1, ['evm-calldata/1']);
          await progress(0);
        } finally {
          spy.mockRestore();
        }
        const covering = prepared.find((s) => s.includes('FROM anchor_publications') && s.includes('UNION ALL'))!;
        const checkpointSql = prepared.find((s) => s.includes('FROM log_checkpoints') && s.includes('LIMIT 1'))!;
        const plan = (source: string, params: Record<string, number>) =>
          (db.prepare(`EXPLAIN QUERY PLAN ${source}`).all(params) as Array<{ detail: string }>).map((r) => r.detail);
        const publicationSteps = plan(covering, { p1: 0 }).filter((d) => d.includes('anchor_publications'));
        expect(publicationSteps.length).toBeGreaterThan(0);
        for (const step of publicationSteps) expect(step).toMatch(/^SEARCH anchor_publications USING .*INDEX .*\(kind=\? AND anchor_size>\?\)/);
        for (const step of plan(checkpointSql, { p1: logId, p2: 0 })) {
          expect(step).toMatch(/^SEARCH log_checkpoints USING (PRIMARY KEY|INDEX)/);
        }
      } finally {
        db.close();
      }
    });
  }
});
