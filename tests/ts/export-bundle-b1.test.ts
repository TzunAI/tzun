/**
 * The `b1` proof bundle export (Bundle §3, §4, §7.7):
 * `Tzun.exportBundle()` writes every slot of `b1`, carries the anchoring
 * material the store holds for an anchored record (each checkpoint's body,
 * the publications of each anchor checkpoint with their heavy material, the
 * subject's anchor into the newest anchored checkpoint, and one direct
 * consistency proof per log), and the `anchorPending` slot for an unanchored
 * one, never a marker in `nonRepudiation`.
 *
 * The anchored stores run the real anchor scheduler on the in-memory EVM
 * chain (tests/ts/helpers/bundle-fixtures.ts), on SQLite always and on
 * Postgres when its legs run.
 */
import { createHash } from 'node:crypto';
import { Transaction, keccak256 } from 'ethers';
import type { TzunConfig } from '@tzun/engine';
import { Tzun, BUNDLE_VERSION, TzunCloudReadUnsupportedError, bundleExitCode, verifyBundle, type ProofBundle } from '../../src/sdk/index';
import { bundleAnchoring } from '../../src/export/bundle';
import { parseCheckpoint } from '../../src/attestation/checkpoint';
import { verifyConsistencyProof, verifyMerkleProof } from '../../src/attestation/merkle';
import { anchorStoreFor, logStoreFor } from '../../src/storage/log-store';
import {
  anchoredStore,
  BUNDLE_CHAIN,
  fakeHeaderSource,
  postgresBundleBackend,
  sqliteBundleBackend,
  type AnchoredStore,
  type BundleBackend,
} from './helpers/bundle-fixtures';

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

function parsed(body: string) {
  const r = parseCheckpoint(body);
  if (!r.ok) throw new Error(`not a checkpoint: ${r.reason}`);
  return r.checkpoint;
}

const backends = [sqliteBundleBackend(), postgresBundleBackend('export_bundle_b1')].filter((b): b is BundleBackend => b !== undefined);

describe.each(backends.map((b) => [b.name, b] as const))('Tzun.exportBundle() on %s', (_name, backend) => {
  jest.setTimeout(120_000);
  let store: AnchoredStore;
  // Epoch 1 anchors r1 and r2; epoch 2 anchors r3 (the chain grew) and the
  // first record of another chain; r4 awaits its epoch.
  let r1: string;
  let r2: string;
  let r3: string;
  let r4: string;

  beforeAll(async () => {
    store = await anchoredStore(await backend.fresh());
    [r1, r2] = await store.capture(2);
    await store.epoch();
    [r3] = await store.capture(1);
    const other = await store.on('other');
    await store.capture(1, other, 'other');
    await store.epoch();
    [r4] = await store.capture(1);
  });

  afterAll(async () => {
    await store.close();
    backend.dispose();
  });

  it('writes every b1 slot, reserved ones null, and survives a JSON round trip (Bundle §3, §4)', async () => {
    const bundle = await store.tzun.exportBundle(r2, { exportedBy: 'auditor-export' });
    expect(bundle.bundleVersion).toBe(BUNDLE_VERSION);
    expect(BUNDLE_VERSION).toBe('b1');
    expect(bundle.profile).toBe('record');
    expect(Object.keys(bundle).sort()).toEqual(
      [
        'anchorPending',
        'anchoring',
        'bundleVersion',
        'chain',
        'credentials',
        'custody',
        'envelope',
        'exporter',
        'extensions',
        'policy',
        'profile',
        'relatedRecords',
        'subject',
      ].sort(),
    );
    expect(bundle.subject).toEqual({ evidenceId: r2, canonicalDigest: bundle.envelope.integrity.canonicalDigest });
    expect(bundle.envelope.payload.evidenceId).toBe(r2);
    expect(bundle.credentials).toBeNull();
    expect(bundle.relatedRecords).toBeNull();
    expect(bundle.policy).toBeNull();
    expect(bundle.extensions).toEqual({ 'witness/1': null });
    expect(bundle.anchorPending).toBeNull();
    expect(bundle.chain).toEqual({
      chainId: 'default',
      predecessor: expect.objectContaining({ evidenceId: r1, sequenceNumber: 1 }),
    });
    // A captured record has no custody ledger rows until a recovery writes one.
    expect(bundle.custody).toMatchObject({ entries: [], offlineTrail: expect.anything() });
    expect(bundle.exporter).toMatchObject({ exportedBy: 'auditor-export', verdict: { status: 'valid' } });
    expect(Date.parse(bundle.exporter.exportedAt)).not.toBeNaN();
    expect(JSON.parse(JSON.stringify(bundle))).toEqual(bundle);
  });

  it('carries the subject\'s checkpoints, the newest anchored ones, their publications and one direct proof per log (Bundle §3, §4, §7.3)', async () => {
    const bundle = await store.tzun.exportBundle(r1);
    const anchor = bundle.envelope.nonRepudiation.anchor!;
    expect(anchor).toBeDefined();
    const logOrigin = parsed(anchor.logCheckpoint).origin;
    const anchorOrigin = await store.anchorOrigin();
    expect(parsed(anchor.anchorCheckpoint).origin).toBe(anchorOrigin);
    expect(Object.keys(bundle.anchoring).sort()).toEqual([anchorOrigin, logOrigin].sort());

    // The evidence log: the subject's own checkpoint (size 2), then the newest
    // anchored one (size 3), which carries the subject's anchor into the
    // newest anchor checkpoint.
    const log = bundle.anchoring[logOrigin];
    expect(log.checkpoints.map((c) => parsed(c.body).size)).toEqual([2, 3]);
    expect(log.checkpoints[0]).toEqual({ body: anchor.logCheckpoint, signatures: [] });
    const newer = log.checkpoints[1];
    const newerCp = parsed(newer.body);

    // The anchor log: the subject's epoch (size 1) and the newest (size 3:
    // two logs grew), each with its finalized EVM publication and heavy material.
    const anchors = bundle.anchoring[anchorOrigin];
    expect(anchors.checkpoints).toHaveLength(2);
    expect(anchors.checkpoints[0].body).toBe(anchor.anchorCheckpoint);
    const [own, newest] = anchors.checkpoints.map((c) => parsed(c.body));
    expect(newest.size).toBeGreaterThan(own.size);
    for (const cp of anchors.checkpoints) {
      expect(cp.signatures).toEqual([]);
      expect(cp.publications).toHaveLength(1);
      const pub = cp.publications![0];
      if (pub.kind !== 'evm-calldata/1') throw new Error('expected an EVM publication');
      expect(keccak256(pub.rawTransaction).toLowerCase()).toBe(pub.transactionId);
      expect(Transaction.from(pub.rawTransaction).data).toBe(`0x${sha256(cp.body)}`);
      expect(pub.publisher).toBe(store.publisher.address.toLowerCase());
      expect(pub.chain).toBe('eip155:31337');
      expect(keccak256(pub.blockHeader!).toLowerCase()).toBe(pub.blockHash);
      expect(Number.isInteger(pub.txIndex)).toBe(true);
      expect(pub.txProof!.length).toBeGreaterThan(0);
    }
    // The envelope's own publication is the first checkpoint's.
    const first = anchors.checkpoints[0].publications![0] as { transactionId: string };
    expect(anchor.publications[0]).toMatchObject({ kind: 'evm-calldata/1', transactionId: first.transactionId });

    // The subject's anchor into the newest checkpoints holds.
    expect(newer.anchorSize).toBe(newest.size);
    expect(verifyMerkleProof(bundle.subject.canonicalDigest, anchor.leafIndex, newerCp.size, newer.logPath!, newerCp.root)).toBe(true);
    expect(verifyMerkleProof(sha256(newer.body), newer.anchorLeafIndex!, newest.size, newer.anchorPath!, newest.root)).toBe(true);
    // Only the newest evidence-log checkpoint carries it; anchor checkpoints never do.
    expect(log.checkpoints[0]).not.toHaveProperty('anchorPath');
    for (const cp of anchors.checkpoints) expect(cp).not.toHaveProperty('anchorPath');

    // One direct proof per log, between the two carried sizes.
    expect(log.consistency).toHaveLength(1);
    expect(log.consistency[0]).toMatchObject({ fromSize: 2, toSize: 3 });
    const ownLog = parsed(log.checkpoints[0].body);
    expect(verifyConsistencyProof(2, 3, log.consistency[0].path, ownLog.root, newerCp.root).valid).toBe(true);
    expect(anchors.consistency).toHaveLength(1);
    expect(anchors.consistency[0]).toMatchObject({ fromSize: own.size, toSize: newest.size });
    expect(verifyConsistencyProof(own.size, newest.size, anchors.consistency[0].path, own.root, newest.root).valid).toBe(true);
  });

  it('carries only the newest checkpoint per log, with the subject\'s anchor into it, for an anchored record whose envelope has no artifact', async () => {
    // A record the fill has not reached, or whose artifact was stripped: no
    // artifact names the record's own checkpoints, so nothing in the bundle
    // could authenticate them, and they are left out.
    const genuine = await store.tzun.exportBundle(r1);
    const envelope = JSON.parse(JSON.stringify(genuine.envelope)) as ProofBundle['envelope'];
    delete (envelope.nonRepudiation as { anchor?: unknown }).anchor;
    const storage = store.tzun.getStorage();
    const { anchoring, anchorPending } = await bundleAnchoring(envelope, logStoreFor(storage), anchorStoreFor(storage));
    expect(anchorPending).toBeNull();
    const logOrigin = parsed(genuine.envelope.nonRepudiation.anchor!.logCheckpoint).origin;
    const anchorOrigin = await store.anchorOrigin();
    expect(Object.keys(anchoring).sort()).toEqual([anchorOrigin, logOrigin].sort());
    // The newest of each log, as the artifact-bearing export carries it.
    expect(anchoring[logOrigin]).toEqual({ checkpoints: [genuine.anchoring[logOrigin].checkpoints[1]], consistency: [] });
    expect(anchoring[anchorOrigin]).toEqual({ checkpoints: [genuine.anchoring[anchorOrigin].checkpoints[1]], consistency: [] });
    expect(anchoring[logOrigin].checkpoints[0].anchorPath).toBeDefined();

    const bundle = { ...genuine, envelope, anchoring, anchorPending };
    const report = await verifyBundle(bundle, { publisherManifest: await store.manifest(), evmHeaderSources: { [BUNDLE_CHAIN]: fakeHeaderSource(store.chain) } });
    expect(report.checks.find((c) => c.id === 'anchor')).toEqual({ id: 'anchor', outcome: 'not-checked', reason: 'absent' });
    expect(report.checks.find((c) => c.id === 'anchor.newer')).toMatchObject({ outcome: 'checked-correct', facts: { treeSize: 3, anchorSize: 3 } });
    expect(report.checks.filter((c) => c.id.startsWith('anchor.consistency'))).toEqual([]);
    expect(bundleExitCode(report)).toBe(0);
  });

  it('carries one checkpoint per log and no proof for a record anchored in the newest epoch', async () => {
    const bundle = await store.tzun.exportBundle(r3);
    const anchor = bundle.envelope.nonRepudiation.anchor!;
    const logOrigin = parsed(anchor.logCheckpoint).origin;
    const anchorOrigin = parsed(anchor.anchorCheckpoint).origin;
    expect(bundle.anchoring[logOrigin]).toEqual({ checkpoints: [{ body: anchor.logCheckpoint, signatures: [] }], consistency: [] });
    expect(bundle.anchoring[anchorOrigin].checkpoints).toHaveLength(1);
    expect(bundle.anchoring[anchorOrigin].checkpoints[0].body).toBe(anchor.anchorCheckpoint);
    expect(bundle.anchoring[anchorOrigin].consistency).toEqual([]);
  });

  it('exports an unanchored record with anchorPending and no marker in nonRepudiation (Bundle §7.7)', async () => {
    const bundle = await store.tzun.exportBundle(r4);
    const logs = logStoreFor(store.tzun.getStorage())!;
    const position = (await logs.getEvidenceLogPosition(r4))!;
    const [leaf] = await logs.listLogLeaves(position.logId, position.leafIndex, position.leafIndex + 1);
    expect(bundle.anchorPending).toEqual({ origin: position.origin, leafIndex: position.leafIndex, since: leaf.loggedAt });
    expect(bundle.anchoring).toEqual({});
    expect(bundle.envelope.nonRepudiation).not.toHaveProperty('anchor');
    expect(JSON.stringify(bundle.envelope.nonRepudiation ?? {})).not.toMatch(/anchor|pending/i);
  });

  it('exports a record whose publication is sent and not final as pending (Bundle §7.7)', async () => {
    const [r5] = await store.capture(1);
    const report = await store.tzun.anchorNow({ force: true });
    expect(report.epoch).toBeTruthy();
    store.chain.mine(1);
    await store.tzun.anchorNow();
    const bundle = await store.tzun.exportBundle(r5);
    expect(bundle.anchorPending).toMatchObject({ leafIndex: 4 });
    expect(bundle.anchoring).toEqual({});
    expect(bundle.envelope.nonRepudiation).not.toHaveProperty('anchor');
    // Settled, the same record exports anchored.
    for (let i = 0; i < 10; i++) {
      store.chain.mine(3);
      await store.tzun.anchorNow();
    }
    const settled = await store.tzun.exportBundle(r5);
    expect(settled.anchorPending).toBeNull();
    expect(settled.envelope.nonRepudiation.anchor).toBeDefined();
  });

  it('refuses an unknown evidence id', async () => {
    await expect(store.tzun.exportBundle('00000000-0000-4000-8000-000000000000')).rejects.toThrow(/not found/);
  });

  // Last: it leaves an epoch in flight.
  it('chooses the newest anchor by the kind that decides the subject: an RFC 3161 token alone at a newer size is not it', async () => {
    const storage = store.tzun.getStorage();
    const anchors = anchorStoreFor(storage)!;
    const anchorLog = (await logStoreFor(storage)!.listLogs()).find((l) => l.kind === 'anchors')!;
    const settled = (await anchors.getLastFinalAnchorSize('evm-calldata/1'))!;
    const before = await store.tzun.exportBundle(r1);
    const anchorOrigin = await store.anchorOrigin();
    const newestSize = (b: ProofBundle) => {
      const cps = b.anchoring[anchorOrigin].checkpoints;
      return parsed(cps[cps.length - 1].body).size;
    };
    expect(newestSize(before)).toBe(settled);

    // A newer epoch whose EVM publication is sent and not final, and an
    // RFC 3161 publication of the same checkpoint that has its token.
    await store.capture(1);
    expect((await store.tzun.anchorNow({ force: true })).epoch).toBeTruthy();
    const size = (await anchors.getLastLogCheckpoint(anchorLog.logId))!.treeSize;
    expect(size).toBeGreaterThan(settled);
    const evm = (await anchors.getAnchorPublicationAt('evm-calldata/1', size))!;
    expect(['prepared', 'submitted', 'included']).toContain(evm.state);
    const tsa = await anchors.insertAnchorPublication({ epochId: evm.epochId, anchorSize: size, p: evm.p, kind: 'rfc3161/1' });
    await anchors.updateAnchorPublication(tsa.id, { state: 'obtained', token: Buffer.from('a token').toString('base64'), genTime: new Date().toISOString() });
    expect(await anchors.getLastFinalAnchorSize('rfc3161/1')).toBe(size);

    const after = await store.tzun.exportBundle(r1);
    expect(newestSize(after)).toBe(settled);
    expect(after.anchoring).toEqual(before.anchoring);
  });
});

describe('Tzun.exportBundle() on a store that does not anchor', () => {
  const sqlite = sqliteBundleBackend();
  afterAll(() => sqlite.dispose());

  it.each([
    ['memory', async () => ({})],
    ['sqlite', () => sqlite.fresh()],
  ])('on %s: no anchoring material and no pending slot', async (_name, keys) => {
    const tzun = await Tzun.init({ mode: 'dev', ...(await keys()) } as TzunConfig);
    try {
      const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { x: 1 }, action: 'approved', reason: 'r' });
      const bundle: ProofBundle = await tzun.exportBundle(r.envelope.payload.evidenceId);
      expect(bundle.anchoring).toEqual({});
      expect(bundle.anchorPending).toBeNull();
      expect(bundle.chain).toEqual({ chainId: 'default', predecessor: null });
    } finally {
      await tzun.close();
    }
  });
});

describe('bundleAnchoring() over tables that contradict each other', () => {
  it('names the leaf a pending record\'s position points at when the log holds none there', async () => {
    const position = { logId: 7, origin: 'test.bundle.tzun/0123/evidence/64656661756c74', chainId: 'default', leafIndex: 41, leafDigest: 'ab'.repeat(32), source: 'capture' };
    const logs = { getEvidenceLogPosition: async () => position, listLogLeaves: async () => [] };
    const anchors = { getLeafAnchorProgress: async () => ({ anchorLeafIndex: null, publications: [] }) };
    const envelope = { payload: { evidenceId: '00000000-0000-4000-8000-000000000001' } };
    await expect(bundleAnchoring(envelope as never, logs as never, anchors as never)).rejects.toThrow(
      'the evidence log test.bundle.tzun/0123/evidence/64656661756c74 names leaf 41 for the record, and holds no leaf there',
    );
  });
});

describe('Tzun.exportBundle() on the cloud transport', () => {
  it('refuses rather than export a bundle with no anchoring material, and asks the server nothing', async () => {
    const urls: string[] = [];
    const tzun = await Tzun.init({
      mode: 'dev',
      apiKey: 'tzk_test_bundle',
      apiUrl: 'https://api.example.invalid',
      attestation: { require: [] },
      _httpFetchFn: async (url: string) => {
        urls.push(url);
        throw new Error('no request is expected');
      },
    } as TzunConfig);
    try {
      await expect(tzun.exportBundle('00000000-0000-4000-8000-000000000000')).rejects.toBeInstanceOf(TzunCloudReadUnsupportedError);
      expect(urls).toEqual([]);
    } finally {
      await tzun.close();
    }
  });
});
