/**
 * Bundle §7.3: a record bundle's anchoring is bounded. A
 * record 8,760 epochs old (a year of hourly epochs) exports a bundle whose
 * anchoring section stays under a fixed byte bound: at most two checkpoints
 * per log and one direct consistency proof per log, whatever the number of
 * epochs between them.
 *
 * The first and the last epochs are published and finalized by the real
 * scheduler on the in-memory EVM chain. The 8,758 between them are cut by the
 * scheduler's own epoch planner over a second chain's evidence log, one record
 * and one leaf per epoch, each planned on the anchor log explained above the
 * epoch before it, and persisted as the scheduler persists an epoch, each with
 * an RFC 3161 publication that has its token and no EVM publication: a year of
 * final publications that are not the kind that decides the subject. The
 * export reads the anchoring tables by point queries, and reads leaves a page
 * at a time: those the subject's path and each consistency proof are computed
 * from, which are the subject's log's growth since its epoch and the anchor
 * log's growth since the record's anchor checkpoint.
 *
 * A second case grows the subject's log by 40,000 leaves after its epoch.
 * The export reads them a page at a time and gives the event loop a turn
 * between pages, so a server exporting an old record from a busy store keeps
 * serving. SQLite only: the bounds are the exporter's, and the other suites
 * run it on Postgres.
 */
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import { expectedOrigin, planEpoch } from '../../src/anchoring/epoch';
import { AnchorLogTrust } from '../../src/anchoring/explain';
import { parseCheckpoint } from '../../src/attestation/checkpoint';
import { anchorStoreFor, logStoreFor } from '../../src/storage/log-store';
import { bundleAnchoring, LEAF_PAGE } from '../../src/export/bundle';
import { verifyBundle, bundleExitCode } from '../../src/sdk/index';
import { anchoredStore, BUNDLE_CHAIN, fakeHeaderSource, sqliteBundleBackend } from './helpers/bundle-fixtures';

const EPOCHS = 8_760;
/**
 * The bound. What the section holds for such a record: two anchor
 * checkpoints, each with one EVM publication (a raw transaction of about
 * 0.2 KB, a header of about 1.2 KB as hex, a trie proof of under 1 KB), two
 * evidence-log checkpoints, the subject's two paths and one consistency proof
 * per log, each ⌈log₂ n⌉ hashes of 66 bytes as JSON. 16 KiB leaves room for
 * the hashes of logs far larger than this one, and none for anything that
 * grows with the number of epochs.
 */
const ANCHORING_BYTE_BOUND = 16 * 1024;
/** A stand-in for an RFC 3161 token: the exporter carries only the tokens of the anchor checkpoints it chooses. */
const TOKEN = Buffer.from('an RFC 3161 token').toString('base64');

const bytes = (value: unknown) => Buffer.byteLength(JSON.stringify(value), 'utf8');

/** `target` with the length of every array each method returns recorded, by method name, one entry per call. */
function counting<T extends object>(target: T, reads: Record<string, number[]>): T {
  return new Proxy(target, {
    get(t, prop, receiver) {
      const value = Reflect.get(t, prop, receiver) as unknown;
      if (typeof value !== 'function') return value;
      return (...args: unknown[]) => {
        const result = (value as (...a: unknown[]) => unknown).apply(t, args);
        const record = (r: unknown) => {
          (reads[String(prop)] ??= []).push(Array.isArray(r) ? r.length : 0);
          return r;
        };
        return result instanceof Promise ? result.then(record) : record(result);
      };
    },
  });
}

/**
 * Run `work` while a 5 ms timer ticks, and return the longest stretch in
 * which the event loop gave the timer no turn, counting to the end of `work`.
 */
async function longestStall(work: () => Promise<unknown>): Promise<number> {
  let last = Date.now();
  let longest = 0;
  const timer = setInterval(() => {
    const now = Date.now();
    longest = Math.max(longest, now - last);
    last = now;
  }, 5);
  try {
    await work();
  } finally {
    clearInterval(timer);
  }
  return Math.max(longest, Date.now() - last);
}

describe('Bundle §7.3: a record 8,760 epochs old', () => {
  jest.setTimeout(600_000);
  const backend = sqliteBundleBackend();
  afterAll(() => backend.dispose());

  it('exports a bundle whose anchoring stays under a fixed byte bound, and verifies', async () => {
    const store = await anchoredStore(await backend.fresh());
    try {
      const [subject] = await store.capture(1);
      await store.epoch();
      const young = await store.tzun.exportBundle(subject);

      const storage = store.tzun.getStorage();
      const logs = logStoreFor(storage)!;
      const anchors = anchorStoreFor(storage)!;
      const state = (await store.tzun.getAnchorState())!;
      const filler = await store.on('filler');
      const anchorLog = await anchors.ensureStoreLog('anchors');
      const trust = new AnchorLogTrust({
        logs,
        anchors,
        anchorLogId: anchorLog.logId,
        anchorOrigin: state.anchorOrigin,
        sourceLogKinds: ['evidence'],
        expectedOrigin: (log) => expectedOrigin(log, state.domainPrefix),
      });
      // Each epoch is planned on the one before it, as the scheduler plans
      // on the published size: the first epoch's, then each RFC 3161 one.
      let previous = { anchorSize: state.lastFinalized!.anchorSize, p: state.lastFinalized!.p };
      for (let i = 0; i < EPOCHS - 2; i++) {
        await store.capture(1, filler, 'filler');
        const explained = await trust.explain(await trust.base(previous.anchorSize, previous.p));
        const { plan } = await planEpoch({
          logs,
          anchors,
          domainPrefix: state.domainPrefix,
          anchorOrigin: state.anchorOrigin,
          chain: BUNDLE_CHAIN,
          forced: false,
          publishedAnchorSize: previous.anchorSize,
          explained,
          trust,
        });
        if (!plan) throw new Error(`epoch ${i + 2} was not planned`);
        const [evm] = plan.write.publications;
        const [tsa] = await anchors.persistEpoch({
          ...plan.write,
          publications: [{ epochId: evm.epochId, anchorSize: evm.anchorSize, p: evm.p, kind: 'rfc3161/1' }],
        });
        await anchors.updateAnchorPublication(tsa.id, { state: 'obtained', token: TOKEN, genTime: new Date().toISOString() });
        previous = { anchorSize: evm.anchorSize, p: evm.p };
      }
      // The subject's chain grows, and the last epoch is published.
      await store.capture(64);
      await store.epoch();

      const old = await store.tzun.exportBundle(subject);
      const anchorOrigin = state.anchorOrigin;
      const anchorSizes = old.anchoring[anchorOrigin].checkpoints.map((c) => {
        const p = parseCheckpoint(c.body);
        return p.ok ? p.checkpoint.size : -1;
      });
      expect(anchorSizes[0]).toBe(1);
      // One leaf per epoch: the filler's 8,758 and the subject's log twice.
      expect(anchorSizes[1]).toBeGreaterThanOrEqual(EPOCHS);
      for (const material of Object.values(old.anchoring)) {
        expect(material.checkpoints.length).toBeLessThanOrEqual(2);
        expect(material.consistency.length).toBeLessThanOrEqual(1);
      }

      expect(bytes(old.anchoring)).toBeLessThan(ANCHORING_BYTE_BOUND);
      expect(bytes(young.anchoring)).toBeLessThan(ANCHORING_BYTE_BOUND);
      // What grows with the epochs is the paths, each at most ⌈log₂ n⌉ + 1 hashes.
      const logBound = (n: number) => Math.ceil(Math.log2(n)) + 1;
      for (const material of Object.values(old.anchoring)) {
        for (const cp of material.checkpoints) {
          if (cp.anchorPath) expect(cp.anchorPath.length).toBeLessThanOrEqual(logBound(cp.anchorSize!));
          if (cp.logPath) expect(cp.logPath.length).toBeLessThanOrEqual(logBound(anchorSizes[1]));
        }
        for (const proof of material.consistency) expect(proof.path.length).toBeLessThanOrEqual(logBound(proof.toSize));
      }

      // The export's reads: no listing of publications or checkpoints, which
      // grow with the epochs, and leaves a page at a time. The leaves read
      // are the subject's log's 64 since its epoch and the anchor log's since
      // the record's anchor checkpoint, each read once.
      const reads: Record<string, number[]> = {};
      const counted = await bundleAnchoring(old.envelope, counting(logs, reads), counting(anchors, reads));
      expect(counted.anchoring).toEqual(old.anchoring);
      expect(reads).not.toHaveProperty('listAnchorPublications');
      expect(reads).not.toHaveProperty('listLogCheckpoints');
      const leafPages = reads.listLogLeaves ?? [];
      expect(Math.max(...leafPages)).toBeLessThanOrEqual(LEAF_PAGE);
      const leavesRead = leafPages.reduce((a, b) => a + b, 0);
      expect(leavesRead).toBeLessThanOrEqual(anchorSizes[1] - anchorSizes[0] + 65 + 2);

      const report = await verifyBundle(old, {
        publisherManifest: await store.manifest(),
        evmHeaderSources: { [BUNDLE_CHAIN]: fakeHeaderSource(store.chain) },
      });
      expect(report.checks.filter((c) => c.outcome === 'checked-wrong')).toEqual([]);
      expect(report.checks.find((c) => c.id === 'anchor.newer')).toMatchObject({ outcome: 'checked-correct' });
      expect(bundleExitCode(report)).toBe(0);
    } finally {
      await store.close();
    }
  });

  it('exports an early record after its log grew by 40,000 leaves a page at a time, without holding the event loop', async () => {
    const GROWTH = 40_000;
    const store = await anchoredStore(await backend.fresh());
    try {
      const [subject] = await store.capture(1);
      await store.epoch();
      // The subject's log grows by leaves written into the store file as
      // captures write them; no record stands behind them, and the export
      // reads only the leaves. The writer is one the store's triggers do not
      // hold: it drops the binding of evidence leaves to stored records
      //, which the next open of the store puts back.
      const storage = store.tzun.getStorage();
      const logs = logStoreFor(storage)!;
      const anchors = anchorStoreFor(storage)!;
      const position = (await logs.getEvidenceLogPosition(subject))!;
      const size = (await anchors.getLastLogCheckpoint(position.logId))!.treeSize;
      const file = new Database(store.storeKeys.dbPath as string);
      try {
        const insert = file.prepare(
          `INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at) VALUES (?, ?, ?, ?, 'capture', ?)`,
        );
        const at = new Date().toISOString();
        file.exec('DROP TRIGGER IF EXISTS log_leaves_bind_record; DROP TRIGGER IF EXISTS log_leaves_logged_now');
        file.transaction(() => {
          for (let i = 0; i < GROWTH; i++) insert.run(position.logId, size + i, randomBytes(32).toString('hex'), `growth-${i}`, at);
        })();
      } finally {
        file.close();
      }
      await store.epoch();

      const reads: Record<string, number[]> = {};
      let bundle: Awaited<ReturnType<typeof bundleAnchoring>> | undefined;
      const stall = await longestStall(async () => {
        bundle = await bundleAnchoring((await store.tzun.get(subject))!.envelope, counting(logs, reads), counting(anchors, reads));
      });
      const material = bundle!.anchoring[position.origin];
      expect(material.checkpoints.map((c) => parseCheckpoint(c.body).ok && (parseCheckpoint(c.body) as { checkpoint: { size: number } }).checkpoint.size)).toEqual([
        size,
        size + GROWTH,
      ]);
      // A page of hashing is a few milliseconds; the whole growth hashed in
      // one turn was seconds.
      expect(stall).toBeLessThan(250);
      // One pass over the growth serves the subject's path and the log's
      // consistency proof, a page at a time.
      const pages = reads.listLogLeaves ?? [];
      expect(Math.max(...pages)).toBeLessThanOrEqual(LEAF_PAGE);
      expect(pages.reduce((a, b) => a + b, 0)).toBeLessThan(GROWTH + 2 * LEAF_PAGE);

      const full = await store.tzun.exportBundle(subject);
      expect(full.anchoring).toEqual(bundle!.anchoring);
      const report = await verifyBundle(full, {
        publisherManifest: await store.manifest(),
        evmHeaderSources: { [BUNDLE_CHAIN]: fakeHeaderSource(store.chain) },
      });
      expect(report.checks.filter((c) => c.outcome === 'checked-wrong')).toEqual([]);
      expect(report.checks.find((c) => c.id === `anchor.consistency[${position.origin}]`)).toMatchObject({
        outcome: 'checked-correct',
        facts: { fromSize: size, toSize: size + GROWTH },
      });
      expect(bundleExitCode(report)).toBe(0);
    } finally {
      await store.close();
    }
  });
});
