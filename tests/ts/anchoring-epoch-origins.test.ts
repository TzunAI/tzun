/**
 * Which source logs `planEpoch` takes into an epoch, by origin (tzun-anchor/1
 * §4.3, §10.3 step 2b).
 *
 * The platform keeps its logs in its own tables and hands the scheduler a
 * `LogStore` over them. Its origins are opaque, `<ns>/<deploymentId>/<32-hex
 * key>` under `log.tzun.ai` or `test.log.tzun.ai`, and a view that spans
 * tenants reports its evidence logs with `chainId: null`, because chain ids
 * are unique only per tenant. `planEpoch` must anchor those logs, under both
 * namespaces, and must keep refusing an SDK evidence log whose origin is not
 * the one its chain id names, and a platform evidence log that reports a chain
 * id under a name that is not an opaque key.
 *
 * The stores here are plain in-memory fakes of the reads `planEpoch` makes:
 * the SDK's SQL tables refuse a platform origin, which is the point.
 */
import { createHash } from 'node:crypto';
import { expectedOrigin, planEpoch } from '../../src/anchoring/epoch';
import { AnchorLogTrust } from '../../src/anchoring/explain';
import {
  anchorLogOrigin,
  checkOriginBinding,
  evidenceLogOrigin,
  parseCheckpoint,
  sourceLogOrigin,
} from '../../src/attestation/checkpoint';
import type { AnchorStore, LogLeaf, LogRecord, LogStore } from '../../src/storage/log-store';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');
const key = (label: string): string => hex(label).slice(0, 32);

const DEPLOYMENT = 'f00523049761d0dca10b587b268c61e0';

interface FakeLog {
  origin: string;
  kind: string;
  chainId: string | null;
  leaves: number;
}

/** The reads planEpoch makes, over logs that have never been anchored. */
function fakeStores(domainPrefix: string, specs: FakeLog[]): { logs: LogStore; anchors: AnchorStore } {
  const records: LogRecord[] = specs.map((s, i) => ({ logId: i + 1, origin: s.origin, kind: s.kind, chainId: s.chainId, createdAt: '2026-09-26T00:00:00.000Z' }));
  const leaves = new Map<number, LogLeaf[]>(
    specs.map((s, i) => [
      i + 1,
      Array.from({ length: s.leaves }, (_, j) => ({
        logId: i + 1,
        leafIndex: j,
        leafDigest: hex(`${s.origin}#${j}`),
        sourceRef: `${s.origin}#${j}`,
        source: 'capture' as const,
        loggedAt: '2026-09-26T00:00:00.000Z',
      })),
    ]),
  );
  const anchorLog: LogRecord = { logId: 999, origin: anchorLogOrigin(domainPrefix), kind: 'anchors', chainId: null, createdAt: '2026-09-26T00:00:00.000Z' };
  const logs = {
    listLogs: async () => records,
    getLogSize: async (logId: number) => {
      const n = leaves.get(logId)?.length ?? 0;
      return { size: n, leafCount: n };
    },
    listLogLeaves: async (logId: number, from: number, to: number) => (leaves.get(logId) ?? []).filter((l) => l.leafIndex >= from && l.leafIndex < to),
  } as Partial<LogStore> as LogStore;
  const anchors = {
    getLastAnchoredCheckpoint: async () => null,
    ensureStoreLog: async () => anchorLog,
    getLastLogCheckpoint: async () => null,
    getLogCheckpoint: async () => null,
  } as Partial<AnchorStore> as AnchorStore;
  return { logs, anchors };
}

async function plan(domainPrefix: string, specs: FakeLog[]) {
  const { logs, anchors } = fakeStores(domainPrefix, specs);
  // The kinds the platform anchors: its evidence logs, and its audit and
  // custody logs, whose leaves its tables bind to their rows.
  const trust = new AnchorLogTrust({
    logs,
    anchors,
    anchorLogId: 999,
    anchorOrigin: anchorLogOrigin(domainPrefix),
    sourceLogKinds: ['evidence', 'custody', 'audit'],
    expectedOrigin: (log) => expectedOrigin(log, domainPrefix),
  });
  // Nothing published, and an empty anchor log: the epoch starts from size 0.
  const explained = await trust.explain(await trust.base(0, null));
  return planEpoch({
    logs,
    anchors,
    domainPrefix,
    anchorOrigin: anchorLogOrigin(domainPrefix),
    chain: 'eip155:11155111',
    forced: false,
    publishedAnchorSize: null,
    explained,
    trust,
  });
}

describe.each([
  ['production', `log.tzun.ai/${DEPLOYMENT}`],
  ['test', `test.log.tzun.ai/${DEPLOYMENT}`],
])('planEpoch over a platform deployment in the %s namespace', (_ns, prefix) => {
  const tenantA = sourceLogOrigin(prefix, key('tenant a, chain default'));
  const tenantB = sourceLogOrigin(prefix, key('tenant b, chain default'));
  const custody = sourceLogOrigin(prefix, key('tenant a, custody'));
  const audit = sourceLogOrigin(prefix, key('audit'));

  it('anchors every evidence log that names no chain, beside the per-scope and domain logs', async () => {
    const { plan: p, refused } = await plan(prefix, [
      { origin: tenantA, kind: 'evidence', chainId: null, leaves: 3 },
      { origin: tenantB, kind: 'evidence', chainId: null, leaves: 1 },
      { origin: custody, kind: 'custody', chainId: null, leaves: 2 },
      { origin: audit, kind: 'audit', chainId: null, leaves: 4 },
    ]);
    expect(refused).toEqual([]);
    expect(p).not.toBeNull();
    // Bytewise origin order, one anchor leaf each, and each checkpoint names its own opaque origin.
    const origins = [tenantA, tenantB, custody, audit].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    expect(p!.members.map((m) => m.log.origin)).toEqual(origins);
    for (const m of p!.members) {
      const body = parseCheckpoint(m.checkpoint.body);
      expect(body.ok && body.checkpoint.origin).toBe(m.log.origin);
      expect(checkOriginBinding(anchorLogOrigin(prefix), m.log.origin, 'any chain id')).toEqual({ ok: true, namespace: prefix.split('/')[0], chainChecked: false });
    }
    expect(p!.write.leaves[0].leaves.map((l) => l.sourceRef)).toEqual(p!.members.map((m) => `${m.log.origin}\n${m.checkpoint.treeSize}`));
    expect(p!.write.checkpoints[p!.write.checkpoints.length - 1].body.startsWith(`${anchorLogOrigin(prefix)}\n4\n`)).toBe(true);
  });

  it('anchors an opaque evidence log that reports a chain id, with the chain unchecked', async () => {
    // A view of one tenant knows the chain; the origin still names none.
    const { plan: p, refused } = await plan(prefix, [{ origin: tenantA, kind: 'evidence', chainId: 'default', leaves: 2 }]);
    expect(refused).toEqual([]);
    expect(p!.members.map((m) => m.log.origin)).toEqual([tenantA]);
  });

  it('refuses an evidence log that reports a chain id under a name that is not an opaque key', async () => {
    // Only a 32-lowercase-hex name is the platform's; any other is held to the SDK form, which it is not.
    const named = [
      sourceLogOrigin(prefix, 'custody'),
      sourceLogOrigin(prefix, key('upper case').toUpperCase()),
      sourceLogOrigin(prefix, key('one short').slice(0, 31)),
      sourceLogOrigin(prefix, `${key('one long')}0`),
    ];
    const { plan: p, refused } = await plan(prefix, named.map((origin) => ({ origin, kind: 'evidence', chainId: 'default', leaves: 1 })));
    expect(p).toBeNull();
    expect(refused.map((r) => [r.origin, r.reason, r.detail])).toEqual(
      named.map((origin) => [origin, 'origin_not_in_domain', 'origin differs from the evidence origin']),
    );
  });

  it('keeps the SDK rule for an evidence log under the SDK form of origin in a platform namespace', async () => {
    const own = evidenceLogOrigin(prefix, 'default');
    const accepted = await plan(prefix, [{ origin: own, kind: 'evidence', chainId: 'default', leaves: 1 }]);
    expect(accepted.refused).toEqual([]);
    const other = await plan(prefix, [{ origin: own, kind: 'evidence', chainId: 'another chain', leaves: 1 }]);
    expect(other.plan).toBeNull();
    expect(other.refused).toEqual([expect.objectContaining({ origin: own, reason: 'origin_not_in_domain' })]);
  });

  it("refuses a log of another domain, even one that only extends the namespace", async () => {
    const elsewhere = sourceLogOrigin(`${prefix.split('/')[0]}.example/${DEPLOYMENT}`, key('tenant a, chain default'));
    const otherDeployment = sourceLogOrigin(`${prefix.split('/')[0]}/${key('another deployment')}`, key('x'));
    const { plan: p, refused } = await plan(prefix, [
      { origin: elsewhere, kind: 'evidence', chainId: null, leaves: 1 },
      { origin: otherDeployment, kind: 'evidence', chainId: null, leaves: 1 },
    ]);
    expect(p).toBeNull();
    expect(refused.map((r) => [r.origin, r.reason])).toEqual([
      [elsewhere, 'origin_not_in_domain'],
      [otherDeployment, 'origin_not_in_domain'],
    ]);
  });
});

describe('planEpoch over an SDK store', () => {
  const prefix = `local.invalid/${DEPLOYMENT}`;

  it("anchors a chain's evidence log under the origin its chain id names", async () => {
    const { plan: p, refused } = await plan(prefix, [{ origin: evidenceLogOrigin(prefix, 'default'), kind: 'evidence', chainId: 'default', leaves: 2 }]);
    expect(refused).toEqual([]);
    expect(p!.members).toHaveLength(1);
  });

  it('refuses an evidence log whose origin names another chain, or no chain, outside the platform namespaces', async () => {
    const otherChain = evidenceLogOrigin(prefix, 'other');
    const opaque = sourceLogOrigin(prefix, key('opaque'));
    const { plan: p, refused } = await plan(prefix, [
      { origin: otherChain, kind: 'evidence', chainId: 'default', leaves: 1 },
      { origin: opaque, kind: 'evidence', chainId: 'default', leaves: 1 },
    ]);
    expect(p).toBeNull();
    expect(refused.map((r) => [r.origin, r.reason, r.detail])).toEqual([
      [otherChain, 'origin_not_in_domain', 'chain_id_mismatch'],
      [opaque, 'origin_not_in_domain', 'chain_id_mismatch'],
    ]);
  });
});
