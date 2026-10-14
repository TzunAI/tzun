/**
 * Cutting an epoch (tzun-anchor/1 §5, §6, §11): a checkpoint for every source
 * log of a kind the scheduler anchors that grew, each proved consistent with
 * the log's anchored checkpoint before anything is persisted, their digests
 * appended to the anchor log in bytewise origin order, and the anchor
 * checkpoint whose digest is P.
 *
 * Proofs and roots come from the compact range stored at the earlier size
 * plus the leaves after it, so an epoch never re-reads a log below its
 * anchored size. The generator (`extendCompactRange`) and the verifier
 * (`verifyConsistencyProof`) are separate implementations: a generator bug
 * cannot certify its own output.
 */
import {
  checkOriginBinding,
  checkpointDigest,
  evidenceLogOrigin,
  formatCheckpoint,
  isPlatformNamespace,
  parseOrigin,
} from '../attestation/checkpoint';
import { extendCompactRange, verifyConsistencyProof } from '../attestation/merkle';
import {
  ANCHOR_LOG_KIND,
  EVIDENCE_LOG_KIND,
  type AnchorStore,
  type LogRecord,
  type LogStore,
  type NewLogCheckpoint,
  type EpochWrite,
} from '../storage/log-store';
import { AnchorTrustError, type AnchorLogTrust, type ExplainedRange } from './explain';

/** One source log's new checkpoint in an epoch. */
export interface EpochMember {
  log: LogRecord;
  /** The size it was last anchored at (0 for none). */
  anchoredSize: number;
  checkpoint: NewLogCheckpoint;
}

/** A source log left out of the epoch, and why. */
export interface RefusedLog {
  origin: string;
  reason: 'log_inconsistent_with_anchor' | 'origin_not_in_domain' | 'log_not_dense';
  detail: string;
}

export interface EpochPlan {
  write: EpochWrite;
  epochId: number;
  anchorSize: number;
  p: string;
  members: EpochMember[];
  refused: RefusedLog[];
}

const byteOrder = (a: string, b: string): number => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

/** The name a platform source log has: an opaque key, 32 lowercase hex (tzun-anchor/1 §4.3.3). */
const PLATFORM_LOG_NAME = /^[0-9a-f]{32}$/;

/**
 * The origin a source log must have, for the log the store reports.
 *
 * An SDK evidence log is `<prefix>/evidence/<chain segment>` (tzun-anchor/1
 * §4.3.2), the one origin its chain id names. A platform log is named by an
 * opaque key, 32 lowercase hex, under `log.tzun.ai` or `test.log.tzun.ai`
 * (tzun-anchor/1 §4.3.3, §4.3.4), so its origin names no chain whatever the
 * store reports: its evidence logs report `chainId: null` in a view that spans
 * tenants, whose chain ids are unique only per tenant, or a chain id in a view
 * of one tenant. Either way the rule is the verifier's (tzun-anchor/1 §10.3
 * step 2b): the log is in the domain, and the chain is unchecked. An evidence
 * log that reports a chain id under any other name is held to the SDK form.
 * Every other log's origin is the store's.
 */
export function expectedOrigin(log: LogRecord, domainPrefix: string): string {
  if (log.kind !== EVIDENCE_LOG_KIND || log.chainId === null) return log.origin;
  const parsed = parseOrigin(log.origin);
  if (parsed?.kind === 'log' && isPlatformNamespace(parsed.namespace) && PLATFORM_LOG_NAME.test(parsed.name)) return log.origin;
  return evidenceLogOrigin(domainPrefix, log.chainId);
}

/**
 * Plan the next epoch: nothing is written. Returns null when no source log
 * grew consistently (there are no empty epochs).
 *
 * The plan never trusts the anchor log's latest checkpoint row. It builds on
 * `explained`: the anchor log explained above the published size B, whose base
 * the scheduler authenticated by its publication's signed transaction. Each
 * member grows from its last anchored checkpoint, authenticated the same way
 * (rule e of `AnchorLogTrust.explain`), and the anchor log is extended from B's
 * compact range over the explained leaves and then the new digests, so the
 * anchor checkpoint's consistency proof runs from B, the size the epoch guard
 * fences on (tzun-anchor/1 §5).
 *
 * @param publishedAnchorSize - B, the anchor size of the last publication
 *   that was broadcast and authenticated (every one but a superseded one, or
 *   the one about to be), or null. `explained` must start there.
 */
export async function planEpoch(input: {
  logs: LogStore;
  anchors: AnchorStore;
  domainPrefix: string;
  anchorOrigin: string;
  chain: string;
  forced: boolean;
  publishedAnchorSize: number | null;
  explained: ExplainedRange;
  trust: Pick<AnchorLogTrust, 'anchors' | 'lastAnchored'>;
}): Promise<{ plan: EpochPlan | null; refused: RefusedLog[] }> {
  const { logs, domainPrefix, anchorOrigin, explained, trust } = input;
  if (explained.base.size !== (input.publishedAnchorSize ?? 0)) {
    throw new Error(`the anchor log was explained from size ${explained.base.size}, not the published size ${input.publishedAnchorSize ?? 0}`);
  }
  const refused: RefusedLog[] = [];
  const members: EpochMember[] = [];

  for (const log of await logs.listLogs()) {
    if (!trust.anchors(log)) continue;
    const { size, leafCount } = await logs.getLogSize(log.logId);
    // The checkpoint the log grows from must be the one the anchor log
    // committed to (rule e). One that is not is never built on: the log is
    // left out, and the others go on.
    let anchored: Awaited<ReturnType<typeof trust.lastAnchored>>;
    try {
      anchored = await trust.lastAnchored(log, explained);
    } catch (err) {
      if (!(err instanceof AnchorTrustError)) throw err;
      refused.push({ origin: log.origin, reason: 'log_inconsistent_with_anchor', detail: err.message });
      continue;
    }
    const m = anchored?.treeSize ?? 0;
    if (size <= m) continue;
    if (leafCount !== size) {
      refused.push({ origin: log.origin, reason: 'log_not_dense', detail: `${leafCount} leaves below size ${size}` });
      continue;
    }
    // The origin the store computed in SQL must be the one the wire spec names.
    const binding = checkOriginBinding(anchorOrigin, log.origin, log.kind === EVIDENCE_LOG_KIND ? log.chainId : undefined);
    if (!binding.ok || expectedOrigin(log, domainPrefix) !== log.origin) {
      refused.push({ origin: log.origin, reason: 'origin_not_in_domain', detail: binding.ok ? 'origin differs from the evidence origin' : binding.reason });
      continue;
    }
    const leaves = await logs.listLogLeaves(log.logId, m, size);
    const ext = extendCompactRange({ size: m, hashes: anchored?.compactRange ?? [] }, leaves.map((l) => l.leafDigest));
    let proof: string[] | null = null;
    if (anchored) {
      proof = ext.consistencyProof ?? [];
      const verified = verifyConsistencyProof(m, size, proof, anchored.root, ext.root);
      if (!verified.valid) {
        refused.push({ origin: log.origin, reason: 'log_inconsistent_with_anchor', detail: `PROOF(${m}, ${size}): ${verified.reason}` });
        continue;
      }
    }
    const body = formatCheckpoint(log.origin, size, ext.root);
    members.push({
      log,
      anchoredSize: m,
      checkpoint: {
        logId: log.logId,
        treeSize: size,
        root: ext.root,
        body,
        bodyDigest: checkpointDigest(body),
        compactRange: ext.range.hashes,
        prevAnchoredSize: anchored ? m : null,
        consistencyProof: proof,
        anchorLeafIndex: null,
        epochId: null,
      },
    });
  }
  if (members.length === 0) return { plan: null, refused };

  members.sort((a, b) => byteOrder(a.log.origin, b.log.origin));
  const anchorLeaves = explained.size;
  // One more than the epoch the anchor log's current size closes: the last
  // explained epoch, or the published one when nothing lies above it.
  const epochId = explained.lastEpochId + 1;
  members.forEach((m, i) => {
    m.checkpoint.anchorLeafIndex = anchorLeaves + i;
    m.checkpoint.epochId = epochId;
  });
  const newDigests = members.map((m) => m.checkpoint.bodyDigest);
  const base = explained.base;
  const ext = extendCompactRange(
    { size: base.size, hashes: base.range },
    [...explained.leaves.map((l) => l.leafDigest), ...newDigests],
  );
  const anchorSize = anchorLeaves + members.length;

  // PROOF(B, N_E): from the published size, over the leaves of any
  // superseded or unsigned epoch between and then this epoch's.
  let anchorProof: string[] | null = null;
  const published = input.publishedAnchorSize;
  if (published !== null) {
    anchorProof = ext.consistencyProof ?? [];
    if (!verifyConsistencyProof(published, anchorSize, anchorProof, base.root as string, ext.root).valid) {
      throw new Error(`the anchor log at ${anchorSize} is not consistent with its published size ${published}`);
    }
  }
  const anchorLogId = (await input.anchors.ensureStoreLog(ANCHOR_LOG_KIND)).logId;
  const anchorBody = formatCheckpoint(anchorOrigin, anchorSize, ext.root);
  const p = checkpointDigest(anchorBody);
  const write: EpochWrite = {
    leaves: [
      {
        logId: anchorLogId,
        // One leaf per (origin, size): the source reference is both, so the
        // tables refuse a second append of the same pair.
        leaves: members.map((m, i) => ({
          leafIndex: anchorLeaves + i,
          leafDigest: m.checkpoint.bodyDigest,
          sourceRef: `${m.log.origin}\n${m.checkpoint.treeSize}`,
        })),
      },
    ],
    checkpoints: [
      ...members.map((m) => m.checkpoint),
      {
        logId: anchorLogId,
        treeSize: anchorSize,
        root: ext.root,
        body: anchorBody,
        bodyDigest: p,
        compactRange: ext.range.hashes,
        prevAnchoredSize: published,
        consistencyProof: anchorProof,
        anchorLeafIndex: null,
        epochId,
      },
    ],
    publications: [{ epochId, anchorSize, p, kind: 'evm-calldata/1', chain: input.chain, forced: input.forced }],
  };
  return { plan: { write, epochId, anchorSize, p, members, refused }, refused };
}
