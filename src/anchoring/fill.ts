/**
 * Filling `nonRepudiation.anchor` after a publication is final (tzun-anchor/1
 * §8, §11).
 *
 * A finalized publication at anchor size N_E covers the anchor leaves
 * [N_prev, N_E), where N_prev is the anchor size of the finalized publication
 * before it (0 for the first). Leaves of an epoch whose broadcast every node
 * rejected are covered by the next publication, because its anchor
 * checkpoint includes them. Each anchor leaf is one source checkpoint: for an
 * evidence log at size n, anchored after size m, the records at leaf indices
 * [m, n) get their artifact.
 *
 * Nothing the fill builds on is taken from a column because it is stored. The
 * caller has authenticated the publication with the node (`valid === true`),
 * and N_prev is the previous authenticated finalized publication's size, never
 * the stored `fill_progress.from`. The anchor checkpoint at N_prev is
 * authenticated by that publication's P, and every anchor leaf of [N_prev, N_E)
 * is explained (`AnchorLogTrust.explain`): a leaf with no source checkpoint
 * stops the fill instead of being skipped. The stored cursor and `done` are
 * hints, taken only when the record they stand after carries this publication's
 * artifact; otherwise the fill walks the range again, which writes nothing
 * twice. The store checks each record against its leaf before it writes
 * (`anchorFillConflict`) and reports the ones that do not match.
 *
 * Every path comes from the compact range at the earlier size plus the
 * leaves after it, and every artifact is checked by the engine's inclusion
 * verifier before it is written: the fill never stores an artifact that does
 * not verify against its own checkpoints. Writes are fill-only, in chunks of
 * `chunkSize` records per transaction, each chunk recording the progress so a
 * restarted fill resumes where it stopped.
 */
import {
  determineAttestationStatus,
  type AnchorArtifact,
  type AttestationExpectation,
  type EvidenceEnvelope,
} from '@tzun/engine';
import { MERKLE_SPEC, extendCompactRange, verifyMerkleProof } from '../attestation/merkle';
import { ANCHOR_SPEC } from '../attestation/anchor-verify';
import {
  EVIDENCE_LOG_KIND,
  type AnchorFill,
  type AnchorPublication,
  type AnchorStore,
  type LogCheckpoint,
  type LogStore,
} from '../storage/log-store';
import { AnchorTrustError, type AnchorLogTrust, type ExplainedRange } from './explain';

/** The shape of `fill_progress`, the progress a fill persists. */
export interface FillProgress {
  /** The anchor size the fill starts from: the previous finalized publication's. */
  from: number;
  /** The next anchor leaf to fill from. */
  anchorLeaf: number;
  /** Within that anchor leaf's source checkpoint, the next evidence leaf index. */
  leafIndex: number | null;
  /** Records filled so far. */
  filled: number;
  /** Records the publication covers. */
  total: number;
  done: boolean;
  /**
   * Whether the fill recomputed statuses with an expectation that includes a
   * timestamp: the leader's `expectation.timestamp !== false`. Another
   * instance whose own expectation differs raises
   * `anchor_expectation_mismatch`.
   */
  timestampExpected?: boolean;
}

export function readFillProgress(publication: AnchorPublication): FillProgress | null {
  const p = publication.fillProgress as Partial<FillProgress> | null;
  if (!p || typeof p.from !== 'number' || typeof p.anchorLeaf !== 'number') return null;
  return {
    from: p.from,
    anchorLeaf: p.anchorLeaf,
    leafIndex: typeof p.leafIndex === 'number' ? p.leafIndex : null,
    filled: typeof p.filled === 'number' ? p.filled : 0,
    total: typeof p.total === 'number' ? p.total : 0,
    done: p.done === true,
    ...(typeof p.timestampExpected === 'boolean' && { timestampExpected: p.timestampExpected }),
  };
}

export interface FillContext {
  logs: LogStore;
  anchors: AnchorStore;
  anchorLogId: number;
  expectation: AttestationExpectation;
  chunkSize: number;
  /** The scheduler's anchor-log trust: the fill explains its range with it. */
  trust: AnchorLogTrust;
  /** Runs before each chunk is written; the scheduler renews its lease here, and a throw stops the fill. */
  beforeChunk?: () => Promise<void>;
}

/** The authenticated facts of the publication a fill writes, and of the one before it. */
export interface FillAuthority {
  /** The finalized publication before this one, authenticated, or null for the first. */
  previous: { anchorSize: number; p: string } | null;
  /** The sender recovered from this publication's mined transaction: the artifact's `publisher`. */
  sender: string;
}

export interface FillOutcome {
  filled: number;
  alreadyAnchored: number;
  missing: string[];
  /** Records whose stored fields do not match their leaf: skipped, nothing written to them. */
  conflicts: string[];
  done: boolean;
  /** The stored cursor or `done` was not taken, because the record it stands after does not carry this publication's artifact. */
  hintRefused: boolean;
}

/** An inclusion path that does not verify: a bug to surface, never an artifact to write. */
export class AnchorFillIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AnchorFillIntegrityError';
  }
}

/** The evidence checkpoints of an explained range, by anchor leaf, in anchor-leaf order. */
function evidenceCheckpoints(range: ExplainedRange): Array<[number, LogCheckpoint]> {
  return [...range.checkpoints.entries()]
    .filter(([, cp]) => range.logs.get(cp.logId)?.kind === EVIDENCE_LOG_KIND)
    .sort(([a], [b]) => a - b);
}

/**
 * Whether the record behind evidence leaf `leafIndex` of `cp` (anchor leaf
 * `k`) carries this publication's artifact: an anchor naming the
 * publication's anchor checkpoint and that anchor leaf. With no record read
 * on the store (`AnchorStore.getRecordAnchor`), the hint is taken as it is.
 */
async function carriesArtifact(ctx: FillContext, cp: LogCheckpoint, leafIndex: number, k: number, anchorBody: string): Promise<boolean> {
  if (typeof ctx.anchors.getRecordAnchor !== 'function') return true;
  const [leaf] = await ctx.logs.listLogLeaves(cp.logId, leafIndex, leafIndex + 1);
  if (!leaf) return false;
  const anchor = (await ctx.anchors.getRecordAnchor(leaf.sourceRef)) as Partial<AnchorArtifact> | null | undefined;
  return !!anchor && typeof anchor === 'object' && anchor.anchorCheckpoint === anchorBody && anchor.anchorLeafIndex === k && anchor.leafIndex === leafIndex;
}

/**
 * Whether a publication's stored `done` holds: the last record of its range
 * carries its artifact. Cheap: it reads where that record is, not the range.
 * True as well for a range with no evidence checkpoint, and for a store with
 * no record read (`AnchorStore.getRecordAnchor`).
 */
export async function fillDoneHolds(ctx: FillContext, publication: AnchorPublication, authority: FillAuthority): Promise<boolean> {
  if (!readFillProgress(publication)?.done) return false;
  if (typeof ctx.anchors.getRecordAnchor !== 'function') return true;
  const from = authority.previous?.anchorSize ?? 0;
  const checkpoints = await ctx.anchors.listCheckpointsByAnchorLeaf(from, publication.anchorSize);
  for (let i = checkpoints.length - 1; i >= 0; i--) {
    const cp = checkpoints[i];
    if ((await ctx.logs.getLog(cp.logId))?.kind !== EVIDENCE_LOG_KIND) continue;
    const anchorCp = await ctx.anchors.getLogCheckpoint(ctx.anchorLogId, publication.anchorSize);
    return anchorCp !== null && (await carriesArtifact(ctx, cp, cp.treeSize - 1, cp.anchorLeafIndex as number, anchorCp.body));
  }
  return true;
}

/**
 * Fill the records a finalized publication covers. The caller has
 * authenticated `publication` with the node (`valid === true`) and passes the
 * authenticated facts in `authority`.
 *
 * @throws {AnchorTrustError} when the range cannot be explained, or the anchor checkpoint is not the publication's.
 * @throws {AnchorFillIntegrityError} when a path the fill computed does not verify.
 */
export async function fillPublication(ctx: FillContext, publication: AnchorPublication, authority: FillAuthority): Promise<FillOutcome> {
  const outcome: FillOutcome = { filled: 0, alreadyAnchored: 0, missing: [], conflicts: [], done: false, hintRefused: false };
  if (publication.state !== 'finalized' || publication.kind !== 'evm-calldata/1') return outcome;

  const from = authority.previous?.anchorSize ?? 0;
  const to = publication.anchorSize;
  const subject = String(publication.id);
  if (!(to > from)) throw new AnchorTrustError('anchor_publication_unexplained', subject, `Publication ${publication.id} at size ${to} does not follow the finalized size ${from}.`);
  const base = await ctx.trust.base(from, authority.previous?.p ?? null, 'anchor_publication_unexplained', subject);
  const range = await ctx.trust.explain(base, to);
  const anchorCp = range.anchorCheckpoint as LogCheckpoint;
  if (anchorCp.bodyDigest !== publication.p) {
    throw new AnchorTrustError('anchor_publication_unexplained', subject, `Publication ${publication.id}: the anchor checkpoint its leaves rebuild at size ${to} is not the one whose digest is P.`);
  }
  const anchorExt = extendCompactRange({ size: from, hashes: base.range }, range.leaves.map((l) => l.leafDigest));
  const sources = evidenceCheckpoints(range);
  let total = 0;
  for (const [, cp] of sources) total += cp.treeSize - (cp.prevAnchoredSize ?? 0);

  // The stored progress is a hint. `done`, or a cursor inside the range, is
  // taken only when the record it stands after carries this publication's
  // artifact; otherwise the fill walks the range from its start.
  const stored = readFillProgress(publication);
  let cursor: { anchorLeaf: number; leafIndex: number | null } | null = null;
  if (stored?.done) {
    const last = sources[sources.length - 1];
    if (!last || (await carriesArtifact(ctx, last[1], last[1].treeSize - 1, last[0], anchorCp.body))) return { ...outcome, done: true };
    outcome.hintRefused = true;
  } else if (stored && stored.anchorLeaf >= from && stored.anchorLeaf < to) {
    const at = sources.findIndex(([k]) => k >= stored.anchorLeaf);
    const here = at === -1 ? null : sources[at];
    let witness: [number, LogCheckpoint, number] | null = null;
    if (here && here[0] === stored.anchorLeaf && stored.leafIndex !== null && stored.leafIndex > (here[1].prevAnchoredSize ?? 0)) {
      witness = [here[0], here[1], stored.leafIndex - 1];
    } else {
      const before = sources.filter(([k]) => k < stored.anchorLeaf).pop();
      if (before) witness = [before[0], before[1], before[1].treeSize - 1];
    }
    if (witness === null || (await carriesArtifact(ctx, witness[1], witness[2], witness[0], anchorCp.body))) {
      cursor = { anchorLeaf: stored.anchorLeaf, leafIndex: here && here[0] === stored.anchorLeaf ? stored.leafIndex : null };
    } else {
      outcome.hintRefused = true;
    }
  } else if (stored) {
    outcome.hintRefused = stored.anchorLeaf !== to || stored.from !== from;
  }

  // The artifact's publication entry: the mined transaction, and the sender
  // recovered from it, never the row's own columns.
  const epochPublications: AnchorArtifact['publications'] = [
    {
      kind: 'evm-calldata/1',
      chain: publication.chain as string,
      transactionId: publication.minedTxHash as string,
      blockNumber: publication.blockNumber as number,
      blockHash: publication.blockHash as string,
      publisher: authority.sender,
    },
  ];
  const statusOf = (envelope: EvidenceEnvelope) =>
    determineAttestationStatus(envelope.nonRepudiation, envelope.integrity.canonicalDigest, ctx.expectation);

  let filledSoFar = cursor && stored ? stored.filled : 0;
  let pending: AnchorFill[] = [];
  const timestampExpected = ctx.expectation.timestamp !== false;
  const flush = async (progress: Omit<FillProgress, 'filled' | 'total' | 'from' | 'done' | 'timestampExpected'>, done: boolean): Promise<void> => {
    await ctx.beforeChunk?.();
    const result = await ctx.anchors.fillAnchorArtifacts({
      publicationId: publication.id,
      fills: pending,
      statusOf,
      ...(ctx.expectation.timestamp === false && { timestampExpected: false }),
      fillProgress: { from, ...progress, filled: filledSoFar + pending.length, total, done, timestampExpected } satisfies FillProgress,
    });
    filledSoFar += pending.length;
    outcome.filled += result.filled;
    outcome.alreadyAnchored += result.alreadyAnchored;
    outcome.missing.push(...result.missing);
    outcome.conflicts.push(...(result.conflicts ?? []));
    pending = [];
  };

  for (const [k, cp] of sources) {
    if (cursor && k < cursor.anchorLeaf) continue;
    const m = cp.prevAnchoredSize ?? 0;
    const n = cp.treeSize;
    const before = m > 0 ? await ctx.anchors.getLogCheckpoint(cp.logId, m) : null;
    if (m > 0 && !before) throw new AnchorFillIntegrityError(`log ${cp.logId}: no checkpoint at its anchored size ${m}`);
    const leaves = await ctx.logs.listLogLeaves(cp.logId, m, n);
    const ext = extendCompactRange({ size: m, hashes: before?.compactRange ?? [] }, leaves.map((l) => l.leafDigest));
    if (ext.root !== cp.root) throw new AnchorFillIntegrityError(`log ${cp.logId}: the leaves do not rebuild the checkpoint at size ${n}`);
    const anchorPath = anchorExt.inclusionProofs[k - from];
    if (!verifyMerkleProof(cp.bodyDigest, k, to, anchorPath, anchorCp.root)) {
      throw new AnchorFillIntegrityError(`anchor leaf ${k}: its path does not verify against the anchor checkpoint`);
    }
    const start = cursor && cursor.anchorLeaf === k && cursor.leafIndex !== null ? Math.max(m, cursor.leafIndex) : m;
    for (let j = start; j < n; j++) {
      const leaf = leaves[j - m];
      const logPath = ext.inclusionProofs[j - m];
      if (!verifyMerkleProof(leaf.leafDigest, leaf.leafIndex, n, logPath, cp.root)) {
        throw new AnchorFillIntegrityError(`log ${cp.logId} leaf ${j}: its path does not verify against the checkpoint`);
      }
      pending.push({
        evidenceId: leaf.sourceRef,
        logId: cp.logId,
        anchor: {
          anchorSpec: ANCHOR_SPEC,
          merkleSpec: MERKLE_SPEC,
          leafIndex: leaf.leafIndex,
          logCheckpoint: cp.body,
          logPath,
          anchorLeafIndex: k,
          anchorCheckpoint: anchorCp.body,
          anchorPath,
          publications: epochPublications,
        },
      });
      if (pending.length >= ctx.chunkSize) {
        const nextJ = j + 1;
        await flush(nextJ < n ? { anchorLeaf: k, leafIndex: nextJ } : { anchorLeaf: k + 1, leafIndex: null }, false);
      }
    }
  }
  await flush({ anchorLeaf: to, leafIndex: null }, true);
  outcome.done = true;
  return outcome;
}
