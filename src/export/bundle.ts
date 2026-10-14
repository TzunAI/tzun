/**
 * Assembling a `b1` proof bundle's anchoring material from a store (Bundle §3,
 * §4, §7.3, §7.7).
 *
 * The material comes from the store's logs and anchoring tables, never from
 * the record's own artifact: the artifact sits outside the hashed fields, so
 * what the store published is the ground a verifier compares it with.
 *
 * WHICH CHECKPOINTS. The subject is anchored when a final publication (EVM
 * `finalized`, RFC 3161 `obtained`) of the kind that decides it (EVM when an
 * EVM publication covers its leaf) covers its leaf. Then, per log, the bundle
 * carries at most two checkpoints, joined by one direct consistency proof:
 *
 *   - the evidence log: the subject's own checkpoint (the first of the log
 *     that took its leaf into the anchor log), and the newest checkpoint of
 *     the log in the newest anchor checkpoint;
 *   - the anchor log: the subject's own anchor checkpoint (the one the
 *     record's artifact names, when a final publication of the store's has
 *     that P, otherwise the one of the earliest final publication covering
 *     the leaf), and the newest anchor checkpoint with a final publication of
 *     the deciding kind. Each carries every final publication of its P, with
 *     the heavy material the envelope leaves out.
 *
 * The subject's own checkpoints are carried only when its artifact names
 * them, since nothing else in the bundle authenticates them. For a record
 * whose envelope has no artifact yet, or one that names other checkpoints,
 * the bundle carries only the newest checkpoint of each log.
 *
 * When the bundle carries anything the record's artifact does not name (a
 * newer checkpoint, or any checkpoint when the artifact is absent or names
 * others), the largest evidence-log checkpoint also carries the subject's
 * anchor into the newest anchor checkpoint: the subject's path in it, and its
 * path into that anchor checkpoint (tzun-anchor/1 §10.8, `anchor.newer`).
 *
 * Every proof is computed on demand from the compact range stored with a
 * checkpoint and the leaves after it (Tree §5.5), so the bundle's size does not
 * grow with the number of epochs, only with their logarithm (Bundle §7.3). The
 * anchoring tables are read by point queries. The only range read is of the
 * leaves the proofs are computed from: per log, one pass from the checkpoint
 * below the record's leaf (or below the older carried checkpoint) to the
 * newest, `LEAF_PAGE` leaves per query, with a turn of the event loop between
 * pages, so the export's hashing grows with a log's growth since the record's
 * epoch and its memory does not. Nothing here judges the material: the exporter
 * writes what the store holds and `verifyBundle()` decides it.
 *
 * WHEN IT IS PENDING. On a store that anchors (one with an anchor log), a
 * subject no final publication covers exports `anchorPending` with its
 * origin, its leaf and when that leaf was logged, and no anchoring material.
 * A store that does not anchor, and a record with no leaf, export neither.
 */
import type { AnchorArtifact, EvidenceEnvelope } from '@tzun/engine';
import { parseCheckpoint } from '../attestation/checkpoint';
import { CompactRangeProver } from '../attestation/merkle';
import {
  ANCHOR_LOG_KIND,
  type AnchorPublication,
  type AnchorStore,
  type LeafAnchorPublication,
  type LogCheckpoint,
  type LogPosition,
  type LogStore,
} from '../storage/log-store';
import type { BundleAnchorPending, BundleCheckpoint, BundleLogMaterial, BundlePublication } from './bundle-types';

/** What `bundleAnchoring` returns: the two anchoring members of a `b1` bundle. */
export interface BundleAnchoringMaterial {
  anchoring: Record<string, BundleLogMaterial>;
  anchorPending: BundleAnchorPending | null;
}

/** Neither anchoring material nor a pending slot: the store does not anchor, or the record has no leaf. */
const none = (): BundleAnchoringMaterial => ({ anchoring: {}, anchorPending: null });

function isFinal(state: string): boolean {
  return state === 'finalized' || state === 'obtained';
}

/** The record's `nonRepudiation.anchor` when it is an object whose bodies are strings. */
function artifactOf(envelope: EvidenceEnvelope): Pick<AnchorArtifact, 'logCheckpoint' | 'anchorCheckpoint'> | null {
  const anchor = (envelope.nonRepudiation as { anchor?: unknown } | undefined)?.anchor as Partial<AnchorArtifact> | undefined;
  if (typeof anchor !== 'object' || anchor === null || Array.isArray(anchor)) return null;
  if (typeof anchor.logCheckpoint !== 'string' || typeof anchor.anchorCheckpoint !== 'string') return null;
  return { logCheckpoint: anchor.logCheckpoint, anchorCheckpoint: anchor.anchorCheckpoint };
}

/** A final publication as a bundle carries it, with its heavy material; null when the store holds too little for one. */
function bundlePublication(publication: AnchorPublication): BundlePublication | null {
  if (publication.kind === 'rfc3161/1') {
    return publication.state === 'obtained' && publication.token !== null ? { kind: 'rfc3161/1', token: publication.token } : null;
  }
  if (publication.state !== 'finalized') return null;
  const mined = publication.attempts.find((a) => a.txHash === publication.minedTxHash);
  if (!mined || publication.chain === null || publication.fromAddress === null || publication.blockNumber === null || publication.blockHash === null) {
    return null;
  }
  return {
    kind: 'evm-calldata/1',
    chain: publication.chain,
    transactionId: mined.txHash,
    blockNumber: publication.blockNumber,
    blockHash: publication.blockHash,
    publisher: publication.fromAddress,
    rawTransaction: mined.rawTx,
    ...(publication.blockHeader !== null && { blockHeader: publication.blockHeader }),
    ...(publication.txIndex !== null && publication.txTrieProof !== null && { txIndex: publication.txIndex, txProof: publication.txTrieProof }),
  };
}

/** Every final publication of the anchor checkpoint at `anchorSize`, EVM first. */
async function publicationsAt(anchors: AnchorStore, anchorSize: number): Promise<BundlePublication[]> {
  const out: BundlePublication[] = [];
  for (const kind of ['evm-calldata/1', 'rfc3161/1'] as const) {
    const publication = await anchors.getAnchorPublicationAt(kind, anchorSize);
    const entry = publication ? bundlePublication(publication) : null;
    if (entry) out.push(entry);
  }
  return out;
}

/** How many leaves a proof reads per query: an export holds one page of leaves at a time, and yields to the event loop between pages. */
export const LEAF_PAGE = 1024;

const nextTurn = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

/**
 * PATH(leafIndex, D[to.treeSize]) and PROOF(fromSize, D[to.treeSize]) in log
 * `logId`, each when asked for, from one pass: the compact range of the log's
 * largest checkpoint at or below both, and the leaves after it, read
 * `LEAF_PAGE` at a time. The leaves must rebuild `to`'s root.
 */
async function proofsTo(
  logs: LogStore,
  anchors: AnchorStore,
  logId: number,
  to: LogCheckpoint,
  want: { leafIndex?: number; fromSize?: number },
): Promise<{ inclusionProof: string[] | null; consistencyProof: string[] | null }> {
  const lowest = Math.min(want.leafIndex ?? to.treeSize, want.fromSize ?? to.treeSize);
  const base = await anchors.getLogCheckpointAtOrBelow(logId, lowest);
  const from = base?.treeSize ?? 0;
  const prover = new CompactRangeProver({ size: from, hashes: base?.compactRange ?? [] }, to.treeSize, want);
  for (let at = from; at < to.treeSize; at += LEAF_PAGE) {
    const end = Math.min(at + LEAF_PAGE, to.treeSize);
    const page = await logs.listLogLeaves(logId, at, end);
    if (page.length !== end - at) throw new Error(`log ${logId} holds ${page.length} of its leaves ${at} to ${end - 1}`);
    prover.append(page.map((l) => l.leafDigest));
    await nextTurn();
  }
  const out = prover.finish();
  if (out.root !== to.root) throw new Error(`log ${logId}: the leaves do not rebuild its checkpoint at size ${to.treeSize}`);
  return out;
}

/** The earliest final publication covering the leaf: the EVM one when there is one (it decides), otherwise the RFC 3161 one. */
function decidingFinal(publications: LeafAnchorPublication[]): LeafAnchorPublication | null {
  const evm = publications.find((p) => p.kind === 'evm-calldata/1');
  const decides = evm ?? publications.find((p) => p.kind === 'rfc3161/1');
  return decides && isFinal(decides.state) ? decides : null;
}

/**
 * The anchoring members of the bundle of `envelope`, from the store's logs and
 * anchoring tables. `logs` and `anchors` are the adapter's; either may be
 * absent for an adapter without them.
 */
export async function bundleAnchoring(
  envelope: EvidenceEnvelope,
  logs: LogStore | undefined,
  anchors: AnchorStore | undefined,
): Promise<BundleAnchoringMaterial> {
  const evidenceId = envelope.payload?.evidenceId;
  if (!logs || !anchors || typeof evidenceId !== 'string') return none();
  const position = await logs.getEvidenceLogPosition(evidenceId);
  if (!position) return none();
  const progress = await anchors.getLeafAnchorProgress(position.logId, position.leafIndex);
  // No anchor log: the store does not anchor.
  if (!progress) return none();

  const deciding = decidingFinal(progress.publications);
  if (!deciding || progress.anchorLeafIndex === null) return { anchoring: {}, anchorPending: await pending(logs, position) };
  return { anchoring: await anchoredMaterial(envelope, logs, anchors, position, progress.anchorLeafIndex, deciding), anchorPending: null };
}

async function pending(logs: LogStore, position: LogPosition): Promise<BundleAnchorPending> {
  const [leaf] = await logs.listLogLeaves(position.logId, position.leafIndex, position.leafIndex + 1);
  if (!leaf) throw new Error(`the evidence log ${position.origin} names leaf ${position.leafIndex} for the record, and holds no leaf there`);
  return { origin: position.origin, leafIndex: position.leafIndex, since: leaf.loggedAt };
}

async function anchoredMaterial(
  envelope: EvidenceEnvelope,
  logs: LogStore,
  anchors: AnchorStore,
  position: LogPosition,
  ownAnchorLeaf: number,
  deciding: LeafAnchorPublication,
): Promise<Record<string, BundleLogMaterial>> {
  const anchorLog = (await logs.listLogs()).find((l) => l.kind === ANCHOR_LOG_KIND);
  const [ownLog] = await anchors.listCheckpointsByAnchorLeaf(ownAnchorLeaf, ownAnchorLeaf + 1);
  if (!anchorLog || !ownLog || ownLog.logId !== position.logId) {
    throw new Error(`the anchoring tables name anchor leaf ${ownAnchorLeaf} for ${position.origin}, and hold no checkpoint of that log there`);
  }

  // The subject's own anchor checkpoint: the one its artifact names when the
  // store published that P and it holds the subject's own log checkpoint;
  // otherwise the deciding publication's.
  const artifact = artifactOf(envelope);
  let ownSize = deciding.anchorSize;
  const named = artifact && artifact.logCheckpoint === ownLog.body ? parseCheckpoint(artifact.anchorCheckpoint) : null;
  if (named?.ok && named.checkpoint.size > ownAnchorLeaf && named.checkpoint.size !== ownSize) {
    const at = await anchors.getLogCheckpoint(anchorLog.logId, named.checkpoint.size);
    if (at && at.body === artifact!.anchorCheckpoint && (await publicationsAt(anchors, at.treeSize)).length > 0) ownSize = at.treeSize;
  }
  const ownAnchor = await anchors.getLogCheckpoint(anchorLog.logId, ownSize);
  if (!ownAnchor) throw new Error(`the anchoring tables hold a final publication at anchor size ${ownSize} and no anchor checkpoint there`);
  const ownPublications = await publicationsAt(anchors, ownAnchor.treeSize);

  // The newest anchor checkpoint with a final publication of the kind that
  // decides the subject (an EVM one on a store that publishes EVM, whatever
  // RFC 3161 tokens a newer checkpoint has), and the newest checkpoint of the
  // subject's log inside it.
  let newestAnchor = ownAnchor;
  let newestPublications = ownPublications;
  const newestSize = await anchors.getLastFinalAnchorSize(deciding.kind);
  if (newestSize !== null && newestSize > ownAnchor.treeSize) {
    const at = await anchors.getLogCheckpoint(anchorLog.logId, newestSize);
    if (!at) throw new Error(`the anchoring tables hold a final publication at anchor size ${newestSize} and no anchor checkpoint there`);
    const publications = await publicationsAt(anchors, newestSize);
    if (publications.some((p) => p.kind === deciding.kind)) {
      newestAnchor = at;
      newestPublications = publications;
    }
  }
  const newestLog = (await anchors.getLastAnchoredCheckpointBelow(position.logId, newestAnchor.treeSize)) ?? ownLog;

  // The record's own checkpoints are carried only when its artifact names
  // them: nothing else in the bundle authenticates them (tzun-anchor/1 §10.8),
  // and a body nobody authenticated only leaves a consistency check undecided.
  // Otherwise the bundle carries the newest of each log, and the subject's
  // anchor into them.
  const artifactNamesOwn = artifact !== null && artifact.logCheckpoint === ownLog.body && artifact.anchorCheckpoint === ownAnchor.body;
  const fromLog = artifactNamesOwn ? ownLog : newestLog;
  const fromAnchor = artifactNamesOwn ? ownAnchor : newestAnchor;
  const logEntries: BundleCheckpoint[] = [{ body: fromLog.body, signatures: [...fromLog.signatures] }];
  if (newestLog.treeSize !== fromLog.treeSize) logEntries.push({ body: newestLog.body, signatures: [...newestLog.signatures] });
  const anchorEntries: BundleCheckpoint[] = [
    { body: fromAnchor.body, signatures: [...fromAnchor.signatures], publications: artifactNamesOwn ? ownPublications : newestPublications },
  ];
  if (newestAnchor.treeSize !== fromAnchor.treeSize) {
    anchorEntries.push({ body: newestAnchor.body, signatures: [...newestAnchor.signatures], publications: newestPublications });
  }

  // The subject's anchor into the newest anchor checkpoint, on the largest
  // evidence-log checkpoint, whenever the bundle carries something the
  // record's artifact does not name. One pass over each log gives its path
  // and its consistency proof.
  const composes = newestLog.treeSize !== ownLog.treeSize || newestAnchor.treeSize !== ownAnchor.treeSize || !artifactNamesOwn;
  const newestLogAnchorLeaf = newestLog.anchorLeafIndex as number;
  const logProofs =
    composes || newestLog.treeSize !== fromLog.treeSize
      ? await proofsTo(logs, anchors, position.logId, newestLog, {
          ...(composes && { leafIndex: position.leafIndex }),
          ...(newestLog.treeSize !== fromLog.treeSize && { fromSize: fromLog.treeSize }),
        })
      : null;
  const anchorProofs =
    composes || newestAnchor.treeSize !== fromAnchor.treeSize
      ? await proofsTo(logs, anchors, anchorLog.logId, newestAnchor, {
          ...(composes && { leafIndex: newestLogAnchorLeaf }),
          ...(newestAnchor.treeSize !== fromAnchor.treeSize && { fromSize: fromAnchor.treeSize }),
        })
      : null;
  if (composes) {
    const last = logEntries[logEntries.length - 1];
    last.logPath = logProofs!.inclusionProof!;
    last.anchorLeafIndex = newestLogAnchorLeaf;
    last.anchorSize = newestAnchor.treeSize;
    last.anchorPath = anchorProofs!.inclusionProof!;
  }

  return {
    [position.origin]: {
      checkpoints: logEntries,
      consistency: logProofs?.consistencyProof ? [{ fromSize: fromLog.treeSize, toSize: newestLog.treeSize, path: logProofs.consistencyProof }] : [],
    },
    [anchorLog.origin]: {
      checkpoints: anchorEntries,
      consistency: anchorProofs?.consistencyProof
        ? [{ fromSize: fromAnchor.treeSize, toSize: newestAnchor.treeSize, path: anchorProofs.consistencyProof }]
        : [],
    },
  };
}
