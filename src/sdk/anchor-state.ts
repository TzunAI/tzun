/**
 * What a store's logs say about one stored record: where it sits in its
 * chain's evidence log, how far its anchor has got, and what the logs show is
 * wrong with it (tzun-anchor/1 §10.9).
 *
 * The stage is worked out from the store's anchoring tables first, which the
 * anchor scheduler writes (src/storage/log-store.ts):
 *
 *   - an epoch covers a record once a checkpoint of the record's evidence log
 *     at a size past the record's leaf sits in the anchor log;
 *   - a publication covers that checkpoint when its anchor size is past the
 *     checkpoint's anchor-log leaf. A later epoch's publication covers every
 *     earlier checkpoint too, because the anchor log only grows. A superseded
 *     publication covers nothing;
 *   - the epoch's `evm-calldata/1` publication decides when there is one,
 *     otherwise its `rfc3161/1` one: the scheduler fills a record once that
 *     publication is final.
 *
 * The record's own artifact counts only as far as the verifier says it
 * holds, only for the record as stored, and only when it is bound to what the
 * store published. `nonRepudiation` is outside the hashed field set, so
 * whoever can write the row can write any artifact there, can edit the
 * payload under an artifact that was genuine, and can rewrite the payload and
 * its digest together under an artifact built over made-up leaves whose
 * proofs hold. `anchored` therefore needs all of:
 *
 *   - a final publication in the tables;
 *   - a payload that still hashes to the stored `canonicalDigest`, and that
 *     digest the leaf the record's evidence log holds for it;
 *   - an artifact made for the record's own log and leaf, whose proofs hold
 *     for the digest recomputed from the payload;
 *   - an anchor checkpoint whose digest is the P of a final publication of
 *     the store's, of the kind that decides the stage. The fill writes the
 *     anchor checkpoint whose digest is the P of the publication it fills
 *     from.
 *
 * Once the publication is final, a record that fails any of that is
 * `anchor_invalid`, since it will never be anchored as stored, except an
 * intact record without an artifact that the fill has not reached yet, which
 * is still `awaiting_finality`. An artifact whose anchor checkpoint is no
 * such P is the finding `anchor_checkpoint_not_published`. The verifier is
 * given no header source, so it makes no network call: the proofs are
 * hashing, and an EVM publication stays undecided.
 */
import { recordDigestCheck } from '@tzun/engine';
import type {
  EvidenceEnvelope,
  RecordAnchorPublication,
  RecordAnchorStage,
  RecordAnchorState,
  RecordLogFinding,
  RecordLogPosition,
  SchemaRegistry,
} from '@tzun/engine';
import { verifyAnchor, type AnchorVerification } from '../attestation/anchor-verify';
import { parseCheckpoint } from '../attestation/checkpoint';
import type { AnchorPublicationState, AnchorStore, LeafAnchorPublication, LogPosition } from '../storage/log-store';

/** The public form of a store's log position. */
export function recordLogPosition(position: LogPosition): RecordLogPosition {
  return { origin: position.origin, leafIndex: position.leafIndex };
}

/** What `get()` adds to a read of a record its store holds a leaf for. */
export interface RecordLogRead {
  logPosition: RecordLogPosition;
  anchorState?: RecordAnchorState;
  logFindings?: RecordLogFinding[];
}

function describePublication(p: LeafAnchorPublication): RecordAnchorPublication {
  return {
    kind: p.kind,
    ...(p.chain !== null && { chain: p.chain }),
    ...(p.transactionId !== null && { transactionId: p.transactionId }),
    ...(p.blockNumber !== null && { blockNumber: p.blockNumber }),
  };
}

/** Whether the scheduler has finished filling the records `publication` covers. */
function fillDone(publication: LeafAnchorPublication): boolean {
  return publication.fillProgress?.done === true;
}

/** Whether a publication is in a final state. */
function isFinal(publication: { state: AnchorPublicationState }): boolean {
  return publication.state === 'finalized' || publication.state === 'obtained';
}

/** The record's `nonRepudiation.anchor` when it is an object, else null. */
function artifactOf(envelope: EvidenceEnvelope): { anchorSpec?: unknown; logCheckpoint?: unknown; leafIndex?: unknown; anchorCheckpoint?: unknown } | null {
  const anchor = (envelope.nonRepudiation as { anchor?: unknown } | undefined)?.anchor;
  return typeof anchor === 'object' && anchor !== null && !Array.isArray(anchor) ? anchor : null;
}

/**
 * Whether `p`, the digest of the record's anchor checkpoint, is the P of a
 * final publication of the store's, of `primary`'s kind, that covers the
 * record's anchor leaf. `primary` is the earliest final one covering it,
 * whose P the fill writes unless it filled the record from a later one first
 * (a later publication marked final before an earlier one). For any other P
 * the store's publication at the size the anchor checkpoint states is read:
 * one index seek.
 */
async function publishedByStore(
  anchors: AnchorStore,
  primary: LeafAnchorPublication,
  anchorLeafIndex: number,
  envelope: EvidenceEnvelope,
  p: string,
): Promise<boolean> {
  if (p === primary.p) return true;
  const parsed = parseCheckpoint(artifactOf(envelope)?.anchorCheckpoint);
  if (!parsed.ok || parsed.checkpoint.size <= anchorLeafIndex) return false;
  const at = await anchors.getAnchorPublicationAt(primary.kind, parsed.checkpoint.size);
  return at !== null && isFinal(at) && at.p === p;
}

/**
 * The verifier's answer on the record's artifact, or null when it carries
 * none: `verifyAnchor` with `digest` (the one recomputed from the record's
 * payload), the record's hashed sequence number and the chain its store
 * logged it under, and no header source, manifest or other input.
 */
async function offlineVerdict(envelope: EvidenceEnvelope, digest: string, position: LogPosition): Promise<AnchorVerification | null> {
  const verdict = await verifyAnchor(envelope.nonRepudiation, digest, {
    sequenceNumber: envelope.payload?.sequenceNumber,
    chainId: position.chainId,
  });
  return verdict.anchorPresent ? verdict : null;
}

/**
 * The leaf the record's `tzun-anchor/1` artifact was made for, when that is
 * another leaf than the record's own at `position`: the artifact's log
 * checkpoint names another log than the record's evidence log, or its
 * `leafIndex` is not the record's leaf. Null otherwise. An artifact whose log
 * checkpoint does not parse, or whose `leafIndex` is not an integer, names no
 * leaf, and the verifier reports it as malformed. The scanner reports the
 * same rule as `anchor_transplanted`.
 */
export function transplantedFrom(
  envelope: EvidenceEnvelope,
  position: Pick<LogPosition, 'origin' | 'leafIndex'>,
): { origin: string; leafIndex: number } | null {
  const artifact = artifactOf(envelope);
  if (artifact === null || artifact.anchorSpec !== 'tzun-anchor/1' || !Number.isSafeInteger(artifact.leafIndex)) return null;
  const log = parseCheckpoint(artifact.logCheckpoint);
  if (!log.ok) return null;
  const named = { origin: log.checkpoint.origin, leafIndex: artifact.leafIndex as number };
  return named.origin !== position.origin || named.leafIndex !== position.leafIndex ? named : null;
}

/** Whether the record carries a `tzun-anchor/1` artifact made for another leaf (`transplantedFrom`). */
function transplanted(envelope: EvidenceEnvelope, position: LogPosition): boolean {
  return transplantedFrom(envelope, position) !== null;
}

/**
 * What the store's logs say about `envelope`, the record at `position`.
 *
 * @param anchors - the store's anchoring tables, when it has them. Without
 *   them, or without an anchor log in them, the store does not anchor and no
 *   anchor state is reported.
 * @param options - `registry`: the schemas the record's digest is recomputed
 *   under (the instance's own). `dueBy`: when the record's epoch is due, asked
 *   only while the record awaits its epoch. Given by an instance that
 *   anchors, which knows the cadence.
 */
export async function readRecordLog(
  envelope: EvidenceEnvelope,
  position: LogPosition,
  anchors: AnchorStore | undefined,
  options: { registry?: SchemaRegistry; dueBy?: () => Promise<string | undefined> } = {},
): Promise<RecordLogRead> {
  const logPosition = recordLogPosition(position);
  const findings: RecordLogFinding[] = [];
  if (position.leafDigest !== envelope.integrity?.canonicalDigest) findings.push('digest_differs_from_logged_leaf');
  if (transplanted(envelope, position)) findings.push('anchor_transplanted');
  const withFindings = (read: RecordLogRead): RecordLogRead => (findings.length > 0 ? { ...read, logFindings: findings } : read);

  const progress = anchors ? await anchors.getLeafAnchorProgress(position.logId, position.leafIndex) : null;
  if (!anchors || !progress) return withFindings({ logPosition });

  const primary =
    progress.publications.find((p) => p.kind === 'evm-calldata/1') ??
    progress.publications.find((p) => p.kind === 'rfc3161/1');
  const final = primary !== undefined && isFinal(primary);
  // The anchor has to hold for the record as it is now: its digest
  // recomputed from its payload (empty when the payload cannot be hashed,
  // which no proof holds for), not the stored one an edit can leave behind.
  const digest = recordDigestCheck(envelope, options.registry);
  const intact = digest.status === 'valid';
  // ...and that digest has to be the leaf the store logged for the record,
  // in the record's own log.
  const logged = position.leafDigest === digest.recomputed && !findings.includes('anchor_transplanted');
  const verdict = await offlineVerdict(envelope, digest.recomputed, position);
  const holds = verdict?.merkleProofValid === true && verdict.anchorValid !== false;
  // ...and its anchor checkpoint has to be one the store published: proofs
  // that hold say nothing about which anchor log they were built over.
  let published = false;
  if (final && verdict?.p != null && progress.anchorLeafIndex !== null) {
    published = await publishedByStore(anchors, primary, progress.anchorLeafIndex, envelope, verdict.p);
    if (!published) findings.push('anchor_checkpoint_not_published');
  }

  let state: RecordAnchorStage;
  if (final && intact && logged && holds && published) state = 'anchored';
  // Final, and not anchored as stored: an altered payload, an artifact that
  // does not hold, was made for another leaf or was not published by the
  // store, or a fill that finished without writing one. Nothing later
  // changes that, so it is not reported as waiting.
  else if (final && (!intact || verdict !== null || (primary !== undefined && fillDone(primary)))) state = 'anchor_invalid';
  else if (!primary || primary.state === 'prepared') state = 'awaiting_epoch';
  else state = 'awaiting_finality';

  let anchorValid: boolean | null = null;
  let anchorReason: string | undefined;
  if (verdict) {
    anchorValid = verdict.anchorValid;
    anchorReason = verdict.anchorReason;
  } else if (primary && final && fillDone(primary)) {
    // The fill finished and left this record without an anchor: the artifact
    // is absent (tzun-anchor/1 §10.1), and the finding says why that matters.
    findings.push('anchor_stripped');
    anchorReason = 'absent';
  } else {
    anchorReason = 'anchor_not_yet_published';
  }

  const dueBy = state === 'awaiting_epoch' && options.dueBy ? await options.dueBy() : undefined;

  return withFindings({
    logPosition,
    anchorState: {
      state,
      origin: position.origin,
      leafIndex: position.leafIndex,
      ...(dueBy !== undefined && { dueBy }),
      anchorValid,
      ...(anchorValid !== true && anchorReason !== undefined && { anchorReason }),
      ...(primary && { publication: describePublication(primary) }),
    },
  });
}
