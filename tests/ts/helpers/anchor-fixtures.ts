/**
 * Anchored records for the `verifyAnchor` suites: an evidence log, its
 * checkpoint, an anchor log that holds that checkpoint's digest among others,
 * and the anchor checkpoint whose digest is P (batching/anchoring design §4.3
 * to §4.7). Built with the engine's Merkle functions and the SDK's checkpoint
 * formatter; vectors/checkpoint-vectors.json pins both independently.
 */
import { createHash } from 'crypto';
import { buildMerkleTree, getMerkleProof, getMerkleRoot } from '../../../src/attestation/merkle';
import {
  anchorLogOrigin,
  checkpointDigest,
  evidenceLogOrigin,
  formatCheckpoint,
} from '../../../src/attestation/checkpoint';
import type { AnchorArtifact } from '@tzun/engine';

export const sha256 = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

/** A 128-bit store id, as §4.3 mints one. */
export const STORE_ID = sha256('anchor-fixture-store').slice(0, 32);
export const SDK_PREFIX = `local.invalid/${STORE_ID}`;
export const TEST_PREFIX = `test.tzun.dev/${STORE_ID}`;
export const PLATFORM_PREFIX = `log.tzun.ai/${sha256('anchor-fixture-deployment').slice(0, 32)}`;

/**
 * An `evm-calldata/1` entry as the scheduler's fill writes it into a record
 * (tzun-anchor/1 §8.2): every member, and no heavy material. From the
 * envelope alone it is not checked (§10.4 item 1, `not_in_bundle:raw_transaction`).
 */
export const ENVELOPE_EVM_ENTRY = Object.freeze({
  kind: 'evm-calldata/1' as const,
  chain: 'eip155:11155111',
  transactionId: '0x' + sha256('anchor-fixture-transaction'),
  blockNumber: 7123456,
  blockHash: '0x' + sha256('anchor-fixture-block'),
  publisher: '0x' + sha256('anchor-fixture-publisher').slice(0, 40),
});

export interface AnchoredRecord {
  /**
   * `nonRepudiation.anchor`, with the publications passed in. By default one
   * `evm-calldata/1` entry in its envelope form ({@link ENVELOPE_EVM_ENTRY}),
   * which no verifier can check from the envelope alone.
   */
  anchor: AnchorArtifact;
  /** The record's canonical digest: leaf `leafIndex` of its evidence log. */
  digest: string;
  sequenceNumber: number;
  chainId: string;
  logOrigin: string;
  anchorOrigin: string;
  /** P = SHA-256(anchor checkpoint body), hex. */
  p: string;
}

export interface AnchoredRecordOptions {
  domainPrefix?: string;
  chainId?: string;
  /** The evidence log's size at its anchored checkpoint. Default 5, or the number of `digests`. */
  logSize?: number;
  /** The evidence log's leaves, in order: real records' canonical digests. Default: made-up leaves. */
  digests?: string[];
  /** Default 2. */
  leafIndex?: number;
  /** Replaces the SDK evidence origin, for a platform-style opaque log. */
  logOrigin?: string;
  /** Other checkpoint digests in the anchor log before this log's. Default 2. */
  before?: number;
  /** Other checkpoint digests in the anchor log after this log's. Default 1. */
  after?: number;
  publications?: AnchorArtifact['publications'];
}

export function anchoredRecord(opts: AnchoredRecordOptions = {}): AnchoredRecord {
  const domainPrefix = opts.domainPrefix ?? SDK_PREFIX;
  const chainId = opts.chainId ?? 'default';
  const logSize = opts.logSize ?? opts.digests?.length ?? 5;
  const leafIndex = opts.leafIndex ?? 2;
  const logOrigin = opts.logOrigin ?? evidenceLogOrigin(domainPrefix, chainId);
  const anchorOrigin = anchorLogOrigin(domainPrefix);

  const leaves = opts.digests ?? Array.from({ length: logSize }, (_, i) => sha256(`${logOrigin}#${i + 1}`));
  const logTree = buildMerkleTree(leaves);
  const logCheckpoint = formatCheckpoint(logOrigin, logSize, getMerkleRoot(logTree));

  const before = Array.from({ length: opts.before ?? 2 }, (_, i) => sha256(`${anchorOrigin}#before-${i}`));
  const after = Array.from({ length: opts.after ?? 1 }, (_, i) => sha256(`${anchorOrigin}#after-${i}`));
  const anchorLeaves = [...before, checkpointDigest(logCheckpoint), ...after];
  const anchorLeafIndex = before.length;
  const anchorTree = buildMerkleTree(anchorLeaves);
  const anchorCheckpoint = formatCheckpoint(anchorOrigin, anchorLeaves.length, getMerkleRoot(anchorTree));

  return {
    anchor: {
      anchorSpec: 'tzun-anchor/1',
      merkleSpec: 'rfc6962',
      leafIndex,
      logCheckpoint,
      logPath: getMerkleProof(logTree, leafIndex),
      anchorLeafIndex,
      anchorCheckpoint,
      anchorPath: getMerkleProof(anchorTree, anchorLeafIndex),
      publications: opts.publications ?? [{ ...ENVELOPE_EVM_ENTRY }],
    },
    digest: leaves[leafIndex],
    sequenceNumber: leafIndex + 1,
    chainId,
    logOrigin,
    anchorOrigin,
    p: checkpointDigest(anchorCheckpoint),
  };
}
