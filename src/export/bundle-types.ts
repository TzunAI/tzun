/**
 * The `b1` proof bundle (Bundle §3): one bundle version, whose every slot is
 * always present.
 *
 * A bundle is one record and everything an auditor needs to verify it with no
 * access to the store it came from: the record, its chain position and custody
 * ledger, and, for an anchored record, the checkpoints, proofs and publication
 * material that place its digest in its evidence log, that log in the domain's
 * anchor log, and the anchor log's checkpoint on a public ledger
 * (tzun-anchor/1). An unanchored record carries the `anchorPending` slot
 * instead, never a marker in `nonRepudiation`.
 *
 * Absent material fills a frozen slot with `null`, so filling it later needs no
 * new version. The sign-off slots (`credentials`, `relatedRecords`, `policy`)
 * and the witness extension are reserved: the exporter writes `null` in each.
 *
 * `verifyBundle()` (./verify-bundle.ts) reads this shape and never trusts it:
 * every member is hostile JSON until a check has decided it.
 */
import type { CustodyLedgerEntry, CustodyLedgerVerdict, CustodyTrailVerdict, EvidenceEnvelope, RecordVerdict } from '@tzun/engine';

/** The bundle version this SDK writes and reads. */
export const BUNDLE_VERSION = 'b1' as const;

/**
 * The profiles of Bundle §3.1 (`chain` is reserved, Bundle §11). This SDK
 * exports and verifies `record` bundles only.
 */
export type BundleProfile = 'record' | 'chain';

/** What the bundle is about. Both members must equal the envelope's. */
export interface BundleSubject {
  evidenceId: string;
  canonicalDigest: string;
}

/** The record at the previous sequence of the subject's chain, as the exporter's store holds it. */
export interface BundleChainPredecessor {
  evidenceId: string;
  sequenceNumber: number;
  canonicalDigest: string;
}

/** The subject's chain and its predecessor: what `integrity.chainLink` is recomputed from. */
export interface BundleChain {
  /** The chain the store files the record under; null when it names none. */
  chainId: string | null;
  /** Null for a genesis record, and for a record whose predecessor the store could not read. */
  predecessor: BundleChainPredecessor | null;
}

/** The subject's custody ledger rows, in the shape `Tzun.exportEvidence()` ships them. */
export interface BundleCustody {
  /** The entry hash rule, in words (`CUSTODY_ENTRY_HASH_PREIMAGE`). */
  hashPreimage: string;
  /** The record's `custody_entries` rows in id order; null when the store could not read them. */
  entries: CustodyLedgerEntry[] | null;
  /** The exporter's ledger verdict: a claim, never an input to a check. */
  trail: CustodyLedgerVerdict | null;
  /** The exporter's envelope-only verdict: a claim, never an input to a check. */
  offlineTrail: CustodyTrailVerdict;
}

/**
 * One publication of an anchor checkpoint's P, with the heavy material an
 * offline verifier needs (tzun-anchor/1 §7.2 rule 4, §8.2; Bundle §7.4).
 *
 * The `evm-calldata/1` entry carries every member of the envelope's entry
 * (`kind`, `chain`, `transactionId`, `blockNumber`, `blockHash`, `publisher`)
 * joined with the material the envelope leaves out: the raw signed
 * transaction, the block header's RLP, the transaction's index in its block
 * and its transactions-trie proof. A verifier joins it to the envelope's
 * entry by `keccak256(rawTransaction) = transactionId`.
 */
export interface BundleEvmPublication {
  kind: 'evm-calldata/1';
  /** CAIP-2. Display only: a verifier takes the chain from its own manifest. */
  chain: string;
  /** `0x` and 64 lowercase hex: `keccak256(rawTransaction)`. */
  transactionId: string;
  blockNumber: number;
  blockHash: string;
  /** Display only: a verifier recovers the sender from the signature. */
  publisher: string;
  /** The signed transaction, `0x` hex. */
  rawTransaction: string;
  /** The block header's RLP, `0x` hex, when the store holds it. */
  blockHeader?: string;
  /** The transaction's index in its block, with `txProof`, when the store holds them. */
  txIndex?: number;
  /** The transactions-trie nodes from the root, each `0x` hex RLP. */
  txProof?: string[];
}

/** An `rfc3161/1` publication: a TimeStampResp whose imprint is P. */
export interface BundleRfc3161Publication {
  kind: 'rfc3161/1';
  /** Base64 DER TimeStampResp. */
  token: string;
}

export type BundlePublication = BundleEvmPublication | BundleRfc3161Publication;

/**
 * One checkpoint of a log, as a bundle carries it.
 *
 * An anchor-log checkpoint carries `publications`: every final publication of
 * its P the store holds.
 *
 * An evidence-log checkpoint carries, when the bundle holds an anchor
 * checkpoint newer than the subject's own, the subject's anchor as of that
 * newer checkpoint (tzun-anchor/1 §10.8, check `anchor.newer`):
 *
 *   - `logPath`: PATH(subject leaf index, this body's tree), leaf first;
 *   - `anchorLeafIndex`: where this body's digest sits in the anchor log;
 *   - `anchorSize`: the size of the carried anchor checkpoint `anchorPath`
 *     leads to;
 *   - `anchorPath`: PATH(anchorLeafIndex, that anchor checkpoint's tree).
 *
 * With the anchor checkpoint at `anchorSize` and its publications, they make a
 * tzun-anchor/1 artifact for the subject over this body, which a verifier
 * checks as it checks the envelope's own. Only the evidence-log checkpoint
 * with the largest size carries them.
 */
export interface BundleCheckpoint {
  /** The exact checkpoint body: `<origin>\n<size>\n<base64 root>\n`. */
  body: string;
  /** Signed-note lines. None until a log key exists. */
  signatures: string[];
  publications?: BundlePublication[];
  logPath?: string[];
  anchorLeafIndex?: number;
  anchorSize?: number;
  anchorPath?: string[];
}

/** PROOF(fromSize, D[toSize]) between two carried checkpoints of one log, leaf first. */
export interface BundleConsistencyProof {
  fromSize: number;
  toSize: number;
  path: string[];
}

/**
 * What a bundle carries for one log (Bundle §7.1, `anchoring[<origin>]`). A
 * record bundle carries at most two checkpoints per log, the subject's own and
 * the newest anchored when it was exported, joined by one direct consistency
 * proof (Bundle §7.3).
 */
export interface BundleLogMaterial {
  /** In size order. */
  checkpoints: BundleCheckpoint[];
  consistency: BundleConsistencyProof[];
}

/**
 * The pending state of an unanchored subject (Bundle §7.7, tzun-anchor/1
 * §10.9). It lives only here, never in `nonRepudiation`.
 */
export interface BundleAnchorPending {
  /** The subject's evidence-log origin. */
  origin: string;
  /** The subject's leaf index in that log. */
  leafIndex: number;
  /** When the subject's leaf was logged: the record has been waiting since then. */
  since: string;
}

/** What the exporter says about itself and the record. Never an input to a check. */
export interface BundleExporter {
  /** When the bundle was assembled. */
  exportedAt: string;
  /** Who assembled it. Default `'tzun-sdk'`. */
  exportedBy: string;
  /** The exporting store's verdict on the record (`recordVerdict`). */
  verdict: RecordVerdict;
}

/** A `b1` proof bundle, record profile. */
export interface ProofBundle {
  bundleVersion: typeof BUNDLE_VERSION;
  profile: 'record';
  subject: BundleSubject;
  /** The record exactly as stored. */
  envelope: EvidenceEnvelope;
  chain: BundleChain;
  custody: BundleCustody;
  /** Reserved for the sign-off credentials: always null in this version. */
  credentials: null;
  /** Reserved for the registration and revocation records: always null in this version. */
  relatedRecords: null;
  /**
   * The subject's evidence log and the domain's anchor log, keyed by origin.
   * Empty when the subject is not anchored by a final publication.
   */
  anchoring: Record<string, BundleLogMaterial>;
  /** Set exactly when the store anchors and the subject awaits its epoch or its publication's finality. */
  anchorPending: BundleAnchorPending | null;
  /** Reserved for the sign-off policy log: always null in this version. */
  policy: null;
  /** `witness/1` is reserved (Bundle §9) and always null. */
  extensions: { 'witness/1': null };
  exporter: BundleExporter;
}
