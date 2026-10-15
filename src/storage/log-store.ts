/**
 * Evidence logs: the store's identity, one growing RFC 6962 log per chain, and
 * the anchoring tables the anchor scheduler writes (Anchor §3, §4.3.2;
 * Tree §5.2).
 *
 * WHAT A STORE HOLDS
 *
 *   store_identity      one row, minted once: a 128-bit random `store_id` and
 *                       the namespace `ns`. Every origin the store names starts
 *                       with `<ns>/<store_id>`, so a wiped store names new logs.
 *   logs                one row per log. An evidence log per chain, origin
 *                       `<ns>/<store_id>/evidence/<hex(UTF-8 chain id)>`; the
 *                       per-store logs the scheduler keeps (the anchor log,
 *                       and later custody, revisions, policy) are
 *                       `<ns>/<store_id>/<kind>`.
 *   log_leaves          the leaves. An evidence log's leaf `leaf_index` is the
 *                       canonical digest of the record at sequence number
 *                       `leaf_index + 1`, so every record commits to its own
 *                       position through its hashed `sequenceNumber`.
 *   log_checkpoints     checkpoint bodies the scheduler cuts (Anchor §4).
 *   anchor_publications the outbox of published values (Anchor §6, §7).
 *   anchor_lease        which scheduler instance anchors for the store. The
 *                       one mutable table: a lease is taken, renewed,
 *                       released and taken over once it expires.
 *   anchor_wallets      each publisher wallet the store has enrolled, with
 *                       the nonce its accounting starts from.
 *   anchor_wallet_txs   the wallet's transactions that are not publications
 *                       (`sweep`, `handover`), each stored before it is sent.
 *
 * WHO WRITES AN EVIDENCE LEAF
 *
 * The database does, on SQLite and Postgres: a trigger on `envelopes` writes
 * the leaf inside the transaction that stores the record. Any writer of the
 * table therefore populates the log, and a rolled-back store rolls its leaf
 * back with it. The trigger is plain SQL; it calls no function this module
 * registers, so a connection that is not the SDK's fires it too. The memory
 * adapter writes the same leaf in code (`MemoryLogStore`).
 *
 * The write follows these rules on every adapter, in this order:
 *
 *   - the record must name a position: a chain id that is a non-empty string
 *     of Unicode scalar values other than U+0000, a positive integer
 *     `sequenceNumber` and a 64-hex `canonicalDigest`, or the store is refused
 *     (`EvidenceLogRefusalError`). The adapters check the chain id before
 *     they write anything; the SQLite trigger checks it again for other
 *     writers;
 *   - write once: when the record's position already has a leaf, nothing is
 *     written and the store goes ahead. A record deleted and stored again at
 *     its position (the demo's tamper) keeps the leaf it was first logged
 *     with, which is what lets a verifier see the rewrite;
 *   - dense: a leaf is refused unless it is leaf 0 or the leaf before it is in
 *     the log (`reason: 'log_gap'`);
 *   - distinct: a leaf at a free position is refused when its record id or
 *     its digest is already a leaf of the log (`reason: 'duplicate_leaf'`).
 *     Skipping it instead would store the record without a leaf and move the
 *     chain's high-water mark past the log, so every later record of the
 *     chain would be refused with `log_gap`;
 *   - insert only: no row of these tables is updated or deleted, apart from
 *     a checkpoint's appended signatures and a publication's progress
 *     (`anchor_publications`, whose state moves forward only). On SQLite no
 *     insert or rowid change replaces a row either: REPLACE conflict
 *     resolution deletes the row it conflicts with and fires no trigger, so
 *     each table refuses an insert over a key a row holds, whatever its
 *     conflict clause (`sqliteLogTriggers`).
 *
 * UPGRADING A STORE THAT ALREADY HAS RECORDS (Tree §5.2)
 *
 * `migrateSqliteLogSchema` / `migratePostgresLogSchema` run in ONE
 * transaction: create the tables, mint the identity when the store has none,
 * create every existing chain's evidence log, backfill its leaves from the
 * stored records in sequence order (`source = 'backfill'`), and only then
 * create the density trigger and the trigger on `envelopes`. SQLite runs it
 * under BEGIN IMMEDIATE; Postgres, when it backfills, first takes `LOCK TABLE
 * envelopes IN SHARE ROW EXCLUSIVE MODE`, so a concurrent store waits for the
 * backfill instead of racing it. The trigger on `envelopes` is the marker that the backfill
 * has run: a store that has it is not backfilled again. Opening a migrated
 * SQLite store only reads it; on Postgres it replaces the functions, as the
 * rest of `ensureTables()` does, and takes no table lock. A migration that
 * fails, or whose process dies, leaves nothing behind, and the next open
 * runs it again from the start.
 *
 * The backfill writes each chain's dense prefix: its records from sequence
 * number 1 up to the first position that has no record the log can take (a
 * record that was deleted, or one with a malformed position or digest, or a
 * digest an earlier position already has). A log is dense, and an RFC 6962
 * root covers every leaf, so leaves past a missing position could never be
 * anchored. A chain that lost a record before its log existed, in the middle
 * or at the tail, therefore takes no new records afterwards: the next
 * record's predecessor leaf is absent, and the refusal (`log_gap`) names the
 * chain. `getEvidenceLogCoverage()` reports the missing positions, the
 * backfilled prefix can still be anchored, and forking the chain continues on
 * a new chain and a new log.
 */
import { createHash, randomBytes } from 'node:crypto';
import BetterSqlite3 from 'better-sqlite3';
import type { Pool, PoolClient } from 'pg';
import { Transaction, keccak256 } from 'ethers';
import { missingAttestationComponents, type AnchorArtifact, type EvidenceEnvelope } from '@tzun/engine';
import {
  ANCHOR_LOG_KIND,
  EVIDENCE_LOG_KIND,
  anchorLogOrigin,
  chainIdRefusal,
  evidenceLogOrigin as evidenceLogOriginOf,
  parseCheckpoint,
  sourceLogOrigin,
  type ChainIdRefusalReason,
} from '../attestation/checkpoint';
import { readEvmTransaction } from '../attestation/blockchain';
import { verifyMerkleProof } from '../attestation/merkle';
import { EXISTING_ROW_TAG, postgresBackdatedIdGuard } from './append-only';
import { fillAbsentArtifacts, nextAttestationStatus } from './attestation-fill';
import { nextRevisionNo } from './revision-log';

// ── Origins (Anchor §4.3) ────────────────────────────────────────────────────
//
// The origin grammar has one implementation, src/attestation/checkpoint.ts:
// the chain-id rule, the chain segment, the three origin forms and their
// reader. What is here is the store's side of Anchor §4.3.2, which a verifier
// never needs: the `ns` and store-id rules, the per-store log kinds, and the
// store-shaped signatures, which build the store's domain prefix and hand it
// to the grammar. The SQL triggers compute the same origins in SQL, held to
// vectors/evidence-log-origin-vectors.json.

export {
  ANCHOR_LOG_KIND,
  EVIDENCE_LOG_KIND,
  chainIdRefusal,
  chainSegment,
  isTestNamespace,
} from '../attestation/checkpoint';
export type { ChainIdRefusalReason } from '../attestation/checkpoint';

/** The namespace a store is minted with when none is configured: a reserved TLD that never looks routable. */
export const DEFAULT_LOG_NAMESPACE = 'local.invalid';

/** The longest `ns` a store accepts: the length limit of a DNS name (RFC 1035). */
export const LOG_NAMESPACE_MAX_LENGTH = 253;

/** The longest label of an `ns`: the length limit of a DNS label (RFC 1035). */
export const LOG_NAMESPACE_LABEL_MAX_LENGTH = 63;

/** A log kind other than `evidence`: lowercase ASCII letters and digits, starting with a letter. */
const LOG_KIND = /^[a-z][a-z0-9]*$/;
const STORE_ID = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
/** One label of an `ns`: `a`–`z` and `0`–`9`, with `-` inside but not at either end. */
const NS_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** A configured namespace the origin rules cannot take. */
export class InvalidLogNamespaceError extends Error {
  readonly code = 'invalid_log_namespace' as const;

  constructor(public readonly namespace: string, public readonly why: string) {
    super(`Log namespace ${JSON.stringify(namespace)} is not usable in a log origin: ${why}.`);
    this.name = 'InvalidLogNamespaceError';
    Object.setPrototypeOf(this, InvalidLogNamespaceError.prototype);
  }
}

/**
 * Check a namespace against the SDK origin rules and return it.
 *
 * `ns` is a lowercase DNS-style name (tzun-anchor/1 §4.3.2): one or more
 * labels of `a`–`z` and `0`–`9`, with `-` inside a label but not at either
 * end, joined by `.`. It has no `/`, so it is exactly the first segment of the
 * two-segment domain prefix `<ns>/<storeId>` that a verifier reads
 * (tzun-anchor/1 §4.3.1).
 * As in DNS, a label is at most 63 characters and the name at most 253.
 */
export function assertLogNamespace(ns: unknown): string {
  if (typeof ns !== 'string') throw new InvalidLogNamespaceError(String(ns), 'it is not a string');
  if (ns.length === 0) throw new InvalidLogNamespaceError(ns, 'it is empty');
  if (ns.length > LOG_NAMESPACE_MAX_LENGTH) {
    throw new InvalidLogNamespaceError(ns, `it is longer than ${LOG_NAMESPACE_MAX_LENGTH} characters`);
  }
  for (const label of ns.split('.')) {
    if (label.length === 0) {
      throw new InvalidLogNamespaceError(ns, 'it has an empty label (a leading, trailing or doubled ".")');
    }
    if (label.length > LOG_NAMESPACE_LABEL_MAX_LENGTH) {
      throw new InvalidLogNamespaceError(ns, `a label is longer than ${LOG_NAMESPACE_LABEL_MAX_LENGTH} characters`);
    }
    if (!NS_LABEL.test(label)) {
      throw new InvalidLogNamespaceError(
        ns,
        'it is not a lowercase DNS-style name: each label is a-z and 0-9, with "-" only inside it, and labels are joined by "."',
      );
    }
  }
  return ns;
}

/** 128 random bits as 32 lowercase hex characters: a new `store_id`. */
export function mintStoreId(): string {
  return randomBytes(16).toString('hex');
}

function assertStoreId(storeId: string): string {
  if (!STORE_ID.test(storeId)) {
    throw new TypeError(`store id ${JSON.stringify(storeId)} is not 32 lowercase hex characters`);
  }
  return storeId;
}

/** `<ns>/<storeId>`: the prefix every origin of one store shares, its anchor origin included. */
export function domainPrefix(ns: string, storeId: string): string {
  return `${assertLogNamespace(ns)}/${assertStoreId(storeId)}`;
}

/**
 * The origin of a chain's evidence log: `<ns>/<storeId>/evidence/<hex(UTF-8 chainId)>`.
 *
 * @throws {InvalidLogNamespaceError} for an `ns` outside the grammar.
 * @throws {TypeError} for a store id that is not 32 lowercase hex characters,
 *   or a value `chainIdRefusal` refuses.
 */
export function evidenceLogOrigin(ns: string, storeId: string, chainId: string): string {
  return evidenceLogOriginOf(domainPrefix(ns, storeId), chainId);
}

/**
 * The origin of a per-store log: `<ns>/<storeId>/anchors` for the anchor log,
 * `<ns>/<storeId>/<kind>` for another kind (later `custody`, `revisions`,
 * `policy`).
 *
 * @throws {TypeError} for a kind that is not lowercase ASCII letters and
 *   digits starting with a letter, or is `evidence`; then as `domainPrefix`.
 */
export function storeLogOrigin(ns: string, storeId: string, kind: string): string {
  if (!LOG_KIND.test(kind) || kind === EVIDENCE_LOG_KIND) {
    throw new TypeError(`log kind ${JSON.stringify(kind)} is not a per-store kind (lowercase letters and digits, not "evidence")`);
  }
  const prefix = domainPrefix(ns, storeId);
  return kind === ANCHOR_LOG_KIND ? anchorLogOrigin(prefix) : sourceLogOrigin(prefix, kind);
}

// ── Refusals ──────────────────────────────────────────────────────────────

/** Why a record could not be given its evidence-log leaf. */
export type EvidenceLogRefusalReason =
  | 'log_gap'
  | 'duplicate_leaf'
  | 'invalid_sequence_number'
  | 'invalid_digest'
  | ChainIdRefusalReason
  | 'store_identity_missing'
  | 'leaf_without_record'
  | 'position_taken';

const REFUSAL_REASONS: ReadonlySet<string> = new Set<EvidenceLogRefusalReason>([
  'log_gap',
  'duplicate_leaf',
  'invalid_sequence_number',
  'invalid_digest',
  'empty_chain_id',
  'invalid_chain_id',
  'store_identity_missing',
  'leaf_without_record',
  'position_taken',
]);

function refusalMessage(reason: EvidenceLogRefusalReason, chainId: unknown, sequenceNumber: unknown): string {
  const chain = typeof chainId === 'string' ? JSON.stringify(chainId) : `(${typeof chainId})`;
  switch (reason) {
    case 'log_gap':
      return (
        `The record at sequence ${String(sequenceNumber)} of chain ${chain} has no place in the chain's evidence log: ` +
        `the leaf before it is not in the log, and a log is dense. A chain that lost records before its log ` +
        `existed cannot take new ones; fork it to continue on a new chain.`
      );
    case 'duplicate_leaf':
      return (
        `The record at sequence ${String(sequenceNumber)} of chain ${chain} carries an evidence id or a canonical ` +
        `digest that is already a leaf of the chain's evidence log, at another position. The leaves of a log are ` +
        `distinct, so the record is refused.`
      );
    case 'invalid_sequence_number':
      return `The record's payload.sequenceNumber (${String(sequenceNumber)}) is not a positive integer, so it has no position in chain ${chain}'s evidence log.`;
    case 'invalid_digest':
      return `The record's integrity.canonicalDigest is not 64 lowercase hex characters, so it cannot be a leaf of chain ${chain}'s evidence log.`;
    case 'empty_chain_id':
      return 'An empty chain id names no evidence log.';
    case 'invalid_chain_id':
      return (
        `The chain id ${chain} names no evidence log: a chain id is a string of Unicode scalar values other than ` +
        `U+0000, and this one is not a string, or holds a lone UTF-16 surrogate or U+0000.`
      );
    case 'store_identity_missing':
      return `The store has no store_identity row, so it cannot name chain ${chain}'s evidence log. Opening the store through the SDK mints one.`;
    case 'leaf_without_record':
      return (
        `An evidence leaf of chain ${chain} at sequence ${String(sequenceNumber)} is not a copy of the record stored at ` +
        `that position (its evidence id, chain, sequence number and canonical digest), so the log refuses it.`
      );
    case 'position_taken':
      return (
        `Another record is already stored at sequence ${String(sequenceNumber)} of chain ${chain}. A position holds ` +
        `one record, so this one is refused; retrying does not help.`
      );
  }
}

/** The unique index that holds one record per chain position. */
export const ENVELOPES_POSITION_INDEX = 'envelopes_position';

/**
 * Whether a driver error is the `envelopes_position` unique index refusing a
 * second record at a position: SQLite names the index's expressions in its
 * message, Postgres names the index as the constraint.
 */
export function isPositionTakenViolation(err: unknown): boolean {
  const e = err as { code?: unknown; message?: unknown; constraint?: unknown } | null;
  if (e === null || typeof e !== 'object') return false;
  if (e.code === '23505') return e.constraint === ENVELOPES_POSITION_INDEX;
  if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
    const message = typeof e.message === 'string' ? e.message : '';
    return message.includes(ENVELOPES_POSITION_INDEX) || /envelopes\.chain_id, json_extract\(/.test(message);
  }
  return false;
}

/**
 * A store refused because the record could not be given its evidence-log
 * leaf. Thrown by `store()` and `storeIdempotent()` on every adapter, with the
 * same class and message; nothing of the record is written.
 */
export class EvidenceLogRefusalError extends Error {
  readonly code = 'evidence_log_refused' as const;

  /** Every refusal is final: the same record is refused on every attempt. */
  readonly retryable = false as const;

  constructor(
    public readonly reason: EvidenceLogRefusalReason,
    public readonly chainId: string,
    public readonly sequenceNumber: unknown,
    options?: { cause?: unknown },
  ) {
    super(refusalMessage(reason, chainId, sequenceNumber));
    this.name = 'EvidenceLogRefusalError';
    if (options?.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
    Object.setPrototypeOf(this, EvidenceLogRefusalError.prototype);
  }
}

/**
 * Refuse a chain id that names no evidence log (`chainIdRefusal`), before the
 * adapter writes anything. Every adapter's `store()` and `storeIdempotent()`
 * call it first, so the four implementations refuse the same chain ids,
 * whatever their driver would have written for them.
 *
 * @throws {EvidenceLogRefusalError} `empty_chain_id` or `invalid_chain_id`.
 */
export function assertEvidenceLogChainId(chainId: unknown, sequenceNumber: unknown): void {
  const reason = chainIdRefusal(chainId);
  if (reason !== null) throw new EvidenceLogRefusalError(reason, chainId as string, sequenceNumber);
}

/**
 * The SQL triggers mark each refusal with `[tzun:<reason>]` in their message,
 * and the `envelopes_position` index refuses a second record at a position.
 * Turn such a driver error into an `EvidenceLogRefusalError`; return any other
 * error unchanged.
 */
export function translateEvidenceLogError(err: unknown, chainId: string, sequenceNumber: unknown): unknown {
  if (isPositionTakenViolation(err)) {
    return new EvidenceLogRefusalError('position_taken', chainId, sequenceNumber, { cause: err });
  }
  // Read the message without `instanceof Error`: a driver error can come from
  // another realm (a native module loaded once for several VM contexts).
  const raw = (err as { message?: unknown } | null)?.message;
  const message = typeof raw === 'string' ? raw : '';
  const match = /\[tzun:([a-z_]+)\]/.exec(message);
  if (match && REFUSAL_REASONS.has(match[1])) {
    return new EvidenceLogRefusalError(match[1] as EvidenceLogRefusalReason, chainId, sequenceNumber, { cause: err });
  }
  return err;
}

/** `init` was given a namespace other than the one the store was minted with. */
export class LogNamespaceMismatchError extends Error {
  readonly code = 'log_namespace_mismatch' as const;

  constructor(public readonly stored: string, public readonly configured: string) {
    super(
      `This store's log namespace is ${JSON.stringify(stored)}, fixed when its identity was minted; ` +
        `the configured namespace ${JSON.stringify(configured)} differs. A namespace never changes under a store.`,
    );
    this.name = 'LogNamespaceMismatchError';
    Object.setPrototypeOf(this, LogNamespaceMismatchError.prototype);
  }
}

/** The store has logs but no identity: its identity row was removed. */
export class StoreIdentityMissingError extends Error {
  readonly code = 'store_identity_missing' as const;

  constructor(public readonly logCount: number) {
    super(
      `This store has ${logCount} log(s) but no store_identity row. The identity names every origin the logs ` +
        `were created under, and minting a new one would put new logs under a different prefix; the store is refused.`,
    );
    this.name = 'StoreIdentityMissingError';
    Object.setPrototypeOf(this, StoreIdentityMissingError.prototype);
  }
}

/** A SQLite store whose text encoding is not UTF-8, where `hex(chain_id)` would not be the UTF-8 hex. */
export class SqliteEncodingError extends Error {
  readonly code = 'sqlite_encoding_not_utf8' as const;

  constructor(public readonly encoding: string) {
    super(
      `This SQLite store's text encoding is ${encoding}. Evidence-log origins are computed in SQL from the UTF-8 ` +
        `bytes of the chain id, so the store must be UTF-8.`,
    );
    this.name = 'SqliteEncodingError';
    Object.setPrototypeOf(this, SqliteEncodingError.prototype);
  }
}

// ── Rows ──────────────────────────────────────────────────────────────────

/** The store's identity (Anchor §4.3.2): minted once, never changed. */
export interface StoreIdentity {
  /** 32 lowercase hex characters (128 random bits). */
  storeId: string;
  /** The namespace; `local.invalid` unless the store was minted with another. */
  ns: string;
  /** ISO 8601 instant the identity was minted. */
  createdAt: string;
}

/** Where a leaf came from: the capture trigger, the upgrade backfill, or the scheduler. */
export type LogLeafSource = 'capture' | 'backfill' | 'scheduler';

/** One `logs` row. */
export interface LogRecord {
  logId: number;
  origin: string;
  kind: string;
  /** The chain, for an evidence log; null for a per-store log. */
  chainId: string | null;
  createdAt: string;
}

/** One `log_leaves` row. */
export interface LogLeaf {
  logId: number;
  leafIndex: number;
  /** The leaf `d(i)`, 32 bytes as 64 lowercase hex. */
  leafDigest: string;
  /** What the leaf stands for: the evidence id, for an evidence log. */
  sourceRef: string;
  source: LogLeafSource;
  loggedAt: string;
}

/** A leaf a caller asks to append to a per-store log. */
export interface NewLogLeaf {
  leafIndex: number;
  leafDigest: string;
  sourceRef: string;
}

/** Where a record sits: its evidence log and its leaf. */
export interface LogPosition {
  logId: number;
  origin: string;
  chainId: string;
  leafIndex: number;
  /** The digest the log holds for the record, which may differ from the record's current one. */
  leafDigest: string;
  source: LogLeafSource;
}

/** How big a log is. */
export interface LogSize {
  /** One past the highest leaf index: the leaf count of a dense log. */
  size: number;
  /** How many leaves the log holds. Less than `size` only for a log backfilled with holes. */
  leafCount: number;
}

/** An inclusive range of leaf indices. */
export interface LeafIndexRange {
  from: number;
  to: number;
}

/**
 * How well a chain's evidence log covers the chain (Tree §5.2): which leaves
 * were written at capture and which by the upgrade backfill, and which
 * positions below the chain's high-water mark have no leaf.
 */
export interface EvidenceLogCoverage {
  chainId: string;
  logId: number;
  origin: string;
  size: number;
  leafCount: number;
  captured: number;
  backfilled: number;
  /** The chain's `last_sequence` high-water mark (0 when the store has no head for it). */
  lastSequence: number;
  /** Positions below `max(size, lastSequence)` with no leaf, as inclusive leaf-index ranges. */
  missing: LeafIndexRange[];
}

/** One `log_checkpoints` row (Anchor §4). */
export interface LogCheckpoint {
  logId: number;
  treeSize: number;
  /** RFC 6962 root, 64 lowercase hex. */
  root: string;
  /** The exact checkpoint body: `<origin>\n<size>\n<base64 root>\n`, its root line being `root` in base64. */
  body: string;
  /** SHA-256 of the body bytes, 64 lowercase hex. */
  bodyDigest: string;
  /** The right-edge subtree roots of size `treeSize`, as hex. */
  compactRange: string[];
  /** The previously anchored size this checkpoint was proved consistent with; null for the first. */
  prevAnchoredSize: number | null;
  /** PROOF(prevAnchoredSize, treeSize) as hex; null exactly when `prevAnchoredSize` is. */
  consistencyProof: string[] | null;
  /**
   * Where `bodyDigest` sits in the anchor log: the tables accept only an
   * index whose anchor-log leaf is `bodyDigest`. Always null for the anchor
   * log's own checkpoints.
   */
  anchorLeafIndex: number | null;
  epochId: number | null;
  /** Signed-note lines. Append-only. */
  signatures: string[];
  createdAt: string;
}

/** A checkpoint to insert. `signatures` defaults to none; `createdAt` is stamped by the store. */
export type NewLogCheckpoint = Omit<LogCheckpoint, 'signatures' | 'createdAt'> & { signatures?: string[] };

/**
 * What the anchoring tables say about one leaf of a source log
 * (`AnchorStore.getLeafAnchorProgress`).
 */
export interface LeafAnchorProgress {
  /**
   * Where the first checkpoint of the log past the leaf sits in the anchor
   * log: the earliest anchor leaf that commits to the leaf. Null when no
   * epoch has taken the leaf into the anchor log.
   */
  anchorLeafIndex: number | null;
  /**
   * For each kind, the publication covering that anchor leaf (its anchor size
   * is past it) that has got furthest: the earliest final one (`finalized`,
   * `obtained`), otherwise the one furthest along of those not yet final
   * (`included`, then `submitted`, then `prepared`; the earliest among
   * equals). A superseded publication covers nothing. Empty when
   * `anchorLeafIndex` is null.
   */
  publications: LeafAnchorPublication[];
}

/** A publication as `getLeafAnchorProgress` reports it: the columns that say how far it has got. */
export interface LeafAnchorPublication {
  id: number;
  kind: AnchorPublicationKind;
  state: Exclude<AnchorPublicationState, 'superseded'>;
  anchorSize: number;
  p: string;
  chain: string | null;
  /** The mined transaction, otherwise the latest one sent; null before one is sent. */
  transactionId: string | null;
  blockNumber: number | null;
  fillProgress: Record<string, unknown> | null;
}

// ── Publications and their state machine (Anchor §7) ─────────

/** The publication kinds of Anchor §7 (`witness/1` is reserved and not stored yet). */
export const ANCHOR_PUBLICATION_KINDS = ['evm-calldata/1', 'rfc3161/1'] as const;
export type AnchorPublicationKind = (typeof ANCHOR_PUBLICATION_KINDS)[number];

/**
 * Publication states.
 *
 *   prepared    P is persisted with its epoch; nothing has been sent.
 *   submitted   EVM: a signed transaction is persisted (and broadcast, or about to be).
 *   included    EVM: a receipt places it in a block.
 *   finalized   EVM: that block is at or below the chain's finalized tag.
 *   obtained    RFC 3161: the token over P is stored.
 *   superseded  EVM: every broadcast was rejected, and a later epoch took the nonce.
 *               The tables refuse the move while any attempt's broadcast is
 *               `accepted` or `unknown`.
 */
export const ANCHOR_PUBLICATION_STATES = [
  'prepared',
  'submitted',
  'included',
  'finalized',
  'obtained',
  'superseded',
] as const;
export type AnchorPublicationState = (typeof ANCHOR_PUBLICATION_STATES)[number];

/** Which states each kind can be in. */
export const ANCHOR_PUBLICATION_STATES_BY_KIND: Readonly<Record<AnchorPublicationKind, readonly AnchorPublicationState[]>> = {
  'evm-calldata/1': ['prepared', 'submitted', 'included', 'finalized', 'superseded'],
  'rfc3161/1': ['prepared', 'obtained'],
};

/**
 * Every state change a publication may make. State moves forward only, with one
 * exception: a reorg returns an `included` transaction to `submitted`, to be
 * rebroadcast. `finalized`, `obtained` and `superseded` are final. Only a
 * `submitted` publication is superseded: one never sent has no attempt for the
 * node to have refused. The SQL triggers are generated from this table.
 */
export const ANCHOR_PUBLICATION_TRANSITIONS: Readonly<Record<AnchorPublicationState, readonly AnchorPublicationState[]>> = {
  prepared: ['submitted', 'obtained'],
  submitted: ['included', 'superseded'],
  included: ['finalized', 'submitted'],
  finalized: [],
  obtained: [],
  superseded: [],
};

/** True when `from → to` is a change the publication tables accept (a same-state write always is). */
export function isAllowedPublicationTransition(from: AnchorPublicationState, to: AnchorPublicationState): boolean {
  return from === to || ANCHOR_PUBLICATION_TRANSITIONS[from].includes(to);
}

/**
 * What the node said to a broadcast. `unknown` counts as accepted: only a
 * publication whose every attempt was `rejected` may be superseded.
 */
export const ANCHOR_BROADCAST_OUTCOMES = ['accepted', 'rejected', 'unknown'] as const;
export type AnchorBroadcastOutcome = (typeof ANCHOR_BROADCAST_OUTCOMES)[number];

/** One broadcast attempt of an EVM publication. `txHash` and `rawTx` never change once stored. */
export interface AnchorPublicationAttempt {
  txHash: string;
  /** The signed raw transaction, persisted before it is broadcast. */
  rawTx: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  sentAt: string;
  broadcast: AnchorBroadcastOutcome;
}

/** One `anchor_publications` row. */
export interface AnchorPublication {
  id: number;
  epochId: number;
  anchorSize: number;
  /**
   * The published value: SHA-256 of the anchor checkpoint body, 64 lowercase
   * hex. The tables accept only the `bodyDigest` of the anchor log's stored
   * checkpoint at `anchorSize`.
   */
  p: string;
  kind: AnchorPublicationKind;
  state: AnchorPublicationState;
  /**
   * The epoch was cut by `anchorNow({ force: true })` when the cadence would
   * not have cut it. Fixed from insert: forced publications are what the
   * rolling force limit counts.
   */
  forced: boolean;
  /** CAIP-2 chain (`eip155:<id>`) for an EVM publication; null for RFC 3161. */
  chain: string | null;
  /**
   * The publisher's address, `0x` and 40 lowercase hex digits: one spelling,
   * so that `(chain, fromAddress, nonce)` is unique among the publications
   * that are not superseded.
   */
  fromAddress: string | null;
  nonce: number | null;
  attempts: AnchorPublicationAttempt[];
  minedTxHash: string | null;
  blockNumber: number | null;
  blockHash: string | null;
  blockHeader: string | null;
  /** The transaction's index in its block: its key in the transactions trie is `rlp(txIndex)`. */
  txIndex: number | null;
  txTrieProof: string[] | null;
  /** Decimal string. */
  gasUsed: string | null;
  /** Decimal string, in wei. */
  effectiveGasPrice: string | null;
  /** Base64 TimeStampResp. */
  token: string | null;
  genTime: string | null;
  fillProgress: Record<string, unknown> | null;
  error: string | null;
  createdAt: string;
  updatedAt: string;
}

/** A publication to insert. It starts `prepared`, with nothing sent. */
export interface NewAnchorPublication {
  epochId: number;
  anchorSize: number;
  p: string;
  kind: AnchorPublicationKind;
  chain?: string | null;
  /** Default false. */
  forced?: boolean;
}

/** The columns an update may write; the triggers decide which changes are allowed. */
export type AnchorPublicationPatch = Partial<
  Pick<
    AnchorPublication,
    | 'state'
    | 'fromAddress'
    | 'nonce'
    | 'attempts'
    | 'minedTxHash'
    | 'blockNumber'
    | 'blockHash'
    | 'blockHeader'
    | 'txIndex'
    | 'txTrieProof'
    | 'gasUsed'
    | 'effectiveGasPrice'
    | 'token'
    | 'genTime'
    | 'fillProgress'
    | 'error'
  >
>;

/**
 * What one epoch persists, in one transaction: the leaves
 * appended to per-store logs (the anchor log first among them), the
 * checkpoints cut, and the publications to send.
 */
export interface EpochWrite {
  leaves: Array<{ logId: number; leaves: NewLogLeaf[] }>;
  checkpoints: NewLogCheckpoint[];
  publications: NewAnchorPublication[];
  /** The state the epoch was planned on, checked in the same transaction before anything is written. */
  guard?: EpochGuard;
}

/**
 * What an epoch's transaction checks before it writes.
 * The epoch is refused with `AnchorEpochFenceError` unless:
 *
 *   - `holder` holds `domain`'s lease and the lease has not expired, by the
 *     database's clock (Postgres locks the lease row until the epoch commits);
 *   - no EVM publication other than `supersedes` is unmined (`prepared` or
 *     `submitted`);
 *   - the largest anchor size broadcast (the EVM publications `submitted`,
 *     `included` or `finalized`, `supersedes` aside) is `publishedAnchorSize`,
 *     the size the anchor checkpoint's consistency proof starts from.
 *
 * `supersedes`, a publication whose every broadcast was rejected, moves to
 * `superseded` in the same transaction.
 */
export interface EpochGuard {
  domain: string;
  holder: string;
  publishedAnchorSize: number | null;
  supersedes?: number | null;
}

/** Why an epoch's transaction refused to write. */
export type AnchorEpochFenceReason = 'lease_not_held' | 'publication_unmined' | 'published_size_moved';

/**
 * An epoch planned on a state that no longer holds: another instance took
 * the lease, or published, while the epoch was being planned. Nothing of the
 * epoch is written.
 */
export class AnchorEpochFenceError extends Error {
  readonly code = 'anchor_epoch_fenced' as const;

  constructor(readonly reason: AnchorEpochFenceReason, detail: string) {
    super(`anchor epoch refused (${reason}): ${detail}`);
    this.name = 'AnchorEpochFenceError';
    Object.setPrototypeOf(this, AnchorEpochFenceError.prototype);
  }
}

/** The guard's reads, as both dialects run them (`?` placeholders; Postgres numbers them). */
const EPOCH_GUARD_UNMINED_SQL = `SELECT id FROM anchor_publications
   WHERE kind = 'evm-calldata/1' AND state IN ('prepared', 'submitted') AND id <> ? ORDER BY id LIMIT 1`;
const EPOCH_GUARD_PUBLISHED_SQL = `SELECT MAX(anchor_size) AS published FROM anchor_publications
   WHERE kind = 'evm-calldata/1' AND state IN ('submitted', 'included', 'finalized') AND id <> ?`;

/** Check what the guard's reads returned. */
function assertEpochGuard(
  guard: EpochGuard,
  leaseHeld: boolean,
  unmined: number | null,
  published: number | null,
): void {
  if (!leaseHeld) {
    throw new AnchorEpochFenceError('lease_not_held', `${guard.holder} does not hold the unexpired lease of ${guard.domain}`);
  }
  if (unmined !== null) throw new AnchorEpochFenceError('publication_unmined', `publication ${unmined} is unmined`);
  if (published !== guard.publishedAnchorSize) {
    throw new AnchorEpochFenceError(
      'published_size_moved',
      `the published anchor size is ${published ?? 'none'}, not ${guard.publishedAnchorSize ?? 'none'}`,
    );
  }
}

// ── Lease, wallets and accounted transactions ─────────

/**
 * The prefix every lease holder carries: the scheduler takes the lease as
 * `tzun-anchor/2:<holder id>`, and the SDK's stores refuse a holder without
 * it, so a scheduler of an SDK release before 0.8.0, which has no sign gate,
 * can neither take nor renew the lease of a store a 0.8.0 process has opened.
 */
export const ANCHOR_LEASE_HOLDER_PREFIX = 'tzun-anchor/2:';

/**
 * Who anchors for a domain. `domain` is the store's domain
 * prefix, `<ns>/<storeId>`. The lease is held until `expiresAt` and renewed
 * by its holder; once it has expired anyone may take it. Expiry is judged by
 * the database's clock, so replicas with skewed clocks agree on it.
 */
export interface AnchorLease {
  domain: string;
  holder: string;
  /** ISO 8601. */
  expiresAt: string;
}

/**
 * A publisher wallet enrolled for a domain. Nonce accounting runs from
 * `nonceBase`, the wallet's transaction count when it was enrolled, never from
 * 0: a wallet may have sent transactions before it was a publisher.
 * INSERT-only; `retiredAt` is set once.
 */
export interface AnchorWallet {
  /** `0x` and 40 lowercase hex. */
  address: string;
  /** CAIP-2, `eip155:<id>`. */
  chain: string;
  /** The domain prefix the wallet publishes for: `<ns>/<storeId>`. */
  domain: string;
  nonceBase: number;
  enrolledAt: string;
  retiredAt: string | null;
}

/** The accounted kinds of wallet transaction that are not publications (Anchor §7.2 rule 2). */
export const ANCHOR_WALLET_TX_KINDS = ['sweep', 'handover'] as const;
export type AnchorWalletTxKind = (typeof ANCHOR_WALLET_TX_KINDS)[number];

/**
 * A wallet transaction that is not a publication, stored before it is sent,
 * so that nonce accounting can name every nonce the wallet uses:
 *
 *   sweep     returning the balance when the wallet is retired;
 *   handover  the last nonce of one domain, when the wallet passes to another
 *             after a wipe (Anchor §4.3.2).
 *
 * INSERT-only. `txHash` is `keccak256(rawTx)`, and the signed transaction's
 * sender, nonce and chain are the row's: the store checks all three before it
 * writes the row.
 */
export interface AnchorWalletTx {
  address: string;
  chain: string;
  nonce: number;
  txHash: string;
  kind: AnchorWalletTxKind;
  rawTx: string;
  createdAt: string;
}

/** An accounted transaction to insert; `createdAt` is stamped by the store. */
export type NewAnchorWalletTx = Omit<AnchorWalletTx, 'createdAt'>;

/** The revision `cause` an anchor fill writes. */
export const ANCHOR_FILL_CAUSE = 'anchor_fill' as const;

/** The actor an anchor fill's revision row is attributed to: the unattended scheduler. */
export const REVISION_ACTOR_ANCHOR = 'tzun-anchor';

/** One record's anchor, to be filled into `nonRepudiation.anchor`. */
export interface AnchorFill {
  evidenceId: string;
  /**
   * The evidence log the record's leaf is in, the log `anchor.logCheckpoint`
   * names. The scheduler's fill always sets it. A store whose evidence ids
   * are unique only per log's scope (a tenant) finds the record by it; the
   * SDK's stores, whose evidence ids are unique, do not read it.
   */
  logId?: number;
  /** The `nonRepudiation.anchor` value (tzun-anchor/1 §8). */
  anchor: AnchorArtifact;
}

/** One chunk of a publication's fill, written in one transaction. */
export interface AnchorFillChunk {
  publicationId: number;
  fills: AnchorFill[];
  /**
   * The record's status with the anchor in place, computed by the caller with
   * the engine's one rule (`determineAttestationStatus`) from the envelope as
   * it will be stored. The store keeps two statuses whatever it returns: a
   * `complete` record stays `complete`, and a `pending` record that still has
   * no timestamp stays `pending` unless `timestampExpected` is `false` (see
   * `fillStatus`).
   */
  statusOf(envelope: EvidenceEnvelope): EvidenceEnvelope['attestationStatus'];
  /**
   * `false` when the store's writers are known not to expect a timestamp
   * (their expectation says `timestamp: false`, as a `Tzun` that anchors
   * without obtaining timestamps does). Absent or `true`, a `pending` record
   * without a timestamp may be waiting for one, and stays `pending`.
   */
  timestampExpected?: boolean;
  /** The publication's `fill_progress` after this chunk, written in the same transaction. */
  fillProgress: Record<string, unknown>;
}

/** What one chunk did. */
export interface AnchorFillResult {
  /** Records that gained `nonRepudiation.anchor`, each with an `anchor_fill` revision row. */
  filled: number;
  /** Records that already had an anchor: fill-only, so nothing was written for them. */
  alreadyAnchored: number;
  /** Evidence ids with no stored record. */
  missing: string[];
  /**
   * Evidence ids whose stored record does not match its leaf
   * (`anchorFillConflict`): another chain, another position, or a digest the
   * artifact's log path does not place under its log checkpoint. Nothing is
   * written to them.
   */
  conflicts: string[];
}

/**
 * Why a stored record cannot take the anchor a fill carries for it, or null
 * when it can: the record's `payload.sequenceNumber` is not the leaf's index
 * plus one, its chain is not the evidence log's (`logChainId`, when the store
 * knows it), or the artifact's log path does not place the record's
 * `integrity.canonicalDigest` at that index under the artifact's log
 * checkpoint, the check a verifier makes. Every store makes it before it writes
 * an artifact, and a store kept outside the SDK can call it.
 */
export function anchorFillConflict(
  envelope: EvidenceEnvelope,
  rowChainId: string | null,
  logChainId: string | null,
  fill: Pick<AnchorFill, 'anchor'>,
): 'position' | 'chain' | 'digest' | null {
  const anchor = fill.anchor;
  const seq = (envelope as { payload?: { sequenceNumber?: unknown } }).payload?.sequenceNumber;
  if (typeof seq !== 'number' || !Number.isSafeInteger(anchor?.leafIndex) || seq !== anchor.leafIndex + 1) return 'position';
  if (logChainId !== null && rowChainId !== logChainId) return 'chain';
  const parsed = parseCheckpoint(anchor.logCheckpoint);
  const digest = (envelope as { integrity?: { canonicalDigest?: unknown } }).integrity?.canonicalDigest;
  if (!parsed.ok || typeof digest !== 'string' || !Array.isArray(anchor.logPath)) return 'digest';
  return verifyMerkleProof(digest, anchor.leafIndex, parsed.checkpoint.size, anchor.logPath, parsed.checkpoint.root) ? null : 'digest';
}

// ── Interfaces ───────────────────────────────────────────────────────────

/** Reading a store's identity and its logs. Every in-tree adapter provides one. */
export interface LogStore {
  getStoreIdentity(): Promise<StoreIdentity>;
  /** Every log, in creation order. */
  listLogs(): Promise<LogRecord[]>;
  getLog(logId: number): Promise<LogRecord | null>;
  /** A chain's evidence log, or null before the chain's first record. */
  getEvidenceLog(chainId: string): Promise<LogRecord | null>;
  getLogSize(logId: number): Promise<LogSize>;
  /** The leaves with `fromIndex <= leafIndex < toIndex`, in index order. */
  listLogLeaves(logId: number, fromIndex: number, toIndex: number): Promise<LogLeaf[]>;
  /** Where a record sits in its chain's evidence log, or null when it has no leaf. */
  getEvidenceLogPosition(evidenceId: string): Promise<LogPosition | null>;
  /** Coverage of every evidence log, in chain-id order. */
  getEvidenceLogCoverage(): Promise<EvidenceLogCoverage[]>;
}

/**
 * The writes the anchor scheduler makes. SQLite and Postgres
 * provide it; the memory adapter does not, because anchoring is refused there.
 */
export interface AnchorStore {
  /** A per-store log of `kind`, created on first use with its origin. */
  ensureStoreLog(kind: string): Promise<LogRecord>;
  /** Append leaves to a per-store log, in order. Dense and write-once, like every leaf. */
  appendLogLeaves(logId: number, leaves: NewLogLeaf[]): Promise<void>;
  insertLogCheckpoint(checkpoint: NewLogCheckpoint): Promise<void>;
  getLogCheckpoint(logId: number, treeSize: number): Promise<LogCheckpoint | null>;
  /** A log's checkpoints in size order. */
  listLogCheckpoints(logId: number): Promise<LogCheckpoint[]>;
  /** A log's largest checkpoint, or null. One index seek. */
  getLastLogCheckpoint(logId: number): Promise<LogCheckpoint | null>;
  /** A log's largest checkpoint that is in the anchor log (`anchorLeafIndex` set), or null. One index seek. */
  getLastAnchoredCheckpoint(logId: number): Promise<LogCheckpoint | null>;
  /**
   * A log's largest checkpoint whose anchor leaf is below `anchorSize`, or
   * null: the newest checkpoint of the log the anchor checkpoint of that size
   * commits to. A backward seek of the anchored-checkpoint index, which passes
   * over only the checkpoints anchored at or after `anchorSize`.
   */
  getLastAnchoredCheckpointBelow(logId: number, anchorSize: number): Promise<LogCheckpoint | null>;
  /** A log's largest checkpoint of size at most `treeSize`, or null. One seek of the primary key. */
  getLogCheckpointAtOrBelow(logId: number, treeSize: number): Promise<LogCheckpoint | null>;
  /** The checkpoints whose digest is anchor-log leaf `fromLeaf <= anchorLeafIndex < toLeaf`, in anchor-leaf order. */
  listCheckpointsByAnchorLeaf(fromLeaf: number, toLeaf: number): Promise<LogCheckpoint[]>;
  /** Append signed-note lines to a checkpoint. The existing lines never change. */
  appendCheckpointSignatures(logId: number, treeSize: number, signatures: string[]): Promise<void>;
  insertAnchorPublication(publication: NewAnchorPublication): Promise<AnchorPublication>;
  getAnchorPublication(id: number): Promise<AnchorPublication | null>;
  /**
   * The publication of `kind` at anchor size `anchorSize`, or null. One seek
   * of the `(kind, anchor_size)` index: a kind has at most one publication per
   * anchor size.
   */
  getAnchorPublicationAt(kind: AnchorPublicationKind, anchorSize: number): Promise<AnchorPublication | null>;
  /**
   * The largest anchor size with a final publication of `kind` (`finalized`,
   * `obtained`), or null. A backward seek of the `(kind, anchor_size)` index,
   * which passes over only the publications of that kind not final yet.
   */
  getLastFinalAnchorSize(kind: AnchorPublicationKind): Promise<number | null>;
  /** Publications in id order, optionally of one kind and in some states. */
  listAnchorPublications(filter?: { kind?: AnchorPublicationKind; states?: AnchorPublicationState[] }): Promise<AnchorPublication[]>;
  /**
   * How far the anchor of leaf `leafIndex` of log `logId` has got, or null
   * when the store has no anchor log. Indexed reads that return at most one
   * checkpoint and four publications, whatever the number of epochs.
   */
  getLeafAnchorProgress(logId: number, leafIndex: number): Promise<LeafAnchorProgress | null>;
  /** Write a patch; the tables refuse a backward state change and a rewrite of anything fixed. */
  updateAnchorPublication(id: number, patch: AnchorPublicationPatch): Promise<AnchorPublication>;
  /**
   * Persist one epoch in one transaction; returns the publications it created.
   *
   * @throws {AnchorEpochFenceError} when `write.guard` no longer holds; nothing is written.
   */
  persistEpoch(write: EpochWrite): Promise<AnchorPublication[]>;

  /**
   * Take or renew the domain's lease for `ttlMs`, and return the lease as it
   * stands afterwards. The caller holds it exactly when `holder` is its own:
   * the lease is taken only when it is free, expired or already the caller's.
   */
  acquireAnchorLease(domain: string, holder: string, ttlMs: number): Promise<AnchorLease>;
  getAnchorLease(domain: string): Promise<AnchorLease | null>;
  /** Give the lease up, when `holder` holds it. */
  releaseAnchorLease(domain: string, holder: string): Promise<void>;

  /**
   * Enrol a publisher wallet, once, for the store's own domain prefix with a
   * nonce base that is an integer at or above 0. Arguments the table refuses
   * are refused whether or not the wallet is enrolled. A wallet already
   * enrolled on that chain keeps its row, whatever nonce base is asked for:
   * the returned row is the stored one.
   */
  enrolAnchorWallet(wallet: Pick<AnchorWallet, 'address' | 'chain' | 'domain' | 'nonceBase'>): Promise<AnchorWallet>;
  getAnchorWallet(address: string, chain: string): Promise<AnchorWallet | null>;
  /** Set `retiredAt`, once. */
  retireAnchorWallet(address: string, chain: string): Promise<AnchorWallet>;
  /** Store an accounted transaction before it is sent. */
  insertAnchorWalletTx(tx: NewAnchorWalletTx): Promise<AnchorWalletTx>;
  /** A wallet's accounted transactions, in nonce order. */
  listAnchorWalletTxs(address: string, chain: string): Promise<AnchorWalletTx[]>;

  /**
   * Fill `nonRepudiation.anchor` into a chunk of records and record the
   * publication's progress, in one transaction. Fill-only: a record that
   * already has an anchor is left as it is. Each record that is
   * filled gets one revision row, cause `anchor_fill`.
   */
  fillAnchorArtifacts(chunk: AnchorFillChunk): Promise<AnchorFillResult>;

  /**
   * A stored record's `nonRepudiation.anchor`, or null when the record has
   * none or is not stored. Optional: the fill reads it to check that its
   * stored progress stands after a record that carries the publication's
   * artifact; a store without it has that progress taken as it is.
   */
  getRecordAnchor?(evidenceId: string): Promise<unknown>;
}

/** An adapter that holds evidence logs. */
export interface LogStoreProvider {
  logStore(): LogStore;
}

/** An adapter that holds the anchoring tables. */
export interface AnchorStoreProvider {
  anchorStore(): AnchorStore;
}

/** The adapter's log store, or undefined for an adapter without one (the cloud transport, a custom adapter). */
export function logStoreFor(storage: unknown): LogStore | undefined {
  const provider = storage as Partial<LogStoreProvider> | null;
  return provider && typeof provider.logStore === 'function' ? provider.logStore() : undefined;
}

/** The adapter's anchor store, or undefined for an adapter without one. */
export function anchorStoreFor(storage: unknown): AnchorStore | undefined {
  const provider = storage as Partial<AnchorStoreProvider> | null;
  return provider && typeof provider.anchorStore === 'function' ? provider.anchorStore() : undefined;
}

/** Options every adapter takes for its logs. */
export interface LogSchemaOptions {
  /**
   * The namespace (`ns`) of the store's origins. Used when the store's
   * identity is minted; on a store that has one, a different value is
   * refused with `LogNamespaceMismatchError`. Absent: `local.invalid` for a
   * new store, and whatever the store holds for an existing one.
   */
  logNamespace?: string;
}

/**
 * @internal Test seam. `afterBackfill` runs inside the upgrade migration,
 * after the leaves are backfilled and before any trigger is created: the
 * point at which an interrupted migration would do the most harm if it were
 * not one transaction. SQLite calls it synchronously; Postgres awaits it.
 */
export const logMigrationTestHooks: { afterBackfill?: () => void | Promise<void> } = {};

// ── Shared checks ────────────────────────────────────────────────────────

function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/**
 * Refuse a checkpoint whose digest is not the SHA-256 of its body, or whose
 * root line is not its `root` in base64. The tables check the body's shape and
 * its origin and size lines, and Postgres checks the root line too; SQLite has
 * neither SHA-256 nor base64, so both checks are made here for every adapter.
 */
function assertCheckpointBody(checkpoint: NewLogCheckpoint): void {
  if (!HEX64.test(checkpoint.bodyDigest) || sha256Hex(checkpoint.body) !== checkpoint.bodyDigest) {
    throw new Error(
      `log_checkpoints: bodyDigest is not the SHA-256 of the checkpoint body (log ${checkpoint.logId}, size ${checkpoint.treeSize})`,
    );
  }
  const rootLine = typeof checkpoint.body === 'string' ? checkpoint.body.split('\n')[2] : undefined;
  if (!HEX64.test(checkpoint.root) || rootLine !== Buffer.from(checkpoint.root, 'hex').toString('base64')) {
    throw new Error(
      `log_checkpoints: the body's root line is not the root in base64 (log ${checkpoint.logId}, size ${checkpoint.treeSize})`,
    );
  }
}

const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const EIP155_CHAIN = /^eip155:([1-9][0-9]*)$/;

/**
 * Refuse an accounted transaction that tzun-anchor/1 §10.4 item 2 does not
 * read (`readEvmTransaction`), whose hash is not `keccak256(rawTx)`, or whose
 * signed sender, nonce or chain is not the row's. The sender and chain are
 * item 2's reading, so a stored twin with n − s and the recovery parity
 * flipped, or the same values in RLP that is not canonical, is refused by the
 * rule it breaks, though a more lenient reader recovers the same sender from
 * it. Neither SQL dialect can hash or parse a transaction, so every
 * `insertAnchorWalletTx` makes the check before it writes, and the scheduler
 * makes it on every accounted transaction it reads (exported from the package
 * root as `assertAnchorWalletTx`, for a store kept outside the SDK).
 *
 * @throws {Error} naming the row and what is wrong with it.
 */
export function assertWalletTx(tx: NewAnchorWalletTx): void {
  const where = `anchor_wallet_txs (${tx.address}, ${tx.chain}, nonce ${tx.nonce})`;
  if (!EVM_ADDRESS.test(tx.address)) throw new Error(`${where}: the address is not 0x and 40 lowercase hex`);
  const chainId = EIP155_CHAIN.exec(tx.chain)?.[1];
  if (chainId === undefined) throw new Error(`${where}: the chain is not eip155:<id>`);
  const reading = readEvmTransaction(tx.rawTx);
  if (!reading.ok) {
    throw new Error(
      reading.rule === null
        ? `${where}: rawTx is not a signed transaction`
        : `${where}: rawTx breaks the ${reading.rule} rule of tzun-anchor/1 §10.4 item 2`,
    );
  }
  let parsed: Transaction;
  try {
    parsed = Transaction.from(tx.rawTx);
  } catch {
    throw new Error(`${where}: rawTx is not a signed transaction`);
  }
  if (keccak256(tx.rawTx) !== tx.txHash) {
    throw new Error(`${where}: txHash is not keccak256(rawTx)`);
  }
  const { sender, chainId: signedChainId } = reading.transaction;
  if (sender !== tx.address || parsed.nonce !== tx.nonce || signedChainId !== BigInt(chainId)) {
    throw new Error(`${where}: the signed transaction's sender, nonce or chain is not the row's`);
  }
}

function sqlList(values: readonly string[]): string {
  return values.map((v) => `'${v.replace(/'/g, "''")}'`).join(', ');
}

/** `(kind = 'k' AND state IN (...)) OR ...`, from ANCHOR_PUBLICATION_STATES_BY_KIND. */
function sqlStatesByKind(): string {
  return Object.entries(ANCHOR_PUBLICATION_STATES_BY_KIND)
    .map(([kind, states]) => `(kind = '${kind}' AND state IN (${sqlList(states)}))`)
    .join(' OR ');
}

/** `(OLD.state = 'a' AND NEW.state IN (...)) OR ...`, from ANCHOR_PUBLICATION_TRANSITIONS. */
function sqlAllowedTransition(): string {
  return Object.entries(ANCHOR_PUBLICATION_TRANSITIONS)
    .filter(([, to]) => to.length > 0)
    .map(([from, to]) => `(OLD.state = '${from}' AND NEW.state IN (${sqlList(to)}))`)
    .join(' OR ');
}

/** The EVM columns that stop changing once a publication is finalized (a null may still be filled). */
const FIXED_AFTER_FINALITY = [
  'mined_tx_hash',
  'block_number',
  'block_hash',
  'block_header',
  'tx_index',
  'tx_trie_proof',
  'gas_used',
  'effective_gas_price',
] as const;

/** Written once: null until set, then fixed. */
const WRITTEN_ONCE = ['from_address', 'nonce', 'token', 'gen_time'] as const;

/** Fixed from insert. */
const PUBLICATION_IDENTITY = ['id', 'epoch_id', 'anchor_size', 'p', 'kind', 'forced', 'chain', 'created_at'] as const;

/** `anchor_wallets`: fixed from insert; only `retired_at` moves, once. */
const WALLET_FIXED = ['address', 'chain', 'domain', 'nonce_base', 'enrolled_at'] as const;

/**
 * How a condition both dialects check names a table and the row being
 * written. A SQLite trigger names both as they are. A Postgres trigger
 * function runs the condition with EXECUTE (`pgExecute`), where a table is
 * named through the schema of the trigger's table and the row is the
 * statement's `$1`.
 */
interface SqlNames {
  table(name: string): string;
  readonly row: string;
}

const SQLITE_NAMES: SqlNames = { table: (name) => name, row: 'NEW' };
const PG_EXECUTE_NAMES: SqlNames = { table: (name) => `%1$I.${name}`, row: '($1)' };

/**
 * An accounted transaction's nonce is not one a publication of the same
 * wallet holds (a superseded one aside), and its wallet is enrolled, not
 * retired, and has an accounting base at or below the nonce. Both dialects.
 */
const sqlWalletTxNonceFree = ({ table, row }: SqlNames): string => `(
    EXISTS (SELECT 1 FROM ${table('anchor_wallets')} w
             WHERE w.address = ${row}.address AND w.chain = ${row}.chain
               AND w.retired_at IS NULL AND w.nonce_base <= ${row}.nonce)
    AND NOT EXISTS (SELECT 1 FROM ${table('anchor_publications')} p
                     WHERE p.chain = ${row}.chain AND p.from_address = ${row}.address
                       AND p.nonce = ${row}.nonce AND p.state <> 'superseded'))`;

/**
 * One nonce per sender and chain among the publications that are not
 * superseded: a later epoch takes a nonce only after the publication that held
 * it has moved to `superseded`. Both dialects run the statement as is.
 */
const ANCHOR_NONCE_INDEX_SQL = `CREATE UNIQUE INDEX IF NOT EXISTS idx_anchor_publications_nonce
    ON anchor_publications(chain, from_address, nonce) WHERE state <> 'superseded';`;

/**
 * The anchored checkpoints, by log and size (a log's last anchored
 * checkpoint is one seek) and by anchor leaf (an epoch's source checkpoints
 * are one range). Both dialects run the statements as is.
 */
const CHECKPOINT_INDEX_SQL = `CREATE INDEX IF NOT EXISTS idx_log_checkpoints_anchored
    ON log_checkpoints(log_id, tree_size) WHERE anchor_leaf_index IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_log_checkpoints_anchor_leaf
    ON log_checkpoints(anchor_leaf_index) WHERE anchor_leaf_index IS NOT NULL;`;

/**
 * A publication takes a nonce only when no accounted wallet transaction holds
 * it and its wallet is not retired: the twin of sqlWalletTxNonceFree, so that
 * neither side can take a nonce the other holds. Both dialects.
 */
const sqlPublicationNonceFree = ({ table, row }: SqlNames): string => `(
    NOT EXISTS (SELECT 1 FROM ${table('anchor_wallet_txs')} t
                 WHERE t.chain = ${row}.chain AND t.address = ${row}.from_address AND t.nonce = ${row}.nonce)
    AND NOT EXISTS (SELECT 1 FROM ${table('anchor_wallets')} w
                     WHERE w.chain = ${row}.chain AND w.address = ${row}.from_address AND w.retired_at IS NOT NULL))`;

/** The row's `p` is the body digest of the anchor log's stored checkpoint at its `anchor_size` (Anchor §6). Both dialects. */
const sqlPIsAnchorCheckpoint = ({ table, row }: SqlNames): string => `EXISTS (
    SELECT 1 FROM ${table('log_checkpoints')} c JOIN ${table('logs')} a ON a.log_id = c.log_id
     WHERE a.kind = '${ANCHOR_LOG_KIND}' AND a.chain_id IS NULL
       AND c.tree_size = ${row}.anchor_size AND c.body_digest = ${row}.p)`;

/**
 * The row's `anchor_leaf_index` is null, or it names the anchor-log leaf that
 * holds its `body_digest` and the checkpoint is not the anchor log's own
 * (Anchor §5). Both dialects.
 */
const sqlAnchorLeafIndexOk = ({ table, row }: SqlNames): string => `(${row}.anchor_leaf_index IS NULL OR (
    NOT EXISTS (SELECT 1 FROM ${table('logs')} WHERE log_id = ${row}.log_id AND kind = '${ANCHOR_LOG_KIND}')
    AND EXISTS (SELECT 1 FROM ${table('log_leaves')} x JOIN ${table('logs')} a ON a.log_id = x.log_id
                 WHERE a.kind = '${ANCHOR_LOG_KIND}' AND a.chain_id IS NULL
                   AND x.leaf_index = ${row}.anchor_leaf_index AND x.leaf_digest = ${row}.body_digest)))`;

/** Fixed from insert; only `signatures` moves. */
const CHECKPOINT_FIXED = [
  'log_id',
  'tree_size',
  'root',
  'body',
  'body_digest',
  'compact_range',
  'prev_anchored_size',
  'consistency_proof',
  'anchor_leaf_index',
  'epoch_id',
  'created_at',
] as const;

// ── SQLite ───────────────────────────────────────────────────────────────

const SQLITE_NOW = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";
const SQLITE_HEX64 = (col: string): string => `(length(${col}) = 64 AND ${col} NOT GLOB '*[^0-9a-f]*')`;
const SQLITE_DECIMAL = (col: string): string => `(${col} IS NULL OR (${col} <> '' AND ${col} NOT GLOB '*[^0-9]*'))`;
const SQLITE_JSON_ARRAY = (col: string): string => `(json_valid(${col}) AND json_type(${col}) = 'array')`;
/** `0x` and 40 lowercase hex: one spelling per address. */
const SQLITE_ADDRESS = (col: string): string =>
  `(length(${col}) = 42 AND substr(${col}, 1, 2) = '0x' AND substr(${col}, 3) NOT GLOB '*[^0-9a-f]*')`;
/** `eip155:` and a decimal chain id with no leading zero. */
const SQLITE_EIP155 = (col: string): string => `(${col} GLOB 'eip155:[1-9]*' AND substr(${col}, 8) NOT GLOB '*[^0-9]*')`;
/** The store's domain prefix, `<ns>/<storeId>`, from `store_identity`. Both dialects. */
const sqlDomainPrefix = ({ table }: SqlNames): string => `(SELECT ns || '/' || store_id FROM ${table('store_identity')})`;

/**
 * `ns` as `assertLogNamespace` takes it, in GLOB: only `a`–`z`, `0`–`9`, `-`
 * and `.`; no `.` or `-` at either end; no empty label and no label that
 * starts or ends with `-`; no run of more than 63 label characters.
 */
const SQLITE_VALID_NS = (col: string): string => `(typeof(${col}) = 'text'
      AND length(${col}) BETWEEN 1 AND ${LOG_NAMESPACE_MAX_LENGTH}
      AND ${col} NOT GLOB '*[^-a-z0-9.]*'
      AND ${col} NOT GLOB '[-.]*' AND ${col} NOT GLOB '*[-.]'
      AND ${col} NOT GLOB '*..*' AND ${col} NOT GLOB '*.-*' AND ${col} NOT GLOB '*-.*'
      AND ${col} NOT GLOB '*${'[-a-z0-9]'.repeat(LOG_NAMESPACE_LABEL_MAX_LENGTH + 1)}*')`;

/**
 * A SQLite chain id `chainIdRefusal` refuses for a reason other than being
 * empty: not text, or holding the bytes of U+0000 or of a UTF-16 surrogate.
 * `instr` on a BLOB compares bytes. In UTF-8 the byte ED only ever leads a
 * three-byte character, and ED followed by A0–BF encodes U+D800–U+DFFF, the
 * bytes better-sqlite3 writes for a lone surrogate.
 */
const SQLITE_INVALID_CHAIN_ID = (col: string): string =>
  `(typeof(${col}) <> 'text' OR instr(CAST(${col} AS BLOB), X'00') > 0 OR ` +
  Array.from({ length: 32 }, (_, i) => `instr(CAST(${col} AS BLOB), X'ED${(0xa0 + i).toString(16).toUpperCase()}') > 0`).join(
    ' OR ',
  ) +
  ')';

/** The tables and indexes. `CREATE ... IF NOT EXISTS`, so a store that has them keeps them. */
const SQLITE_LOG_TABLES = `
  CREATE TABLE IF NOT EXISTS store_identity (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    store_id   TEXT NOT NULL CHECK (length(store_id) = 32 AND store_id NOT GLOB '*[^0-9a-f]*'),
    ns         TEXT NOT NULL CHECK ${SQLITE_VALID_NS('ns')},
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS logs (
    log_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    origin     TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind GLOB '[a-z]*' AND kind NOT GLOB '*[^a-z0-9]*'),
    chain_id   TEXT CHECK (chain_id IS NULL OR (chain_id <> '' AND NOT ${SQLITE_INVALID_CHAIN_ID('chain_id')})),
    created_at TEXT NOT NULL,
    CHECK ((kind = '${EVIDENCE_LOG_KIND}') = (chain_id IS NOT NULL))
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_evidence_chain ON logs(chain_id) WHERE kind = '${EVIDENCE_LOG_KIND}';
  CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_store_kind ON logs(kind) WHERE chain_id IS NULL;

  CREATE TABLE IF NOT EXISTS log_leaves (
    log_id      INTEGER NOT NULL REFERENCES logs(log_id),
    leaf_index  INTEGER NOT NULL CHECK (typeof(leaf_index) = 'integer' AND leaf_index >= 0),
    leaf_digest TEXT NOT NULL CHECK ${SQLITE_HEX64('leaf_digest')},
    source_ref  TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('capture', 'backfill', 'scheduler')),
    logged_at   TEXT NOT NULL,
    PRIMARY KEY (log_id, leaf_index),
    UNIQUE (log_id, source_ref),
    UNIQUE (log_id, leaf_digest)
  );
  CREATE INDEX IF NOT EXISTS idx_log_leaves_source_ref ON log_leaves(source_ref);

  CREATE TABLE IF NOT EXISTS log_checkpoints (
    log_id             INTEGER NOT NULL REFERENCES logs(log_id),
    tree_size          INTEGER NOT NULL CHECK (typeof(tree_size) = 'integer' AND tree_size >= 1),
    root               TEXT NOT NULL CHECK ${SQLITE_HEX64('root')},
    body               TEXT NOT NULL,
    body_digest        TEXT NOT NULL UNIQUE CHECK ${SQLITE_HEX64('body_digest')},
    compact_range      TEXT NOT NULL CHECK ${SQLITE_JSON_ARRAY('compact_range')},
    prev_anchored_size INTEGER CHECK (prev_anchored_size IS NULL OR (typeof(prev_anchored_size) = 'integer'
                         AND prev_anchored_size >= 1 AND prev_anchored_size < tree_size)),
    consistency_proof  TEXT CHECK (consistency_proof IS NULL OR ${SQLITE_JSON_ARRAY('consistency_proof')}),
    anchor_leaf_index  INTEGER CHECK (anchor_leaf_index IS NULL OR (typeof(anchor_leaf_index) = 'integer' AND anchor_leaf_index >= 0)),
    epoch_id           INTEGER CHECK (epoch_id IS NULL OR typeof(epoch_id) = 'integer'),
    signatures         TEXT NOT NULL DEFAULT '[]' CHECK ${SQLITE_JSON_ARRAY('signatures')},
    created_at         TEXT NOT NULL,
    PRIMARY KEY (log_id, tree_size),
    CHECK ((prev_anchored_size IS NULL) = (consistency_proof IS NULL))
  );
  ${CHECKPOINT_INDEX_SQL}

  CREATE TABLE IF NOT EXISTS anchor_publications (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_id            INTEGER NOT NULL CHECK (typeof(epoch_id) = 'integer'),
    anchor_size         INTEGER NOT NULL CHECK (typeof(anchor_size) = 'integer' AND anchor_size >= 1),
    p                   TEXT NOT NULL CHECK ${SQLITE_HEX64('p')},
    kind                TEXT NOT NULL CHECK (kind IN (${sqlList(ANCHOR_PUBLICATION_KINDS)})),
    state               TEXT NOT NULL,
    forced              INTEGER NOT NULL DEFAULT 0 CHECK (forced IN (0, 1)),
    chain               TEXT,
    from_address        TEXT CHECK (from_address IS NULL OR ${SQLITE_ADDRESS('from_address')}),
    nonce               INTEGER CHECK (nonce IS NULL OR (typeof(nonce) = 'integer' AND nonce >= 0)),
    attempts            TEXT NOT NULL DEFAULT '[]' CHECK ${SQLITE_JSON_ARRAY('attempts')},
    mined_tx_hash       TEXT,
    block_number        INTEGER CHECK (block_number IS NULL OR (typeof(block_number) = 'integer' AND block_number >= 0)),
    block_hash          TEXT,
    block_header        TEXT,
    tx_index            INTEGER CHECK (tx_index IS NULL OR (typeof(tx_index) = 'integer' AND tx_index >= 0)),
    tx_trie_proof       TEXT CHECK (tx_trie_proof IS NULL OR ${SQLITE_JSON_ARRAY('tx_trie_proof')}),
    gas_used            TEXT CHECK ${SQLITE_DECIMAL('gas_used')},
    effective_gas_price TEXT CHECK ${SQLITE_DECIMAL('effective_gas_price')},
    token               TEXT,
    gen_time            TEXT,
    fill_progress       TEXT CHECK (fill_progress IS NULL OR (json_valid(fill_progress) AND json_type(fill_progress) = 'object')),
    error               TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    UNIQUE (kind, anchor_size),
    CHECK (${sqlStatesByKind()}),
    CHECK ((kind = 'evm-calldata/1' AND chain IS NOT NULL AND ${SQLITE_EIP155('chain')})
        OR (kind = 'rfc3161/1' AND chain IS NULL)),
    CHECK (state NOT IN ('submitted', 'included', 'finalized')
        OR (from_address IS NOT NULL AND nonce IS NOT NULL AND json_array_length(attempts) >= 1)),
    CHECK (state NOT IN ('included', 'finalized')
        OR (mined_tx_hash IS NOT NULL AND block_number IS NOT NULL AND block_hash IS NOT NULL)),
    CHECK (state <> 'obtained' OR (token IS NOT NULL AND gen_time IS NOT NULL))
  );
  ${ANCHOR_NONCE_INDEX_SQL}

  CREATE TABLE IF NOT EXISTS anchor_lease (
    domain     TEXT PRIMARY KEY,
    holder     TEXT NOT NULL CHECK (length(holder) BETWEEN 1 AND 200),
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS anchor_wallets (
    address     TEXT NOT NULL CHECK ${SQLITE_ADDRESS('address')},
    chain       TEXT NOT NULL CHECK ${SQLITE_EIP155('chain')},
    domain      TEXT NOT NULL,
    nonce_base  INTEGER NOT NULL CHECK (typeof(nonce_base) = 'integer' AND nonce_base >= 0),
    enrolled_at TEXT NOT NULL,
    retired_at  TEXT,
    PRIMARY KEY (address, chain)
  );

  CREATE TABLE IF NOT EXISTS anchor_wallet_txs (
    address    TEXT NOT NULL,
    chain      TEXT NOT NULL,
    nonce      INTEGER NOT NULL CHECK (typeof(nonce) = 'integer' AND nonce >= 0),
    tx_hash    TEXT NOT NULL UNIQUE CHECK (length(tx_hash) = 66 AND substr(tx_hash, 1, 2) = '0x'
                 AND substr(tx_hash, 3) NOT GLOB '*[^0-9a-f]*'),
    kind       TEXT NOT NULL CHECK (kind IN (${sqlList(ANCHOR_WALLET_TX_KINDS)})),
    raw_tx     TEXT NOT NULL CHECK (length(raw_tx) > 2 AND length(raw_tx) % 2 = 0 AND substr(raw_tx, 1, 2) = '0x'
                 AND substr(raw_tx, 3) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    PRIMARY KEY (address, chain, nonce),
    FOREIGN KEY (address, chain) REFERENCES anchor_wallets(address, chain)
  );
`;

/** The origin a `logs` row must carry, from `store_identity`, for the row `NEW`. */
const SQLITE_EXPECTED_ORIGIN = `(
  SELECT si.ns || '/' || si.store_id ||
         CASE WHEN NEW.kind = '${EVIDENCE_LOG_KIND}' THEN '/${EVIDENCE_LOG_KIND}/' || lower(hex(NEW.chain_id))
              ELSE '/' || NEW.kind END
    FROM store_identity si
)`;

/** A named trigger, as the exact CREATE statement sqlite_schema keeps for it. */
interface SqliteTrigger {
  name: string;
  sql: string;
}

/**
 * Every trigger on the log tables, in creation order. The density trigger and
 * the trigger on `envelopes` come last: the migration backfills before either
 * exists. A trigger whose stored statement differs from this one is dropped
 * and created again, so a store runs the current bodies.
 */
function sqliteLogTriggers(): SqliteTrigger[] {
  const trigger = (name: string, body: string): SqliteTrigger => ({ name, sql: `CREATE TRIGGER ${name} ${body.trim()}` });
  const blockUpdateDelete = (table: string, what: string): SqliteTrigger[] => [
    trigger(`${table}_block_update`, `BEFORE UPDATE ON ${table}
      BEGIN SELECT RAISE(ABORT, '${table}: ${what} (UPDATE refused)'); END`),
    trigger(`${table}_block_delete`, `BEFORE DELETE ON ${table}
      BEGIN SELECT RAISE(ABORT, '${table}: ${what} (DELETE refused)'); END`),
  ];
  const changed = (cols: readonly string[]): string => cols.map((c) => `NEW.${c} IS NOT OLD.${c}`).join(' OR ');

  // No insert or rowid change replaces a row, as on the tables
  // of sqlite.ts (see envelopes_block_replace there). REPLACE conflict
  // resolution (INSERT OR REPLACE, REPLACE INTO, UPDATE OR REPLACE) deletes
  // the row a write conflicts with; that delete fires no DELETE trigger unless
  // recursive_triggers is on, and no UPDATE trigger at all, so the UPDATE and
  // DELETE refusals above and below would not stop it. A BEFORE INSERT
  // trigger runs before conflict handling, so <table>_block_replace refuses an
  // insert naming a key a row holds, whatever its conflict clause. An insert
  // that names no rowid reads NEW.rowid as -1 there; SQLite never assigns a
  // negative rowid itself, and <table>_block_negative_rowid refuses one
  // written explicitly, so no row holds -1. <table>_block_rowid_change sits on
  // each table whose UPDATE trigger lets some updates through and does not
  // already fix the rowid; the others refuse every UPDATE.
  const held = (table: string, where: string): string => `EXISTS (SELECT 1 FROM ${table} WHERE ${where})`;
  const blockReplace = (table: string, keys: string[]): SqliteTrigger =>
    trigger(`${table}_block_replace`, `BEFORE INSERT ON ${table}
    BEGIN
      SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} ${table} rows are append-only (INSERT over an existing row refused)')
       WHERE ${keys.join('\n          OR ')};
    END`);
  const blockNegativeRowid = (table: string, rowid = 'rowid'): SqliteTrigger =>
    trigger(`${table}_block_negative_rowid`, `AFTER INSERT ON ${table}
      BEGIN SELECT RAISE(ABORT, '${table}: a rowid cannot be negative') WHERE NEW.${rowid} < 0; END`);
  const blockRowidChange = (table: string): SqliteTrigger =>
    trigger(`${table}_block_rowid_change`, `BEFORE UPDATE ON ${table}
      BEGIN SELECT RAISE(ABORT, '${table}.rowid is immutable') WHERE NEW.rowid IS NOT OLD.rowid; END`);
  // An id written explicitly is above every id the table holds. These tables
  // are read in id order, so a row written below the last would read ahead of
  // the rows it follows. An insert that names no id reads it as -1 here and
  // gets the next one; an id a row holds is left to <table>_block_replace,
  // which reports it as the duplicate it is.
  const blockBackdatedId = (table: string, id: string): SqliteTrigger =>
    trigger(`${table}_block_backdated_id`, `BEFORE INSERT ON ${table}
    BEGIN
      SELECT RAISE(ABORT, '${table}: an explicit ${id} must be above every existing ${id}')
       WHERE NEW.${id} <> -1
         AND NEW.${id} < (SELECT MAX(${id}) FROM ${table})
         AND NOT ${held(table, `${id} = NEW.${id}`)};
    END`);
  /**
   * Another publication that is not superseded holds `NEW`'s sender and
   * nonce: the key of idx_anchor_publications_nonce. `other` excludes the row
   * an UPDATE is writing.
   */
  const nonceHeld = (other = ''): string => `(NEW.nonce IS NOT NULL AND NEW.state IS NOT 'superseded'
         AND ${held('anchor_publications p', `${other}p.chain = NEW.chain AND p.from_address = NEW.from_address
                     AND p.nonce = NEW.nonce AND p.state <> 'superseded'`)})`;

  return [
    // The trust rules come first: the triggers that bind what the anchoring
    // pipeline reads to stored data. Each is a trigger of its own, under a
    // name no earlier release knows, so a process of an earlier release that
    // opens the store reconciles only its own triggers and leaves these in
    // place. SQLite fires a table's triggers newest first, and the migration
    // creates these before the other triggers of their table, so on a raw
    // write the guards below refuse first, with their own messages, and these
    // rules after them.
    // Record binding: an evidence leaf is a copy of the record stored at its
    // position (evidence id, chain, sequence number, digest), written by the
    // capture trigger on envelopes. Created after the upgrade backfill, which
    // writes `backfill` leaves; no SDK path writes that label afterwards.
    trigger(SQLITE_BIND_RECORD_TRIGGER, `BEFORE INSERT ON log_leaves
    BEGIN
      SELECT RAISE(ABORT, '[tzun:leaf_without_record] log_leaves: an evidence leaf is a copy of the record stored at its position (evidence id, chain, sequence number, digest)')
       WHERE (SELECT kind FROM logs WHERE log_id = NEW.log_id) = '${EVIDENCE_LOG_KIND}'
         AND (NEW.source IS NOT 'capture'
              OR NOT EXISTS (
                   SELECT 1 FROM envelopes e JOIN logs l ON l.log_id = NEW.log_id
                    WHERE e.evidence_id = NEW.source_ref
                      AND e.chain_id = l.chain_id
                      AND json_type(e.envelope, '$.payload.sequenceNumber') = 'integer'
                      AND json_extract(e.envelope, '$.payload.sequenceNumber') = NEW.leaf_index + 1
                      AND json_extract(e.envelope, '$.integrity.canonicalDigest') = NEW.leaf_digest));
    END`),

    // A publication's created_at and a leaf's logged_at are the insert's own
    // time: SQLite holds 'now' fixed within one statement, its triggers
    // included, so an insert that writes the expression passes and any other
    // value is refused. The scheduler's clock, cadence and force window read
    // these times.
    trigger('anchor_publications_created_now', `BEFORE INSERT ON anchor_publications
    BEGIN
      SELECT RAISE(ABORT, 'anchor_publications: created_at is the insert''s own time')
       WHERE NEW.created_at IS NOT ${SQLITE_NOW};
    END`),
    trigger('log_leaves_logged_now', `BEFORE INSERT ON log_leaves
    BEGIN
      SELECT RAISE(ABORT, 'log_leaves: logged_at is the insert''s own time')
       WHERE NEW.logged_at IS NOT ${SQLITE_NOW};
    END`),
    // Superseding needs an attempt, every one rejected; an attempt's broadcast
    // moves only unknown -> accepted, unknown -> rejected or rejected ->
    // accepted, so accepted is final. The supersede rule of
    // anchor_publications_guard_update is restated here.
    trigger('anchor_publications_guard_transitions', `BEFORE UPDATE ON anchor_publications
    BEGIN
      SELECT RAISE(ABORT, 'anchor_publications: only a publication with an attempt, every one rejected, may be superseded')
       WHERE NEW.state = 'superseded' AND OLD.state IS NOT 'superseded'
         AND (json_array_length(NEW.attempts) = 0
              OR EXISTS (SELECT 1 FROM json_each(NEW.attempts) AS n WHERE json_extract(n.value, '$.broadcast') IS NOT 'rejected'));
      SELECT RAISE(ABORT, 'anchor_publications: a broadcast outcome moves only from unknown, or from rejected to accepted')
       WHERE EXISTS (SELECT 1 FROM json_each(OLD.attempts) AS o
                      WHERE json_extract(NEW.attempts, '$[' || o.key || '].broadcast') IS NOT json_extract(o.value, '$.broadcast')
                        AND NOT (json_extract(o.value, '$.broadcast') = 'unknown'
                                 OR (json_extract(o.value, '$.broadcast') = 'rejected'
                                     AND json_extract(NEW.attempts, '$[' || o.key || '].broadcast') = 'accepted')));
    END`),
    // A lease holder is a ${ANCHOR_LEASE_HOLDER_PREFIX} scheduler.
    trigger('anchor_lease_require_protocol', `BEFORE INSERT ON anchor_lease
    BEGIN
      SELECT RAISE(ABORT, 'anchor_lease: the holder is not a ${ANCHOR_LEASE_HOLDER_PREFIX} scheduler')
       WHERE substr(NEW.holder, 1, ${ANCHOR_LEASE_HOLDER_PREFIX.length}) IS NOT '${ANCHOR_LEASE_HOLDER_PREFIX}';
    END`),
    trigger('anchor_lease_require_protocol_update', `BEFORE UPDATE ON anchor_lease
    BEGIN
      SELECT RAISE(ABORT, 'anchor_lease: the holder is not a ${ANCHOR_LEASE_HOLDER_PREFIX} scheduler')
       WHERE substr(NEW.holder, 1, ${ANCHOR_LEASE_HOLDER_PREFIX.length}) IS NOT '${ANCHOR_LEASE_HOLDER_PREFIX}';
    END`),

    ...blockUpdateDelete('store_identity', 'the store identity is immutable'),
    ...blockUpdateDelete('logs', 'logs are insert-only'),
    ...blockUpdateDelete('log_leaves', 'leaves are insert-only'),

    trigger('logs_verify_insert', `BEFORE INSERT ON logs
    BEGIN
      SELECT RAISE(ABORT, 'logs: the origin is not the one the store identity names for this log')
       WHERE NEW.origin IS NOT ${SQLITE_EXPECTED_ORIGIN};
    END`),

    trigger('log_checkpoints_verify_insert', `BEFORE INSERT ON log_checkpoints
    BEGIN
      SELECT RAISE(ABORT, 'log_checkpoints: the log has no leaf at tree_size - 1')
       WHERE NOT EXISTS (SELECT 1 FROM log_leaves WHERE log_id = NEW.log_id AND leaf_index = NEW.tree_size - 1);
      SELECT RAISE(ABORT, 'log_checkpoints: the body is not three lines naming this log''s origin and this size')
       WHERE substr(NEW.body, 1, length((SELECT origin FROM logs WHERE log_id = NEW.log_id) || char(10) || NEW.tree_size || char(10)))
               IS NOT (SELECT origin FROM logs WHERE log_id = NEW.log_id) || char(10) || NEW.tree_size || char(10)
          OR substr(NEW.body, -1) IS NOT char(10)
          OR length(NEW.body) - length(replace(NEW.body, char(10), '')) <> 3;
      SELECT RAISE(ABORT, 'log_checkpoints: anchor_leaf_index must name the anchor-log leaf that holds this body''s digest, and the anchor log''s own checkpoints have none')
       WHERE NOT ${sqlAnchorLeafIndexOk(SQLITE_NAMES)};
      SELECT RAISE(ABORT, 'log_checkpoints: signatures must be an array of strings')
       WHERE EXISTS (SELECT 1 FROM json_each(NEW.signatures) WHERE type <> 'text');
    END`),
    trigger('log_checkpoints_guard_update', `BEFORE UPDATE ON log_checkpoints
    BEGIN
      SELECT RAISE(ABORT, 'log_checkpoints: a checkpoint is immutable; only signatures may be appended')
       WHERE ${changed(CHECKPOINT_FIXED)};
      SELECT RAISE(ABORT, 'log_checkpoints: signatures are append-only')
       WHERE json_array_length(NEW.signatures) < json_array_length(OLD.signatures)
          OR EXISTS (SELECT 1 FROM json_each(OLD.signatures) AS o
                      WHERE json_extract(NEW.signatures, '$[' || o.key || ']') IS NOT o.value)
          OR EXISTS (SELECT 1 FROM json_each(NEW.signatures) WHERE type <> 'text');
    END`),
    trigger('log_checkpoints_block_delete', `BEFORE DELETE ON log_checkpoints
      BEGIN SELECT RAISE(ABORT, 'log_checkpoints: checkpoints are insert-only (DELETE refused)'); END`),

    trigger('anchor_publications_verify_insert', `BEFORE INSERT ON anchor_publications
    BEGIN
      SELECT RAISE(ABORT, 'anchor_publications: a publication starts prepared, with nothing sent or stored')
       WHERE NEW.state IS NOT 'prepared' OR json_array_length(NEW.attempts) <> 0
          OR ${[...WRITTEN_ONCE, ...FIXED_AFTER_FINALITY].map((c) => `NEW.${c} IS NOT NULL`).join(' OR ')};
      SELECT RAISE(ABORT, 'anchor_publications: P is not the digest of the anchor log''s stored checkpoint at anchor_size')
       WHERE NOT ${sqlPIsAnchorCheckpoint(SQLITE_NAMES)};
    END`),
    trigger('anchor_publications_guard_update', `BEFORE UPDATE ON anchor_publications
    BEGIN
      SELECT RAISE(ABORT, 'anchor_publications: id, epoch, anchor size, P, kind, chain and created_at are fixed')
       WHERE ${changed(PUBLICATION_IDENTITY)};
      SELECT RAISE(ABORT, 'anchor_publications: state moves forward only')
       WHERE NEW.state IS NOT OLD.state AND NOT (${sqlAllowedTransition()});
      SELECT RAISE(ABORT, 'anchor_publications: sender, nonce, token and genTime are written once')
       WHERE ${WRITTEN_ONCE.map((c) => `(OLD.${c} IS NOT NULL AND NEW.${c} IS NOT OLD.${c})`).join(' OR ')};
      SELECT RAISE(ABORT, 'anchor_publications: an accounted wallet transaction holds the nonce, or the wallet is retired')
       WHERE OLD.nonce IS NULL AND NEW.nonce IS NOT NULL AND NOT ${sqlPublicationNonceFree(SQLITE_NAMES)};
      SELECT RAISE(ABORT, 'anchor_publications: attempts are append-only, and an attempt''s txHash and rawTx never change')
       WHERE json_array_length(NEW.attempts) < json_array_length(OLD.attempts)
          OR EXISTS (SELECT 1 FROM json_each(OLD.attempts) AS o
                      WHERE json_extract(NEW.attempts, '$[' || o.key || '].txHash') IS NOT json_extract(o.value, '$.txHash')
                         OR json_extract(NEW.attempts, '$[' || o.key || '].rawTx') IS NOT json_extract(o.value, '$.rawTx'))
          OR EXISTS (SELECT 1 FROM json_each(NEW.attempts) AS n
                      WHERE n.type <> 'object'
                         OR json_type(n.value, '$.txHash') IS NOT 'text'
                         OR json_type(n.value, '$.rawTx') IS NOT 'text');
      SELECT RAISE(ABORT, 'anchor_publications: an attempt''s broadcast is ${ANCHOR_BROADCAST_OUTCOMES.join(', ')}')
       WHERE EXISTS (SELECT 1 FROM json_each(NEW.attempts) AS n
                      WHERE json_type(n.value, '$.broadcast') IS NOT 'text'
                         OR json_extract(n.value, '$.broadcast') NOT IN (${sqlList(ANCHOR_BROADCAST_OUTCOMES)}));
      SELECT RAISE(ABORT, 'anchor_publications: only a publication whose every broadcast was rejected may be superseded')
       WHERE NEW.state = 'superseded' AND OLD.state IS NOT 'superseded'
         AND EXISTS (SELECT 1 FROM json_each(NEW.attempts) AS n WHERE json_extract(n.value, '$.broadcast') IS NOT 'rejected');
      SELECT RAISE(ABORT, 'anchor_publications: once finalized, the mined transaction and its proof material are fixed')
       WHERE OLD.state = 'finalized'
         AND (${FIXED_AFTER_FINALITY.map((c) => `(OLD.${c} IS NOT NULL AND NEW.${c} IS NOT OLD.${c})`).join(' OR ')});
    END`),
    trigger('anchor_publications_block_delete', `BEFORE DELETE ON anchor_publications
      BEGIN SELECT RAISE(ABORT, 'anchor_publications: publications are never deleted (DELETE refused)'); END`),

    trigger('anchor_lease_verify_insert', `BEFORE INSERT ON anchor_lease
    BEGIN
      SELECT RAISE(ABORT, 'anchor_lease: the domain is not the store''s domain prefix')
       WHERE NEW.domain IS NOT ${sqlDomainPrefix(SQLITE_NAMES)};
    END`),
    trigger('anchor_lease_guard_update', `BEFORE UPDATE ON anchor_lease
    BEGIN
      SELECT RAISE(ABORT, 'anchor_lease: the domain is fixed')
       WHERE NEW.domain IS NOT OLD.domain;
    END`),

    trigger('anchor_wallets_verify_insert', `BEFORE INSERT ON anchor_wallets
    BEGIN
      SELECT RAISE(ABORT, 'anchor_wallets: a wallet is enrolled for the store''s own domain prefix, unretired')
       WHERE NEW.domain IS NOT ${sqlDomainPrefix(SQLITE_NAMES)} OR NEW.retired_at IS NOT NULL;
    END`),
    trigger('anchor_wallets_guard_update', `BEFORE UPDATE ON anchor_wallets
    BEGIN
      SELECT RAISE(ABORT, 'anchor_wallets: an enrolment is fixed; only retired_at is set, once')
       WHERE ${changed(WALLET_FIXED)} OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS NOT OLD.retired_at);
    END`),
    trigger('anchor_wallets_block_delete', `BEFORE DELETE ON anchor_wallets
      BEGIN SELECT RAISE(ABORT, 'anchor_wallets: enrolments are never deleted (DELETE refused)'); END`),

    trigger('anchor_wallet_txs_verify_insert', `BEFORE INSERT ON anchor_wallet_txs
    BEGIN
      SELECT RAISE(ABORT, 'anchor_wallet_txs: the wallet is not enrolled and unretired from at or below this nonce, or a publication holds the nonce')
       WHERE NOT ${sqlWalletTxNonceFree(SQLITE_NAMES)};
    END`),
    ...blockUpdateDelete('anchor_wallet_txs', 'accounted transactions are insert-only'),

    // store_identity: `singleton` is the rowid, and its CHECK allows only 1,
    // so no row can sit at a negative rowid.
    blockReplace('store_identity', [held('store_identity', 'singleton = NEW.singleton')]),

    // logs: `log_id` is the rowid. Its leaves keep their log_id, so a REPLACE
    // at a log's log_id would hand them to another log.
    blockReplace('logs', [
      held('logs', 'log_id = NEW.log_id'),
      held('logs', 'origin = NEW.origin'),
      `(NEW.kind = '${EVIDENCE_LOG_KIND}' AND ${held('logs', `kind = '${EVIDENCE_LOG_KIND}' AND chain_id = NEW.chain_id`)})`,
      `(NEW.chain_id IS NULL AND ${held('logs', 'chain_id IS NULL AND kind = NEW.kind')})`,
    ]),
    blockNegativeRowid('logs', 'log_id'),
    blockBackdatedId('logs', 'log_id'),

    // log_leaves: log_leaves_verify_insert, below, refuses a taken position,
    // source or digest, with the messages the adapters translate; this guard
    // adds the rowid, which REPLACE could otherwise name to erase any leaf.
    blockReplace('log_leaves', [held('log_leaves', 'rowid = NEW.rowid')]),
    blockNegativeRowid('log_leaves'),

    blockReplace('log_checkpoints', [
      held('log_checkpoints', 'log_id = NEW.log_id AND tree_size = NEW.tree_size'),
      held('log_checkpoints', 'body_digest = NEW.body_digest'),
      held('log_checkpoints', 'rowid = NEW.rowid'),
    ]),
    blockNegativeRowid('log_checkpoints'),
    blockRowidChange('log_checkpoints'),

    // anchor_publications: `id` is the rowid, which
    // anchor_publications_guard_update already fixes. The verify trigger
    // accepts a prepared row, so without the guard REPLACE at a finalized
    // publication's kind and anchor size would put a fresh one in its place.
    blockReplace('anchor_publications', [
      held('anchor_publications', 'id = NEW.id'),
      held('anchor_publications', 'kind = NEW.kind AND anchor_size = NEW.anchor_size'),
      nonceHeld(),
    ]),
    blockNegativeRowid('anchor_publications', 'id'),
    blockBackdatedId('anchor_publications', 'id'),
    // A sender and nonce are set once, from null, and the nonce index keeps
    // them to one publication that is not superseded. UPDATE OR REPLACE onto
    // a nonce another publication holds would delete that publication.
    trigger('anchor_publications_block_nonce_replace', `BEFORE UPDATE ON anchor_publications
    BEGIN
      SELECT RAISE(ABORT, '${EXISTING_ROW_TAG} anchor_publications: another publication that is not superseded holds this sender and nonce (UPDATE onto its nonce refused)')
       WHERE ${nonceHeld('p.id <> OLD.id AND ')};
    END`),

    // anchor_lease is mutable, and its UPSERT is how a lease is taken, so it
    // has no insert guard. Its UPDATE trigger fixes only the domain.
    blockRowidChange('anchor_lease'),

    blockReplace('anchor_wallets', [
      held('anchor_wallets', 'address = NEW.address AND chain = NEW.chain'),
      held('anchor_wallets', 'rowid = NEW.rowid'),
    ]),
    blockNegativeRowid('anchor_wallets'),
    blockRowidChange('anchor_wallets'),

    blockReplace('anchor_wallet_txs', [
      held('anchor_wallet_txs', 'address = NEW.address AND chain = NEW.chain AND nonce = NEW.nonce'),
      held('anchor_wallet_txs', 'tx_hash = NEW.tx_hash'),
      held('anchor_wallet_txs', 'rowid = NEW.rowid'),
    ]),
    blockNegativeRowid('anchor_wallet_txs'),

    // The density trigger, in the order every adapter applies the rules: an
    // occupied position, then density, then a repeated source or digest. It
    // also refuses a leaf whose position is taken: SQLite's REPLACE conflict
    // resolution deletes a conflicting row without firing a DELETE trigger,
    // so any conflicting leaf is refused here, before conflict handling runs.
    // The trigger on envelopes checks the position first, and skips.
    trigger('log_leaves_verify_insert', `BEFORE INSERT ON log_leaves
    BEGIN
      SELECT RAISE(ABORT, 'log_leaves: a leaf is written once (its position is already in the log)')
       WHERE EXISTS (SELECT 1 FROM log_leaves WHERE log_id = NEW.log_id AND leaf_index = NEW.leaf_index);
      SELECT RAISE(ABORT, '[tzun:log_gap] log_leaves: the leaf before this one is not in the log, and a log is dense')
       WHERE NEW.leaf_index <> 0
         AND NOT EXISTS (SELECT 1 FROM log_leaves WHERE log_id = NEW.log_id AND leaf_index = NEW.leaf_index - 1);
      SELECT RAISE(ABORT, '[tzun:duplicate_leaf] log_leaves: the source or the digest is already a leaf of this log, and its leaves are distinct')
       WHERE EXISTS (SELECT 1 FROM log_leaves WHERE log_id = NEW.log_id AND source_ref = NEW.source_ref)
          OR EXISTS (SELECT 1 FROM log_leaves WHERE log_id = NEW.log_id AND leaf_digest = NEW.leaf_digest);
      SELECT RAISE(ABORT, 'log_leaves: an evidence log takes capture and backfill leaves, a per-store log takes scheduler leaves')
       WHERE ((SELECT kind FROM logs WHERE log_id = NEW.log_id) = '${EVIDENCE_LOG_KIND}') <> (NEW.source IN ('capture', 'backfill'));
    END`),

    // The evidence leaf, inside the transaction that stores the record.
    trigger(SQLITE_EVIDENCE_TRIGGER, `AFTER INSERT ON envelopes
    BEGIN
      SELECT RAISE(ABORT, '[tzun:empty_chain_id] evidence log: an empty chain id names no log')
       WHERE NEW.chain_id = '';
      SELECT RAISE(ABORT, '[tzun:invalid_chain_id] evidence log: a chain id is text of Unicode scalar values other than U+0000')
       WHERE ${SQLITE_INVALID_CHAIN_ID('NEW.chain_id')};
      SELECT RAISE(ABORT, '[tzun:invalid_sequence_number] evidence log: payload.sequenceNumber is not a positive integer')
       WHERE json_type(NEW.envelope, '$.payload.sequenceNumber') IS NOT 'integer'
          OR json_extract(NEW.envelope, '$.payload.sequenceNumber') < 1;
      SELECT RAISE(ABORT, '[tzun:invalid_digest] evidence log: integrity.canonicalDigest is not 64 lowercase hex')
       WHERE json_type(NEW.envelope, '$.integrity.canonicalDigest') IS NOT 'text'
          OR NOT ${SQLITE_HEX64("json_extract(NEW.envelope, '$.integrity.canonicalDigest')")};
      SELECT RAISE(ABORT, '[tzun:store_identity_missing] evidence log: the store has no store_identity')
       WHERE NOT EXISTS (SELECT 1 FROM store_identity);
      INSERT INTO logs (origin, kind, chain_id, created_at)
      SELECT si.ns || '/' || si.store_id || '/${EVIDENCE_LOG_KIND}/' || lower(hex(NEW.chain_id)),
             '${EVIDENCE_LOG_KIND}', NEW.chain_id, ${SQLITE_NOW}
        FROM store_identity si
       WHERE NOT EXISTS (SELECT 1 FROM logs WHERE kind = '${EVIDENCE_LOG_KIND}' AND chain_id = NEW.chain_id);
      -- Write once: a record at a position that already has a leaf keeps
      -- that leaf, and the store goes ahead. At a free position the leaf is
      -- written, and log_leaves_verify_insert refuses a gap or a repeat.
      INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at)
      SELECT l.log_id,
             json_extract(NEW.envelope, '$.payload.sequenceNumber') - 1,
             json_extract(NEW.envelope, '$.integrity.canonicalDigest'),
             NEW.evidence_id, 'capture', ${SQLITE_NOW}
        FROM logs l
       WHERE l.kind = '${EVIDENCE_LOG_KIND}' AND l.chain_id = NEW.chain_id
         AND NOT EXISTS (SELECT 1 FROM log_leaves x WHERE x.log_id = l.log_id
                           AND x.leaf_index = json_extract(NEW.envelope, '$.payload.sequenceNumber') - 1);
    END`),
  ];
}

/** The trigger on `envelopes`; its presence marks a store whose backfill has run. */
const SQLITE_EVIDENCE_TRIGGER = 'envelopes_evidence_log_append';

/** The record binding of evidence leaves, created after the backfill. */
const SQLITE_BIND_RECORD_TRIGGER = 'log_leaves_bind_record';

/** The trust rules' triggers: the record binding, the insert times, the transitions and the lease protocol. */
const SQLITE_TRUST_TRIGGERS: ReadonlySet<string> = new Set([
  SQLITE_BIND_RECORD_TRIGGER,
  'anchor_publications_created_now',
  'log_leaves_logged_now',
  'anchor_publications_guard_transitions',
  'anchor_lease_require_protocol',
  'anchor_lease_require_protocol_update',
]);

/** The table a trigger's CREATE statement names. */
function sqliteTriggerTable(sql: string): string | undefined {
  return /\sON\s+(\w+)/.exec(sql)?.[1];
}

/** The indexes SQLITE_LOG_TABLES creates. */
const SQLITE_LOG_INDEXES = [
  'idx_logs_evidence_chain',
  'idx_logs_store_kind',
  'idx_log_leaves_source_ref',
  'idx_log_checkpoints_anchored',
  'idx_log_checkpoints_anchor_leaf',
  'idx_anchor_publications_nonce',
];

/**
 * One evidence log for every chain that has records and none yet. A chain id
 * that names no log (`chainIdRefusal`) gets none, and a store refuses every
 * later record on it.
 */
const SQLITE_CREATE_EVIDENCE_LOGS = `
  INSERT INTO logs (origin, kind, chain_id, created_at)
  SELECT si.ns || '/' || si.store_id || '/${EVIDENCE_LOG_KIND}/' || lower(hex(c.chain_id)),
         '${EVIDENCE_LOG_KIND}', c.chain_id, ${SQLITE_NOW}
    FROM (SELECT DISTINCT chain_id FROM envelopes
           WHERE chain_id <> '' AND NOT ${SQLITE_INVALID_CHAIN_ID('chain_id')}) AS c
   CROSS JOIN store_identity si
   WHERE NOT EXISTS (SELECT 1 FROM logs l WHERE l.kind = '${EVIDENCE_LOG_KIND}' AND l.chain_id = c.chain_id)
   ORDER BY c.chain_id
`;

/**
 * Each chain's dense prefix of leaves, in sequence order (Tree §5.2). The
 * records that can be leaves are those with a positive integer sequence number
 * and a 64-hex digest. Of two at one position the first stored is taken, and a
 * digest an earlier position already has is not taken again. The prefix is
 * then the positions 1..n that all have a record: the n-th position of a
 * chain, counted in sequence order, is position n exactly when none before it
 * is missing. IGNORE keeps the statement from failing on a store that already
 * holds some of these leaves.
 */
const SQLITE_BACKFILL_LEAVES = `
  INSERT OR IGNORE INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at)
  SELECT l.log_id, p.seq - 1, p.digest, p.evidence_id, 'backfill', ${SQLITE_NOW}
    FROM (
      SELECT chain_id, seq, digest, evidence_id,
             ROW_NUMBER() OVER (PARTITION BY chain_id ORDER BY seq) AS rank_in_chain
        FROM (
          SELECT chain_id, seq, digest, evidence_id,
                 ROW_NUMBER() OVER (PARTITION BY chain_id, digest ORDER BY seq) AS digest_rank
            FROM (
              SELECT chain_id, seq, digest, evidence_id,
                     ROW_NUMBER() OVER (PARTITION BY chain_id, seq ORDER BY rid) AS position_rank
                FROM (SELECT rowid AS rid, evidence_id, chain_id,
                             json_type(envelope, '$.payload.sequenceNumber') AS seq_type,
                             json_extract(envelope, '$.payload.sequenceNumber') AS seq,
                             json_extract(envelope, '$.integrity.canonicalDigest') AS digest
                        FROM envelopes) AS e
               WHERE e.seq_type = 'integer' AND e.seq >= 1
                 AND typeof(e.digest) = 'text' AND ${SQLITE_HEX64('e.digest')}
            ) AS positions
           WHERE position_rank = 1
        ) AS distinct_digests
       WHERE digest_rank = 1
    ) AS p
    JOIN logs l ON l.kind = '${EVIDENCE_LOG_KIND}' AND l.chain_id = p.chain_id
   WHERE p.rank_in_chain = p.seq
   ORDER BY l.log_id, p.seq
`;

/** Refuse a SQLite database whose text encoding is not UTF-8 (Anchor §4.3.2). */
export function assertSqliteUtf8(db: BetterSqlite3.Database): void {
  const encoding = db.pragma('encoding', { simple: true }) as string;
  if (encoding !== 'UTF-8') throw new SqliteEncodingError(encoding);
}

function sqliteIdentity(db: BetterSqlite3.Database): StoreIdentity | null {
  const row = db.prepare('SELECT store_id, ns, created_at FROM store_identity WHERE singleton = 1').get() as
    | { store_id: string; ns: string; created_at: string }
    | undefined;
  return row ? { storeId: row.store_id, ns: row.ns, createdAt: row.created_at } : null;
}

/** The stored CREATE statement of every trigger and index on the log tables, by name. */
function sqliteSchemaSql(db: BetterSqlite3.Database): Map<string, string | null> {
  const rows = db
    .prepare("SELECT name, sql FROM sqlite_schema WHERE type IN ('trigger', 'index')")
    .all() as Array<{ name: string; sql: string | null }>;
  return new Map(rows.map((r) => [r.name, r.sql]));
}

/**
 * The store needs nothing from the migration: it has its identity, every
 * index, and every trigger with the current statement. Read-only, so opening
 * a migrated store takes no write lock and leaves the schema untouched.
 */
function sqliteLogSchemaIsCurrent(db: BetterSqlite3.Database, triggers: SqliteTrigger[]): boolean {
  const hasIdentityTable = db
    .prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'store_identity'")
    .get();
  if (!hasIdentityTable || !sqliteIdentity(db)) return false;
  const stored = sqliteSchemaSql(db);
  return (
    SQLITE_LOG_INDEXES.every((name) => stored.has(name)) &&
    triggers.every((t) => stored.get(t.name) === t.sql)
  );
}

function assertNamespaceMatches(held: StoreIdentity, configured: string | undefined): void {
  if (configured !== undefined && held.ns !== configured) throw new LogNamespaceMismatchError(held.ns, configured);
}

/**
 * Create the log tables, mint the identity, backfill an existing store and
 * install the triggers: the upgrade migration, in one BEGIN IMMEDIATE
 * transaction. Idempotent: a store that has the trigger on `envelopes` is not
 * backfilled again, and a store whose schema is current is only read.
 * Returns the store's identity.
 *
 * @throws {LogNamespaceMismatchError} when `logNamespace` differs from the stored one.
 * @throws {StoreIdentityMissingError} when the store has logs but no identity.
 * @throws {InvalidLogNamespaceError} when `logNamespace` breaks the origin rules.
 */
export function migrateSqliteLogSchema(db: BetterSqlite3.Database, options: LogSchemaOptions = {}): StoreIdentity {
  const configured = options.logNamespace === undefined ? undefined : assertLogNamespace(options.logNamespace);
  const triggers = sqliteLogTriggers();
  if (sqliteLogSchemaIsCurrent(db, triggers)) {
    const held = sqliteIdentity(db)!;
    assertNamespaceMatches(held, configured);
    return held;
  }
  const run = db.transaction((): StoreIdentity => {
    db.exec(SQLITE_LOG_TABLES);
    const held = sqliteIdentity(db);
    if (!held) {
      const logs = (db.prepare('SELECT COUNT(*) AS n FROM logs').get() as { n: number }).n;
      if (logs > 0) throw new StoreIdentityMissingError(logs);
      db.prepare('INSERT INTO store_identity (singleton, store_id, ns, created_at) VALUES (1, ?, ?, ?)').run(
        mintStoreId(),
        configured ?? DEFAULT_LOG_NAMESPACE,
        new Date().toISOString(),
      );
    } else {
      assertNamespaceMatches(held, configured);
    }
    const stored = sqliteSchemaSql(db);
    if (!stored.has(SQLITE_EVIDENCE_TRIGGER)) {
      // Not migrated yet: the leaves come from the stored records, and
      // neither the density trigger nor the record binding may exist while a
      // chain with holes is backfilled.
      for (const name of ['log_leaves_verify_insert', SQLITE_BIND_RECORD_TRIGGER, 'log_leaves_logged_now']) {
        db.exec(`DROP TRIGGER IF EXISTS ${name}`);
        stored.delete(name);
      }
      db.exec(SQLITE_CREATE_EVIDENCE_LOGS);
      db.exec(SQLITE_BACKFILL_LEAVES);
      const pending = logMigrationTestHooks.afterBackfill?.();
      if (pending instanceof Promise) throw new TypeError('the SQLite migration hook must be synchronous');
    }
    // A trust-rule trigger that is (re)created is created before the other
    // triggers of its table, which are created again after it, so that they
    // fire first.
    for (const t of triggers) {
      if (!SQLITE_TRUST_TRIGGERS.has(t.name) || stored.get(t.name) === t.sql) continue;
      const table = sqliteTriggerTable(t.sql);
      for (const other of triggers) {
        if (!SQLITE_TRUST_TRIGGERS.has(other.name) && sqliteTriggerTable(other.sql) === table) stored.delete(other.name);
      }
    }
    for (const t of triggers) {
      if (stored.get(t.name) === t.sql) continue;
      db.exec(`DROP TRIGGER IF EXISTS ${t.name}`);
      db.exec(t.sql);
    }
    return sqliteIdentity(db)!;
  });
  return run.immediate();
}

interface LogRow {
  log_id: number | string;
  origin: string;
  kind: string;
  chain_id: string | null;
  created_at: string | Date;
}

interface LeafRow {
  log_id: number | string;
  leaf_index: number | string;
  leaf_digest: string;
  source_ref: string;
  source: LogLeafSource;
  logged_at: string | Date;
}

interface CheckpointRow {
  log_id: number | string;
  tree_size: number | string;
  root: string;
  body: string;
  body_digest: string;
  compact_range: string | string[];
  prev_anchored_size: number | string | null;
  consistency_proof: string | string[] | null;
  anchor_leaf_index: number | string | null;
  epoch_id: number | string | null;
  signatures: string | string[];
  created_at: string | Date;
}

interface PublicationRow {
  id: number | string;
  epoch_id: number | string;
  anchor_size: number | string;
  p: string;
  kind: AnchorPublicationKind;
  state: AnchorPublicationState;
  forced: number | boolean;
  chain: string | null;
  from_address: string | null;
  nonce: number | string | null;
  attempts: string | AnchorPublicationAttempt[];
  mined_tx_hash: string | null;
  block_number: number | string | null;
  block_hash: string | null;
  block_header: string | null;
  tx_index: number | string | null;
  tx_trie_proof: string | string[] | null;
  gas_used: string | null;
  effective_gas_price: string | null;
  token: string | null;
  gen_time: string | null;
  fill_progress: string | Record<string, unknown> | null;
  error: string | null;
  created_at: string | Date;
  updated_at: string | Date;
}

const iso = (v: string | Date): string => (v instanceof Date ? v.toISOString() : v);
const num = (v: number | string): number => Number(v);
const numOrNull = (v: number | string | null): number | null => (v === null ? null : Number(v));
const json = <T>(v: string | T): T => (typeof v === 'string' ? (JSON.parse(v) as T) : v);
const jsonOrNull = <T>(v: string | T | null): T | null => (v === null ? null : json<T>(v));

function logFromRow(row: LogRow): LogRecord {
  return { logId: num(row.log_id), origin: row.origin, kind: row.kind, chainId: row.chain_id, createdAt: iso(row.created_at) };
}

function leafFromRow(row: LeafRow): LogLeaf {
  return {
    logId: num(row.log_id),
    leafIndex: num(row.leaf_index),
    leafDigest: row.leaf_digest,
    sourceRef: row.source_ref,
    source: row.source,
    loggedAt: iso(row.logged_at),
  };
}

function checkpointFromRow(row: CheckpointRow): LogCheckpoint {
  return {
    logId: num(row.log_id),
    treeSize: num(row.tree_size),
    root: row.root,
    body: row.body,
    bodyDigest: row.body_digest,
    compactRange: json<string[]>(row.compact_range),
    prevAnchoredSize: numOrNull(row.prev_anchored_size),
    consistencyProof: jsonOrNull<string[]>(row.consistency_proof),
    anchorLeafIndex: numOrNull(row.anchor_leaf_index),
    epochId: numOrNull(row.epoch_id),
    signatures: json<string[]>(row.signatures),
    createdAt: iso(row.created_at),
  };
}

/**
 * The checkpoint of a source log that first commits to a leaf: the smallest
 * one past it that sits in the anchor log. Reads the `(log_id, tree_size)`
 * primary key in order and stops at the first row. `logId` and `leafIndex`
 * are the parameters `p(1)` and `p(2)`.
 */
const FIRST_ANCHORED_CHECKPOINT_SQL = (p: (n: number) => string): string =>
  `SELECT anchor_leaf_index FROM log_checkpoints
    WHERE log_id = ${p(1)} AND tree_size > ${p(2)} AND anchor_leaf_index IS NOT NULL
    ORDER BY tree_size LIMIT 1`;

const FINAL_STATES = `('finalized', 'obtained')`;
const LIVE_STATES = `('prepared', 'submitted', 'included')`;

/**
 * For each kind, the publication that has got furthest among those covering
 * anchor leaf `k` (`anchor_size > k`, parameter `p(1)`): the earliest final
 * one, and only when there is none, the one furthest along of the live ones.
 * Every branch searches the `(kind, anchor_size)` index from `k`, and the
 * final branch needs only the first final row it meets. The live branch runs
 * only when its kind has no final publication past `k`, and then the
 * publications past `k` are the ones not yet final, a few at the tail. So the
 * cost does not grow with the number of epochs the store has published.
 * `lastTx` reads the latest attempt's hash out of `attempts` in the dialect.
 */
const COVERING_PUBLICATIONS_SQL = (p: (n: number) => string, lastTx: string): string =>
  ANCHOR_PUBLICATION_KINDS.map((kind, i) => {
    const covering = `kind = '${kind}' AND anchor_size > ${p(1)}`;
    const columns = `id, kind, state, anchor_size, p, chain, mined_tx_hash, block_number, ${lastTx} AS last_tx_hash, fill_progress`;
    return (
      `SELECT * FROM (SELECT ${columns} FROM anchor_publications
         WHERE ${covering} AND state IN ${FINAL_STATES}
         ORDER BY anchor_size LIMIT 1) AS final_${i}
       UNION ALL
       SELECT * FROM (SELECT ${columns} FROM anchor_publications
         WHERE ${covering} AND state IN ${LIVE_STATES}
           AND NOT EXISTS (SELECT 1 FROM anchor_publications WHERE ${covering} AND state IN ${FINAL_STATES})
         ORDER BY CASE state WHEN 'included' THEN 0 WHEN 'submitted' THEN 1 ELSE 2 END, anchor_size
         LIMIT 1) AS live_${i}`
    );
  }).join('\n UNION ALL\n');

interface CoveringPublicationRow {
  id: number | string;
  kind: AnchorPublicationKind;
  state: Exclude<AnchorPublicationState, 'superseded'>;
  anchor_size: number | string;
  p: string;
  chain: string | null;
  mined_tx_hash: string | null;
  block_number: number | string | null;
  last_tx_hash: string | null;
  fill_progress: string | Record<string, unknown> | null;
}

function coveringPublicationFromRow(row: CoveringPublicationRow): LeafAnchorPublication {
  return {
    id: num(row.id),
    kind: row.kind,
    state: row.state,
    anchorSize: num(row.anchor_size),
    p: row.p,
    chain: row.chain,
    transactionId: row.mined_tx_hash ?? row.last_tx_hash ?? null,
    blockNumber: numOrNull(row.block_number),
    fillProgress: jsonOrNull<Record<string, unknown>>(row.fill_progress),
  };
}

function publicationFromRow(row: PublicationRow): AnchorPublication {
  return {
    id: num(row.id),
    epochId: num(row.epoch_id),
    anchorSize: num(row.anchor_size),
    p: row.p,
    kind: row.kind,
    state: row.state,
    forced: row.forced === true || row.forced === 1,
    chain: row.chain,
    fromAddress: row.from_address,
    nonce: numOrNull(row.nonce),
    attempts: json<AnchorPublicationAttempt[]>(row.attempts),
    minedTxHash: row.mined_tx_hash,
    blockNumber: numOrNull(row.block_number),
    blockHash: row.block_hash,
    blockHeader: row.block_header,
    txIndex: numOrNull(row.tx_index),
    txTrieProof: jsonOrNull<string[]>(row.tx_trie_proof),
    gasUsed: row.gas_used,
    effectiveGasPrice: row.effective_gas_price,
    token: row.token,
    genTime: row.gen_time,
    fillProgress: jsonOrNull<Record<string, unknown>>(row.fill_progress),
    error: row.error,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

interface LeaseRow {
  domain: string;
  holder: string;
  expires_at: string | Date;
}

interface WalletRow {
  address: string;
  chain: string;
  domain: string;
  nonce_base: number | string;
  enrolled_at: string | Date;
  retired_at: string | Date | null;
}

interface WalletTxRow {
  address: string;
  chain: string;
  nonce: number | string;
  tx_hash: string;
  kind: AnchorWalletTxKind;
  raw_tx: string;
  created_at: string | Date;
}

function leaseFromRow(row: LeaseRow): AnchorLease {
  return { domain: row.domain, holder: row.holder, expiresAt: iso(row.expires_at) };
}

function walletFromRow(row: WalletRow): AnchorWallet {
  return {
    address: row.address,
    chain: row.chain,
    domain: row.domain,
    nonceBase: num(row.nonce_base),
    enrolledAt: iso(row.enrolled_at),
    retiredAt: row.retired_at === null ? null : iso(row.retired_at),
  };
}

function walletTxFromRow(row: WalletTxRow): AnchorWalletTx {
  return {
    address: row.address,
    chain: row.chain,
    nonce: num(row.nonce),
    txHash: row.tx_hash,
    kind: row.kind,
    rawTx: row.raw_tx,
    createdAt: iso(row.created_at),
  };
}

/** Why `retireAnchorWallet` changed no row. */
function walletNotRetirable(held: AnchorWallet | null, address: string, chain: string): string {
  return held
    ? `anchor_wallets: ${address} on ${chain} was already retired at ${held.retiredAt}; retired_at is set, once`
    : `anchor_wallets: ${address} is not enrolled on ${chain}`;
}

function assertLeaseTtl(ttlMs: number): void {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new RangeError(`anchor lease ttlMs must be a positive integer (got ${ttlMs})`);
}

/**
 * The status a fill stores. The caller's rule decides, with two exceptions.
 * A `complete` record stays `complete` (`nextAttestationStatus`). A `pending`
 * record that still has no timestamp stays `pending`: a fill adds only the
 * anchor, and such a record is the pending-attestation retry's work
 * (`listByMissingObtainable(['timestamp'])` lists exactly the `pending`
 * records without one). The retry sets its status when the timestamp lands.
 * The second exception does not apply when the caller says its writers
 * expect no timestamp (`timestampExpected: false`): such a record was
 * `pending` for its anchor alone, and nothing else will ever change it.
 */
export function fillStatus(
  stored: EvidenceEnvelope['attestationStatus'],
  computed: EvidenceEnvelope['attestationStatus'],
  filled: EvidenceEnvelope['nonRepudiation'],
  timestampExpected: boolean | undefined,
): EvidenceEnvelope['attestationStatus'] {
  if (timestampExpected !== false && stored === 'pending' && missingAttestationComponents(filled, { timestamp: true }).length > 0) {
    return 'pending';
  }
  return nextAttestationStatus(stored, computed);
}

/**
 * The envelope a fill stores for `envelope`, or null when the record already
 * has an anchor (fill-only), with the status `fillStatus` gives it. Pure: the
 * stores call it inside the transaction that locks the record, and a store
 * kept outside the SDK can hold its own write to it.
 */
export function filledEnvelope(
  envelope: EvidenceEnvelope,
  fill: Pick<AnchorFill, 'anchor'>,
  chunk: Pick<AnchorFillChunk, 'statusOf' | 'timestampExpected'>,
): EvidenceEnvelope | null {
  const { merged, filled } = fillAbsentArtifacts(envelope.nonRepudiation, { anchor: fill.anchor });
  if (!filled) return null;
  const next: EvidenceEnvelope = { ...envelope, nonRepudiation: merged };
  next.attestationStatus = fillStatus(envelope.attestationStatus, chunk.statusOf(next), merged, chunk.timestampExpected);
  return next;
}

/** Patch key → column, and whether the column holds JSON. */
const PATCH_COLUMNS: Record<keyof AnchorPublicationPatch, { column: string; json: boolean }> = {
  state: { column: 'state', json: false },
  fromAddress: { column: 'from_address', json: false },
  nonce: { column: 'nonce', json: false },
  attempts: { column: 'attempts', json: true },
  minedTxHash: { column: 'mined_tx_hash', json: false },
  blockNumber: { column: 'block_number', json: false },
  blockHash: { column: 'block_hash', json: false },
  blockHeader: { column: 'block_header', json: false },
  txIndex: { column: 'tx_index', json: false },
  txTrieProof: { column: 'tx_trie_proof', json: true },
  gasUsed: { column: 'gas_used', json: false },
  effectiveGasPrice: { column: 'effective_gas_price', json: false },
  token: { column: 'token', json: false },
  genTime: { column: 'gen_time', json: false },
  fillProgress: { column: 'fill_progress', json: true },
  error: { column: 'error', json: false },
};

function patchEntries(patch: AnchorPublicationPatch): Array<{ column: string; value: unknown }> {
  const out: Array<{ column: string; value: unknown }> = [];
  for (const key of Object.keys(patch) as Array<keyof AnchorPublicationPatch>) {
    const spec = PATCH_COLUMNS[key];
    if (!spec) throw new TypeError(`anchor publication patch: unknown field ${JSON.stringify(key)}`);
    const value = patch[key];
    if (value === undefined) continue;
    out.push({ column: spec.column, value: spec.json && value !== null ? JSON.stringify(value) : value });
  }
  return out;
}

function assertLeafRange(fromIndex: number, toIndex: number): void {
  if (!Number.isSafeInteger(fromIndex) || !Number.isSafeInteger(toIndex) || fromIndex < 0 || toIndex < fromIndex) {
    throw new RangeError(`leaf range [${fromIndex}, ${toIndex}) is not 0 <= from <= to`);
  }
}

/** Checkpoint reads both dialects run as is (`?` placeholders; Postgres numbers them with `numberedSql`). */
const LAST_CHECKPOINT_SQL = 'SELECT * FROM log_checkpoints WHERE log_id = ? ORDER BY tree_size DESC LIMIT 1';
const LAST_ANCHORED_CHECKPOINT_SQL = `SELECT * FROM log_checkpoints
   WHERE log_id = ? AND anchor_leaf_index IS NOT NULL ORDER BY tree_size DESC LIMIT 1`;
const CHECKPOINTS_BY_ANCHOR_LEAF_SQL = `SELECT * FROM log_checkpoints
   WHERE anchor_leaf_index >= ? AND anchor_leaf_index < ? ORDER BY anchor_leaf_index`;
const LAST_ANCHORED_CHECKPOINT_BELOW_SQL = `SELECT * FROM log_checkpoints
   WHERE log_id = ? AND anchor_leaf_index IS NOT NULL AND anchor_leaf_index < ? ORDER BY tree_size DESC LIMIT 1`;
const CHECKPOINT_AT_OR_BELOW_SQL = `SELECT * FROM log_checkpoints
   WHERE log_id = ? AND tree_size <= ? ORDER BY tree_size DESC LIMIT 1`;
const LAST_FINAL_ANCHOR_SIZE_SQL = `SELECT anchor_size FROM anchor_publications
   WHERE kind = ? AND state IN ('finalized', 'obtained') ORDER BY anchor_size DESC LIMIT 1`;

/** `?` placeholders as Postgres's `$1`, `$2`, ... */
function numberedSql(sql: string): string {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

/** The SQL that finds the holes of one log, for `getEvidenceLogCoverage`. Both dialects run it as is, `?`/`$1` aside. */
const GAPS_SQL = (param: string): string => `
  SELECT a.leaf_index + 1 AS from_index,
         (SELECT MIN(b.leaf_index) FROM log_leaves b WHERE b.log_id = a.log_id AND b.leaf_index > a.leaf_index) - 1 AS to_index
    FROM log_leaves a
   WHERE a.log_id = ${param}
     AND NOT EXISTS (SELECT 1 FROM log_leaves c WHERE c.log_id = a.log_id AND c.leaf_index = a.leaf_index + 1)
   ORDER BY a.leaf_index
`;

/** Turn the gap rows, the lowest leaf and the bound into the missing ranges below `bound`. */
function missingRanges(
  lowest: number | null,
  gaps: Array<{ from_index: number | string; to_index: number | string | null }>,
  bound: number,
): LeafIndexRange[] {
  const out: LeafIndexRange[] = [];
  if (lowest === null) {
    if (bound > 0) out.push({ from: 0, to: bound - 1 });
    return out;
  }
  if (lowest > 0) out.push({ from: 0, to: lowest - 1 });
  for (const gap of gaps) {
    const from = Number(gap.from_index);
    const to = gap.to_index === null ? bound - 1 : Number(gap.to_index);
    if (to >= from) out.push({ from, to });
  }
  return out;
}

/** The SQLite log and anchor store, sharing the adapter's connection. */
export class SqliteLogStore implements LogStore, AnchorStore {
  constructor(private readonly db: BetterSqlite3.Database) {}

  async getStoreIdentity(): Promise<StoreIdentity> {
    const identity = sqliteIdentity(this.db);
    if (!identity) throw new StoreIdentityMissingError(0);
    return identity;
  }

  async listLogs(): Promise<LogRecord[]> {
    return (this.db.prepare('SELECT * FROM logs ORDER BY log_id').all() as LogRow[]).map(logFromRow);
  }

  async getLog(logId: number): Promise<LogRecord | null> {
    const row = this.db.prepare('SELECT * FROM logs WHERE log_id = ?').get(logId) as LogRow | undefined;
    return row ? logFromRow(row) : null;
  }

  async getEvidenceLog(chainId: string): Promise<LogRecord | null> {
    const row = this.db
      .prepare(`SELECT * FROM logs WHERE kind = '${EVIDENCE_LOG_KIND}' AND chain_id = ?`)
      .get(chainId) as LogRow | undefined;
    return row ? logFromRow(row) : null;
  }

  async getLogSize(logId: number): Promise<LogSize> {
    const row = this.db
      .prepare('SELECT COALESCE(MAX(leaf_index) + 1, 0) AS size, COUNT(*) AS n FROM log_leaves WHERE log_id = ?')
      .get(logId) as { size: number; n: number };
    return { size: row.size, leafCount: row.n };
  }

  async listLogLeaves(logId: number, fromIndex: number, toIndex: number): Promise<LogLeaf[]> {
    assertLeafRange(fromIndex, toIndex);
    return (
      this.db
        .prepare('SELECT * FROM log_leaves WHERE log_id = ? AND leaf_index >= ? AND leaf_index < ? ORDER BY leaf_index')
        .all(logId, fromIndex, toIndex) as LeafRow[]
    ).map(leafFromRow);
  }

  async getEvidenceLogPosition(evidenceId: string): Promise<LogPosition | null> {
    const row = this.db
      .prepare(
        `SELECT x.log_id, l.origin, l.chain_id, x.leaf_index, x.leaf_digest, x.source
           FROM log_leaves x JOIN logs l ON l.log_id = x.log_id
          WHERE x.source_ref = ? AND l.kind = '${EVIDENCE_LOG_KIND}'`,
      )
      .get(evidenceId) as
      | { log_id: number; origin: string; chain_id: string; leaf_index: number; leaf_digest: string; source: LogLeafSource }
      | undefined;
    if (!row) return null;
    return {
      logId: row.log_id,
      origin: row.origin,
      chainId: row.chain_id,
      leafIndex: row.leaf_index,
      leafDigest: row.leaf_digest,
      source: row.source,
    };
  }

  async getEvidenceLogCoverage(): Promise<EvidenceLogCoverage[]> {
    const read = this.db.transaction((): EvidenceLogCoverage[] => {
      const rows = this.db
        .prepare(
          `SELECT l.log_id, l.origin, l.chain_id,
                  (SELECT COALESCE(MAX(leaf_index) + 1, 0) FROM log_leaves WHERE log_id = l.log_id) AS size,
                  (SELECT MIN(leaf_index) FROM log_leaves WHERE log_id = l.log_id) AS lowest,
                  (SELECT COUNT(*) FROM log_leaves WHERE log_id = l.log_id) AS leaf_count,
                  (SELECT COUNT(*) FROM log_leaves WHERE log_id = l.log_id AND source = 'capture') AS captured,
                  (SELECT COUNT(*) FROM log_leaves WHERE log_id = l.log_id AND source = 'backfill') AS backfilled,
                  COALESCE((SELECT last_sequence FROM chain_state WHERE chain_id = l.chain_id), 0) AS last_sequence
             FROM logs l
            WHERE l.kind = '${EVIDENCE_LOG_KIND}'
            ORDER BY l.chain_id`,
        )
        .all() as Array<{
        log_id: number;
        origin: string;
        chain_id: string;
        size: number;
        lowest: number | null;
        leaf_count: number;
        captured: number;
        backfilled: number;
        last_sequence: number;
      }>;
      const gaps = this.db.prepare(GAPS_SQL('?'));
      return rows.map((row) => ({
        chainId: row.chain_id,
        logId: row.log_id,
        origin: row.origin,
        size: row.size,
        leafCount: row.leaf_count,
        captured: row.captured,
        backfilled: row.backfilled,
        lastSequence: row.last_sequence,
        missing: missingRanges(
          row.lowest,
          gaps.all(row.log_id) as Array<{ from_index: number; to_index: number | null }>,
          Math.max(row.size, row.last_sequence),
        ),
      }));
    });
    return read();
  }

  async ensureStoreLog(kind: string): Promise<LogRecord> {
    const identity = await this.getStoreIdentity();
    const origin = storeLogOrigin(identity.ns, identity.storeId, kind);
    this.db
      .prepare(
        `INSERT INTO logs (origin, kind, chain_id, created_at)
         SELECT ?, ?, NULL, ? WHERE NOT EXISTS (SELECT 1 FROM logs WHERE kind = ? AND chain_id IS NULL)`,
      )
      .run(origin, kind, new Date().toISOString(), kind);
    const row = this.db.prepare('SELECT * FROM logs WHERE kind = ? AND chain_id IS NULL').get(kind) as LogRow;
    return logFromRow(row);
  }

  async appendLogLeaves(logId: number, leaves: NewLogLeaf[]): Promise<void> {
    this.db.transaction(() => this.appendLeavesSync(logId, leaves)).immediate();
  }

  private appendLeavesSync(logId: number, leaves: NewLogLeaf[]): void {
    // logged_at is the statement's own time: log_leaves_logged_now refuses any other.
    const insert = this.db.prepare(
      `INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source, logged_at)
       VALUES (?, ?, ?, ?, 'scheduler', ${SQLITE_NOW})`,
    );
    for (const leaf of leaves) insert.run(logId, leaf.leafIndex, leaf.leafDigest, leaf.sourceRef);
  }

  async insertLogCheckpoint(checkpoint: NewLogCheckpoint): Promise<void> {
    this.insertCheckpointSync(checkpoint);
  }

  private insertCheckpointSync(checkpoint: NewLogCheckpoint): void {
    assertCheckpointBody(checkpoint);
    this.db
      .prepare(
        `INSERT INTO log_checkpoints
           (log_id, tree_size, root, body, body_digest, compact_range, prev_anchored_size, consistency_proof,
            anchor_leaf_index, epoch_id, signatures, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        checkpoint.logId,
        checkpoint.treeSize,
        checkpoint.root,
        checkpoint.body,
        checkpoint.bodyDigest,
        JSON.stringify(checkpoint.compactRange),
        checkpoint.prevAnchoredSize,
        checkpoint.consistencyProof === null ? null : JSON.stringify(checkpoint.consistencyProof),
        checkpoint.anchorLeafIndex,
        checkpoint.epochId,
        JSON.stringify(checkpoint.signatures ?? []),
        new Date().toISOString(),
      );
  }

  async getLogCheckpoint(logId: number, treeSize: number): Promise<LogCheckpoint | null> {
    const row = this.db
      .prepare('SELECT * FROM log_checkpoints WHERE log_id = ? AND tree_size = ?')
      .get(logId, treeSize) as CheckpointRow | undefined;
    return row ? checkpointFromRow(row) : null;
  }

  async listLogCheckpoints(logId: number): Promise<LogCheckpoint[]> {
    return (
      this.db.prepare('SELECT * FROM log_checkpoints WHERE log_id = ? ORDER BY tree_size').all(logId) as CheckpointRow[]
    ).map(checkpointFromRow);
  }

  async getLastLogCheckpoint(logId: number): Promise<LogCheckpoint | null> {
    const row = this.db.prepare(LAST_CHECKPOINT_SQL).get(logId) as CheckpointRow | undefined;
    return row ? checkpointFromRow(row) : null;
  }

  async getLastAnchoredCheckpoint(logId: number): Promise<LogCheckpoint | null> {
    const row = this.db.prepare(LAST_ANCHORED_CHECKPOINT_SQL).get(logId) as CheckpointRow | undefined;
    return row ? checkpointFromRow(row) : null;
  }

  async getLastAnchoredCheckpointBelow(logId: number, anchorSize: number): Promise<LogCheckpoint | null> {
    const row = this.db.prepare(LAST_ANCHORED_CHECKPOINT_BELOW_SQL).get(logId, anchorSize) as CheckpointRow | undefined;
    return row ? checkpointFromRow(row) : null;
  }

  async getLogCheckpointAtOrBelow(logId: number, treeSize: number): Promise<LogCheckpoint | null> {
    const row = this.db.prepare(CHECKPOINT_AT_OR_BELOW_SQL).get(logId, treeSize) as CheckpointRow | undefined;
    return row ? checkpointFromRow(row) : null;
  }

  async listCheckpointsByAnchorLeaf(fromLeaf: number, toLeaf: number): Promise<LogCheckpoint[]> {
    assertLeafRange(fromLeaf, toLeaf);
    return (this.db.prepare(CHECKPOINTS_BY_ANCHOR_LEAF_SQL).all(fromLeaf, toLeaf) as CheckpointRow[]).map(checkpointFromRow);
  }

  async appendCheckpointSignatures(logId: number, treeSize: number, signatures: string[]): Promise<void> {
    this.db
      .transaction(() => {
        const row = this.db
          .prepare('SELECT signatures FROM log_checkpoints WHERE log_id = ? AND tree_size = ?')
          .get(logId, treeSize) as { signatures: string } | undefined;
        if (!row) throw new Error(`log_checkpoints: no checkpoint of size ${treeSize} in log ${logId}`);
        const next = [...(JSON.parse(row.signatures) as string[]), ...signatures];
        this.db
          .prepare('UPDATE log_checkpoints SET signatures = ? WHERE log_id = ? AND tree_size = ?')
          .run(JSON.stringify(next), logId, treeSize);
      })
      .immediate();
  }

  async insertAnchorPublication(publication: NewAnchorPublication): Promise<AnchorPublication> {
    return this.insertPublicationSync(publication);
  }

  private insertPublicationSync(publication: NewAnchorPublication): AnchorPublication {
    // created_at is the statement's own time: anchor_publications_created_now refuses any other.
    const row = this.db
      .prepare(
        `INSERT INTO anchor_publications (epoch_id, anchor_size, p, kind, state, forced, chain, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'prepared', ?, ?, ${SQLITE_NOW}, ${SQLITE_NOW})
         RETURNING *`,
      )
      .get(
        publication.epochId,
        publication.anchorSize,
        publication.p,
        publication.kind,
        publication.forced === true ? 1 : 0,
        publication.chain ?? null,
      ) as PublicationRow;
    return publicationFromRow(row);
  }

  async getAnchorPublication(id: number): Promise<AnchorPublication | null> {
    const row = this.db.prepare('SELECT * FROM anchor_publications WHERE id = ?').get(id) as PublicationRow | undefined;
    return row ? publicationFromRow(row) : null;
  }

  async getAnchorPublicationAt(kind: AnchorPublicationKind, anchorSize: number): Promise<AnchorPublication | null> {
    const row = this.db
      .prepare('SELECT * FROM anchor_publications WHERE kind = ? AND anchor_size = ?')
      .get(kind, anchorSize) as PublicationRow | undefined;
    return row ? publicationFromRow(row) : null;
  }

  async getLastFinalAnchorSize(kind: AnchorPublicationKind): Promise<number | null> {
    const row = this.db.prepare(LAST_FINAL_ANCHOR_SIZE_SQL).get(kind) as { anchor_size: number } | undefined;
    return row ? num(row.anchor_size) : null;
  }

  async listAnchorPublications(
    filter: { kind?: AnchorPublicationKind; states?: AnchorPublicationState[] } = {},
  ): Promise<AnchorPublication[]> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (filter.kind !== undefined) {
      where.push('kind = ?');
      params.push(filter.kind);
    }
    if (filter.states !== undefined) {
      if (filter.states.length === 0) return [];
      where.push(`state IN (${filter.states.map(() => '?').join(', ')})`);
      params.push(...filter.states);
    }
    const sql = `SELECT * FROM anchor_publications ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id`;
    return (this.db.prepare(sql).all(...params) as PublicationRow[]).map(publicationFromRow);
  }

  async getLeafAnchorProgress(logId: number, leafIndex: number): Promise<LeafAnchorProgress | null> {
    const read = this.db.transaction((): LeafAnchorProgress | null => {
      const anchorLog = this.db
        .prepare(`SELECT 1 FROM logs WHERE kind = '${ANCHOR_LOG_KIND}' AND chain_id IS NULL`)
        .get();
      if (!anchorLog) return null;
      const checkpoint = this.db
        .prepare(FIRST_ANCHORED_CHECKPOINT_SQL((n) => `@p${n}`))
        .get({ p1: logId, p2: leafIndex }) as { anchor_leaf_index: number } | undefined;
      if (!checkpoint) return { anchorLeafIndex: null, publications: [] };
      const rows = this.db
        .prepare(COVERING_PUBLICATIONS_SQL((n) => `@p${n}`, `json_extract(attempts, '$[#-1].txHash')`))
        .all({ p1: checkpoint.anchor_leaf_index }) as CoveringPublicationRow[];
      return { anchorLeafIndex: checkpoint.anchor_leaf_index, publications: rows.map(coveringPublicationFromRow) };
    });
    return read();
  }

  async updateAnchorPublication(id: number, patch: AnchorPublicationPatch): Promise<AnchorPublication> {
    const entries = patchEntries(patch);
    const sets = [...entries.map((e) => `${e.column} = ?`), 'updated_at = ?'];
    const row = this.db
      .prepare(`UPDATE anchor_publications SET ${sets.join(', ')} WHERE id = ? RETURNING *`)
      .get(...entries.map((e) => e.value), new Date().toISOString(), id) as PublicationRow | undefined;
    if (!row) throw new Error(`anchor_publications: no publication ${id}`);
    return publicationFromRow(row);
  }

  async persistEpoch(write: EpochWrite): Promise<AnchorPublication[]> {
    return this.db
      .transaction((): AnchorPublication[] => {
        if (write.guard) this.guardEpochSync(write.guard);
        for (const group of write.leaves) this.appendLeavesSync(group.logId, group.leaves);
        for (const checkpoint of write.checkpoints) this.insertCheckpointSync(checkpoint);
        return write.publications.map((p) => this.insertPublicationSync(p));
      })
      .immediate();
  }

  /** `EpochGuard`, inside the epoch's IMMEDIATE transaction, which holds the write lock until it commits. */
  private guardEpochSync(guard: EpochGuard): void {
    const lease = this.db
      .prepare(`SELECT 1 FROM anchor_lease WHERE domain = ? AND holder = ? AND expires_at > ${SQLITE_NOW}`)
      .get(guard.domain, guard.holder);
    const except = guard.supersedes ?? -1;
    const unmined = this.db.prepare(EPOCH_GUARD_UNMINED_SQL).get(except) as { id: number } | undefined;
    const published = this.db.prepare(EPOCH_GUARD_PUBLISHED_SQL).get(except) as { published: number | null };
    assertEpochGuard(guard, lease !== undefined, unmined ? num(unmined.id) : null, published.published === null ? null : num(published.published));
    if (guard.supersedes != null) {
      this.db
        .prepare(`UPDATE anchor_publications SET state = 'superseded', updated_at = ? WHERE id = ?`)
        .run(new Date().toISOString(), guard.supersedes);
    }
  }

  async acquireAnchorLease(domain: string, holder: string, ttlMs: number): Promise<AnchorLease> {
    assertLeaseTtl(ttlMs);
    const expires = `strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+' || ? || ' seconds')`;
    return this.db
      .transaction((): AnchorLease => {
        this.db
          .prepare(
            `INSERT INTO anchor_lease (domain, holder, expires_at) VALUES (?, ?, ${expires})
             ON CONFLICT (domain) DO UPDATE SET holder = excluded.holder, expires_at = excluded.expires_at
              WHERE anchor_lease.holder = excluded.holder OR anchor_lease.expires_at <= ${SQLITE_NOW}`,
          )
          .run(domain, holder, (ttlMs / 1000).toFixed(3));
        return leaseFromRow(this.db.prepare('SELECT * FROM anchor_lease WHERE domain = ?').get(domain) as LeaseRow);
      })
      .immediate();
  }

  async getAnchorLease(domain: string): Promise<AnchorLease | null> {
    const row = this.db.prepare('SELECT * FROM anchor_lease WHERE domain = ?').get(domain) as LeaseRow | undefined;
    return row ? leaseFromRow(row) : null;
  }

  async releaseAnchorLease(domain: string, holder: string): Promise<void> {
    this.db.prepare('DELETE FROM anchor_lease WHERE domain = ? AND holder = ?').run(domain, holder);
  }

  async enrolAnchorWallet(wallet: Pick<AnchorWallet, 'address' | 'chain' | 'domain' | 'nonceBase'>): Promise<AnchorWallet> {
    // WHERE NOT EXISTS rather than ON CONFLICT DO NOTHING:
    // anchor_wallets_block_replace refuses an insert over an enrolled wallet
    // whatever its conflict clause. An enrolled wallet is not written to.
    const { changes } = this.db
      .prepare(
        `INSERT INTO anchor_wallets (address, chain, domain, nonce_base, enrolled_at)
         SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM anchor_wallets WHERE address = ? AND chain = ?)`,
      )
      .run(wallet.address, wallet.chain, wallet.domain, wallet.nonceBase, new Date().toISOString(), wallet.address, wallet.chain);
    if (changes === 0) this.refuseEnrolmentArguments(wallet);
    return (await this.getAnchorWallet(wallet.address, wallet.chain))!;
  }

  /**
   * For a wallet already enrolled, where no insert ran: refuse the arguments
   * a first enrolment's insert would be refused for, with the same error.
   * `anchor_wallets_verify_insert` refuses another domain first, then the
   * `nonce_base` CHECK refuses a nonce base that is not an integer at or
   * above 0 (a BEFORE trigger runs before a CHECK). Postgres refuses the same
   * calls: its ON CONFLICT DO NOTHING runs both before the conflict check.
   * The address and chain need no check, as an enrolled row holds them.
   */
  private refuseEnrolmentArguments(wallet: Pick<AnchorWallet, 'domain' | 'nonceBase'>): void {
    const { elsewhere } = this.db.prepare(`SELECT ? IS NOT ${sqlDomainPrefix(SQLITE_NAMES)} AS elsewhere`).get(wallet.domain) as {
      elsewhere: number;
    };
    if (elsewhere) {
      throw new BetterSqlite3.SqliteError(
        "anchor_wallets: a wallet is enrolled for the store's own domain prefix, unretired",
        'SQLITE_CONSTRAINT_TRIGGER',
      );
    }
    const n = wallet.nonceBase;
    if (!(Number.isInteger(n) && n >= 0 && n < 2 ** 63)) {
      throw new BetterSqlite3.SqliteError(
        "CHECK constraint failed: typeof(nonce_base) = 'integer' AND nonce_base >= 0",
        'SQLITE_CONSTRAINT_CHECK',
      );
    }
  }

  async getAnchorWallet(address: string, chain: string): Promise<AnchorWallet | null> {
    const row = this.db
      .prepare('SELECT * FROM anchor_wallets WHERE address = ? AND chain = ?')
      .get(address, chain) as WalletRow | undefined;
    return row ? walletFromRow(row) : null;
  }

  async retireAnchorWallet(address: string, chain: string): Promise<AnchorWallet> {
    const row = this.db
      .prepare('UPDATE anchor_wallets SET retired_at = ? WHERE address = ? AND chain = ? AND retired_at IS NULL RETURNING *')
      .get(new Date().toISOString(), address, chain) as WalletRow | undefined;
    if (!row) throw new Error(walletNotRetirable(await this.getAnchorWallet(address, chain), address, chain));
    return walletFromRow(row);
  }

  async insertAnchorWalletTx(tx: NewAnchorWalletTx): Promise<AnchorWalletTx> {
    assertWalletTx(tx);
    const row = this.db
      .prepare(
        `INSERT INTO anchor_wallet_txs (address, chain, nonce, tx_hash, kind, raw_tx, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`,
      )
      .get(tx.address, tx.chain, tx.nonce, tx.txHash, tx.kind, tx.rawTx, new Date().toISOString()) as WalletTxRow;
    return walletTxFromRow(row);
  }

  async listAnchorWalletTxs(address: string, chain: string): Promise<AnchorWalletTx[]> {
    return (
      this.db
        .prepare('SELECT * FROM anchor_wallet_txs WHERE address = ? AND chain = ? ORDER BY nonce')
        .all(address, chain) as WalletTxRow[]
    ).map(walletTxFromRow);
  }

  async getRecordAnchor(evidenceId: string): Promise<unknown> {
    const row = this.db.prepare('SELECT envelope FROM envelopes WHERE evidence_id = ?').get(evidenceId) as { envelope: string } | undefined;
    if (!row) return null;
    return (JSON.parse(row.envelope) as { nonRepudiation?: { anchor?: unknown } }).nonRepudiation?.anchor ?? null;
  }

  async fillAnchorArtifacts(chunk: AnchorFillChunk): Promise<AnchorFillResult> {
    return this.db
      .transaction((): AnchorFillResult => {
        const read = this.db.prepare('SELECT envelope, chain_id FROM envelopes WHERE evidence_id = ?');
        const logChain = this.db.prepare('SELECT chain_id FROM logs WHERE log_id = ?');
        const write = this.db.prepare('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?');
        const highest = this.db.prepare('SELECT MAX(revision_no) AS highest FROM envelope_revisions WHERE evidence_id = ?');
        const revision = this.db.prepare(
          `INSERT INTO envelope_revisions (evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor)
           VALUES (?, ?, ?, ?, ?, '${ANCHOR_FILL_CAUSE}', '${REVISION_ACTOR_ANCHOR}')`,
        );
        const result: AnchorFillResult = { filled: 0, alreadyAnchored: 0, missing: [], conflicts: [] };
        for (const fill of chunk.fills) {
          const row = read.get(fill.evidenceId) as { envelope: string; chain_id: string } | undefined;
          if (!row) {
            result.missing.push(fill.evidenceId);
            continue;
          }
          const stored = JSON.parse(row.envelope) as EvidenceEnvelope;
          const chainOfLog = fill.logId === undefined ? null : ((logChain.get(fill.logId) as { chain_id: string | null } | undefined)?.chain_id ?? null);
          if (anchorFillConflict(stored, row.chain_id, chainOfLog, fill) !== null) {
            result.conflicts.push(fill.evidenceId);
            continue;
          }
          const next = filledEnvelope(stored, fill, chunk);
          if (!next) {
            result.alreadyAnchored += 1;
            continue;
          }
          write.run(JSON.stringify(next), fill.evidenceId);
          const head = highest.get(fill.evidenceId) as { highest: number | null };
          revision.run(
            fill.evidenceId,
            nextRevisionNo(head.highest),
            next.integrity.canonicalDigest,
            next.integrity.chainLink ?? null,
            new Date().toISOString(),
          );
          result.filled += 1;
        }
        const progressed = this.db
          .prepare('UPDATE anchor_publications SET fill_progress = ?, updated_at = ? WHERE id = ?')
          .run(JSON.stringify(chunk.fillProgress), new Date().toISOString(), chunk.publicationId);
        if (progressed.changes !== 1) throw new Error(`anchor_publications: no publication ${chunk.publicationId}`);
        return result;
      })
      .immediate();
  }
}

// ── Postgres ─────────────────────────────────────────────────────────────

const PG_HEX64 = (col: string): string => `(${col} ~ '^[0-9a-f]{64}$')`;
const PG_DECIMAL = (col: string): string => `(${col} IS NULL OR ${col} ~ '^[0-9]+$')`;
const PG_JSON_ARRAY = (col: string): string => `(jsonb_typeof(${col}) = 'array')`;
/** `ns` as `assertLogNamespace` takes it. Postgres regular-expression ranges are code-point ranges. */
const PG_VALID_NS = (col: string): string =>
  `(char_length(${col}) BETWEEN 1 AND ${LOG_NAMESPACE_MAX_LENGTH}` +
  ` AND ${col} ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?([.][a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'` +
  ` AND ${col} !~ '[a-z0-9-]{${LOG_NAMESPACE_LABEL_MAX_LENGTH + 1}}')`;

const POSTGRES_LOG_TABLES = `
  CREATE TABLE IF NOT EXISTS store_identity (
    singleton  SMALLINT PRIMARY KEY CHECK (singleton = 1),
    store_id   TEXT NOT NULL CHECK (store_id ~ '^[0-9a-f]{32}$'),
    ns         TEXT NOT NULL CHECK ${PG_VALID_NS('ns')},
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS logs (
    log_id     BIGSERIAL PRIMARY KEY,
    origin     TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind ~ '^[a-z][a-z0-9]*$'),
    chain_id   TEXT CHECK (chain_id IS NULL OR chain_id <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK ((kind = '${EVIDENCE_LOG_KIND}') = (chain_id IS NOT NULL))
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_evidence_chain ON logs(chain_id) WHERE kind = '${EVIDENCE_LOG_KIND}';
  CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_store_kind ON logs(kind) WHERE chain_id IS NULL;

  CREATE TABLE IF NOT EXISTS log_leaves (
    log_id      BIGINT NOT NULL REFERENCES logs(log_id),
    leaf_index  BIGINT NOT NULL CHECK (leaf_index >= 0),
    leaf_digest TEXT NOT NULL CHECK ${PG_HEX64('leaf_digest')},
    source_ref  TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('capture', 'backfill', 'scheduler')),
    logged_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (log_id, leaf_index),
    UNIQUE (log_id, source_ref),
    UNIQUE (log_id, leaf_digest)
  );
  CREATE INDEX IF NOT EXISTS idx_log_leaves_source_ref ON log_leaves(source_ref);

  CREATE TABLE IF NOT EXISTS log_checkpoints (
    log_id             BIGINT NOT NULL REFERENCES logs(log_id),
    tree_size          BIGINT NOT NULL CHECK (tree_size >= 1),
    root               TEXT NOT NULL CHECK ${PG_HEX64('root')},
    body               TEXT NOT NULL,
    body_digest        TEXT NOT NULL UNIQUE CHECK ${PG_HEX64('body_digest')},
    compact_range      JSONB NOT NULL CHECK ${PG_JSON_ARRAY('compact_range')},
    prev_anchored_size BIGINT CHECK (prev_anchored_size IS NULL OR (prev_anchored_size >= 1 AND prev_anchored_size < tree_size)),
    consistency_proof  JSONB CHECK (consistency_proof IS NULL OR ${PG_JSON_ARRAY('consistency_proof')}),
    anchor_leaf_index  BIGINT CHECK (anchor_leaf_index IS NULL OR anchor_leaf_index >= 0),
    epoch_id           BIGINT,
    signatures         JSONB NOT NULL DEFAULT '[]'::jsonb CHECK ${PG_JSON_ARRAY('signatures')},
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (log_id, tree_size),
    CHECK ((prev_anchored_size IS NULL) = (consistency_proof IS NULL))
  );
  ${CHECKPOINT_INDEX_SQL}

  CREATE TABLE IF NOT EXISTS anchor_publications (
    id                  BIGSERIAL PRIMARY KEY,
    epoch_id            BIGINT NOT NULL,
    anchor_size         BIGINT NOT NULL CHECK (anchor_size >= 1),
    p                   TEXT NOT NULL CHECK ${PG_HEX64('p')},
    kind                TEXT NOT NULL CHECK (kind IN (${sqlList(ANCHOR_PUBLICATION_KINDS)})),
    state               TEXT NOT NULL,
    forced              BOOLEAN NOT NULL DEFAULT false,
    chain               TEXT,
    from_address        TEXT CHECK (from_address IS NULL OR from_address ~ '^0x[0-9a-f]{40}$'),
    nonce               BIGINT CHECK (nonce IS NULL OR nonce >= 0),
    attempts            JSONB NOT NULL DEFAULT '[]'::jsonb CHECK ${PG_JSON_ARRAY('attempts')},
    mined_tx_hash       TEXT,
    block_number        BIGINT CHECK (block_number IS NULL OR block_number >= 0),
    block_hash          TEXT,
    block_header        TEXT,
    tx_index            BIGINT CHECK (tx_index IS NULL OR tx_index >= 0),
    tx_trie_proof       JSONB CHECK (tx_trie_proof IS NULL OR ${PG_JSON_ARRAY('tx_trie_proof')}),
    gas_used            TEXT CHECK ${PG_DECIMAL('gas_used')},
    effective_gas_price TEXT CHECK ${PG_DECIMAL('effective_gas_price')},
    token               TEXT,
    gen_time            TEXT,
    fill_progress       JSONB CHECK (fill_progress IS NULL OR jsonb_typeof(fill_progress) = 'object'),
    error               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (kind, anchor_size),
    CHECK (${sqlStatesByKind()}),
    CHECK ((kind = 'evm-calldata/1' AND chain IS NOT NULL AND chain ~ '^eip155:[1-9][0-9]*$')
        OR (kind = 'rfc3161/1' AND chain IS NULL)),
    CHECK (state NOT IN ('submitted', 'included', 'finalized')
        OR (from_address IS NOT NULL AND nonce IS NOT NULL AND jsonb_array_length(attempts) >= 1)),
    CHECK (state NOT IN ('included', 'finalized')
        OR (mined_tx_hash IS NOT NULL AND block_number IS NOT NULL AND block_hash IS NOT NULL)),
    CHECK (state <> 'obtained' OR (token IS NOT NULL AND gen_time IS NOT NULL))
  );
  ${ANCHOR_NONCE_INDEX_SQL}

  CREATE TABLE IF NOT EXISTS anchor_lease (
    domain     TEXT PRIMARY KEY,
    holder     TEXT NOT NULL CHECK (char_length(holder) BETWEEN 1 AND 200),
    expires_at TIMESTAMPTZ NOT NULL
  );

  CREATE TABLE IF NOT EXISTS anchor_wallets (
    address     TEXT NOT NULL CHECK (address ~ '^0x[0-9a-f]{40}$'),
    chain       TEXT NOT NULL CHECK (chain ~ '^eip155:[1-9][0-9]*$'),
    domain      TEXT NOT NULL,
    nonce_base  BIGINT NOT NULL CHECK (nonce_base >= 0),
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ,
    PRIMARY KEY (address, chain)
  );

  CREATE TABLE IF NOT EXISTS anchor_wallet_txs (
    address    TEXT NOT NULL,
    chain      TEXT NOT NULL,
    nonce      BIGINT NOT NULL CHECK (nonce >= 0),
    tx_hash    TEXT NOT NULL UNIQUE CHECK (tx_hash ~ '^0x[0-9a-f]{64}$'),
    kind       TEXT NOT NULL CHECK (kind IN (${sqlList(ANCHOR_WALLET_TX_KINDS)})),
    raw_tx     TEXT NOT NULL CHECK (raw_tx ~ '^0x([0-9a-f]{2})+$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (address, chain, nonce),
    FOREIGN KEY (address, chain) REFERENCES anchor_wallets(address, chain)
  );
`;

/**
 * A plpgsql statement that runs `sql` with EXECUTE. In `sql`,
 * `%1$I` is the schema of the trigger's table and `%2$I` the trigger's table,
 * so every table it names is the store's, whatever the search_path of the
 * session that fired the trigger; `$1` is the row being written (NEW), then
 * `using`'s values in order. `into` receives its first row, or nulls when it
 * returns none.
 */
function pgExecute(sql: string, { into, using = [] }: { into?: string; using?: string[] } = {}): string {
  return `EXECUTE format($q$${sql.trim()}$q$, TG_TABLE_SCHEMA, TG_TABLE_NAME)${into ? ` INTO ${into}` : ''} USING ${['NEW', ...using].join(', ')};`;
}

/** The origin a `logs` row must carry, from `store_identity`: a statement for `pgExecute`. */
const POSTGRES_EXPECTED_ORIGIN = `
  SELECT si.ns || '/' || si.store_id ||
         CASE WHEN ($1).kind = '${EVIDENCE_LOG_KIND}'
              THEN '/${EVIDENCE_LOG_KIND}/' || encode(convert_to(($1).chain_id, 'UTF8'), 'hex')
              ELSE '/' || ($1).kind END
    FROM %1$I.store_identity si
`;

/** The id of the evidence log of the row's chain: a statement for `pgExecute`. */
const POSTGRES_EVIDENCE_LOG_ID = `SELECT log_id FROM %1$I.logs WHERE kind = '${EVIDENCE_LOG_KIND}' AND chain_id = ($1).chain_id`;

/**
 * Every function, as CREATE OR REPLACE: a store runs the current bodies after
 * every `ensureTables()`, and a trigger created once keeps calling the
 * replaced function. Each runs with its search_path pinned to `pg_catalog,
 * pg_temp` and names every table through `pgExecute`, so a temporary table,
 * or a table, function or operator in a schema the session that fires it puts
 * first, does not stand in for the store's.
 */
function postgresLogFunctions(): string {
  const changed = (cols: readonly string[]): string => cols.map((c) => `NEW.${c} IS DISTINCT FROM OLD.${c}`).join(' OR ');
  const LANGUAGE = 'LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp';
  const block = (fn: string, message: string): string => `
    CREATE OR REPLACE FUNCTION ${fn}() RETURNS TRIGGER AS $$
    BEGIN
      RAISE EXCEPTION '${message} (% refused)', TG_OP;
    END;
    $$ ${LANGUAGE};
  `;
  const P = PG_EXECUTE_NAMES;
  return `
    ${block('store_identity_block_mutation', 'store_identity: the store identity is immutable')}
    ${block('logs_block_mutation', 'logs: logs are insert-only')}
    ${block('log_leaves_block_mutation', 'log_leaves: leaves are insert-only')}
    ${block('log_checkpoints_block_removal', 'log_checkpoints: checkpoints are insert-only')}
    ${block('anchor_publications_block_removal', 'anchor_publications: publications are never deleted')}
    ${block('anchor_wallets_block_removal', 'anchor_wallets: enrolments are never deleted')}
    ${block('anchor_wallet_txs_block_mutation', 'anchor_wallet_txs: accounted transactions are insert-only')}

    CREATE OR REPLACE FUNCTION anchor_lease_verify() RETURNS TRIGGER AS $$
    DECLARE
      v_prefix TEXT;
    BEGIN
      IF TG_OP = 'UPDATE' AND NEW.domain IS DISTINCT FROM OLD.domain THEN
        RAISE EXCEPTION 'anchor_lease: the domain is fixed';
      END IF;
      ${pgExecute(`SELECT ${sqlDomainPrefix(P)}`, { into: 'v_prefix' })}
      IF NEW.domain IS DISTINCT FROM v_prefix THEN
        RAISE EXCEPTION 'anchor_lease: the domain is not the store''s domain prefix';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    CREATE OR REPLACE FUNCTION anchor_wallets_verify_insert() RETURNS TRIGGER AS $$
    DECLARE
      v_prefix TEXT;
    BEGIN
      ${pgExecute(`SELECT ${sqlDomainPrefix(P)}`, { into: 'v_prefix' })}
      IF NEW.domain IS DISTINCT FROM v_prefix OR NEW.retired_at IS NOT NULL THEN
        RAISE EXCEPTION 'anchor_wallets: a wallet is enrolled for the store''s own domain prefix, unretired';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    CREATE OR REPLACE FUNCTION anchor_wallets_guard_update() RETURNS TRIGGER AS $$
    BEGIN
      IF ${changed(WALLET_FIXED)} OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at) THEN
        RAISE EXCEPTION 'anchor_wallets: an enrolment is fixed; only retired_at is set, once';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    CREATE OR REPLACE FUNCTION anchor_wallet_txs_verify_insert() RETURNS TRIGGER AS $$
    DECLARE
      v_free BOOLEAN;
    BEGIN
      ${pgExecute(`SELECT ${sqlWalletTxNonceFree(P)}`, { into: 'v_free' })}
      IF NOT v_free THEN
        RAISE EXCEPTION 'anchor_wallet_txs: the wallet is not enrolled and unretired from at or below this nonce, or a publication holds the nonce';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    -- No log or publication written ahead of the rows it follows:
    -- listLogs() and listAnchorPublications() read in id
    -- order, and so does the epoch guard's read of an unmined publication. A
    -- log_id or id the sequence did not hand the insert, or one below an id
    -- already committed, is refused, and every row gets an id drawn as it is
    -- written (postgresBackdatedIdGuard); the store's own writes name none.
    ${postgresBackdatedIdGuard('logs_block_backdated_id', 'logs', 'log_id')}
    ${postgresBackdatedIdGuard('anchor_publications_block_backdated_id', 'anchor_publications', 'id')}

    CREATE OR REPLACE FUNCTION logs_verify_insert() RETURNS TRIGGER AS $$
    DECLARE
      v_expected TEXT;
    BEGIN
      ${pgExecute(POSTGRES_EXPECTED_ORIGIN, { into: 'v_expected' })}
      IF v_expected IS NULL OR NEW.origin IS DISTINCT FROM v_expected THEN
        RAISE EXCEPTION 'logs: the origin % is not the one the store identity names for this log', NEW.origin;
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    -- The density trigger: a gap, then a repeated source or digest, in the
    -- order every adapter applies the rules. An occupied position is left to
    -- the primary key, or to the ON CONFLICT of evidence_log_append(). Evidence
    -- and per-store logs take their own sources.
    CREATE OR REPLACE FUNCTION log_leaves_verify_insert() RETURNS TRIGGER AS $$
    DECLARE
      v_held BOOLEAN;
      v_kind TEXT;
    BEGIN
      IF NEW.leaf_index <> 0 THEN
        ${pgExecute('SELECT EXISTS (SELECT 1 FROM %1$I.%2$I WHERE log_id = ($1).log_id AND leaf_index = ($1).leaf_index - 1)', { into: 'v_held' })}
        IF NOT v_held THEN
          RAISE EXCEPTION '[tzun:log_gap] log_leaves: leaf % of log % has no predecessor, and a log is dense',
            NEW.leaf_index, NEW.log_id;
        END IF;
      END IF;
      ${pgExecute(
        `SELECT EXISTS (SELECT 1 FROM %1$I.%2$I WHERE log_id = ($1).log_id AND leaf_index <> ($1).leaf_index
                          AND (source_ref = ($1).source_ref OR leaf_digest = ($1).leaf_digest))`,
        { into: 'v_held' },
      )}
      IF v_held THEN
        RAISE EXCEPTION '[tzun:duplicate_leaf] log_leaves: leaf % of log % repeats a source or digest the log already has, and its leaves are distinct',
          NEW.leaf_index, NEW.log_id;
      END IF;
      ${pgExecute('SELECT kind FROM %1$I.logs WHERE log_id = ($1).log_id', { into: 'v_kind' })}
      IF (v_kind = '${EVIDENCE_LOG_KIND}') IS DISTINCT FROM (NEW.source IN ('capture', 'backfill')) THEN
        RAISE EXCEPTION 'log_leaves: an evidence log takes capture and backfill leaves, a per-store log takes scheduler leaves';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    -- The evidence leaf, inside the transaction that stores the record.
    CREATE OR REPLACE FUNCTION evidence_log_append() RETURNS TRIGGER AS $$
    DECLARE
      v_log    BIGINT;
      v_seq    TEXT := NEW.envelope->'payload'->>'sequenceNumber';
      v_digest TEXT := NEW.envelope->'integrity'->>'canonicalDigest';
      v_index  BIGINT;
      v_held   BOOLEAN;
    BEGIN
      IF NEW.chain_id = '' THEN
        RAISE EXCEPTION '[tzun:empty_chain_id] evidence log: an empty chain id names no log';
      END IF;
      IF jsonb_typeof(NEW.envelope->'payload'->'sequenceNumber') IS DISTINCT FROM 'number'
         OR v_seq !~ '^[1-9][0-9]{0,17}$' THEN
        RAISE EXCEPTION '[tzun:invalid_sequence_number] evidence log: payload.sequenceNumber is not a positive integer';
      END IF;
      IF jsonb_typeof(NEW.envelope->'integrity'->'canonicalDigest') IS DISTINCT FROM 'string'
         OR v_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION '[tzun:invalid_digest] evidence log: integrity.canonicalDigest is not 64 lowercase hex';
      END IF;
      v_index := v_seq::bigint - 1;

      ${pgExecute(POSTGRES_EVIDENCE_LOG_ID, { into: 'v_log' })}
      IF v_log IS NULL THEN
        ${pgExecute('SELECT EXISTS (SELECT 1 FROM %1$I.store_identity)', { into: 'v_held' })}
        IF NOT v_held THEN
          RAISE EXCEPTION '[tzun:store_identity_missing] evidence log: the store has no store_identity';
        END IF;
        ${pgExecute(`
          INSERT INTO %1$I.logs (origin, kind, chain_id)
          SELECT si.ns || '/' || si.store_id || '/${EVIDENCE_LOG_KIND}/' || encode(convert_to(($1).chain_id, 'UTF8'), 'hex'),
                 '${EVIDENCE_LOG_KIND}', ($1).chain_id
            FROM %1$I.store_identity si
          ON CONFLICT DO NOTHING`)}
        ${pgExecute(POSTGRES_EVIDENCE_LOG_ID, { into: 'v_log' })}
      END IF;

      -- Write once: a record at a position that already has a leaf keeps
      -- that leaf, and the store goes ahead. At a free position the leaf is
      -- written, and log_leaves_verify_insert() refuses a gap or a repeat.
      ${pgExecute('SELECT EXISTS (SELECT 1 FROM %1$I.log_leaves WHERE log_id = $2 AND leaf_index = $3)', {
        into: 'v_held',
        using: ['v_log', 'v_index'],
      })}
      IF v_held THEN
        RETURN NULL;
      END IF;
      ${pgExecute(
        `INSERT INTO %1$I.log_leaves (log_id, leaf_index, leaf_digest, source_ref, source)
         VALUES ($2, $3, $4, ($1).evidence_id, 'capture')
         ON CONFLICT (log_id, leaf_index) DO NOTHING`,
        { using: ['v_log', 'v_index', 'v_digest'] },
      )}
      RETURN NULL;
    END;
    $$ ${LANGUAGE};

    CREATE OR REPLACE FUNCTION log_checkpoints_verify_insert() RETURNS TRIGGER AS $$
    DECLARE
      v_held   BOOLEAN;
      v_prefix TEXT;
    BEGIN
      ${pgExecute('SELECT EXISTS (SELECT 1 FROM %1$I.log_leaves WHERE log_id = ($1).log_id AND leaf_index = ($1).tree_size - 1)', { into: 'v_held' })}
      IF NOT v_held THEN
        RAISE EXCEPTION 'log_checkpoints: log % has no leaf at tree_size - 1 (%)', NEW.log_id, NEW.tree_size - 1;
      END IF;
      ${pgExecute(`SELECT origin || E'\\n' || ($1).tree_size::text || E'\\n' FROM %1$I.logs WHERE log_id = ($1).log_id`, { into: 'v_prefix' })}
      IF left(NEW.body, char_length(v_prefix)) IS DISTINCT FROM v_prefix
         OR right(NEW.body, 1) IS DISTINCT FROM E'\\n'
         OR char_length(NEW.body) - char_length(replace(NEW.body, E'\\n', '')) <> 3 THEN
        RAISE EXCEPTION 'log_checkpoints: the body is not three lines naming this log''s origin and this size';
      END IF;
      IF split_part(NEW.body, E'\\n', 3) IS DISTINCT FROM encode(decode(NEW.root, 'hex'), 'base64') THEN
        RAISE EXCEPTION 'log_checkpoints: the body''s root line is not the root in base64';
      END IF;
      ${pgExecute(`SELECT ${sqlAnchorLeafIndexOk(P)}`, { into: 'v_held' })}
      IF NOT v_held THEN
        RAISE EXCEPTION 'log_checkpoints: anchor_leaf_index must name the anchor-log leaf that holds this body''s digest, and the anchor log''s own checkpoints have none';
      END IF;
      IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.signatures) s WHERE jsonb_typeof(s) <> 'string') THEN
        RAISE EXCEPTION 'log_checkpoints: signatures must be an array of strings';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    CREATE OR REPLACE FUNCTION log_checkpoints_guard_update() RETURNS TRIGGER AS $$
    BEGIN
      IF ${changed(CHECKPOINT_FIXED)} THEN
        RAISE EXCEPTION 'log_checkpoints: a checkpoint is immutable; only signatures may be appended';
      END IF;
      IF jsonb_array_length(NEW.signatures) < jsonb_array_length(OLD.signatures)
         OR EXISTS (SELECT 1 FROM jsonb_array_elements(OLD.signatures) WITH ORDINALITY AS o(v, i)
                     WHERE NEW.signatures -> (i::int - 1) IS DISTINCT FROM o.v)
         OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.signatures) s WHERE jsonb_typeof(s) <> 'string') THEN
        RAISE EXCEPTION 'log_checkpoints: signatures are append-only';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    CREATE OR REPLACE FUNCTION anchor_publications_verify_insert() RETURNS TRIGGER AS $$
    DECLARE
      v_held BOOLEAN;
    BEGIN
      IF NEW.state IS DISTINCT FROM 'prepared' OR jsonb_array_length(NEW.attempts) <> 0
         OR ${[...WRITTEN_ONCE, ...FIXED_AFTER_FINALITY].map((c) => `NEW.${c} IS NOT NULL`).join(' OR ')} THEN
        RAISE EXCEPTION 'anchor_publications: a publication starts prepared, with nothing sent or stored';
      END IF;
      ${pgExecute(`SELECT ${sqlPIsAnchorCheckpoint(P)}`, { into: 'v_held' })}
      IF NOT v_held THEN
        RAISE EXCEPTION 'anchor_publications: P is not the digest of the anchor log''s stored checkpoint at anchor_size';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    CREATE OR REPLACE FUNCTION anchor_publications_guard_update() RETURNS TRIGGER AS $$
    DECLARE
      v_free BOOLEAN;
    BEGIN
      IF ${changed(PUBLICATION_IDENTITY)} THEN
        RAISE EXCEPTION 'anchor_publications: id, epoch, anchor size, P, kind, chain and created_at are fixed';
      END IF;
      IF NEW.state IS DISTINCT FROM OLD.state AND NOT (${sqlAllowedTransition()}) THEN
        RAISE EXCEPTION 'anchor_publications: state moves forward only (% -> % refused)', OLD.state, NEW.state;
      END IF;
      IF ${WRITTEN_ONCE.map((c) => `(OLD.${c} IS NOT NULL AND NEW.${c} IS DISTINCT FROM OLD.${c})`).join(' OR ')} THEN
        RAISE EXCEPTION 'anchor_publications: sender, nonce, token and genTime are written once';
      END IF;
      IF OLD.nonce IS NULL AND NEW.nonce IS NOT NULL THEN
        ${pgExecute(`SELECT ${sqlPublicationNonceFree(P)}`, { into: 'v_free' })}
        IF NOT v_free THEN
          RAISE EXCEPTION 'anchor_publications: an accounted wallet transaction holds the nonce, or the wallet is retired';
        END IF;
      END IF;
      IF jsonb_array_length(NEW.attempts) < jsonb_array_length(OLD.attempts)
         OR EXISTS (SELECT 1 FROM jsonb_array_elements(OLD.attempts) WITH ORDINALITY AS o(v, i)
                     WHERE (NEW.attempts -> (i::int - 1) ->> 'txHash') IS DISTINCT FROM (o.v ->> 'txHash')
                        OR (NEW.attempts -> (i::int - 1) ->> 'rawTx') IS DISTINCT FROM (o.v ->> 'rawTx'))
         OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.attempts) n
                     WHERE jsonb_typeof(n) <> 'object'
                        OR jsonb_typeof(n -> 'txHash') IS DISTINCT FROM 'string'
                        OR jsonb_typeof(n -> 'rawTx') IS DISTINCT FROM 'string') THEN
        RAISE EXCEPTION 'anchor_publications: attempts are append-only, and an attempt''s txHash and rawTx never change';
      END IF;
      IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.attempts) n
                  WHERE jsonb_typeof(n -> 'broadcast') IS DISTINCT FROM 'string'
                     OR (n ->> 'broadcast') NOT IN (${sqlList(ANCHOR_BROADCAST_OUTCOMES)})) THEN
        RAISE EXCEPTION 'anchor_publications: an attempt''s broadcast is ${ANCHOR_BROADCAST_OUTCOMES.join(', ')}';
      END IF;
      IF NEW.state = 'superseded' AND OLD.state IS DISTINCT FROM 'superseded'
         AND EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.attempts) n WHERE (n ->> 'broadcast') IS DISTINCT FROM 'rejected') THEN
        RAISE EXCEPTION 'anchor_publications: only a publication whose every broadcast was rejected may be superseded';
      END IF;
      IF OLD.state = 'finalized'
         AND (${FIXED_AFTER_FINALITY.map((c) => `(OLD.${c} IS NOT NULL AND NEW.${c} IS DISTINCT FROM OLD.${c})`).join(' OR ')}) THEN
        RAISE EXCEPTION 'anchor_publications: once finalized, the mined transaction and its proof material are fixed';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};
    ${postgresTrustFunctions()}
  `;
}

/**
 * The trust rules (the record binding, the owner gate, the derived digests,
 * times and transitions, and the lease protocol), each a function and a
 * trigger under a name no earlier release knows: a process of an earlier
 * release replaces only its own functions and creates only its own triggers,
 * so it leaves these in place. Each pins its search_path and names tables
 * through `pgExecute`, as every function here does.
 */
function postgresTrustFunctions(): string {
  const LANGUAGE = 'LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp';
  return `
    -- Record binding: an evidence leaf is a copy of the record stored at its
    -- position: the row of envelopes with the leaf's source_ref as evidence
    -- id, the log's chain, the leaf index plus one as payload.sequenceNumber
    -- (the canonical text evidence_log_append() requires) and the leaf digest
    -- as integrity.canonicalDigest. An evidence log takes capture leaves only:
    -- the upgrade backfill runs before this trigger exists.
    CREATE OR REPLACE FUNCTION log_leaves_bind_record() RETURNS TRIGGER AS $$
    DECLARE
      v_kind TEXT;
      v_held BOOLEAN;
    BEGIN
      ${pgExecute('SELECT kind FROM %1$I.logs WHERE log_id = ($1).log_id', { into: 'v_kind' })}
      IF v_kind = '${EVIDENCE_LOG_KIND}' THEN
        IF NEW.source IS DISTINCT FROM 'capture' THEN
          RAISE EXCEPTION '[tzun:leaf_without_record] log_leaves: an evidence log takes capture leaves only';
        END IF;
        ${pgExecute(
          `SELECT EXISTS (
             SELECT 1 FROM %1$I.envelopes e JOIN %1$I.logs l ON l.log_id = ($1).log_id
              WHERE e.evidence_id = ($1).source_ref AND e.chain_id = l.chain_id
                AND jsonb_typeof(e.envelope->'payload'->'sequenceNumber') = 'number'
                AND (e.envelope->'payload'->>'sequenceNumber') = (($1).leaf_index + 1)::text
                AND (e.envelope->'integrity'->>'canonicalDigest') = ($1).leaf_digest)`,
          { into: 'v_held' },
        )}
        IF NOT v_held THEN
          RAISE EXCEPTION '[tzun:leaf_without_record] log_leaves: leaf % of evidence log % is not the record stored at that position',
            NEW.leaf_index, NEW.log_id;
        END IF;
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    -- Owner gate: every anchoring write needs the store's owner. The SDK
    -- connects as the role that owns the store (ensureTables() needs it), so
    -- every other writer is another role: ETL, reporting, a second service.
    -- session_user, not current_user, so a SECURITY DEFINER function cannot
    -- lend the right. The owner is a role session_user can act as: from
    -- PostgreSQL 16, one it holds with INHERIT (USAGE) or with SET; before 16,
    -- which has no SET option, any membership (a member can SET ROLE to it).
    -- Evidence logs and evidence leaves stay open to a capture role, since the
    -- record binding confines them to copies of stored records. On envelopes,
    -- any change to a record's nonRepudiation.anchor is the owner's (the fill
    -- adds it; no other SDK path changes or removes one). On anchor_lease, a
    -- DELETE is the owner's too (releaseAnchorLease).
    CREATE OR REPLACE FUNCTION anchoring_require_owner() RETURNS TRIGGER AS $$
    DECLARE
      v_owner OID;
      v_kind  TEXT;
      v_owner_acts BOOLEAN;
    BEGIN
      -- Nested, not AND: PL/pgSQL plans each expression with NEW's own
      -- columns, so a field another table lacks is read only on its table.
      IF TG_OP <> 'DELETE' THEN
        IF TG_TABLE_NAME = 'logs' THEN
          IF NEW.kind = '${EVIDENCE_LOG_KIND}' THEN
            RETURN NEW;
          END IF;
        ELSIF TG_TABLE_NAME = 'log_leaves' THEN
          ${pgExecute('SELECT kind FROM %1$I.logs WHERE log_id = ($1).log_id', { into: 'v_kind' })}
          IF v_kind = '${EVIDENCE_LOG_KIND}' THEN
            RETURN NEW;
          END IF;
        ELSIF TG_TABLE_NAME = 'envelopes' THEN
          IF (OLD.envelope->'nonRepudiation'->'anchor') IS NOT DISTINCT FROM (NEW.envelope->'nonRepudiation'->'anchor') THEN
            RETURN NEW;
          END IF;
        END IF;
      END IF;
      SELECT relowner INTO v_owner FROM pg_catalog.pg_class WHERE oid = TG_RELID;
      IF current_setting('server_version_num')::int >= 160000 THEN
        v_owner_acts := pg_catalog.pg_has_role(session_user, v_owner, 'USAGE') OR pg_catalog.pg_has_role(session_user, v_owner, 'SET');
      ELSE
        v_owner_acts := pg_catalog.pg_has_role(session_user, v_owner, 'MEMBER');
      END IF;
      IF NOT v_owner_acts THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
          MESSAGE = format('[tzun:anchoring_owner_required] %s: %s by %s refused; only the role that owns the store writes the anchoring tables',
                           TG_TABLE_NAME, TG_OP, session_user);
      END IF;
      IF TG_OP = 'DELETE' THEN
        RETURN OLD;
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    -- A checkpoint's body_digest is the SHA-256 of its body.
    CREATE OR REPLACE FUNCTION log_checkpoints_check_digest() RETURNS TRIGGER AS $$
    BEGIN
      IF NEW.body_digest IS DISTINCT FROM encode(sha256(convert_to(NEW.body, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION 'log_checkpoints: body_digest is not the SHA-256 of the body (log %, size %)', NEW.log_id, NEW.tree_size;
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    -- The database assigns the times the scheduler's clock, cadence and
    -- force window read.
    CREATE OR REPLACE FUNCTION anchor_publications_assign_created_at() RETURNS TRIGGER AS $$
    BEGIN
      NEW.created_at := now();
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    CREATE OR REPLACE FUNCTION log_leaves_assign_logged_at() RETURNS TRIGGER AS $$
    BEGIN
      NEW.logged_at := now();
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    -- Superseding needs an attempt, every one rejected (the supersede
    -- rule of anchor_publications_guard_update, restated); an attempt's
    -- broadcast moves only unknown -> accepted, unknown -> rejected or
    -- rejected -> accepted, so accepted is final.
    CREATE OR REPLACE FUNCTION anchor_publications_guard_transitions() RETURNS TRIGGER AS $$
    BEGIN
      IF NEW.state = 'superseded' AND OLD.state IS DISTINCT FROM 'superseded'
         AND (jsonb_array_length(NEW.attempts) = 0
              OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.attempts) n WHERE (n ->> 'broadcast') IS DISTINCT FROM 'rejected')) THEN
        RAISE EXCEPTION 'anchor_publications: only a publication with an attempt, every one rejected, may be superseded';
      END IF;
      IF EXISTS (SELECT 1 FROM jsonb_array_elements(OLD.attempts) WITH ORDINALITY AS o(v, i)
                  WHERE (NEW.attempts -> (i::int - 1) ->> 'broadcast') IS DISTINCT FROM (o.v ->> 'broadcast')
                    AND NOT ((o.v ->> 'broadcast') = 'unknown'
                             OR ((o.v ->> 'broadcast') = 'rejected' AND (NEW.attempts -> (i::int - 1) ->> 'broadcast') = 'accepted'))) THEN
        RAISE EXCEPTION 'anchor_publications: a broadcast outcome moves only from unknown, or from rejected to accepted';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};

    -- A lease holder is a ${ANCHOR_LEASE_HOLDER_PREFIX} scheduler.
    CREATE OR REPLACE FUNCTION anchor_lease_require_protocol() RETURNS TRIGGER AS $$
    BEGIN
      IF left(NEW.holder, ${ANCHOR_LEASE_HOLDER_PREFIX.length}) IS DISTINCT FROM '${ANCHOR_LEASE_HOLDER_PREFIX}' THEN
        RAISE EXCEPTION 'anchor_lease: the holder is not a ${ANCHOR_LEASE_HOLDER_PREFIX} scheduler';
      END IF;
      RETURN NEW;
    END;
    $$ ${LANGUAGE};
  `;
}

interface PgTrigger {
  table: string;
  name: string;
  when: string;
  level: 'ROW' | 'STATEMENT';
  fn: string;
}

/** Guard triggers, created when absent. The functions they call are replaced on every run. */
const POSTGRES_GUARD_TRIGGERS: PgTrigger[] = [
  { table: 'store_identity', name: 'store_identity_block_mutation_trigger', when: 'BEFORE UPDATE OR DELETE', level: 'ROW', fn: 'store_identity_block_mutation' },
  { table: 'store_identity', name: 'store_identity_block_truncate_trigger', when: 'BEFORE TRUNCATE', level: 'STATEMENT', fn: 'store_identity_block_mutation' },
  { table: 'logs', name: 'logs_block_backdated_id_trigger', when: 'BEFORE INSERT', level: 'ROW', fn: 'logs_block_backdated_id' },
  { table: 'logs', name: 'logs_verify_insert_trigger', when: 'BEFORE INSERT', level: 'ROW', fn: 'logs_verify_insert' },
  { table: 'logs', name: 'logs_block_mutation_trigger', when: 'BEFORE UPDATE OR DELETE', level: 'ROW', fn: 'logs_block_mutation' },
  { table: 'logs', name: 'logs_block_truncate_trigger', when: 'BEFORE TRUNCATE', level: 'STATEMENT', fn: 'logs_block_mutation' },
  { table: 'log_leaves', name: 'log_leaves_block_mutation_trigger', when: 'BEFORE UPDATE OR DELETE', level: 'ROW', fn: 'log_leaves_block_mutation' },
  { table: 'log_leaves', name: 'log_leaves_block_truncate_trigger', when: 'BEFORE TRUNCATE', level: 'STATEMENT', fn: 'log_leaves_block_mutation' },
  { table: 'log_checkpoints', name: 'log_checkpoints_verify_insert_trigger', when: 'BEFORE INSERT', level: 'ROW', fn: 'log_checkpoints_verify_insert' },
  { table: 'log_checkpoints', name: 'log_checkpoints_guard_update_trigger', when: 'BEFORE UPDATE', level: 'ROW', fn: 'log_checkpoints_guard_update' },
  { table: 'log_checkpoints', name: 'log_checkpoints_block_delete_trigger', when: 'BEFORE DELETE', level: 'ROW', fn: 'log_checkpoints_block_removal' },
  { table: 'log_checkpoints', name: 'log_checkpoints_block_truncate_trigger', when: 'BEFORE TRUNCATE', level: 'STATEMENT', fn: 'log_checkpoints_block_removal' },
  { table: 'anchor_publications', name: 'anchor_publications_block_backdated_id_trigger', when: 'BEFORE INSERT', level: 'ROW', fn: 'anchor_publications_block_backdated_id' },
  { table: 'anchor_publications', name: 'anchor_publications_verify_insert_trigger', when: 'BEFORE INSERT', level: 'ROW', fn: 'anchor_publications_verify_insert' },
  { table: 'anchor_publications', name: 'anchor_publications_guard_update_trigger', when: 'BEFORE UPDATE', level: 'ROW', fn: 'anchor_publications_guard_update' },
  { table: 'anchor_publications', name: 'anchor_publications_block_delete_trigger', when: 'BEFORE DELETE', level: 'ROW', fn: 'anchor_publications_block_removal' },
  { table: 'anchor_publications', name: 'anchor_publications_block_truncate_trigger', when: 'BEFORE TRUNCATE', level: 'STATEMENT', fn: 'anchor_publications_block_removal' },
  { table: 'anchor_lease', name: 'anchor_lease_verify_trigger', when: 'BEFORE INSERT OR UPDATE', level: 'ROW', fn: 'anchor_lease_verify' },
  { table: 'anchor_wallets', name: 'anchor_wallets_verify_insert_trigger', when: 'BEFORE INSERT', level: 'ROW', fn: 'anchor_wallets_verify_insert' },
  { table: 'anchor_wallets', name: 'anchor_wallets_guard_update_trigger', when: 'BEFORE UPDATE', level: 'ROW', fn: 'anchor_wallets_guard_update' },
  { table: 'anchor_wallets', name: 'anchor_wallets_block_delete_trigger', when: 'BEFORE DELETE', level: 'ROW', fn: 'anchor_wallets_block_removal' },
  { table: 'anchor_wallets', name: 'anchor_wallets_block_truncate_trigger', when: 'BEFORE TRUNCATE', level: 'STATEMENT', fn: 'anchor_wallets_block_removal' },
  { table: 'anchor_wallet_txs', name: 'anchor_wallet_txs_verify_insert_trigger', when: 'BEFORE INSERT', level: 'ROW', fn: 'anchor_wallet_txs_verify_insert' },
  { table: 'anchor_wallet_txs', name: 'anchor_wallet_txs_block_mutation_trigger', when: 'BEFORE UPDATE OR DELETE', level: 'ROW', fn: 'anchor_wallet_txs_block_mutation' },
  { table: 'anchor_wallet_txs', name: 'anchor_wallet_txs_block_truncate_trigger', when: 'BEFORE TRUNCATE', level: 'STATEMENT', fn: 'anchor_wallet_txs_block_mutation' },
];

/**
 * The trust rules' triggers (the owner gate, the derived digests, times and
 * transitions, and the lease protocol), created when absent with the guards.
 * Postgres fires a table's triggers in name order, and each of these is named
 * `tzun_<table>_<rule>`, after the table's other triggers: on a raw write the
 * guards refuse first, with their own messages, and these rules after them,
 * the time assignments last.
 */
const POSTGRES_TRUST_TRIGGERS: PgTrigger[] = [
  ...['logs', 'log_leaves'].map((table): PgTrigger => ({
    table,
    name: `tzun_${table}_require_owner`,
    when: 'BEFORE INSERT',
    level: 'ROW',
    fn: 'anchoring_require_owner',
  })),
  ...['log_checkpoints', 'anchor_publications', 'anchor_wallets', 'anchor_lease'].map((table): PgTrigger => ({
    table,
    name: `tzun_${table}_require_owner`,
    when: 'BEFORE INSERT OR UPDATE',
    level: 'ROW',
    fn: 'anchoring_require_owner',
  })),
  { table: 'anchor_wallet_txs', name: 'tzun_anchor_wallet_txs_require_owner', when: 'BEFORE INSERT', level: 'ROW', fn: 'anchoring_require_owner' },
  { table: 'anchor_lease', name: 'tzun_anchor_lease_require_owner_delete', when: 'BEFORE DELETE', level: 'ROW', fn: 'anchoring_require_owner' },
  { table: 'envelopes', name: 'tzun_envelopes_anchor_require_owner', when: 'BEFORE UPDATE', level: 'ROW', fn: 'anchoring_require_owner' },
  { table: 'log_checkpoints', name: 'tzun_log_checkpoints_check_digest', when: 'BEFORE INSERT', level: 'ROW', fn: 'log_checkpoints_check_digest' },
  { table: 'anchor_publications', name: 'tzun_anchor_publications_assign_created_at', when: 'BEFORE INSERT', level: 'ROW', fn: 'anchor_publications_assign_created_at' },
  { table: 'log_leaves', name: 'tzun_log_leaves_assign_logged_at', when: 'BEFORE INSERT', level: 'ROW', fn: 'log_leaves_assign_logged_at' },
  { table: 'anchor_publications', name: 'tzun_anchor_publications_guard_transitions', when: 'BEFORE UPDATE', level: 'ROW', fn: 'anchor_publications_guard_transitions' },
  { table: 'anchor_lease', name: 'tzun_anchor_lease_require_protocol', when: 'BEFORE INSERT OR UPDATE', level: 'ROW', fn: 'anchor_lease_require_protocol' },
];

/**
 * The record binding of evidence leaves, created after the backfill with
 * the density trigger, and named, like the triggers above, to fire after the
 * table's other triggers.
 */
const POSTGRES_BIND_RECORD_TRIGGER: PgTrigger = {
  table: 'log_leaves',
  name: 'tzun_log_leaves_bind_record',
  when: 'BEFORE INSERT',
  level: 'ROW',
  fn: 'log_leaves_bind_record',
};

/** The density trigger, then the trigger on `envelopes`: created last, after the backfill. */
const POSTGRES_DENSITY_TRIGGER: PgTrigger = {
  table: 'log_leaves',
  name: 'log_leaves_verify_insert_trigger',
  when: 'BEFORE INSERT',
  level: 'ROW',
  fn: 'log_leaves_verify_insert',
};
const POSTGRES_EVIDENCE_TRIGGER: PgTrigger = {
  table: 'envelopes',
  name: 'evidence_log_append_trigger',
  when: 'AFTER INSERT',
  level: 'ROW',
  fn: 'evidence_log_append',
};

function createIfAbsent(triggers: PgTrigger[]): string {
  const body = triggers
    .map(
      (t) => `
      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = '${t.table}'::regclass AND tgname = '${t.name}') THEN
        CREATE TRIGGER ${t.name} ${t.when} ON ${t.table} FOR EACH ${t.level} EXECUTE FUNCTION ${t.fn}();
      END IF;`,
    )
    .join('');
  return `DO $$ BEGIN ${body} END $$;`;
}

const POSTGRES_CREATE_EVIDENCE_LOGS = `
  INSERT INTO logs (origin, kind, chain_id)
  SELECT si.ns || '/' || si.store_id || '/${EVIDENCE_LOG_KIND}/' || encode(convert_to(c.chain_id, 'UTF8'), 'hex'),
         '${EVIDENCE_LOG_KIND}', c.chain_id
    FROM (SELECT DISTINCT chain_id FROM envelopes WHERE chain_id <> '') AS c
   CROSS JOIN store_identity si
   WHERE NOT EXISTS (SELECT 1 FROM logs l WHERE l.kind = '${EVIDENCE_LOG_KIND}' AND l.chain_id = c.chain_id)
   ORDER BY c.chain_id
`;

/**
 * The Postgres twin of SQLITE_BACKFILL_LEAVES: each chain's dense prefix. The
 * first stored record wins a shared position (created_at, then id).
 */
const POSTGRES_BACKFILL_LEAVES = `
  INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source)
  SELECT l.log_id, p.seq - 1, p.digest, p.evidence_id, 'backfill'
    FROM (
      SELECT chain_id, seq, digest, evidence_id,
             ROW_NUMBER() OVER (PARTITION BY chain_id ORDER BY seq) AS rank_in_chain
        FROM (
          SELECT chain_id, seq, digest, evidence_id,
                 ROW_NUMBER() OVER (PARTITION BY chain_id, digest ORDER BY seq) AS digest_rank
            FROM (
              SELECT DISTINCT ON (chain_id, seq) evidence_id, chain_id, seq, digest
                FROM (
                  SELECT evidence_id, chain_id, created_at,
                         CASE WHEN jsonb_typeof(envelope->'payload'->'sequenceNumber') = 'number'
                               AND (envelope->'payload'->>'sequenceNumber') ~ '^[1-9][0-9]{0,17}$'
                              THEN (envelope->'payload'->>'sequenceNumber')::bigint END AS seq,
                         CASE WHEN jsonb_typeof(envelope->'integrity'->'canonicalDigest') = 'string'
                              THEN envelope->'integrity'->>'canonicalDigest' END AS digest
                    FROM envelopes
                ) AS r
               WHERE seq IS NOT NULL AND digest ~ '^[0-9a-f]{64}$'
               ORDER BY chain_id, seq, created_at, evidence_id
            ) AS positions
        ) AS distinct_digests
       WHERE digest_rank = 1
    ) AS p
    JOIN logs l ON l.kind = '${EVIDENCE_LOG_KIND}' AND l.chain_id = p.chain_id
   WHERE p.rank_in_chain = p.seq
   ORDER BY l.log_id, p.seq
  ON CONFLICT DO NOTHING
`;

async function postgresIdentity(db: Pick<PoolClient, 'query'>): Promise<StoreIdentity | null> {
  const result = await db.query<{ store_id: string; ns: string; created_at: Date | string }>(
    'SELECT store_id, ns, created_at FROM store_identity WHERE singleton = 1',
  );
  const row = result.rows[0];
  return row ? { storeId: row.store_id, ns: row.ns, createdAt: iso(row.created_at) } : null;
}

/**
 * The Postgres twin of `migrateSqliteLogSchema`, on `client`, in one
 * transaction. A store that is not migrated yet has `envelopes` locked IN
 * SHARE ROW EXCLUSIVE MODE first: a store from any other session waits until
 * the backfill and the triggers are committed. `ensureTables()` calls it under
 * its advisory lock, which serialises concurrent migrations, so the check
 * before the lock cannot race another migration.
 */
export async function migratePostgresLogSchema(client: PoolClient, options: LogSchemaOptions = {}): Promise<void> {
  const configured = options.logNamespace === undefined ? undefined : assertLogNamespace(options.logNamespace);
  await client.query('BEGIN');
  try {
    const hasTrigger = async (): Promise<boolean> =>
      (
        await client.query(
          `SELECT 1 FROM pg_trigger WHERE tgrelid = 'envelopes'::regclass AND tgname = '${POSTGRES_EVIDENCE_TRIGGER.name}'`,
        )
      ).rows.length > 0;
    const migrated = await hasTrigger();
    if (!migrated) await client.query('LOCK TABLE envelopes IN SHARE ROW EXCLUSIVE MODE');
    await client.query(POSTGRES_LOG_TABLES);
    await client.query(postgresLogFunctions());
    await client.query(createIfAbsent(POSTGRES_GUARD_TRIGGERS));
    await client.query(createIfAbsent(POSTGRES_TRUST_TRIGGERS));
    const held = await postgresIdentity(client);
    if (!held) {
      const logs = Number((await client.query<{ n: string }>('SELECT COUNT(*) AS n FROM logs')).rows[0]?.n ?? 0);
      if (logs > 0) throw new StoreIdentityMissingError(logs);
      await client.query('INSERT INTO store_identity (singleton, store_id, ns) VALUES (1, $1, $2)', [
        mintStoreId(),
        configured ?? DEFAULT_LOG_NAMESPACE,
      ]);
    } else if (configured !== undefined && held.ns !== configured) {
      throw new LogNamespaceMismatchError(held.ns, configured);
    }
    if (!migrated) {
      await client.query(`DROP TRIGGER IF EXISTS ${POSTGRES_DENSITY_TRIGGER.name} ON log_leaves`);
      await client.query(`DROP TRIGGER IF EXISTS ${POSTGRES_BIND_RECORD_TRIGGER.name} ON log_leaves`);
      await client.query(POSTGRES_CREATE_EVIDENCE_LOGS);
      await client.query(POSTGRES_BACKFILL_LEAVES);
      await logMigrationTestHooks.afterBackfill?.();
    }
    await client.query(createIfAbsent([POSTGRES_DENSITY_TRIGGER, POSTGRES_BIND_RECORD_TRIGGER, POSTGRES_EVIDENCE_TRIGGER]));
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  }
}

/** The Postgres log and anchor store, sharing the adapter's pool. */
export class PostgresLogStore implements LogStore, AnchorStore {
  constructor(private readonly pool: Pool) {}

  private async inTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async getStoreIdentity(): Promise<StoreIdentity> {
    const identity = await postgresIdentity(this.pool);
    if (!identity) throw new StoreIdentityMissingError(0);
    return identity;
  }

  async listLogs(): Promise<LogRecord[]> {
    return (await this.pool.query<LogRow>('SELECT * FROM logs ORDER BY log_id')).rows.map(logFromRow);
  }

  async getLog(logId: number): Promise<LogRecord | null> {
    const row = (await this.pool.query<LogRow>('SELECT * FROM logs WHERE log_id = $1', [logId])).rows[0];
    return row ? logFromRow(row) : null;
  }

  async getEvidenceLog(chainId: string): Promise<LogRecord | null> {
    const row = (
      await this.pool.query<LogRow>(`SELECT * FROM logs WHERE kind = '${EVIDENCE_LOG_KIND}' AND chain_id = $1`, [chainId])
    ).rows[0];
    return row ? logFromRow(row) : null;
  }

  async getLogSize(logId: number): Promise<LogSize> {
    const row = (
      await this.pool.query<{ size: string; n: string }>(
        'SELECT COALESCE(MAX(leaf_index) + 1, 0) AS size, COUNT(*) AS n FROM log_leaves WHERE log_id = $1',
        [logId],
      )
    ).rows[0];
    return { size: Number(row.size), leafCount: Number(row.n) };
  }

  async listLogLeaves(logId: number, fromIndex: number, toIndex: number): Promise<LogLeaf[]> {
    assertLeafRange(fromIndex, toIndex);
    return (
      await this.pool.query<LeafRow>(
        'SELECT * FROM log_leaves WHERE log_id = $1 AND leaf_index >= $2 AND leaf_index < $3 ORDER BY leaf_index',
        [logId, fromIndex, toIndex],
      )
    ).rows.map(leafFromRow);
  }

  async getEvidenceLogPosition(evidenceId: string): Promise<LogPosition | null> {
    const row = (
      await this.pool.query<{
        log_id: string;
        origin: string;
        chain_id: string;
        leaf_index: string;
        leaf_digest: string;
        source: LogLeafSource;
      }>(
        `SELECT x.log_id, l.origin, l.chain_id, x.leaf_index, x.leaf_digest, x.source
           FROM log_leaves x JOIN logs l ON l.log_id = x.log_id
          WHERE x.source_ref = $1 AND l.kind = '${EVIDENCE_LOG_KIND}'`,
        [evidenceId],
      )
    ).rows[0];
    if (!row) return null;
    return {
      logId: Number(row.log_id),
      origin: row.origin,
      chainId: row.chain_id,
      leafIndex: Number(row.leaf_index),
      leafDigest: row.leaf_digest,
      source: row.source,
    };
  }

  async getEvidenceLogCoverage(): Promise<EvidenceLogCoverage[]> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const rows = (
        await client.query<{
          log_id: string;
          origin: string;
          chain_id: string;
          size: string;
          lowest: string | null;
          leaf_count: string;
          captured: string;
          backfilled: string;
          last_sequence: string;
        }>(
          `SELECT l.log_id, l.origin, l.chain_id,
                  (SELECT COALESCE(MAX(leaf_index) + 1, 0) FROM log_leaves WHERE log_id = l.log_id) AS size,
                  (SELECT MIN(leaf_index) FROM log_leaves WHERE log_id = l.log_id) AS lowest,
                  (SELECT COUNT(*) FROM log_leaves WHERE log_id = l.log_id) AS leaf_count,
                  (SELECT COUNT(*) FROM log_leaves WHERE log_id = l.log_id AND source = 'capture') AS captured,
                  (SELECT COUNT(*) FROM log_leaves WHERE log_id = l.log_id AND source = 'backfill') AS backfilled,
                  COALESCE((SELECT last_sequence FROM chain_state WHERE chain_id = l.chain_id), 0) AS last_sequence
             FROM logs l
            WHERE l.kind = '${EVIDENCE_LOG_KIND}'
            ORDER BY l.chain_id`,
        )
      ).rows;
      const out: EvidenceLogCoverage[] = [];
      for (const row of rows) {
        const gaps = (
          await client.query<{ from_index: string; to_index: string | null }>(GAPS_SQL('$1'), [row.log_id])
        ).rows;
        const size = Number(row.size);
        const lastSequence = Number(row.last_sequence);
        out.push({
          chainId: row.chain_id,
          logId: Number(row.log_id),
          origin: row.origin,
          size,
          leafCount: Number(row.leaf_count),
          captured: Number(row.captured),
          backfilled: Number(row.backfilled),
          lastSequence,
          missing: missingRanges(row.lowest === null ? null : Number(row.lowest), gaps, Math.max(size, lastSequence)),
        });
      }
      await client.query('COMMIT');
      return out;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async ensureStoreLog(kind: string): Promise<LogRecord> {
    const identity = await this.getStoreIdentity();
    const origin = storeLogOrigin(identity.ns, identity.storeId, kind);
    await this.pool.query(
      `INSERT INTO logs (origin, kind, chain_id)
       SELECT $1, $2, NULL WHERE NOT EXISTS (SELECT 1 FROM logs WHERE kind = $2 AND chain_id IS NULL)
       ON CONFLICT DO NOTHING`,
      [origin, kind],
    );
    const row = (await this.pool.query<LogRow>('SELECT * FROM logs WHERE kind = $1 AND chain_id IS NULL', [kind])).rows[0];
    return logFromRow(row);
  }

  async appendLogLeaves(logId: number, leaves: NewLogLeaf[]): Promise<void> {
    await this.inTransaction((client) => this.appendLeavesWith(client, logId, leaves));
  }

  private async appendLeavesWith(client: PoolClient, logId: number, leaves: NewLogLeaf[]): Promise<void> {
    for (const leaf of leaves) {
      await client.query(
        `INSERT INTO log_leaves (log_id, leaf_index, leaf_digest, source_ref, source) VALUES ($1, $2, $3, $4, 'scheduler')`,
        [logId, leaf.leafIndex, leaf.leafDigest, leaf.sourceRef],
      );
    }
  }

  async insertLogCheckpoint(checkpoint: NewLogCheckpoint): Promise<void> {
    await this.insertCheckpointWith(this.pool, checkpoint);
  }

  private async insertCheckpointWith(db: Pick<Pool | PoolClient, 'query'>, checkpoint: NewLogCheckpoint): Promise<void> {
    assertCheckpointBody(checkpoint);
    await db.query(
      `INSERT INTO log_checkpoints
         (log_id, tree_size, root, body, body_digest, compact_range, prev_anchored_size, consistency_proof,
          anchor_leaf_index, epoch_id, signatures)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        checkpoint.logId,
        checkpoint.treeSize,
        checkpoint.root,
        checkpoint.body,
        checkpoint.bodyDigest,
        JSON.stringify(checkpoint.compactRange),
        checkpoint.prevAnchoredSize,
        checkpoint.consistencyProof === null ? null : JSON.stringify(checkpoint.consistencyProof),
        checkpoint.anchorLeafIndex,
        checkpoint.epochId,
        JSON.stringify(checkpoint.signatures ?? []),
      ],
    );
  }

  async getLogCheckpoint(logId: number, treeSize: number): Promise<LogCheckpoint | null> {
    const row = (
      await this.pool.query<CheckpointRow>('SELECT * FROM log_checkpoints WHERE log_id = $1 AND tree_size = $2', [logId, treeSize])
    ).rows[0];
    return row ? checkpointFromRow(row) : null;
  }

  async listLogCheckpoints(logId: number): Promise<LogCheckpoint[]> {
    return (
      await this.pool.query<CheckpointRow>('SELECT * FROM log_checkpoints WHERE log_id = $1 ORDER BY tree_size', [logId])
    ).rows.map(checkpointFromRow);
  }

  async getLastLogCheckpoint(logId: number): Promise<LogCheckpoint | null> {
    const row = (await this.pool.query<CheckpointRow>(numberedSql(LAST_CHECKPOINT_SQL), [logId])).rows[0];
    return row ? checkpointFromRow(row) : null;
  }

  async getLastAnchoredCheckpoint(logId: number): Promise<LogCheckpoint | null> {
    const row = (await this.pool.query<CheckpointRow>(numberedSql(LAST_ANCHORED_CHECKPOINT_SQL), [logId])).rows[0];
    return row ? checkpointFromRow(row) : null;
  }

  async getLastAnchoredCheckpointBelow(logId: number, anchorSize: number): Promise<LogCheckpoint | null> {
    const row = (await this.pool.query<CheckpointRow>(numberedSql(LAST_ANCHORED_CHECKPOINT_BELOW_SQL), [logId, anchorSize])).rows[0];
    return row ? checkpointFromRow(row) : null;
  }

  async getLogCheckpointAtOrBelow(logId: number, treeSize: number): Promise<LogCheckpoint | null> {
    const row = (await this.pool.query<CheckpointRow>(numberedSql(CHECKPOINT_AT_OR_BELOW_SQL), [logId, treeSize])).rows[0];
    return row ? checkpointFromRow(row) : null;
  }

  async listCheckpointsByAnchorLeaf(fromLeaf: number, toLeaf: number): Promise<LogCheckpoint[]> {
    assertLeafRange(fromLeaf, toLeaf);
    return (
      await this.pool.query<CheckpointRow>(numberedSql(CHECKPOINTS_BY_ANCHOR_LEAF_SQL), [fromLeaf, toLeaf])
    ).rows.map(checkpointFromRow);
  }

  async appendCheckpointSignatures(logId: number, treeSize: number, signatures: string[]): Promise<void> {
    const result = await this.pool.query(
      `UPDATE log_checkpoints SET signatures = signatures || $3::jsonb WHERE log_id = $1 AND tree_size = $2`,
      [logId, treeSize, JSON.stringify(signatures)],
    );
    if ((result.rowCount ?? 0) === 0) throw new Error(`log_checkpoints: no checkpoint of size ${treeSize} in log ${logId}`);
  }

  async insertAnchorPublication(publication: NewAnchorPublication): Promise<AnchorPublication> {
    return this.insertPublicationWith(this.pool, publication);
  }

  private async insertPublicationWith(
    db: Pick<Pool | PoolClient, 'query'>,
    publication: NewAnchorPublication,
  ): Promise<AnchorPublication> {
    const row = (
      await db.query<PublicationRow>(
        `INSERT INTO anchor_publications (epoch_id, anchor_size, p, kind, state, forced, chain)
         VALUES ($1, $2, $3, $4, 'prepared', $5, $6)
         RETURNING *`,
        [
          publication.epochId,
          publication.anchorSize,
          publication.p,
          publication.kind,
          publication.forced === true,
          publication.chain ?? null,
        ],
      )
    ).rows[0];
    return publicationFromRow(row);
  }

  async getAnchorPublication(id: number): Promise<AnchorPublication | null> {
    const row = (await this.pool.query<PublicationRow>('SELECT * FROM anchor_publications WHERE id = $1', [id])).rows[0];
    return row ? publicationFromRow(row) : null;
  }

  async getAnchorPublicationAt(kind: AnchorPublicationKind, anchorSize: number): Promise<AnchorPublication | null> {
    const row = (
      await this.pool.query<PublicationRow>('SELECT * FROM anchor_publications WHERE kind = $1 AND anchor_size = $2', [kind, anchorSize])
    ).rows[0];
    return row ? publicationFromRow(row) : null;
  }

  async getLastFinalAnchorSize(kind: AnchorPublicationKind): Promise<number | null> {
    const row = (await this.pool.query<{ anchor_size: number | string }>(numberedSql(LAST_FINAL_ANCHOR_SIZE_SQL), [kind])).rows[0];
    return row ? num(row.anchor_size) : null;
  }

  async listAnchorPublications(
    filter: { kind?: AnchorPublicationKind; states?: AnchorPublicationState[] } = {},
  ): Promise<AnchorPublication[]> {
    if (filter.states !== undefined && filter.states.length === 0) return [];
    const rows = (
      await this.pool.query<PublicationRow>(
        `SELECT * FROM anchor_publications
          WHERE ($1::text IS NULL OR kind = $1) AND ($2::text[] IS NULL OR state = ANY($2))
          ORDER BY id`,
        [filter.kind ?? null, filter.states ?? null],
      )
    ).rows;
    return rows.map(publicationFromRow);
  }

  async getLeafAnchorProgress(logId: number, leafIndex: number): Promise<LeafAnchorProgress | null> {
    const head = (
      await this.pool.query<{ anchor_log: boolean; anchor_leaf_index: number | string | null }>(
        `SELECT EXISTS (SELECT 1 FROM logs WHERE kind = '${ANCHOR_LOG_KIND}' AND chain_id IS NULL) AS anchor_log,
                (${FIRST_ANCHORED_CHECKPOINT_SQL((n) => `$${n}::bigint`)}) AS anchor_leaf_index`,
        [logId, leafIndex],
      )
    ).rows[0];
    if (!head.anchor_log) return null;
    if (head.anchor_leaf_index === null) return { anchorLeafIndex: null, publications: [] };
    const anchorLeafIndex = num(head.anchor_leaf_index);
    const rows = (
      await this.pool.query<CoveringPublicationRow>(
        COVERING_PUBLICATIONS_SQL((n) => `$${n}::bigint`, `attempts -> -1 ->> 'txHash'`),
        [anchorLeafIndex],
      )
    ).rows;
    return { anchorLeafIndex, publications: rows.map(coveringPublicationFromRow) };
  }

  async updateAnchorPublication(id: number, patch: AnchorPublicationPatch): Promise<AnchorPublication> {
    const entries = patchEntries(patch);
    const sets = [...entries.map((e, i) => `${e.column} = $${i + 1}`), 'updated_at = NOW()'];
    const row = (
      await this.pool.query<PublicationRow>(
        `UPDATE anchor_publications SET ${sets.join(', ')} WHERE id = $${entries.length + 1} RETURNING *`,
        [...entries.map((e) => e.value), id],
      )
    ).rows[0];
    if (!row) throw new Error(`anchor_publications: no publication ${id}`);
    return publicationFromRow(row);
  }

  async persistEpoch(write: EpochWrite): Promise<AnchorPublication[]> {
    return this.inTransaction(async (client) => {
      if (write.guard) await this.guardEpochWith(client, write.guard);
      for (const group of write.leaves) await this.appendLeavesWith(client, group.logId, group.leaves);
      for (const checkpoint of write.checkpoints) await this.insertCheckpointWith(client, checkpoint);
      const created: AnchorPublication[] = [];
      for (const publication of write.publications) created.push(await this.insertPublicationWith(client, publication));
      return created;
    });
  }

  /**
   * `EpochGuard`, inside the epoch's transaction. The lease row stays locked
   * until the epoch commits, so no other instance takes the lease, and then
   * publishes, between this check and the commit; an epoch of another holder
   * committed first is seen by the reads after the lock.
   */
  private async guardEpochWith(client: PoolClient, guard: EpochGuard): Promise<void> {
    const lease = await client.query(
      'SELECT 1 FROM anchor_lease WHERE domain = $1 AND holder = $2 AND expires_at > clock_timestamp() FOR UPDATE',
      [guard.domain, guard.holder],
    );
    const except = guard.supersedes ?? -1;
    const unmined = (await client.query<{ id: string }>(numberedSql(EPOCH_GUARD_UNMINED_SQL), [except])).rows[0];
    const published = (await client.query<{ published: string | null }>(numberedSql(EPOCH_GUARD_PUBLISHED_SQL), [except])).rows[0];
    assertEpochGuard(
      guard,
      (lease.rowCount ?? 0) > 0,
      unmined ? num(unmined.id) : null,
      published?.published == null ? null : num(published.published),
    );
    if (guard.supersedes != null) {
      await client.query(`UPDATE anchor_publications SET state = 'superseded', updated_at = NOW() WHERE id = $1`, [guard.supersedes]);
    }
  }

  async acquireAnchorLease(domain: string, holder: string, ttlMs: number): Promise<AnchorLease> {
    assertLeaseTtl(ttlMs);
    // clock_timestamp(), not NOW(): NOW() is the transaction's start, and the
    // lease is judged against the moment of this statement.
    await this.pool.query(
      `INSERT INTO anchor_lease (domain, holder, expires_at)
       VALUES ($1, $2, clock_timestamp() + ($3::double precision * interval '1 millisecond'))
       ON CONFLICT (domain) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at
        WHERE anchor_lease.holder = EXCLUDED.holder OR anchor_lease.expires_at <= clock_timestamp()`,
      [domain, holder, ttlMs],
    );
    return (await this.getAnchorLease(domain))!;
  }

  async getAnchorLease(domain: string): Promise<AnchorLease | null> {
    const row = (await this.pool.query<LeaseRow>('SELECT * FROM anchor_lease WHERE domain = $1', [domain])).rows[0];
    return row ? leaseFromRow(row) : null;
  }

  async releaseAnchorLease(domain: string, holder: string): Promise<void> {
    await this.pool.query('DELETE FROM anchor_lease WHERE domain = $1 AND holder = $2', [domain, holder]);
  }

  async enrolAnchorWallet(wallet: Pick<AnchorWallet, 'address' | 'chain' | 'domain' | 'nonceBase'>): Promise<AnchorWallet> {
    await this.pool.query(
      `INSERT INTO anchor_wallets (address, chain, domain, nonce_base) VALUES ($1, $2, $3, $4)
       ON CONFLICT (address, chain) DO NOTHING`,
      [wallet.address, wallet.chain, wallet.domain, wallet.nonceBase],
    );
    return (await this.getAnchorWallet(wallet.address, wallet.chain))!;
  }

  async getAnchorWallet(address: string, chain: string): Promise<AnchorWallet | null> {
    const row = (
      await this.pool.query<WalletRow>('SELECT * FROM anchor_wallets WHERE address = $1 AND chain = $2', [address, chain])
    ).rows[0];
    return row ? walletFromRow(row) : null;
  }

  async retireAnchorWallet(address: string, chain: string): Promise<AnchorWallet> {
    const row = (
      await this.pool.query<WalletRow>(
        'UPDATE anchor_wallets SET retired_at = NOW() WHERE address = $1 AND chain = $2 AND retired_at IS NULL RETURNING *',
        [address, chain],
      )
    ).rows[0];
    if (!row) throw new Error(walletNotRetirable(await this.getAnchorWallet(address, chain), address, chain));
    return walletFromRow(row);
  }

  async insertAnchorWalletTx(tx: NewAnchorWalletTx): Promise<AnchorWalletTx> {
    assertWalletTx(tx);
    const row = (
      await this.pool.query<WalletTxRow>(
        `INSERT INTO anchor_wallet_txs (address, chain, nonce, tx_hash, kind, raw_tx)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [tx.address, tx.chain, tx.nonce, tx.txHash, tx.kind, tx.rawTx],
      )
    ).rows[0];
    return walletTxFromRow(row);
  }

  async listAnchorWalletTxs(address: string, chain: string): Promise<AnchorWalletTx[]> {
    return (
      await this.pool.query<WalletTxRow>(
        'SELECT * FROM anchor_wallet_txs WHERE address = $1 AND chain = $2 ORDER BY nonce',
        [address, chain],
      )
    ).rows.map(walletTxFromRow);
  }

  async getRecordAnchor(evidenceId: string): Promise<unknown> {
    const row = (
      await this.pool.query<{ anchor: unknown }>(`SELECT envelope->'nonRepudiation'->'anchor' AS anchor FROM envelopes WHERE evidence_id = $1`, [evidenceId])
    ).rows[0];
    return row?.anchor ?? null;
  }

  async fillAnchorArtifacts(chunk: AnchorFillChunk): Promise<AnchorFillResult> {
    return this.inTransaction(async (client) => {
      const ids = chunk.fills.map((f) => f.evidenceId);
      // Row locks on the whole chunk, in one statement and a stable order, as
      // updateAttestation() takes one: a concurrent attestation retry waits
      // rather than writing an envelope this chunk then overwrites.
      const rows = (
        await client.query<{ evidence_id: string; envelope: EvidenceEnvelope | string; chain_id: string }>(
          'SELECT evidence_id, envelope, chain_id FROM envelopes WHERE evidence_id = ANY($1) ORDER BY evidence_id FOR UPDATE',
          [ids],
        )
      ).rows;
      const byId = new Map(
        rows.map((r) => [r.evidence_id, { envelope: (typeof r.envelope === 'string' ? JSON.parse(r.envelope) : r.envelope) as EvidenceEnvelope, chainId: r.chain_id }]),
      );
      const logIds = [...new Set(chunk.fills.map((f) => f.logId).filter((id): id is number => id !== undefined))];
      const chainOfLog = new Map(
        logIds.length === 0
          ? []
          : (await client.query<{ log_id: string | number; chain_id: string | null }>('SELECT log_id, chain_id FROM logs WHERE log_id = ANY($1)', [logIds])).rows.map(
              (r) => [Number(r.log_id), r.chain_id] as const,
            ),
      );
      const result: AnchorFillResult = { filled: 0, alreadyAnchored: 0, missing: [], conflicts: [] };
      for (const fill of chunk.fills) {
        const row = byId.get(fill.evidenceId);
        if (!row) {
          result.missing.push(fill.evidenceId);
          continue;
        }
        const stored = row.envelope;
        const logChain = fill.logId === undefined ? null : (chainOfLog.get(fill.logId) ?? null);
        if (anchorFillConflict(stored, row.chainId, logChain, fill) !== null) {
          result.conflicts.push(fill.evidenceId);
          continue;
        }
        const next = filledEnvelope(stored, fill, chunk);
        if (!next) {
          result.alreadyAnchored += 1;
          continue;
        }
        await client.query('UPDATE envelopes SET envelope = $1 WHERE evidence_id = $2', [JSON.stringify(next), fill.evidenceId]);
        const head = await client.query<{ highest: string | number | null }>(
          'SELECT MAX(revision_no) AS highest FROM envelope_revisions WHERE evidence_id = $1',
          [fill.evidenceId],
        );
        const highest = head.rows[0]?.highest;
        await client.query(
          `INSERT INTO envelope_revisions (evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor)
           VALUES ($1, $2, $3, $4, $5, '${ANCHOR_FILL_CAUSE}', '${REVISION_ACTOR_ANCHOR}')`,
          [
            fill.evidenceId,
            nextRevisionNo(highest == null ? null : Number(highest)),
            next.integrity.canonicalDigest,
            next.integrity.chainLink ?? null,
            new Date().toISOString(),
          ],
        );
        result.filled += 1;
      }
      const progressed = await client.query(
        'UPDATE anchor_publications SET fill_progress = $1, updated_at = NOW() WHERE id = $2',
        [JSON.stringify(chunk.fillProgress), chunk.publicationId],
      );
      if ((progressed.rowCount ?? 0) !== 1) throw new Error(`anchor_publications: no publication ${chunk.publicationId}`);
      return result;
    });
  }
}

// ── Memory ───────────────────────────────────────────────────────────────

/** What `MemoryLogStore.planEvidenceLeaf` decided: a leaf to write, or nothing (write once). */
export type EvidenceLeafPlan =
  | { write: false }
  | { write: true; chainId: string; origin: string; leafIndex: number; leafDigest: string; sourceRef: string };

/**
 * The memory adapter's evidence logs. The adapter plans the leaf before it
 * writes the record, so a refusal leaves nothing written, and commits it
 * after, in the same synchronous section: the same outcome as the SQL
 * trigger's, on every rule.
 */
export class MemoryLogStore implements LogStore {
  private readonly identity: StoreIdentity;
  private readonly logs: LogRecord[] = [];
  private readonly evidenceLogs = new Map<string, LogRecord>();
  private readonly leaves = new Map<number, Map<number, LogLeaf>>();
  private readonly sourceRefs = new Map<number, Set<string>>();
  private readonly digests = new Map<number, Set<string>>();

  constructor(
    options: LogSchemaOptions,
    /** The adapter's `last_sequence` high-water mark for a chain, for coverage. */
    private readonly lastSequence: (chainId: string) => number,
  ) {
    const ns = options.logNamespace === undefined ? DEFAULT_LOG_NAMESPACE : assertLogNamespace(options.logNamespace);
    this.identity = { storeId: mintStoreId(), ns, createdAt: new Date().toISOString() };
  }

  /**
   * Decide the leaf for `envelope` stored on `chainId`, throwing the refusal
   * the SQL triggers raise, in their order: the chain id, the position and
   * the digest; an occupied position (write once, no leaf); a gap; a repeated
   * record id or digest. Everything that can throw, the origin of a new log
   * included, runs here, so a refusal leaves the store untouched. Writes
   * nothing.
   */
  planEvidenceLeaf(envelope: EvidenceEnvelope, chainId: string): EvidenceLeafPlan {
    const seq: unknown = envelope.payload?.sequenceNumber;
    const digest: unknown = envelope.integrity?.canonicalDigest;
    const chainRefusal = chainIdRefusal(chainId);
    if (chainRefusal !== null) throw new EvidenceLogRefusalError(chainRefusal, chainId, seq);
    if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 1) {
      throw new EvidenceLogRefusalError('invalid_sequence_number', chainId, seq);
    }
    if (typeof digest !== 'string' || !HEX64.test(digest)) {
      throw new EvidenceLogRefusalError('invalid_digest', chainId, seq);
    }
    const leafIndex = seq - 1;
    const sourceRef = envelope.payload.evidenceId;
    const log = this.evidenceLogs.get(chainId);
    if (log && this.leaves.get(log.logId)!.has(leafIndex)) return { write: false };
    if (leafIndex !== 0 && !(log && this.leaves.get(log.logId)!.has(leafIndex - 1))) {
      throw new EvidenceLogRefusalError('log_gap', chainId, seq);
    }
    if (log && (this.sourceRefs.get(log.logId)!.has(sourceRef) || this.digests.get(log.logId)!.has(digest))) {
      throw new EvidenceLogRefusalError('duplicate_leaf', chainId, seq);
    }
    const origin = log ? log.origin : evidenceLogOrigin(this.identity.ns, this.identity.storeId, chainId);
    return { write: true, chainId, origin, leafIndex, leafDigest: digest, sourceRef };
  }

  /** Write a planned leaf, creating the chain's log on its first. Never throws. */
  /** Whether `chainId`'s evidence log holds at least one leaf. */
  hasEvidenceLeaves(chainId: string): boolean {
    const log = this.evidenceLogs.get(chainId);
    return log !== undefined && (this.leaves.get(log.logId)?.size ?? 0) > 0;
  }

  commitEvidenceLeaf(plan: EvidenceLeafPlan): void {
    if (!plan.write) return;
    let log = this.evidenceLogs.get(plan.chainId);
    if (!log) {
      log = {
        logId: this.logs.length + 1,
        origin: plan.origin,
        kind: EVIDENCE_LOG_KIND,
        chainId: plan.chainId,
        createdAt: new Date().toISOString(),
      };
      this.logs.push(log);
      this.evidenceLogs.set(plan.chainId, log);
      this.leaves.set(log.logId, new Map());
      this.sourceRefs.set(log.logId, new Set());
      this.digests.set(log.logId, new Set());
    }
    this.leaves.get(log.logId)!.set(plan.leafIndex, {
      logId: log.logId,
      leafIndex: plan.leafIndex,
      leafDigest: plan.leafDigest,
      sourceRef: plan.sourceRef,
      source: 'capture',
      loggedAt: new Date().toISOString(),
    });
    this.sourceRefs.get(log.logId)!.add(plan.sourceRef);
    this.digests.get(log.logId)!.add(plan.leafDigest);
  }

  async getStoreIdentity(): Promise<StoreIdentity> {
    return { ...this.identity };
  }

  async listLogs(): Promise<LogRecord[]> {
    return this.logs.map((l) => ({ ...l }));
  }

  async getLog(logId: number): Promise<LogRecord | null> {
    const log = this.logs[logId - 1];
    return log ? { ...log } : null;
  }

  async getEvidenceLog(chainId: string): Promise<LogRecord | null> {
    const log = this.evidenceLogs.get(chainId);
    return log ? { ...log } : null;
  }

  async getLogSize(logId: number): Promise<LogSize> {
    const leaves = this.leaves.get(logId);
    if (!leaves || leaves.size === 0) return { size: 0, leafCount: 0 };
    return { size: Math.max(...leaves.keys()) + 1, leafCount: leaves.size };
  }

  async listLogLeaves(logId: number, fromIndex: number, toIndex: number): Promise<LogLeaf[]> {
    assertLeafRange(fromIndex, toIndex);
    const leaves = this.leaves.get(logId);
    if (!leaves) return [];
    return [...leaves.values()]
      .filter((l) => l.leafIndex >= fromIndex && l.leafIndex < toIndex)
      .sort((a, b) => a.leafIndex - b.leafIndex)
      .map((l) => ({ ...l }));
  }

  async getEvidenceLogPosition(evidenceId: string): Promise<LogPosition | null> {
    for (const log of this.evidenceLogs.values()) {
      if (!this.sourceRefs.get(log.logId)!.has(evidenceId)) continue;
      const leaf = [...this.leaves.get(log.logId)!.values()].find((l) => l.sourceRef === evidenceId)!;
      return {
        logId: log.logId,
        origin: log.origin,
        chainId: log.chainId!,
        leafIndex: leaf.leafIndex,
        leafDigest: leaf.leafDigest,
        source: leaf.source,
      };
    }
    return null;
  }

  async getEvidenceLogCoverage(): Promise<EvidenceLogCoverage[]> {
    return [...this.evidenceLogs.values()]
      .sort((a, b) => (a.chainId! < b.chainId! ? -1 : a.chainId! > b.chainId! ? 1 : 0))
      .map((log) => {
        const leaves = this.leaves.get(log.logId)!;
        const indices = [...leaves.keys()].sort((a, b) => a - b);
        const size = indices.length === 0 ? 0 : indices[indices.length - 1] + 1;
        const lastSequence = this.lastSequence(log.chainId!);
        const gaps: Array<{ from_index: number; to_index: number | null }> = [];
        indices.forEach((index, i) => {
          if (leaves.has(index + 1)) return;
          gaps.push({ from_index: index + 1, to_index: i + 1 < indices.length ? indices[i + 1] - 1 : null });
        });
        const all = [...leaves.values()];
        return {
          chainId: log.chainId!,
          logId: log.logId,
          origin: log.origin,
          size,
          leafCount: leaves.size,
          captured: all.filter((l) => l.source === 'capture').length,
          backfilled: all.filter((l) => l.source === 'backfill').length,
          lastSequence,
          missing: missingRanges(indices.length === 0 ? null : indices[0], gaps, Math.max(size, lastSequence)),
        };
      });
  }
}
