/**
 * The storage rules the anchor scheduler relies on, as cases any `LogStore`
 * and `AnchorStore` can be run against (tzun-anchor/1 §3, §6, §7; Tree §5.2).
 *
 * WHO RUNS IT
 *
 * The SDK's own SQLite and Postgres stores run it
 * (tests/ts/anchor-store-conformance.test.ts), which is what shows the kit
 * asks the right questions. A deployment that keeps its logs and anchoring
 * tables in its own schema, and implements the two interfaces over them,
 * runs it too: such a store restates the SDK's guards in its own SQL, and the
 * kit is what keeps the two sets of rules the same.
 *
 * HOW
 *
 * `anchorStoreConformanceCases(harness)` returns the cases. Each has a stable
 * name, and a `run()` that opens a new store with `harness.open()`, checks
 * one rule, and closes the store. A case whose hook the harness has declared
 * it lacks (`harness.without`) carries that reason as `skip`. The kit uses no
 * test framework: a case throws an `AssertionError` (node:assert) when the
 * store breaks its rule. Under jest:
 *
 *     for (const c of anchorStoreConformanceCases(harness)) {
 *       (c.skip ? it.skip : it)(c.name, () => c.run(), 60_000);
 *     }
 *
 * `runAnchorStoreConformance(harness)` runs every case and reports.
 *
 * WHAT IT CHECKS
 *
 * What the interfaces return, and whether a write is refused. A refused write
 * must leave the store as it was, which the case reads back. Error messages
 * are not matched, since a store words its own, with one exception: an epoch
 * its guard refuses throws `AnchorEpochFenceError`, which is what the
 * scheduler catches to defer the epoch instead of failing the pass.
 *
 * An attack through `raw()` counts as refused only once `raw()` has shown it
 * can write the store (an UPDATE of the lease that `getAnchorLease` then
 * reads) and the same statement has run on no row without error, so that a
 * refusal is the guard's and not a missing grant or column. A row refused for
 * the explicit id it is written at must then be accepted with the id left to
 * the store. Whether a guard reads the table through the inserting session's
 * names (a temporary table of the same name, a schema put ahead of
 * `pg_catalog`) is not something `raw()`, the owner with no temporary
 * objects, can show; that is the store's own test.
 *
 *   - leaves: dense, written once, distinct by digest and by source, one call
 *     one transaction, never updated or deleted; an evidence log holds its
 *     records' canonical digests at `sequenceNumber - 1` and takes no other
 *     leaf; a record's position and a log's coverage read those leaves;
 *   - checkpoints: a leaf at `treeSize - 1`, a body naming the log and the
 *     size, a digest that is the body's, a root line that is the root, a
 *     consistency proof exactly when there is a previous size, an anchor leaf
 *     that holds the digest; never updated, signatures appended only; the
 *     indexed reads;
 *   - logs: none is written at an explicit `log_id` below the last, where
 *     `listLogs` would read it ahead of the logs it follows;
 *   - publications: they start `prepared`; P is the anchor checkpoint's
 *     digest; one per kind and anchor size; the kind fixes the chain; none is
 *     written at an explicit id below the last; every state change is
 *     accepted exactly when `ANCHOR_PUBLICATION_TRANSITIONS` allows it
 *     within `ANCHOR_PUBLICATION_STATES_BY_KIND`; sender, nonce,
 *     token and genTime are written once; attempts are appended only; only a
 *     publication whose every broadcast was rejected is superseded; one
 *     unsuperseded publication per sender and nonce; the mined transaction is
 *     fixed once finalized; never deleted; the reads, `getLeafAnchorProgress`
 *     among them;
 *   - epochs: one transaction; the guard's three refusals, and its supersede;
 *   - the lease: taken when free, renewed by its holder, refused to another,
 *     taken over once expired, released by its holder;
 *   - wallets and nonce accounting: enrolled once, retired once, an accounted
 *     transaction held to its signed bytes (`assertWalletTx`), and a nonce
 *     held by a publication or by an accounted transaction, never both;
 *   - the fill: fill-only (an anchor that is null or '' is absent, any other
 *     value is kept), the envelope `filledEnvelope` gives, the progress
 *     written in the same transaction, missing records reported, a chunk for
 *     no publication refused whole.
 */
import { AssertionError, deepStrictEqual, ok, rejects, strictEqual } from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Transaction, Wallet } from 'ethers';
import { assembleEnvelope, type AnchorArtifact, type EvidenceEnvelope } from '@tzun/engine';
import { ANCHOR_SPEC } from '../attestation/anchor-verify';
import { anchorLogOrigin, checkOriginBinding, checkpointDigest, formatCheckpoint } from '../attestation/checkpoint';
import { MERKLE_SPEC, extendCompactRange } from '../attestation/merkle';
import {
  ANCHOR_LEASE_HOLDER_PREFIX,
  ANCHOR_PUBLICATION_STATES,
  ANCHOR_PUBLICATION_STATES_BY_KIND,
  AnchorEpochFenceError,
  filledEnvelope,
  isAllowedPublicationTransition,
  storeLogOrigin,
  type AnchorFillChunk,
  type AnchorPublication,
  type AnchorPublicationAttempt,
  type AnchorPublicationKind,
  type AnchorPublicationPatch,
  type AnchorPublicationState,
  type AnchorStore,
  type EpochWrite,
  type EvidenceLogCoverage,
  type LogPosition,
  type LogRecord,
  type LogStore,
  type NewAnchorWalletTx,
  type NewLogCheckpoint,
  type NewLogLeaf,
  type StoreIdentity,
} from '../storage/log-store';

// ── The harness ─────────────────────────────────────────────────────────

/** One store, opened for one case. */
export interface AnchorStoreConformanceStore {
  logs: LogStore;
  anchors: AnchorStore;
  /**
   * Run one statement on the store's database, outside the interfaces, with
   * `?` placeholders. The kit uses it for the writes a store must refuse to
   * any writer: an UPDATE or DELETE of a row that is insert-only or fixed.
   * Required unless `harness.without.raw` gives a reason.
   *
   * It must connect as the owner of the store's tables. A refusal for want of
   * a grant says nothing about the store's guards, so the kit first shows that
   * `raw()` can write (an UPDATE of `anchor_lease` that `getAnchorLease` must
   * then see), and runs each attack first against no row, which must succeed.
   */
  raw?(sql: string, params: unknown[]): Promise<unknown>;
  /**
   * The SQL expression a `raw()` INSERT writes for a row's insert time
   * (`created_at`, `logged_at`), for a store whose tables require the
   * statement's own time there: SQLite's anchoring tables refuse any other
   * value. Default: a fixed timestamp, passed as a parameter.
   */
  rawNow?: string;
  /**
   * A source log other than the anchor log and the evidence logs, that
   * `appendLogLeaves` writes to; every call returns the same log. Default:
   * `anchors.ensureStoreLog('custody')`.
   */
  sourceLog?(): Promise<LogRecord>;
  /**
   * Store records on a chain, in order, the way the store's capture path
   * writes them, evidence leaves included; reject when the store refuses one.
   * Required unless `harness.without.records` gives a reason.
   */
  storeRecords?(chainId: string, envelopes: EvidenceEnvelope[]): Promise<void>;
  /** A stored record as it is now, or null. Required with `storeRecords`. */
  readRecord?(evidenceId: string): Promise<EvidenceEnvelope | null>;
  /** A chain's evidence log, or null. Default: `logs.getEvidenceLog(chainId)`. */
  evidenceLog?(chainId: string): Promise<LogRecord | null>;
  /** A record's evidence-log position, or null. Default: `logs.getEvidenceLogPosition(evidenceId)`. */
  evidenceLogPosition?(evidenceId: string): Promise<LogPosition | null>;
  /** Every evidence log's coverage. Default: `logs.getEvidenceLogCoverage()`. */
  evidenceLogCoverage?(): Promise<EvidenceLogCoverage[]>;
  close(): Promise<void>;
}

export interface AnchorStoreConformanceHarness {
  /** A new, empty store with its identity minted. Called once for every case. */
  open(): Promise<AnchorStoreConformanceStore>;
  /**
   * What this harness's stores cannot do, each with the reason. The cases
   * that need it carry the reason as `skip`. `raw`, `storeRecords` and
   * `readRecord` must be on every store `open()` returns unless named here,
   * and `storeRecords` must take records that arrive with an anchor value
   * unless `presetAnchors` is; the other hooks have defaults.
   */
  without?: {
    /** No `raw()`: the attacks on the tables are skipped. */
    raw?: string;
    /** No `storeRecords()` / `readRecord()`: the evidence-log and fill cases are skipped. */
    records?: string;
    /**
     * `storeRecords()` refuses, or rewrites, a record whose
     * `nonRepudiation.anchor` is already set (to null, '' or false): the case
     * on where "absent" ends for the fill is skipped.
     */
    presetAnchors?: string;
  };
  /**
   * Whether the fill stores the status `filledEnvelope` gives: the chunk's
   * `statusOf`, then `fillStatus`. Default true. A store that rates a
   * record's status by a rule of its own sets false; the kit then compares
   * every field of a filled record but `attestationStatus`, and skips the
   * status case.
   */
  fillStatusFromChunk?: boolean;
}

export interface AnchorStoreConformanceCase {
  /** Stable: `<area>: <the rule>`. */
  readonly name: string;
  /** Why the case cannot run on this harness; the case is not run when set. */
  readonly skip?: string;
  /** Open a store, check the rule, close the store. Throws when the rule is broken. */
  run(): Promise<void>;
}

export interface AnchorStoreConformanceReport {
  passed: string[];
  failed: Array<{ name: string; error: unknown }>;
  skipped: Array<{ name: string; reason: string }>;
}

// ── Fixtures ────────────────────────────────────────────────────────────

const hex = (label: string): string => createHash('sha256').update(label, 'utf8').digest('hex');

/**
 * Deep equality of two values as data. Both sides are copied through JSON
 * first: a driver's native addon (better-sqlite3) builds its rows in the
 * process's main realm, and a test runner that loads the kit in a realm of
 * its own (jest) would otherwise see equal rows as unequal, because strict
 * deep equality compares prototypes.
 */
function same(actual: unknown, expected: unknown, message = 'the values differ'): void {
  const plain = (v: unknown): unknown => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
  deepStrictEqual(plain(actual), plain(expected), message);
}
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** The chain every EVM publication of the kit names, and its EIP-155 id. */
const CHAIN = 'eip155:11155111';
/** The created_at a row written through raw() carries: SQLite's columns have no default. */
const CREATED_AT = '2026-09-27T12:00:00.000Z';
const CHAIN_ID = 11155111n;
/** The sender of the publications that are not about nonce accounting. */
const SENDER = `0x${'1'.repeat(40)}`;
/** Two lease holders: a scheduler takes the lease as `tzun-anchor/2:<holder id>`. */
const HOLDER_A = `${ANCHOR_LEASE_HOLDER_PREFIX}holder-a`;
const HOLDER_B = `${ANCHOR_LEASE_HOLDER_PREFIX}holder-b`;
/** A raw row's insert-time cell: the harness's `rawNow` expression, or `CREATED_AT`. */
const NOW_CELL = Symbol('insert time');

/** A publisher key derived from a label: never funded, never a well-known test key. */
const signer = (label: string): Wallet => new Wallet(`0x${hex(`tzun anchor-store conformance: ${label}`)}`);

function attempt(n: number, broadcast: AnchorPublicationAttempt['broadcast'] = 'accepted'): AnchorPublicationAttempt {
  return {
    txHash: `0x${hex(`tx ${n}`)}`,
    rawTx: `0x02f8${hex(`raw ${n}`)}`,
    maxFeePerGas: '2000000000',
    maxPriorityFeePerGas: '1000000',
    sentAt: '2026-09-26T10:00:00.000Z',
    broadcast,
  };
}

/** A checkpoint of `log` at `treeSize`, with a made-up root: the tables check the body, not the tree. */
function checkpointOf(log: LogRecord, treeSize: number, extra: Partial<NewLogCheckpoint> = {}): NewLogCheckpoint {
  const root = hex(`root ${log.origin} ${treeSize}`);
  const body = formatCheckpoint(log.origin, treeSize, root);
  return {
    logId: log.logId,
    treeSize,
    root,
    body,
    bodyDigest: checkpointDigest(body),
    compactRange: [root],
    prevAnchoredSize: null,
    consistencyProof: null,
    anchorLeafIndex: null,
    epochId: null,
    ...extra,
  };
}

const leavesOf = (label: string, from: number, to: number): NewLogLeaf[] =>
  Array.from({ length: to - from }, (_, i) => ({ leafIndex: from + i, leafDigest: hex(`${label} ${from + i}`), sourceRef: `${label}-${from + i}` }));

/**
 * The columns each state requires, so that a move is refused only by the
 * transition rule. Each publication takes its own nonce (its anchor size), and
 * a move to `superseded` records every broadcast as rejected.
 */
function fieldsFor(state: AnchorPublicationState, current: AnchorPublication): AnchorPublicationPatch {
  const patch: AnchorPublicationPatch = { state };
  if (state === 'submitted' || state === 'included' || state === 'finalized') {
    if (current.fromAddress === null) patch.fromAddress = SENDER;
    if (current.nonce === null) patch.nonce = current.anchorSize;
    // Of unknown outcome, which may still become accepted or rejected.
    if (current.attempts.length === 0) patch.attempts = [attempt(current.anchorSize, 'unknown')];
  }
  if (state === 'superseded' && current.attempts.length > 0) {
    patch.attempts = current.attempts.map((a) => ({ ...a, broadcast: 'rejected' as const }));
  }
  if (state === 'included' || state === 'finalized') {
    if (current.minedTxHash === null) patch.minedTxHash = (patch.attempts ?? current.attempts)[0].txHash;
    if (current.blockNumber === null) patch.blockNumber = 100 + current.anchorSize;
    if (current.blockHash === null) patch.blockHash = `0x${hex(`block ${current.anchorSize}`)}`;
  }
  if (state === 'obtained') {
    if (current.token === null) patch.token = Buffer.from(`token ${current.anchorSize}`).toString('base64');
    if (current.genTime === null) patch.genTime = '2026-09-26T10:00:00Z';
  }
  return patch;
}

/** A path of allowed moves from `prepared` to each state. */
const PATH_TO: Record<AnchorPublicationState, AnchorPublicationState[]> = {
  prepared: [],
  submitted: ['submitted'],
  included: ['submitted', 'included'],
  finalized: ['submitted', 'included', 'finalized'],
  obtained: ['obtained'],
  superseded: ['submitted', 'superseded'],
};

async function signedTx(wallet: Wallet, nonce: number, chainId: bigint = CHAIN_ID): Promise<{ rawTx: string; txHash: string }> {
  const rawTx = await wallet.signTransaction({
    type: 2,
    chainId,
    nonce,
    to: `0x${'2'.repeat(40)}`,
    value: 0n,
    gasLimit: 21_000n,
    maxFeePerGas: 2_000_000_000n,
    maxPriorityFeePerGas: 1_000_000n,
    data: '0x',
  });
  return { rawTx, txHash: Transaction.from(rawTx).hash as string };
}

/** A version-4 UUID derived from `label`, so a case's records have the same ids on every run. */
function derivedEvidenceId(label: string): string {
  const h = createHash('sha256').update(label, 'utf8').digest('hex');
  const variant = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${variant}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/** Genuine records at sequence numbers 1 to n of one chain, each linked to the one before. */
function records(label: string, n: number): EvidenceEnvelope[] {
  const out: EvidenceEnvelope[] = [];
  for (let seq = 1; seq <= n; seq++) {
    out.push(
      assembleEnvelope(
        {
          aiSystemId: 'anchor-store-conformance',
          aiOutput: { label, seq },
          action: 'approved',
          reason: 'conformance',
          decider: { kind: 'human', id: 'acct:conformance', agent: null, credential: null, freshness: null },
        },
        {
          previousDigest: out[seq - 2]?.integrity.canonicalDigest,
          sequenceNumber: seq,
          capturedAt: '2026-09-26T10:00:00.000Z',
          evidenceId: derivedEvidenceId(`${label}-${seq}`),
        },
      ),
    );
  }
  return out;
}

/** Everything a case works with: the store, its domain, and the writes the cases share. */
class Ctx {
  readonly logs: LogStore;
  readonly anchors: AnchorStore;
  private nextAnchorSize = 1;
  private rawWrites = false;

  private constructor(
    readonly store: AnchorStoreConformanceStore,
    readonly identity: StoreIdentity,
    readonly domain: string,
    readonly anchorLog: LogRecord,
    private readonly harness: AnchorStoreConformanceHarness,
  ) {
    this.logs = store.logs;
    this.anchors = store.anchors;
  }

  static async open(harness: AnchorStoreConformanceHarness): Promise<Ctx> {
    const store = await harness.open();
    try {
      const identity = await store.logs.getStoreIdentity();
      const domain = `${identity.ns}/${identity.storeId}`;
      const anchorLog = await store.anchors.ensureStoreLog('anchors');
      return new Ctx(store, identity, domain, anchorLog, harness);
    } catch (err) {
      await store.close();
      throw err;
    }
  }

  get fillStatusFromChunk(): boolean {
    return this.harness.fillStatusFromChunk !== false;
  }

  /** Run one statement through the harness's `raw()`, once `rawCanWrite()` has shown it writes the store. */
  async raw(sql: string, params: unknown[]): Promise<unknown> {
    if (!this.rawWrites) {
      await this.rawCanWrite();
      this.rawWrites = true;
    }
    return this.rawHook()(sql, params);
  }

  private rawHook(): NonNullable<AnchorStoreConformanceStore['raw']> {
    if (!this.store.raw) throw new AssertionError({ message: 'the store has no raw(), and harness.without.raw gives no reason' });
    return this.store.raw.bind(this.store);
  }

  /**
   * Show that `raw()` runs on the store's tables and can write them: an UPDATE
   * of the lease, the one table any writer may change, must be what
   * `getAnchorLease` then reads. The lease is released afterwards.
   */
  async rawCanWrite(): Promise<void> {
    const raw = this.rawHook();
    const holder = `${ANCHOR_LEASE_HOLDER_PREFIX}conformance: the raw() check`;
    const rewritten = `${ANCHOR_LEASE_HOLDER_PREFIX}conformance: the raw() check, rewritten`;
    const cannot = "raw() cannot write the store's tables; it must run on the store's database, as the tables' owner";
    await this.anchors.acquireAnchorLease(this.domain, holder, 60_000);
    try {
      await raw('UPDATE anchor_lease SET holder = ? WHERE domain = ?', [rewritten, this.domain]);
    } catch (err) {
      throw new AssertionError({ message: `${cannot} (an UPDATE of anchor_lease through it failed: ${describe(err)})` });
    }
    const lease = await this.anchors.getAnchorLease(this.domain);
    if (lease?.holder !== rewritten) {
      throw new AssertionError({ message: `${cannot} (an UPDATE of anchor_lease through it did not reach the store: getAnchorLease reads holder ${JSON.stringify(lease?.holder ?? null)})` });
    }
    await this.anchors.releaseAnchorLease(this.domain, rewritten);
  }

  sourceLog(): Promise<LogRecord> {
    return this.store.sourceLog ? this.store.sourceLog() : this.anchors.ensureStoreLog('custody');
  }

  async storeRecords(chainId: string, envelopes: EvidenceEnvelope[]): Promise<void> {
    if (!this.store.storeRecords) throw new AssertionError({ message: 'the store has no storeRecords(), and harness.without.records gives no reason' });
    await this.store.storeRecords(chainId, envelopes);
  }

  async readRecord(evidenceId: string): Promise<EvidenceEnvelope | null> {
    if (!this.store.readRecord) throw new AssertionError({ message: 'the store has no readRecord(), and harness.without.records gives no reason' });
    return this.store.readRecord(evidenceId);
  }

  evidenceLog(chainId: string): Promise<LogRecord | null> {
    return this.store.evidenceLog ? this.store.evidenceLog(chainId) : this.logs.getEvidenceLog(chainId);
  }

  evidenceLogPosition(evidenceId: string): Promise<LogPosition | null> {
    return this.store.evidenceLogPosition ? this.store.evidenceLogPosition(evidenceId) : this.logs.getEvidenceLogPosition(evidenceId);
  }

  evidenceLogCoverage(): Promise<EvidenceLogCoverage[]> {
    return this.store.evidenceLogCoverage ? this.store.evidenceLogCoverage() : this.logs.getEvidenceLogCoverage();
  }

  async size(logId: number): Promise<{ size: number; leafCount: number }> {
    return this.logs.getLogSize(logId);
  }

  /** Grow the anchor log to `size` leaves and store its checkpoint there; returns the checkpoint's digest. */
  async anchorCheckpoint(size: number): Promise<string> {
    const { size: have } = await this.size(this.anchorLog.logId);
    if (have < size) await this.anchors.appendLogLeaves(this.anchorLog.logId, leavesOf('anchor leaf', have, size));
    const existing = await this.anchors.getLogCheckpoint(this.anchorLog.logId, size);
    if (existing) return existing.bodyDigest;
    const cp = checkpointOf(this.anchorLog, size);
    await this.anchors.insertLogCheckpoint(cp);
    return cp.bodyDigest;
  }

  /** A publication of `kind` walked to `state`, at the next anchor size (which is also its nonce). */
  async publication(kind: AnchorPublicationKind, state: AnchorPublicationState): Promise<AnchorPublication> {
    const anchorSize = Math.max(this.nextAnchorSize, (await this.size(this.anchorLog.logId)).size + 1);
    this.nextAnchorSize = anchorSize + 1;
    let p = await this.anchors.insertAnchorPublication({
      epochId: anchorSize,
      anchorSize,
      p: await this.anchorCheckpoint(anchorSize),
      kind,
      chain: kind === 'evm-calldata/1' ? CHAIN : null,
    });
    for (const step of PATH_TO[state]) p = await this.anchors.updateAnchorPublication(p.id, fieldsFor(step, p));
    strictEqual(p.state, state, `a new ${kind} publication walked to ${state}`);
    return p;
  }

  /** An epoch of `count` anchor leaves after the anchor log's current size, with one EVM publication. */
  async epoch(count = 1): Promise<EpochWrite> {
    const { size: from } = await this.size(this.anchorLog.logId);
    const to = from + count;
    const epochId = to;
    this.nextAnchorSize = Math.max(this.nextAnchorSize, to + 1);
    const cp = checkpointOf(this.anchorLog, to, { epochId });
    return {
      leaves: [{ logId: this.anchorLog.logId, leaves: leavesOf(`epoch ${epochId}`, from, to) }],
      checkpoints: [cp],
      publications: [{ epochId, anchorSize: to, p: cp.bodyDigest, kind: 'evm-calldata/1', chain: CHAIN }],
    };
  }

  /** What an epoch leaves behind, to show a refused one left nothing. */
  async footprint(): Promise<unknown> {
    return {
      anchorLeaves: await this.size(this.anchorLog.logId),
      anchorCheckpoints: (await this.anchors.listLogCheckpoints(this.anchorLog.logId)).map((c) => c.treeSize),
      publications: (await this.anchors.listAnchorPublications()).map((p) => [p.id, p.state]),
    };
  }

  close(): Promise<void> {
    return this.store.close();
  }
}

/** The store must refuse `work`. */
async function refuses(work: () => Promise<unknown>, what: string): Promise<void> {
  await rejects(work, `the store should refuse ${what}`);
}

/** The store must refuse `work` and be left as it was, by `read`. */
async function refusesAndKeeps(read: () => Promise<unknown>, work: () => Promise<unknown>, what: string): Promise<void> {
  const before = await read();
  await refuses(work, what);
  same(await read(), before, `a refused ${what} left the store changed`);
}

/** An UPDATE of one column (`set`) or, without it, a DELETE, of the row `where` names, through `raw()`. */
interface RawWrite {
  table: string;
  set?: [column: string, value: unknown];
  where: Array<[column: string, value: unknown]>;
}

/**
 * The store must refuse `write` to any writer, and be left as it was, by
 * `read`. The same statement is run first with a predicate no row meets,
 * which must succeed: that shows `raw()` can run it (the table and columns
 * exist, and the role has the grant), so the refusal that follows is the
 * guard's on the row.
 */
async function refusesRaw(ctx: Ctx, read: () => Promise<unknown>, write: RawWrite, what: string): Promise<void> {
  const predicate = write.where.map(([column]) => `${column} = ?`).join(' AND ');
  const statement = (where: string): string =>
    write.set ? `UPDATE ${write.table} SET ${write.set[0]} = ? WHERE ${where}` : `DELETE FROM ${write.table} WHERE ${where}`;
  const params = [...(write.set ? [write.set[1]] : []), ...write.where.map(([, value]) => value)];
  try {
    await ctx.raw(statement(`${predicate} AND 1 = 0`), params);
  } catch (err) {
    if (err instanceof AssertionError) throw err;
    throw new AssertionError({
      message:
        `raw() cannot run ${what} even on no row (${describe(err)}), so a refusal would not show the guard: ` +
        `it must run as the tables' owner, on tables with the columns the kit names`,
    });
  }
  await refusesAndKeeps(read, () => ctx.raw(statement(predicate), params), what);
}

/** A row to INSERT through `raw()`, column by column. */
type RawRow = Array<[column: string, value: unknown]>;

/**
 * The store must refuse `row` written at the explicit id `id`, and be left as
 * it was, by `read`. The same INSERT is run first as a SELECT no row meets,
 * which must succeed, as in `refusesRaw`; and after the refusal the same row
 * with no id, the id left to the store, must be accepted. Together they show
 * the refusal is the guard's on the id, not a missing grant or column or
 * another rule the row breaks.
 */
async function refusesRawInsertAt(
  ctx: Ctx,
  read: () => Promise<unknown>,
  table: string,
  id: [column: string, value: unknown],
  row: RawRow,
  what: string,
): Promise<void> {
  const insert = (cells: RawRow, from: 'values' | 'no row'): [string, unknown[]] => rawInsert(ctx, table, cells, from);
  const withId: RawRow = [id, ...row];
  try {
    await ctx.raw(...insert(withId, 'no row'));
  } catch (err) {
    if (err instanceof AssertionError) throw err;
    throw new AssertionError({
      message:
        `raw() cannot run ${what} even on no row (${describe(err)}), so a refusal would not show the guard: ` +
        `it must run as the tables' owner, on tables with the columns the kit names`,
    });
  }
  await refusesAndKeeps(read, () => ctx.raw(...insert(withId, 'values')), what);
  try {
    await ctx.raw(...insert(row, 'values'));
  } catch (err) {
    throw new AssertionError({
      message: `the same row with no ${id[0]} was refused too (${describe(err)}), so the refusal of ${what} does not show the guard on the id`,
    });
  }
}

/**
 * An INSERT of `cells` into `table` through `raw()`, as a VALUES row or as a
 * SELECT no row meets. A `NOW_CELL` value is the harness's `rawNow`
 * expression, or `CREATED_AT` as a parameter.
 */
function rawInsert(ctx: Ctx, table: string, cells: RawRow, from: 'values' | 'no row'): [string, unknown[]] {
  const columns = cells.map(([column]) => column).join(', ');
  const now = ctx.store.rawNow;
  const marks = cells.map(([, value]) => (value === NOW_CELL && now !== undefined ? now : '?')).join(', ');
  const params = cells.filter(([, value]) => !(value === NOW_CELL && now !== undefined)).map(([, value]) => (value === NOW_CELL ? CREATED_AT : value));
  const source = from === 'values' ? `VALUES (${marks})` : `SELECT ${marks} WHERE 1 = 0`;
  return [`INSERT INTO ${table} (${columns}) ${source}`, params];
}

/** An error's message; a driver's error may be from another realm, so not by `instanceof`. */
function describe(err: unknown): string {
  const message = (err as { message?: unknown } | null)?.message;
  return typeof message === 'string' ? message : String(err);
}

/** The guard must refuse the epoch with `reason`, and write nothing of it. */
async function fenced(ctx: Ctx, write: EpochWrite, reason: AnchorEpochFenceError['reason']): Promise<void> {
  const before = await ctx.footprint();
  let thrown: unknown;
  try {
    await ctx.anchors.persistEpoch(write);
  } catch (err) {
    thrown = err;
  }
  ok(thrown !== undefined, `the epoch guard should refuse (${reason}), and the epoch was written`);
  ok(
    thrown instanceof AnchorEpochFenceError,
    `a fenced epoch must throw AnchorEpochFenceError, which the scheduler defers on; got ${String((thrown as Error)?.message ?? thrown)}`,
  );
  strictEqual(thrown.reason, reason, `the fence reason`);
  same(await ctx.footprint(), before, `a fenced epoch (${reason}) left something behind`);
}

// ── The cases ───────────────────────────────────────────────────────────

type Needs = 'raw' | 'records' | 'presetAnchors';

interface CaseSpec {
  name: string;
  needs?: Needs[];
  statusFromChunk?: boolean;
  body(ctx: Ctx): Promise<void>;
}

const CASES: CaseSpec[] = [];
const define = (name: string, body: (ctx: Ctx) => Promise<void>, options: Omit<CaseSpec, 'name' | 'body'> = {}): void => {
  CASES.push({ name, body, ...options });
};

// Identity and logs

define('identity: the store names one domain, <ns>/<storeId>, and one anchor log in it', async (ctx) => {
  ok(/^[0-9a-f]{32}$/.test(ctx.identity.storeId), 'storeId is 32 lowercase hex');
  same(await ctx.logs.getStoreIdentity(), ctx.identity, 'the identity does not change');
  strictEqual(ctx.anchorLog.origin, anchorLogOrigin(ctx.domain), 'the anchor log is <domain>/anchors');
  strictEqual(ctx.anchorLog.kind, 'anchors');
  strictEqual(ctx.anchorLog.chainId, null, 'the anchor log names no chain');
  same(await ctx.anchors.ensureStoreLog('anchors'), ctx.anchorLog, 'the anchor log is created once');
  same(await ctx.logs.getLog(ctx.anchorLog.logId), ctx.anchorLog);
  ok((await ctx.logs.listLogs()).some((l) => l.logId === ctx.anchorLog.logId), 'listLogs lists the anchor log');
  const source = await ctx.sourceLog();
  ok(checkOriginBinding(ctx.anchorLog.origin, source.origin).ok, 'the source log is in the domain');
  strictEqual((await ctx.sourceLog()).logId, source.logId, 'the source log is the same log on every call');
});

define("raw: raw() writes the store's tables: an UPDATE of the lease through it is what getAnchorLease reads", async (ctx) => {
  await ctx.rawCanWrite();
  strictEqual(await ctx.anchors.getAnchorLease(ctx.domain), null, 'the check releases the lease it took');
}, { needs: ['raw'] });

define('logs: none is written at an explicit log_id below the last, where listLogs would read it ahead of the logs it follows', async (ctx) => {
  await ctx.sourceLog();
  const kind = 'conformance';
  const row: RawRow = [
    ['origin', storeLogOrigin(ctx.identity.ns, ctx.identity.storeId, kind)],
    ['kind', kind],
    ['created_at', CREATED_AT],
  ];
  await refusesRawInsertAt(ctx, () => ctx.logs.listLogs(), 'logs', ['log_id', 0], row, 'a log written at log_id 0');
  const logs = await ctx.logs.listLogs();
  strictEqual(logs[logs.length - 1]?.kind, kind, 'a log written with no log_id reads last');
}, { needs: ['raw'] });

// Leaves

define('leaves: a log is dense; a leaf past a gap is refused', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 2));
  same(await ctx.size(log.logId), { size: 2, leafCount: 2 });
  await refusesAndKeeps(() => ctx.size(log.logId), () => ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 3, 4)), 'a leaf past a gap');
  await refuses(() => ctx.anchors.appendLogLeaves(ctx.anchorLog.logId, leavesOf('a', 1, 2)), 'a first leaf that is not leaf 0');
});

define('leaves: a position is written once', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 2));
  const read = () => ctx.logs.listLogLeaves(log.logId, 0, 10);
  await refusesAndKeeps(read, () => ctx.anchors.appendLogLeaves(log.logId, [{ leafIndex: 1, leafDigest: hex('another'), sourceRef: 'another' }]), 'a second leaf at a position');
  await refusesAndKeeps(read, () => ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 1, 2)), 'the same leaf again');
});

define('leaves: the leaves of a log are distinct, by digest and by source', async (ctx) => {
  const log = await ctx.sourceLog();
  const [l0, l1] = leavesOf('s', 0, 2);
  await ctx.anchors.appendLogLeaves(log.logId, [l0, l1]);
  const read = () => ctx.logs.listLogLeaves(log.logId, 0, 10);
  await refusesAndKeeps(read, () => ctx.anchors.appendLogLeaves(log.logId, [{ leafIndex: 2, leafDigest: l0.leafDigest, sourceRef: 'fresh' }]), 'a digest the log already holds');
  await refusesAndKeeps(read, () => ctx.anchors.appendLogLeaves(log.logId, [{ leafIndex: 2, leafDigest: hex('fresh'), sourceRef: l1.sourceRef }]), 'a source the log already holds');
  // Distinct within a log only: another log may hold the same digest.
  await ctx.anchors.appendLogLeaves(ctx.anchorLog.logId, [{ leafIndex: 0, leafDigest: l0.leafDigest, sourceRef: l0.sourceRef }]);
});

define('leaves: one call is one transaction', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 1));
  await refusesAndKeeps(
    () => ctx.logs.listLogLeaves(log.logId, 0, 10),
    () => ctx.anchors.appendLogLeaves(log.logId, [...leavesOf('s', 1, 3), ...leavesOf('s', 4, 5)]),
    'a call whose last leaf is past a gap',
  );
});

define('leaves: reads return [from, to) in index order, as written', async (ctx) => {
  const log = await ctx.sourceLog();
  const written = leavesOf('s', 0, 5);
  await ctx.anchors.appendLogLeaves(log.logId, written.slice(0, 3));
  await ctx.anchors.appendLogLeaves(log.logId, written.slice(3));
  const read = await ctx.logs.listLogLeaves(log.logId, 1, 4);
  same(
    read.map((l) => [l.logId, l.leafIndex, l.leafDigest, l.sourceRef, l.source]),
    written.slice(1, 4).map((l) => [log.logId, l.leafIndex, l.leafDigest, l.sourceRef, 'scheduler']),
  );
  same(await ctx.logs.listLogLeaves(log.logId, 5, 9), []);
  same(await ctx.logs.listLogLeaves(log.logId, 2, 2), []);
  same(await ctx.size(log.logId), { size: 5, leafCount: 5 });
  same(await ctx.size(ctx.anchorLog.logId), { size: 0, leafCount: 0 });
});

define('leaves: a leaf is never updated or deleted', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 2));
  const read = () => ctx.logs.listLogLeaves(log.logId, 0, 10);
  const leaf: RawWrite['where'] = [['log_id', log.logId], ['leaf_index', 1]];
  await refusesRaw(ctx, read, { table: 'log_leaves', set: ['leaf_digest', hex('forged')], where: leaf }, 'an UPDATE of a leaf');
  await refusesRaw(ctx, read, { table: 'log_leaves', where: leaf }, 'a DELETE of a leaf');
}, { needs: ['raw'] });

define("evidence log: a chain's records are its leaves, each at sequenceNumber - 1", async (ctx) => {
  const chain = 'conformance-evidence';
  const recs = records('evidence', 3);
  await ctx.storeRecords(chain, recs);
  const log = await ctx.evidenceLog(chain);
  ok(log, 'the chain has an evidence log once it has a record');
  strictEqual(log.kind, 'evidence');
  ok(log.chainId === chain || log.chainId === null, 'an evidence log names its chain, or none in a view that spans tenants');
  ok(checkOriginBinding(ctx.anchorLog.origin, log.origin).ok, "the evidence log is in the store's domain");
  same(await ctx.size(log.logId), { size: 3, leafCount: 3 });
  same(
    (await ctx.logs.listLogLeaves(log.logId, 0, 3)).map((l) => [l.leafIndex, l.leafDigest, l.sourceRef, l.source]),
    recs.map((r, i) => [i, r.integrity.canonicalDigest, r.payload.evidenceId, 'capture']),
  );
}, { needs: ['records'] });

define('evidence log: it takes no leaf but its records’, and no record past a gap', async (ctx) => {
  const chain = 'conformance-evidence-gap';
  const recs = records('gap', 5);
  await ctx.storeRecords(chain, recs.slice(0, 3));
  const log = (await ctx.evidenceLog(chain))!;
  const read = () => ctx.logs.listLogLeaves(log.logId, 0, 10);
  await refusesAndKeeps(read, () => ctx.anchors.appendLogLeaves(log.logId, [{ leafIndex: 3, leafDigest: hex('forged'), sourceRef: 'forged' }]), 'a leaf appended to an evidence log');
  await refusesAndKeeps(read, () => ctx.storeRecords(chain, [recs[4]]), 'a record past a gap in its chain');
  strictEqual(await ctx.readRecord(recs[4].payload.evidenceId), null, 'the refused record is not stored');
}, { needs: ['records'] });

define("evidence log: a record's position is its leaf: the log, its origin, sequenceNumber - 1, the digest logged, and the chain", async (ctx) => {
  const chain = 'conformance-evidence-position';
  const recs = records('position', 3);
  await ctx.storeRecords(chain, recs);
  const log = (await ctx.evidenceLog(chain))!;
  for (const [i, r] of recs.entries()) {
    same(
      await ctx.evidenceLogPosition(r.payload.evidenceId),
      { logId: log.logId, origin: log.origin, chainId: chain, leafIndex: i, leafDigest: r.integrity.canonicalDigest, source: 'capture' },
      `the position of record ${i + 1}`,
    );
  }
  strictEqual(await ctx.evidenceLogPosition('position-no-such-record'), null, 'a record the store does not have has no position');
  const source = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(source.logId, [{ leafIndex: 0, leafDigest: hex('not a record'), sourceRef: 'position-not-a-record' }]);
  strictEqual(await ctx.evidenceLogPosition('position-not-a-record'), null, 'a leaf of a log that is not an evidence log is no record’s position');
}, { needs: ['records'] });

define("evidence log: its coverage counts a chain's captured leaves and its high-water mark, with nothing missing", async (ctx) => {
  const chain = 'conformance-evidence-coverage';
  const recs = records('coverage', 3);
  await ctx.storeRecords(chain, recs);
  const log = (await ctx.evidenceLog(chain))!;
  same(
    await ctx.evidenceLogCoverage(),
    [{ chainId: chain, logId: log.logId, origin: log.origin, size: 3, leafCount: 3, captured: 3, backfilled: 0, lastSequence: 3, missing: [] }],
    'the coverage of the one evidence log',
  );
}, { needs: ['records'] });

// Checkpoints

define('checkpoints: one is read back as written, and listed in size order', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 3));
  const two = checkpointOf(log, 2);
  const three = checkpointOf(log, 3, { prevAnchoredSize: 2, consistencyProof: [hex('proof')], epochId: 4, signatures: ['— witness.example Az3Dsig1'] });
  await ctx.anchors.insertLogCheckpoint(two);
  await ctx.anchors.insertLogCheckpoint(three);
  const read = await ctx.anchors.getLogCheckpoint(log.logId, 3);
  ok(read, 'the checkpoint is read back');
  const { createdAt, ...rest } = read;
  ok(typeof createdAt === 'string' && !Number.isNaN(Date.parse(createdAt)), 'createdAt is stamped');
  same(rest, { ...three, signatures: ['— witness.example Az3Dsig1'] });
  same((await ctx.anchors.listLogCheckpoints(log.logId)).map((c) => c.treeSize), [2, 3]);
  strictEqual((await ctx.anchors.getLastLogCheckpoint(log.logId))?.treeSize, 3);
  strictEqual(await ctx.anchors.getLogCheckpoint(log.logId, 1), null);
});

define('checkpoints: a checkpoint needs a leaf at treeSize - 1', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 2));
  await refusesAndKeeps(() => ctx.anchors.listLogCheckpoints(log.logId), () => ctx.anchors.insertLogCheckpoint(checkpointOf(log, 3)), 'a checkpoint past the last leaf');
});

define("checkpoints: the body names the log and the size, bodyDigest is the body's SHA-256, and its root line is the root", async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 3));
  const read = () => ctx.anchors.listLogCheckpoints(log.logId);
  const good = checkpointOf(log, 2);
  const withBody = (body: string): NewLogCheckpoint => ({ ...good, body, bodyDigest: checkpointDigest(body) });
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint(withBody(formatCheckpoint(log.origin, 3, good.root))), 'a body naming another size');
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint(withBody(formatCheckpoint(ctx.anchorLog.origin, 2, good.root))), 'a body naming another log');
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint(withBody(formatCheckpoint(log.origin, 2, hex('another root')))), 'a body whose root line is not the root');
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint({ ...good, bodyDigest: hex('not the body') }), "a digest that is not the body's");
  await ctx.anchors.insertLogCheckpoint(good);
});

define('checkpoints: a consistency proof is given exactly when a previous size is', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 3));
  const read = () => ctx.anchors.listLogCheckpoints(log.logId);
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint(checkpointOf(log, 2, { prevAnchoredSize: 1 })), 'a previous size without a proof');
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint(checkpointOf(log, 2, { consistencyProof: [hex('proof')] })), 'a proof without a previous size');
});

define("checkpoints: anchorLeafIndex names the anchor-log leaf that holds the body's digest, and the anchor log's own checkpoints name none", async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 2));
  const source = checkpointOf(log, 2);
  await ctx.anchors.appendLogLeaves(ctx.anchorLog.logId, leavesOf('a', 0, 2));
  const read = () => ctx.anchors.listLogCheckpoints(log.logId);
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint({ ...source, anchorLeafIndex: 2 }), 'an anchor leaf the anchor log does not have');
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint({ ...source, anchorLeafIndex: 1 }), 'an anchor leaf that holds another digest');
  await ctx.anchors.appendLogLeaves(ctx.anchorLog.logId, [{ leafIndex: 2, leafDigest: source.bodyDigest, sourceRef: `${log.origin}\n2` }]);
  await ctx.anchors.insertLogCheckpoint({ ...source, anchorLeafIndex: 2 });
  strictEqual((await ctx.anchors.getLogCheckpoint(log.logId, 2))?.anchorLeafIndex, 2);
  await refusesAndKeeps(
    () => ctx.anchors.listLogCheckpoints(ctx.anchorLog.logId),
    () => ctx.anchors.insertLogCheckpoint(checkpointOf(ctx.anchorLog, 3, { anchorLeafIndex: 2 })),
    'an anchor checkpoint that names an anchor leaf',
  );
});

define('checkpoints: the anchored reads find the right checkpoint by size and by anchor leaf', async (ctx) => {
  // A source log with checkpoints at 1, 3 and 5; the first two anchored at anchor leaves 3 and 4.
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 5));
  const one = checkpointOf(log, 1, { anchorLeafIndex: 3 });
  const three = checkpointOf(log, 3, { anchorLeafIndex: 4 });
  await ctx.anchors.appendLogLeaves(ctx.anchorLog.logId, [
    ...leavesOf('a', 0, 3),
    { leafIndex: 3, leafDigest: one.bodyDigest, sourceRef: `${log.origin}\n1` },
    { leafIndex: 4, leafDigest: three.bodyDigest, sourceRef: `${log.origin}\n3` },
  ]);
  for (const cp of [one, three, checkpointOf(log, 5)]) await ctx.anchors.insertLogCheckpoint(cp);
  const size = async (p: Promise<{ treeSize: number } | null>): Promise<number | null> => (await p)?.treeSize ?? null;
  strictEqual(await size(ctx.anchors.getLastLogCheckpoint(log.logId)), 5);
  strictEqual(await size(ctx.anchors.getLastAnchoredCheckpoint(log.logId)), 3);
  for (const [at, want] of [[0, null], [1, 1], [2, 1], [4, 3], [99, 5]] as const) {
    strictEqual(await size(ctx.anchors.getLogCheckpointAtOrBelow(log.logId, at)), want, `the checkpoint at or below ${at}`);
  }
  for (const [below, want] of [[3, null], [4, 1], [5, 3], [99, 3]] as const) {
    strictEqual(await size(ctx.anchors.getLastAnchoredCheckpointBelow(log.logId, below)), want, `the anchored checkpoint below anchor size ${below}`);
  }
  same((await ctx.anchors.listCheckpointsByAnchorLeaf(0, 10)).map((c) => [c.logId, c.treeSize, c.anchorLeafIndex]), [[log.logId, 1, 3], [log.logId, 3, 4]]);
  same((await ctx.anchors.listCheckpointsByAnchorLeaf(4, 5)).map((c) => c.treeSize), [3]);
  strictEqual(await ctx.anchors.getLastAnchoredCheckpoint(ctx.anchorLog.logId), null);
});

define('checkpoints: a checkpoint is inserted once and never changed; signatures are appended only', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 2));
  const cp = checkpointOf(log, 2);
  await ctx.anchors.insertLogCheckpoint(cp);
  const read = () => ctx.anchors.getLogCheckpoint(log.logId, 2);
  await refusesAndKeeps(read, () => ctx.anchors.insertLogCheckpoint(cp), 'a second checkpoint at a size');
  await ctx.anchors.appendCheckpointSignatures(log.logId, 2, ['— tzun.ai/log Az3Dsig1']);
  await ctx.anchors.appendCheckpointSignatures(log.logId, 2, ['— witness.example Bq9sig2']);
  same((await read())?.signatures, ['— tzun.ai/log Az3Dsig1', '— witness.example Bq9sig2']);
});

define('checkpoints: a checkpoint is never updated or deleted, and its signatures never rewritten', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 2));
  await ctx.anchors.insertLogCheckpoint(checkpointOf(log, 2));
  await ctx.anchors.appendCheckpointSignatures(log.logId, 2, ['— tzun.ai/log Az3Dsig1']);
  const read = () => ctx.anchors.getLogCheckpoint(log.logId, 2);
  const checkpoint: RawWrite['where'] = [['log_id', log.logId], ['tree_size', 2]];
  await refusesRaw(ctx, read, { table: 'log_checkpoints', set: ['root', hex('forged')], where: checkpoint }, 'an UPDATE of a checkpoint');
  await refusesRaw(ctx, read, { table: 'log_checkpoints', set: ['signatures', '["forged"]'], where: checkpoint }, 'a rewrite of its signatures');
  await refusesRaw(ctx, read, { table: 'log_checkpoints', set: ['signatures', '[]'], where: checkpoint }, 'a removal of its signatures');
  await refusesRaw(ctx, read, { table: 'log_checkpoints', where: checkpoint }, 'a DELETE of a checkpoint');
}, { needs: ['raw'] });

// Publications

define('publications: one starts prepared; its kind fixes its chain; one per kind and anchor size', async (ctx) => {
  const evm = await ctx.publication('evm-calldata/1', 'prepared');
  ok(evm.state === 'prepared' && evm.chain === CHAIN && evm.nonce === null && evm.fromAddress === null, 'a new EVM publication is prepared, with nothing sent');
  same(evm.attempts, []);
  strictEqual(evm.forced, false);
  const tsa = await ctx.publication('rfc3161/1', 'prepared');
  strictEqual(tsa.chain, null);
  const p = await ctx.anchorCheckpoint(9);
  const read = () => ctx.anchors.listAnchorPublications();
  await refusesAndKeeps(read, () => ctx.anchors.insertAnchorPublication({ epochId: 9, anchorSize: 9, p, kind: 'evm-calldata/1' }), 'an EVM publication with no chain');
  await refusesAndKeeps(read, () => ctx.anchors.insertAnchorPublication({ epochId: 9, anchorSize: 9, p, kind: 'rfc3161/1', chain: CHAIN }), 'an RFC 3161 publication with a chain');
  await refusesAndKeeps(read, () => ctx.anchors.insertAnchorPublication({ epochId: 1, anchorSize: evm.anchorSize, p: evm.p, kind: 'evm-calldata/1', chain: CHAIN }), 'a second EVM publication at an anchor size');
  const forced = await ctx.anchors.insertAnchorPublication({ epochId: 9, anchorSize: 9, p, kind: 'evm-calldata/1', chain: CHAIN, forced: true });
  strictEqual(forced.forced, true);
  same(await ctx.anchors.getAnchorPublication(forced.id), forced);
});

define("publications: P is the digest of the anchor log's stored checkpoint at the anchor size", async (ctx) => {
  const p3 = await ctx.anchorCheckpoint(3);
  await ctx.anchorCheckpoint(4);
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 3));
  const other = checkpointOf(log, 3);
  await ctx.anchors.insertLogCheckpoint(other);
  const read = () => ctx.anchors.listAnchorPublications();
  await refusesAndKeeps(read, () => ctx.anchors.insertAnchorPublication({ epochId: 1, anchorSize: 3, p: hex('not a checkpoint'), kind: 'rfc3161/1' }), 'a P that is no checkpoint');
  await refusesAndKeeps(read, () => ctx.anchors.insertAnchorPublication({ epochId: 1, anchorSize: 4, p: p3, kind: 'rfc3161/1' }), 'the P of another anchor size');
  await refusesAndKeeps(read, () => ctx.anchors.insertAnchorPublication({ epochId: 1, anchorSize: 2, p: p3, kind: 'rfc3161/1' }), 'an anchor size with no checkpoint');
  await refusesAndKeeps(read, () => ctx.anchors.insertAnchorPublication({ epochId: 1, anchorSize: 3, p: other.bodyDigest, kind: 'rfc3161/1' }), "another log's checkpoint at that size");
  strictEqual((await ctx.anchors.insertAnchorPublication({ epochId: 1, anchorSize: 3, p: p3, kind: 'rfc3161/1' })).p, p3);
});

for (const [kind, states] of Object.entries(ANCHOR_PUBLICATION_STATES_BY_KIND) as Array<[AnchorPublicationKind, readonly AnchorPublicationState[]]>) {
  define(`publications: ${kind}: every state change is accepted exactly when ANCHOR_PUBLICATION_TRANSITIONS allows it within the kind's states`, async (ctx) => {
    const wrong: string[] = [];
    for (const from of states) {
      for (const to of ANCHOR_PUBLICATION_STATES) {
        if (from === to) continue;
        const p = await ctx.publication(kind, from);
        const allowed = states.includes(to) && isAllowedPublicationTransition(from, to);
        const accepted = await ctx.anchors.updateAnchorPublication(p.id, fieldsFor(to, p)).then(
          () => true,
          () => false,
        );
        const now = (await ctx.anchors.getAnchorPublication(p.id))!.state;
        if (accepted !== allowed || now !== (allowed ? to : from)) {
          wrong.push(`${from} -> ${to}: ${accepted ? 'accepted' : 'refused'} (now ${now}), should be ${allowed ? 'accepted' : 'refused'}`);
        }
      }
    }
    same(wrong, [], `${kind}: the state changes the store gets wrong`);
  });
}

define('publications: sender, nonce, token and genTime are written once; attempts are appended only', async (ctx) => {
  const p = await ctx.publication('evm-calldata/1', 'submitted');
  const read = () => ctx.anchors.getAnchorPublication(p.id);
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { nonce: p.nonce! + 100 }), 'a second nonce');
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { fromAddress: `0x${'2'.repeat(40)}` }), 'a second sender');
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { attempts: [] }), 'a removed attempt');
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { attempts: [{ ...p.attempts[0], rawTx: '0x02f8ff' }] }), "a changed attempt's rawTx");
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { attempts: [{ ...p.attempts[0], txHash: `0x${hex('other')}` }] }), "a changed attempt's txHash");
  // A stored attempt's broadcast outcome may be learned later, and an attempt appended.
  const learned = await ctx.anchors.updateAnchorPublication(p.id, { attempts: [{ ...p.attempts[0], broadcast: 'accepted' }, attempt(900)] });
  same(learned.attempts.map((a) => [a.txHash, a.broadcast]), [[p.attempts[0].txHash, 'accepted'], [attempt(900).txHash, 'accepted']]);
  const tsa = await ctx.publication('rfc3161/1', 'obtained');
  await refusesAndKeeps(() => ctx.anchors.getAnchorPublication(tsa.id), () => ctx.anchors.updateAnchorPublication(tsa.id, { token: Buffer.from('other').toString('base64') }), 'a second token');
  await refusesAndKeeps(() => ctx.anchors.getAnchorPublication(tsa.id), () => ctx.anchors.updateAnchorPublication(tsa.id, { genTime: '2026-09-27T10:00:00Z' }), 'a second genTime');
});

define("publications: an attempt's broadcast is accepted, rejected or unknown", async (ctx) => {
  const p = await ctx.publication('evm-calldata/1', 'submitted');
  const read = () => ctx.anchors.getAnchorPublication(p.id);
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { attempts: [p.attempts[0], { ...attempt(901), broadcast: 'lost' as 'unknown' }] }), 'a broadcast outcome outside the three');
  const { broadcast: _dropped, ...withoutOutcome } = attempt(902);
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { attempts: [p.attempts[0], withoutOutcome as AnchorPublicationAttempt] }), 'an attempt with no broadcast outcome');
});

define('publications: only a publication with an attempt, every one rejected, is superseded', async (ctx) => {
  const accepted = await ctx.publication('evm-calldata/1', 'submitted');
  await ctx.anchors.updateAnchorPublication(accepted.id, { attempts: [{ ...accepted.attempts[0], broadcast: 'accepted' }] });
  await refusesAndKeeps(
    () => ctx.anchors.getAnchorPublication(accepted.id),
    () => ctx.anchors.updateAnchorPublication(accepted.id, { state: 'superseded' }),
    'superseding an accepted broadcast',
  );
  const p = await ctx.publication('evm-calldata/1', 'submitted');
  const read = () => ctx.anchors.getAnchorPublication(p.id);
  const supersede = () => ctx.anchors.updateAnchorPublication(p.id, { state: 'superseded' });
  strictEqual(p.attempts[0].broadcast, 'unknown');
  await refusesAndKeeps(read, supersede, 'superseding a broadcast of unknown outcome');
  await ctx.anchors.updateAnchorPublication(p.id, { attempts: [{ ...p.attempts[0], broadcast: 'rejected' }, attempt(903, 'unknown')] });
  await refusesAndKeeps(read, supersede, 'superseding one rejected and one unknown broadcast');
  await ctx.anchors.updateAnchorPublication(p.id, { attempts: [{ ...p.attempts[0], broadcast: 'rejected' }, { ...attempt(903), broadcast: 'rejected' }] });
  strictEqual((await supersede()).state, 'superseded');
  const unsent = await ctx.publication('evm-calldata/1', 'prepared');
  await refusesAndKeeps(
    () => ctx.anchors.getAnchorPublication(unsent.id),
    () => ctx.anchors.updateAnchorPublication(unsent.id, { state: 'superseded' }),
    'superseding a publication never sent (it has no attempt)',
  );
});

define("publications: an accepted broadcast is final; an outcome moves only from unknown, or from rejected to accepted", async (ctx) => {
  const p = await ctx.publication('evm-calldata/1', 'submitted');
  const read = () => ctx.anchors.getAnchorPublication(p.id);
  const at = (broadcast: AnchorPublicationAttempt['broadcast']) => ctx.anchors.updateAnchorPublication(p.id, { attempts: [{ ...p.attempts[0], broadcast }] });
  await at('rejected');
  await at('accepted');
  await refusesAndKeeps(read, () => at('rejected'), 'an accepted broadcast called rejected');
  await refusesAndKeeps(read, () => at('unknown'), 'an accepted broadcast called unknown');
  const q = await ctx.publication('evm-calldata/1', 'submitted');
  await ctx.anchors.updateAnchorPublication(q.id, { attempts: [{ ...q.attempts[0], broadcast: 'rejected' }] });
  await refusesAndKeeps(
    () => ctx.anchors.getAnchorPublication(q.id),
    () => ctx.anchors.updateAnchorPublication(q.id, { attempts: [{ ...q.attempts[0], broadcast: 'unknown' }] }),
    'a rejected broadcast called unknown',
  );
});

define('publications: a sender and nonce belong to one publication at a time until it is superseded; the sender is 0x and 40 lowercase hex', async (ctx) => {
  const first = await ctx.publication('evm-calldata/1', 'prepared');
  const second = await ctx.publication('evm-calldata/1', 'prepared');
  await ctx.anchors.updateAnchorPublication(first.id, { state: 'submitted', fromAddress: SENDER, nonce: 3, attempts: [attempt(910, 'rejected')] });
  const take = () => ctx.anchors.updateAnchorPublication(second.id, { state: 'submitted', fromAddress: SENDER, nonce: 3, attempts: [attempt(911)] });
  await refusesAndKeeps(() => ctx.anchors.getAnchorPublication(second.id), take, 'a nonce another publication holds');
  await ctx.anchors.updateAnchorPublication(first.id, { state: 'superseded' });
  const took = await take();
  ok(took.state === 'submitted' && took.nonce === 3, 'the nonce of a superseded publication is free');
  const third = await ctx.publication('evm-calldata/1', 'prepared');
  const read = () => ctx.anchors.getAnchorPublication(third.id);
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(third.id, { fromAddress: `0x${'A'.repeat(40)}` }), 'an uppercase sender');
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(third.id, { fromAddress: 'a'.repeat(40) }), 'a sender without 0x');
});

define('publications: once finalized, the mined transaction and its proof material are fixed; a null may still be filled, and progress still moves', async (ctx) => {
  let p = await ctx.publication('evm-calldata/1', 'finalized');
  const read = () => ctx.anchors.getAnchorPublication(p.id);
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { blockHash: `0x${hex('reorged')}` }), 'a new block hash after finality');
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { minedTxHash: `0x${hex('another tx')}` }), 'a new mined transaction after finality');
  p = await ctx.anchors.updateAnchorPublication(p.id, { blockHeader: '0xf90211', txIndex: 0, txTrieProof: ['0xf851'], gasUsed: '22280', effectiveGasPrice: '1100000000' });
  same([p.blockHeader, p.txIndex, p.txTrieProof, p.gasUsed, p.effectiveGasPrice], ['0xf90211', 0, ['0xf851'], '22280', '1100000000']);
  await refusesAndKeeps(read, () => ctx.anchors.updateAnchorPublication(p.id, { blockHeader: '0xf90212' }), 'a new block header after finality');
  p = await ctx.anchors.updateAnchorPublication(p.id, { fillProgress: { through: 500 }, error: 'a note' });
  same([p.fillProgress, p.error], [{ through: 500 }, 'a note']);
});

define('publications: a reorg returns an included publication to submitted, and it walks forward again', async (ctx) => {
  let p = await ctx.publication('evm-calldata/1', 'included');
  p = await ctx.anchors.updateAnchorPublication(p.id, { state: 'submitted', attempts: [...p.attempts, attempt(920)] });
  strictEqual(p.state, 'submitted');
  p = await ctx.anchors.updateAnchorPublication(p.id, { state: 'included', minedTxHash: attempt(920).txHash, blockNumber: 201, blockHash: `0x${hex('block 201')}` });
  p = await ctx.anchors.updateAnchorPublication(p.id, { state: 'finalized' });
  same([p.state, p.minedTxHash, p.blockNumber], ['finalized', attempt(920).txHash, 201]);
});

define('publications: the identity columns are fixed, and a publication is never deleted', async (ctx) => {
  const p = await ctx.publication('evm-calldata/1', 'submitted');
  const read = () => ctx.anchors.getAnchorPublication(p.id);
  const row: RawWrite['where'] = [['id', p.id]];
  await refusesRaw(ctx, read, { table: 'anchor_publications', set: ['p', hex('another P')], where: row }, 'a rewrite of P');
  await refusesRaw(ctx, read, { table: 'anchor_publications', set: ['anchor_size', p.anchorSize + 50], where: row }, 'a rewrite of the anchor size');
  await refusesRaw(ctx, read, { table: 'anchor_publications', set: ['epoch_id', p.epochId + 50], where: row }, 'a rewrite of the epoch');
  await refusesRaw(ctx, read, { table: 'anchor_publications', set: ['state', 'prepared'], where: row }, 'a state moved back by any writer');
  await refusesRaw(ctx, read, { table: 'anchor_publications', where: row }, 'a DELETE of a publication');
}, { needs: ['raw'] });

define('publications: none is written at an explicit id below the last, where the reads in id order would take it first', async (ctx) => {
  await ctx.publication('evm-calldata/1', 'prepared');
  await ctx.publication('rfc3161/1', 'prepared');
  const anchorSize = (await ctx.size(ctx.anchorLog.logId)).size + 1;
  const row: RawRow = [
    ['epoch_id', anchorSize],
    ['anchor_size', anchorSize],
    ['p', await ctx.anchorCheckpoint(anchorSize)],
    ['kind', 'rfc3161/1'],
    ['state', 'prepared'],
    ['created_at', NOW_CELL],
    ['updated_at', NOW_CELL],
  ];
  const read = () => ctx.anchors.listAnchorPublications();
  await refusesRawInsertAt(ctx, read, 'anchor_publications', ['id', 0], row, 'a publication written at id 0');
  const publications = await read();
  strictEqual(publications[publications.length - 1]?.anchorSize, anchorSize, 'a publication written with no id reads last');
}, { needs: ['raw'] });

define('publications: the reads find them by id, by kind and anchor size, by state, and the last final anchor size', async (ctx) => {
  strictEqual(await ctx.anchors.getLastFinalAnchorSize('evm-calldata/1'), null);
  strictEqual(await ctx.anchors.getLastFinalAnchorSize('rfc3161/1'), null);
  const made = [
    await ctx.publication('evm-calldata/1', 'finalized'),
    await ctx.publication('evm-calldata/1', 'finalized'),
    await ctx.publication('rfc3161/1', 'obtained'),
    await ctx.publication('evm-calldata/1', 'included'),
    await ctx.publication('evm-calldata/1', 'superseded'),
    await ctx.publication('rfc3161/1', 'prepared'),
  ];
  strictEqual(await ctx.anchors.getLastFinalAnchorSize('evm-calldata/1'), made[1].anchorSize);
  strictEqual(await ctx.anchors.getLastFinalAnchorSize('rfc3161/1'), made[2].anchorSize);
  same(await ctx.anchors.getAnchorPublicationAt('evm-calldata/1', made[3].anchorSize), made[3]);
  strictEqual(await ctx.anchors.getAnchorPublicationAt('rfc3161/1', made[3].anchorSize), null);
  strictEqual(await ctx.anchors.getAnchorPublication(made[5].id + 1000), null);
  same((await ctx.anchors.listAnchorPublications()).map((p) => p.id), made.map((p) => p.id), 'listed in id order');
  same((await ctx.anchors.listAnchorPublications({ kind: 'rfc3161/1' })).map((p) => p.id), [made[2].id, made[5].id]);
  same((await ctx.anchors.listAnchorPublications({ kind: 'evm-calldata/1', states: ['included', 'superseded'] })).map((p) => p.id), [made[3].id, made[4].id]);
  same(await ctx.anchors.listAnchorPublications({ states: [] }), []);
});

define("publications: getLeafAnchorProgress names the first anchored checkpoint past a leaf and, per kind, the covering publication that got furthest", async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 5));
  const atTwo = checkpointOf(log, 2, { anchorLeafIndex: 0 });
  const atFive = checkpointOf(log, 5, { anchorLeafIndex: 1 });
  await ctx.anchors.appendLogLeaves(ctx.anchorLog.logId, [
    { leafIndex: 0, leafDigest: atTwo.bodyDigest, sourceRef: `${log.origin}\n2` },
    { leafIndex: 1, leafDigest: atFive.bodyDigest, sourceRef: `${log.origin}\n5` },
  ]);
  await ctx.anchors.insertLogCheckpoint(atTwo);
  await ctx.anchors.insertLogCheckpoint(atFive);
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 5, 6));

  type Seen = Array<[AnchorPublicationKind, number, AnchorPublicationState]>;
  const progress = async (leaf: number): Promise<{ anchorLeafIndex: number | null; seen: Seen }> => {
    const got = await ctx.anchors.getLeafAnchorProgress(log.logId, leaf);
    ok(got, 'the store has an anchor log');
    const seen: Seen = got.publications.map((p) => [p.kind, p.anchorSize, p.state]);
    return { anchorLeafIndex: got.anchorLeafIndex, seen: seen.sort((a, b) => a[0].localeCompare(b[0])) };
  };
  same(await progress(0), { anchorLeafIndex: 0, seen: [] }, 'leaf 0: its epoch, no publication yet');
  same(await progress(3), { anchorLeafIndex: 1, seen: [] }, 'leaf 3: the checkpoint at 5');
  same(await progress(5), { anchorLeafIndex: null, seen: [] }, 'leaf 5: no epoch yet');

  // Publications at anchor size 1 (covering anchor leaf 0) and 2 (covering both).
  const at = async (size: number, kind: AnchorPublicationKind): Promise<AnchorPublication> => {
    if (!(await ctx.anchors.getLogCheckpoint(ctx.anchorLog.logId, size))) await ctx.anchors.insertLogCheckpoint(checkpointOf(ctx.anchorLog, size));
    const cp = (await ctx.anchors.getLogCheckpoint(ctx.anchorLog.logId, size))!;
    return ctx.anchors.insertAnchorPublication({ epochId: size, anchorSize: size, p: cp.bodyDigest, kind, chain: kind === 'evm-calldata/1' ? CHAIN : null });
  };
  let one = await at(1, 'evm-calldata/1');
  same((await progress(0)).seen, [['evm-calldata/1', 1, 'prepared']]);
  same((await progress(3)).seen, [], 'anchor size 1 does not cover anchor leaf 1');
  let two = await at(2, 'evm-calldata/1');
  for (const step of PATH_TO.included) two = await ctx.anchors.updateAnchorPublication(two.id, fieldsFor(step, two));
  same((await progress(0)).seen, [['evm-calldata/1', 2, 'included']], 'none final: the one furthest along');
  for (const step of PATH_TO.submitted) one = await ctx.anchors.updateAnchorPublication(one.id, fieldsFor(step, one));
  same((await progress(0)).seen, [['evm-calldata/1', 2, 'included']], 'included is further along than submitted');
  for (const step of ['included', 'finalized'] as const) one = await ctx.anchors.updateAnchorPublication(one.id, fieldsFor(step, one));
  same((await progress(0)).seen, [['evm-calldata/1', 1, 'finalized']], 'the earliest final one');
  same((await progress(3)).seen, [['evm-calldata/1', 2, 'included']]);
  const tsa = await at(2, 'rfc3161/1');
  await ctx.anchors.updateAnchorPublication(tsa.id, fieldsFor('obtained', tsa));
  same((await progress(3)).seen, [['evm-calldata/1', 2, 'included'], ['rfc3161/1', 2, 'obtained']], 'one per kind');
  const got = await ctx.anchors.getLeafAnchorProgress(log.logId, 0);
  const evm = got!.publications.find((p) => p.kind === 'evm-calldata/1')!;
  same(
    [evm.id, evm.p, evm.chain, evm.transactionId, evm.blockNumber, evm.fillProgress],
    [one.id, one.p, CHAIN, one.minedTxHash, one.blockNumber, null],
  );
  const live = (await ctx.anchors.getLeafAnchorProgress(log.logId, 3))!.publications.find((p) => p.kind === 'evm-calldata/1')!;
  strictEqual(live.transactionId, two.minedTxHash);
});

define('publications: a superseded publication covers nothing', async (ctx) => {
  const log = await ctx.sourceLog();
  await ctx.anchors.appendLogLeaves(log.logId, leavesOf('s', 0, 1));
  const cp = checkpointOf(log, 1, { anchorLeafIndex: 0 });
  await ctx.anchors.appendLogLeaves(ctx.anchorLog.logId, [{ leafIndex: 0, leafDigest: cp.bodyDigest, sourceRef: `${log.origin}\n1` }]);
  await ctx.anchors.insertLogCheckpoint(cp);
  const anchorCp = checkpointOf(ctx.anchorLog, 1);
  await ctx.anchors.insertLogCheckpoint(anchorCp);
  const p = await ctx.anchors.insertAnchorPublication({ epochId: 1, anchorSize: 1, p: anchorCp.bodyDigest, kind: 'evm-calldata/1', chain: CHAIN });
  await ctx.anchors.updateAnchorPublication(p.id, { state: 'submitted', fromAddress: SENDER, nonce: 1, attempts: [attempt(1, 'rejected')] });
  await ctx.anchors.updateAnchorPublication(p.id, { state: 'superseded' });
  same(await ctx.anchors.getLeafAnchorProgress(log.logId, 0), { anchorLeafIndex: 0, publications: [] });
});

// Epochs

define('epochs: persistEpoch writes leaves, checkpoints and publications in one transaction', async (ctx) => {
  const write = await ctx.epoch(2);
  const cp = write.checkpoints[0];
  const created = await ctx.anchors.persistEpoch({
    ...write,
    publications: [...write.publications, { epochId: cp.epochId!, anchorSize: cp.treeSize, p: cp.bodyDigest, kind: 'rfc3161/1' }],
  });
  same(created.map((c) => [c.kind, c.state, c.anchorSize, c.p]), [['evm-calldata/1', 'prepared', 2, cp.bodyDigest], ['rfc3161/1', 'prepared', 2, cp.bodyDigest]]);
  same(await ctx.size(ctx.anchorLog.logId), { size: 2, leafCount: 2 });
  const next = await ctx.epoch(1);
  // A refusal anywhere in the epoch (here its publication's P) leaves nothing of it behind.
  await refusesAndKeeps(() => ctx.footprint(), () => ctx.anchors.persistEpoch({ ...next, publications: [{ ...next.publications[0], p: hex('not the checkpoint') }] }), 'an epoch whose publication has the wrong P');
  await refusesAndKeeps(() => ctx.footprint(), () => ctx.anchors.persistEpoch({ ...next, checkpoints: [{ ...next.checkpoints[0], bodyDigest: hex('no') }] }), 'an epoch whose checkpoint has the wrong digest');
});

define("epochs: the guard refuses an epoch whose holder does not hold the domain's unexpired lease (lease_not_held)", async (ctx) => {
  const guard = { domain: ctx.domain, holder: HOLDER_A, publishedAnchorSize: null };
  await fenced(ctx, { ...(await ctx.epoch()), guard }, 'lease_not_held');
  await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_B, 60_000);
  await fenced(ctx, { ...(await ctx.epoch()), guard }, 'lease_not_held');
  await ctx.anchors.releaseAnchorLease(ctx.domain, HOLDER_B);
  await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 1);
  await sleep(50);
  await fenced(ctx, { ...(await ctx.epoch()), guard }, 'lease_not_held');
  await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 60_000);
  strictEqual((await ctx.anchors.persistEpoch({ ...(await ctx.epoch()), guard })).length, 1, 'the holder of the unexpired lease writes the epoch');
});

define('epochs: the guard refuses an epoch while an EVM publication is unmined (publication_unmined)', async (ctx) => {
  await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 60_000);
  const guard = { domain: ctx.domain, holder: HOLDER_A, publishedAnchorSize: null };
  await ctx.publication('rfc3161/1', 'prepared');
  const prepared = await ctx.publication('evm-calldata/1', 'prepared');
  await fenced(ctx, { ...(await ctx.epoch()), guard }, 'publication_unmined');
  await ctx.anchors.updateAnchorPublication(prepared.id, fieldsFor('submitted', prepared));
  await fenced(ctx, { ...(await ctx.epoch()), guard }, 'publication_unmined');
});

define('epochs: the guard refuses an epoch planned on another published anchor size (published_size_moved)', async (ctx) => {
  await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 60_000);
  const included = await ctx.publication('evm-calldata/1', 'included');
  await ctx.publication('evm-calldata/1', 'superseded');
  await ctx.publication('rfc3161/1', 'obtained');
  await fenced(ctx, { ...(await ctx.epoch()), guard: { domain: ctx.domain, holder: HOLDER_A, publishedAnchorSize: null } }, 'published_size_moved');
  await fenced(ctx, { ...(await ctx.epoch()), guard: { domain: ctx.domain, holder: HOLDER_A, publishedAnchorSize: included.anchorSize + 1 } }, 'published_size_moved');
  const finalized = await ctx.publication('evm-calldata/1', 'finalized');
  await fenced(ctx, { ...(await ctx.epoch()), guard: { domain: ctx.domain, holder: HOLDER_A, publishedAnchorSize: included.anchorSize } }, 'published_size_moved');
  const created = await ctx.anchors.persistEpoch({ ...(await ctx.epoch()), guard: { domain: ctx.domain, holder: HOLDER_A, publishedAnchorSize: finalized.anchorSize } });
  strictEqual(created.length, 1);
});

define('epochs: the guard supersedes the publication it names in the same transaction, and a refused epoch leaves it as it was', async (ctx) => {
  await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 60_000);
  const published = await ctx.publication('evm-calldata/1', 'included');
  let stuck = await ctx.publication('evm-calldata/1', 'submitted');
  stuck = await ctx.anchors.updateAnchorPublication(stuck.id, { attempts: stuck.attempts.map((a) => ({ ...a, broadcast: 'rejected' as const })) });
  const guard = { domain: ctx.domain, holder: HOLDER_A, publishedAnchorSize: published.anchorSize, supersedes: stuck.id };
  const refusedWrite = await ctx.epoch();
  await refusesAndKeeps(
    () => ctx.footprint(),
    () => ctx.anchors.persistEpoch({ ...refusedWrite, guard, checkpoints: [{ ...refusedWrite.checkpoints[0], bodyDigest: hex('no') }] }),
    'an epoch that supersedes and then fails',
  );
  const created = await ctx.anchors.persistEpoch({ ...(await ctx.epoch()), guard });
  strictEqual(created.length, 1);
  strictEqual((await ctx.anchors.getAnchorPublication(stuck.id))?.state, 'superseded');
});

// The lease

define('lease: taken when free, renewed by its holder, kept from another while unexpired, taken over once expired', async (ctx) => {
  strictEqual(await ctx.anchors.getAnchorLease(ctx.domain), null);
  const taken = await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 60_000);
  strictEqual(taken.domain, ctx.domain);
  strictEqual(taken.holder, HOLDER_A);
  strictEqual((await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_B, 60_000)).holder, HOLDER_A, 'an unexpired lease stays with its holder');
  const renewed = await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 120_000);
  strictEqual(renewed.holder, HOLDER_A, 'the holder renews it');
  // Both expiries are the store's clock plus the ttl, so a 120 s renewal a moment
  // after a 60 s take moves the expiry on by 60 s and the moment between.
  const movedMs = Date.parse(renewed.expiresAt) - Date.parse(taken.expiresAt);
  ok(movedMs >= 50_000 && movedMs < 600_000, `the lease runs for its ttl in milliseconds: renewing for 120 s after 60 s moved the expiry ${movedMs} ms`);
  same(await ctx.anchors.getAnchorLease(ctx.domain), renewed);
  await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 1);
  await sleep(50);
  strictEqual((await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_B, 60_000)).holder, HOLDER_B, 'an expired lease is taken over');
});

define('lease: released only by its holder', async (ctx) => {
  await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, 60_000);
  await ctx.anchors.releaseAnchorLease(ctx.domain, HOLDER_B);
  strictEqual((await ctx.anchors.getAnchorLease(ctx.domain))?.holder, HOLDER_A);
  await ctx.anchors.releaseAnchorLease(ctx.domain, HOLDER_A);
  strictEqual(await ctx.anchors.getAnchorLease(ctx.domain), null);
  strictEqual((await ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_B, 60_000)).holder, HOLDER_B);
});

define("lease: ttlMs is a positive integer, and the lease is the store's own domain's", async (ctx) => {
  for (const ttl of [0, -1, 1.5, Number.NaN]) {
    await refuses(() => ctx.anchors.acquireAnchorLease(ctx.domain, HOLDER_A, ttl), `a ttl of ${ttl}`);
  }
  strictEqual(await ctx.anchors.getAnchorLease(ctx.domain), null);
  const other = `${ctx.identity.ns}/${hex('another store').slice(0, 32)}`;
  await refuses(() => ctx.anchors.acquireAnchorLease(other, HOLDER_A, 60_000), "a lease for another store's domain");
  strictEqual(await ctx.anchors.getAnchorLease(other), null);
});

// Wallets and nonce accounting

define('wallets: a wallet is enrolled once, for the store’s own domain, and retired once', async (ctx) => {
  const address = signer('wallet').address.toLowerCase();
  const enrolled = await ctx.anchors.enrolAnchorWallet({ address, chain: CHAIN, domain: ctx.domain, nonceBase: 5 });
  ok(enrolled.address === address && enrolled.chain === CHAIN && enrolled.domain === ctx.domain && enrolled.nonceBase === 5 && enrolled.retiredAt === null, 'the enrolment as given');
  same(await ctx.anchors.enrolAnchorWallet({ address, chain: CHAIN, domain: ctx.domain, nonceBase: 9 }), enrolled, 'a second enrolment returns the stored row');
  same(await ctx.anchors.getAnchorWallet(address, CHAIN), enrolled);
  strictEqual(await ctx.anchors.getAnchorWallet(address, 'eip155:1'), null);
  const other = signer('another wallet').address.toLowerCase();
  await refuses(() => ctx.anchors.enrolAnchorWallet({ address: other, chain: CHAIN, domain: `${ctx.identity.ns}/${hex('another store').slice(0, 32)}`, nonceBase: 0 }), "an enrolment for another store's domain");
  strictEqual(await ctx.anchors.getAnchorWallet(other, CHAIN), null);
  const retired = await ctx.anchors.retireAnchorWallet(address, CHAIN);
  ok(retired.retiredAt !== null && retired.nonceBase === 5, 'retired, with the enrolment kept');
  await refusesAndKeeps(() => ctx.anchors.getAnchorWallet(address, CHAIN), () => ctx.anchors.retireAnchorWallet(address, CHAIN), 'a second retirement');
  await refuses(() => ctx.anchors.retireAnchorWallet(other, CHAIN), 'retiring a wallet that is not enrolled');
});

define('wallets: an enrolment is never changed or deleted', async (ctx) => {
  const address = signer('wallet').address.toLowerCase();
  await ctx.anchors.enrolAnchorWallet({ address, chain: CHAIN, domain: ctx.domain, nonceBase: 5 });
  const read = () => ctx.anchors.getAnchorWallet(address, CHAIN);
  const wallet: RawWrite['where'] = [['address', address], ['chain', CHAIN]];
  await refusesRaw(ctx, read, { table: 'anchor_wallets', set: ['nonce_base', 0], where: wallet }, "a rewrite of the wallet's nonce base");
  await refusesRaw(ctx, read, { table: 'anchor_wallets', where: wallet }, 'a DELETE of an enrolment');
}, { needs: ['raw'] });

define("wallet transactions: txHash is keccak256(rawTx), and the signed sender, nonce and chain are the row's", async (ctx) => {
  const wallet = signer('wallet');
  const address = wallet.address.toLowerCase();
  await ctx.anchors.enrolAnchorWallet({ address, chain: CHAIN, domain: ctx.domain, nonceBase: 0 });
  await ctx.anchors.enrolAnchorWallet({ address, chain: 'eip155:1', domain: ctx.domain, nonceBase: 0 });
  const row = async (nonce: number, over: Partial<NewAnchorWalletTx> = {}): Promise<NewAnchorWalletTx> => ({ address, chain: CHAIN, nonce, kind: 'sweep', ...(await signedTx(wallet, nonce)), ...over });
  const read = () => ctx.anchors.listAnchorWalletTxs(address, CHAIN);
  await refusesAndKeeps(read, async () => ctx.anchors.insertAnchorWalletTx(await row(1, { txHash: `0x${hex('not the hash')}` })), 'a txHash that is not keccak256(rawTx)');
  await refusesAndKeeps(read, async () => ctx.anchors.insertAnchorWalletTx(await row(1, await signedTx(signer('someone else'), 1))), 'a transaction another key signed');
  await refusesAndKeeps(read, async () => ctx.anchors.insertAnchorWalletTx(await row(1, await signedTx(wallet, 2))), 'a transaction signed with another nonce');
  await refusesAndKeeps(read, async () => ctx.anchors.insertAnchorWalletTx(await row(1, { rawTx: '0x1234', txHash: `0x${hex('0x1234')}` })), 'bytes that are not a signed transaction');
  await refusesAndKeeps(read, async () => ctx.anchors.insertAnchorWalletTx(await row(1, { kind: 'refund' as 'sweep' })), 'a kind that is neither sweep nor handover');
  await refusesAndKeeps(() => ctx.anchors.listAnchorWalletTxs(address, 'eip155:1'), async () => ctx.anchors.insertAnchorWalletTx(await row(1, { chain: 'eip155:1' })), 'a transaction signed for another chain');
  const good = await row(1, { kind: 'handover' });
  const stored = await ctx.anchors.insertAnchorWalletTx(good);
  const { createdAt, ...fields } = stored;
  same(fields, good);
  ok(!Number.isNaN(Date.parse(createdAt)), 'createdAt is stamped');
  same(await read(), [stored]);
});

define('nonce accounting: a nonce is held by a publication or by an accounted transaction, never both', async (ctx) => {
  const wallet = signer('publisher');
  const address = wallet.address.toLowerCase();
  const tx = async (nonce: number): Promise<NewAnchorWalletTx> => ({ address, chain: CHAIN, nonce, kind: 'sweep', ...(await signedTx(wallet, nonce)) });
  const txs = () => ctx.anchors.listAnchorWalletTxs(address, CHAIN);
  await refusesAndKeeps(txs, async () => ctx.anchors.insertAnchorWalletTx(await tx(5)), 'a transaction of a wallet that is not enrolled');
  await ctx.anchors.enrolAnchorWallet({ address, chain: CHAIN, domain: ctx.domain, nonceBase: 5 });
  await refusesAndKeeps(txs, async () => ctx.anchors.insertAnchorWalletTx(await tx(4)), 'a nonce below the nonce base');
  await ctx.anchors.insertAnchorWalletTx(await tx(5));

  const p = await ctx.publication('evm-calldata/1', 'prepared');
  const send = (nonce: number, n: number) => ctx.anchors.updateAnchorPublication(p.id, { state: 'submitted', fromAddress: address, nonce, attempts: [attempt(n, 'rejected')] });
  await refusesAndKeeps(() => ctx.anchors.getAnchorPublication(p.id), () => send(5, 930), 'a publication taking a nonce an accounted transaction holds');
  await send(6, 931);
  await refusesAndKeeps(txs, async () => ctx.anchors.insertAnchorWalletTx(await tx(6)), 'an accounted transaction taking a nonce a publication holds');
  await ctx.anchors.updateAnchorPublication(p.id, { state: 'superseded' });
  await ctx.anchors.insertAnchorWalletTx(await tx(6));
  same((await txs()).map((t) => t.nonce), [5, 6], 'listed in nonce order');

  await ctx.anchors.retireAnchorWallet(address, CHAIN);
  await refusesAndKeeps(txs, async () => ctx.anchors.insertAnchorWalletTx(await tx(7)), 'an accounted transaction of a retired wallet');
  const q = await ctx.publication('evm-calldata/1', 'prepared');
  await refusesAndKeeps(
    () => ctx.anchors.getAnchorPublication(q.id),
    () => ctx.anchors.updateAnchorPublication(q.id, { state: 'submitted', fromAddress: address, nonce: 8, attempts: [attempt(932)] }),
    'a publication taking a nonce of a retired wallet',
  );
});

define('wallet transactions: an accounted transaction is never changed or deleted', async (ctx) => {
  const wallet = signer('wallet');
  const address = wallet.address.toLowerCase();
  await ctx.anchors.enrolAnchorWallet({ address, chain: CHAIN, domain: ctx.domain, nonceBase: 0 });
  await ctx.anchors.insertAnchorWalletTx({ address, chain: CHAIN, nonce: 0, kind: 'sweep', ...(await signedTx(wallet, 0)) });
  const read = () => ctx.anchors.listAnchorWalletTxs(address, CHAIN);
  const tx: RawWrite['where'] = [['address', address], ['chain', CHAIN], ['nonce', 0]];
  await refusesRaw(ctx, read, { table: 'anchor_wallet_txs', set: ['raw_tx', '0x02'], where: tx }, 'an UPDATE of an accounted transaction');
  await refusesRaw(ctx, read, { table: 'anchor_wallet_txs', where: tx }, 'a DELETE of an accounted transaction');
}, { needs: ['raw'] });

// The fill

/**
 * A record's anchor artifact, naming its evidence log at `size` and the
 * publication's anchor checkpoint. With the log's leaves (`digests`, the
 * records' canonical digests in sequence order), its log checkpoint and path
 * are the log's real ones, as a store's fill checks (`anchorFillConflict`);
 * without them, made up. The anchor half is made up: no store reads it.
 */
function artifactFor(
  evidenceLog: LogRecord,
  leafIndex: number,
  size: number,
  publication: AnchorPublication,
  anchorLog: LogRecord,
  variant = '',
  digests?: string[],
): AnchorArtifact {
  const real = digests && digests.length >= size ? extendCompactRange({ size: 0, hashes: [] }, digests.slice(0, size)) : null;
  return {
    anchorSpec: ANCHOR_SPEC,
    merkleSpec: MERKLE_SPEC,
    leafIndex,
    logCheckpoint: formatCheckpoint(evidenceLog.origin, size, real ? real.root : hex(`log root ${size}${variant}`)),
    logPath: real ? real.inclusionProofs[leafIndex] : [hex(`log path ${leafIndex}${variant}`)],
    anchorLeafIndex: 0,
    anchorCheckpoint: formatCheckpoint(anchorLog.origin, publication.anchorSize, hex(`anchor root ${publication.anchorSize}${variant}`)),
    anchorPath: [],
    publications: [
      {
        kind: 'evm-calldata/1',
        chain: CHAIN,
        transactionId: publication.minedTxHash ?? `0x${hex('mined')}`,
        blockNumber: publication.blockNumber ?? 1,
        blockHash: publication.blockHash ?? `0x${hex('block')}`,
        publisher: publication.fromAddress ?? SENDER,
      },
    ],
  };
}

/** The status rule the kit's chunks use: `partial` once an anchor is in place. */
const statusOf: AnchorFillChunk['statusOf'] = (envelope) =>
  (envelope.nonRepudiation as { anchor?: unknown } | undefined)?.anchor ? 'partial' : envelope.attestationStatus;

/** What a filled record must equal: `filledEnvelope`, all of it, or all but its status. */
function expectFilled(ctx: Ctx, got: EvidenceEnvelope | null, want: EvidenceEnvelope, what: string): void {
  ok(got, `${what} is still stored`);
  if (ctx.fillStatusFromChunk) {
    same(got, want, `${what} is filled as filledEnvelope gives`);
  } else {
    const { attestationStatus: _a, ...gotRest } = got;
    const { attestationStatus: _b, ...wantRest } = want;
    same(gotRest, wantRest, `${what} is filled as filledEnvelope gives (the status aside)`);
  }
}

define("fill: a record without an anchor gets it, as filledEnvelope gives, and the publication's progress is written with it", async (ctx) => {
  const chain = 'conformance-fill';
  const recs = records('fill', 3);
  await ctx.storeRecords(chain, recs);
  const log = (await ctx.evidenceLog(chain))!;
  const publication = await ctx.publication('evm-calldata/1', 'finalized');
  const before = await Promise.all(recs.map((r) => ctx.readRecord(r.payload.evidenceId)));
  const digests = recs.map((r) => r.integrity.canonicalDigest);
  const fills = [0, 1].map((i) => ({ evidenceId: recs[i].payload.evidenceId, logId: log.logId, anchor: artifactFor(log, i, 3, publication, ctx.anchorLog, '', digests) }));
  const chunk: AnchorFillChunk = { publicationId: publication.id, fills: [...fills, { evidenceId: 'fill-no-such-record', logId: log.logId, anchor: artifactFor(log, 7, 8, publication, ctx.anchorLog) }], statusOf, fillProgress: { anchorLeaf: 1, filled: 2 } };
  const result = await ctx.anchors.fillAnchorArtifacts(chunk);
  same(result, { filled: 2, alreadyAnchored: 0, missing: ['fill-no-such-record'], conflicts: [] });
  for (const i of [0, 1]) {
    expectFilled(ctx, await ctx.readRecord(recs[i].payload.evidenceId), filledEnvelope(before[i]!, fills[i], chunk)!, `record ${i + 1}`);
  }
  same(await ctx.readRecord(recs[2].payload.evidenceId), before[2], 'a record the chunk does not name is not written');
  same((await ctx.anchors.getAnchorPublication(publication.id))?.fillProgress, { anchorLeaf: 1, filled: 2 });
  // The records' leaves are what they were: the fill writes records, never the log.
  same((await ctx.logs.listLogLeaves(log.logId, 0, 3)).map((l) => l.leafDigest), recs.map((r) => r.integrity.canonicalDigest));
}, { needs: ['records'] });

define('fill: fill-only; a record that has an anchor keeps it', async (ctx) => {
  const chain = 'conformance-fill-once';
  const recs = records('once', 2);
  await ctx.storeRecords(chain, recs);
  const log = (await ctx.evidenceLog(chain))!;
  const publication = await ctx.publication('evm-calldata/1', 'finalized');
  const digests = recs.map((r) => r.integrity.canonicalDigest);
  const first = { evidenceId: recs[0].payload.evidenceId, logId: log.logId, anchor: artifactFor(log, 0, 2, publication, ctx.anchorLog, '', digests) };
  await ctx.anchors.fillAnchorArtifacts({ publicationId: publication.id, fills: [first], statusOf, fillProgress: { step: 1 } });
  const filled = await ctx.readRecord(recs[0].payload.evidenceId);
  const again = { ...first, anchor: artifactFor(log, 0, 2, publication, ctx.anchorLog, ' (another fill)', digests) };
  again.anchor.anchorCheckpoint = formatCheckpoint(ctx.anchorLog.origin, publication.anchorSize, hex(`anchor root ${publication.anchorSize} (another fill)`));
  const second = { evidenceId: recs[1].payload.evidenceId, logId: log.logId, anchor: artifactFor(log, 1, 2, publication, ctx.anchorLog, '', digests) };
  const result = await ctx.anchors.fillAnchorArtifacts({ publicationId: publication.id, fills: [again, second], statusOf, fillProgress: { step: 2 } });
  same(result, { filled: 1, alreadyAnchored: 1, missing: [], conflicts: [] });
  same(await ctx.readRecord(recs[0].payload.evidenceId), filled, 'the first anchor stays');
  same((await ctx.readRecord(recs[1].payload.evidenceId))?.nonRepudiation, { anchor: second.anchor });
  same((await ctx.anchors.getAnchorPublication(publication.id))?.fillProgress, { step: 2 });
}, { needs: ['records'] });

define("fill: an anchor that is null or '' is absent, and is filled; any other value, false among them, is kept", async (ctx) => {
  const chain = 'conformance-fill-absent';
  const held: unknown[] = [null, '', false];
  const recs = records('absent', held.length).map((r, i) => ({ ...r, nonRepudiation: { ...r.nonRepudiation, anchor: held[i] } }) as EvidenceEnvelope);
  await ctx.storeRecords(chain, recs);
  const log = (await ctx.evidenceLog(chain))!;
  const before = await Promise.all(recs.map((r) => ctx.readRecord(r.payload.evidenceId)));
  same(
    before.map((r) => (r?.nonRepudiation as { anchor?: unknown } | undefined)?.anchor),
    held,
    'storeRecords keeps the anchor value each record arrives with (a store that cannot names harness.without.presetAnchors)',
  );
  const publication = await ctx.publication('evm-calldata/1', 'finalized');
  const digests = recs.map((r) => r.integrity.canonicalDigest);
  const fills = recs.map((r, i) => ({ evidenceId: r.payload.evidenceId, logId: log.logId, anchor: artifactFor(log, i, held.length, publication, ctx.anchorLog, '', digests) }));
  const chunk: AnchorFillChunk = { publicationId: publication.id, fills, statusOf, fillProgress: { absent: true } };
  same(await ctx.anchors.fillAnchorArtifacts(chunk), { filled: 2, alreadyAnchored: 1, missing: [], conflicts: [] }, 'null and empty are filled; false is kept');
  for (const i of [0, 1]) {
    expectFilled(ctx, await ctx.readRecord(recs[i].payload.evidenceId), filledEnvelope(before[i]!, fills[i], chunk)!, `the record held at ${JSON.stringify(held[i])}`);
  }
  same(await ctx.readRecord(recs[2].payload.evidenceId), before[2], 'the record held at false keeps it');
}, { needs: ['records', 'presetAnchors'] });

define('fill: a chunk for no stored publication is refused whole', async (ctx) => {
  const chain = 'conformance-fill-refused';
  const recs = records('refused', 1);
  await ctx.storeRecords(chain, recs);
  const log = (await ctx.evidenceLog(chain))!;
  const publication = await ctx.publication('evm-calldata/1', 'finalized');
  const fill = { evidenceId: recs[0].payload.evidenceId, logId: log.logId, anchor: artifactFor(log, 0, 1, publication, ctx.anchorLog, '', [recs[0].integrity.canonicalDigest]) };
  await refusesAndKeeps(
    () => ctx.readRecord(recs[0].payload.evidenceId),
    () => ctx.anchors.fillAnchorArtifacts({ publicationId: publication.id + 1000, fills: [fill], statusOf, fillProgress: { done: true } }),
    'a fill chunk for a publication the store does not have',
  );
}, { needs: ['records'] });

define('fill: the status is the chunk’s, except that complete stays complete and pending without a timestamp stays pending while one is expected', async (ctx) => {
  const chain = 'conformance-fill-status';
  const recs = records('status', 4);
  const statuses: Array<EvidenceEnvelope['attestationStatus']> = ['none', 'pending', 'complete', 'pending'];
  recs.forEach((r, i) => (r.attestationStatus = statuses[i]));
  await ctx.storeRecords(chain, recs);
  const log = (await ctx.evidenceLog(chain))!;
  const publication = await ctx.publication('evm-calldata/1', 'finalized');
  const digests = recs.map((r) => r.integrity.canonicalDigest);
  const fill = (i: number) => ({ evidenceId: recs[i].payload.evidenceId, logId: log.logId, anchor: artifactFor(log, i, 4, publication, ctx.anchorLog, '', digests) });
  await ctx.anchors.fillAnchorArtifacts({ publicationId: publication.id, fills: [0, 1, 2].map(fill), statusOf, fillProgress: {} });
  await ctx.anchors.fillAnchorArtifacts({ publicationId: publication.id, fills: [fill(3)], statusOf, timestampExpected: false, fillProgress: {} });
  const now = await Promise.all(recs.map(async (r) => (await ctx.readRecord(r.payload.evidenceId))?.attestationStatus));
  same(now, ['partial', 'pending', 'complete', 'partial']);
}, { needs: ['records'], statusFromChunk: true });

define('fill: a record that does not match its leaf is reported in conflicts, and nothing is written to it', async (ctx) => {
  const chain = 'conformance-fill-conflict';
  const recs = records('conflict', 3);
  await ctx.storeRecords(chain, recs);
  const log = (await ctx.evidenceLog(chain))!;
  const publication = await ctx.publication('evm-calldata/1', 'finalized');
  const digests = recs.map((r) => r.integrity.canonicalDigest);
  const before = await Promise.all(recs.map((r) => ctx.readRecord(r.payload.evidenceId)));
  // Record 1 with record 2's artifact (another position); record 2 with a
  // path that does not place its digest; record 3 as it should be.
  const elsewhere = { evidenceId: recs[0].payload.evidenceId, logId: log.logId, anchor: artifactFor(log, 1, 3, publication, ctx.anchorLog, '', digests) };
  const wrongPath = { evidenceId: recs[1].payload.evidenceId, logId: log.logId, anchor: { ...artifactFor(log, 1, 3, publication, ctx.anchorLog, '', digests), logPath: [hex('not the sibling')] } };
  const right = { evidenceId: recs[2].payload.evidenceId, logId: log.logId, anchor: artifactFor(log, 2, 3, publication, ctx.anchorLog, '', digests) };
  const chunk: AnchorFillChunk = { publicationId: publication.id, fills: [elsewhere, wrongPath, right], statusOf, fillProgress: { conflicts: true } };
  same(await ctx.anchors.fillAnchorArtifacts(chunk), {
    filled: 1,
    alreadyAnchored: 0,
    missing: [],
    conflicts: [recs[0].payload.evidenceId, recs[1].payload.evidenceId],
  });
  same(await ctx.readRecord(recs[0].payload.evidenceId), before[0], 'a record given another position\'s artifact is not written');
  same(await ctx.readRecord(recs[1].payload.evidenceId), before[1], 'a record whose path does not place its digest is not written');
  expectFilled(ctx, await ctx.readRecord(recs[2].payload.evidenceId), filledEnvelope(before[2]!, right, chunk)!, 'the record that matches its leaf');
}, { needs: ['records'] });

define('leaves: an evidence leaf that copies no stored record is refused, whoever writes it', async (ctx) => {
  const chain = 'conformance-bind';
  const other = 'conformance-bind-other';
  const recs = records('bind', 2);
  await ctx.storeRecords(chain, recs.slice(0, 1));
  const [elsewhere] = records('bind-elsewhere', 1);
  await ctx.storeRecords(other, [elsewhere]);
  const log = (await ctx.evidenceLog(chain))!;
  const read = () => ctx.logs.listLogLeaves(log.logId, 0, 10);
  const leaf = (sourceRef: string, leafIndex: number, leafDigest: string, source = 'capture'): RawRow => [
    ['log_id', log.logId],
    ['leaf_index', leafIndex],
    ['leaf_digest', leafDigest],
    ['source_ref', sourceRef],
    ['source', source],
    ['logged_at', NOW_CELL],
  ];
  const attacks: Array<[string, RawRow]> = [
    ['a leaf naming no stored record', leaf('bind-phantom', 1, hex('phantom'))],
    ["a stored record's id with another digest", leaf(recs[0].payload.evidenceId, 1, hex('another digest'))],
    ['a stored record at another position', leaf(recs[0].payload.evidenceId, 1, recs[0].integrity.canonicalDigest)],
    ["another chain's record", leaf(elsewhere.payload.evidenceId, 1, elsewhere.integrity.canonicalDigest)],
    ['a backfill leaf on an open store', leaf('bind-backfill', 1, hex('backfill'), 'backfill')],
  ];
  for (const [what, row] of attacks) {
    try {
      await ctx.raw(...rawInsert(ctx, 'log_leaves', row, 'no row'));
    } catch (err) {
      if (err instanceof AssertionError) throw err;
      throw new AssertionError({ message: `raw() cannot run ${what} even on no row (${describe(err)}), so a refusal would not show the guard` });
    }
    await refusesAndKeeps(read, () => ctx.raw(...rawInsert(ctx, 'log_leaves', row, 'values')), what);
  }
  // The genuine record then takes its position and its leaf.
  await ctx.storeRecords(chain, recs.slice(1));
  same((await read()).map((l) => l.leafDigest), recs.map((r) => r.integrity.canonicalDigest), 'the genuine record gets its leaf');
}, { needs: ['raw', 'records'] });

// ── Running them ────────────────────────────────────────────────────────

/**
 * The conformance cases for the stores `harness` opens, in a stable order.
 * A case the harness cannot run carries the reason as `skip`.
 */
export function anchorStoreConformanceCases(harness: AnchorStoreConformanceHarness): AnchorStoreConformanceCase[] {
  return CASES.map((spec) => {
    const lacking = (spec.needs ?? []).map((need) => harness.without?.[need]).find((reason): reason is string => typeof reason === 'string');
    const skip = lacking ?? (spec.statusFromChunk && harness.fillStatusFromChunk === false ? 'the store rates the status by a rule of its own (fillStatusFromChunk: false)' : undefined);
    return {
      name: spec.name,
      ...(skip !== undefined && { skip }),
      run: async () => {
        const ctx = await Ctx.open(harness);
        try {
          await spec.body(ctx);
        } finally {
          await ctx.close();
        }
      },
    };
  });
}

/** Run every case, one after another, and report which passed, failed and were skipped. */
export async function runAnchorStoreConformance(harness: AnchorStoreConformanceHarness): Promise<AnchorStoreConformanceReport> {
  const report: AnchorStoreConformanceReport = { passed: [], failed: [], skipped: [] };
  for (const c of anchorStoreConformanceCases(harness)) {
    if (c.skip !== undefined) {
      report.skipped.push({ name: c.name, reason: c.skip });
      continue;
    }
    try {
      await c.run();
      report.passed.push(c.name);
    } catch (error) {
      report.failed.push({ name: c.name, error });
    }
  }
  return report;
}
