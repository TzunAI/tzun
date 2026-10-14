/**
 * Storage extensions: how a feature that owns tables of its own (mandates,
 * the agent catalog, the link index, decider openings) plugs into the SDK's
 * three local adapters without editing them.
 *
 * The adapters (`sqlite.ts`, `postgres.ts`, `memory.ts`) have one owner. A
 * feature delivers a {@link StorageExtension} from a module of its own
 * (`src/storage/ddl/<feature>.ts` for the DDL, `src/storage/<feature>-sql.ts`
 * for the statements), and the adapters call it at these points:
 *
 *   1. **migrate**: when the store opens, after every core table and the
 *      evidence-log schema (SQLite: the constructor; Postgres:
 *      `ensureTables()`, under its advisory lock, on the client it holds).
 *   2. **lock** (Postgres only): right after `BEGIN`, BEFORE the chain's
 *      append lock and before `storeIdempotent()`'s key lookup, so a row of
 *      the extension's own (a mandate row) is locked first and the chain head
 *      second (the lock order of `ddl/mandates.ts`). It takes locks and
 *      nothing else: it must not refuse and must not write, because a keyed
 *      retry that replays runs it too. (SQLite's IMMEDIATE transaction and
 *      memory's synchronous section already exclude every other writer.)
 *   3. **beforeInsert**: inside `store()`'s transaction, after the
 *      duplicate-id, sealed-chain and chain-head checks (and, under a key,
 *      after the key was found free), before the record is written. The
 *      place to refuse, and to make a compare-and-swap claim.
 *   4. **afterInsert**: inside the same transaction, after the envelope row,
 *      the chain state, the capture revision and the evidence-log leaf.
 *   5. **methods**: the optional `StorageAdapter` methods the extension
 *      provides ({@link ExtensionMethodName}), bound to the adapter's
 *      connection when the adapter is constructed. An adapter whose
 *      extensions provide none of a feature's methods does not have them, so
 *      `typeof adapter.getMandate === 'function'` is how the SDK tells a store
 *      with mandates from one without.
 *
 * A hook refuses by throwing. `store()` then rolls back and nothing of the
 * record, its leaf or any extension row is written; the error reaches the
 * caller as thrown. `storeIdempotent()` runs the same hooks, after its key
 * lookup: a replay runs none of them.
 *
 * The adapters take the extension list as a constructor option
 * (`extensions`), defaulting to `DEFAULT_STORAGE_EXTENSIONS`
 * (`extensions-registry.ts`), so a feature can be tested end to end before
 * it is registered by default.
 */
import type Database from 'better-sqlite3';
import type { Pool, PoolClient } from 'pg';
import type { EvidenceEnvelope, StorageAdapter, StoreOptions } from '@tzun/engine';

/** What one `store()` (or `storeIdempotent()`) call writes, as every hook sees it. */
export interface StoreWrite {
  readonly envelope: EvidenceEnvelope;
  /** The chain the record is appended to (`'default'` when none was named). */
  readonly chainId: string;
  /** The options the caller passed (`{}` when none). Read the option of your feature, ignore the rest. */
  readonly options: StoreOptions;
}

/** The optional `StorageAdapter` methods an extension may provide. */
export type ExtensionMethodName =
  | 'putAgentDescriptor'
  | 'getAgentDescriptor'
  | 'listAgentDescriptors'
  | 'getMandate'
  | 'getMandateTotals'
  | 'listMandateEvents'
  | 'expireMandate'
  | 'listMandates'
  | 'getDeciderOpening'
  | 'getDeciderCommitmentSecret'
  | 'listLinksTo';

/** Implementations of some of those methods. */
export type ExtensionMethods = { [K in ExtensionMethodName]?: NonNullable<StorageAdapter[K]> };

/** The SQLite part of an extension. Every call is synchronous (better-sqlite3). */
export interface SqliteStorageExtension {
  /**
   * Idempotent DDL (`CREATE TABLE IF NOT EXISTS`, `CREATE TRIGGER IF NOT
   * EXISTS`), run once per open, after the core tables and the evidence-log
   * schema, outside any transaction.
   */
  migrate(db: Database.Database): void;
  /** Inside `store()`'s IMMEDIATE transaction, before the record is written. Throw to refuse. */
  beforeInsert?(db: Database.Database, write: StoreWrite): void;
  /** Inside the same transaction, after the record is written. Throw to refuse (the record is rolled back with it). */
  afterInsert?(db: Database.Database, write: StoreWrite): void;
  /**
   * The adapter methods this extension provides, bound to the adapter's
   * connection. A method that writes more than one row runs them in
   * `db.transaction(...).immediate()`.
   */
  methods?(db: Database.Database): ExtensionMethods;
}

/** What a Postgres extension's methods are given: the adapter's pool and its transaction helper. */
export interface PostgresExtensionDb {
  /** The adapter's pool. Statements use unqualified table names (the connection's `search_path`). */
  readonly pool: Pool;
  /** Run `work` on one client between `BEGIN` and `COMMIT`; `ROLLBACK` when it throws, and rethrow. */
  inTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T>;
}

/** The Postgres part of an extension. */
export interface PostgresStorageExtension {
  /**
   * Idempotent DDL, run by `ensureTables()` under its advisory lock, after the
   * core tables and the evidence-log schema, on the client it holds.
   * Unqualified table names. A trigger function follows the store's
   * search-path pattern: `SET search_path = pg_catalog, pg_temp`, and every
   * table read through `format('%1$I.<table>', TG_TABLE_SCHEMA)`.
   * `CREATE OR REPLACE FUNCTION` and `DROP TRIGGER IF EXISTS` / `CREATE
   * TRIGGER` are safe here: the advisory lock serialises every opener.
   */
  migrate(client: PoolClient): Promise<void>;
  /**
   * Right after `BEGIN`, before the chain's append lock and before
   * `storeIdempotent()`'s key lookup: lock rows of your own here (`SELECT …
   * FOR UPDATE`), so every path that takes both locks takes yours first.
   * Takes locks only: never refuses, never writes.
   */
  lock?(client: PoolClient, write: StoreWrite): Promise<void>;
  /** Inside `store()`'s transaction, after the chain-head check, before the record is written. Throw to refuse. */
  beforeInsert?(client: PoolClient, write: StoreWrite): Promise<void>;
  /** Inside the same transaction, after the record is written. Throw to refuse. */
  afterInsert?(client: PoolClient, write: StoreWrite): Promise<void>;
  /** The adapter methods this extension provides. */
  methods?(db: PostgresExtensionDb): ExtensionMethods;
}

/** What the memory adapter lets an extension read of the records it holds. Every result is a detached copy. */
export interface MemoryStoreReads {
  retrieve(evidenceId: string): EvidenceEnvelope | null;
  /** Every stored record, in insertion order. */
  all(): EvidenceEnvelope[];
  /** The chain a stored record belongs to, or `null`. */
  chainOf(evidenceId: string): string | null;
}

/**
 * The memory part of an extension. The memory adapter's `store()` is one
 * synchronous critical section, so its two hooks split refusing from writing:
 * `check` may throw and must not change `state`; `apply` changes `state` and
 * must not throw. That keeps a refused record from leaving any row behind.
 */
export interface MemoryStorageExtension<S = unknown> {
  /** The extension's state for one adapter instance (its "tables"). */
  createState(): S;
  /** Before the record is written, after the duplicate-id, sealed-chain, head and evidence-log checks. Throw to refuse; do not mutate. */
  check?(state: S, write: StoreWrite, reads: MemoryStoreReads): void;
  /** After the record and its leaf are written, in the same critical section. Never throws. */
  apply?(state: S, write: StoreWrite, reads: MemoryStoreReads): void;
  /** The adapter methods this extension provides, over its state. */
  methods?(state: S, reads: MemoryStoreReads): ExtensionMethods;
}

/** One feature's tables, hooks and methods, for each adapter it supports. */
export interface StorageExtension {
  /** A stable, unique name (`'deciders'`, `'mandates'`, `'agents'`, `'links'`). */
  readonly name: string;
  readonly sqlite?: SqliteStorageExtension;
  readonly postgres?: PostgresStorageExtension;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly memory?: MemoryStorageExtension<any>;
}

/** Thrown when two extensions of one adapter provide the same method. */
export class StorageExtensionConflictError extends Error {
  constructor(method: string, first: string, second: string) {
    super(`Storage extensions "${first}" and "${second}" both provide ${method}.`);
    this.name = 'StorageExtensionConflictError';
  }
}

/**
 * Merge the methods each extension provides into one map, refusing a method
 * two extensions both provide. `provided` is in extension order, `null` for an
 * extension that provides none on this adapter.
 */
export function mergeExtensionMethods(
  provided: ReadonlyArray<{ name: string; methods: ExtensionMethods | undefined }>,
): ExtensionMethods {
  const merged: ExtensionMethods = {};
  const owner = new Map<string, string>();
  for (const { name, methods } of provided) {
    if (!methods) continue;
    for (const key of Object.keys(methods) as ExtensionMethodName[]) {
      const fn = methods[key];
      if (typeof fn !== 'function') continue;
      const first = owner.get(key);
      if (first !== undefined) throw new StorageExtensionConflictError(key, first, name);
      owner.set(key, name);
      (merged as Record<string, unknown>)[key] = fn;
    }
  }
  return merged;
}

/**
 * Assign merged extension methods onto an adapter instance as own
 * properties, so `typeof adapter.<method> === 'function'` holds exactly for
 * the methods some extension provides.
 */
export function installExtensionMethods(adapter: object, methods: ExtensionMethods): void {
  for (const [key, fn] of Object.entries(methods)) {
    Object.defineProperty(adapter, key, { value: fn, enumerable: false, writable: true, configurable: true });
  }
}

/** Names that must be unique within one adapter's list. */
export function assertUniqueExtensionNames(extensions: readonly StorageExtension[]): void {
  const seen = new Set<string>();
  for (const ext of extensions) {
    if (seen.has(ext.name)) throw new Error(`Storage extension "${ext.name}" is listed twice.`);
    seen.add(ext.name);
  }
}
