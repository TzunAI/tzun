/**
 * Refusing, at open, a store an earlier release wrote.
 *
 * The v1.0 hashed field set was revised in place by 0.7.0 (it added
 * `signoffExpectation`) and by 0.8.0 (it renamed `humanAction` and
 * `humanReason`, added `decider`, `contributions` and `links`, and moved
 * `aiBom` into the contribution steps). A record captured before has a digest
 * over an earlier set, so every check this release runs would read it as
 * tampered, and every capture would link a new record to it. Nothing is
 * migrated: the answer is a new store. The refusal is never silent:
 * `Tzun.init()` throws `StoreSchemaOutdatedError`, naming the record and the
 * generation of its field set.
 *
 * For SQLite and Postgres the records are read before the adapter's own
 * setup runs (the SQLite file opened read-only, the Postgres tables only
 * read), so no table, trigger, identity or log leaf is added to a refused
 * store, and a SQLite store's main file is unchanged (SQLite may create the
 * `-wal` and `-shm` sidecars of a WAL-mode file when it opens one).
 *
 * The first and newest records are read by insertion order as the store
 * records it, and a writer with access to the store can plant a row there:
 * an old-format record put first locks a 0.8.0 store out with
 * `StoreSchemaOutdatedError`, and a new-format one put first lets an old
 * store open. On SQLite the adapter's `envelopes_block_low_rowid` refuses an
 * insert ahead of the first row, which leaves a writer who drops the trigger;
 * on Postgres `created_at` is a column such a writer can set. Integrity does
 * not rest on this check: the verifiers report every record whose digest
 * does not recompute, whichever way the store opened.
 */
import { existsSync } from 'node:fs';
import Database from 'better-sqlite3';
import { StoreSchemaOutdatedError, recordFieldSetGeneration } from '@tzun/engine';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

function evidenceIdOf(record: unknown): string {
  const payload = isPlainObject(record) ? record.payload : undefined;
  return String(isPlainObject(payload) ? payload.evidenceId : undefined);
}

/** Whether a record's payload has the `decider` key every 0.8.0 writer writes. */
function hasDeciderKey(record: unknown): boolean {
  const payload = isPlainObject(record) ? record.payload : undefined;
  return isPlainObject(payload) && Object.prototype.hasOwnProperty.call(payload, 'decider');
}

/** The earlier generation a record's digest recomputes under, or `null` (the current one, or none). */
function earlierGeneration(record: unknown): '0.7' | 'before-0.7' | null {
  const generation = recordFieldSetGeneration(record);
  return generation === '0.7' || generation === 'before-0.7' ? generation : null;
}

/**
 * Throw `StoreSchemaOutdatedError` when the store was written by a release
 * before 0.8.0: its digest recomputes under an earlier field set
 * (`recordFieldSetGeneration`).
 *
 * The store's first record decides it, so a single record appended later
 * cannot make a 0.8.0 store read as old, and a single record altered later
 * cannot make an old store read as new:
 *
 *   - no first record (an empty store)          → accepted;
 *   - the first record is of an earlier generation → refused, naming it and
 *     its generation;
 *   - the first record is of the current generation, or has the current
 *     payload's `decider` key (0.8.0 wrote it, and it was altered after)
 *     → accepted; an older record after it was written by something else,
 *     and the verifiers report it as tampered;
 *   - otherwise (a digest that holds under no field set: an older record
 *     altered after capture) the newest record decides: refused, naming it,
 *     when it is of an earlier generation.
 *
 * `readNewest` is called only in that last case.
 */
export async function refuseOutdatedStore(first: unknown, readNewest: () => Promise<unknown>): Promise<void> {
  if (first === null || first === undefined) return;
  const firstGeneration = recordFieldSetGeneration(first);
  if (firstGeneration === '0.7' || firstGeneration === 'before-0.7') {
    throw new StoreSchemaOutdatedError(evidenceIdOf(first), firstGeneration);
  }
  if (firstGeneration === '0.8' || hasDeciderKey(first)) return;
  const newest = await readNewest();
  if (newest === null || newest === undefined) return;
  const newestGeneration = earlierGeneration(newest);
  if (newestGeneration !== null) throw new StoreSchemaOutdatedError(evidenceIdOf(newest), newestGeneration);
}

/**
 * The store-generation check on an SQLite file, before `SqliteStorageAdapter`
 * opens it (its constructor creates and evolves tables). The file is opened
 * read-only; a path that is not a file on disk, a file that does not exist,
 * and a file with no `envelopes` table are new stores and pass. First and
 * newest are the lowest and highest `rowid`. SQLite assigns a rowid above
 * every other when an insert names none; an insert that names one below the
 * first row's is refused by `envelopes_block_low_rowid` on a store this SDK
 * has opened, and a writer who can drop that trigger can put any row first.
 */
export async function refuseSqliteStoreBeforeSignoffExpectation(dbPath: string): Promise<void> {
  if (dbPath === ':memory:' || dbPath === '' || !existsSync(dbPath)) return;
  // The umask the adapter opens under, in case SQLite creates the WAL
  // sidecars of a WAL-mode file here.
  const previousUmask = process.umask(0o077);
  let db: Database.Database;
  try {
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
  } finally {
    process.umask(previousUmask);
  }
  try {
    const table = db.prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'envelopes'`).get();
    if (table === undefined) return;
    const read = (order: 'ASC' | 'DESC'): unknown => {
      const row = db.prepare(`SELECT envelope FROM envelopes ORDER BY rowid ${order} LIMIT 1`).get() as
        | { envelope: string }
        | undefined;
      if (row === undefined) return null;
      try {
        return JSON.parse(row.envelope);
      } catch {
        // Not a record of any release: neither old nor new, so it decides
        // nothing (the verifiers report it).
        return row.envelope;
      }
    };
    await refuseOutdatedStore(read('ASC'), async () => read('DESC'));
  } finally {
    db.close();
  }
}

/** What the Postgres check reads: `PostgresStorageAdapter.readEnvelopeAtEnd`. */
export interface EnvelopeEndReader {
  readEnvelopeAtEnd(end: 'first' | 'newest'): Promise<unknown>;
}

/**
 * The store-generation check on a Postgres store, before its adapter's
 * `ensureTables()` runs: the adapter only reads (`readEnvelopeAtEnd`), and a
 * schema with no `envelopes` table is a new store and passes. First and
 * newest are by `created_at`, which defaults to the insertion time; a writer
 * with INSERT on the table can set it, and so put any row first.
 */
export async function refusePostgresStoreBeforeSignoffExpectation(adapter: EnvelopeEndReader): Promise<void> {
  await refuseOutdatedStore(await adapter.readEnvelopeAtEnd('first'), () => adapter.readEnvelopeAtEnd('newest'));
}
