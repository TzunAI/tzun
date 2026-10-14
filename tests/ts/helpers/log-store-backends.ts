/**
 * The two SQL backends of the evidence-log suites (Tree §5.2), behind one
 * shape.
 *
 * A suite asks a backend for a store and gets the adapter plus a raw handle
 * on the same database, for the statements the SDK never issues: the attacks
 * the triggers refuse, and the writes a writer other than the SDK makes. SQL
 * is written with `?` placeholders; the Postgres handle numbers them.
 *
 * SQLite stores are files in a temporary directory. Postgres stores are one
 * schema per suite (tests/ts/helpers/postgres-test-db.ts), reset before each
 * store is opened, so every store starts empty and mints its own identity.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type BetterSqlite3 from 'better-sqlite3';
import { Client } from 'pg';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';
import type { LogSchemaOptions } from '../../../src/storage/log-store';
import { PG_TESTS_ENABLED, pgSuiteSchema, type PgTestSchema } from './postgres-test-db';

/** Raw SQL on the store's database, outside the adapter, and the driver object behind it. */
export interface RawDb {
  run(sql: string, params?: unknown[]): Promise<void>;
  all<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>;
  sqlite?: BetterSqlite3.Database;
  pg?: Client;
}

export interface OpenedStore<A> {
  adapter: A;
  raw: RawDb;
  /** Where the store lives: a file path, or a connection URL. */
  location: string;
  /** Close the adapter and the raw handle. The store itself stays. */
  close(): Promise<void>;
}

export interface LogBackend {
  name: 'sqlite' | 'postgres';
  /** Start from nothing: a new file, or an emptied schema. */
  fresh(): Promise<void>;
  /** The current store: its file, or its connection URL. */
  location(): string;
  /** Open (or reopen) the current store through the adapter, which runs the migration. */
  open(options?: LogSchemaOptions): Promise<OpenedStore<SqliteStorageAdapter | PostgresStorageAdapter>>;
  /** A raw handle on the current store without opening the adapter. */
  rawOnly(): Promise<{ raw: RawDb; close(): Promise<void> }>;
  /** Remove what `fresh()` made. */
  dispose(): Promise<void>;
}

function sqliteRaw(db: BetterSqlite3.Database): RawDb {
  return {
    sqlite: db,
    async run(sql, params = []) {
      db.prepare(sql).run(...params);
    },
    async all<T>(sql: string, params: unknown[] = []) {
      return db.prepare(sql).all(...params) as T[];
    },
  };
}

function numbered(sql: string): string {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

function pgRaw(client: Client): RawDb {
  return {
    pg: client,
    async run(sql, params = []) {
      await client.query(numbered(sql), params);
    },
    async all<T>(sql: string, params: unknown[] = []) {
      return (await client.query(numbered(sql), params)).rows as T[];
    },
  };
}

export function sqliteBackend(): LogBackend {
  let dir: string | undefined;
  let file = '';
  return {
    name: 'sqlite',
    async fresh() {
      if (dir) rmSync(dir, { recursive: true, force: true });
      dir = mkdtempSync(join(tmpdir(), 'tzun-test-logs-'));
      file = join(dir, 'store.db');
    },
    location: () => file,
    async open(options = {}) {
      const adapter = new SqliteStorageAdapter(file, options);
      const db = (adapter as unknown as { db: BetterSqlite3.Database }).db;
      return { adapter, raw: sqliteRaw(db), location: file, close: () => adapter.close() };
    },
    async rawOnly() {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const Database = require('better-sqlite3') as typeof BetterSqlite3;
      const db = new Database(file);
      return {
        raw: sqliteRaw(db),
        close: async () => {
          db.close();
        },
      };
    },
    async dispose() {
      if (dir) rmSync(dir, { recursive: true, force: true });
      dir = undefined;
    },
  };
}

/**
 * The Postgres backend over one suite schema. Call it while the suite is
 * collected (it registers the schema's hooks); with the Postgres legs off it
 * returns undefined.
 */
export function postgresBackend(label: string): LogBackend | undefined {
  const schema: PgTestSchema = pgSuiteSchema(label);
  if (!PG_TESTS_ENABLED) return undefined;
  const connect = async (): Promise<Client> => {
    const client = new Client({ connectionString: schema.url });
    await client.connect();
    return client;
  };
  return {
    name: 'postgres',
    fresh: () => schema.reset(),
    location: () => schema.url,
    async open(options = {}) {
      const adapter = new PostgresStorageAdapter(schema.url, undefined, options);
      try {
        await adapter.ensureTables();
      } catch (err) {
        await adapter.close();
        throw err;
      }
      const client = await connect();
      return {
        adapter,
        raw: pgRaw(client),
        location: schema.url,
        close: async () => {
          await client.end();
          await adapter.close();
        },
      };
    },
    async rawOnly() {
      const client = await connect();
      return { raw: pgRaw(client), close: () => client.end() };
    },
    async dispose() {
      /* the suite schema is dropped by its afterAll */
    },
  };
}

/**
 * Await `work` and return the message it was refused with; fail when it goes
 * through. Reads the message without `instanceof Error`, and so without
 * jest's `toThrow`: better-sqlite3's native addon is loaded once per process
 * and keeps the error class of the first test file that loaded it, so a
 * SqliteError raised in a later file belongs to another realm.
 */
export async function refusal(work: Promise<unknown> | (() => Promise<unknown>), pattern?: RegExp): Promise<string> {
  let message: string;
  try {
    await (typeof work === 'function' ? work() : work);
  } catch (err) {
    const raw = (err as { message?: unknown } | null)?.message;
    message = typeof raw === 'string' ? raw : String(err);
    if (pattern && !pattern.test(message)) {
      throw new Error(`refused with ${JSON.stringify(message)}, which does not match ${pattern}`);
    }
    return message;
  }
  throw new Error(`expected a refusal${pattern ? ` matching ${pattern}` : ''}, but it went through`);
}

/** The backends a suite runs on: SQLite always, Postgres when its legs are on. */
export function logBackends(label: string): LogBackend[] {
  const pg = postgresBackend(label);
  return pg ? [sqliteBackend(), pg] : [sqliteBackend()];
}
