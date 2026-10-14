/**
 * Postgres for the test suite: when the Postgres legs run, which database they
 * may touch, and a schema of its own for every suite.
 *
 * WHEN. A Postgres leg runs when RUN_INTEGRATION_TESTS=true and DATABASE_URL
 * is set, and at no other time. `PG_TESTS_ENABLED` is that rule; a suite gates
 * on it rather than reading the environment itself.
 *
 * WHICH DATABASE. DATABASE_URL must name a database whose name ends in
 * `_test`. The suites create and drop schemas in it, and inside their own
 * schema they truncate, drop tables and columns, and step around the
 * append-only triggers. A `_test` suffix is the one signal that the database
 * is a throwaway, so anything else — `tzun_dev`, another project's database, a
 * copy of production — is refused when the suite loads: a misdirected run is a
 * loud failure, never a silently green skip. `assertThrowawayDatabase` is the
 * rule; `pgSuiteSchema` and `pgCaseSchema` apply it.
 *
 * ISOLATION. Every suite works in a schema created for it and dropped after
 * it, reached through the connection's `search_path`. The URL a schema hands
 * out carries `options=-c search_path=<schema>`, so everything built from it —
 * `new PostgresStorageAdapter(url)`, `Tzun.init({ dbUrl: url })`, a raw `pg`
 * Pool or Client — creates and reads its tables there and nowhere else. Suites
 * can therefore share one database and run in parallel under jest's default
 * workers: none can see another's chains, seal another's `default` chain, or
 * drop a schema another is using.
 *
 *   - `pgSuiteSchema(label)` — one schema for the suite (or the `describe`
 *     it is called in): created in a `beforeAll`, dropped in an `afterAll`.
 *   - `pgCaseSchema(label)` — one schema for one case, created on the call,
 *     dropped by `drop()`.
 *
 * Between cases, `empty()` deletes every row in the schema and keeps the
 * tables; `reset()` drops the schema's contents altogether, for a case that
 * has to watch `ensureTables()` build the store from nothing. Prefer
 * `empty()`: `ensureTables()` holds an advisory lock that is database-wide,
 * so the Postgres legs of every worker queue on each other's DDL, and on a
 * schema that already has its tables that DDL is a fraction of the cost.
 * `empty()` deletes rather than truncates because TRUNCATE gives every table a
 * new file and syncs it to disk, which on the dev database costs seconds per
 * call where a DELETE of a few test rows costs milliseconds.
 *
 * Running the legs:
 *
 *   createdb -h host.docker.internal -p 55432 -U postgres tzun_sdk_test
 *   RUN_INTEGRATION_TESTS=true \
 *   DATABASE_URL=postgres://postgres:<password>@host.docker.internal:55432/tzun_sdk_test \
 *   npx jest
 *
 * One database serves the whole run; no `--runInBand` is needed. A run that is
 * killed mid-suite can leave `test_*` schemas behind; they hold nothing another
 * run reads, and dropping the database clears them.
 */
import { randomBytes } from 'node:crypto';
import type * as PgModule from 'pg';

// The real driver, even in a file that mocks `pg` for the code under test.
const { Client } = jest.requireActual<typeof PgModule>('pg');

const HELPER_PATH = 'tests/ts/helpers/postgres-test-db.ts';

const RULE =
  'The Postgres legs create, empty and drop schemas in the database they are given, so DATABASE_URL ' +
  `must name a throwaway database whose name ends in "_test" (see ${HELPER_PATH}).`;

/** True when the Postgres legs run: RUN_INTEGRATION_TESTS=true and DATABASE_URL set. */
export const PG_TESTS_ENABLED =
  process.env.RUN_INTEGRATION_TESTS === 'true' && (process.env.DATABASE_URL ?? '') !== '';

/** How long the helper's own hooks may take: a DROP ... CASCADE waits for locks. */
const HOOK_TIMEOUT_MS = 30_000;

/**
 * The database-name rule. Returns the database name `url` names, or throws
 * when it names none, cannot be parsed, or names one that does not end in
 * `_test`.
 */
export function assertThrowawayDatabase(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (err) {
    throw new Error(`DATABASE_URL is not a parseable URL (${(err as Error).message}), and the rule is not guessed at. ${RULE}`);
  }
  const name = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
  if (name === '') {
    throw new Error(`DATABASE_URL names no database. ${RULE}`);
  }
  if (!name.endsWith('_test')) {
    throw new Error(`refusing to run against database "${name}". ${RULE}`);
  }
  return name;
}

const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

/**
 * `url` with every connection made from it pointed at `schema`. Any `options`
 * already on the URL is replaced; every other part is kept.
 */
export function withSearchPath(url: string, schema: string): string {
  if (!IDENTIFIER.test(schema)) {
    throw new Error(`schema "${schema}" is not a plain lower-case identifier, and it is spliced into SQL`);
  }
  const parsed = new URL(url);
  parsed.searchParams.set('options', `-c search_path=${schema}`);
  return parsed.toString();
}

/** A fresh schema name built from `label`: `test_<label>_<10 hex>`, at most 63 bytes. */
export function pgSchemaName(label: string): string {
  const clean =
    label
      .toLowerCase()
      .replace(/[^a-z0-9_]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 40) || 'suite';
  return `test_${clean}_${randomBytes(5).toString('hex')}`;
}

export interface PgTestSchema {
  /** The schema's name — a plain identifier, safe to splice into SQL. */
  readonly name: string;
  /** DATABASE_URL with `search_path` set to this schema. Empty when the legs are off. */
  readonly url: string;
  /**
   * Delete every row in the schema — the append-only tables included, under
   * `session_replication_role = 'replica'` — and restart its sequences. The
   * tables, functions and triggers stay.
   */
  empty(): Promise<void>;
  /** Drop everything in the schema and hand it back empty, under the same name. */
  reset(): Promise<void>;
}

export interface PgCaseSchema extends PgTestSchema {
  /** Drop the schema and everything in it. */
  drop(): Promise<void>;
}

function databaseUrl(): string {
  const url = process.env.DATABASE_URL ?? '';
  assertThrowawayDatabase(url);
  return url;
}

async function onDatabase(sql: string): Promise<void> {
  const client = new Client({ connectionString: databaseUrl(), connectionTimeoutMillis: 10_000 });
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

// One transaction. `replica` switches off every ordinary trigger for it — the
// append-only guards and the foreign-key checks alike — so the tables can be
// emptied in any order.
async function emptyAll(name: string): Promise<void> {
  const client = new Client({ connectionString: databaseUrl(), connectionTimeoutMillis: 10_000 });
  await client.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    const tables = await client.query<{ tablename: string }>(
      'SELECT tablename FROM pg_tables WHERE schemaname = $1',
      [name],
    );
    for (const { tablename } of tables.rows) {
      await client.query(`DELETE FROM ${name}."${tablename}"`);
    }
    const sequences = await client.query<{ sequencename: string }>(
      'SELECT sequencename FROM pg_sequences WHERE schemaname = $1',
      [name],
    );
    for (const { sequencename } of sequences.rows) {
      await client.query(`ALTER SEQUENCE ${name}."${sequencename}" RESTART`);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    await client.end();
  }
}

const create = (name: string): Promise<void> => onDatabase(`CREATE SCHEMA ${name}`);
const drop = (name: string): Promise<void> => onDatabase(`DROP SCHEMA IF EXISTS ${name} CASCADE`);
const recreate = (name: string): Promise<void> =>
  onDatabase(`DROP SCHEMA IF EXISTS ${name} CASCADE; CREATE SCHEMA ${name}`);

async function legsOff(): Promise<never> {
  throw new Error('the Postgres legs are off (RUN_INTEGRATION_TESTS / DATABASE_URL)');
}

/**
 * A schema for the suite, or for the `describe` block this is called in.
 * Call it while the suite is being collected: it registers the `beforeAll`
 * that creates the schema and the `afterAll` that drops it. The URL is usable
 * at once — to build configs and adapters — and connects once the `beforeAll`
 * has run. Jest runs `afterAll` hooks in the order they were declared, nested
 * blocks first, so calling this at the top level of the file is what makes the
 * drop come after every `afterAll` of the suite's own.
 *
 * With the legs off it registers nothing and hands back an empty URL, so a
 * suite may call it unconditionally and gate its cases on `PG_TESTS_ENABLED`.
 */
export function pgSuiteSchema(label: string): PgTestSchema {
  const name = pgSchemaName(label);
  if (!PG_TESTS_ENABLED) {
    return {
      name,
      url: '',
      empty: legsOff,
      reset: legsOff,
    };
  }
  const url = withSearchPath(databaseUrl(), name);
  beforeAll(() => create(name), HOOK_TIMEOUT_MS);
  afterAll(() => drop(name), HOOK_TIMEOUT_MS);
  return { name, url, empty: () => emptyAll(name), reset: () => recreate(name) };
}

/** A schema for one case, created now; the caller drops it with `drop()`. */
export async function pgCaseSchema(label: string): Promise<PgCaseSchema> {
  if (!PG_TESTS_ENABLED) return legsOff();
  const name = pgSchemaName(label);
  const url = withSearchPath(databaseUrl(), name);
  await create(name);
  return { name, url, empty: () => emptyAll(name), reset: () => recreate(name), drop: () => drop(name) };
}
