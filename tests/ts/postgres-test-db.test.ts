/**
 * The Postgres test helper: one gate, one database-name guard,
 * and a schema of its own for every suite.
 *
 * The first half is plain unit tests of the pieces and always runs. The second
 * half proves the isolation against a live database — the property the whole
 * helper exists for — and runs when the Postgres legs do.
 *
 * The last block is a guardrail over the test tree: a suite that reads
 * DATABASE_URL itself, drops the public schema, or carries its own copy of the
 * `_test` rule is how a shared database came back.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { Client, Pool } from 'pg';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import {
  PG_TESTS_ENABLED,
  assertThrowawayDatabase,
  pgCaseSchema,
  pgSchemaName,
  pgSuiteSchema,
  withSearchPath,
} from './helpers/postgres-test-db';

describe('assertThrowawayDatabase — the one `_test` rule', () => {
  it('accepts a database whose name ends in _test, and returns the name', () => {
    expect(assertThrowawayDatabase('postgres://u:p@db.example:55432/tzun_sdk_lane_test')).toBe('tzun_sdk_lane_test');
  });

  it('refuses a database whose name does not end in _test, naming it and the rule', () => {
    expect(() => assertThrowawayDatabase('postgres://u:p@db.example:55432/tzun_dev')).toThrow(
      /refusing to run against database "tzun_dev".*must name a throwaway database whose name ends in "_test"/s,
    );
  });

  it('refuses a name that only contains _test', () => {
    expect(() => assertThrowawayDatabase('postgres://u:p@db.example/tzun_test_copy')).toThrow(/tzun_test_copy/);
  });

  it('refuses a URL naming no database at all', () => {
    expect(() => assertThrowawayDatabase('postgres://u:p@db.example:55432')).toThrow(/names no database/);
  });

  it('refuses a connection string it cannot parse rather than guessing', () => {
    expect(() => assertThrowawayDatabase('host=db.example dbname=tzun_test')).toThrow(/not a parseable URL/);
  });

  it('points the reader at the helper, where the rule is written down', () => {
    expect(() => assertThrowawayDatabase('postgres://u:p@db.example/prod')).toThrow(
      /tests\/ts\/helpers\/postgres-test-db\.ts/,
    );
  });
});

describe('withSearchPath', () => {
  // pg reads `options` from the query string and sends it in the startup
  // message; the live block below proves a connection made this way lands in
  // the schema.
  it('points every connection made from the URL at one schema, and changes nothing else', () => {
    const url = new URL(withSearchPath('postgres://u:p@db.example:55432/tzun_x_test', 'test_a_0123456789'));
    expect(url.searchParams.get('options')).toBe('-c search_path=test_a_0123456789');
    expect(url.pathname).toBe('/tzun_x_test');
    expect(url.host).toBe('db.example:55432');
    expect(url.username).toBe('u');
  });

  it('keeps the query parameters that were there and replaces an existing options', () => {
    const url = new URL(
      withSearchPath('postgres://u:p@db.example/tzun_x_test?sslmode=disable&options=-c%20search_path%3Dpublic', 's1'),
    );
    expect(url.searchParams.getAll('options')).toEqual(['-c search_path=s1']);
    expect(url.searchParams.get('sslmode')).toBe('disable');
  });

  it('refuses a schema name that is not a plain identifier, since it is spliced into SQL', () => {
    expect(() => withSearchPath('postgres://u:p@db.example/tzun_x_test', 'a; DROP SCHEMA public')).toThrow(/identifier/);
  });
});

describe('pgSchemaName', () => {
  it('is a lower-case unquoted identifier within the 63-byte limit, built from the label', () => {
    const name = pgSchemaName('Demo-Tamper Hooks');
    expect(name).toMatch(/^test_demo_tamper_hooks_[0-9a-f]{10}$/);
    expect(pgSchemaName('x'.repeat(200)).length).toBeLessThanOrEqual(63);
    expect(pgSchemaName('x'.repeat(200))).toMatch(/^[a-z_][a-z0-9_]*$/);
  });

  it('never hands two callers the same schema', () => {
    const names = new Set(Array.from({ length: 500 }, () => pgSchemaName('same')));
    expect(names.size).toBe(500);
  });
});

// ── live: the isolation itself ──────────────────────────────────────────────

const suite = pgSuiteSchema('helper_self_test');

// Catalog reads go through a connection on the suite's own URL: the catalog
// sees every schema, whichever one the connection is pointed at.
async function tablesIn(schema: string): Promise<string[]> {
  const admin = new Client({ connectionString: suite.url });
  await admin.connect();
  try {
    const r = await admin.query(
      'SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY table_name',
      [schema],
    );
    return r.rows.map((row: { table_name: string }) => row.table_name);
  } finally {
    await admin.end();
  }
}

async function schemaExists(schema: string): Promise<boolean> {
  const admin = new Client({ connectionString: suite.url });
  await admin.connect();
  try {
    const r = await admin.query('SELECT 1 FROM pg_namespace WHERE nspname = $1', [schema]);
    return r.rowCount === 1;
  } finally {
    await admin.end();
  }
}

(PG_TESTS_ENABLED ? describe : describe.skip)('the helper against a live database', () => {
  jest.setTimeout(30_000);

  it('the suite schema exists before the first case, and a connection made from its URL lands in it', async () => {
    expect(await schemaExists(suite.name)).toBe(true);
    const pool = new Pool({ connectionString: suite.url });
    try {
      const r = await pool.query('SELECT current_schema() AS s');
      expect(r.rows[0].s).toBe(suite.name);
    } finally {
      await pool.end();
    }
  });

  it("an adapter on the suite URL builds its tables in the suite's schema", async () => {
    const adapter = new PostgresStorageAdapter(suite.url);
    try {
      await adapter.ensureTables();
    } finally {
      await adapter.close();
    }
    const tables = await tablesIn(suite.name);
    expect(tables).toEqual(expect.arrayContaining(['chains', 'envelopes', 'chain_state']));
  });

  it('reset() hands the suite back an empty schema of the same name', async () => {
    const adapter = new PostgresStorageAdapter(suite.url);
    await adapter.ensureTables();
    await adapter.close();
    expect((await tablesIn(suite.name)).length).toBeGreaterThan(0);
    await suite.reset();
    expect(await schemaExists(suite.name)).toBe(true);
    expect(await tablesIn(suite.name)).toEqual([]);
  });

  it('empty() removes every row in the schema, append-only tables included, restarts its sequences, and keeps the tables', async () => {
    const adapter = new PostgresStorageAdapter(suite.url);
    const client = new Client({ connectionString: suite.url });
    await client.connect();
    try {
      await adapter.ensureTables();
      const now = new Date().toISOString();
      await adapter.storeChain({ chainId: 'default', createdAt: now, status: 'active' });
      await adapter.sealChain('default', now);
      const sequences = await client.query<{ sequencename: string }>(
        'SELECT sequencename FROM pg_sequences WHERE schemaname = $1',
        [suite.name],
      );
      expect(sequences.rows.length).toBeGreaterThan(0);
      for (const { sequencename } of sequences.rows) await client.query(`SELECT nextval('"${sequencename}"')`);
      const before = await tablesIn(suite.name);

      await suite.empty();

      expect(await adapter.listChains()).toEqual([]);
      expect(await tablesIn(suite.name)).toEqual(before);
      const advanced = await client.query(
        'SELECT sequencename FROM pg_sequences WHERE schemaname = $1 AND last_value IS NOT NULL',
        [suite.name],
      );
      expect(advanced.rows).toEqual([]);
    } finally {
      await client.end();
      await adapter.close();
    }
  });

  it('two schemas in one database do not see each other: a sealed default chain in one is not sealed in the other', async () => {
    const a = await pgCaseSchema('helper_iso_a');
    const b = await pgCaseSchema('helper_iso_b');
    const inA = new PostgresStorageAdapter(a.url);
    const inB = new PostgresStorageAdapter(b.url);
    try {
      await inA.ensureTables();
      await inB.ensureTables();
      const now = new Date().toISOString();
      await inA.storeChain({ chainId: 'default', createdAt: now, status: 'active' });
      await inA.sealChain('default', now);
      expect((await inA.listChains()).map((c) => [c.chainId, c.status])).toEqual([['default', 'sealed']]);
      expect(await inB.listChains()).toEqual([]);
    } finally {
      await inA.close();
      await inB.close();
      await a.drop();
      await b.drop();
    }
  });

  it('drop() removes a case schema and everything in it', async () => {
    const c = await pgCaseSchema('helper_drop');
    const adapter = new PostgresStorageAdapter(c.url);
    await adapter.ensureTables();
    await adapter.close();
    expect(await schemaExists(c.name)).toBe(true);
    await c.drop();
    expect(await schemaExists(c.name)).toBe(false);
  });
});

// ── guardrail over the test tree ────────────────────────────────────────────

const TESTS_ROOT = resolve(__dirname, '..');
const HELPER = 'ts/helpers/postgres-test-db.ts';

/**
 * Files that set DATABASE_URL (or save and restore it) to exercise the SDK's
 * own environment fallback with a fake URL. None of them connects.
 */
const ENV_WIRING_TESTS = new Set([
  'ts/anchoring-refused-at-init.test.ts',
  'ts/mode-fail-closed.test.ts',
  'ts/sdk-postgres-wiring.test.ts',
  'ts/sdk.test.ts',
]);

function testSources(): Array<{ file: string; src: string }> {
  const out: Array<{ file: string; src: string }> = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== 'fixtures') walk(full);
      } else if (entry.name.endsWith('.ts')) {
        out.push({ file: relative(TESTS_ROOT, full), src: readFileSync(full, 'utf8') });
      }
    }
  };
  walk(join(TESTS_ROOT, 'ts'));
  return out;
}

/** Source with comments removed, so a sentence ABOUT a pattern is not the pattern. */
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');
}

describe('guardrail: every Postgres suite takes its schema from the helper', () => {
  const sources = testSources().filter((s) => s.file !== HELPER && s.file !== 'ts/postgres-test-db.test.ts');

  it('found the test tree', () => {
    expect(sources.length).toBeGreaterThan(100);
  });

  it('no test file reads DATABASE_URL except the helper and the SDK env-wiring tests', () => {
    const offenders = sources
      .filter((s) => !ENV_WIRING_TESTS.has(s.file))
      .filter((s) => /process\.env\.DATABASE_URL|process\.env\[['"]DATABASE_URL['"]\]/.test(code(s.src)))
      .map((s) => s.file);
    expect(offenders).toEqual([]);
  });

  it('no test file drops or recreates the public schema', () => {
    const offenders = sources.filter((s) => /\b(DROP|CREATE)\s+SCHEMA\s+(IF\s+EXISTS\s+)?public\b/i.test(code(s.src)));
    expect(offenders.map((s) => s.file)).toEqual([]);
  });

  it('the `_test` database rule is written once, in the helper', () => {
    const offenders = sources.filter((s) => /endsWith\(\s*['"`]_test['"`]\s*\)/.test(code(s.src)));
    expect(offenders.map((s) => s.file)).toEqual([]);
  });
});
