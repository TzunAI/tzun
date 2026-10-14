/**
 * Append-only enforcement — the SQL the adapter installs.
 *
 * Two layers, because only one of them can run without a database.
 *
 * 1. This file — no database needed. Asserts that `ensureTables()` actually
 *    issues each guard, against a mocked `pg`. This is the layer CI runs.
 * 2. `storage-postgres-append-only-live.test.ts` — runs when the Postgres legs
 *    do. Executes the attack statements and the legitimate ones against a real
 *    server, which is the only way to know the plpgsql is right. It lives in a
 *    file of its own because this one mocks `pg` for every module it loads,
 *    the adapter included.
 *
 * Each guard asserted here refuses a statement that succeeds against a schema
 * without it (checked against PostgreSQL 16.13).
 */
import { PostgresStorageAdapter } from '../../src/storage/postgres';

jest.mock('pg', () => {
  const mockClient = {
    query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    release: jest.fn(),
  };
  const mockPool = {
    query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    connect: jest.fn().mockResolvedValue(mockClient),
    end: jest.fn().mockResolvedValue(undefined),
  };
  return { Pool: jest.fn(() => mockPool), __mockPool: mockPool, __mockClient: mockClient };
});

const { __mockClient: mockClient } = jest.requireMock('pg');

async function ddlIssuedByEnsureTables(): Promise<string> {
  mockClient.query.mockClear();
  const adapter = new PostgresStorageAdapter('postgres://unused/unused');
  await adapter.ensureTables();
  return mockClient.query.mock.calls
    .map((c: unknown[]) => c[0])
    .filter((q: unknown): q is string => typeof q === 'string')
    .join('\n');
}

describe('append-only DDL', () => {
  let ddl: string;

  beforeAll(async () => {
    ddl = await ddlIssuedByEnsureTables();
  });

  // The gap that matters most: PostgreSQL does not fire ON DELETE triggers on
  // TRUNCATE. With only the row-level DELETE trigger, `TRUNCATE envelopes`
  // empties the whole evidence table and no trigger runs (a live 16.13
  // answers `TRUNCATE TABLE`).
  it('installs a statement-level TRUNCATE blocker on envelopes', () => {
    expect(ddl).toContain('BEFORE TRUNCATE ON envelopes');
    expect(ddl).toContain('FOR EACH STATEMENT');
    expect(ddl).toContain('envelopes_block_truncate');
  });

  // Rewriting chain_id moves a record out of every chain-scoped read without
  // touching a single hashed byte, so no digest check notices.
  it('makes chain_id and ai_system_id immutable', () => {
    expect(ddl).toContain('OLD.chain_id IS DISTINCT FROM NEW.chain_id');
    expect(ddl).toContain('envelopes.chain_id is immutable');
    expect(ddl).toContain('OLD.ai_system_id IS DISTINCT FROM NEW.ai_system_id');
    expect(ddl).toContain('envelopes.ai_system_id is immutable');
  });

  // custodyChain may only grow. A guard that merely lets it change would let
  // one UPDATE truncate it to [] or rewrite an actor.
  it('makes custodyChain append-only rather than merely mutable', () => {
    expect(ddl).toContain("envelope->'custodyChain'");
    expect(ddl).toContain('jsonb_array_length');
    expect(ddl).toContain('custodyChain is append-only');
  });

  // The recovery records — who annotated or re-linked what — are append-only,
  // as the hosted service's `recoveries` table is.
  it('makes chain_annotations and chain_relinks append-only, TRUNCATE included', () => {
    for (const table of ['chain_annotations', 'chain_relinks']) {
      expect(ddl).toContain(`BEFORE UPDATE OR DELETE ON ${table}`);
      expect(ddl).toContain(`BEFORE TRUNCATE ON ${table}`);
      expect(ddl).toContain(`DROP TRIGGER IF EXISTS ${table}_block_mutation_trigger ON ${table}`);
    }
  });

  // Containment (`NEW @> OLD`) is a subset test, so it would let an existing
  // custody entry gain keys in place — an unhashed entry given an entryHash.
  // Existing entries are compared exactly, and an appended entry that carries
  // an entryHash must be a custody_entries row for the record.
  it('compares existing custody entries exactly, and checks appended hashes against the ledger', () => {
    expect(ddl).not.toContain("@> COALESCE(OLD.envelope->'custodyChain'");
    expect(ddl).toContain('jsonb_array_elements(v_new_custody) WITH ORDINALITY');
    expect(ddl).toContain("e ? 'entryHash'");
    expect(ddl).toContain('entryHash with no custody_entries row');
  });

  // `EvidenceEnvelope.integrity` is `{ canonicalDigest,
  // chainLink }`; a predicate on `integrity.schemaVersion` would compare NULL
  // with NULL on every row and guard nothing. The schema version lives in the
  // payload, which the payload predicate freezes whole.
  it('checks no field the envelope does not have', () => {
    expect(ddl).not.toContain("'integrity'->>'schemaVersion'");
    expect(ddl).toContain("OLD.envelope->'payload' IS DISTINCT FROM NEW.envelope->'payload'");
  });

  // The model_descriptors catalog gets an immutability trigger and DELETE and
  // TRUNCATE blockers. Without them a plain UPDATE rewrites canonical_bytes,
  // with no bypass needed.
  it('protects the model_descriptors catalog', () => {
    expect(ddl).toContain('model_descriptors_enforce_immutable');
    expect(ddl).toContain('model_descriptors.canonical_bytes is immutable');
    expect(ddl).toContain('BEFORE DELETE ON model_descriptors');
    expect(ddl).toContain('BEFORE TRUNCATE ON model_descriptors');
  });

  // A BIGSERIAL column takes an explicit id, and these four
  // tables are read in id order: one INSERT at credential_events seq 0 would
  // put another key on a registered credential. Each gets a guard that refuses an
  // id its sequence did not hand the insert, or one below an id already
  // committed, then gives the row an id drawn as it is written. STABLE, so it
  // reads the INSERT statement's snapshot and never refuses an id drawn before
  // a higher one committed. It finds the table and its sequence through
  // TG_TABLE_SCHEMA and TG_TABLE_NAME and pins its search_path, so the
  // inserting session's temp tables and search_path are not what it reads.
  // The live half is postgres-backdated-id-guards.test.ts.
  const GUARD_LANGUAGE = '$$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp;';
  it.each([
    ['credential_events', 'seq', 'credential_events_block_backdated_seq'],
    ['custody_entries', 'id', 'custody_entries_block_backdated_id'],
    ['logs', 'log_id', 'logs_block_backdated_id'],
    ['anchor_publications', 'id', 'anchor_publications_block_backdated_id'],
  ])('refuses a row written ahead of the rows it follows on %s', (table, column, fn) => {
    const start = ddl.indexOf(`CREATE OR REPLACE FUNCTION ${fn}()`);
    expect(start).toBeGreaterThanOrEqual(0);
    const end = ddl.indexOf('$$ LANGUAGE plpgsql', start);
    const body = ddl.slice(start, end);
    expect(body).toContain("v_table TEXT := format('%I.%I', TG_TABLE_SCHEMA, TG_TABLE_NAME);");
    expect(body).toContain(`v_seq TEXT := pg_get_serial_sequence(v_table, '${column}');`);
    expect(body).toContain(`EXECUTE format('SELECT MAX(%I) FROM %s', '${column}', v_table) INTO v_last;`);
    expect(body).toContain(`IF NEW.${column} < v_last THEN`);
    expect(body).toContain('v_drawn := currval(v_seq);');
    expect(body).toContain(`NEW.${column} := nextval(v_seq);`);
    // No name the inserting session resolves: the table is named only in messages.
    expect(body).not.toMatch(new RegExp(`FROM ${table}\\b|pg_get_serial_sequence\\('${table}'`));
    expect(ddl.slice(end, end + GUARD_LANGUAGE.length)).toBe(GUARD_LANGUAGE);
    expect(ddl).toMatch(new RegExp(`CREATE TRIGGER ${fn}_trigger\\s+BEFORE INSERT ON ${table}\\s+FOR EACH ROW EXECUTE FUNCTION ${fn}\\(\\)`));
  });

  // A trigger function runs with the search_path of the session
  // whose statement fired it, so a table it names bare is whatever that
  // session resolves the name to: a temporary table, or one in a schema it
  // put first. Every function is created with its search_path pinned, and
  // names each table through the schema of its trigger's table in a statement
  // it runs with EXECUTE. The live half is postgres-trigger-search-path.test.ts.
  it('creates every function with its search_path pinned, and names no table of the store bare in one', () => {
    const tables = [...ddl.matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map((m) => m[1]);
    expect(tables).toEqual(expect.arrayContaining(['envelopes', 'custody_entries', 'credential_events', 'logs', 'log_leaves', 'store_identity']));
    // A table named after FROM, JOIN, INTO or UPDATE, after a comma (a join
    // list), or cast as a string to regclass.
    const names = tables.join('|');
    const bare = new RegExp(`(?:\\b(?:FROM|JOIN|INTO|UPDATE)\\s+|,\\s*)(?:${names})\\b|'(?:${names})'::regclass`, 'i');
    for (const body of ['PERFORM 1 FROM logs;', 'SELECT 1 FROM x a, logs b;', "SELECT 'logs'::regclass;", 'UPDATE logs SET x = 1;']) {
      expect([body, bare.test(body)]).toEqual([body, true]);
    }
    for (const body of ['PERFORM 1 FROM %1$I.logs;', 'SELECT 1 FROM %1$I.x a, %1$I.logs b;', 'SELECT logsx FROM v;']) {
      expect([body, bare.test(body)]).toEqual([body, false]);
    }
    const functions = [...ddl.matchAll(/CREATE OR REPLACE FUNCTION (\w+)\(([\s\S]*?)\$\$([\s\S]*?)\$\$([^;]*);/g)];
    expect(functions.length).toBeGreaterThan(30);
    const unpinned = functions.filter(([, , header, , tail]) => !`${header} ${tail}`.includes('SET search_path = pg_catalog, pg_temp'));
    expect(unpinned.map(([, name]) => name)).toEqual([]);
    const naming = functions.filter(([, , , body]) => bare.test(body));
    expect(naming.map(([, name, , body]) => `${name}: ${body.match(bare)![0]}`)).toEqual([]);
    // The custody hash computes without a helper function, and the DDL drops
    // the helper a store set up by an earlier version may still hold.
    expect(ddl).toContain('DROP FUNCTION IF EXISTS custody_entries_length_prefix(TEXT);');
    expect(ddl).not.toContain('CREATE OR REPLACE FUNCTION custody_entries_length_prefix');
  });
});
