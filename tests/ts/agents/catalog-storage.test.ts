/**
 * The agent catalog as a storage extension (src/storage/ddl/agents.ts,
 * src/storage/agent-sql.ts) on the memory, SQLite and
 * Postgres adapters: registration under the descriptor's digest, idempotent
 * on identical bytes; the grammar and writer limits; reads; paged listing in
 * registration order; immutable rows.
 */
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type Database from 'better-sqlite3';
import { Client } from 'pg';
import {
  AGENT_DESCRIPTOR_MAX_ATTESTATION,
  AGENT_DESCRIPTOR_MAX_SET,
  AGENT_DESCRIPTOR_MAX_STRING,
  InvalidPaginationError,
  SchemaRegistry,
  agentDescriptorDigest,
} from '@tzun/engine';
import type { AgentDescriptor, StorageAdapter } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../../src/storage/memory';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';
import { VerifyingStorageProxy } from '../../../src/monitoring/storage-proxy';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import { agentsStorageExtension } from '../../../src/storage/ddl/agents';
import {
  AGENT_CATALOG_LOCK_KEY,
  AGENT_LIST_MAX_LIMIT,
  AgentDescriptorConflictError,
  InvalidAgentDescriptorError,
  agentDescriptorWrite,
  createMemoryAgentCatalog,
  memoryAgentMethods,
  prefixedSha256,
} from '../../../src/storage/agent-sql';
import type { StorageExtension } from '../../../src/storage/extensions';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';
import { X12, descriptorNamed, vectorDescriptors } from './fixtures';

type Catalog = Required<Pick<StorageAdapter, 'putAgentDescriptor' | 'getAgentDescriptor' | 'listAgentDescriptors'>>;

interface Leg {
  name: 'memory' | 'sqlite' | 'postgres';
  open(extensions: StorageExtension[]): Promise<StorageAdapter>;
}

const dir = mkdtempSync(join(tmpdir(), 'tzun-test-agent-catalog-'));
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

let n = 0;
const pg = pgSuiteSchema('agent_catalog');
const legs: Leg[] = [
  { name: 'memory', open: async (extensions) => new MemoryStorageAdapter({ extensions }) },
  { name: 'sqlite', open: async (extensions) => new SqliteStorageAdapter(join(dir, `agents-${++n}.db`), { extensions }) },
  ...(PG_TESTS_ENABLED
    ? [
        {
          name: 'postgres' as const,
          open: async (extensions: StorageExtension[]) => {
            await pg.reset();
            const adapter = new PostgresStorageAdapter(pg.url, undefined, { extensions });
            await adapter.ensureTables();
            return adapter;
          },
        },
      ]
    : []),
];

const EXTENSIONS = [decidersExtension, agentsStorageExtension];

describe.each(legs)('the agent catalog on $name', (leg) => {
  let adapter: StorageAdapter;
  let catalog: Catalog;

  beforeEach(async () => {
    adapter = await leg.open(EXTENSIONS);
    catalog = adapter as unknown as Catalog;
  });
  afterEach(async () => {
    await adapter.close?.();
  });

  it('has the three catalog methods exactly when the extension is installed', async () => {
    for (const method of ['putAgentDescriptor', 'getAgentDescriptor', 'listAgentDescriptors'] as const) {
      expect(typeof adapter[method]).toBe('function');
    }
    const without = await leg.open([decidersExtension]);
    try {
      expect(typeof without.putAgentDescriptor).toBe('undefined');
      expect(typeof without.getAgentDescriptor).toBe('undefined');
      expect(typeof without.listAgentDescriptors).toBe('undefined');
    } finally {
      await without.close?.();
    }
  });

  it('registers each vector descriptor under its digest, as its canonical bytes, idempotently', async () => {
    for (const v of vectorDescriptors()) {
      const first = await catalog.putAgentDescriptor(v.descriptor);
      expect(first).toEqual({ digest: v.digest, alreadyExisted: false });
      const again = await catalog.putAgentDescriptor(v.descriptor);
      expect(again).toEqual({ digest: v.digest, alreadyExisted: true });
      const row = await catalog.getAgentDescriptor(v.digest);
      expect(row).toMatchObject({
        digest: v.digest,
        canonicalBytes: v.canonical,
        name: v.descriptor.name,
        organization: v.descriptor.operator.organization,
        parent: v.descriptor.parent,
      });
      expect(row!.registeredAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(Buffer.byteLength(row!.canonicalBytes, 'utf8')).toBe(v.byteLength);
      expect(prefixedSha256(row!.canonicalBytes)).toBe(v.digest);
    }
  });

  it('gives a descriptor whose sets arrive in another order the same digest and row', async () => {
    const sorted = { ...X12, identities: ['spiffe://a.example/x', 'spiffe://b.example/y'] };
    const reversed = { ...sorted, identities: [...sorted.identities].reverse() };
    const a = await catalog.putAgentDescriptor(sorted);
    const b = await catalog.putAgentDescriptor(reversed);
    expect(b).toEqual({ digest: a.digest, alreadyExisted: true });
    expect(a.digest).toBe(agentDescriptorDigest(reversed));
  });

  it('refuses a descriptor that breaks the grammar or a writer limit, and stores nothing', async () => {
    const long = (units: number) => 'a'.repeat(units);
    const key = (kid: string, attestation: string | null = null) => ({ kid, alg: 'EdDSA' as const, custody: 'software' as const, attestation });
    const kid = (i: number) => i.toString(36).padStart(43, 'A');
    const cases: Array<[string, unknown]> = [
      ['not an object', 'agent'],
      ['an unknown member', { ...X12, extra: true }],
      ['a missing member', (({ parent: _p, ...rest }) => rest)(X12)],
      ['another version', { ...X12, v: 'tzun-agent/2' }],
      ['an empty name', { ...X12, name: '' }],
      ['a repeated identity', { ...X12, identities: ['spiffe://x', 'spiffe://x'] }],
      ['a repeated kid', { ...X12, keys: [key(kid(1)), key(kid(1), 'tpm')] }],
      ['a bare model digest', { ...X12, models: ['6c'.repeat(32)] }],
      ['a model set with an uppercase digest', { ...X12, models: [`sha256:${'AB'.repeat(32)}`] }],
      ['an unknown derivation', { ...X12, derivation: 'copy' }],
      [`${AGENT_DESCRIPTOR_MAX_SET + 1} identities`, { ...X12, identities: Array.from({ length: AGENT_DESCRIPTOR_MAX_SET + 1 }, (_, i) => `spiffe://x/${i}`) }],
      [`${AGENT_DESCRIPTOR_MAX_SET + 1} keys`, { ...X12, keys: Array.from({ length: AGENT_DESCRIPTOR_MAX_SET + 1 }, (_, i) => key(kid(i))) }],
      ['a name over the string limit', { ...X12, name: long(AGENT_DESCRIPTOR_MAX_STRING + 1) }],
      ['an organization over the string limit', { ...X12, operator: { ...X12.operator, organization: long(AGENT_DESCRIPTOR_MAX_STRING + 1) } }],
      ['an attestation over its limit', { ...X12, keys: [key(kid(1), long(AGENT_DESCRIPTOR_MAX_ATTESTATION + 1))] }],
      ['a lone surrogate', { ...X12, name: 'agent\ud800' }],
      ['U+0000 in the name', { ...X12, name: 'agent\u0000x' }],
      ['U+0000 in the organization', { ...X12, operator: { ...X12.operator, organization: 'Org\u0000' } }],
      ['an identities set with a hole', { ...X12, identities: [, 'spiffe://a/1'] }],
      ['a models set with a hole', { ...X12, models: [, ...X12.models] }],
      ['a keys set with a hole', { ...X12, keys: [, key(kid(1))] }],
      ['measurements with a hole', { ...X12, runtime: { format: 'oci', measurements: [, 'm1'] } }],
      ['a value with no JSON form (a BigInt)', { ...X12, name: BigInt(1) }],
      ['a value with no JSON form (a cycle)', (() => { const d: Record<string, unknown> = { ...X12 }; d.self = d; return d; })()],
      [
        'canonical bytes over 16 KiB',
        { ...X12, keys: Array.from({ length: 3 }, (_, i) => key(kid(i), long(AGENT_DESCRIPTOR_MAX_ATTESTATION))) },
      ],
    ];
    for (const [label, descriptor] of cases) {
      const refused = catalog.putAgentDescriptor(descriptor as AgentDescriptor);
      await expect(refused).rejects.toBeInstanceOf(InvalidAgentDescriptorError);
      await expect(catalog.putAgentDescriptor(descriptor as AgentDescriptor)).rejects.toMatchObject({
        code: 'invalid_agent_descriptor',
        field: 'descriptor',
      });
      expect([label, (await catalog.listAgentDescriptors()).rows]).toEqual([label, []]);
    }
    // At the limits, accepted.
    const atLimits = {
      ...X12,
      name: long(AGENT_DESCRIPTOR_MAX_STRING),
      identities: Array.from({ length: AGENT_DESCRIPTOR_MAX_SET }, (_, i) => `spiffe://x/${String(i).padStart(3, '0')}`),
      keys: [key(kid(1), long(AGENT_DESCRIPTOR_MAX_ATTESTATION))],
    };
    await expect(catalog.putAgentDescriptor(atLimits)).resolves.toMatchObject({ alreadyExisted: false });
  });

  it('reads each member of the descriptor once, and stores what it checked', async () => {
    let reads = 0;
    const shifting = { ...X12 } as Record<string, unknown>;
    // Answers a short name on its first read and a name over the writer limit after.
    Object.defineProperty(shifting, 'name', { enumerable: true, get: () => (++reads > 1 ? 'x'.repeat(5000) : 'shifting-agent') });
    const { digest } = await catalog.putAgentDescriptor(shifting as unknown as AgentDescriptor);
    expect(reads).toBe(1);
    const row = await catalog.getAgentDescriptor(digest);
    expect(row!.name).toBe('shifting-agent');
    expect(JSON.parse(row!.canonicalBytes).name).toBe('shifting-agent');
    expect(digest).toBe(agentDescriptorDigest({ ...X12, name: 'shifting-agent' }));
  });

  it('keeps a descriptor\'s parent in its lookup column', async () => {
    const parent = `sha256:${'cd'.repeat(32)}`;
    const child = { ...X12, parent, derivation: 'revision' as const };
    const { digest } = await catalog.putAgentDescriptor(child);
    expect(await catalog.getAgentDescriptor(digest)).toMatchObject({ digest, parent });
    expect((await catalog.listAgentDescriptors()).rows.map((r) => r.parent)).toEqual([parent]);
  });

  it('answers null for a digest it does not hold or one that is not a digest', async () => {
    await catalog.putAgentDescriptor(X12);
    expect(await catalog.getAgentDescriptor(`sha256:${'0'.repeat(64)}`)).toBeNull();
    expect(await catalog.getAgentDescriptor('eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f')).toBeNull();
    expect(await catalog.getAgentDescriptor(`SHA256:${'0'.repeat(64)}`)).toBeNull();
    expect(await catalog.getAgentDescriptor("sha256:' OR 1=1 --")).toBeNull();
  });

  it('lists in registration order, filtered by name and organization, a page at a time', async () => {
    const registered: string[] = [];
    for (let i = 0; i < 7; i++) {
      const d = descriptorNamed(i % 2 === 0 ? 'triage' : 'review', i < 4 ? 'Org A' : 'Org B', i);
      registered.push((await catalog.putAgentDescriptor(d)).digest);
    }
    const all = await catalog.listAgentDescriptors();
    expect(all.rows.map((r) => r.digest)).toEqual(registered);
    expect(all.cursor).toBeNull();

    const pages: string[][] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await catalog.listAgentDescriptors({ limit: 3, ...(cursor !== undefined && { cursor }) });
      pages.push(page.rows.map((r) => r.digest));
      if (page.cursor === null) break;
      cursor = page.cursor;
    }
    expect(pages).toEqual([registered.slice(0, 3), registered.slice(3, 6), registered.slice(6)]);

    // A page that ends exactly at the last row says no row follows.
    const exact = await catalog.listAgentDescriptors({ limit: 7 });
    expect(exact.rows).toHaveLength(7);
    expect(exact.cursor).toBeNull();

    const triage = await catalog.listAgentDescriptors({ name: 'triage' });
    expect(triage.rows.map((r) => r.digest)).toEqual([registered[0], registered[2], registered[4], registered[6]]);
    const orgB = await catalog.listAgentDescriptors({ organization: 'Org B' });
    expect(orgB.rows.map((r) => r.digest)).toEqual(registered.slice(4));
    expect((await catalog.listAgentDescriptors({ name: 'review', organization: 'Org B' })).rows.map((r) => r.digest)).toEqual([registered[5]]);
    const both = await catalog.listAgentDescriptors({ name: 'triage', organization: 'Org B', limit: 1 });
    expect(both.rows.map((r) => r.digest)).toEqual([registered[4]]);
    expect(both.cursor).not.toBeNull();
    const next = await catalog.listAgentDescriptors({ name: 'triage', organization: 'Org B', limit: 1, cursor: both.cursor! });
    expect(next.rows.map((r) => r.digest)).toEqual([registered[6]]);
    expect(next.cursor).toBeNull();
    expect(await catalog.listAgentDescriptors({ name: 'nobody' })).toEqual({ rows: [], cursor: null });
    // A registration made while a caller pages is on a later page, never skipped.
    const first = await catalog.listAgentDescriptors({ limit: 3 });
    const late = (await catalog.putAgentDescriptor(descriptorNamed('triage', 'Org A', 99))).digest;
    const rest = await catalog.listAgentDescriptors({ cursor: first.cursor! });
    expect(rest.rows.map((r) => r.digest)).toEqual([...registered.slice(3), late]);
  });

  it('refuses a limit or cursor it cannot use', async () => {
    for (const limit of [0, -1, AGENT_LIST_MAX_LIMIT + 1, 1.5, Number.NaN, '10']) {
      await expect(catalog.listAgentDescriptors({ limit: limit as number })).rejects.toBeInstanceOf(InvalidPaginationError);
    }
    // '9999999999999999' has 16 digits but is above 2^53: it would page from a rounded value.
    for (const cursor of ['', '0', '-1', 'abc', '1e3', ' 1', '9999999999999999', '99999999999999999', 7]) {
      await expect(catalog.listAgentDescriptors({ cursor: cursor as string })).rejects.toBeInstanceOf(InvalidPaginationError);
    }
    await expect(catalog.listAgentDescriptors({ name: 7 as unknown as string })).rejects.toBeInstanceOf(TypeError);
    await expect(catalog.listAgentDescriptors({ limit: AGENT_LIST_MAX_LIMIT })).resolves.toEqual({ rows: [], cursor: null });
  });

  it('is forwarded by the verifying proxy', async () => {
    const proxy: StorageAdapter = new VerifyingStorageProxy(adapter, null, new SchemaRegistry());
    const { digest } = await proxy.putAgentDescriptor!(X12);
    expect((await proxy.getAgentDescriptor!(digest))?.canonicalBytes).toBe((await catalog.getAgentDescriptor(digest))?.canonicalBytes);
    expect((await proxy.listAgentDescriptors!()).rows).toHaveLength(1);
  });
});

describe('agent catalog rows are immutable', () => {
  it('SQLite refuses an UPDATE or a DELETE, and a digest that is not one', async () => {
    const adapter = new SqliteStorageAdapter(join(dir, `immutable-${++n}.db`), { extensions: EXTENSIONS });
    try {
      const { digest } = await adapter.putAgentDescriptor!(X12);
      const db = (adapter as unknown as { db: Database.Database }).db;
      expect(() => db.prepare("UPDATE agent_descriptors SET name = 'other' WHERE digest = ?").run(digest)).toThrow(/immutable \(UPDATE refused\)/);
      expect(() => db.prepare('DELETE FROM agent_descriptors WHERE digest = ?').run(digest)).toThrow(/immutable \(DELETE refused\)/);
      const insert = db.prepare(
        "INSERT INTO agent_descriptors (digest, canonical_bytes, name, organization, parent, registered_at, seq) VALUES (?, '{}', 'n', 'o', NULL, 't', 99)",
      );
      for (const bad of [`sha256:${'A'.repeat(64)}`, `sha256:${'0'.repeat(63)}`, `sha512:${'0'.repeat(64)}`, '0'.repeat(71)]) {
        expect(() => insert.run(bad)).toThrow(/CHECK constraint failed/);
      }
      expect((await adapter.getAgentDescriptor!(digest))?.name).toBe(X12.name);
    } finally {
      await adapter.close();
    }
  });

  it('SQLite refuses an INSERT over an existing row, whatever its conflict clause, and a negative rowid', async () => {
    const adapter = new SqliteStorageAdapter(join(dir, `replace-${++n}.db`), { extensions: EXTENSIONS });
    try {
      const x = await adapter.putAgentDescriptor!(X12);
      const y = await adapter.putAgentDescriptor!(descriptorNamed('other', 'Org', 1));
      const before = [await adapter.getAgentDescriptor!(x.digest), await adapter.getAgentDescriptor!(y.digest)];
      const db = (adapter as unknown as { db: Database.Database }).db;
      const columns = '(digest, canonical_bytes, name, organization, parent, registered_at, seq)';
      const zero = `sha256:${'0'.repeat(64)}`;
      const attempts: Array<[string, unknown[]]> = [
        // The same digest, other bytes.
        [`INSERT OR REPLACE INTO agent_descriptors ${columns} VALUES (?, '{"forged":true}', 'n', 'o', NULL, 't', 99)`, [x.digest]],
        [`REPLACE INTO agent_descriptors ${columns} VALUES (?, '{"forged":true}', 'n', 'o', NULL, 't', 99)`, [x.digest]],
        // Another digest, the seq row y holds: REPLACE would delete y.
        [`INSERT OR REPLACE INTO agent_descriptors ${columns} VALUES (?, '{}', 'n', 'o', NULL, 't', 2)`, [zero]],
        // Another digest, the rowid row x holds.
        [`INSERT OR REPLACE INTO agent_descriptors (rowid, digest, canonical_bytes, name, organization, parent, registered_at, seq) VALUES (1, ?, '{}', 'n', 'o', NULL, 't', 99)`, [zero]],
        [`INSERT OR IGNORE INTO agent_descriptors ${columns} VALUES (?, '{"forged":true}', 'n', 'o', NULL, 't', 99)`, [x.digest]],
      ];
      for (const [sql, params] of attempts) {
        expect(() => db.prepare(sql).run(...params)).toThrow(/\[tzun:duplicate_record\] agent_descriptors rows are immutable \(INSERT over an existing row refused\)/);
      }
      expect(() =>
        db.prepare(`INSERT INTO agent_descriptors (rowid, digest, canonical_bytes, name, organization, parent, registered_at, seq) VALUES (-5, ?, '{}', 'n', 'o', NULL, 't', 99)`).run(zero),
      ).toThrow(/a rowid cannot be negative/);
      expect([await adapter.getAgentDescriptor!(x.digest), await adapter.getAgentDescriptor!(y.digest)]).toEqual(before);
      expect(await adapter.getAgentDescriptor!(zero)).toBeNull();
      // Registration still numbers past every row.
      const z = await adapter.putAgentDescriptor!(descriptorNamed('third', 'Org', 3));
      expect((await adapter.listAgentDescriptors!()).rows.map((r) => r.digest)).toEqual([x.digest, y.digest, z.digest]);
    } finally {
      await adapter.close();
    }
  });

  it('a row rewritten around the triggers is refused on registration (AgentDescriptorConflictError)', async () => {
    const adapter = new SqliteStorageAdapter(join(dir, `conflict-${++n}.db`), { extensions: EXTENSIONS });
    try {
      const { digest } = await adapter.putAgentDescriptor!(X12);
      const db = (adapter as unknown as { db: Database.Database }).db;
      db.exec('DROP TRIGGER agent_descriptors_block_update');
      db.prepare("UPDATE agent_descriptors SET canonical_bytes = replace(canonical_bytes, 'claims-triage-agent', 'other') WHERE digest = ?").run(digest);
      await expect(adapter.putAgentDescriptor!(X12)).rejects.toBeInstanceOf(AgentDescriptorConflictError);
      await expect(adapter.putAgentDescriptor!(X12)).rejects.toMatchObject({ code: 'agent_descriptor_conflict', digest });
    } finally {
      await adapter.close();
    }
    const state = createMemoryAgentCatalog();
    const methods = memoryAgentMethods(state);
    const { digest } = await methods.putAgentDescriptor!(X12);
    state.byDigest.get(digest)!.canonicalBytes = '{}';
    await expect(methods.putAgentDescriptor!(X12)).rejects.toBeInstanceOf(AgentDescriptorConflictError);
  });

  (PG_TESTS_ENABLED ? it : it.skip)('Postgres refuses an UPDATE, a DELETE, a TRUNCATE, and a row whose bytes do not hash to its digest', async () => {
    await pg.reset();
    const adapter = new PostgresStorageAdapter(pg.url, undefined, { extensions: EXTENSIONS });
    const client = new Client({ connectionString: pg.url });
    await client.connect();
    try {
      await adapter.ensureTables();
      const { digest } = await adapter.putAgentDescriptor!(X12);
      await expect(client.query("UPDATE agent_descriptors SET name = 'other' WHERE digest = $1", [digest])).rejects.toThrow(/immutable \(UPDATE refused\)/);
      await expect(client.query('DELETE FROM agent_descriptors WHERE digest = $1', [digest])).rejects.toThrow(/immutable \(DELETE refused\)/);
      await expect(client.query('TRUNCATE agent_descriptors')).rejects.toThrow(/immutable \(TRUNCATE refused\)/);
      await expect(
        client.query(
          "INSERT INTO agent_descriptors (digest, canonical_bytes, name, organization, parent, registered_at) VALUES ($1, '{}', 'n', 'o', NULL, NOW())",
          [`sha256:${'0'.repeat(64)}`],
        ),
      ).rejects.toThrow(/agent_descriptors_digest_hashes_bytes/);
      // The CHECK hashes the UTF-8 bytes: the non-ASCII vector's row is accepted as the adapter wrote it.
      const nonAscii = vectorDescriptors()[2];
      await expect(adapter.putAgentDescriptor!(nonAscii.descriptor)).resolves.toEqual({ digest: nonAscii.digest, alreadyExisted: false });
      // Opening the store again runs the DDL again over the rows it holds.
      const reopened = new PostgresStorageAdapter(pg.url, undefined, { extensions: EXTENSIONS });
      await reopened.ensureTables();
      expect((await reopened.listAgentDescriptors!()).rows.map((r) => r.digest)).toEqual([digest, nonAscii.digest]);
      await reopened.close();
    } finally {
      await client.end();
      await adapter.close();
    }
  });

  (PG_TESTS_ENABLED ? it : it.skip)('Postgres numbers registrations in the order they commit: one waits for another in progress', async () => {
    await pg.reset();
    const adapter = new PostgresStorageAdapter(pg.url, undefined, { extensions: EXTENSIONS });
    const client = new Client({ connectionString: pg.url });
    await client.connect();
    try {
      await adapter.ensureTables();
      await adapter.putAgentDescriptor!(X12);
      // A registration in progress: it holds the catalog lock and has drawn its seq, uncommitted.
      const write = agentDescriptorWrite(descriptorNamed('early', 'Org', 900));
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock($1)', [AGENT_CATALOG_LOCK_KEY]);
      await client.query(
        'INSERT INTO agent_descriptors (digest, canonical_bytes, name, organization, parent, registered_at) VALUES ($1, $2, $3, $4, NULL, NOW())',
        [write.digest, write.canonicalBytes, write.name, write.organization],
      );
      let lateDone = false;
      const late = adapter.putAgentDescriptor!(descriptorNamed('late', 'Org', 901)).then((r) => {
        lateDone = true;
        return r;
      });
      await new Promise((resolve) => setTimeout(resolve, 300));
      // The later registration waits: a pager sees neither row yet.
      expect(lateDone).toBe(false);
      const page = await adapter.listAgentDescriptors!({ limit: 1 });
      expect(page.rows.map((r) => r.name)).toEqual([X12.name]);
      expect(page.cursor).toBeNull();
      await client.query('COMMIT');
      await late;
      expect((await adapter.listAgentDescriptors!()).rows.map((r) => r.name)).toEqual([X12.name, 'early', 'late']);
      // Identical registrations in parallel: one writes, the rest find it.
      const again = await Promise.all(Array.from({ length: 8 }, () => adapter.putAgentDescriptor!(descriptorNamed('same', 'Org', 7))));
      expect(again.filter((r) => !r.alreadyExisted)).toHaveLength(1);
      expect((await adapter.listAgentDescriptors!()).rows).toHaveLength(4);
    } finally {
      await client.query('ROLLBACK').catch(() => undefined);
      await client.end();
      await adapter.close();
    }
  });

  it('SQLite keeps its rows and their order across a reopen', async () => {
    const path = join(dir, `reopen-${++n}.db`);
    const first = new SqliteStorageAdapter(path, { extensions: EXTENSIONS });
    const a = await first.putAgentDescriptor!(descriptorNamed('a', 'Org', 1));
    const b = await first.putAgentDescriptor!(descriptorNamed('b', 'Org', 2));
    await first.close();
    const second = new SqliteStorageAdapter(path, { extensions: EXTENSIONS });
    try {
      const c = await second.putAgentDescriptor!(descriptorNamed('c', 'Org', 3));
      expect((await second.listAgentDescriptors!()).rows.map((r) => r.digest)).toEqual([a.digest, b.digest, c.digest]);
      expect(await second.putAgentDescriptor!(descriptorNamed('a', 'Org', 1))).toEqual({ digest: a.digest, alreadyExisted: true });
    } finally {
      await second.close();
    }
  });
});

describe('the vectors file', () => {
  it('holds the example descriptor the engine hashes to the same digest', () => {
    const file = JSON.parse(readFileSync(join(__dirname, '..', '..', '..', 'vectors', 'v1.0-worked-example-vectors.json'), 'utf8'));
    expect(file.agentDescriptors[0].digest).toBe(agentDescriptorDigest(X12));
  });
});
