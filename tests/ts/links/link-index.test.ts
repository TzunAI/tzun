/**
 * The link index (`evidence_links`) on the memory, SQLite
 * and Postgres adapters: the rows each stored record contributes, written in
 * the storing transaction; `listLinksTo` a page at a time, with its relation
 * and statement filters and its cursor; the refusals of a malformed query;
 * rows that never change; and the backfill of a store that held records
 * before the index existed, past its first batch, created and filled in one
 * transaction.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { Pool } from 'pg';
import Database from 'better-sqlite3';
import { SchemaRegistry, type EvidenceEnvelope, type Link, type StorageAdapter } from '@tzun/engine';
import { MemoryStorageAdapter } from '../../../src/storage/memory';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../../src/storage/postgres';
import type { StorageExtension } from '../../../src/storage/extensions';
import { decidersExtension } from '../../../src/storage/ddl/deciders';
import { linksStorageExtension } from '../../../src/storage/ddl/links';
import { LinkIndexQueryError, linkIndexRows, type LinkIndexPage, type LinkIndexRow } from '../../../src/storage/links-sql';
import { VerifyingStorageProxy } from '../../../src/monitoring/storage-proxy';
import { PG_TESTS_ENABLED, pgSuiteSchema } from '../helpers/postgres-test-db';

const hex = (label: string): string => createHash('sha256').update(label).digest('hex');
const link = (rel: string, target: string): Link => ({ rel, target: { digest: target, evidenceId: null, locator: null }, attrs: null });

function envelope(id: string, sequenceNumber: number, links: Link[] | null, aiSystemId = 'index-suite'): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      evidenceId: id,
      schemaVersion: 'v1.0',
      aiSystemId,
      aiOutput: { id },
      action: aiSystemId === 'tzun:link' ? 'link' : 'approve',
      reason: 'link index suite',
      capturedAt: '2026-10-01T10:00:00.000Z',
      sequenceNumber,
      decider: { kind: 'human', id: 'acct:u-index', agent: null, credential: null, freshness: null },
      contributions: null,
      links,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: hex(id), chainLink: null },
    nonRepudiation: {},
    custodyChain: [],
    attestationStatus: 'none',
  };
}

type Lister = (digest: string, options?: Record<string, unknown>) => Promise<LinkIndexPage>;
const listerOf = (adapter: StorageAdapter): Lister => adapter.listLinksTo as unknown as Lister;

const T1 = hex('target one');
const T2 = hex('target two');
const SUBJECT = hex('complaint subject');

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'tzun-test-link-index-'));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

let n = 0;
const pg = pgSuiteSchema('link_index');

interface Leg {
  name: 'memory' | 'sqlite' | 'postgres';
  open(extensions: StorageExtension[], reuse?: boolean): Promise<StorageAdapter>;
  /** Run a statement on the store's own connection (SQL legs). */
  sql?(adapter: StorageAdapter, statement: string): Promise<void>;
}

let sqliteFile = '';
const legs: Leg[] = [
  { name: 'memory', open: async (extensions) => new MemoryStorageAdapter({ extensions }) },
  {
    name: 'sqlite',
    open: async (extensions, reuse) => {
      if (!reuse) sqliteFile = join(dir, `index-${++n}.db`);
      return new SqliteStorageAdapter(sqliteFile, { extensions });
    },
    sql: async (adapter, statement) => {
      (adapter as unknown as { db: { exec(s: string): void } }).db.exec(statement);
    },
  },
  ...(PG_TESTS_ENABLED
    ? [
        {
          name: 'postgres' as const,
          open: async (extensions: StorageExtension[], reuse?: boolean) => {
            if (!reuse) await pg.reset();
            const adapter = new PostgresStorageAdapter(pg.url, undefined, { extensions });
            await adapter.ensureTables();
            return adapter;
          },
          sql: async (_adapter: StorageAdapter, statement: string) => {
            const pool = new Pool({ connectionString: pg.url });
            try {
              await pool.query(statement);
            } finally {
              await pool.end();
            }
          },
        },
      ]
    : []),
];

describe('linkIndexRows', () => {
  it('one row per well-formed link, a link record statement carrying its subject', () => {
    const record = envelope('lr-1', 1, [link('appeals', T1), link('subject', SUBJECT)], 'tzun:link');
    expect(linkIndexRows(record)).toEqual([
      { evidenceId: 'lr-1', idx: 0, rel: 'appeals', targetDigest: T1, subjectDigest: SUBJECT },
      { evidenceId: 'lr-1', idx: 1, rel: 'subject', targetDigest: SUBJECT, subjectDigest: null },
    ]);
  });

  it('skips a link that is not well formed, and a record without links', () => {
    const bad = envelope('bad-1', 1, [link('derivedFrom', 'not-hex'), link('Bad Rel', T1), link('implements', T2)]);
    expect(linkIndexRows(bad)).toEqual([{ evidenceId: 'bad-1', idx: 2, rel: 'implements', targetDigest: T2, subjectDigest: null }]);
    expect(linkIndexRows(envelope('none-1', 1, null))).toEqual([]);
    expect(linkIndexRows(null)).toEqual([]);
  });
});

describe.each(legs)('the link index on $name', (leg) => {
  let adapter: StorageAdapter;
  let list: Lister;

  beforeEach(async () => {
    adapter = await leg.open([decidersExtension, linksStorageExtension]);
    list = listerOf(adapter);
  });
  afterEach(async () => {
    await adapter.close?.();
  });

  it('writes a row per link with the record, and listLinksTo finds the records naming a digest', async () => {
    expect(typeof adapter.listLinksTo).toBe('function');
    await adapter.store(envelope('rec-a', 1, [link('derivedFrom', T1), link('root', T1), link('x-acme.contract', T2)]));
    await adapter.store(envelope('rec-b', 2, null));
    const toT1 = await list(T1);
    expect(toT1).toEqual({
      rows: [
        { evidenceId: 'rec-a', idx: 0, rel: 'derivedFrom', targetDigest: T1, subjectDigest: null },
        { evidenceId: 'rec-a', idx: 1, rel: 'root', targetDigest: T1, subjectDigest: null },
      ],
      cursor: null,
    });
    expect((await list(T2)).rows.map((r) => r.rel)).toEqual(['x-acme.contract']);
    expect(await list(hex('nobody'))).toEqual({ rows: [], cursor: null });
  });

  it('keeps a link record statement apart from its subject row', async () => {
    await adapter.store(envelope('lr-1', 1, [link('appeals', T1), link('subject', SUBJECT)], 'tzun:link'));
    expect((await list(T1)).rows).toEqual([{ evidenceId: 'lr-1', idx: 0, rel: 'appeals', targetDigest: T1, subjectDigest: SUBJECT }]);
    expect((await list(T1, { statements: true })).rows).toHaveLength(1);
    expect((await list(SUBJECT, { rels: ['subject'] })).rows).toEqual([
      { evidenceId: 'lr-1', idx: 1, rel: 'subject', targetDigest: SUBJECT, subjectDigest: null },
    ]);
    expect((await list(SUBJECT, { statements: true })).rows).toEqual([]);
  });

  it('pages by (evidence id, index), each page continuing after the last', async () => {
    const ids = ['p-3', 'p-1', 'p-5', 'p-2', 'p-4'];
    for (let i = 0; i < ids.length; i++) await adapter.store(envelope(ids[i], i + 1, [link('derivedFrom', T1)]));
    const seen: string[] = [];
    let page = await list(T1, { limit: 2 });
    const sizes = [page.rows.length];
    seen.push(...page.rows.map((r) => r.evidenceId));
    while (page.cursor !== null) {
      page = await list(T1, { limit: 2, cursor: page.cursor });
      sizes.push(page.rows.length);
      seen.push(...page.rows.map((r) => r.evidenceId));
    }
    expect(sizes).toEqual([2, 2, 1]);
    expect(seen).toEqual(['p-1', 'p-2', 'p-3', 'p-4', 'p-5']);
    // An exact last page has no cursor.
    expect((await list(T1, { limit: 5 })).cursor).toBeNull();
  });

  it('filters by relation; an empty relation list matches nothing', async () => {
    await adapter.store(envelope('r-1', 1, [link('derivedFrom', T1), link('root', T1)]));
    await adapter.store(envelope('r-2', 2, [link('reviews', T1)]));
    expect((await list(T1, { rels: ['reviews', 'root'] })).rows.map((r) => `${r.evidenceId}:${r.rel}`)).toEqual(['r-1:root', 'r-2:reviews']);
    expect((await list(T1, { rels: [] })).rows).toEqual([]);
  });

  it('refuses a malformed query, naming the field and never the value', async () => {
    const refused = async (digest: string, options: Record<string, unknown>, code: string) => {
      const error = await list(digest, options).then(
        () => null,
        (e: unknown) => e,
      );
      expect(error).toBeInstanceOf(LinkIndexQueryError);
      expect(error).toMatchObject({ code });
      expect(String((error as Error).message)).not.toContain('secret-value');
    };
    await refused('secret-value', {}, 'invalid_target_digest');
    await refused(T1.toUpperCase(), {}, 'invalid_target_digest');
    await refused(T1, { limit: 0 }, 'invalid_limit');
    await refused(T1, { limit: 201 }, 'invalid_limit');
    await refused(T1, { limit: '10' }, 'invalid_limit');
    await refused(T1, { cursor: 'secret-value' }, 'invalid_cursor');
    await refused(T1, { cursor: Buffer.from('["a",-1]').toString('base64url') }, 'invalid_cursor');
    await refused(T1, { rels: ['Not A Relation'] }, 'invalid_relation');
    await refused(T1, { rels: 'derivedFrom' }, 'invalid_relation');
    await refused(T1, { rels: Array.from({ length: 65 }, (_, i) => `r${i}`) }, 'invalid_relation');
  });

  it('a refused store writes no row', async () => {
    await adapter.store(envelope('first', 1, [link('derivedFrom', T1)]));
    // The same position again: refused, and nothing of the second record is kept.
    await expect(adapter.store(envelope('second', 1, [link('derivedFrom', T2)]))).rejects.toThrow();
    expect((await list(T2)).rows).toEqual([]);
    expect((await list(T1)).rows.map((r) => r.evidenceId)).toEqual(['first']);
  });

  it('a keyed replay writes no second row', async () => {
    const claim = { key: 'k-1', fingerprint: 'f' };
    await adapter.storeIdempotent!(envelope('keyed', 1, [link('derivedFrom', T1)]), 'default', { idempotency: claim });
    const replay = await adapter.storeIdempotent!(envelope('keyed-again', 2, [link('derivedFrom', T1)]), 'default', { idempotency: claim });
    expect(replay.kind).toBe('replay');
    expect((await list(T1)).rows.map((r) => r.evidenceId)).toEqual(['keyed']);
  });

  it('the verifying proxy forwards listLinksTo with its options', async () => {
    await adapter.store(envelope('lr-2', 1, [link('appeals', T1), link('subject', SUBJECT)], 'tzun:link'));
    await adapter.store(envelope('plain', 2, [link('derivedFrom', T1)]));
    const proxy = new VerifyingStorageProxy(adapter, null, new SchemaRegistry());
    const rows = (await listerOf(proxy)(T1, { statements: true })).rows as LinkIndexRow[];
    expect(rows.map((r) => r.evidenceId)).toEqual(['lr-2']);
  });

  if (leg.sql !== undefined) {
    it('refuses a change or a removal of a row', async () => {
      await adapter.store(envelope('fixed', 1, [link('derivedFrom', T1)]));
      expect((await list(T1)).rows.map((r) => r.evidenceId)).toEqual(['fixed']);
      // The refusal is read by its message: a SqliteError raised in a jest
      // worker that loaded better-sqlite3 for an earlier file is not an
      // `instanceof Error` of this file's realm, so `rejects.toThrow` misses it.
      const refusal = (statement: string) =>
        leg.sql!(adapter, statement).then(
          () => 'no error',
          (e: unknown) => String((e as { message?: unknown })?.message),
        );
      expect(await refusal(`UPDATE evidence_links SET rel = 'appeals' WHERE evidence_id = 'fixed'`)).toMatch(/derived from immutable records/);
      expect(await refusal(`DELETE FROM evidence_links WHERE evidence_id = 'fixed'`)).toMatch(/derived from immutable records/);
      expect((await list(T1)).rows).toHaveLength(1);
    });

    it('indexes every stored record once, when the index is first created on a store that holds records', async () => {
      await adapter.close?.();
      // A store opened without the link index, written to, then reopened with it.
      const without = await leg.open([decidersExtension]);
      expect(typeof without.listLinksTo).toBe('undefined');
      await without.store(envelope('old-1', 1, [link('derivedFrom', T1), link('root', T1)]));
      await without.store(envelope('old-2', 2, null));
      await without.store(envelope('old-lr', 3, [link('appeals', T1), link('subject', SUBJECT)], 'tzun:link'));
      await without.close?.();
      adapter = await leg.open([decidersExtension, linksStorageExtension], true);
      list = listerOf(adapter);
      expect((await list(T1)).rows.map((r) => `${r.evidenceId}:${r.idx}:${r.rel}:${r.subjectDigest === null ? '-' : 's'}`)).toEqual([
        'old-1:0:derivedFrom:-',
        'old-1:1:root:-',
        'old-lr:0:appeals:s',
      ]);
      // A further store is indexed as it is written; reopening indexes nothing twice.
      await adapter.store(envelope('new-1', 4, [link('implements', T1)]));
      await adapter.close?.();
      adapter = await leg.open([decidersExtension, linksStorageExtension], true);
      list = listerOf(adapter);
      expect((await list(T1)).rows.map((r) => r.evidenceId)).toEqual(['new-1', 'old-1', 'old-1', 'old-lr']);
    });

    it('backfills past its first batch: 1,201 linked records, each indexed once', async () => {
      await adapter.close?.();
      const without = await leg.open([decidersExtension]);
      const count = 1201;
      for (let i = 1; i <= count; i++) await without.store(envelope(`bf-${String(i).padStart(4, '0')}`, i, [link('derivedFrom', T1)]));
      await without.close?.();
      adapter = await leg.open([decidersExtension, linksStorageExtension], true);
      list = listerOf(adapter);
      const seen: string[] = [];
      let page = await list(T1, { limit: 200 });
      seen.push(...page.rows.map((r) => r.evidenceId));
      while (page.cursor !== null) {
        page = await list(T1, { limit: 200, cursor: page.cursor });
        seen.push(...page.rows.map((r) => r.evidenceId));
      }
      expect(seen).toHaveLength(count);
      expect(new Set(seen).size).toBe(count);
      expect(seen[0]).toBe('bf-0001');
      expect(seen[count - 1]).toBe(`bf-${count}`);
    }, 180_000);
  }
});

describe('the SQLite link index migration', () => {
  it('creates and fills the table in one transaction: a backfill that fails leaves no table', () => {
    const db = new Database(join(dir, `atomic-${++n}.db`));
    try {
      // No envelopes table: the backfill's read fails after the DDL has run.
      let threw = false;
      try {
        linksStorageExtension.sqlite!.migrate(db);
      } catch {
        threw = true;
      }
      expect(threw).toBe(true);
      expect(db.prepare("SELECT name FROM sqlite_master WHERE name LIKE '%evidence_links%'").all()).toEqual([]);
    } finally {
      db.close();
    }
  });
});
