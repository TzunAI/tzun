/**
 * The custody trail is checked by the database on both SQL adapters, as the
 * platform checks it.
 *
 * (a) INSERT. `custody_entries.entry_hash` was computed in application code
 *     and the table refused only UPDATE, DELETE and TRUNCATE, so a row
 *     inserted with any hash was accepted. An INSERT trigger now binds the
 *     row to the record as it stands (the record exists, the digest is the
 *     record's, the row extends the record's current tail) and recomputes
 *     the hash; a row that disagrees is refused.
 * (b) Exact prefix. The Postgres envelope trigger tested `custodyChain` with
 *     jsonb containment, a subset test, so an existing entry could gain keys
 *     in place (an unhashed entry given an `entryHash`, say). Existing entries
 *     are now compared exactly, as SQLite's envelope trigger compares them.
 * (c) Ledger. An appended custody entry that carries an `entryHash` must be
 *     the mirror of a `custody_entries` row for the same record.
 *
 * Every attack is a raw statement on the adapter's own connection. Legs:
 * sqlite always; postgres when the Postgres legs run
 * (tests/ts/helpers/postgres-test-db.ts), in a schema of this file's own,
 * under run-unique ids and chains.
 */
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  canonicalCustodyMetadata,
  computeCustodyEntryHash,
  verifyCustodyTrail,
} from '@tzun/engine';
import type { EvidenceEnvelope, StorageAdapter } from '@tzun/engine';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { makeEnvelope } from './storage-conformance/fixtures';

interface Leg {
  name: 'sqlite' | 'postgres';
  make: () => Promise<{ adapter: StorageAdapter; teardown: () => Promise<void> }>;
  /** One raw statement on the adapter's own connection; `?` placeholders on both legs. */
  raw: (adapter: StorageAdapter, sql: string, params?: unknown[]) => Promise<void>;
}

const sqliteLeg: Leg = {
  name: 'sqlite',
  make: async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-'));
    const adapter = new SqliteStorageAdapter(path.join(dir, 'custody.db'));
    return {
      adapter,
      teardown: async () => {
        await adapter.close();
        fs.rmSync(dir, { recursive: true, force: true });
      },
    };
  },
  raw: async (adapter, sql, params = []) => {
    const db = (adapter as unknown as { db: import('better-sqlite3').Database }).db;
    db.prepare(sql).run(...params);
  },
};

const pgSchema = pgSuiteSchema('ledger_checks');

const postgresLeg: Leg = {
  name: 'postgres',
  make: async () => {
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    await adapter.ensureTables();
    return { adapter, teardown: async () => adapter.close() };
  },
  raw: async (adapter, sql, params = []) => {
    const pool = (adapter as unknown as { pool: import('pg').Pool }).pool;
    let n = 0;
    await pool.query(sql.replace(/\?/g, () => `$${++n}`), params);
  },
};

const legs: Leg[] = PG_TESTS_ENABLED ? [sqliteLeg, postgresLeg] : [sqliteLeg];

/** The message a statement was refused with (realm-independent; see custody-trail-hashed-and-atomic.test.ts). */
async function refusal(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (err) {
    const message = (err as { message?: unknown } | null)?.message;
    return typeof message === 'string' ? message : String(err);
  }
  throw new Error('expected the statement to be refused, but it went through');
}

/** A 64-hex string no row in any database holds: the postgres leg's database is shared across runs. */
const forgedHash = (): string => createHash('sha256').update(`forged-${Date.now()}-${Math.random()}`).digest('hex');

let counter = 0;
const unique = (label: string): string =>
  `${label}-${Date.now().toString(36)}-${(counter += 1)}-${Math.random().toString(36).slice(2, 8)}`;

const INSERT_ROW = `
  INSERT INTO custody_entries
    (evidence_id, chain_id, canonical_digest, action, actor, ts, system_id,
     metadata, metadata_canonical, prev_entry_hash, entry_hash, recovery_id)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

interface Row {
  evidenceId: string;
  chainId: string;
  canonicalDigest: string;
  action: string;
  actor: string;
  ts: string;
  systemId: string;
  metadata: Record<string, unknown> | null;
  metadataCanonical: string | null;
  prevEntryHash: string | null;
  entryHash: string;
}

const params = (r: Row): unknown[] => [
  r.evidenceId, r.chainId, r.canonicalDigest, r.action, r.actor, r.ts, r.systemId,
  r.metadata === null ? null : JSON.stringify(r.metadata), r.metadataCanonical,
  r.prevEntryHash, r.entryHash, null,
];

describe.each(legs)('the custody trail is checked by the database — $name adapter', (leg) => {
  let adapter: StorageAdapter;
  let teardown: () => Promise<void>;
  let evidenceId: string;
  let chainId: string;

  beforeEach(async () => {
    ({ adapter, teardown } = await leg.make());
    evidenceId = unique('ev');
    chainId = unique('chain');
    await adapter.store(makeEnvelope({ evidenceId }), chainId);
  });

  afterEach(async () => {
    await teardown();
  });

  const raw = (sql: string, p?: unknown[]) => leg.raw(adapter, sql, p);

  /** A row that is exactly what the adapter would write next for `id`. */
  async function honestRow(id = evidenceId, metadata: Record<string, unknown> | null = { reviewId: 'r-1', z: 1, a: [2, 'x'] }): Promise<Row> {
    const envelope = (await adapter.retrieve(id))!;
    const trail = await adapter.listCustodyEntries!(id);
    const prevEntryHash = trail.length > 0 ? trail[trail.length - 1].entryHash : null;
    const fields = {
      evidenceId: id,
      canonicalDigest: envelope.integrity.canonicalDigest,
      action: 'reviewed',
      actor: 'admin@acme.example',
      ts: '2026-09-18T10:00:00.000Z',
      systemId: 'tzun-recovery',
    };
    return {
      ...fields,
      chainId,
      metadata,
      metadataCanonical: canonicalCustodyMetadata(metadata),
      prevEntryHash,
      entryHash: computeCustodyEntryHash({ ...fields, timestamp: fields.ts, prevEntryHash, metadata }),
    };
  }

  describe('(a) an inserted row must recompute', () => {
    it('refuses a row whose entry_hash is not the hash of its fields', async () => {
      const row = { ...(await honestRow()), entryHash: forgedHash() };
      expect(await refusal(() => raw(INSERT_ROW, params(row)))).toMatch(/entry_hash does not recompute/);
      expect(await adapter.listCustodyEntries!(evidenceId)).toEqual([]);
    });

    it('refuses a field rewritten after the hash was taken', async () => {
      const row = { ...(await honestRow()), actor: 'mallory@acme.example' };
      expect(await refusal(() => raw(INSERT_ROW, params(row)))).toMatch(/entry_hash does not recompute/);
    });

    it('refuses a row that does not extend the record’s current tail', async () => {
      await adapter.appendCustodyEntry!(evidenceId, {
        timestamp: '2026-09-18T09:00:00.000Z', actor: 'admin@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
      });
      // Hashed as the FIRST entry (prev null), although the record already has one.
      const envelope = (await adapter.retrieve(evidenceId))!;
      const fields = {
        evidenceId, canonicalDigest: envelope.integrity.canonicalDigest, action: 'reviewed',
        actor: 'admin@acme.example', ts: '2026-09-18T10:00:00.000Z', systemId: 'tzun-recovery',
      };
      const row: Row = {
        ...fields, chainId, metadata: null, metadataCanonical: null, prevEntryHash: null,
        entryHash: computeCustodyEntryHash({ ...fields, timestamp: fields.ts, prevEntryHash: null, metadata: null }),
      };
      expect(await refusal(() => raw(INSERT_ROW, params(row)))).toMatch(/prev_entry_hash is not the record's current tail/);
    });

    it('refuses a row for a record that does not exist', async () => {
      const row = { ...(await honestRow()), evidenceId: unique('ghost') };
      expect(await refusal(() => raw(INSERT_ROW, params(row)))).toMatch(/no evidence record/);
    });

    it('refuses a row bound to a digest the record does not carry', async () => {
      const honest = await honestRow();
      const canonicalDigest = 'sha256:' + '9'.repeat(64);
      const row = {
        ...honest,
        canonicalDigest,
        entryHash: computeCustodyEntryHash({
          prevEntryHash: null, evidenceId, canonicalDigest, action: honest.action, actor: honest.actor,
          timestamp: honest.ts, systemId: honest.systemId, metadata: honest.metadata,
        }),
      };
      expect(await refusal(() => raw(INSERT_ROW, params(row)))).toMatch(/canonical_digest does not match the record/);
    });

    it('refuses a row whose metadata and metadata_canonical disagree', async () => {
      const row = { ...(await honestRow()), metadataCanonical: '{"reviewId":"r-2"}' };
      expect(await refusal(() => raw(INSERT_ROW, params(row)))).toMatch(/metadata and metadata_canonical disagree/);
    });

    it('accepts a row that is exactly what the hash rule says — the check recomputes, it does not forbid', async () => {
      const row = await honestRow();
      await raw(INSERT_ROW, params(row));
      const trail = await adapter.listCustodyEntries!(evidenceId);
      expect(trail.map((e) => e.entryHash)).toEqual([row.entryHash]);
    });

    it('the adapter’s own appends go through, with and without metadata', async () => {
      await adapter.appendCustodyEntry!(evidenceId, {
        timestamp: '2026-09-18T09:00:00.000Z', actor: 'ünï 😀', action: 'reviewed', systemId: 'tzun-recovery',
        metadata: { b: 1, a: { d: [1, 'é'], c: null } },
      });
      await adapter.appendCustodyEntry!(evidenceId, {
        timestamp: '2026-09-18T09:01:00.000Z', actor: 'admin@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
      });
      const envelope = (await adapter.retrieve(evidenceId))!;
      expect(verifyCustodyTrail(envelope)).toMatchObject({ valid: true, hashedEntries: 2 });
    });
  });

  describe('(b) and (c) the envelope’s custody chain', () => {
    /** Rewrite the stored envelope's custody chain with a raw UPDATE (no bypass). */
    async function rewriteCustody(mutate: (chain: Array<Record<string, unknown>>) => void): Promise<void> {
      const envelope = (await adapter.retrieve(evidenceId))! as EvidenceEnvelope;
      const chain = envelope.custodyChain as unknown as Array<Record<string, unknown>>;
      mutate(chain);
      await raw('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?', [JSON.stringify(envelope), evidenceId]);
    }

    it('(b) an existing entry cannot gain a key in place', async () => {
      expect(await refusal(() => rewriteCustody((chain) => { chain[0].entryHash = forgedHash(); })))
        .toMatch(/custodyChain is append-only/);
      expect(await refusal(() => rewriteCustody((chain) => { chain[0].note = 'added later'; })))
        .toMatch(/custodyChain is append-only/);
      expect((await adapter.retrieve(evidenceId))!.custodyChain[0]).not.toHaveProperty('entryHash');
    });

    it('(b) existing entries cannot be reordered', async () => {
      await adapter.appendCustodyEntry!(evidenceId, {
        timestamp: '2026-09-18T09:00:00.000Z', actor: 'admin@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
      });
      expect(await refusal(() => rewriteCustody((chain) => { chain.reverse(); })))
        .toMatch(/custodyChain is append-only/);
    });

    it('(c) an appended entry claiming an entryHash with no custody_entries row is refused', async () => {
      const forged = {
        timestamp: '2026-09-18T10:00:00.000Z', actor: 'staff@example.com', action: 'reviewed', systemId: 'tzun-recovery',
        entryHash: forgedHash(), prevEntryHash: null,
      };
      expect(await refusal(() => rewriteCustody((chain) => { chain.push(forged); })))
        .toMatch(/entryHash with no custody_entries row/);
      expect((await adapter.retrieve(evidenceId))!.custodyChain).toHaveLength(1);
    });

    it('(c) the row must be this record’s — another record’s hash does not count', async () => {
      const otherId = unique('ev-other');
      await adapter.store(makeEnvelope({ evidenceId: otherId, sequenceNumber: 2 }), chainId);
      await adapter.appendCustodyEntry!(otherId, {
        timestamp: '2026-09-18T09:00:00.000Z', actor: 'admin@acme.example', action: 'reviewed', systemId: 'tzun-recovery',
      });
      const borrowed = (await adapter.retrieve(otherId))!.custodyChain[1];
      expect(await refusal(() => rewriteCustody((chain) => { chain.push(borrowed as unknown as Record<string, unknown>); })))
        .toMatch(/entryHash with no custody_entries row/);
    });

    it('(c) an unhashed append is still accepted — the client-attested form', async () => {
      await rewriteCustody((chain) => {
        chain.push({ timestamp: '2026-09-18T10:00:00.000Z', actor: 'jane@acme.example', action: 'reviewed', systemId: 'client' });
      });
      expect((await adapter.retrieve(evidenceId))!.custodyChain).toHaveLength(2);
    });
  });
});
