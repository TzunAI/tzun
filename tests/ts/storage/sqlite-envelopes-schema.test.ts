/**
 * The designed `envelopes` schema on SQLite — the columns a brand-new store is
 * born with.
 *
 * `chain_id` is part of the table, defined in `CREATE TABLE`, not added by a
 * later ALTER as if it were a migration step. It is not optional:
 * `getActiveChainId()`, `getChainForRecord()` and every chain-scoped read
 * select on it, so a store created without it is unusable from the first
 * capture. This test holds the column, and `captured_at_ms` beside it, inside
 * `CREATE TABLE` where they are defined — so a future tidy-up of the DDL
 * fails here rather than in the field.
 *
 * Column ORDER is asserted too. Nothing in the SDK inserts positionally, but
 * `tests/ts/active-chain-resolution.test.ts` copies rows by reading
 * `table_info(envelopes)`, and the demo reads the file with sqlite3 by hand;
 * an unannounced reshuffle should be a failure, not a surprise.
 */
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SqliteStorageAdapter } from '../../../src/storage/sqlite';
import { makeEnvelope } from '../storage-conformance/fixtures';

function columnsOf(adapter: SqliteStorageAdapter, table: string): string[] {
  const db = (adapter as unknown as { db: Database.Database }).db;
  return (db.pragma(`table_info(${table})`) as Array<{ name: string }>).map((c) => c.name);
}

function indexesOf(adapter: SqliteStorageAdapter, table: string): string[] {
  const db = (adapter as unknown as { db: Database.Database }).db;
  return (db.pragma(`index_list(${table})`) as Array<{ name: string }>).map((c) => c.name);
}

describe('SqliteStorageAdapter designed schema', () => {
  let dir: string;
  let adapter: SqliteStorageAdapter;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-schema-'));
    adapter = new SqliteStorageAdapter(join(dir, 'fresh.db'));
  });

  afterEach(async () => {
    await adapter.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('creates envelopes with chain_id and captured_at_ms, in that order', () => {
    expect(columnsOf(adapter, 'envelopes')).toEqual([
      'evidence_id',
      'envelope',
      'captured_at',
      'captured_at_ms',
      'ai_system_id',
      'digest',
      'created_at',
      'chain_id',
    ]);
  });

  it('indexes the two columns the chain and ordering reads depend on', () => {
    const indexes = indexesOf(adapter, 'envelopes');
    expect(indexes).toContain('idx_envelopes_chain_id');
    expect(indexes).toContain('idx_envelopes_captured_at_ms');
  });

  it('creates chain_forks with sealed_old_chain_head and chain_state with last_sequence', () => {
    expect(columnsOf(adapter, 'chain_forks')).toContain('sealed_old_chain_head');
    expect(columnsOf(adapter, 'chain_state')).toContain('last_sequence');
  });

  it('a brand-new store resolves its active chain and scopes reads by it', async () => {
    expect(await adapter.getActiveChainId()).toBe('default');

    await adapter.store(makeEnvelope({ evidenceId: 'sch-1', sequenceNumber: 1 }));
    await adapter.store(makeEnvelope({ evidenceId: 'sch-2', sequenceNumber: 1 }), 'tenant-b');

    expect(await adapter.getChainForRecord('sch-1')).toBe('default');
    expect(await adapter.getChainForRecord('sch-2')).toBe('tenant-b');
    expect(await adapter.listRecordChainIds()).toEqual(['default', 'tenant-b']);
    expect((await adapter.list({ chainId: 'tenant-b' })).map((e) => e.payload.evidenceId)).toEqual(['sch-2']);
  });
});
