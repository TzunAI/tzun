/**
 * Hashed, ledgered custody entries on the Postgres adapter, without a
 * database: the DDL
 * `ensureTables()` issues for the custody ledger, and the one-transaction
 * shape of `applyRelink` — including the crash-after-link-update rollback,
 * which the live leg in custody-trail-hashed-and-atomic.test.ts cannot
 * inject and this mocked client can.
 *
 * Red before the ledger existed (4 failed / 4):
 *   `Expected substring: "CREATE TABLE IF NOT EXISTS custody_entries"` /
 *   `Received string: "SELECT pg_advisory_lock(2026052501)…"` (no ledger DDL at all), and
 *   `TypeError: adapter.applyRelink is not a function` for both transaction cases.
 */
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import type { EvidenceEnvelope, RelinkRecord } from '@tzun/engine';

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

const { __mockPool: mockPool, __mockClient: mockClient } = jest.requireMock('pg');

function envelope(evidenceId: string): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId, schemaVersion: 'v1.0', aiSystemId: 'sys', aiOutput: { r: 1 }, action: 'approved',
      reason: 'ok', capturedAt: '2026-09-09T00:00:00.000Z', sequenceNumber: 3, contributions: null, signoffExpectation: null,
    },
    integrity: { canonicalDigest: 'd'.repeat(64), chainLink: 'tampered-link' },
    nonRepudiation: {},
    custodyChain: [{ timestamp: '2026-09-09T00:00:00.000Z', actor: 'jane', action: 'decision_captured', systemId: 'sys' }],
    attestationStatus: 'none',
  };
}

const relink: RelinkRecord = {
  id: 'rlk-1', incidentId: 'inc-1', relinkedAt: '2026-09-09T01:00:00.000Z', relinkedBy: 'admin', fromSequence: 3, toSequence: 5,
  modifiedLinks: [{ evidenceId: 'ev-3', sequenceNumber: 3, previousChainLink: 'tampered-link', newChainLink: 'repaired' }],
};
const entry = { timestamp: relink.relinkedAt, actor: 'admin', action: 'relinked' as const, systemId: 'tzun-recovery' };

describe('custody_entries DDL', () => {
  let ddl: string;

  beforeAll(async () => {
    mockClient.query.mockClear();
    const adapter = new PostgresStorageAdapter('postgres://unused/unused');
    await adapter.ensureTables();
    ddl = mockClient.query.mock.calls
      .map((c: unknown[]) => c[0])
      .filter((q: unknown): q is string => typeof q === 'string')
      .join('\n');
  });

  it('creates the ledger idempotently, with a unique entry_hash and a per-record index', () => {
    expect(ddl).toContain('CREATE TABLE IF NOT EXISTS custody_entries');
    expect(ddl).toMatch(/entry_hash TEXT NOT NULL UNIQUE/);
    expect(ddl).toMatch(/canonical_digest TEXT NOT NULL/);
    expect(ddl).toContain('CREATE INDEX IF NOT EXISTS idx_custody_entries_record ON custody_entries(evidence_id, id)');
  });

  // the SDK computed entry_hash in application code and the table
  // accepted any value an INSERT carried. The platform recomputes it in a
  // BEFORE INSERT trigger; so does the SDK now.
  it('recomputes every inserted row in a BEFORE INSERT trigger, re-installed on every boot', () => {
    expect(ddl).toContain('BEFORE INSERT ON custody_entries');
    expect(ddl).toContain('DROP TRIGGER IF EXISTS custody_entries_verify_insert_trigger ON custody_entries');
    expect(ddl).toContain('encode(sha256(convert_to(');
    expect(ddl).toContain('entry_hash does not recompute');
    expect(ddl).toContain("prev_entry_hash is not the record''s current tail");
    expect(ddl).toContain('canonical_digest does not match the record');
    expect(ddl).toContain('metadata and metadata_canonical disagree');
  });

  it('refuses UPDATE and DELETE row by row and TRUNCATE by statement, re-installed on every boot', () => {
    expect(ddl).toContain('BEFORE UPDATE OR DELETE ON custody_entries');
    expect(ddl).toContain('BEFORE TRUNCATE ON custody_entries');
    expect(ddl).toContain('FOR EACH STATEMENT EXECUTE FUNCTION custody_entries_block_mutation()');
    expect(ddl).toContain('DROP TRIGGER IF EXISTS custody_entries_block_mutation_trigger ON custody_entries');
    expect(ddl).toContain('DROP TRIGGER IF EXISTS custody_entries_block_truncate_trigger ON custody_entries');
    // Distinct from the platform's guard names, so the two schemas cannot
    // replace each other's triggers should they ever share a database.
    expect(ddl).not.toContain('custody_entries_append_only');
    expect(ddl).not.toContain('tzun_custody_entries');
  });
});

describe('applyRelink is one transaction on one client', () => {
  let adapter: PostgresStorageAdapter;

  beforeEach(() => {
    adapter = new PostgresStorageAdapter('postgres://unused/unused');
    mockClient.query.mockReset();
    mockClient.release.mockReset();
    mockPool.connect.mockClear();
  });

  it('issues the link update, the relink insert and the hashed custody append between ONE BEGIN and ONE COMMIT', async () => {
    mockClient.query
      .mockResolvedValueOnce({ rows: [] }) // BEGIN
      .mockResolvedValueOnce({ rows: [{ envelope: JSON.stringify(envelope('ev-3')) }] }) // SELECT ... FOR UPDATE (link)
      .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // UPDATE envelopes (link)
      .mockResolvedValueOnce({ rows: [{ highest: null }] }) // SELECT MAX(revision_no)
      .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // INSERT envelope_revisions
      .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // INSERT chain_relinks
      .mockResolvedValueOnce({ rows: [{ envelope: JSON.stringify({ ...envelope('ev-3'), integrity: { canonicalDigest: 'd'.repeat(64), chainLink: 'repaired' } }), chain_id: 'default' }] }) // SELECT ... FOR UPDATE (custody)
      .mockResolvedValueOnce({ rows: [] }) // SELECT entry_hash tail
      .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // INSERT custody_entries
      .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // UPDATE envelopes (mirror)
      .mockResolvedValueOnce({ rows: [] }); // COMMIT

    await adapter.applyRelink(relink, [{ evidenceId: 'ev-3', entry }]);

    expect(mockPool.connect).toHaveBeenCalledTimes(1);
    const queries: string[] = mockClient.query.mock.calls.map((c: unknown[]) => c[0] as string);
    expect(queries.filter((q) => q === 'BEGIN')).toHaveLength(1);
    expect(queries.filter((q) => q === 'COMMIT')).toHaveLength(1);
    expect(queries).not.toContain('ROLLBACK');
    expect(queries[0]).toBe('BEGIN');
    expect(queries[1]).toMatch(/SELECT envelope FROM envelopes WHERE evidence_id = \$1 FOR UPDATE/);
    expect(queries[2]).toContain('UPDATE envelopes SET envelope');
    expect(JSON.parse(mockClient.query.mock.calls[2][1][0]).integrity.chainLink).toBe('repaired');
    // UPDATED: the revision row for the repair is inside the same
    // transaction as the link it describes, and is attributed to the operator
    // who authorised the relink rather than to the subsystem.
    expect(queries[3]).toContain('SELECT MAX(revision_no) AS highest FROM envelope_revisions');
    expect(queries[4]).toContain('INSERT INTO envelope_revisions');
    expect(mockClient.query.mock.calls[4][1][3]).toBe('repaired');
    expect(mockClient.query.mock.calls[4][1][5]).toBe('relink');
    expect(mockClient.query.mock.calls[4][1][6]).toBe('admin');
    expect(queries[5]).toContain('INSERT INTO chain_relinks');
    expect(queries[6]).toMatch(/SELECT envelope, chain_id FROM envelopes WHERE evidence_id = \$1 FOR UPDATE/);
    expect(queries[7]).toContain('SELECT entry_hash FROM custody_entries');
    expect(queries[8]).toContain('INSERT INTO custody_entries');
    expect(mockClient.query.mock.calls[8][1][11]).toBe('rlk-1'); // recovery_id = relink.id
    expect(queries[9]).toContain('UPDATE envelopes SET envelope');
    const mirrored = JSON.parse(mockClient.query.mock.calls[9][1][0]).custodyChain.at(-1);
    expect(mirrored.entryHash).toMatch(/^[0-9a-f]{64}$/);
    expect(mirrored.prevEntryHash).toBeNull();
    expect(queries[10]).toBe('COMMIT');
    expect(mockClient.release).toHaveBeenCalledTimes(1);
  });

  it('a crash after the link update ROLLBACKs: no relink insert reaches COMMIT, no custody row is attempted', async () => {
    mockClient.query
      .mockResolvedValueOnce({ rows: [] }) // BEGIN
      .mockResolvedValueOnce({ rows: [{ envelope: JSON.stringify(envelope('ev-3')) }] }) // SELECT ... FOR UPDATE
      .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // UPDATE envelopes (link written)
      .mockResolvedValueOnce({ rows: [{ highest: null }] }) // SELECT MAX(revision_no)
      .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // INSERT envelope_revisions
      .mockRejectedValueOnce(new Error('connection reset by peer')) // INSERT chain_relinks — the crash
      .mockResolvedValueOnce({ rows: [] }); // ROLLBACK

    await expect(adapter.applyRelink(relink, [{ evidenceId: 'ev-3', entry }])).rejects.toThrow('connection reset by peer');

    const queries: string[] = mockClient.query.mock.calls.map((c: unknown[]) => c[0] as string);
    expect(queries).toContain('ROLLBACK');
    expect(queries).not.toContain('COMMIT');
    expect(queries.some((q) => q.includes('INSERT INTO custody_entries'))).toBe(false);
    expect(mockClient.release).toHaveBeenCalledTimes(1);
  });
});
