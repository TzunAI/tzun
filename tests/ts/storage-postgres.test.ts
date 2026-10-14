/**
 * PostgreSQL Storage Adapter Tests
 *
 * These tests mock the pg Pool to avoid requiring a running PostgreSQL instance.
 * They verify that the adapter issues correct SQL queries with correct parameters.
 */
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { EvidenceEnvelope, ChainConflictError } from '@tzun/engine';
import { computeCustodyEntryHash } from '@tzun/engine';
import { FailureRecord } from '@tzun/engine';

// Mock pg module
jest.mock('pg', () => {
  const mockClient = {
    query: jest.fn(),
    release: jest.fn(),
  };
  const mockPool = {
    query: jest.fn(),
    connect: jest.fn().mockResolvedValue(mockClient),
    end: jest.fn().mockResolvedValue(undefined),
  };
  return {
    Pool: jest.fn(() => mockPool),
    __mockPool: mockPool,
    __mockClient: mockClient,
  };
});

const { __mockPool: mockPool, __mockClient: mockClient } = jest.requireMock('pg');

function makeEnvelope(overrides: Partial<{
  evidenceId: string;
  aiSystemId: string;
  capturedAt: string;
  digest: string;
  sequenceNumber: number;
}> = {}): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      links: null,
      evidenceId: overrides.evidenceId ?? 'ev-001',
      schemaVersion: 'v1.0',
      aiSystemId: overrides.aiSystemId ?? 'openai-gpt4',
      aiOutput: { recommendation: 'approve', confidence: 0.94 },
      action: 'approved',
      reason: 'All criteria met',
      capturedAt: overrides.capturedAt ?? '2026-03-22T10:00:00.000Z',
      sequenceNumber: overrides.sequenceNumber ?? 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: {
      canonicalDigest: overrides.digest ?? 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
      chainLink: null,
    },
    nonRepudiation: {},
    custodyChain: [{
      timestamp: '2026-03-22T10:00:00.000Z',
      actor: 'jane@acme.example',
      action: 'decision_captured',
      systemId: 'openai-gpt4',
    }],
    attestationStatus: 'none',
  };
}

describe('PostgresStorageAdapter', () => {
  let adapter: PostgresStorageAdapter;

  beforeEach(async () => {
    jest.clearAllMocks();
    mockPool.query.mockResolvedValue({ rows: [] });
    mockClient.query.mockResolvedValue({ rows: [] });
    adapter = new PostgresStorageAdapter('postgresql://localhost:5432/tzun_test');
    await adapter.ensureTables();
    // ensureTables() acquires a client from the pool and runs its DDL on that
    // client (so the pg_advisory_lock + unlock both happen on the same
    // session). Clear the per-test mockClient call history AFTER setup so
    // subsequent tests only see the calls made by the operation under test.
    mockClient.query.mockClear();
  });

  afterEach(async () => {
    await adapter.close();
  });

  it('creates tables on ensureTables()', async () => {
    // Re-run ensureTables in a fresh context so we capture its call sequence.
    mockClient.query.mockClear();
    adapter = new PostgresStorageAdapter('postgresql://localhost:5432/tzun_test');
    await adapter.ensureTables();

    const calls = mockClient.query.mock.calls;
    // The DDL runs on a dedicated client, bracketed by the advisory lock +
    // unlock on that same client session, so concurrent callers serialize.
    expect(calls[0][0]).toBe('SELECT pg_advisory_lock(2026052501)');
    const createTableCall = calls.find(
      (c: any[]) => typeof c[0] === 'string' && c[0].includes('CREATE TABLE IF NOT EXISTS envelopes')
    );
    expect(createTableCall).toBeDefined();
    expect(calls[calls.length - 1][0]).toBe('SELECT pg_advisory_unlock(2026052501)');
  });

  it('stores an envelope via transactional INSERT', async () => {
    const envelope = makeEnvelope();
    mockClient.query.mockResolvedValue({ rows: [], rowCount: 0 });

    await adapter.store(envelope);

    const queries = mockClient.query.mock.calls.map((c: any[]) => c[0]);
    // mockClient.query was cleared in beforeEach after ensureTables, so these
    // calls are only the store() transaction.
    //
    // The transaction takes the chain append advisory lock as its first act
    // and re-reads the head under it. Both are
    // load-bearing — without the lock two connections read the same head and
    // each write a record at the same sequence — so the order is pinned here
    // deliberately, not incidentally.
    //
    // The sealed-chain check is also inside the transaction, and
    // deliberately so — a seal that lands between an
    // out-of-transaction check and the INSERT would be stepped over.
    //
    // The lock is taken on the TARGET CHAIN — the
    // two-key form, keyed by hashtext(chainId) — and the head is read for that
    // chain. A single-key form would serialise every append in the database
    // across every chain, so a per-chain head would buy correctness and no
    // concurrency.
    expect(queries[0]).toBe('BEGIN');
    expect(queries[1]).toBe('SELECT pg_advisory_xact_lock($1, hashtext($2))');
    expect(queries[2]).toContain('SELECT evidence_id FROM envelopes');
    expect(queries[3]).toContain('SELECT status, sealed_at FROM chains');
    expect(queries[4]).toContain('SELECT last_digest, last_sequence FROM chain_state');
    expect(queries[4]).toContain('WHERE chain_id = $1');
    expect(queries[4]).toContain('FOR UPDATE');
    expect(queries[5]).toContain('INSERT INTO envelopes');
    expect(queries[6]).toContain('INSERT INTO chain_state');
    // The capture revision is written inside the SAME
    // transaction as the record it describes. A separate write would leave a
    // window in which a record exists with no record of what it hashed to,
    // and a record with no capture revision is indistinguishable from a
    // pre-0.3.16 one — which every verifier must treat as unprovable, i.e.
    // exactly the silence the reseat attack needs.
    expect(queries[7]).toContain('INSERT INTO envelope_revisions');
    expect(queries[7]).toContain('ON CONFLICT (evidence_id, revision_no) DO NOTHING');
    expect(mockClient.query.mock.calls[7][1]?.[1]).toBe(0);
    expect(mockClient.query.mock.calls[7][1]?.[5]).toBe('capture');
    expect(queries[8]).toBe('COMMIT');
    expect(mockClient.release).toHaveBeenCalled();
  });

  it('rejects duplicate evidenceId', async () => {
    const envelope = makeEnvelope();
    mockClient.query
      .mockResolvedValueOnce({ rows: [] }) // BEGIN
      .mockResolvedValueOnce({ rows: [] }) // pg_advisory_xact_lock
      .mockResolvedValueOnce({ rows: [{ evidence_id: 'ev-001' }], rowCount: 1 }) // SELECT finds duplicate
      .mockResolvedValueOnce({ rows: [] }); // ROLLBACK

    await expect(adapter.store(envelope)).rejects.toThrow('already exists');
  });

  it('refuses a conditional append when the stored head is not the expected one', async () => {
    // The head check runs against the row read INSIDE the
    // locked transaction, and a mismatch must abort the write entirely.
    const envelope = makeEnvelope();
    mockClient.query
      .mockResolvedValueOnce({ rows: [] }) // BEGIN
      .mockResolvedValueOnce({ rows: [] }) // pg_advisory_xact_lock
      .mockResolvedValueOnce({ rows: [], rowCount: 0 }) // no duplicate evidence id
      .mockResolvedValueOnce({ rows: [{ last_digest: 'sha256:other', last_sequence: 7 }] })
      .mockResolvedValueOnce({ rows: [] }); // ROLLBACK

    await expect(
      adapter.store(envelope, 'default', {
        expectChainHead: { sequence: 3, digest: 'sha256:ours' },
      }),
    ).rejects.toThrow(ChainConflictError);

    const queries = mockClient.query.mock.calls.map((c: any[]) => c[0]);
    expect(queries).not.toContain(expect.stringContaining('INSERT INTO envelopes'));
    expect(queries[queries.length - 1]).toBe('ROLLBACK');
  });

  it('retrieves an envelope by evidenceId', async () => {
    const envelope = makeEnvelope();
    mockPool.query.mockResolvedValueOnce({
      rows: [{ envelope: JSON.stringify(envelope) }],
    });

    const result = await adapter.retrieve('ev-001');
    expect(result).toEqual(envelope);

    const queryCall = mockPool.query.mock.calls[mockPool.query.mock.calls.length - 1];
    expect(queryCall[0]).toContain('SELECT envelope FROM envelopes WHERE evidence_id');
    expect(queryCall[1]).toEqual(['ev-001']);
  });

  it('returns null for non-existent evidenceId', async () => {
    mockPool.query.mockResolvedValueOnce({ rows: [] });
    const result = await adapter.retrieve('non-existent');
    expect(result).toBeNull();
  });

  it('lists envelopes with optional filtering and pagination', async () => {
    const envelope1 = makeEnvelope({ evidenceId: 'ev-001' });
    const envelope2 = makeEnvelope({ evidenceId: 'ev-002' });
    mockPool.query.mockResolvedValueOnce({
      rows: [
        { envelope: JSON.stringify(envelope2) },
        { envelope: JSON.stringify(envelope1) },
      ],
    });

    const results = await adapter.list({ aiSystemId: 'openai-gpt4', limit: 10, offset: 0, order: 'desc' });
    expect(results).toHaveLength(2);

    const queryCall = mockPool.query.mock.calls[mockPool.query.mock.calls.length - 1];
    // Not a bare `ORDER BY captured_at DESC`: a sort on the microsecond
    // TIMESTAMPTZ with no tie-break would order two records 500µs apart by
    // instant here and by sequence on memory/SQLite, and leave equal instants
    // in arbitrary order. The contract (src/storage/list-order.ts)
    // is the instant at millisecond precision, then sequenceNumber, then
    // evidenceId, all in one direction.
    expect(queryCall[0]).not.toContain('ORDER BY captured_at DESC');
    expect(queryCall[0]).toContain("ORDER BY date_trunc('milliseconds', captured_at) DESC");
    expect(queryCall[0]).toContain("(envelope->'payload'->>'sequenceNumber')::int DESC");
    expect(queryCall[0]).toContain('evidence_id DESC');
    expect(queryCall[0]).toContain('ai_system_id = $');
    expect(queryCall[0]).toContain('LIMIT');
    expect(queryCall[0]).toContain('OFFSET');
  });

  it('tracks last digest via chain_state table', async () => {
    mockPool.query.mockResolvedValueOnce({
      rows: [{ last_digest: 'digest-aaa' }],
    });

    const result = await adapter.getLastDigest();
    expect(result).toBe('digest-aaa');

    const queryCall = mockPool.query.mock.calls[mockPool.query.mock.calls.length - 1];
    expect(queryCall[0]).toContain('SELECT last_digest FROM chain_state');
  });

  it('tracks last sequence via chain_state table', async () => {
    mockPool.query.mockResolvedValueOnce({
      rows: [{ last_sequence: 5 }],
    });

    const result = await adapter.getLastSequence();
    expect(result).toBe(5);

    const queryCall = mockPool.query.mock.calls[mockPool.query.mock.calls.length - 1];
    expect(queryCall[0]).toContain('SELECT last_sequence FROM chain_state');
  });

  it('returns 0 for getLastSequence when no records exist', async () => {
    mockPool.query.mockResolvedValueOnce({ rows: [] });

    const result = await adapter.getLastSequence();
    expect(result).toBe(0);
  });

  it('stores failure records', async () => {
    const failure: FailureRecord = {
      failureType: 'validation_failure',
      evidenceId: 'ev-001',
      diagnosticMetadata: { reason: 'missing field' },
      capturedAt: '2026-03-22T10:00:00.000Z',
    };
    mockPool.query.mockResolvedValueOnce({ rows: [] });
    await expect(adapter.storeFailure(failure)).resolves.toBeUndefined();

    const queryCall = mockPool.query.mock.calls[mockPool.query.mock.calls.length - 1];
    expect(queryCall[0]).toContain('INSERT INTO failures');
  });

  // `updateEnvelopeChainLink` and
  // `appendCustodyEntry` rewrite the full envelope JSONB blob after a
  // SELECT — without a row lock, concurrent calls race and lose updates.
  // Both methods must run in a transaction with `SELECT ... FOR UPDATE`
  // so they serialize against each other on the same row.
  describe('updateEnvelopeChainLink (row lock)', () => {
    it('serializes via BEGIN / SELECT ... FOR UPDATE / UPDATE / COMMIT on a dedicated client', async () => {
      const envelope = makeEnvelope();
      // Clear the ensureTables traffic so we can assert this method's traffic in isolation.
      mockClient.query.mockReset();
      mockClient.release.mockReset();
      mockPool.connect.mockClear();

      mockClient.query
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [{ envelope: JSON.stringify(envelope) }] }) // SELECT ... FOR UPDATE
        .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // UPDATE
        .mockResolvedValueOnce({ rows: [{ highest: null }] }) // SELECT MAX(revision_no)
        .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // INSERT envelope_revisions
        .mockResolvedValueOnce({ rows: [] }); // COMMIT

      await adapter.updateEnvelopeChainLink('ev-001', 'new-chain-link-digest');

      expect(mockPool.connect).toHaveBeenCalledTimes(1);

      const queries = mockClient.query.mock.calls.map((c: any[]) => c[0]);
      expect(queries[0]).toBe('BEGIN');
      expect(queries[1]).toContain('SELECT envelope FROM envelopes WHERE evidence_id');
      expect(queries[1]).toMatch(/FOR UPDATE\s*$/);
      expect(mockClient.query.mock.calls[1][1]).toEqual(['ev-001']);
      expect(queries[2]).toContain('UPDATE envelopes SET envelope');
      // The serialized envelope on the UPDATE must include the new chainLink.
      const updateParams = mockClient.query.mock.calls[2][1];
      const serialized = JSON.parse(updateParams[0]);
      expect(serialized.integrity.chainLink).toBe('new-chain-link-digest');
      expect(updateParams[1]).toBe('ev-001');
      // The link rewrite leaves a revision row in the same
      // transaction, carrying the digest forward unchanged and the NEW link.
      // A repair the store cannot later account for is a repair an auditor
      // has to take on trust.
      expect(queries[3]).toContain('SELECT MAX(revision_no) AS highest FROM envelope_revisions');
      expect(queries[4]).toContain('INSERT INTO envelope_revisions');
      const revisionParams = mockClient.query.mock.calls[4][1];
      // No prior rows -> revision 1, NOT 0: revision 0 is the capture
      // assertion and must never be backfilled from a record's present state.
      expect(revisionParams[1]).toBe(1);
      expect(revisionParams[3]).toBe('new-chain-link-digest');
      expect(revisionParams[5]).toBe('relink');
      expect(queries[5]).toBe('COMMIT');

      expect(mockClient.release).toHaveBeenCalledTimes(1);
    });

    it('ROLLBACKs and releases the client when the record is missing', async () => {
      mockClient.query.mockReset();
      mockClient.release.mockReset();
      mockPool.connect.mockClear();

      mockClient.query
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [] }) // SELECT ... FOR UPDATE (no row)
        .mockResolvedValueOnce({ rows: [] }); // ROLLBACK

      await expect(adapter.updateEnvelopeChainLink('missing', 'x')).rejects.toThrow(
        'Evidence record "missing" not found.'
      );

      const queries = mockClient.query.mock.calls.map((c: any[]) => c[0]);
      expect(queries).toContain('ROLLBACK');
      expect(queries).not.toContain('COMMIT');
      expect(mockClient.release).toHaveBeenCalledTimes(1);
    });
  });

  describe('appendCustodyEntry (row lock; hashed and chained)', () => {
    // The append is a `custody_entries` row insert plus the mirrored, hashed
    // entry, under the row lock and on one client between one BEGIN and one
    // COMMIT. An entry written into the blob VERBATIM, as plain JSON in a
    // write nothing else is part of, could be removed with one UPDATE, and
    // nothing would bind it to the record.
    it('serializes via BEGIN / SELECT ... FOR UPDATE / tail read / INSERT row / UPDATE / COMMIT on a dedicated client', async () => {
      const envelope = makeEnvelope();
      mockClient.query.mockReset();
      mockClient.release.mockReset();
      mockPool.connect.mockClear();

      mockClient.query
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [{ envelope: JSON.stringify(envelope), chain_id: 'default' }] }) // SELECT ... FOR UPDATE
        .mockResolvedValueOnce({ rows: [] }) // SELECT entry_hash (no previous row)
        .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // INSERT INTO custody_entries
        .mockResolvedValueOnce({ rows: [], rowCount: 1 }) // UPDATE
        .mockResolvedValueOnce({ rows: [] }); // COMMIT

      const newEntry = {
        timestamp: '2026-05-10T12:00:00.000Z',
        actor: 'auditor@acme.example',
        action: 'reviewed' as const,
        systemId: 'recovery-ui',
      };

      await adapter.appendCustodyEntry('ev-001', newEntry, { recoveryId: 'ann-1' });

      expect(mockPool.connect).toHaveBeenCalledTimes(1);

      const queries = mockClient.query.mock.calls.map((c: any[]) => c[0]);
      expect(queries[0]).toBe('BEGIN');
      expect(queries[1]).toContain('SELECT envelope, chain_id FROM envelopes WHERE evidence_id');
      expect(queries[1]).toMatch(/FOR UPDATE\s*$/);
      expect(mockClient.query.mock.calls[1][1]).toEqual(['ev-001']);
      expect(queries[2]).toContain('SELECT entry_hash FROM custody_entries WHERE evidence_id');
      expect(queries[3]).toContain('INSERT INTO custody_entries');
      const insertParams = mockClient.query.mock.calls[3][1];
      const expectedHash = computeCustodyEntryHash({
        prevEntryHash: null,
        evidenceId: 'ev-001',
        canonicalDigest: envelope.integrity.canonicalDigest,
        ...newEntry,
        metadata: null,
      });
      // (evidence_id, chain_id, canonical_digest, action, actor, ts, system_id,
      //  metadata, metadata_canonical, prev_entry_hash, entry_hash, recovery_id)
      expect(insertParams).toEqual([
        'ev-001', 'default', envelope.integrity.canonicalDigest, 'reviewed', 'auditor@acme.example',
        '2026-05-10T12:00:00.000Z', 'recovery-ui', null, null, null, expectedHash, 'ann-1',
      ]);
      expect(queries[4]).toContain('UPDATE envelopes SET envelope');
      const updateParams = mockClient.query.mock.calls[4][1];
      const serialized = JSON.parse(updateParams[0]);
      expect(serialized.custodyChain[serialized.custodyChain.length - 1]).toEqual({
        ...newEntry, entryHash: expectedHash, prevEntryHash: null,
      });
      expect(updateParams[1]).toBe('ev-001');
      expect(queries[5]).toBe('COMMIT');

      expect(mockClient.release).toHaveBeenCalledTimes(1);
    });

    it('ROLLBACKs and releases the client when the record is missing', async () => {
      mockClient.query.mockReset();
      mockClient.release.mockReset();
      mockPool.connect.mockClear();

      mockClient.query
        .mockResolvedValueOnce({ rows: [] }) // BEGIN
        .mockResolvedValueOnce({ rows: [] }) // SELECT ... FOR UPDATE (no row)
        .mockResolvedValueOnce({ rows: [] }); // ROLLBACK

      await expect(adapter.appendCustodyEntry('missing', {
        timestamp: '2026-05-10T12:00:00.000Z',
        actor: 'auditor@acme.example',
        action: 'reviewed',
        systemId: 'recovery-ui',
      })).rejects.toThrow('Evidence record "missing" not found.');

      const queries = mockClient.query.mock.calls.map((c: any[]) => c[0]);
      expect(queries).toContain('ROLLBACK');
      expect(queries).not.toContain('COMMIT');
      expect(mockClient.release).toHaveBeenCalledTimes(1);
    });
  });
});
