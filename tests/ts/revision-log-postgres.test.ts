/**
 * The append-only revision log against a LIVE Postgres.
 *
 * Why a live leg and not the mocked one. The SQLite and memory legs in
 * `revision-log.test.ts` prove the adapter logic; what only a real Postgres
 * proves is that the DDL `ensureTables()` issues actually installs, that the
 * append-only triggers actually fire on UPDATE, DELETE and TRUNCATE, and that
 * the partial covering index is really the plan the planner picks for the
 * capture probe. Those are the parts that would fail silently in production —
 * a trigger that was never created refuses nothing, and nothing else in the
 * system notices.
 *
 * Runs when the Postgres legs do (tests/ts/helpers/postgres-test-db.ts), in a
 * schema of this file's own, emptied before each case.
 */
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { EvidenceEnvelope, SchemaRegistry, TamperIncident } from '@tzun/engine';

const pgSchema = pgSuiteSchema('revision_log_postgres');

function makeEnvelope(
  evidenceId: string,
  sequenceNumber: number,
  digest: string,
  chainLink: string | null,
): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'rec-test',
      aiOutput: { recommendation: 'approve' },
      action: 'approved',
      reason: `record-${sequenceNumber}`,
      capturedAt: '2026-09-12T10:00:00.000Z',
      sequenceNumber,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: { canonicalDigest: digest, chainLink },
    nonRepudiation: {},
    custodyChain: [
      { timestamp: '2026-09-12T10:00:00.000Z', actor: 'jane@acme.example', action: 'decision_captured', systemId: 'rec-test' },
    ],
    attestationStatus: 'none',
  };
}

const digestFor = (n: number): string => String(n).repeat(64).slice(0, 64);

if (PG_TESTS_ENABLED) {
  describe('revision log (live Postgres)', () => {
    let adapter: PostgresStorageAdapter;

    const pool = (): import('pg').Pool =>
      (adapter as unknown as { pool: import('pg').Pool }).pool;

    beforeAll(async () => {
      adapter = new PostgresStorageAdapter(pgSchema.url);
      await adapter.ensureTables();
    });
    // Every table in the schema, so one case cannot leak into the next. The
    // store identity goes with the rows, and a store with no identity cannot
    // name its evidence logs, so each case opens the store again, as the SDK
    // does on start-up, and it mints a new one.
    beforeEach(async () => {
      await pgSchema.empty();
      await adapter.ensureTables();
    });
    afterAll(async () => { await adapter.close(); });

    it('ensureTables installs the table, the partial covering index and the append-only triggers', async () => {
      const cols = await pool().query<{ column_name: string; data_type: string; is_nullable: string }>(
        `SELECT column_name, data_type, is_nullable FROM information_schema.columns
          WHERE table_schema = current_schema() AND table_name = 'envelope_revisions'
          ORDER BY column_name`,
      );
      expect(cols.rows.map((r) => r.column_name)).toEqual([
        'actor', 'canonical_digest', 'cause', 'chain_link', 'created_at',
        'evidence_id', 'recorded_at', 'revision_no',
      ]);
      // chain_link is the one nullable field that matters: a genesis record
      // has no link, and recording that as the string 'null' would be
      // indistinguishable from a real link with that value.
      expect(cols.rows.find((r) => r.column_name === 'chain_link')!.is_nullable).toBe('YES');
      expect(cols.rows.find((r) => r.column_name === 'canonical_digest')!.is_nullable).toBe('NO');

      const indexes = await pool().query<{ indexdef: string }>(
        `SELECT indexdef FROM pg_indexes
          WHERE schemaname = current_schema() AND tablename = 'envelope_revisions'`,
      );
      const defs = indexes.rows.map((r) => r.indexdef).join('\n');
      expect(defs).toMatch(/PRIMARY KEY|UNIQUE INDEX .*_pkey/);
      expect(defs).toContain('idx_envelope_revisions_capture');
      expect(defs).toMatch(/WHERE \(revision_no = 0\)/);

      const triggers = await pool().query<{ tgname: string }>(
        `SELECT tgname FROM pg_trigger WHERE tgrelid = 'envelope_revisions'::regclass AND NOT tgisinternal
          ORDER BY tgname`,
      );
      expect(triggers.rows.map((r) => r.tgname)).toEqual([
        'envelope_revisions_block_mutation_trigger',
        'envelope_revisions_block_truncate_trigger',
      ]);
    });

    it('store() writes revision 0 in the same transaction, and the capture probe is index-only', async () => {
      const envelope = makeEnvelope('pg-rev-1', 1, digestFor(1), null);
      await adapter.store(envelope, 'default');

      const revisions = await adapter.listEnvelopeRevisions('pg-rev-1');
      expect(revisions).toEqual([
        expect.objectContaining({
          evidenceId: 'pg-rev-1',
          revisionNo: 0,
          canonicalDigest: digestFor(1),
          chainLink: null,
          cause: 'capture',
          actor: 'jane@acme.example',
        }),
      ]);
      // recorded_at is TEXT, not TIMESTAMPTZ: the driver hands back a string
      // on every backend, which is what keeps the adapters comparable.
      expect(typeof revisions[0].recordedAt).toBe('string');
      expect(revisions[0].recordedAt).toMatch(/^\d{4}-\d{2}-\d{2}T.*Z$/);

      // The O(1) probe, checked on the PLAN rather than on faith. A table
      // born without the index plans as "Seq Scan on envelope_revisions",
      // which is O(rows) per chain walk and is what would make this check
      // something a caller switches off. seqscan is disabled for the EXPLAIN
      // because on a one-row table Postgres would rightly pick a seq scan
      // whether the index existed or not, and then the assertion would be
      // about table size instead of about the schema.
      const planText = await explainCaptureProbe(pool(), 'pg-rev-1');
      expect(planText).toContain('idx_envelope_revisions_capture');
      expect(planText).not.toContain('Seq Scan on envelope_revisions');
    });

    it('UPDATE, DELETE and TRUNCATE against the revision rows are all refused by the database', async () => {
      await adapter.store(makeEnvelope('pg-rev-2', 1, digestFor(2), null), 'default');

      await expect(
        pool().query("UPDATE envelope_revisions SET canonical_digest = 'f' WHERE evidence_id = 'pg-rev-2'"),
      ).rejects.toThrow(/append-only \(UPDATE refused\)/);
      await expect(
        pool().query("DELETE FROM envelope_revisions WHERE evidence_id = 'pg-rev-2'"),
      ).rejects.toThrow(/append-only \(DELETE refused\)/);
      // Row-level DELETE triggers do not fire on TRUNCATE; the statement-level
      // one is why the whole log cannot be emptied in one statement.
      await expect(
        pool().query('TRUNCATE envelope_revisions'),
      ).rejects.toThrow(/append-only \(TRUNCATE refused\)/);

      const rows = await adapter.listEnvelopeRevisions('pg-rev-2');
      expect(rows).toHaveLength(1);
      expect(rows[0].canonicalDigest).toBe(digestFor(2));
    });

    it('relink() refuses the rewrite-and-reseat and leaves nothing behind; an honest link break still repairs', async () => {
      // Three records, honestly linked. The digests here are literals rather
      // than real canonical hashes, so the recompute guard would refuse
      // everything; the relink is driven through a RecoveryManager whose
      // registry knows no such schema... which is why this case builds the
      // chain through the SDK-shaped path instead: real digests, real links.
      const { Tzun } = await import('../../src/sdk/index');
      const tzun = await Tzun.init({ dbUrl: pgSchema.url });
      let victimId = '';
      let successorId = '';
      let captureDigest = '';
      try {
        const captured: EvidenceEnvelope[] = [];
        for (let i = 1; i <= 4; i++) {
          const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `record-${i}` });
          expect(r.stored).toBe(true);
          captured.push(r.envelope);
        }
        victimId = captured[1].payload.evidenceId;
        successorId = captured[2].payload.evidenceId;
        captureDigest = captured[1].integrity.canonicalDigest;

        // THE RESEAT, applied behind the adapter's back under the explicit
        // trigger bypass — the append-only triggers on `envelopes` are what an
        // attacker with the DB owner's credentials steps over, and this is
        // that step, made visible.
        const registry = new SchemaRegistry();
        const schema = registry.get('v1.0')!;
        const { canonicalSerialize, computeDigest, EvidenceChain } = await import('@tzun/engine');
        const victim = (await adapter.retrieve(victimId))!;
        victim.payload.reason = 'Approved — the approver never wrote this';
        const forged = computeDigest(
          canonicalSerialize(victim.payload as unknown as Record<string, unknown>, schema.hashedFieldSet),
        );
        victim.integrity.canonicalDigest = forged;
        const chain = new EvidenceChain();
        chain.restore(captured[0].integrity.canonicalDigest);
        victim.integrity.chainLink = chain.computeLink(forged);
        await rawUpdateEnvelope(pool(), victimId, victim, forged);
        expect(forged).not.toBe(captureDigest);

        // The signature an operator sees: ONE broken link, no digest mismatch
        // — plus digestSuperseded, the finding that separates it from an
        // honest break.
        const before = await tzun.verifyChainCompleteness();
        expect(before.brokenLinks).toEqual([successorId]);
        expect(before.digestMismatches).toEqual([]);
        expect(before.digestSuperseded).toEqual([victimId]);
        expect(before.valid).toBe(false);

        const incident: TamperIncident = {
          id: 'pg-inc-reseat',
          detectedAt: new Date().toISOString(),
          severity: 'critical',
          type: 'chain_break',
          affectedRecords: [successorId],
          details: 'Chain break detected during scan.',
          status: 'open',
        };
        await tzun.getStorage().storeIncident(incident);
        await expect(
          tzun.recovery.relink('pg-inc-reseat', { fromSequence: 3, authorizedBy: 'operator@acme.example' }),
        ).rejects.toThrow(/no longer hashes to the digest it was CAPTURED with/);

        // Nothing was written: no relink record, no custody entry vouching
        // for the forged record, and the successor's link is untouched.
        expect(await tzun.getStorage().listRelinks('pg-inc-reseat')).toEqual([]);
        for (const id of [victimId, successorId]) {
          const entries = await tzun.getStorage().listCustodyEntries(id);
          expect(entries.filter((e) => e.action === 'relinked')).toEqual([]);
        }
        expect((await adapter.retrieve(successorId))!.integrity.chainLink)
          .toBe(captured[2].integrity.chainLink);
      } finally {
        await tzun.close();
      }
    });

    it('an HONEST single-link corruption still re-links cleanly and records the repair', async () => {
      const { Tzun } = await import('../../src/sdk/index');
      const tzun = await Tzun.init({ dbUrl: pgSchema.url });
      try {
        const captured: EvidenceEnvelope[] = [];
        for (let i = 1; i <= 4; i++) {
          const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i }, action: 'approved', reason: `honest-${i}` });
          captured.push(r.envelope);
        }
        const victim = captured[2];
        const victimId = victim.payload.evidenceId;

        // Same observable signature as the attack — one inconsistent link —
        // but the payload is untouched, so the record still hashes to the
        // digest it was captured with. This is the discrimination the whole
        // feature buys; if it went red the defence would just be relink()
        // refusing everything.
        const corrupted = (await adapter.retrieve(victimId))!;
        corrupted.integrity.chainLink = 'c'.repeat(64);
        await rawUpdateEnvelope(pool(), victimId, corrupted, corrupted.integrity.canonicalDigest);

        const before = await tzun.verifyChainCompleteness();
        expect(before.brokenLinks).toEqual([victimId]);
        expect(before.digestMismatches).toEqual([]);
        expect(before.digestSuperseded).toEqual([]);

        const incident: TamperIncident = {
          id: 'pg-inc-honest',
          detectedAt: new Date().toISOString(),
          severity: 'critical',
          type: 'chain_break',
          affectedRecords: [victimId],
          details: 'Chain break detected during scan.',
          status: 'open',
        };
        await tzun.getStorage().storeIncident(incident);
        const result = await tzun.recovery.relink('pg-inc-honest', {
          fromSequence: 3,
          authorizedBy: 'operator@acme.example',
        });
        expect(result.chainVerified).toBe(true);
        expect(result.relink.modifiedLinks.map((l) => l.evidenceId)).toEqual([victimId]);

        const after = await tzun.verifyChainCompleteness();
        expect(after).toMatchObject({ valid: true, brokenLinks: [], digestSuperseded: [] });

        const revisions = await adapter.listEnvelopeRevisions(victimId);
        expect(revisions.map((r) => [r.revisionNo, r.cause])).toEqual([[0, 'capture'], [1, 'relink']]);
        expect(revisions[1].actor).toBe('operator@acme.example');
        expect(revisions[1].canonicalDigest).toBe(revisions[0].canonicalDigest);
        expect(revisions[1].chainLink).toBe(victim.integrity.chainLink);
      } finally {
        await tzun.close();
      }
    });
  });
} else {
  describe('revision log (live Postgres)', () => {
    it.skip('skipped: set RUN_INTEGRATION_TESTS=true and DATABASE_URL to run', () => { /* gated */ });
  });
}

/**
 * The plan Postgres would use for the capture probe, with sequential scans
 * disabled so the answer is about the schema rather than about how few rows
 * the test happens to have written.
 */
async function explainCaptureProbe(pool: import('pg').Pool, evidenceId: string): Promise<string> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET LOCAL enable_seqscan = off');
    const result = await client.query<{ 'QUERY PLAN': string }>(
      `EXPLAIN (COSTS OFF) SELECT evidence_id, canonical_digest FROM envelope_revisions
        WHERE revision_no = 0 AND evidence_id = ANY($1::text[])`,
      [[evidenceId]],
    );
    await client.query('COMMIT');
    return result.rows.map((r) => r['QUERY PLAN']).join('\n');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => { /* ignore */ });
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Rewrite a stored envelope the way an attacker with the DB owner's
 * credentials does: straight `UPDATE envelopes`, under the transaction-scoped
 * `session_replication_role = 'replica'` that steps over the immutability
 * triggers. Those triggers are defence in depth against a least-privileged DML
 * role, never a boundary against the owner — which is the entire reason the
 * revision log has to exist.
 */
async function rawUpdateEnvelope(
  pool: import('pg').Pool,
  evidenceId: string,
  envelope: EvidenceEnvelope,
  digest: string,
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query('UPDATE envelopes SET envelope = $1, digest = $2 WHERE evidence_id = $3', [
      JSON.stringify(envelope),
      digest,
      evidenceId,
    ]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => { /* ignore */ });
    throw err;
  } finally {
    client.release();
  }
}
