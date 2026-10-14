/**
 * Append-only enforcement against a live Postgres —
 * the second layer of `storage-postgres-append-only.test.ts`, which asserts
 * the DDL `ensureTables()` issues against a mocked `pg`. This layer executes
 * the attack statements and the legitimate ones against a real server, which
 * is the only way to know the plpgsql is right.
 *
 * It is a file of its own because the DDL layer mocks `pg` for every module
 * it loads, the adapter included: there, `ensureTables()` built nothing, and
 * this block passed only when an earlier suite had left the tables behind in a
 * shared schema.
 *
 * Runs when the Postgres legs do (tests/ts/helpers/postgres-test-db.ts), in a
 * schema of this file's own.
 */
import { Pool } from 'pg';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const pgSchema = pgSuiteSchema('append_only_live');
const describeLive = PG_TESTS_ENABLED ? describe : describe.skip;

describeLive('append-only enforcement (live Postgres)', () => {
  let pool: Pool;
  const evidenceId = `ev-h15-${Date.now()}`;

  const envelopeJson = JSON.stringify({
    payload: { evidenceId, action: 'approved', sequenceNumber: 1 },
    integrity: { canonicalDigest: 'd1'.repeat(32), schemaVersion: 'v1.0', chainLink: null },
    custodyChain: [{ actor: 'jane@acme.example', action: 'decision_captured' }],
    nonRepudiation: {},
    attestationStatus: 'none',
  });

  beforeAll(async () => {
    const adapter = new PostgresStorageAdapter(pgSchema.url);
    try {
      await adapter.ensureTables();
    } finally {
      await adapter.close();
    }
    pool = new Pool({ connectionString: pgSchema.url });
    await pool.query(
      `INSERT INTO envelopes (evidence_id, envelope, captured_at, ai_system_id, digest, chain_id)
       VALUES ($1, $2::jsonb, $3, $4, $5, $6)`,
      [evidenceId, envelopeJson, '2026-01-01T00:00:00Z', 'sys-a', `d-${evidenceId}`, 'default'],
    );
  });

  afterAll(async () => {
    await pool?.end();
  });

  const rejected = (sql: string, params: unknown[] = []) =>
    expect(pool.query(sql, params)).rejects.toThrow();

  it('refuses TRUNCATE on envelopes', () => rejected('TRUNCATE envelopes'));

  it('refuses to move a record to another chain', () =>
    rejected('UPDATE envelopes SET chain_id = $1 WHERE evidence_id = $2', ['stolen', evidenceId]));

  it('refuses to reassign ai_system_id', () =>
    rejected('UPDATE envelopes SET ai_system_id = $1 WHERE evidence_id = $2', ['other', evidenceId]));

  it('refuses to rewrite payload.schemaVersion', () =>
    expect(
      pool.query(
        `UPDATE envelopes SET envelope = jsonb_set(envelope,'{payload,schemaVersion}','"v9.9"'::jsonb)
         WHERE evidence_id = $1`,
        [evidenceId],
      ),
    ).rejects.toThrow(/payload is immutable/));

  it('refuses to empty the custody chain', () =>
    rejected(
      `UPDATE envelopes SET envelope = jsonb_set(envelope,'{custodyChain}','[]'::jsonb)
       WHERE evidence_id = $1`,
      [evidenceId],
    ));

  it('refuses to give an existing custody entry a key it did not have', () =>
    expect(
      pool.query(
        `UPDATE envelopes SET envelope = jsonb_set(envelope,'{custodyChain,0,entryHash}','"${'a'.repeat(64)}"'::jsonb)
         WHERE evidence_id = $1`,
        [evidenceId],
      ),
    ).rejects.toThrow(/custodyChain is append-only/));

  it('refuses to rewrite an existing custody actor', () =>
    rejected(
      `UPDATE envelopes SET envelope = jsonb_set(envelope,'{custodyChain,0,actor}','"bob@acme.example"'::jsonb)
       WHERE evidence_id = $1`,
      [evidenceId],
    ));

  it('still allows the writes the SDK itself makes', async () => {
    // relink
    await pool.query(
      `UPDATE envelopes SET envelope = jsonb_set(envelope,'{integrity,chainLink}','"abc"'::jsonb)
       WHERE evidence_id = $1`,
      [evidenceId],
    );
    // custody append
    await pool.query(
      `UPDATE envelopes SET envelope = jsonb_set(envelope,'{custodyChain}',
         (envelope->'custodyChain') || '[{"actor":"admin@acme.example","action":"reviewed"}]'::jsonb)
       WHERE evidence_id = $1`,
      [evidenceId],
    );
    // attestation retry — replaces the artifact, which is why nonRepudiation
    // deliberately is NOT containment-checked
    await pool.query(
      `UPDATE envelopes SET envelope = jsonb_set(envelope,'{nonRepudiation}','{"rfc3161Token":"tok"}'::jsonb)
       WHERE evidence_id = $1`,
      [evidenceId],
    );
  });
});
