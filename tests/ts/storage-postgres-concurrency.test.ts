/**
 * Live-DB concurrency test for the whole-blob writers' row lock.
 *
 * Runs when the Postgres legs do (tests/ts/helpers/postgres-test-db.ts), in a
 * schema of this file's own; CI has no Postgres service.
 *
 * The race this pins: `updateEnvelopeChainLink` and
 * `appendCustodyEntry` both follow a SELECT-then-UPDATE pattern on the entire
 * envelope JSONB blob. Without the row lock, two concurrent calls can each
 * read the same envelope, each rewrite it (one with a new chainLink, the
 * other with a new custody entry), and the second UPDATE clobbers the first.
 *
 * Every iteration uses a unique evidence ID, so the cases in this file do not
 * collide with each other in the schema they share.
 */
import { createHash } from 'node:crypto';
import { PostgresStorageAdapter } from '../../src/storage/postgres';
import { EvidenceEnvelope, ChainConflictError } from '@tzun/engine';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const itIntegration = PG_TESTS_ENABLED ? it : it.skip;
const pgSchema = pgSuiteSchema('storage_concurrency');
const TEST_DB_URL = pgSchema.url;

function makeEnvelope(evidenceId: string): EvidenceEnvelope {
  return {
    envelopeVersion: 'e1',
    payload: {
      links: null,
      decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
      evidenceId,
      schemaVersion: 'v1.0',
      aiSystemId: 'concurrency-test',
      aiOutput: { recommendation: 'approve' },
      action: 'approved',
      reason: 'concurrency-test',
      capturedAt: '2026-05-10T00:00:00.000Z',
      sequenceNumber: 1,
      contributions: null,
      signoffExpectation: null,
    },
    integrity: {
      // 64 lowercase hex, unique per record: the shape of a real digest and
      // of an evidence-log leaf.
      canonicalDigest: createHash('sha256').update(evidenceId).digest('hex'),
      chainLink: null,
    },
    nonRepudiation: {},
    custodyChain: [
      {
        timestamp: '2026-05-10T00:00:00.000Z',
        actor: 'concurrency-test@tzun.test',
        action: 'decision_captured',
        systemId: 'concurrency-test',
      },
    ],
    attestationStatus: 'none',
  };
}

describe('PostgresStorageAdapter — concurrent updateEnvelopeChainLink + appendCustodyEntry (row lock)', () => {
  let adapter: PostgresStorageAdapter;

  beforeAll(async () => {
    if (!PG_TESTS_ENABLED) return;
    adapter = new PostgresStorageAdapter(TEST_DB_URL);
    await adapter.ensureTables();
  }, 30000);

  afterAll(async () => {
    if (!PG_TESTS_ENABLED) return;
    // No row cleanup: the envelopes table has an append-only delete trigger;
    // the schema goes, rows and all, when the file is done.
    if (adapter) await adapter.close();
  }, 30000);

  itIntegration(
    'never loses an update under 50 concurrent (chainLink, custodyEntry) races',
    async () => {
      const ITERATIONS = 50;
      const runId = `concurrency-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

      for (let i = 0; i < ITERATIONS; i++) {
        const evidenceId = `${runId}-${i}`;
        const envelope = makeEnvelope(evidenceId);
        // Each record on a chain of its own: one record per position.
        await adapter.store(envelope, evidenceId);

        const newChainLink = `relinked-digest-${i}`;
        const newEntry = {
          timestamp: '2026-05-10T00:00:01.000Z',
          actor: 'concurrent-appender@tzun.test',
          action: 'reviewed' as const,
          systemId: 'concurrency-test',
          metadata: { iteration: i },
        };

        await Promise.all([
          adapter.updateEnvelopeChainLink(evidenceId, newChainLink),
          adapter.appendCustodyEntry(evidenceId, newEntry),
        ]);

        const after = await adapter.retrieve(evidenceId);
        expect(after).not.toBeNull();
        expect(after!.integrity.chainLink).toBe(newChainLink);
        // Original `decision_captured` entry plus our concurrent `reviewed` append.
        expect(after!.custodyChain).toHaveLength(2);
        expect(after!.custodyChain[1]).toMatchObject({
          actor: 'concurrent-appender@tzun.test',
          action: 'reviewed',
          systemId: 'concurrency-test',
          metadata: { iteration: i },
        });
      }
    },
    120000
  );

  // -------------------------------------------------------------------------
  // updateAttestation is the THIRD whole-blob rewriter, and it takes the same
  // row lock as the other two.
  //
  // updateEnvelopeChainLink and appendCustodyEntry run
  // BEGIN / SELECT ... FOR UPDATE / UPDATE / COMMIT on a dedicated client, and
  // every whole-blob rewriter must take the same lock or "the loser overwrites
  // the winner". Were updateAttestation to run its SELECT and its UPDATE as
  // two autocommit pool queries, a recovery write committing in between would
  // be silently reverted: retryPendingAttestations() on a timer + an operator
  // relinking a chain would never converge, because each attestation write
  // would roll the healed chainLink back to the broken value and the next scan
  // would raise chain_break again.
  //
  // Both updates below touch DIFFERENT fields of the envelope — that is the
  // point. The blob is rewritten whole, so field-disjointness saves nothing.
  // -------------------------------------------------------------------------
  itIntegration(
    'never loses a concurrent relink under 50 (updateAttestation, chainLink) races',
    async () => {
      const ITERATIONS = 50;
      const runId = `attest-race-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

      for (let i = 0; i < ITERATIONS; i++) {
        const evidenceId = `${runId}-${i}`;
        await adapter.store(makeEnvelope(evidenceId), evidenceId);

        const healedChainLink = `relinked-digest-${i}`;

        await Promise.all([
          adapter.updateEnvelopeChainLink(evidenceId, healedChainLink),
          adapter.updateAttestation(
            evidenceId,
            { rfc3161Token: `token-${i}` },
            'complete',
          ),
        ]);

        const after = await adapter.retrieve(evidenceId);
        expect(after).not.toBeNull();
        // The relink must survive the attestation write...
        expect(after!.integrity.chainLink).toBe(healedChainLink);
        // ...and the attestation write must survive the relink.
        expect(after!.attestationStatus).toBe('complete');
        expect(after!.nonRepudiation.rfc3161Token).toBe(`token-${i}`);
      }
    },
    120000,
  );

  // Same race against the custody append, which is the other row-locked writer.
  itIntegration(
    'never loses a concurrent custody append under 50 (updateAttestation, custody) races',
    async () => {
      const ITERATIONS = 50;
      const runId = `attest-custody-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

      for (let i = 0; i < ITERATIONS; i++) {
        const evidenceId = `${runId}-${i}`;
        await adapter.store(makeEnvelope(evidenceId), evidenceId);

        await Promise.all([
          adapter.appendCustodyEntry(evidenceId, {
            timestamp: '2026-05-10T00:00:01.000Z',
            actor: 'forker@tzun.test',
            action: 'reviewed' as const,
            systemId: 'concurrency-test',
            metadata: { iteration: i },
          }),
          adapter.updateAttestation(
            evidenceId,
            { rfc3161Token: `token-${i}` },
            'partial',
          ),
        ]);

        const after = await adapter.retrieve(evidenceId);
        expect(after!.custodyChain).toHaveLength(2);
        expect(after!.attestationStatus).toBe('partial');
        expect(after!.nonRepudiation.rfc3161Token).toBe(`token-${i}`);
      }
    },
    120000,
  );

  // ensureTables() runs its full DDL block (incl. CREATE OR REPLACE FUNCTION +
  // CREATE TRIGGER) under a pg_advisory_lock. Without a serializing lock,
  // several processes calling it against the same Postgres — jest workers,
  // demo server + integration tests, several SDK instances booting in
  // parallel — race on pg_proc / pg_trigger catalog rows, and Postgres
  // surfaces the race as `tuple concurrently updated`. This test calls
  // ensureTables() N times in parallel and asserts none of them throw.
  itIntegration(
    'ensureTables() is safe to call concurrently from many adapters',
    async () => {
      const PARALLEL = 8;
      const adapters: PostgresStorageAdapter[] = [];
      try {
        for (let i = 0; i < PARALLEL; i++) {
          adapters.push(new PostgresStorageAdapter(TEST_DB_URL));
        }
        const results = await Promise.allSettled(adapters.map((a) => a.ensureTables()));
        const failures = results.filter((r) => r.status === 'rejected');
        if (failures.length > 0) {
          const reasons = failures.map((f) =>
            (f as PromiseRejectedResult).reason instanceof Error
              ? ((f as PromiseRejectedResult).reason as Error).message
              : String((f as PromiseRejectedResult).reason),
          );
          throw new Error(`expected all ensureTables() to succeed; got ${failures.length} failures:\n${reasons.join('\n')}`);
        }
        expect(results.every((r) => r.status === 'fulfilled')).toBe(true);
      } finally {
        await Promise.allSettled(adapters.map((a) => a.close()));
      }
    },
    60000,
  );
});

/**
 * Live-DB proof that a conditional append is atomic.
 *
 * The mocked suite (storage-postgres.test.ts) pins the query shape; this pins
 * the behaviour under real concurrency. Two adapters share one database, both
 * believing the chain head is X, and both try to append onto it. Exactly one
 * must win. A `store()` that inserted the row and upserted `chain_state` with
 * no head check would land BOTH at the same sequence, and the later
 * `last_digest` write would orphan the other.
 *
 * It appends from sequence 0 on a chain of its own.
 */
describe('chain append is atomic under real concurrency', () => {
  itIntegration('lets exactly one of two concurrent appends onto the same head win', async () => {
    const a = new PostgresStorageAdapter(TEST_DB_URL);
    const b = new PostgresStorageAdapter(TEST_DB_URL);
    await a.ensureTables();

    try {
      const tag = `race-${Date.now()}`;
      const chain = tag;

      const first = makeEnvelope(`${tag}-1`);
      first.payload.sequenceNumber = 1;
      await a.store(first, chain, { expectChainHead: { sequence: 0, digest: null } });
      const head = first.integrity.canonicalDigest;

      // Both contenders were built against the same head.
      const c1 = makeEnvelope(`${tag}-2a`);
      c1.payload.sequenceNumber = 2;
      const c2 = makeEnvelope(`${tag}-2b`);
      c2.payload.sequenceNumber = 2;

      const outcomes = await Promise.allSettled([
        a.store(c1, chain, { expectChainHead: { sequence: 1, digest: head } }),
        b.store(c2, chain, { expectChainHead: { sequence: 1, digest: head } }),
      ]);

      const fulfilled = outcomes.filter((o) => o.status === 'fulfilled');
      const rejected = outcomes.filter((o) => o.status === 'rejected');
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0] as PromiseRejectedResult).reason).toBeInstanceOf(ChainConflictError);

      // Only the winner is on disk.
      const stored = await Promise.all([a.retrieve(`${tag}-2a`), a.retrieve(`${tag}-2b`)]);
      expect(stored.filter(Boolean)).toHaveLength(1);
      expect(await a.getLastSequence(chain)).toBe(2);
    } finally {
      await a.close();
      await b.close();
    }
  });
});
