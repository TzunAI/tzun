// tests/ts/two-writers-chain-conflict-retry.test.ts
//
// Two writers on one store land every capture.
//
// Two `Tzun` instances on one store is what a customer has the day they scale
// one service from one pod to two. The adapter-level compare-and-swap
// (`StoreOptions.expectChainHead`, pinned in capture-sequence-race.test.ts)
// refuses a record built against a head that has moved. This file pins
// everything after the refusal:
//
//   1. the failure is typed: a lost CAS is reported as `chain_conflict` with
//      a `code` and `retryable`, not flattened into an anonymous
//      `serialization_failure`, so a customer can tell "the head moved under
//      me" from "the database is broken";
//   2. `capture()` retries: a refused CAS is retried against the value it
//      lost to, rather than reported as the loss.
//
// Without them, two instances on one Postgres DATABASE_URL running 20
// concurrent `capture()` calls store 10 and drop 10 silently, each as a
// `serialization_failure` with no retryable flag; and on SQLite, with the two
// writers alternating, A stores every round and B fails every round, forever,
// because B's resync after each refusal lands exactly one step behind A's
// next write.
//
// Both layers are pinned here, on REAL adapters — SQLite in every run, and
// Postgres when the Postgres legs run (tests/ts/helpers/postgres-test-db.ts).
// The memory adapter is not evidence about production and is not used.
import { Tzun } from '../../src/sdk/index';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { webauthnChallengeForDigest } from '../../src/attestation/verify-attestation';
import { makeGenuineAssertion } from './attestation-assertion-helpers';
import { computeDigest, type AttestationArtifacts } from '@tzun/engine';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const input = (label: string) => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { label },
  action: 'approved',
  reason: `because ${label}`,
});

function tmpDb(name: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `tzun-test-two-writers-${name}-`));
  return path.join(dir, 'tzun.db');
}

type LogLine = [string, Record<string, unknown>];
function logSink(): { lines: LogLine[]; onLog: (e: string, f: Record<string, unknown>) => void } {
  const lines: LogLine[] = [];
  return { lines, onLog: (e, f) => { lines.push([e, f]); } };
}
const retriesIn = (lines: LogLine[]) =>
  lines.filter(([event]) => event === 'capture_chain_conflict_retry');

/** Rows of the SQLite `failures` table — what an operator's failure query sees. */
function failureRows(dbPath: string): Array<{ failure_type: string; diagnostic_metadata: string }> {
  const adapter = new SqliteStorageAdapter(dbPath);
  try {
    const db = (adapter as unknown as {
      db: { prepare(sql: string): { all(): Array<{ failure_type: string; diagnostic_metadata: string }> } };
    }).db;
    return db.prepare('SELECT failure_type, diagnostic_metadata FROM failures').all();
  } finally {
    void adapter.close();
  }
}

/** How many records the SQLite `envelopes` table holds — what was actually stored. */
function envelopeCount(dbPath: string): number {
  const adapter = new SqliteStorageAdapter(dbPath);
  try {
    const db = (adapter as unknown as {
      db: { prepare(sql: string): { get(): { n: number } } };
    }).db;
    return db.prepare('SELECT count(*) AS n FROM envelopes').get().n;
  } finally {
    void adapter.close();
  }
}

/**
 * A stub orchestrator that records what it is asked to attest, so a test can
 * count ceremonies / TSA round trips and see which digest each one covered.
 * `delayMs` holds the first call open so a timestamp minted before it and one
 * minted after it are distinguishable.
 */
function stubOrchestrator(tzun: Tzun, opts: { delayMs?: number; artifacts?: AttestationArtifacts } = {}) {
  const calls: Array<{ digest: string; inputs: unknown; calledAt: number }> = [];
  (tzun as unknown as { orchestrator: unknown }).orchestrator = {
    attest: async (digest: string, inputs: unknown) => {
      calls.push({ digest, inputs, calledAt: Date.now() });
      if (calls.length === 1 && opts.delayMs) {
        await new Promise((r) => setTimeout(r, opts.delayMs));
      }
      return { ...(opts.artifacts ?? {}), ...((inputs as AttestationArtifacts | undefined) ?? {}) };
    },
    flush: async () => {},
  };
  return calls;
}

const twenty = Array.from({ length: 20 }, (_, i) => i + 1);

/**
 * The measurement, as a reusable assertion: two instances on one store, 20
 * concurrent captures interleaved across them → 20/20 stored, sequences
 * 1..20 with no duplicate, chain verifies clean, and — non-vacuity — at least
 * one refusal actually happened and was retried, so the test is exercising
 * the mechanism and not a store that happened to serialise everything.
 */
async function twentyConcurrentCapturesLandCleanly(
  a: Tzun,
  b: Tzun,
  logs: LogLine[],
): Promise<void> {
  const results = await Promise.all(
    Array.from({ length: 10 }, (_, i) => [a.capture(input(`a${i}`)), b.capture(input(`b${i}`))]).flat(),
  );

  const dropped = results.filter((r) => !r.stored);
  expect(dropped.map((r) => r.failure?.failureType)).toEqual([]);
  expect(results.filter((r) => r.stored)).toHaveLength(20);

  const seqs = results.map((r) => r.envelope.payload.sequenceNumber).sort((x, y) => x - y);
  expect(seqs).toEqual(twenty);

  const completeness = await a.verifyChainCompleteness();
  expect(completeness.valid).toBe(true);
  expect(completeness.totalRecords).toBe(20);
  expect(completeness.brokenLinks).toEqual([]);
  expect(completeness.sequenceGaps).toEqual([]);
  expect(completeness.duplicateSequences).toEqual([]);

  // Both instances agree on the head afterwards: a capture from either lands
  // at 21, which proves the loser's view was re-synced, not just its record.
  const r21 = await b.capture(input('after'));
  expect(r21.stored).toBe(true);
  expect(r21.envelope.payload.sequenceNumber).toBe(21);

  expect(retriesIn(logs).length).toBeGreaterThan(0);
}

describe('two writers on one SQLite file (real adapter)', () => {
  it('20 concurrent captures across two instances → 20/20 stored, chain verifies clean', async () => {
    const dbPath = tmpDb('concurrent');
    const log = logSink();
    const a = await Tzun.init({ mode: 'dev', dbPath, onLog: log.onLog });
    const b = await Tzun.init({ mode: 'dev', dbPath, onLog: log.onLog });
    try {
      await twentyConcurrentCapturesLandCleanly(a, b, log.lines);
      expect(failureRows(dbPath)).toEqual([]);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('alternating writers: the second instance lands every capture', async () => {
    // The permanent form of the conflict. A's cached head is always current
    // (it wrote last) and B's is always one behind. Without the retry, B's
    // resync after each refusal would adopt the head A had ALREADY moved past
    // by the time B's next capture ran: four rounds, four records, all A's,
    // and four `serialization_failure` rows for B.
    const dbPath = tmpDb('alternating');
    const logA = logSink();
    const logB = logSink();
    const a = await Tzun.init({ mode: 'dev', dbPath, onLog: logA.onLog });
    const b = await Tzun.init({ mode: 'dev', dbPath, onLog: logB.onLog });
    try {
      const results = [];
      for (let round = 0; round < 4; round++) {
        results.push(await a.capture(input(`a${round}`)));
        results.push(await b.capture(input(`b${round}`)));
      }
      expect(results.map((r) => r.stored)).toEqual(Array(8).fill(true));
      expect(results.map((r) => r.envelope.payload.sequenceNumber)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);

      const completeness = await a.verifyChainCompleteness();
      expect(completeness.valid).toBe(true);
      expect(completeness.totalRecords).toBe(8);

      // Every one of B's records was refused once (built against A's
      // previous head) and then landed on the retry.
      expect(retriesIn(logB.lines).length).toBeGreaterThan(0);
      expect(failureRows(dbPath)).toEqual([]);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('gives up LOUDLY when attempts run out: a typed, retryable chain_conflict naming both heads', async () => {
    const dbPath = tmpDb('exhausted');
    const log = logSink();
    const a = await Tzun.init({ mode: 'dev', dbPath });
    // `1` disables the retry, so the first refusal is the surfaced one.
    const b = await Tzun.init({ mode: 'dev', dbPath, chainConflictMaxAttempts: 1, onLog: log.onLog });
    try {
      const ra = await a.capture(input('from-a'));
      expect(ra.stored).toBe(true);

      const rb = await b.capture(input('from-b'));
      expect(rb.stored).toBe(false);
      // Layer 1 — the failure is typed: `chain_conflict` with a `code` and
      // `retryable`, not a `serialization_failure` with both undefined.
      expect(rb.failure?.failureType).toBe('chain_conflict');
      expect(rb.failure?.evidenceId).toEqual(expect.any(String));
      expect(rb.failure?.diagnosticMetadata).toMatchObject({
        code: 'chain_conflict',
        retryable: true,
        attempts: 1,
        expectedHead: { sequence: 0, digest: null },
        actualHead: { sequence: 1, digest: ra.envelope.integrity.canonicalDigest },
      });
      expect(rb.failure?.diagnosticMetadata.reason).toMatch(/Chain conflict/);

      // …and it is what the failure table holds, so an operator's alert on
      // `failure_type` files it where it belongs.
      const rows = failureRows(dbPath);
      expect(rows.map((r) => r.failure_type)).toEqual(['chain_conflict']);
      expect(JSON.parse(rows[0].diagnostic_metadata)).toMatchObject({
        code: 'chain_conflict',
        retryable: true,
      });

      expect(log.lines.map(([e]) => e)).toContain('capture_chain_conflict_exhausted');

      // Exhaustion is not a wedge: the store's head was adopted on the way
      // out, so the NEXT capture links from the truth and lands at 2.
      const rb2 = await b.capture(input('from-b-again'));
      expect(rb2.stored).toBe(true);
      expect(rb2.envelope.payload.sequenceNumber).toBe(2);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('re-attests the rebuilt record: the stored digest is the one the orchestrator last saw', async () => {
    // With an orchestrator the digest is attested BEFORE the store. A refused
    // record's attestation covers a digest that was never stored, so the retry
    // must attest the rebuilt digest, not reuse the first attempt's artifacts.
    const dbPath = tmpDb('reattest');
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const b = await Tzun.init({ mode: 'dev', dbPath });
    const attested: string[] = [];
    (b as unknown as { orchestrator: unknown }).orchestrator = {
      attest: async (digest: string) => {
        attested.push(digest);
        return {};
      },
      flush: async () => {},
    };
    try {
      await a.capture(input('from-a'));
      const rb = await b.capture(input('from-b'));
      expect(rb.stored).toBe(true);
      expect(rb.envelope.payload.sequenceNumber).toBe(2);
      // Two attempts, two distinct digests (the sequence number is hashed),
      // and what landed is the second one.
      expect(attested).toHaveLength(2);
      expect(attested[0]).not.toBe(attested[1]);
      expect(rb.envelope.integrity.canonicalDigest).toBe(attested[1]);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it.each([0, -1, 1.5, Number.NaN])('refuses chainConflictMaxAttempts=%p at init', async (bad) => {
    await expect(
      Tzun.init({ mode: 'dev', dbPath: tmpDb('bad-config'), chainConflictMaxAttempts: bad }),
    ).rejects.toThrow(/chainConflictMaxAttempts/);
  });
});

describe('a caller-supplied WebAuthn assertion is bound to ONE digest', () => {
  // The reviewer's ceremony signs `webauthnChallengeForDigest(digest)` for the
  // record they were shown (verify-attestation.ts); that is the whole
  // reason the signature means "this person approved THIS decision". Rebuilding
  // the record at a new sequence changes the digest — the sequence number is
  // hashed — so re-attaching the caller's assertion to the rebuilt record
  // stores a signature that verifies `challenge_mismatch` against its own
  // record: genuine evidence that reads as forged. The backend refuses exactly
  // this server-side (`attested_envelope_cannot_be_restamped`); the local
  // adapters have no such guard, so the retry loop must not walk through
  // it. The SDK cannot re-run a human ceremony, so the only honest
  // answer to a lost CAS here is a loud refusal: the caller re-runs the
  // ceremony against the head they lost to and captures again.
  const reviewed = computeDigest('the record jane was shown');
  const { assertion } = makeGenuineAssertion({
    challenge: webauthnChallengeForDigest(reviewed),
    credentialId: 'cred-jane',
  });

  it('refuses to retry a lost CAS with the assertion attached: typed chain_conflict, nothing stored, not wedged', async () => {
    const dbPath = tmpDb('caller-assertion');
    const log = logSink();
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const b = await Tzun.init({ mode: 'dev', dbPath, onLog: log.onLog });
    try {
      expect((await a.capture(input('from-a'))).stored).toBe(true);

      const rb = await b.capture({
        ...input('from-b'),
        attestationInputs: { webauthnAssertion: assertion },
      });

      // Without the guard this would be `stored: true` at sequence 2,
      // carrying the assertion verbatim, with nothing anywhere saying its
      // challenge was for a different digest.
      expect(rb.stored).toBe(false);
      expect(rb.failure?.failureType).toBe('chain_conflict');
      expect(rb.failure?.diagnosticMetadata).toMatchObject({
        code: 'chain_conflict',
        retryable: true,
        attempts: 1,
        retryRefused: 'caller_attestation_is_digest_bound',
      });
      expect(envelopeCount(dbPath)).toBe(1);
      expect(failureRows(dbPath).map((r) => r.failure_type)).toEqual(['chain_conflict']);
      expect(JSON.parse(failureRows(dbPath)[0].diagnostic_metadata)).toMatchObject({
        retryRefused: 'caller_attestation_is_digest_bound',
      });

      // No retry was attempted; the refusal is its own log event.
      expect(retriesIn(log.lines)).toEqual([]);
      const refused = log.lines.filter(([e]) => e === 'capture_chain_conflict_retry_refused');
      expect(refused).toHaveLength(1);
      expect(refused[0][1]).toMatchObject({
        reason: 'caller_attestation_is_digest_bound',
        attempt: 1,
        actualHead: { sequence: 1 },
      });

      // Not a wedge: the head was adopted on the way out, so a fresh ceremony
      // (here: a capture without one) lands at 2.
      const rb2 = await b.capture(input('from-b-again'));
      expect(rb2.stored).toBe(true);
      expect(rb2.envelope.payload.sequenceNumber).toBe(2);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('refuses before paying for a second ceremony or TSA round trip (orchestrator path)', async () => {
    const dbPath = tmpDb('caller-assertion-orchestrated');
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const b = await Tzun.init({ mode: 'dev', dbPath });
    const calls = stubOrchestrator(b, { artifacts: { rfc3161Token: 'tok' } });
    try {
      await a.capture(input('from-a'));
      const rb = await b.capture({
        ...input('from-b'),
        attestationInputs: { webauthnAssertion: assertion },
      });
      expect(rb.stored).toBe(false);
      expect(rb.failure?.failureType).toBe('chain_conflict');
      expect(rb.failure?.diagnosticMetadata.retryRefused).toBe('caller_attestation_is_digest_bound');
      // One attestation — the refused record's. The loop did not go around.
      expect(calls).toHaveLength(1);
      expect((calls[0].inputs as { webauthnAssertion: unknown }).webauthnAssertion).toBe(assertion);
      expect(envelopeCount(dbPath)).toBe(1);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('still retries when the caller supplied only a signerIdentity — an IdP token is not digest-bound', async () => {
    const dbPath = tmpDb('caller-identity');
    const log = logSink();
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const b = await Tzun.init({ mode: 'dev', dbPath, onLog: log.onLog });
    const signerIdentity = { idpToken: 'jwt-abc', idpIssuer: 'https://accounts.example' };
    try {
      await a.capture(input('from-a'));
      const rb = await b.capture({ ...input('from-b'), attestationInputs: { signerIdentity } });
      expect(rb.stored).toBe(true);
      expect(rb.envelope.payload.sequenceNumber).toBe(2);
      expect(rb.envelope.nonRepudiation.signerIdentity).toEqual(signerIdentity);
      expect(retriesIn(log.lines)).toHaveLength(1);
      expect(envelopeCount(dbPath)).toBe(2);
    } finally {
      await a.close();
      await b.close();
    }
  });
});

describe('the rebuilt record keeps the identity of the first attempt', () => {
  // A retry is the same decision at a new chain position, so the record keeps
  // its `evidenceId` and `capturedAt`; only the sequence, link and digest
  // change. A fresh id and timestamp per attempt would make the
  // `capture_chain_conflict_retry` log line name an evidenceId that never
  // reaches storage — so a retry could not be correlated with the record it
  // produced — and let `capturedAt` drift later by one TSA round trip per
  // attempt. The Python SDK pins both.
  it('the evidenceId in the retry log is the evidenceId that was stored (dev path)', async () => {
    const dbPath = tmpDb('pinned-id');
    const log = logSink();
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const b = await Tzun.init({ mode: 'dev', dbPath, onLog: log.onLog });
    try {
      await a.capture(input('from-a'));
      const rb = await b.capture(input('from-b'));
      expect(rb.stored).toBe(true);
      expect(rb.envelope.payload.sequenceNumber).toBe(2);
      const retries = retriesIn(log.lines);
      expect(retries).toHaveLength(1);
      expect(retries[0][1].evidenceId).toBe(rb.envelope.payload.evidenceId);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it('evidenceId and capturedAt are minted once, before the first attestation (orchestrator path)', async () => {
    const dbPath = tmpDb('pinned-identity');
    const log = logSink();
    const a = await Tzun.init({ mode: 'dev', dbPath });
    const b = await Tzun.init({ mode: 'dev', dbPath, onLog: log.onLog });
    // Hold the first attestation open, so a timestamp minted for the second
    // attempt would be measurably later than the first attest call.
    const holdMs = 30;
    const calls = stubOrchestrator(b, { delayMs: holdMs, artifacts: { rfc3161Token: 'tok' } });
    try {
      await a.capture(input('from-a'));
      const rb = await b.capture(input('from-b'));
      expect(rb.stored).toBe(true);
      expect(calls).toHaveLength(2);
      expect(calls[0].digest).not.toBe(calls[1].digest);
      expect(rb.envelope.integrity.canonicalDigest).toBe(calls[1].digest);

      const retries = retriesIn(log.lines);
      expect(retries).toHaveLength(1);
      expect(retries[0][1].evidenceId).toBe(rb.envelope.payload.evidenceId);
      // capturedAt predates the FIRST attest call, not the second.
      expect(Date.parse(rb.envelope.payload.capturedAt)).toBeLessThanOrEqual(calls[0].calledAt);
      // Non-vacuity: the hold was long enough that a per-attempt timestamp
      // would have tripped the line above. NOT `>= holdMs`: Node stamps a
      // timer with libuv's cached loop time, which predates the setTimeout()
      // call by however long this tick has already run (here: the digest
      // and the SQLite refusal), so a 30 ms timer can fire after 29 ms of
      // `Date.now()`. Half the hold is ten times the skew ever observed.
      expect(calls[1].calledAt - calls[0].calledAt).toBeGreaterThanOrEqual(holdMs / 2);
    } finally {
      await a.close();
      await b.close();
    }
  });
});

/**
 * The same measurement on Postgres — the deployment shape of a service
 * scaled to two pods. Two instances, each with its own pool, on one database.
 *
 * Runs in a schema of this file's own, because `envelopes` is append-only
 * (delete and truncate are trigger-blocked): a schema nothing else writes to
 * is how `verifyChainCompleteness()` is handed a chain that only this test
 * wrote.
 */
const pgSchema = pgSuiteSchema('two_writers');
const itPg = PG_TESTS_ENABLED ? it : it.skip;

describe('two writers on one Postgres database (real adapter, integration)', () => {
  const scratchUrl = pgSchema.url;

  itPg(
    '20 concurrent captures across two instances → 20/20 stored, chain verifies clean',
    async () => {
      const log = logSink();
      const a = await Tzun.init({ dbUrl: scratchUrl, onLog: log.onLog });
      const b = await Tzun.init({ dbUrl: scratchUrl, onLog: log.onLog });
      try {
        await twentyConcurrentCapturesLandCleanly(a, b, log.lines);
      } finally {
        await a.close();
        await b.close();
      }
    },
    60000,
  );

  itPg(
    'a stale writer that runs out of attempts reports chain_conflict, not serialization_failure',
    async () => {
      const a = await Tzun.init({ dbUrl: scratchUrl });
      const b = await Tzun.init({ dbUrl: scratchUrl, chainConflictMaxAttempts: 1 });
      try {
        const ra = await a.capture(input('pg-a'));
        expect(ra.stored).toBe(true);
        const rb = await b.capture(input('pg-b'));
        expect(rb.stored).toBe(false);
        expect(rb.failure?.failureType).toBe('chain_conflict');
        expect(rb.failure?.diagnosticMetadata).toMatchObject({
          code: 'chain_conflict',
          retryable: true,
          attempts: 1,
          actualHead: { sequence: ra.envelope.payload.sequenceNumber, digest: ra.envelope.integrity.canonicalDigest },
        });
        const rb2 = await b.capture(input('pg-b-again'));
        expect(rb2.stored).toBe(true);
        expect(rb2.envelope.payload.sequenceNumber).toBe(ra.envelope.payload.sequenceNumber + 1);
      } finally {
        await a.close();
        await b.close();
      }
    },
    60000,
  );
});
