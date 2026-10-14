// tests/ts/integrity-status-measured.test.ts — GET /v1/integrity/status reports
// what was measured, not what is reassuring.
//
// A store nothing has ever scanned has no incidents, so a `chainStatus`
// derived from open incidents alone would answer 'healthy' on a fresh
// deployment's first request, over evidence no scanner had touched. The
// endpoint answers 'unknown' until a pass completes, and reports the duration
// and attestation coverage that pass measured — null where nothing was
// measured, never a fixed figure. An integrator's dashboard showing a green
// badge, "duration: —" and "0% attested" over an unscanned store would be
// showing two fabricated figures and a third indistinguishable from a
// measurement.
//
// This suite drives the endpoint over HTTP against REAL adapters — SQLite on
// a temp file always; Postgres when the Postgres legs run
// (tests/ts/helpers/postgres-test-db.ts) — because the memory adapter is not
// evidence about production storage. The scanner is the SDK's own, configured
// the way an integrator configures it; nothing is hand-constructed. The
// tamper in each case is an edit made to the store from outside the SDK,
// which is what tampering is.
import Database from 'better-sqlite3';
import { withSqliteEnvelopeTriggersLifted } from './helpers/tamper-store';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Pool } from 'pg';
import request from 'supertest';
import { createServer } from '../../src/api/server';
import { Tzun } from '../../src/sdk/index';
import { EvidenceEnvelope, ScannerConfig } from '@tzun/engine';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';
import { signedTimestampToken } from './rfc3161-fixture';
import { anchoredRecord } from './helpers/anchor-fixtures';

const scannerConfig: ScannerConfig = {
  batchSize: 100,
  workers: 2,
  mode: 'interval' as const,
  intervalMs: 0,
  // Off in the first scenario, deliberately: the artifacts seeded there are
  // placeholders, and that scenario is about presence being COUNTED and
  // coverage therefore being NULL, not a presence figure. The second scenario
  // turns it on and seeds one genuine token beside one that is not a token.
  verifyAttestation: false,
  verifyChainCompleteness: true,
};

interface AdapterHarness {
  /** Open the SDK the way an integrator does. */
  boot(scanner?: ScannerConfig): Promise<Tzun>;
  /** Rewrite a payload field on a stored envelope, leaving its digest alone. */
  tamperPayload(evidenceId: string): Promise<void>;
  teardown(): Promise<void>;
}

// ---------------------------------------------------------------------------
// SQLite harness
// ---------------------------------------------------------------------------
function sqliteHarness(): AdapterHarness {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tzun-test-status-measured-'));
  const dbPath = path.join(dir, 'store.db');
  return {
    boot: (scanner = scannerConfig) =>
      Tzun.init({
        mode: 'dev',
        dbPath,
        verifyReads: false,
        monitoring: { enabled: true, scanner },
      }),
    tamperPayload: async (evidenceId) => {
      const db = new Database(dbPath);
      try {
        const row = db
          .prepare('SELECT envelope FROM envelopes WHERE evidence_id = ?')
          .get(evidenceId) as { envelope: string } | undefined;
        if (!row) throw new Error(`no envelope row for ${evidenceId}`);
        const envelope = JSON.parse(row.envelope) as EvidenceEnvelope;
        envelope.payload.reason = 'rewritten behind the SDK';
        withSqliteEnvelopeTriggersLifted(db, () =>
          db.prepare('UPDATE envelopes SET envelope = ? WHERE evidence_id = ?')
            .run(JSON.stringify(envelope), evidenceId),
        );
      } finally {
        db.close();
      }
    },
    teardown: async () => {
      for (const suffix of ['', '-wal', '-shm']) {
        try { fs.unlinkSync(dbPath + suffix); } catch { /* ignore */ }
      }
      try { fs.rmdirSync(dir); } catch { /* ignore */ }
    },
  };
}

// ---------------------------------------------------------------------------
// Postgres harness — gated. A schema of the file's own, emptied of everything
// before each case.
// ---------------------------------------------------------------------------
const pgSchema = pgSuiteSchema('integrity_status');

function postgresHarness(): AdapterHarness {
  const pool = new Pool({ connectionString: pgSchema.url });
  return {
    boot: async (scanner = scannerConfig) => {
      return Tzun.init({
        mode: 'dev',
        dbUrl: pgSchema.url,
        verifyReads: false,
        monitoring: { enabled: true, scanner },
      });
    },
    tamperPayload: async (evidenceId) => {
      // The adapter installs a BEFORE UPDATE trigger that refuses payload
      // edits. The threat this models is an insider with the database's own
      // superuser, for whom that trigger is one statement away — exactly the
      // edit the scanner exists to catch.
      const client = await pool.connect();
      try {
        await client.query('ALTER TABLE envelopes DISABLE TRIGGER envelopes_enforce_immutable_trigger');
        const updated = await client.query(
          `UPDATE envelopes
              SET envelope = jsonb_set(envelope::jsonb, '{payload,reason}', '"rewritten behind the SDK"')
            WHERE evidence_id = $1`,
          [evidenceId],
        );
        if (updated.rowCount !== 1) throw new Error(`no envelope row for ${evidenceId}`);
      } finally {
        await client.query('ALTER TABLE envelopes ENABLE TRIGGER envelopes_enforce_immutable_trigger')
          .catch(() => { /* best effort; the next case starts from a reset schema */ });
        client.release();
      }
    },
    teardown: async () => {
      await pool.end();
    },
  };
}

// ---------------------------------------------------------------------------
// The scenarios, once per adapter. Each test gets a fresh store.
// ---------------------------------------------------------------------------
function runScenario(adapterName: string, makeHarness: () => AdapterHarness, resetStore?: () => Promise<void>) {
  describe(`GET /v1/integrity/status on ${adapterName}`, () => {
    let harness: AdapterHarness;

    beforeEach(async () => {
      if (resetStore) await resetStore();
      harness = makeHarness();
    });

    afterEach(async () => {
      await harness.teardown();
    });

    it('is unknown until a scan has completed, then reports what the scan found', async () => {
      const evidenceIds: string[] = [];
      const positions: Array<{ origin: string; leafIndex: number }> = [];

      // --- Session 1: fresh store, then records, then a real pass. ----------
      let tzun = await harness.boot();
      try {
        let app = createServer(tzun, { allowUnauthenticated: true });

        // Fresh store, no scan. This is the request every new deployment
        // makes first, and it must not answer 'healthy'.
        let res = await request(app).get('/v1/integrity/status').expect(200);
        expect(res.body.chainStatus).toBe('unknown');
        expect(res.body.totalRecords).toBe(0);
        expect(res.body.incidents).toEqual({ unresolvedIntegrity: 0, unresolvedOther: 0, reviewedStillObserved: 0 });
        expect(res.body.lastFullScanAt).toBeNull();
        expect(res.body.lastFullScanDuration).toBeNull();
        expect(res.body.lastFullScan).toBeNull();
        expect(res.body.attestationCoverage).toBeNull();

        for (let i = 1; i <= 3; i++) {
          const r = await tzun.capture({
            decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
            aiOutput: { step: i },
            action: 'approved',
            reason: `step-${i}`,
          });
          evidenceIds.push(r.envelope.payload.evidenceId);
          positions.push(r.logPosition!);
        }

        // Seed attestation artifacts through the adapter's one permitted
        // mutation, so coverage has something to measure: 2 of 3 carry a
        // timestamp token, 1 of 3 an anchor, none a signature.
        const storage = tzun.getStorage();
        await storage.updateAttestation(evidenceIds[0], { rfc3161Token: 'placeholder-token' }, 'partial');
        await storage.updateAttestation(evidenceIds[1], { rfc3161Token: 'placeholder-token' }, 'partial');
        // The anchor is a placeholder in the sense this scenario needs: a
        // well-formed tzun-anchor/1 artifact for the record's own leaf whose
        // proofs are about other leaves, with no publication, so it can never
        // be validated, only counted.
        await storage.updateAttestation(
          evidenceIds[0],
          {
            anchor: anchoredRecord({ logOrigin: positions[0].origin, leafIndex: positions[0].leafIndex }).anchor,
          },
          'partial',
        );

        // Records exist and nothing has scanned them: still unknown, and
        // still nothing to say about coverage or duration.
        res = await request(app).get('/v1/integrity/status').expect(200);
        expect(res.body.chainStatus).toBe('unknown');
        expect(res.body.totalRecords).toBe(3);
        expect(res.body.lastFullScanDuration).toBeNull();
        expect(res.body.attestationCoverage).toBeNull();

        // The measurement.
        await tzun.runScan();

        res = await request(app).get('/v1/integrity/status').expect(200);
        expect(res.body.chainStatus).toBe('healthy');
        expect(res.body.incidents).toEqual({ unresolvedIntegrity: 0, unresolvedOther: 0, reviewedStillObserved: 0 });
        expect(res.body.totalRecords).toBe(3);
        expect(res.body.lastFullScanAt).not.toBeNull();
        expect(typeof res.body.lastFullScanDuration).toBe('number');
        expect(res.body.lastFullScanDuration).toBeGreaterThanOrEqual(0);
        expect(res.body.lastFullScan).toMatchObject({
          passNumber: 1,
          recordsChecked: 3,
          issuesFound: 0,
          logFindings: 0,
          digestMismatches: 0,
          chainBreaks: 0,
          sequenceGaps: 0,
          attestationFailures: 0,
          attestationPresence: { timestamp: 2, signature: 0, anchor: 1 },
        });
        expect(res.body.lastFullScan.completedAt).toBe(res.body.lastFullScanAt);
        expect(res.body.lastFullScan.durationMs).toBe(res.body.lastFullScanDuration);
        // The field is the percentage of records with VALID timestamps. With
        // attestation verification OFF and placeholder artifacts that could
        // never verify, the pass verified nothing, so every component is
        // null — not the presence counts above read as percentages
        // (≈ 66.7% and ≈ 33.3%). The presence figures live under their own
        // name in `lastFullScan.attestationPresence`, asserted above.
        expect(res.body.lastFullScan.attestationValid).toEqual({ timestamp: null, signature: null, anchor: null });
        expect(res.body.attestationCoverage).toEqual({ timestamp: null, signature: null, anchor: null });

        // The scanner endpoint carries the same summary (additive field).
        const scanner = await request(app).get('/v1/integrity/scanner').expect(200);
        expect(scanner.body.totalPasses).toBe(1);
        expect(scanner.body.lastCompletedPass).toEqual(res.body.lastFullScan);

        void app;
      } finally {
        await tzun.close();
      }

      // --- The tamper, made with the SDK down. ------------------------------
      await harness.tamperPayload(evidenceIds[1]);

      // --- Session 2: a plain restart, then a pass over the tampered store. --
      tzun = await harness.boot();
      try {
        const app = createServer(tzun, { allowUnauthenticated: true });

        // Scanner state lives in the process. After a restart nothing in THIS
        // process has scanned, and the endpoint says so rather than carrying
        // the previous process's verdict forward over a store that has been
        // edited since.
        let res = await request(app).get('/v1/integrity/status').expect(200);
        expect(res.body.chainStatus).toBe('unknown');
        expect(res.body.totalRecords).toBe(3);

        await tzun.runScan();

        // No polling: `runScan()` waits for the detector's in-flight persists
        // to settle, so the FIRST read after it must already see the
        // incident, on every adapter. On an adapter with a real round trip
        // (Postgres; SQLite and memory are synchronous underneath), a scan
        // that resolved before the row existed would leave a window in which
        // this endpoint answered 'healthy' beside a summary saying
        // `digestMismatches: 1`.
        const incidents = await request(app).get('/v1/integrity/incidents?status=open').expect(200);
        expect(incidents.body.length).toBeGreaterThanOrEqual(1);

        res = await request(app).get('/v1/integrity/status').expect(200);
        expect(res.body.chainStatus).toBe('compromised');
        expect(res.body.incidents.unresolvedIntegrity).toBeGreaterThanOrEqual(1);
        expect(res.body.lastFullScan.recordsChecked).toBe(3);
        expect(res.body.lastFullScan.digestMismatches).toBe(1);
        expect(res.body.lastFullScan.issuesFound).toBeGreaterThanOrEqual(1);
        expect(typeof res.body.lastFullScanDuration).toBe('number');
        // The tamper touched the payload, not the artifacts: presence is the
        // same 2 / 0 / 1 as before, and coverage is still unmeasured.
        expect(res.body.lastFullScan.attestationPresence).toEqual({ timestamp: 2, signature: 0, anchor: 1 });
        expect(res.body.attestationCoverage).toEqual({ timestamp: null, signature: null, anchor: null });
      } finally {
        await tzun.close();
      }
    });

    it('a record carrying an anchor made for another leaf reads degraded, and stays degraded across a restart', async () => {
      const evidenceIds: string[] = [];
      let tzun = await harness.boot();
      try {
        const app = createServer(tzun, { allowUnauthenticated: true });
        for (let i = 1; i <= 3; i++) {
          const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { step: i }, action: 'approved', reason: `step-${i}` });
          evidenceIds.push(r.envelope.payload.evidenceId);
        }
        // A well-formed tzun-anchor/1 artifact made for a leaf of another log.
        await tzun.getStorage().updateAttestation(evidenceIds[0], { anchor: anchoredRecord().anchor }, 'partial');

        await tzun.runScan();

        // `anchor_transplanted` is rated a warning: a finding to review, so
        // 'degraded', not 'healthy' and not 'compromised'.
        const found = await request(app).get('/v1/integrity/incidents?status=open').expect(200);
        expect(found.body.map((i: { type: string; affectedRecords: string[] }) => [i.type, i.affectedRecords])).toEqual([
          ['anchor_transplanted', [evidenceIds[0]]],
        ]);
        const res = await request(app).get('/v1/integrity/status').expect(200);
        expect(res.body.chainStatus).toBe('degraded');
        expect(res.body.incidents).toEqual({ unresolvedIntegrity: 0, unresolvedOther: 1, reviewedStillObserved: 0 });
        expect(res.body.lastFullScan).toMatchObject({ recordsChecked: 3, issuesFound: 1, logFindings: 1, digestMismatches: 0 });
      } finally {
        await tzun.close();
      }

      // After a restart, before any scan: the incident the last session
      // stored is still open, so the status is that finding's, not 'unknown'.
      tzun = await harness.boot();
      try {
        const app = createServer(tzun, { allowUnauthenticated: true });
        const res = await request(app).get('/v1/integrity/status').expect(200);
        expect(res.body.chainStatus).toBe('degraded');
        expect(res.body.lastFullScan).toBeNull();
      } finally {
        await tzun.close();
      }
    });

    it('attestationCoverage is the share of records whose artifact the pass verified, not the share that carry one', async () => {
      // The store this models: a genuine RFC 3161 token over one record
      // and, on another, what a TSA client stores when a captive portal
      // answers HTTP 200 with an HTML page. Both are "present"; one is valid.
      const tzun = await harness.boot({ ...scannerConfig, verifyAttestation: true });
      try {
        const app = createServer(tzun, { allowUnauthenticated: true });
        const captured = [];
        for (let i = 1; i <= 3; i++) {
          captured.push(await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { step: i }, action: 'approved', reason: `step-${i}` }));
        }
        const [genuine, garbage] = captured.map((r) => r.envelope);
        const storage = tzun.getStorage();
        await storage.updateAttestation(
          genuine.payload.evidenceId,
          { rfc3161Token: await signedTimestampToken(genuine.integrity.canonicalDigest) },
          'partial',
        );
        await storage.updateAttestation(
          garbage.payload.evidenceId,
          { rfc3161Token: Buffer.from('<html><body>Sign in to the network</body></html>').toString('base64') },
          'partial',
        );

        await tzun.runScan();

        const res = await request(app).get('/v1/integrity/status').expect(200);
        // Two records carry a token; the pass verified one of them. No
        // signatures or anchors were seeded, and the scanner has no
        // credential store or anchor-chain verifier to verify them with.
        expect(res.body.lastFullScan.attestationPresence).toEqual({ timestamp: 2, signature: 0, anchor: 0 });
        expect(res.body.lastFullScan.attestationValid).toEqual({ timestamp: 1, signature: null, anchor: null });
        expect(res.body.lastFullScan.attestationFailures).toBe(1);
        expect(res.body.attestationCoverage.timestamp).toBeCloseTo((1 / 3) * 100, 6);
        expect(res.body.attestationCoverage.signature).toBeNull();
        expect(res.body.attestationCoverage.anchor).toBeNull();
        // The page-as-token is an open warning incident, so the chain is
        // degraded — and the summary beside it agrees (issuesFound: 1).
        expect(res.body.lastFullScan.issuesFound).toBe(1);
        // An attestation that would not verify is rated for review, not alarm:
        // it sits in the count below the integrity bar, which is what degraded is.
        expect(res.body.incidents.unresolvedOther).toBe(1);
        expect(res.body.incidents.unresolvedIntegrity).toBe(0);
        expect(res.body.chainStatus).toBe('degraded');

        const incidents = await request(app).get('/v1/integrity/incidents?status=open').expect(200);
        expect(incidents.body).toHaveLength(1);
        expect(incidents.body[0]).toMatchObject({ type: 'attestation_invalid', affectedRecords: [garbage.payload.evidenceId] });
      } finally {
        await tzun.close();
      }
    });
  });
}

runScenario('SQLite', sqliteHarness);

if (!PG_TESTS_ENABLED) {
  describe('GET /v1/integrity/status on Postgres', () => {
    it.skip('skipped: set RUN_INTEGRATION_TESTS=true and DATABASE_URL to run', () => {});
  });
} else {
  runScenario('Postgres', postgresHarness, () => pgSchema.reset());
}
