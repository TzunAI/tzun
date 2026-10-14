import request from 'supertest';
import { createServer } from '../../src/api/server';
import { Tzun } from '../../src/sdk/index';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
// The tamper cases rewrite the stored row itself through
// `rewriteStoredEnvelope`, which works on every backend. The memory adapter
// clones on read and write, so assigning to the object it returns changes
// nothing stored, exactly as with a real database.
import { TamperIncident } from '@tzun/engine';

describe('Dashboard & Benchmark Integration', () => {
  let app: ReturnType<typeof createServer>;
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init({
      monitoring: {
        enabled: true,
        scanner: {
          batchSize: 100,
          workers: 2,
          mode: 'interval',
          intervalMs: 0,
          verifyAttestation: false,
          verifyChainCompleteness: true,
        },
      },
    });
    // Benchmark routes are opt-in; this suite asserts them, so
    // it turns the flag on. Default-off is pinned in benchmark-web.test.ts.
    app = createServer(tzun, { allowUnauthenticated: true, benchmark: true });
  });

  afterEach(async () => {
    await tzun.close();
  });

  describe('Full integrity monitoring flow', () => {
    it('unknown -> capture records -> verify -> still unknown -> scan -> healthy', async () => {
      // 'healthy' needs a completed scanner pass. An empty store and five
      // unscanned records are both 'unknown': nothing has measured the chain
      // at either point, and "no open incidents" alone is not a measurement.
      // The scan below is what earns 'healthy'.
      let statusRes = await request(app).get('/v1/integrity/status').expect(200);
      expect(statusRes.body.chainStatus).toBe('unknown');
      expect(statusRes.body.totalRecords).toBe(0);

      // Capture records
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/v1/evidence')
          .send({
            decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
            aiOutput: { step: i },
            action: 'approved',
            reason: `Step ${i}`,
          })
          .expect(201);
      }

      // Verify chain is complete
      const chainRes = await request(app).get('/v1/integrity/chain').expect(200);
      expect(chainRes.body.valid).toBe(true);
      expect(chainRes.body.totalRecords).toBe(5);

      // Five records exist and nothing has scanned them: still unknown. (The
      // chain walk above is an on-demand verification, not a scanner pass,
      // and it raised no incident — which is all it can say.)
      statusRes = await request(app).get('/v1/integrity/status').expect(200);
      expect(statusRes.body.chainStatus).toBe('unknown');
      expect(statusRes.body.totalRecords).toBe(5);

      // A real pass over the five records: now there is a measurement.
      await tzun.runScan();
      statusRes = await request(app).get('/v1/integrity/status').expect(200);
      expect(statusRes.body.chainStatus).toBe('healthy');
      expect(statusRes.body.totalRecords).toBe(5);
      expect(statusRes.body.lastFullScan.recordsChecked).toBe(5);
      expect(statusRes.body.lastFullScan.issuesFound).toBe(0);
      expect(typeof statusRes.body.lastFullScanDuration).toBe('number');
    });

    it('tamper detection: capture -> tamper -> on-demand verify -> status compromised', async () => {
      // Capture a record
      const captureRes = await request(app)
        .post('/v1/evidence')
        .send({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { recommendation: 'approve' },
          action: 'approved',
          reason: 'Valid decision',
        })
        .expect(201);

      const evidenceId = captureRes.body.envelope.payload.evidenceId;

      // Tamper with the record in storage (behind the proxy, in the row itself)
      await rewriteStoredEnvelope(tzun.getStorage(), evidenceId, (e) => { e.payload.reason = 'TAMPERED REASON'; });

      // On-demand verify detects the tampering
      const verifyRes = await request(app)
        .post(`/v1/integrity/verify/${evidenceId}`)
        .expect(200);

      expect(verifyRes.body.verified).toBe(false);

      // Allow async processing for incident creation
      await new Promise(resolve => setTimeout(resolve, 100));

      // Status should be compromised (critical incident created)
      const statusRes = await request(app).get('/v1/integrity/status').expect(200);
      expect(statusRes.body.chainStatus).toBe('compromised');
      expect(statusRes.body.incidents.unresolvedIntegrity).toBeGreaterThanOrEqual(1);

      // Incidents list should contain the tamper detection
      const incidentsRes = await request(app)
        .get('/v1/integrity/incidents?status=open')
        .expect(200);
      expect(incidentsRes.body.length).toBeGreaterThanOrEqual(1);
      expect(incidentsRes.body[0].type).toBe('digest_mismatch');

      // Individual incident should be retrievable
      const incidentId = incidentsRes.body[0].id;
      const incidentRes = await request(app)
        .get(`/v1/integrity/incidents/${incidentId}`)
        .expect(200);
      expect(incidentRes.body.id).toBe(incidentId);
      expect(incidentRes.body.affectedRecords).toContain(evidenceId);
    });

    it('range verification detects issues in a subset of records', async () => {
      // Capture 5 records
      const results = [];
      for (let i = 0; i < 5; i++) {
        const r = await request(app)
          .post('/v1/evidence')
          .send({
            decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
            aiOutput: { step: i },
            action: 'approved',
            reason: `Step ${i}`,
          })
          .expect(201);
        results.push(r.body);
      }

      // Tamper with record 3
      await rewriteStoredEnvelope(tzun.getStorage(), results[2].envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

      // Range verify that includes the tampered record
      const rangeRes = await request(app)
        .post('/v1/integrity/verify/range')
        .send({ fromSequence: 2, toSequence: 4 })
        .expect(200);

      expect(rangeRes.body.recordsVerified).toBe(3);
      expect(rangeRes.body.issuesFound).toBeGreaterThanOrEqual(1);
    });

    it('on-demand verification fires notifications through monitoring pipeline', async () => {
      const incidents: TamperIncident[] = [];
      tzun.on('tamper', (incident: TamperIncident) => incidents.push(incident));

      // Capture a record
      const captureRes = await request(app)
        .post('/v1/evidence')
        .send({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { test: true },
          action: 'approved',
          reason: 'For notification test',
        })
        .expect(201);

      // Tamper and verify
      await rewriteStoredEnvelope(tzun.getStorage(), captureRes.body.envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

      await request(app)
        .post(`/v1/integrity/verify/${captureRes.body.envelope.payload.evidenceId}`)
        .expect(200);

      // Allow async processing
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(incidents.length).toBeGreaterThanOrEqual(1);
      expect(incidents[0].type).toBe('digest_mismatch');
    });
  });

  describe('Scanner state endpoint', () => {
    it('reports scanner state after a scan pass', async () => {
      // Capture some records
      for (let i = 0; i < 3; i++) {
        await tzun.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { step: i },
          action: 'approved',
          reason: `Step ${i}`,
        });
      }

      // Run a scan
      await tzun.runScan();

      const res = await request(app).get('/v1/integrity/scanner').expect(200);
      expect(res.body.totalPasses).toBe(1);
      expect(res.body.highWaterMark).toBe(3);
      expect(res.body.lastCompletedPassAt).not.toBeNull();
    });
  });

  describe('Benchmark web interface', () => {
    it('HTML page loads', async () => {
      const res = await request(app).get('/v1/benchmark').expect(200);
      expect(res.headers['content-type']).toContain('text/html');
      expect(res.text).toContain('Tzun SDK Benchmark');
    });

    it('benchmark run endpoint returns valid report', async () => {
      const res = await request(app)
        .post('/v1/benchmark/run')
        .send({
          suites: ['serialization'],
          minDurationMs: 100,
          warmupIterations: 2,
        })
        .expect(200);

      expect(res.body.hardware).toBeDefined();
      expect(res.body.measurements.length).toBeGreaterThan(0);
      expect(res.body.scanEstimates.length).toBeGreaterThan(0);
      expect(res.body.digestBackend).toBe('cpu');
    }, 30000);
  });
});
