import { singleModel } from '@tzun/engine';
import request from 'supertest';
import { createServer } from '../../src/api/server';
import { Tzun } from '../../src/sdk/index';
import { rewriteStoredEnvelope } from './helpers/tamper-store';
// These cases tamper by rewriting the stored row itself, through
// `rewriteStoredEnvelope`, which works on every backend. The memory adapter
// clones on read and write, as the SQL adapters do, so mutating an object a
// read returned would change nothing in the store and leave the detection
// under test with nothing to detect.

describe('Integrity Dashboard API', () => {
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
    app = createServer(tzun, { allowUnauthenticated: true });
  });

  afterEach(async () => {
    await tzun.close();
  });

  describe('GET /v1/integrity/status', () => {
    it('returns IntegrityStatus with correct shape', async () => {
      const res = await request(app)
        .get('/v1/integrity/status')
        .expect(200);

      expect(res.body).toHaveProperty('chainStatus');
      expect(res.body).toHaveProperty('totalRecords');
      expect(res.body).toHaveProperty('activeChainId');
      expect(res.body).toHaveProperty('sealedChains');
      expect(res.body).toHaveProperty('incidents');
      expect(res.body).toHaveProperty('lastFullScanAt');
      expect(res.body).toHaveProperty('lastFullScanDuration');
      expect(res.body).toHaveProperty('lastFullScan');
      expect(res.body).toHaveProperty('scannerRunning');
      expect(res.body).toHaveProperty('attestationCoverage');
      expect(res.body).toHaveProperty('pendingAttestations');
    });

    it('reports unknown, not healthy, for a store nothing has scanned', async () => {
      // The store is empty and the scanner has never run, so nothing has
      // measured anything: 'healthy' here would be a green light no check
      // stands behind, on every fresh deployment. The same store after a real
      // pass is in integrity-status-measured.test.ts.
      const res = await request(app)
        .get('/v1/integrity/status')
        .expect(200);

      expect(res.body.chainStatus).toBe('unknown');
      expect(res.body.totalRecords).toBe(0);
      expect(res.body.incidents).toEqual({ unresolvedIntegrity: 0, unresolvedOther: 0, reviewedStillObserved: 0 });
      expect(res.body.lastFullScanAt).toBeNull();
      expect(res.body.lastFullScanDuration).toBeNull();
      expect(res.body.lastFullScan).toBeNull();
      expect(res.body.attestationCoverage).toBeNull();
    });
  });

  describe('GET /v1/integrity/incidents', () => {
    it('returns empty list when no incidents exist', async () => {
      const res = await request(app)
        .get('/v1/integrity/incidents')
        .expect(200);

      expect(res.body).toEqual([]);
    });

    it('returns incidents filtered by status', async () => {
      const captureResult = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'approve' },
        action: 'approved',
        reason: 'Valid',
      });

      // Tamper with the stored record to create an incident
      await rewriteStoredEnvelope(tzun.getStorage(), captureResult.envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

      // The read is verified; the failed digest check creates the incident
      await tzun.get(captureResult.envelope.payload.evidenceId);

      // Allow async processing
      await new Promise(resolve => setTimeout(resolve, 50));

      const res = await request(app)
        .get('/v1/integrity/incidents?status=open')
        .expect(200);

      expect(res.body.length).toBeGreaterThanOrEqual(1);
      expect(res.body.every((i: any) => i.status === 'open')).toBe(true);
    });

    it('returns incidents filtered by severity', async () => {
      const res = await request(app)
        .get('/v1/integrity/incidents?severity=critical')
        .expect(200);

      expect(Array.isArray(res.body)).toBe(true);
    });
  });

  describe('GET /v1/integrity/incidents/:id', () => {
    it('returns 404 for non-existent incident', async () => {
      await request(app)
        .get('/v1/integrity/incidents/non-existent')
        .expect(404);
    });
  });

  describe('GET /v1/integrity/chain', () => {
    it('returns chain completeness report', async () => {
      const res = await request(app)
        .get('/v1/integrity/chain')
        .expect(200);

      expect(res.body).toHaveProperty('valid');
      expect(res.body).toHaveProperty('totalRecords');
      expect(res.body).toHaveProperty('sequenceGaps');
      expect(res.body).toHaveProperty('brokenLinks');
    });

    it('returns valid: true for empty chain', async () => {
      const res = await request(app)
        .get('/v1/integrity/chain')
        .expect(200);

      expect(res.body.valid).toBe(true);
      expect(res.body.totalRecords).toBe(0);
    });

    it('returns valid: true for clean chain with records', async () => {
      for (let i = 0; i < 3; i++) {
        await tzun.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { step: i },
          action: 'approved',
          reason: `Step ${i}`,
        });
      }

      const res = await request(app)
        .get('/v1/integrity/chain')
        .expect(200);

      expect(res.body.valid).toBe(true);
      expect(res.body.totalRecords).toBe(3);
      expect(res.body.sequenceGaps).toEqual([]);
      expect(res.body.brokenLinks).toEqual([]);
    });
  });

  describe('GET /v1/integrity/scanner', () => {
    it('returns scanner state', async () => {
      const res = await request(app)
        .get('/v1/integrity/scanner')
        .expect(200);

      expect(res.body).toHaveProperty('totalPasses');
      expect(res.body).toHaveProperty('highWaterMark');
      expect(res.body).toHaveProperty('lastCompletedPassAt');
      expect(res.body).toHaveProperty('segmentsInProgress');
    });
  });

  describe('POST /v1/integrity/verify/:evidenceId', () => {
    it('verifies a single record and returns verification result', async () => {
      const captureResult = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'approve' },
        action: 'approved',
        reason: 'Valid',
      });

      const res = await request(app)
        .post(`/v1/integrity/verify/${captureResult.envelope.payload.evidenceId}`)
        .expect(200);

      expect(res.body.verified).toBe(true);
      expect(res.body.storedDigest).toMatch(/^[a-f0-9]{64}$/);
      expect(res.body.recomputedDigest).toMatch(/^[a-f0-9]{64}$/);
      expect(res.body.verifiedAt).toBeDefined();
    });

    it('returns 404 for non-existent evidenceId', async () => {
      await request(app)
        .post('/v1/integrity/verify/non-existent')
        .expect(404);
    });

    it('detects tampered record and creates incident', async () => {
      const captureResult = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'approve' },
        action: 'approved',
        reason: 'Valid',
      });

      // Tamper with the stored record
      await rewriteStoredEnvelope(tzun.getStorage(), captureResult.envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

      const res = await request(app)
        .post(`/v1/integrity/verify/${captureResult.envelope.payload.evidenceId}`)
        .expect(200);

      expect(res.body.verified).toBe(false);

      // Allow async processing for incident creation
      await new Promise(resolve => setTimeout(resolve, 50));

      // Verify incident was created
      const incidentsRes = await request(app)
        .get('/v1/integrity/incidents?status=open')
        .expect(200);

      expect(incidentsRes.body.length).toBeGreaterThanOrEqual(1);
    });

    it('emits chain_break (not digest_mismatch) when only chain link is invalid', async () => {
      // Capture two records to establish a chain
      await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'first' },
        action: 'approved',
        reason: 'First',
      });
      const second = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'second' },
        action: 'approved',
        reason: 'Second',
      });

      const evidenceId = second.envelope.payload.evidenceId;

      // Tamper with the chain link only (not the payload/digest)
      await rewriteStoredEnvelope(tzun.getStorage(), evidenceId, (e) => { e.integrity.chainLink = 'deadbeef_broken_link'; });

      // No previousDigest in the request body: a caller-supplied predecessor
      // never reaches the incident pipeline (it is the forgery vector), so the
      // server resolves the predecessor itself and still finds the break.
      const firstEnvelope = (await tzun.getStorage().list({ order: 'asc' }))[0];
      const res = await request(app)
        .post(`/v1/integrity/verify/${evidenceId}`)
        .expect(200);

      expect(res.body.verified).toBe(false);
      // Digest should still match (payload untouched)
      expect(res.body.storedDigest).toBe(res.body.recomputedDigest);
      // Chain link should be invalid
      expect(res.body.chainLinkValid).toBe(false);

      // Allow async processing for incident creation
      await new Promise(resolve => setTimeout(resolve, 50));

      // Verify incident was created with chain_break type, not digest_mismatch
      const incidentsRes = await request(app)
        .get('/v1/integrity/incidents?status=open')
        .expect(200);

      const chainBreakIncidents = incidentsRes.body.filter(
        (i: any) => i.type === 'chain_break'
      );
      expect(chainBreakIncidents.length).toBeGreaterThanOrEqual(1);

      // The incident must describe the real record — its sequence number and
      // the predecessor digest it should link to — not a placeholder
      // `sequenceNumber: 0` / `expectedPrevDigest: ''`.
      const incident = chainBreakIncidents[0];
      expect(incident.affectedSequenceRange).toEqual({ from: 2, to: 2 });
      expect(incident.details).toContain('sequence 2');
      expect(incident.details).toContain(firstEnvelope.integrity.canonicalDigest);
    });

    it('a caller-supplied previousDigest cannot forge a persisted incident', async () => {
      // The forgery: POST an arbitrary previousDigest against an untouched
      // record. Tzun.verify prefers the caller's value, so chainLinkValid goes
      // false. If the route persisted that as a CRITICAL chain_break incident,
      // any caller could add one row per call, flip /v1/integrity/status to
      // 'compromised' and page on-call, with no evidence having been touched.
      await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'first' },
        action: 'approved',
        reason: 'First',
      });
      const second = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'second' },
        action: 'approved',
        reason: 'Second',
      });
      const genesisId = (await tzun.getStorage().list({ order: 'asc' }))[0]
        .payload.evidenceId;

      // Baseline: the honest store has no incidents.
      const before = await request(app).get('/v1/integrity/incidents').expect(200);
      expect(before.body).toHaveLength(0);

      for (const id of [second.envelope.payload.evidenceId, genesisId]) {
        for (let i = 0; i < 3; i++) {
          const res = await request(app)
            .post(`/v1/integrity/verify/${id}`)
            .send({ previousDigest: 'deadbeef' })
            .expect(200);
          // The ad-hoc check still runs and still reports its result...
          expect(res.body.verified).toBe(false);
          expect(res.body.chainLinkValid).toBe(false);
        }
      }

      await new Promise((resolve) => setTimeout(resolve, 50));

      // ...but nothing was persisted and the store is still healthy.
      const after = await request(app).get('/v1/integrity/incidents').expect(200);
      expect(after.body).toHaveLength(0);

      const status = await request(app).get('/v1/integrity/status').expect(200);
      expect(status.body.incidents).toEqual({ unresolvedIntegrity: 0, unresolvedOther: 0, reviewedStillObserved: 0 });
      expect(status.body.chainStatus).not.toBe('compromised');
    });

    it('still raises a real incident on a server-resolved verify of a tampered record', async () => {
      // The other side of the previous case: suppressing caller-supplied
      // predecessors must not suppress genuine detection.
      const first = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { recommendation: 'first' },
        action: 'approved',
        reason: 'First',
      });

      await rewriteStoredEnvelope(tzun.getStorage(), first.envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

      await request(app)
        .post(`/v1/integrity/verify/${first.envelope.payload.evidenceId}`)
        .expect(200);

      await new Promise((resolve) => setTimeout(resolve, 50));

      const incidents = await request(app).get('/v1/integrity/incidents').expect(200);
      expect(incidents.body.map((i: any) => i.type)).toContain('digest_mismatch');
    });
  });

  describe('POST /v1/integrity/verify/range', () => {
    it('verifies a range of records by sequence number', async () => {
      for (let i = 0; i < 5; i++) {
        await tzun.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { step: i },
          action: 'approved',
          reason: `Step ${i}`,
        });
      }

      const res = await request(app)
        .post('/v1/integrity/verify/range')
        .send({ fromSequence: 1, toSequence: 5 })
        .expect(200);

      expect(res.body).toHaveProperty('recordsVerified');
      expect(res.body).toHaveProperty('issuesFound');
      expect(res.body.recordsVerified).toBe(5);
      expect(res.body.issuesFound).toBe(0);
    });

    it('records a broken chain link as chain_break, not as a digest mismatch', async () => {
      // verifyRange records the cause of verified===false, not a blanket
      // 'digest_mismatch'. Filed as a digest mismatch, the incident a
      // regulator would read says "stored=<X>, recomputed=<X>" — a mismatch
      // between two identical digests — while the actual broken link goes
      // unrecorded, and the notification router's
      // `${evidenceId}:digest_mismatch` dedup key suppresses a genuine later
      // digest_mismatch on that record for an hour.
      await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { i: 1 }, action: 'approved', reason: 'One' });
      const second = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { i: 2 },
        action: 'approved',
        reason: 'Two',
      });

      const ordered = await tzun.getStorage().list({ order: 'asc' });
      const firstDigest = ordered[0].integrity.canonicalDigest;
      // Break ONLY the chain link. The payload — and therefore the digest — is
      // untouched.
      await rewriteStoredEnvelope(tzun.getStorage(), second.envelope.payload.evidenceId, (e) => {
        e.integrity.chainLink = 'broken';
      });

      const res = await request(app)
        .post('/v1/integrity/verify/range')
        .send({ fromSequence: 1 })
        .expect(200);
      expect(res.body.issuesFound).toBe(1);

      await new Promise((resolve) => setTimeout(resolve, 50));
      const incidents = (await request(app).get('/v1/integrity/incidents').expect(200)).body;

      expect(incidents.map((i: any) => i.type)).toEqual(['chain_break']);
      expect(incidents[0].affectedRecords).toEqual([second.envelope.payload.evidenceId]);
      expect(incidents[0].affectedSequenceRange).toEqual({ from: 2, to: 2 });
      expect(incidents[0].details).toContain(firstDigest);
    });

    it('records a tampered descriptor row as a descriptor incident, not as a digest mismatch', async () => {
      const { digest } = await tzun.models.register({
        descriptorVersion: 'd1',
        vendor: 'openai',
        modelName: 'range-descriptor',
        modelVersion: 'v1',
        modelType: 'llm',
        integrityTier: 'vendor-asserted',
        modelDigest: null,
        parentModelDescriptorDigest: null,
        derivation: null,
        trainedBy: 'TestCorp',
        license: 'mit',
        modelCardUrl: null,
        training: {
          trainingDataDigest: null,
          trainingDataRef: null,
          lastTrainingDate: null,
          evaluations: [],
        },
        regulatoryMarkings: [],
        externalIdentifiers: [],
      } as any);

      await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { i: 1 },
        action: 'approved',
        reason: 'With AI-BOM',
        contributions: singleModel({
          modelDescriptorDigest: digest,
          vendorFingerprint: null,
          promptTemplate: null,
          inferenceParameters: null,
          infrastructure: null,
        }),
      } as any);

      // Rewrite the catalog row's bytes: the evidence digest and chain link are
      // both untouched, so only the descriptor path can see this.
      const innerStorage = tzun.getStorage();
      const descriptors = (innerStorage as any).modelDescriptors as Map<string, any>;
      const row = descriptors.get(digest);
      descriptors.set(digest, {
        ...row,
        canonicalBytes: row.canonicalBytes.replace('"TestCorp"', '"FakeCorp"'),
      });

      const res = await request(app)
        .post('/v1/integrity/verify/range')
        .send({ fromSequence: 1 })
        .expect(200);
      expect(res.body.issuesFound).toBe(1);

      await new Promise((resolve) => setTimeout(resolve, 50));
      const incidents = (await request(app).get('/v1/integrity/incidents').expect(200)).body;

      expect(incidents.map((i: any) => i.type)).toEqual(['descriptor_digest_mismatch']);
    });

    it('returns 400 when fromSequence is missing', async () => {
      await request(app)
        .post('/v1/integrity/verify/range')
        .send({})
        .expect(400);
    });

    it('returns 400 when fromSequence > toSequence', async () => {
      await request(app)
        .post('/v1/integrity/verify/range')
        .send({ fromSequence: 10, toSequence: 5 })
        .expect(400);
    });

    it('detects issues in a range and reports count', async () => {
      const results = [];
      for (let i = 0; i < 5; i++) {
        const r = await tzun.capture({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { step: i },
          action: 'approved',
          reason: `Step ${i}`,
        });
        results.push(r);
      }

      // Tamper with record 3
      await rewriteStoredEnvelope(tzun.getStorage(), results[2].envelope.payload.evidenceId, (e) => { e.payload.reason = 'TAMPERED'; });

      const res = await request(app)
        .post('/v1/integrity/verify/range')
        .send({ fromSequence: 1, toSequence: 5 })
        .expect(200);

      expect(res.body.issuesFound).toBeGreaterThanOrEqual(1);
    });
  });
});
