import request from 'supertest';
import { createServer } from '../../src/api/server';
import { Tzun } from '../../src/sdk/index';
import { rewriteStoredEnvelope } from './helpers/tamper-store';

describe('REST API', () => {
  let app: ReturnType<typeof createServer>;
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init(); // dev mode, in-memory storage
    app = createServer(tzun, { allowUnauthenticated: true });
  });

  describe('POST /v1/evidence', () => {
    it('captures evidence and returns 201 with envelope', async () => {
      const res = await request(app)
        .post('/v1/evidence')
        .send({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { recommendation: 'approve', confidence: 0.94 },
          action: 'approved',
          reason: 'All criteria met',
        })
        .expect(201);

      expect(res.body.stored).toBe(true);
      expect(res.body.envelope.envelopeVersion).toBe('e1');
      expect(res.body.envelope.payload.action).toBe('approved');
      expect(res.body.envelope.integrity.canonicalDigest).toMatch(/^[a-f0-9]{64}$/);
    });

    it('returns 400 for invalid input (an empty action and reason)', async () => {
      const res = await request(app)
        .post('/v1/evidence')
        .send({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { recommendation: 'approve' },
          action: '',
          reason: '',
        })
        .expect(400);

      expect(res.body.stored).toBe(false);
      expect(res.body.failure.failureType).toBe('validation_failure');
    });
  });

  describe('GET /v1/evidence/:id', () => {
    it('retrieves a stored envelope', async () => {
      const captureRes = await request(app)
        .post('/v1/evidence')
        .send({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { text: 'test' },
          action: 'accepted',
          reason: 'Valid',
        })
        .expect(201);

      const evidenceId = captureRes.body.envelope.payload.evidenceId;

      const res = await request(app)
        .get(`/v1/evidence/${evidenceId}`)
        .expect(200);

      expect(res.body.envelope.payload.evidenceId).toBe(evidenceId);
      expect(res.body.verdict.status).toBe('valid');
      expect(res.body.verdict.digest.recomputed).toBe(res.body.envelope.integrity.canonicalDigest);
    });

    it('returns 404 for non-existent evidenceId', async () => {
      await request(app)
        .get('/v1/evidence/non-existent')
        .expect(404);
    });

    it('returns a tampered record with an invalid verdict, not an error and not a 404', async () => {
      const captureRes = await request(app)
        .post('/v1/evidence')
        .send({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { text: 'test' }, action: 'accepted', reason: 'Valid' })
        .expect(201);
      const evidenceId = captureRes.body.envelope.payload.evidenceId;
      await rewriteStoredEnvelope(tzun.getStorage(), evidenceId, (e) => {
        e.payload.action = 'rejected';
      });

      const res = await request(app).get(`/v1/evidence/${evidenceId}`).expect(200);

      expect(res.body.envelope.payload.action).toBe('rejected');
      expect(res.body.verdict.status).toBe('invalid');
      expect(res.body.verdict.digest.reason).toBe('digest_mismatch');
    });
  });

  describe('POST /v1/evidence/:id/verify', () => {
    it('verifies a stored envelope', async () => {
      const captureRes = await request(app)
        .post('/v1/evidence')
        .send({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { text: 'test' },
          action: 'accepted',
          reason: 'Valid',
        })
        .expect(201);

      const evidenceId = captureRes.body.envelope.payload.evidenceId;

      const res = await request(app)
        .post(`/v1/evidence/${evidenceId}/verify`)
        .expect(200);

      expect(res.body.verified).toBe(true);
      expect(res.body.storedDigest).toMatch(/^[a-f0-9]{64}$/);
    });

    it('returns 404 for non-existent evidenceId', async () => {
      await request(app)
        .post('/v1/evidence/non-existent/verify')
        .expect(404);
    });
  });

  describe('GET /v1/evidence', () => {
    it('lists evidence records', async () => {
      await request(app)
        .post('/v1/evidence')
        .send({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { step: 1 },
          action: 'approved',
          reason: 'First',
        })
        .expect(201);

      await request(app)
        .post('/v1/evidence')
        .send({
          decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
          aiOutput: { step: 2 },
          action: 'approved',
          reason: 'Second',
        })
        .expect(201);

      const res = await request(app)
        .get('/v1/evidence')
        .expect(200);

      expect(res.body).toHaveLength(2);
      for (const read of res.body) {
        expect(read.envelope.payload.evidenceId).toEqual(expect.any(String));
        expect(read.verdict.status).toBe('valid');
      }
    });

    it('supports limit and offset query params', async () => {
      for (let i = 1; i <= 3; i++) {
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

      const res = await request(app)
        .get('/v1/evidence?limit=1&offset=1')
        .expect(200);

      expect(res.body).toHaveLength(1);
    });
  });
});
