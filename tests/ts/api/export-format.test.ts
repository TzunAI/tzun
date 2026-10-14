// tests/ts/api/export-format.test.ts — the export route's `format` parameter.
import express from 'express';
import request from 'supertest';
import { Tzun } from '../../../src/sdk/index';
import { createExportRouter } from '../../../src/api/export-routes';

async function makeApp() {
  const tzun = await Tzun.init();
  const r = await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'approved', reason: 'ok' });
  const id = r.envelope.payload.evidenceId;
  const app = express();
  app.use(express.json());
  app.use(createExportRouter(tzun));
  return { app, id };
}

describe('export format parsing', () => {
  it('format absent → 200 (unchanged default)', async () => {
    const { app, id } = await makeApp();
    const res = await request(app).get(`/v1/evidence/${id}/export`);
    expect(res.status).toBe(200);
  });

  it('format=json (any case) → 200, current behavior', async () => {
    const { app, id } = await makeApp();
    const res = await request(app).get(`/v1/evidence/${id}/export?format=JSON`);
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toContain(`evidence-${id}.json`);
  });

  it('format=xml → 400 with the exact contract message', async () => {
    const { app, id } = await makeApp();
    const res = await request(app).get(`/v1/evidence/${id}/export?format=xml`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unsupported export format "xml"; supported: json');
  });
});
