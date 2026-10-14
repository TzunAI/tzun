// tests/ts/api/export-exported-by.test.ts
//
// The export route is unauthenticated, and it used to copy `?exportedBy=` into
// the bundle's `exportedBy` field, so any caller could make a bundle name
// anyone as its exporter. The route cannot know who is calling, so the bundle
// records the route itself ('rest-export', as the AI-BOM runbook documents),
// and a caller-supplied `exportedBy` is refused rather than silently dropped.
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
  return { app, id, tzun };
}

describe('export exportedBy is not caller-chosen', () => {
  it('records the route, not a caller identity, when no exportedBy is given', async () => {
    const { app, id } = await makeApp();
    const res = await request(app).get(`/v1/evidence/${id}/export`);
    expect(res.status).toBe(200);
    expect(res.body.exportedBy).toBe('rest-export');
  });

  it('refuses ?exportedBy= with 400 instead of recording it', async () => {
    const { app, id, tzun } = await makeApp();
    const exportSpy = jest.spyOn(tzun, 'exportEvidence');
    const res = await request(app).get(`/v1/evidence/${id}/export?exportedBy=court%40example.com`);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/exportedBy/);
    expect(res.body.exportedBy).toBeUndefined();
    expect(exportSpy).not.toHaveBeenCalled();
  });

  it('refuses an empty ?exportedBy= too', async () => {
    const { app, id } = await makeApp();
    const res = await request(app).get(`/v1/evidence/${id}/export?exportedBy=`);
    expect(res.status).toBe(400);
  });

  it('refuses a repeated ?exportedBy= (array-valued query)', async () => {
    const { app, id } = await makeApp();
    const res = await request(app).get(`/v1/evidence/${id}/export?exportedBy=a&exportedBy=b`);
    expect(res.status).toBe(400);
  });

  it('the in-process API still takes exportedBy from its caller', async () => {
    // The programmatic caller IS the host application, so the name it passes
    // is its own statement. Only the unauthenticated HTTP route lost it.
    const { id, tzun } = await makeApp();
    const bundle = await tzun.exportEvidence(id, { exportedBy: 'subpoena-response-2026-05' });
    expect(bundle.exportedBy).toBe('subpoena-response-2026-05');
  });
});
