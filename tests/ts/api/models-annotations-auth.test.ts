// tests/ts/api/models-annotations-auth.test.ts — who may post a freeform-note annotation.
import express from 'express';
import request from 'supertest';
import { Tzun } from '../../../src/sdk/index';
import { createModelsRouter } from '../../../src/api/models-routes';
import { apiKeyActorResolver } from '../../../src/api/actor-resolver';

async function appWith(resolver?: ReturnType<typeof apiKeyActorResolver>) {
  const tzun = await Tzun.init();
  const { digest } = await tzun.models.register(
    { vendor: 'openai', modelName: 'gpt-4o', modelVersion: '2024-08-06' });
  const app = express();
  app.use(express.json());
  app.use(createModelsRouter(tzun, resolver ? { resolveActor: resolver } : undefined));
  return { app, digest };
}
const note = { annotationType: 'freeform-note', value: { text: 'n' } };

describe('freeform-note actor auth', () => {
  beforeEach(() => { delete process.env.TZUN_ADMIN_TOKEN; });

  it('resolver-authenticated non-admin posts a freeform note; annotatedBy is server-assigned', async () => {
    const { app, digest } = await appWith(apiKeyActorResolver({ 'key-1': 'dana' }));
    const res = await request(app)
      .post(`/v1/models/${digest}/annotations`).set('x-tzun-api-key', 'key-1').send(note);
    expect(res.status).toBe(201);
    expect(res.body.annotatedBy).toBe('dana'); // server-derived, not client-asserted
  });

  it('client-supplied annotatedBy that disagrees with the principal → 400', async () => {
    const { app, digest } = await appWith(apiKeyActorResolver({ 'key-1': 'dana' }));
    const res = await request(app).post(`/v1/models/${digest}/annotations`)
      .set('x-tzun-api-key', 'key-1').send({ ...note, annotatedBy: 'mallory' });
    expect(res.status).toBe(400);
  });

  it('typed annotation still 403 for the resolver-authenticated non-admin', async () => {
    // "deprecation" is a verbatim member of TYPED_ANNOTATION_TYPES (src/models/annotations.ts).
    const { app, digest } = await appWith(apiKeyActorResolver({ 'key-1': 'dana' }));
    const res = await request(app).post(`/v1/models/${digest}/annotations`)
      .set('x-tzun-api-key', 'key-1')
      .send({ annotationType: 'deprecation', value: { reason: 'old' }, annotatedBy: 'dana' });
    expect(res.status).toBe(403);
  });

  it('no resolver configured → exactly today: freeform-note 403 without admin', async () => {
    const { app, digest } = await appWith(undefined);
    const res = await request(app).post(`/v1/models/${digest}/annotations`)
      .send({ ...note, annotatedBy: 'anyone' });
    expect(res.status).toBe(403);
  });

  it('wrong api key → no principal → 403', async () => {
    const { app, digest } = await appWith(apiKeyActorResolver({ 'key-1': 'dana' }));
    const res = await request(app).post(`/v1/models/${digest}/annotations`)
      .set('x-tzun-api-key', 'wrong').send(note);
    expect(res.status).toBe(403);
  });
});
