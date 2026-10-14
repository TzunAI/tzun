// tests/ts/api/rest-auth-all-routes.test.ts
//
// On the platform nothing is readable anonymously: capture needs an API key,
// and evidence reads, integrity and export need an authenticated session. The
// auth choice createServer / createRouter require governs every route they
// mount, not only capture:
//
//   - with `resolveActor`, a request without a recognised credential is a 401
//     on every route, before any body is read;
//   - with `allowUnauthenticated: true`, every route stays open.
//
// createServer also hands its resolver to the models router, so a resolved
// actor can post freeform-note annotations. The standalone createModelsRouter
// and createExportRouter require no auth choice and answer reads without a
// credential, because an application that mounts the routers directly puts
// them behind its own session auth.
import express from 'express';
import request from 'supertest';
import { createServer } from '../../../src/api/server';
import { createRouter } from '../../../src/api/routes';
import { createModelsRouter } from '../../../src/api/models-routes';
import { createExportRouter } from '../../../src/api/export-routes';
import { apiKeyActorResolver, ACTOR_AUTH_HEADER } from '../../../src/api/actor-resolver';
import type { ResolveActor } from '../../../src/api/actor-resolver';
import { Tzun } from '../../../src/sdk/index';

const KEY = 'key-2f9a61';
const ADMIN_TOKEN = 'admin-token-5d0c';
const resolveActor = apiKeyActorResolver({ [KEY]: 'dana' });

const CAPTURE = { decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { d: 1 }, action: 'approved', reason: 'ok' };
const DESCRIPTOR = {
  vendor: 'Acme AI',
  modelName: 'acme-2',
  modelVersion: '1.0',
  modelType: 'language-model',
  integrityTier: 'vendor-asserted',
  license: 'Apache-2.0',
  modelCardUrl: null,
  regulatoryMarkings: [],
  externalIdentifiers: [],
};

type Method = 'get' | 'post';
interface Route {
  method: Method;
  path: string;
  body?: object;
}

/** Every route createServer mounts with the benchmark on, with a usable body. */
function everyRoute(evidenceId: string, digest: string): Route[] {
  return [
    { method: 'post', path: '/v1/evidence', body: CAPTURE },
    { method: 'get', path: `/v1/evidence/${evidenceId}` },
    { method: 'post', path: `/v1/evidence/${evidenceId}/verify`, body: {} },
    { method: 'get', path: '/v1/evidence' },
    { method: 'get', path: `/v1/evidence/${evidenceId}/export` },
    { method: 'get', path: '/v1/integrity/status' },
    { method: 'get', path: '/v1/integrity/incidents' },
    { method: 'get', path: '/v1/integrity/incidents/no-such-incident' },
    { method: 'get', path: '/v1/integrity/chain' },
    { method: 'get', path: '/v1/integrity/scanner' },
    { method: 'post', path: '/v1/integrity/verify/range', body: { fromSequence: 1 } },
    { method: 'post', path: `/v1/integrity/verify/${evidenceId}`, body: {} },
    { method: 'get', path: '/v1/models' },
    { method: 'get', path: '/v1/models/by-alias/no-such-alias' },
    { method: 'get', path: '/v1/models/usage' },
    { method: 'get', path: `/v1/models/${digest}` },
    { method: 'get', path: `/v1/models/${digest}/enriched` },
    { method: 'get', path: `/v1/models/${digest}/annotations` },
    { method: 'get', path: `/v1/models/${digest}/lineage` },
    { method: 'post', path: '/v1/models', body: { descriptor: DESCRIPTOR } },
    {
      method: 'post',
      path: `/v1/models/${digest}/annotations`,
      body: { annotationType: 'freeform-note', value: { text: 'n' } },
    },
    { method: 'post', path: '/v1/models/aliases', body: { slug: 'acme', digest } },
    { method: 'get', path: '/v1/benchmark' },
    // Refused as unbounded once admitted, so the test never runs a benchmark.
    { method: 'post', path: '/v1/benchmark/run', body: { minDurationMs: 999_999_999 } },
  ];
}

function send(app: express.Express, route: Route, headers: Record<string, string> = {}) {
  let req = request(app)[route.method](route.path);
  for (const [k, v] of Object.entries(headers)) req = req.set(k, v);
  return route.body !== undefined ? req.send(route.body) : req;
}

describe('the auth choice governs every route', () => {
  let tzun: Tzun;
  let evidenceId: string;
  let digest: string;
  let routes: Route[];

  beforeEach(async () => {
    delete process.env.TZUN_ADMIN_TOKEN;
    tzun = await Tzun.init();
    const r = await tzun.capture(CAPTURE);
    evidenceId = r.envelope.payload.evidenceId;
    ({ digest } = await tzun.models.register({
      vendor: 'openai',
      modelName: 'gpt-4o',
      modelVersion: '2024-08-06',
    }));
    routes = everyRoute(evidenceId, digest);
  });

  afterEach(async () => {
    delete process.env.TZUN_ADMIN_TOKEN;
    await tzun.close();
  });

  it('covers all 24 routes', () => {
    expect(routes).toHaveLength(24);
  });

  describe('with resolveActor', () => {
    let app: express.Express;

    beforeEach(() => {
      app = createServer(tzun, { resolveActor, benchmark: true });
    });

    it('answers every route 401 without a credential', async () => {
      for (const route of routes) {
        const res = await send(app, route);
        expect({ route: `${route.method} ${route.path}`, status: res.status, body: res.body })
          .toEqual({ route: `${route.method} ${route.path}`, status: 401, body: { error: 'unauthenticated' } });
      }
    });

    it('answers every route 401 with an unknown credential', async () => {
      for (const route of routes) {
        const res = await send(app, route, { [ACTOR_AUTH_HEADER]: 'key-not-issued' });
        expect(`${route.method} ${route.path} → ${res.status}`)
          .toBe(`${route.method} ${route.path} → 401`);
      }
    });

    it('admits every route with a recognised credential', async () => {
      for (const route of routes) {
        const res = await send(app, route, { [ACTOR_AUTH_HEADER]: KEY });
        expect(`${route.method} ${route.path} → ${res.status === 401 ? 401 : 'admitted'}`)
          .toBe(`${route.method} ${route.path} → admitted`);
      }
    });

    it('authenticates before reading any body: malformed JSON without a credential is 401 on every POST', async () => {
      for (const route of routes.filter((r) => r.method === 'post')) {
        const res = await request(app)
          .post(route.path)
          .set('Content-Type', 'application/json')
          .send('{"broken": ');
        expect(`${route.path} → ${res.status}`).toBe(`${route.path} → 401`);
      }
    });

    it('an unknown /v1 path is 401 too, so an anonymous caller cannot map the routes', async () => {
      await request(app).get('/v1/no-such-route').expect(401);
      await request(app).get('/v1/no-such-route').set(ACTOR_AUTH_HEADER, KEY).expect(404);
    });

    it('admin-token routes need the credential as well as the admin token', async () => {
      process.env.TZUN_ADMIN_TOKEN = ADMIN_TOKEN;
      await request(app)
        .post('/v1/models')
        .set('x-tzun-admin-token', ADMIN_TOKEN)
        .send({ descriptor: DESCRIPTOR })
        .expect(401);
      await request(app)
        .post('/v1/models')
        .set('x-tzun-admin-token', ADMIN_TOKEN)
        .set(ACTOR_AUTH_HEADER, KEY)
        .send({ descriptor: DESCRIPTOR })
        .expect(201);
    });

    it('passes the resolver to the models router: a resolved actor posts a freeform note as itself', async () => {
      const res = await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .set(ACTOR_AUTH_HEADER, KEY)
        .send({ annotationType: 'freeform-note', value: { text: 'looks fine' } });
      expect(res.status).toBe(201);
      expect(res.body.annotatedBy).toBe('dana');
    });

    it('a resolved actor still cannot post a typed annotation', async () => {
      const res = await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .set(ACTOR_AUTH_HEADER, KEY)
        .send({ annotationType: 'deprecation', value: { reason: 'old' }, annotatedBy: 'dana' });
      expect(res.status).toBe(403);
    });

    it('asks the resolver once per request, however many checks the request passes', async () => {
      const counted = jest.fn(resolveActor);
      const counting = createServer(tzun, { resolveActor: counted as ResolveActor });
      const probes: Route[] = [
        { method: 'post', path: '/v1/evidence', body: CAPTURE },
        { method: 'get', path: '/v1/evidence' },
        { method: 'get', path: '/v1/integrity/status' },
        {
          method: 'post',
          path: `/v1/models/${digest}/annotations`,
          body: { annotationType: 'freeform-note', value: { text: 'n' } },
        },
      ];
      for (const probe of probes) {
        counted.mockClear();
        await send(counting, probe, { [ACTOR_AUTH_HEADER]: KEY });
        expect(`${probe.path}: ${counted.mock.calls.length}`).toBe(`${probe.path}: 1`);
      }
    });

    it('leaves a host route outside /v1 alone when the app is mounted inside another', async () => {
      const host = express();
      host.use(app);
      host.get('/healthz', (_req, res) => {
        res.json({ ok: true });
      });
      await request(host).get('/healthz').expect(200);
    });
  });

  describe('with allowUnauthenticated: true', () => {
    it('leaves every route open', async () => {
      const app = createServer(tzun, { allowUnauthenticated: true, benchmark: true });
      for (const route of routes) {
        const res = await send(app, route);
        expect(`${route.method} ${route.path} → ${res.status === 401 ? 401 : 'open'}`)
          .toBe(`${route.method} ${route.path} → open`);
      }
    });

    it('does not enable freeform notes for anonymous callers', async () => {
      const app = createServer(tzun, { allowUnauthenticated: true });
      const res = await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .send({ annotationType: 'freeform-note', value: { text: 'n' }, annotatedBy: 'anyone' });
      expect(res.status).toBe(403);
    });
  });

  describe('createRouter on a host app', () => {
    it('gates all four evidence routes, and no host route mounted beside it', async () => {
      const host = express();
      host.use(createRouter(tzun, { resolveActor }));
      host.get('/v1/host-status', (_req, res) => {
        res.json({ ok: true });
      });

      const evidenceRoutes = routes.slice(0, 4);
      for (const route of evidenceRoutes) {
        const res = await send(host, route);
        expect(`${route.method} ${route.path} → ${res.status}`)
          .toBe(`${route.method} ${route.path} → 401`);
        const admitted = await send(host, route, { [ACTOR_AUTH_HEADER]: KEY });
        expect(admitted.status).not.toBe(401);
      }
      await request(host).get('/v1/host-status').expect(200);
    });
  });

  describe('standalone routers an application mounts directly leave auth to that application', () => {
    it('createModelsRouter and createExportRouter answer without credentials', async () => {
      const host = express();
      host.use(express.json());
      host.use(createExportRouter(tzun));
      host.use(createModelsRouter(tzun, { resolveActor }));
      await request(host).get(`/v1/evidence/${evidenceId}/export`).expect(200);
      await request(host).get('/v1/models').expect(200);
      await request(host).get(`/v1/models/${digest}`).expect(200);
    });
  });
});
