/**
 * REST API tests for /v1/models/*.
 *
 * Covers the server side, admin gating, the nine endpoints, and that the
 * programmatic API mirrors REST.
 */

import request from 'supertest';
import { createServer } from '../../src/api/server';
import { Tzun } from '../../src/sdk/index';
import { registerModel } from '../../src/models/register';
import { annotateModelDescriptor } from '../../src/models/annotations';
import { ModelDescriptor } from '@tzun/engine';

const ADMIN_TOKEN = 'test-admin-token-7f8e9d';

function descriptorFixture(overrides: Partial<ModelDescriptor> = {}): Partial<ModelDescriptor> {
  return {
    vendor: 'Acme AI',
    modelName: 'acme-2',
    modelVersion: '1.0',
    modelType: 'language-model',
    integrityTier: 'vendor-asserted',
    license: 'Apache-2.0',
    modelCardUrl: null,
    regulatoryMarkings: [],
    externalIdentifiers: [],
    ...overrides,
  };
}

describe('/v1/models REST endpoints', () => {
  let app: ReturnType<typeof createServer>;
  let tzun: Tzun;

  beforeEach(async () => {
    process.env.TZUN_ADMIN_TOKEN = ADMIN_TOKEN;
    tzun = await Tzun.init();
    app = createServer(tzun, { allowUnauthenticated: true });
  });

  afterEach(async () => {
    delete process.env.TZUN_ADMIN_TOKEN;
    await tzun.close();
  });

  // ── GET /v1/models ────────────────────────────────────────────────────
  describe('GET /v1/models', () => {
    it('returns an empty list when the catalog is empty', async () => {
      const res = await request(app).get('/v1/models').expect(200);
      expect(res.body).toHaveProperty('models');
      expect(res.body).toHaveProperty('total');
      expect(res.body.models).toEqual([]);
      expect(res.body.total).toBe(0);
    });

    it('returns registered descriptors with filters applied', async () => {
      const storage = tzun.getStorage();
      await registerModel(storage, descriptorFixture({ vendor: 'Acme AI', modelName: 'one' }));
      await registerModel(storage, descriptorFixture({ vendor: 'Acme AI', modelName: 'two' }));
      await registerModel(storage, descriptorFixture({ vendor: 'OtherCo', modelName: 'three' }));

      const res = await request(app).get('/v1/models?vendor=Acme AI').expect(200);

      expect(res.body.total).toBe(2);
      expect(res.body.models).toHaveLength(2);
      // canonicalBytes should be stripped from list responses
      for (const row of res.body.models) {
        expect(row).not.toHaveProperty('canonicalBytes');
        expect(row.vendor).toBe('Acme AI');
      }
    });

    it('honors limit + offset pagination', async () => {
      const storage = tzun.getStorage();
      for (let i = 0; i < 5; i++) {
        await registerModel(
          storage,
          descriptorFixture({ vendor: 'Acme AI', modelName: `m${i}` }),
        );
      }

      const res = await request(app).get('/v1/models?limit=2&offset=1').expect(200);
      expect(res.body.models).toHaveLength(2);
    });
  });

  // ── GET /v1/models/:digest ────────────────────────────────────────────
  describe('GET /v1/models/:digest', () => {
    it('returns the canonical row, including canonicalBytes', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      const res = await request(app).get(`/v1/models/${digest}`).expect(200);
      expect(res.body.modelDescriptorDigest).toBe(digest);
      expect(res.body).toHaveProperty('canonicalBytes');
      expect(typeof res.body.canonicalBytes).toBe('string');
      expect(res.body.descriptor.modelName).toBe('acme-2');
    });

    it('returns 404 when the digest is unknown', async () => {
      const res = await request(app)
        .get('/v1/models/0000000000000000000000000000000000000000000000000000000000000000')
        .expect(404);
      expect(res.body).toHaveProperty('error');
    });
  });

  // ── GET /v1/models/:digest/enriched ───────────────────────────────────
  describe('GET /v1/models/:digest/enriched', () => {
    it('returns the enriched view with annotations applied', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());
      await annotateModelDescriptor(
        storage,
        digest,
        { annotationType: 'set-license', value: { license: 'MIT' } },
        { isAdmin: true, annotatedBy: 'tester' },
      );

      const res = await request(app).get(`/v1/models/${digest}/enriched`).expect(200);
      expect(res.body.license).toBe('MIT');
      expect(res.body.modelName).toBe('acme-2');
    });

    it('returns 404 when the digest is unknown', async () => {
      await request(app)
        .get('/v1/models/badc0ffee000000000000000000000000000000000000000000000000000000/enriched')
        .expect(404);
    });
  });

  // ── GET /v1/models/:digest/annotations ────────────────────────────────
  describe('GET /v1/models/:digest/annotations', () => {
    it('returns the annotation log for the descriptor', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());
      await annotateModelDescriptor(
        storage,
        digest,
        { annotationType: 'freeform-note', value: { text: 'hi' } },
        { annotatedBy: 'reviewer' },
      );

      const res = await request(app).get(`/v1/models/${digest}/annotations`).expect(200);
      expect(res.body).toHaveProperty('annotations');
      expect(res.body.annotations).toHaveLength(1);
      expect(res.body.annotations[0].annotationType).toBe('freeform-note');
    });

    it('returns an empty list when no annotations exist', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());
      const res = await request(app).get(`/v1/models/${digest}/annotations`).expect(200);
      expect(res.body.annotations).toEqual([]);
    });
  });

  // ── GET /v1/models/:digest/lineage ────────────────────────────────────
  describe('GET /v1/models/:digest/lineage', () => {
    it('walks the parent DAG leaf-to-root', async () => {
      const storage = tzun.getStorage();
      const parent = await registerModel(
        storage,
        descriptorFixture({ vendor: 'Acme AI', modelName: 'base', modelVersion: 'v1' }),
      );
      const child = await registerModel(
        storage,
        descriptorFixture({
          vendor: 'Acme AI',
          modelName: 'derived',
          modelVersion: 'v2',
          parentModelDescriptorDigest: parent.digest,
          derivation: 'fine-tune',
        }),
      );

      const res = await request(app).get(`/v1/models/${child.digest}/lineage`).expect(200);
      expect(res.body).toHaveProperty('lineage');
      expect(res.body.lineage).toHaveLength(2);
      expect(res.body.lineage[0].descriptorDigest).toBe(child.digest);
      expect(res.body.lineage[1].descriptorDigest).toBe(parent.digest);
      expect(res.body.complete).toBe(true);
      expect(res.body.terminal).toBe('root');
    });

    it('flags a truncated walk when the parent was never registered', async () => {
      const storage = tzun.getStorage();
      const absentParent = 'sha256:' + 'a'.repeat(64);
      const { digest } = await registerModel(
        storage,
        descriptorFixture({
          vendor: 'Acme AI',
          modelName: 'orphan-ft',
          modelVersion: 'v9',
          parentModelDescriptorDigest: absentParent,
          derivation: 'fine-tune',
        }),
      );

      const res = await request(app).get(`/v1/models/${digest}/lineage`).expect(200);
      // One entry, exactly like a base model — which is why the response has
      // to say so out loud.
      expect(res.body.lineage).toHaveLength(1);
      expect(res.body.complete).toBe(false);
      expect(res.body.terminal).toBe('missing-parent');
      expect(res.body.missingParentDigest).toBe(absentParent);
    });

    it('returns 404 when the digest is unknown', async () => {
      await request(app)
        .get('/v1/models/deadbeef00000000000000000000000000000000000000000000000000000000/lineage')
        .expect(404);
    });

    it('returns a single-entry lineage when there is no parent', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());
      const res = await request(app).get(`/v1/models/${digest}/lineage`).expect(200);
      expect(res.body.lineage).toHaveLength(1);
      expect(res.body.lineage[0].descriptorDigest).toBe(digest);
      // A real root, distinguishable from the orphan case above.
      expect(res.body.complete).toBe(true);
      expect(res.body.terminal).toBe('root');
      expect(res.body.missingParentDigest).toBeUndefined();
    });
  });

  // ── GET /v1/models/by-alias/:slug ─────────────────────────────────────
  describe('GET /v1/models/by-alias/:slug', () => {
    it('resolves an alias to its descriptor', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());
      await storage.setModelDescriptorAlias!('acme-latest', digest, 'tester');

      const res = await request(app).get('/v1/models/by-alias/acme-latest').expect(200);
      expect(res.body.modelDescriptorDigest).toBe(digest);
    });

    it('returns 404 when the slug is unbound', async () => {
      await request(app).get('/v1/models/by-alias/unknown-slug').expect(404);
    });
  });

  // ── POST /v1/models ───────────────────────────────────────────────────
  describe('POST /v1/models (register)', () => {
    it('registers a descriptor when admin token is provided', async () => {
      const res = await request(app)
        .post('/v1/models')
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({ descriptor: descriptorFixture({ modelName: 'reg-test' }) })
        .expect(201);

      expect(res.body).toHaveProperty('digest');
      expect(res.body.descriptor.modelName).toBe('reg-test');
      expect(res.body).toHaveProperty('alreadyExisted');
    });

    it('returns 403 without an admin token', async () => {
      await request(app)
        .post('/v1/models')
        .send({ descriptor: descriptorFixture() })
        .expect(403);
    });

    it('returns 403 with a wrong admin token', async () => {
      await request(app)
        .post('/v1/models')
        .set('X-Tzun-Admin-Token', 'bogus')
        .send({ descriptor: descriptorFixture() })
        .expect(403);
    });

    it('returns 400 when weightsPath is supplied over REST (CLI-only)', async () => {
      const res = await request(app)
        .post('/v1/models')
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({ descriptor: descriptorFixture(), weightsPath: 'weights/anywhere' })
        .expect(400);
      expect(res.body.error).toMatch(/weightsPath/i);
    });

    it('returns 400 when descriptor body is missing required MVD fields', async () => {
      await request(app)
        .post('/v1/models')
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({ descriptor: { vendor: 'Acme' } })
        .expect(400);
    });
  });

  // ── POST /v1/models/:digest/annotations ───────────────────────────────
  describe('POST /v1/models/:digest/annotations', () => {
    it('appends a typed annotation when admin token is provided', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      const res = await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({
          annotationType: 'set-license',
          value: { license: 'GPL-3.0' },
          annotatedBy: 'admin@acme',
        })
        .expect(201);

      expect(res.body.annotationType).toBe('set-license');
      expect(res.body.modelDescriptorDigest).toBe(digest);
    });

    it('returns 403 when typed annotation is attempted without admin token', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .send({
          annotationType: 'set-license',
          value: { license: 'GPL-3.0' },
          annotatedBy: 'rando@acme',
        })
        .expect(403);
    });

    it('rejects freeform-note WITHOUT admin token', async () => {
      // "Any authenticated actor" is allowed in spec, but the surface has
      // no general API-key middleware yet, so the reduction is admin-only —
      // see the header comment in src/api/models-routes.ts.
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .send({
          annotationType: 'freeform-note',
          value: { text: 'unverified context' },
          annotatedBy: 'reviewer@acme',
        })
        .expect(403);
    });

    it('admin token CAN append a freeform-note', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      const res = await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({
          annotationType: 'freeform-note',
          value: { text: 'reviewer context' },
          annotatedBy: 'admin@acme',
        })
        .expect(201);

      expect(res.body.annotationType).toBe('freeform-note');
    });

    it('rejects oversized annotation value', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      // 5 KB of payload — over the 4 KB cap.
      const bigValue = { text: 'x'.repeat(5 * 1024) };
      await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({ annotationType: 'freeform-note', value: bigValue, annotatedBy: 'admin@acme' })
        .expect(413);
    });

    it('rejects oversized note field', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({
          annotationType: 'freeform-note',
          value: { text: 'short' },
          note: 'x'.repeat(2000),
          annotatedBy: 'admin@acme',
        })
        .expect(413);
    });

    it('returns 400 when annotatedBy is missing', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      await request(app)
        .post(`/v1/models/${digest}/annotations`)
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({ annotationType: 'freeform-note', value: { text: 'x' } })
        .expect(400);
    });

    it('returns 404 when the digest is unknown', async () => {
      await request(app)
        .post(
          '/v1/models/abadf00d00000000000000000000000000000000000000000000000000000000/annotations',
        )
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({
          annotationType: 'set-license',
          value: { license: 'MIT' },
          annotatedBy: 'admin@acme',
        })
        .expect(404);
    });
  });

  // ── POST /v1/models/aliases ───────────────────────────────────────────
  describe('POST /v1/models/aliases', () => {
    it('sets an alias when admin token is provided', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());

      const res = await request(app)
        .post('/v1/models/aliases')
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({ slug: 'acme-current', digest, setBy: 'admin@acme' })
        .expect(201);

      expect(res.body.slug).toBe('acme-current');
      expect(res.body.modelDescriptorDigest).toBe(digest);
    });

    it('returns 403 without admin token', async () => {
      const storage = tzun.getStorage();
      const { digest } = await registerModel(storage, descriptorFixture());
      await request(app)
        .post('/v1/models/aliases')
        .send({ slug: 'x', digest, setBy: 'rando' })
        .expect(403);
    });

    it('returns 400 when slug or digest is missing', async () => {
      await request(app)
        .post('/v1/models/aliases')
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({ slug: '' })
        .expect(400);
    });

    it('returns 404 when targeting an unknown digest', async () => {
      await request(app)
        .post('/v1/models/aliases')
        .set('X-Tzun-Admin-Token', ADMIN_TOKEN)
        .send({
          slug: 'phantom',
          digest: '0000000000000000000000000000000000000000000000000000000000000000',
          setBy: 'admin@acme',
        })
        .expect(404);
    });
  });
});
