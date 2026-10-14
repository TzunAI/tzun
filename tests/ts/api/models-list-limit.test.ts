// tests/ts/api/models-list-limit.test.ts
//
// GET /v1/models read `limit` and `offset` with parseInt, which has two
// failure modes: 'abc' became NaN and was dropped, so the request listed the
// whole catalog, and '9 OR 1=1' became 9, a silent truncation that looked like
// success. A negative value reached the storage adapter's own guard and came
// back as a 500. Nothing capped a well-formed limit either.
//
// The hosted service's GET /v1/models returns at most MAX_MODEL_ROWS = 1000
// rows and takes no limit, so it always returns up to 1000. This route
// defaults to 1000, clamps a larger limit to 1000, and refuses a malformed one
// with 400.
import express from 'express';
import request from 'supertest';
import {
  createModelsRouter,
  DEFAULT_MODEL_LIST_LIMIT,
  MAX_MODEL_LIST_LIMIT,
} from '../../../src/api/models-routes';
import { registerModel } from '../../../src/models/register';
import { Tzun } from '../../../src/sdk/index';
import { ModelDescriptor } from '@tzun/engine';

function descriptor(modelName: string): Partial<ModelDescriptor> {
  return {
    vendor: 'Acme AI',
    modelName,
    modelVersion: '1.0',
    modelType: 'language-model',
    integrityTier: 'vendor-asserted',
    license: 'Apache-2.0',
    modelCardUrl: null,
    regulatoryMarkings: [],
    externalIdentifiers: [],
  };
}

describe('GET /v1/models limit', () => {
  let tzun: Tzun;
  let app: express.Express;
  let listSpy: jest.SpyInstance;

  beforeEach(async () => {
    tzun = await Tzun.init();
    app = express();
    app.use(express.json());
    app.use(createModelsRouter(tzun));
    listSpy = jest.spyOn(tzun.getStorage(), 'listModelDescriptors' as never);
  });

  afterEach(async () => {
    listSpy.mockRestore();
    await tzun.close();
  });

  function filterPassedToStorage(): { limit?: unknown; offset?: unknown } {
    expect(listSpy).toHaveBeenCalledTimes(1);
    return (listSpy.mock.calls[0] as unknown[])[0] as { limit?: unknown; offset?: unknown };
  }

  it('matches the platform: default and ceiling are both MAX_MODEL_ROWS, 1000', () => {
    expect(DEFAULT_MODEL_LIST_LIMIT).toBe(1000);
    expect(MAX_MODEL_LIST_LIMIT).toBe(1000);
  });

  it('an absent limit is the default, not the whole catalog', async () => {
    await request(app).get('/v1/models').expect(200);
    expect(filterPassedToStorage().limit).toBe(DEFAULT_MODEL_LIST_LIMIT);
  });

  it('a limit above the ceiling is clamped to the ceiling', async () => {
    await request(app).get('/v1/models?limit=100000000').expect(200);
    expect(filterPassedToStorage().limit).toBe(MAX_MODEL_LIST_LIMIT);
  });

  it('a limit one past the ceiling is clamped', async () => {
    await request(app).get(`/v1/models?limit=${MAX_MODEL_LIST_LIMIT + 1}`).expect(200);
    expect(filterPassedToStorage().limit).toBe(MAX_MODEL_LIST_LIMIT);
  });

  it('a limit under the ceiling is honoured as given', async () => {
    await request(app).get('/v1/models?limit=7').expect(200);
    expect(filterPassedToStorage().limit).toBe(7);
  });

  it('a well-formed offset is passed through', async () => {
    await request(app).get('/v1/models?offset=4').expect(200);
    expect(filterPassedToStorage().offset).toBe(4);
  });

  it.each([
    ['9 OR 1=1'],
    ['abc'],
    ['-1'],
    ['1.5'],
    ['1e3'],
    [' 5'],
  ])('limit=%j is a 400, never reaching storage', async (raw) => {
    const res = await request(app).get('/v1/models?limit=' + encodeURIComponent(raw));
    expect(res.status).toBe(400);
    expect(res.body.message).toMatch(/limit/);
    expect(listSpy).not.toHaveBeenCalled();
  });

  it.each([['9 OR 1=1'], ['abc'], ['-1']])(
    'offset=%j is a 400, never reaching storage',
    async (raw) => {
      const res = await request(app).get('/v1/models?offset=' + encodeURIComponent(raw));
      expect(res.status).toBe(400);
      expect(res.body.message).toMatch(/offset/);
      expect(listSpy).not.toHaveBeenCalled();
    },
  );

  it('a repeated limit (array-valued query) is a 400', async () => {
    const res = await request(app).get('/v1/models?limit=2&limit=3');
    expect(res.status).toBe(400);
    expect(listSpy).not.toHaveBeenCalled();
  });

  it('returns no more than the ceiling even when the catalog holds more', async () => {
    const storage = tzun.getStorage();
    const total = MAX_MODEL_LIST_LIMIT + 3;
    for (let i = 0; i < total; i++) {
      await registerModel(storage, descriptor(`m${i}`));
    }

    const unspecified = await request(app).get('/v1/models').expect(200);
    expect(unspecified.body.models.length).toBe(MAX_MODEL_LIST_LIMIT);

    const huge = await request(app).get('/v1/models?limit=100000').expect(200);
    expect(huge.body.models.length).toBe(MAX_MODEL_LIST_LIMIT);

    const tail = await request(app)
      .get(`/v1/models?offset=${MAX_MODEL_LIST_LIMIT}`)
      .expect(200);
    expect(tail.body.models.length).toBe(total - MAX_MODEL_LIST_LIMIT);
  }, 60_000);
});
