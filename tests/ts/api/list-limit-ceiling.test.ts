// tests/ts/api/list-limit-ceiling.test.ts
//
// GET /v1/evidence defaults `limit` to 100 rows and clamps it at 200, as the
// hosted service's list reads do. Without the ceiling, an absent or huge
// `limit` would let one request pull every envelope in the store into memory.
import request from 'supertest';
import { createServer } from '../../../src/api/server';
import { DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT } from '../../../src/api/routes';
import { Tzun } from '../../../src/sdk/index';

describe('GET /v1/evidence limit ceiling', () => {
  let tzun: Tzun;
  let app: ReturnType<typeof createServer>;
  let listSpy: jest.SpyInstance;

  beforeEach(async () => {
    tzun = await Tzun.init();
    app = createServer(tzun, { allowUnauthenticated: true });
    listSpy = jest.spyOn(tzun.getStorage(), 'list');
  });

  afterEach(async () => {
    listSpy.mockRestore();
    await tzun.close();
  });

  function limitPassedToStorage(): unknown {
    expect(listSpy).toHaveBeenCalledTimes(1);
    return listSpy.mock.calls[0][0]?.limit;
  }

  it('matches the platform: default 100, ceiling 200', () => {
    expect(DEFAULT_LIST_LIMIT).toBe(100);
    expect(MAX_LIST_LIMIT).toBe(200);
  });

  it('an absent limit is the default, not the whole store', async () => {
    await request(app).get('/v1/evidence').expect(200);
    expect(limitPassedToStorage()).toBe(DEFAULT_LIST_LIMIT);
  });

  it('a limit above the ceiling is clamped to the ceiling', async () => {
    await request(app).get('/v1/evidence?limit=100000000').expect(200);
    expect(limitPassedToStorage()).toBe(MAX_LIST_LIMIT);
  });

  it('a limit one past the ceiling is clamped', async () => {
    await request(app).get(`/v1/evidence?limit=${MAX_LIST_LIMIT + 1}`).expect(200);
    expect(limitPassedToStorage()).toBe(MAX_LIST_LIMIT);
  });

  it('a limit at the ceiling is honoured as given', async () => {
    await request(app).get(`/v1/evidence?limit=${MAX_LIST_LIMIT}`).expect(200);
    expect(limitPassedToStorage()).toBe(MAX_LIST_LIMIT);
  });

  it('a limit under the ceiling is honoured as given', async () => {
    await request(app).get('/v1/evidence?limit=7').expect(200);
    expect(limitPassedToStorage()).toBe(7);
  });

  it('a malformed limit is still a 400, not clamped', async () => {
    const res = await request(app).get('/v1/evidence?limit=abc');
    expect(res.status).toBe(400);
    expect(listSpy).not.toHaveBeenCalled();
  });

  it('returns no more than the ceiling even when the store holds more', async () => {
    const total = MAX_LIST_LIMIT + 5;
    for (let i = 0; i < total; i++) {
      const r = await tzun.capture({
        decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
        aiOutput: { i },
        action: 'approved',
        reason: `row ${i}`,
      });
      expect(r.stored).toBe(true);
    }

    const huge = await request(app).get('/v1/evidence?limit=100000').expect(200);
    expect(huge.body.length).toBe(MAX_LIST_LIMIT);

    const unspecified = await request(app).get('/v1/evidence').expect(200);
    expect(unspecified.body.length).toBe(DEFAULT_LIST_LIMIT);

    // Paging past the ceiling still reaches every row.
    const tail = await request(app)
      .get(`/v1/evidence?limit=${MAX_LIST_LIMIT}&offset=${MAX_LIST_LIMIT}`)
      .expect(200);
    expect(tail.body.length).toBe(total - MAX_LIST_LIMIT);
  });
});
