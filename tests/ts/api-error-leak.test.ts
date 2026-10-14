import request from 'supertest';
import { createServer } from '../../src/api/server';
import { Tzun } from '../../src/sdk/index';

/**
 * The SDK REST 500 handlers answer with a generic body, never the raw exception
 * message. On a SQLite deployment that message is better-sqlite3's SQL text; on
 * Postgres it is a pg message carrying column names and sometimes the
 * connection target. The read routes can be served unauthenticated, so echoing
 * it would tell an anonymous prober the storage backend and the query shape
 * from a single malformed request. The detail goes to the server log, and into
 * the body only under an explicit opt-in.
 */
const LEAKY =
  'SQLITE_ERROR: no such column: envelopes.chain_id (postgres://tzun:hunter2@db.example:5432/evidence)';

describe('REST 500 responses do not echo adapter internals', () => {
  let app: ReturnType<typeof createServer>;
  let errorSpy: jest.SpyInstance;
  const savedNodeEnv = process.env.NODE_ENV;
  const savedVerbose = process.env.TZUN_VERBOSE_ERRORS;

  beforeEach(async () => {
    const tzun = await Tzun.init();
    const storage = tzun.getStorage();
    // Make the storage layer fail the way a real adapter fault does.
    jest.spyOn(storage, 'list').mockRejectedValue(new Error(LEAKY));
    jest.spyOn(storage, 'retrieve').mockRejectedValue(new Error(LEAKY));
    app = createServer(tzun, { allowUnauthenticated: true });
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    delete process.env.NODE_ENV;
    delete process.env.TZUN_VERBOSE_ERRORS;
  });

  afterEach(() => {
    jest.restoreAllMocks();
    if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = savedNodeEnv;
    if (savedVerbose === undefined) delete process.env.TZUN_VERBOSE_ERRORS;
    else process.env.TZUN_VERBOSE_ERRORS = savedVerbose;
  });

  it('GET /v1/evidence returns a generic body when the adapter throws', async () => {
    const res = await request(app).get('/v1/evidence').expect(500);

    expect(res.body).toEqual({ error: 'Internal server error' });
    expect(JSON.stringify(res.body)).not.toContain('SQLITE_ERROR');
    expect(JSON.stringify(res.body)).not.toContain('hunter2');
  });

  it('GET /v1/evidence/:id returns a generic body when the adapter throws', async () => {
    const res = await request(app).get('/v1/evidence/ev-1').expect(500);

    expect(res.body).toEqual({ error: 'Internal server error' });
    expect(JSON.stringify(res.body)).not.toContain('db.example');
  });

  it('still logs the full detail server-side for the operator', async () => {
    await request(app).get('/v1/evidence').expect(500);

    const logged = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toContain('SQLITE_ERROR');
  });

  it('echoes the message only under an explicit opt-in', async () => {
    process.env.TZUN_VERBOSE_ERRORS = '1';
    const res = await request(app).get('/v1/evidence').expect(500);

    expect(res.body.message).toContain('SQLITE_ERROR');
  });

  it('an unset NODE_ENV redacts (the opt-in is fail-closed)', async () => {
    expect(process.env.NODE_ENV).toBeUndefined();
    const res = await request(app).get('/v1/evidence').expect(500);

    expect(res.body.message).toBeUndefined();
  });
});
