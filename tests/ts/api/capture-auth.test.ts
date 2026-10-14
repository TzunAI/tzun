// tests/ts/api/capture-auth.test.ts
//
// The cloud refuses a capture without an API key, and the SDK's POST
// /v1/evidence does not store a record for anyone who can reach it unless told
// to. Whatever builds the capture route (createRouter, and createServer
// through it) has to be told how callers are authenticated: `resolveActor`
// requires a recognised credential on every capture, `allowUnauthenticated:
// true` says out loud that none is required. Saying neither is an error when
// the route is built, never a per-request surprise.
//
// As on the platform, the credential authorises the request and is not
// written into the evidence; the record is what the body says.
import express from 'express';
import request from 'supertest';
import { createRouter } from '../../../src/api/routes';
import { createServer } from '../../../src/api/server';
import { apiKeyActorResolver, ACTOR_AUTH_HEADER } from '../../../src/api/actor-resolver';
import type { ResolveActor } from '../../../src/api/actor-resolver';
import { Tzun } from '../../../src/sdk/index';

const KEY = 'key-7c1e0b4d';
const resolveActor = apiKeyActorResolver({ [KEY]: 'ops-bot' });

const CAPTURE = {
  aiOutput: { recommendation: 'approve' },
  action: 'approved',
  reason: 'criteria met',
  decider: { kind: 'human' as const, id: 'acct:jane.chen-example.com', agent: null, credential: null, freshness: null },
};

describe('capture auth is an explicit choice at construction', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  const noChoice: Array<[string, unknown]> = [
    ['no options', undefined],
    ['empty options', {}],
    ['allowUnauthenticated: false', { allowUnauthenticated: false }],
    ['allowUnauthenticated: "true" (a string)', { allowUnauthenticated: 'true' }],
    ['benchmark only', { benchmark: true }],
  ];

  it.each(noChoice)('createRouter with %s throws, naming both choices', (_label, options) => {
    const build = () => createRouter(tzun, options as never);
    expect(build).toThrow(/createRouter/);
    expect(build).toThrow(/resolveActor/);
    expect(build).toThrow(/allowUnauthenticated: true/);
  });

  it.each(noChoice)('createServer with %s throws, naming createServer', (_label, options) => {
    const build = () => createServer(tzun, options as never);
    expect(build).toThrow(/createServer/);
    expect(build).toThrow(/resolveActor/);
    expect(build).toThrow(/allowUnauthenticated: true/);
  });

  it('refuses a resolveActor that is not a function', () => {
    expect(() => createRouter(tzun, { resolveActor: 'key-abc' } as never)).toThrow(
      /resolveActor must be a function/,
    );
  });

  it('refuses both choices at once', () => {
    expect(() =>
      createRouter(tzun, { resolveActor, allowUnauthenticated: true } as never),
    ).toThrow(/not both/);
  });

  it('accepts either choice', () => {
    expect(() => createRouter(tzun, { resolveActor })).not.toThrow();
    expect(() => createRouter(tzun, { allowUnauthenticated: true })).not.toThrow();
    expect(() => createServer(tzun, { resolveActor })).not.toThrow();
    expect(() => createServer(tzun, { allowUnauthenticated: true, benchmark: true })).not.toThrow();
  });
});

describe('POST /v1/evidence with a resolver', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init();
  });

  afterEach(async () => {
    await tzun.close();
  });

  async function stored(): Promise<number> {
    return (await tzun.getStorage().list()).length;
  }

  describe.each([
    ['createServer', () => createServer(tzun, { resolveActor })],
    [
      'createRouter on a bare app',
      () => {
        const app = express();
        app.use(createRouter(tzun, { resolveActor }));
        return app;
      },
    ],
  ])('%s', (_label, build) => {
    it('refuses a capture with no credential: 401, nothing stored', async () => {
      const res = await request(build()).post('/v1/evidence').send(CAPTURE);
      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'unauthenticated' });
      expect(await stored()).toBe(0);
    });

    it('refuses a capture with an unknown credential', async () => {
      const res = await request(build())
        .post('/v1/evidence')
        .set(ACTOR_AUTH_HEADER, 'key-not-issued')
        .send(CAPTURE);
      expect(res.status).toBe(401);
      expect(await stored()).toBe(0);
    });

    it('stores a capture that carries a recognised credential', async () => {
      const res = await request(build())
        .post('/v1/evidence')
        .set(ACTOR_AUTH_HEADER, KEY)
        .send(CAPTURE);
      expect(res.status).toBe(201);
      expect(res.body.stored).toBe(true);
      expect(await stored()).toBe(1);
    });

    it('does not write the resolved actor into the evidence', async () => {
      const res = await request(build())
        .post('/v1/evidence')
        .set(ACTOR_AUTH_HEADER, KEY)
        .send(CAPTURE)
        .expect(201);
      const envelope = res.body.envelope;
      expect(envelope.custodyChain[0].actor).toBe('acct:jane.chen-example.com');
      expect(JSON.stringify(envelope)).not.toContain('ops-bot');
    });

    it('authenticates before reading the body: malformed JSON without a credential is 401, not 400', async () => {
      const res = await request(build())
        .post('/v1/evidence')
        .set('Content-Type', 'application/json')
        .send('{"humanAction": ');
      expect(res.status).toBe(401);
    });

    it('authenticates before reading the body: an oversized body without a credential is 401, not 413', async () => {
      const res = await request(build())
        .post('/v1/evidence')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify({ ...CAPTURE, reason: 'a'.repeat(1024 * 1024 + 1) }));
      expect(res.status).toBe(401);
    });

    it('still parses and limits the body once authenticated', async () => {
      const malformed = await request(build())
        .post('/v1/evidence')
        .set(ACTOR_AUTH_HEADER, KEY)
        .set('Content-Type', 'application/json')
        .send('{"humanAction": ');
      expect(malformed.status).toBe(400);
      expect(malformed.headers['content-type']).toMatch(/application\/json/);

      const oversized = await request(build())
        .post('/v1/evidence')
        .set(ACTOR_AUTH_HEADER, KEY)
        .set('Content-Type', 'application/json')
        .send(JSON.stringify({ ...CAPTURE, reason: 'a'.repeat(1024 * 1024 + 1) }));
      expect(oversized.status).toBe(413);
      expect(oversized.headers['content-type']).toMatch(/application\/json/);
      expect(await stored()).toBe(0);
    });
  });

  it('a resolver answering with an empty actor is not authentication', async () => {
    const empty: ResolveActor = () => ({ actor: '' });
    const res = await request(createServer(tzun, { resolveActor: empty }))
      .post('/v1/evidence')
      .send(CAPTURE);
    expect(res.status).toBe(401);
    expect(await stored()).toBe(0);
  });

  it('a resolver that throws is a 500 with no detail, and nothing is stored', async () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const broken: ResolveActor = () => {
      throw new Error('key table unavailable at db-host-3');
    };
    const res = await request(createServer(tzun, { resolveActor: broken }))
      .post('/v1/evidence')
      .send(CAPTURE);
    spy.mockRestore();
    expect(res.status).toBe(500);
    expect(JSON.stringify(res.body)).not.toContain('db-host-3');
    expect(await stored()).toBe(0);
  });
});

describe('POST /v1/evidence with allowUnauthenticated: true', () => {
  it('stores a capture from a caller with no credential', async () => {
    const tzun = await Tzun.init();
    const res = await request(createServer(tzun, { allowUnauthenticated: true }))
      .post('/v1/evidence')
      .send(CAPTURE);
    expect(res.status).toBe(201);
    expect(res.body.stored).toBe(true);
    await tzun.close();
  });
});
