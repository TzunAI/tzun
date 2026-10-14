// tests/ts/api/json-body-limit.test.ts
//
// createServer() mounted a bare `express.json()`, whose default limit is
// 100 KB, so the self-hosted POST /v1/evidence refused captures the cloud
// accepts: the platform parses JSON bodies up to 1 MiB with inflate disabled.
// The body-parser refusals also came back as Express's default HTML error
// page; they are JSON here, as on the platform.
import { gzipSync } from 'zlib';
import request from 'supertest';
import { createServer, JSON_BODY_LIMIT } from '../../../src/api/server';
import { Tzun } from '../../../src/sdk/index';

const ONE_MIB = 1024 * 1024;

/** A capture body serialised to exactly `bytes` bytes of UTF-8 JSON. */
/**
 * A capture body of exactly `bytes` bytes. The bulk sits in an unhashed
 * member (the signer identity's token), since a record's hashed object is
 * capped at 256 KiB, well below the body limit.
 */
function captureBodyOfSize(bytes: number): string {
  const head =
    '{"aiOutput":{"x":1},"action":"approved","reason":"ok","decider":{"kind":"human","id":"acct:u-1"},' +
    '"attestationInputs":{"signerIdentity":{"idpIssuer":"https://idp.example","idpToken":"';
  const tail = '"}}}';
  const pad = bytes - head.length - tail.length;
  if (pad < 1) throw new Error(`cannot build a capture body of ${bytes} bytes`);
  const body = head + 'a'.repeat(pad) + tail;
  expect(Buffer.byteLength(body, 'utf8')).toBe(bytes);
  return body;
}

describe('POST /v1/evidence JSON body limit matches the platform', () => {
  let tzun: Tzun;
  let app: ReturnType<typeof createServer>;

  beforeEach(async () => {
    tzun = await Tzun.init();
    app = createServer(tzun, { allowUnauthenticated: true });
  });

  afterEach(async () => {
    await tzun.close();
  });

  function post(body: string) {
    return request(app)
      .post('/v1/evidence')
      .set('Content-Type', 'application/json')
      .send(body);
  }

  it('the limit is the platform value, 1 MiB', () => {
    expect(JSON_BODY_LIMIT).toBe('1mb');
  });

  it('accepts a 300 KB capture that the 100 KB default refused', async () => {
    const res = await post(captureBodyOfSize(300 * 1024));
    expect(res.status).toBe(201);
    expect(res.body.stored).toBe(true);
  });

  it('accepts a body of exactly 1 MiB', async () => {
    const res = await post(captureBodyOfSize(ONE_MIB));
    expect(res.status).toBe(201);
    expect(res.body.stored).toBe(true);
  });

  it('refuses a body one byte over 1 MiB with a JSON 413', async () => {
    const res = await post(captureBodyOfSize(ONE_MIB + 1));
    expect(res.status).toBe(413);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body.error).toMatch(/1mb/);
    expect(await tzun.getStorage().list()).toHaveLength(0);
  });

  it('refuses a compressed body with a JSON 415 rather than inflating it', async () => {
    const res = await request(app)
      .post('/v1/evidence')
      .set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip')
      .send(gzipSync(Buffer.from(captureBodyOfSize(1024))));
    expect(res.status).toBe(415);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(await tzun.getStorage().list()).toHaveLength(0);
  });

  it('answers malformed JSON with a JSON 400', async () => {
    const res = await post('{"humanAction": ');
    expect(res.status).toBe(400);
    expect(res.headers['content-type']).toMatch(/application\/json/);
    expect(res.body.error).toMatch(/JSON/);
  });

  it('the refusal body carries no parser detail or stack', async () => {
    const res = await post('{"humanAction": ');
    expect(JSON.stringify(res.body)).not.toMatch(/at \w+ \(|node_modules|SyntaxError/);
  });
});
