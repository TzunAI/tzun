import request from 'supertest';
import { createServer } from '../../src/api/server';
import { Tzun } from '../../src/sdk/index';

describe('Benchmark Web Interface', () => {
  let app: ReturnType<typeof createServer>;
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init();
    // The benchmark routes are opt-in. These tests exercise the
    // routes themselves, so they turn the flag on explicitly; the default-off
    // behaviour is pinned in its own describe block below.
    app = createServer(tzun, { allowUnauthenticated: true, benchmark: true });
  });

  afterEach(async () => {
    await tzun.close();
  });

  describe('GET /v1/benchmark', () => {
    it('returns HTML page with benchmark UI', async () => {
      const res = await request(app)
        .get('/v1/benchmark')
        .expect(200);

      expect(res.headers['content-type']).toContain('text/html');
      expect(res.text).toContain('Tzun SDK Benchmark');
      expect(res.text).toContain('Run Benchmark');
      expect(res.text).toContain('<button');
    });
  });

  describe('POST /v1/benchmark/run', () => {
    it('runs benchmark and returns JSON report', async () => {
      const res = await request(app)
        .post('/v1/benchmark/run')
        .send({
          suites: ['serialization'],
          minDurationMs: 100,
          warmupIterations: 2,
        })
        .expect(200);

      expect(res.body).toHaveProperty('startedAt');
      expect(res.body).toHaveProperty('completedAt');
      expect(res.body).toHaveProperty('hardware');
      expect(res.body).toHaveProperty('measurements');
      expect(res.body.measurements.length).toBeGreaterThan(0);
    }, 30000);

    it('runs with default options when no body is provided', async () => {
      const res = await request(app)
        .post('/v1/benchmark/run')
        .send({
          suites: ['digest'],
          minDurationMs: 100,
          warmupIterations: 2,
        })
        .expect(200);

      expect(res.body).toHaveProperty('measurements');
    }, 30000);
  });
});

// ---------------------------------------------------------------------------
// The benchmark routes let the caller size a synchronous busy loop, so they
// are off by default and their inputs are bounded.
//
// `runTimed` is a synchronous `while (elapsed < minDurationMs) { fn(); }` run
// three times per suite, so a single POST with `minDurationMs: 3600000` would
// block the whole Node process for hours — every capture, verify and health
// request on it stalled. Worse, `scannerWorkerCounts: [0]` would reach a
// phase-1 loop that advances by `config.workers`, so it would never advance:
// 100% CPU, no timers, no signals, SIGKILL required.
// ---------------------------------------------------------------------------
describe('Benchmark routes are opt-in and input-bounded', () => {
  let tzun: Tzun;

  beforeEach(async () => {
    tzun = await Tzun.init();
  });
  afterEach(async () => {
    await tzun.close();
  });

  it('does not mount the benchmark routes by default', async () => {
    const app = createServer(tzun, { allowUnauthenticated: true });
    await request(app).get('/v1/benchmark').expect(404);
    await request(app)
      .post('/v1/benchmark/run')
      .send({ suites: ['serialization'], minDurationMs: 100 })
      .expect(404);
  });

  it('rejects an unbounded minDurationMs with 400 instead of blocking the event loop', async () => {
    const app = createServer(tzun, { allowUnauthenticated: true, benchmark: true });

    const started = Date.now();
    const res = await request(app)
      .post('/v1/benchmark/run')
      .send({ suites: ['serialization'], minDurationMs: 3_600_000 })
      .expect(400);
    const elapsed = Date.now() - started;

    expect(res.body.error).toBe('invalid_request');
    expect(res.body.message).toContain('minDurationMs');
    // The whole point: it must return, not run for an hour.
    expect(elapsed).toBeLessThan(5_000);
  });

  it('rejects a zero scanner worker count with 400 instead of hanging forever', async () => {
    const app = createServer(tzun, { allowUnauthenticated: true, benchmark: true });

    const res = await request(app)
      .post('/v1/benchmark/run')
      .send({ suites: ['scanner'], minDurationMs: 100, scannerWorkerCounts: [0] })
      .expect(400);

    expect(res.body.message).toContain('scannerWorkerCounts');
  });

  it('rejects an unknown suite name with 400', async () => {
    const app = createServer(tzun, { allowUnauthenticated: true, benchmark: true });

    const res = await request(app)
      .post('/v1/benchmark/run')
      .send({ suites: ['../../etc/passwd'] })
      .expect(400);

    expect(res.body.message).toContain('unknown suite');
  });

  it('rejects an out-of-range warmupIterations with 400', async () => {
    const app = createServer(tzun, { allowUnauthenticated: true, benchmark: true });

    await request(app)
      .post('/v1/benchmark/run')
      .send({ suites: ['serialization'], minDurationMs: 100, warmupIterations: 10_000_000 })
      .expect(400);
  });
});
