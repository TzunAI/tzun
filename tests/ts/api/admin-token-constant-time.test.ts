/**
 * The admin-token guard compares with constant-time equality, as the api-key
 * resolver does.
 *
 * `actor-resolver.ts` documents its api-key comparison as "constant-time
 * equality to mitigate timing attacks, mirroring the admin-token guard", and
 * the api-key resolver uses `timingSafeEqual`. The admin-token guard has to
 * hold the same property: TZUN_ADMIN_TOKEN gates catalog registration and
 * alias writes, and a plain `!==` / `===` on the header would leave it open to
 * the timing attack that comment says both guards mitigate.
 *
 * These tests pin the OUTCOME (which tokens are accepted and rejected, and
 * that the guard is routed through the shared constant-time helper) rather
 * than trying to measure wall-clock timing, which is not a stable assertion in
 * a test suite.
 */
import { constantTimeEqual } from '../../../src/api/constant-time';
import { apiKeyActorResolver } from '../../../src/api/actor-resolver';
import type { Request } from 'express';
import request from 'supertest';
import { createServer } from '../../../src/api/server';
import { Tzun } from '../../../src/sdk/index';
import { readFileSync } from 'fs';
import { resolve } from 'path';

function reqWith(headers: Record<string, string>): Request {
  return {
    header: (name: string) => headers[name.toLowerCase()],
  } as unknown as Request;
}

describe('constantTimeEqual', () => {
  it('accepts an exact match', () => {
    expect(constantTimeEqual('s3cret-token', 's3cret-token')).toBe(true);
  });

  it('rejects a same-length near-miss', () => {
    expect(constantTimeEqual('s3cret-token', 's3cret-tokeN')).toBe(false);
  });

  it('rejects on length mismatch without throwing', () => {
    // timingSafeEqual throws on unequal lengths — the helper must not.
    expect(() => constantTimeEqual('short', 'a-much-longer-token')).not.toThrow();
    expect(constantTimeEqual('short', 'a-much-longer-token')).toBe(false);
  });

  it('rejects undefined on either side (a missing header is not a match)', () => {
    expect(constantTimeEqual(undefined, 'tok')).toBe(false);
    expect(constantTimeEqual('tok', undefined)).toBe(false);
    expect(constantTimeEqual(undefined, undefined)).toBe(false);
  });

  it('handles multi-byte tokens by bytes, not code units', () => {
    expect(constantTimeEqual('tökén', 'tökén')).toBe(true);
    expect(constantTimeEqual('tökén', 'token')).toBe(false);
  });
});

describe('the admin-token guard is routed through the constant-time helper', () => {
  const ADMIN_HEADER = 'x-tzun-admin-token';
  const TOKEN = 'admin-s3cret-token';
  let saved: string | undefined;

  beforeEach(() => {
    saved = process.env.TZUN_ADMIN_TOKEN;
    process.env.TZUN_ADMIN_TOKEN = TOKEN;
  });
  afterEach(() => {
    if (saved === undefined) delete process.env.TZUN_ADMIN_TOKEN;
    else process.env.TZUN_ADMIN_TOKEN = saved;
  });

  /**
   * Constant-time comparison has no observable outcome to assert — the same
   * tokens are accepted and rejected either way. So this pins the SOURCE:
   * neither admin guard compares the header with a raw `===` / `!==`, and both
   * go through the helper, without pretending to measure wall-clock timing in
   * a test suite.
   */
  it('models-routes.ts compares the admin header only via constantTimeEqual', () => {
    const src = readFileSync(
      resolve(__dirname, '../../../src/api/models-routes.ts'),
      'utf8',
    );
    const guardRegion = src.slice(
      src.indexOf('function requireAdminToken'),
      src.indexOf('/** Strips `canonicalBytes`'),
    );
    expect(guardRegion.length).toBeGreaterThan(100); // the slice actually found the guards

    // No raw comparison of the header or the expected token anywhere in the
    // two guard functions.
    expect(guardRegion).not.toMatch(/supplied\s*!==\s*expected/);
    expect(guardRegion).not.toMatch(/ADMIN_HEADER\)\s*===\s*expected/);
    // Both guards go through the helper.
    expect(guardRegion.match(/constantTimeEqual\(/g) ?? []).toHaveLength(2);
  });

  it('still 403s a same-length near-miss and admits the real token', async () => {
    const tzun = await Tzun.init();
    const app = createServer(tzun, { allowUnauthenticated: true });

    const nearMiss = TOKEN.slice(0, -1) + 'X';
    await request(app)
      .get('/v1/models/usage')
      .set(ADMIN_HEADER, nearMiss)
      .expect(403);

    // The real token is not rejected — proves the guard is not simply broken
    // shut, which a comparison that always returns false would also satisfy.
    const ok = await request(app).get('/v1/models/usage').set(ADMIN_HEADER, TOKEN);
    expect(ok.status).not.toBe(403);

    await request(app).get('/v1/models/usage').expect(403);
  });
});

describe('apiKeyActorResolver still resolves through the shared helper', () => {
  it('matches a known key and rejects an unknown one', () => {
    const resolve = apiKeyActorResolver({ 'key-aaa': 'alice', 'key-bbb': 'bob' });
    expect(resolve(reqWith({ 'x-tzun-api-key': 'key-bbb' }))).toEqual({ actor: 'bob' });
    expect(resolve(reqWith({ 'x-tzun-api-key': 'key-bbc' }))).toBeNull();
    expect(resolve(reqWith({}))).toBeNull();
  });

  it('does not throw when the supplied key length differs from a configured key', () => {
    const resolve = apiKeyActorResolver({ 'a-long-configured-key': 'alice' });
    expect(() => resolve(reqWith({ 'x-tzun-api-key': 'x' }))).not.toThrow();
    expect(resolve(reqWith({ 'x-tzun-api-key': 'x' }))).toBeNull();
  });
});
