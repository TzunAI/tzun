/**
 * The guard itself. Fails on the pre-guard tree: without
 * tests/ts/setup/no-live-network.ts wired into jest.config.js, the first test
 * reaches https://freetsa.org for real and either succeeds or fails with a
 * transport error — neither is a LiveNetworkRefused rejection.
 */
import * as http from 'http';
import { AddressInfo } from 'net';
import {
  drainRefusals,
  installNoLiveNetworkGuard,
  isGuardInstalled,
  liveNetworkAllowed,
  isLoopback,
  INTEGRATION_FLAG,
  REFUSED_ERROR_NAME,
} from './helpers/no-live-network';

const describeOffline = liveNetworkAllowed() ? describe.skip : describe;

describeOffline('no-live-network guard', () => {
  afterEach(() => {
    // Every test here drains what it caused; nothing must leak to the
    // suite-wide afterEach in tests/ts/setup/no-live-network.ts.
    expect(drainRefusals()).toEqual([]);
  });

  it('is installed by the jest setup file (not by this test)', () => {
    // Observe only. Installing here would mask a missing jest.config.js
    // wiring: every later test in this file would then pass against a guard
    // that no OTHER test file has.
    expect(isGuardInstalled()).toBe(true);
  });

  it('refuses a fetch to a non-loopback host and records it', async () => {
    await expect(
      fetch('https://freetsa.org/tsr', { method: 'POST', body: 'x' }),
    ).rejects.toMatchObject({
      name: REFUSED_ERROR_NAME,
      message: expect.stringContaining('https://freetsa.org/tsr'),
    });
    const refused = drainRefusals();
    expect(refused).toHaveLength(1);
    expect(refused[0].url).toBe('https://freetsa.org/tsr');
    expect(refused[0].test).toContain('refuses a fetch to a non-loopback host');
  });

  it('still records the refusal when the caller swallows it (the SDK does)', async () => {
    const swallowed = await fetch('https://freetsa.org/tsr').then(
      () => 'resolved',
      () => 'rejected-and-ignored',
    );
    expect(swallowed).toBe('rejected-and-ignored');
    // This is what lets the suite-wide afterEach fail the test by name.
    expect(drainRefusals().map((r) => r.url)).toEqual(['https://freetsa.org/tsr']);
  });

  it('refuses a Request object and a URL object too', async () => {
    await expect(fetch(new URL('https://example.com/a'))).rejects.toMatchObject({
      name: REFUSED_ERROR_NAME,
    });
    await expect(fetch(new Request('https://example.com/b'))).rejects.toMatchObject({
      name: REFUSED_ERROR_NAME,
    });
    expect(drainRefusals().map((r) => r.url)).toEqual([
      'https://example.com/a',
      'https://example.com/b',
    ]);
  });

  it('lets a loopback host through to the real fetch', async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('loopback ok');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const res = await fetch(`http://127.0.0.1:${port}/`);
      expect(res.status).toBe(200);
      expect(await res.text()).toBe('loopback ok');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    expect(drainRefusals()).toEqual([]);
  });

  it('classifies loopback the way the other gates expect', () => {
    for (const h of ['localhost', 'LOCALHOST', 'api.localhost', '127.0.0.1', '127.1.2.3', '[::1]', '::1', '0.0.0.0']) {
      expect(isLoopback(h)).toBe(true);
    }
    for (const h of ['freetsa.org', '172.17.0.1', '10.0.0.1', '1270.0.0.1', 'localhost.evil.com']) {
      expect(isLoopback(h)).toBe(false);
    }
  });

  it(`opens only on ${INTEGRATION_FLAG}=true — the exact value the Postgres gates use`, () => {
    const saved = process.env[INTEGRATION_FLAG];
    try {
      process.env[INTEGRATION_FLAG] = '1';
      expect(liveNetworkAllowed()).toBe(false);
      process.env[INTEGRATION_FLAG] = 'true';
      expect(liveNetworkAllowed()).toBe(true);
    } finally {
      if (saved === undefined) delete process.env[INTEGRATION_FLAG];
      else process.env[INTEGRATION_FLAG] = saved;
    }
  });

  // Last on purpose: this is the one test that INSTALLS, and on a tree where
  // jest.config.js does not wire the setup file it would otherwise hand every
  // test after it a guard the rest of the suite does not have.
  it('installs idempotently — a second install returns the guard already in place', () => {
    const before = globalThis.fetch;
    expect(installNoLiveNetworkGuard()).toBe(before);
    expect(globalThis.fetch).toBe(before);
  });
});
