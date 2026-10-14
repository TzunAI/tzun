/**
 * Suite-wide guard against live network calls from unit tests.
 *
 * Why this exists. `mode: 'local'` obtains an RFC 3161 timestamp for every
 * record and refuses `require: []` (src/sdk/mode-resolver.ts), so every
 * capture() under it is a live round trip to https://freetsa.org/tsr. A failed
 * round trip comes back as `{ stored: false, failure: attestation_failure }`
 * with nothing on the console, so a unit test that reaches the TSA flakes
 * whenever the TSA hiccups, and the log says only "Expected: true, Received:
 * false". Without a guard, nothing stops a new test from reaching the network
 * by accident; a test that needs a live host is gated on RUN_INTEGRATION_TESTS.
 *
 * What it does. `installNoLiveNetworkGuard()` replaces `globalThis.fetch`
 * with a wrapper that lets loopback hosts through, lets everything through
 * when RUN_INTEGRATION_TESTS=true, and otherwise records the call and throws.
 * The RFC3161Client captures `globalThis.fetch` at construction, so a client
 * built inside a test gets the guard unless the test installed its own stub
 * first — which is exactly what the attestation tests do
 * (tests/ts/helpers/mock-tsa.ts).
 *
 * Recording matters as much as throwing. The SDK's attestation path CATCHES
 * the error (src/attestation/orchestrator.ts) and turns it into a failure
 * record, so a throw alone would be swallowed and the test would fail — or
 * pass — for an unrelated reason. tests/ts/setup/no-live-network.ts drains the
 * record in an `afterEach` and fails the test by name, quoting the URL.
 */

export interface Refusal {
  url: string;
  /** Name of the test running when the call was refused, when known. */
  test: string | undefined;
  stack: string | undefined;
}

export const INTEGRATION_FLAG = 'RUN_INTEGRATION_TESTS';
export const REFUSED_ERROR_NAME = 'LiveNetworkRefused';

const GUARD_MARK = Symbol.for('tzun.tests.noLiveNetworkGuard');
const refusals: Refusal[] = [];

/** Live hosts are allowed only by the exact value the other gates use. */
export function liveNetworkAllowed(): boolean {
  return process.env[INTEGRATION_FLAG] === 'true';
}

export function isLoopback(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return (
    h === 'localhost' ||
    h.endsWith('.localhost') ||
    h === '::1' ||
    h === '0.0.0.0' ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)
  );
}

function urlOf(input: unknown): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  if (input && typeof (input as { url?: unknown }).url === 'string') {
    return (input as { url: string }).url;
  }
  return String(input);
}

export function refusalMessage(url: string): string {
  return (
    `${REFUSED_ERROR_NAME}: refused fetch(${JSON.stringify(url)}) — unit tests must not ` +
    `reach a non-loopback host. Stub fetch (tests/ts/helpers/mock-tsa.ts) ` +
    `or capture in mode: 'dev'; set ${INTEGRATION_FLAG}=true to run against live services.`
  );
}

/** True when `globalThis.fetch` is the guard (jest.config.js wires it in). */
export function isGuardInstalled(): boolean {
  return Boolean((globalThis.fetch as unknown as Record<symbol, unknown>)[GUARD_MARK]);
}

/** Take (and clear) every refusal recorded since the last drain. */
export function drainRefusals(): Refusal[] {
  return refusals.splice(0);
}

/**
 * Install the guard on `globalThis.fetch`. Idempotent: installing over an
 * already-guarded fetch is a no-op, so a test file may import this module
 * without stacking wrappers.
 */
export function installNoLiveNetworkGuard(): typeof fetch {
  const real = globalThis.fetch;
  if ((real as unknown as Record<symbol, unknown>)[GUARD_MARK]) return real;

  const guarded = async function guardedFetch(
    input: Parameters<typeof fetch>[0],
    init?: Parameters<typeof fetch>[1],
  ): Promise<Response> {
    const url = urlOf(input);
    let hostname = '';
    try {
      hostname = new URL(url).hostname;
    } catch {
      /* unparsable → treated as non-loopback below */
    }
    if ((hostname && isLoopback(hostname)) || liveNetworkAllowed()) {
      return real(input, init);
    }
    const err = new Error(refusalMessage(url));
    err.name = REFUSED_ERROR_NAME;
    const state =
      typeof expect !== 'undefined' && typeof expect.getState === 'function'
        ? expect.getState()
        : undefined;
    refusals.push({ url, test: state?.currentTestName, stack: err.stack });
    throw err;
  } as unknown as typeof fetch;

  (guarded as unknown as Record<symbol, unknown>)[GUARD_MARK] = true;
  globalThis.fetch = guarded;
  return guarded;
}
