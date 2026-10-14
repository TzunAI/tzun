/**
 * A capture taken while the TSA circuit breakers are open is
 * stored 'pending', and the retry timestamps it once the breakers let a
 * request through again.
 *
 * The breaker exists so an outage does not hold every capture for the full
 * timeout: after `failureThreshold` consecutive failures an authority is
 * skipped without a request until `coolDownMs` has passed. A capture made
 * then gets no token from any authority, and with the timestamp deferrable
 * (the production default) the record is stored 'pending' — the status
 * `retryPendingAttestations()` lists. The token the retry obtains is a
 * genuine RFC 3161 token, issued by an offline TSA over the stored digest,
 * and the real verifier accepts it in trust-chain mode.
 *
 * Runs on the memory, SQLite and (when the Postgres legs run,
 * tests/ts/helpers/postgres-test-db.ts) Postgres adapters: the retry reads and
 * writes through the StorageAdapter contract alone.
 */
import {
  Tzun,
  DEFAULT_TIMESTAMP_AUTHORITIES,
  verifyAttestation,
} from '../../src/sdk/index';
import type { CaptureInput, TzunConfig } from '@tzun/engine';
import { makeSigningTsa, type SigningTsa } from './rfc3161-fixture';
import { makeResponse, parseTimestampQuery } from './helpers/mock-tsa';
import { PG_TESTS_ENABLED, pgSuiteSchema } from './helpers/postgres-test-db';

const [PRIMARY, FALLBACK] = DEFAULT_TIMESTAMP_AUTHORITIES;
/** RFC3161Client's per-authority breaker defaults. */
const FAILURE_THRESHOLD = 3;
const COOL_DOWN_MS = 60_000;

const decision = (i: number): CaptureInput => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', case: i },
  action: 'approved',
  reason: `Meets all criteria (${i})`,
});

const pgSchema = pgSuiteSchema('breaker_pending_retry');

const stores: Array<[string, TzunConfig]> = [
  // Production modes refuse in-memory storage, so the memory leg names the
  // production default explicitly in dev mode.
  ['memory (dev, deferrable timestamp)', { mode: 'dev', attestation: { deferrable: ['timestamp'] } }],
  ['SQLite (local, default config)', { mode: 'local', dbPath: ':memory:' }],
  ...(PG_TESTS_ENABLED
    ? ([['Postgres (local, default config)', { mode: 'local', dbUrl: pgSchema.url }]] as Array<
        [string, TzunConfig]
      >)
    : []),
];

describe.each(stores)('breaker open → pending → breaker closes → retry attests: %s', (_label, config) => {
  let tsa: SigningTsa;
  let savedFetch: typeof globalThis.fetch;
  let tsaUp: boolean;
  let calls: string[];
  let clockOffsetMs: number;
  let tzun: Tzun;

  beforeAll(async () => {
    tsa = await makeSigningTsa();
  });

  beforeEach(async () => {
    savedFetch = globalThis.fetch;
    tsaUp = false;
    calls = [];
    clockOffsetMs = 0;

    const realNow = Date.now.bind(Date);
    jest.spyOn(Date, 'now').mockImplementation(() => realNow() + clockOffsetMs);

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = String(input);
      calls.push(url);
      if (!tsaUp) throw new Error(`connect ECONNREFUSED (${url})`);
      const { digest, nonce } = parseTimestampQuery(
        Buffer.from(init!.body as unknown as Uint8Array),
      );
      return makeResponse(await tsa.issue(digest, nonce), 'application/timestamp-reply');
    }) as unknown as typeof fetch;

    // Built after the stub is installed: the RFC3161Client keeps the fetch it
    // was constructed with.
    tzun = await Tzun.init({ ...config, onLog: () => {} });
  });

  afterEach(async () => {
    await tzun.close();
    globalThis.fetch = savedFetch;
    jest.restoreAllMocks();
  });

  it('stores pending while the breakers are open, and the retry obtains a token the verifier accepts', async () => {
    // The outage: every authority refuses until each breaker opens.
    const captured = [];
    for (let i = 0; i < FAILURE_THRESHOLD; i++) {
      const result = await tzun.capture(decision(i));
      expect(result.stored).toBe(true);
      expect(result.envelope.attestationStatus).toBe('pending');
      captured.push(result.envelope);
    }
    expect(calls.filter((u) => u === PRIMARY)).toHaveLength(FAILURE_THRESHOLD);
    expect(calls.filter((u) => u === FALLBACK)).toHaveLength(FAILURE_THRESHOLD);

    // Breakers open: no authority is asked, and the capture is still stored.
    const callsBefore = calls.length;
    const whileOpen = await tzun.capture(decision(FAILURE_THRESHOLD));
    expect(calls.length).toBe(callsBefore);
    expect(whileOpen.stored).toBe(true);
    expect(whileOpen.failure).toBeUndefined();
    expect(whileOpen.envelope.attestationStatus).toBe('pending');
    expect(whileOpen.envelope.nonRepudiation.rfc3161Token).toBeUndefined();
    captured.push(whileOpen.envelope);
    const ids = captured.map((e) => e.payload.evidenceId);

    // The authorities are back, but the breakers are still cooling down: the
    // retry asks nobody and writes nothing.
    tsaUp = true;
    const early = await tzun.retryPendingAttestations();
    expect(calls.length).toBe(callsBefore);
    for (const id of ids) {
      const d = early.details.find((x) => x.evidenceId === id)!;
      expect(d.success).toBe(false);
      expect(d.stillMissing).toEqual(['timestamp']);
      expect((await tzun.getStorage().retrieve(id))!.attestationStatus).toBe('pending');
    }

    // The breakers close: the cool-down has passed, and the probe succeeds.
    clockOffsetMs = COOL_DOWN_MS + 1;
    const retry = await tzun.retryPendingAttestations();
    for (const id of ids) {
      expect(retry.details.find((x) => x.evidenceId === id)).toEqual({ evidenceId: id, success: true });
    }
    const pendingIds = (await tzun.getStorage().listByAttestationStatus('pending')).map(
      (e) => e.payload.evidenceId,
    );
    expect(pendingIds.filter((id) => ids.includes(id))).toEqual([]);

    for (const original of captured) {
      const stored = (await tzun.getStorage().retrieve(original.payload.evidenceId))!;
      // The record itself is untouched: same payload, same digest.
      expect(stored.payload).toEqual(original.payload);
      expect(stored.integrity).toEqual(original.integrity);
      expect(stored.attestationStatus).toBe('partial');
      expect(stored.nonRepudiation.rfc3161Token).toBeDefined();

      // The real verifier, trust-chain mode: parse, imprint, CMS signature,
      // and a chain to the supplied root.
      const verdict = await verifyAttestation(
        stored.nonRepudiation,
        stored.integrity.canonicalDigest,
        undefined,
        {
          timestampVerification: 'trust-chain',
          trustAnchorsPem: [tsa.caPem],
          capturedAt: stored.payload.capturedAt,
        },
      );
      expect(verdict.timestampReason).toBeUndefined();
      expect(verdict.timestampValid).toBe(true);
      expect(verdict.capturedAtValid).toBe(true);

      // And the record still verifies as captured.
      expect((await tzun.verify(original.payload.evidenceId)).verified).toBe(true);
    }
  });
});
