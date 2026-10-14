/**
 * The pending-attestation retry runs on its own in a production mode
 *, through Tzun.init() and Tzun.close().
 *
 * - A production mode on a local store with a deferrable component starts
 *   the schedule at init (default: every 60 s, 100 records a pass).
 * - Dev mode, `intervalMs: 0`, `autoStart: false`, a config with nothing
 *   deferrable and the cloud transport do not.
 * - A record a TSA outage left 'pending' is timestamped by the schedule, with
 *   no manual call.
 * - A manual retryPendingAttestations() never overlaps a scheduled pass.
 * - close() stops the schedule and waits for the pass in flight before the
 *   store is closed.
 * - A pass attests at most `batchSize` records.
 */
import {
  Tzun,
  DEFAULT_ATTESTATION_RETRY_INTERVAL_MS,
  DEFAULT_ATTESTATION_RETRY_BATCH_SIZE,
} from '../../src/sdk/index';
import type { CaptureInput, TzunConfig } from '@tzun/engine';
import { mockTsaFetch } from './helpers/mock-tsa';

const decision = (i = 0): CaptureInput => ({
  decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null },
  aiOutput: { recommendation: 'approve', case: i },
  action: 'approved',
  reason: `Meets all criteria (${i})`,
});

async function until(check: () => Promise<boolean>, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error('condition not reached before the deadline');
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe('the pending-attestation retry schedule, through Tzun', () => {
  let savedFetch: typeof globalThis.fetch;
  let tsaUp: boolean;
  let tsaCalls: number;
  let hold: Promise<void> | null;
  let tzun: Tzun | undefined;
  let clockOffsetMs: number;

  /**
   * Five captures during an outage open both authorities' breakers (three
   * consecutive failures each). Moving the clock past their 60 s cool-down
   * lets the next request probe, as it would after a real outage.
   */
  const coolBreakers = () => {
    clockOffsetMs += 60_001;
  };

  beforeEach(() => {
    savedFetch = globalThis.fetch;
    tsaUp = true;
    tsaCalls = 0;
    hold = null;
    tzun = undefined;
    clockOffsetMs = 0;
    const realNow = Date.now.bind(Date);
    jest.spyOn(Date, 'now').mockImplementation(() => realNow() + clockOffsetMs);
    const tsa = mockTsaFetch();
    globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
      tsaCalls++;
      if (hold) await hold;
      if (!tsaUp) throw new Error('connect ECONNREFUSED');
      return tsa(...args);
    }) as unknown as typeof fetch;
  });

  afterEach(async () => {
    await tzun?.close();
    globalThis.fetch = savedFetch;
    jest.restoreAllMocks();
  });

  const init = async (config: TzunConfig) => {
    tzun = await Tzun.init({ onLog: () => {}, ...config });
    return tzun;
  };

  describe('when it starts', () => {
    it.each(['local', 'self-hosted', 'cloud'] as const)(
      '%s mode on a local store starts it by default',
      async (mode) => {
        const t = await init({ mode, dbPath: ':memory:' });
        expect(t.getAttestationRetryState()).toMatchObject({
          scheduled: true,
          running: true,
          intervalMs: DEFAULT_ATTESTATION_RETRY_INTERVAL_MS,
          batchSize: DEFAULT_ATTESTATION_RETRY_BATCH_SIZE,
        });
        expect(DEFAULT_ATTESTATION_RETRY_INTERVAL_MS).toBe(60_000);
        expect(DEFAULT_ATTESTATION_RETRY_BATCH_SIZE).toBe(100);
      },
    );

    it('dev mode has no schedule unless one is configured', async () => {
      const t = await init({ mode: 'dev', attestation: { deferrable: ['timestamp'] } });
      expect(t.getAttestationRetryState()).toMatchObject({ scheduled: false, running: false });
    });

    it('dev mode with an interval runs it', async () => {
      const t = await init({
        mode: 'dev',
        attestation: { deferrable: ['timestamp'], retry: { intervalMs: 1000 } },
      });
      expect(t.getAttestationRetryState()).toMatchObject({
        scheduled: true,
        running: true,
        intervalMs: 1000,
      });
    });

    it('intervalMs: 0 is manual only', async () => {
      const t = await init({ mode: 'local', dbPath: ':memory:', attestation: { retry: { intervalMs: 0 } } });
      expect(t.getAttestationRetryState()).toMatchObject({ scheduled: false, running: false });
    });

    it('autoStart: false is manual only, even with an interval', async () => {
      const t = await init({
        mode: 'local',
        dbPath: ':memory:',
        attestation: { retry: { autoStart: false, intervalMs: 1000 } },
      });
      expect(t.getAttestationRetryState()).toMatchObject({ scheduled: true, running: false });

      tsaUp = false;
      const pending = await t.capture(decision());
      expect(pending.envelope.attestationStatus).toBe('pending');
      await new Promise((r) => setTimeout(r, 1100));
      expect((await t.getStorage().retrieve(pending.envelope.payload.evidenceId))!.attestationStatus).toBe(
        'pending',
      );

      tsaUp = true;
      const manual = await t.retryPendingAttestations();
      expect(manual.succeeded).toBe(1);
    });

    it('a production config with nothing deferrable has no schedule', async () => {
      const t = await init({ mode: 'local', dbPath: ':memory:', attestation: { require: ['timestamp'] } });
      expect(t.getAttestationRetryState()).toMatchObject({ scheduled: false, running: false });
    });

    it('the cloud transport has no schedule: the platform worker attests cloud records', async () => {
      const t = await init({
        apiKey: 'tk_test',
        apiUrl: 'https://api.example.test',
        _httpFetchFn: (async () => new Response('{}', { status: 200 })) as never,
      });
      expect(t.getAttestationRetryState()).toMatchObject({ scheduled: false, running: false });
    });

    it('the cloud transport refuses a configured schedule: it cannot list pending records', async () => {
      await expect(
        Tzun.init({
          apiKey: 'tk_test',
          apiUrl: 'https://api.example.test',
          attestation: { deferrable: ['timestamp'], retry: { intervalMs: 1000 } },
        }),
      ).rejects.toThrow(/attestation\.retry.*cloud transport/);
    });

    it.each([
      [{ intervalMs: -1 }],
      [{ intervalMs: 1.5 }],
      [{ batchSize: 0 }],
      [{ intervalMs: 1000, maxBackoffMs: 10 }],
    ])('refuses an unusable retry option %j at init', async (retry) => {
      await expect(
        Tzun.init({ mode: 'local', dbPath: ':memory:', attestation: { retry } }),
      ).rejects.toThrow(RangeError);
    });
  });

  it('timestamps a record a TSA outage left pending, with no manual call', async () => {
    const t = await init({
      mode: 'local',
      dbPath: ':memory:',
      attestation: { retry: { intervalMs: 50 } },
    });

    tsaUp = false;
    const result = await t.capture(decision());
    expect(result.stored).toBe(true);
    expect(result.envelope.attestationStatus).toBe('pending');
    const id = result.envelope.payload.evidenceId;

    tsaUp = true;
    await until(async () => (await t.getStorage().retrieve(id))!.attestationStatus !== 'pending');

    const stored = (await t.getStorage().retrieve(id))!;
    expect(stored.attestationStatus).toBe('partial');
    expect(stored.nonRepudiation.rfc3161Token).toBeDefined();
    expect(stored.integrity).toEqual(result.envelope.integrity);
  });

  it('a manual retry waits for the scheduled pass in flight, and finds its work done', async () => {
    const t = await init({
      mode: 'local',
      dbPath: ':memory:',
      attestation: { retry: { intervalMs: 50 } },
    });
    tsaUp = false;
    const result = await t.capture(decision());
    const id = result.envelope.payload.evidenceId;
    tsaUp = true;

    let release!: () => void;
    hold = new Promise<void>((r) => (release = r));
    const callsBefore = tsaCalls;
    await until(async () => tsaCalls > callsBefore); // the scheduled pass is in its TSA request

    const manual = t.retryPendingAttestations();
    await new Promise((r) => setTimeout(r, 100));
    expect(tsaCalls).toBe(callsBefore + 1); // the manual pass has not started

    release();
    hold = null;
    const manualResult = await manual;
    expect(manualResult.attempted).toBe(0);
    expect(tsaCalls).toBe(callsBefore + 1); // one token request for the record, not two
    expect((await t.getStorage().retrieve(id))!.attestationStatus).toBe('partial');
  });

  it('close() stops the schedule and waits for the pass in flight before closing the store', async () => {
    const t = await init({
      mode: 'local',
      dbPath: ':memory:',
      attestation: { retry: { intervalMs: 50 } },
    });
    tsaUp = false;
    const result = await t.capture(decision());
    const id = result.envelope.payload.evidenceId;
    tsaUp = true;

    let release!: () => void;
    hold = new Promise<void>((r) => (release = r));
    const callsBefore = tsaCalls;
    await until(async () => tsaCalls > callsBefore);

    const storage = t.getStorage();
    const closeSpy = jest.spyOn(storage, 'close' as never);
    let closed = false;
    const closing = t.close().then(() => {
      closed = true;
    });
    await new Promise((r) => setTimeout(r, 100));
    expect(closed).toBe(false);
    expect(closeSpy).not.toHaveBeenCalled();

    release();
    hold = null;
    await closing;
    expect(closeSpy).toHaveBeenCalledTimes(1);
    expect(t.getAttestationRetryState().running).toBe(false);
    // The pass finished its write before the store closed.
    expect(t.getAttestationRetryState().lastPass).toEqual({ attempted: 1, succeeded: 1, failed: 0 });
    expect(id).toBeDefined();

    const callsAtClose = tsaCalls;
    await new Promise((r) => setTimeout(r, 200));
    expect(tsaCalls).toBe(callsAtClose);
    tzun = undefined;
  });

  it('a scheduled pass attests at most batchSize records; a manual pass takes a limit', async () => {
    const t = await init({
      mode: 'local',
      dbPath: ':memory:',
      attestation: { retry: { autoStart: false, intervalMs: 1000, batchSize: 2 } },
    });
    tsaUp = false;
    for (let i = 0; i < 5; i++) await t.capture(decision(i));
    tsaUp = true;
    coolBreakers();

    const first = await t.retryPendingAttestations({ limit: 2 });
    expect(first).toMatchObject({ attempted: 2, succeeded: 2, failed: 0 });
    expect(await t.getStorage().listByAttestationStatus('pending')).toHaveLength(3);

    const rest = await t.retryPendingAttestations();
    expect(rest).toMatchObject({ attempted: 3, succeeded: 3 });
    await expect(t.retryPendingAttestations({ limit: 0 })).rejects.toThrow(RangeError);
  });

  it('the scheduled pass uses batchSize as its limit', async () => {
    const t = await init({
      mode: 'local',
      dbPath: ':memory:',
      attestation: { retry: { intervalMs: 50, batchSize: 2 } },
    });
    tsaUp = false;
    for (let i = 0; i < 5; i++) await t.capture(decision(i));
    tsaUp = true;
    coolBreakers();
    await until(async () => t.getAttestationRetryState().lastPass?.succeeded === 2);
    expect(t.getAttestationRetryState().lastPass).toEqual({ attempted: 2, succeeded: 2, failed: 0 });
    await until(async () => (await t.getStorage().listByAttestationStatus('pending')).length === 0);
  });

  it('backs off while every authority is failing', async () => {
    const t = await init({
      mode: 'local',
      dbPath: ':memory:',
      attestation: { retry: { intervalMs: 50 } },
    });
    tsaUp = false;
    await t.capture(decision());
    await until(async () => t.getAttestationRetryState().stalledPasses >= 2);
    const state = t.getAttestationRetryState();
    expect(state.nextDelayMs).toBe(50 * 2 ** state.stalledPasses);
  });
});
