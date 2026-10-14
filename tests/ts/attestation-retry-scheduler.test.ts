/**
 * The pending-attestation retry schedule, unit-level.
 *
 * The scheduler owns when a retry pass runs, never what it does: the pass is
 * a function it is given. What it guarantees:
 * - a positive `intervalMs` is a schedule; 0 or absent is manual passes only;
 * - the first scheduled pass runs one interval after start(), and the wait
 *   timer never holds the process open;
 * - passes never overlap, whether scheduled or called by hand;
 * - a pass that throws is reported and the schedule carries on;
 * - while passes request attestation for records and obtain nothing (every
 *   authority failing), the wait doubles up to `maxBackoffMs`, and progress
 *   resets it;
 * - stop() ends the schedule and resolves only once a pass in flight is done.
 */
import {
  AttestationRetryScheduler,
  DEFAULT_ATTESTATION_RETRY_BATCH_SIZE,
  DEFAULT_ATTESTATION_RETRY_MAX_BACKOFF_MS,
} from '../../src/sdk/attestation-retry-scheduler';

interface Counts {
  attempted: number;
  succeeded: number;
  failed: number;
}
type Outcome = { result: Counts; requested: number; progressed: boolean };

const nothingPending: Outcome = {
  result: { attempted: 0, succeeded: 0, failed: 0 },
  requested: 0,
  progressed: false,
};
const stalled: Outcome = {
  result: { attempted: 2, succeeded: 0, failed: 2 },
  requested: 2,
  progressed: false,
};
const progressed: Outcome = {
  result: { attempted: 2, succeeded: 2, failed: 0 },
  requested: 2,
  progressed: true,
};
/** Pending only for a component this writer does not obtain: nothing requested. */
const nothingRequestable: Outcome = {
  result: { attempted: 3, succeeded: 0, failed: 3 },
  requested: 0,
  progressed: false,
};

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('AttestationRetryScheduler', () => {
  describe('schedule or manual', () => {
    it.each([
      ['absent', undefined],
      ['0', 0],
    ])('intervalMs %s: no schedule, start() runs nothing', async (_label, intervalMs) => {
      jest.useFakeTimers();
      try {
        const pass = jest.fn(async () => nothingPending);
        const s = new AttestationRetryScheduler(pass, { intervalMs });
        expect(s.isScheduled()).toBe(false);
        await s.start();
        await jest.advanceTimersByTimeAsync(10 * 60_000);
        expect(pass).not.toHaveBeenCalled();
        expect(s.getState().running).toBe(false);
        await s.stop();
      } finally {
        jest.useRealTimers();
      }
    });

    it('a manual pass runs with no schedule, with the limit it is given', async () => {
      const pass = jest.fn(async () => progressed);
      const s = new AttestationRetryScheduler(pass, {});
      await expect(s.runPass(7)).resolves.toEqual(progressed.result);
      expect(pass).toHaveBeenCalledWith(7);
      await expect(s.runPass()).resolves.toEqual(progressed.result);
      expect(pass).toHaveBeenLastCalledWith(undefined);
    });

    it('refuses an interval, batch size or backoff ceiling that is not a usable number', () => {
      const pass = async () => nothingPending;
      expect(() => new AttestationRetryScheduler(pass, { intervalMs: -1 })).toThrow(RangeError);
      expect(() => new AttestationRetryScheduler(pass, { intervalMs: 1.5 })).toThrow(RangeError);
      expect(() => new AttestationRetryScheduler(pass, { intervalMs: NaN })).toThrow(RangeError);
      expect(() => new AttestationRetryScheduler(pass, { batchSize: 0 })).toThrow(RangeError);
      expect(() => new AttestationRetryScheduler(pass, { batchSize: 2.5 })).toThrow(RangeError);
      expect(
        () => new AttestationRetryScheduler(pass, { intervalMs: 1000, maxBackoffMs: 999 }),
      ).toThrow(RangeError);
    });
  });

  describe('on a schedule', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    it('runs the first pass one interval after start(), then every interval, with the batch size as limit', async () => {
      const pass = jest.fn(async () => nothingPending);
      const s = new AttestationRetryScheduler(pass, { intervalMs: 1000 });
      void s.start();

      await jest.advanceTimersByTimeAsync(999);
      expect(pass).not.toHaveBeenCalled();
      await jest.advanceTimersByTimeAsync(1);
      expect(pass).toHaveBeenCalledTimes(1);
      expect(pass).toHaveBeenCalledWith(DEFAULT_ATTESTATION_RETRY_BATCH_SIZE);
      await jest.advanceTimersByTimeAsync(1000);
      expect(pass).toHaveBeenCalledTimes(2);

      await s.stop();
      await jest.advanceTimersByTimeAsync(10_000);
      expect(pass).toHaveBeenCalledTimes(2);
      expect(s.getState().running).toBe(false);
    });

    it('start() twice runs one schedule', async () => {
      const pass = jest.fn(async () => nothingPending);
      const s = new AttestationRetryScheduler(pass, { intervalMs: 1000 });
      void s.start();
      void s.start();
      await jest.advanceTimersByTimeAsync(1000);
      expect(pass).toHaveBeenCalledTimes(1);
      await s.stop();
    });

    it('a pass that throws is reported, and the schedule carries on', async () => {
      const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
      const pass = jest
        .fn<Promise<Outcome>, [number | undefined]>()
        .mockRejectedValueOnce(new Error('store unavailable'))
        .mockResolvedValue(nothingPending);
      const s = new AttestationRetryScheduler(pass, {
        intervalMs: 1000,
        onLog: (event, fields) => events.push({ event, fields }),
      });
      void s.start();

      await jest.advanceTimersByTimeAsync(1000);
      expect(pass).toHaveBeenCalledTimes(1);
      const failed = events.filter((e) => e.event === 'attestation_retry_pass_failed');
      expect(failed).toHaveLength(1);
      expect(failed[0].fields).toMatchObject({ errorName: 'Error', error: 'store unavailable' });
      expect(s.getState().lastError).toBe('store unavailable');

      // Backed off once (2000), then back on the interval.
      await jest.advanceTimersByTimeAsync(2000);
      expect(pass).toHaveBeenCalledTimes(2);
      expect(s.getState().lastError).toBeNull();
      expect(s.getState().running).toBe(true);
      await s.stop();
    });

    it('a sink that throws does not end the schedule', async () => {
      const pass = jest.fn(async () => progressed);
      const s = new AttestationRetryScheduler(pass, {
        intervalMs: 1000,
        onLog: () => {
          throw new Error('sink down');
        },
      });
      void s.start();
      await jest.advanceTimersByTimeAsync(3000);
      expect(pass).toHaveBeenCalledTimes(3);
      await s.stop();
    });

    it('backs off while passes obtain nothing, up to the ceiling, and resets on progress', async () => {
      const outcomes = [stalled, stalled, stalled, stalled, progressed, nothingPending];
      const at: number[] = [];
      const start = Date.now();
      const pass = jest.fn(async () => {
        at.push(Date.now() - start);
        return outcomes.shift() ?? nothingPending;
      });
      const s = new AttestationRetryScheduler(pass, { intervalMs: 1000, maxBackoffMs: 5000 });
      void s.start();

      await jest.advanceTimersByTimeAsync(1000 + 2000 + 4000 + 5000 + 5000 + 1000);
      // stalled → 2000, stalled → 4000, stalled → 8000 capped at 5000,
      // stalled → 5000, progress → 1000.
      expect(at).toEqual([1000, 3000, 7000, 12000, 17000, 18000]);
      expect(s.getState().nextDelayMs).toBe(1000);
      expect(s.getState().stalledPasses).toBe(0);
      await s.stop();
    });

    it.each([
      ['nothing pending', nothingPending],
      ['nothing this writer can request', nothingRequestable],
    ])('a pass with %s is not a stalled pass', async (_label, outcome) => {
      const pass = jest.fn(async () => outcome);
      const s = new AttestationRetryScheduler(pass, { intervalMs: 1000 });
      void s.start();
      await jest.advanceTimersByTimeAsync(3000);
      expect(pass).toHaveBeenCalledTimes(3);
      expect(s.getState().stalledPasses).toBe(0);
      await s.stop();
    });

    it('defaults the backoff ceiling to 15 minutes, or the interval when that is longer', () => {
      const pass = async () => nothingPending;
      expect(new AttestationRetryScheduler(pass, { intervalMs: 1000 }).getState().maxBackoffMs).toBe(
        DEFAULT_ATTESTATION_RETRY_MAX_BACKOFF_MS,
      );
      expect(
        new AttestationRetryScheduler(pass, { intervalMs: 3_600_000 }).getState().maxBackoffMs,
      ).toBe(3_600_000);
    });

    it('logs a pass that requested attestation, with what it did and the next wait', async () => {
      const events: Array<{ event: string; fields: Record<string, unknown> }> = [];
      const outcomes = [nothingPending, nothingRequestable, stalled];
      const pass = jest.fn(async () => outcomes.shift() ?? nothingPending);
      const s = new AttestationRetryScheduler(pass, {
        intervalMs: 1000,
        onLog: (event, fields) => events.push({ event, fields }),
      });
      void s.start();
      await jest.advanceTimersByTimeAsync(3000);
      expect(events.map((e) => e.event)).toEqual(['attestation_retry_pass']);
      expect(events[0].fields).toEqual({ attempted: 2, succeeded: 0, failed: 2, nextDelayMs: 2000 });
      await s.stop();
    });
  });

  describe('passes never overlap', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    it('a manual pass waits for the scheduled pass in flight', async () => {
      let running = 0;
      let maxRunning = 0;
      const gates = [deferred<Outcome>(), deferred<Outcome>()];
      let call = 0;
      const pass = jest.fn(async () => {
        running++;
        maxRunning = Math.max(maxRunning, running);
        try {
          return await gates[call++].promise;
        } finally {
          running--;
        }
      });
      const s = new AttestationRetryScheduler(pass, { intervalMs: 1000 });
      void s.start();
      await jest.advanceTimersByTimeAsync(1000);
      expect(pass).toHaveBeenCalledTimes(1);

      const manual = s.runPass();
      await jest.advanceTimersByTimeAsync(0);
      expect(pass).toHaveBeenCalledTimes(1);

      gates[0].resolve(nothingPending);
      await jest.advanceTimersByTimeAsync(0);
      expect(pass).toHaveBeenCalledTimes(2);
      gates[1].resolve(progressed);
      await expect(manual).resolves.toEqual(progressed.result);
      expect(maxRunning).toBe(1);
      await s.stop();
    });

    it('a failed manual pass does not block the next one', async () => {
      const pass = jest
        .fn<Promise<Outcome>, [number | undefined]>()
        .mockRejectedValueOnce(new Error('boom'))
        .mockResolvedValue(nothingPending);
      const s = new AttestationRetryScheduler(pass, {});
      await expect(s.runPass()).rejects.toThrow('boom');
      await expect(s.runPass()).resolves.toEqual(nothingPending.result);
    });
  });

  describe('stop()', () => {
    it('ends the schedule and resolves only after the pass in flight has finished', async () => {
      jest.useFakeTimers();
      try {
        const gate = deferred<Outcome>();
        const pass = jest.fn(() => gate.promise);
        const s = new AttestationRetryScheduler(pass, { intervalMs: 1000 });
        void s.start();
        await jest.advanceTimersByTimeAsync(1000);
        expect(pass).toHaveBeenCalledTimes(1);

        let stopped = false;
        const stopping = s.stop().then(() => {
          stopped = true;
        });
        await jest.advanceTimersByTimeAsync(0);
        expect(stopped).toBe(false);

        gate.resolve(nothingPending);
        await stopping;
        expect(stopped).toBe(true);
        await jest.advanceTimersByTimeAsync(10_000);
        expect(pass).toHaveBeenCalledTimes(1);
      } finally {
        jest.useRealTimers();
      }
    });

    it('waits for a manual pass in flight too', async () => {
      const gate = deferred<Outcome>();
      const s = new AttestationRetryScheduler(() => gate.promise, {});
      const manual = s.runPass();
      let stopped = false;
      const stopping = s.stop().then(() => {
        stopped = true;
      });
      await new Promise((r) => setImmediate(r));
      expect(stopped).toBe(false);
      gate.resolve(nothingPending);
      await manual;
      await stopping;
      expect(stopped).toBe(true);
    });

    it('cuts the wait short: a stop between passes resolves at once', async () => {
      const pass = jest.fn(async () => nothingPending);
      const s = new AttestationRetryScheduler(pass, { intervalMs: 3_600_000 });
      void s.start();
      const t0 = Date.now();
      await s.stop();
      expect(Date.now() - t0).toBeLessThan(1000);
      expect(pass).not.toHaveBeenCalled();
    });
  });

  it('never holds the process open: the wait timer is unref’d', async () => {
    const timers: NodeJS.Timeout[] = [];
    const real = global.setTimeout;
    const spy = jest.spyOn(global, 'setTimeout').mockImplementation(((
      fn: (...a: unknown[]) => void,
      ms?: number,
    ) => {
      const t = real(fn, ms);
      timers.push(t);
      return t;
    }) as typeof setTimeout);
    try {
      const s = new AttestationRetryScheduler(async () => nothingPending, { intervalMs: 60_000 });
      void s.start();
      await new Promise((r) => setImmediate(r));
      const wait = timers.find((t) => (t as unknown as { _idleTimeout: number })._idleTimeout === 60_000);
      expect(wait).toBeDefined();
      expect(wait!.hasRef()).toBe(false);
      spy.mockRestore();
      await s.stop();
    } finally {
      spy.mockRestore();
    }
  });
});
