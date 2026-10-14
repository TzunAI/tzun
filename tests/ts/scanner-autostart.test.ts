/**
 * A scanner configured with a schedule runs on that schedule.
 *
 * `Tzun.init()` builds the ScheduledScanner from `monitoring.scanner`. A config
 * that names a schedule — `mode: 'interval'` with `intervalMs > 0`, or
 * `mode: 'continuous'` — starts the loop at the end of init. `intervalMs: 0`
 * means no schedule: the caller drives passes with `tzun.runScan()`, which
 * stays public because it is the right model for serverless and cron, where an
 * in-process timer does not survive between invocations. `autoStart: false`
 * keeps a scheduled config manual, for deployments where one designated worker
 * scans a store that many instances share.
 *
 * Four properties the loop has to keep, each pinned below:
 *   - its sleep timer never holds the process open;
 *   - `close()` stops it and waits for a pass already in flight, so the store
 *     is not closed underneath it;
 *   - a manual `runScan()` never overlaps a background pass;
 *   - one failing pass does not end scheduled scanning.
 */
import { Tzun } from '../../src/sdk/index';
import type { ScanSummary, ScannerConfig } from '@tzun/engine';

const base = { batchSize: 100, workers: 2, verifyAttestation: false } as const;

async function initWith(scanner: Partial<ScannerConfig> & { autoStart?: boolean }): Promise<Tzun> {
  return Tzun.init({
    verifyReads: false,
    monitoring: { enabled: true, scanner: { ...base, mode: 'interval', ...scanner } as ScannerConfig },
  });
}

/** Resolves with the first `n` scan.completed summaries, or rejects after `ms`. */
function passes(tzun: Tzun, n: number, ms = 3000): Promise<ScanSummary[]> {
  return new Promise((resolve, reject) => {
    const seen: ScanSummary[] = [];
    const timer = setTimeout(() => reject(new Error(`only ${seen.length}/${n} passes in ${ms}ms`)), ms);
    tzun.on('scan.completed', (s) => {
      seen.push(s);
      if (seen.length === n) {
        clearTimeout(timer);
        resolve(seen);
      }
    });
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('a scheduled scanner starts itself', () => {
  it('runs a pass on its own when configured with an interval', async () => {
    const tzun = await initWith({ intervalMs: 50 });
    try {
      await expect(passes(tzun, 1)).resolves.toHaveLength(1);
    } finally {
      await tzun.close();
    }
  });

  it('keeps running on the interval, not just once', async () => {
    const tzun = await initWith({ intervalMs: 20 });
    try {
      await expect(passes(tzun, 3)).resolves.toHaveLength(3);
    } finally {
      await tzun.close();
    }
  });

  it('runs continuous mode as passes back to back, not a single pass', async () => {
    const tzun = await initWith({ mode: 'continuous', intervalMs: undefined });
    try {
      await expect(passes(tzun, 3)).resolves.toHaveLength(3);
    } finally {
      await tzun.close();
    }
  });
});

describe('a scanner without a schedule stays manual', () => {
  it('does not start itself when intervalMs is 0 — runScan() drives it', async () => {
    const tzun = await initWith({ intervalMs: 0 });
    let completed = 0;
    tzun.on('scan.completed', () => { completed++; });
    try {
      await sleep(150);
      expect(completed).toBe(0);
      await tzun.runScan();
      expect(completed).toBe(1);
    } finally {
      await tzun.close();
    }
  });

  it('does not start itself when autoStart is false, even with an interval', async () => {
    const tzun = await initWith({ intervalMs: 20, autoStart: false });
    let completed = 0;
    tzun.on('scan.completed', () => { completed++; });
    try {
      await sleep(150);
      expect(completed).toBe(0);
    } finally {
      await tzun.close();
    }
  });
});

describe('the loop is safe to leave running', () => {
  it('never holds the process open: its sleep timer is unref\'d', async () => {
    const created: NodeJS.Timeout[] = [];
    const real = global.setTimeout;
    const spy = jest.spyOn(global, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
      const t = real(fn, ms);
      created.push(t);
      return t;
    }) as typeof setTimeout);
    const tzun = await initWith({ intervalMs: 60_000 });
    try {
      await passes(tzun, 1);
      await sleep(10);
      const sleepTimers = created.filter((t) => (t as unknown as { _idleTimeout: number })._idleTimeout === 60_000);
      expect(sleepTimers.length).toBeGreaterThan(0);
      for (const t of sleepTimers) expect(t.hasRef()).toBe(false);
    } finally {
      spy.mockRestore();
      await tzun.close();
    }
  });

  it('close() stops the loop: no pass completes after close() resolves', async () => {
    const tzun = await initWith({ intervalMs: 10 });
    await passes(tzun, 1);
    let after = 0;
    await tzun.close();
    tzun.on('scan.completed', () => { after++; });
    await sleep(100);
    expect(after).toBe(0);
  });

  it('close() waits for a pass already in flight before closing the store', async () => {
    const tzun = await initWith({ intervalMs: 10 });
    await passes(tzun, 1);
    const storage = tzun.getStorage();
    const original = storage.getLastSequence.bind(storage);
    let inFlight = false;
    let storeClosedMidPass = false;
    storage.getLastSequence = async () => {
      inFlight = true;
      await sleep(80);
      inFlight = false;
      return original();
    };
    const originalClose = storage.close?.bind(storage);
    storage.close = async () => {
      if (inFlight) storeClosedMidPass = true;
      await originalClose?.();
    };
    await sleep(30); // let the next scheduled pass enter getLastSequence
    await tzun.close();
    expect(storeClosedMidPass).toBe(false);
  });

  it('a manual runScan() never overlaps a background pass', async () => {
    const tzun = await initWith({ intervalMs: 5 });
    await passes(tzun, 1);
    const storage = tzun.getStorage();
    const original = storage.getLastSequence.bind(storage);
    let concurrent = 0;
    let maxConcurrent = 0;
    storage.getLastSequence = async () => {
      concurrent++;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await sleep(25);
      concurrent--;
      return original();
    };
    try {
      await Promise.all([tzun.runScan(), tzun.runScan(), sleep(120)]);
      expect(maxConcurrent).toBe(1);
    } finally {
      await tzun.close();
    }
  });

  it('keeps scanning after a pass fails', async () => {
    const tzun = await initWith({ intervalMs: 10 });
    const storage = tzun.getStorage();
    const original = storage.getLastSequence.bind(storage);
    let calls = 0;
    storage.getLastSequence = async () => {
      calls++;
      if (calls === 1) throw new Error('transient storage failure');
      return original();
    };
    try {
      await expect(passes(tzun, 2)).resolves.toHaveLength(2);
    } finally {
      await tzun.close();
    }
  });
});
