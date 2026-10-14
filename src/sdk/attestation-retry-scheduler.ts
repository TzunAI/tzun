import { sdkLog, type LogSink } from './log';

/**
 * Wait between scheduled pending-attestation retry passes in a production
 * mode on a local store with a deferrable component, unless
 * `attestation.retry.intervalMs` says otherwise.
 *
 * A timestamp obtained by the retry carries the genTime of the retry, not of
 * the capture, so the wait bounds how far a record's timestamp can trail the
 * end of an outage. One minute keeps that gap short while the pass itself,
 * which lists the store's pending records, stays infrequent; it is also the
 * TSA circuit breaker's cool-down, so a pass during an outage finds each
 * breaker ready for one probe.
 */
export const DEFAULT_ATTESTATION_RETRY_INTERVAL_MS = 60_000;

/** Most records a scheduled pass requests attestation for, unless configured. */
export const DEFAULT_ATTESTATION_RETRY_BATCH_SIZE = 100;

/**
 * Ceiling on the backed-off wait while passes obtain nothing, unless
 * configured (or the interval is longer). With the default interval the
 * waits run 2, 4, 8 and then 15 minutes, so an outage that ends is noticed
 * within 15 minutes at worst.
 */
export const DEFAULT_ATTESTATION_RETRY_MAX_BACKOFF_MS = 15 * 60_000;

/** The counts a retry pass reports. */
export interface AttestationRetryCounts {
  attempted: number;
  succeeded: number;
  failed: number;
}

/** What one pass did. */
export interface AttestationRetryPassOutcome<R extends AttestationRetryCounts> {
  result: R;
  /** Records the pass requested an attestation component for. */
  requested: number;
  /** Whether any record gained an artifact. */
  progressed: boolean;
}

export interface AttestationRetrySchedulerOptions {
  /** Wait between scheduled passes. 0 or absent: no schedule, passes run only on request. */
  intervalMs?: number;
  /** The limit a scheduled pass is given. Default {@link DEFAULT_ATTESTATION_RETRY_BATCH_SIZE}. */
  batchSize?: number;
  /**
   * Ceiling on the backed-off wait. Default
   * {@link DEFAULT_ATTESTATION_RETRY_MAX_BACKOFF_MS}, or `intervalMs` when that
   * is longer. Must not be shorter than `intervalMs`.
   */
  maxBackoffMs?: number;
  /** Where scheduled passes are reported. */
  onLog?: LogSink;
}

/**
 * Throw a RangeError unless `intervalMs` is an integer >= 0, `batchSize` an
 * integer >= 1 and `maxBackoffMs` an integer no shorter than `intervalMs`.
 * Absent values take their defaults.
 */
export function validateAttestationRetryOptions(options: AttestationRetrySchedulerOptions): void {
  const intervalMs = options.intervalMs ?? 0;
  const batchSize = options.batchSize ?? DEFAULT_ATTESTATION_RETRY_BATCH_SIZE;
  const maxBackoffMs =
    options.maxBackoffMs ?? Math.max(DEFAULT_ATTESTATION_RETRY_MAX_BACKOFF_MS, intervalMs);
  if (!Number.isSafeInteger(intervalMs) || intervalMs < 0) {
    throw new RangeError(
      `attestation.retry.intervalMs must be an integer >= 0 (got ${String(options.intervalMs)}); ` +
        '0 means no schedule.',
    );
  }
  if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
    throw new RangeError(
      `attestation.retry.batchSize must be an integer >= 1 (got ${String(options.batchSize)}).`,
    );
  }
  if (!Number.isSafeInteger(maxBackoffMs) || maxBackoffMs < intervalMs) {
    throw new RangeError(
      `attestation.retry.maxBackoffMs must be an integer >= intervalMs (${intervalMs}) ` +
        `(got ${String(options.maxBackoffMs)}).`,
    );
  }
}

/** A snapshot of the retry schedule, for `Tzun.getAttestationRetryState()`. */
export interface AttestationRetryState {
  /** Whether passes run on a schedule: a positive `intervalMs`. */
  scheduled: boolean;
  /** Whether the schedule has been started and not stopped. */
  running: boolean;
  intervalMs: number;
  batchSize: number;
  maxBackoffMs: number;
  /** The wait before the next scheduled pass: the interval, or longer while passes stall. */
  nextDelayMs: number;
  /**
   * Consecutive passes that stalled: requested attestation for records and
   * obtained no artifact for any of them, or failed outright.
   */
  stalledPasses: number;
  /** When the last pass, scheduled or manual, finished. */
  lastPassAt: string | null;
  /** The counts of the last pass that finished, or null if none has. */
  lastPass: AttestationRetryCounts | null;
  /** The error the last pass failed with, or null if it did not fail. */
  lastError: string | null;
}

/**
 * Runs pending-attestation retry passes on a schedule and serialises every
 * pass, scheduled or manual, so two never run at once.
 *
 * The scheduler decides when a pass runs, not what it does: the pass is the
 * function it is constructed with, called with the record limit for that
 * pass. With a positive `intervalMs`, `start()` runs a pass every interval,
 * the first one interval after the start. The wait is an unref'd timer, so
 * the schedule never holds the process open. A pass that throws is reported
 * on the log sink and the schedule carries on. While passes stall — they
 * requested attestation for records and obtained nothing, which is what every
 * authority failing looks like, or they threw — the wait doubles after each one, up to
 * `maxBackoffMs`; the first pass that obtains something, or finds nothing to
 * do, puts it back to `intervalMs`. `stop()` ends the schedule and resolves
 * once any pass in flight has finished.
 */
export class AttestationRetryScheduler<R extends AttestationRetryCounts> {
  private readonly intervalMs: number;
  private readonly batchSize: number;
  private readonly maxBackoffMs: number;
  private readonly onLog: LogSink | undefined;
  /** Serialises passes. Never rejects. */
  private passChain: Promise<unknown> = Promise.resolve();
  /** The running schedule, if `start()` has been called and not stopped. */
  private loop: Promise<void> | null = null;
  private stopRequested = false;
  private sleepTimer: ReturnType<typeof setTimeout> | null = null;
  private wake: (() => void) | null = null;
  private stalledPasses = 0;
  private lastPassAt: string | null = null;
  private lastPass: AttestationRetryCounts | null = null;
  private lastError: string | null = null;
  private lastRequested = 0;

  constructor(
    private readonly pass: (limit: number | undefined) => Promise<AttestationRetryPassOutcome<R>>,
    options: AttestationRetrySchedulerOptions = {},
  ) {
    this.intervalMs = options.intervalMs ?? 0;
    this.batchSize = options.batchSize ?? DEFAULT_ATTESTATION_RETRY_BATCH_SIZE;
    this.maxBackoffMs =
      options.maxBackoffMs ?? Math.max(DEFAULT_ATTESTATION_RETRY_MAX_BACKOFF_MS, this.intervalMs);
    this.onLog = options.onLog;
    validateAttestationRetryOptions(options);
  }

  /** Whether passes run on a schedule: a positive `intervalMs`. */
  isScheduled(): boolean {
    return this.intervalMs > 0;
  }

  /**
   * Run one pass, after every pass already running or queued. `limit` is
   * handed to the pass as is. The pass counts toward the schedule's backoff
   * like a scheduled one.
   */
  runPass(limit?: number): Promise<R> {
    const run = this.passChain.then(() => this.passAndRecord(limit));
    this.passChain = run.catch(() => undefined);
    return run;
  }

  /**
   * Start the schedule, or return the one already running. Without a
   * schedule (`intervalMs` 0) this runs nothing and resolves at once.
   */
  start(): Promise<void> {
    if (this.loop) return this.loop;
    if (!this.isScheduled()) return Promise.resolve();
    this.stopRequested = false;
    this.loop = (async () => {
      while (!this.stopRequested) {
        await this.sleep(this.nextDelayMs());
        if (this.stopRequested) break;
        try {
          const result = await this.runPass(this.batchSize);
          if (this.lastRequested > 0) {
            this.log('attestation_retry_pass', {
              attempted: result.attempted,
              succeeded: result.succeeded,
              failed: result.failed,
              nextDelayMs: this.nextDelayMs(),
            });
          }
        } catch (err) {
          // One failed pass must not end the schedule: a transient storage
          // error would otherwise leave pending records unretried for the
          // life of the process.
          this.log('attestation_retry_pass_failed', {
            errorName: err instanceof Error ? err.name : typeof err,
            error: err instanceof Error ? err.message : String(err),
            nextDelayMs: this.nextDelayMs(),
          });
        }
      }
    })().finally(() => {
      this.loop = null;
    });
    return this.loop;
  }

  /**
   * End the schedule and resolve once it has exited — including a pass in
   * flight, scheduled or manual. A caller about to close the store awaits
   * this, so the store never closes under a running pass.
   */
  async stop(): Promise<void> {
    this.stopRequested = true;
    if (this.sleepTimer) {
      clearTimeout(this.sleepTimer);
      this.sleepTimer = null;
    }
    this.wake?.();
    this.wake = null;
    await this.loop;
    await this.passChain;
  }

  getState(): AttestationRetryState {
    return {
      scheduled: this.isScheduled(),
      running: this.loop !== null,
      intervalMs: this.intervalMs,
      batchSize: this.batchSize,
      maxBackoffMs: this.maxBackoffMs,
      nextDelayMs: this.nextDelayMs(),
      stalledPasses: this.stalledPasses,
      lastPassAt: this.lastPassAt,
      lastPass: this.lastPass ? { ...this.lastPass } : null,
      lastError: this.lastError,
    };
  }

  /** The wait before the next scheduled pass. */
  private nextDelayMs(): number {
    if (this.stalledPasses === 0 || this.intervalMs === 0) return this.intervalMs;
    return Math.min(this.intervalMs * 2 ** this.stalledPasses, this.maxBackoffMs);
  }

  private async passAndRecord(limit: number | undefined): Promise<R> {
    try {
      const { result, requested, progressed } = await this.pass(limit);
      this.lastPassAt = new Date().toISOString();
      this.lastPass = {
        attempted: result.attempted,
        succeeded: result.succeeded,
        failed: result.failed,
      };
      this.lastRequested = requested;
      this.lastError = null;
      this.stalledPasses = requested > 0 && !progressed ? this.stalledPasses + 1 : 0;
      return result;
    } catch (err) {
      this.lastPassAt = new Date().toISOString();
      this.lastError = err instanceof Error ? err.message : String(err);
      this.stalledPasses++;
      throw err;
    }
  }

  /** Report on the sink; a sink that throws does not end the schedule. */
  private log(event: string, fields: Record<string, unknown>): void {
    try {
      sdkLog(this.onLog, event, fields);
    } catch {
      /* the schedule outlives its sink */
    }
  }

  /** An unref'd wait that `stop()` can cut short. */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      this.wake = resolve;
      this.sleepTimer = setTimeout(() => {
        this.sleepTimer = null;
        this.wake = null;
        resolve();
      }, ms);
      this.sleepTimer.unref?.();
    });
  }
}
