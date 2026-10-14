import {
  NotificationChannel,
  TamperIncident,
  TamperSeverity,
} from '@tzun/engine';

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/** Binds a channel to the severity levels it should receive. */
export interface ChannelRegistration {
  channel: NotificationChannel;
  severities: TamperSeverity[];
}

/** Configuration for NotificationRouter. */
export interface NotificationRouterConfig {
  /** Channels to dispatch incidents to. */
  channels: ChannelRegistration[];
  /**
   * Window in milliseconds during which a duplicate incident (same
   * firstEvidenceId + type) is suppressed after the first notification.
   * Default: 3_600_000 (1 hour).
   */
  deduplicationWindowMs?: number;
  /**
   * Maximum number of notifications dispatched per minute across all channels.
   * Default: 60.
   */
  rateLimitPerMinute?: number;
}

// ---------------------------------------------------------------------------
// Internal deduplication record
// ---------------------------------------------------------------------------

interface DedupEntry {
  /** Monotonic timestamp (ms) when this key was first dispatched. */
  firstSeenMs: number;
}

// ---------------------------------------------------------------------------
// NotificationRouter
// ---------------------------------------------------------------------------

/**
 * Routes TamperIncident objects to configured notification channels with:
 * - Severity filtering per channel
 * - Deduplication within a configurable window
 * - Rate limiting (max N notifications per minute, global)
 * - Error isolation (one channel failure does not block others)
 */
export class NotificationRouter {
  private readonly channels: ChannelRegistration[];
  private readonly deduplicationWindowMs: number;
  private readonly rateLimitPerMinute: number;

  /** key → DedupEntry for active deduplication window entries. */
  private readonly dedupMap = new Map<string, DedupEntry>();

  /**
   * Monotonic timestamps (ms) of recent dispatches used for rate-limit
   * tracking. Entries older than 60 s are pruned on each dispatch call.
   */
  private readonly dispatchTimestamps: number[] = [];

  constructor(config: NotificationRouterConfig) {
    this.channels = config.channels;
    this.deduplicationWindowMs = config.deduplicationWindowMs ?? 3_600_000;
    this.rateLimitPerMinute = config.rateLimitPerMinute ?? 60;
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Dispatch an incident to all registered channels that match its severity,
   * subject to deduplication and rate limiting.
   */
  async dispatch(incident: TamperIncident): Promise<void> {
    // Order matters. The rate limit is checked FIRST and the dedup key is
    // committed LAST, because `isDuplicate()` records the key on a miss: in
    // the other order (dedup, then rate limit) a rate-limited incident would
    // have its key written on the way to being dropped, so every later
    // re-detection of that same incident would return at the dedup guard for
    // the whole deduplication window. A burst larger than
    // `rateLimitPerMinute` — exactly what a bulk tamper or a post-fork rescan
    // produces — would then lose its overflow incidents permanently from every
    // channel, with nothing logged.
    if (this.isRateLimited()) {
      console.warn(
        `[NotificationRouter] Rate limit (${this.rateLimitPerMinute}/min) reached; ` +
          `dropping incident "${incident.id}" (${incident.type}, ${incident.severity}). ` +
          'It is NOT deduplicated and will be delivered on a later scan pass.',
      );
      return;
    }

    if (this.isDuplicate(incident)) {
      return;
    }

    // Commit the dedup key only now that the incident is actually going out.
    this.rememberDispatched(incident);

    // Record this dispatch for rate limiting before sending.
    this.dispatchTimestamps.push(Date.now());

    const matchingChannels = this.channels.filter((reg) =>
      reg.severities.includes(incident.severity),
    );

    await Promise.allSettled(
      matchingChannels.map(async (reg) => {
        try {
          await reg.channel.send(incident);
        } catch (err) {
          console.error(
            `[NotificationRouter] Channel "${reg.channel.name}" failed to send incident "${incident.id}":`,
            err instanceof Error ? err.message : err,
          );
        }
      }),
    );
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Returns true if this incident is a duplicate within the deduplication
   * window. A duplicate is defined as: same (firstEvidenceId, type) pair seen
   * within deduplicationWindowMs.
   *
   * Pure query — the key is committed separately by `rememberDispatched()`
   * only when the incident actually goes out.
   */
  private isDuplicate(incident: TamperIncident): boolean {
    const existing = this.dedupMap.get(this.dedupKey(incident));
    if (existing === undefined) return false;
    // Window expired — treat as a new occurrence.
    return Date.now() - existing.firstSeenMs < this.deduplicationWindowMs;
  }

  /**
   * Commit the deduplication key for an incident that is about to be sent.
   *
   * Split out of `isDuplicate()` so that a query never has a write side
   * effect: a dropped incident must not consume its own dedup window.
   */
  private rememberDispatched(incident: TamperIncident): void {
    this.dedupMap.set(this.dedupKey(incident), { firstSeenMs: Date.now() });
  }

  /** Stable dedup identity for an incident. */
  private dedupKey(incident: TamperIncident): string {
    const firstId = incident.affectedRecords[0];
    if (firstId) {
      return `${firstId}:${incident.type}`;
    }
    if (incident.affectedSequenceRange) {
      return `${incident.affectedSequenceRange.from}-${incident.affectedSequenceRange.to}:${incident.type}`;
    }
    return `${incident.id}:${incident.type}`; // fallback to incident id (no dedup)
  }

  /**
   * Returns true if the global rate limit for the past 60 seconds has been
   * reached. Prunes stale entries from dispatchTimestamps as a side effect.
   */
  private isRateLimited(): boolean {
    const now = Date.now();
    const windowStart = now - 60_000;

    // Remove timestamps outside the rolling one-minute window.
    while (
      this.dispatchTimestamps.length > 0 &&
      this.dispatchTimestamps[0] < windowStart
    ) {
      this.dispatchTimestamps.shift();
    }

    return this.dispatchTimestamps.length >= this.rateLimitPerMinute;
  }
}
