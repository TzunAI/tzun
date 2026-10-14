import { NotificationChannel, TamperIncident, TamperSeverity, PagerDutyNotificationConfig } from '@tzun/engine';

const DEFAULT_EVENTS_URL = 'https://events.pagerduty.com/v2/enqueue';

// PagerDuty Events API v2 supports: critical, error, warning, info.
// Our TamperSeverity maps directly except we don't use 'error'.
const SEVERITY_MAP: Record<TamperSeverity, string> = {
  critical: 'critical',
  warning: 'warning',
  info: 'info',
};

// ---------------------------------------------------------------------------
// PagerDutyChannel
// ---------------------------------------------------------------------------

/**
 * PagerDuty Channel (Tier 3 -- Enterprise)
 *
 * Creates incidents via PagerDuty Events API v2.
 * Maps TamperSeverity to PagerDuty severity levels.
 * Resolve events: send() maps `incident.status === 'resolved'` to
 * event_action 'resolve'. The channel does not resolve incidents on its own:
 * TamperDetector only ever dispatches freshly created 'open' incidents, so
 * nothing in the SDK calls send() with a resolved one and PagerDuty incidents
 * are closed by hand. The resolve branch works, but it is a hook for a caller
 * to drive, not an automatic behaviour.
 * Uses incident id as dedup_key.
 */
export class PagerDutyChannel implements NotificationChannel {
  readonly name = 'pagerduty';
  private fetchFn: typeof fetch;
  private eventsUrl: string;

  constructor(
    private config: PagerDutyNotificationConfig,
    fetchFn?: typeof fetch,
  ) {
    this.fetchFn = fetchFn ?? globalThis.fetch;
    this.eventsUrl = config.apiUrl ?? DEFAULT_EVENTS_URL;
  }

  async send(incident: TamperIncident): Promise<void> {
    const eventAction = incident.status === 'resolved' ? 'resolve' : 'trigger';

    const payload = {
      routing_key: this.config.integrationKey,
      event_action: eventAction,
      dedup_key: incident.id,
      payload: {
        summary:
          `Tzun tamper alert: ${incident.type.replace(/_/g, ' ')} (${incident.severity})` +
          ` -- affected records: ${incident.affectedRecords.join(', ') || 'none'}`,
        source: 'tzun-sdk',
        severity: SEVERITY_MAP[incident.severity],
        timestamp: incident.detectedAt,
        component: 'evidence-chain',
        group: 'integrity',
        class: incident.type,
        custom_details: {
          incidentId: incident.id,
          affectedRecords: incident.affectedRecords,
          details: incident.details,
        },
      },
    };

    // Abort after the timeout. Dispatch is fire-and-forget, so a stalled
    // endpoint blocks nothing, but without a timeout each pending promise
    // would stay open for as long as the process lives.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 5000);
    let response: Response;
    try {
      response = await this.fetchFn(this.eventsUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        redirect: 'error',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (!response.ok) {
      throw new Error(`PagerDuty Events API returned HTTP ${response.status}`);
    }
  }

  async test(): Promise<void> {
    // PagerDuty Events API v2 does not have a dedicated test endpoint.
    // Send a trigger event that can be immediately resolved.
    const dedupKey = `tzun-test-${Date.now()}`;

    const payload = {
      routing_key: this.config.integrationKey,
      event_action: 'trigger',
      dedup_key: dedupKey,
      payload: {
        summary: 'Tzun SDK: notification channel test',
        source: 'tzun-sdk',
        severity: 'info',
        timestamp: new Date().toISOString(),
      },
    };

    // Abort after the timeout. Dispatch is fire-and-forget, so a stalled
    // endpoint blocks nothing, but without a timeout each pending promise
    // would stay open for as long as the process lives.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 5000);
    let response: Response;
    try {
      response = await this.fetchFn(this.eventsUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        redirect: 'error',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }

    if (!response.ok) {
      throw new Error(`PagerDuty test returned HTTP ${response.status}`);
    }
  }
}
