import { createHmac } from 'crypto';
import { NotificationChannel, TamperIncident, WebhookNotificationConfig } from '@tzun/engine';

// ---------------------------------------------------------------------------
// Extended config for retry behaviour (not part of the base type)
// ---------------------------------------------------------------------------

export interface WebhookChannelConfig extends WebhookNotificationConfig {
  /** Number of retry attempts after the initial request (default: 2). */
  retries?: number;
  /** Delay in milliseconds between retry attempts (default: 1000). */
  retryDelayMs?: number;
}

/**
 * HMAC-SHA256 over `${timestamp}.${payload}` (the Stripe construction).
 *
 * Exported so a receiver -- and the tests -- can recompute it without
 * reaching into the channel.
 */
export function computeWebhookSignature(
  secret: string,
  timestamp: string,
  payload: string,
): string {
  const hmac = createHmac('sha256', secret).update(`${timestamp}.${payload}`).digest('hex');
  return `sha256=${hmac}`;
}

// ---------------------------------------------------------------------------
// WebhookChannel
// ---------------------------------------------------------------------------

/**
 * Webhook Channel (Tier 2 -- Integration)
 *
 * POSTs a signed JSON payload to a configured HTTPS endpoint.
 * Signed with HMAC-SHA256 using a shared secret (GitHub/Stripe pattern).
 * Includes retry logic with configurable attempts and delay.
 *
 * Payload format:
 *   {
 *     "event": "tamper.detected",
 *     "timestamp": "2026-04-04T...",
 *     "incident": { ... }
 *   }
 *
 * Headers:
 *   X-Tzun-Signature: sha256=<hex>   (omitted entirely when no secret is set)
 *   X-Tzun-Timestamp: <unix seconds> (covered by the signature)
 *   X-Tzun-Event: tamper.detected | test
 *
 * SIGNATURE INPUT. The HMAC is computed
 * over `${timestamp}.${payload}`, not over the payload alone. Without a
 * timestamp inside the signed bytes a captured POST replays for ever, since
 * nothing in the signature ties it to a moment. Receivers must reject a
 * X-Tzun-Timestamp outside their tolerance window before verifying.
 *
 * The header is OMITTED when `secret` is unset. An HMAC keyed on the empty
 * string cannot be told apart from a genuine signature, so a receiver that
 * verifies "if the header is present" would accept anything a forger could
 * compute with the publicly-known empty key.
 */
export class WebhookChannel implements NotificationChannel {
  readonly name = 'webhook';
  private config: WebhookChannelConfig;
  private fetchFn: typeof fetch;

  constructor(config: WebhookChannelConfig, fetchFn?: typeof fetch) {
    this.config = config;
    this.fetchFn = fetchFn ?? globalThis.fetch;
  }

  async send(incident: TamperIncident): Promise<void> {
    const payload = JSON.stringify({
      event: 'tamper.detected',
      timestamp: new Date().toISOString(),
      incident,
    });

    const headers = this.buildHeaders(payload, 'tamper.detected');
    const retries = this.config.retries ?? 2;
    const maxAttempts = 1 + retries;
    const retryDelayMs = this.config.retryDelayMs ?? 1000;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutMs = this.config.timeoutMs ?? 5000;
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        try {
          const response = await this.fetchFn(this.config.url, {
            method: 'POST',
            headers,
            body: payload,
            // Redirects are refused. Following a 30x would re-POST the
            // incident -- evidence ids, digests, details -- plus the signature
            // to whatever host the redirect named, so a moved receiver left
            // with a 301 to a third party would hand every tamper incident
            // away.
            redirect: 'error',
            signal: controller.signal,
          });

          if (response.ok) {
            return;
          }
          lastError = new Error(`Webhook returned HTTP ${response.status}`);
        } finally {
          clearTimeout(timeoutId);
        }
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
      }

      // Wait before retrying (skip on last attempt).
      if (attempt < maxAttempts - 1 && retryDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }

    // All attempts exhausted -- log but do not throw.
    console.error(
      `[WebhookChannel] All ${maxAttempts} attempts to ${this.config.url} failed:`,
      lastError?.message,
    );
  }

  async test(): Promise<void> {
    const payload = JSON.stringify({
      event: 'test',
      timestamp: new Date().toISOString(),
    });

    const headers = this.buildHeaders(payload, 'test');
    const controller = new AbortController();
    const timeoutMs = this.config.timeoutMs ?? 5000;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await this.fetchFn(this.config.url, {
        method: 'POST',
        headers,
        body: payload,
        redirect: 'error',
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Webhook test returned HTTP ${response.status}`);
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Build the request headers, signing only when a secret is configured.
   *
   * `X-Tzun-Signature` is absent when `secret` is unset — an HMAC keyed on the
   * empty string is not a signature, and emitting one makes "unsigned" and
   * "signed" indistinguishable to the receiver.
   */
  private buildHeaders(payload: string, event: string): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Tzun-Event': event,
    };
    const secret = this.config.secret;
    if (secret !== undefined && secret !== '') {
      const timestamp = Math.floor(Date.now() / 1000).toString();
      headers['X-Tzun-Timestamp'] = timestamp;
      headers['X-Tzun-Signature'] = computeWebhookSignature(secret, timestamp, payload);
    }
    return headers;
  }
}
