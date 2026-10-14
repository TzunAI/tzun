/**
 * Minimal circuit breaker for external-service calls.
 *
 * Three states:
 *   CLOSED     — normal. Requests pass through. Consecutive failures
 *                increment a counter; on threshold → OPEN.
 *   OPEN       — the service is presumed down. Requests fail fast with
 *                a CircuitOpenError (no network call). After coolDownMs
 *                → HALF_OPEN.
 *   HALF_OPEN  — one probe request is allowed through. Success → CLOSED,
 *                failure counter resets. Failure → OPEN again.
 *
 * Purpose: stop hammering a dead upstream (RFC 3161 TSA, etc.) on every
 * capture. During a TSA outage each request otherwise waits out the
 * full 10-second timeout before falling back. With the breaker, the
 * first few capture requests during an outage see real timeouts, then
 * subsequent requests fail in <1ms. A capture whose every authority is
 * skipped or fails has no token: with the timestamp deferrable it is stored
 * attestationStatus 'pending', and the pending-attestation retry, which uses
 * the same clients and so the same breakers, obtains the token once a probe
 * succeeds; with the timestamp required it is refused.
 */

export class CircuitOpenError extends Error {
  constructor(message: string = 'Circuit open — upstream service is presumed unavailable') {
    super(message);
    this.name = 'CircuitOpenError';
  }
}

export interface CircuitBreakerOptions {
  /** How many consecutive failures before opening. Default: 3. */
  failureThreshold?: number;
  /** How long to stay OPEN before trying a HALF_OPEN probe (ms). Default: 60_000. */
  coolDownMs?: number;
  /** Optional name for logs. */
  name?: string;
}

type State = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export class CircuitBreaker {
  private state: State = 'CLOSED';
  private failures = 0;
  private openedAt = 0;
  private readonly failureThreshold: number;
  private readonly coolDownMs: number;
  private readonly name: string;

  constructor(options: CircuitBreakerOptions = {}) {
    this.failureThreshold = options.failureThreshold ?? 3;
    this.coolDownMs = options.coolDownMs ?? 60_000;
    this.name = options.name ?? 'circuit';
  }

  /**
   * Run the supplied async function under the circuit's protection.
   * Throws CircuitOpenError synchronously (without calling fn) when OPEN.
   * Re-throws whatever the underlying fn throws, after recording the failure.
   */
  async fire<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (Date.now() - this.openedAt >= this.coolDownMs) {
        this.state = 'HALF_OPEN';
      } else {
        throw new CircuitOpenError(
          `${this.name}: upstream unavailable, retry in ${Math.max(0, this.coolDownMs - (Date.now() - this.openedAt))}ms`
        );
      }
    }
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    if (this.state !== 'CLOSED') {
      this.state = 'CLOSED';
    }
  }

  private onFailure(): void {
    this.failures += 1;
    if (this.state === 'HALF_OPEN' || this.failures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.openedAt = Date.now();
    }
  }

  /**
   * Introspection for observability endpoints.
   */
  snapshot(): { state: State; failures: number; openedAt: number | null } {
    return {
      state: this.state,
      failures: this.failures,
      openedAt: this.state === 'OPEN' ? this.openedAt : null,
    };
  }
}
