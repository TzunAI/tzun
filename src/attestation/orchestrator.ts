import { AttestationArtifacts } from '@tzun/engine';
import { RFC3161Client, TimestampResult, TimestampAuthorityError } from './rfc3161';
import { sdkLog } from '../sdk/log';

export interface OrchestratorConfig {
  /** RFC 3161 timestamp client. If not provided, timestamps are skipped. */
  timestampClient?: RFC3161Client;
  /**
   * Structured log sink, wired from `TzunConfig.onLog`. A timestamp no
   * authority issued is reported here as `attestation_component_failed`, a
   * token a fallback authority issued as `attestation_timestamp_failover`, and
   * a token that does not meet tzun-anchor/1 §10.5 steps 1 to 3, which every
   * verifier will refuse, as `attestation_timestamp_nonconformant`.
   * With no sink configured, each event goes to the console as one JSON line,
   * the fallback every other SDK event takes through `sdkLog()`, so an
   * outage is never silent under the default config.
   */
  onLog?: (event: string, fields: Record<string, unknown>) => void;
}

/** Pre-computed attestation inputs (e.g., WebAuthn already verified). */
export interface AttestationInputs {
  webauthnAssertion?: AttestationArtifacts['webauthnAssertion'];
  signerIdentity?: AttestationArtifacts['signerIdentity'];
}

/**
 * Attestation Orchestrator
 *
 * Produces the attestation artifacts a capture obtains for a digest:
 * 1. Obtains an RFC 3161 timestamp for the digest
 * 2. Passes through pre-verified WebAuthn assertions and signer identity
 *
 * It never touches a chain. An anchor is published for a batch of stored
 * records, off the capture path, so `attest()` has nothing to wait for but
 * the timestamp authority.
 *
 * A failed timestamp is fault-tolerant: the orchestrator returns the artifacts
 * it has rather than failing, and reports the failure on the log sink.
 */
export class AttestationOrchestrator {
  private timestampClient?: RFC3161Client;
  private onLog?: (event: string, fields: Record<string, unknown>) => void;

  constructor(config: OrchestratorConfig = {}) {
    this.timestampClient = config.timestampClient;
    this.onLog = config.onLog;
  }

  /**
   * Report an upstream attestation failure on the log sink.
   *
   * Security: the error's class name and message are both included because
   * these are operator-facing transport diagnostics ('getaddrinfo ENOTFOUND',
   * an open circuit breaker) — the whole point is to tell a typo'd URL apart
   * from an outage. No digest payload, no key material, and no caller
   * content passes through this path; the digest itself is already a public
   * value carried in the envelope.
   */
  private reportFailure(component: 'timestamp', digest: string, err: unknown): void {
    // No early return on a missing sink: sdkLog() falls back to a JSON
    // line on console.log, exactly as capture_skipped / registration / the
    // chain-conflict events already do. A failure nobody configured a sink
    // for is the one that most needs to be visible.
    sdkLog(this.onLog, 'attestation_component_failed', {
      component,
      digest,
      errorName: err instanceof Error ? err.name : typeof err,
      error: err instanceof Error ? err.message : String(err),
      // Which authorities were tried and why each one failed. Without this the
      // report said only "timestamp failed" — true of a typo'd primary, of one
      // TSA being down, and of every authority in the list being down, which
      // are three different pages for three different people. The per-attempt
      // `outcome` also separates 'failed' (contacted just now) from 'skipped'
      // (breaker already open), so a flapping TSA reads differently from one
      // that has been down since Tuesday.
      attempts: err instanceof TimestampAuthorityError ? err.attempts : undefined,
      breaker: this.timestampClient?.breakerState(),
    });
  }

  /**
   * Produce attestation artifacts for a digest: its RFC 3161 token, when a
   * timestamp client is configured and an authority answers, and the
   * pre-verified inputs passed through.
   *
   * @param digest - 64-char hex SHA-256 digest to attest
   * @param inputs - Pre-computed attestation inputs (WebAuthn, identity)
   * @returns AttestationArtifacts (without a token if no authority answered)
   */
  async attest(
    digest: string,
    inputs?: AttestationInputs
  ): Promise<AttestationArtifacts> {
    const artifacts: AttestationArtifacts = {};

    // Pass through pre-verified inputs
    if (inputs?.webauthnAssertion) {
      artifacts.webauthnAssertion = inputs.webauthnAssertion;
    }
    if (inputs?.signerIdentity) {
      artifacts.signerIdentity = inputs.signerIdentity;
    }

    const timestamp = await this.obtainTimestamp(digest);
    if (timestamp) {
      artifacts.rfc3161Token = timestamp.token;
      if (timestamp.metadata) {
        artifacts.rfc3161Metadata = timestamp.metadata;
      }
    }

    return artifacts;
  }

  /**
   * Obtain an RFC 3161 timestamp token with metadata.
   * Returns null on failure (partial attestation).
   */
  private async obtainTimestamp(digest: string): Promise<TimestampResult | null> {
    if (!this.timestampClient) return null;

    try {
      const result = await this.timestampClient.requestTimestamp(digest);

      // A SUCCESSFUL failover is the event nobody would otherwise ever see.
      // The capture worked, the envelope carries a valid token, every health
      // check is green — and the primary TSA has been unreachable for a week.
      // Silence here is how an organisation discovers, at renewal time, that
      // all of last quarter's evidence was timestamped by the fallback.
      //
      // Read defensively. `timestampClient` is a structural type on a
      // published API — the platform backend and several test suites pass a
      // hand-rolled stand-in rather than a real RFC3161Client — and a stub
      // written before `provenance` existed has none. Reaching straight
      // through it would throw a TypeError that this method's own catch would
      // then file as `attestation_component_failed`, turning a telemetry-only
      // addition into "the timestamp service is down".
      if (result.provenance?.failedOver) {
        sdkLog(this.onLog, 'attestation_timestamp_failover', {
          digest,
          authorityUrl: result.provenance.authorityUrl,
          authorityIndex: result.provenance.authorityIndex,
          attempts: result.provenance.attempts,
          breaker: this.timestampClient.breakerState?.(),
        });
      }

      // A token the client kept that every verifier will refuse: a private
      // authority that writes BER, omits signingCertificate(V2), or signs
      // without a critical timestamping-only extendedKeyUsage. The record keeps
      // it (the capture is not failed for it), and this says so at the first
      // capture, before a scan or an auditor finds every such record.
      if (result.conformance && !result.conformance.holds) {
        sdkLog(this.onLog, 'attestation_timestamp_nonconformant', {
          digest,
          authorityUrl: result.provenance?.authorityUrl,
          reason: result.conformance.reason,
          ...(result.conformance.error !== undefined && { error: result.conformance.error }),
        });
      }

      return result;
    } catch (err) {
      this.reportFailure('timestamp', digest, err);
      return null;
    }
  }
}
