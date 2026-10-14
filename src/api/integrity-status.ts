import { StorageAdapter } from '@tzun/engine';
import { MonitoringEventType, ScannerState, ScanSummary, TamperIncident } from '@tzun/engine';

/**
 * The incident statuses that mean nobody has signed off on the finding yet. One
 * group: acknowledging an incident, and the hosted service starting a recovery
 * on it, say who is looking, not that the evidence is whole again.
 */
const UNRESOLVED_STATUSES: ReadonlySet<string> = new Set(['open', 'acknowledged', 'in_progress']);

/**
 * The findings that say the evidence itself is not intact: a rewritten digest, a
 * broken or reseated chain link, a duplicated sequence, an altered custody
 * trail, a mismatched descriptor, a gap, a missing record; and, from the
 * evidence logs, a record that is not the one logged, a log that no longer
 * reproduces what was anchored, is truncated below it, or is inconsistent with
 * it or split, and a publisher nonce someone else used.
 *
 * Keyed by TYPE rather than by severity, because the two vocabularies do not
 * line up. The hosted service rates `sequence_gap` and `missing_record`
 * 'high' — integrity-breaking, and red — while this SDK's coarser three-value
 * scale rates both 'warning', the same word it gives an attestation that would
 * not verify. A deleted record is not a matter for review, so mirroring the
 * hosted service's rule means naming the types.
 *
 * Below this set sit the findings rated for review rather than alarm: an
 * attestation that does not check out, an artifact this build cannot read, a
 * `capturedAt` that ran backwards, a descriptor that would not resolve, an
 * anchor stripped from a record, an anchor made for another record, an anchor
 * overdue.
 */
export const INTEGRITY_INCIDENT_TYPES: ReadonlySet<MonitoringEventType> = new Set<MonitoringEventType>([
  'digest_mismatch',
  'chain_break',
  'duplicate_sequence',
  'digest_superseded',
  'custody_trail_invalid',
  'descriptor_digest_mismatch',
  'parent_descriptor_digest_mismatch',
  'sequence_gap',
  'missing_record',
  'digest_differs_from_logged_leaf',
  'log_rewritten_below_anchor',
  'log_truncated_below_anchor',
  'log_inconsistent_with_anchor',
  'split_view',
  'anchor_wallet_nonce_unaccounted',
]);

/** Does this finding say the evidence is not intact? */
export function incidentBreaksIntegrity(incident: TamperIncident): boolean {
  if (INTEGRITY_INCIDENT_TYPES.has(incident.type)) return true;
  // A type this build does not recognise, rated critical by whoever raised it,
  // is treated as integrity-breaking: err toward 'compromised'.
  return incident.severity === 'critical';
}

/** The findings in the store, grouped the three ways `chainStatus` reads them. */
export interface IncidentCounts {
  /**
   * Unresolved (open, acknowledged, in progress) at a finding type that means
   * the evidence is not intact. The 'compromised' rule.
   */
  unresolvedIntegrity: number;
  /** Unresolved below that: a finding to review, not an alarm. 'degraded'. */
  unresolvedOther: number;
  /**
   * Resolved — a human reviewed it — and observed again by the last completed
   * pass. A hashed record can never be repaired in place, so `resolved` on a
   * tamper finding means reviewed, not gone: while the finding is still there
   * the store is not clean. 'degraded'.
   */
  reviewedStillObserved: number;
}

export const NO_INCIDENTS: IncidentCounts = Object.freeze({
  unresolvedIntegrity: 0,
  unresolvedOther: 0,
  reviewedStillObserved: 0,
});

/**
 * Group the stored incidents the three ways `chainStatus` reads them.
 *
 * `passStartedAt` is when the last completed pass STARTED
 * (`ScanSummary.startedAt`). A resolved incident whose finding was observed at
 * or after it was seen again by that pass, which is what makes "resolved"
 * different from "gone": the detector does not raise a second incident for a
 * finding that already has one, so an observation is the only evidence that the
 * finding is still true.
 *
 * With no completed pass every observed resolved incident counts. Nothing has
 * re-checked the store, so no finding may be claimed gone, and the store holds
 * at 'degraded' rather than falling through. An incident with no observation at
 * all — raised before `lastObservedAt` existed — is counted in neither
 * direction.
 *
 * The hosted service counts incidents the same way.
 */
export function countIncidents(
  incidents: readonly TamperIncident[],
  passStartedAt: string | null,
): IncidentCounts {
  const counts = { unresolvedIntegrity: 0, unresolvedOther: 0, reviewedStillObserved: 0 };
  for (const incident of incidents) {
    if (UNRESOLVED_STATUSES.has(incident.status)) {
      if (incidentBreaksIntegrity(incident)) counts.unresolvedIntegrity += 1;
      else counts.unresolvedOther += 1;
      continue;
    }
    if (incident.status !== 'resolved' || incident.lastObservedAt === undefined) continue;
    if (passStartedAt === null || incident.lastObservedAt >= passStartedAt) {
      counts.reviewedStillObserved += 1;
    }
  }
  return counts;
}

/**
 * System-wide integrity health summary — the body of `GET /v1/integrity/status`.
 *
 * Every field is either a count taken from storage or a figure the scheduled
 * scanner measured on a pass that ran to completion. Nothing here defaults to
 * a reassuring value.
 *
 * chainStatus derivation, in precedence order (spec 7.2):
 *   - 'compromised': a finding that means the evidence is not intact, and
 *                    nobody has signed off on it
 *   - 'degraded':    findings exist, but each is either below that — rated for
 *                    review — or was reviewed and is STILL OBSERVED by the last
 *                    completed pass
 *   - 'healthy':     no finding standing AND the last completed scanner pass
 *                    found nothing (`lastFullScan.issuesFound === 0`)
 *   - 'unknown':     anything else — nothing has scanned the store, or the
 *                    last pass found issues that no incident accounts for
 *
 * 'unknown' is the default state. A rule of "no open incidents" would answer
 * 'healthy' for a store no scanner had ever touched, since a store nothing has
 * looked at has no incidents, and an integrator wiring a dashboard to it would
 * get a green light on day one over evidence that had never been verified.
 * 'unknown' is what keeps "never looked" from reading as "looked and fine".
 *
 * Incidents outrank the scan upward. They are the persisted, triaged record of
 * what verification found — from a scan pass, a verifying read, or an on-demand
 * verify — so a finding is measured trouble even before any full pass. They do
 * not outrank it downward: 'healthy' needs the pass itself to have been clean.
 * A pass that found issues with no incident to show for them is one still on
 * its way to storage; that is not "looked and fine", so it is 'unknown' until
 * the next clean pass. `lastFullScan` carries that pass's own numbers unchanged
 * for anyone who wants them.
 *
 * A REVIEWED FINDING THAT IS STILL THERE is why 'degraded' outranks the
 * scan too. A hashed record can never be repaired in place, so resolving a
 * tamper finding records a review, not a repair. TamperDetector raises the
 * finding once and re-observes it thereafter, and
 * `incidents.reviewedStillObserved` is what holds the store at 'degraded' for
 * exactly as long as it remains true. Without it the answer for that store
 * would be at best 'unknown' — via the clean-pass rule, since the pass still
 * reports the finding — which says "nobody knows" about something known
 * precisely.
 *
 * A completed pass says nothing about records captured after it. Compare
 * `lastFullScan.recordsChecked` with `totalRecords`, and `lastFullScanAt`
 * with the clock, before treating 'healthy' as current.
 */
export interface IntegrityStatus {
  chainStatus: 'unknown' | 'healthy' | 'degraded' | 'compromised';
  totalRecords: number;
  activeChainId: string;
  sealedChains: number;
  /**
   * The findings in the store, grouped as `chainStatus` reads them: unresolved
   * at a type that means the evidence is not intact, unresolved below that, and
   * reviewed but still observed by the last completed pass.
   *
   * REPLACES `openIncidents: number`, which counted `status: 'open'` alone — so
   * the store came off 'compromised' when its last finding was acknowledged, or
   * when the hosted service started a recovery on it, and a single number
   * could not say which of the three cases a store was in. The hosted service
   * reports the same groups for a chain.
   */
  incidents: IncidentCounts;
  /** When the last scanner pass ran to completion. `null` = never scanned. */
  lastFullScanAt: string | null;
  /**
   * Wall-clock milliseconds of that pass. `null` = never scanned.
   *
   * Was permanently `null` — the comment beside it said "computed from scan
   * summary", and nothing ever did.
   */
  lastFullScanDuration: number | null;
  /**
   * What that pass found: records checked, issues by category, the
   * attestation-presence counts (`attestationPresence`) and the verified-valid
   * counts (`attestationValid`) `attestationCoverage` is derived from. `null`
   * = never scanned. Additive (2026-09).
   */
  lastFullScan: ScanSummary | null;
  scannerRunning: boolean;
  /**
   * Percentage (0–100) of the records the last completed pass checked whose
   * attestation artifact that pass VERIFIED — an RFC 3161 token parsed and
   * stamped over this record's digest, a WebAuthn assertion verified against
   * its registered key and bound to this record, an anchor whose publication
   * was checked. Validity, per spec 7.2 ("percentage with valid timestamps"), not
   * presence: a placeholder string, or a captive-portal page a TSA client
   * stored on an HTTP 200, counts in `lastFullScan.attestationPresence` and
   * not here. Verification failures are `lastFullScan.attestationFailures`.
   *
   * Per component, `null` means the pass did not verify that kind of
   * artifact — every component under `verifyAttestation: false`; `signature`
   * unless the scanner has a credential store (the per-record challenge is not
   * a precondition: the scanner derives it from the record's digest when the
   * caller supplies no scheme of its own); `anchor`
   * always, because the scanner checks an anchor's proofs and not its
   * publications. Null is "not measured", never 0%.
   *
   * The whole field is `null` when no completed pass has checked a record —
   * no pass, or a pass over an empty store — because `{0,0,0}` there would be
   * indistinguishable from "measured, and no record is attested".
   */
  attestationCoverage: AttestationCoverage | null;
  pendingAttestations: number;
}

/** See `IntegrityStatus.attestationCoverage`. */
export interface AttestationCoverage {
  timestamp: number | null;
  signature: number | null;
  anchor: number | null;
}

export interface IntegrityStatusInput {
  storage: StorageAdapter;
  scannerState: ScannerState | null;
  activeChainId: string;
  sealedChains: number;
  totalRecords?: number;
  pendingAttestations?: number;
  /**
   * A coverage figure the caller measured itself — its own verification pass
   * over its own store, say. Overrides the scan-derived figure. Absent means
   * "derive it from the last completed pass, or report null"; it never means
   * zero.
   */
  attestationCoverage?: AttestationCoverage;
}

/**
 * Derive attestation coverage percentages from a completed pass: verified-valid
 * records over records checked, per component, with `null` for a component
 * the pass did not verify. `null` as a whole when the pass did not report
 * validity (an older producer) or checked no records — a percentage of
 * nothing is not 0%.
 *
 * Presence (`summary.attestationPresence`) is deliberately NOT a fallback
 * here: it is a different measurement that was briefly served under this
 * name, and a field the spec defines as "valid" must not quietly become
 * "present" when validity was not measured.
 */
export function attestationCoverageFromScan(
  summary: ScanSummary | null,
): AttestationCoverage | null {
  if (!summary || !summary.attestationValid || summary.recordsChecked <= 0) {
    return null;
  }
  const valid = summary.attestationValid;
  const pct = (n: number | null): number | null =>
    n === null ? null : (n / summary.recordsChecked) * 100;
  return {
    timestamp: pct(valid.timestamp),
    signature: pct(valid.signature),
    anchor: pct(valid.anchor),
  };
}

/**
 * Compute the system-wide IntegrityStatus from storage and scanner state.
 *
 * Pure computation over the provided inputs -- no side effects.
 */
export async function computeIntegrityStatus(
  input: IntegrityStatusInput,
): Promise<IntegrityStatus> {
  const { storage, scannerState, activeChainId, sealedChains } = input;

  // The scanner sets `lastCompletedPassAt` and `lastCompletedPass` together,
  // at the end of a pass that ran to completion. A pass that threw sets
  // neither. No scanner configured means both are absent.
  const lastFullScanAt = scannerState?.lastCompletedPassAt ?? null;
  const lastFullScan = scannerState?.lastCompletedPass ?? null;

  // EVERY incident, not just the open ones: a reviewed finding still being
  // observed is as much a reason not to say 'healthy' as an open one, and a
  // single status filter cannot see it. `lastFullScan.startedAt` is the anchor —
  // the pass that would have re-observed the finding, stamped by the scanner
  // from this process's clock, the same clock TamperDetector stamps
  // `lastObservedAt` from.
  const incidents = countIncidents(
    await storage.listIncidents(),
    lastFullScan?.startedAt ?? null,
  );

  // Derive chain status (see the IntegrityStatus doc for the precedence).
  // 'healthy' is reachable only from a completed pass that found nothing:
  // with no open incidents and no pass, the honest answer is that nobody has
  // looked; with no open incidents and a pass that found issues, the honest
  // answer is that the store has not been verified clean since — the incident
  // is either still in flight (TamperDetector persists after the pass has
  // returned) or was resolved without a re-scan. Spec 7.2: healthy = no open
  // incidents AND last scan clean.
  let chainStatus: IntegrityStatus['chainStatus'];
  if (incidents.unresolvedIntegrity > 0) {
    chainStatus = 'compromised';
  } else if (incidents.unresolvedOther > 0 || incidents.reviewedStillObserved > 0) {
    chainStatus = 'degraded';
  } else if (lastFullScan !== null && lastFullScan.issuesFound === 0) {
    chainStatus = 'healthy';
  } else {
    chainStatus = 'unknown';
  }

  // Determine scanner running state
  const scannerRunning = scannerState !== null &&
    scannerState.segmentsInProgress.length > 0;

  // Get total records from input or storage.
  //
  // A COUNT across every chain, not a chain's sequence counter. A counter
  // describes one chain: on a store holding 7 records across three chains it
  // reported `totalRecords: 2` — beside `sealedChains: 2`, a status payload that
  // contradicts itself, published through `GET /v1/integrity/status`. Every
  // sealed record, which is exactly the evidence a fork was performed to
  // preserve, had vanished from the count.
  //
  // `getChainLength()` with no chain id counts the whole store. The HTTP
  // transport refuses it, and cannot fork through this SDK either, so there it
  // falls back to the active chain's counter, which is the only chain it has.
  let totalRecords = input.totalRecords;
  if (totalRecords === undefined) {
    try {
      totalRecords = await storage.getChainLength();
    } catch {
      totalRecords = await storage.getLastSequence(activeChainId);
    }
  }

  return {
    chainStatus,
    totalRecords,
    activeChainId,
    sealedChains,
    incidents,
    lastFullScanAt,
    lastFullScanDuration: lastFullScan?.durationMs ?? null,
    lastFullScan,
    scannerRunning,
    attestationCoverage:
      input.attestationCoverage ?? attestationCoverageFromScan(lastFullScan),
    pendingAttestations: input.pendingAttestations ?? 0,
  };
}
