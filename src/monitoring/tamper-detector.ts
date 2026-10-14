import { randomUUID } from 'crypto';
import { MonitoringEventBus } from './event-bus';
import { StorageAdapter } from '@tzun/engine';
import {
  MonitoringEvent,
  TamperIncident,
  TamperSeverity,
  AI_BOM_TAMPER_INCIDENT_SEVERITY,
  type EvmFinality,
} from '@tzun/engine';

/** Callback type for external consumers (e.g. NotificationRouter). */
export type IncidentCallback = (incident: TamperIncident) => void;

/**
 * `capturedAtSkewMs` (`genTime - capturedAt`) in words, with the raw value.
 * Negative: the record claims a capture instant after the TSA stamped it.
 */
function describeCapturedAtSkew(skewMs: number): string {
  const seconds = Math.abs(skewMs) / 1000;
  const direction = skewMs < 0 ? 'later' : 'earlier';
  return (
    `capturedAt is ${seconds} s ${direction} than the genTime of the timestamp token that ` +
    `notarised it (capturedAtSkewMs ${skewMs})`
  );
}

/**
 * What a chain counted as final when it judged an anchor (an
 * `attestation_invalid` event's `anchorFinality`), in words. `null`: the
 * chains behind the anchor's publications count different blocks as final.
 */
function describeFinality(finality: EvmFinality | null): string {
  if (finality === null) return 'judged by chains that count different blocks as final';
  if (finality === 'finalized') return "judged at the chain's finalized block";
  const depth = `judged at ${finality.confirmations} confirmations`;
  return finality.acceptNonFinal === true ? `${depth}, which may not be final` : depth;
}

/**
 * The findings about a whole log or a publisher wallet (checks b, c, d and g
 * of `anchor-log-checks.ts`). A `TamperIncident` has no field for a log or a
 * wallet, so the first line of such an incident's `details` names the
 * finding: the log's origin and chain, the anchored size and the reason, or
 * the wallet, its chain and the nonce. Nothing on it changes from pass to
 * pass. What does (whether the root came from the chain, the log's size now,
 * the records a rewrite names) follows on the next line.
 */
const LOG_FINDING_TYPES: ReadonlySet<string> = new Set([
  'log_rewritten_below_anchor',
  'log_truncated_below_anchor',
  'log_inconsistent_with_anchor',
  'split_view',
  'anchor_wallet_nonce_unaccounted',
  'mandate_slot_duplicate',
  'mandate_slot_gap',
  'mandate_totals_unexplained',
]);

/**
 * Which finding an incident reports: its type and what it is about. For a
 * finding about a log or a publisher wallet, what it is about is the first
 * line of its details; for any other, the records it names, sorted, else its
 * sequence range, else the chain.
 *
 * The hosted service's dedupe key is the second rule for every type, under
 * the account, environment and chain. An SDK store has one account and one
 * environment, and a `TamperIncident` carries no chain id, so here the key is
 * the type and the target alone.
 */
export function incidentDedupeKey(incident: TamperIncident): string {
  const target = LOG_FINDING_TYPES.has(incident.type)
    ? `finding:${incident.details.split('\n', 1)[0]}`
    : incident.affectedRecords.length > 0
      ? [...incident.affectedRecords].sort().join(',')
      : incident.affectedSequenceRange
        ? `seq:${incident.affectedSequenceRange.from}-${incident.affectedSequenceRange.to}`
        : 'chain';
  return `${incident.type}|${target}`;
}

/** Leaves `[from, to)` of an evidence log as the sequence numbers of their records. */
function leafSequenceRange(from: number, to: number): { from: number; to: number } | undefined {
  return to > from ? { from: from + 1, to } : undefined;
}

/** How a log is named in an incident: its origin, and its chain when it is an evidence log. */
function describeLog(origin: string, chainId: string | null): string {
  return chainId === null ? `anchor log ${origin}` : `evidence log ${origin} (chain ${JSON.stringify(chainId)})`;
}

/**
 * TamperDetector subscribes to the MonitoringEventBus, enriches raw monitoring
 * events into TamperIncident objects with severity classification, and — for a
 * finding no incident already reports — notifies registered callbacks and
 * persists the incident. For a finding that one does, it records the
 * re-observation instead.
 *
 * Severity mapping:
 *   digest_mismatch                       → critical
 *   chain_break                           → critical
 *   sequence_gap                          → warning
 *   duplicate_sequence                    → critical
 *   digest_superseded                     → critical
 *   captured_at_regression                → warning
 *   custody_trail_invalid                 → critical
 *   missing_record                        → warning
 *   attestation_invalid                   → warning
 *   attestation_unverifiable              → warning
 *   descriptor_resolution_failure         → warning
 *   descriptor_digest_mismatch            → critical
 *   parent_descriptor_resolution_failure  → warning
 *   parent_descriptor_digest_mismatch     → critical
 *   digest_differs_from_logged_leaf       → critical
 *   log_rewritten_below_anchor            → critical
 *   log_truncated_below_anchor            → critical
 *   log_inconsistent_with_anchor          → critical
 *   split_view                            → critical
 *   anchor_wallet_nonce_unaccounted       → critical
 *   anchor_stripped                       → warning
 *   anchor_transplanted                   → warning
 *   anchor_overdue                        → warning
 *   record_verified                       → ignored
 *   scan_completed                        → ignored
 *   chain_relinked                        → ignored
 *   chain_forked                          → ignored
 *   incident_annotated                    → ignored
 *
 * Deduplication. The scanner reports every finding on every pass, and a
 * tampered record stays tampered, so each pass would otherwise open another
 * incident for the same finding — one per scan interval, forever, however
 * often an operator acknowledged the last one.
 *
 * ONE INCIDENT PER FINDING, WHATEVER ITS STATUS. A finding that already has an
 * incident (same `incidentDedupeKey`) is never raised again: no callback, no new
 * row. Instead the pass records that it observed the finding again, by stamping
 * `lastObservedAt` on the incident that already holds it.
 *
 * A 'resolved' incident holds its finding back too. A hashed record can never
 * be repaired in place, so "resolved" on a tamper finding means a human
 * reviewed it, not that it is gone. Raising the finding again as a brand new
 * critical incident would make resolving one a treadmill: the store would go
 * back to 'compromised' on the next pass and the same finding would have to be
 * resolved again, forever. Recording the observation instead is what lets
 * `computeIntegrityStatus` hold the store at 'degraded' for exactly as long as
 * the reviewed finding is still there, and let it reach 'healthy' once a pass
 * stops seeing it. The hosted service does the same in one statement.
 *
 * The stored incidents are read from storage once per burst of events — every
 * event handled back to back, a scan pass typically — rather than once per
 * event, which would make a pass over a store with many findings quadratic. An
 * incident an operator resolves mid-burst is therefore seen from the next burst.
 * A store that cannot list incidents (the platform's chain-scoped scanner view,
 * which deduplicates in its own incident writer) gets every finding raised
 * rather than any dropped.
 */
export class TamperDetector {
  private callbacks: IncidentCallback[] = [];
  /**
   * Incidents that have been handed to the detector and have not finished —
   * looked up, and if new, persisted — settled either way. `settle()` drains
   * it. Kept as a set of the promises themselves so that one started while
   * `settle()` is already waiting is still waited for.
   */
  private readonly inFlight = new Set<Promise<void>>();
  /**
   * Incidents are raised one at a time, in the order their events arrived: the
   * lookup, the decision and the write for one incident finish before the next
   * incident's lookup starts, so a reload of `known` never misses a row this
   * detector is still writing.
   */
  private queue: Promise<void> = Promise.resolve();
  /** Incidents queued and not yet finished. */
  private queued = 0;
  /**
   * The id of the incident that already holds each finding, by dedupe key, for
   * the current burst: loaded from storage when the burst starts, extended with
   * every incident raised in it, and dropped when the queue runs empty so the
   * next burst reads storage again. `null` between bursts.
   */
  private known: Map<string, string> | null = null;
  private lookupFailureLogged = false;

  constructor(
    private readonly bus: MonitoringEventBus,
    private readonly storage: StorageAdapter,
  ) {
    this.bus.subscribe((event) => this.handleEvent(event));
  }

  /**
   * Register a callback to be notified whenever a new incident is raised — once
   * the detector has found no incident already reporting its finding, and before
   * the incident is written to storage. A finding that is merely observed again
   * fires nothing: that is the point of raising it once. Used by
   * NotificationRouter and other external consumers.
   */
  onIncident(callback: IncidentCallback): void {
    this.callbacks.push(callback);
  }

  /**
   * Process an incoming monitoring event: enrich it into a TamperIncident if
   * applicable, and queue it — to be raised, or, when its finding already has an
   * incident, to be recorded as observed again on that one.
   *
   * Nothing here blocks the event bus: `MonitoringEventBus.emit` is
   * synchronous, so by the time `ScheduledScanner.runFullPass()` returns every
   * incident of that pass has been QUEUED, but none has necessarily LANDED in
   * storage. A caller that resolved in that window would let
   * `GET /v1/integrity/incidents` right after it answer `[]`, and
   * `Tzun.close()` close the pool under the INSERT. `settle()` is what closes
   * the window; `Tzun.runScan()` awaits it.
   */
  handleEvent(event: MonitoringEvent): void {
    const incident = this.enrichToIncident(event);
    if (incident === null) {
      return;
    }

    this.queued += 1;
    const work: Promise<void> = this.queue
      .then(() => this.raise(incident))
      .finally(() => {
        this.queued -= 1;
        if (this.queued === 0) this.known = null;
        this.inFlight.delete(work);
      });
    // A step that failed must not stop the incidents queued behind it.
    this.queue = work.catch(() => undefined);
    this.inFlight.add(work);
  }

  /**
   * Resolve once every incident handed to the detector so far has been looked
   * up and, if new, persisted — including any handed over while this is
   * waiting. Never rejects: a persist that failed has already been logged by
   * `raise()`, and a caller draining before `storage.close()` needs to
   * proceed either way.
   */
  async settle(): Promise<void> {
    while (this.inFlight.size > 0) {
      await Promise.allSettled([...this.inFlight]);
    }
  }

  /**
   * Raise one incident — or, when its finding already has one, record that this
   * pass observed the finding again and raise nothing. Never rejects.
   */
  private async raise(incident: TamperIncident): Promise<void> {
    const key = incidentDedupeKey(incident);
    const known = await this.knownFindings();
    if (known !== null) {
      const existingId = known.get(key);
      if (existingId !== undefined) {
        await this.observe(existingId, incident.detectedAt);
        return;
      }
      known.set(key, incident.id);
    }

    // The instant this pass saw the finding, on the same clock
    // `ScanSummary.startedAt` is stamped from, which is what it is compared
    // against (computeIntegrityStatus).
    incident.lastObservedAt = incident.detectedAt;

    for (const cb of this.callbacks) {
      try {
        cb(incident);
      } catch (err) {
        console.error(
          `[TamperDetector] Callback threw for incident "${incident.id}":`,
          err instanceof Error ? err.message : err,
        );
      }
    }

    try {
      await this.storage.storeIncident(incident);
    } catch (err) {
      console.error(
        `[TamperDetector] Failed to persist incident "${incident.id}":`,
        err instanceof Error ? err.message : err,
      );
    }
  }

  /**
   * Stamp `lastObservedAt` on the incident that already holds this finding, so
   * that a reviewed finding still being seen can be told from one that has gone
   * away. Never rejects: a failed stamp costs a store the ability to make that
   * distinction, and must not stop the pass.
   *
   * Silently skipped by a store with no `recordIncidentObservation` — the HTTP
   * transport, which has no local store, and the platform's chain-scoped view,
   * which records observations in its own incident writer.
   */
  private async observe(incidentId: string, observedAt: string): Promise<void> {
    if (typeof this.storage.recordIncidentObservation !== 'function') return;
    try {
      await this.storage.recordIncidentObservation(incidentId, observedAt);
    } catch (err) {
      console.error(
        `[TamperDetector] Failed to record an observation on incident "${incidentId}":`,
        err instanceof Error ? err.message : err,
      );
    }
  }

  /**
   * The incident that already holds each finding, read from storage once per
   * burst — or `null` when the store cannot say, in which case every finding is
   * raised. A lookup that fails is retried on the next incident; the first
   * failure is logged.
   *
   * Every status, in one unfiltered call, resolved included: reading only
   * 'open', 'acknowledged' and 'in_progress' would let a resolved finding be
   * raised a second time. A resolved incident is as much the record of its
   * finding as an open one.
   */
  private async knownFindings(): Promise<Map<string, string> | null> {
    if (this.known !== null) return this.known;
    if (typeof this.storage.listIncidents !== 'function') return null;
    try {
      const stored = await this.storage.listIncidents();
      // listIncidents orders detectedAt DESC, so the first row for a key is the
      // newest incident reporting that finding — the one to stamp if a store
      // already holds duplicate incidents for it (an earlier SDK version raised
      // a resolved finding again).
      const known = new Map<string, string>();
      for (const incident of stored) {
        const key = incidentDedupeKey(incident);
        if (!known.has(key)) known.set(key, incident.id);
      }
      this.known = known;
      return this.known;
    } catch (err) {
      if (!this.lookupFailureLogged) {
        this.lookupFailureLogged = true;
        console.error(
          '[TamperDetector] could not list the stored incidents, so findings are raised ' +
            'without deduplication:',
          err instanceof Error ? err.message : err,
        );
      }
      return null;
    }
  }

  /**
   * Convert a raw MonitoringEvent into a TamperIncident, or return null for
   * informational events that do not warrant an incident record.
   */
  enrichToIncident(event: MonitoringEvent): TamperIncident | null {
    const id = randomUUID();
    const detectedAt = new Date().toISOString();

    switch (event.type) {
      case 'digest_mismatch': {
        const severity: TamperSeverity = 'critical';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [event.evidenceId],
          details: `Digest mismatch on evidence record "${event.evidenceId}": stored=${event.stored}, recomputed=${event.recomputed}`,
          status: 'open',
        };
      }

      case 'chain_break': {
        const severity: TamperSeverity = 'critical';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [event.evidenceId],
          affectedSequenceRange: {
            from: event.sequenceNumber,
            to: event.sequenceNumber,
          },
          details: `Chain break at evidence record "${event.evidenceId}" (sequence ${event.sequenceNumber}): expectedPrevDigest=${event.expectedPrevDigest}`,
          status: 'open',
        };
      }

      case 'sequence_gap': {
        const severity: TamperSeverity = 'warning';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [],
          affectedSequenceRange: {
            from: event.expectedSequence,
            to: event.foundSequence - 1,
          },
          details: `Sequence gap detected: expected sequence ${event.expectedSequence}, found ${event.foundSequence}`,
          status: 'open',
        };
      }

      case 'duplicate_sequence': {
        // Critical, unlike sequence_gap's warning. A gap can be a benign
        // deletion (a pruned test record, a botched migration); a DUPLICATE
        // sequence number cannot arise from ordinary operation at all — every
        // capture path assigns headSequence + 1 under a lock — so its presence
        // means a write reached the store outside the SDK.
        const severity: TamperSeverity = 'critical';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [event.evidenceId],
          affectedSequenceRange: {
            from: event.sequenceNumber,
            to: event.sequenceNumber,
          },
          details:
            `Duplicate or out-of-order sequence number on evidence record ` +
            `"${event.evidenceId}": sequence ${event.sequenceNumber} follows ` +
            `sequence ${event.previousSequence} in the chain.`,
          status: 'open',
        };
      }

      case 'digest_superseded': {
        // Critical: the record was rewritten after capture. It hashes to the
        // digest it carries — the digest was recomputed — so no check of the
        // store's present state can see it; the capture revision can.
        const severity: TamperSeverity = 'critical';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [event.evidenceId],
          affectedSequenceRange: {
            from: event.sequenceNumber,
            to: event.sequenceNumber,
          },
          details:
            `Evidence record "${event.evidenceId}" (sequence ${event.sequenceNumber}) is not the record ` +
            `that was captured: it was captured with digest ${event.capturedDigest} and now carries ` +
            `${event.currentDigest}. Its payload was rewritten and its digest recomputed after capture.`,
          status: 'open',
        };
      }

      case 'captured_at_regression': {
        // Warning, not critical. A capturedAt earlier than the record before
        // it is suspicious — backdating is the direction with legal value —
        // but an NTP correction produces one honestly, so the wording must not
        // assert tampering. It is for an operator to look at once.
        const severity: TamperSeverity = 'warning';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [event.evidenceId],
          affectedSequenceRange: {
            from: event.sequenceNumber,
            to: event.sequenceNumber,
          },
          details:
            `capturedAt on evidence record "${event.evidenceId}" (sequence ${event.sequenceNumber}) is ` +
            `${event.capturedAt}, earlier than the record before it in the chain. The capturing clock ` +
            `moved backwards between the two captures. This is not proof of tampering — a clock ` +
            `correction produces it honestly — and should be reviewed.`,
          status: 'open',
        };
      }

      case 'custody_trail_invalid': {
        // Critical: a custody entry is the record of who repaired or reviewed
        // what, and an altered one is the same class of finding as a
        // rewritten payload.
        const severity: TamperSeverity = 'critical';
        const where = event.failures
          .map((f) => {
            const at = [
              f.index !== undefined ? `custodyChain[${f.index}]` : null,
              'rowId' in f && f.rowId !== undefined ? `custody_entries row ${f.rowId}` : null,
            ]
              .filter((s) => s !== null)
              .join(', ');
            return at ? `${f.reason} (${at})` : f.reason;
          })
          .join('; ');
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [event.evidenceId],
          details: `Custody trail of evidence record "${event.evidenceId}" failed verification: ${where}`,
          status: 'open',
        };
      }

      case 'missing_record': {
        const severity: TamperSeverity = 'warning';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [],
          affectedSequenceRange: {
            from: event.sequenceNumber,
            to: event.sequenceNumber,
          },
          details: `Missing record at sequence number ${event.sequenceNumber}`,
          status: 'open',
        };
      }

      case 'attestation_invalid': {
        // The verifier's reason — and, for a capturedAt checked against its
        // token, the skew — is what tells a capturing clock that ran ahead
        // (`captured_after_timestamp`) from a token issued over some other
        // record (`imprint_mismatch`). Both go into the stored incident.
        const severity: TamperSeverity = 'warning';
        const why = event.reason ? `: ${event.reason}` : '';
        const skew =
          event.capturedAtSkewMs !== undefined ? ` — ${describeCapturedAtSkew(event.capturedAtSkewMs)}` : '';
        // What the chain counted as final, when a chain took part in an
        // anchor's verdict.
        const finality = event.anchorFinality !== undefined ? ` (${describeFinality(event.anchorFinality)})` : '';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [event.evidenceId],
          details:
            `Attestation component "${event.component}" failed verification for evidence record ` +
            `"${event.evidenceId}"${why}${skew}${finality}`,
          status: 'open',
        };
      }

      case 'attestation_unverifiable': {
        // Warning, like attestation_invalid — but a DIFFERENT incident type, so
        // the two never merge in an operator's list. The wording carries the
        // whole point: nothing here says the record is bad, because nothing
        // established that. The remedy is to upgrade the verifier or re-attest,
        // not to investigate a tampering.
        const severity: TamperSeverity = 'warning';
        const why = event.reason ? ` (${event.reason})` : '';
        return {
          id,
          detectedAt,
          severity,
          type: event.type,
          affectedRecords: [event.evidenceId],
          details:
            `Attestation component "${event.component}" on evidence record ` +
            `"${event.evidenceId}" could not be verified by this build${why}. ` +
            `The artifact is present; it was not checked, and it was not found bad.`,
          status: 'open',
        };
      }

      // AI-BOM descriptor catalog integrity.
      case 'descriptor_resolution_failure': {
        return {
          id,
          detectedAt,
          severity: AI_BOM_TAMPER_INCIDENT_SEVERITY.descriptor_resolution_failure,
          type: event.type,
          affectedRecords: [event.evidenceId],
          details: `Model descriptor "${event.modelDescriptorDigest}" referenced by evidence record "${event.evidenceId}" was not resolvable in the catalog.`,
          status: 'open',
        };
      }

      case 'descriptor_digest_mismatch': {
        return {
          id,
          detectedAt,
          severity: AI_BOM_TAMPER_INCIDENT_SEVERITY.descriptor_digest_mismatch,
          type: event.type,
          affectedRecords: [event.evidenceId],
          details: `Model descriptor digest mismatch on evidence record "${event.evidenceId}": claimed=${event.claimedDigest}, recomputed=${event.recomputedDigest}`,
          status: 'open',
        };
      }

      case 'parent_descriptor_resolution_failure': {
        const noteSuffix = event.note ? ` (${event.note})` : '';
        return {
          id,
          detectedAt,
          severity: AI_BOM_TAMPER_INCIDENT_SEVERITY.parent_descriptor_resolution_failure,
          type: event.type,
          affectedRecords: [event.evidenceId],
          details: `Parent model descriptor "${event.modelDescriptorDigest}" in the lineage of evidence record "${event.evidenceId}" was not resolvable${noteSuffix}.`,
          status: 'open',
        };
      }

      case 'parent_descriptor_digest_mismatch': {
        return {
          id,
          detectedAt,
          severity: AI_BOM_TAMPER_INCIDENT_SEVERITY.parent_descriptor_digest_mismatch,
          type: event.type,
          affectedRecords: [event.evidenceId],
          details: `Parent model descriptor digest mismatch in the lineage of evidence record "${event.evidenceId}": claimed=${event.claimedDigest}, recomputed=${event.recomputedDigest}`,
          status: 'open',
        };
      }

      // Evidence logs and anchoring (`anchor-log-checks.ts`).
      case 'digest_differs_from_logged_leaf': {
        // Critical: the leaf is written inside the transaction that stored
        // the record and the log is insert-only, so the record was rewritten
        // after it was logged.
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [event.evidenceId],
          affectedSequenceRange: { from: event.sequenceNumber, to: event.sequenceNumber },
          details:
            `Evidence record "${event.evidenceId}" (sequence ${event.sequenceNumber}) is not the record its ` +
            `evidence log ${event.origin} logged at its position: the log holds ${event.loggedDigest}, and the ` +
            `record now carries ${event.currentDigest}. It was rewritten after it was logged.`,
          status: 'open',
        };
      }

      case 'log_rewritten_below_anchor': {
        // Critical: anchored history no longer reproduces.
        const source = event.authenticated
          ? 'the root published on chain (the calldata of the publisher\'s transaction)'
          : 'the store\'s own anchored checkpoint (no chain was read, so the published value was not re-derived)';
        const where = event.leafRange ? ` The rewrite lies in leaves ${event.leafRange.from} to ${event.leafRange.to - 1}.` : '';
        const named = event.evidenceIds.length > 0 ? ` Records named through their embedded paths: ${[...event.evidenceIds].sort().join(', ')}.` : '';
        const tx = event.transactionId ? ` Transaction ${event.transactionId} (publication ${event.publicationId}).` : '';
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [...event.evidenceIds],
          ...(event.chainId !== null && event.leafRange && { affectedSequenceRange: leafSequenceRange(event.leafRange.from, event.leafRange.to) }),
          details:
            `The ${describeLog(event.origin, event.chainId)} no longer reproduces what was anchored at size ` +
            `${event.anchoredSize} (${event.reason}).\nChecked against ${source}.${where}${tx}${named}`,
          status: 'open',
        };
      }

      case 'log_truncated_below_anchor': {
        const head = event.lastSequence === null ? '' : `, and its chain head is at ${event.lastSequence}`;
        const reached = event.lastSequence === null ? event.logSize : Math.min(event.logSize, event.lastSequence);
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [],
          ...(event.chainId !== null && { affectedSequenceRange: leafSequenceRange(reached, event.anchoredSize) }),
          details:
            `The ${describeLog(event.origin, event.chainId)} was anchored at size ${event.anchoredSize}, and its ` +
            `anchored history was truncated.\nThe log now ends at size ${event.logSize}${head}.`,
          status: 'open',
        };
      }

      case 'log_inconsistent_with_anchor': {
        const pair = event.fromSize === null ? `size ${event.toSize}` : `sizes ${event.fromSize} and ${event.toSize}`;
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [],
          details:
            `The stored anchored checkpoints of the ${describeLog(event.origin, event.chainId)} are not one ` +
            `growing log at ${pair} (${event.reason}).`,
          status: 'open',
        };
      }

      case 'split_view': {
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [],
          details:
            `Two published checkpoints of the ${describeLog(event.origin, event.chainId)} state size ` +
            `${event.size} with different roots: the log was published with two histories.\n` +
            `The roots: ${[...event.roots].sort().join(', ')}.`,
          status: 'open',
        };
      }

      case 'anchor_wallet_nonce_unaccounted': {
        // Critical: someone else sends from the dedicated publisher wallet,
        // and whoever holds its key and the database can re-anchor history.
        const held =
          event.publicationId === null
            ? 'The store holds nothing at that nonce.'
            : `The store's publication ${event.publicationId} (epoch ${event.epochId}) holds the nonce, but none of the ` +
              'transactions it stores for it is the mined transaction the wallet signed with its anchor checkpoint.';
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [],
          details:
            `Nonce ${event.nonce} of the publisher wallet ${event.address} on ${event.chain} maps to no publication ` +
            `and no accounted transaction this store holds.\nAccounted from nonce ${event.nonceBase}. ${held}`,
          status: 'open',
        };
      }

      case 'anchor_stripped': {
        // Warning, like an attestation finding: the record's own content is
        // intact, and what was removed is an attestation of it.
        return {
          id,
          detectedAt,
          severity: 'warning',
          type: event.type,
          affectedRecords: [event.evidenceId],
          affectedSequenceRange: { from: event.sequenceNumber, to: event.sequenceNumber },
          details:
            `Evidence record "${event.evidenceId}" (sequence ${event.sequenceNumber}) carries no anchor, although ` +
            `the store finished filling the epoch of its evidence log ${event.origin} that anchors it. The anchor ` +
            `was removed.`,
          status: 'open',
        };
      }

      case 'anchor_transplanted': {
        // Warning, like anchor_stripped: the record's own content is intact,
        // and what is wrong is its attestation, which was made for another
        // record.
        return {
          id,
          detectedAt,
          severity: 'warning',
          type: event.type,
          affectedRecords: [event.evidenceId],
          affectedSequenceRange: { from: event.sequenceNumber, to: event.sequenceNumber },
          details:
            `Evidence record "${event.evidenceId}" (sequence ${event.sequenceNumber}) carries an anchor made for ` +
            `another record: it names leaf ${event.artifactLeafIndex} of ${event.artifactOrigin}, and the record is ` +
            `leaf ${event.sequenceNumber - 1} of its evidence log ${event.origin}.`,
          status: 'open',
        };
      }

      case 'anchor_overdue': {
        // Warning: an anchoring delay, not a finding about the evidence.
        // Named by the oldest waiting record, so the incident stays one while
        // that record waits.
        return {
          id,
          detectedAt,
          severity: 'warning',
          type: event.type,
          affectedRecords: [event.evidenceId],
          affectedSequenceRange: { from: event.leafIndex + 1, to: event.leafIndex + 1 },
          details:
            `The oldest record of ${describeLog(event.origin, event.chainId)} without an anchor, "${event.evidenceId}" ` +
            `(logged ${event.loggedAt}), has waited longer than ${event.maxStalenessMs} ms for one (${event.reason}).`,
          status: 'open',
        };
      }

      // A record a conforming writer would have refused, whose bytes are as
      // captured: not tampering, so a warning.
      case 'record_rule_violated': {
        return {
          id,
          detectedAt,
          severity: 'warning',
          type: event.type,
          affectedRecords: [event.evidenceId],
          details: `Evidence record "${event.evidenceId}" breaks the record rule ${event.rule} (${event.reason}); a conforming writer refuses such a record.`,
          status: 'open',
        };
      }

      // Mandate consumption (Record §9.10): a slot held twice, a slot
      // held by no record, or a running total that does not step by the
      // record's own value. Each means a record under the mandate was added,
      // removed or rewritten outside the claim.
      case 'mandate_slot_duplicate': {
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [...event.evidenceIds],
          details:
            `Mandate ${event.mandateDigest}: slot ${event.slot} is held by ${event.evidenceIds.length} records.\n` +
            `Records: ${event.evidenceIds.join(', ')}`,
          status: 'open',
        };
      }

      case 'mandate_slot_gap': {
        const unexplained = Object.entries(event.unexplained).map(([cap, amount]) => `${cap}=${amount}`).join(', ');
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [],
          details:
            `Mandate ${event.mandateDigest}: slots ${event.from} to ${event.to} are held by no record.\n` +
            `Unexplained movement of the running totals: ${unexplained === '' ? 'none' : unexplained}`,
          status: 'open',
        };
      }

      case 'mandate_totals_unexplained': {
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [],
          details:
            `Mandate ${event.mandateDigest}: the running total of cap ${event.cap} at slot ${event.slot} does not step by the record's own value.\n` +
            `Expected ${event.expected}, found ${event.actual}.`,
          status: 'open',
        };
      }

      // A decider freshness reference that names no canonical block: a
      // reference planted through the shared row.
      case 'freshness_reference_invalid': {
        return {
          id,
          detectedAt,
          severity: 'critical',
          type: event.type,
          affectedRecords: [event.evidenceId],
          details: `Evidence record "${event.evidenceId}" carries the freshness reference ${event.reference}, which is not the canonical block at that height on the anchoring chain.`,
          status: 'open',
        };
      }

      // Informational events — no incident created.
      case 'record_verified':
      case 'scan_completed':
      case 'chain_relinked':
      case 'chain_forked':
      case 'incident_annotated':
        return null;

      default: {
        // Exhaustiveness guard — TypeScript narrows to `never` here.
        const _exhaustive: never = event;
        return null;
      }
    }
  }
}
