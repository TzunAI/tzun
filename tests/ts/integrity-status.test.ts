import {
  NO_INCIDENTS,
  attestationCoverageFromScan,
  computeIntegrityStatus,
} from '../../src/api/integrity-status';
import { MemoryStorageAdapter } from '../../src/storage/memory';
import { ScannerState, ScanSummary, TamperIncident } from '@tzun/engine';

// Unit tests for the pure derivation in computeIntegrityStatus. The memory
// adapter is used because the only storage calls here are listIncidents() and
// getChainLength(), and the derivation is what is under test. The same
// contract driven over HTTP against SQLite and Postgres — with the SDK's own
// scanner doing the measuring — is tests/ts/integrity-status-measured.test.ts.

function makeIncident(overrides: Partial<TamperIncident> = {}): TamperIncident {
  return {
    id: overrides.id ?? 'inc-001',
    detectedAt: overrides.detectedAt ?? '2026-04-04T12:00:00Z',
    severity: overrides.severity ?? 'critical',
    type: overrides.type ?? 'digest_mismatch',
    affectedRecords: overrides.affectedRecords ?? ['ev-001'],
    affectedSequenceRange: overrides.affectedSequenceRange ?? { from: 1, to: 1 },
    details: overrides.details ?? 'Digest mismatch on ev-001',
    status: overrides.status ?? 'open',
    // Copied rather than defaulted: absent means no scan has ever observed this
    // finding, which is a distinct, meaningful state (pre-0.4.6 rows).
    lastObservedAt: overrides.lastObservedAt,
  };
}

function makeSummary(overrides: Partial<ScanSummary> = {}): ScanSummary {
  return {
    passNumber: 1,
    startedAt: '2026-04-04T11:54:00Z',
    completedAt: '2026-04-04T11:55:00Z',
    durationMs: 60_000,
    recordsChecked: 4,
    issuesFound: 0,
    digestMismatches: 0,
    chainBreaks: 0,
    sequenceGaps: 0,
    duplicateSequences: 0,
    attestationFailures: 0,
    attestationPresence: { timestamp: 2, signature: 1, anchor: 0 },
    // A scanner with verifyAttestation on and no credential store / anchor
    // verifier: timestamps verified, the other two not measured.
    attestationValid: { timestamp: 2, signature: null, anchor: null },
    ...overrides,
  };
}

/** A scanner that has completed one pass and is idle. */
function scannedState(summary: ScanSummary = makeSummary()): ScannerState {
  return {
    currentPassStartedAt: null,
    lastCompletedPassAt: summary.completedAt,
    lastCompletedPass: summary,
    totalPasses: summary.passNumber,
    highWaterMark: summary.recordsChecked,
    segmentsInProgress: [],
  };
}

/** A scanner that is configured but has never completed a pass. */
function unscannedState(): ScannerState {
  return {
    currentPassStartedAt: null,
    lastCompletedPassAt: null,
    lastCompletedPass: null,
    totalPasses: 0,
    highWaterMark: 0,
    segmentsInProgress: [],
  };
}

describe('computeIntegrityStatus', () => {
  let storage: MemoryStorageAdapter;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  describe('chainStatus is unknown until something has measured the store', () => {
    it('reports unknown, not healthy, for a store nothing has scanned', async () => {
      // A store nothing has looked at has no open incidents, so a status
      // derived from open incidents alone would answer 'healthy' on every
      // fresh deployment's first request. 'unknown' is the state for "never
      // looked".
      const status = await computeIntegrityStatus({
        storage,
        scannerState: null,
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('unknown');
      expect(status.totalRecords).toBe(0);
      expect(status.activeChainId).toBe('chain-001');
      expect(status.sealedChains).toBe(0);
      expect(status.incidents).toEqual(NO_INCIDENTS);
      expect(status.lastFullScanAt).toBeNull();
      expect(status.lastFullScanDuration).toBeNull();
      expect(status.lastFullScan).toBeNull();
      expect(status.attestationCoverage).toBeNull();
      expect(status.scannerRunning).toBe(false);
      expect(status.pendingAttestations).toBe(0);
    });

    it('stays unknown when a scanner is configured but has not completed a pass', async () => {
      const status = await computeIntegrityStatus({
        storage,
        scannerState: unscannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('unknown');
      expect(status.lastFullScanAt).toBeNull();
      expect(status.lastFullScanDuration).toBeNull();
      expect(status.attestationCoverage).toBeNull();
    });

    it('stays unknown when every incident is resolved but nothing has scanned', async () => {
      // Resolved incidents say the past trouble was dealt with; they do not
      // say anyone has verified the store since. Only a completed pass says
      // that.
      //
      // The resolved incident carries no `lastObservedAt`: nothing has scanned,
      // so no pass has seen its finding still standing, and it is counted in
      // neither direction. An acknowledged incident is unresolved, not
      // resolved; it has a case of its own below.
      await storage.storeIncident(makeIncident({ id: 'inc-001', status: 'resolved', severity: 'critical' }));

      const status = await computeIntegrityStatus({
        storage,
        scannerState: null,
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('unknown');
      expect(status.incidents).toEqual(NO_INCIDENTS);
    });
  });

  describe('healthy is reachable only from a completed pass', () => {
    it('reports healthy after a completed pass with no open incidents', async () => {
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('healthy');
      expect(status.lastFullScanAt).toBe('2026-04-04T11:55:00Z');
    });

    it('reports healthy after a completed pass when every incident is resolved and none is still observed', async () => {
      await storage.storeIncident(makeIncident({ id: 'inc-001', status: 'resolved', severity: 'critical' }));

      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('healthy');
      expect(status.incidents).toEqual(NO_INCIDENTS);
    });

    it('is unknown, not healthy, when the last pass found issues that no open incident accounts for', async () => {
      // Healthy means no open incidents AND a clean last scan. The pass
      // found a digest mismatch; the incident it raised is either still on
      // its way to storage (TamperDetector persists after the pass returns —
      // on Postgres the row lands after `runScan()` resolves) or was resolved
      // without anyone re-scanning. Either way nobody has verified the store
      // clean since, and 'healthy' beside `lastFullScan.digestMismatches: 1`
      // is the endpoint contradicting its own summary.
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(makeSummary({ issuesFound: 1, digestMismatches: 1 })),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('unknown');
      expect(status.incidents).toEqual(NO_INCIDENTS);
      expect(status.lastFullScan!.issuesFound).toBe(1);
    });

    it('stays unknown after the incident a dirty pass raised is resolved, until a clean pass completes', async () => {
      await storage.storeIncident(makeIncident({ id: 'inc-001', status: 'resolved', severity: 'critical' }));

      const afterResolve = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(makeSummary({ passNumber: 1, issuesFound: 1, digestMismatches: 1 })),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });
      expect(afterResolve.chainStatus).toBe('unknown');

      const afterRescan = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(makeSummary({ passNumber: 2, issuesFound: 0 })),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });
      expect(afterRescan.chainStatus).toBe('healthy');
    });
  });

  describe('unresolved findings outrank the scan', () => {
    // 'open', 'acknowledged' and 'in_progress' are ONE group. Counting
    // `status: 'open'` alone would let acknowledging a store's last finding —
    // or merely beginning a recovery on it, which the hosted service records
    // as 'in_progress' — take the store off 'compromised' with the rewritten
    // record exactly where it was.
    it.each(['open', 'acknowledged', 'in_progress'] as const)(
      'returns compromised for an integrity finding that is %s, scanned or not',
      async (incidentStatus) => {
        await storage.storeIncident(
          makeIncident({ id: 'inc-001', status: incidentStatus, severity: 'critical' }),
        );

        for (const scannerState of [null, unscannedState(), scannedState()]) {
          const status = await computeIntegrityStatus({
            storage,
            scannerState,
            activeChainId: 'chain-001',
            sealedChains: 0,
          });
          expect(status.chainStatus).toBe('compromised');
          expect(status.incidents).toEqual({
            unresolvedIntegrity: 1,
            unresolvedOther: 0,
            reviewedStillObserved: 0,
          });
        }
      },
    );

    // A gap and a missing record are integrity findings even though this SDK's
    // three-value scale calls them 'warning' — the platform rates both 'high'.
    // Classification is by TYPE for exactly this reason.
    it.each(['sequence_gap', 'missing_record'] as const)(
      'returns compromised for an open %s, which this SDK rates only "warning"',
      async (type) => {
        await storage.storeIncident(
          makeIncident({ id: 'inc-001', status: 'open', severity: 'warning', type }),
        );

        const status = await computeIntegrityStatus({
          storage,
          scannerState: scannedState(),
          activeChainId: 'chain-001',
          sealedChains: 0,
        });

        expect(status.chainStatus).toBe('compromised');
        expect(status.incidents.unresolvedIntegrity).toBe(1);
      },
    );

    it('returns degraded for open findings below that — an attestation that would not verify', async () => {
      await storage.storeIncident(
        makeIncident({ id: 'inc-001', status: 'open', severity: 'warning', type: 'attestation_invalid' }),
      );
      await storage.storeIncident(
        makeIncident({ id: 'inc-002', status: 'open', severity: 'warning', type: 'captured_at_regression' }),
      );

      for (const scannerState of [null, scannedState()]) {
        const status = await computeIntegrityStatus({
          storage,
          scannerState,
          activeChainId: 'chain-001',
          sealedChains: 0,
        });
        expect(status.chainStatus).toBe('degraded');
        expect(status.incidents).toEqual({
          unresolvedIntegrity: 0,
          unresolvedOther: 2,
          reviewedStillObserved: 0,
        });
      }
    });

    // The evidence-log findings that say the evidence, or what was anchored of
    // it, is not intact — by type, whatever the severity.
    it.each([
      'digest_differs_from_logged_leaf',
      'log_rewritten_below_anchor',
      'log_truncated_below_anchor',
      'log_inconsistent_with_anchor',
      'split_view',
      'anchor_wallet_nonce_unaccounted',
    ] as const)('returns compromised for an open %s', async (type) => {
      await storage.storeIncident(makeIncident({ id: 'inc-001', status: 'open', severity: 'warning', type }));
      const status = await computeIntegrityStatus({ storage, scannerState: scannedState(), activeChainId: 'chain-001', sealedChains: 0 });
      expect(status.chainStatus).toBe('compromised');
    });

    it.each(['anchor_stripped', 'anchor_transplanted', 'anchor_overdue'] as const)('returns degraded for an open %s: a finding to review', async (type) => {
      await storage.storeIncident(makeIncident({ id: 'inc-001', status: 'open', severity: 'warning', type }));
      const status = await computeIntegrityStatus({ storage, scannerState: scannedState(), activeChainId: 'chain-001', sealedChains: 0 });
      expect(status.chainStatus).toBe('degraded');
    });

    it('returns degraded when only an open descriptor-resolution failure exists', async () => {
      await storage.storeIncident(
        makeIncident({
          id: 'inc-001',
          status: 'open',
          severity: 'info',
          type: 'descriptor_resolution_failure',
        }),
      );

      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('degraded');
      expect(status.incidents.unresolvedOther).toBe(1);
    });
  });

  // A finding a human reviewed, that is still there, keeps the store off
  // 'healthy'.
  describe('a reviewed finding that is still observed holds the store at degraded', () => {
    const reviewed = (lastObservedAt: string): TamperIncident =>
      makeIncident({ id: 'inc-rev', status: 'resolved', severity: 'critical', lastObservedAt });

    it('is degraded when the last completed pass observed it again', async () => {
      // scannedState()'s summary started at 11:54; the pass saw the finding at
      // 11:54:30, so the review did not make it go away.
      await storage.storeIncident(reviewed('2026-04-04T11:54:30Z'));

      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('degraded');
      expect(status.incidents).toEqual({
        unresolvedIntegrity: 0,
        unresolvedOther: 0,
        reviewedStillObserved: 1,
      });
    });

    it('is healthy once a later pass no longer observes it', async () => {
      // The observation is frozen before this pass began, so this pass looked
      // and did not find it.
      await storage.storeIncident(reviewed('2026-04-04T11:54:30Z'));

      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(makeSummary({ passNumber: 2, startedAt: '2026-04-04T12:10:00Z' })),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('healthy');
      expect(status.incidents).toEqual(NO_INCIDENTS);
    });

    it('counts an observed reviewed finding when no pass has completed at all', async () => {
      // Nothing has re-checked the store, so the finding cannot be claimed gone.
      // Degraded, not 'unknown': this is known precisely.
      await storage.storeIncident(reviewed('2026-04-04T11:54:30Z'));

      const status = await computeIntegrityStatus({
        storage,
        scannerState: null,
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('degraded');
      expect(status.incidents.reviewedStillObserved).toBe(1);
    });

    it('ignores a resolved incident raised before observations were recorded', async () => {
      // No `lastObservedAt` at all: pre-0.4.6. Counted in neither direction —
      // inventing an observation would claim a scan saw it when none was looking.
      await storage.storeIncident(
        makeIncident({ id: 'inc-old', status: 'resolved', severity: 'critical' }),
      );

      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('healthy');
      expect(status.incidents).toEqual(NO_INCIDENTS);
    });

    it('an unresolved integrity finding still outranks a reviewed one', async () => {
      await storage.storeIncident(reviewed('2026-04-04T11:54:30Z'));
      await storage.storeIncident(
        makeIncident({ id: 'inc-open', status: 'open', severity: 'critical', affectedRecords: ['ev-002'] }),
      );

      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('compromised');
      expect(status.incidents).toEqual({
        unresolvedIntegrity: 1,
        unresolvedOther: 0,
        reviewedStillObserved: 1,
      });
    });
  });

  describe('scanner state', () => {
    it('includes scanner state when scanner is running', async () => {
      const scannerState: ScannerState = {
        currentPassStartedAt: '2026-04-04T12:00:00Z',
        lastCompletedPassAt: '2026-04-04T11:55:00Z',
        lastCompletedPass: makeSummary(),
        totalPasses: 5,
        highWaterMark: 1000,
        segmentsInProgress: [{ from: 500, to: 750 }],
      };

      const status = await computeIntegrityStatus({
        storage,
        scannerState,
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.scannerRunning).toBe(true);
      expect(status.lastFullScanAt).toBe('2026-04-04T11:55:00Z');
    });

    it('scannerRunning is false when scanner state has no segments in progress', async () => {
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.scannerRunning).toBe(false);
    });

    it('scannerRunning is false when a pass has a start time but no segment in flight', async () => {
      // Segments, not the start timestamp, are what "running" means: between
      // a pass's first line and its first segment, and after its last segment
      // has finished, `currentPassStartedAt` is set and nothing is in flight.
      const status = await computeIntegrityStatus({
        storage,
        scannerState: { ...scannedState(), currentPassStartedAt: '2026-04-04T12:00:00Z' },
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.scannerRunning).toBe(false);
    });
  });

  describe('the last completed pass is what gets reported', () => {
    it('lastFullScanDuration and lastFullScan come from the last completed pass', async () => {
      // Both come from the scanner's last completed pass: how long it took,
      // and the summary of what it found.
      const summary = makeSummary({ durationMs: 1234, recordsChecked: 9, issuesFound: 2, digestMismatches: 2 });
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(summary),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.lastFullScanDuration).toBe(1234);
      expect(status.lastFullScan).toEqual(summary);
    });

    it('attestationCoverage is the percentage of checked records whose artifact the pass VERIFIED', async () => {
      // Coverage is verified-valid over checked (2 of 4 timestamps valid: 50),
      // and a component the pass did not verify is null, not a presence
      // figure. The name means "percentage with VALID timestamps"; derived
      // from presence instead (3 of 4 records CARRY a token: 75), a store
      // whose every token is a captive-portal page would report 100%.
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(makeSummary({
          recordsChecked: 4,
          attestationPresence: { timestamp: 3, signature: 1, anchor: 2 },
          attestationValid: { timestamp: 2, signature: null, anchor: 0 },
        })),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.attestationCoverage).toEqual({ timestamp: 50, signature: null, anchor: 0 });
      // Presence is still served, under its own name.
      expect(status.lastFullScan!.attestationPresence).toEqual({ timestamp: 3, signature: 1, anchor: 2 });
    });

    it('attestationCoverage is null per component when the pass verified nothing, not 0%', async () => {
      // verifyAttestation: false. Three artifacts are present; none was
      // looked at. Null is "not measured"; 0 would be "measured, none valid".
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(makeSummary({
          recordsChecked: 4,
          attestationPresence: { timestamp: 3, signature: 1, anchor: 2 },
          attestationValid: { timestamp: null, signature: null, anchor: null },
        })),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.attestationCoverage).toEqual({ timestamp: null, signature: null, anchor: null });
    });

    it('attestationCoverage is null when the pass checked no records', async () => {
      // A percentage of nothing is not 0%.
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(makeSummary({
          recordsChecked: 0,
          attestationPresence: { timestamp: 0, signature: 0, anchor: 0 },
          attestationValid: { timestamp: 0, signature: null, anchor: null },
        })),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.chainStatus).toBe('healthy');
      expect(status.attestationCoverage).toBeNull();
    });

    it('attestationCoverage is null when the pass reported no validity, even though it counted presence', async () => {
      // An older producer that counted presence but not validity must not
      // have its presence served as coverage.
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(makeSummary({
          attestationPresence: { timestamp: 4, signature: 4, anchor: 4 },
          attestationValid: undefined,
        })),
        activeChainId: 'chain-001',
        sealedChains: 0,
      });

      expect(status.attestationCoverage).toBeNull();
    });

    it('a caller-measured attestationCoverage overrides the scan-derived figure', async () => {
      const status = await computeIntegrityStatus({
        storage,
        scannerState: scannedState(),
        activeChainId: 'chain-001',
        sealedChains: 0,
        attestationCoverage: {
          timestamp: 95.5,
          signature: 0,
          anchor: 10.2,
        },
      });

      expect(status.attestationCoverage).toEqual({ timestamp: 95.5, signature: 0, anchor: 10.2 });
    });
  });

  describe('attestationCoverageFromScan', () => {
    it('is null for no pass', () => {
      expect(attestationCoverageFromScan(null)).toBeNull();
    });

    it('divides verified-valid by records checked, null per component the pass did not verify', () => {
      expect(
        attestationCoverageFromScan(makeSummary({
          recordsChecked: 3,
          attestationPresence: { timestamp: 2, signature: 0, anchor: 1 },
          attestationValid: { timestamp: 1, signature: null, anchor: 1 },
        })),
      ).toEqual({ timestamp: (1 / 3) * 100, signature: null, anchor: (1 / 3) * 100 });
    });

    it('never serves presence as coverage', () => {
      // Every record carries every artifact; the pass verified none of the
      // timestamps as valid and could not check the other two.
      expect(
        attestationCoverageFromScan(makeSummary({
          recordsChecked: 3,
          attestationPresence: { timestamp: 3, signature: 3, anchor: 3 },
          attestationValid: { timestamp: 0, signature: null, anchor: null },
        })),
      ).toEqual({ timestamp: 0, signature: null, anchor: null });
    });
  });

  it('counts pending attestations', async () => {
    const status = await computeIntegrityStatus({
      storage,
      scannerState: null,
      activeChainId: 'chain-001',
      sealedChains: 0,
      pendingAttestations: 3,
    });

    expect(status.pendingAttestations).toBe(3);
  });

  it('sealedChains count is passed through', async () => {
    const status = await computeIntegrityStatus({
      storage,
      scannerState: null,
      activeChainId: 'chain-002',
      sealedChains: 3,
    });

    expect(status.sealedChains).toBe(3);
    expect(status.activeChainId).toBe('chain-002');
  });

  it('totalRecords reflects the last sequence number', async () => {
    const status = await computeIntegrityStatus({
      storage,
      scannerState: null,
      activeChainId: 'chain-001',
      sealedChains: 0,
      totalRecords: 42,
    });

    expect(status.totalRecords).toBe(42);
  });
});
