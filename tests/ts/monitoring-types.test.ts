/**
 * Type-validation tests for the monitoring subsystem.
 *
 * Each test constructs a valid instance of a monitoring type and asserts
 * that the expected fields are present and typed correctly. These tests
 * also serve as living documentation for how each type is used.
 */

import type {
  MonitoringEvent,
  MonitoringEventType,
  MonitoringEventHandler,
  TamperIncident,
  TamperSeverity,
  TamperIncidentStatus,
  ScannerConfig,
  ScannerMode,
  ScannerState,
  ScanSummary,
  NotificationConfig,
  NotificationChannel,
  MonitoringConfig,
  DeduplicationEntry,
  DigestMismatchEvent,
  ChainBreakEvent,
  SequenceGapEvent,
  MissingRecordEvent,
  AttestationInvalidEvent,
  RecordVerifiedEvent,
  ScanCompletedEvent,
  ChainRelinkedEvent,
  ChainForkedEvent,
} from '@tzun/engine';

// ---------------------------------------------------------------------------
// MonitoringEvent variants
// ---------------------------------------------------------------------------

describe('MonitoringEvent — digest_mismatch', () => {
  it('accepts a valid DigestMismatchEvent', () => {
    const event: DigestMismatchEvent = {
      type: 'digest_mismatch',
      evidenceId: 'deo-001',
      stored: 'abc123',
      recomputed: 'def456',
    };

    expect(event.type).toBe('digest_mismatch');
    expect(event.evidenceId).toBe('deo-001');
    expect(event.stored).toBe('abc123');
    expect(event.recomputed).toBe('def456');
  });
});

describe('MonitoringEvent — chain_break', () => {
  it('accepts a valid ChainBreakEvent', () => {
    const event: ChainBreakEvent = {
      type: 'chain_break',
      evidenceId: 'deo-002',
      sequenceNumber: 42,
      expectedPrevDigest: 'prevhash999',
    };

    expect(event.type).toBe('chain_break');
    expect(event.sequenceNumber).toBe(42);
    expect(event.expectedPrevDigest).toBe('prevhash999');
  });
});

describe('MonitoringEvent — sequence_gap', () => {
  it('accepts a valid SequenceGapEvent', () => {
    const event: SequenceGapEvent = {
      type: 'sequence_gap',
      expectedSequence: 10,
      foundSequence: 12,
    };

    expect(event.type).toBe('sequence_gap');
    expect(event.expectedSequence).toBe(10);
    expect(event.foundSequence).toBe(12);
  });
});

describe('MonitoringEvent — missing_record', () => {
  it('accepts a valid MissingRecordEvent', () => {
    const event: MissingRecordEvent = {
      type: 'missing_record',
      sequenceNumber: 7,
    };

    expect(event.type).toBe('missing_record');
    expect(event.sequenceNumber).toBe(7);
  });
});

describe('MonitoringEvent — attestation_invalid', () => {
  it('accepts a valid AttestationInvalidEvent for each component', () => {
    const timestamp: AttestationInvalidEvent = {
      type: 'attestation_invalid',
      evidenceId: 'deo-003',
      component: 'timestamp',
    };
    const signature: AttestationInvalidEvent = {
      type: 'attestation_invalid',
      evidenceId: 'deo-003',
      component: 'signature',
    };
    const anchor: AttestationInvalidEvent = {
      type: 'attestation_invalid',
      evidenceId: 'deo-003',
      component: 'anchor',
    };

    expect(timestamp.component).toBe('timestamp');
    expect(signature.component).toBe('signature');
    expect(anchor.component).toBe('anchor');
  });
});

describe('MonitoringEvent — record_verified', () => {
  it('accepts a valid RecordVerifiedEvent', () => {
    const event: RecordVerifiedEvent = {
      type: 'record_verified',
      evidenceId: 'deo-004',
    };

    expect(event.type).toBe('record_verified');
    expect(event.evidenceId).toBe('deo-004');
  });
});

describe('MonitoringEvent — scan_completed', () => {
  it('accepts a valid ScanCompletedEvent', () => {
    const event: ScanCompletedEvent = {
      type: 'scan_completed',
      recordsChecked: 500,
      issuesFound: 3,
      durationMs: 42,
      digestMismatches: 1,
      chainBreaks: 1,
      sequenceGaps: 1,
      attestationFailures: 0,
    };

    expect(event.type).toBe('scan_completed');
    expect(event.recordsChecked).toBe(500);
    expect(event.issuesFound).toBe(3);
    expect(event.durationMs).toBe(42);
    expect(event.digestMismatches).toBe(1);
    expect(event.chainBreaks).toBe(1);
    expect(event.sequenceGaps).toBe(1);
    expect(event.attestationFailures).toBe(0);
  });
});

describe('MonitoringEvent — chain_relinked', () => {
  it('accepts a valid ChainRelinkedEvent', () => {
    const event: ChainRelinkedEvent = {
      type: 'chain_relinked',
      incidentId: 'inc-001',
      relinkId: 'rlk-001',
      fromSequence: 10,
      toSequence: 20,
      authorizedBy: 'admin@example.com',
      modifiedCount: 5,
      timestamp: '2026-04-04T10:00:00Z',
    };

    expect(event.type).toBe('chain_relinked');
    expect(event.fromSequence).toBe(10);
    expect(event.toSequence).toBe(20);
    expect(event.authorizedBy).toBe('admin@example.com');
  });
});

describe('MonitoringEvent — chain_forked', () => {
  it('accepts a valid ChainForkedEvent', () => {
    const event: ChainForkedEvent = {
      type: 'chain_forked',
      incidentId: 'inc-002',
      forkId: 'frk-001',
      oldChainId: 'chain-alpha',
      newChainId: 'chain-beta',
      forkPoint: 99,
      authorizedBy: 'cto@example.com',
      timestamp: '2026-04-04T10:00:00Z',
    };

    expect(event.type).toBe('chain_forked');
    expect(event.oldChainId).toBe('chain-alpha');
    expect(event.newChainId).toBe('chain-beta');
    expect(event.forkPoint).toBe(99);
  });
});

// ---------------------------------------------------------------------------
// TamperIncident
// ---------------------------------------------------------------------------

describe('TamperIncident', () => {
  it('accepts a minimal open incident without optional fields', () => {
    const incident: TamperIncident = {
      id: 'inc-001',
      detectedAt: '2026-04-04T10:00:00.000Z',
      severity: 'critical',
      type: 'digest_mismatch',
      affectedRecords: ['deo-001', 'deo-002'],
      details: 'Recomputed digest differs from stored value.',
      status: 'open',
    };

    expect(incident.id).toBe('inc-001');
    expect(incident.severity).toBe('critical');
    expect(incident.type).toBe('digest_mismatch');
    expect(incident.affectedRecords).toHaveLength(2);
    expect(incident.status).toBe('open');
    expect(incident.resolvedAt).toBeUndefined();
  });

  it('accepts a resolved incident with all optional fields', () => {
    const incident: TamperIncident = {
      id: 'inc-002',
      detectedAt: '2026-04-04T08:00:00.000Z',
      severity: 'warning',
      type: 'chain_break',
      affectedRecords: ['deo-010'],
      affectedSequenceRange: { from: 10, to: 10 },
      details: 'Chain link mismatch at sequence 10.',
      status: 'resolved',
      resolvedAt: '2026-04-04T09:30:00.000Z',
      resolvedBy: 'operator@example.com',
      resolutionNotes: 'Re-linked chain under CAB approval.',
    };

    expect(incident.status).toBe('resolved');
    expect(incident.affectedSequenceRange?.from).toBe(10);
    expect(incident.resolvedBy).toBe('operator@example.com');
  });
});

// ---------------------------------------------------------------------------
// ScannerConfig
// ---------------------------------------------------------------------------

describe('ScannerConfig', () => {
  it('accepts a valid interval-mode scanner config', () => {
    const config: ScannerConfig = {
      batchSize: 100,
      workers: 4,
      mode: 'interval',
      intervalMs: 60_000,
      verifyAttestation: true,
      verifyChainCompleteness: true,
    };

    expect(config.mode).toBe('interval');
    expect(config.intervalMs).toBe(60_000);
    expect(config.workers).toBe(4);
  });

  it('accepts a continuous-mode scanner config without intervalMs', () => {
    const config: ScannerConfig = {
      batchSize: 50,
      workers: 2,
      mode: 'continuous',
      verifyAttestation: false,
      verifyChainCompleteness: true,
    };

    expect(config.mode).toBe('continuous');
    expect(config.intervalMs).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// ScannerState
// ---------------------------------------------------------------------------

describe('ScannerState', () => {
  it('accepts a state with an in-progress pass', () => {
    const state: ScannerState = {
      currentPassStartedAt: '2026-04-04T12:00:00.000Z',
      lastCompletedPassAt: '2026-04-04T11:55:00.000Z',
      lastCompletedPass: {
        passNumber: 17,
        startedAt: '2026-04-04T11:50:00.000Z',
        completedAt: '2026-04-04T11:55:00.000Z',
        durationMs: 300_000,
        recordsChecked: 1_234,
        issuesFound: 0,
        digestMismatches: 0,
        chainBreaks: 0,
        sequenceGaps: 0,
        duplicateSequences: 0,
        attestationFailures: 0,
        attestationPresence: { timestamp: 1_234, signature: 0, anchor: 12 },
      },
      totalPasses: 17,
      highWaterMark: 1_234,
      segmentsInProgress: [
        { from: 1_200, to: 1_250 },
        { from: 1_251, to: 1_300 },
      ],
    };

    expect(state.totalPasses).toBe(17);
    expect(state.highWaterMark).toBe(1_234);
    expect(state.segmentsInProgress).toHaveLength(2);
  });

  it('accepts an idle state with null timestamps', () => {
    const state: ScannerState = {
      currentPassStartedAt: null,
      lastCompletedPassAt: null,
      lastCompletedPass: null,
      totalPasses: 0,
      highWaterMark: 0,
      segmentsInProgress: [],
    };

    expect(state.currentPassStartedAt).toBeNull();
    expect(state.lastCompletedPass).toBeNull();
    expect(state.segmentsInProgress).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// ScanSummary
// ---------------------------------------------------------------------------

describe('ScanSummary', () => {
  it('accepts a valid scan summary with zero issues', () => {
    const summary: ScanSummary = {
      passNumber: 5,
      startedAt: '2026-04-04T11:00:00.000Z',
      completedAt: '2026-04-04T11:04:30.000Z',
      durationMs: 270_000,
      recordsChecked: 2_500,
      issuesFound: 0,
      digestMismatches: 0,
      chainBreaks: 0,
      sequenceGaps: 0,
      attestationFailures: 0,
    };

    expect(summary.passNumber).toBe(5);
    expect(summary.recordsChecked).toBe(2_500);
    expect(summary.issuesFound).toBe(0);
    expect(summary.durationMs).toBe(270_000);
  });
});

// ---------------------------------------------------------------------------
// NotificationConfig
// ---------------------------------------------------------------------------

describe('NotificationConfig', () => {
  it('accepts a config with all four channels configured', () => {
    const config: NotificationConfig = {
      webhook: {
        url: 'https://hooks.example.com/tzun',
        secret: 'supersecret',
        timeoutMs: 3_000,
      },
      slack: {
        webhookUrl: 'https://hooks.slack.com/services/XXX/YYY/ZZZ',
        username: 'TzunMonitor',
        iconEmoji: ':shield:',
      },
      pagerduty: {
        integrationKey: 'pagerduty-routing-key',
      },
      email: {
        host: 'smtp.example.com',
        port: 587,
        secure: true,
        auth: { user: 'alerts@example.com', pass: 'smtp-pass' },
        from: 'alerts@example.com',
        to: ['oncall@example.com'],
        subjectPrefix: '[Tzun]',
      },
    };

    expect(config.webhook?.url).toBe('https://hooks.example.com/tzun');
    expect(config.slack?.username).toBe('TzunMonitor');
    expect(config.pagerduty?.integrationKey).toBe('pagerduty-routing-key');
    expect(config.email?.to).toContain('oncall@example.com');
  });

  it('accepts a config with only webhook defined', () => {
    const config: NotificationConfig = {
      webhook: { url: 'https://hooks.example.com/minimal' },
    };

    expect(config.slack).toBeUndefined();
    expect(config.pagerduty).toBeUndefined();
    expect(config.email).toBeUndefined();
    expect(config.webhook?.timeoutMs).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// MonitoringConfig
// ---------------------------------------------------------------------------

describe('MonitoringConfig', () => {
  it('accepts an enabled config with scanner and notifications', () => {
    const config: MonitoringConfig = {
      enabled: true,
      scanner: {
        batchSize: 200,
        workers: 8,
        mode: 'continuous',
        verifyAttestation: true,
        verifyChainCompleteness: true,
      },
      notifications: {
        slack: {
          webhookUrl: 'https://hooks.slack.com/services/A/B/C',
          severities: ['critical', 'warning'],
        },
      },
    };

    expect(config.enabled).toBe(true);
    expect(config.scanner?.workers).toBe(8);
    expect(config.notifications?.slack?.webhookUrl).toContain('slack.com');
  });

  it('accepts a disabled config with only required fields', () => {
    const config: MonitoringConfig = {
      enabled: false,
    };

    expect(config.enabled).toBe(false);
    expect(config.scanner).toBeUndefined();
    expect(config.notifications).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// NotificationChannel interface shape
// ---------------------------------------------------------------------------

describe('NotificationChannel interface', () => {
  it('accepts an object that satisfies the NotificationChannel interface', () => {
    const mockChannel: NotificationChannel = {
      name: 'test-channel',
      send: async (_incident: TamperIncident): Promise<void> => {
        // no-op for test
      },
      test: async (): Promise<void> => {
        // no-op for test
      },
    };

    expect(mockChannel.name).toBe('test-channel');
    expect(typeof mockChannel.send).toBe('function');
    expect(typeof mockChannel.test).toBe('function');
  });
});

// ---------------------------------------------------------------------------
// DeduplicationEntry
// ---------------------------------------------------------------------------

describe('DeduplicationEntry', () => {
  it('accepts a valid deduplication entry', () => {
    const entry: DeduplicationEntry = {
      key: 'digest_mismatch:deo-001',
      firstSeenAt: '2026-04-04T10:00:00.000Z',
      count: 3,
    };

    expect(entry.key).toBe('digest_mismatch:deo-001');
    expect(entry.firstSeenAt).toBe('2026-04-04T10:00:00.000Z');
    expect(entry.count).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// TamperSeverity values
// ---------------------------------------------------------------------------

describe('TamperSeverity', () => {
  it('covers all three severity levels', () => {
    const severities: TamperSeverity[] = ['critical', 'warning', 'info'];

    expect(severities).toContain('critical');
    expect(severities).toContain('warning');
    expect(severities).toContain('info');
    expect(severities).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// MonitoringEventHandler callback type
// ---------------------------------------------------------------------------

describe('MonitoringEventHandler', () => {
  it('accepts a function matching the handler signature', () => {
    const received: MonitoringEvent[] = [];

    const handler: MonitoringEventHandler = (event: MonitoringEvent) => {
      received.push(event);
    };

    const testEvent: RecordVerifiedEvent = {
      type: 'record_verified',
      evidenceId: 'deo-handler-test',
    };

    handler(testEvent);
    expect(received).toHaveLength(1);
    expect((received[0] as RecordVerifiedEvent).evidenceId).toBe('deo-handler-test');
  });
});

// ---------------------------------------------------------------------------
// MonitoringEventType — exhaustive check
// ---------------------------------------------------------------------------

describe('MonitoringEventType', () => {
  it('covers all 10 defined event types', () => {
    const allTypes: MonitoringEventType[] = [
      'digest_mismatch',
      'chain_break',
      'sequence_gap',
      'missing_record',
      'attestation_invalid',
      'record_verified',
      'scan_completed',
      'chain_relinked',
      'chain_forked',
      'incident_annotated',
    ];

    expect(allTypes).toHaveLength(10);
    // Spot-check that the discriminant field round-trips through MonitoringEvent
    const e: MonitoringEvent = { type: 'missing_record', sequenceNumber: 1 };
    expect(allTypes).toContain(e.type);
  });
});
