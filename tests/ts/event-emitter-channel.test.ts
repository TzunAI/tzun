import { EventEmitterChannel } from '../../src/monitoring/event-emitter-channel';
import { TamperIncident, ScanSummary } from '@tzun/engine';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeIncident(overrides: Partial<TamperIncident> = {}): TamperIncident {
  return {
    id: overrides.id ?? 'inc-001',
    detectedAt: '2026-04-04T12:00:00Z',
    severity: overrides.severity ?? 'critical',
    type: overrides.type ?? 'digest_mismatch',
    affectedRecords: ['ev-001'],
    details: 'Digest mismatch on ev-001',
    status: 'open',
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('EventEmitterChannel', () => {
  let channel: EventEmitterChannel;

  beforeEach(() => {
    channel = new EventEmitterChannel();
  });

  it('on("tamper") receives TamperIncident', () => {
    const received: TamperIncident[] = [];
    channel.on('tamper', (incident) => received.push(incident));

    channel.emitTamper(makeIncident());

    expect(received).toHaveLength(1);
    expect(received[0].type).toBe('digest_mismatch');
  });

  it('on("scan.completed") receives ScanSummary', () => {
    const received: ScanSummary[] = [];
    channel.on('scan.completed', (summary) => received.push(summary));

    const summary: ScanSummary = {
      passNumber: 1,
      startedAt: '2026-04-04T12:00:00Z',
      completedAt: '2026-04-04T12:01:00Z',
      durationMs: 60000,
      recordsChecked: 1000,
      issuesFound: 0,
      digestMismatches: 0,
      chainBreaks: 0,
      sequenceGaps: 0,
      attestationFailures: 0,
    };
    channel.emitScanCompleted(summary);

    expect(received).toHaveLength(1);
    expect(received[0].passNumber).toBe(1);
  });

  it('multiple listeners receive the same event', () => {
    const received1: TamperIncident[] = [];
    const received2: TamperIncident[] = [];

    channel.on('tamper', (i) => received1.push(i));
    channel.on('tamper', (i) => received2.push(i));

    channel.emitTamper(makeIncident());

    expect(received1).toHaveLength(1);
    expect(received2).toHaveLength(1);
  });

  it('off() removes a listener', () => {
    const received: TamperIncident[] = [];
    const handler = (i: TamperIncident) => received.push(i);

    channel.on('tamper', handler);
    channel.emitTamper(makeIncident());
    expect(received).toHaveLength(1);

    channel.off('tamper', handler);
    channel.emitTamper(makeIncident({ id: 'inc-002' }));
    expect(received).toHaveLength(1);
  });

  it('implements NotificationChannel interface via send()', async () => {
    const received: TamperIncident[] = [];
    channel.on('tamper', (i) => received.push(i));

    // send() is the NotificationChannel interface method
    await channel.send(makeIncident());

    expect(received).toHaveLength(1);
  });

  it('test() resolves without error (no external dependencies)', async () => {
    await expect(channel.test()).resolves.toBeUndefined();
  });

  it('name is "event-emitter"', () => {
    expect(channel.name).toBe('event-emitter');
  });
});
