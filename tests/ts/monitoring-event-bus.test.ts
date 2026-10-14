import { MonitoringEventBus } from '../../src/monitoring/event-bus';
import { MonitoringEvent } from '@tzun/engine';

describe('MonitoringEventBus', () => {
  it('dispatches events to all subscribers', () => {
    const bus = new MonitoringEventBus();
    const received1: MonitoringEvent[] = [];
    const received2: MonitoringEvent[] = [];

    bus.subscribe((e) => received1.push(e));
    bus.subscribe((e) => received2.push(e));

    const event: MonitoringEvent = { type: 'scan_completed', recordsChecked: 10, issuesFound: 0, durationMs: 0, digestMismatches: 0, chainBreaks: 0, sequenceGaps: 0, attestationFailures: 0 };
    bus.emit(event);

    expect(received1).toHaveLength(1);
    expect(received1[0]).toBe(event);
    expect(received2).toHaveLength(1);
    expect(received2[0]).toBe(event);
  });

  it('typed events carry correct payload for digest_mismatch, chain_break, scan_completed', () => {
    const bus = new MonitoringEventBus();
    const received: MonitoringEvent[] = [];
    bus.subscribe((e) => received.push(e));

    const digestMismatch: MonitoringEvent = {
      type: 'digest_mismatch',
      evidenceId: 'ev-001',
      stored: 'aabbcc',
      recomputed: 'ddeeff',
    };
    const chainBreak: MonitoringEvent = {
      type: 'chain_break',
      evidenceId: 'ev-002',
      sequenceNumber: 5,
      expectedPrevDigest: '112233',
    };
    const scanCompleted: MonitoringEvent = {
      type: 'scan_completed',
      recordsChecked: 42,
      issuesFound: 2,
      durationMs: 0,
      digestMismatches: 0,
      chainBreaks: 0,
      sequenceGaps: 0,
      attestationFailures: 0,
    };

    bus.emit(digestMismatch);
    bus.emit(chainBreak);
    bus.emit(scanCompleted);

    expect(received).toHaveLength(3);

    const dm = received[0];
    expect(dm.type).toBe('digest_mismatch');
    if (dm.type === 'digest_mismatch') {
      expect(dm.evidenceId).toBe('ev-001');
      expect(dm.stored).toBe('aabbcc');
      expect(dm.recomputed).toBe('ddeeff');
    }

    const cb = received[1];
    expect(cb.type).toBe('chain_break');
    if (cb.type === 'chain_break') {
      expect(cb.evidenceId).toBe('ev-002');
      expect(cb.sequenceNumber).toBe(5);
      expect(cb.expectedPrevDigest).toBe('112233');
    }

    const sc = received[2];
    expect(sc.type).toBe('scan_completed');
    if (sc.type === 'scan_completed') {
      expect(sc.recordsChecked).toBe(42);
      expect(sc.issuesFound).toBe(2);
    }
  });

  it('unsubscribe works correctly', () => {
    const bus = new MonitoringEventBus();
    const received: MonitoringEvent[] = [];
    const handler = (e: MonitoringEvent) => received.push(e);

    bus.subscribe(handler);
    bus.emit({ type: 'scan_completed', recordsChecked: 1, issuesFound: 0, durationMs: 0, digestMismatches: 0, chainBreaks: 0, sequenceGaps: 0, attestationFailures: 0 });
    expect(received).toHaveLength(1);

    bus.unsubscribe(handler);
    bus.emit({ type: 'scan_completed', recordsChecked: 2, issuesFound: 0, durationMs: 0, digestMismatches: 0, chainBreaks: 0, sequenceGaps: 0, attestationFailures: 0 });
    expect(received).toHaveLength(1); // no new events after unsubscribe
  });

  it('no event loss under 100 rapid emissions', () => {
    const bus = new MonitoringEventBus();
    const received: MonitoringEvent[] = [];
    bus.subscribe((e) => received.push(e));

    for (let i = 0; i < 100; i++) {
      bus.emit({ type: 'record_verified', evidenceId: `ev-${i}` });
    }

    expect(received).toHaveLength(100);
    for (let i = 0; i < 100; i++) {
      const e = received[i];
      expect(e.type).toBe('record_verified');
      if (e.type === 'record_verified') {
        expect(e.evidenceId).toBe(`ev-${i}`);
      }
    }
  });

  it('emitting with no subscribers does not throw', () => {
    const bus = new MonitoringEventBus();
    expect(() => {
      bus.emit({ type: 'scan_completed', recordsChecked: 0, issuesFound: 0, durationMs: 0, digestMismatches: 0, chainBreaks: 0, sequenceGaps: 0, attestationFailures: 0 });
    }).not.toThrow();
  });

  it('unsubscribing a non-subscribed handler does not throw', () => {
    const bus = new MonitoringEventBus();
    const handler = (_e: MonitoringEvent) => {};

    expect(() => {
      bus.unsubscribe(handler);
    }).not.toThrow();
  });

  it('subscriber throwing does not prevent others from receiving', () => {
    const bus = new MonitoringEventBus();
    const received: MonitoringEvent[] = [];

    const throwingHandler = (_e: MonitoringEvent) => {
      throw new Error('subscriber error');
    };
    const safeHandler = (e: MonitoringEvent) => received.push(e);

    bus.subscribe(throwingHandler);
    bus.subscribe(safeHandler);

    const event: MonitoringEvent = { type: 'scan_completed', recordsChecked: 5, issuesFound: 1, durationMs: 0, digestMismatches: 0, chainBreaks: 0, sequenceGaps: 0, attestationFailures: 0 };

    // Should not throw even though throwingHandler throws
    expect(() => bus.emit(event)).not.toThrow();
    expect(received).toHaveLength(1);
    expect(received[0]).toBe(event);
  });
});
