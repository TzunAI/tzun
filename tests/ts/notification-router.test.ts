import { NotificationRouter } from '../../src/monitoring/notification-router';
import { NotificationChannel, TamperIncident, TamperSeverity } from '@tzun/engine';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeIncident(overrides: Partial<TamperIncident> = {}): TamperIncident {
  return {
    id: overrides.id ?? 'inc-001',
    detectedAt: overrides.detectedAt ?? '2026-04-04T10:00:00.000Z',
    severity: overrides.severity ?? 'critical',
    type: overrides.type ?? 'digest_mismatch',
    affectedRecords: overrides.affectedRecords ?? ['ev-001'],
    details: overrides.details ?? 'Digest mismatch on ev-001',
    status: overrides.status ?? 'open',
  };
}

/**
 * Creates a mock NotificationChannel with Jest spy functions.
 * `sent` accumulates every incident successfully passed to `send`.
 */
function mockChannel(
  name: string,
  severities: TamperSeverity[],
): { registration: { channel: NotificationChannel; severities: TamperSeverity[] }; sent: TamperIncident[] } {
  const sent: TamperIncident[] = [];

  const channel: NotificationChannel = {
    name,
    send: jest.fn(async (incident: TamperIncident) => {
      sent.push(incident);
    }),
    test: jest.fn(async () => {}),
  };

  return { registration: { channel, severities }, sent };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NotificationRouter', () => {
  // -------------------------------------------------------------------------
  // Test 1: dispatches to all configured channels
  // -------------------------------------------------------------------------
  it('dispatches a critical incident to all configured channels', async () => {
    const alpha = mockChannel('alpha', ['critical', 'warning', 'info']);
    const beta = mockChannel('beta', ['critical', 'warning', 'info']);

    const router = new NotificationRouter({
      channels: [alpha.registration, beta.registration],
    });

    const incident = makeIncident({ severity: 'critical' });
    await router.dispatch(incident);

    expect(alpha.sent).toHaveLength(1);
    expect(alpha.sent[0]).toBe(incident);
    expect(beta.sent).toHaveLength(1);
    expect(beta.sent[0]).toBe(incident);
  });

  // -------------------------------------------------------------------------
  // Test 2: severity filtering — critical-only channel ignores warnings
  // -------------------------------------------------------------------------
  it('does not send a warning incident to a critical-only channel', async () => {
    const criticalOnly = mockChannel('critical-only', ['critical']);
    const allSeverities = mockChannel('all', ['critical', 'warning', 'info']);

    const router = new NotificationRouter({
      channels: [criticalOnly.registration, allSeverities.registration],
    });

    const warning = makeIncident({ id: 'inc-w1', severity: 'warning', type: 'sequence_gap', affectedRecords: [] });
    await router.dispatch(warning);

    expect(criticalOnly.sent).toHaveLength(0);
    expect(allSeverities.sent).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // Test 3: deduplication — same evidenceId + type within window → 1 send
  // -------------------------------------------------------------------------
  it('deduplicates incidents with same evidenceId and type within the window', async () => {
    const ch = mockChannel('ch', ['critical']);

    const router = new NotificationRouter({
      channels: [ch.registration],
      deduplicationWindowMs: 60_000,
    });

    const incident1 = makeIncident({ id: 'inc-a', affectedRecords: ['ev-001'], type: 'digest_mismatch' });
    const incident2 = makeIncident({ id: 'inc-b', affectedRecords: ['ev-001'], type: 'digest_mismatch' });

    await router.dispatch(incident1);
    await router.dispatch(incident2);

    expect(ch.sent).toHaveLength(1);
    expect(ch.sent[0]).toBe(incident1);
  });

  // -------------------------------------------------------------------------
  // Test 4: different evidenceId → not deduplicated (2 notifications)
  // -------------------------------------------------------------------------
  it('does not deduplicate incidents with different evidenceIds', async () => {
    const ch = mockChannel('ch', ['critical']);

    const router = new NotificationRouter({
      channels: [ch.registration],
      deduplicationWindowMs: 60_000,
    });

    const incident1 = makeIncident({ id: 'inc-a', affectedRecords: ['ev-001'], type: 'digest_mismatch' });
    const incident2 = makeIncident({ id: 'inc-b', affectedRecords: ['ev-002'], type: 'digest_mismatch' });

    await router.dispatch(incident1);
    await router.dispatch(incident2);

    expect(ch.sent).toHaveLength(2);
  });

  // -------------------------------------------------------------------------
  // Test 5: rate limiting — 10 dispatches with limit 5 → at most 5 sent
  // -------------------------------------------------------------------------
  it('rate-limits dispatches to the configured maximum per minute', async () => {
    const ch = mockChannel('ch', ['critical', 'warning', 'info']);

    const router = new NotificationRouter({
      channels: [ch.registration],
      rateLimitPerMinute: 5,
      // A REAL dedup window (the production default), not 0: a window of 0
      // would hide the dedup/rate-limit interaction tested in 5b below.
      deduplicationWindowMs: 3_600_000,
    });

    // Dispatch 10 distinct incidents (different ids + affectedRecords).
    for (let i = 0; i < 10; i++) {
      await router.dispatch(
        makeIncident({ id: `inc-${i}`, affectedRecords: [`ev-${i}`] }),
      );
    }

    expect(ch.sent).toHaveLength(5);
    expect(ch.sent.map((i) => i.id)).toEqual([
      'inc-0',
      'inc-1',
      'inc-2',
      'inc-3',
      'inc-4',
    ]);
  });

  // -------------------------------------------------------------------------
  // Test 5b: a rate-limited incident must NOT consume its deduplication
  // window, and the drop must be logged.
  //
  // If an incident dropped by the rate limit still recorded its dedup key,
  // every later re-detection of the same tamper would be suppressed as a
  // duplicate for the whole window (1 h by default), and a tamper burst larger
  // than the limit would lose its overflow incidents from every channel,
  // silently.
  // -------------------------------------------------------------------------
  it('re-delivers a rate-limited incident on the next scan pass (does not burn its dedup key)', async () => {
    const ch = mockChannel('ch', ['critical', 'warning', 'info']);

    const router = new NotificationRouter({
      channels: [ch.registration],
      rateLimitPerMinute: 1,
      deduplicationWindowMs: 3_600_000, // 1 h — the production default
    });

    const nowSpy = jest.spyOn(Date, 'now');
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    try {
      const t0 = 1_800_000_000_000;

      // t0: incident A is delivered and consumes the one-per-minute budget.
      nowSpy.mockReturnValue(t0);
      await router.dispatch(makeIncident({ id: 'inc-A', affectedRecords: ['ev-A'] }));

      // t0: incident B arrives in the same burst and is rate-limited.
      await router.dispatch(makeIncident({ id: 'inc-B', affectedRecords: ['ev-B'] }));

      expect(ch.sent.map((i) => i.id)).toEqual(['inc-A']);
      // The drop must be observable.
      expect(warnSpy).toHaveBeenCalledTimes(1);
      expect(String(warnSpy.mock.calls[0][0])).toContain('inc-B');

      // t0 + 61 s: the rate-limit window has rolled over and the scanner
      // re-emits the SAME still-unrepaired tamper on ev-B. The dedup window is
      // still wide open, and it must not suppress this as a duplicate of an
      // incident that was never actually sent.
      nowSpy.mockReturnValue(t0 + 61_000);
      await router.dispatch(
        makeIncident({ id: 'inc-B2', affectedRecords: ['ev-B'] }),
      );

      expect(ch.sent.map((i) => i.id)).toEqual(['inc-A', 'inc-B2']);

      // And genuine deduplication still works: a third re-detection of ev-B
      // inside the 1 h window after a successful send is suppressed.
      nowSpy.mockReturnValue(t0 + 62_000);
      await router.dispatch(
        makeIncident({ id: 'inc-B3', affectedRecords: ['ev-B'] }),
      );
      expect(ch.sent.map((i) => i.id)).toEqual(['inc-A', 'inc-B2']);
    } finally {
      nowSpy.mockRestore();
      warnSpy.mockRestore();
    }
  });

  // -------------------------------------------------------------------------
  // Test 6: channel error doesn't prevent other channels from receiving
  // -------------------------------------------------------------------------
  it('isolates channel errors so other channels still receive the incident', async () => {
    const good = mockChannel('good', ['critical']);
    const bad: NotificationChannel = {
      name: 'bad',
      send: jest.fn(async () => {
        throw new Error('delivery failure');
      }),
      test: jest.fn(async () => {}),
    };

    const router = new NotificationRouter({
      channels: [
        { channel: bad, severities: ['critical'] },
        good.registration,
      ],
    });

    const incident = makeIncident({ severity: 'critical' });

    // Should not throw even though 'bad' channel fails.
    await expect(router.dispatch(incident)).resolves.toBeUndefined();

    expect(good.sent).toHaveLength(1);
    expect(bad.send).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // Test 7: no channels — dispatch doesn't throw
  // -------------------------------------------------------------------------
  it('does not throw when no channels are configured', async () => {
    const router = new NotificationRouter({ channels: [] });

    await expect(
      router.dispatch(makeIncident()),
    ).resolves.toBeUndefined();
  });
});
