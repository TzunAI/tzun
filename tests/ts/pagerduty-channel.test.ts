import { PagerDutyChannel } from '../../src/monitoring/pagerduty-channel';
import { TamperIncident, PagerDutyNotificationConfig } from '@tzun/engine';

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
    status: overrides.status ?? 'open',
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PagerDutyChannel', () => {
  const config: PagerDutyNotificationConfig = {
    integrationKey: 'test-routing-key',
  };

  it('creates incident with correct payload and severity mapping', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 202 });

    const channel = new PagerDutyChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident({ severity: 'critical' }));

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe('https://events.pagerduty.com/v2/enqueue');

    const body = JSON.parse(options.body);
    expect(body.routing_key).toBe('test-routing-key');
    expect(body.event_action).toBe('trigger');
    expect(body.payload.severity).toBe('critical');
    expect(body.payload.summary).toContain('digest mismatch');
    expect(body.dedup_key).toBe('inc-001');
  });

  it('maps warning severity correctly', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 202 });

    const channel = new PagerDutyChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident({ severity: 'warning' }));

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.payload.severity).toBe('warning');
  });

  it('maps info severity correctly', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 202 });

    const channel = new PagerDutyChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident({ severity: 'info' }));

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.payload.severity).toBe('info');
  });

  it('sends resolve event when incident status is resolved', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 202 });

    const channel = new PagerDutyChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident({ status: 'resolved' }));

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.event_action).toBe('resolve');
  });

  it('test() resolves when API responds OK', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 202 });
    const channel = new PagerDutyChannel(config, mockFetch as unknown as typeof fetch);

    await expect(channel.test()).resolves.toBeUndefined();
  });

  it('test() rejects on failure', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('unreachable'));
    const channel = new PagerDutyChannel(config, mockFetch as unknown as typeof fetch);

    await expect(channel.test()).rejects.toThrow('unreachable');
  });

  it('name is "pagerduty"', () => {
    const channel = new PagerDutyChannel(config);
    expect(channel.name).toBe('pagerduty');
  });
});
