import { SlackChannel } from '../../src/monitoring/slack-channel';
import { TamperIncident, SlackNotificationConfig } from '@tzun/engine';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeIncident(overrides: Partial<TamperIncident> = {}): TamperIncident {
  return {
    id: overrides.id ?? 'inc-001',
    detectedAt: '2026-04-04T12:00:00Z',
    severity: overrides.severity ?? 'critical',
    type: overrides.type ?? 'digest_mismatch',
    affectedRecords: overrides.affectedRecords ?? ['ev-001'],
    details: 'Digest mismatch on ev-001',
    status: 'open',
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SlackChannel', () => {
  const config: SlackNotificationConfig = {
    webhookUrl: 'https://hooks.slack.com/services/T000/B000/xxxx',
  };

  it('sends Block Kit message with correct structure', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });

    const channel = new SlackChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident({ severity: 'critical' }));

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe(config.webhookUrl);

    const body = JSON.parse(options.body);
    expect(body.blocks).toBeDefined();
    expect(Array.isArray(body.blocks)).toBe(true);

    // Should have colour attachment for critical.
    expect(body.attachments).toBeDefined();
    expect(body.attachments[0].color).toBe('#dc3545'); // red
  });

  it('critical severity uses red colour', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });

    const channel = new SlackChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident({ severity: 'critical' }));

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.attachments[0].color).toBe('#dc3545');
  });

  it('warning severity uses yellow colour', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });

    const channel = new SlackChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident({ severity: 'warning' }));

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.attachments[0].color).toBe('#ffc107');
  });

  it('info severity uses blue colour', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });

    const channel = new SlackChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident({ severity: 'info' }));

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.attachments[0].color).toBe('#17a2b8');
  });

  it('message includes incident details', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });

    const channel = new SlackChannel(config, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident());

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    const bodyText = JSON.stringify(body);
    expect(bodyText).toContain('inc-001');
    expect(bodyText).toContain('digest_mismatch');
    expect(bodyText).toContain('ev-001');
  });

  it('test() resolves when webhook responds OK', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const channel = new SlackChannel(config, mockFetch as unknown as typeof fetch);

    await expect(channel.test()).resolves.toBeUndefined();
  });

  it('test() rejects on failure', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('unreachable'));
    const channel = new SlackChannel(config, mockFetch as unknown as typeof fetch);

    await expect(channel.test()).rejects.toThrow('unreachable');
  });

  it('name is "slack"', () => {
    const channel = new SlackChannel(config);
    expect(channel.name).toBe('slack');
  });
});
