import { SlackChannel } from '../../src/monitoring/slack-channel';
import { PagerDutyChannel } from '../../src/monitoring/pagerduty-channel';
import { TamperIncident } from '@tzun/engine';

/**
 * SlackChannel and PagerDutyChannel pass an abort signal and
 * `redirect: 'error'` to every fetch. Without the signal a stalled
 * operator-configured endpoint would hold the dispatch promise open
 * indefinitely: dispatch is fire-and-forget, so detection is never blocked,
 * but the pending promises would accumulate for the life of the process.
 * Without `redirect: 'error'` a 30x would forward the incident body to
 * whatever host the redirect named.
 */
function makeIncident(): TamperIncident {
  return {
    id: 'inc-001',
    detectedAt: '2026-04-04T12:00:00Z',
    severity: 'critical',
    type: 'digest_mismatch',
    affectedRecords: ['ev-001'],
    details: 'Digest mismatch on ev-001',
    status: 'open',
  };
}

describe('Slack/PagerDuty channels bound and pin their HTTP requests', () => {
  it('SlackChannel.send passes an abort signal and refuses redirects', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const channel = new SlackChannel(
      { webhookUrl: 'https://hooks.slack.example/x' },
      mockFetch as unknown as typeof fetch,
    );
    await channel.send(makeIncident());

    const [, options] = mockFetch.mock.calls[0];
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(options.redirect).toBe('error');
  });

  it('PagerDutyChannel.send passes an abort signal and refuses redirects', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const channel = new PagerDutyChannel(
      { integrationKey: 'k' },
      mockFetch as unknown as typeof fetch,
    );
    await channel.send(makeIncident());

    const [, options] = mockFetch.mock.calls[0];
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(options.redirect).toBe('error');
  });

  it('a stalled Slack endpoint aborts instead of hanging for ever', async () => {
    const mockFetch = jest.fn(
      (_url: string, init: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new Error('aborted')));
        }),
    );
    const channel = new SlackChannel(
      { webhookUrl: 'https://hooks.slack.example/x', timeoutMs: 20 },
      mockFetch as unknown as typeof fetch,
    );

    await expect(channel.send(makeIncident())).rejects.toThrow('aborted');
  });

  it('a stalled PagerDuty endpoint aborts instead of hanging for ever', async () => {
    const mockFetch = jest.fn(
      (_url: string, init: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new Error('aborted')));
        }),
    );
    const channel = new PagerDutyChannel(
      { integrationKey: 'k', timeoutMs: 20 },
      mockFetch as unknown as typeof fetch,
    );

    await expect(channel.send(makeIncident())).rejects.toThrow('aborted');
  });
});
