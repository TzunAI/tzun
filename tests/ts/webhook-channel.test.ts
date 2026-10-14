import { createHmac } from 'crypto';
import {
  WebhookChannel,
  WebhookChannelConfig,
  computeWebhookSignature,
} from '../../src/monitoring/webhook-channel';
import { TamperIncident } from '@tzun/engine';

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

describe('WebhookChannel', () => {
  const defaultConfig: WebhookChannelConfig = {
    url: 'https://example.com/tzun-events',
    secret: 'test-secret-key',
    retries: 3,
    retryDelayMs: 10, // fast for tests
    timeoutMs: 5000,
  };

  it('POSTs to configured URL with correct payload format', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });

    const channel = new WebhookChannel(defaultConfig, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident());

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toBe('https://example.com/tzun-events');
    expect(options.method).toBe('POST');
    expect(options.headers['Content-Type']).toBe('application/json');

    const body = JSON.parse(options.body);
    expect(body.event).toBe('tamper.detected');
    expect(body.timestamp).toBeDefined();
    expect(body.incident).toBeDefined();
    expect(body.incident.id).toBe('inc-001');
  });

  // The signed bytes include the transmitted timestamp, so a captured POST
  // cannot be replayed for ever. A receiver can reproduce the signature from
  // what it was sent, and an HMAC over the payload alone must NOT verify.
  it('signature is verifiable by a receiver, over timestamp + payload', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });

    const channel = new WebhookChannel(defaultConfig, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident());

    const [, options] = mockFetch.mock.calls[0];
    const signature = options.headers['X-Tzun-Signature'];
    const timestamp = options.headers['X-Tzun-Timestamp'];
    expect(signature).toMatch(/^sha256=[a-f0-9]{64}$/);
    expect(timestamp).toMatch(/^[0-9]+$/);

    const body = options.body;
    // A receiver recomputes from the header it was sent.
    expect(signature).toBe(
      'sha256=' +
        createHmac('sha256', 'test-secret-key')
          .update(`${timestamp}.${body}`)
          .digest('hex'),
    );
    // An HMAC over the payload alone is not a valid signature: that is what
    // makes a captured POST non-replayable.
    expect(signature).not.toBe(
      'sha256=' + createHmac('sha256', 'test-secret-key').update(body).digest('hex'),
    );
    // The helper the receiver is meant to use agrees.
    expect(computeWebhookSignature('test-secret-key', timestamp, body)).toBe(signature);
  });

  it('omits the signature header entirely when no secret is configured', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const channel = new WebhookChannel(
      { url: 'https://example.com/tzun-events', retries: 0, retryDelayMs: 0 },
      mockFetch as unknown as typeof fetch,
    );
    await channel.send(makeIncident());

    const [, options] = mockFetch.mock.calls[0];
    // A `sha256=<hmac keyed on the empty string>` header is one a receiver
    // cannot tell apart from a real signature -- and one any forger can
    // compute, the key being publicly known to be ''.
    expect(options.headers['X-Tzun-Signature']).toBeUndefined();
    expect(options.headers['X-Tzun-Timestamp']).toBeUndefined();
    expect(JSON.stringify(options.headers)).not.toContain('sha256=');
  });

  it('does not follow redirects, so a moved endpoint cannot forward incidents', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const channel = new WebhookChannel(defaultConfig, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident());

    const [, options] = mockFetch.mock.calls[0];
    // Following a 301 to a third-party host would re-POST the incident --
    // evidence ids, digests, details -- plus the signature to whatever it named.
    expect(options.redirect).toBe('error');
  });

  it('retries on failure up to configured retries', async () => {
    const mockFetch = jest
      .fn()
      .mockRejectedValueOnce(new Error('network error'))
      .mockRejectedValueOnce(new Error('network error'))
      .mockResolvedValueOnce({ ok: true, status: 200 });

    const channel = new WebhookChannel(defaultConfig, mockFetch as unknown as typeof fetch);
    await channel.send(makeIncident());

    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('gives up after max retries and does not throw', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('network error'));

    const channel = new WebhookChannel(
      { ...defaultConfig, retries: 2 },
      mockFetch as unknown as typeof fetch,
    );

    // Should not throw -- webhook failures are logged, not thrown.
    await expect(channel.send(makeIncident())).resolves.toBeUndefined();
    expect(mockFetch).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it('aborts on timeout with slow receiver', async () => {
    const mockFetch = jest.fn().mockImplementation((_url: string, options?: RequestInit) => {
      return new Promise((_resolve, reject) => {
        if (options?.signal) {
          options.signal.addEventListener('abort', () => {
            reject(new DOMException('The operation was aborted.', 'AbortError'));
          });
        }
      });
    });

    const channel = new WebhookChannel(
      { ...defaultConfig, retries: 0, timeoutMs: 50 },
      mockFetch as unknown as typeof fetch,
    );

    await expect(channel.send(makeIncident())).resolves.toBeUndefined();
  }, 5000);

  it('test() resolves when endpoint responds OK', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true, status: 200 });
    const channel = new WebhookChannel(defaultConfig, mockFetch as unknown as typeof fetch);

    await expect(channel.test()).resolves.toBeUndefined();
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('test() rejects on failure', async () => {
    const mockFetch = jest.fn().mockRejectedValue(new Error('unreachable'));
    const channel = new WebhookChannel(defaultConfig, mockFetch as unknown as typeof fetch);

    await expect(channel.test()).rejects.toThrow('unreachable');
  });

  it('name is "webhook"', () => {
    const channel = new WebhookChannel(defaultConfig);
    expect(channel.name).toBe('webhook');
  });
});
