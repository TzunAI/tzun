import { EmailChannel, EmailChannelConfig } from '../../src/monitoring/email-channel';
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

describe('EmailChannel', () => {
  const config: EmailChannelConfig = {
    host: 'localhost',
    port: 2525,
    auth: { user: 'test', pass: 'test' },
    from: 'tzun-alerts@example.com',
    to: ['default@example.com'],
    recipientsBySeverity: {
      critical: ['security-team@example.com', 'cto@example.com'],
      warning: ['ops-team@example.com'],
    },
  };

  it('HTML email formatted correctly with incident details', () => {
    const channel = new EmailChannel(config);
    const html = channel.formatEmail(makeIncident());

    expect(html).toContain('inc-001');
    expect(html).toContain('digest_mismatch');
    expect(html).toContain('ev-001');
    expect(html).toContain('CRITICAL');
  });

  it('recipients match severity config', () => {
    const channel = new EmailChannel(config);

    const criticalRecipients = channel.getRecipients('critical');
    expect(criticalRecipients).toEqual(['security-team@example.com', 'cto@example.com']);

    const warningRecipients = channel.getRecipients('warning');
    expect(warningRecipients).toEqual(['ops-team@example.com']);

    // No info recipients configured in recipientsBySeverity -> empty.
    const infoRecipients = channel.getRecipients('info');
    expect(infoRecipients).toEqual([]);
  });

  it('falls back to base "to" list when recipientsBySeverity is not set', () => {
    const simpleConfig: EmailChannelConfig = {
      host: 'localhost',
      port: 2525,
      auth: { user: 'test', pass: 'test' },
      from: 'tzun-alerts@example.com',
      to: ['default@example.com'],
    };
    const channel = new EmailChannel(simpleConfig);

    expect(channel.getRecipients('critical')).toEqual(['default@example.com']);
    expect(channel.getRecipients('info')).toEqual(['default@example.com']);
  });

  it('formatSubject includes severity and type', () => {
    const channel = new EmailChannel(config);
    const subject = channel.formatSubject(
      makeIncident({ severity: 'warning', type: 'chain_break' }),
    );
    expect(subject).toContain('WARNING');
    expect(subject).toContain('chain_break');
  });

  it('name is "email"', () => {
    const channel = new EmailChannel(config);
    expect(channel.name).toBe('email');
  });

  it('test() rejects when SMTP is unreachable', async () => {
    const channel = new EmailChannel({
      ...config,
      host: 'localhost',
      port: 59999, // unlikely to be listening
    });

    await expect(channel.test()).rejects.toThrow();
  });

  it('send() does not throw when SMTP is unreachable', async () => {
    const channel = new EmailChannel({
      ...config,
      host: 'localhost',
      port: 59999,
    });

    // Should not throw -- email failures are logged, not thrown.
    await expect(channel.send(makeIncident())).resolves.toBeUndefined();
  });
});

/**
 * The SMTP client checks every reply code.
 *
 * A 530/550/554 read as if it were a 250 would let `sendSmtp()` resolve with
 * the catch in `send()` never firing, and the alert would be lost with
 * nothing logged — monitoring would look healthy while no email ever
 * arrived. The channel also issues STARTTLS and AUTH, so the REQUIRED
 * `auth: { user, pass }` in the public config type is what authenticates the
 * send; port-587 relays answer MAIL FROM with '530 Must issue a STARTTLS
 * command first' to a client that skips them.
 *
 * These tests drive a real local SMTP server.
 */
describe('EmailChannel — SMTP conversation', () => {
  const net = require('net') as typeof import('net');

  /** Start a scripted SMTP server; returns its port and the verbs it saw. */
  async function startServer(
    reply: (verb: string, line: string) => string,
  ): Promise<{ port: number; verbs: string[]; close: () => Promise<void> }> {
    const verbs: string[] = [];
    let inData = false;
    const server = net.createServer((socket) => {
      socket.write('220 test.example ESMTP\r\n');
      socket.on('data', (chunk) => {
        for (const line of chunk.toString().split('\r\n')) {
          if (line === '' && !inData) continue;
          if (inData) {
            if (line === '.') {
              inData = false;
              socket.write('250 OK queued\r\n');
            }
            continue;
          }
          const verb = line.split(' ')[0].toUpperCase();
          verbs.push(verb);
          const out = reply(verb, line);
          if (out === '__DATA__') {
            inData = true;
            socket.write('354 Start mail input\r\n');
            continue;
          }
          socket.write(out);
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as import('net').AddressInfo).port;
    return {
      port,
      verbs,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  const baseConfig = {
    host: '127.0.0.1',
    from: 'alerts@example.com',
    to: ['ops@example.com'],
    auth: { user: 'u', pass: 'p' },
    secure: false as const,
  };

  it('logs a failure when the relay refuses with 530 instead of dropping it silently', async () => {
    const srv = await startServer(() => '530 Must issue a STARTTLS command first\r\n');
    const errors: unknown[][] = [];
    const spy = jest.spyOn(console, 'error').mockImplementation((...a) => {
      errors.push(a);
    });
    try {
      const channel = new EmailChannel({ ...baseConfig, port: srv.port });
      await channel.send(makeIncident());
      expect(errors.length).toBeGreaterThan(0);
      expect(errors.flat().join(' ')).toContain('530');
    } finally {
      spy.mockRestore();
      await srv.close();
    }
  });

  it('test() rejects on a refused relay instead of reporting success', async () => {
    // A relay that accepts the TCP connection and the EHLO but rejects the
    // credentials: a check that only opened a socket would report healthy
    // for exactly this configuration.
    const srv = await startServer((verb) =>
      verb === 'EHLO' ? '250-test.example\r\n250 AUTH PLAIN\r\n' : '535 bad credentials\r\n',
    );
    try {
      const channel = new EmailChannel({ ...baseConfig, port: srv.port });
      await expect(channel.test()).rejects.toThrow(/535/);
    } finally {
      await srv.close();
    }
  });

  it('issues AUTH with the configured credentials', async () => {
    const srv = await startServer((verb) => {
      if (verb === 'EHLO') return '250-test.example\r\n250 AUTH PLAIN LOGIN\r\n';
      if (verb === 'AUTH') return '235 accepted\r\n';
      if (verb === 'DATA') return '__DATA__';
      if (verb === 'QUIT') return '221 bye\r\n';
      return '250 ok\r\n';
    });
    try {
      const channel = new EmailChannel({ ...baseConfig, port: srv.port });
      await channel.send(makeIncident());
      expect(srv.verbs).toContain('AUTH');
      expect(srv.verbs).toContain('QUIT');
    } finally {
      await srv.close();
    }
  });

  it('survives a multi-line EHLO without desynchronising', async () => {
    const srv = await startServer((verb) => {
      if (verb === 'EHLO')
        return '250-test.example\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 AUTH PLAIN\r\n';
      if (verb === 'AUTH') return '235 accepted\r\n';
      if (verb === 'DATA') return '__DATA__';
      if (verb === 'QUIT') return '221 bye\r\n';
      return '250 ok\r\n';
    });
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const channel = new EmailChannel({ ...baseConfig, port: srv.port });
      await channel.send(makeIncident());
      expect(spy).not.toHaveBeenCalled();
      expect(srv.verbs).toEqual(
        expect.arrayContaining(['EHLO', 'AUTH', 'MAIL', 'RCPT', 'DATA', 'QUIT']),
      );
    } finally {
      spy.mockRestore();
      await srv.close();
    }
  });
});
