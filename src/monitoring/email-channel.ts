import * as net from 'net';
import * as tls from 'tls';
import { NotificationChannel, TamperIncident, TamperSeverity, EmailNotificationConfig } from '@tzun/engine';

// ---------------------------------------------------------------------------
// Extended config for per-severity recipient routing
// ---------------------------------------------------------------------------

export interface EmailChannelConfig extends EmailNotificationConfig {
  /**
   * Per-severity recipient overrides. When set, only recipients listed for
   * the incident severity receive the email. Falls back to the base `to`
   * field when no severity-specific recipients are configured.
   */
  recipientsBySeverity?: Partial<Record<TamperSeverity, string[]>>;
}

// ---------------------------------------------------------------------------
// Severity colours for HTML email
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<TamperSeverity, string> = {
  critical: '#dc3545',
  warning: '#ffc107',
  info: '#17a2b8',
};

// ---------------------------------------------------------------------------
// EmailChannel
// ---------------------------------------------------------------------------

/**
 * Email Channel (Tier 3 -- Enterprise)
 *
 * SMTP-based email notifications with formatted HTML.
 * Configurable recipients per severity level.
 *
 * Uses raw SMTP commands over TCP (net module) rather than a third-party
 * library to avoid additional npm dependencies. Speaks STARTTLS and
 * AUTH PLAIN/LOGIN, and checks every reply code.
 */
export class EmailChannel implements NotificationChannel {
  readonly name = 'email';

  constructor(private config: EmailChannelConfig) {}

  async send(incident: TamperIncident): Promise<void> {
    const recipients = this.getRecipients(incident.severity);
    if (recipients.length === 0) return;

    const subject = this.formatSubject(incident);
    const html = this.formatEmail(incident);

    try {
      await this.sendSmtp(recipients, subject, html);
    } catch (err) {
      console.error(
        '[EmailChannel] Failed to send email:',
        err instanceof Error ? err.message : err,
      );
    }
  }

  /**
   * Operator-facing config check.
   *
   * Completes the handshake the real send performs, short of a message:
   * greeting, EHLO, STARTTLS if applicable, AUTH, QUIT. Opening a TCP socket
   * alone answers a different question than the one the operator is asking:
   * a relay that refuses the envelope, or rejects the configured credentials,
   * still accepts a connection, so a connect-only check would report healthy
   * for a configuration that drops every alert.
   */
  async test(): Promise<void> {
    let socket: net.Socket | tls.TLSSocket = await this.connect();
    const session = new SmtpSession(socket);
    try {
      await session.readReply(['220']);
      let ehlo = await session.command('EHLO tzun-sdk', ['250']);
      if (this.config.secure !== false && /\bSTARTTLS\b/i.test(ehlo)) {
        await session.command('STARTTLS', ['220']);
        socket = await upgradeToTls(socket as net.Socket, this.config.host);
        session.adopt(socket);
        ehlo = await session.command('EHLO tzun-sdk', ['250']);
      }
      if (this.config.auth) {
        await this.authenticate(session, ehlo);
      }
      await session.command('QUIT', ['221']);
    } finally {
      session.dispose();
      socket.destroy();
    }
  }

  /**
   * Get recipients for a given severity level.
   * Falls back to the base `to` list when no severity-specific recipients
   * are configured.
   */
  getRecipients(severity: TamperSeverity): string[] {
    if (this.config.recipientsBySeverity) {
      return this.config.recipientsBySeverity[severity] ?? [];
    }
    return this.config.to;
  }

  /**
   * Format the email subject line.
   */
  formatSubject(incident: TamperIncident): string {
    const prefix = this.config.subjectPrefix ?? '[Tzun Alert]';
    return `${prefix} ${incident.severity.toUpperCase()}: ${incident.type} -- incident ${incident.id}`;
  }

  /**
   * Format the email body as HTML.
   */
  formatEmail(incident: TamperIncident): string {
    const color = SEVERITY_COLORS[incident.severity];
    const affectedRecords =
      incident.affectedRecords.length > 0
        ? incident.affectedRecords.map((r) => `<code>${r}</code>`).join(', ')
        : 'none';

    return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="border-left: 4px solid ${color}; padding: 12px 16px; margin-bottom: 20px;">
    <h2 style="margin: 0 0 8px 0; color: ${color};">${incident.severity.toUpperCase()}: ${incident.type.replace(/_/g, ' ')}</h2>
    <p style="margin: 0; color: #666;">Detected at ${incident.detectedAt}</p>
  </div>

  <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Incident ID</td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;"><code>${incident.id}</code></td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Severity</td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;">${incident.severity.toUpperCase()}</td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Type</td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;">${incident.type}</td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Affected Records</td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;">${affectedRecords}</td>
    </tr>
    <tr>
      <td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Status</td>
      <td style="padding: 8px; border-bottom: 1px solid #eee;">${incident.status}</td>
    </tr>
  </table>

  <p style="color: #999; font-size: 12px;">Generated by Tzun SDK integrity monitoring</p>
</body>
</html>`;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private connect(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const port = this.config.port ?? 587;
      const socket = net.createConnection(
        { host: this.config.host, port },
        () => resolve(socket),
      );
      socket.setTimeout(SMTP_IDLE_TIMEOUT_MS);
      socket.on('error', reject);
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('SMTP connection timed out'));
      });
    });
  }

  /**
   * Drive one SMTP session and throw if the relay refused anything.
   *
   * Every reply code is checked. A 530/550/554 read as if it were a 250
   * would let `sendSmtp()` resolve with `send()`'s catch never firing, and
   * the alert would vanish with nothing logged. The session issues STARTTLS
   * and AUTH (port-587 relays answer MAIL FROM with '530 Must issue a
   * STARTTLS command first' to a client that does not), so the configured
   * `auth: { user, pass }` is what authenticates the send.
   *
   * Also:
   *  - replies are read to the terminating `NNN<space>` line, so multi-line
   *    replies (every real EHLO) do not desynchronise the session, and a
   *    reply split across TCP segments is reassembled.
   *  - body lines are dot-stuffed per RFC 5321 §4.5.2, so a line beginning
   *    with '.' cannot terminate DATA early and truncate the message.
   *  - `error`, `close` and `timeout` reject the in-flight command, and the
   *    whole session runs under one deadline, so a relay that stalls
   *    mid-conversation cannot leave a command pending forever and keep the
   *    router's allSettled from returning.
   */
  private async sendSmtp(
    recipients: string[],
    subject: string,
    html: string,
  ): Promise<void> {
    let socket: net.Socket | tls.TLSSocket = await this.connect();
    const session = new SmtpSession(socket);
    const deadline = setTimeout(() => {
      session.fail(new Error('SMTP session timed out'));
      socket.destroy();
    }, SMTP_SESSION_TIMEOUT_MS);
    try {
      await session.readReply(['220']);
      let ehlo = await session.command('EHLO tzun-sdk', ['250']);

      // `secure` documents itself as "use TLS (default: true)". Honour it: try
      // STARTTLS unless explicitly disabled, and fail loudly if it was asked
      // for and the relay does not offer it, rather than sending credentials
      // over cleartext.
      const wantsTls = this.config.secure !== false;
      const offersStartTls = /\bSTARTTLS\b/i.test(ehlo);
      if (wantsTls && offersStartTls) {
        await session.command('STARTTLS', ['220']);
        socket = await upgradeToTls(socket as net.Socket, this.config.host);
        session.adopt(socket);
        ehlo = await session.command('EHLO tzun-sdk', ['250']);
      } else if (wantsTls && this.config.auth) {
        throw new Error(
          `SMTP: ${this.config.host} does not offer STARTTLS and credentials were ` +
            'configured; refusing to send AUTH over an unencrypted connection. ' +
            'Set secure: false to allow it explicitly.',
        );
      }

      if (this.config.auth) {
        await this.authenticate(session, ehlo);
      }

      await session.command(`MAIL FROM:<${this.config.from}>`, ['250']);
      for (const recipient of recipients) {
        await session.command(`RCPT TO:<${recipient}>`, ['250', '251']);
      }
      await session.command('DATA', ['354']);

      const headers = [
        `From: ${this.config.from}`,
        `To: ${recipients.join(', ')}`,
        `Subject: ${subject}`,
        'MIME-Version: 1.0',
        'Content-Type: text/html; charset=utf-8',
        '',
      ];
      const body = [...headers, ...dotStuff(html)].join('\r\n');
      await session.command(`${body}\r\n.`, ['250']);
      await session.command('QUIT', ['221']);
    } finally {
      clearTimeout(deadline);
      session.dispose();
      socket.destroy();
    }
  }

  /** AUTH PLAIN when offered, else AUTH LOGIN. Both carry the same secret. */
  private async authenticate(session: SmtpSession, ehlo: string): Promise<void> {
    const auth = this.config.auth!;
    const mechanisms = /AUTH[ =]([^\r\n]*)/i.exec(ehlo)?.[1]?.toUpperCase() ?? '';
    if (mechanisms.includes('PLAIN') || mechanisms === '') {
      const token = Buffer.from(`\0${auth.user}\0${auth.pass}`, 'utf8').toString('base64');
      await session.command(`AUTH PLAIN ${token}`, ['235']);
      return;
    }
    if (mechanisms.includes('LOGIN')) {
      await session.command('AUTH LOGIN', ['334']);
      await session.command(Buffer.from(auth.user, 'utf8').toString('base64'), ['334']);
      await session.command(Buffer.from(auth.pass, 'utf8').toString('base64'), ['235']);
      return;
    }
    throw new Error(`SMTP: no supported AUTH mechanism offered (server said: ${mechanisms})`);
  }
}

// ---------------------------------------------------------------------------
// SMTP plumbing
// ---------------------------------------------------------------------------

/** Idle timeout on the socket, per read. */
const SMTP_IDLE_TIMEOUT_MS = 5000;
/** Hard ceiling on a whole SMTP conversation. */
const SMTP_SESSION_TIMEOUT_MS = 20000;

/**
 * RFC 5321 §4.5.2 transparency: a body line that begins with '.' must be sent
 * with an extra leading '.', or it terminates DATA early and silently
 * truncates the message.
 */
function dotStuff(body: string): string[] {
  return body
    .split(/\r?\n/)
    .map((line) => (line.startsWith('.') ? `.${line}` : line));
}

/** Wrap an established plaintext socket in TLS after a 220 STARTTLS reply. */
function upgradeToTls(socket: net.Socket, host: string): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const secured = tls.connect({ socket, servername: host }, () => resolve(secured));
    secured.once('error', reject);
  });
}

/**
 * Reply-aware SMTP conversation over one socket.
 *
 * Reads to the terminating `NNN<space>` line so a multi-line EHLO cannot
 * desynchronise the stream, reassembles a reply split across TCP segments,
 * and rejects the in-flight command on error/close/timeout so a stalled relay
 * cannot leave a promise pending forever.
 */
class SmtpSession {
  private buffer = '';
  private waiter: {
    resolve: (reply: string) => void;
    reject: (err: Error) => void;
  } | null = null;
  private failure: Error | null = null;
  private socket!: net.Socket | tls.TLSSocket;
  private readonly onData = (chunk: Buffer | string): void => {
    this.buffer += chunk.toString();
    this.drain();
  };
  private readonly onError = (err: Error): void => this.fail(err);
  private readonly onClose = (): void =>
    this.fail(new Error('SMTP connection closed unexpectedly'));
  private readonly onTimeout = (): void => {
    this.fail(new Error('SMTP connection timed out'));
    this.socket.destroy();
  };

  constructor(socket: net.Socket | tls.TLSSocket) {
    this.adopt(socket);
  }

  /** Move the conversation onto the TLS socket after STARTTLS. */
  adopt(socket: net.Socket | tls.TLSSocket): void {
    if (this.socket) this.detach();
    this.socket = socket;
    this.buffer = '';
    socket.setTimeout(SMTP_IDLE_TIMEOUT_MS);
    socket.on('data', this.onData);
    socket.on('error', this.onError);
    socket.on('close', this.onClose);
    socket.on('timeout', this.onTimeout);
  }

  fail(err: Error): void {
    this.failure ??= err;
    const waiter = this.waiter;
    this.waiter = null;
    waiter?.reject(err);
  }

  dispose(): void {
    this.detach();
  }

  private detach(): void {
    this.socket.off('data', this.onData);
    this.socket.off('error', this.onError);
    this.socket.off('close', this.onClose);
    this.socket.off('timeout', this.onTimeout);
  }

  /** Write a command and assert the reply code is one the caller expects. */
  async command(line: string, expected: string[]): Promise<string> {
    await this.write(line);
    return this.readReply(expected, line.split('\r\n')[0].split(' ')[0]);
  }

  private write(line: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.write(`${line}\r\n`, (err) => (err ? reject(err) : resolve()));
    });
  }

  /**
   * Await one complete reply and throw unless its code is expected. Without
   * this check a 530 reads exactly like a 250 and every alert is silently
   * dropped.
   */
  async readReply(expected: string[], context = 'greeting'): Promise<string> {
    const reply = await this.nextReply();
    const code = reply.slice(0, 3);
    if (!expected.includes(code)) {
      throw new Error(`SMTP ${context} failed: ${reply.trim()}`);
    }
    return reply;
  }

  private nextReply(): Promise<string> {
    if (this.failure) return Promise.reject(this.failure);
    const ready = this.takeReply();
    if (ready !== null) return Promise.resolve(ready);
    return new Promise<string>((resolve, reject) => {
      this.waiter = { resolve, reject };
    });
  }

  private drain(): void {
    if (!this.waiter) return;
    const reply = this.takeReply();
    if (reply === null) return;
    const waiter = this.waiter;
    this.waiter = null;
    waiter.resolve(reply);
  }

  /**
   * Pull one complete reply off the buffer, or null if it has not all arrived.
   * A multi-line reply continues while the 4th character is '-' and ends on
   * the first line whose 4th character is a space.
   */
  private takeReply(): string | null {
    const lines = this.buffer.split('\r\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\d{3} /.test(line)) {
        const reply = lines.slice(0, i + 1).join('\r\n');
        this.buffer = lines.slice(i + 1).join('\r\n');
        return reply;
      }
    }
    return null;
  }
}
