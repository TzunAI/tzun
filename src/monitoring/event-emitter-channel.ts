import { EventEmitter } from 'events';
import { NotificationChannel, TamperIncident, ScanSummary } from '@tzun/engine';

/**
 * Event Emitter Channel (Tier 1 -- Developer)
 *
 * Standard Node.js EventEmitter pattern. Always available, zero configuration.
 * Implements NotificationChannel so it can be registered with the
 * NotificationRouter.
 *
 * Events:
 *   'tamper'         - Emitted when a TamperIncident is created
 *   'scan.completed' - Emitted when a full scan pass completes
 */
export class EventEmitterChannel implements NotificationChannel {
  readonly name = 'event-emitter';
  private emitter = new EventEmitter();

  /**
   * Register a listener for monitoring events.
   */
  on(event: 'tamper', listener: (incident: TamperIncident) => void): void;
  on(event: 'scan.completed', listener: (summary: ScanSummary) => void): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  on(event: string, listener: (...args: any[]) => void): void {
    this.emitter.on(event, listener);
  }

  /**
   * Remove a listener.
   */
  off(event: 'tamper', listener: (incident: TamperIncident) => void): void;
  off(event: 'scan.completed', listener: (summary: ScanSummary) => void): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  off(event: string, listener: (...args: any[]) => void): void {
    this.emitter.off(event, listener);
  }

  /**
   * Emit a tamper incident event.
   * Called by the TamperDetector via the NotificationRouter.
   */
  emitTamper(incident: TamperIncident): void {
    this.emitter.emit('tamper', incident);
  }

  /**
   * Emit a scan completed event.
   */
  emitScanCompleted(summary: ScanSummary): void {
    this.emitter.emit('scan.completed', summary);
  }

  /**
   * NotificationChannel.send() -- routes to emitTamper().
   */
  async send(incident: TamperIncident): Promise<void> {
    this.emitTamper(incident);
  }

  /**
   * NotificationChannel.test() -- always succeeds (no external dependencies).
   */
  async test(): Promise<void> {
    // No external dependencies to validate; emit a no-op test event.
  }
}
