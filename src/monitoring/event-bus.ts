import { MonitoringEvent, MonitoringEventHandler } from '@tzun/engine';

export class MonitoringEventBus {
  private handlers: Set<MonitoringEventHandler> = new Set();

  subscribe(handler: MonitoringEventHandler): void {
    this.handlers.add(handler);
  }

  unsubscribe(handler: MonitoringEventHandler): void {
    this.handlers.delete(handler);
  }

  emit(event: MonitoringEvent): void {
    for (const handler of this.handlers) {
      try {
        handler(event);
      } catch (err) {
        console.error(`[MonitoringEventBus] Subscriber threw on "${event.type}":`,
          err instanceof Error ? err.message : err);
      }
    }
  }
}
