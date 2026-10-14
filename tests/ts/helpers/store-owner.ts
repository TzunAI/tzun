/**
 * Writes only a store's owner can make: a store-write attacker who steps
 * around a rule the store holds. A test of a
 * detector that must catch such a write builds the store state with these.
 */
import type { EvidenceEnvelope, StorageAdapter } from '@tzun/engine';

/**
 * Store `envelope` at a chain position another record already holds: on the
 * memory adapter its position map is cleared first; on SQLite the
 * `envelopes_position` index is dropped. Either way the store's other rules
 * still apply.
 */
export async function storeAtTakenPosition(storage: StorageAdapter, envelope: EvidenceEnvelope, chainId?: string): Promise<void> {
  const inner = (storage as unknown as { unwrap?: () => StorageAdapter }).unwrap?.() ?? storage;
  const memory = inner as unknown as { positions?: Map<string, string> };
  if (memory.positions instanceof Map) {
    memory.positions.clear();
  }
  const sqlite = inner as unknown as { db?: { exec(sql: string): void } };
  if (sqlite.db && typeof sqlite.db.exec === 'function') {
    sqlite.db.exec('DROP INDEX IF EXISTS envelopes_position');
  }
  await inner.store(envelope, chainId);
}
