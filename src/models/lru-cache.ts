/**
 * Tiny in-process LRU cache — wrapper-layer descriptor-digest cache.
 *
 * Used by the wrapper layer to memoize the descriptor-registration round
 * trip per `(vendor, modelName, modelVersion, knownModelsRefVersion)`
 * tuple. Default capacity is 256; callers may construct with a custom
 * capacity.
 *
 * Implementation note: JavaScript's `Map` preserves insertion order, which
 * is sufficient for an LRU. `get` and `set` bump recency by delete-then-
 * insert; eviction drops the iteration-order-oldest entry once `size >
 * capacity`. No external deps; deterministic; safe for the hot path
 * (no I/O).
 */

export class LruCache<K, V> {
  private readonly capacity: number;
  private readonly store: Map<K, V>;

  constructor(capacity: number = 256) {
    if (!Number.isInteger(capacity) || capacity <= 0) {
      throw new Error(
        `LruCache capacity must be a positive integer (got ${String(capacity)})`,
      );
    }
    this.capacity = capacity;
    this.store = new Map();
  }

  /**
   * Returns the cached value for `key`, bumping it to most-recently-used.
   * Returns `undefined` on miss.
   */
  get(key: K): V | undefined {
    if (!this.store.has(key)) return undefined;
    const value = this.store.get(key) as V;
    // Bump recency: delete-then-set moves the entry to the tail of the
    // insertion-order map, which is the LRU "youngest" slot.
    this.store.delete(key);
    this.store.set(key, value);
    return value;
  }

  /**
   * Inserts or refreshes a key. On overflow, drops the iteration-order
   * head entry (the oldest, least-recently-used).
   */
  set(key: K, value: V): void {
    if (this.store.has(key)) {
      // Refresh recency by removing first so the re-insert lands at the tail.
      this.store.delete(key);
    }
    this.store.set(key, value);
    if (this.store.size > this.capacity) {
      // Map iteration is insertion-ordered → first key is the oldest.
      const oldestKey = this.store.keys().next().value as K | undefined;
      if (oldestKey !== undefined) {
        this.store.delete(oldestKey);
      }
    }
  }

  has(key: K): boolean {
    return this.store.has(key);
  }

  size(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }
}
