/**
 * LRU cache unit tests.
 *
 * The cache is small, deterministic, and consumed exclusively by the
 * wrapper layer. Tests assert the LRU contract: get / set recency,
 * capacity-driven eviction, and clear/size accounting.
 */

import { LruCache } from '../../src/models/lru-cache';

describe('LruCache', () => {
  it('returns undefined on miss and stores on set', () => {
    const cache = new LruCache<string, number>(4);
    expect(cache.get('a')).toBeUndefined();
    cache.set('a', 1);
    expect(cache.get('a')).toBe(1);
    expect(cache.size()).toBe(1);
    expect(cache.has('a')).toBe(true);
  });

  it('defaults to capacity 256', () => {
    const cache = new LruCache<number, number>();
    for (let i = 0; i < 256; i++) cache.set(i, i);
    expect(cache.size()).toBe(256);
    cache.set(256, 256);
    expect(cache.size()).toBe(256);
    // Oldest entry (0) should have been evicted.
    expect(cache.has(0)).toBe(false);
    expect(cache.has(256)).toBe(true);
  });

  it('evicts the least-recently-used entry on overflow', () => {
    const cache = new LruCache<string, number>(3);
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);
    // Touch 'a' → 'b' becomes the LRU.
    expect(cache.get('a')).toBe(1);
    cache.set('d', 4);
    expect(cache.has('b')).toBe(false);
    expect(cache.has('a')).toBe(true);
    expect(cache.has('c')).toBe(true);
    expect(cache.has('d')).toBe(true);
  });

  it('refreshes recency on set of an existing key (no eviction)', () => {
    const cache = new LruCache<string, number>(2);
    cache.set('a', 1);
    cache.set('b', 2);
    // Re-set 'a' → 'b' is now the LRU.
    cache.set('a', 10);
    cache.set('c', 3);
    expect(cache.has('b')).toBe(false);
    expect(cache.get('a')).toBe(10);
    expect(cache.get('c')).toBe(3);
  });

  it('clear() empties the cache', () => {
    const cache = new LruCache<string, number>(3);
    cache.set('a', 1);
    cache.set('b', 2);
    expect(cache.size()).toBe(2);
    cache.clear();
    expect(cache.size()).toBe(0);
    expect(cache.has('a')).toBe(false);
  });

  it('rejects invalid capacities', () => {
    expect(() => new LruCache<string, number>(0)).toThrow(/positive integer/);
    expect(() => new LruCache<string, number>(-1)).toThrow(/positive integer/);
    expect(() => new LruCache<string, number>(2.5)).toThrow(/positive integer/);
  });
});
