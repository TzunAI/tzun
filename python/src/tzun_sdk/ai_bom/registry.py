"""Descriptor LRU cache + per-digest dedup map.

The cache is bound to a ``Tzun`` instance. Default size 256; configurable via
``Tzun.init(descriptor_cache_size=N)``. Per-digest locks deduplicate
concurrent ``hook()`` calls so at most one catalog write per unique digest
fires even under heavy contention.
"""

from __future__ import annotations

import asyncio
import threading
from collections import OrderedDict
from typing import Any

DEFAULT_CACHE_SIZE = 256


class DescriptorCache:
    """LRU cache mapping ``modelDigest`` → ``ModelDescriptor``.

    The cache is empty on ``Tzun.init()`` and discarded on ``Tzun.close()``.
    Entries are inserted on ``hook()`` and ``tzun.models.register()`` and
    looked up on ``verify()`` and ``hook()``.
    """

    def __init__(self, capacity: int = DEFAULT_CACHE_SIZE) -> None:
        if capacity < 1:
            raise ValueError(f"capacity must be >= 1, got {capacity}")
        self._capacity = capacity
        self._cache: OrderedDict[str, Any] = OrderedDict()
        self._async_locks: dict[str, asyncio.Lock] = {}
        self._sync_locks: dict[str, threading.Lock] = {}
        self._lock_map_lock = threading.Lock()

    def get(self, digest: str) -> Any | None:
        try:
            value = self._cache.pop(digest)
        except KeyError:
            return None
        self._cache[digest] = value
        return value

    def put(self, digest: str, value: Any) -> None:
        if digest in self._cache:
            self._cache.pop(digest)
        self._cache[digest] = value
        while len(self._cache) > self._capacity:
            self._cache.popitem(last=False)

    def invalidate(self, digest: str) -> None:
        """Remove ``digest`` from the cache."""
        self._cache.pop(digest, None)

    def clear(self) -> None:
        """Evict every entry."""
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, digest: object) -> bool:
        return digest in self._cache

    # ── Dedup lock map ────────────────────────────────

    def async_lock_for(self, digest: str) -> asyncio.Lock:
        """Get-or-create the asyncio.Lock for ``digest``."""
        with self._lock_map_lock:
            lock = self._async_locks.get(digest)
            if lock is None:
                lock = asyncio.Lock()
                self._async_locks[digest] = lock
            return lock

    def sync_lock_for(self, digest: str) -> threading.Lock:
        """Get-or-create the threading.Lock for ``digest`` (TzunSync path)."""
        with self._lock_map_lock:
            lock = self._sync_locks.get(digest)
            if lock is None:
                lock = threading.Lock()
                self._sync_locks[digest] = lock
            return lock


__all__ = ("DEFAULT_CACHE_SIZE", "DescriptorCache")
