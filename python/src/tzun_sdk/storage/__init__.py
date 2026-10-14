"""Storage adapters for tzun-sdk.

Four adapters:

* :class:`MemoryAdapter` — in-process dict-backed (default for tests).
* :class:`SqliteAdapter` — ``aiosqlite`` + stdlib ``sqlite3`` (requires
  the ``[sqlite]`` extra).
* :class:`PostgresAdapter` — ``asyncpg`` + ``psycopg`` (requires
  the ``[postgres]`` extra).
* :class:`HttpBackendAdapter` — ``httpx`` against ``api.tzun.ai`` /
  custom backend.

All implement the :class:`StorageAdapter` ``Protocol`` declared in
``_protocol.py``. Method names are snake_case (Python
convention) regardless of the TS interface's camelCase.
"""

from __future__ import annotations

from tzun_sdk.storage._protocol import StorageAdapter
from tzun_sdk.storage.http import HttpBackendAdapter
from tzun_sdk.storage.memory import MemoryAdapter

# SqliteAdapter and PostgresAdapter live under the optional extras and
# raise MissingExtraError if the extra isn't installed.
from tzun_sdk.storage.postgres import PostgresAdapter
from tzun_sdk.storage.sqlite import SqliteAdapter

__all__ = (
    "HttpBackendAdapter",
    "MemoryAdapter",
    "PostgresAdapter",
    "SqliteAdapter",
    "StorageAdapter",
)
