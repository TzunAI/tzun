"""A ``store`` fixture over every local adapter: memory, SQLite, and Postgres when ``RUN_INTEGRATION_TESTS=true``.

The Postgres leg needs ``DATABASE_URL`` naming ``tzun_sdk_conf_test`` and
empties the Python SDK's tables before each case.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlparse

import pytest

from tzun_sdk.storage import MemoryAdapter, PostgresAdapter, SqliteAdapter

CONF_DB = "tzun_sdk_conf_test"
DATABASE_URL = os.environ.get("DATABASE_URL", "")

STORES = [
    "memory",
    "sqlite",
    pytest.param("postgres", marks=pytest.mark.integration),
]

_TABLES = (
    "evidence_envelopes, attestations, recovery_records, tzun_py_tamper_incidents, envelope_revisions, "
    "model_descriptor_annotations, model_descriptor_aliases, model_descriptors, decider_openings, "
    "tzun_py_agent_descriptors, tzun_py_evidence_links, tzun_py_mandates, tzun_py_mandate_totals, "
    "tzun_py_mandate_events"
)


async def _wipe_postgres(url: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(dsn=url)
    try:
        async with conn.transaction():
            await conn.execute("SET LOCAL session_replication_role = 'replica'")
            await conn.execute(f"TRUNCATE {_TABLES} CASCADE")
    finally:
        await conn.close()


async def open_store(kind: str, tmp_path: Any) -> Any:
    if kind == "memory":
        return MemoryAdapter()
    if kind == "sqlite":
        return SqliteAdapter(str(tmp_path / "store.db"), mode="async")
    if urlparse(DATABASE_URL).path != f"/{CONF_DB}":
        pytest.skip(f"DATABASE_URL must name /{CONF_DB} to run the Postgres leg")
    store = PostgresAdapter(DATABASE_URL, mode="async")
    await store.ensure_tables()
    await _wipe_postgres(DATABASE_URL)
    return store


@pytest.fixture(params=STORES)
async def store(request: pytest.FixtureRequest, tmp_path: Any) -> AsyncIterator[Any]:
    s = await open_store(request.param, tmp_path)
    yield s
    # ``Tzun.close()`` closes its store; a test that never opened one leaves it open.
    with contextlib.suppress(Exception):
        await s.close()
