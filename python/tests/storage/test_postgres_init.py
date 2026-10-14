"""Two-process concurrent ensure_tables race — proves the advisory lock.

Gated behind RUN_INTEGRATION_TESTS=true per conftest.py marker.
"""
from __future__ import annotations

import multiprocessing
import os

import pytest

# The local Postgres container.
_PG_HOST = "host.docker.internal"

pytestmark = pytest.mark.integration

DB_URL = os.environ.get(
    "DATABASE_URL",
    f"postgres://postgres:dev@{_PG_HOST}:55432/tzun_dev",
)


def _init_worker(dsn: str, result_queue: multiprocessing.Queue) -> None:  # type: ignore[type-arg]
    """Run ensure_tables() in a subprocess and report success/failure."""
    import asyncio

    from tzun_sdk.storage.postgres import PostgresAdapter

    async def _run() -> None:
        a = PostgresAdapter(dsn, mode="async")
        await a.ensure_tables()
        await a.close()

    try:
        asyncio.run(_run())
        result_queue.put(("ok", None))
    except Exception as exc:
        result_queue.put(("error", str(exc)))


@pytest.mark.anyio
async def test_concurrent_ensure_tables_two_processes():
    """Spawn two processes both calling ensure_tables() concurrently.

    The advisory lock (pg_advisory_lock(2026052501)) serializes the DDL
    run; both processes must finish without error.
    """
    ctx = multiprocessing.get_context("spawn")
    q: multiprocessing.Queue = ctx.Queue()  # type: ignore[type-arg]

    p1 = ctx.Process(target=_init_worker, args=(DB_URL, q))
    p2 = ctx.Process(target=_init_worker, args=(DB_URL, q))
    p1.start()
    p2.start()
    p1.join(timeout=30)
    p2.join(timeout=30)

    results = [q.get_nowait() for _ in range(2)]
    errors = [(s, m) for s, m in results if s == "error"]
    assert not errors, f"Concurrent init raised: {errors}"
