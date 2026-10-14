"""Tzun lifecycle tests."""

from __future__ import annotations

import asyncio

import pytest

from tzun_sdk import Tzun
from tzun_sdk.errors import TzunError
from tzun_sdk.storage import MemoryAdapter


async def test_init_returns_active_instance() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    assert tzun.state == "ACTIVE"
    await tzun.close()


async def test_close_is_idempotent() -> None:
    """Two sequential closes; second is no-op."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    await tzun.close()
    await tzun.close()  # MUST NOT raise
    assert tzun.state == "CLOSED"


async def test_concurrent_close_safe() -> None:
    """Two concurrent closes both succeed."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    await asyncio.gather(tzun.close(), tzun.close())
    assert tzun.state == "CLOSED"


async def test_operations_on_closed_raise() -> None:
    """Capture/verify on CLOSED raises."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    await tzun.close()
    with pytest.raises(TzunError):
        await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )


async def test_async_context_manager() -> None:
    """``async with`` closes on exit."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    async with tzun:
        assert tzun.state == "ACTIVE"
    assert tzun.state == "CLOSED"
