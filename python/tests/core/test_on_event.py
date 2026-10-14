"""on_event hook."""

from __future__ import annotations

from tzun_sdk import Tzun
from tzun_sdk.events import TzunEvent
from tzun_sdk.storage import MemoryAdapter


async def test_on_event_fires_on_capture() -> None:
    received: list[TzunEvent] = []
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        unsub = tzun.on_event(lambda e: received.append(e))
        await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        assert any(e.event_type == "decision_captured" for e in received)
        # PII (human_reason, ai_output) not in payload.
        captured = next(e for e in received if e.event_type == "decision_captured")
        assert "human_reason" not in captured.payload
        assert "humanReason" not in captured.payload
        assert "aiOutput" not in captured.payload
        unsub()
    finally:
        await tzun.close()
