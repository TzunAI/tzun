"""attach() tests."""

from __future__ import annotations

import pytest

from tzun_sdk import Tzun, attach
from tzun_sdk.errors import TzunError
from tzun_sdk.models import DecisionInput
from tzun_sdk.storage import MemoryAdapter


class _FakeOpenAI:
    """Quack-alike OpenAI client; has chat.completions.create."""

    class _Chat:
        class _Completions:
            def __init__(self) -> None:
                self.last_kwargs: dict = {}

            async def create(self, **kwargs):  # type: ignore[no-untyped-def]
                self.last_kwargs = dict(kwargs)
                return {"model": "gpt-4o-2024-08-06", "choices": [{"text": "yes"}]}

        def __init__(self) -> None:
            self.completions = self._Completions()

    def __init__(self) -> None:
        self.chat = self._Chat()


async def test_attach_passthrough_when_no_tzun_capture() -> None:
    """Kwarg-absent path is pure pass-through."""
    inner = _FakeOpenAI()
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")
        out = await wrapped.chat.completions.create(model="gpt-4o-2024-08-06")
        assert out["model"] == "gpt-4o-2024-08-06"
        # Inner saw no tzun_capture kwarg.
        assert "tzun_capture" not in inner.chat.completions.last_kwargs
        # No capture was emitted.
        assert len(await tzun._storage.list()) == 0
    finally:
        await tzun.close()


async def test_attach_strips_tzun_capture_and_emits() -> None:
    """Kwarg stripped before forwarding; hook+capture fire."""
    inner = _FakeOpenAI()
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")
        await wrapped.chat.completions.create(
            model="gpt-4o-2024-08-06",
            tzun_capture=DecisionInput(
                action="approved",
                decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None}, reason="ok"
            ),
        )
        assert "tzun_capture" not in inner.chat.completions.last_kwargs
        envelopes = await tzun._storage.list()
        assert len(envelopes) == 1
        steps = envelopes[0].payload.contributions.steps
        assert len(steps) == 1 and steps[0].role == "propose" and steps[0].actor is None
        assert steps[0].aiBom is not None
    finally:
        await tzun.close()


async def test_attach_streaming_with_capture_raises() -> None:
    """stream=True + tzun_capture raises."""
    inner = _FakeOpenAI()
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")
        with pytest.raises(TzunError):
            await wrapped.chat.completions.create(
                model="gpt-4o-2024-08-06",
                stream=True,
                tzun_capture=DecisionInput(
                    action="approved",
                    decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None}, reason="ok"
                ),
            )
    finally:
        await tzun.close()


async def test_attach_forwards_decider_into_record_and_custody_chain() -> None:
    """On the 0.8.0 record: the decider reaches the hashed payload, and its id the custody actor.

    Asserted through the public path — call the wrapped client, then read the
    envelope the SDK actually stored.
    """
    inner = _FakeOpenAI()
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")
        await wrapped.chat.completions.create(
            model="gpt-4o-2024-08-06",
            tzun_capture=DecisionInput(
                action="approved",
                decider={"kind": "human", "id": "acct:carol"},
                reason="ok",
                aiSystemId="loan-desk",
            ),
        )
        envelopes = await tzun._storage.list()
        assert len(envelopes) == 1
        assert envelopes[0].payload.decider.id == "acct:carol"
        assert [e.actor for e in envelopes[0].custodyChain] == ["acct:carol"]
        assert envelopes[0].custodyChain[0].systemId == "loan-desk"
    finally:
        await tzun.close()


async def test_attach_warns_when_decision_input_metadata_is_dropped(caplog) -> None:
    """`metadata` has no v1 wire slot; it must be dropped LOUDLY, not silently."""
    import logging

    inner = _FakeOpenAI()
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")
        with caplog.at_level(logging.WARNING, logger="tzun_sdk.ai_bom.attach"):
            await wrapped.chat.completions.create(
                model="gpt-4o-2024-08-06",
                tzun_capture=DecisionInput(
                    action="approved",
                    decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
                    reason="ok",
                    metadata={"ticket": "OPS-1"},
                ),
            )
        assert any(
            "decision_input_metadata_dropped" in r.getMessage() for r in caplog.records
        )
    finally:
        await tzun.close()


# ── capture failure must not take the vendor response away ────────────────


class _SyncFakeOpenAI:
    """Quack-alike with a SYNCHRONOUS chat.completions.create."""

    class _Chat:
        class _Completions:
            def create(self, **kwargs):  # type: ignore[no-untyped-def]
                return {"model": "gpt-4o-2024-08-06", "choices": [{"text": "yes"}]}

        def __init__(self) -> None:
            self.completions = self._Completions()

    def __init__(self) -> None:
        self.chat = self._Chat()


async def test_capture_failure_still_returns_the_vendor_response() -> None:
    """Return the original vendor response unchanged.

    The vendor call has already completed — and already been billed — by the
    time capture runs. A storage failure that escaped the wrapper would leave
    the application paying for the completion and getting an exception
    instead of the text.
    """
    inner = _FakeOpenAI()
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")

        async def _boom(*a, **k):  # type: ignore[no-untyped-def]
            raise TzunError("storage unavailable")

        tzun.capture = _boom  # type: ignore[assignment,method-assign]

        out = await wrapped.chat.completions.create(
            model="gpt-4o-2024-08-06",
            tzun_capture=DecisionInput(action="approved", reason="ok", decider={"kind": "human", "id": "acct:test-reviewer"}),
        )
        assert out["choices"][0]["text"] == "yes"
    finally:
        await tzun.close()


async def test_capture_failure_is_logged_not_silent() -> None:
    """Swallowing must be observable — the failure goes to the module logger."""
    import logging

    inner = _FakeOpenAI()
    tzun = await Tzun.init(storage=MemoryAdapter())
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    log = logging.getLogger("tzun_sdk.ai_bom.attach")
    handler = _Capture()
    log.addHandler(handler)
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")

        async def _boom(*a, **k):  # type: ignore[no-untyped-def]
            raise TzunError("storage unavailable")

        tzun.capture = _boom  # type: ignore[assignment,method-assign]
        await wrapped.chat.completions.create(
            model="gpt-4o-2024-08-06",
            tzun_capture=DecisionInput(action="approved", reason="ok", decider={"kind": "human", "id": "acct:test-reviewer"}),
        )
        assert any(r.levelno >= logging.ERROR for r in records)
    finally:
        log.removeHandler(handler)
        await tzun.close()


async def test_sync_client_captures_from_inside_a_running_event_loop() -> None:
    """A sync vendor client used from an async app must still capture.

    anyio.run() on the calling thread raises
    RuntimeError('Already running asyncio in this thread') when a loop is
    already running there, i.e. on every captured call made from a FastAPI
    handler with a synchronous OpenAI client, so the capture must still land
    when the sync path is entered from inside a running loop.
    """
    inner = _SyncFakeOpenAI()
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")
        # This coroutine IS the running loop, so the sync path below is
        # invoked with asyncio.get_running_loop() succeeding.
        out = wrapped.chat.completions.create(
            model="gpt-4o-2024-08-06",
            tzun_capture=DecisionInput(action="approved", reason="ok", decider={"kind": "human", "id": "acct:test-reviewer"}),
        )
        assert out["choices"][0]["text"] == "yes"
        stored = await tzun._storage.list()
        assert len(stored) == 1, "the capture must actually have been recorded"
    finally:
        await tzun.close()
