"""Event-bus for tzun-sdk.

Applications register callbacks via ``Tzun.on_event(callback)`` and receive
typed :class:`TzunEvent` records for state-of-interest moments
(``decision_captured``, ``verification_completed``, ``tamper_detected``,
``circuit_opened``, ``descriptor_registered``, …).

The bus is intentionally narrow; OpenTelemetry integration is out of scope.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

LOG = logging.getLogger(__name__)

TzunEventCallback = Callable[["TzunEvent"], None]


class TzunEvent(BaseModel):
    """One SDK event delivered to ``on_event`` callbacks."""

    model_config = ConfigDict(extra="forbid")

    event_type: str
    timestamp: str
    payload: dict[str, Any] = Field(default_factory=dict)


class EventBus:
    """In-process event bus.

    Callbacks are invoked synchronously in registration order. Exceptions
    raised by a callback are logged at WARNING and swallowed so one
    misbehaving subscriber cannot break the SDK.
    """

    def __init__(self) -> None:
        self._callbacks: list[TzunEventCallback] = []

    def subscribe(self, cb: TzunEventCallback) -> Callable[[], None]:
        """Register a callback. Returns an unsubscribe function."""
        self._callbacks.append(cb)

        def _unsubscribe() -> None:
            try:
                self._callbacks.remove(cb)
            except ValueError:
                pass

        return _unsubscribe

    def dispatch(self, event: TzunEvent) -> None:
        """Deliver an event to every subscriber. Exceptions are swallowed."""
        for cb in list(self._callbacks):
            try:
                cb(event)
            except Exception:
                LOG.warning(
                    "event_callback_failed event_type=%s",
                    event.event_type,
                    exc_info=True,
                )

    def clear(self) -> None:
        self._callbacks.clear()


__all__ = ("EventBus", "TzunEvent", "TzunEventCallback")
