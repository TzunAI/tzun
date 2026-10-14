"""``tzun_sdk.attach()`` — optional per-call opt-in sugar.

``attach(client, *, tzun)`` returns a quack-alike wrapper that forwards
attribute access via ``__getattr__`` but intercepts vendor-specific
methods. When the caller passes ``tzun_capture=DecisionInput(...)``, the
wrapper:

1. Strips the kwarg before forwarding.
2. Calls the underlying client.
3. Builds an AI-BOM via ``hook()``. When ``hook()`` fails (the connector
   cannot read the call, or registering the descriptor fails), it logs
   ``event=connector_hook_failure`` and goes on without the model.
4. Calls ``tzun.capture(...)`` with the AI-BOM as the record's one
   contribution step (Record §7.3), or with
   ``contributions=None`` when there is no AI-BOM.

When ``tzun_capture`` is absent, the wrapper is a pure pass-through.
``stream=True`` + ``tzun_capture`` raises.

Capture-failure contract ("return the original vendor response
unchanged"): the vendor call has already happened and has already
been paid for by the time capture runs, so a storage or hook failure MUST
NOT take the response away from the caller. Such a failure is logged at
ERROR through this module's logger and the response is returned. This
matches the TypeScript SDK's onLog path. A malformed ``tzun_capture``
payload is a different thing — a deterministic caller mistake that does not
depend on the backend — and still raises.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import logging
from typing import TYPE_CHECKING, Any, cast

from tzun_sdk.ai_bom.hook import hook
from tzun_sdk.contributions import single_model
from tzun_sdk.errors import TzunError
from tzun_sdk.models import DecisionInput

if TYPE_CHECKING:
    from tzun_sdk.core import Tzun

LOG = logging.getLogger(__name__)

TZUN_ATTACHED_MARKER = "_tzun_attached"
TZUN_CAPTURE_KWARG = "tzun_capture"

#: Method-paths each vendor's client exposes that we intercept.
#: Other methods/attributes pass through unchanged.
INTERCEPTED_PATHS: dict[str, list[tuple[str, ...]]] = {
    "openai": [("chat", "completions", "create"), ("responses", "create")],
    "anthropic": [("messages", "create"), ("messages", "stream")],
    "bedrock": [("converse",), ("invoke_model",)],
    "vertex": [("generate_content",), ("predict",)],
    "azure_ai": [("complete",), ("chat",)],
}


def _detect_vendor(client: Any) -> str | None:
    """Duck-type detect the vendor from the client's class hierarchy."""
    module = type(client).__module__ or ""
    qualname = type(client).__qualname__ or ""
    haystack = f"{module}.{qualname}".lower()
    if "azureopenai" in haystack or "azure.openai" in haystack:
        # Azure-OpenAI shape — caller should pass vendor='openai' explicitly
        # if they want the azure-detection path; default to openai.
        return "openai"
    for name in ("openai", "anthropic", "vertex"):
        if name in haystack:
            return name
    if "boto" in haystack or "bedrock" in haystack:
        return "bedrock"
    if "azure" in haystack:
        return "azure_ai"
    return None


def attach(
    client: Any,
    *,
    tzun: Tzun,
    vendor: str | None = None,
) -> Any:
    """Wrap ``client`` to support per-call ``tzun_capture`` opt-in.

    Returns a wrapper that forwards every attribute except the intercepted
    methods listed in :data:`INTERCEPTED_PATHS`. The intercepted methods
    strip the ``tzun_capture`` kwarg before forwarding, then call
    ``hook() + tzun.capture()`` if ``tzun_capture`` was present.

    ``vendor`` is auto-detected from the client class when omitted; pass
    explicitly to disambiguate (e.g., Azure-OpenAI vs. OpenAI direct).

    Re-attaching a wrapped client returns the same wrapper (no nesting).
    """
    if getattr(client, TZUN_ATTACHED_MARKER, False):
        return client
    resolved_vendor = vendor or _detect_vendor(client)
    if resolved_vendor not in INTERCEPTED_PATHS:
        raise TzunError(
            f"attach(): cannot detect a supported vendor from {type(client).__name__!r}. "
            f"Pass vendor= explicitly. Supported: {list(INTERCEPTED_PATHS)}."
        )
    return _TzunAttachedClient(client, tzun=tzun, vendor=resolved_vendor)


class _TzunAttachedClient:
    """Wrapper installed by :func:`attach`."""

    __slots__ = ("_inner", "_method_cache", "_tzun", "_vendor")

    def __init__(self, inner: Any, *, tzun: Tzun, vendor: str) -> None:
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_tzun", tzun)
        object.__setattr__(self, "_vendor", vendor)
        object.__setattr__(self, "_method_cache", {})
        try:
            object.__setattr__(inner, TZUN_ATTACHED_MARKER, True)
        except (AttributeError, TypeError):
            pass

    def __getattr__(self, name: str) -> Any:
        inner = object.__getattribute__(self, "_inner")
        vendor = object.__getattribute__(self, "_vendor")
        attr = getattr(inner, name)
        # Check if this is an intercepted top-level path.
        paths = INTERCEPTED_PATHS.get(vendor, [])
        for path in paths:
            if path[0] == name:
                return _AttrProxy(self, attr, path[1:], vendor)
        return attr

    # ── Helpers used by the proxy ──────────────────────────────

    async def _maybe_capture_async(
        self,
        params: dict[str, Any],
        response: Any,
        capture_input: DecisionInput,
    ) -> None:
        vendor = object.__getattribute__(self, "_vendor")
        tzun = object.__getattribute__(self, "_tzun")
        try:
            ai_bom = await hook(vendor, params, response, tzun=tzun)
        except Exception as exc:
            # The connector failed on the call's shape, or the descriptor's
            # registration failed (a backend 5xx, a 401, a timeout). The
            # decision is still captured, without its model; this line is the
            # signal that the model was lost. The error's class name only:
            # its message can echo caller-supplied values. The TS twin is the
            # wrapper's `connector_hook_failure`.
            LOG.warning(
                "event=connector_hook_failure vendor=%s error_name=%s",
                vendor,
                type(exc).__name__,
            )
            ai_bom = None
        ai_output = _coerce_to_dict(response)
        if capture_input.metadata is not None:
            # `metadata` has no slot in the shared v1 wire envelope and the TS
            # DecisionInput (src/sdk/wrappers.ts:68-73) has no such field, so
            # forwarding it would put Python-only bytes on the wire. It is
            # dropped deliberately — but say so, rather than swallowing it.
            LOG.warning(
                "event=decision_input_metadata_dropped vendor=%s keys=%s "
                "reason=no_wire_slot_in_v1_envelope",
                vendor,
                sorted(capture_input.metadata),
            )
        # The model the call used is the record's one contribution step
        # (Record §7.3): the caller's own `aiBom` when it names one,
        # otherwise the one hook() resolved from the call.
        model = capture_input.aiBom if capture_input.aiBom is not None else ai_bom
        await tzun.capture(
            ai_output=ai_output,
            action=capture_input.action,
            reason=capture_input.reason,
            decider=capture_input.decider,
            contributions=single_model(model, actor=capture_input.actor) if model is not None else None,
            links=capture_input.links,
            ai_system_id=capture_input.aiSystemId,
        )

    def _maybe_capture_sync(
        self,
        params: dict[str, Any],
        response: Any,
        capture_input: DecisionInput,
    ) -> None:
        import anyio

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No loop on this thread — the ordinary sync-script case.
            anyio.run(self._maybe_capture_async, params, response, capture_input)
            return

        # A loop IS already running on this thread: a sync vendor client used
        # from inside an async application (a sync OpenAI client called from a
        # FastAPI handler, say). anyio.run() would raise
        # RuntimeError("Already running asyncio in this thread") on every
        # captured call. Run the capture on a worker thread with its own loop.
        # The caller is already blocking this thread — the vendor call it just
        # made was synchronous — so waiting here changes no concurrency
        # property that was not already given up.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(
                anyio.run, self._maybe_capture_async, params, response, capture_input
            ).result()


class _AttrProxy:
    """Recursive proxy walking the intercepted-method path."""

    def __init__(
        self,
        root: _TzunAttachedClient,
        bound: Any,
        remaining: tuple[str, ...],
        vendor: str,
    ) -> None:
        object.__setattr__(self, "_root", root)
        object.__setattr__(self, "_bound", bound)
        object.__setattr__(self, "_remaining", remaining)
        object.__setattr__(self, "_vendor", vendor)

    def __getattr__(self, name: str) -> Any:
        bound = object.__getattribute__(self, "_bound")
        remaining = object.__getattribute__(self, "_remaining")
        attr = getattr(bound, name)
        if not remaining or remaining[0] != name:
            return attr
        new_remaining = remaining[1:]
        if not new_remaining:
            return _make_intercepted(
                root=object.__getattribute__(self, "_root"),
                callable_=attr,
                vendor=object.__getattribute__(self, "_vendor"),
            )
        return _AttrProxy(
            object.__getattribute__(self, "_root"),
            attr,
            new_remaining,
            object.__getattribute__(self, "_vendor"),
        )


def _make_intercepted(
    *,
    root: _TzunAttachedClient,
    callable_: Any,
    vendor: str,
) -> Any:
    """Wrap an intercepted vendor method to handle ``tzun_capture``."""
    is_coroutine = inspect.iscoroutinefunction(callable_)

    if is_coroutine:

        async def _async_call(*args: Any, **kwargs: Any) -> Any:
            capture = kwargs.pop(TZUN_CAPTURE_KWARG, None)
            stream = kwargs.get("stream", False)
            if stream and capture is not None:
                raise TzunError(
                    "attach(): tzun_capture is not supported with stream=True. "
                    "Use hook() directly for streaming responses."
                )
            response = await callable_(*args, **kwargs)
            if capture is not None:
                if not isinstance(capture, DecisionInput):
                    capture = DecisionInput.model_validate(capture)
                params = dict(kwargs)
                try:
                    await root._maybe_capture_async(params, response, capture)
                except Exception:  # see module docstring: the return-response contract
                    LOG.error(
                        "attach(): capture failed after a successful vendor call; "
                        "returning the vendor response unchanged",
                        exc_info=True,
                    )
            return response

        return _async_call

    def _sync_call(*args: Any, **kwargs: Any) -> Any:
        capture = kwargs.pop(TZUN_CAPTURE_KWARG, None)
        stream = kwargs.get("stream", False)
        if stream and capture is not None:
            raise TzunError(
                "attach(): tzun_capture is not supported with stream=True. "
                "Use hook() directly for streaming responses."
            )
        response = callable_(*args, **kwargs)
        if capture is not None:
            if not isinstance(capture, DecisionInput):
                capture = DecisionInput.model_validate(capture)
            params = dict(kwargs)
            try:
                root._maybe_capture_sync(params, response, capture)
            except Exception:  # see module docstring: the return-response contract
                LOG.error(
                    "attach(): capture failed after a successful vendor call; "
                    "returning the vendor response unchanged",
                    exc_info=True,
                )
        return response

    return _sync_call


def _coerce_to_dict(value: Any) -> dict[str, Any]:
    """Coerce a vendor SDK response object into a plain dict."""
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "model_dump"):
        try:
            return cast("dict[str, Any]", value.model_dump())
        except Exception:
            pass
    if hasattr(value, "to_dict"):
        try:
            return cast("dict[str, Any]", value.to_dict())
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        return {k: v for k, v in vars(value).items() if not k.startswith("_")}
    return {"value": repr(value)}


__all__ = ("INTERCEPTED_PATHS", "TZUN_ATTACHED_MARKER", "TZUN_CAPTURE_KWARG", "attach")
