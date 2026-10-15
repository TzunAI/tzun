"""OpenRouter through ``attach()`` and ``hook("openrouter", ...)``.

The Python twin of ``tests/ts/wrappers/openrouter.test.ts``. An OpenAI SDK
client pointed at OpenRouter has OpenAI's call surface, so ``attach()`` tells
them apart by the client's base URL: a host of ``openrouter.ai`` is the
gateway. Its captures register a descriptor with ``vendor: 'openrouter'`` (not
``openai``), record the base URL as ``infrastructure.endpoint`` and the
upstream OpenRouter names as ``infrastructure.provider``. The base URL is read
off the client instance and given to the connector only; it never reaches the
forwarded call.

The fake clients and responses are synthetic.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from tzun_sdk import Tzun, attach, hook
from tzun_sdk.ai_bom.attach import INTERCEPTED_PATHS, _detect_vendor
from tzun_sdk.ai_bom.connectors.openrouter import openrouter_endpoint
from tzun_sdk.errors import TzunError
from tzun_sdk.models import DecisionInput, ModelDescriptor
from tzun_sdk.storage import MemoryAdapter

DECIDER = {"kind": "human", "id": "acct:u-test", "agent": None, "credential": None, "freshness": None}


def gateway_response(model: str, provider: str | None = "Nvidia") -> dict[str, Any]:
    """``provider=None`` leaves the member out, as a response that names no upstream."""
    response: dict[str, Any] = {
        "id": "gen-0000000000-scrubbed000000000000",
        "object": "chat.completion",
        "created": 1790000000,
        "model": model,
        "system_fingerprint": None,
        "service_tier": None,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "native_finish_reason": "stop",
                "logprobs": None,
                "message": {"role": "assistant", "content": "approve", "refusal": None, "reasoning": None},
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
    }
    if provider is not None:
        response["provider"] = provider
    return response


class _URL:
    """Stand-in for ``httpx.URL``: not a ``str``, renders as one."""

    def __init__(self, text: str) -> None:
        self._text = text

    def __str__(self) -> str:
        return self._text


class _FakeOpenAI:
    """Quack-alike openai-python client: ``base_url`` on the instance, ``chat.completions.create``."""

    class _Chat:
        class _Completions:
            def __init__(self, response: dict[str, Any]) -> None:
                self.response = response
                self.calls: list[dict[str, Any]] = []

            async def create(self, **kwargs: Any) -> dict[str, Any]:
                self.calls.append(dict(kwargs))
                return self.response

        def __init__(self, response: dict[str, Any]) -> None:
            self.completions = self._Completions(response)

    def __init__(self, base_url: str | None, response: dict[str, Any]) -> None:
        if base_url is not None:
            # openai-python keeps an httpx.URL, and its base_url ends with `/`.
            self.base_url = _URL(base_url)
        self.chat = self._Chat(response)


class _FakeSyncOpenAI:
    """The synchronous client shape."""

    class _Chat:
        class _Completions:
            def __init__(self, response: dict[str, Any]) -> None:
                self.response = response
                self.calls: list[dict[str, Any]] = []

            def create(self, **kwargs: Any) -> dict[str, Any]:
                self.calls.append(dict(kwargs))
                return self.response

        def __init__(self, response: dict[str, Any]) -> None:
            self.completions = self._Completions(response)

    def __init__(self, base_url: str, response: dict[str, Any]) -> None:
        self.base_url = _URL(base_url)
        self.chat = self._Chat(response)


def capture_input() -> DecisionInput:
    return DecisionInput(action="approved", decider=DECIDER, reason="ok")


async def _init() -> tuple[Tzun, list[ModelDescriptor]]:
    """A Tzun on a memory store, and the descriptors it registers."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    registered: list[ModelDescriptor] = []
    original = tzun._storage.register_descriptor

    async def spy(descriptor: ModelDescriptor) -> str:
        registered.append(descriptor)
        digest: str = await original(descriptor)
        return digest

    tzun._storage.register_descriptor = spy  # type: ignore[method-assign]
    return tzun, registered


async def _stored_ai_bom(tzun: Tzun) -> tuple[dict[str, Any], dict[str, Any]]:
    """The one stored record's aiBom and aiOutput, as plain JSON."""
    envelopes = await tzun._storage.list()
    assert len(envelopes) == 1
    payload = envelopes[0].payload
    steps = payload.contributions.steps
    assert len(steps) == 1 and steps[0].aiBom is not None
    ai_bom: dict[str, Any] = steps[0].aiBom.model_dump(mode="json", exclude_none=False)
    ai_output: dict[str, Any] = payload.aiOutput
    return ai_bom, ai_output


def test_openrouter_intercepts_chat_completions_only() -> None:
    assert INTERCEPTED_PATHS["openrouter"] == [("chat", "completions", "create")]


async def test_detects_a_client_on_openrouter_and_records_the_gateway_truthfully() -> None:
    inner = _FakeOpenAI("https://openrouter.ai/api/v1/", gateway_response("nvidia/nemotron-3-super-120b-a12b:free"))
    tzun, registered = await _init()
    try:
        wrapped = attach(inner, tzun=tzun)
        await wrapped.chat.completions.create(
            model="nvidia/nemotron-3-super-120b-a12b:free",
            messages=[{"role": "user", "content": "Approve?"}],
            temperature=0.2,
            max_tokens=1200,
            tzun_capture=capture_input(),
        )

        # The forwarded call carries neither the capture kwarg nor the endpoint hint.
        forwarded = inner.chat.completions.calls[0]
        assert sorted(forwarded) == ["max_tokens", "messages", "model", "temperature"]

        assert len(registered) == 1
        d = registered[0]
        assert d.vendor == "openrouter"
        assert d.modelName == "nvidia/nemotron-3-super-120b-a12b:free"
        assert d.trainedBy == "nvidia"
        assert d.license == "nvidia-nemotron-open-model-license"
        assert d.integrityTier == "vendor-asserted"

        ai_bom, ai_output = await _stored_ai_bom(tzun)
        assert ai_bom["modelDescriptorDigest"].startswith("sha256:")
        # openai-python's trailing slash is dropped: the same endpoint TS records.
        assert ai_bom["infrastructure"] == {
            "provider": "Nvidia",
            "region": None,
            "apiVersion": None,
            "endpoint": "https://openrouter.ai/api/v1",
        }
        assert ai_bom["inferenceParameters"] == {
            "temperature": 0.2,
            "topP": None,
            "maxTokens": 1200,
            "seed": None,
            "stopSequences": None,
        }
        # The record's aiOutput keeps the gateway's own facts.
        assert ai_output["provider"] == "Nvidia"
        assert ai_output["model"] == "nvidia/nemotron-3-super-120b-a12b:free"
    finally:
        await tzun.close()


async def test_an_httpx_url_base_url_records_the_endpoint_ts_records() -> None:
    """openai-python keeps an ``httpx.URL``: host lowercased, default port dropped, ``/`` appended.

    openai-node keeps ``https://OpenRouter.AI:443/api/v1`` as given, and the
    connector normalises that raw string to the same endpoint.
    """
    inner = _FakeOpenAI(None, gateway_response("openai/gpt-6-astra", "OpenAI"))
    inner.base_url = httpx.URL("https://OpenRouter.AI:443/api/v1/")  # type: ignore[assignment]
    tzun, _ = await _init()
    try:
        wrapped = attach(inner, tzun=tzun)
        await wrapped.chat.completions.create(model="openai/gpt-6-astra", messages=[], tzun_capture=capture_input())
        ai_bom, _ = await _stored_ai_bom(tzun)
        assert ai_bom["infrastructure"]["endpoint"] == "https://openrouter.ai/api/v1"
        assert openrouter_endpoint("https://OpenRouter.AI:443/api/v1") == "https://openrouter.ai/api/v1"
    finally:
        await tzun.close()


@pytest.mark.parametrize(
    "base_url",
    [
        "https://openrouter.ai/api/v1",
        "https://OpenRouter.AI:443/api/v1",
        "https://OPENROUTER.ai",
        "https://openrouter.ai:443",
        "http://openrouter.ai:80/x",
        "http://openrouter.ai:443/x",
        "https://openrouter.ai:80/x",
        "https://openrouter.ai:8443/api/v1",
        "https://[::1]:443/api/v1",
        "https://[::ABCD]:443/v1",
        "https://Gateway.Example.COM/API/V1",
        "https://Key:@OpenRouter.AI/api/v1",
        "https://openrouter.ai/api/v1?x=1",
    ],
)
def test_the_endpoint_of_an_httpx_url_is_the_endpoint_of_the_raw_string(base_url: str) -> None:
    """What the Python attach path reads (``str(httpx.URL(...))``) and what TS reads (the raw string) agree."""
    assert openrouter_endpoint(str(httpx.URL(base_url))) == openrouter_endpoint(base_url)


async def test_explicit_vendor_openai_restores_the_openai_classification() -> None:
    inner = _FakeOpenAI("https://openrouter.ai/api/v1/", gateway_response("openai/gpt-6-astra", "OpenAI"))
    tzun, registered = await _init()
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openai")
        await wrapped.chat.completions.create(model="openai/gpt-6-astra", messages=[], tzun_capture=capture_input())
        assert registered[0].vendor == "openai"
        ai_bom, _ = await _stored_ai_bom(tzun)
        # The openai connector claims no infrastructure for a non-Azure client.
        assert ai_bom["infrastructure"] is None
    finally:
        await tzun.close()


async def test_a_client_on_another_host_stays_openai() -> None:
    inner = _FakeOpenAI("https://api.openai.com/v1/", {"id": "chatcmpl-test", "model": "gpt-4o-2024-08-06"})
    tzun, registered = await _init()
    try:
        wrapped = attach(inner, tzun=tzun)
        await wrapped.chat.completions.create(model="gpt-4o-2024-08-06", messages=[], tzun_capture=capture_input())
        assert registered[0].vendor == "openai"
        ai_bom, _ = await _stored_ai_bom(tzun)
        assert ai_bom["infrastructure"] is None
        assert "openrouter_endpoint" not in inner.chat.completions.calls[0]
    finally:
        await tzun.close()


async def test_explicit_vendor_openrouter_for_a_gateway_behind_another_host() -> None:
    inner = _FakeOpenAI("https://gateway.example.com/openrouter/v1/", gateway_response("x-ai/grok-4.7", "xAI"))
    tzun, registered = await _init()
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openrouter")
        await wrapped.chat.completions.create(model="x-ai/grok-4.7", messages=[], tzun_capture=capture_input())
        d = registered[0]
        assert (d.vendor, d.trainedBy, d.license) == ("openrouter", "x-ai", "xai-commercial")
        ai_bom, _ = await _stored_ai_bom(tzun)
        assert ai_bom["infrastructure"] == {
            "provider": "xAI",
            "region": None,
            "apiVersion": None,
            "endpoint": "https://gateway.example.com/openrouter/v1",
        }
        assert "openrouter_endpoint" not in inner.chat.completions.calls[0]
    finally:
        await tzun.close()


async def test_a_client_with_no_base_url_records_no_endpoint() -> None:
    inner = _FakeOpenAI(None, gateway_response("qwen/qwen3.8-27b", None))
    tzun, _ = await _init()
    try:
        wrapped = attach(inner, tzun=tzun, vendor="openrouter")
        await wrapped.chat.completions.create(model="qwen/qwen3.8-27b", messages=[], tzun_capture=capture_input())
        ai_bom, _ = await _stored_ai_bom(tzun)
        assert ai_bom["infrastructure"] == {"provider": None, "region": None, "apiVersion": None, "endpoint": None}
    finally:
        await tzun.close()


async def test_records_the_served_model_not_the_requested_one() -> None:
    inner = _FakeOpenAI("https://openrouter.ai/api/v1/", gateway_response("anthropic/claude-haiku-5.5", "Anthropic"))
    tzun, registered = await _init()
    try:
        wrapped = attach(inner, tzun=tzun)
        await wrapped.chat.completions.create(model="openrouter/auto", messages=[], tzun_capture=capture_input())
        assert registered[0].modelName == "anthropic/claude-haiku-5.5"
        ai_bom, _ = await _stored_ai_bom(tzun)
        assert ai_bom["infrastructure"]["provider"] == "Anthropic"
    finally:
        await tzun.close()


async def test_passes_through_without_capture_when_tzun_capture_is_absent() -> None:
    inner = _FakeOpenAI("https://openrouter.ai/api/v1/", gateway_response("openai/gpt-6-astra"))
    tzun, registered = await _init()
    try:
        wrapped = attach(inner, tzun=tzun)
        out = await wrapped.chat.completions.create(model="openai/gpt-6-astra", messages=[])
        assert out["model"] == "openai/gpt-6-astra"
        assert sorted(inner.chat.completions.calls[0]) == ["messages", "model"]
        assert registered == []
        assert len(await tzun._storage.list()) == 0
    finally:
        await tzun.close()


async def test_the_sync_client_records_the_same_ai_bom() -> None:
    inner = _FakeSyncOpenAI("https://openrouter.ai/api/v1/", gateway_response("openai/gpt-6-astra", "OpenAI"))
    tzun, registered = await _init()
    try:
        wrapped = attach(inner, tzun=tzun)
        # A sync client called while a loop runs: the capture runs on a worker thread.
        wrapped.chat.completions.create(model="openai/gpt-6-astra", messages=[], tzun_capture=capture_input())
        assert registered[0].vendor == "openrouter"
        assert "openrouter_endpoint" not in inner.chat.completions.calls[0]
        ai_bom, _ = await _stored_ai_bom(tzun)
        assert ai_bom["infrastructure"]["endpoint"] == "https://openrouter.ai/api/v1"
    finally:
        await tzun.close()


# ── Detection ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("base_url", "vendor"),
    [
        ("https://openrouter.ai/api/v1/", "openrouter"),
        ("https://OpenRouter.ai:443/api/v1/", "openrouter"),
        ("https://api.openai.com/v1/", "openai"),
        ("https://openrouter.ai.example.com/api/v1/", "openai"),
        ("https://openrouter.ai@gateway.example.com/v1/", "openai"),
        ("https://contoso.openai.azure.com/", "openai"),
        (None, "openai"),
    ],
)
def test_detect_vendor_by_base_url(base_url: str | None, vendor: str) -> None:
    assert _detect_vendor(_FakeOpenAI(base_url, {})) == vendor


def test_a_plain_string_base_url_is_read_too() -> None:
    client = _FakeOpenAI(None, {})
    client.base_url = "https://openrouter.ai/api/v1"  # type: ignore[assignment]
    assert _detect_vendor(client) == "openrouter"


def test_an_openrouter_base_url_on_another_vendors_client_changes_nothing() -> None:
    class _FakeAnthropic:
        base_url = "https://openrouter.ai/api/v1/"

    assert _detect_vendor(_FakeAnthropic()) == "anthropic"


def test_an_unrecognized_client_lists_openrouter_among_the_supported() -> None:
    class _Unknown:
        base_url = "https://openrouter.ai/api/v1/"

    with pytest.raises(TzunError, match="openrouter"):
        attach(_Unknown(), tzun=None)  # type: ignore[arg-type]


# ── hook("openrouter", ...) ────────────────────────────────────────────


async def test_hook_builds_an_ai_bom_with_the_endpoint_the_caller_passes() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        ai_bom = await hook(
            "openrouter",
            {"model": "mistralai/mistral-small-2603", "seed": 7, "openrouter_endpoint": "https://openrouter.ai/api/v1"},
            gateway_response("mistralai/mistral-small-2603", "Mistral"),
            tzun=tzun,
        )
        assert ai_bom is not None
        assert ai_bom.modelDescriptorDigest.startswith("sha256:")
        assert ai_bom.inferenceParameters is not None and ai_bom.inferenceParameters.seed == 7
        assert ai_bom.infrastructure is not None
        assert ai_bom.infrastructure.model_dump(mode="json") == {
            "provider": "Mistral",
            "region": None,
            "apiVersion": None,
            "endpoint": "https://openrouter.ai/api/v1",
        }
    finally:
        await tzun.close()


async def test_hook_assumes_no_endpoint_when_the_caller_passes_none() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        ai_bom = await hook(
            "openrouter",
            {"model": "mistralai/mistral-small-2603"},
            gateway_response("mistralai/mistral-small-2603", "Mistral"),
            tzun=tzun,
        )
        assert ai_bom is not None and ai_bom.infrastructure is not None
        assert ai_bom.infrastructure.endpoint is None
    finally:
        await tzun.close()


async def test_hook_returns_none_for_a_response_with_no_model() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        response = gateway_response("x")
        del response["model"]
        assert await hook("openrouter", {"model": "openai/gpt-6-astra"}, response, tzun=tzun) is None
    finally:
        await tzun.close()


async def test_hook_registers_a_free_id_and_its_base_as_distinct_descriptors() -> None:
    tzun, registered = await _init()
    try:
        a = await hook("openrouter", {}, gateway_response("google/gemma-4-31b-it"), tzun=tzun)
        b = await hook("openrouter", {}, gateway_response("google/gemma-4-31b-it:free"), tzun=tzun)
        assert a is not None and b is not None
        assert len(registered) == 2
        assert a.modelDescriptorDigest != b.modelDescriptorDigest
    finally:
        await tzun.close()
