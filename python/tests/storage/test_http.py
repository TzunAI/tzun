"""HttpBackendAdapter unit tests."""

from __future__ import annotations

import pytest

from tzun_sdk.errors import TzunError
from tzun_sdk.storage import HttpBackendAdapter


def test_constructor_rejects_plain_http_for_non_localhost() -> None:
    """HTTPS-only for non-localhost."""
    with pytest.raises(TzunError):
        HttpBackendAdapter(base_url="http://api.example.com", api_token="t")


def test_constructor_accepts_http_localhost() -> None:
    """Localhost may use plain HTTP for dev."""
    adapter = HttpBackendAdapter(base_url="http://localhost:8080", api_token="t")
    assert adapter._base_url == "http://localhost:8080"


def test_constructor_accepts_https() -> None:
    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="t")
    assert adapter._base_url == "https://api.tzun.ai"


def test_constructor_rejects_invalid_scheme() -> None:
    with pytest.raises(TzunError):
        HttpBackendAdapter(base_url="ftp://api.tzun.ai", api_token="t")


def test_headers_include_bearer() -> None:
    """Bearer auth in Authorization header."""
    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="secret")
    h = adapter._headers()
    assert h["Authorization"] == "Bearer secret"


async def test_list_by_sequence_pages_and_filters_client_side() -> None:
    """The platform's list has no sequence filter, so the adapter pages + filters.

    GET /v1/app/evidence applies only limit (at most 200) and offset, so
    list_by_sequence walks it and narrows the range in the client.
    """
    import httpx

    def _envelope(seq: int) -> dict:
        return {
            "envelopeVersion": "e1",
            "payload": {
                "evidenceId": f"ev-{seq}",
                "schemaVersion": "v1.0",
                "aiSystemId": "test",
                "aiOutput": {},
                "action": "approved",
                "decider": {"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
                "reason": "ok",
                "capturedAt": "2026-06-10T00:00:00.000Z",
                "sequenceNumber": seq,
            },
            "integrity": {"canonicalDigest": "a" * 64, "chainLink": None},
            "nonRepudiation": {},
            "custodyChain": [],
            "attestationStatus": "none",
        }

    calls: list[httpx.URL] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url)
        offset = int(request.url.params.get("offset", 0))
        # One short page: the loop must stop after a single request.
        items = [_envelope(s) for s in range(1 + offset, 121 + offset)] if offset == 0 else []
        return httpx.Response(200, json={"evidence": [{"envelope": e, "verdict": {}} for e in items]})

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="t")
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai",
        transport=httpx.MockTransport(_handler),
    )

    got = await adapter.list_by_sequence(104, 104)
    assert [e.payload.sequenceNumber for e in got] == [104]
    assert len(calls) == 1 and calls[0].path == "/v1/app/evidence"
    assert calls[0].params.get("include") == "envelope" and calls[0].params.get("limit") == "200"

    got_all = await adapter.list_by_sequence()
    assert len(got_all) == 120


# ── alias/enriched lookups must not swallow non-404 failures ──────────────


def _adapter_answering(status: int, body: dict | None = None) -> HttpBackendAdapter:
    import httpx

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body if body is not None else {"error": "boom"})

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="t", max_attempts=1)
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai",
        transport=httpx.MockTransport(_handler),
    )
    return adapter


async def test_resolve_alias_returns_none_only_for_404() -> None:
    """A missing alias is None; anything else must surface.

    Only a 404 means the alias is unset. If any other failure answered None, a
    rotated API key would make `resolve_alias('prod')` answer None and the
    caller would treat production model routing as unset instead of failing
    loudly.
    """
    missing = _adapter_answering(404)
    assert await missing.resolve_model_descriptor_alias("prod") is None

    for status in (401, 403, 429, 500, 503):
        adapter = _adapter_answering(status)
        with pytest.raises(TzunError):
            await adapter.resolve_model_descriptor_alias("prod")


async def test_get_enriched_descriptor_returns_none_only_for_404() -> None:
    missing = _adapter_answering(404)
    assert await missing.get_enriched_model_descriptor("sha256:" + "a" * 64) is None

    for status in (401, 403, 500):
        adapter = _adapter_answering(status)
        with pytest.raises(TzunError):
            await adapter.get_enriched_model_descriptor("sha256:" + "a" * 64)


async def test_connection_failure_is_not_reported_as_missing_alias() -> None:
    """A connection error raises a status-less TzunError; it is not a 404."""
    import httpx

    def _handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("backend unreachable", request=request)

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="t", max_attempts=1)
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai",
        transport=httpx.MockTransport(_handler),
    )
    with pytest.raises(TzunError):
        await adapter.resolve_model_descriptor_alias("prod")
