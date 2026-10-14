"""Wire-contract tests for HttpBackendAdapter.store().

Uses httpx.MockTransport to intercept requests without a live server.
Verifies:
  - Body shape: completeness / envelope (nested) / chainId (not _chainId)
  - Headers: Authorization always present; Idempotency-Key when provided
  - 202 success: parsed JSON dict returned
  - 4xx error: typed TzunCaptureError raised with stable `code`
"""

from __future__ import annotations

import json

import httpx
import pytest

from tzun_sdk.errors import TzunCaptureError, TzunError
from tzun_sdk.models import EvidenceEnvelope, EvidencePayload, IntegrityBlock
from tzun_sdk.storage import HttpBackendAdapter

# ── helpers ─────────────────────────────────────────────────────────────


def _make_envelope() -> EvidenceEnvelope:
    payload = EvidencePayload(
        evidenceId="ev-001",
        aiSystemId="sys-1",
        aiOutput={"score": 0.9},
        action="approved",
        decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
        reason="looks good",
        capturedAt="2026-06-07T00:00:00Z",
        sequenceNumber=1,
    )
    integrity = IntegrityBlock(canonicalDigest="a" * 64)
    return EvidenceEnvelope(payload=payload, integrity=integrity)


def _adapter_with_transport(transport: httpx.MockTransport) -> HttpBackendAdapter:
    """Build an HttpBackendAdapter whose async client uses the given transport."""
    adapter = HttpBackendAdapter(
        base_url="https://api.tzun.ai",
        api_token="test-token-abc",
    )
    # Inject mock transport directly so no real HTTP is attempted.
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai",
        transport=transport,
    )
    return adapter


def _success_202(body: dict | None = None) -> httpx.Response:
    body = body or {
        "ok": True,
        "evidenceId": "ev-001",
        "chainId": None,
        "sequence": 1,
        "state": "stored",
        "verification": "ok",
        "canonicalDigest": "a" * 64,
        "headDigest": "b" * 64,
    }
    return httpx.Response(
        status_code=202,
        headers={"Content-Type": "application/json"},
        content=json.dumps(body).encode(),
    )


def _error_response(status: int, code: str) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        headers={"Content-Type": "application/json"},
        content=json.dumps({"ok": False, "error": code}).encode(),
    )


# ── tests ────────────────────────────────────────────────────────────────


async def test_store_body_has_nested_envelope_not_top_level() -> None:
    """Envelope is nested under 'envelope' key, not top-level."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return _success_202()

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    envelope = _make_envelope()
    await adapter.store(envelope)

    assert len(captured) == 1
    body = json.loads(captured[0].content)
    assert "envelope" in body, "body must have 'envelope' key"
    # The envelope payload fields should be nested, not at top level.
    assert "payload" in body["envelope"], "envelope dict should contain 'payload'"
    assert "evidenceId" not in body, "evidenceId must NOT appear at top level"


async def test_store_default_completeness_is_partial() -> None:
    """Completeness defaults to 'partial'."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return _success_202()

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    await adapter.store(_make_envelope())

    body = json.loads(captured[0].content)
    assert body["completeness"] == "partial"


async def test_store_chain_id_key_is_camel_not_underscore() -> None:
    """chain_id becomes 'chainId' (not '_chainId')."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return _success_202()

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    await adapter.store(_make_envelope(), chain_id="chain-abc")

    body = json.loads(captured[0].content)
    assert body.get("chainId") == "chain-abc", "chainId must use camelCase"
    assert "_chainId" not in body, "the chain id key is chainId; _chainId must not be sent"


async def test_store_no_chain_id_omits_chain_id_field() -> None:
    """When chain_id=None, 'chainId' is absent from the body."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return _success_202()

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    await adapter.store(_make_envelope())

    body = json.loads(captured[0].content)
    assert "chainId" not in body


async def test_store_authorization_header_always_present() -> None:
    """Bearer token always in Authorization header."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return _success_202()

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    await adapter.store(_make_envelope())

    assert captured[0].headers["Authorization"] == "Bearer test-token-abc"


async def test_store_idempotency_key_sent_when_provided() -> None:
    """Idempotency-Key header sent when idempotency_key given."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return _success_202()

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    await adapter.store(_make_envelope(), idempotency_key="idem-key-xyz")

    assert captured[0].headers["Idempotency-Key"] == "idem-key-xyz"


async def test_store_idempotency_key_absent_when_not_provided() -> None:
    """Idempotency-Key header absent when not provided."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return _success_202()

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    await adapter.store(_make_envelope())

    assert "idempotency-key" not in {k.lower() for k in captured[0].headers.keys()}


async def test_store_returns_parsed_json_on_202() -> None:
    """202 response is returned as parsed dict."""
    success_body = {
        "ok": True,
        "evidenceId": "ev-999",
        "chainId": "chain-1",
        "sequence": 5,
        "state": "stored",
        "verification": "ok",
        "canonicalDigest": "c" * 64,
        "headDigest": "d" * 64,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return _success_202(success_body)

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    result = await adapter.store(_make_envelope())

    assert isinstance(result, dict)
    assert result["ok"] is True
    assert result["evidenceId"] == "ev-999"
    assert result["sequence"] == 5


async def test_store_422_verification_failed_raises_typed_error() -> None:
    """422 verification_failed raises TzunCaptureError with code."""

    def handler(request: httpx.Request) -> httpx.Response:
        return _error_response(422, "verification_failed")

    adapter = _adapter_with_transport(httpx.MockTransport(handler))

    with pytest.raises(TzunCaptureError) as exc_info:
        await adapter.store(_make_envelope())

    err = exc_info.value
    assert err.code == "verification_failed"
    assert err.status == 422


async def test_store_401_raises_typed_error_with_unauthenticated_code() -> None:
    """401 raises TzunCaptureError(code='unauthenticated')."""

    def handler(request: httpx.Request) -> httpx.Response:
        return _error_response(401, "unauthenticated")

    adapter = _adapter_with_transport(httpx.MockTransport(handler))

    with pytest.raises(TzunCaptureError) as exc_info:
        await adapter.store(_make_envelope())

    assert exc_info.value.code == "unauthenticated"
    assert exc_info.value.status == 401


async def test_store_typed_error_is_subclass_of_tzun_error() -> None:
    """TzunCaptureError is a TzunError, so a catch-all ``except TzunError`` catches it."""

    def handler(request: httpx.Request) -> httpx.Response:
        return _error_response(409, "chain_conflict")

    adapter = _adapter_with_transport(httpx.MockTransport(handler))

    with pytest.raises(TzunError):
        await adapter.store(_make_envelope())


async def test_store_completeness_explicit_value_passed_through() -> None:
    """Explicit completeness value is forwarded."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return _success_202()

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    await adapter.store(_make_envelope(), completeness="complete")

    body = json.loads(captured[0].content)
    assert body["completeness"] == "complete"


async def test_retrieve_reads_the_envelope_from_the_evidence_route() -> None:
    """retrieve() reads GET /v1/app/evidence/{id}, which answers
    ``{envelope, verdict}``, and returns the envelope.
    """
    env_body = _make_envelope().model_dump(mode="json")
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=json.dumps({"envelope": env_body, "verdict": {}}).encode(),
        )

    adapter = _adapter_with_transport(httpx.MockTransport(handler))
    result = await adapter.retrieve("ev-001")
    assert result is not None
    assert result.payload.evidenceId == "ev-001"
    assert paths == ["/v1/app/evidence/ev-001"]
