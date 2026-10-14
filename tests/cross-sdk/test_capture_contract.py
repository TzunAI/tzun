"""Cross-SDK cloud-capture request-contract parity.

Asserts that the TypeScript ``HttpTransport.capture()`` and the Python
``HttpBackendAdapter.store()`` build **identical** ``POST /v1/evidence``
request bodies for the same input — same top-level field names
(``completeness``, ``chainId``, ``envelope``), same field ordering
invariant (``chainId`` in camelCase, never ``_chainId``), and identical
``envelope.integrity.canonicalDigest`` for a shared evidence payload.

Design (mirrors the cross-SDK harness pattern):
  1. Use the TS ``capture`` harness action to produce a deterministic
     envelope JSON from a fixed AI output, action and reason.
  2. Feed that envelope + parameters to the TS ``build-capture-request``
     harness action → captures what HttpTransport *would* POST.
  3. Build the Python side with ``HttpBackendAdapter.store()`` against an
     ``httpx.MockTransport`` that captures the outgoing request body instead
     of making a real HTTP call.
  4. Round-trip the TS envelope dict into a Python ``EvidenceEnvelope``
     model, then compare field-by-field.

Non-deterministic fields (``evidenceId``, ``capturedAt``) are excluded from
equality — the comparison focuses on the deterministic structural contract
(top-level keys, ``completeness``, ``chainId``, nested ``envelope`` shape)
and the cryptographically deterministic ``envelope.integrity.canonicalDigest``.

The async adapter calls are wrapped in ``asyncio.run()`` to keep the tests
compatible with the cross-SDK suite runner (invoked from the repo root without
asyncio_mode=auto), mirroring ``test_ts_to_py_roundtrip.py``.
"""

from __future__ import annotations

import asyncio
import json

import httpx

from tzun_sdk.models import EvidenceEnvelope
from tzun_sdk.storage import HttpBackendAdapter


# ── helpers ─────────────────────────────────────────────────────────────────


def _make_adapter_with_capture() -> tuple[HttpBackendAdapter, list[dict]]:
    """Return (adapter, captured_bodies) where adapter uses a MockTransport.

    The transport captures the request body JSON for every POST and returns
    a stub 202 so store() does not raise.
    """
    captured_bodies: list[dict] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured_bodies.append(json.loads(request.content))
        return httpx.Response(
            status_code=202,
            headers={"Content-Type": "application/json"},
            content=json.dumps(
                {
                    "ok": True,
                    "evidenceId": "ev-x",
                    "chainId": "default",
                    "sequence": 1,
                    "state": "stored",
                    "verification": "ok",
                    "canonicalDigest": "a" * 64,
                    "headDigest": "b" * 64,
                }
            ).encode(),
        )

    adapter = HttpBackendAdapter(
        base_url="https://api.tzun.ai",
        api_token="test-token",
    )
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai",
        transport=httpx.MockTransport(_handler),
    )
    return adapter, captured_bodies


def _py_store(envelope: EvidenceEnvelope, **kwargs) -> dict:
    """Run adapter.store() synchronously via asyncio.run(); return the captured body."""
    adapter, captured = _make_adapter_with_capture()

    async def _run():
        await adapter.store(envelope, **kwargs)

    asyncio.run(_run())
    assert len(captured) == 1, f"Expected exactly one intercepted request, got {len(captured)}"
    return captured[0]


# ── tests ────────────────────────────────────────────────────────────────────


def test_capture_contract_top_level_keys_with_chain_id(ts_invoke) -> None:
    """TS and Python request bodies have the same top-level keys when
    chainId is provided: {completeness, chainId, envelope}."""
    # Step 1: get a TS-built envelope via the "capture" action.
    ts_capture = ts_invoke(
        {
            "action": "capture",
            "aiOutput": {"score": 0.9, "label": "approve"},
            "decision": {"action": "approved", "reason": "verified by reviewer"},
        }
    )
    ts_envelope_dict = ts_capture["envelope"]

    # Step 2: get the TS request body via the "build-capture-request" action.
    ts_req = ts_invoke(
        {
            "action": "build-capture-request",
            "envelope": ts_envelope_dict,
            "completeness": "partial",
            "chainId": "chain-alpha",
        }
    )
    ts_body = ts_req["requestBody"]

    # Step 3: build the Python side — round-trip the TS envelope dict into
    # EvidenceEnvelope, then call store() with the same chainId.
    py_envelope = EvidenceEnvelope.model_validate(ts_envelope_dict)
    py_body = _py_store(py_envelope, chain_id="chain-alpha")

    # ── structural assertions ────────────────────────────────────────────────
    assert set(ts_body.keys()) == set(py_body.keys()), (
        f"Top-level key mismatch:\n  TS:  {sorted(ts_body.keys())}\n"
        f"  Py:  {sorted(py_body.keys())}"
    )
    assert ts_body["completeness"] == py_body["completeness"] == "partial"
    assert ts_body.get("chainId") == py_body.get("chainId") == "chain-alpha", (
        "chainId must be camelCase and equal on both sides "
        f"(TS: {ts_body.get('chainId')!r}, Py: {py_body.get('chainId')!r})"
    )
    assert "_chainId" not in ts_body, "TS must send chainId, never _chainId"
    assert "_chainId" not in py_body, "Python must send chainId, never _chainId"
    assert "envelope" in ts_body and "envelope" in py_body, (
        "Both bodies must have a nested 'envelope' key"
    )


def test_capture_contract_no_chain_id_omits_field(ts_invoke) -> None:
    """When chainId is absent, neither side includes the key."""
    ts_capture = ts_invoke(
        {
            "action": "capture",
            "aiOutput": {"decision": "reject"},
            "decision": {"action": "rejected", "reason": "risk too high"},
        }
    )
    ts_envelope_dict = ts_capture["envelope"]

    ts_req = ts_invoke(
        {
            "action": "build-capture-request",
            "envelope": ts_envelope_dict,
            "completeness": "partial",
            # no chainId
        }
    )
    ts_body = ts_req["requestBody"]

    py_envelope = EvidenceEnvelope.model_validate(ts_envelope_dict)
    py_body = _py_store(py_envelope)  # no chain_id

    assert "chainId" not in ts_body, "TS must omit chainId when not provided"
    assert "chainId" not in py_body, "Python must omit chainId when not provided"
    assert ts_body["completeness"] == py_body["completeness"] == "partial"


def test_capture_contract_canonical_digest_matches(ts_invoke) -> None:
    """envelope.integrity.canonicalDigest is identical across TS and
    Python for the same evidence payload.

    The digest is cryptographically deterministic for a given canonical payload,
    so it must match byte-for-byte if the serialization is correct on both sides.
    """
    ts_capture = ts_invoke(
        {
            "action": "capture",
            "aiOutput": {"score": 0.5, "label": "review"},
            "decision": {"action": "escalated", "reason": "needs second opinion"},
        }
    )
    ts_envelope_dict = ts_capture["envelope"]
    ts_digest = ts_envelope_dict["integrity"]["canonicalDigest"]

    # Round-trip: Python validates the same envelope dict and re-serialises
    # it; the canonicalDigest in the nested envelope must survive intact.
    py_envelope = EvidenceEnvelope.model_validate(ts_envelope_dict)
    py_body = _py_store(py_envelope, chain_id="chain-beta")

    py_digest = py_body["envelope"]["integrity"]["canonicalDigest"]
    assert py_digest == ts_digest, (
        f"canonicalDigest mismatch:\n"
        f"  TS:     {ts_digest}\n"
        f"  Python: {py_digest}"
    )


def test_capture_contract_envelope_structure(ts_invoke) -> None:
    """Both sides nest the envelope under the 'envelope' key with the
    same integrity block structure (envelopeVersion, payload, integrity)."""
    ts_capture = ts_invoke(
        {
            "action": "capture",
            "aiOutput": {"answer": "yes"},
            "decision": {"action": "confirmed", "reason": "all good"},
        }
    )
    ts_envelope_dict = ts_capture["envelope"]
    ts_req = ts_invoke(
        {
            "action": "build-capture-request",
            "envelope": ts_envelope_dict,
            "completeness": "partial",
            "chainId": "chain-gamma",
        }
    )
    ts_body = ts_req["requestBody"]

    py_envelope = EvidenceEnvelope.model_validate(ts_envelope_dict)
    py_body = _py_store(py_envelope, chain_id="chain-gamma")

    ts_env = ts_body["envelope"]
    py_env = py_body["envelope"]

    # Both envelopes must carry the nested integrity block with canonicalDigest.
    assert "integrity" in ts_env, "TS envelope body must contain 'integrity'"
    assert "integrity" in py_env, "Python envelope body must contain 'integrity'"
    assert "canonicalDigest" in ts_env["integrity"]
    assert "canonicalDigest" in py_env["integrity"]
    assert ts_env["integrity"]["canonicalDigest"] == py_env["integrity"]["canonicalDigest"]

    # Envelope must be nested, NOT a top-level dump.
    assert "evidenceId" not in ts_body, "evidenceId must NOT appear at top level in TS body"
    assert "evidenceId" not in py_body, "evidenceId must NOT appear at top level in Py body"

    # envelopeVersion must survive the round-trip.
    assert ts_env.get("envelopeVersion") == py_env.get("envelopeVersion") == "e1"
