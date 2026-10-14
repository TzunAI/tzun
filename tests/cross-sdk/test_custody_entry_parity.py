"""Cross-SDK parity for server-minted custody-entry hashes.

Two contracts, both invisible to the existing suite until now:

1. The WIRE a Python client sends. A TS ``?:`` property has no JSON key when
   undefined; a Pydantic ``x: T | None = None`` field serialises as ``null``.
   The hosted service's capture allowlist (``CUSTODY_ENTRY_KEYS``)
   refuses unknown keys even when null, so the moment ``CustodyEntry`` gained
   ``entryHash`` / ``prevEntryHash`` a Python ``POST /v1/evidence`` would have
   carried ``"entryHash": null`` and been answered ``400 unknown_field``.
   ``test_capture_contract.py`` compares only the top-level body keys, so it
   stayed green. Red before the ``@tzun-omit-when-unset`` serializer:
   ``{'entryHash', 'prevEntryHash'} <= set(entry)``.

2. The ENVELOPE each side accepts from the other. A repaired record's export
   carries the mirrored entries; both SDKs must read it and agree on the
   digest, which the keys do not touch (``custodyChain`` is outside the hashed
   field set).
"""

from __future__ import annotations

import asyncio
import json

import httpx

from tzun_sdk.models import EvidenceEnvelope
from tzun_sdk.storage import HttpBackendAdapter

# The hosted service's CUSTODY_ENTRY_KEYS: the exact key set a client may send.
PLATFORM_CLIENT_CUSTODY_KEYS = {"timestamp", "actor", "action", "systemId", "metadata"}

ENTRY_HASH_1 = "sha256:" + "a" * 64
ENTRY_HASH_2 = "sha256:" + "b" * 64


def _server_minted(entry_hash: str, prev: str | None, action: str = "relinked") -> dict:
    return {
        "timestamp": "2026-09-09T10:00:00.000Z",
        "actor": "admin@acme.example",
        "action": action,
        "systemId": "hosted-platform",
        "metadata": {"recoveryId": "rec-1"},
        "entryHash": entry_hash,
        "prevEntryHash": prev,
    }


def _py_capture() -> dict:
    """A Python-SDK-captured envelope as JSON (asyncio.run: no asyncio_mode here)."""
    from tzun_sdk import Tzun
    from tzun_sdk.storage import MemoryAdapter

    async def _run() -> dict:
        tzun = await Tzun.init(storage=MemoryAdapter())
        try:
            r = await tzun.capture(
                ai_output={"score": 0.7, "label": "approve"},
                action="approved",
                reason="ok",
                decider={"kind": "human", "id": "acct:u-cross-sdk"},
            )
            return r.envelope.model_dump(mode="json")
        finally:
            await tzun.close()

    return asyncio.run(_run())


def _py_store_body(envelope: EvidenceEnvelope) -> dict:
    """What HttpBackendAdapter.store() actually POSTs, captured off a MockTransport."""
    captured: list[dict] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(
            status_code=202,
            headers={"Content-Type": "application/json"},
            content=json.dumps(
                {"ok": True, "evidenceId": "ev-x", "chainId": "default", "sequence": 1,
                 "state": "stored", "verification": "ok",
                 "canonicalDigest": "a" * 64, "headDigest": "b" * 64}
            ).encode(),
        )

    adapter = HttpBackendAdapter(base_url="https://api.tzun.ai", api_token="test-token")
    adapter._async_client = httpx.AsyncClient(
        base_url="https://api.tzun.ai", transport=httpx.MockTransport(_handler)
    )
    asyncio.run(adapter.store(envelope))
    assert len(captured) == 1
    return captured[0]


def test_python_capture_wire_custody_entry_carries_only_client_keys() -> None:
    envelope = EvidenceEnvelope.model_validate(_py_capture())
    body = _py_store_body(envelope)
    chain = body["envelope"]["custodyChain"]
    assert len(chain) == 1, chain
    keys = set(chain[0])
    assert "entryHash" not in keys and "prevEntryHash" not in keys, sorted(keys)
    assert keys <= PLATFORM_CLIENT_CUSTODY_KEYS, sorted(keys - PLATFORM_CLIENT_CUSTODY_KEYS)


def test_ts_verifies_a_python_envelope_carrying_server_minted_entries(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    envelope = _py_capture()
    envelope["custodyChain"] += [
        _server_minted(ENTRY_HASH_1, None),
        _server_minted(ENTRY_HASH_2, ENTRY_HASH_1, "chain_forked"),
    ]
    result = ts_invoke({"action": "verify", "envelope": envelope})
    assert result["valid"] is True, result
    assert result["canonicalDigest"] == envelope["integrity"]["canonicalDigest"]


def test_python_reads_a_ts_envelope_carrying_server_minted_entries_at_the_same_digest(
    ts_invoke,  # type: ignore[no-untyped-def]
) -> None:
    import hashlib

    from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize

    ts_envelope = ts_invoke(
        {
            "action": "capture",
            "aiOutput": {"score": 0.7, "label": "approve"},
            "decision": {"action": "approved", "reason": "ok"},
        }
    )["envelope"]
    ts_envelope["custodyChain"] += [
        _server_minted(ENTRY_HASH_1, None),
        _server_minted(ENTRY_HASH_2, ENTRY_HASH_1, "chain_forked"),
    ]

    # Red before the model change: pydantic extra_forbidden on entryHash.
    envelope = EvidenceEnvelope.model_validate(ts_envelope)
    assert envelope.custodyChain[0].entryHash == ENTRY_HASH_1
    assert envelope.custodyChain[1].prevEntryHash == ENTRY_HASH_1

    canonical = canonical_serialize(envelope.payload.model_dump(mode="json"), list(V1_HASHED_FIELDS))
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == ts_envelope["integrity"]["canonicalDigest"]

    # The explicit null on the first server-minted entry survives a Python round trip;
    # the keys never appear on an entry that did not carry them.
    wire = envelope.model_dump(mode="json")["custodyChain"]
    assert wire[0]["prevEntryHash"] is None and wire[0]["entryHash"] == ENTRY_HASH_1
    assert wire[1]["prevEntryHash"] == ENTRY_HASH_1
