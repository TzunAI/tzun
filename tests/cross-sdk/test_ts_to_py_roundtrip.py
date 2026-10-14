"""TS-capture → Py-verify roundtrip.

The TS harness builds a v1.0 envelope structurally; the Python SDK
recomputes the canonical digest and asserts it matches.
"""

from __future__ import annotations


def test_ts_captured_envelope_verifies_in_python(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    """Capture in TS, verify in Python."""
    import hashlib

    from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize

    result = ts_invoke(
        {
            "action": "capture",
            "aiOutput": {"score": 0.7, "label": "approve"},
            "decision": {"action": "approved", "reason": "ok"},
        }
    )
    envelope = result["envelope"]
    payload = envelope["payload"]
    canonical = canonical_serialize(payload, list(V1_HASHED_FIELDS))
    py_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    ts_digest = envelope["integrity"]["canonicalDigest"]
    assert py_digest == ts_digest, (
        f"TS-captured envelope failed Python verification:\n"
        f"  TS digest: {ts_digest}\n  Py digest: {py_digest}"
    )


def test_py_captured_envelope_verifies_in_ts(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    """Capture in Python, verify in TS."""
    import asyncio

    from tzun_sdk import Tzun
    from tzun_sdk.storage import MemoryAdapter

    async def _capture() -> dict:
        tzun = await Tzun.init(storage=MemoryAdapter())
        try:
            result = await tzun.capture(
                ai_output={"score": 0.7, "label": "approve"},
                action="approved",
                reason="ok",
                decider={"kind": "human", "id": "acct:u-cross-sdk"},
            )
            return result.envelope.model_dump(mode="json")
        finally:
            await tzun.close()

    envelope = asyncio.run(_capture())
    ts_result = ts_invoke({"action": "verify", "envelope": envelope})
    assert ts_result["valid"] is True, (
        f"Py-captured envelope failed TS verification: {ts_result}"
    )
