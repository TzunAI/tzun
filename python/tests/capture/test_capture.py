"""Capture path tests."""

from __future__ import annotations

import hashlib

import pytest

from tzun_sdk import Tzun
from tzun_sdk.contributions import single_model
from tzun_sdk.errors import TzunError
from tzun_sdk.storage import MemoryAdapter


async def test_capture_roundtrip_memory() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"score": 0.7, "label": "approve"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        assert result.evidenceId
        assert len(result.canonicalDigest) == 64 and ":" not in result.canonicalDigest
        assert result.sequenceNumber == 1
        retrieved = await tzun._storage.retrieve(result.evidenceId)
        assert retrieved is not None
        assert retrieved.payload.evidenceId == result.evidenceId
    finally:
        await tzun.close()


async def test_capture_chain_link_correctness() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r1 = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        r2 = await tzun.capture(
            ai_output={"r": "y"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        expected_chain = hashlib.sha256(
            (r1.canonicalDigest + r2.canonicalDigest).encode()
        ).hexdigest()
        assert r2.envelope.integrity.chainLink == expected_chain
        assert r2.sequenceNumber == 2
    finally:
        await tzun.close()


async def test_capture_with_no_contributions_writes_every_member() -> None:
    """A capture naming no model writes contributions and links as null, and every one of the twelve keys."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
            contributions=None,
        )
        assert result.envelope.payload.contributions is None
        stored = await tzun._storage.retrieve_raw(result.evidenceId)
        assert sorted(stored["payload"]) == sorted(
            ["evidenceId", "schemaVersion", "aiSystemId", "aiOutput", "action", "reason", "capturedAt",
             "sequenceNumber", "decider", "contributions", "links", "signoffExpectation"]
        )
        assert stored["payload"]["decider"] == {
            "kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None,
        }
        assert stored["payload"]["links"] is None
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_capture_digest_is_bare_hex_and_chainlink_is_hash() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        r1 = await tzun.capture(ai_output={"r": "approve"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="a", reason="b")
        assert ":" not in r1.canonicalDigest
        assert len(r1.canonicalDigest) == 64
        r2 = await tzun.capture(ai_output={"r": "deny"}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="c", reason="d")
        env2 = await tzun._storage.retrieve(r2.evidenceId)
        expected = hashlib.sha256((r1.canonicalDigest + r2.canonicalDigest).encode()).hexdigest()
        assert env2.integrity.chainLink == expected
    finally:
        await tzun.close()


# ── The decider and the custody chain ──────────────────────────────────────
# Who decided is the hashed `decider`; the client-attested `decision_captured`
# custody entry takes its id as `actor`, outside the digest.


async def test_capture_records_the_decider_in_the_payload_and_custody_chain() -> None:
    """The decider reaches the STORED payload, and its id the custody entry."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"score": 0.7},
            action="approved",
            reason="ok",
            ai_system_id="risk-engine",
            decider={"kind": "human", "id": "acct:alice"},
        )
        stored = await tzun._storage.retrieve(result.evidenceId)
        assert stored is not None
        assert stored.payload.decider.id == "acct:alice"
        assert len(stored.custodyChain) == 1
        entry = stored.custodyChain[0]
        assert entry.actor == "acct:alice"
        assert entry.action == "decision_captured"
        assert entry.systemId == "risk-engine"
        assert entry.timestamp == stored.payload.capturedAt
    finally:
        await tzun.close()


async def test_capture_requires_a_decider_and_refuses_the_07_names() -> None:
    """``capture()`` requires a decider and takes no ``reviewer``, ``human_action``, ``human_reason`` or ``ai_bom``.

    Passing any of those names is a TypeError, and nothing is stored.
    """
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        with pytest.raises(TypeError):
            await tzun.capture(ai_output={}, action="approved", reason="ok")  # type: ignore[call-arg]
        for old in ("human_action", "human_reason", "reviewer", "ai_bom"):
            with pytest.raises(TypeError):
                await tzun.capture(  # type: ignore[call-arg]
                    ai_output={}, action="approved", reason="ok",
                    decider={"kind": "human", "id": "acct:u"}, **{old: "x"},
                )
        assert await tzun._storage.list() == []
    finally:
        await tzun.close()


async def test_the_decider_is_hashed_and_the_custody_actor_is_not() -> None:
    """Relabelling who decided moves the digest; editing the custody actor does not."""
    from tzun_sdk.errors import TzunError as _E  # noqa: F401

    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        kwargs = dict(
            ai_output={"score": 1},
            action="approved",
            reason="ok",
            evidence_id="0f1e2d3c-4b5a-4987-8796-a5b4c3d2e1f0",
            captured_at="2026-01-01T00:00:00.000Z",
        )
        a = await tzun.capture(decider={"kind": "human", "id": "acct:alice"}, **kwargs)
        b_tzun = await Tzun.init(storage=MemoryAdapter())
        b = await b_tzun.capture(decider={"kind": "human", "id": "acct:bob"}, **kwargs)
        await b_tzun.close()
        assert a.canonicalDigest != b.canonicalDigest
        raw = tzun._storage._envelopes[a.evidenceId]  # type: ignore[attr-defined]
        raw["custodyChain"][0]["actor"] = "acct:mallory"
        assert (await tzun.verify(a.evidenceId)).valid is True
        raw["payload"]["decider"]["id"] = "acct:mallory"
        assert (await tzun.verify(a.evidenceId)).valid is False
    finally:
        await tzun.close()


# ── Non-finite / unserializable ai_output ────────────────────────
# pydantic v2 defaults to ser_json_inf_nan='null', so model_dump(mode="json")
# rewrites NaN and Infinity to null BEFORE canonical_serialize() sees them, and
# the canonicalizer's own non-finite guard cannot fire from capture(). capture()
# checks ai_output before the dump and raises; otherwise the record would store
# a null the model never produced, under a valid digest.


async def test_capture_refuses_nan_in_ai_output() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        with pytest.raises(TzunError, match="non-finite"):
            await tzun.capture(
                ai_output={"confidence": float("nan")},
                decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                reason="edge case",
            )
        # Nothing was written: no record asserting a null score.
        assert await tzun._storage.list() == []
    finally:
        await tzun.close()


@pytest.mark.parametrize("bad", [float("inf"), float("-inf")])
async def test_capture_refuses_infinity_in_ai_output(bad: float) -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        with pytest.raises(TzunError, match="non-finite"):
            await tzun.capture(
                ai_output={"scores": [0.1, bad]},
                decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                reason="ok",
            )
    finally:
        await tzun.close()


async def test_capture_refuses_non_utf8_bytes_with_a_tzun_error() -> None:
    """Bytes that are not UTF-8 raise a TzunError, not a raw UnicodeDecodeError."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        with pytest.raises(TzunError, match="not valid UTF-8"):
            await tzun.capture(
                ai_output={"raw_body": b"\x00\xff"},
                decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                reason="ok",
            )
    finally:
        await tzun.close()


async def test_capture_refuses_nan_inside_ai_bom() -> None:
    """aiBom is in V1_HASHED_FIELDS too, and it fails DIFFERENTLY.

    A NaN nested in a pydantic sub-model survives model_dump(mode="json"), so
    unchecked it would reach the canonicalizer and escape capture() as a bare
    CanonicalSerializationError (a ValueError, not a TzunError) after the
    sequence number was reserved. capture() raises one refusal, a TzunError,
    before anything is reserved.
    """
    from tzun_sdk.models import AiBom

    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        bom = AiBom.model_validate(
            {
                "modelDescriptorDigest": "sha256:" + "0" * 64,
                "vendorFingerprint": None,
                "promptTemplate": None,
                "inferenceParameters": {"temperature": float("nan")},
                "infrastructure": None,
            }
        )
        with pytest.raises(TzunError, match="non-finite"):
            await tzun.capture(
                ai_output={"ok": 1},
                decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                reason="ok",
                contributions=single_model(bom),
            )
    finally:
        await tzun.close()


async def test_refused_capture_does_not_burn_a_sequence_number() -> None:
    """A gap in the sequence is what the tamper scanner reports as a missing record.

    The guard therefore runs before the sequence is reserved, not after.
    """
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        with pytest.raises(TzunError):
            await tzun.capture(
                ai_output={"confidence": float("nan")},
                decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                reason="ok",
            )
        ok = await tzun.capture(
            ai_output={"confidence": 0.5},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        assert ok.sequenceNumber == 1
    finally:
        await tzun.close()


async def test_capture_still_accepts_finite_edge_values() -> None:
    """The guard must not reject legitimate numbers — 0, negatives, huge floats."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={
                "zero": 0,
                "zero_float": 0.0,
                "negative": -1.5,
                "big": 1.7976931348623157e308,
                "nested": {"list": [0, -0.0, {"deep": 1}]},
                "utf8_bytes": b"hello",
            },
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        stored = await tzun._storage.retrieve(result.evidenceId)
        assert stored is not None
        assert stored.payload.aiOutput["zero"] == 0
    finally:
        await tzun.close()
