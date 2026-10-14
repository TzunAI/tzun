"""hook() tests."""

from __future__ import annotations

import pytest

from tzun_sdk import Tzun, hook
from tzun_sdk.contributions import single_model
from tzun_sdk.errors import TzunError
from tzun_sdk.storage import MemoryAdapter


async def test_hook_unknown_vendor_raises() -> None:
    """Unknown vendor lists supported vendors verbatim."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        with pytest.raises(TzunError) as exc_info:
            await hook("not-a-vendor", {}, {}, tzun=tzun)
        msg = str(exc_info.value)
        assert "openai" in msg
        assert "anthropic" in msg
    finally:
        await tzun.close()


async def test_hook_no_tzun_raises() -> None:
    """No tzun resolvable → TzunError."""
    # Use a fresh contextvar scope by not initializing any Tzun.
    from tzun_sdk.ai_bom.hook import active_tzun

    # Ensure the contextvar is clean.
    active_tzun.set(None)
    with pytest.raises(TzunError):
        await hook("openai", {"temperature": 0.7}, {"model": "gpt-4o-2024-08-06"})


async def test_hook_openai_happy_path() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        ai_bom = await hook(
            "openai",
            {"temperature": 0.7, "max_tokens": 100},
            {"model": "gpt-4o-2024-08-06", "system_fingerprint": "fp_abc"},
            tzun=tzun,
        )
        assert ai_bom is not None
        assert ai_bom.modelDescriptorDigest.startswith("sha256:")
        assert ai_bom.vendorFingerprint == "fp_abc"
        assert ai_bom.inferenceParameters is not None
        assert ai_bom.inferenceParameters.temperature == 0.7
        assert ai_bom.inferenceParameters.maxTokens == 100
    finally:
        await tzun.close()


async def test_hook_anthropic_happy_path() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        ai_bom = await hook(
            "anthropic",
            {"temperature": 0.5, "max_tokens": 200},
            {"model": "claude-3-5-sonnet-20240620"},
            tzun=tzun,
        )
        assert ai_bom is not None
        assert ai_bom.modelDescriptorDigest.startswith("sha256:")
    finally:
        await tzun.close()


async def test_hook_returns_none_when_no_model() -> None:
    """Connector returns None for unresolvable shapes."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        # Response without model: connector should return None.
        ai_bom = await hook("openai", {}, {}, tzun=tzun)
        assert ai_bom is None
    finally:
        await tzun.close()


async def test_hook_dedup_cache_short_circuits_catalog_write() -> None:
    """Cache hit avoids storage write."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        params = {"temperature": 0.7}
        resp = {"model": "gpt-4o-2024-08-06"}
        b1 = await hook("openai", params, resp, tzun=tzun)
        b2 = await hook("openai", params, resp, tzun=tzun)
        assert b1.modelDescriptorDigest == b2.modelDescriptorDigest
        # Catalog write count: exactly 1 in the descriptor map.
        assert len(tzun._storage._descriptors) == 1  # type: ignore[attr-defined]
    finally:
        await tzun.close()


async def test_captured_ai_bom_records_temperature_zero_end_to_end() -> None:
    """Through the real public path: hook() → capture() → storage.

    `temperature: 0` is the standard setting for a deterministic decision.
    Stored evidence that recorded it as `temperature: null` would misstate the
    actual inference configuration of the decision it is there to prove.
    """
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        ai_bom = await hook(
            "vertex",
            {
                "model": "gemini-1.5-pro",
                "generationConfig": {
                    "temperature": 0,
                    "maxOutputTokens": 256,
                    "stopSequences": ["END"],
                },
                "location": "us-central1",
            },
            {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]},
            tzun=tzun,
        )
        assert ai_bom is not None
        result = await tzun.capture(
            ai_output={"decision": "approve"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
            contributions=single_model(ai_bom),
        )
        stored = await tzun._storage.retrieve(result.evidenceId)
        assert stored is not None
        step_bom = stored.payload.contributions.steps[0].aiBom
        assert step_bom is not None
        ip = step_bom.inferenceParameters
        assert ip is not None
        assert ip.temperature == 0
        assert ip.stopSequences == ["END"]
    finally:
        await tzun.close()


async def test_temperature_zero_changes_the_canonical_digest() -> None:
    """A step's aiBom is hashed (inside contributions), so 0-vs-null is a DIGEST difference.

    Two captures identical but for temperature 0 vs. temperature absent must
    not hash the same; if they did, a TS verifier re-deriving the AI-BOM would
    see a mismatch.
    """

    async def digest_for(gen_config: dict) -> str:
        tzun = await Tzun.init(storage=MemoryAdapter())
        try:
            ai_bom = await hook(
                "vertex",
                {"model": "gemini-1.5-pro", "generationConfig": gen_config},
                {},
                tzun=tzun,
            )
            result = await tzun.capture(
                ai_output={"decision": "approve"},
                decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                reason="ok",
                contributions=single_model(ai_bom),
                evidence_id="0f1e2d3c-4b5a-4987-8796-a5b4c3d2e1f0",
                captured_at="2026-01-01T00:00:00.000Z",
            )
            return result.canonicalDigest
        finally:
            await tzun.close()

    assert await digest_for({"temperature": 0}) != await digest_for({})
