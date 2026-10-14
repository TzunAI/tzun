"""Five connectors registered."""

from __future__ import annotations

from tzun_sdk.ai_bom.connectors import CONNECTORS, SUPPORTED_VENDORS


def test_five_connectors_registered() -> None:
    assert len(CONNECTORS) == 5
    assert set(CONNECTORS) == {"openai", "anthropic", "bedrock", "vertex", "azure_ai"}


def test_nim_and_hf_not_in_v1() -> None:
    """NIM and HF-Inference deferred."""
    assert "nim" not in CONNECTORS
    assert "nvidia-nim" not in CONNECTORS
    assert "hf-inference" not in CONNECTORS


def test_supported_vendors_tuple_matches_keys() -> None:
    assert set(SUPPORTED_VENDORS) == set(CONNECTORS.keys())
