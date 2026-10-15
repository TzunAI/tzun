"""Six connectors registered."""

from __future__ import annotations

from tzun_sdk.ai_bom.connectors import CONNECTORS, SUPPORTED_VENDORS


def test_six_connectors_registered() -> None:
    assert len(CONNECTORS) == 6
    assert set(CONNECTORS) == {"openai", "anthropic", "bedrock", "vertex", "azure_ai", "openrouter"}


def test_registry_keys_match_each_connector_vendor_label() -> None:
    """The registry key is the label hook() takes and the connector's own ``vendor``."""
    assert {key: c.vendor for key, c in CONNECTORS.items()} == {key: key for key in CONNECTORS}


def test_nim_and_hf_not_in_v1() -> None:
    """NIM and HF-Inference deferred."""
    assert "nim" not in CONNECTORS
    assert "nvidia-nim" not in CONNECTORS
    assert "hf-inference" not in CONNECTORS


def test_supported_vendors_tuple_matches_keys() -> None:
    assert set(SUPPORTED_VENDORS) == set(CONNECTORS.keys())
