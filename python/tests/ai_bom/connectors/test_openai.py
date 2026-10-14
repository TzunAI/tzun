"""OpenAI connector fixture tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from tzun_sdk.ai_bom.connectors.openai import openai_connector as connector

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "openai"


class _Obj:
    """Object-shaped view of a dict (object AND dict shapes)."""

    def __init__(self, d: dict) -> None:  # type: ignore[type-arg]
        for k, v in d.items():
            setattr(self, k, _Obj(v) if isinstance(v, dict) else v)


@pytest.mark.parametrize("case", ["happy", "optional_fields_populated", "optional_fields_absent"])
@pytest.mark.parametrize("shape", ["dict", "object"])
def test_fixture_produces_skeleton(case: str, shape: str) -> None:
    fx = json.loads((FIXTURES / f"{case}.json").read_text())
    req, resp = fx["request"], fx["response"]
    if shape == "object":
        resp = _Obj(resp)
    skeleton = connector.build_ai_bom(req, resp)
    assert skeleton is not None
    assert skeleton.model_descriptor.vendor == "openai"
    assert skeleton.model_descriptor.modelName  # non-empty identity


def test_unknown_shape_no_raise() -> None:
    """Unknown shape → None, no raise."""
    assert connector.build_ai_bom({}, {"unexpected": True}) is None


def test_azure_hit_resolves_underlying_model() -> None:
    """Azure deployment name resolved via known-models entry."""
    fx = json.loads((FIXTURES / "azure_hit.json").read_text())
    # Build a known_models reference with a matching azure-deployment-name entry.
    known_models_with_azure = {
        "version": "tzun-known-models-v1",
        "entries": [
            {
                "vendor": "openai",
                "modelName": "gpt-4o",
                "modelVersion": "2024-08-06",
                "externalIdentifiers": [
                    {"scheme": "azure-deployment-name", "value": "gpt4o-prod-deployment"}
                ],
            }
        ],
    }
    s = connector.build_ai_bom(fx["request"], fx["response"], known_models_with_azure)
    assert s is not None
    # The resolved name should NOT be the raw deployment name
    assert s.model_descriptor.modelName != fx["response"]["model"]
    # It should be the underlying OpenAI model name
    assert s.model_descriptor.modelName == "gpt-4o"


def test_azure_miss_passes_deployment_through_vendor_asserted() -> None:
    """Unknown Azure deployment → vendor-asserted pass-through."""
    fx = json.loads((FIXTURES / "azure_miss.json").read_text())
    s = connector.build_ai_bom(fx["request"], fx["response"])
    assert s is not None
    assert s.model_descriptor.modelName == fx["response"]["model"]
    assert s.model_descriptor.integrityTier == "vendor-asserted"
    assert s.model_descriptor.modelVersion == "unknown"
