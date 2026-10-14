"""Azure AI connector fixture tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from tzun_sdk.ai_bom.connectors.azure_ai import azure_ai_connector as connector

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "azure_ai"


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
    assert skeleton.model_descriptor.vendor == "azure-ai"
    assert skeleton.model_descriptor.modelName  # non-empty identity


def test_unknown_shape_no_raise() -> None:
    """Unknown shape → None, no raise."""
    # azure_ai requires at least model in response or params; empty both → None
    assert connector.build_ai_bom({}, {}) is None
