"""Vertex connector fixture tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from tzun_sdk.ai_bom.connectors.vertex import vertex_connector as connector

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "vertex"


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
    assert skeleton.model_descriptor.vendor == "vertex"
    assert skeleton.model_descriptor.modelName  # non-empty identity


def test_unknown_shape_no_raise() -> None:
    """Unknown shape → None, no raise."""
    assert connector.build_ai_bom({}, {"unexpected": True}) is None


# ── zero-valued and predict-surface inference parameters ─────────────────────
# `temperature: 0` is the standard setting for a deterministic decision, so a
# zero-valued parameter is recorded as 0, never coalesced to null; the predict
# surface's `parameters` block is read as well. Every expectation below was
# produced by running the SAME request through the TS connector via
# tests/cross-sdk/ts-harness (src/sdk/connectors/vertex.ts).


def test_generate_content_preserves_zero_valued_parameters() -> None:
    skeleton = connector.build_ai_bom(
        {
            "model": "gemini-1.5-pro",
            "generationConfig": {
                "temperature": 0,
                "topP": 0,
                "maxOutputTokens": 0,
                "stopSequences": ["END"],
            },
        },
        {},
    )
    assert skeleton is not None
    ip = skeleton.inference_parameters
    assert ip is not None
    assert ip.temperature == 0
    assert ip.topP == 0
    assert ip.maxTokens == 0
    assert ip.stopSequences == ["END"]


def test_generate_content_extracts_stop_sequences() -> None:
    """TS normalizeStopSequences: a bare string becomes a one-element list."""
    skeleton = connector.build_ai_bom(
        {"model": "gemini-1.5-pro", "generationConfig": {"stopSequences": "STOP"}},
        {},
    )
    assert skeleton is not None
    assert skeleton.inference_parameters is not None
    assert skeleton.inference_parameters.stopSequences == ["STOP"]


def test_predict_surface_reads_the_parameters_block() -> None:
    """Both SDKs read params['parameters'] on the predict surface."""
    skeleton = connector.build_ai_bom(
        {
            "endpoint": "projects/p/locations/l/publishers/google/models/text-bison",
            "instances": [{"prompt": "hi"}],
            "parameters": {
                "temperature": 0,
                "topP": 0.5,
                "maxOutputTokens": 128,
                "stopSequences": ["X"],
            },
        },
        {},
    )
    assert skeleton is not None
    ip = skeleton.inference_parameters
    assert ip is not None
    assert ip.temperature == 0
    assert ip.topP == 0.5
    assert ip.maxTokens == 128
    assert ip.stopSequences == ["X"]


def test_seed_is_not_extracted_matching_ts() -> None:
    """TS vertex.ts hard-codes `seed: null` on both surfaces.

    inferenceParameters is inside aiBom, which is in V1_HASHED_FIELDS, so a
    seed recorded by Python alone would put a field in the Python AI-BOM that
    the TS AI-BOM for the same call lacks, and the two SDKs would digest the
    same call differently.
    """
    skeleton = connector.build_ai_bom(
        {"model": "gemini-1.5-pro", "generationConfig": {"seed": 42}}, {}
    )
    assert skeleton is not None
    assert skeleton.inference_parameters is not None
    assert skeleton.inference_parameters.seed is None


def test_top_level_params_are_not_a_fallback() -> None:
    """Neither SDK reads top-level params.temperature or params.maxOutputTokens."""
    skeleton = connector.build_ai_bom(
        {"model": "gemini-1.5-pro", "temperature": 0.9, "maxOutputTokens": 64}, {}
    )
    assert skeleton is not None
    ip = skeleton.inference_parameters
    assert ip is not None
    assert ip.temperature is None
    assert ip.maxTokens is None
