"""Bedrock connector fixture tests."""

from __future__ import annotations

import json
import pathlib

import pytest

from tzun_sdk.ai_bom.connectors.bedrock import bedrock_connector as connector

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "bedrock"


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
    assert skeleton.model_descriptor.vendor == "bedrock"
    assert skeleton.model_descriptor.modelName  # non-empty identity


def test_unknown_shape_no_raise() -> None:
    """Unknown shape → None, no raise."""
    assert connector.build_ai_bom({}, {"unexpected": True}) is None


# ── zero-valued Converse params + InvokeModel body extraction ────────────────
# A parameter set to 0 is a real setting and is recorded as 0, not dropped as
# missing; stopSequences and Llama's max_gen_len are extracted too. Expectations
# below were produced by running the SAME request through the TS connector via
# tests/cross-sdk/ts-harness (src/sdk/connectors/bedrock.ts).


def test_converse_preserves_zero_valued_top_p_and_max_tokens() -> None:
    skeleton = connector.build_ai_bom(
        {
            "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "inferenceConfig": {
                "temperature": 0.0,
                "topP": 0,
                "maxTokens": 0,
                "stopSequences": ["X"],
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
    assert ip.stopSequences == ["X"]


def test_invoke_model_llama_body_extracts_max_gen_len_and_stops() -> None:
    """Llama-on-Bedrock spells it max_gen_len; both SDKs record it as maxTokens."""
    import json

    skeleton = connector.build_ai_bom(
        {
            "modelId": "meta.llama3-70b-instruct-v1:0",
            "body": json.dumps(
                {
                    "temperature": 0,
                    "top_p": 0,
                    "max_gen_len": 512,
                    "stop_sequences": ["Z"],
                }
            ),
        },
        {},
    )
    assert skeleton is not None
    ip = skeleton.inference_parameters
    assert ip is not None
    assert ip.temperature == 0
    assert ip.topP == 0
    assert ip.maxTokens == 512
    assert ip.stopSequences == ["Z"]


def test_invoke_model_max_tokens_beats_max_gen_len_even_at_zero() -> None:
    """TS uses `??`, so max_tokens: 0 still wins over max_gen_len.

    Pins the null-coalescing rule the extractor spells explicitly
    (`if max_tokens is None`); an `or` would treat 0 as missing and record
    max_gen_len instead.
    """
    import json

    skeleton = connector.build_ai_bom(
        {
            "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "body": json.dumps({"max_tokens": 0, "max_gen_len": 999}),
        },
        {},
    )
    assert skeleton is not None
    assert skeleton.inference_parameters is not None
    assert skeleton.inference_parameters.maxTokens == 0


def test_converse_does_not_bleed_invoke_model_body_spellings() -> None:
    """A Converse request reads only inferenceConfig, never InvokeModel body spellings.

    TS dispatches Converse XOR InvokeModel; merging the two would record body
    values TS ignores, so the two SDKs would describe the same call differently.
    """
    import json

    skeleton = connector.build_ai_bom(
        {
            "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "inferenceConfig": {"temperature": 0.3},
            "body": json.dumps({"top_p": 0.77, "max_tokens": 111}),
        },
        {},
    )
    assert skeleton is not None
    ip = skeleton.inference_parameters
    assert ip is not None
    assert ip.temperature == 0.3
    assert ip.topP is None
    assert ip.maxTokens is None


def test_bedrock_seed_is_not_extracted_matching_ts() -> None:
    """Bedrock records no seed, even when the request carries one.

    Pins the TS contract (bedrock.ts hard-codes `seed: null`), so both SDKs
    record the same inference parameters for the same request.
    """
    skeleton = connector.build_ai_bom(
        {
            "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "inferenceConfig": {"temperature": 0.3, "seed": 9},
        },
        {},
    )
    assert skeleton is not None
    assert skeleton.inference_parameters is not None
    assert skeleton.inference_parameters.seed is None
