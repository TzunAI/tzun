"""OpenRouter gateway connector tests.

The Python twin of ``tests/ts/connectors/openrouter.test.ts``: the same cases,
the same values and the same expected records. The ``fixtures/openrouter``
files are synthetic, on the shape of an OpenRouter ``/api/v1/chat/completions``
response (``id``, ``object``, ``created``, ``model``, ``provider``,
``system_fingerprint``, ``service_tier``, ``choices[]``, ``usage``); generation
ids, content and account fields are placeholders. Upstream provider names are
written the way OpenRouter reports them (``"Nvidia"``, ``"Google AI Studio"``);
the connector records them verbatim, so the tests do not depend on any
particular spelling.

The cross-SDK gate (``tests/cross-sdk/test_openrouter_parity.py`` and
``test_connector_parity.py``) runs the same fixtures through both SDKs; the
digests pinned below are the ones the TypeScript SDK produces for them, so this
file fails on a Python-side regression even when that harness is not running.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import pathlib
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from tzun_sdk._generated.canonical import canonical_serialize, canonical_serialize_descriptor
from tzun_sdk.ai_bom.connectors import CONNECTORS, get_connector
from tzun_sdk.ai_bom.connectors._base import AiBomSkeleton
from tzun_sdk.ai_bom.connectors.openrouter import (
    is_openrouter_base_url,
    openrouter_connector,
    openrouter_endpoint,
)
from tzun_sdk.ai_bom.known_models import load_known_models
from tzun_sdk.payload_rules import ai_bom_violation

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "openrouter"
CASES = [
    "happy",
    "optional_fields_populated",
    "optional_fields_absent",
    "zero_valued",
    "stop_string",
    "stop_over_limits",
    "alias_id",
    "router_id",
    "endpoint_normalized",
    "overlong_strings",
    "non_integer_tokens",
]
NULL_INFRASTRUCTURE = {"provider": None, "region": None, "apiVersion": None, "endpoint": None}

# The TypeScript SDK's digests for each fixture: the descriptor's
# (`canonicalSerializeDescriptor`) and the wire aiBom's once that digest
# replaces the descriptor (`canonicalSerialize` over its five members), from
# `tests/cross-sdk/ts-harness/openrouter.ts`.
TS_DIGESTS: dict[str, tuple[str, str]] = {
    "alias_id": (
        "sha256:2212961b1c799a9b827f06a25760a3d0f58fa821ad8466841bda99051e953964",
        "c8d904b45d14fa29ed9cb411458fc50734d95e8429f657548bb0cbf33985ea5e",
    ),
    "endpoint_normalized": (
        "sha256:25ffced380868563c508db66fc227b092e1efff7c532a94aa432909a349aca6b",
        "53bdc1fce542a324be3f9d27c42259267a2af4537183ec50ed8fc083586076d2",
    ),
    "happy": (
        "sha256:cee92abf7baee4f3bbeeddd8080c54bfcf871c14950c726cc61fd5f97c2e969d",
        "3d19e6f0ca869f7ddfde4567fa3cb78ce2fe6b5a0619568259ca0a8b9ff6973e",
    ),
    "non_integer_tokens": (
        "sha256:b670355c905ffdf830042b9226d592a1acefe262254c977c6e8bb0f3740ed94e",
        "60adc5c7e003d37ab5f3771d70e4539eded9e47c55486808186b8ab2932c474f",
    ),
    "optional_fields_absent": (
        "sha256:7500363807e56e2af6aab5ddaa5f282bc8f6cff8622617a6f991ab8b6ebbf053",
        "9b430b9e43654a8ba153f222344743dd21f2ca29c90b2db41afbac251373d0e3",
    ),
    "optional_fields_populated": (
        "sha256:c708a7cf3ed3c85d709e0e0ec46cba10797f660acd481c4489206a1206198ec4",
        "cbe6f32c6e54b9c6346148096e87df37264a48d95b5543abfed6dc5078cbd228",
    ),
    "overlong_strings": (
        "sha256:19e4de93514b5b07d1f11fde2f47424f3ccd3ea24003e2eaa3ad72e79c45fe00",
        "59a8f8542cdce6822d04b9c8713f8f7afd18b81930a07dcf3e619fbae453d3dc",
    ),
    "router_id": (
        "sha256:0f0003411d88746a94195a77c3cc24b5d81746ad9ee5c541cb7182eb005ad228",
        "ee8ae12f7638d15947e0ddcaac672d13104bda4aff2495f2d3c92691e93d257a",
    ),
    "stop_string": (
        "sha256:e30e366dc86eff4a7e9584d98a267bb6044886ab08afbb85c07b0af20b2c7064",
        "82394a70b7b30895b027f7bb092818654b4603bbd2159e65f44afbb9ec255e27",
    ),
    "stop_over_limits": (
        "sha256:714a8d9393d24dbae4f7a6725ed8c003b50efb5510c9b4f1d7703e90e983399c",
        "21538ded3afa681a919caf554bdd0fb24e8bce65e070268848bb05e0acd84df5",
    ),
    "zero_valued": (
        "sha256:d6f8c68a529b308d55a82d54568af05abe01fb210c4c86ce8451c1e0afffe16c",
        "c834dd5272909a61f6d058b01d2fb2b93022713eb85b7340163810df88e23d0b",
    ),
}


def ok_response(model: Any, **extra: Any) -> dict[str, Any]:
    """An OpenRouter-shaped chat-completions response with placeholder values."""
    response: dict[str, Any] = {
        "id": "gen-0000000000-scrubbed000000000000",
        "object": "chat.completion",
        "created": 1790000000,
        "model": model,
        "system_fingerprint": None,
        "service_tier": None,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "native_finish_reason": "stop",
                "logprobs": None,
                "message": {"role": "assistant", "content": "approve", "refusal": None, "reasoning": None},
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
    }
    response.update(extra)
    return response


def hf(repo: str) -> dict[str, Any]:
    return {
        "scheme": "hf-repo",
        "value": repo,
        "issuedBy": None,
        "issuedAt": None,
        "url": f"https://huggingface.co/{repo}",
    }


def fixture(case: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / f"{case}.json").read_text(encoding="utf-8"))
    return data


def build(params: dict[str, Any], response: Any) -> AiBomSkeleton:
    skeleton = openrouter_connector.build_ai_bom(params, response, load_known_models())
    assert skeleton is not None
    return skeleton


def as_dict(s: AiBomSkeleton) -> dict[str, Any]:
    """The skeleton as plain JSON, the shape the TS connector returns."""

    def dump(model: Any) -> Any:
        return None if model is None else model.model_dump(mode="json", exclude_none=False)

    return {
        "modelDescriptor": dump(s.model_descriptor),
        "vendorFingerprint": s.vendor_fingerprint,
        "promptTemplate": dump(s.prompt_template),
        "inferenceParameters": dump(s.inference_parameters),
        "infrastructure": dump(s.infrastructure),
    }


def wire_ai_bom(s: AiBomSkeleton) -> tuple[str, dict[str, Any]]:
    """The descriptor digest and the wire aiBom the skeleton becomes."""
    d = as_dict(s)
    canonical = canonical_serialize_descriptor(d["modelDescriptor"])
    digest = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest, {
        "modelDescriptorDigest": digest,
        "vendorFingerprint": d["vendorFingerprint"],
        "promptTemplate": d["promptTemplate"],
        "inferenceParameters": d["inferenceParameters"],
        "infrastructure": d["infrastructure"],
    }


class _Obj:
    """Object-shaped view of a dict (object AND dict shapes)."""

    def __init__(self, d: dict[str, Any]) -> None:
        for k, v in d.items():
            setattr(self, k, _Obj(v) if isinstance(v, dict) else v)


class _TypedResponse(BaseModel):
    """openai-python's response models are pydantic models with ``extra="allow"``.

    OpenRouter's ``provider`` is not a member of openai-python's
    ``ChatCompletion``, so it is kept as an extra attribute; this stand-in
    reproduces that without installing the vendor package.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    model: str
    system_fingerprint: str | None = None


def test_exposes_vendor_openrouter() -> None:
    assert openrouter_connector.vendor == "openrouter"
    assert CONNECTORS["openrouter"] is openrouter_connector
    assert get_connector("openrouter") is openrouter_connector


# ── The shared fixture cases ───────────────────────────────────────────


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("shape", ["dict", "object"])
def test_fixture_produces_skeleton(case: str, shape: str) -> None:
    fx = fixture(case)
    resp = fx["response"] if shape == "dict" else _Obj(fx["response"])
    s = build(fx["request"], resp)
    assert s.model_descriptor.vendor == "openrouter"
    assert s.model_descriptor.modelName == fx["response"]["model"]
    # Same record from either response shape.
    assert as_dict(s) == as_dict(build(fx["request"], fx["response"]))


@pytest.mark.parametrize("case", CASES)
def test_fixture_digests_match_the_typescript_sdk(case: str) -> None:
    s = build(fixture(case)["request"], fixture(case)["response"])
    digest, ai_bom = wire_ai_bom(s)
    ts_descriptor_digest, ts_ai_bom_digest = TS_DIGESTS[case]
    assert digest == ts_descriptor_digest
    assert hashlib.sha256(canonical_serialize(ai_bom).encode("utf-8")).hexdigest() == ts_ai_bom_digest


def test_happy_a_free_nemotron_call_through_the_gateway() -> None:
    fx = fixture("happy")
    assert as_dict(build(fx["request"], fx["response"])) == {
        "modelDescriptor": {
            "descriptorVersion": "d1",
            "vendor": "openrouter",
            "modelName": "nvidia/nemotron-3-super-120b-a12b:free",
            "modelVersion": "unknown",
            "modelType": "llm",
            "integrityTier": "vendor-asserted",
            "modelDigest": None,
            "parentModelDescriptorDigest": None,
            "derivation": None,
            "trainedBy": "nvidia",
            "license": "nvidia-nemotron-open-model-license",
            "modelCardUrl": "https://openrouter.ai/nvidia/nemotron-3-super-120b-a12b",
            "training": {
                "trainingDataDigest": None,
                "trainingDataRef": None,
                "lastTrainingDate": None,
                "evaluations": [],
            },
            "regulatoryMarkings": [],
            "externalIdentifiers": [hf("nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16")],
        },
        "vendorFingerprint": None,
        "promptTemplate": None,
        "inferenceParameters": {
            "temperature": 0.2,
            "topP": None,
            "maxTokens": 1200,
            "seed": None,
            "stopSequences": None,
        },
        "infrastructure": {
            "provider": "Nvidia",
            "region": None,
            "apiVersion": None,
            "endpoint": "https://openrouter.ai/api/v1",
        },
    }


def test_optional_fields_populated() -> None:
    fx = fixture("optional_fields_populated")
    s = build(fx["request"], fx["response"])
    d = s.model_descriptor
    assert (d.vendor, d.modelName, d.trainedBy) == ("openrouter", "google/gemini-3.8-flash", "google")
    assert d.license == "google-commercial"
    assert d.externalIdentifiers == []
    assert s.vendor_fingerprint == "fp_synthetic01"
    assert as_dict(s)["inferenceParameters"] == {
        "temperature": 0.7,
        "topP": 0.9,
        "maxTokens": 256,
        "seed": 42,
        "stopSequences": ["END", "STOP"],
    }
    assert as_dict(s)["infrastructure"] == {
        "provider": "Google AI Studio",
        "region": None,
        "apiVersion": None,
        "endpoint": "https://openrouter.ai/api/v1",
    }


def test_optional_fields_absent() -> None:
    fx = fixture("optional_fields_absent")
    assert "system_fingerprint" not in fx["response"] and "usage" not in fx["response"]
    s = build(fx["request"], fx["response"])
    assert s.model_descriptor.trainedBy == "qwen"
    assert s.model_descriptor.license == "apache-2.0"
    assert s.vendor_fingerprint is None
    assert as_dict(s)["inferenceParameters"] == {
        "temperature": None,
        "topP": None,
        "maxTokens": None,
        "seed": None,
        "stopSequences": None,
    }
    # Always an object for this connector, with nothing assumed.
    assert as_dict(s)["infrastructure"] == NULL_INFRASTRUCTURE


def test_zero_valued_zeros_are_kept() -> None:
    fx = fixture("zero_valued")
    s = build(fx["request"], fx["response"])
    assert as_dict(s)["inferenceParameters"] == {
        "temperature": 0,
        "topP": 0,
        "maxTokens": 0,
        "seed": 0,
        "stopSequences": None,
    }
    assert s.infrastructure is not None and s.infrastructure.provider == "DeepSeek"
    assert s.model_descriptor.license == "mit"


def test_stop_string_becomes_a_one_element_list() -> None:
    fx = fixture("stop_string")
    s = build(fx["request"], fx["response"])
    assert s.inference_parameters is not None
    assert s.inference_parameters.stopSequences == ["END"]


def test_stop_over_limits_is_none_as_a_whole() -> None:
    fx = fixture("stop_over_limits")
    s = build(fx["request"], fx["response"])
    assert s.inference_parameters is not None
    assert s.inference_parameters.stopSequences is None
    _, ai_bom = wire_ai_bom(s)
    assert ai_bom_violation(ai_bom) is None
    # An open-weights entry: the license of the Hugging Face card, and its repo.
    d = as_dict(s)["modelDescriptor"]
    assert d["license"] == "apache-2.0"
    assert d["externalIdentifiers"] == [hf("CohereLabs/command-a-plus-05-2026-bf16")]


def test_alias_id_recorded_verbatim_not_enriched() -> None:
    fx = fixture("alias_id")
    s = build(fx["request"], fx["response"])
    d = s.model_descriptor
    assert d.modelName == "~anthropic/claude-opus-latest"
    assert d.modelVersion == "unknown"
    assert d.trainedBy == "anthropic"
    assert d.license is None
    assert d.modelCardUrl is None
    assert s.infrastructure is not None and s.infrastructure.provider == "Anthropic"


def test_router_id_names_no_maker() -> None:
    fx = fixture("router_id")
    d = build(fx["request"], fx["response"]).model_descriptor
    assert d.vendor == "openrouter"
    assert d.modelName == "openrouter/auto"
    assert d.trainedBy is None
    assert d.license is None


def test_endpoint_normalized() -> None:
    fx = fixture("endpoint_normalized")
    s = build(fx["request"], fx["response"])
    assert s.infrastructure is not None
    assert s.infrastructure.endpoint == "https://gateway.example.com/api/v1"


def test_overlong_strings_are_null() -> None:
    fx = fixture("overlong_strings")
    assert as_dict(build(fx["request"], fx["response"]))["infrastructure"] == NULL_INFRASTRUCTURE
    # Exactly 256 is allowed.
    at = build({"model": "minimax/minimax-m3"}, ok_response("minimax/minimax-m3", provider="P" * 256))
    assert at.infrastructure is not None and at.infrastructure.provider == "P" * 256
    # UTF-16 code units, not code points: 128 astral characters are 256 units,
    # 129 are 258.
    astral = "\U0001f600"
    s128 = build({"model": "minimax/minimax-m3"}, ok_response("minimax/minimax-m3", provider=astral * 128))
    assert s128.infrastructure is not None and s128.infrastructure.provider == astral * 128
    s129 = build({"model": "minimax/minimax-m3"}, ok_response("minimax/minimax-m3", provider=astral * 129))
    assert s129.infrastructure is not None and s129.infrastructure.provider is None


def test_non_integer_tokens_are_null() -> None:
    fx = fixture("non_integer_tokens")
    s = build(fx["request"], fx["response"])
    assert s.inference_parameters is not None
    assert s.inference_parameters.maxTokens is None
    assert s.inference_parameters.seed is None


# ── Parameter edges (unit tests only) ──────────────────────────────────


@pytest.mark.parametrize(
    ("label", "extra", "member", "expected"),
    [
        ("2^53 max_tokens", {"max_tokens": 9007199254740992}, "maxTokens", None),
        ("2^53 max_tokens as a float", {"max_tokens": 9007199254740992.0}, "maxTokens", None),
        ("negative max_tokens", {"max_tokens": -1}, "maxTokens", None),
        ("string max_tokens", {"max_tokens": "100"}, "maxTokens", None),
        ("integral-float max_tokens", {"max_tokens": 64.0}, "maxTokens", 64),
        ("max safe max_tokens", {"max_tokens": 9007199254740991}, "maxTokens", 9007199254740991),
        ("boolean max_tokens", {"max_tokens": True}, "maxTokens", None),
        ("negative seed", {"seed": -7}, "seed", -7),
        ("min safe seed", {"seed": -9007199254740991}, "seed", -9007199254740991),
        ("seed below -(2^53-1)", {"seed": -9007199254740992}, "seed", None),
        ("boolean seed", {"seed": True}, "seed", None),
        ("NaN temperature", {"temperature": math.nan}, "temperature", None),
        ("Infinity top_p", {"top_p": math.inf}, "topP", None),
        ("string temperature", {"temperature": "0.5"}, "temperature", None),
        ("empty stop array", {"stop": []}, "stopSequences", None),
        ("stop array with non-strings", {"stop": ["A", 1, None, "B"]}, "stopSequences", ["A", "B"]),
        ("stop number", {"stop": 5}, "stopSequences", None),
        # The AI-BOM bound: at most 16 stop sequences of at most 256 UTF-16 code
        # units each, counted after non-strings are dropped; past it, None.
        ("16 stops", {"stop": ["S"] * 16}, "stopSequences", ["S"] * 16),
        ("17 stops", {"stop": ["S"] * 17}, "stopSequences", None),
        ("16 stops and a non-string", {"stop": ["S"] * 16 + [7]}, "stopSequences", ["S"] * 16),
        ("a 256-unit stop", {"stop": "x" * 256}, "stopSequences", ["x" * 256]),
        ("a 257-unit stop", {"stop": "x" * 257}, "stopSequences", None),
        ("one 257-unit stop among short ones", {"stop": ["END", "x" * 257]}, "stopSequences", None),
        ("128 astral characters (256 units)", {"stop": ["\U0001f600" * 128]}, "stopSequences", ["\U0001f600" * 128]),
        ("129 astral characters (258 units)", {"stop": ["\U0001f600" * 129]}, "stopSequences", None),
    ],
)
def test_parameter_edges(label: str, extra: dict[str, Any], member: str, expected: Any) -> None:
    s = build({"model": "openai/gpt-5.4-mini", **extra}, ok_response("openai/gpt-5.4-mini"))
    assert as_dict(s)["inferenceParameters"][member] == expected, label


def test_every_skeleton_passes_the_ai_bom_exact_members_rule() -> None:
    cases: list[tuple[dict[str, Any], dict[str, Any]]] = [
        ({"max_tokens": 100.5, "seed": 1.5}, {"provider": "x" * 300}),
        ({"max_tokens": -1, "seed": 2**53, "openrouter_endpoint": "https://openrouter.ai/" + "a" * 300}, {}),
        ({"temperature": 0, "top_p": 0, "max_tokens": 0, "seed": 0, "stop": "END"}, {"provider": "Nvidia"}),
        ({"openrouter_endpoint": "ftp://openrouter.ai"}, {"provider": 42}),
        ({"stop": ["S"] * 17}, {}),
        ({"stop": ["x" * 300]}, {}),
    ]
    cases += [(fixture(c)["request"], {}) for c in CASES]
    for params, extra in cases:
        s = build({"model": "qwen/qwen3.8-27b", **params}, ok_response("qwen/qwen3.8-27b", **extra))
        _, ai_bom = wire_ai_bom(s)
        assert ai_bom_violation(ai_bom) is None, (params, extra)


# ── No AI-BOM without a served model ──────────────────────────────────


def test_returns_none_when_the_response_has_no_model() -> None:
    response = ok_response("x")
    del response["model"]
    assert openrouter_connector.build_ai_bom({"model": "openai/gpt-5.4-mini"}, response) is None


@pytest.mark.parametrize("model", ["", 42, None])
def test_returns_none_when_response_model_is_empty_or_not_a_string(model: Any) -> None:
    assert openrouter_connector.build_ai_bom({"model": "openai/gpt-5.4-mini"}, ok_response(model)) is None


def test_unknown_shape_no_raise() -> None:
    assert openrouter_connector.build_ai_bom({}, {"unexpected": True}) is None


def test_records_the_served_model_never_the_requested_one() -> None:
    # A fallback list or a router: the gateway served another model.
    s = build(
        {"model": "openrouter/auto", "models": ["anthropic/claude-opus-5.5", "openai/gpt-6-astra"]},
        ok_response("openai/gpt-6-astra", provider="OpenAI"),
    )
    assert s.model_descriptor.modelName == "openai/gpt-6-astra"
    assert s.model_descriptor.trainedBy == "openai"
    assert s.model_descriptor.license == "openai-commercial"


def test_is_deterministic() -> None:
    params = {"model": "x-ai/grok-4.7", "temperature": 0.1, "openrouter_endpoint": "https://openrouter.ai/api/v1/"}
    response = ok_response("x-ai/grok-4.7", provider="xAI")
    snapshot = copy.deepcopy((params, response))
    assert as_dict(build(params, response)) == as_dict(build(params, response))
    # Neither input is mutated.
    assert (params, response) == snapshot


def test_defaults_to_the_bundled_catalog() -> None:
    fx = fixture("happy")
    s = openrouter_connector.build_ai_bom(fx["request"], fx["response"])
    assert s is not None
    assert as_dict(s) == as_dict(build(fx["request"], fx["response"]))


def test_reads_provider_off_a_typed_response_as_an_extra_attribute() -> None:
    """A pydantic response with ``extra="allow"`` keeps ``provider`` as an attribute."""
    typed = _TypedResponse(
        id="gen-0000000000-scrubbed000000000000",
        model="nvidia/nemotron-3-super-120b-a12b:free",
        provider="Nvidia",  # type: ignore[call-arg]
    )
    assert typed.provider == "Nvidia"  # type: ignore[attr-defined]
    s = build({"openrouter_endpoint": "https://openrouter.ai/api/v1/"}, typed)
    assert as_dict(s)["infrastructure"] == {
        "provider": "Nvidia",
        "region": None,
        "apiVersion": None,
        "endpoint": "https://openrouter.ai/api/v1",
    }
    assert s.model_descriptor.trainedBy == "nvidia"


# ── Every major vendor through the gateway ─────────────────────────────

# One served id per major author on OpenRouter, with the license the bundled
# entry gives it (None: no entry, so the descriptor is truthful but
# unenriched). Provider names are illustrative; the connector copies them.
MAJOR_VENDORS: list[tuple[str, str, str, str | None]] = [
    ("openai", "openai/gpt-6.1-sol", "OpenAI", "openai-commercial"),
    ("openai", "openai/gpt-oss-120b", "Nvidia", "apache-2.0"),
    ("anthropic", "anthropic/claude-sonnet-5.5", "Anthropic", "anthropic-commercial"),
    ("google", "google/gemini-4-argon", "Google Vertex", "google-commercial"),
    ("google", "google/gemma-4-31b-it:free", "Google AI Studio", "apache-2.0"),
    ("meta-llama", "meta-llama/llama-4-maverick", "Groq", "llama4"),
    ("meta", "meta/muse-spark-1.3", "Meta", "meta-commercial"),
    ("meta", "meta/muse-glimmer-30b", "Meta", "apache-2.0"),
    # A major author's id without an entry: truthful, unenriched.
    ("meta", "meta/muse-spark-1.3-contributor", "Meta", None),
    ("mistralai", "mistralai/mistral-large-4-0", "Mistral", "mistral-commercial"),
    ("mistralai", "mistralai/mistral-medium-3-5:batch", "Mistral", "mistral-modified-mit"),
    ("x-ai", "x-ai/grok-4.7", "xAI", "xai-commercial"),
    ("deepseek", "deepseek/deepseek-v4-pro-0813", "DeepSeek", "mit"),
    ("qwen", "qwen/qwen3.8-2.4t-a95b", "Alibaba", "qwen3.8-max"),
    ("nvidia", "nvidia/nemotron-3-ultra-550b-a55b:free", "Nvidia", "openmdw-1.1"),
    ("microsoft", "microsoft/phi-4", "DeepInfra", "mit"),
    ("amazon", "amazon/nova-premier-v1", "Amazon Bedrock", "amazon-commercial"),
    ("cohere", "cohere/command-a", "Cohere", "cc-by-nc-4.0"),
    ("cohere", "cohere/command-a-plus", "Cohere", "apache-2.0"),
    ("moonshotai", "moonshotai/kimi-k3", "Moonshot AI", "kimi-k3"),
    ("z-ai", "z-ai/glm-5.3-flash", "Z.AI", "mit"),
    ("minimax", "minimax/minimax-m3", "Minimax", "minimax-community"),
]


@pytest.mark.parametrize(("author", "served", "provider", "license_"), MAJOR_VENDORS)
def test_major_vendor_through_the_gateway(author: str, served: str, provider: str, license_: str | None) -> None:
    s = build({"model": served, "openrouter_endpoint": "https://openrouter.ai/api/v1"}, ok_response(served, provider=provider))
    d = s.model_descriptor
    # Served by the gateway, made by the author, run by the upstream.
    assert d.vendor == "openrouter"
    assert d.modelName == served
    assert d.modelVersion == "unknown"
    assert d.trainedBy == author
    assert d.integrityTier == "vendor-asserted"
    assert d.modelDigest is None
    assert d.license == license_
    if license_ is not None:
        assert d.modelType == "llm"
        base = served[: served.rfind(":")] if ":" in served else served
        assert d.modelCardUrl == f"https://openrouter.ai/{base}"
    assert as_dict(s)["infrastructure"] == {
        "provider": provider,
        "region": None,
        "apiVersion": None,
        "endpoint": "https://openrouter.ai/api/v1",
    }


def test_open_weights_entries_name_their_hugging_face_repo() -> None:
    open_ = build({}, ok_response("meta-llama/llama-3.3-70b-instruct"))
    assert as_dict(open_)["modelDescriptor"]["externalIdentifiers"] == [hf("meta-llama/Llama-3.3-70B-Instruct")]
    closed = build({}, ok_response("anthropic/claude-opus-5.5"))
    assert closed.model_descriptor.externalIdentifiers == []


# ── Unknown authors: no false vendor, no false maker ───────────────────


@pytest.mark.parametrize(
    ("served", "author"),
    [
        ("unbiased/pareto-26.9", "unbiased"),
        ("tencent/hunyuan-a13b-instruct", "tencent"),
        ("some-new-lab/model-x", "some-new-lab"),
    ],
)
def test_unknown_author_stays_openrouter_and_is_not_enriched(served: str, author: str) -> None:
    d = build({}, ok_response(served, provider="Some Host")).model_descriptor
    assert d.vendor == "openrouter"
    assert d.trainedBy == author
    assert d.license is None
    assert d.modelType is None
    assert d.modelCardUrl is None
    assert d.externalIdentifiers == []


@pytest.mark.parametrize("served", ["no-prefix", "/leading-slash", "~", ""])
def test_an_id_with_no_author_prefix_names_no_maker(served: str) -> None:
    s = openrouter_connector.build_ai_bom({}, ok_response(served), load_known_models())
    if served == "":
        assert s is None
        return
    assert s is not None
    assert s.model_descriptor.trainedBy is None
    assert s.model_descriptor.vendor == "openrouter"


def test_an_author_that_is_a_vendor_label_elsewhere_does_not_become_that_vendor() -> None:
    # `amazon/*` is not a Bedrock call, `nvidia/*` not a NIM call, `openai/*`
    # not an OpenAI call: the gateway served them.
    for served in ["amazon/nova-2-lite-v1", "nvidia/nemotron-3.5-lightning", "openai/gpt-6-luna"]:
        s = build({}, ok_response(served, provider="Upstream"))
        assert s.model_descriptor.vendor == "openrouter"
        assert s.infrastructure is not None and s.infrastructure.provider == "Upstream"


# ── No infrastructure the gateway did not report ───────────────────────


def test_claims_no_infrastructure_it_was_not_told_about() -> None:
    s = build(
        {
            "model": "nvidia/nemotron-3-super-120b-a12b",
            # Routing preferences are a request option, not the upstream that ran it.
            "provider": {"order": ["Nvidia"], "allow_fallbacks": False},
            # Other connectors' hint keys are not this connector's endpoint.
            "azure_endpoint": "https://example.openai.azure.com",
            "nim_endpoint": "https://integrate.api.nvidia.com/v1",
            "base_url": "https://openrouter.ai/api/v1",
            "api_version": "2024-10-21",
            "azure_region": "eastus",
            "region": "us-east-1",
        },
        ok_response("nvidia/nemotron-3-super-120b-a12b"),
    )
    assert as_dict(s)["infrastructure"] == NULL_INFRASTRUCTURE


def test_never_names_the_gateway_or_the_maker_as_the_provider() -> None:
    s = build({"openrouter_endpoint": "https://openrouter.ai/api/v1"}, ok_response("google/gemini-4-argon"))
    assert s.infrastructure is not None
    assert s.infrastructure.provider is None


@pytest.mark.parametrize(
    ("provider", "expected"),
    [("Azure", "Azure"), ("", None), (42, None), ({"name": "Azure"}, None), (None, None), (True, None)],
)
def test_takes_the_provider_from_the_response_only_verbatim(provider: Any, expected: str | None) -> None:
    s = build({}, ok_response("openai/gpt-6-astra", provider=provider))
    assert s.infrastructure is not None and s.infrastructure.provider == expected


def test_vendor_fingerprint_is_system_fingerprint_only() -> None:
    s = build({}, ok_response("openai/gpt-6-astra", provider="OpenAI", system_fingerprint=None))
    assert s.vendor_fingerprint is None
    n = build({}, ok_response("openai/gpt-6-astra", system_fingerprint=7))
    assert n.vendor_fingerprint is None


# ── openrouter_endpoint ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://openrouter.ai/api/v1", "https://openrouter.ai/api/v1"),
        # openai-python's base_url carries a trailing slash; both SDKs record the same.
        ("https://openrouter.ai/api/v1/", "https://openrouter.ai/api/v1"),
        ("https://openrouter.ai/api/v1///", "https://openrouter.ai/api/v1"),
        ("https://openrouter.ai", "https://openrouter.ai"),
        ("https://openrouter.ai/", "https://openrouter.ai"),
        ("http://localhost:8080/v1", "http://localhost:8080/v1"),
        # The host's ASCII letters are lowercased and the scheme's default port
        # is dropped, as httpx.URL does; any other port, and the path's case,
        # are kept.
        ("https://OpenRouter.AI:443/api/v1", "https://openrouter.ai/api/v1"),
        ("https://OpenRouter.AI:443/api/v1/", "https://openrouter.ai/api/v1"),
        ("https://openrouter.ai:443", "https://openrouter.ai"),
        ("http://openrouter.ai:80/x", "http://openrouter.ai/x"),
        ("http://openrouter.ai:443/x", "http://openrouter.ai:443/x"),
        ("https://openrouter.ai:80/x", "https://openrouter.ai:80/x"),
        ("https://openrouter.ai:8443/api/v1", "https://openrouter.ai:8443/api/v1"),
        ("https://openrouter.ai:1443/api/v1", "https://openrouter.ai:1443/api/v1"),
        ("https://[::1]:443/api/v1", "https://[::1]/api/v1"),
        ("https://Gateway.Example.COM/API/V1", "https://gateway.example.com/API/V1"),
        ("https://Key:@OpenRouter.AI/api/v1", "https://openrouter.ai/api/v1"),
        # Only ASCII letters: other characters are kept as given.
        ("https://\u0130penrouter.ai/v1", "https://\u0130penrouter.ai/v1"),
        ("https://:443/api/v1", None),
        ("https://openrouter.ai?x=1", "https://openrouter.ai"),
        ("https://openrouter.ai/api/v1#frag", "https://openrouter.ai/api/v1"),
        ("https://openrouter.ai/api/v1/?a=b/c#d", "https://openrouter.ai/api/v1"),
        # Userinfo is dropped (written with an empty password here: `user:@host`).
        ("https://user:@openrouter.ai/api/v1", "https://openrouter.ai/api/v1"),
        ("https://a@b:c:@openrouter.ai/api/v1", "https://openrouter.ai/api/v1"),
        # A `\` in the host part is refused: openai-node reads it as `/`, httpx
        # keeps it in the userinfo, so the two would call different hosts.
        ("https://evil.example.com\\@openrouter.ai/v1", None),
        ("https://evil.example.com\\@eu.openrouter.ai/v1", None),
        ("https://openrouter.ai\\@evil.example.com/v1", None),
        # The scheme match is case-sensitive.
        ("HTTPS://openrouter.ai/api/v1", None),
        ("ftp://openrouter.ai/api/v1", None),
        ("openrouter.ai/api/v1", None),
        ("https://", None),
        ("https:///api/v1", None),
        ("https://user@/api/v1", None),
        ("https://?q", None),
        ("", None),
        (None, None),
        (42, None),
        ({"href": "https://openrouter.ai/api/v1"}, None),
    ],
)
def test_openrouter_endpoint(value: Any, expected: str | None) -> None:
    assert openrouter_endpoint(value) == expected


def test_openrouter_endpoint_allows_256_utf16_code_units_and_refuses_257() -> None:
    prefix = "https://openrouter.ai/"
    at = prefix + "a" * (256 - len(prefix))
    assert openrouter_endpoint(at) == at
    assert openrouter_endpoint(at + "a") is None
    # Trailing slashes are stripped before the length is measured.
    assert openrouter_endpoint(at + "/") == at
    # Measured in UTF-16 code units: an astral character counts twice.
    astral = prefix + "\U0001f600" * ((256 - len(prefix)) // 2)
    assert openrouter_endpoint(astral) == astral
    assert openrouter_endpoint(astral + "a") is None


# ── is_openrouter_base_url ─────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://openrouter.ai/api/v1", True),
        ("https://openrouter.ai/api/v1/", True),
        ("https://openrouter.ai", True),
        ("http://openrouter.ai/api/v1", True),
        ("https://OpenRouter.AI/api/v1", True),
        ("https://openrouter.ai:443/api/v1", True),
        ("https://key:@openrouter.ai/api/v1", True),
        ("https://openrouter.ai?x=1", True),
        # A subdomain is OpenRouter's too: the data-region hosts among them.
        ("https://eu.openrouter.ai/api/v1", True),
        ("https://us.openrouter.ai/api/v1", True),
        ("https://EU.OpenRouter.AI:443/api/v1", True),
        ("https://api.openrouter.ai/v1", True),
        ("https://a.b-c.openrouter.ai/v1", True),
        # One trailing dot: the fully qualified form of the same host.
        ("https://openrouter.ai./api/v1", True),
        ("https://eu.openrouter.ai.:443/api/v1", True),
        ("https://openrouter.ai../api/v1", False),
        ("https://.openrouter.ai/api/v1", False),
        ("https://eu..openrouter.ai/api/v1", False),
        ("https://eu_1.openrouter.ai/api/v1", False),
        ("https://evil.example.com\\.openrouter.ai/v1", False),
        # A `\` in the host part: openai-node and httpx would call different hosts.
        ("https://evil.example.com\\@openrouter.ai/v1", False),
        ("https://evil.example.com\\@eu.openrouter.ai/v1", False),
        ("https://openrouter.ai\\@evil.example.com/v1", False),
        ("https://notopenrouter.ai/api/v1", False),
        ("https://eu.openrouter.ai.example.com/api/v1", False),
        ("https://api.openai.com/v1", False),
        ("https://openrouter.ai.example.com/api/v1", False),
        ("https://openrouter.ai@gateway.example.com/api/v1", False),
        ("https://gateway.example.com/openrouter.ai", False),
        ("https://gateway.example.com/?u=openrouter.ai", False),
        ("openrouter.ai", False),
        ("HTTPS://openrouter.ai", False),
        ("", False),
        (None, False),
        (123, False),
    ],
)
def test_is_openrouter_base_url(value: Any, expected: bool) -> None:
    assert is_openrouter_base_url(value) is expected
