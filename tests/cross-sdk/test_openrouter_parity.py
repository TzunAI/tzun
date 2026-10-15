"""Cross-SDK parity of the OpenRouter connector.

``ts-harness/openrouter.ts`` runs the TypeScript SDK; this file runs
``tzun_sdk.ai_bom.connectors`` on the same inputs and compares:

- the string helpers, which both SDKs implement with string operations only so
  they agree byte for byte: the author prefix (``trainedBy``), the variant base
  (the enrichment fallback), the id parse, the recorded endpoint and the
  ``openrouter.ai`` base-URL check ``attach()`` detects the gateway with. The
  tables are the TypeScript unit tests' rows plus the inputs where JavaScript
  and Python strings differ: astral characters (UTF-16 code units against code
  points), lone surrogates, non-ASCII case mapping and IPv6 hosts;
- whole connector outputs, for every shared fixture and for one call per major
  model author on OpenRouter plus the parameter and provider edges: the
  skeleton, the descriptor's canonical bytes and digest, and the canonical
  bytes and digest of the wire ``aiBom`` the skeleton becomes. The descriptor
  is content-addressed and the ``aiBom`` is inside the hashed field set, so
  equal bytes here mean the two SDKs register the same catalog row and write
  the same record digest for the same call.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

from tzun_sdk._generated.canonical import (
    canonical_serialize,
    canonical_serialize_descriptor,
)
from tzun_sdk.ai_bom.connectors._base import (
    AiBomSkeleton,
    openrouter_author,
    openrouter_variant_base,
    parse_model_id,
)
from tzun_sdk.ai_bom.connectors.openrouter import (
    is_openrouter_base_url,
    openrouter_connector,
    openrouter_endpoint,
)
from tzun_sdk.ai_bom.known_models import load_known_models

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "openrouter.ts"
FIXTURES = REPO_ROOT / "python" / "tests" / "ai_bom" / "connectors" / "fixtures" / "openrouter"
FIXTURE_CASES = [
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
ASTRAL = "\U0001f600"

Harness = Callable[[dict[str, Any]], dict[str, Any]]


@pytest.fixture(scope="module")
def ts_openrouter() -> Harness:
    if shutil.which("node") is None:
        pytest.skip("Node not available — cross-SDK suite requires Node 22+")

    def run(cmd: dict[str, Any]) -> dict[str, Any]:
        proc = subprocess.run(
            ["npx", "tsx", str(HARNESS)],
            check=False,
            input=json.dumps(cmd, allow_nan=False),
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=180,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"openrouter harness failed (exit {proc.returncode})\n{proc.stderr}")
        result: dict[str, Any] = json.loads(proc.stdout)
        return result

    return run


# ── The string helpers ─────────────────────────────────────────────────

IDS: list[str] = [
    # openRouterAuthor rows.
    "openai/gpt-6.1-sol",
    "meta-llama/llama-4-maverick",
    "x-ai/grok-4.7",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "google/gemini-4-argon:batch",
    "~anthropic/claude-opus-latest",
    "~~anthropic/claude-opus-latest",
    "openrouter/auto",
    "openrouter/free",
    "~openrouter/auto",
    "OpenRouter/auto",
    "no-prefix",
    "/leading-slash",
    "~/x",
    "~",
    "",
    "a/b/c",
    "author:x/model",
    # openRouterVariantBase rows.
    "a/b:c:d",
    "a:b/c",
    "a/b:",
    "a/:free",
    "no-slash:free",
    "~anthropic/claude-opus-latest:free",
    # parseModelId rows.
    "openai/gpt-4o-2024-08-06",
    "deepseek/deepseek-v4-pro-0813",
    "openai/gpt-oss-120b\n",
    # Where JavaScript and Python strings differ.
    f"{ASTRAL}/model:free",
    f"author/{ASTRAL}:{ASTRAL}",
    f"author/model:{ASTRAL}",
    f"~{ASTRAL}{ASTRAL}/m",
    "\ud800/m:free",
    "author/m:\ud800",
    "\u0130penrouter/auto",
    "OPENROUTER/auto",
    "author\u2028x/model:free",
    "author/model:free\r",
]

URLS: list[Any] = [
    # openRouterEndpoint rows.
    "https://openrouter.ai/api/v1",
    "https://openrouter.ai/api/v1/",
    "https://openrouter.ai/api/v1///",
    "https://openrouter.ai",
    "https://openrouter.ai/",
    "http://localhost:8080/v1",
    "https://OpenRouter.AI:443/api/v1",
    "https://openrouter.ai?x=1",
    "https://openrouter.ai/api/v1#frag",
    "https://openrouter.ai/api/v1/?a=b/c#d",
    "https://user:@openrouter.ai/api/v1",
    "https://a@b:c:@openrouter.ai/api/v1",
    "HTTPS://openrouter.ai/api/v1",
    "ftp://openrouter.ai/api/v1",
    "openrouter.ai/api/v1",
    "https://",
    "https:///api/v1",
    "https://user@/api/v1",
    "https://?q",
    "",
    None,
    42,
    {"href": "https://openrouter.ai/api/v1"},
    # isOpenRouterBaseUrl rows.
    "http://openrouter.ai/api/v1",
    "https://OpenRouter.AI/api/v1",
    "https://openrouter.ai:443/api/v1",
    "https://key:@openrouter.ai/api/v1",
    "https://api.openai.com/v1",
    "https://api.openrouter.ai/v1",
    "https://openrouter.ai.example.com/api/v1",
    "https://openrouter.ai@gateway.example.com/api/v1",
    "https://gateway.example.com/openrouter.ai",
    "https://gateway.example.com/?u=openrouter.ai",
    "openrouter.ai",
    "HTTPS://openrouter.ai",
    123,
    True,
    [],
    # The endpoint hint of the endpoint_normalized fixture.
    "https://alice:pw@Gateway.Example.COM:443/api/v1/?trace=1#frag",
    # Host case and default ports: lowercased ASCII letters, :443 (https) and
    # :80 (http) dropped, every other port and the path kept.
    "https://OpenRouter.AI:443/api/v1/",
    "https://openrouter.ai:443",
    "http://openrouter.ai:80/x",
    "http://openrouter.ai:443/x",
    "https://openrouter.ai:80/x",
    "https://openrouter.ai:8443/api/v1",
    "https://openrouter.ai:1443/api/v1",
    "https://[::1]:443/api/v1",
    "https://[::ABCD]:443/v1",
    "https://Gateway.Example.COM/API/V1",
    "https://Key:@OpenRouter.AI/api/v1",
    "https://:443/api/v1",
    "http://:80",
    "https://\u0130penrouter.ai/v1",
    "https://OPENROUTER.\u0130I:443/v1",
    "https://\uff2fpenrouter.ai:443/v1",
    "https://openrouter.ai:443:443/v1",
    # Length in UTF-16 code units: 256 allowed, 257 refused, astral counts twice.
    "https://openrouter.ai/" + "a" * 234,
    "https://openrouter.ai/" + "a" * 235,
    "https://openrouter.ai/" + "a" * 234 + "///",
    "https://openrouter.ai/" + ASTRAL * 117,
    "https://openrouter.ai/" + ASTRAL * 117 + "a",
    "https://openrouter.ai/" + ASTRAL * 118,
    "https://openrouter.ai/" + "a" * 233 + "\ud800",
    # Hosts where case mapping, ports or brackets could split the two SDKs.
    "https://OPENROUTER.AI/api/v1",
    "https://\u0130openrouter.ai/api/v1",
    "https://openrouter.a\u0130/api/v1",
    "https://\uff2f\uff30\uff25\uff2e\uff32\uff2f\uff35\uff34\uff25\uff32.ai/api/v1",
    "https://openrouter.ai\u3002/api/v1",
    "https://openrouter.ai:/api/v1",
    "https://openrouter.ai:99999/api/v1",
    "https://[::1]:8080/v1",
    "https://[::1]/v1",
    "https://openrouter.ai%2F/api/v1",
    "https://openrouter.ai#@evil.example.com/v1",
    "https://evil.example.com#@openrouter.ai/v1",
    "https://openrouter.ai?@evil.example.com",
    "https://evil.example.com?@openrouter.ai",
    "https://user:@openrouter.ai:@gateway.example.com/v1",
    "https://evil.example.com\\@openrouter.ai/v1",
    "https:/openrouter.ai/api/v1",
    " https://openrouter.ai/api/v1",
    "https://openrouter.ai /api/v1",
]


@pytest.fixture(scope="module")
def ts_helpers(ts_openrouter: Harness) -> dict[str, Any]:
    return ts_openrouter({"action": "helpers", "ids": IDS, "urls": URLS})


def test_helper_tables_are_answered_in_full(ts_helpers: dict[str, Any]) -> None:
    assert [r["id"] for r in ts_helpers["ids"]] == IDS
    assert [r["url"] for r in ts_helpers["urls"]] == URLS


def test_author_variant_base_and_parse_agree_on_every_id(ts_helpers: dict[str, Any]) -> None:
    diffs: list[str] = []
    for model_id, ts in zip(IDS, ts_helpers["ids"], strict=True):
        name, version = parse_model_id("openrouter", model_id)
        py = {
            "author": openrouter_author(model_id),
            "variantBase": openrouter_variant_base(model_id),
            "parsed": {"modelName": name, "modelVersion": version},
        }
        ts_answer = {k: ts[k] for k in ("author", "variantBase", "parsed")}
        if py != ts_answer:
            diffs.append(f"{model_id!r}: python={py} ts={ts_answer}")
    assert diffs == []


def test_endpoint_and_base_url_check_agree_on_every_url(ts_helpers: dict[str, Any]) -> None:
    diffs: list[str] = []
    for url, ts in zip(URLS, ts_helpers["urls"], strict=True):
        py = {"endpoint": openrouter_endpoint(url), "isOpenRouter": is_openrouter_base_url(url)}
        ts_answer = {"endpoint": ts["endpoint"], "isOpenRouter": ts["isOpenRouter"]}
        if py != ts_answer:
            diffs.append(f"{url!r}: python={py} ts={ts_answer}")
    assert diffs == []


def test_the_tables_reach_both_answers_of_every_helper() -> None:
    """Guard: a table that never produced a None (or never a value) would prove little."""
    assert {openrouter_author(i) is None for i in IDS} == {True, False}
    assert {openrouter_variant_base(i) is None for i in IDS} == {True, False}
    assert {openrouter_endpoint(u) is None for u in URLS} == {True, False}
    assert {is_openrouter_base_url(u) for u in URLS} == {True, False}


# ── Whole connector outputs ────────────────────────────────────────────


def _response(model: Any, **extra: Any) -> dict[str, Any]:
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


def _fixture_cases() -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    out = []
    for case in FIXTURE_CASES:
        fx = json.loads((FIXTURES / f"{case}.json").read_text(encoding="utf-8"))
        out.append((f"fixture/{case}", fx["request"], fx["response"]))
    return out


# One served id per major author on OpenRouter (the TS connector test's
# table), and the ids without an entry or without an author.
SERVED: list[tuple[str, str]] = [
    ("openai/gpt-6.1-sol", "OpenAI"),
    ("openai/gpt-oss-120b", "Nvidia"),
    ("anthropic/claude-sonnet-5.5", "Anthropic"),
    ("google/gemini-4-argon", "Google Vertex"),
    ("google/gemma-4-31b-it:free", "Google AI Studio"),
    ("meta-llama/llama-4-maverick", "Groq"),
    ("meta-llama/llama-3.3-70b-instruct", "Groq"),
    ("meta/muse-spark-1.3", "Meta"),
    ("meta/muse-glimmer-30b", "Meta"),
    ("meta/muse-spark-1.3-contributor", "Meta"),
    ("mistralai/mistral-large-4-0", "Mistral"),
    ("mistralai/mistral-medium-3-5:batch", "Mistral"),
    ("x-ai/grok-4.7", "xAI"),
    ("deepseek/deepseek-v4-pro-0813", "DeepSeek"),
    ("deepseek/deepseek-v4.1-flash:batch", "DeepSeek"),
    ("qwen/qwen3.8-2.4t-a95b", "Alibaba"),
    ("nvidia/nemotron-3-ultra-550b-a55b:free", "Nvidia"),
    ("microsoft/phi-4", "DeepInfra"),
    ("amazon/nova-premier-v1", "Amazon Bedrock"),
    ("cohere/command-a", "Cohere"),
    ("cohere/command-a-plus", "Cohere"),
    ("moonshotai/kimi-k3", "Moonshot AI"),
    ("z-ai/glm-5.3-flash", "Z.AI"),
    ("minimax/minimax-m3", "Minimax"),
    ("anthropic/claude-opus-5.5:batch", "Anthropic"),
    ("tencent/hunyuan-a13b-instruct", "Some Host"),
    ("acme/unknown:free", "Some Host"),
    ("no-prefix", "Some Host"),
    ("/leading-slash", "Some Host"),
    ("~", "Some Host"),
]

EDGE_PARAMS: list[dict[str, Any]] = [
    {"max_tokens": 9007199254740992},
    {"max_tokens": 9007199254740991},
    {"max_tokens": -1},
    {"max_tokens": "100"},
    {"max_tokens": 64.0},
    {"max_tokens": True},
    {"max_tokens": 1e300},
    {"seed": -7},
    {"seed": -9007199254740991},
    {"seed": -9007199254740992},
    {"seed": True},
    {"seed": 1.5},
    {"temperature": "0.5"},
    {"temperature": 1e-7, "top_p": 0.1},
    {"temperature": 1.0, "top_p": 1},
    {"stop": []},
    {"stop": ["A", 1, None, "B"]},
    {"stop": 5},
    {"stop": ""},
    {"stop": ["S"] * 16},
    {"stop": ["S"] * 17},
    {"stop": ["S"] * 16 + [7]},
    {"stop": "x" * 256},
    {"stop": "x" * 257},
    {"stop": ["END", "x" * 257]},
    {"stop": [ASTRAL * 128]},
    {"stop": [ASTRAL * 129]},
    {"provider": {"order": ["Nvidia"]}, "azure_endpoint": "https://example.openai.azure.com"},
    {"model": "openrouter/auto", "models": ["anthropic/claude-opus-5.5", "openai/gpt-6-astra"]},
    {"openrouter_endpoint": "https://openrouter.ai/api/v1/"},
    {"openrouter_endpoint": "ftp://openrouter.ai"},
    {"openrouter_endpoint": 7},
]

PROVIDERS: list[Any] = ["Azure", "", 42, {"name": "Azure"}, None, True, "P" * 256, "P" * 257, ASTRAL * 128, ASTRAL * 129]


def _synthetic_cases() -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for served, provider in SERVED:
        out.append(
            (
                f"served/{served}",
                {"model": served, "openrouter_endpoint": "https://openrouter.ai/api/v1"},
                _response(served, provider=provider),
            )
        )
    for i, params in enumerate(EDGE_PARAMS):
        out.append((f"params/{i}", {"model": "openai/gpt-5.4-mini", **params}, _response("openai/gpt-5.4-mini")))
    for i, provider in enumerate(PROVIDERS):
        out.append((f"provider/{i}", {}, _response("openai/gpt-6-astra", provider=provider)))
    out.append(("fingerprint/string", {}, _response("openai/gpt-6-astra", system_fingerprint="fp_x")))
    out.append(("fingerprint/number", {}, _response("openai/gpt-6-astra", system_fingerprint=7)))
    for model in ["", 42, None]:
        out.append((f"no-model/{model!r}", {"model": "openai/gpt-5.4-mini"}, _response(model)))
    missing = _response("x")
    del missing["model"]
    out.append(("no-model/missing", {"model": "openai/gpt-5.4-mini"}, missing))
    return out


def _py_result(request: dict[str, Any], response: dict[str, Any], known: dict[str, Any]) -> dict[str, Any]:
    """The Python twin of the harness's per-case answer."""
    skeleton: AiBomSkeleton | None = openrouter_connector.build_ai_bom(request, response, known)
    if skeleton is None:
        return {"skeleton": None}

    def dump(model: Any) -> Any:
        return None if model is None else model.model_dump(mode="json", exclude_none=False)

    as_json = {
        "modelDescriptor": dump(skeleton.model_descriptor),
        "vendorFingerprint": skeleton.vendor_fingerprint,
        "promptTemplate": dump(skeleton.prompt_template),
        "inferenceParameters": dump(skeleton.inference_parameters),
        "infrastructure": dump(skeleton.infrastructure),
    }
    descriptor_canonical = canonical_serialize_descriptor(as_json["modelDescriptor"])
    descriptor_digest = "sha256:" + hashlib.sha256(descriptor_canonical.encode("utf-8")).hexdigest()
    ai_bom = {**as_json, "modelDescriptorDigest": descriptor_digest}
    del ai_bom["modelDescriptor"]
    ai_bom_canonical = canonical_serialize(ai_bom)
    return {
        "skeleton": as_json,
        "descriptorCanonical": descriptor_canonical,
        "descriptorDigest": descriptor_digest,
        "aiBomCanonical": ai_bom_canonical,
        "aiBomDigest": hashlib.sha256(ai_bom_canonical.encode("utf-8")).hexdigest(),
    }


def _compare(
    ts_openrouter: Harness,
    cases: list[tuple[str, dict[str, Any], dict[str, Any]]],
    known: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    cmd: dict[str, Any] = {
        "action": "aibom",
        "cases": [{"request": req, "response": resp} for _, req, resp in cases],
    }
    if known is not None:
        cmd["knownModels"] = known
    ts_results = ts_openrouter(cmd)["results"]
    assert len(ts_results) == len(cases), "harness returned a different number of results"
    catalog = known if known is not None else load_known_models()
    diffs: list[str] = []
    py_results = []
    for (label, req, resp), ts in zip(cases, ts_results, strict=True):
        py = _py_result(req, resp, catalog)
        py_results.append(py)
        if py != ts:
            diffs.append(f"{label}:\n  python={py}\n  ts=    {ts}")
    assert diffs == [], "\n".join(diffs)
    return py_results


def test_every_fixture_gives_the_same_descriptor_and_ai_bom_bytes(ts_openrouter: Harness) -> None:
    results = _compare(ts_openrouter, _fixture_cases())
    assert all(r["skeleton"] is not None for r in results)


def test_every_major_author_and_edge_gives_the_same_bytes(ts_openrouter: Harness) -> None:
    cases = _synthetic_cases()
    results = _compare(ts_openrouter, cases)
    # Guard: both SDKs built an AI-BOM for every case with a served model, and
    # none for the four without one.
    produced = {label: r["skeleton"] is not None for (label, _, _), r in zip(cases, results, strict=True)}
    assert [label for label, ok in produced.items() if not ok] == [
        "no-model/''",
        "no-model/42",
        "no-model/None",
        "no-model/missing",
    ]


def test_a_catalog_override_enriches_alike(ts_openrouter: Harness) -> None:
    """The variant fallback, an exact variant entry, and an entry's own ``trainedBy``."""
    known = {
        "version": "test",
        "entries": [
            {"vendor": "openrouter", "modelName": "acme/m", "modelVersion": "unknown", "license": "base-license", "modelType": "llm"},
            {"vendor": "openrouter", "modelName": "acme/m:free", "modelVersion": "unknown", "license": "free-license"},
            {"vendor": "openrouter", "modelName": "acme/n", "modelVersion": "unknown", "trainedBy": "Acme"},
            {"vendor": "nvidia-nim", "modelName": "acme/o", "modelVersion": "unknown", "license": "x"},
        ],
    }
    cases = [
        (f"override/{served}", {}, _response(served, provider="Some Host"))
        for served in ["acme/m", "acme/m:free", "acme/m:batch", "acme/n:free", "acme/o:free", "acme/o"]
    ]
    results = _compare(ts_openrouter, cases, known)
    licenses = [r["skeleton"]["modelDescriptor"]["license"] for r in results]
    makers = [r["skeleton"]["modelDescriptor"]["trainedBy"] for r in results]
    assert licenses == ["base-license", "free-license", "base-license", None, None, None]
    assert makers == ["acme", "acme", "acme", "Acme", "acme", "acme"]
