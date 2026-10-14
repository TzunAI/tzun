"""Cross-SDK model-id parser parity.

The descriptor is content-addressed and ``(vendor, modelName, modelVersion)``
is the identity triple, so if the two SDKs split a vendor id differently they
register different rows — and put different ``aiBom.modelDescriptorDigest``
values into the hashed field set — for the same vendor call. The connector
parity gate only covers the ids that happen to be in the recorded fixtures;
this one drives every bundled known-models wire id, plus the edge shapes where
JS and Python regex semantics differ (``$`` vs ``\\Z``, ``\\d`` vs ``[0-9]``,
what ``.`` excludes), through both parsers in one harness call each.
"""

from __future__ import annotations

import json
import pathlib

from tzun_sdk.ai_bom.connectors._base import lookup_known_model, parse_model_id
from tzun_sdk.ai_bom.known_models import load_known_models

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
WIRE_IDS = REPO_ROOT / "tests" / "fixtures" / "known-model-wire-ids.json"

# Shapes that are NOT in the wire-id table, chosen so a parser that is subtly
# wrong on one side shows up here rather than in production. Every one must
# parse identically; several must deliberately NOT split.
EDGE_SHAPES: list[dict[str, object]] = [
    # Anthropic: undashed snapshot (real), alias (real), dashed (synthetic).
    {"vendor": "anthropic", "modelId": "claude-sonnet-4-20250514"},
    {"vendor": "anthropic", "modelId": "claude-opus-4-1-20250805"},
    {"vendor": "anthropic", "modelId": "claude-3-5-sonnet-20240620"},
    {"vendor": "anthropic", "modelId": "claude-haiku-4-5"},
    {"vendor": "anthropic", "modelId": "claude-3-5-sonnet-2024-10-22"},
    {"vendor": "anthropic", "modelId": "claude-opus-4-7-2026-01-15"},
    # Empty head: JS `(.*)` matches the empty string and so must Python.
    {"vendor": "anthropic", "modelId": "-20241022"},
    {"vendor": "openai", "modelId": "-2024-08-06"},
    # Anchoring: JS `$` (no `m` flag) does not match before a trailing newline.
    {"vendor": "anthropic", "modelId": "claude-3-5-sonnet-20241022\n"},
    {"vendor": "openai", "modelId": "gpt-4o-2024-08-06\n"},
    {"vendor": "vertex", "modelId": "gemini-1.5-pro-001\n"},
    {"vendor": "bedrock", "modelId": "meta.llama3-1-70b-instruct-v1:0\n"},
    # JS `.` excludes \\r; Python's does not.
    {"vendor": "anthropic", "modelId": "claude\r-3-5-sonnet-20241022"},
    # JS `\\d` is ASCII-only; Python's is Unicode-aware.
    {"vendor": "anthropic", "modelId": "claude-x-" + "\uff12\uff10\uff12\uff14\uff11\uff10\uff12\uff12"},
    {"vendor": "vertex", "modelId": "gemini-" + "\uff10\uff10\uff11"},
    # OpenAI: dashed only.
    {"vendor": "openai", "modelId": "gpt-4o"},
    {"vendor": "openai", "modelId": "gpt-4o-20240806"},
    {"vendor": "openai", "modelId": "x-2024-01-01-2024-02-02"},
    # Bedrock: variants, cross-region prefix, no-variant ids.
    {"vendor": "bedrock", "modelId": "anthropic.claude-3-5-sonnet-20240620-v1:0"},
    {"vendor": "bedrock", "modelId": "meta.llama3-70b-instruct-v1:0"},
    {"vendor": "bedrock", "modelId": "us.anthropic.claude-3-5-sonnet-20241022-v2:0"},
    {"vendor": "bedrock", "modelId": "cohere.command-text-v14"},
    {"vendor": "bedrock", "modelId": "amazon.titan-text-express-v1"},
    {"vendor": "bedrock", "modelId": "x-1234-5678-v1:0"},
    # Context-length variant after the `:M`: neither side may split it.
    {"vendor": "bedrock", "modelId": "anthropic.claude-3-sonnet-20240229-v1:0:28k"},
    # Vertex / azure-ai / nim / hf.
    {"vendor": "vertex", "modelId": "gemini-1.5-pro"},
    {"vendor": "vertex", "modelId": "gemini-1.0-pro"},
    {"vendor": "azure-ai", "modelId": "Phi-3-mini-4k-instruct"},
    {"vendor": "nvidia-nim", "modelId": "meta/llama-3.1-70b-instruct"},
    {"vendor": "hf-inference", "modelId": "meta-llama/Llama-3.1-70B-Instruct"},
    # apiMetadata fallback: used only when the id encodes no version.
    {"vendor": "anthropic", "modelId": "claude-opus-4-7", "apiMetadata": {"modelVersion": "hint"}},
    {
        "vendor": "anthropic",
        "modelId": "claude-3-5-sonnet-20241022",
        "apiMetadata": {"modelVersion": "hint"},
    },
    {"vendor": "hf-inference", "modelId": "org/repo", "apiMetadata": {"modelVersion": "rev"}},
    {"vendor": "vertex", "modelId": "gemini-1.5-pro", "apiMetadata": {"modelVersion": "hint"}},
    # A non-string hint is ignored on both sides.
    {"vendor": "vertex", "modelId": "gemini-1.5-pro", "apiMetadata": {"modelVersion": 7}},
]


def _rows() -> list[dict[str, str]]:
    assert WIRE_IDS.is_file(), f"wire-id fixture missing at {WIRE_IDS}"
    rows = json.loads(WIRE_IDS.read_text(encoding="utf-8"))["rows"]
    assert rows, "wire-id fixture is empty"
    return rows


def _py_parse(item: dict[str, object]) -> tuple[str, str]:
    api_metadata = item.get("apiMetadata")
    return parse_model_id(
        str(item["vendor"]),
        str(item["modelId"]),
        api_metadata if isinstance(api_metadata, dict) else None,
    )


def _compare(items: list[dict[str, object]], ts_invoke) -> None:  # type: ignore[no-untyped-def]
    ts = ts_invoke({"action": "parse-model-ids", "items": items})
    results = ts["results"]
    assert len(results) == len(items), "harness returned a different number of results"
    diffs: list[str] = []
    for item, ts_res in zip(items, results, strict=True):
        assert ts_res["modelId"] == item["modelId"]
        py_name, py_version = _py_parse(item)
        ts_pair = (ts_res["modelName"], ts_res["modelVersion"])
        if (py_name, py_version) != ts_pair:
            diffs.append(
                f"{item['vendor']} {item['modelId']!r}: "
                f"python=({py_name!r}, {py_version!r}) ts=({ts_pair[0]!r}, {ts_pair[1]!r})"
            )
    assert diffs == []


def test_wire_id_fixture_is_present_and_covers_the_seed() -> None:
    """Guard: a missing or shrunken fixture must fail, not empty the gate."""
    known = load_known_models()
    assert len(_rows()) == len(known["entries"])


def test_every_bundled_wire_id_parses_identically_in_both_sdks(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    items: list[dict[str, object]] = [
        {"vendor": r["vendor"], "modelId": r["wireId"]} for r in _rows()
    ]
    _compare(items, ts_invoke)


def test_every_bundled_wire_id_resolves_to_the_same_catalog_entry(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    """Parity on the parse is necessary; parity on the lookup is the point.

    Both sides load the same bundled catalog (python/src/tzun_sdk/_data is a
    byte copy of data/known-models.json, drift-checked in CI), so if the parsed
    keys agree the lookups agree. This asserts the Python lookup actually hits
    for every row: an entry keyed on a shape no vendor id produces shows up as a miss.
    """
    known = load_known_models()
    ts = ts_invoke({
        "action": "parse-model-ids",
        "items": [{"vendor": r["vendor"], "modelId": r["wireId"]} for r in _rows()],
    })
    misses: list[str] = []
    for r, ts_res in zip(_rows(), ts["results"], strict=True):
        name, version = parse_model_id(r["vendor"], r["wireId"])
        assert (name, version) == (ts_res["modelName"], ts_res["modelVersion"])
        if lookup_known_model(known, r["vendor"], name, version) is None:
            misses.append(f"MISS {r['vendor']} {r['wireId']} -> ({name}, {version})")
    assert misses == []


def test_edge_shapes_parse_identically_in_both_sdks(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    _compare(EDGE_SHAPES, ts_invoke)
