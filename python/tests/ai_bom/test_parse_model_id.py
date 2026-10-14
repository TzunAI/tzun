"""Vendor model-id parsing and known-models reachability.

``parse_model_id`` is the Python twin of TS ``parseModelId``; the bundled
catalog is keyed on what it yields for a vendor's real wire id. Every real
wire id must hit a bundled entry and every bundled entry must be reachable
from a real ``response.model``: an entry keyed on a version segment that never
appears on the wire is never applied, so the evidence would record an
unenriched descriptor for that model.

The wire-id table lives in ``tests/fixtures/known-model-wire-ids.json`` at the
repo root and is shared with the TS suite and the cross-SDK parity gate, so all
three see the same ids.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from tzun_sdk.ai_bom.connectors._base import lookup_known_model, parse_model_id
from tzun_sdk.ai_bom.known_models import load_known_models

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
WIRE_IDS = REPO_ROOT / "tests" / "fixtures" / "known-model-wire-ids.json"


def _rows() -> list[dict[str, str]]:
    assert WIRE_IDS.is_file(), f"wire-id fixture missing at {WIRE_IDS}"
    rows = json.loads(WIRE_IDS.read_text(encoding="utf-8"))["rows"]
    assert rows, "wire-id fixture is empty"
    return rows


def _key(entry: dict[str, object]) -> str:
    return f"{entry.get('vendor')}/{entry.get('modelName')}@{entry.get('modelVersion')}"


def test_wire_id_table_and_bundled_seed_are_the_same_size() -> None:
    known = load_known_models()
    assert len(_rows()) == len(known["entries"])


def test_every_real_wire_id_hits_a_bundled_entry() -> None:
    known = load_known_models()
    misses: list[str] = []
    for row in _rows():
        vendor, wire_id = row["vendor"], row["wireId"]
        name, version = parse_model_id(vendor, wire_id)
        if lookup_known_model(known, vendor, name, version) is None:
            misses.append(f"MISS {vendor:<12} wireId={wire_id} parsed=({name}, {version})")
    assert misses == []


def test_every_bundled_entry_is_reachable_from_a_real_wire_id() -> None:
    known = load_known_models()
    reached: set[str] = set()
    for row in _rows():
        vendor, wire_id = row["vendor"], row["wireId"]
        name, version = parse_model_id(vendor, wire_id)
        hit = lookup_known_model(known, vendor, name, version)
        if hit is not None:
            reached.add(_key(hit))
    unreachable = [f"UNREACHABLE {_key(e)}" for e in known["entries"] if _key(e) not in reached]
    assert unreachable == []


@pytest.mark.parametrize(
    ("wire_id", "name", "version"),
    [
        # Real Anthropic wire ids.
        ("claude-3-5-sonnet-20241022", "claude-3-5-sonnet", "20241022"),
        ("claude-sonnet-4-20250514", "claude-sonnet-4", "20250514"),
        ("claude-opus-4-1-20250805", "claude-opus-4-1", "20250805"),
        ("claude-3-5-sonnet-20240620", "claude-3-5-sonnet", "20240620"),
        ("claude-haiku-4-5-20251001", "claude-haiku-4-5", "20251001"),
        # No snapshot suffix: whole id is the name.
        ("claude-opus-4-7", "claude-opus-4-7", "unknown"),
        ("claude-sonnet-4-6", "claude-sonnet-4-6", "unknown"),
    ],
)
def test_anthropic_snapshot_ids_split_on_the_undashed_date(
    wire_id: str, name: str, version: str
) -> None:
    assert parse_model_id("anthropic", wire_id) == (name, version)


def test_anthropic_dashed_date_is_not_split() -> None:
    """A dashed date is not an Anthropic snapshot, so it is not split.

    No Anthropic id has a dashed date; splitting one would register a phantom
    snapshot. It stays whole and unversioned.
    """
    assert parse_model_id("anthropic", "claude-3-5-sonnet-2024-10-22") == (
        "claude-3-5-sonnet-2024-10-22",
        "unknown",
    )


def test_openai_keeps_the_dashed_rule_and_not_the_undashed_one() -> None:
    assert parse_model_id("openai", "gpt-4o-2024-08-06") == ("gpt-4o", "2024-08-06")
    assert parse_model_id("openai", "gpt-4o-20240806") == ("gpt-4o-20240806", "unknown")
    assert parse_model_id("openai", "gpt-4o") == ("gpt-4o", "unknown")


@pytest.mark.parametrize(
    ("wire_id", "name", "version"),
    [
        ("anthropic.claude-3-5-sonnet-20241022-v2:0", "anthropic.claude-3-5-sonnet", "20241022-v2:0"),
        ("anthropic.claude-3-5-sonnet-20240620-v1:0", "anthropic.claude-3-5-sonnet", "20240620-v1:0"),
        ("meta.llama3-1-70b-instruct-v1:0", "meta.llama3-1-70b-instruct", "v1:0"),
        ("mistral.mistral-large-2402-v1:0", "mistral.mistral-large", "2402-v1:0"),
        ("us.anthropic.claude-3-5-sonnet-20241022-v2:0", "us.anthropic.claude-3-5-sonnet", "20241022-v2:0"),
        # No `:variant` — kept whole.
        ("cohere.command-text-v14", "cohere.command-text-v14", "unknown"),
        ("amazon.titan-text-express-v1", "amazon.titan-text-express-v1", "unknown"),
        # A context-length variant after the `:M` is not a `-vN:M` tail — kept whole.
        (
            "anthropic.claude-3-sonnet-20240229-v1:0:28k",
            "anthropic.claude-3-sonnet-20240229-v1:0:28k",
            "unknown",
        ),
    ],
)
def test_bedrock_ids_split_on_the_vN_M_suffix(wire_id: str, name: str, version: str) -> None:
    """Bedrock ids split at the ``-vN:M`` tail; an id not ending in one stays whole."""
    assert parse_model_id("bedrock", wire_id) == (name, version)


def test_vertex_azure_nim_hf_rules() -> None:
    assert parse_model_id("vertex", "gemini-1.5-pro-001") == ("gemini-1.5-pro", "001")
    assert parse_model_id("vertex", "gemini-2.0-flash-exp") == ("gemini-2.0-flash-exp", "unknown")
    assert parse_model_id("azure-ai", "phi-3-medium-4k-instruct") == (
        "phi-3-medium-4k-instruct",
        "unknown",
    )
    assert parse_model_id("nvidia-nim", "meta/llama-3.1-70b-instruct") == (
        "meta/llama-3.1-70b-instruct",
        "unknown",
    )
    assert parse_model_id("hf-inference", "org/repo") == ("org/repo", "main")


def test_api_metadata_is_a_fallback_only_when_the_id_encodes_no_version() -> None:
    hint = {"modelVersion": "hint"}
    assert parse_model_id("anthropic", "claude-opus-4-7", hint) == ("claude-opus-4-7", "hint")
    assert parse_model_id("anthropic", "claude-3-5-sonnet-20241022", hint) == (
        "claude-3-5-sonnet",
        "20241022",
    )
    assert parse_model_id("hf-inference", "org/repo", hint) == ("org/repo", "hint")
    # A non-string hint is ignored, as TS's `?? 'unknown'` ignores undefined.
    assert parse_model_id("vertex", "gemini-1.5-pro", {"modelVersion": 7}) == (
        "gemini-1.5-pro",
        "unknown",
    )


def test_anchoring_and_ascii_digits_match_the_js_regex_semantics() -> None:
    """A bare ``$`` would accept a trailing newline and ``\\d`` a fullwidth digit.

    Both would make Python split ids that TS keeps whole, and the descriptor is
    content-addressed — so the two SDKs would register different rows for the
    same bytes. ``re.fullmatch`` + ``[0-9]`` close both gaps.
    """
    assert parse_model_id("anthropic", "claude-3-5-sonnet-20241022\n") == (
        "claude-3-5-sonnet-20241022\n",
        "unknown",
    )
    fullwidth = "claude-x-" + "\uff12\uff10\uff12\uff14\uff11\uff10\uff12\uff12"  # fullwidth 20241022
    assert parse_model_id("anthropic", fullwidth) == (fullwidth, "unknown")
    assert parse_model_id("openai", "gpt-4o-2024-08-06\n") == ("gpt-4o-2024-08-06\n", "unknown")


def test_unsupported_vendor_raises() -> None:
    with pytest.raises(ValueError):
        parse_model_id("not-a-vendor", "x")
