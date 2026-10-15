"""The ``openrouter`` vendor in id parsing and enrichment.

The Python twin of ``tests/ts/importer-openrouter.test.ts``: id parsing, the
maker taken from the author prefix, and the variant fallback that lets a
``:free`` or ``:batch`` id enrich from its base model's entry. The helper
tables are the TypeScript ones, row for row; ``tests/cross-sdk`` also runs
them through both SDKs.
"""

from __future__ import annotations

from typing import Any

import pytest

from tzun_sdk.ai_bom.connectors._base import (
    enrich_from_known_models,
    openrouter_author,
    openrouter_variant_base,
    parse_model_id,
)
from tzun_sdk.ai_bom.known_models import load_known_models
from tzun_sdk.models import ModelDescriptor


def mvd(model_id: str, vendor: str = "openrouter") -> ModelDescriptor:
    """The descriptor a connector builds before enrichment."""
    name, version = parse_model_id(vendor, model_id)
    return ModelDescriptor(
        descriptorVersion="d1",
        vendor=vendor,
        modelName=name,
        modelVersion=version,
        integrityTier="vendor-asserted",
        trainedBy=openrouter_author(name) if vendor == "openrouter" else None,
    )


@pytest.mark.parametrize(
    ("model_id", "expected"),
    [
        ("openai/gpt-6.1-sol", "openai"),
        ("meta-llama/llama-4-maverick", "meta-llama"),
        ("x-ai/grok-4.7", "x-ai"),
        ("nvidia/nemotron-3-super-120b-a12b:free", "nvidia"),
        ("google/gemini-4-argon:batch", "google"),
        # One alias tilde is dropped: the alias lives in the maker's namespace.
        ("~anthropic/claude-opus-latest", "anthropic"),
        ("~~anthropic/claude-opus-latest", "~anthropic"),
        # Routers are not makers.
        ("openrouter/auto", None),
        ("openrouter/free", None),
        ("~openrouter/auto", None),
        # Case is kept: the comparison with `openrouter` is exact.
        ("OpenRouter/auto", "OpenRouter"),
        ("no-prefix", None),
        ("/leading-slash", None),
        ("~/x", None),
        ("~", None),
        ("", None),
        ("a/b/c", "a"),
        ("author:x/model", "author:x"),
    ],
)
def test_openrouter_author(model_id: str, expected: str | None) -> None:
    assert openrouter_author(model_id) == expected


@pytest.mark.parametrize(
    ("model_id", "expected"),
    [
        ("nvidia/nemotron-3-super-120b-a12b:free", "nvidia/nemotron-3-super-120b-a12b"),
        ("google/gemini-4-argon:batch", "google/gemini-4-argon"),
        ("openai/gpt-6.1-sol", None),
        # The last colon separates the variant.
        ("a/b:c:d", "a/b:c"),
        # A colon before the slash is not a variant.
        ("a:b/c", None),
        ("a/b:", None),
        ("a/:free", "a/"),
        ("no-slash:free", None),
        ("~anthropic/claude-opus-latest:free", "~anthropic/claude-opus-latest"),
        ("", None),
    ],
)
def test_openrouter_variant_base(model_id: str, expected: str | None) -> None:
    assert openrouter_variant_base(model_id) == expected


@pytest.mark.parametrize(
    "model_id",
    [
        "nvidia/nemotron-3-super-120b-a12b:free",
        # A dated id is kept whole: no date is split out for this vendor.
        "openai/gpt-4o-2024-08-06",
        "deepseek/deepseek-v4-pro-0813",
        "~anthropic/claude-opus-latest",
        "openrouter/auto",
        "no-prefix",
        "openai/gpt-oss-120b\n",
    ],
)
def test_parse_model_id_keeps_the_whole_id_with_version_unknown(model_id: str) -> None:
    assert parse_model_id("openrouter", model_id) == (model_id, "unknown")


def test_parse_model_id_takes_a_string_version_hint_nothing_else() -> None:
    assert parse_model_id("openrouter", "x/y", {"modelVersion": "v9"}) == ("x/y", "v9")
    assert parse_model_id("openrouter", "x/y", {"modelVersion": 9}) == ("x/y", "unknown")


# ── Enrichment ─────────────────────────────────────────────────────────


def test_enriches_a_base_id_and_names_the_maker_by_its_author_prefix() -> None:
    d = enrich_from_known_models(mvd("meta-llama/llama-3.3-70b-instruct"), load_known_models())
    assert d.vendor == "openrouter"
    assert d.modelName == "meta-llama/llama-3.3-70b-instruct"
    assert d.modelVersion == "unknown"
    assert d.trainedBy == "meta-llama"
    assert d.license == "llama3.3"
    assert d.modelType == "llm"
    assert d.modelCardUrl == "https://openrouter.ai/meta-llama/llama-3.3-70b-instruct"
    assert d.integrityTier == "vendor-asserted"
    assert d.modelDigest is None


@pytest.mark.parametrize(
    ("model_id", "base", "license_"),
    [
        ("nvidia/nemotron-3-super-120b-a12b:free", "nvidia/nemotron-3-super-120b-a12b", "nvidia-nemotron-open-model-license"),
        ("google/gemma-4-31b-it:free", "google/gemma-4-31b-it", "apache-2.0"),
        ("anthropic/claude-opus-5.5:batch", "anthropic/claude-opus-5.5", "anthropic-commercial"),
        ("deepseek/deepseek-v4.1-flash:batch", "deepseek/deepseek-v4.1-flash", "mit"),
    ],
)
def test_a_variant_enriches_from_its_base_and_keeps_the_variant(model_id: str, base: str, license_: str) -> None:
    d = enrich_from_known_models(mvd(model_id), load_known_models())
    assert d.modelName == model_id
    assert d.modelVersion == "unknown"
    assert d.license == license_
    assert d.modelCardUrl == f"https://openrouter.ai/{base}"


def test_the_variant_and_its_base_are_distinct_descriptors() -> None:
    known = load_known_models()
    base = enrich_from_known_models(mvd("google/gemma-4-31b-it"), known)
    free = enrich_from_known_models(mvd("google/gemma-4-31b-it:free"), known)
    assert free.model_dump(mode="json") == {
        **base.model_dump(mode="json"),
        "modelName": "google/gemma-4-31b-it:free",
    }


def test_an_exact_free_entry_wins_over_the_base_entry() -> None:
    ref: dict[str, Any] = {
        "version": "test",
        "entries": [
            {"vendor": "openrouter", "modelName": "acme/m", "modelVersion": "unknown", "license": "base-license"},
            {"vendor": "openrouter", "modelName": "acme/m:free", "modelVersion": "unknown", "license": "free-license"},
        ],
    }
    assert enrich_from_known_models(mvd("acme/m:free"), ref).license == "free-license"


def test_a_variant_of_an_unknown_base_is_not_enriched() -> None:
    d = enrich_from_known_models(mvd("acme/unknown:free"), load_known_models())
    assert d.modelName == "acme/unknown:free"
    assert d.trainedBy == "acme"
    assert d.license is None


def test_an_alias_is_not_enriched_from_its_current_target() -> None:
    d = enrich_from_known_models(mvd("~anthropic/claude-opus-latest"), load_known_models())
    assert d.trainedBy == "anthropic"
    assert d.license is None


def test_the_variant_fallback_applies_to_openrouter_only() -> None:
    ref: dict[str, Any] = {
        "version": "test",
        "entries": [{"vendor": "nvidia-nim", "modelName": "meta/m", "modelVersion": "unknown", "license": "x"}],
    }
    d = enrich_from_known_models(mvd("meta/m:free", vendor="nvidia-nim"), ref)
    assert d.license is None
    assert d.trainedBy is None


def test_the_bundled_openrouter_entries_carry_no_trained_by() -> None:
    """So the author prefix stands, and both SDKs serialize the same bytes."""
    entries = [e for e in load_known_models()["entries"] if e.get("vendor") == "openrouter"]
    assert len(entries) == 39
    for e in entries:
        for absent in ("trainedBy", "integrityTier", "modelDigest", "parentModelDescriptorDigest", "derivation"):
            assert absent not in e, (e["modelName"], absent)
        assert e["modelVersion"] == "unknown"
        assert e["modelType"] == "llm"
        assert isinstance(e["license"], str)
        assert e["modelCardUrl"] == f"https://openrouter.ai/{e['modelName']}"
        # Base ids only: no variant and no alias.
        assert openrouter_variant_base(e["modelName"]) is None
        assert not e["modelName"].startswith("~")
        # Every external identifier spells out all five keys, so the TS and
        # Python descriptors serialize to the same bytes.
        for ident in e.get("externalIdentifiers", []):
            assert sorted(ident) == ["issuedAt", "issuedBy", "scheme", "url", "value"]
            assert ident["scheme"] == "hf-repo"
            assert ident["url"] == f"https://huggingface.co/{ident['value']}"
        # `<maker>-commercial` means the weights are not published, so such an
        # entry names no repository, and every other entry names exactly one.
        commercial = e["license"].endswith("-commercial")
        assert len(e.get("externalIdentifiers", [])) == (0 if commercial else 1), e["modelName"]


def test_an_entry_trained_by_still_overlays_the_author_prefix() -> None:
    """As in TS: the prefix is set before enrichment, so an entry may name the maker."""
    ref: dict[str, Any] = {
        "version": "test",
        "entries": [{"vendor": "openrouter", "modelName": "acme/m", "modelVersion": "unknown", "trainedBy": "Acme"}],
    }
    assert enrich_from_known_models(mvd("acme/m:free"), ref).trainedBy == "Acme"
