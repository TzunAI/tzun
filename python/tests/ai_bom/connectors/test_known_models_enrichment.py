"""Connector descriptors must carry the known-models overlay.

Every TS connector routes through ``importFromVendor``, which looks the parsed
``(vendor, modelName, modelVersion)`` up in the bundled known-models reference
and overlays ``modelType`` / ``license`` / ``modelCardUrl`` / ``trainedBy`` and
friends. The Python connectors apply the same overlay.

The descriptor is content-addressed, so a connector that skipped the overlay
would register a different row and put a different
``aiBom.modelDescriptorDigest`` into the hashed field set than TS does for an
identical vendor call, on the most common path there is: a plain
``gpt-4o-2024-08-06`` chat completion.

The digest asserted below is the one the TypeScript SDK produces for that call.
It is pinned as a literal so this file fails on a Python-side regression even
when the cross-SDK harness is not running.
"""

from __future__ import annotations

import hashlib

from tzun_sdk._generated.canonical import canonical_serialize_descriptor
from tzun_sdk.ai_bom.connectors._base import (
    lookup_known_model,
    merge_mvd_with_enrichment,
)
from tzun_sdk.ai_bom.connectors.anthropic import anthropic_connector
from tzun_sdk.ai_bom.connectors.openai import openai_connector
from tzun_sdk.models import ModelDescriptor

# TS: importFromVendor('openai', 'gpt-4o-2024-08-06') → canonical descriptor
# digest, as the TS suite's `connector_auto_registration` log line reports it.
TS_GPT_4O_DIGEST = (
    "sha256:db9563b129289c2bb30f23d271b8a09cdd5facf01394305a7b52fd846b8abfc7"
)


def _digest(descriptor: ModelDescriptor) -> str:
    canonical = canonical_serialize_descriptor(
        descriptor.model_dump(mode="json", exclude_none=False)
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_openai_connector_descriptor_matches_the_ts_digest() -> None:
    skeleton = openai_connector.build_ai_bom({}, {"model": "gpt-4o-2024-08-06"})
    assert skeleton is not None
    assert _digest(skeleton.model_descriptor) == TS_GPT_4O_DIGEST


def test_openai_connector_carries_the_enrichment_fields() -> None:
    """The overlay fills modelType, license, trainedBy and modelCardUrl from the catalog."""
    skeleton = openai_connector.build_ai_bom({}, {"model": "gpt-4o-2024-08-06"})
    assert skeleton is not None
    d = skeleton.model_descriptor
    assert d.modelType == "llm"
    assert d.license == "openai-commercial"
    assert d.trainedBy == "OpenAI"
    assert d.modelCardUrl == "https://platform.openai.com/docs/models/gpt-4o"


def test_anthropic_connector_is_enriched_too() -> None:
    """The overlay is applied by every connector, not only the openai one.

    The input is the real ``response.model`` shape,
    ``claude-3-5-sonnet-20241022``, which the parser splits into the model name
    and the snapshot version before the catalog lookup.
    """
    skeleton = anthropic_connector.build_ai_bom(
        {}, {"model": "claude-3-5-sonnet-20241022"}
    )
    assert skeleton is not None
    d = skeleton.model_descriptor
    assert d.modelName == "claude-3-5-sonnet"
    assert d.modelVersion == "20241022"
    assert d.modelType == "llm"
    assert d.license == "anthropic-commercial"
    assert d.trainedBy == "Anthropic"
    assert d.modelCardUrl is not None


def test_anthropic_dashed_id_is_neither_split_nor_enriched() -> None:
    """A dashed-date Anthropic id is kept whole and is not enriched.

    A dashed date is not an Anthropic snapshot. The connector keeps the id
    whole, records no version, and — since no catalog entry can be keyed on a
    shape the vendor never emits — does not enrich.
    """
    skeleton = anthropic_connector.build_ai_bom(
        {}, {"model": "claude-3-5-sonnet-2024-10-22"}
    )
    assert skeleton is not None
    d = skeleton.model_descriptor
    assert d.modelName == "claude-3-5-sonnet-2024-10-22"
    assert d.modelVersion == "unknown"
    assert d.license is None
    assert d.trainedBy is None


def test_anthropic_current_generation_id_without_snapshot_is_enriched() -> None:
    skeleton = anthropic_connector.build_ai_bom({}, {"model": "claude-opus-4-7"})
    assert skeleton is not None
    d = skeleton.model_descriptor
    assert (d.modelName, d.modelVersion) == ("claude-opus-4-7", "unknown")
    assert d.license == "anthropic-commercial"


def test_a_model_absent_from_the_catalog_stays_a_bare_mvd() -> None:
    """A lookup miss must not invent fields — the guard is not indiscriminate."""
    skeleton = openai_connector.build_ai_bom(
        {}, {"model": "gpt-9-nonexistent-2099-01-01"}
    )
    assert skeleton is not None
    d = skeleton.model_descriptor
    assert d.modelName == "gpt-9-nonexistent"
    assert d.modelVersion == "2099-01-01"
    assert d.modelType is None
    assert d.license is None
    assert d.trainedBy is None
    assert d.modelCardUrl is None
    assert d.integrityTier == "vendor-asserted"


def test_identity_triple_is_never_overwritten_by_the_catalog() -> None:
    """Port of the TS rule: the parsed id wins over the catalog entry."""
    mvd = ModelDescriptor(
        descriptorVersion="d1",
        vendor="openai",
        modelName="gpt-4o",
        modelVersion="2024-08-06",
        integrityTier="vendor-asserted",
    )
    merged = merge_mvd_with_enrichment(
        mvd,
        {
            "vendor": "someone-else",
            "modelName": "not-this",
            "modelVersion": "9999-99-99",
            "descriptorVersion": "d9",
            "license": "overlaid",
        },
    )
    assert merged.vendor == "openai"
    assert merged.modelName == "gpt-4o"
    assert merged.modelVersion == "2024-08-06"
    assert merged.descriptorVersion == "d1"
    assert merged.license == "overlaid"


def test_lookup_is_exact_and_case_sensitive() -> None:
    ref = {
        "version": "v1",
        "entries": [
            {"vendor": "openai", "modelName": "gpt-4o", "modelVersion": "2024-08-06"}
        ],
    }
    assert lookup_known_model(ref, "openai", "gpt-4o", "2024-08-06") is not None
    assert lookup_known_model(ref, "OpenAI", "gpt-4o", "2024-08-06") is None
    assert lookup_known_model(ref, "openai", "gpt-4o", "2024-08-07") is None
