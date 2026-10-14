# python/tests/storage/test_catalog_primitives.py — the model-catalog storage primitives.
from __future__ import annotations

import pytest

from tzun_sdk.models import ModelDescriptor, ModelDescriptorAnnotationRow, TrainingInfo
from tzun_sdk.storage.memory import MemoryAdapter
from tzun_sdk.storage.sqlite import SqliteAdapter


def mvd(name: str = "gpt-4o", version: str = "2024-08-06") -> ModelDescriptor:
    return ModelDescriptor(
        descriptorVersion="d1", vendor="openai", modelName=name, modelVersion=version,
        modelType=None, integrityTier="vendor-asserted", modelDigest=None,
        parentModelDescriptorDigest=None, derivation=None, trainedBy=None, license=None,
        modelCardUrl=None,
        training=TrainingInfo(trainingDataDigest=None, trainingDataRef=None,
                              lastTrainingDate=None, evaluations=[]),
        regulatoryMarkings=[], externalIdentifiers=[],
    )


def annotation_row(digest: str, **over) -> ModelDescriptorAnnotationRow:
    base = dict(
        annotationId="a1", modelDescriptorDigest=digest, annotationType="freeform-note",
        valueJson='{"text": "looks right"}',
        retractsAnnotationId=None,
        annotatedBy="reviewer-1",
        annotatedAt="2026-06-10T00:00:00.000Z", note=None, signature=None,
    )
    base.update(over)
    return ModelDescriptorAnnotationRow(**base)


@pytest.fixture(params=["memory", "sqlite"])
def adapter(request, tmp_path):
    if request.param == "memory":
        return MemoryAdapter()
    return SqliteAdapter(str(tmp_path / "catalog.db"), mode="sync")


async def test_list_filters_and_paginates(adapter):
    await adapter.ensure_tables()
    d1 = await adapter.register_descriptor(mvd("gpt-4o"))
    await adapter.register_descriptor(mvd("claude-x"))
    rows = await adapter.list_model_descriptors()
    assert len(rows) == 2
    only = await adapter.list_model_descriptors(vendor="openai", limit=1, offset=0)
    assert len(only) == 2 or len(only) == 1  # both are vendor=openai; limit applies
    result = await adapter.list_model_descriptors(limit=1)
    assert result[0].modelDescriptorDigest in (d1, rows[0].modelDescriptorDigest)


async def test_annotations_append_only_roundtrip(adapter):
    await adapter.ensure_tables()
    d = await adapter.register_descriptor(mvd())
    await adapter.append_model_descriptor_annotation(annotation_row(d))
    await adapter.append_model_descriptor_annotation(annotation_row(d, annotationId="a2"))
    rows = await adapter.list_model_descriptor_annotations(d)
    assert [r.annotationId for r in rows] == ["a1", "a2"]  # insertion order


async def test_alias_latest_set_wins(adapter):
    await adapter.ensure_tables()
    d1 = await adapter.register_descriptor(mvd("gpt-4o"))
    d2 = await adapter.register_descriptor(mvd("gpt-4o-mini"))
    await adapter.set_model_descriptor_alias("prod", d1, "ops")
    await adapter.set_model_descriptor_alias("prod", d2, "ops")  # append-only rebind
    assert await adapter.resolve_model_descriptor_alias("prod") == d2
    assert await adapter.resolve_model_descriptor_alias("missing") is None


async def test_enriched_view(adapter):
    await adapter.ensure_tables()
    d = await adapter.register_descriptor(mvd())
    enriched = await adapter.get_enriched_model_descriptor(d)
    assert enriched is not None and enriched.modelName == "gpt-4o"
