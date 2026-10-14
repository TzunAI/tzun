# python/tests/core/test_models_namespace.py — the tzun.models namespace (and its admin-token policy layer).
from __future__ import annotations

import pytest

from tests.storage.test_catalog_primitives import mvd  # reuse the builder
from tzun_sdk.core import Tzun
from tzun_sdk.errors import AdminTokenRequiredError
from tzun_sdk.storage.memory import MemoryAdapter


@pytest.fixture
async def tzun():
    t = await Tzun.init(storage=MemoryAdapter(), admin_token="s3cret")
    yield t
    await t.close()


async def test_freeform_note_needs_no_admin_and_typed_does(tzun):
    digest = await tzun.models.register(mvd())
    row = await tzun.models.annotate(digest, "freeform-note", {"text": "n"}, annotated_by="rev")
    assert row.annotatedBy == "rev"
    # Any type that isn't 'freeform-note' is admin-gated — 'deprecation' is a custom type
    # (mirrors TS annotations.ts: "any other type → throws unless isAdmin").
    with pytest.raises(AdminTokenRequiredError):
        await tzun.models.annotate(digest, "deprecation", {"reason": "old"}, annotated_by="rev")
    typed = await tzun.models.annotate(
        digest, "deprecation", {"reason": "old"}, annotated_by="rev", admin_token="s3cret")
    assert typed.annotationType == "deprecation"


async def test_alias_and_lists(tzun):
    d = await tzun.models.register(mvd())
    await tzun.models.set_alias("prod", d, set_by="ops", admin_token="s3cret")
    assert await tzun.models.resolve_alias("prod") == d
    assert len(await tzun.models.list()) == 1
    assert (await tzun.models.get_annotations(d)) == []
    assert (await tzun.models.get_enriched(d)).modelName == "gpt-4o"


async def test_lineage_walk_semantics(tzun):
    root = await tzun.models.register(mvd("base", "1"))
    child_desc = mvd("ft", "1").model_copy(update={"parentModelDescriptorDigest": root})
    child = await tzun.models.register(child_desc)
    lineage = await tzun.models.get_lineage(child)
    assert [e.descriptorDigest for e in lineage] == [child, root]  # leaf → root
    assert await tzun.models.get_lineage("sha256:" + "0" * 64) is None  # unknown root → None
