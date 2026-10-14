"""MemoryAdapter unit tests."""

from __future__ import annotations

import os

import pytest

from tzun_sdk.errors import TzunError
from tzun_sdk.models import (
    AnnotationRecord,
    EvidenceEnvelope,
    EvidencePayload,
    IntegrityBlock,
    ModelDescriptor,
)
from tzun_sdk.storage import MemoryAdapter


def _make_envelope(evidence_id: str = "e1", seq: int = 1) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=evidence_id,
            schemaVersion="v1.0",
            aiSystemId="sys",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason="ok",
            capturedAt="2026-01-01T00:00:00Z",
            sequenceNumber=seq,
        ),
        integrity=IntegrityBlock(canonicalDigest="sha256:abc", chainLink=None),
    )


async def test_store_and_retrieve() -> None:
    adapter = MemoryAdapter()
    env = _make_envelope()
    await adapter.store(env)
    got = await adapter.retrieve("e1")
    assert got is not None
    assert got.payload.evidenceId == "e1"


async def test_list_orders_by_sequence() -> None:
    adapter = MemoryAdapter()
    await adapter.store(_make_envelope("e2", seq=2))
    await adapter.store(_make_envelope("e1", seq=1))
    items = await adapter.list()
    assert [e.payload.evidenceId for e in items] == ["e1", "e2"]


async def test_head_returns_latest() -> None:
    adapter = MemoryAdapter()
    await adapter.store(_make_envelope("e1", seq=1))
    await adapter.store(_make_envelope("e2", seq=2))
    head = await adapter.head()
    assert head is not None
    assert head.payload.evidenceId == "e2"


async def test_descriptor_register_and_get() -> None:
    adapter = MemoryAdapter()
    desc = ModelDescriptor(
        descriptorVersion="d1",
        vendor="openai",
        modelName="gpt-4o",
        modelVersion="2024-08-06",
        integrityTier="vendor-asserted",
    )
    digest = await adapter.register_descriptor(desc)
    assert digest.startswith("sha256:")
    got = await adapter.get_descriptor(digest)
    assert got is not None
    assert got.modelName == "gpt-4o"


async def test_recovery_store() -> None:
    adapter = MemoryAdapter()
    await adapter.store_annotation(
        AnnotationRecord(
            id="a1",
            incidentId="i1",
            affectedRecords=["e1"],
            annotatedAt="2026-01-01T00:00:00Z",
            annotatedBy="alice",
            notes="n",
            originalDigests={"e1": "sha256:abc"},
        )
    )
    assert len(adapter._annotations) == 1


async def test_demo_delete_gated() -> None:
    """TZUN_ENABLE_DEMO_DELETE gate."""
    adapter = MemoryAdapter()
    await adapter.store(_make_envelope())
    # Default: gate off → raises.
    os.environ.pop("TZUN_ENABLE_DEMO_DELETE", None)
    with pytest.raises(TzunError):
        await adapter.delete_envelope_for_demo("e1")
    # Gate on: succeeds.
    os.environ["TZUN_ENABLE_DEMO_DELETE"] = "1"
    try:
        await adapter.delete_envelope_for_demo("e1")
        assert await adapter.retrieve("e1") is None
    finally:
        os.environ.pop("TZUN_ENABLE_DEMO_DELETE", None)


async def test_list_by_sequence_is_chain_scoped_and_ranged() -> None:
    """list_by_sequence filters on chain_id and an inclusive sequence range."""
    adapter = MemoryAdapter()
    for seq in (1, 2, 3):
        await adapter.store(_make_envelope(f"a{seq}", seq=seq), "chain-a")
    for seq in (1, 2):
        await adapter.store(_make_envelope(f"b{seq}", seq=seq), "chain-b")

    got = await adapter.list_by_sequence(2, 2, "chain-a")
    assert [e.payload.evidenceId for e in got] == ["a2"]

    # Unbounded upper bound, chain-scoped, ordered ascending.
    got = await adapter.list_by_sequence(1, None, "chain-b")
    assert [e.payload.evidenceId for e in got] == ["b1", "b2"]

    # chain_id=None means the DEFAULT chain, not "every chain".
    assert await adapter.list_by_sequence(1, None, None) == []
