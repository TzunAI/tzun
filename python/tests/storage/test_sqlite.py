"""SqliteAdapter unit tests."""

from __future__ import annotations

import pytest

from tzun_sdk.models import (
    EvidenceEnvelope,
    EvidencePayload,
    IntegrityBlock,
    ModelDescriptor,
)
from tzun_sdk.storage import SqliteAdapter


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


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_sqlite_roundtrip(mode: str, tmp_path) -> None:
    adapter = SqliteAdapter(str(tmp_path / f"tzun-{mode}.db"), mode=mode)
    await adapter.ensure_tables()
    env = _make_envelope()
    await adapter.store(env)
    got = await adapter.retrieve("e1")
    assert got is not None
    assert got.payload.evidenceId == "e1"
    await adapter.close()


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_sqlite_descriptor_dedup(mode: str, tmp_path) -> None:
    adapter = SqliteAdapter(str(tmp_path / f"tzun-{mode}.db"), mode=mode)
    await adapter.ensure_tables()
    desc = ModelDescriptor(
        descriptorVersion="d1",
        vendor="openai",
        modelName="gpt-4o",
        modelVersion="2024-08-06",
        integrityTier="vendor-asserted",
    )
    d1 = await adapter.register_descriptor(desc)
    d2 = await adapter.register_descriptor(desc)
    assert d1 == d2
    got = await adapter.get_descriptor(d1)
    assert got is not None
    await adapter.close()


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_sqlite_head(mode: str, tmp_path) -> None:
    adapter = SqliteAdapter(str(tmp_path / f"tzun-{mode}.db"), mode=mode)
    await adapter.ensure_tables()
    await adapter.store(_make_envelope("e1", seq=1))
    await adapter.store(_make_envelope("e2", seq=2))
    head = await adapter.head()
    assert head is not None
    assert head.payload.evidenceId == "e2"
    await adapter.close()


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_list_by_sequence_ignores_the_list_page_limit(mode: str, tmp_path) -> None:
    """list() defaults to limit=100; list_by_sequence must not be paged.

    Verification looks up a record's predecessor through list_by_sequence. If
    that lookup were paged like list(), record 104 would be invisible and
    honest records at sequence >= 102 would fail verification.
    """
    adapter = SqliteAdapter(str(tmp_path / f"seq-{mode}.db"), mode=mode)
    await adapter.ensure_tables()
    for seq in range(1, 121):
        await adapter.store(_make_envelope(f"e{seq}", seq=seq))

    assert len(await adapter.list()) == 100  # list() itself stays paged
    assert len(await adapter.list_by_sequence()) == 120
    got = await adapter.list_by_sequence(104, 104)
    assert [e.payload.evidenceId for e in got] == ["e104"]
    await adapter.close()


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_list_by_sequence_is_chain_scoped(mode: str, tmp_path) -> None:
    """Unlike list(), list_by_sequence filters on chain_id."""
    adapter = SqliteAdapter(str(tmp_path / f"chain-{mode}.db"), mode=mode)
    await adapter.ensure_tables()
    await adapter.store(_make_envelope("a1", seq=1), "chain-a")
    await adapter.store(_make_envelope("b1", seq=1), "chain-b")

    got = await adapter.list_by_sequence(1, 1, "chain-a")
    assert [e.payload.evidenceId for e in got] == ["a1"]
    assert len(await adapter.list()) == 2
    await adapter.close()
