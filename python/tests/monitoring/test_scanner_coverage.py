"""The scheduled scanner must read the whole chain, not one page of it.

`ScheduledScanner` reads the chain-scoped, unpaged `list_by_sequence()`, as
`verify()` and `verify_range()` do, and not `list()`: `list()` is the paged,
chain-unscoped query the SDK's own Protocol docstring calls "unsuitable for any
integrity check". A scanner that read one page of it would stop looking at the
page boundary and report a tampered store clean, though finding tampering is
its entire job.
"""

from __future__ import annotations

import json
import uuid

import pytest

from tzun_sdk import Tzun
from tzun_sdk.models import (
    EvidenceEnvelope,
    EvidencePayload,
    IntegrityBlock,
)
from tzun_sdk.monitoring.scanner import ScheduledScanner
from tzun_sdk.storage import MemoryAdapter

# One past a 1000-record page: a scan that read a single page would miss it.
_PAST_THE_PAGE = 1001


def _envelope(seq: int, *, digest: str) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=f"e-{seq:05d}",
            schemaVersion="v1.0",
            aiSystemId="test-sys",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason="ok",
            capturedAt="2026-01-01T00:00:00.000Z",
            sequenceNumber=seq,
        ),
        integrity=IntegrityBlock(canonicalDigest=digest, chainLink=None),
    )


async def _honest_digest(seq: int) -> str:
    """The digest a record at `seq` really hashes to."""
    import hashlib

    from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize

    probe = _envelope(seq, digest="placeholder")
    canonical = canonical_serialize(
        probe.payload.model_dump(mode="json"), list(V1_HASHED_FIELDS)
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def test_scanner_detects_a_tamper_past_a_1000_record_page() -> None:
    storage = MemoryAdapter()
    tzun = await Tzun.init(storage=storage)
    try:
        for seq in range(1, _PAST_THE_PAGE + 1):
            await storage.store(_envelope(seq, digest=await _honest_digest(seq)))

        # Tamper the record just past that page boundary: its stored digest
        # no longer matches its payload.
        tampered = _envelope(_PAST_THE_PAGE, digest="sha256:" + "00" * 32)
        storage._envelopes[tampered.payload.evidenceId] = json.loads(tampered.model_dump_json())

        incidents = await ScheduledScanner(tzun).scan_once()

        assert [i.evidenceId for i in incidents] == [tampered.payload.evidenceId]
        assert incidents[0].eventType == "digest_mismatch"
        # And it was persisted, not merely returned.
        assert storage._incidents[-1].evidenceId == tampered.payload.evidenceId
    finally:
        await tzun.close()


async def test_scanner_reports_a_clean_chain_as_clean() -> None:
    """Non-vacuity guard: the scan is not simply flagging everything."""
    storage = MemoryAdapter()
    tzun = await Tzun.init(storage=storage)
    try:
        for seq in range(1, 5):
            await storage.store(_envelope(seq, digest=await _honest_digest(seq)))
        assert await ScheduledScanner(tzun).scan_once() == []
    finally:
        await tzun.close()


async def test_scanner_is_scoped_to_the_chain_it_was_given() -> None:
    """After a fork the scan must not mix in records from another chain."""
    storage = MemoryAdapter()
    tzun = await Tzun.init(storage=storage, chain_id="chain-b")
    try:
        # A tampered record on a DIFFERENT chain.
        other = _envelope(1, digest="sha256:" + "00" * 32)
        other.payload.evidenceId = f"other-{uuid.uuid4().hex[:8]}"
        await storage.store(other, "chain-a")
        # A clean record on the chain under scan.
        await storage.store(_envelope(1, digest=await _honest_digest(1)), "chain-b")

        assert await ScheduledScanner(tzun).scan_once() == []
    finally:
        await tzun.close()


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_sqlite_scan_ignores_records_from_another_chain(mode: str, tmp_path) -> None:
    """`list()` is chain-blind on the SQL adapters at ANY limit.

    A scan over `list()` would report a tampered record on a chain this
    scanner is not scanning as an incident against the chain it is, because
    `list()` has no chain predicate. `list_by_sequence()` does, so the scan
    reports nothing here.
    """
    from tzun_sdk.storage import SqliteAdapter

    storage = SqliteAdapter(str(tmp_path / f"scan-{mode}.db"), mode=mode)
    tzun = await Tzun.init(storage=storage)
    try:
        await storage.store(_envelope(1, digest=await _honest_digest(1)))
        other = _envelope(2, digest="sha256:" + "00" * 32)
        other.payload.evidenceId = f"other-{uuid.uuid4().hex[:8]}"
        await storage.store(other, "some-other-chain")

        assert await ScheduledScanner(tzun).scan_once() == []
    finally:
        await tzun.close()
