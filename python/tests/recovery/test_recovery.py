"""Recovery surface — annotate / relink / fork.

Covers the three-tier recovery operations through both ``Tzun.recovery``
and the standalone ``RecoveryManager``, including the admin-token gate.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from tzun_sdk import Tzun
from tzun_sdk.errors import AdminTokenRequiredError
from tzun_sdk.models import AnnotationRecord, ForkRecord, ModifiedLink, RelinkRecord
from tzun_sdk.recovery import RecoveryManager
from tzun_sdk.storage import MemoryAdapter


def _annotation() -> AnnotationRecord:
    return AnnotationRecord(
        id="ann-1",
        incidentId="inc-1",
        affectedRecords=["ev-1"],
        annotatedAt="2026-05-29T00:00:00.000Z",
        annotatedBy="reviewer@example.com",
        notes="reviewed and accepted",
        originalDigests={"ev-1": "sha256:" + "a" * 64},
    )


def _relink() -> RelinkRecord:
    return RelinkRecord(
        id="rel-1",
        incidentId="inc-1",
        relinkedAt="2026-05-29T00:00:00.000Z",
        relinkedBy="reviewer@example.com",
        fromSequence=2,
        toSequence=5,
        modifiedLinks=[
            ModifiedLink(
                evidenceId="ev-2",
                sequenceNumber=2,
                previousChainLink="sha256:" + "b" * 64,
                newChainLink="sha256:" + "c" * 64,
            )
        ],
    )


def _fork() -> ForkRecord:
    return ForkRecord(
        id="fork-1",
        incidentId="inc-1",
        forkedAt="2026-05-29T00:00:00.000Z",
        forkedBy="reviewer@example.com",
        reason="tamper detected",
        oldChainId="chain-a",
        newChainId="chain-b",
        forkAfterSequence=3,
        sealedOldChainLength=3,
        sealedOldChainHead=3,
    )


async def test_annotate_relink_fork_persist_no_admin_token() -> None:
    """All three operations persist via the storage adapter."""
    storage = MemoryAdapter()
    async with await Tzun.init(storage=storage) as tzun:
        await tzun.recovery.annotate(_annotation())
        await tzun.recovery.relink(_relink())
        await tzun.recovery.fork(_fork())
    # MemoryAdapter keeps the records in-process; assert they landed.
    assert len(storage._annotations) == 1
    assert len(storage._relinks) == 1
    assert len(storage._forks) == 1


async def test_recovery_admin_gate_blocks_without_token() -> None:
    """When admin_token is set, a matching token is required."""
    storage = MemoryAdapter()
    async with await Tzun.init(storage=storage, admin_token="s3cret") as tzun:
        with pytest.raises(AdminTokenRequiredError):
            await tzun.recovery.annotate(_annotation())
        with pytest.raises(AdminTokenRequiredError):
            await tzun.recovery.relink(_relink(), admin_token="wrong")
        # Correct token admits the operation.
        await tzun.recovery.fork(_fork(), admin_token="s3cret")
    assert len(storage._forks) == 1


async def test_standalone_recovery_manager_mirrors_namespace() -> None:
    """The standalone RecoveryManager shares the Tzun storage + admin gate."""
    storage = MemoryAdapter()
    async with await Tzun.init(storage=storage, admin_token="tok") as tzun:
        mgr = RecoveryManager(tzun)
        with pytest.raises(AdminTokenRequiredError):
            await mgr.annotate(_annotation())
        await mgr.annotate(_annotation(), admin_token="tok")
    assert len(storage._annotations) == 1


def test_fork_record_carries_the_sealed_chain_head_and_tolerates_legacy_rows() -> None:
    """``ForkRecord`` mirrors the TS engine type.

    ``sealedOldChainLength`` is a ROW COUNT; the sealed chain's sequence upper
    bound is ``sealedOldChainHead``. A fork record written by SDK 0.3.13 has no
    head field at all, and it must still validate (``None``), while the field
    round-trips when present and the model stays ``extra="forbid"``.
    """
    base = {
        "id": "fork-legacy",
        "incidentId": "inc-1",
        "forkedAt": "2026-05-29T00:00:00.000Z",
        "forkedBy": "reviewer@example.com",
        "reason": "tamper detected",
        "oldChainId": "chain-a",
        "newChainId": "chain-b",
        "forkAfterSequence": 3,
        # Four rows, but the chain reached sequence 5 (one gap) — the pair of
        # numbers the row count conflated.
        "sealedOldChainLength": 4,
    }
    legacy = ForkRecord.model_validate(base)
    assert legacy.sealedOldChainHead is None
    assert legacy.sealedOldChainLength == 4

    current = ForkRecord.model_validate({**base, "sealedOldChainHead": 5})
    assert current.sealedOldChainHead == 5
    assert json.loads(current.model_dump_json())["sealedOldChainHead"] == 5

    with pytest.raises(ValidationError):
        ForkRecord.model_validate({**base, "sealedOldChainHigh": 5})
