"""TzunSync end-to-end tests.

``TzunSync.init`` runs the keyword-only ``Tzun.init`` via ``anyio.run`` and
must hand every argument over by keyword. These tests construct the sync
client, round-trip a capture through it, and check that each keyword reaches
the parameter it names.
"""

from __future__ import annotations

import anyio
import pytest

from tzun_sdk import TzunSync
from tzun_sdk.errors import AdminTokenRequiredError
from tzun_sdk.models import AnnotationRecord
from tzun_sdk.storage import MemoryAdapter


def test_sync_init_capture_verify_round_trip() -> None:
    """The documented sync entry point must actually construct.

    A positional hand-off to the keyword-only ``Tzun.init`` would raise
    ``TypeError: Tzun.init() takes 1 positional argument but 6 were given`` on
    the first line.
    """
    tzun = TzunSync.init(storage=MemoryAdapter(), chain_id="sync-chain")
    try:
        result = tzun.capture(
            ai_output={"recommendation": "approve"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="looks fine",
        )
        assert result.evidenceId
        verification = tzun.verify(result.evidenceId)
        assert verification.valid is True
    finally:
        tzun.close()


def test_sync_init_forwards_each_keyword_to_its_own_parameter() -> None:
    """Every argument must reach the parameter it names.

    ``chain_id`` is observable through the storage adapter; ``admin_token``
    is observable through an admin-gated recovery call.
    """
    storage = MemoryAdapter()
    tzun = TzunSync.init(storage=storage, admin_token="tok-abc", chain_id="chain-42")
    try:
        result = tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        head = anyio.run(storage.head, "chain-42")
        assert head is not None
        assert head.payload.evidenceId == result.evidenceId
        # A record was written to "chain-42", not to the default chain.
        assert anyio.run(storage.head, "some-other-chain") is None

        record = AnnotationRecord(
            id="ann-1",
            incidentId="inc-1",
            affectedRecords=[result.evidenceId],
            annotatedAt="2026-09-02T00:00:00.000Z",
            annotatedBy="tester",
            notes="n",
            originalDigests={},
        )
        with pytest.raises(AdminTokenRequiredError):
            anyio.run(
                lambda: tzun.recovery.annotate(record, admin_token="wrong-token")
            )
    finally:
        tzun.close()


def test_sync_capture_inside_running_loop_raises_clearly() -> None:
    """``_run_async``'s in-loop branch: ``anyio.from_thread.run`` needs a
    worker thread or portal, so calling a sync method from the loop thread
    must fail loudly rather than deadlock."""
    tzun = TzunSync.init(storage=MemoryAdapter())

    async def _inner() -> None:
        with pytest.raises(RuntimeError):
            tzun.capture(
                ai_output={"r": "x"},
                decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                reason="ok",
            )

    try:
        anyio.run(_inner)
    finally:
        tzun.close()
