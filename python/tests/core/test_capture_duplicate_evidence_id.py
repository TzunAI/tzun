"""``capture()`` with a reused caller-supplied ``evidence_id``.

``Tzun.capture(evidence_id=...)`` lets the caller pick the id. Reusing one is
refused with ``DuplicateEvidenceError`` (code ``evidence_id_conflict``) by
the adapter, and the first record stays exactly as it was stored. The
refused capture then hands its sequence number back: ``capture()`` resyncs its
counter from the store's real head, as it does on ``ChainConflictError`` (TS
``resyncChainFromStore()`` runs on any store failure). If the counter kept the
reserved number it would sit one ahead of the store, and the NEXT, unrelated
capture would be refused with a ``ChainConflictError`` it did nothing to earn:
one bad id would write off the following good decision.

Adapters exercised: ``MemoryAdapter``; ``SqliteAdapter`` async and sync on a
``tmp_path`` file.
"""

from __future__ import annotations

import pytest

from tzun_sdk import Tzun
from tzun_sdk.errors import DuplicateEvidenceError
from tzun_sdk.storage import MemoryAdapter, SqliteAdapter

FIXED_ID = "0f1e2d3c-4b5a-4987-8796-a5b4c3d2e1f0"


def _adapter(kind: str, tmp_path):
    if kind == "memory":
        return MemoryAdapter()
    mode = kind.split("-")[1]
    if mode == "async":
        pytest.importorskip("aiosqlite")
    return SqliteAdapter(str(tmp_path / f"{kind}.db"), mode=mode)


@pytest.mark.parametrize("kind", ["memory", "sqlite-async", "sqlite-sync"])
async def test_reused_evidence_id_is_refused_and_burns_no_sequence(kind: str, tmp_path) -> None:
    adapter = _adapter(kind, tmp_path)
    tzun = await Tzun.init(storage=adapter)
    try:
        first = await tzun.capture(
            ai_output={"n": 1},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="original",
            evidence_id=FIXED_ID,
        )

        with pytest.raises(DuplicateEvidenceError) as exc:
            await tzun.capture(
                ai_output={"n": 2},
                decider={"kind": "human", "id": "acct:test-reviewer"}, action="rejected",
                reason="rewrite",
                evidence_id=FIXED_ID,
            )
        assert exc.value.evidence_id == FIXED_ID
        assert exc.value.code == "evidence_id_conflict"

        # The first record is untouched.
        stored = await adapter.retrieve(FIXED_ID)
        assert stored is not None
        assert stored.payload.reason == "original"
        assert stored.integrity.canonicalDigest == first.canonicalDigest

        # The refused capture handed its sequence back: the next capture is
        # sequence 2, the chain is gap-free, and it verifies.
        third = await tzun.capture(
            ai_output={"n": 3}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="next"
        )
        third_env = await adapter.retrieve(third.evidenceId)
        assert third_env is not None
        assert third_env.payload.sequenceNumber == 2
        assert [e.payload.sequenceNumber for e in await adapter.list_by_sequence()] == [1, 2]
        verdict = await tzun.verify(third.evidenceId)
        assert verdict.valid, verdict.reasons
    finally:
        await tzun.close()
