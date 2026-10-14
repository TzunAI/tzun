"""A store failure that is NOT a chain conflict: it surfaces once, hands the
sequence back, and is named for what it is in the log.

``capture()`` retries exactly one refusal — ``ChainConflictError``, the
adapter's compare-and-swap saying the head moved (test_two_writers_retry.py).
Every other failure the adapter can raise means the record was not written
and will not be by resubmitting it at the next position: a
``DuplicateEvidenceError`` (the id is taken — the same id at sequence N+1 is
refused exactly as it was at N), ``PostgresAdapter.store failed: ...`` (a
dropped connection, wrapped), a raw driver error. Those surface on the first
attempt, not after ``chain_conflict_max_attempts`` identical refusals.

Two things must still happen on the way out:

1. the sequence reserved for the refused record is handed back. ``capture()``
   takes its sequence from the live head, so the CHAIN is not at risk, but
   ``_sequence_counter`` is: it is the diagnostic "store's head as this
   instance last saw it", which the conflict path promises is never a step
   behind the store. After a foreign append and then a refused store it is
   resynced from the live head, or from ``seq - 1`` when the store cannot
   even answer ``head()``, rather than keeping the pre-foreign value;
2. the log names the failure's own ``code`` in a ``capture store_refused``
   line and never says ``chain_conflict``, so an operator counting chain
   conflicts does not count duplicates, and a non-conflict failure is logged
   rather than passing silently.

Real ``SqliteAdapter`` on a ``tmp_path`` file. The failure is injected by a
wrapper whose ``store()`` raises what ``PostgresAdapter.store()`` raises on a
dropped connection, and whose ``head()`` can be taken down with it.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from tzun_sdk import Tzun
from tzun_sdk.errors import DuplicateEvidenceError, TzunError
from tzun_sdk.storage import SqliteAdapter

LOGGER = "tzun_sdk.core"

FIXED_ID = "0f1e2d3c-4b5a-4987-8796-a5b4c3d2e1f0"


def _cap(tzun: Tzun, label: str, **kw: Any) -> Any:
    return tzun.capture(
        ai_output={"label": label},
        decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
        reason=f"because {label}",
        **kw,
    )


def _refusals(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "capture store_refused" in r.getMessage()]


class _ConnectionDropsAtStore:
    """A REAL adapter whose next ``store()`` calls fail the way a dropped
    Postgres connection does, optionally taking ``head()`` down with them.

    Everything else delegates, so the records that DO land are written by the
    real SQLite adapter and the chain assertions below are about real rows.
    """

    def __init__(self, inner: Any, *, head_stays_down: bool) -> None:
        self._inner = inner
        self._store_failures = 0
        self._head_stays_down = head_stays_down
        self.head_down = False
        self.store_calls = 0

    def arm(self, store_failures: int) -> None:
        """Make the next ``store_failures`` calls to ``store()`` fail. Armed
        AFTER the fixture's setup captures, so those land on the real adapter."""
        self._store_failures = store_failures

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def store(self, envelope: Any, chain_id: Any = None, options: Any = None) -> None:
        self.store_calls += 1
        if self._store_failures > 0:
            self._store_failures -= 1
            self.head_down = self._head_stays_down
            raise TzunError("PostgresAdapter.store failed: connection reset")
        await self._inner.store(envelope, chain_id, options)

    async def head(self, chain_id: Any = None) -> Any:
        if self.head_down:
            raise TzunError("PostgresAdapter.head failed: connection reset")
        return await self._inner.head(chain_id)


async def _two_writers(tmp_path: Any, *, head_stays_down: bool) -> tuple[Tzun, Tzun, Any]:
    """``ours`` and ``other`` on one file; ``ours`` has seen sequence 1 as the
    head and ``other`` has since appended sequence 2, so ``ours``'s diagnostic
    counter is one behind the store — the state a resync must repair."""
    db = str(tmp_path / "drop.db")
    dropping = _ConnectionDropsAtStore(
        SqliteAdapter(db, mode="async"), head_stays_down=head_stays_down
    )
    ours = await Tzun.init(storage=dropping)
    other = await Tzun.init(storage=SqliteAdapter(db, mode="async"))
    first = await _cap(ours, "ours-1")
    assert first.sequenceNumber == 1
    assert ours._sequence_counter == 1
    second = await _cap(other, "other-2")
    assert second.sequenceNumber == 2
    assert ours._sequence_counter == 1  # behind the store, legitimately, until it looks
    dropping.arm(1)  # the NEXT store from `ours` is the one that fails
    return ours, other, dropping


async def test_other_store_failure_surfaces_once_and_resyncs_from_the_live_head(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    ours, other, dropping = await _two_writers(tmp_path, head_stays_down=False)
    try:
        calls_before = dropping.store_calls
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            with pytest.raises(TzunError, match="connection reset") as exc:
                await _cap(ours, "ours-3")
        # The failure is the adapter's own, verbatim — not re-typed as a chain
        # conflict, and not retried: one submission, then the caller decides.
        assert type(exc.value) is TzunError
        assert dropping.store_calls == calls_before + 1

        # The sequence is handed back: after the refusal the counter says what
        # the store says (2), not what this instance last wrote (1).
        assert ours._sequence_counter == 2

        # And the log says what happened, by the failure's own name.
        refused = _refusals(caplog)
        assert len(refused) == 1, [r.getMessage() for r in caplog.records]
        msg = refused[0].getMessage()
        assert "code=TzunError" in msg
        assert "attempted_seq=3" in msg
        assert "resynced_to=2" in msg
        assert not any("chain_conflict" in r.getMessage() for r in caplog.records)

        # Non-vacuity: the chain is intact and the next capture lands at 3.
        third = await _cap(ours, "ours-3-again")
        assert third.sequenceNumber == 3
        rows = await other._storage.list_by_sequence()
        assert [r.payload.sequenceNumber for r in rows] == [1, 2, 3]
        verdict = await other.verify(third.evidenceId)
        assert verdict.valid, verdict.reasons
    finally:
        await ours.close()
        await other.close()


async def test_head_unreachable_during_resync_falls_back_to_the_head_this_attempt_used(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The connection dropped at the store and is still down when the resync
    asks ``head()``. The counter cannot be read from the store, so it falls
    back to the head this attempt was built against (``seq - 1``) — the last
    value known to be true — rather than raising a second error out of the
    handler, which would have replaced the caller's real failure with
    ``head failed``."""
    ours, other, dropping = await _two_writers(tmp_path, head_stays_down=True)
    try:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            with pytest.raises(TzunError, match="store failed") as exc:
                await _cap(ours, "ours-3")
        # The STORE failure is what surfaces, not the head() failure behind it.
        assert "store failed" in str(exc.value)
        assert dropping.head_down  # the resync's head() did run into the outage
        # Built against head 2 (read live before the store), so seq - 1 == 2.
        assert ours._sequence_counter == 2
        refused = _refusals(caplog)
        assert len(refused) == 1, [r.getMessage() for r in caplog.records]
        assert "resynced_to=2" in refused[0].getMessage()

        # Connection back: the next capture reads the live head and lands at 3.
        dropping.head_down = False
        third = await _cap(ours, "ours-3-again")
        assert third.sequenceNumber == 3
        rows = await other._storage.list_by_sequence()
        assert [r.payload.sequenceNumber for r in rows] == [1, 2, 3]
    finally:
        await ours.close()
        await other.close()


async def test_duplicate_evidence_id_is_refused_once_not_retried_as_a_chain_conflict(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A reused ``evidence_id`` is not a moved head. It is submitted exactly
    once — not ``chain_conflict_max_attempts`` times at successive sequences,
    each refused for the same reason — and the log names it by its own code,
    not as a chain conflict. (Sequence hand-back and chain intactness for this
    case are pinned in test_capture_duplicate_evidence_id.py.)"""
    counting = _ConnectionDropsAtStore(
        SqliteAdapter(str(tmp_path / "dup.db"), mode="async"), head_stays_down=False
    )
    tzun = await Tzun.init(storage=counting, chain_conflict_max_attempts=10)
    try:
        await _cap(tzun, "first", evidence_id=FIXED_ID)
        assert counting.store_calls == 1
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            with pytest.raises(DuplicateEvidenceError):
                await _cap(tzun, "replay", evidence_id=FIXED_ID)
        assert counting.store_calls == 2, "a duplicate id must be submitted once, not retried"

        refused = _refusals(caplog)
        assert len(refused) == 1, [r.getMessage() for r in caplog.records]
        msg = refused[0].getMessage()
        assert f"code={DuplicateEvidenceError.code}" in msg
        assert f"evidence_id={FIXED_ID}" in msg
        assert "attempted_seq=2" in msg
        assert "resynced_to=1" in msg
        assert not any("chain_conflict" in r.getMessage() for r in caplog.records)
    finally:
        await tzun.close()
