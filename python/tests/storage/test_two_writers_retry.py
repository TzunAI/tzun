"""Two writers on one store: a refused compare-and-swap is retried, not dropped.

Two SDK instances on one database each build a record against the head they
read. When the other instance appends in between, the chain-head
compare-and-swap refuses the record. Stopping there would lose a decision on
every conflict, and a writer that kept building against the head it last saw
would be refused on every attempt, so the second of two alternating writers
would never store anything again. The TypeScript twin
(``tests/ts/two-writers-chain-conflict-retry.test.ts``) pins the same
contract.

Two layers are pinned, both on REAL adapters — SQLite in every run, Postgres
under ``RUN_INTEGRATION_TESTS=true``:

1. the error is typed: ``ChainConflictError.code == "chain_conflict"`` and
   ``ChainConflictError.retryable is True``, so a caller can tell "the head
   moved under me" from "the database is broken";
2. the SDK recovers: a refused append is rebuilt against the head the refusal
   reported and tried again, bounded by ``chain_conflict_max_attempts``, and
   only then raised.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import uuid
from typing import Any

import pytest

from tzun_sdk import Tzun, TzunSync
from tzun_sdk.errors import ChainConflictError
from tzun_sdk.models import CaptureResult
from tzun_sdk.storage import MemoryAdapter, SqliteAdapter

# The local Postgres container.
_PG_HOST = "host.docker.internal"

LOGGER = "tzun_sdk.core"


def _cap(tzun: Tzun, label: str) -> Any:
    return tzun.capture(
        ai_output={"label": label},
        decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
        reason=f"because {label}",
    )


def _retries(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "chain_conflict_retry" in r.getMessage()]


class _ForeignAppendBeforeStore:
    """A REAL adapter, with another ``Tzun`` appending just before the first
    ``times`` calls to ``store()``.

    A deterministic stand-in for "the other pod committed between our head
    read and our write". Everything else delegates to the wrapped adapter, so
    the compare-and-swap that refuses the record is the real SQLite one.
    """

    def __init__(self, inner: Any, foreign: Tzun, times: int) -> None:
        self._inner = inner
        self._foreign = foreign
        self._remaining = times
        self.foreign_captures: list[CaptureResult] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def store(self, envelope: Any, chain_id: Any = None, options: Any = None) -> None:
        if self._remaining > 0:
            self._remaining -= 1
            self.foreign_captures.append(
                await _cap(self._foreign, f"foreign-{len(self.foreign_captures) + 1}")
            )
        return await self._inner.store(envelope, chain_id, options)


async def _assert_chain_clean(tzun: Tzun, expected_len: int) -> None:
    rows = await tzun._storage.list_by_sequence()
    assert [r.payload.sequenceNumber for r in rows] == list(range(1, expected_len + 1))
    verdicts = await tzun.verify_range(1, expected_len)
    assert len(verdicts) == expected_len
    assert all(v.valid for v in verdicts), [
        (v.evidenceId, v.digestValid, v.chainLinkValid) for v in verdicts if not v.valid
    ]


# ── SQLite ────────────────────────────────────────────────────────────────


async def test_sqlite_twenty_concurrent_captures_across_two_instances_all_land(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The measurement: two instances, one file, 20 concurrent captures → 20/20.

    Contention depends on how the event loop interleaves the two writers, and a
    loaded machine can serialise a round, so the round is repeated (up to five
    times) until one has been refused and retried. Every round must land all
    of its captures, in sequence.
    """
    db = str(tmp_path / "two-writers.db")
    a = await Tzun.init(storage=SqliteAdapter(db, mode="async"))
    b = await Tzun.init(storage=SqliteAdapter(db, mode="async"))
    try:
        landed = 0
        for round_no in range(5):
            with caplog.at_level(logging.WARNING, logger=LOGGER):
                results = await asyncio.gather(
                    *[_cap(a, f"r{round_no}-a{i}") for i in range(10)],
                    *[_cap(b, f"r{round_no}-b{i}") for i in range(10)],
                )
            assert len(results) == 20
            assert sorted(r.sequenceNumber for r in results) == list(range(landed + 1, landed + 21))
            landed += 20
            if _retries(caplog):
                break
        await _assert_chain_clean(a, landed)
        # Both instances agree on the head afterwards.
        after = await _cap(b, "after")
        assert after.sequenceNumber == landed + 1
        # Non-vacuity: contention really happened and was retried, so this is
        # the mechanism under test and not a store that serialised everything.
        assert _retries(caplog), "expected at least one refused-and-retried append in five rounds"
    finally:
        await a.close()
        await b.close()


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_sqlite_alternating_writers_second_instance_is_not_starved(
    mode: str, tmp_path: Any
) -> None:
    """Two instances capturing in turn both land every round: sequences 1 to 8,
    in order, on a clean chain, so the second writer is never starved."""
    db = str(tmp_path / "alternating.db")
    a = await Tzun.init(storage=SqliteAdapter(db, mode=mode))
    b = await Tzun.init(storage=SqliteAdapter(db, mode=mode))
    try:
        seqs: list[int] = []
        for round_no in range(4):
            seqs.append((await _cap(a, f"a{round_no}")).sequenceNumber)
            seqs.append((await _cap(b, f"b{round_no}")).sequenceNumber)
        assert seqs == [1, 2, 3, 4, 5, 6, 7, 8]
        await _assert_chain_clean(a, 8)
    finally:
        await a.close()
        await b.close()


async def test_refused_append_is_rebuilt_against_the_head_it_lost_to(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """Deterministic contention: the other writer commits between our head
    read and our store. The CAS refuses us once; we land on the retry, linked
    to the record that beat us."""
    db = str(tmp_path / "lost-once.db")
    foreign = await Tzun.init(storage=SqliteAdapter(db, mode="async"))
    racing = _ForeignAppendBeforeStore(SqliteAdapter(db, mode="async"), foreign, times=1)
    ours = await Tzun.init(storage=racing)
    try:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            result = await _cap(ours, "ours")
        assert len(racing.foreign_captures) == 1
        assert racing.foreign_captures[0].sequenceNumber == 1
        assert result.sequenceNumber == 2
        assert result.envelope.integrity.chainLink is not None
        assert len(_retries(caplog)) == 1
        await _assert_chain_clean(foreign, 2)
    finally:
        await ours.close()
        await foreign.close()


async def test_exhausted_retry_raises_typed_retryable_error_and_stores_nothing(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    db = str(tmp_path / "exhausted.db")
    foreign = await Tzun.init(storage=SqliteAdapter(db, mode="async"))
    # Beaten to the head on every one of its two attempts.
    racing = _ForeignAppendBeforeStore(SqliteAdapter(db, mode="async"), foreign, times=2)
    ours = await Tzun.init(storage=racing, chain_conflict_max_attempts=2)
    try:
        with (
            caplog.at_level(logging.WARNING, logger=LOGGER),
            pytest.raises(ChainConflictError) as exc,
        ):
            await _cap(ours, "ours")
        # Layer 1 — the error is typed and says it is worth trying again.
        assert exc.value.code == "chain_conflict"
        assert exc.value.retryable is True
        assert exc.value.expected.sequence == 1
        assert exc.value.actual.sequence == 2
        assert exc.value.actual.digest == racing.foreign_captures[1].canonicalDigest
        assert any("chain_conflict_exhausted" in r.getMessage() for r in caplog.records)
        # Nothing of ours landed; the chain is the two foreign records, clean.
        await _assert_chain_clean(foreign, 2)
        # Exhaustion is not a wedge: the next capture links from the truth.
        assert (await _cap(ours, "ours-again")).sequenceNumber == 3
        await _assert_chain_clean(foreign, 3)
    finally:
        await ours.close()
        await foreign.close()


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "3"])
async def test_chain_conflict_max_attempts_is_validated(bad: Any, tmp_path: Any) -> None:
    with pytest.raises(ValueError, match="chain_conflict_max_attempts"):
        await Tzun.init(
            storage=SqliteAdapter(str(tmp_path / "bad.db"), mode="async"),
            chain_conflict_max_attempts=bad,
        )


class _CountsInFlightStores:
    """A REAL adapter that counts how many ``store()`` calls are in flight at
    once, and the highest that count ever reached.

    ``store()`` on the async SQLite adapter genuinely suspends (aiosqlite
    hands the write to a worker thread), so without a per-instance capture
    lock N concurrent captures would all be inside ``store()`` together and
    ``peak`` would climb past 1. With the lock it cannot: the head read, the
    build and the store of one capture finish before the next begins.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.in_flight = 0
        self.peak = 0
        self._guard = threading.Lock()  # the sync-wrapper test drives threads

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def store(self, envelope: Any, chain_id: Any = None, options: Any = None) -> None:
        with self._guard:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        try:
            # Widen the window: a store that returns before the next capture
            # can be scheduled would hide the race the lock exists to close.
            await asyncio.sleep(0.005)
            return await self._inner.store(envelope, chain_id, options)
        finally:
            with self._guard:
                self.in_flight -= 1


async def test_sqlite_one_instance_has_at_most_one_store_in_flight(
    tmp_path: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The per-instance serialisation TS `runCaptureExclusive()`
    gives, pinned: 20 concurrent captures on ONE instance are one append at a
    time. Without the lock `peak` reaches 20 here (every coroutine reads the
    same head and sits in `store()` together) and the CAS then refuses all
    but one per round: N-way contention."""
    counting = _CountsInFlightStores(SqliteAdapter(str(tmp_path / "one.db"), mode="async"))
    tzun = await Tzun.init(storage=counting)
    try:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            results = await asyncio.gather(*[_cap(tzun, f"c{i}") for i in range(20)])
        assert sorted(r.sequenceNumber for r in results) == list(range(1, 21))
        assert counting.peak == 1, f"{counting.peak} stores were in flight at once"
        # One writer, serialised: nothing to lose a CAS to, so nothing retried.
        assert _retries(caplog) == []
        await _assert_chain_clean(tzun, 20)
    finally:
        await tzun.close()


def test_sync_wrapper_serialises_captures_across_threads() -> None:
    """The sync mirror has its own path — one event loop per call, driven from
    whatever thread called it — so the inner ``asyncio.Lock`` cannot serialise
    it. ``TzunSync.capture`` holds a thread lock across the same section.
    Without it, threads either shared the critical section (`peak` > 1) or one
    of them parked on a future its loop never woke (the join below times
    out).

    ``MemoryAdapter`` on purpose: a ``sqlite3`` connection is bound to the
    thread that opened it, so the sync SQLite adapter cannot be driven from
    several threads whatever the SDK does, and the window this test needs is
    the wrapper's own await, not the adapter's."""
    counting = _CountsInFlightStores(MemoryAdapter())
    tzun = TzunSync.init(storage=counting)
    results: list[Any] = []
    errors: list[BaseException] = []

    def worker(label: str) -> None:
        try:
            results.append(tzun.capture(
                ai_output={"label": label}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason=label
            ))
        except BaseException as exc:  # collected for the assertion below
            errors.append(exc)

    try:
        threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not any(t.is_alive() for t in threads), "a capture never returned"
        assert errors == []
        assert sorted(r.sequenceNumber for r in results) == list(range(1, 9))
        assert counting.peak == 1, f"{counting.peak} stores were in flight at once"
    finally:
        tzun.close()


# ── Postgres (integration-gated) ──────────────────────────────────────────


@pytest.mark.integration
async def test_postgres_twenty_concurrent_captures_across_two_instances_all_land(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The measurement on the deployment shape: two pools, one database. A
    unique chain id isolates the run — the Python CAS and ``head()`` are both
    chain-scoped.

    The loser of a CAS learns it lost only after the winner commits, by which
    time the winner's next capture can already be queued on the append lock.
    ONE record could then be refused once per capture of the other instance's
    burst until its attempts ran out (``chain_conflict_exhausted``).
    ``capture()`` reads the head back before releasing its lock, which lets
    the loser's rebuild queue first, so the instances alternate and all 20
    land. Loop this: it must be green every run, not most."""
    from tzun_sdk.storage.postgres import PostgresAdapter

    dsn = os.environ.get(
        "DATABASE_URL",
        f"postgres://postgres:dev@{_PG_HOST}:55432/tzun_dev",
    )
    chain = f"two-writers-{uuid.uuid4().hex[:8]}"
    a = await Tzun.init(storage=PostgresAdapter(dsn, mode="async"), chain_id=chain)
    b = await Tzun.init(storage=PostgresAdapter(dsn, mode="async"), chain_id=chain)
    try:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            results = await asyncio.gather(
                *[_cap(a, f"a{i}") for i in range(10)],
                *[_cap(b, f"b{i}") for i in range(10)],
            )
        assert sorted(r.sequenceNumber for r in results) == list(range(1, 21))
        rows = await a._storage.list_by_sequence(chain_id=chain)
        assert [r.payload.sequenceNumber for r in rows] == list(range(1, 21))
        verdicts = await a.verify_range(1, 20)
        assert len(verdicts) == 20
        assert all(v.valid for v in verdicts)
        assert (await _cap(b, "after")).sequenceNumber == 21
        assert _retries(caplog), "expected at least one refused-and-retried append"
    finally:
        await a.close()
        await b.close()
