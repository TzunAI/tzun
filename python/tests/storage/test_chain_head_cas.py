"""Cross-process chain compare-and-swap — TS parity for `StoreOptions.expectChainHead`.

`Tzun.capture()` reserves a sequence number and computes a chain link from the
head it read, then hashes BOTH into the record's digest. `_sequence_lock`
serialises that read-build-write inside one process. It cannot see a second
process — or a second `Tzun` instance on the same database file — so two
writers can each read the same head and each link to it. If both rows landed
at the same sequence number, every later verifier would report a chain break
on evidence nobody tampered with.

Python applies the same compare-and-swap the TypeScript adapters apply
(`src/storage/chain-head-guard.ts`): the head is re-read and compared inside
whatever makes the adapter's write atomic — the memory adapter's chain lock,
SQLite's `BEGIN IMMEDIATE`, the Postgres advisory-lock transaction. A
conditional append whose expected head is not the live head raises
`ChainConflictError` and writes nothing.
"""

from __future__ import annotations

import os
import uuid

import pytest

from tzun_sdk import Tzun
from tzun_sdk.errors import ChainConflictError
from tzun_sdk.models import (
    ChainHead,
    EvidenceEnvelope,
    EvidencePayload,
    IntegrityBlock,
    StoreOptions,
)
from tzun_sdk.storage import MemoryAdapter, SqliteAdapter

# The local Postgres container.
_PG_HOST = "host.docker.internal"


def _envelope(seq: int, digest_byte: int = 0xAB) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=f"e-{uuid.uuid4().hex[:12]}",
            schemaVersion="v1.0",
            aiSystemId="test-sys",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason="ok",
            capturedAt="2026-01-01T00:00:00.000Z",
            sequenceNumber=seq,
        ),
        integrity=IntegrityBlock(
            canonicalDigest="sha256:" + f"{digest_byte:02x}" * 32,
            chainLink=None,
        ),
    )


# ── Memory adapter ────────────────────────────────────────────────────────


async def test_memory_conditional_append_refused_when_head_moved() -> None:
    adapter = MemoryAdapter()
    first = _envelope(1, 0x11)
    await adapter.store(first)

    # A writer that still believes the chain is empty.
    stale = _envelope(1, 0x22)
    with pytest.raises(ChainConflictError) as exc:
        await adapter.store(
            stale, None, StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None))
        )

    assert exc.value.code == "chain_conflict"
    assert exc.value.expected.sequence == 0
    assert exc.value.actual.sequence == 1
    assert exc.value.actual.digest == first.integrity.canonicalDigest
    # Non-vacuity: the refused record must NOT be in the store.
    assert await adapter.retrieve(stale.payload.evidenceId) is None
    assert len(await adapter.list_by_sequence()) == 1


async def test_memory_conditional_append_accepted_on_matching_head() -> None:
    adapter = MemoryAdapter()
    first = _envelope(1, 0x11)
    await adapter.store(
        first, None, StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None))
    )
    second = _envelope(2, 0x22)
    await adapter.store(
        second,
        None,
        StoreOptions(
            expectChainHead=ChainHead(sequence=1, digest=first.integrity.canonicalDigest)
        ),
    )
    assert len(await adapter.list_by_sequence()) == 2


async def test_memory_unconditional_store_still_writes() -> None:
    """`store()` stays a low-level primitive when no expectation is given."""
    adapter = MemoryAdapter()
    await adapter.store(_envelope(1, 0x11))
    await adapter.store(_envelope(1, 0x22))  # same sequence, no CAS: allowed
    assert len(await adapter.list_by_sequence()) == 2


# ── SQLite: the two-connection (two-process proxy) case ───────────────────


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_sqlite_cas_refuses_append_from_a_second_connection(
    mode: str, tmp_path
) -> None:
    """Two adapters on ONE file: the losing writer's conditional append fails.

    Two `SqliteAdapter` objects on the same path hold two independent SQLite
    connections — the same isolation a second OS process has. Writer A reads an
    empty head; writer B appends; writer A's conditional store must be refused
    rather than land a second row at sequence 1.
    """
    db = str(tmp_path / "cas.db")
    writer_a = SqliteAdapter(db, mode=mode)
    writer_b = SqliteAdapter(db, mode=mode)
    await writer_a.ensure_tables()
    await writer_b.ensure_tables()
    try:
        # A observes an empty chain.
        head_seen_by_a = await writer_a.head()
        assert head_seen_by_a is None

        # B gets there first.
        b_record = _envelope(1, 0xB0)
        await writer_b.store(
            b_record, None, StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None))
        )

        # A now writes the record it built against the head it saw.
        a_record = _envelope(1, 0xA0)
        with pytest.raises(ChainConflictError) as exc:
            await writer_a.store(
                a_record,
                None,
                StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None)),
            )
        assert exc.value.actual.digest == b_record.integrity.canonicalDigest

        # Non-vacuity: exactly one record at sequence 1, and it is B's.
        rows = await writer_b.list_by_sequence()
        assert [r.payload.evidenceId for r in rows] == [b_record.payload.evidenceId]
        assert await writer_a.retrieve(a_record.payload.evidenceId) is None
    finally:
        await writer_a.close()
        await writer_b.close()


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_sqlite_cas_accepts_the_live_head(mode: str, tmp_path) -> None:
    db = str(tmp_path / "cas-ok.db")
    adapter = SqliteAdapter(db, mode=mode)
    await adapter.ensure_tables()
    try:
        first = _envelope(1, 0x11)
        await adapter.store(
            first, None, StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None))
        )
        second = _envelope(2, 0x22)
        await adapter.store(
            second,
            None,
            StoreOptions(
                expectChainHead=ChainHead(
                    sequence=1, digest=first.integrity.canonicalDigest
                )
            ),
        )
        assert len(await adapter.list_by_sequence()) == 2
    finally:
        await adapter.close()


@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_sqlite_refused_append_leaves_no_partial_transaction(
    mode: str, tmp_path
) -> None:
    """A conflict must roll back cleanly — the adapter stays usable afterwards."""
    db = str(tmp_path / "cas-rollback.db")
    adapter = SqliteAdapter(db, mode=mode)
    await adapter.ensure_tables()
    try:
        first = _envelope(1, 0x11)
        await adapter.store(first)
        with pytest.raises(ChainConflictError):
            await adapter.store(
                _envelope(1, 0x22),
                None,
                StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None)),
            )
        # The connection is not wedged in an aborted transaction.
        third = _envelope(2, 0x33)
        await adapter.store(
            third,
            None,
            StoreOptions(
                expectChainHead=ChainHead(
                    sequence=1, digest=first.integrity.canonicalDigest
                )
            ),
        )
        assert len(await adapter.list_by_sequence()) == 2
    finally:
        await adapter.close()


# ── The end-to-end case: two Tzun instances, one chain ────────────────────


async def test_two_tzun_instances_on_one_database_cannot_fork_the_chain(
    tmp_path,
) -> None:
    """Two SDK instances on one SQLite file: every capture lands, no fork.

    Each `Tzun` has its own `_sequence_lock` and its own `_sequence_counter`,
    so neither can see the other. Both init against an empty chain. Without the
    CAS both would reserve sequence 1 and link from `None`, leaving two
    sequence-1 records linked to the same (absent) predecessor — an
    unrecoverable fork produced by ordinary concurrent use, indistinguishable
    from tampering to every later verifier.

    The adapter refuses a record built against a stale head, and `capture()`
    retries a refused append against the head it lost to (bounded by
    `chain_conflict_max_attempts`), so `b`'s first capture links to `a`'s
    record and lands at 2: no fork and no lost decision.
    test_two_writers_retry.py measures the two-writer case in full, including
    writers that alternate.
    """
    db = str(tmp_path / "two-writers.db")
    a = await Tzun.init(storage=SqliteAdapter(db, mode="async"))
    b = await Tzun.init(storage=SqliteAdapter(db, mode="async"))
    try:
        await a.capture(
            ai_output={"score": 1}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="a"
        )
        # `b` initialised before `a` wrote. It reads the live head, links to
        # `a`'s record, and lands at 2 — no fork, no lost decision.
        result = await b.capture(
            ai_output={"score": 2}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="b"
        )
        assert result.sequenceNumber == 2

        # Non-vacuity: exactly two records, 1 then 2, and nothing duplicated.
        rows = await a._storage.list_by_sequence()
        assert [r.payload.sequenceNumber for r in rows] == [1, 2]

        # And `b`'s view stays current: its next capture lands at 3.
        result = await b.capture(
            ai_output={"score": 3}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason="b2"
        )
        assert result.sequenceNumber == 3
        rows = await a._storage.list_by_sequence()
        assert [r.payload.sequenceNumber for r in rows] == [1, 2, 3]
        # Every record past genesis links to the record actually before it.
        for row in rows[1:]:
            assert row.integrity.chainLink is not None
            verdict = await a.verify(row.payload.evidenceId)
            assert verdict.valid is True
    finally:
        await a.close()
        await b.close()


# ── Postgres (integration-gated) ──────────────────────────────────────────


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_postgres_cas_refuses_append_from_a_second_pool(mode: str) -> None:
    from tzun_sdk.storage.postgres import PostgresAdapter

    dsn = os.environ.get(
        "DATABASE_URL",
        f"postgres://postgres:dev@{_PG_HOST}:55432/tzun_dev",
    )
    chain = f"cas-{uuid.uuid4().hex[:8]}"
    writer_a = PostgresAdapter(dsn, mode=mode)
    writer_b = PostgresAdapter(dsn, mode=mode)
    await writer_a.ensure_tables()
    try:
        b_record = _envelope(1, 0xB0)
        await writer_b.store(
            b_record, chain, StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None))
        )
        with pytest.raises(ChainConflictError):
            await writer_a.store(
                _envelope(1, 0xA0),
                chain,
                StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None)),
            )
        rows = await writer_b.list_by_sequence(chain_id=chain)
        assert [r.payload.evidenceId for r in rows] == [b_record.payload.evidenceId]
    finally:
        await writer_a.close()
        await writer_b.close()
