"""A second ``store()`` of an ``evidenceId`` that is already stored is refused.

Every adapter raises :class:`~tzun_sdk.errors.DuplicateEvidenceError` with
the message the TypeScript adapters throw, checked inside the adapter's write
lock and BEFORE the chain-head compare-and-swap (the TS order), so a duplicate
is never misreported as a chain conflict and the original record is untouched:
``retrieve()``, ``list_by_sequence()``, ``list()`` and ``head()`` all still
return the original, exactly once. An adapter that accepted the second store
would overwrite evidence in place and list the id twice in the chain; one that
refused it with a raw driver error would leave callers a different exception
to catch on every backend.

Adapters exercised: ``MemoryAdapter``; ``SqliteAdapter`` in both its ``async``
(aiosqlite) and ``sync`` (stdlib sqlite3) modes on a file under ``tmp_path``;
``PostgresAdapter`` in both driver modes (asyncpg / psycopg), integration-gated
like ``test_postgres.py``.
"""

from __future__ import annotations

import os
import uuid

import pytest

from tzun_sdk.errors import ChainConflictError, DuplicateEvidenceError, TzunError
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

DB_URL = os.environ.get(
    "DATABASE_URL",
    f"postgres://postgres:dev@{_PG_HOST}:55432/tzun_dev",
)


def _envelope(
    evidence_id: str, seq: int = 1, digest_byte: int = 0x11, reason: str = "original"
) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=evidence_id,
            schemaVersion="v1.0",
            aiSystemId="test-sys",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason=reason,
            capturedAt="2026-01-01T00:00:00.000Z",
            sequenceNumber=seq,
        ),
        integrity=IntegrityBlock(
            canonicalDigest="sha256:" + f"{digest_byte:02x}" * 32,
            chainLink=None,
        ),
    )


def _fresh_ids() -> tuple[str, str]:
    """A chain id and an evidence id unique to one test run.

    Postgres runs against a shared, persistent database, so every test scopes
    its chain and its record by a fresh uuid rather than assuming an empty store.
    """
    return f"dup-{uuid.uuid4().hex[:8]}", f"e-{uuid.uuid4().hex[:12]}"


@pytest.fixture(
    params=[
        "memory",
        "sqlite-async",
        "sqlite-sync",
        pytest.param("postgres-async", marks=pytest.mark.integration),
        pytest.param("postgres-sync", marks=pytest.mark.integration),
    ]
)
async def adapter(request, tmp_path):
    """One connected adapter per parametrisation; closed afterwards."""
    kind = request.param
    if kind == "memory":
        a = MemoryAdapter()
    elif kind.startswith("sqlite"):
        mode = kind.split("-")[1]
        if mode == "async":
            pytest.importorskip("aiosqlite")
        a = SqliteAdapter(str(tmp_path / f"{kind}.db"), mode=mode)
    else:
        from tzun_sdk.storage.postgres import PostgresAdapter

        a = PostgresAdapter(DB_URL, mode=kind.split("-")[1])
    await a.ensure_tables()
    try:
        yield a
    finally:
        await a.close()


async def _records_with_id(adapter, evidence_id: str) -> list[EvidenceEnvelope]:
    # `list()` is store-wide and paged (default LIMIT 100 on the SQL adapters);
    # ask for everything so a record cannot hide behind the page boundary.
    return [
        e for e in await adapter.list(limit=1_000_000) if e.payload.evidenceId == evidence_id
    ]


async def test_second_store_of_same_id_is_refused_and_original_is_intact(adapter) -> None:
    chain, eid = _fresh_ids()
    original = _envelope(eid, seq=1, digest_byte=0x11, reason="original")
    rewrite = _envelope(eid, seq=1, digest_byte=0x22, reason="rewrite")
    await adapter.store(original, chain)

    with pytest.raises(DuplicateEvidenceError) as exc:
        await adapter.store(rewrite, chain)

    # Contract surface: base class, discriminator, id, TS-identical message.
    assert isinstance(exc.value, TzunError)
    assert exc.value.code == "evidence_id_conflict"
    assert exc.value.evidence_id == eid
    assert str(exc.value) == (
        f'Evidence record "{eid}" already exists. Storage is append-only.'
    )

    # Non-vacuity of state: the ORIGINAL record survives, exactly once, and the
    # head did not move: retrieve(), list_by_sequence(), list() and head() all
    # answer with the original record, never the rewrite.
    got = await adapter.retrieve(eid)
    assert got is not None
    assert got.payload.reason == "original"
    assert got.integrity.canonicalDigest == original.integrity.canonicalDigest

    by_seq = await adapter.list_by_sequence(chain_id=chain)
    assert [e.payload.evidenceId for e in by_seq] == [eid]
    assert by_seq[0].integrity.canonicalDigest == original.integrity.canonicalDigest

    listed = await _records_with_id(adapter, eid)
    assert len(listed) == 1
    assert listed[0].payload.reason == "original"

    head = await adapter.head(chain)
    assert head is not None
    assert head.payload.evidenceId == eid
    assert head.integrity.canonicalDigest == original.integrity.canonicalDigest


async def test_storing_the_identical_envelope_twice_is_refused(adapter) -> None:
    """A byte-identical replay is still a duplicate — there is no idempotent path."""
    chain, eid = _fresh_ids()
    env = _envelope(eid)
    await adapter.store(env, chain)

    with pytest.raises(DuplicateEvidenceError) as exc:
        await adapter.store(env, chain)

    assert exc.value.evidence_id == eid
    assert len(await adapter.list_by_sequence(chain_id=chain)) == 1
    assert len(await _records_with_id(adapter, eid)) == 1


async def test_duplicate_is_reported_before_a_stale_chain_head_expectation(adapter) -> None:
    """Precedence: the duplicate check runs before the compare-and-swap.

    A retried write that already landed will, by construction, carry the head
    expectation it was built against — which is now stale. It must be told
    "this record already exists", not "the head moved", because the two call
    for opposite recoveries (stop, versus rebuild-and-retry).
    """
    chain, eid = _fresh_ids()
    original = _envelope(eid, seq=1, digest_byte=0x11)
    await adapter.store(original, chain)

    with pytest.raises(DuplicateEvidenceError) as exc:
        await adapter.store(
            _envelope(eid, seq=1, digest_byte=0x22, reason="retry"),
            chain,
            StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None)),
        )

    assert not isinstance(exc.value, ChainConflictError)
    assert exc.value.code == "evidence_id_conflict"
    got = await adapter.retrieve(eid)
    assert got is not None
    assert got.integrity.canonicalDigest == original.integrity.canonicalDigest
    assert len(await adapter.list_by_sequence(chain_id=chain)) == 1


async def test_demo_delete_then_restore_of_the_same_bytes_is_accepted(
    adapter, monkeypatch
) -> None:
    """The demo's tamper-then-restore path must keep working.

    ``delete_envelope_for_demo()`` removes the record; storing the very same
    bytes again is then a first store of that id, not a duplicate.
    """
    monkeypatch.setenv("TZUN_ENABLE_DEMO_DELETE", "1")
    chain, eid = _fresh_ids()
    env = _envelope(eid)
    await adapter.store(env, chain)

    await adapter.delete_envelope_for_demo(eid)
    assert await adapter.retrieve(eid) is None

    await adapter.store(env, chain)  # must not raise

    got = await adapter.retrieve(eid)
    assert got is not None
    assert got.model_dump(mode="json") == env.model_dump(mode="json")
    assert [e.payload.evidenceId for e in await adapter.list_by_sequence(chain_id=chain)] == [
        eid
    ]
    assert len(await _records_with_id(adapter, eid)) == 1


# ── Postgres: the unique violation that slips past the pre-check ───────────


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["async", "sync"])
async def test_postgres_translates_a_unique_violation_the_precheck_missed(
    mode: str, monkeypatch
) -> None:
    """A writer that does not hold the append lock can insert the id between
    the pre-check and the INSERT. The primary key still refuses the row; the
    driver's ``23505`` must come back as the same ``DuplicateEvidenceError``
    the pre-check raises, not as the generic ``store failed`` wrapper.

    The race is reproduced deterministically by making the pre-check blind
    (``AND FALSE``) so the INSERT is what meets the existing row.
    """
    from tzun_sdk.storage.postgres import PostgresAdapter

    monkeypatch.setattr(
        PostgresAdapter,
        "_SELECT_EXISTING_SQL",
        PostgresAdapter._SELECT_EXISTING_SQL + " AND FALSE",
    )
    chain, eid = _fresh_ids()
    original = _envelope(eid, seq=1, digest_byte=0x11, reason="original")
    a = PostgresAdapter(DB_URL, mode=mode)
    await a.ensure_tables()
    try:
        await a.store(original, chain)
        with pytest.raises(DuplicateEvidenceError) as exc:
            await a.store(_envelope(eid, seq=1, digest_byte=0x22, reason="rewrite"), chain)

        assert exc.value.evidence_id == eid
        assert getattr(exc.value.__cause__, "sqlstate", None) == "23505"
        got = await a.retrieve(eid)
        assert got is not None
        assert got.payload.reason == "original"
        assert len(await a.list_by_sequence(chain_id=chain)) == 1
    finally:
        await a.close()


def test_unique_violation_translation_is_scoped_to_the_evidence_table() -> None:
    """Driver-shape unit test for the translation predicate (runs without a DB).

    asyncpg exposes ``sqlstate``/``table_name``/``constraint_name`` on the
    exception; psycopg exposes the latter two on ``exc.diag``. A 23505 on any
    other table, or any other sqlstate on this table, keeps its generic wrap.
    """
    from tzun_sdk.storage.postgres import _is_evidence_unique_violation

    class AsyncpgShaped(Exception):
        sqlstate = "23505"
        table_name = "evidence_envelopes"
        constraint_name = "evidence_envelopes_pkey"

    class _Diag:
        table_name = "evidence_envelopes"
        constraint_name = "evidence_envelopes_pkey"

    class PsycopgShaped(Exception):
        sqlstate = "23505"
        diag = _Diag()

    class OtherTable(Exception):
        sqlstate = "23505"
        table_name = "model_descriptors"
        constraint_name = "model_descriptors_pkey"

    class OtherState(Exception):
        sqlstate = "23503"
        table_name = "evidence_envelopes"
        constraint_name = "evidence_envelopes_pkey"

    class SameTableOtherConstraint(Exception):
        # A unique violation on the evidence table that is NOT the primary key
        # (a future `UNIQUE (chain_id, sequence_number)`): a sequence
        # collision, not a reused id. Translating it would tell the caller to
        # pick a new evidence id, which is the wrong cause.
        sqlstate = "23505"
        table_name = "evidence_envelopes"
        constraint_name = "evidence_envelopes_chain_id_sequence_number_key"

    class ConstraintOmitted(Exception):
        # Postgres always names the constraint on a 23505; a proxy or an older
        # driver might not. The table name is the fallback then, not a second
        # sufficient condition.
        sqlstate = "23505"
        table_name = "evidence_envelopes"
        constraint_name = None

    assert _is_evidence_unique_violation(AsyncpgShaped())
    assert _is_evidence_unique_violation(PsycopgShaped())
    assert _is_evidence_unique_violation(ConstraintOmitted())
    assert not _is_evidence_unique_violation(OtherTable())
    assert not _is_evidence_unique_violation(OtherState())
    assert not _is_evidence_unique_violation(SameTableOtherConstraint())
    assert not _is_evidence_unique_violation(RuntimeError("connection reset"))
