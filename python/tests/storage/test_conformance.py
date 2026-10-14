"""Storage adapter conformance suite — the Python twin of
``tests/ts/storage-conformance/``.

One test per observable behaviour, named for the fact it asserts, parametrised
over every in-tree adapter: ``MemoryAdapter``, ``SqliteAdapter`` (async and
sync), and ``PostgresAdapter`` (async and sync, integration-marked and gated on
``DATABASE_URL`` naming ``tzun_sdk_conf_test``, because the leg TRUNCATEs
every table for isolation). Behaviour names mirror the TypeScript contract
where the concept exists in both SDKs, so the two matrices can be compared by
name.

Every adapter is asked the same questions, so an answer that depends on the
adapter fails here: ``list()`` pages at 100, ``head()`` is the highest
sequence number on the chain (MAX(sequence_number), not the last insert), a
read hands out a fresh object rather than the one the store holds, and a
duplicate evidenceId is refused. A memory double that answered any of these
differently would let a test pass on memory against behaviour the SQL
adapters do not have.

    RUN_INTEGRATION_TESTS=true \\
    DATABASE_URL=postgres://postgres:dev@172.17.0.1:55432/tzun_sdk_conf_test \\
    PYTHONPATH=$PWD/src python3 -m pytest -q tests/storage/test_conformance.py
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

from tests.storage.test_catalog_primitives import annotation_row, mvd
from tzun_sdk.errors import ChainConflictError, DuplicateEvidenceError, TzunError
from tzun_sdk.models import (
    ChainHead,
    EvidenceEnvelope,
    EvidencePayload,
    IntegrityBlock,
    StoreOptions,
)
from tzun_sdk.storage import MemoryAdapter, PostgresAdapter, SqliteAdapter

CONF_DB = "tzun_sdk_conf_test"
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Every adapter, every mode. The Postgres legs carry the integration marker so
# conftest.py auto-skips them unless RUN_INTEGRATION_TESTS=true.
ADAPTERS = [
    "memory",
    "sqlite-async",
    "sqlite-sync",
    pytest.param("postgres-async", marks=pytest.mark.integration),
    pytest.param("postgres-sync", marks=pytest.mark.integration),
]

# A payload string containing U+0000 captures on memory and SQLite and
# hard-fails on Postgres, whose jsonb cannot represent it. The intended remedy
# is validation at capture() time on every backend, outside this suite. Until
# capture() validates it, the adapter-level fact is pinned both ways: Postgres
# refuses (a customer sees this today) and the two local backends are
# EXPECTED-FAIL on the converged behaviour — strict, so the day an adapter
# starts refusing, the mark comes off and the asserted-divergence case below it
# is retired with it.
XFAIL_NUL_ACCEPTED = pytest.mark.xfail(
    strict=True,
    reason="memory and SQLite accept U+0000 in a payload string today; "
    "fix is capture-time validation on every backend",
)


def _url_names_conf_db(url: str) -> bool:
    try:
        return urlparse(url).path == f"/{CONF_DB}"
    except ValueError:
        return False


async def _wipe_postgres(url: str) -> None:
    """TRUNCATE every Python-SDK table so one case's residue cannot leak into
    the next. The TS adapter's append-only triggers block TRUNCATE on
    ``model_descriptors`` in a database both SDKs have initialised;
    ``session_replication_role = 'replica'`` is the same explicit,
    transaction-scoped bypass the TS test helpers use."""
    import asyncpg

    conn = await asyncpg.connect(dsn=url)
    try:
        async with conn.transaction():
            await conn.execute("SET LOCAL session_replication_role = 'replica'")
            await conn.execute(
                "TRUNCATE evidence_envelopes, attestations, recovery_records, "
                "tzun_py_tamper_incidents, envelope_revisions, "
                "model_descriptor_annotations, "
                "model_descriptor_aliases, model_descriptors, decider_openings, "
                "tzun_py_agent_descriptors, tzun_py_evidence_links, tzun_py_mandates, "
                "tzun_py_mandate_totals, tzun_py_mandate_events CASCADE"
            )
    finally:
        await conn.close()


@pytest.fixture(params=ADAPTERS)
async def adapter(request, tmp_path):
    kind: str = request.param
    if kind == "memory":
        a = MemoryAdapter()
    elif kind.startswith("sqlite-"):
        a = SqliteAdapter(str(tmp_path / f"{kind}.db"), mode=kind.split("-", 1)[1])
    else:
        if not _url_names_conf_db(DATABASE_URL):
            pytest.skip(f"DATABASE_URL must name /{CONF_DB} to run the Postgres leg")
        a = PostgresAdapter(DATABASE_URL, mode=kind.split("-", 1)[1])
    await a.ensure_tables()
    if kind.startswith("postgres-"):
        await _wipe_postgres(DATABASE_URL)
    yield a
    await a.close()


def env(evidence_id: str, seq: int = 1, *, reason: str = "ok", digest: str | None = None) -> EvidenceEnvelope:
    """A fresh envelope every call — the reference-isolation cases depend on it."""
    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=evidence_id,
            schemaVersion="v1.0",
            aiSystemId="conformance-system",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason=reason,
            capturedAt="2026-03-22T10:00:00.000Z",
            sequenceNumber=seq,
        ),
        integrity=IntegrityBlock(
            canonicalDigest=digest or ("sha256:" + evidence_id.encode().hex().ljust(64, "0")[:64]),
            chainLink=None,
        ),
    )


def ids(items: list[EvidenceEnvelope]) -> list[str]:
    return [e.payload.evidenceId for e in items]


# ── The append-only revision log ─────────────────────────────────────
#
# The defence itself is in the TypeScript SDK, which is the one with a recovery
# path: a record whose CURRENT canonicalDigest is not the one it was CAPTURED
# with was rewritten after capture, and relink() refuses over it. What has to
# be true HERE is that evidence captured through the Python SDK also gets its
# capture digest written down. A record with no revision 0 is unprovable, and
# unprovable is exactly the silence the rewrite-and-reseat attack needs — so a
# Python-captured record that never got a row would be a permanently
# undefended record in an otherwise defended store.


async def test_store_writes_revision_0_with_the_capture_digest_link_and_actor(adapter) -> None:
    e = env("rv-1")
    await adapter.store(e)
    revisions = await adapter.list_envelope_revisions("rv-1")
    assert len(revisions) == 1
    row = revisions[0]
    assert row.evidenceId == "rv-1"
    assert row.revisionNo == 0
    assert row.canonicalDigest == e.integrity.canonicalDigest
    assert row.cause == "capture"
    # Attributed to the capturing actor when there is one, and never to the
    # empty string — a row with a blank actor reads as "nobody".
    assert row.actor == "tzun-sdk"
    assert row.recordedAt.endswith("Z")


async def test_a_genesis_record_records_a_null_chain_link_not_the_string_null(adapter) -> None:
    await adapter.store(env("rv-2"))
    assert (await adapter.list_envelope_revisions("rv-2"))[0].chainLink is None


async def test_get_capture_digests_maps_the_ids_it_has_revision_0_for_and_omits_the_rest(adapter) -> None:
    e = env("rv-3")
    await adapter.store(e)
    digests = await adapter.get_capture_digests(["rv-3", "rv-never-stored"])
    assert digests["rv-3"] == e.integrity.canonicalDigest
    # ABSENT, not None: a record this store cannot speak for must not be
    # mistakable for one it is vouching for. Records written before the log
    # existed are exactly that case, and a verifier reading absence as "clean"
    # would hand every one of them a clean bill of health.
    assert "rv-never-stored" not in digests
    assert await adapter.get_capture_digests([]) == {}


async def test_list_envelope_revisions_is_empty_for_an_unknown_record(adapter) -> None:
    assert await adapter.list_envelope_revisions("rv-nope") == []


# ── Evidence round trip ─────────────────────────────────────────────────────


async def test_store_then_retrieve_returns_an_equal_envelope(adapter) -> None:
    e = env("rt-1")
    await adapter.store(e)
    assert await adapter.retrieve("rt-1") == e


async def test_retrieve_of_an_unknown_evidence_id_is_none(adapter) -> None:
    assert await adapter.retrieve("nope") is None


async def test_a_duplicate_evidence_id_is_refused_with_tzun_error(adapter) -> None:
    # Every adapter refuses with the same class — a DuplicateEvidenceError (a
    # TzunError with code "evidence_id_conflict") — and keeps the first
    # record, listed once in the chain, so a caller keeps one branch per
    # backend and a reused id cannot overwrite stored evidence.
    await adapter.store(env("dup-1", 1))
    with pytest.raises(DuplicateEvidenceError) as excinfo:
        await adapter.store(env("dup-1", 2, reason="SECOND WRITE"))
    assert excinfo.value.code == "evidence_id_conflict"
    assert excinfo.value.evidence_id == "dup-1"
    got = await adapter.retrieve("dup-1")
    assert got is not None and got.payload.sequenceNumber == 1
    assert len(await adapter.list_by_sequence()) == 1


# ── Reference isolation ──────────────────────────────────────────────


async def test_retrieve_returns_a_detached_copy(adapter) -> None:
    e = env("iso-1")
    expected = e.model_copy(deep=True)
    await adapter.store(e)
    first = await adapter.retrieve("iso-1")
    assert first is not None
    first.payload.reason = "TAMPERED"
    first.integrity.canonicalDigest = "sha256:" + "d" * 64
    first.payload.aiOutput["injected"] = True
    assert await adapter.retrieve("iso-1") == expected


async def test_two_retrieve_calls_return_distinct_objects(adapter) -> None:
    await adapter.store(env("iso-2"))
    a = await adapter.retrieve("iso-2")
    b = await adapter.retrieve("iso-2")
    assert a == b
    assert a is not b
    assert a.payload is not b.payload


async def test_store_keeps_no_reference_to_the_callers_object(adapter) -> None:
    e = env("iso-3")
    expected = e.model_copy(deep=True)
    await adapter.store(e)
    e.payload.reason = "CHANGED AFTER STORE"
    assert await adapter.retrieve("iso-3") == expected


async def test_list_list_by_sequence_and_head_return_detached_copies(adapter) -> None:
    e = env("iso-4")
    expected = e.model_copy(deep=True)
    await adapter.store(e)
    for read in (adapter.list, adapter.list_by_sequence):
        got = (await read())[0]
        got.payload.reason = "TAMPERED"
    head = await adapter.head()
    assert head is not None
    head.payload.reason = "TAMPERED"
    assert await adapter.retrieve("iso-4") == expected


# ── list(): a page across chains, ordered by sequence ────────────────


async def test_list_default_page_is_100_on_every_adapter(adapter) -> None:
    for seq in range(1, 151):
        await adapter.store(env(f"pg-{seq:03d}", seq))
    page = await adapter.list()
    assert len(page) == 100
    assert ids(page) == [f"pg-{seq:03d}" for seq in range(1, 101)]
    # The unpaged, chain-scoped read still sees everything.
    assert len(await adapter.list_by_sequence()) == 150


async def test_list_honours_limit_and_offset(adapter) -> None:
    for seq in range(1, 6):
        await adapter.store(env(f"l-{seq}", seq))
    assert ids(await adapter.list(limit=2)) == ["l-1", "l-2"]
    assert ids(await adapter.list(limit=2, offset=2)) == ["l-3", "l-4"]
    assert ids(await adapter.list(offset=4)) == ["l-5"]
    assert ids(await adapter.list(limit=0)) == []


async def test_list_orders_by_sequence_number_across_every_chain(adapter) -> None:
    await adapter.store(env("b-2", 2), "chain-b")
    await adapter.store(env("a-3", 3), "chain-a")
    await adapter.store(env("a-1", 1), "chain-a")
    listed = ids(await adapter.list())
    assert listed[0] == "a-1"
    assert listed[-1] == "a-3"
    assert sorted(listed) == ["a-1", "a-3", "b-2"]


# ── list_by_sequence(): chain-scoped, unpaged ───────────────────────────────


async def test_list_by_sequence_is_chain_scoped_and_none_means_the_default_chain(adapter) -> None:
    await adapter.store(env("a-1", 1), "chain-a")
    await adapter.store(env("a-2", 2), "chain-a")
    await adapter.store(env("b-1", 1), "chain-b")
    await adapter.store(env("d-1", 1))
    assert ids(await adapter.list_by_sequence(1, None, "chain-a")) == ["a-1", "a-2"]
    assert ids(await adapter.list_by_sequence(1, None, "chain-b")) == ["b-1"]
    assert ids(await adapter.list_by_sequence()) == ["d-1"]


async def test_list_by_sequence_honours_both_inclusive_bounds_and_defaults_the_lower_to_1(adapter) -> None:
    for seq in range(1, 6):
        await adapter.store(env(f"s-{seq}", seq))
    assert ids(await adapter.list_by_sequence(2, 4)) == ["s-2", "s-3", "s-4"]
    assert ids(await adapter.list_by_sequence(4)) == ["s-4", "s-5"]
    assert ids(await adapter.list_by_sequence()) == ["s-1", "s-2", "s-3", "s-4", "s-5"]


# ── head(): highest sequence on the chain ───────────────────────────────────


async def test_head_is_none_on_an_empty_chain_and_is_chain_scoped(adapter) -> None:
    assert await adapter.head() is None
    await adapter.store(env("h-a", 1), "chain-a")
    assert await adapter.head() is None
    assert (await adapter.head("chain-a")).payload.evidenceId == "h-a"


async def test_head_is_the_highest_sequence_on_the_chain_not_the_last_insert(adapter) -> None:
    # A post-fork replay writes a lower sequence AFTER a higher one. The head
    # is "f-2" (MAX), not "f-3" (insertion order), on every adapter.
    await adapter.store(env("f-1", 1))
    await adapter.store(env("f-2", 2))
    await adapter.store(env("f-3", 1))
    assert (await adapter.head()).payload.evidenceId == "f-2"


async def test_head_tie_on_an_equal_sequence_goes_to_the_later_insert(adapter) -> None:
    await adapter.store(env("t-first", 7))
    await adapter.store(env("t-second", 7))
    assert (await adapter.head()).payload.evidenceId == "t-second"


async def test_head_after_a_demo_delete_and_re_store_of_a_middle_record_is_still_the_highest_sequence(
    adapter, monkeypatch
) -> None:
    # The demo's delete-then-re-store of a middle record. The head stays
    # "e-3" (MAX(sequence_number)), not "e-2" (last appended), so a capture
    # after the re-store builds against the right head, and list_by_sequence()
    # keeps sequence order.
    monkeypatch.setenv("TZUN_ENABLE_DEMO_DELETE", "1")
    await adapter.store(env("e-1", 1))
    await adapter.store(env("e-2", 2))
    await adapter.store(env("e-3", 3))
    held = await adapter.retrieve("e-2")
    await adapter.delete_envelope_for_demo("e-2")
    assert await adapter.retrieve("e-2") is None
    await adapter.store(held)
    assert (await adapter.head()).payload.evidenceId == "e-3"
    assert ids(await adapter.list_by_sequence()) == ["e-1", "e-2", "e-3"]


# ── Chain-head compare-and-swap ─────────────────────────────────────────────


async def test_expect_chain_head_against_a_stale_head_is_refused_with_chain_conflict_error(adapter) -> None:
    await adapter.store(env("c-1", 1, digest="sha256:" + "11" * 32))
    with pytest.raises(ChainConflictError) as info:
        await adapter.store(
            env("c-2", 2),
            None,
            StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None)),
        )
    assert isinstance(info.value, TzunError)
    assert await adapter.retrieve("c-2") is None


async def test_expect_chain_head_that_matches_the_live_head_is_accepted(adapter) -> None:
    first = env("c-1", 1, digest="sha256:" + "11" * 32)
    await adapter.store(first)
    await adapter.store(
        env("c-2", 2),
        None,
        StoreOptions(expectChainHead=ChainHead(sequence=1, digest=first.integrity.canonicalDigest)),
    )
    assert (await adapter.head()).payload.evidenceId == "c-2"


async def test_an_empty_chain_expectation_against_an_empty_chain_is_accepted(adapter) -> None:
    await adapter.store(env("c-1", 1), None, StoreOptions(expectChainHead=ChainHead(sequence=0, digest=None)))
    assert await adapter.retrieve("c-1") is not None


# ── Catalog ─────────────────────────────────────────────────────────────────


async def test_register_descriptor_is_idempotent_and_get_descriptor_round_trips(adapter) -> None:
    d1 = await adapter.register_descriptor(mvd("conf-model"))
    d2 = await adapter.register_descriptor(mvd("conf-model"))
    assert d1 == d2 and d1.startswith("sha256:")
    got = await adapter.get_descriptor(d1)
    assert got is not None and got.modelName == "conf-model"
    assert await adapter.get_descriptor("sha256:" + "0" * 64) is None


async def test_get_descriptor_returns_a_detached_copy(adapter) -> None:
    d = await adapter.register_descriptor(mvd("conf-model"))
    first = await adapter.get_descriptor(d)
    first.modelName = "TAMPERED"
    assert (await adapter.get_descriptor(d)).modelName == "conf-model"


async def test_annotation_for_a_descriptor_that_was_never_registered_is_refused(adapter) -> None:
    orphan = "sha256:" + "0" * 64
    with pytest.raises(TzunError):
        await adapter.append_model_descriptor_annotation(annotation_row(orphan, annotationId="orphan-1"))
    assert await adapter.list_model_descriptor_annotations(orphan) == []


async def test_a_duplicate_annotation_id_is_refused(adapter) -> None:
    d = await adapter.register_descriptor(mvd("conf-model"))
    await adapter.append_model_descriptor_annotation(annotation_row(d, annotationId="dup-a"))
    with pytest.raises(TzunError):
        await adapter.append_model_descriptor_annotation(
            annotation_row(d, annotationId="dup-a", valueJson='{"second": true}')
        )
    rows = await adapter.list_model_descriptor_annotations(d)
    assert [r.valueJson for r in rows] == ['{"text": "looks right"}']


async def test_annotations_list_in_annotated_at_then_id_order_not_insertion(adapter) -> None:
    d = await adapter.register_descriptor(mvd("conf-model"))
    await adapter.append_model_descriptor_annotation(annotation_row(d, annotationId="an-c", annotatedAt="2026-05-03T00:00:00.000Z"))
    await adapter.append_model_descriptor_annotation(annotation_row(d, annotationId="an-a", annotatedAt="2026-05-01T00:00:00.000Z"))
    await adapter.append_model_descriptor_annotation(annotation_row(d, annotationId="an-b2", annotatedAt="2026-05-02T00:00:00.000Z"))
    await adapter.append_model_descriptor_annotation(annotation_row(d, annotationId="an-b1", annotatedAt="2026-05-02T00:00:00.000Z"))
    rows = await adapter.list_model_descriptor_annotations(d)
    assert [r.annotationId for r in rows] == ["an-a", "an-b1", "an-b2", "an-c"]


async def test_list_model_descriptor_annotations_returns_detached_copies(adapter) -> None:
    d = await adapter.register_descriptor(mvd("conf-model"))
    await adapter.append_model_descriptor_annotation(annotation_row(d, annotationId="iso-a"))
    (await adapter.list_model_descriptor_annotations(d))[0].valueJson = "{}"
    assert (await adapter.list_model_descriptor_annotations(d))[0].valueJson == '{"text": "looks right"}'


async def test_alias_resolves_to_the_latest_binding_and_a_same_instant_rebind_is_last_writer_wins(adapter, monkeypatch) -> None:
    d1 = await adapter.register_descriptor(mvd("m", "1"))
    d2 = await adapter.register_descriptor(mvd("m", "2"))
    assert await adapter.resolve_model_descriptor_alias("missing") is None
    # Force the millisecond collision on the adapters that stamp set_at from
    # `_utcnow_iso` (memory, SQLite, Postgres-sync). Postgres-async stamps a
    # datetime; two rapid binds there differ by microseconds and the assertion
    # below holds by ordinary latest-wins.
    frozen = "2026-05-01T10:00:00.000Z"
    for module in ("tzun_sdk.storage.memory", "tzun_sdk.storage.sqlite", "tzun_sdk.storage.postgres"):
        monkeypatch.setattr(f"{module}._utcnow_iso", lambda: frozen)
    await adapter.set_model_descriptor_alias("prod", d1, "ops")
    await adapter.set_model_descriptor_alias("prod", d2, "ops")
    assert await adapter.resolve_model_descriptor_alias("prod") == d2
    monkeypatch.undo()
    await adapter.set_model_descriptor_alias("prod", d1, "ops")
    assert await adapter.resolve_model_descriptor_alias("prod") == d1


# ── Demo hook gate ──────────────────────────────────────────────────────────


async def test_delete_envelope_for_demo_is_refused_unless_the_env_gate_is_set(adapter, monkeypatch) -> None:
    await adapter.store(env("demo-1"))
    monkeypatch.delenv("TZUN_ENABLE_DEMO_DELETE", raising=False)
    with pytest.raises(TzunError):
        await adapter.delete_envelope_for_demo("demo-1")
    assert await adapter.retrieve("demo-1") is not None
    monkeypatch.setenv("TZUN_ENABLE_DEMO_DELETE", "1")
    await adapter.delete_envelope_for_demo("demo-1")
    assert await adapter.retrieve("demo-1") is None


# ── Payload round-tripping: what JSON storage does to U+0000 ─────────

NUL = "before\x00after"


@pytest.mark.parametrize(
    "adapter",
    [
        pytest.param("memory", marks=XFAIL_NUL_ACCEPTED),
        pytest.param("sqlite-async", marks=XFAIL_NUL_ACCEPTED),
        pytest.param("sqlite-sync", marks=XFAIL_NUL_ACCEPTED),
        pytest.param("postgres-async", marks=pytest.mark.integration),
        pytest.param("postgres-sync", marks=pytest.mark.integration),
    ],
    indirect=True,
)
async def test_a_payload_string_containing_u0000_is_refused_by_the_store(adapter) -> None:
    with pytest.raises(TzunError):
        await adapter.store(env("nul-1", reason=NUL))
    assert await adapter.retrieve("nul-1") is None


@pytest.mark.parametrize("adapter", ["memory", "sqlite-async", "sqlite-sync"], indirect=True)
async def test_asserted_divergence_a_payload_string_containing_u0000_round_trips_on_memory_and_sqlite(
    adapter,
) -> None:
    # A documented difference that silently disappears is as much a drift as
    # one that appears: retire this with the xfail above when capture-time validation lands.
    await adapter.store(env("nul-2", reason=NUL))
    assert (await adapter.retrieve("nul-2")).payload.reason == NUL
