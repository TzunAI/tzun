"""The Python revision log against a LIVE Postgres.

What only a live database can prove: the DDL ``ensure_tables()`` issues
actually installs — the table, the partial covering index, and the two
append-only triggers — and the triggers actually fire. A trigger that was never
created refuses nothing, and nothing else in the system notices.

This is the ONE Python table with immutability triggers. ``MIGRATION.md``
records, honestly, that the Python adapters install none anywhere else; here
they are not optional, because a revision log an insider can DELETE from
restores exactly the silence the defence removes.

Gated: ``RUN_INTEGRATION_TESTS=true`` (the ``integration`` marker, per
conftest) AND ``DATABASE_URL`` naming ``tzun_sdk_rec_test``. The leg TRUNCATEs,
so it refuses any other database name — ``tzun_dev``, ``tzun_sdk_conf_test``
and ``tzun_sdk_w1_test`` belong to other lanes.

    RUN_INTEGRATION_TESTS=true \\
    DATABASE_URL=postgres://postgres:dev@172.17.0.1:55432/tzun_sdk_rec_test \\
    PYTHONPATH=$PWD/src python3 -m pytest -q tests/storage/test_revision_log_postgres.py
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

from tzun_sdk.models import EvidenceEnvelope, EvidencePayload, IntegrityBlock
from tzun_sdk.storage.postgres import PostgresAdapter

pytestmark = pytest.mark.integration

REC_DB = "tzun_sdk_rec_test"
DATABASE_URL = os.environ.get("DATABASE_URL", "")


def _url_names_rec_db(url: str) -> bool:
    try:
        return urlparse(url).path == f"/{REC_DB}"
    except ValueError:
        return False


def _envelope(evidence_id: str, digest: str, chain_link: str | None) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=evidence_id,
            schemaVersion="v1.0",
            aiSystemId="rec-test-py",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason="ok",
            capturedAt="2026-09-12T10:00:00.000Z",
            sequenceNumber=1,
        ),
        integrity=IntegrityBlock(canonicalDigest=digest, chainLink=chain_link),
    )


async def _wipe(url: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(dsn=url)
    try:
        async with conn.transaction():
            # The truncate trigger below is exactly what makes this bypass
            # necessary, and making it explicit is the point.
            await conn.execute("SET LOCAL session_replication_role = 'replica'")
            await conn.execute(
                "TRUNCATE evidence_envelopes, envelope_revisions RESTART IDENTITY CASCADE"
            )
    finally:
        await conn.close()


@pytest.fixture
async def adapter():
    if not _url_names_rec_db(DATABASE_URL):
        pytest.skip(f"DATABASE_URL must name /{REC_DB} to run this leg")
    a = PostgresAdapter(DATABASE_URL, mode="async")
    await a.ensure_tables()
    await _wipe(DATABASE_URL)
    yield a
    await a.close()


async def _conn():
    import asyncpg

    return await asyncpg.connect(dsn=DATABASE_URL)


@pytest.mark.anyio
async def test_ensure_tables_installs_the_table_index_and_append_only_triggers(adapter) -> None:
    conn = await _conn()
    try:
        cols = await conn.fetch(
            "SELECT column_name, is_nullable FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'envelope_revisions' "
            "ORDER BY column_name"
        )
        assert [r["column_name"] for r in cols] == [
            "actor",
            "canonical_digest",
            "cause",
            "chain_link",
            "created_at",
            "evidence_id",
            "recorded_at",
            "revision_no",
        ]
        nullable = {r["column_name"]: r["is_nullable"] for r in cols}
        # A genesis record has no link, and recording that as the string
        # 'null' is the mistake ModifiedLink.previousChainLink was corrected
        # for on the TS side.
        assert nullable["chain_link"] == "YES"
        assert nullable["canonical_digest"] == "NO"

        defs = "\n".join(
            r["indexdef"]
            for r in await conn.fetch(
                "SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() "
                "AND tablename = 'envelope_revisions'"
            )
        )
        assert "idx_envelope_revisions_capture" in defs
        assert "WHERE (revision_no = 0)" in defs

        triggers = await conn.fetch(
            "SELECT tgname FROM pg_trigger WHERE tgrelid = 'envelope_revisions'::regclass "
            "AND NOT tgisinternal ORDER BY tgname"
        )
        assert [r["tgname"] for r in triggers] == [
            "envelope_revisions_block_mutation_trigger",
            "envelope_revisions_block_truncate_trigger",
        ]

        # The function runs with its search_path pinned, as the TS adapter
        # creates it.
        config = await conn.fetchval(
            "SELECT proconfig FROM pg_proc WHERE oid = 'envelope_revisions_block_mutation()'::regprocedure"
        )
        assert config == ["search_path=pg_catalog, pg_temp"]
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_store_writes_revision_0_and_the_capture_probe_reads_it_back(adapter) -> None:
    envelope = _envelope("py-rev-1", "d" * 64, None)
    await adapter.store(envelope, "default")

    revisions = await adapter.list_envelope_revisions("py-rev-1")
    assert len(revisions) == 1
    row = revisions[0]
    assert (row.evidenceId, row.revisionNo, row.cause) == ("py-rev-1", 0, "capture")
    assert row.canonicalDigest == "d" * 64
    assert row.chainLink is None
    # recorded_at is TEXT on both sides, so the driver hands back a string on
    # every backend and the two SDKs stay comparable.
    assert isinstance(row.recordedAt, str) and row.recordedAt.endswith("Z")

    assert await adapter.get_capture_digests(["py-rev-1", "py-never"]) == {
        "py-rev-1": "d" * 64
    }


@pytest.mark.anyio
async def test_update_delete_and_truncate_are_all_refused_by_the_database(adapter) -> None:
    await adapter.store(_envelope("py-rev-2", "e" * 64, None), "default")
    conn = await _conn()
    try:
        for sql in (
            "UPDATE envelope_revisions SET canonical_digest = 'f' WHERE evidence_id = 'py-rev-2'",
            "DELETE FROM envelope_revisions WHERE evidence_id = 'py-rev-2'",
            # Row-level DELETE triggers do not fire on TRUNCATE; the
            # statement-level one is why the whole log cannot be emptied in
            # one statement.
            "TRUNCATE envelope_revisions",
        ):
            with pytest.raises(Exception, match="append-only"):
                await conn.execute(sql)
        rows = await conn.fetch(
            "SELECT canonical_digest FROM envelope_revisions WHERE evidence_id = 'py-rev-2'"
        )
        assert [r["canonical_digest"] for r in rows] == ["e" * 64]
    finally:
        await conn.close()
