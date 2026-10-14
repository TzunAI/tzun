"""On SQLite, an insert never replaces a revision-log row.

SQLite's REPLACE conflict resolution (``INSERT OR REPLACE``, ``REPLACE INTO``)
deletes the row an insert conflicts with and then inserts. That delete fires a
DELETE trigger only under ``recursive_triggers``, and no UPDATE trigger fires
at all, so the triggers that refuse UPDATE and DELETE on ``envelope_revisions``
do not by themselves stop a writer holding the file from reseating a record's
capture revision. ``envelope_revisions_block_replace`` is a BEFORE INSERT
guard, run before conflict handling, that refuses an insert naming an
``(evidence_id, revision_no)`` or a rowid a row already holds, whatever the
conflict clause. The TypeScript adapter installs the same trigger on the same
shared table (``tests/cross-sdk/test_sqlite_revision_guard_parity.py``).

The guard reads ``NEW.rowid`` as -1 for an insert that names no rowid, so a
row planted at rowid -1 would make every later insert collide with it.
``envelope_revisions_block_negative_rowid`` refuses a negative rowid AFTER
INSERT, where ``NEW.rowid`` is the value written.

``envelope_revisions`` is the one table of this adapter with append-only
triggers (``python/MIGRATION.md``), so it is the one guarded here.

Each case depends on its guard: without the two guards the REPLACE and rowid
cases go through, the other conflict clauses meet the primary key or are
skipped instead of meeting the guard, and a row planted at rowid -1 is
accepted.
"""

from __future__ import annotations

import sqlite3

import pytest

from tzun_sdk.models import EvidenceEnvelope, EvidencePayload, IntegrityBlock
from tzun_sdk.storage import SqliteAdapter

GUARDED = r"INSERT over an existing row refused"

COLUMNS = ("evidence_id", "revision_no", "canonical_digest", "chain_link", "recorded_at", "cause", "actor")
_COLS = ", ".join(COLUMNS)
_MARKS = ", ".join("?" for _ in COLUMNS)

#: The ways an INSERT can meet an existing key. The first two replace the row;
#: the rest would otherwise fail on the key or be skipped, and are refused by
#: the guard all the same, so no conflict clause is a way past it.
EVERY_CLAUSE = {
    "INSERT OR REPLACE": f"INSERT OR REPLACE INTO envelope_revisions ({_COLS}) VALUES ({_MARKS})",
    "REPLACE INTO": f"REPLACE INTO envelope_revisions ({_COLS}) VALUES ({_MARKS})",
    "INSERT OR IGNORE": f"INSERT OR IGNORE INTO envelope_revisions ({_COLS}) VALUES ({_MARKS})",
    "INSERT OR FAIL": f"INSERT OR FAIL INTO envelope_revisions ({_COLS}) VALUES ({_MARKS})",
    "plain INSERT": f"INSERT INTO envelope_revisions ({_COLS}) VALUES ({_MARKS})",
    "ON CONFLICT DO NOTHING": (
        f"INSERT INTO envelope_revisions ({_COLS}) VALUES ({_MARKS}) ON CONFLICT DO NOTHING"
    ),
}


def _envelope(evidence_id: str, digest: str = "a" * 64, reason: str = "original") -> EvidenceEnvelope:
    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=evidence_id,
            schemaVersion="v1.0",
            aiSystemId="guard-test",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason=reason,
            capturedAt="2026-09-26T10:00:00.000Z",
            sequenceNumber=1,
        ),
        integrity=IntegrityBlock(canonicalDigest=digest, chainLink=None),
    )


async def _store_one(path: str) -> None:
    adapter = SqliteAdapter(path, mode="sync")
    await adapter.ensure_tables()
    await adapter.store(_envelope("ev-1"))
    await adapter.close()


def _revisions(conn: sqlite3.Connection) -> list[tuple]:
    return conn.execute(
        f"SELECT rowid, {_COLS} FROM envelope_revisions ORDER BY rowid"
    ).fetchall()


@pytest.mark.asyncio
@pytest.mark.parametrize("verb", ["INSERT OR REPLACE INTO", "REPLACE INTO"])
async def test_replace_cannot_reseat_a_capture_revision(tmp_path, verb: str) -> None:
    db = str(tmp_path / "reseat.db")
    await _store_one(db)
    conn = sqlite3.connect(db)
    try:
        before = _revisions(conn)
        row = conn.execute(
            f"SELECT {_COLS} FROM envelope_revisions WHERE evidence_id = 'ev-1' AND revision_no = 0"
        ).fetchone()
        reseated = (row[0], row[1], "f" * 64, *row[3:])
        with pytest.raises(sqlite3.IntegrityError, match=GUARDED):
            conn.execute(f"{verb} envelope_revisions ({_COLS}) VALUES ({_MARKS})", reseated)
        conn.rollback()
        assert _revisions(conn) == before
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_replace_cannot_delete_a_capture_revision_by_naming_its_rowid(tmp_path) -> None:
    db = str(tmp_path / "rowid.db")
    await _store_one(db)
    conn = sqlite3.connect(db)
    try:
        before = _revisions(conn)
        (victim,) = conn.execute(
            "SELECT rowid FROM envelope_revisions WHERE evidence_id = 'ev-1' AND revision_no = 0"
        ).fetchone()
        with pytest.raises(sqlite3.IntegrityError, match=GUARDED):
            conn.execute(
                f"INSERT OR REPLACE INTO envelope_revisions (rowid, {_COLS}) VALUES (?, {_MARKS})",
                (victim, "ev-unrelated", 0, "b" * 64, None, "2026-09-26T12:00:00.000Z", "capture", "mallory"),
            )
        conn.rollback()
        assert _revisions(conn) == before
    finally:
        conn.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("clause", sorted(EVERY_CLAUSE))
async def test_every_conflict_clause_over_an_existing_key_is_refused_by_the_guard(tmp_path, clause: str) -> None:
    db = str(tmp_path / "clauses.db")
    await _store_one(db)
    conn = sqlite3.connect(db)
    try:
        before = _revisions(conn)
        row = conn.execute(
            f"SELECT {_COLS} FROM envelope_revisions WHERE evidence_id = 'ev-1' AND revision_no = 0"
        ).fetchone()
        with pytest.raises(sqlite3.IntegrityError, match=GUARDED):
            conn.execute(EVERY_CLAUSE[clause], row)
        conn.rollback()
        assert _revisions(conn) == before
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_a_row_at_a_negative_rowid_is_refused_and_the_next_capture_goes_through(tmp_path) -> None:
    db = str(tmp_path / "negative.db")
    await _store_one(db)
    conn = sqlite3.connect(db)
    try:
        before = _revisions(conn)
        with pytest.raises(sqlite3.IntegrityError, match=r"rowid cannot be negative"):
            conn.execute(
                f"INSERT INTO envelope_revisions (rowid, {_COLS}) VALUES (-1, {_MARKS})",
                ("ghost", 0, "b" * 64, None, "2026-09-26T12:00:00.000Z", "capture", "mallory"),
            )
        conn.rollback()
        assert _revisions(conn) == before
    finally:
        conn.close()

    # A plant at -1 would have collided with this capture's revision insert,
    # which names no rowid.
    adapter = SqliteAdapter(db, mode="sync")
    await adapter.ensure_tables()
    try:
        await adapter.store(_envelope("ev-2", digest="d" * 64))
        rows = await adapter.list_envelope_revisions("ev-2")
        assert [(r.revisionNo, r.canonicalDigest) for r in rows] == [(0, "d" * 64)]
    finally:
        await adapter.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_a_record_deleted_and_re_stored_keeps_its_capture_revision(tmp_path, monkeypatch, mode: str) -> None:
    """The adapter's own capture write skips an existing revision 0.

    The guard refuses ``ON CONFLICT DO NOTHING`` over an existing key, so the
    adapter writes the row only where none exists. A record deleted and
    re-stored keeps its original capture revision.
    """
    monkeypatch.setenv("TZUN_ENABLE_DEMO_DELETE", "1")
    adapter = SqliteAdapter(str(tmp_path / f"restore-{mode}.db"), mode=mode)
    await adapter.ensure_tables()
    try:
        await adapter.store(_envelope("ev-1"))
        await adapter.delete_envelope_for_demo("ev-1")
        await adapter.store(_envelope("ev-1", digest="c" * 64, reason="tampered"))

        stored = await adapter.retrieve("ev-1")
        assert stored is not None and stored.integrity.canonicalDigest == "c" * 64
        rows = await adapter.list_envelope_revisions("ev-1")
        assert [(r.revisionNo, r.canonicalDigest, r.cause) for r in rows] == [(0, "a" * 64, "capture")]
    finally:
        await adapter.close()


@pytest.mark.asyncio
async def test_a_store_without_the_guards_gets_them_from_ensure_tables(tmp_path) -> None:
    db = str(tmp_path / "older.db")
    await _store_one(db)
    conn = sqlite3.connect(db)
    conn.execute("DROP TRIGGER envelope_revisions_block_replace")
    conn.execute("DROP TRIGGER envelope_revisions_block_negative_rowid")
    conn.commit()
    conn.close()

    adapter = SqliteAdapter(db, mode="sync")
    await adapter.ensure_tables()
    await adapter.close()

    conn = sqlite3.connect(db)
    try:
        assert conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'envelope_revisions' ORDER BY name"
        ).fetchall() == [
            ("envelope_revisions_block_delete",),
            ("envelope_revisions_block_negative_rowid",),
            ("envelope_revisions_block_replace",),
            ("envelope_revisions_block_update",),
        ]
    finally:
        conn.close()
