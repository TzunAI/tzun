"""The two SDKs must not fight over one table name.

The two SDKs' DDLs differ, and a shared advisory lock only serialises two
different CREATE TABLE scripts. `tamper_incidents` is the concrete case: the
TS adapter creates it with the engine's TamperIncident columns (id /
detected_at / severity / type / affected_records / details / status / ...);
the Python adapter's incident row has its own local shape (incident_id /
event_type / evidence_id / incident_json / detected_at). `CREATE TABLE IF NOT
EXISTS` is a silent no-op when the name is taken, so if both SDKs used that
name, whichever initialised second could not record tamper incidents at all,
with no error until the first incident. The Python adapter writes its
incidents to `tzun_py_tamper_incidents`.

SQLite reaches the same failure without a live Postgres server: the TS-shaped
table is created first, then the Python adapter initialises against the same
file and records an incident.
"""

from __future__ import annotations

import sqlite3

import pytest

from tzun_sdk.models import TamperIncident
from tzun_sdk.storage.sqlite import SqliteAdapter

# Byte-for-byte the TS adapter's tamper_incidents columns
# (src/storage/postgres.ts / src/storage/sqlite.ts), in SQLite spelling.
TS_TAMPER_INCIDENTS_DDL = """
CREATE TABLE IF NOT EXISTS tamper_incidents (
    id TEXT PRIMARY KEY,
    detected_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    type TEXT NOT NULL,
    affected_records TEXT NOT NULL,
    affected_sequence_range TEXT,
    details TEXT NOT NULL,
    status TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by TEXT,
    resolution_notes TEXT
)
"""


def _incident(incident_id: str = "inc-1") -> TamperIncident:
    return TamperIncident(
        incidentId=incident_id,
        eventType="digest_mismatch",
        evidenceId="ev-1",
        detectedAt="2026-09-02T00:00:00.000Z",
        details={"reason": "recomputed digest did not match"},
    )


@pytest.mark.asyncio
async def test_python_records_incidents_in_a_db_the_ts_sdk_initialised_first(tmp_path):
    db = str(tmp_path / "shared.db")
    conn = sqlite3.connect(db)
    conn.execute(TS_TAMPER_INCIDENTS_DDL)
    conn.commit()
    conn.close()

    adapter = SqliteAdapter(db, mode="sync")
    await adapter.ensure_tables()
    await adapter.store_incident(_incident())
    await adapter.close()

    conn = sqlite3.connect(db)
    try:
        # The Python row landed in its own table...
        rows = conn.execute(
            "SELECT incident_id, event_type FROM tzun_py_tamper_incidents"
        ).fetchall()
        assert rows == [("inc-1", "digest_mismatch")]
        # ...and the TS table is untouched and still its own shape.
        ts_cols = {r[1] for r in conn.execute("PRAGMA table_info(tamper_incidents)")}
        assert "severity" in ts_cols and "affected_records" in ts_cols
        assert conn.execute("SELECT COUNT(*) FROM tamper_incidents").fetchone()[0] == 0
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_storing_the_same_incident_twice_keeps_the_first(tmp_path):
    """A second store of the same incident id keeps the first write. The table
    is documented as append-only, so a replace would silently overwrite a
    stored incident. First write wins, matching the Postgres adapter's ON
    CONFLICT DO NOTHING."""
    adapter = SqliteAdapter(str(tmp_path / "incidents.db"), mode="sync")
    await adapter.ensure_tables()
    await adapter.store_incident(_incident())
    second = _incident()
    second = second.model_copy(update={"details": {"reason": "REWRITTEN"}})
    await adapter.store_incident(second)
    await adapter.close()

    conn = sqlite3.connect(str(tmp_path / "incidents.db"))
    try:
        rows = conn.execute(
            "SELECT incident_json FROM tzun_py_tamper_incidents"
        ).fetchall()
        assert len(rows) == 1
        assert "REWRITTEN" not in rows[0][0]
    finally:
        conn.close()


# ── envelope_revisions is deliberately SHARED, not namespaced ─────────
#
# `tzun_py_tamper_incidents` above is namespaced because the two SDKs hold
# DIFFERENT shapes under one name, which is a collision. The revision log is
# the opposite case: the columns are identical on both sides, so
# CREATE TABLE IF NOT EXISTS converges rather than silently no-opping into a
# broken adapter. Sharing is also what we want — the log's whole job is to
# remember what a record hashed to at capture, and two disjoint logs in one
# database would each be blind to half the evidence.
#
# The evidence tables stay disjoint (evidence_envelopes vs envelopes) and
# evidence ids are UUIDs, so the two record populations coexist in the rows
# without meeting.

# Byte-for-byte the TS adapter's envelope_revisions columns
# (src/storage/sqlite.ts), in the order it declares them.
TS_ENVELOPE_REVISIONS_DDL = """
CREATE TABLE IF NOT EXISTS envelope_revisions (
    evidence_id      TEXT NOT NULL,
    revision_no      INTEGER NOT NULL,
    canonical_digest TEXT NOT NULL,
    chain_link       TEXT,
    recorded_at      TEXT NOT NULL,
    cause            TEXT NOT NULL,
    actor            TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (evidence_id, revision_no)
)
"""


def _envelope(evidence_id: str = "shared-1"):
    from tzun_sdk.models import EvidenceEnvelope, EvidencePayload, IntegrityBlock

    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=evidence_id,
            schemaVersion="v1.0",
            aiSystemId="cross-sdk",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason="ok",
            capturedAt="2026-09-12T10:00:00.000Z",
            sequenceNumber=1,
        ),
        integrity=IntegrityBlock(canonicalDigest="a" * 64, chainLink=None),
    )


@pytest.mark.asyncio
async def test_python_writes_revision_0_into_a_table_the_ts_sdk_created(tmp_path):
    db = str(tmp_path / "shared-revisions.db")
    conn = sqlite3.connect(db)
    conn.execute(TS_ENVELOPE_REVISIONS_DDL)
    conn.commit()
    conn.close()

    adapter = SqliteAdapter(db, mode="sync")
    await adapter.ensure_tables()  # a no-op against the existing table
    await adapter.store(_envelope())
    rows = await adapter.list_envelope_revisions("shared-1")
    await adapter.close()

    assert [(r.revisionNo, r.canonicalDigest, r.cause) for r in rows] == [
        (0, "a" * 64, "capture")
    ]

    # And the row is readable by the exact query the TS adapter's
    # getCaptureDigests() issues — which is the point of sharing the name.
    conn = sqlite3.connect(db)
    try:
        got = conn.execute(
            "SELECT canonical_digest FROM envelope_revisions "
            "WHERE evidence_id = ? AND revision_no = ?",
            ("shared-1", 0),
        ).fetchone()
        assert got == ("a" * 64,)
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_the_python_revision_rows_are_append_only_in_sqlite(tmp_path):
    """UPDATE and DELETE are refused by the database, not merely unimplemented.

    This is the one Python table with immutability triggers. MIGRATION.md
    records, honestly, that the Python adapters install none anywhere else —
    but a revision log an insider can DELETE from restores exactly the silence
    the defence removes, so here they are not optional.
    """
    db = str(tmp_path / "append-only.db")
    adapter = SqliteAdapter(db, mode="sync")
    await adapter.ensure_tables()
    await adapter.store(_envelope("appendonly-1"))
    await adapter.close()

    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.DatabaseError, match=r"append-only \(DELETE refused\)"):
            conn.execute("DELETE FROM envelope_revisions WHERE evidence_id = ?", ("appendonly-1",))
        with pytest.raises(sqlite3.DatabaseError, match=r"append-only \(UPDATE refused\)"):
            conn.execute(
                "UPDATE envelope_revisions SET canonical_digest = ? WHERE evidence_id = ?",
                ("f" * 64, "appendonly-1"),
            )
        assert conn.execute(
            "SELECT canonical_digest FROM envelope_revisions WHERE evidence_id = ?",
            ("appendonly-1",),
        ).fetchall() == [("a" * 64,)]
    finally:
        conn.close()
