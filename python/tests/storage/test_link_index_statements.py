"""The link index marks a link record's statements, and a store opened with an index from before the mark is brought up.

``subject_digest`` is set on each link of a link record other than its
``subject`` link; ``list_links_to(statements=True)`` returns those rows only.
A SQLite store whose ``tzun_py_evidence_links`` has no ``subject_digest`` gets
the column, the marks on the rows it already holds, and the index over them.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from tzun_sdk import Tzun
from tzun_sdk.storage import SqliteAdapter

ALICE = {"kind": "human", "id": "acct:alice"}


async def _link_world(path: str) -> tuple[Any, Any, Any]:
    tzun = await Tzun.init(storage=SqliteAdapter(path, mode="async"))
    try:
        a = await tzun.capture(ai_output={"x": 1}, action="approve", reason="a", decider=ALICE)
        b = await tzun.capture(ai_output={"x": 2}, action="approve", reason="b", decider={"kind": "human", "id": "acct:carol"})
        statement = await tzun.links.relate(
            subject={"evidenceId": b.evidenceId},
            relations=[{"rel": "reviews", "target": {"evidenceId": a.evidenceId}}],
            reason="review",
            decider={"kind": "human", "id": "acct:bob"},
        )
    finally:
        await tzun.close()
    return a, b, statement


def _rows(path: str) -> list[tuple[Any, ...]]:
    con = sqlite3.connect(path)
    try:
        return con.execute(
            "SELECT evidence_id, idx, rel, target_digest, subject_digest FROM tzun_py_evidence_links ORDER BY evidence_id, idx"
        ).fetchall()
    finally:
        con.close()


async def test_statements_are_marked_and_listed_on_their_own(tmp_path: Any) -> None:
    path = str(tmp_path / "store.db")
    a, b, statement = await _link_world(path)
    assert (statement.evidenceId, 0, "reviews", a.canonicalDigest, b.canonicalDigest) in _rows(path)
    assert (statement.evidenceId, 1, "subject", b.canonicalDigest, None) in _rows(path)
    store = SqliteAdapter(path, mode="async")
    await store.ensure_tables()
    try:
        rows, _ = await store.list_links_to(a.canonicalDigest, statements=True)
        assert [(r.evidenceId, r.rel) for r in rows] == [(statement.evidenceId, "reviews")]
        subjects, _ = await store.list_links_to(b.canonicalDigest, statements=True)
        assert subjects == []
    finally:
        await store.close()


async def test_an_index_from_before_the_statement_mark_is_brought_up(tmp_path: Any) -> None:
    path = str(tmp_path / "store.db")
    a, b, statement = await _link_world(path)
    con = sqlite3.connect(path)
    con.executescript(
        """
        DROP INDEX IF EXISTS idx_tzun_py_evidence_links_statements;
        CREATE TABLE old_links AS SELECT evidence_id, idx, rel, target_digest FROM tzun_py_evidence_links;
        DROP TABLE tzun_py_evidence_links;
        CREATE TABLE tzun_py_evidence_links (
            evidence_id TEXT NOT NULL, idx INTEGER NOT NULL, rel TEXT NOT NULL, target_digest TEXT NOT NULL,
            PRIMARY KEY (evidence_id, idx));
        INSERT INTO tzun_py_evidence_links SELECT * FROM old_links;
        DROP TABLE old_links;
        """
    )
    con.commit()
    con.close()
    store = SqliteAdapter(path, mode="async")
    await store.ensure_tables()
    await store.close()
    assert (statement.evidenceId, 0, "reviews", a.canonicalDigest, b.canonicalDigest) in _rows(path)
    assert (statement.evidenceId, 1, "subject", b.canonicalDigest, None) in _rows(path)
    con = sqlite3.connect(path)
    try:
        indexes = {r[1] for r in con.execute("PRAGMA index_list(tzun_py_evidence_links)")}
        assert "idx_tzun_py_evidence_links_statements" in indexes
        envelope_indexes = {r[1] for r in con.execute("PRAGMA index_list(evidence_envelopes)")}
        assert "idx_evidence_envelopes_digest" in envelope_indexes
        plan = " ".join(
            str(r[-1])
            for r in con.execute(
                "EXPLAIN QUERY PLAN SELECT envelope_json FROM evidence_envelopes "
                "WHERE json_extract(envelope_json, '$.integrity.canonicalDigest') = ? ORDER BY rowid LIMIT 1",
                (a.canonicalDigest,),
            )
        )
        assert "idx_evidence_envelopes_digest" in plan
    finally:
        con.close()
