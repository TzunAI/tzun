"""Both SDKs guard the shared SQLite revision log with the same triggers.

``envelope_revisions`` is one table under one name in a database both SDKs
open (``python/tests/storage/test_cross_sdk_table_collision.py``), and each
creates its triggers with ``CREATE TRIGGER IF NOT EXISTS``: whichever SDK
opens the file first installs them, and the other's are skipped. So the two
sets must say the same thing, or a store's rules would depend on which SDK
opened it first. This compares the triggers a TypeScript-created store
carries with the ones the Python adapter creates, whitespace aside (the two
sources indent differently), and then checks that the TypeScript store's
guards refuse a REPLACE and a row at a negative rowid from a Python
connection.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import re
import sqlite3
import subprocess
from typing import Any

import pytest

from tzun_sdk.storage import SqliteAdapter

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LOG_STORE_HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "log-store.ts"


def _harness(cmd: dict[str, Any]) -> dict[str, Any]:
    proc = subprocess.run(
        ["npx", "tsx", str(LOG_STORE_HARNESS)],
        input=json.dumps(cmd),
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"log-store harness failed (exit {proc.returncode})\nstderr: {proc.stderr}")
    return json.loads(proc.stdout)


def _revision_triggers(path: pathlib.Path) -> dict[str, str]:
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'envelope_revisions'"
        ).fetchall()
    finally:
        conn.close()
    return {name: re.sub(r"\s+", " ", sql).strip() for name, sql in rows}


def test_the_revision_log_triggers_are_the_same_in_both_sdks(has_node: bool, tmp_path: pathlib.Path) -> None:
    if not has_node:
        pytest.skip("Node not available")
    ts_store = tmp_path / "ts.db"
    _harness({"action": "create-sqlite-store", "path": str(ts_store)})

    py_store = tmp_path / "py.db"
    adapter = SqliteAdapter(str(py_store), mode="sync")
    asyncio.run(adapter.ensure_tables())
    asyncio.run(adapter.close())

    ts_triggers = _revision_triggers(ts_store)
    assert sorted(ts_triggers) == [
        "envelope_revisions_block_delete",
        "envelope_revisions_block_negative_rowid",
        "envelope_revisions_block_replace",
        "envelope_revisions_block_update",
    ]
    assert _revision_triggers(py_store) == ts_triggers

    conn = sqlite3.connect(str(ts_store))
    try:
        row = ("shared-1", 0, "a" * 64, None, "2026-09-26T10:00:00.000Z", "capture", "py-writer")
        insert = (
            "INTO envelope_revisions (evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        conn.execute(f"INSERT {insert}", row)
        with pytest.raises(sqlite3.IntegrityError, match=r"\[tzun:duplicate_record\]"):
            conn.execute(f"INSERT OR REPLACE {insert}", (*row[:2], "f" * 64, *row[3:]))
        with pytest.raises(sqlite3.IntegrityError, match=r"rowid cannot be negative"):
            conn.execute(
                "INSERT INTO envelope_revisions (rowid, evidence_id, revision_no, canonical_digest, chain_link,"
                " recorded_at, cause, actor) VALUES (-1, ?, ?, ?, ?, ?, ?, ?)",
                ("shared-2", *row[1:]),
            )
        conn.rollback()
    finally:
        conn.close()
