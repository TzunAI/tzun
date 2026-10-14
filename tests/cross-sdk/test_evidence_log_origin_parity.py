"""Evidence-log origins agree across implementations (Anchor §4.3.2),
and the SQLite trigger writes a record's leaf for any writer (Tree §5.2).

``vectors/evidence-log-origin-vectors.json`` pins the origin of each chain id,
the chain ids a store refuses and the namespaces it accepts and refuses. This
file holds four implementations to it:

- Python, ``tzun_sdk.log_origin``;
- TypeScript, ``src/storage/log-store.ts``, live through the harness;
- SQLite SQL, ``lower(hex(chain_id))``, run by Python's own SQLite build; and
- the trigger and the ``store_identity.ns`` CHECK a TypeScript-created store
  carries, reached by a Python ``sqlite3`` connection that has none of the
  SDK's registered functions.

``tests/ts/evidence-log-origin-vectors.test.ts`` runs the same file through the
TypeScript functions and the SQLite and Postgres triggers.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
import subprocess
from typing import Any

import pytest

from tzun_sdk.log_origin import (
    assert_log_namespace,
    chain_id_refusal,
    chain_segment,
    domain_prefix,
    evidence_log_origin,
    store_log_origin,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
DOC = json.loads((REPO_ROOT / "vectors" / "evidence-log-origin-vectors.json").read_text(encoding="utf-8"))
VECTORS = DOC["vectors"]
INVALID_CHAIN_IDS = DOC["invalidChainIds"]
VALID_NAMESPACES = DOC["namespaces"]["valid"]
INVALID_NAMESPACES = DOC["namespaces"]["invalid"]
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


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"][:40] for v in VECTORS])
def test_python_computes_every_origin(vector: dict[str, Any]) -> None:
    assert chain_segment(vector["chainId"]) == vector["chainSegment"]
    assert evidence_log_origin(DOC["ns"], DOC["storeId"], vector["chainId"]) == vector["origin"]


def test_python_computes_every_store_log_origin() -> None:
    for entry in DOC["storeLogs"]:
        assert store_log_origin(DOC["ns"], DOC["storeId"], entry["kind"]) == entry["origin"]


def test_typescript_computes_the_same_origins(has_node: bool) -> None:
    if not has_node:
        pytest.skip("Node not available")
    out = _harness(
        {
            "action": "origins",
            "ns": DOC["ns"],
            "storeId": DOC["storeId"],
            "chainIds": [v["chainId"] for v in VECTORS],
            "kinds": [e["kind"] for e in DOC["storeLogs"]],
        }
    )
    assert out["evidence"] == [v["origin"] for v in VECTORS]
    assert out["storeLogs"] == [e["origin"] for e in DOC["storeLogs"]]


def test_sqlite_sql_computes_the_same_chain_segments() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        assert conn.execute("PRAGMA encoding").fetchone()[0] == "UTF-8"
        for vector in VECTORS:
            (segment,) = conn.execute("SELECT lower(hex(?))", (vector["chainId"],)).fetchone()
            assert segment == vector["chainSegment"], vector["name"]
    finally:
        conn.close()


@pytest.mark.parametrize("vector", INVALID_CHAIN_IDS, ids=[v["name"][:40] for v in INVALID_CHAIN_IDS])
def test_python_refuses_every_refused_chain_id(vector: dict[str, Any]) -> None:
    assert chain_id_refusal(vector["chainId"]) == vector["reason"]
    with pytest.raises(ValueError):
        chain_segment(vector["chainId"])
    with pytest.raises(ValueError):
        evidence_log_origin(DOC["ns"], DOC["storeId"], vector["chainId"])


def test_python_accepts_and_refuses_the_same_namespaces() -> None:
    for entry in VALID_NAMESPACES:
        assert assert_log_namespace(entry["ns"]) == entry["ns"], entry["name"]
    for entry in INVALID_NAMESPACES:
        with pytest.raises(ValueError):
            assert_log_namespace(entry["ns"])
        with pytest.raises(ValueError):
            domain_prefix(entry["ns"], DOC["storeId"])


def test_typescript_refuses_the_same_chain_ids_and_namespaces(has_node: bool) -> None:
    if not has_node:
        pytest.skip("Node not available")
    namespaces = VALID_NAMESPACES + INVALID_NAMESPACES
    out = _harness(
        {
            "action": "refusals",
            "chainIds": [v["chainId"] for v in VECTORS + INVALID_CHAIN_IDS],
            "namespaces": [e["ns"] for e in namespaces],
        }
    )
    assert out["chainIds"] == [None] * len(VECTORS) + [v["reason"] for v in INVALID_CHAIN_IDS]
    assert out["namespaces"] == [True] * len(VALID_NAMESPACES) + [False] * len(INVALID_NAMESPACES)


def test_bad_store_ids_and_kinds_are_refused_as_in_typescript() -> None:
    with pytest.raises(ValueError):
        domain_prefix("local.invalid", "NOT-HEX")
    with pytest.raises(ValueError):
        store_log_origin(DOC["ns"], DOC["storeId"], "evidence")
    assert chain_id_refusal(42) == "invalid_chain_id"


def _envelope_row(evidence_id: str, chain_id: str, sequence_number: int) -> tuple[Any, ...]:
    digest = hashlib.sha256(evidence_id.encode("utf-8")).hexdigest()
    envelope = {
        "envelopeVersion": "e1",
        "payload": {
            "evidenceId": evidence_id,
            "schemaVersion": "v1.0",
            "aiSystemId": "py-writer",
            "aiOutput": {"ok": True},
            "action": "approved",
            "reason": "written from Python",
            "capturedAt": "2026-09-25T10:00:00.000Z",
            "sequenceNumber": sequence_number,
            "decider": {"kind": "human", "id": "acct:u-cross-sdk", "agent": None, "credential": None, "freshness": None},
            "contributions": None,
            "links": None,
            "signoffExpectation": None,
        },
        "integrity": {"canonicalDigest": digest, "chainLink": None},
        "nonRepudiation": {},
        "custodyChain": [],
        "attestationStatus": "none",
    }
    return (
        evidence_id,
        json.dumps(envelope),
        envelope["payload"]["capturedAt"],
        1790330400000,
        "py-writer",
        digest,
        chain_id,
    )


def test_a_python_writer_on_a_shared_sqlite_store_gets_leaves_and_origins(has_node: bool, tmp_path: pathlib.Path) -> None:
    """Tree §5.2: the leaf is the database's doing, not the TypeScript adapter's.

    The store is created by the TypeScript adapter; the records are written by
    Python's ``sqlite3`` straight into ``envelopes``. Every chain gets its log,
    under the origin the vectors pin, and every record its leaf.
    """
    if not has_node:
        pytest.skip("Node not available")
    path = tmp_path / "shared.db"
    identity = _harness({"action": "create-sqlite-store", "path": str(path)})

    conn = sqlite3.connect(str(path))
    try:
        insert = (
            "INSERT INTO envelopes (evidence_id, envelope, captured_at, captured_at_ms, ai_system_id, digest, chain_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        for i, vector in enumerate(VECTORS):
            conn.execute(insert, _envelope_row(f"py-{i}-1", vector["chainId"], 1))
            conn.execute(insert, _envelope_row(f"py-{i}-2", vector["chainId"], 2))
        conn.commit()

        for i, vector in enumerate(VECTORS):
            (log_id, origin) = conn.execute(
                "SELECT log_id, origin FROM logs WHERE kind = 'evidence' AND chain_id = ?", (vector["chainId"],)
            ).fetchone()
            assert origin == f"{identity['ns']}/{identity['storeId']}/evidence/{vector['chainSegment']}", vector["name"]
            leaves = conn.execute(
                "SELECT leaf_index, source_ref, source FROM log_leaves WHERE log_id = ? ORDER BY leaf_index", (log_id,)
            ).fetchall()
            assert leaves == [(0, f"py-{i}-1", "capture"), (1, f"py-{i}-2", "capture")], vector["name"]

        # A record with no predecessor leaf is refused, and nothing of it is written.
        with pytest.raises(sqlite3.IntegrityError, match=r"\[tzun:log_gap\]"):
            conn.execute(insert, _envelope_row("py-gap", "default", 5))
        conn.rollback()
        assert conn.execute("SELECT COUNT(*) FROM envelopes WHERE evidence_id = 'py-gap'").fetchone()[0] == 0

        # A refused chain id is refused by the trigger, with the reason TypeScript gives.
        for i, vector in enumerate(INVALID_CHAIN_IDS):
            row = _envelope_row(f"py-bad-{i}", vector["chainId"], 1)
            if any(0xD800 <= ord(c) <= 0xDFFF for c in vector["chainId"]):
                # Python's sqlite3 cannot encode a surrogate, so it never reaches SQLite.
                with pytest.raises(UnicodeEncodeError):
                    conn.execute(insert, row)
                continue
            with pytest.raises(sqlite3.IntegrityError, match=rf"\[tzun:{vector['reason']}\]"):
                conn.execute(insert, row)
            conn.rollback()
        assert conn.execute("SELECT COUNT(*) FROM envelopes WHERE evidence_id LIKE 'py-bad-%'").fetchone()[0] == 0

        # And no leaf can be rewritten or removed.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE log_leaves SET leaf_digest = ? WHERE leaf_index = 0", ("0" * 64,))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM log_leaves")
        conn.rollback()
    finally:
        conn.close()


def test_the_sqlite_ns_check_accepts_and_refuses_the_same_namespaces(has_node: bool, tmp_path: pathlib.Path) -> None:
    """The ``store_identity.ns`` CHECK of a TypeScript-created store, reached from Python."""
    if not has_node:
        pytest.skip("Node not available")
    path = tmp_path / "ns.db"
    _harness({"action": "create-sqlite-store", "path": str(path)})
    conn = sqlite3.connect(str(path))
    try:
        # Step around the immutability guard, as only the file's owner can.
        conn.execute("DROP TRIGGER store_identity_block_delete")
        insert = "INSERT INTO store_identity (singleton, store_id, ns, created_at) VALUES (1, ?, ?, ?)"
        for entry in VALID_NAMESPACES:
            conn.execute("DELETE FROM store_identity")
            conn.execute(insert, (DOC["storeId"], entry["ns"], "2026-09-25T10:00:00Z"))
        for entry in INVALID_NAMESPACES:
            conn.execute("DELETE FROM store_identity")
            with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
                conn.execute(insert, (DOC["storeId"], entry["ns"], "2026-09-25T10:00:00Z"))
        conn.rollback()
    finally:
        conn.close()
