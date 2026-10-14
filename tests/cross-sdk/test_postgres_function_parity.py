"""Both SDKs create their Postgres functions with the search_path pinned, and the shared one alike.

A trigger function runs with the search_path of the session whose statement
fired it. The TypeScript adapter creates every function with ``SET search_path
= pg_catalog, pg_temp`` and names each table through the schema of its
trigger's table, so a temporary table, or a table in a schema the session
puts first, does not stand in for the store's. The Python adapter creates one
function, ``envelope_revisions_block_mutation``, under the TypeScript
function's name, so that a database both SDKs open has one guard on the
revision log they share (``python/tests/storage/test_cross_sdk_table_collision.py``).
Each ``ensure_tables()`` replaces it (CREATE OR REPLACE), so the two
definitions must say the same thing, or the guard a store runs would depend on
which SDK opened it last.

This reads the statements each SDK sends, with no database: the TypeScript
ones from ``PostgresStorageAdapter.ensureTables()`` through
``ts-harness/log-store.ts``, the Python ones from ``_POSTGRES_DDL``, and
compares them whitespace aside (the two sources indent differently).
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
from typing import Any

import pytest

from tzun_sdk.storage.postgres import _POSTGRES_DDL

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LOG_STORE_HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "log-store.ts"

PINNED = "SET search_path = pg_catalog, pg_temp"
FUNCTION = re.compile(r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+(\w+)\s*\(.*?\$\$.*?\$\$[^;]*;", re.IGNORECASE | re.DOTALL)
SHARED = "envelope_revisions_block_mutation"


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


def _functions(ddl: str) -> dict[str, str]:
    """Each CREATE OR REPLACE FUNCTION statement by function name, whitespace collapsed."""
    return {m.group(1): re.sub(r"\s+", " ", m.group(0)).strip() for m in FUNCTION.finditer(ddl)}


@pytest.fixture(scope="module")
def ts_functions(has_node: bool) -> dict[str, str]:
    if not has_node:
        pytest.skip("Node not available")
    return _functions("\n;\n".join(_harness({"action": "postgres-ddl"})["statements"]))


def test_every_function_either_sdk_creates_pins_its_search_path(ts_functions: dict[str, str]) -> None:
    py_functions = _functions(_POSTGRES_DDL)
    assert len(ts_functions) > 30
    assert SHARED in ts_functions
    assert sorted(py_functions) == [SHARED]
    unpinned = [f"ts:{name}" for name, sql in ts_functions.items() if PINNED not in sql] + [
        f"py:{name}" for name, sql in py_functions.items() if PINNED not in sql
    ]
    assert unpinned == []


def test_the_function_both_sdks_create_is_the_same_in_both(ts_functions: dict[str, str]) -> None:
    assert _functions(_POSTGRES_DDL)[SHARED] == ts_functions[SHARED]
