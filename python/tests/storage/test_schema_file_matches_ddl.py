"""``import tzun_sdk`` writes no file, and the committed SQLite schema is the adapter's DDL.

``tzun_sdk/__init__`` eagerly imports ``storage.sqlite``, so whatever that
module does at import runs on every ``import tzun_sdk``. A write relative to
an *installed* module's parents lands outside the package: five levels up from
it is the interpreter's ``lib/`` directory, not the repo. An import-time
filesystem write outside the package is exactly what supply chain scanners
flag, and it contradicts the import-safety property the rest of the suite
defends.

``schema/migrations/sqlite/0001_init.sql`` is the human-readable copy of the
adapter's ``_DDL``. These tests hold it equal to ``_DDL`` and to every table
the adapter creates, so the committed copy cannot drift from what
``ensure_tables()`` runs.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import tzun_sdk.storage.sqlite as sqlite_module

# python/tests/storage/ -> python/tests -> python -> repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_FILE = REPO_ROOT / "schema" / "migrations" / "sqlite" / "0001_init.sql"


def _statements(sql: str) -> str:
    """Strip a leading ``--`` header block and normalise trailing whitespace."""
    lines = sql.split("\n")
    i = 0
    while i < len(lines) and (lines[i].startswith("--") or not lines[i].strip()):
        i += 1
    return "\n".join(lines[i:]).strip()


def test_committed_schema_file_matches_the_inline_ddl() -> None:
    """The human-readable copy must be the DDL that ensure_tables() runs.

    A copy that drifts, for example one missing the
    ``model_descriptor_annotations`` table, would claim to be the canonical
    schema while describing a different one.
    """
    assert SCHEMA_FILE.exists(), f"{SCHEMA_FILE} must be committed to the repo"
    assert _statements(SCHEMA_FILE.read_text(encoding="utf-8")) == sqlite_module._DDL.strip()


def test_every_table_the_adapter_creates_is_in_the_committed_file() -> None:
    """Non-vacuity: the comparison above must actually cover real tables."""
    names = set(
        re.findall(
            r"CREATE TABLE IF NOT EXISTS (\w+)", sqlite_module._DDL, re.IGNORECASE
        )
    )
    assert "model_descriptor_annotations" in names, "the adapter must create model_descriptor_annotations"
    assert len(names) >= 5, f"expected the full table set, got {sorted(names)}"
    committed = SCHEMA_FILE.read_text(encoding="utf-8")
    for name in names:
        assert f"CREATE TABLE IF NOT EXISTS {name}" in committed


def test_module_defines_no_import_time_schema_writer() -> None:
    """The module defines no ``_ensure_schema_dir`` import-time schema writer."""
    assert not hasattr(sqlite_module, "_ensure_schema_dir")


def test_importing_tzun_sdk_creates_no_files_outside_the_package() -> None:
    """End-to-end: import the package with the module's parents[4] redirected.

    Runs a child interpreter whose ``sys.path`` puts a throwaway copy of the
    package five levels deep, so that an import-time write to ``parents[4]``
    would land inside a directory this test owns and can inspect. The
    assertion is on the outcome (nothing appeared on disk), not on the absent
    code.
    """
    import os
    import shutil
    import tempfile

    pkg_src = Path(sqlite_module.__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # <root>/a/b/site-packages/tzun_sdk/storage/sqlite.py
        #   parents[4] == <root>/a  -> where an import-time write would land.
        site = root / "a" / "b" / "site-packages"
        site.mkdir(parents=True)
        shutil.copytree(pkg_src, site / "tzun_sdk")
        sentinel_root = root / "a"

        before = {p for p in sentinel_root.rglob("*")}
        # Inherit the real environment (HOME in particular — the user
        # site-packages that carries pydantic is resolved from it) and only
        # PREPEND the throwaway copy so it shadows the installed package.
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(site)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
        )
        result = subprocess.run(
            [sys.executable, "-c", "import tzun_sdk; import tzun_sdk.storage.sqlite as m; print(m.__file__)"],
            capture_output=True,
            text=True,
            env=env,
            cwd=tmp,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        # Non-vacuity: the child must really have imported the shadow copy,
        # otherwise "nothing was created" would prove nothing.
        assert str(site) in result.stdout, result.stdout
        after = {p for p in sentinel_root.rglob("*")}

        created = {p for p in after - before if "__pycache__" not in p.parts}
        assert created == set(), f"import created files outside the package: {sorted(created)}"
