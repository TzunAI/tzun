"""Every Postgres function the Python adapter creates pins its search_path.

A trigger function runs with the search_path of the session whose statement
fired it, so a table it names bare is whatever that session resolves the name
to: a temporary table of the same name, or one in a schema the session puts
first. The TS adapter creates every function with ``SET search_path =
pg_catalog, pg_temp`` and names each table through the schema of its
trigger's table. The Python adapter creates one function,
``envelope_revisions_block_mutation``, which reads no table; it is created
with the same pinned search_path, and the day the Python DDL gains a function
that names a table, this fails until it names it the TS way.
``tests/cross-sdk/test_postgres_function_parity.py`` holds the shared function
to the TS adapter's definition.
"""

from __future__ import annotations

import re

from tzun_sdk.storage.postgres import _POSTGRES_DDL

PINNED = "SET search_path = pg_catalog, pg_temp"
FUNCTION = re.compile(
    r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+(\w+)\s*\((.*?)\$\$(.*?)\$\$([^;]*);", re.IGNORECASE | re.DOTALL
)


def _functions(ddl: str) -> dict[str, tuple[str, str]]:
    """Each function's name → (header and tail, body)."""
    return {m.group(1): (f"{m.group(2)} {m.group(4)}", m.group(3)) for m in FUNCTION.finditer(ddl)}


def _tables(ddl: str) -> list[str]:
    return re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", ddl, re.IGNORECASE)


def test_the_ddl_is_read_the_way_this_test_reads_it() -> None:
    sample = (
        "CREATE TABLE IF NOT EXISTS t (x INT);\n"
        "CREATE OR REPLACE FUNCTION f()\nRETURNS TRIGGER AS $$\nBEGIN\n  PERFORM 1 FROM t;\nEND;\n"
        "$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;"
    )
    assert _tables(sample) == ["t"]
    header, body = _functions(sample)["f"]
    assert PINNED in header
    assert "FROM t" in body
    assert sorted(_functions(_POSTGRES_DDL)) == ["envelope_revisions_block_mutation"]


def test_every_function_pins_its_search_path() -> None:
    unpinned = [name for name, (header, _) in _functions(_POSTGRES_DDL).items() if PINNED not in header]
    assert unpinned == []


def _bare(tables: list[str]) -> re.Pattern[str]:
    """A table named after FROM, JOIN, INTO or UPDATE, after a comma (a join list), or cast as a string to regclass."""
    names = "|".join(tables)
    return re.compile(rf"(?:\b(?:FROM|JOIN|INTO|UPDATE)\s+|,\s*)(?:{names})\b|'(?:{names})'::regclass", re.IGNORECASE)


def test_the_bare_name_pattern_finds_each_form() -> None:
    bare = _bare(["t", "u"])
    for body in ("PERFORM 1 FROM t;", "SELECT 1 FROM x a, u b;", "SELECT 'u'::regclass;", "UPDATE t SET x = 1;"):
        assert bare.search(body), body
    for body in ("PERFORM 1 FROM %1$I.t;", "SELECT 1 FROM %1$I.x a, %1$I.u b;", "SELECT tt FROM v;"):
        assert not bare.search(body), body


def test_no_function_names_a_table_of_the_store_bare() -> None:
    bare = _bare(_tables(_POSTGRES_DDL))
    naming = [name for name, (_, body) in _functions(_POSTGRES_DDL).items() if bare.search(body)]
    assert naming == []
