"""The Python Postgres adapter has no table the back-dated-id guards would sit on.

On Postgres a ``BIGSERIAL`` column takes an id written
explicitly, and the TS SDK reads ``credential_events``, ``custody_entries``,
``logs`` and ``anchor_publications`` in id order, so a row planted below the
last read ahead of the rows it follows (one INSERT at ``credential_events``
``seq`` 0 put another key on a registered credential). The TS adapter guards
each of those tables with ``<table>_block_backdated_<id>``
(``postgresBackdatedIdGuard`` in ``src/storage/append-only.ts``).

The Python adapter creates none of the four (``python/MIGRATION.md``, "Storage
backends"), so there is no Python twin to keep in step. This pins that: the day
the Python DDL creates one of them, this fails and names the guard that must
come with it, built as ``postgresBackdatedIdGuard`` builds it: the same two
refusals with the same messages, the id drawn in the guard, and the pinned
``search_path``.
"""

from __future__ import annotations

import re

import pytest

from tzun_sdk.storage.postgres import _POSTGRES_DDL

GUARDED = {
    "credential_events": "credential_events_block_backdated_seq",
    "custody_entries": "custody_entries_block_backdated_id",
    "logs": "logs_block_backdated_id",
    "anchor_publications": "anchor_publications_block_backdated_id",
}


def _created_tables(ddl: str) -> set[str]:
    return {
        m.lower()
        for m in re.findall(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)", ddl, re.IGNORECASE)
    }


def test_the_ddl_is_read_the_way_this_test_reads_it():
    assert _created_tables("CREATE TABLE logs (log_id BIGSERIAL)") == {"logs"}
    assert _created_tables("create table if not exists Logs (log_id bigserial)") == {"logs"}
    tables = _created_tables(_POSTGRES_DDL)
    assert {"evidence_envelopes", "attestations", "recovery_records", "envelope_revisions"} <= tables


@pytest.mark.parametrize("table", sorted(GUARDED))
def test_the_python_adapter_creates_no_table_the_ts_guards_sit_on(table):
    assert table not in _created_tables(_POSTGRES_DDL), (
        f"the Python Postgres DDL now creates {table}: install {GUARDED[table]} with it, "
        "as src/storage/append-only.ts postgresBackdatedIdGuard() builds it for the TS adapter"
    )
