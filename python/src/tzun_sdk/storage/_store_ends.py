"""What the 0.7.0 store check reads from a store before its setup runs.

``read_envelope_at_end`` on the SQLite and Postgres adapters hands back a
record as its stored JSON, through :func:`stored_json`, so that
``Tzun.init()`` can refuse a store a release before 0.7.0 wrote without
creating a table in it first.
"""

from __future__ import annotations

from typing import Any

from tzun_sdk._record_rules import js_json_loads


def stored_json(text: str) -> Any:
    """``text`` parsed as ``JSON.parse`` parses it, or ``text`` itself when it does not parse.

    An integer literal past 2^53 - 1 reads as the nearest double, as the
    JavaScript writer that hashed it read it (:func:`~tzun_sdk._record_rules.js_json_loads`).
    A row that is not JSON is not a record of any release, so it neither
    passes nor refuses a store: the check reads it as a record with no
    payload, and the verifiers report it.
    """
    try:
        return js_json_loads(text)
    except (TypeError, ValueError):
        return text
