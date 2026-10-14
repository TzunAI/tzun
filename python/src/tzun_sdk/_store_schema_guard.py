"""Refusing, at open, a store an earlier release wrote.

The v1.0 hashed field set was revised in place, by 0.7.0 and again by 0.8.0,
so a record an earlier release captured has a digest over an earlier set
(Record §4.1, "Earlier field sets"), and every check this release runs reads
it as tampered. ``Tzun.init()`` refuses
such a store with :class:`~tzun_sdk.errors.StoreSchemaOutdatedError`, which
names the record and its field-set generation (``"0.7"`` or
``"before-0.7"``). The twin of the TS SDK's ``src/sdk/store-schema-guard.ts``.

For the SQLite and Postgres adapters the records are read before
``ensure_tables()`` runs (``read_envelope_at_end``, which only reads), so no
table, trigger or row is added to a refused store, and a SQLite store's main
file is unchanged (SQLite may create the ``-wal`` and ``-shm`` sidecars of a
WAL-mode file when it opens one).

The first and newest records are read by insertion order as the store records
it, and a writer with access to the store can plant a row there: an old-format
record put first locks a current store out, and a new-format one put first lets
an old store open. Integrity does not rest on this check: ``verify()`` reports
every record whose digest does not recompute (with the ``fieldSet`` fact),
whichever way the store opened.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import BaseModel

from tzun_sdk.errors import StoreSchemaOutdatedError
from tzun_sdk.payload_rules import record_field_set_generation


def _plain(record: Any) -> Any:
    return record.model_dump(mode="json", exclude_unset=True) if isinstance(record, BaseModel) else record


def _payload(record: Any) -> dict[str, Any] | None:
    plain = _plain(record)
    payload = plain.get("payload") if isinstance(plain, dict) else None
    return payload if isinstance(payload, dict) else None


def _evidence_id(record: Any) -> str:
    payload = _payload(record)
    return str(payload.get("evidenceId") if payload is not None else None)


def _earlier_generation(record: Any) -> str | None:
    generation = record_field_set_generation(_plain(record))
    return generation if generation in ("0.7", "before-0.7") else None


async def refuse_outdated_store(first: Any, read_newest: Callable[[], Awaitable[Any]]) -> None:
    """Raise :class:`StoreSchemaOutdatedError` when an earlier release wrote the store.

    The store's first record decides it:

    * no first record (an empty store): accepted;
    * the first record recomputes under the 0.7 or the pre-0.7 field set:
      refused, naming it and its generation;
    * the first record recomputes under the current set, or carries a
      ``decider`` key (0.8.0 writes it): accepted; an older record after it
      was written by something else, and the verifiers report it as tampered;
    * otherwise (an old record that was altered, recomputing under no set)
      the newest record decides: refused, naming it, when it is of an earlier
      generation.

    ``read_newest`` is awaited only in that last case. The engine twin is
    ``refuseOutdatedStore``.
    """
    if first is None:
        return
    generation = _earlier_generation(first)
    if generation is not None:
        raise StoreSchemaOutdatedError(_evidence_id(first), generation)
    payload = _payload(first)
    if record_field_set_generation(_plain(first)) == "0.8" or (payload is not None and "decider" in payload):
        return
    newest = await read_newest()
    if newest is None:
        return
    generation = _earlier_generation(newest)
    if generation is not None:
        raise StoreSchemaOutdatedError(_evidence_id(newest), generation)


async def refuse_store_before_setup(storage: Any) -> bool:
    """Run the check on an adapter that can be read before its setup.

    ``True`` when ``storage`` has ``read_envelope_at_end`` (the SQLite,
    Postgres and memory adapters) and the check ran on it; ``False`` when it
    has not, and the caller checks it through the adapter once it is set up.
    """
    reader = getattr(storage, "read_envelope_at_end", None)
    if reader is None:
        return False
    await refuse_outdated_store(await reader("first"), lambda: reader("newest"))
    return True


__all__ = ("refuse_outdated_store", "refuse_store_before_setup")
