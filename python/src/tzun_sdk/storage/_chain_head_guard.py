"""The one place that decides whether a conditional chain append may proceed.

Python twin of ``src/storage/chain-head-guard.ts``. Every adapter must apply
:func:`assert_chain_head` INSIDE whatever makes its write atomic — the memory
adapter's ``_chain_lock`` critical section, SQLite's ``BEGIN IMMEDIATE``
transaction, the Postgres transaction holding the chain advisory lock. Checking
outside that boundary reintroduces exactly the read-modify-write race it exists
to close.
"""

from __future__ import annotations

from tzun_sdk.errors import ChainConflictError
from tzun_sdk.models import ChainHead

__all__ = ("CHAIN_APPEND_LOCK_KEY", "assert_chain_head", "head_of")

#: Postgres advisory-lock key for the chain-append critical section. Identical
#: to ``PostgresStorageAdapter.CHAIN_APPEND_LOCK`` in ``src/storage/postgres.ts``
#: so a TypeScript writer and a Python writer on one database serialise against
#: each other rather than each holding a lock the other never takes.
CHAIN_APPEND_LOCK_KEY = 2026090201


def head_of(sequence: int | float | None, digest: str | None) -> ChainHead:
    """Build a :class:`ChainHead` from a raw ``(sequence, digest)`` pair.

    ``None`` and ``0``/``''`` all mean "empty chain", which is the shape the
    SQL adapters produce for a table with no rows.
    """
    return ChainHead(sequence=int(sequence or 0), digest=digest or None)


def assert_chain_head(expected: ChainHead | None, actual: ChainHead) -> None:
    """Raise :class:`ChainConflictError` unless the live head is ``expected``.

    A no-op when ``expected`` is ``None``: ``store()`` stays usable as a
    low-level primitive for writes that are not chain appends (imports, test
    fixtures, recovery flows).

    ``''`` is normalised to ``None`` on both sides because a SQL adapter may
    keep "no head yet" as the empty string rather than NULL.
    """
    if expected is None:
        return

    actual_digest = actual.digest if actual.digest else None
    expected_digest = expected.digest if expected.digest else None

    if int(expected.sequence) != int(actual.sequence) or expected_digest != actual_digest:
        raise ChainConflictError(
            ChainHead(sequence=int(expected.sequence), digest=expected_digest),
            ChainHead(sequence=int(actual.sequence), digest=actual_digest),
        )
