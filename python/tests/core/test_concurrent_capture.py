"""Concurrent capture() calls on one instance append one unforked chain.

`capture()` holds its lock across the whole append: the head read, the
chain-link computation and the store. With an adapter that genuinely suspends
at an await (`SqliteAdapter(mode="async")`, `PostgresAdapter(mode="async")`),
two in-flight captures that read the same head would both link to it, and
`verify()` would report `chain_link_mismatch` on genuine evidence.

These tests drive four captures through `asyncio.gather` against the async
SQLite adapter and assert that every record verifies and that the sequences
run gap-free, each linked to its predecessor. `MemoryAdapter` cannot exercise
this: its coroutines never interleave, so a suite run only on it would pass
even without the lock.
"""

import asyncio
from itertools import pairwise

import pytest

from tzun_sdk import Tzun
from tzun_sdk.storage.sqlite import SqliteAdapter

pytest.importorskip("aiosqlite")

CONCURRENCY = 4


@pytest.mark.asyncio
async def test_concurrent_captures_all_verify(tmp_path):
    adapter = SqliteAdapter(str(tmp_path / "chain.db"), mode="async")
    tzun = await Tzun.init(storage=adapter)
    try:
        results = await asyncio.gather(
            *(
                tzun.capture(
                    ai_output={"n": i},
                    decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                    reason="ok",
                )
                for i in range(CONCURRENCY)
            )
        )
        assert len(results) == CONCURRENCY

        verdicts = await asyncio.gather(
            *(tzun.verify(r.evidenceId) for r in results)
        )
        bad = [
            (r.evidenceId, v.chainLinkValid, v.reasons)
            for r, v in zip(results, verdicts, strict=True)
            if not v.valid or v.chainLinkValid is False
        ]
        assert bad == [], f"records failing verify after concurrent capture: {bad}"
    finally:
        await tzun.close()


@pytest.mark.asyncio
async def test_concurrent_captures_take_consecutive_sequences(tmp_path):
    """Serialising the append must still hand out a gap-free sequence run.

    Concurrent captures that merely *failed safely* would leave holes the
    tamper scanner reports as missing records; the point of holding the lock
    across the whole append is that every capture succeeds, in order.
    """
    adapter = SqliteAdapter(str(tmp_path / "chain.db"), mode="async")
    tzun = await Tzun.init(storage=adapter)
    try:
        await asyncio.gather(
            *(
                tzun.capture(
                    ai_output={"n": i},
                    decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
                    reason="ok",
                )
                for i in range(CONCURRENCY)
            )
        )
        stored = await adapter.list()
        seqs = sorted(e.payload.sequenceNumber for e in stored)
        assert seqs == list(range(1, CONCURRENCY + 1))

        # Every non-genesis link must be H(previous-by-sequence || own digest).
        by_seq = sorted(stored, key=lambda e: e.payload.sequenceNumber)
        from tzun_sdk._generated.chain import compute_chain_link

        for prev, cur in pairwise(by_seq):
            assert cur.integrity.chainLink == compute_chain_link(
                prev.integrity.canonicalDigest, cur.integrity.canonicalDigest
            )
    finally:
        await tzun.close()
