# python/tests/core/test_export.py — evidence export bundles.
from __future__ import annotations

import importlib.util

import pytest

from tests.storage.test_catalog_primitives import mvd
from tzun_sdk.contributions import single_model
from tzun_sdk.core import Tzun
from tzun_sdk.errors import TzunError
from tzun_sdk.models import AiBom
from tzun_sdk.storage.memory import MemoryAdapter


@pytest.mark.asyncio
async def test_export_bundles_lineage_by_default():
    tzun = await Tzun.init(storage=MemoryAdapter())
    root = await tzun.models.register(mvd("base", "1"))
    child = await tzun.models.register(
        mvd("ft", "1").model_copy(update={"parentModelDescriptorDigest": root})
    )
    bom = {
        "modelDescriptorDigest": child,
        "vendorFingerprint": None,
        "promptTemplate": None,
        "inferenceParameters": None,
        "infrastructure": None,
    }
    r = await tzun.capture(
        ai_output={"d": 1},
        decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
        reason="ok",
        contributions=single_model(AiBom.model_validate(bom)),
    )
    bundle = await tzun.export_evidence(r.evidenceId)
    assert bundle.envelope.payload.evidenceId == r.evidenceId
    # resolvedModelDescriptors is a dict keyed by descriptor digest
    assert child in bundle.resolvedModelDescriptors
    assert root in bundle.resolvedModelDescriptors  # lineage walked

    shallow = await tzun.export_evidence(r.evidenceId, walk_lineage=False)
    assert child in shallow.resolvedModelDescriptors
    assert root not in shallow.resolvedModelDescriptors
    await tzun.close()


@pytest.mark.asyncio
async def test_export_unknown_id_raises_not_found():
    tzun = await Tzun.init(storage=MemoryAdapter())
    with pytest.raises(TzunError, match="not found"):
        await tzun.export_evidence("missing-id")
    await tzun.close()


# ---------------------------------------------------------------------------
# An exported bundle must be internally checkable
#
# `canonicalBytes` in an export bundle is what an offline verifier re-hashes to
# confirm the descriptor the evidence points at, so sha256(canonicalBytes) must
# equal the descriptor digest (pydantic's model_dump_json(), with its different
# key order, would not). `firstRegisteredAt` must be the time of registration,
# not the time of the export call. Both are asserted here for every adapter,
# not only the memory one.
# ---------------------------------------------------------------------------


def _sha256_digest(text: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture(params=["memory", "sqlite"])
def export_adapter(request, tmp_path):
    from tzun_sdk.storage.sqlite import SqliteAdapter

    if request.param == "memory":
        return MemoryAdapter()
    return SqliteAdapter(str(tmp_path / "export.db"), mode="sync")


@pytest.mark.asyncio
async def test_exported_canonical_bytes_hash_to_the_descriptor_digest(export_adapter):
    tzun = await Tzun.init(storage=export_adapter)
    # mvd() has modelDigest=None, so the registered digest IS the canonical
    # hash — the assertion below does not depend on the model-manifest shape.
    digest = await tzun.models.register(mvd("base", "1"))
    bom = {
        "modelDescriptorDigest": digest,
        "vendorFingerprint": None,
        "promptTemplate": None,
        "inferenceParameters": None,
        "infrastructure": None,
    }
    r = await tzun.capture(
        ai_output={"d": 1},
        decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
        reason="ok",
        contributions=single_model(AiBom.model_validate(bom)),
    )
    bundle = await tzun.export_evidence(r.evidenceId)
    entry = bundle.resolvedModelDescriptors[digest]

    assert entry.canonicalBytes != ""
    assert _sha256_digest(entry.canonicalBytes) == digest
    await tzun.close()


@pytest.mark.asyncio
async def test_exported_first_registered_at_is_stable_across_reads(export_adapter):
    """`firstRegisteredAt` is a property of the row, not of the read.

    A stamp taken at read time would make every export claim the model was
    first registered at the instant the bundle was produced, and two reads of
    the same row would disagree.
    """
    import asyncio
    import datetime as dt

    tzun = await Tzun.init(storage=export_adapter)
    digest = await tzun.models.register(mvd("base", "1"))

    def _stamp(rows):
        return next(r for r in rows if r.modelDescriptorDigest == digest).firstRegisteredAt

    first_read = _stamp(await export_adapter.list_model_descriptors())
    # Longer than SQLite's one-second `datetime('now')` resolution, so a
    # read-time stamp cannot coincidentally match.
    await asyncio.sleep(1.2)
    second_read = _stamp(await export_adapter.list_model_descriptors())

    assert first_read == second_read
    # And it is a real registration time, not a placeholder: it parses, and it
    # is at least a second behind the clock now that we have slept.
    parsed = dt.datetime.fromisoformat(first_read.replace("Z", "+00:00"))
    now = dt.datetime.now(dt.UTC)
    assert (now - parsed).total_seconds() >= 1.0
    await tzun.close()


@pytest.mark.asyncio
async def test_sqlite_rows_predating_the_canonical_bytes_column_still_export(tmp_path):
    """A database created before `canonical_bytes` existed must not break.

    The column is added by an idempotent ALTER, so old rows carry NULL. The
    read path recomputes from the stored descriptor rather than falling back to
    the pydantic JSON, whose key order does not hash to the digest.
    """
    import sqlite3

    from tzun_sdk.storage.sqlite import SqliteAdapter

    db = str(tmp_path / "legacy.db")
    # Build the table without `canonical_bytes` by hand and insert a row.
    legacy = sqlite3.connect(db)
    legacy.execute(
        "CREATE TABLE model_descriptors ("
        "digest TEXT PRIMARY KEY, descriptor_json TEXT NOT NULL, "
        "created_at TEXT NOT NULL DEFAULT (datetime('now')))"
    )
    descriptor = mvd("legacy", "1")
    from tzun_sdk.storage.memory import _compute_descriptor_digest

    digest = _compute_descriptor_digest(descriptor)
    legacy.execute(
        "INSERT INTO model_descriptors (digest, descriptor_json, created_at) "
        "VALUES (?, ?, ?)",
        (digest, descriptor.model_dump_json(), "2026-01-02 03:04:05"),
    )
    legacy.commit()
    legacy.close()

    adapter = SqliteAdapter(db, mode="sync")
    await adapter.ensure_tables()
    rows = await adapter.list_model_descriptors()
    row = next(r for r in rows if r.modelDescriptorDigest == digest)

    assert _sha256_digest(row.canonicalBytes) == digest
    # And the legacy `datetime('now')` string is normalised, not replaced.
    assert row.firstRegisteredAt == "2026-01-02T03:04:05Z"
    await adapter.close()


# Needs the psycopg driver, which CI does not install (the sibling Postgres
# suite gates itself the same way, via pytest.mark.integration). Without this the
# test fails with ModuleNotFoundError rather than skipping, which is a CI-config
# failure dressed up as a product failure.
@pytest.mark.skipif(
    importlib.util.find_spec("psycopg") is None,
    reason="psycopg is not installed; this exercises the Postgres write path",
)
@pytest.mark.asyncio
async def test_postgres_register_descriptor_writes_canonical_bytes(monkeypatch):
    """The Postgres `canonical_bytes` column must hold canonical bytes.

    The column name is the TS adapter's, and the TS verifier re-hashes it as
    the descriptor's canonical form. Were Python to write `model_dump_json()`
    into it, a TS descriptor check against a Python-written row in a shared
    catalog would raise descriptor_digest_mismatch. Asserted without a live
    database by capturing the parameters the adapter binds.
    """
    from tzun_sdk.storage.memory import _compute_descriptor_digest
    from tzun_sdk.storage.postgres import PostgresAdapter

    captured: dict[str, object] = {}

    class _FakeCursor:
        pass

    class _FakeConn:
        def execute(self, sql, params):
            captured["sql"] = sql
            captured["params"] = params
            return _FakeCursor()

    class _FakePool:
        def connection(self):
            class _Ctx:
                def __enter__(self_inner):
                    return _FakeConn()

                def __exit__(self_inner, *exc):
                    return False

            return _Ctx()

    adapter = PostgresAdapter("postgres://unused/unused", mode="sync")
    monkeypatch.setattr(adapter, "_ensure_sync_pool", lambda: _FakePool())

    descriptor = mvd("pg", "1")
    digest = await adapter.register_descriptor(descriptor)

    assert digest == _compute_descriptor_digest(descriptor)
    params = captured["params"]
    canonical_bytes = params[1]
    assert _sha256_digest(canonical_bytes) == digest
    # And it is NOT the pydantic dump, whose key order differs.
    assert canonical_bytes != descriptor.model_dump_json()


# ---------------------------------------------------------------------------
# The bundle carries its predecessor and a verdict
#
# The same three blocks the TS exporter ships: `chain` (so an offline verifier
# can recompute `integrity.chainLink`), `custody`, and `verdict`. The Python
# adapters keep no custody ledger, and the bundle says so rather than claiming
# an empty one.
# ---------------------------------------------------------------------------


async def _capture_three(tzun: Tzun) -> list[str]:
    ids = []
    for i in range(3):
        r = await tzun.capture(ai_output={"step": i}, decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved", reason=f"step {i}")
        ids.append(r.evidenceId)
    return ids


@pytest.mark.asyncio
async def test_export_carries_the_predecessor_the_chain_link_was_computed_over(export_adapter):
    from tzun_sdk._generated.chain import compute_chain_link

    tzun = await Tzun.init(storage=export_adapter)
    first, second, _ = await _capture_three(tzun)
    one = await tzun.export_evidence(first)
    two = await tzun.export_evidence(second)

    assert one.chain.predecessor is None
    assert one.verdict.chainLink.status == "valid"
    pred = two.chain.predecessor
    assert pred is not None
    assert (pred.evidenceId, pred.sequenceNumber) == (first, 1)
    assert pred.canonicalDigest == one.envelope.integrity.canonicalDigest
    assert compute_chain_link(pred.canonicalDigest, two.envelope.integrity.canonicalDigest) == (
        two.envelope.integrity.chainLink
    )
    assert two.verdict.status == "valid"
    assert two.verdict.digest.status == "valid"
    assert two.verdict.digest.recomputed == two.envelope.integrity.canonicalDigest
    assert two.verdict.chainLink.status == "valid"
    assert two.verdict.chainLink.predecessorDigest == pred.canonicalDigest
    await tzun.close()


@pytest.mark.asyncio
async def test_export_says_there_is_no_custody_ledger_rather_than_an_empty_one():
    from tzun_sdk.custody_hash import CUSTODY_ENTRY_HASH_PREIMAGE

    tzun = await Tzun.init(storage=MemoryAdapter())
    first, *_ = await _capture_three(tzun)
    bundle = await tzun.export_evidence(first)

    assert bundle.custody.hashPreimage == CUSTODY_ENTRY_HASH_PREIMAGE
    assert bundle.custody.entries is None
    assert bundle.custody.trail is None
    assert bundle.custody.offlineTrail.valid is None
    assert bundle.verdict.custodyTrail.status == "unmeasured"
    assert bundle.verdict.custodyTrail.reason == "no_custody_ledger"
    await tzun.close()


@pytest.mark.asyncio
async def test_a_record_tampered_in_the_store_is_exported_with_an_invalid_verdict():
    adapter = MemoryAdapter()
    tzun = await Tzun.init(storage=adapter)
    _, second, _ = await _capture_three(tzun)
    adapter._envelopes[second]["payload"]["reason"] = "rewritten"

    bundle = await tzun.export_evidence(second)
    assert bundle.envelope.payload.reason == "rewritten"
    assert bundle.verdict.status == "invalid"
    assert bundle.verdict.digest.reason == "digest_mismatch"
    await tzun.close()


@pytest.mark.asyncio
async def test_a_record_whose_predecessor_is_gone_is_exported_with_the_link_unprovable():
    adapter = MemoryAdapter()
    tzun = await Tzun.init(storage=adapter)
    first, second, _ = await _capture_three(tzun)
    del adapter._envelopes[first]

    bundle = await tzun.export_evidence(second)
    assert bundle.chain.predecessor is None
    assert bundle.verdict.status == "invalid"
    assert bundle.verdict.chainLink.reason == "predecessor_missing"
    await tzun.close()
