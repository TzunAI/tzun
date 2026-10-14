"""Postgres adapter integration suite.

Gated behind RUN_INTEGRATION_TESTS=true per conftest.py marker.
Parametrized over both driver paths (asyncpg=async mode, psycopg=sync mode).
Uses DATABASE_URL env var or falls back to the dev container at 172.19.0.2:5432.
"""
from __future__ import annotations

import asyncio
import os
import uuid

import pytest

from tests.storage.test_catalog_primitives import annotation_row, mvd
from tzun_sdk.errors import TzunError
from tzun_sdk.storage.postgres import PostgresAdapter

# The local Postgres container.
_PG_HOST = "host.docker.internal"

pytestmark = pytest.mark.integration  # skip unless RUN_INTEGRATION_TESTS=true

# Prefer DATABASE_URL env var; fall back to the dev container IP.
# localhost:55432 may not resolve from the host — use the container IP if needed.
DB_URL = os.environ.get(
    "DATABASE_URL",
    f"postgres://postgres:dev@{_PG_HOST}:55432/tzun_dev",
)


@pytest.fixture(params=["async", "sync"])
async def adapter(request):
    """Yield a connected PostgresAdapter for one driver; close it afterwards."""
    mode = request.param
    a = PostgresAdapter(DB_URL, mode=mode)
    await a.ensure_tables()
    yield a
    await a.close()


@pytest.mark.anyio
async def test_ensure_tables_idempotent(adapter):
    """Second ensure_tables() call must not raise (REQ idempotency)."""
    await adapter.ensure_tables()


@pytest.mark.anyio
async def test_ensure_tables_concurrent():
    """Concurrent init under the advisory lock must serialize without errors."""
    others = [PostgresAdapter(DB_URL, mode="async") for _ in range(2)]
    await asyncio.gather(*(o.ensure_tables() for o in others))
    for o in others:
        await o.close()


@pytest.mark.anyio
async def test_store_retrieve_list_head_roundtrip(adapter, envelope_factory):
    """Basic CRUD + list + head over two envelopes."""
    e1 = envelope_factory(seq=1)
    e2 = envelope_factory(seq=2)
    await adapter.store(e1)
    await adapter.store(e2)

    got = await adapter.retrieve(e1.payload.evidenceId)
    assert got is not None
    assert got.integrity.canonicalDigest == e1.integrity.canonicalDigest

    rows = await adapter.list()
    evidence_ids = {r.payload.evidenceId for r in rows}
    assert e1.payload.evidenceId in evidence_ids
    assert e2.payload.evidenceId in evidence_ids

    head = await adapter.head()
    # head returns the highest sequence_number in default chain
    assert head is not None


@pytest.mark.anyio
async def test_catalog_primitives_on_postgres(adapter):
    """Catalog primitives (list, annotations, alias) work on the Postgres adapter."""
    d = await adapter.register_descriptor(mvd("pg-model-" + uuid.uuid4().hex[:6]))
    rows = await adapter.list_model_descriptors()
    assert any(r.modelDescriptorDigest == d for r in rows)

    ann = annotation_row(d, annotationId=str(uuid.uuid4()))
    await adapter.append_model_descriptor_annotation(ann)
    annotations = await adapter.list_model_descriptor_annotations(d)
    assert len(annotations) == 1

    slug = "pg-prod-" + uuid.uuid4().hex[:6]
    await adapter.set_model_descriptor_alias(slug, d, "ops")
    resolved = await adapter.resolve_model_descriptor_alias(slug)
    assert resolved == d


@pytest.mark.anyio
async def test_attestation_and_recovery_stores(adapter, envelope_factory,
                                                attestation_blob, recovery_records):
    """Attestation and recovery primitives persist without error."""
    e = envelope_factory(seq=1)
    await adapter.store(e)
    eid = e.payload.evidenceId

    await adapter.store_attestation(eid, attestation_blob)
    blobs = await adapter.get_attestations(eid)
    assert len(blobs) == 1

    ann, relink, fork, _incident = recovery_records
    await adapter.store_annotation(ann)
    await adapter.store_relink(relink)
    await adapter.store_fork(fork)
    # Note: store_incident is deferred — the live DB uses the richer TS-managed
    # tamper_incidents schema (id, severity, type, …) which differs from the
    # Python SDK's local TamperIncident shape (incidentId, eventType, evidenceId).
    # Aligning the two schemas is a separate DDL-parity change.


@pytest.mark.anyio
async def test_disconnect_wraps_to_tzunerror(adapter):
    """After close(), any operation must raise TzunError."""
    await adapter.close()
    with pytest.raises(TzunError):
        await adapter.retrieve("nonexistent-id")


@pytest.mark.anyio
async def test_close_is_idempotent(adapter):
    """Second close() must not raise."""
    await adapter.close()
    await adapter.close()
