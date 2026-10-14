"""Admin-token gating."""

from __future__ import annotations

import pytest

from tzun_sdk import Tzun
from tzun_sdk.errors import AdminTokenRequiredError
from tzun_sdk.models import AnnotationRecord
from tzun_sdk.storage import MemoryAdapter


async def test_admin_token_check_when_unset_is_noop() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        await tzun.recovery.annotate(
            AnnotationRecord(
                id="a1",
                incidentId="i1",
                affectedRecords=["e1"],
                annotatedAt="2026-01-01T00:00:00Z",
                annotatedBy="alice",
                notes="x",
                originalDigests={"e1": "sha256:abc"},
            )
        )
    finally:
        await tzun.close()


async def test_admin_token_required_when_set() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter(), admin_token="s3cret")
    try:
        with pytest.raises(AdminTokenRequiredError):
            await tzun.recovery.annotate(
                AnnotationRecord(
                    id="a1",
                    incidentId="i1",
                    affectedRecords=["e1"],
                    annotatedAt="2026-01-01T00:00:00Z",
                    annotatedBy="alice",
                    notes="x",
                    originalDigests={"e1": "sha256:abc"},
                )
            )
    finally:
        await tzun.close()


async def test_admin_token_admits_correct_token() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter(), admin_token="s3cret")
    try:
        await tzun.recovery.annotate(
            AnnotationRecord(
                id="a1",
                incidentId="i1",
                affectedRecords=["e1"],
                annotatedAt="2026-01-01T00:00:00Z",
                annotatedBy="alice",
                notes="x",
                originalDigests={"e1": "sha256:abc"},
            ),
            admin_token="s3cret",
        )
    finally:
        await tzun.close()


async def test_admin_token_wrong_token_rejected() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter(), admin_token="s3cret")
    try:
        with pytest.raises(AdminTokenRequiredError):
            await tzun.recovery.annotate(
                AnnotationRecord(
                    id="a1",
                    incidentId="i1",
                    affectedRecords=["e1"],
                    annotatedAt="2026-01-01T00:00:00Z",
                    annotatedBy="alice",
                    notes="x",
                    originalDigests={"e1": "sha256:abc"},
                ),
                admin_token="WRONG",
            )
    finally:
        await tzun.close()
