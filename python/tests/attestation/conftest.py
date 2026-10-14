"""Fixtures for attestation tests."""
from __future__ import annotations

import pytest

from tzun_sdk.core import Tzun
from tzun_sdk.models import EvidenceEnvelope
from tzun_sdk.storage.memory import MemoryAdapter


@pytest.fixture
async def envelope_fixture() -> EvidenceEnvelope:
    """A captured EvidenceEnvelope for attestation tests."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"d": 1},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        envelope = await tzun._storage.retrieve(result.evidenceId)
    finally:
        await tzun.close()
    assert envelope is not None
    return envelope
