# python/tests/attestation/test_circuit.py — the TSA circuit breaker (3 failures / 60 s / single probe).
from __future__ import annotations

import pytest

from tzun_sdk.attestation import rfc3161
from tzun_sdk.attestation.rfc3161 import RFC3161Backend
from tzun_sdk.errors import TsaUnavailableError


async def test_breaker_opens_after_3_and_half_open_probes(
    envelope_fixture, monkeypatch, caplog
):
    """Breaker opens after 3 consecutive failures; half-open probes once."""
    import logging
    caplog.set_level(logging.INFO, logger="tzun_sdk.attestation.rfc3161")

    async def failing(url, body, timeout):
        raise ConnectionError("down")

    b = RFC3161Backend(transport=failing)
    for _ in range(3):
        with pytest.raises(TsaUnavailableError):
            await b.attest(envelope_fixture)

    # 4th call: circuit OPEN — fails fast without invoking transport
    with pytest.raises(TsaUnavailableError, match="OPEN"):
        await b.attest(envelope_fixture)

    # Advance the monotonic clock past the 60s cool-down → half-open single probe
    real = rfc3161.time.monotonic()
    monkeypatch.setattr(rfc3161.time, "monotonic", lambda: real + 61.0)

    ok_calls = []
    # The probe response is a real TimeStampResp from the mock TSA: the client
    # fails closed on a body it cannot parse, so a stub body would count as
    # another failure and the breaker would never close. The test asserts one
    # probe, and that the breaker closes after it.
    from tests.attestation.mock_tsa import mock_tsa_transport

    mock = mock_tsa_transport()

    async def ok(url, body, timeout):
        ok_calls.append(1)
        return await mock(url, body, timeout)

    b._transport = ok  # swap transport for the probe
    blob = await b.attest(envelope_fixture)
    assert blob is not None and len(ok_calls) == 1
    assert b._state == "closed"
    # State-change log events present
    assert any("rfc3161_circuit_state_change" in r.message for r in caplog.records)


async def test_breaker_threshold_is_3(envelope_fixture):
    """Exactly 3 failures open the breaker (TS rfc3161.ts failureThreshold=3)."""
    async def failing(url, body, timeout):
        raise ConnectionError("down")

    b = RFC3161Backend(transport=failing)
    # First 2 failures: circuit still CLOSED (breaker not yet open)
    for _ in range(2):
        with pytest.raises(TsaUnavailableError):
            await b.attest(envelope_fixture)

    assert b._state == "closed"

    # 3rd failure: breaker opens
    with pytest.raises(TsaUnavailableError):
        await b.attest(envelope_fixture)

    assert b._state == "open"


@pytest.mark.skipif(
    not __import__("os").environ.get("RUN_INTEGRATION_TESTS"),
    reason="integration test — set RUN_INTEGRATION_TESTS=true to run",
)
async def test_live_freetsa_grants(envelope_fixture):
    """Live network test — only runs when RUN_INTEGRATION_TESTS=true."""
    blob = await RFC3161Backend().attest(envelope_fixture)
    assert blob is not None
    assert blob.rfc3161Token is not None
