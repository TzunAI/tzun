"""TamperDetector + MonitoringEventType."""

from __future__ import annotations

from tests._raw import RawView
from tzun_sdk import Tzun
from tzun_sdk.monitoring import MonitoringEventType, TamperDetector
from tzun_sdk.storage import MemoryAdapter


def test_monitoring_event_type_union_matches_ts() -> None:
    """The event-type union matches the TS SDK exactly."""
    assert set(MonitoringEventType) == {
        "digest_mismatch",
        "chain_break",
        "sequence_gap",
        "descriptor_resolution_failure",
        "descriptor_digest_mismatch",
        "parent_descriptor_resolution_failure",
        "parent_descriptor_digest_mismatch",
        "incident_annotated",
    }


async def test_detector_clean_envelope_no_incident() -> None:
    """A freshly captured envelope verifies clean — no incidents."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        env = RawView(tzun._storage._envelopes[result.evidenceId])
        incidents = await TamperDetector().detect(env.raw)
        assert incidents == []
    finally:
        await tzun.close()


async def test_detector_flags_digest_mismatch() -> None:
    """A tampered payload yields a digest_mismatch incident."""
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
        )
        env = RawView(tzun._storage._envelopes[result.evidenceId])
        env.payload.reason = "TAMPERED"
        incidents = await TamperDetector().detect(env.raw)
        assert len(incidents) == 1
        assert incidents[0].eventType == "digest_mismatch"
        assert incidents[0].evidenceId == result.evidenceId
        assert incidents[0].details["expected"] == result.canonicalDigest
    finally:
        await tzun.close()


async def test_detector_stamps_detection_time_not_capture_time() -> None:
    """detectedAt is when the tamper was DETECTED, not payload.capturedAt.

    capturedAt is attacker-influenced payload data and is always earlier than
    detection, which made incident timelines wrong.
    """
    import datetime

    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        result = await tzun.capture(
            ai_output={"r": "x"},
            decider={"kind": "human", "id": "acct:test-reviewer"}, action="approved",
            reason="ok",
            captured_at="2020-01-01T00:00:00.000Z",
        )
        env = RawView(tzun._storage._envelopes[result.evidenceId])
        env.payload.reason = "TAMPERED"
        before = datetime.datetime.now(datetime.UTC)
        incidents = await TamperDetector().detect(env.raw)
        after = datetime.datetime.now(datetime.UTC)

        assert len(incidents) == 1
        detected_at = incidents[0].detectedAt
        assert detected_at != env.payload.capturedAt
        parsed = datetime.datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
        # Allow a millisecond of truncation slack at each end.
        slack = datetime.timedelta(milliseconds=1)
        assert before - slack <= parsed <= after + slack
    finally:
        await tzun.close()
