"""Anchor §8.4, §11: records the anchor scheduler filled parse in the Python models.

The TS harness stores records in a SQLite store, runs the scheduler to
finality against an in-memory chain, and returns the records as the store
holds them: each carries `nonRepudiation.anchor` and an `anchor_fill`
revision. The Python wire models must accept them unchanged, and the
artifact must still verify in TS after the round trip.
"""

from __future__ import annotations

from tzun_sdk.models import AnchorArtifact, EvidenceEnvelope


def test_scheduler_filled_records_parse_and_round_trip(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    filled = ts_invoke({"action": "scheduler-fill", "chainId": "default", "count": 3})
    envelopes = filled["envelopes"]
    assert len(envelopes) == 3
    assert filled["causes"] == [["capture", "anchor_fill"]] * 3

    for envelope in envelopes:
        model = EvidenceEnvelope.model_validate(envelope)
        assert isinstance(model.nonRepudiation.anchor, AnchorArtifact)
        assert model.nonRepudiation.anchor.leafIndex == envelope["payload"]["sequenceNumber"] - 1
        assert model.model_dump(mode="json", exclude_unset=True) == envelope

        verdict = ts_invoke({"action": "verify-anchor", "envelope": envelope, "chainId": "default"})
        assert verdict["anchorPresent"] is True
        assert verdict["merkleProofValid"] is True

    # The fill leaves a pending record without a timestamp pending (review P1).
    assert [e["attestationStatus"] for e in envelopes] == ["pending", "partial", "partial"]
