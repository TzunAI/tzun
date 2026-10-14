"""Anchor §8: an anchored envelope crosses TS → Python → TS unchanged.

The TS harness attaches a tzun-anchor/1 artifact (`nonRepudiation.anchor`,
§8) to a captured envelope; the Python wire models parse it and dump it back
byte-for-byte; `verifyAnchor` in TS then checks the round-tripped artifact's
proofs against the record. An anchor this build does not read crosses Python
unchanged too, and TS abstains on it (§10.3).
"""

from __future__ import annotations

import copy

import pytest

from tzun_sdk.models import AnchorArtifact, EvidenceEnvelope


def test_an_anchored_envelope_round_trips_through_the_python_models(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    captured = ts_invoke(
        {"action": "capture", "aiOutput": {"score": 0.7}, "decision": {"action": "approved", "reason": "ok"}}
    )["envelope"]
    anchored = ts_invoke({"action": "anchor-envelope", "envelope": captured, "chainId": "default"})["envelope"]

    model = EvidenceEnvelope.model_validate(anchored)
    assert isinstance(model.nonRepudiation.anchor, AnchorArtifact)
    assert model.nonRepudiation.anchor.leafIndex == anchored["payload"]["sequenceNumber"] - 1

    dumped = model.model_dump(mode="json", exclude_unset=True)
    assert dumped == anchored

    # Steps 1 to 5 of tzun-anchor/1 §10.3 hold on what Python handed back: the
    # tags, both bodies, the origin (with the chain), the position and both
    # inclusion proofs. The publications are placeholders, and not the point.
    verdict = ts_invoke({"action": "verify-anchor", "envelope": dumped, "chainId": "default"})
    assert verdict["anchorPresent"] is True
    outcomes = {c["id"]: c for c in verdict["checks"]}
    for check in ("anchor.spec", "anchor.checkpoint", "anchor.origin", "anchor.leafIndex", "anchor.inclusion", "anchor.anchorInclusion"):
        assert outcomes[check]["outcome"] == "checked-correct", outcomes[check]
    assert outcomes["anchor.origin"]["facts"]["chainChecked"] is True


def _anchored(ts_invoke) -> dict:  # type: ignore[no-untyped-def]
    captured = ts_invoke(
        {"action": "capture", "aiOutput": {"score": 0.7}, "decision": {"action": "approved", "reason": "ok"}}
    )["envelope"]
    return ts_invoke({"action": "anchor-envelope", "envelope": captured, "chainId": "default"})["envelope"]


@pytest.mark.parametrize("tag", ["tzun-anchor/2", None])
def test_an_anchor_under_another_tag_crosses_python_unchanged_and_ts_abstains(ts_invoke, tag) -> None:  # type: ignore[no-untyped-def]
    envelope = copy.deepcopy(_anchored(ts_invoke))
    if tag is None:
        del envelope["nonRepudiation"]["anchor"]["anchorSpec"]
    else:
        envelope["nonRepudiation"]["anchor"]["anchorSpec"] = tag

    model = EvidenceEnvelope.model_validate(envelope)
    assert not isinstance(model.nonRepudiation.anchor, AnchorArtifact)
    dumped = model.model_dump(mode="json", exclude_unset=True)
    assert dumped == envelope

    verdict = ts_invoke({"action": "verify-anchor", "envelope": dumped, "chainId": "default"})
    assert verdict["anchorValid"] is None
    assert verdict["anchorReason"] == "unsupported_anchor_spec"


def test_a_publication_of_a_reserved_kind_crosses_python_unchanged_and_ts_abstains_on_it(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    envelope = copy.deepcopy(_anchored(ts_invoke))
    envelope["nonRepudiation"]["anchor"]["publications"].append({"kind": "witness/1", "cosignature": "x"})

    model = EvidenceEnvelope.model_validate(envelope)
    dumped = model.model_dump(mode="json", exclude_unset=True)
    assert dumped == envelope

    verdict = ts_invoke({"action": "verify-anchor", "envelope": dumped, "chainId": "default"})
    assert verdict["merkleProofValid"] is True
    witness = verdict["publications"][-1]
    assert witness == {"index": 2, "kind": "witness/1", "valid": None, "reason": "unsupported_publication_kind"}
