# python/tests/core/test_anchor_artifact_model.py — the record artifact (tzun-anchor/1 §8).
#
# `AnchorArtifact` is `nonRepudiation.anchor` exactly as tzun-anchor/1 §8.1
# and §8.2 define it: nine members, non-negative integer indices, and at least
# one publication entry, of two kinds. `blockchainAnchor` is not part of the
# spec and no writer writes it (tzun-anchor/1 §8.4).
#
# An envelope loads whatever its `anchor` holds (tzun-anchor/1 §10.1: verification never
# throws; §10.3 step 1: an artifact under another tag is abstained on). A value
# `AnchorArtifact` does not take is kept exactly as it was read, so the
# envelope round-trips unchanged and the verifier decides on it.
from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from tzun_sdk._generated.models import VerificationResult
from tzun_sdk.models import (
    AnchorArtifact,
    EvidenceEnvelope,
    EvmAnchorPublication,
    Rfc3161AnchorPublication,
)

HEX = "ab" * 32

ANCHOR = {
    "anchorSpec": "tzun-anchor/1",
    "merkleSpec": "rfc6962",
    "leafIndex": 41,
    "logCheckpoint": "local.invalid/" + "3f" * 16 + "/evidence/64656661756c74\n1024\n" + "A" * 43 + "=\n",
    "logPath": [HEX] * 10,
    "anchorLeafIndex": 377,
    "anchorCheckpoint": "local.invalid/" + "3f" * 16 + "/anchors\n412\n" + "B" * 43 + "=\n",
    "anchorPath": [HEX] * 9,
    "publications": [
        {
            "kind": "evm-calldata/1",
            "chain": "eip155:11155111",
            "transactionId": "0x" + "5d" * 32,
            "blockNumber": 11781565,
            "blockHash": "0x" + "cd" * 32,
            "publisher": "0x" + "b6" * 20,
        },
        {"kind": "rfc3161/1", "token": "MIIB"},
    ],
}


def _envelope(non_repudiation: dict) -> dict:
    return {
        "envelopeVersion": "e1",
        "payload": {
            "evidenceId": "00000000-0000-4000-8000-000000000042",
            "schemaVersion": "v1.0",
            "aiSystemId": "default",
            "aiOutput": {"recommendation": "approve"},
            "action": "approved",
            "decider": {"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            "reason": "ok",
            "capturedAt": "2026-09-25T12:00:00.000Z",
            "sequenceNumber": 42,
            "contributions": None,
            "links": None,
        },
        "integrity": {"canonicalDigest": HEX, "chainLink": None},
        "nonRepudiation": non_repudiation,
        "custodyChain": [],
        "attestationStatus": "partial",
    }


def test_an_anchored_envelope_parses_and_round_trips():
    env = EvidenceEnvelope.model_validate(_envelope({"anchor": ANCHOR}))
    anchor = env.nonRepudiation.anchor
    assert isinstance(anchor, AnchorArtifact)
    assert anchor.leafIndex == 41
    assert isinstance(anchor.publications[0], EvmAnchorPublication)
    assert isinstance(anchor.publications[1], Rfc3161AnchorPublication)
    assert anchor.publications[0].blockNumber == 11781565
    dumped = env.model_dump(mode="json", exclude_none=True)
    assert dumped["nonRepudiation"]["anchor"] == ANCHOR


def test_a_record_not_yet_anchored_has_no_anchor_key():
    env = EvidenceEnvelope.model_validate(_envelope({"rfc3161Token": "MIIB"}))
    assert env.nonRepudiation.anchor is None
    assert "anchor" not in env.model_dump(mode="json", exclude_none=True)["nonRepudiation"]


def test_a_member_outside_section_8_1_is_not_an_anchor_artifact():
    anchor = {**ANCHOR, "treeSize": 1024}
    with pytest.raises(ValidationError):
        AnchorArtifact.model_validate(anchor)
    _assert_loaded_verbatim(anchor)


def _mutated(mutate) -> dict:
    anchor = copy.deepcopy(ANCHOR)
    mutate(anchor)
    return anchor


def _assert_loaded_verbatim(anchor) -> None:
    raw = _envelope({"anchor": anchor})
    env = EvidenceEnvelope.model_validate(raw)
    assert not isinstance(env.nonRepudiation.anchor, AnchorArtifact)
    assert env.nonRepudiation.anchor == anchor
    assert env.model_dump(mode="json", exclude_unset=True) == raw


# What pydantic's lax mode would coerce into an int, and what the TS verifier
# refuses: the model refuses both, rather than writing a coerced value back.
LOOSE_INDICES = [
    ("leafIndex as a numeric string", lambda a: a.__setitem__("leafIndex", "41")),
    ("leafIndex as a float", lambda a: a.__setitem__("leafIndex", 41.0)),
    ("leafIndex as a bool", lambda a: a.__setitem__("leafIndex", True)),
    ("leafIndex negative", lambda a: a.__setitem__("leafIndex", -1)),
    ("leafIndex past 2^53 - 1", lambda a: a.__setitem__("leafIndex", 2**60)),
    ("anchorLeafIndex as a numeric string", lambda a: a.__setitem__("anchorLeafIndex", "377")),
    ("anchorLeafIndex negative", lambda a: a.__setitem__("anchorLeafIndex", -1)),
    ("blockNumber as a numeric string", lambda a: a["publications"][0].__setitem__("blockNumber", "11781565")),
    ("blockNumber as a bool", lambda a: a["publications"][0].__setitem__("blockNumber", False)),
    ("blockNumber negative", lambda a: a["publications"][0].__setitem__("blockNumber", -1)),
    ("no publication", lambda a: a.__setitem__("publications", [])),
]


@pytest.mark.parametrize(("label", "mutate"), LOOSE_INDICES, ids=[label for label, _ in LOOSE_INDICES])
def test_the_model_takes_no_coerced_index_and_no_empty_publication_list(label, mutate):
    with pytest.raises(ValidationError):
        AnchorArtifact.model_validate(_mutated(mutate))


@pytest.mark.parametrize(("label", "mutate"), LOOSE_INDICES, ids=[label for label, _ in LOOSE_INDICES])
def test_an_envelope_with_such_an_anchor_loads_it_verbatim(label, mutate):
    _assert_loaded_verbatim(_mutated(mutate))


def test_the_largest_exact_json_integer_is_an_index():
    anchor = _mutated(lambda a: a.__setitem__("leafIndex", 2**53 - 1))
    assert AnchorArtifact.model_validate(anchor).leafIndex == 2**53 - 1


FOREIGN_ANCHORS = [
    ("another anchorSpec", _mutated(lambda a: a.__setitem__("anchorSpec", "tzun-anchor/2"))),
    ("another merkleSpec", _mutated(lambda a: a.__setitem__("merkleSpec", "rfc6962-v2"))),
    ("the reserved witness/1 kind", _mutated(lambda a: a["publications"].append({"kind": "witness/1", "sig": "x"}))),
    ("a publication that is null", _mutated(lambda a: a["publications"].append(None))),
    ("no tags at all", {}),
    ("a string", "garbage"),
    ("false", False),
    ("zero", 0),
]


@pytest.mark.parametrize(("label", "anchor"), FOREIGN_ANCHORS, ids=[label for label, _ in FOREIGN_ANCHORS])
def test_an_envelope_loads_an_anchor_this_build_does_not_read(label, anchor):
    _assert_loaded_verbatim(anchor)


def test_every_member_is_required():
    for member in ANCHOR:
        anchor = {k: v for k, v in ANCHOR.items() if k != member}
        with pytest.raises(ValidationError):
            AnchorArtifact.model_validate(anchor)


def test_an_evm_entry_carries_every_member_and_no_other():
    entry = ANCHOR["publications"][0]
    for member in entry:
        partial = {k: v for k, v in entry.items() if k != member}
        with pytest.raises(ValidationError):
            EvmAnchorPublication.model_validate(partial)
    # The heavy material travels in the export bundle, never in the envelope.
    with pytest.raises(ValidationError):
        EvmAnchorPublication.model_validate({**entry, "rawTransaction": "0x02"})


def test_the_tags_are_the_spec_tags():
    for member, value in (("anchorSpec", "tzun-anchor/2"), ("merkleSpec", "rfc6962-v2")):
        anchor = copy.deepcopy(ANCHOR)
        anchor[member] = value
        with pytest.raises(ValidationError):
            AnchorArtifact.model_validate(anchor)


def test_the_publication_kinds_are_the_spec_kinds():
    with pytest.raises(ValidationError):
        AnchorArtifact.model_validate(_mutated(lambda a: a["publications"].append({"kind": "witness/1", "sig": "x"})))


def test_blockchain_anchor_is_not_a_wire_field():
    legacy = {
        "chain": "ethereum-sepolia",
        "transactionId": "0x" + "ff" * 32,
        "batchMerkleRoot": HEX,
        "merklePath": [],
        "leafIndex": 0,
        "treeSize": 1,
        "merkleSpec": "rfc6962",
    }
    with pytest.raises(ValidationError):
        EvidenceEnvelope.model_validate(_envelope({"blockchainAnchor": legacy}))


def test_the_anchor_stages_are_the_three_of_section_5_1_and_anchor_invalid():
    from typing import get_args

    from tzun_sdk._generated.models import RecordAnchorStage

    assert set(get_args(RecordAnchorStage)) == {"awaiting_epoch", "awaiting_finality", "anchored", "anchor_invalid"}


def test_the_record_log_findings():
    from typing import get_args

    from tzun_sdk._generated.models import RecordLogFinding

    assert set(get_args(RecordLogFinding)) == {
        "digest_differs_from_logged_leaf",
        "anchor_stripped",
        "anchor_transplanted",
        "anchor_checkpoint_not_published",
    }


def test_the_engine_verdict_field_is_anchor_valid():
    fields = VerificationResult.model_fields
    assert "anchorValid" in fields
    assert "blockchainAnchorValid" not in fields


def _verification(**anchor_fields):
    return {
        "verified": True,
        "storedDigest": "a" * 64,
        "recomputedDigest": "a" * 64,
        "schemaVersion": "v1.0",
        "schemaValid": True,
        "chainLinkValid": None,
        "signatureValid": None,
        "timestampValid": None,
        "anchorValid": True,
        "attestationStatus": "partial",
        "verifiedAt": "2026-09-25T10:00:00.000Z",
        **anchor_fields,
    }


@pytest.mark.parametrize(
    "finality",
    ["finalized", {"confirmations": 64}, {"confirmations": 2, "acceptNonFinal": True}, None],
)
def test_the_verdict_carries_the_anchor_namespace_finality_and_existed_by(finality):
    result = VerificationResult.model_validate(
        _verification(
            anchorNamespace="test",
            anchorFinality=finality,
            existedBy={"at": "2026-09-25T10:00:00.000Z", "source": "evm-calldata"},
        )
    )
    assert result.anchorNamespace == "test"
    dumped = result.model_dump(mode="json", exclude_none=True)
    if finality is None:
        assert "anchorFinality" not in dumped
    else:
        assert dumped["anchorFinality"] == finality
    assert dumped["existedBy"] == {"at": "2026-09-25T10:00:00.000Z", "source": "evm-calldata"}


@pytest.mark.parametrize(
    "fields",
    [
        {"anchorNamespace": "staging"},
        {"anchorFinality": "latest"},
        {"anchorFinality": {"confirmations": 2.5}},
        {"anchorFinality": {"confirmations": 2, "extra": 1}},
        {"existedBy": {"at": "2026-09-25T10:00:00.000Z", "source": "witness"}},
    ],
)
def test_the_verdict_refuses_anchor_fields_outside_their_shapes(fields):
    with pytest.raises(ValidationError):
        VerificationResult.model_validate(_verification(**fields))
