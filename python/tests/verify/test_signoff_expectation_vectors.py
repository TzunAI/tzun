"""vectors/signoff-expectation-vectors.json (Record §9.2, §9.4; Verification §5).

The Python SDK gives every answer the file states, as the TS engine does
(tests/ts/signoff-expectation-vectors.test.ts): the expectation's shape rule,
the sign-off statement digest, the check against a record's sign-off material,
the rule that recognises a record captured before 0.7.0, and what
``Tzun.verify()`` and ``export_evidence()``'s verdict report for a whole
record, whose expectation they read only when its digest recomputes. Each
envelope is also loaded through the generated models and checked again,
because that is the form ``Tzun.verify()`` and ``Tzun.init()`` hold a record
in.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from tzun_sdk import Tzun
from tzun_sdk.models import EvidenceEnvelope
from tzun_sdk.signoff_expectation import (
    check_signoff_expectation,
    record_predates_signoff_expectation,
    signoff_expectation_violation,
    signoff_statement_challenge,
    signoff_statement_digest,
)
from tzun_sdk.storage.sqlite import SqliteAdapter

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[3] / "vectors" / "signoff-expectation-vectors.json").read_text(
        encoding="utf-8"
    )
)


def test_the_file_holds_every_part() -> None:
    assert len(VECTORS["shapes"]) > 20
    assert len(VECTORS["statementDigests"]) > 0
    assert len(VECTORS["checks"]) > 15
    assert len(VECTORS["predates"]) > 2
    assert len(VECTORS["verifications"]) > 5


@pytest.mark.parametrize("case", VECTORS["shapes"], ids=lambda c: c["case"])
def test_shape(case: dict[str, Any]) -> None:
    assert signoff_expectation_violation(case["value"]) == case["violation"]


@pytest.mark.parametrize("case", VECTORS["statementDigests"], ids=lambda c: c["case"])
def test_statement_digest(case: dict[str, Any]) -> None:
    assert signoff_statement_digest(case["statement"]) == case["digest"]
    challenge = None if case["digest"] is None else signoff_statement_challenge(case["digest"])
    assert challenge == case["challenge"]


@pytest.mark.parametrize("case", VECTORS["checks"], ids=lambda c: c["case"])
def test_check(case: dict[str, Any]) -> None:
    assert check_signoff_expectation(case["envelope"]) == case["expect"]
    # Loaded through the models from a dict and from the JSON text a store
    # holds, as Tzun.verify() and Tzun.init() hold a record: the model must
    # neither coerce a value (a slot of "4" read as 4) nor refuse the record,
    # and it must dump what it loaded.
    for model in (
        EvidenceEnvelope.model_validate(case["envelope"]),
        EvidenceEnvelope.model_validate_json(json.dumps(case["envelope"])),
    ):
        assert model.model_dump(mode="json", exclude_unset=True) == case["envelope"]
        assert json.loads(model.model_dump_json(exclude_unset=True)) == case["envelope"]
        assert check_signoff_expectation(model) == case["expect"]


_OLD_NAMES = ("humanAction", "humanReason", "aiBom")


@pytest.mark.parametrize("case", VECTORS["predates"], ids=lambda c: c["case"])
def test_predates(case: dict[str, Any]) -> None:
    assert record_predates_signoff_expectation(case["envelope"]) is case["expect"]
    if any(name in case["envelope"]["payload"] for name in _OLD_NAMES):
        # A record of an earlier field set is read from its stored JSON: the
        # models are this release's, and refuse the 0.7 names.
        with pytest.raises(ValueError):
            EvidenceEnvelope.model_validate(case["envelope"])
        return
    for model in (
        EvidenceEnvelope.model_validate(case["envelope"]),
        EvidenceEnvelope.model_validate_json(json.dumps(case["envelope"])),
    ):
        assert record_predates_signoff_expectation(model) is case["expect"]


@pytest.mark.parametrize("case", VECTORS["verifications"], ids=lambda c: c["case"])
async def test_verification(case: dict[str, Any], tmp_path: pathlib.Path) -> None:
    """``Tzun.verify()`` and the export's verdict over a SQLite store holding the case's record."""
    expected = case["expect"]
    path = str(tmp_path / "store.db")
    # Opened first, so the store check sees an empty store; the record is then
    # written as a store writer would write it.
    tzun = await Tzun.init(storage=SqliteAdapter(path))
    try:
        writer = SqliteAdapter(path)
        await writer.ensure_tables()
        # The stored JSON as a store writer would write it.
        await writer.store(json.loads(json.dumps(case["envelope"])))
        await writer.close()
        evidence_id = case["envelope"]["payload"]["evidenceId"]
        result = await tzun.verify(evidence_id)
        assert result.valid is expected["verified"]
        assert result.signoffExpectationValid == expected["signoffExpectation"]["valid"]
        assert result.signoffExpectationReason == expected["signoffExpectation"].get("reason")
        payload = case["envelope"]["payload"]
        if any(name in payload for name in _OLD_NAMES):
            # An earlier field set reproduces the stored digest: the fact names
            # it. A 0.7 release wrote signoffExpectation; earlier ones did not.
            assert result.fieldSet == ("0.7" if "signoffExpectation" in payload else "before-0.7")
            return
        exported = await tzun.export_evidence(evidence_id)
        assert exported.verdict.signoffExpectation is not None
        assert exported.verdict.signoffExpectation.valid == expected["signoffExpectation"]["valid"]
        assert exported.verdict.signoffExpectation.reason == expected["signoffExpectation"].get(
            "reason"
        )
    finally:
        await tzun.close()
