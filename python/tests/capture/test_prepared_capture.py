"""A prepared capture stores what its input resolves to, never the prepared object's word for it (Record §6, §6.9, §8.7, §9.1).

``prepare_assertion_challenge`` hands back the record a ceremony signs; the
capture that stores it resolves its input again with every writer rule and
requires the prepared members to be the resolved ones. The prepared
expectation passes the caller's expectation rules, and the prepared identity
the rules for a client-chosen evidence id and capture time.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import pytest

from tests._stores import store  # noqa: F401 - the fixture
from tzun_sdk import Tzun
from tzun_sdk._capture import payload_digest
from tzun_sdk.attestation.webauthn import webauthn_challenge_for_digest
from tzun_sdk.errors import (
    InvalidDeciderError,
    InvalidPayloadError,
    InvalidSignoffExpectationError,
)
from tzun_sdk.storage import MemoryAdapter

HUMAN = {"kind": "human", "id": "acct:u-1"}
INPUT: dict[str, Any] = {"ai_output": {"x": 1}, "action": "approve", "reason": "r", "decider": HUMAN, "ai_system_id": "sys"}


@pytest.fixture
async def tzun(store: Any) -> Any:  # noqa: F811 - the fixture
    t = await Tzun.init(storage=store)
    yield t
    await t.close()


def _now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


async def _forged(tzun: Tzun, **members: Any) -> dict[str, Any]:
    """A prepared object built by hand at the chain's next position, its digest over the members given."""
    seq, previous = await tzun._head_parts()
    evidence_id, at = str(uuid.uuid4()), _now()
    decider = members.pop("decider", {**HUMAN, "agent": None, "credential": None, "freshness": None})
    payload = {
        "evidenceId": evidence_id,
        "schemaVersion": "v1.0",
        "aiSystemId": "sys",
        "aiOutput": {"x": 1},
        "action": "approve",
        "reason": "r",
        "capturedAt": at,
        "sequenceNumber": seq + 1,
        "decider": decider,
        "contributions": members.get("contributions"),
        "links": members.get("links"),
        "signoffExpectation": members.get("signoffExpectation"),
    }
    digest = payload_digest(payload)
    return {
        "digest": digest,
        "challenge": webauthn_challenge_for_digest(digest),
        "evidenceId": evidence_id,
        "capturedAt": at,
        "sequenceNumber": seq + 1,
        "previousDigest": previous,
        "signoffExpectation": payload["signoffExpectation"],
        "decider": decider,
        "contributions": payload["contributions"],
        "links": payload["links"],
    }


async def test_a_prepared_record_is_stored_as_it_was_prepared(tzun: Tzun) -> None:
    parent = await tzun.capture(**INPUT)
    links = [{"rel": "derivedFrom", "target": {"evidenceId": parent.evidenceId}}]
    committed = {"kind": "human", "id": "acct:u-2", "commit": True}
    prepared = await tzun.prepare_assertion_challenge(**{**INPUT, "decider": committed}, links=links)
    stored = await tzun.capture(**{**INPUT, "decider": committed}, links=links, prepared=prepared)
    assert stored.canonicalDigest == prepared["digest"]
    assert stored.evidenceId == prepared["evidenceId"]
    assert stored.deciderOpening is not None and stored.deciderOpening.salt == prepared["deciderOpening"]["salt"]
    assert (await tzun.verify(stored.evidenceId)).valid is True


async def test_a_prepared_mandate_form_expectation_is_refused(tzun: Tzun) -> None:
    form = {"mandateAssertion": "aa" * 32, "mandateSeq": 1, "totals": None, "confirm": False}
    prepared = await _forged(tzun, signoffExpectation=form)
    with pytest.raises(InvalidSignoffExpectationError) as exc:
        await tzun.capture(**INPUT, prepared=prepared)
    assert exc.value.violation == "mandate_form_not_writable"
    session = {"statementDigest": "bb" * 32, "sessionSeq": 1}
    prepared = await _forged(tzun, signoffExpectation=session)
    with pytest.raises(InvalidSignoffExpectationError) as sess:
        await tzun.capture(**INPUT, prepared=prepared)
    assert sess.value.violation == "session_form_not_writable"


async def test_prepared_members_the_input_does_not_resolve_to_are_refused(tzun: Tzun) -> None:
    reserved = [{"rel": "mandate", "target": {"digest": "bb" * 32, "evidenceId": None, "locator": None}, "attrs": None}]
    prepared = await _forged(tzun, links=reserved)
    before, _ = await tzun._head_parts()
    with pytest.raises(InvalidDeciderError) as links:
        await tzun.capture(**INPUT, prepared=prepared)
    assert (links.value.code, links.value.field) == ("invalid_prepared", "prepared.links")
    agent = "sha256:" + "7" * 64
    unregistered = {"kind": "agent-mandated", "id": f"desc:{agent}", "agent": agent, "credential": None, "freshness": None}
    prepared = await _forged(tzun, decider=unregistered)
    with pytest.raises(InvalidDeciderError) as decider:
        await tzun.capture(**INPUT, prepared=prepared)
    assert (decider.value.code, decider.value.field) == ("invalid_prepared", "prepared.decider")
    assert (await tzun._head_parts())[0] == before


async def test_a_prepared_record_for_another_input_is_refused_at_its_own_position(tzun: Tzun) -> None:
    prepared = await tzun.prepare_assertion_challenge(**INPUT)
    with pytest.raises(InvalidDeciderError) as exc:
        await tzun.capture(**{**INPUT, "reason": "another reason"}, prepared=prepared)
    assert (exc.value.code, exc.value.field) == ("invalid_prepared", "prepared.digest")


async def test_a_prepared_identity_is_held_to_the_client_identity_rules() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        prepared = await tzun.prepare_assertion_challenge(**INPUT)
        ahead = (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        with pytest.raises(InvalidPayloadError) as future:
            await tzun.capture(**INPUT, prepared={**prepared, "capturedAt": ahead})
        assert (future.value.code, future.value.field) == ("invalid_captured_at", "prepared.capturedAt")
        with pytest.raises(InvalidPayloadError) as eid:
            await tzun.capture(**INPUT, prepared={**prepared, "evidenceId": "not-a-uuid"})
        assert (eid.value.code, eid.value.field) == ("invalid_evidence_id", "prepared.evidenceId")
        with pytest.raises(InvalidDeciderError) as decider:
            await tzun.capture(**INPUT, prepared={**prepared, "decider": "acct:u-1"})
        assert (decider.value.code, decider.value.field) == ("invalid_prepared", "prepared.decider")
        with pytest.raises(InvalidDeciderError) as shape:
            await tzun.capture(**INPUT, prepared={"digest": 5})
        assert shape.value.code == "invalid_prepared"
    finally:
        await tzun.close()
