"""Mandates end to end (Record §9.6 to §9.11): issue, capture under a mandate, confirm, revoke, supersede, expire.

Every case runs on each local store (memory, SQLite, and Postgres when the
integration gate is on). The principal's and revoker's assertions are real
Ed25519 WebAuthn assertions over the challenges the SDK hands out; the
verifier stands in for the relying party's credential store, except in the
case that verifies them with ``WebAuthnAssertionVerifier`` over py_webauthn.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid
from typing import Any

import pytest

from tests._stores import store  # noqa: F401 - the fixture
from tests._webauthn import ORIGIN, RP_ID, Authenticator, FakeVerifier
from tests.storage.test_catalog_primitives import mvd
from tzun_sdk import Tzun, TzunSync
from tzun_sdk.errors import InvalidMandateError, MandateRefusedError
from tzun_sdk.mandate.statement import mandate_confirmation_challenge
from tzun_sdk.mandates_api import WebAuthnAssertionVerifier
from tzun_sdk.storage import MemoryAdapter

PRINCIPAL = "user-2c9d"
REVOKER = "ops-7"
SYSTEM = "claims-triage-v4"


def _iso(at: dt.datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"


class World:
    """A Tzun with a registered model and agent, an authenticator and a verifier."""

    def __init__(self, tzun: Tzun, auth: Authenticator, verifier: Any, model: str, agent: str) -> None:
        self.tzun = tzun
        self.auth = auth
        self.verifier = verifier
        self.model = model
        self.agent = agent
        self.decider = {"kind": "agent-mandated", "id": f"desc:{agent}", "agent": agent}

    def document(self, **over: Any) -> dict[str, Any]:
        now = dt.datetime.now(dt.UTC)
        doc: dict[str, Any] = {
            "v": "tzun-mandate/1",
            "mandateId": str(uuid.uuid4()),
            "principal": {"signer": PRINCIPAL, "credential": None},
            "agents": [f"desc:{self.agent}"],
            "schemaVersion": "v1.0",
            "scope": {
                "aiSystemIds": [SYSTEM],
                "actions": ["approve", "refer"],
                "models": [self.model],
                "predicates": {"cap": {"op": "le", "path": "/aiOutput/amountMinor", "quant": None, "value": 500000}},
            },
            "confirm": {"fraud": {"op": "eq", "path": "/aiOutput/fraudFlag", "quant": None, "value": True}},
            "validity": {"notBefore": _iso(now - dt.timedelta(days=1)), "notAfter": _iso(now + dt.timedelta(days=30))},
            "limits": {"maxRecords": 3, "cumulative": {"paid": {"path": "/aiOutput/amountMinor", "max": 1000000}}},
            "delegation": {"allowed": False, "maxDepth": 0, "attenuation": "subset"},
            "review": {"maxAgeMs": 604800000},
            "policyDigest": None,
            "predecessor": None,
            "parent": None,
        }
        doc.update(over)
        return doc

    async def issue(self, doc: dict[str, Any], signer: str = PRINCIPAL) -> dict[str, Any]:
        prepared = await self.tzun.mandates.prepare(doc)
        return await self.tzun.mandates.issue(
            document=doc, statement=prepared["statement"], assertion=self.auth.sign(signer, prepared["challenge"])
        )

    async def capture(self, mandate_id: str, amount: int, *, fraud: bool = False, action: str = "approve") -> Any:
        return await self.tzun.capture(
            ai_output={"amountMinor": amount, "fraudFlag": fraud},
            action=action,
            reason="matches the estimate",
            decider=self.decider,
            ai_system_id=SYSTEM,
            contributions={
                "steps": [
                    {"role": "propose", "actor": self.decider, "aiBom": {"modelDescriptorDigest": self.model}, "inputs": []}
                ]
            },
            mandate={"mandateId": mandate_id},
        )


async def make_world(storage: Any, *, verifier_of: Any = FakeVerifier) -> World:
    """``verifier_of(authenticator)`` is the assertion verifier (a :class:`FakeVerifier` by default)."""
    auth = Authenticator()
    auth.enrol(PRINCIPAL)
    auth.enrol(REVOKER)
    verifier = verifier_of(auth)
    tzun = await Tzun.init(storage=storage, assertion_verifier=verifier)
    model = await tzun.models.register(mvd())
    registered = await tzun.agents.register(
        {
            "v": "tzun-agent/1",
            "derivation": "base",
            "identities": ["spiffe://claims.example/agent/triage"],
            "instructions": None,
            "keys": [],
            "models": [model],
            "name": "claims-triage-agent",
            "operator": {"organization": "Example Insurer", "owner": None},
            "parent": None,
            "policy": None,
            "runtime": None,
            "tools": None,
        }
    )
    return World(tzun, auth, verifier, model, registered["digest"])


@pytest.fixture
async def world(store: Any) -> Any:  # noqa: F811 - the fixture
    w = await make_world(store)
    yield w
    await w.tzun.close()


async def test_issue_stores_the_mandate_its_event_and_a_verifiable_issuance_record(world: World) -> None:
    doc = world.document()
    issued = await world.issue(doc)
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.state == "open" and row.used == 0
    assert row.mandateDigest == issued["mandateDigest"]
    assert json.loads(row.documentBytes) == doc
    assert [e.body.event for e in await world.tzun.mandates.events(doc["mandateId"])] == ["issued"]
    result = await world.tzun.verify(issued["issuance"].evidenceId)
    assert result.valid is True
    assert result.mandate is not None and result.mandate.issuance is not None
    assert result.mandate.issuance.valid is True
    assert world.verifier.challenges[-1] == (await world.tzun.mandates.prepare(doc))["challenge"]


async def test_captures_under_a_mandate_claim_slots_and_running_totals(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    first = await world.capture(doc["mandateId"], 120000)
    second = await world.capture(doc["mandateId"], 1000, action="refer")
    assert (first.mandate.slot, first.mandate.totals) == (1, {"paid": 120000})
    assert (second.mandate.slot, second.mandate.totals) == (2, {"paid": 121000})
    assert await world.tzun.mandates.totals(doc["mandateId"]) == {"paid": 121000}
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.used == 2
    for evidence_id in (first.evidenceId, second.evidenceId):
        result = await world.tzun.verify(evidence_id)
        assert result.valid is True
        assert result.mandate is not None
        assert result.mandate.scope.valid is True and result.mandate.limits.valid is True
        assert result.links is not None and result.links.relationNames == ["mandate"]
        raw = await world.tzun._stored_raw(evidence_id)
        assert raw is not None
        assert raw["payload"]["signoffExpectation"]["mandateAssertion"] == row.assertionDigest
        custody = raw["custodyChain"]
        assert [(c["action"], c["actor"]) for c in custody] == [
            ("decision_captured", world.decider["id"]),
            ("captured_under_mandate", world.decider["id"]),
        ]
        issuance = await world.tzun._stored_raw(row.issuanceEvidenceId)
        assert issuance is not None
        assert custody[1]["metadata"] == {
            "mandateId": doc["mandateId"],
            "slot": raw["payload"]["signoffExpectation"]["mandateSeq"],
            "statementDigest": issuance["payload"]["aiOutput"]["statementDigest"],
            "assertionDigest": issuance["payload"]["aiOutput"]["assertionDigest"],
        }
        assert raw["nonRepudiation"]["mandate"] == {**issuance["nonRepudiation"]["mandateIssuance"], "document": doc}
    assert all(r.valid for r in await world.tzun.verify_range(1, 3))


@pytest.mark.parametrize(
    ("amount", "action", "code"),
    [
        (600000, "approve", "outside_scope"),
        (1000, "deny", "outside_scope"),
    ],
)
async def test_a_capture_outside_the_scope_is_refused_and_claims_nothing(
    world: World, amount: int, action: str, code: str
) -> None:
    doc = world.document()
    await world.issue(doc)
    with pytest.raises(MandateRefusedError) as exc:
        await world.capture(doc["mandateId"], amount, action=action)
    assert exc.value.code == code
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.used == 0


async def test_the_limits_refuse_a_full_mandate_and_a_cap_overrun(world: World) -> None:
    doc = world.document(limits={"maxRecords": 2, "cumulative": {"paid": {"path": "/aiOutput/amountMinor", "max": 500000}}})
    await world.issue(doc)
    await world.capture(doc["mandateId"], 400000)
    with pytest.raises(MandateRefusedError) as over:
        await world.capture(doc["mandateId"], 200000)
    assert over.value.code == "cap_exceeded"
    await world.capture(doc["mandateId"], 100000)
    with pytest.raises(MandateRefusedError) as full:
        await world.capture(doc["mandateId"], 1)
    assert full.value.code == "mandate_full"
    assert await world.tzun.mandates.totals(doc["mandateId"]) == {"paid": 500000}


async def test_a_record_the_confirm_predicate_holds_for_owes_one_confirmation(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    plain = await world.capture(doc["mandateId"], 1000)
    flagged = await world.capture(doc["mandateId"], 1000, fraud=True)
    raw = await world.tzun._stored_raw(flagged.evidenceId)
    assert raw is not None and raw["payload"]["signoffExpectation"]["confirm"] is True
    assert [c["action"] for c in raw["custodyChain"]] == [
        "decision_captured",
        "captured_under_mandate",
        "confirmation_required",
    ]
    assert raw["custodyChain"][2]["metadata"] == {"mandateId": doc["mandateId"], "slot": 2, "predicates": ["fraud"]}
    challenge = mandate_confirmation_challenge(raw["integrity"]["canonicalDigest"])
    confirmed = await world.tzun.mandates.confirm(flagged.evidenceId, world.auth.sign(PRINCIPAL, challenge))
    assert confirmed == {"evidenceId": flagged.evidenceId, "confirmedBy": f"acct:{PRINCIPAL}"}
    with pytest.raises(MandateRefusedError) as again:
        await world.tzun.mandates.confirm(flagged.evidenceId, world.auth.sign(PRINCIPAL, challenge))
    assert again.value.code == "already_confirmed"
    plain_raw = await world.tzun._stored_raw(plain.evidenceId)
    assert plain_raw is not None
    with pytest.raises(MandateRefusedError) as not_owed:
        await world.tzun.mandates.confirm(
            plain.evidenceId,
            world.auth.sign(PRINCIPAL, mandate_confirmation_challenge(plain_raw["integrity"]["canonicalDigest"])),
        )
    assert not_owed.value.code == "confirmation_not_owed"
    assert (await world.tzun.verify(flagged.evidenceId)).valid is True


async def test_any_verified_account_revokes_and_later_captures_are_refused(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    await world.capture(doc["mandateId"], 2500)
    prepared = await world.tzun.mandates.prepare_revocation(mandate_id=doc["mandateId"], reason="rotating", revoker=REVOKER)
    revocation = await world.tzun.mandates.revoke(
        mandate_id=doc["mandateId"], prepared=prepared, assertion=world.auth.sign(REVOKER, prepared["challenge"])
    )
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.state == "revoked"
    events = await world.tzun.mandates.events(doc["mandateId"])
    assert [e.body.event for e in events] == ["issued", "revoked"]
    assert events[-1].body.used == 1 and events[-1].body.totals == {"paid": 2500}
    result = await world.tzun.verify(revocation.evidenceId)
    assert result.valid is True
    assert result.links is not None and result.links.relationNames == ["revokes"]
    raw = await world.tzun._stored_raw(revocation.evidenceId)
    assert raw is not None and raw["payload"]["decider"]["id"] == f"acct:{REVOKER}"
    with pytest.raises(MandateRefusedError) as exc:
        await world.capture(doc["mandateId"], 1)
    assert exc.value.code == "mandate_not_open"


async def test_a_revocation_signed_by_another_account_than_the_named_revoker_is_refused(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    prepared = await world.tzun.mandates.prepare_revocation(mandate_id=doc["mandateId"], reason="rotating", revoker=REVOKER)
    with pytest.raises(Exception) as exc:
        await world.tzun.mandates.revoke(
            mandate_id=doc["mandateId"], prepared=prepared, assertion=world.auth.sign(PRINCIPAL, prepared["challenge"])
        )
    assert getattr(exc.value, "code", None) == "assertion_not_verified"
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.state == "open"


async def test_a_successor_supersedes_its_predecessor_in_the_issuing_transaction(world: World) -> None:
    first = world.document()
    issued = await world.issue(first)
    await world.capture(first["mandateId"], 7000)
    successor = world.document(predecessor=issued["mandateDigest"])
    replaced = await world.issue(successor)
    old = await world.tzun.mandates.get(first["mandateId"])
    assert old is not None and old.state == "superseded"
    events = await world.tzun.mandates.events(first["mandateId"])
    assert events[-1].body.event == "superseded" and events[-1].body.successor == replaced["mandateDigest"]
    raw = await world.tzun._stored_raw(replaced["issuance"].evidenceId)
    assert raw is not None
    supersedes = [link for link in raw["payload"]["links"] if link["rel"] == "supersedes"]
    assert [link["target"]["evidenceId"] for link in supersedes] == [issued["issuance"].evidenceId]
    assert (await world.tzun.verify(replaced["issuance"].evidenceId)).valid is True
    with pytest.raises(MandateRefusedError) as exc:
        await world.capture(first["mandateId"], 1)
    assert exc.value.code == "mandate_not_open"
    assert (await world.capture(successor["mandateId"], 1)).mandate.slot == 1


async def test_a_successor_for_another_principal_is_refused(world: World) -> None:
    first = world.document()
    issued = await world.issue(first)
    other = world.document(predecessor=issued["mandateDigest"], principal={"signer": REVOKER, "credential": None})
    with pytest.raises(MandateRefusedError) as exc:
        await world.tzun.mandates.prepare(other)
    assert exc.value.code == "predecessor_principal_mismatch"


async def test_expire_due_moves_a_mandate_past_its_window_to_expired(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    await world.capture(doc["mandateId"], 300)
    assert await world.tzun.mandates.expire_due() == []
    later = _iso(dt.datetime.now(dt.UTC) + dt.timedelta(days=31))
    assert await world.tzun.mandates.expire_due(later) == [doc["mandateId"]]
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.state == "expired"
    events = await world.tzun.mandates.events(doc["mandateId"])
    assert events[-1].body.event == "expired" and events[-1].body.used == 1


async def test_issue_refuses_an_assertion_by_anyone_but_the_principal_or_over_another_challenge(world: World) -> None:
    doc = world.document()
    prepared = await world.tzun.mandates.prepare(doc)
    with pytest.raises(InvalidMandateError) as other_user:
        await world.tzun.mandates.issue(
            document=doc, statement=prepared["statement"], assertion=world.auth.sign(REVOKER, prepared["challenge"])
        )
    assert other_user.value.code == "assertion_not_verified"
    with pytest.raises(InvalidMandateError) as other_challenge:
        await world.tzun.mandates.issue(
            document=doc, statement=prepared["statement"], assertion=world.auth.sign(PRINCIPAL, "A" * 43)
        )
    assert other_challenge.value.code == "assertion_not_verified"
    assert await world.tzun.mandates.get(doc["mandateId"]) is None


async def test_the_caller_writes_neither_the_mandate_form_nor_an_expectation_beside_a_mandate(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    mandate_form = {"mandateAssertion": "a" * 64, "mandateSeq": 1, "totals": None, "confirm": False}
    with pytest.raises(Exception) as form:
        await world.tzun.capture(
            ai_output={"amountMinor": 1, "fraudFlag": False},
            action="approve",
            reason="r",
            decider=world.decider,
            ai_system_id=SYSTEM,
            signoff_expectation=mandate_form,
        )
    assert getattr(form.value, "violation", None) == "mandate_form_not_writable"
    with pytest.raises(Exception) as beside:
        await world.tzun.capture(
            ai_output={"amountMinor": 1, "fraudFlag": False},
            action="approve",
            reason="r",
            decider=world.decider,
            ai_system_id=SYSTEM,
            signoff_expectation={"policyDigest": "b" * 64},
            mandate={"mandateId": doc["mandateId"]},
        )
    assert getattr(beside.value, "violation", None) == "expectation_with_mandate"


async def test_a_human_decider_cannot_capture_under_a_mandate(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    with pytest.raises(MandateRefusedError) as exc:
        await world.tzun.capture(
            ai_output={"amountMinor": 1, "fraudFlag": False},
            action="approve",
            reason="r",
            decider={"kind": "human", "id": "acct:someone"},
            ai_system_id=SYSTEM,
            mandate={"mandateId": doc["mandateId"]},
        )
    assert exc.value.code == "agent_not_in_mandate"


async def test_two_writers_racing_for_the_last_slot_claim_it_once(tmp_path: Any) -> None:
    """Two ``Tzun`` on one SQLite file: the claim is compared and set in the storing transaction."""
    from tzun_sdk.storage import SqliteAdapter

    path = str(tmp_path / "race.db")
    a = await make_world(SqliteAdapter(path, mode="async"))
    try:
        doc = a.document(limits={"maxRecords": 1, "cumulative": {"paid": {"path": "/aiOutput/amountMinor", "max": 10}}})
        await a.issue(doc)
        b_tzun = await Tzun.init(storage=SqliteAdapter(path, mode="async"), assertion_verifier=a.verifier)
        b = World(b_tzun, a.auth, a.verifier, a.model, a.agent)
        try:
            results = await asyncio.gather(
                a.capture(doc["mandateId"], 1), b.capture(doc["mandateId"], 1), return_exceptions=True
            )
        finally:
            await b_tzun.close()
        won = [r for r in results if not isinstance(r, BaseException)]
        lost = [r for r in results if isinstance(r, BaseException)]
        assert len(won) == 1 and len(lost) == 1
        assert isinstance(lost[0], MandateRefusedError) and lost[0].code == "mandate_full"
        row = await a.tzun.mandates.get(doc["mandateId"])
        assert row is not None and row.used == 1
    finally:
        await a.tzun.close()


async def test_the_webauthn_verifier_checks_the_signature_with_the_registered_key() -> None:
    w = await make_world(
        MemoryAdapter(), verifier_of=lambda auth: WebAuthnAssertionVerifier(auth.lookup, rp_id=RP_ID, origins=[ORIGIN])
    )
    try:
        doc = w.document()
        prepared = await w.tzun.mandates.prepare(doc)
        tampered = w.auth.sign(PRINCIPAL, prepared["challenge"])
        tampered["signature"] = w.auth.sign(PRINCIPAL, "B" * 43)["signature"]
        with pytest.raises(InvalidMandateError) as bad:
            await w.tzun.mandates.issue(document=doc, statement=prepared["statement"], assertion=tampered)
        assert bad.value.code == "assertion_not_verified"
        no_uv = w.auth.sign(PRINCIPAL, prepared["challenge"], uv=False)
        with pytest.raises(InvalidMandateError):
            await w.tzun.mandates.issue(document=doc, statement=prepared["statement"], assertion=no_uv)
        issued = await w.tzun.mandates.issue(
            document=doc, statement=prepared["statement"], assertion=w.auth.sign(PRINCIPAL, prepared["challenge"])
        )
        assert (await w.tzun.verify(issued["issuance"].evidenceId)).valid is True
    finally:
        await w.tzun.close()


async def test_without_an_assertion_verifier_the_ceremonies_are_refused() -> None:
    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        w = World(tzun, Authenticator(), None, "sha256:" + "0" * 64, "sha256:" + "1" * 64)
        w.auth.enrol(PRINCIPAL)
        doc = w.document()
        prepared = await tzun.mandates.prepare(doc)
        with pytest.raises(InvalidMandateError) as exc:
            await tzun.mandates.issue(
                document=doc, statement=prepared["statement"], assertion=w.auth.sign(PRINCIPAL, prepared["challenge"])
            )
        assert exc.value.code == "assertion_not_verified"
    finally:
        await tzun.close()


def test_the_sync_client_issues_and_captures_under_a_mandate() -> None:
    auth = Authenticator()
    auth.enrol(PRINCIPAL)
    tzun = TzunSync.init(storage=MemoryAdapter(), assertion_verifier=FakeVerifier(auth))
    try:
        world = asyncio.run(_sync_setup(tzun))
        doc = world.document()
        prepared = tzun.mandates.prepare(doc)
        issued = tzun.mandates.issue(
            document=doc, statement=prepared["statement"], assertion=auth.sign(PRINCIPAL, prepared["challenge"])
        )
        result = tzun.capture(
            ai_output={"amountMinor": 5, "fraudFlag": False},
            action="approve",
            reason="r",
            decider=world.decider,
            ai_system_id=SYSTEM,
            contributions={
                "steps": [
                    {"role": "propose", "actor": world.decider, "aiBom": {"modelDescriptorDigest": world.model}, "inputs": []}
                ]
            },
            mandate={"mandateId": issued["mandateId"]},
        )
        assert result.mandate is not None and result.mandate.slot == 1
        assert tzun.mandates.totals(issued["mandateId"]) == {"paid": 5}
        assert tzun.verify(result.evidenceId).valid is True
    finally:
        tzun.close()


async def _sync_setup(tzun: TzunSync) -> World:
    inner = tzun._inner
    model = await inner.models.register(mvd())
    agent = await inner.agents.register(
        {
            "v": "tzun-agent/1",
            "derivation": "base",
            "identities": [],
            "instructions": None,
            "keys": [],
            "models": [model],
            "name": "sync-agent",
            "operator": {"organization": "Example Insurer", "owner": None},
            "parent": None,
            "policy": None,
            "runtime": None,
            "tools": None,
        }
    )
    return World(inner, Authenticator(), None, model, agent["digest"])
