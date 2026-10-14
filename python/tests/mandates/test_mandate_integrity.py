"""A mandate's state moves only as its records say, judged on the SDK's clock (Record §9.1, §9.6, §9.9, §9.10).

The capture under a mandate takes its identity from the SDK; a revocation is
rebuilt from the mandate row, so a prepared object edited to describe another
mandate, a later instant or another revoker is refused; issuance checks the
statement's policy and refuses an existing mandate before the ceremony; the
store refuses a claim or a close that does not match the row it locked.
Every end-to-end case runs on each local store (memory, SQLite, and Postgres
when the integration gate is on).
"""

from __future__ import annotations

import asyncio
import copy
import datetime as dt
from typing import Any

import pytest

from tests._stores import STORES, open_store, store  # noqa: F401 - the fixture
from tests.mandates.test_mandates import PRINCIPAL, REVOKER, SYSTEM, World, _iso, make_world
from tzun_sdk import Tzun
from tzun_sdk._capture import payload_digest
from tzun_sdk.attestation.webauthn import webauthn_challenge_for_digest
from tzun_sdk.errors import (
    CaptureRefusedError,
    InvalidDeciderError,
    InvalidMandateError,
    InvalidPayloadError,
    MandateClaimConflictError,
    MandateRefusedError,
)
from tzun_sdk.mandate.statement import mandate_confirmation_challenge
from tzun_sdk.mandates_api import _expire_if_still_due
from tzun_sdk.models import MandateCapClaim, MandateClaimStore, MandateRevokeStore
from tzun_sdk.storage._records import check_mandate_claim, check_mandate_transition


@pytest.fixture
async def world(store: Any) -> Any:  # noqa: F811 - the fixture
    w = await make_world(store)
    yield w
    await w.tzun.close()


def _ended(world: World) -> dict[str, Any]:
    now = dt.datetime.now(dt.UTC)
    return world.document(validity={"notBefore": _iso(now - dt.timedelta(days=10)), "notAfter": _iso(now - dt.timedelta(days=5))})


async def _capture(world: World, mandate_id: str, amount: int, **extra: Any) -> Any:
    return await world.tzun.capture(
        ai_output={"amountMinor": amount, "fraudFlag": False},
        action="approve",
        reason="matches the estimate",
        decider=world.decider,
        ai_system_id=SYSTEM,
        contributions={
            "steps": [{"role": "propose", "actor": world.decider, "aiBom": {"modelDescriptorDigest": world.model}, "inputs": []}]
        },
        mandate={"mandateId": mandate_id},
        **extra,
    )


async def _head_sequence(world: World) -> int:
    seq, _ = await world.tzun._head_parts()
    return seq


# ── The capture's identity is the SDK's ──────────────────────────────────────


async def test_a_back_dated_capture_under_an_ended_mandate_is_refused_and_stores_nothing(world: World) -> None:
    doc = _ended(world)
    await world.issue(doc)
    before = await _head_sequence(world)
    back = _iso(dt.datetime.now(dt.UTC) - dt.timedelta(days=7))
    with pytest.raises(MandateRefusedError) as exc:
        await _capture(world, doc["mandateId"], 100, captured_at=back)
    assert (exc.value.code, exc.value.field) == ("captured_at_with_mandate", "capturedAt")
    assert await _head_sequence(world) == before
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.used == 0


async def test_a_future_dated_capture_is_refused_and_leaves_the_mandate_open(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    with pytest.raises(MandateRefusedError) as exc:
        await _capture(world, doc["mandateId"], 100, captured_at="2099-01-01T00:00:00.000Z")
    assert exc.value.code == "captured_at_with_mandate"
    with pytest.raises(MandateRefusedError) as eid:
        await _capture(world, doc["mandateId"], 100, evidence_id="9b2f1d4e-1111-4a1a-8a1a-000000000001")
    assert (eid.value.code, eid.value.field) == ("evidence_id_with_mandate", "evidenceId")
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.state == "open" and row.used == 0
    assert [e.body.event for e in await world.tzun.mandates.events(doc["mandateId"])] == ["issued"]


async def test_a_capture_after_the_window_moves_the_mandate_to_expired_with_its_event(world: World) -> None:
    doc = _ended(world)
    await world.issue(doc)
    with pytest.raises(MandateRefusedError) as exc:
        await _capture(world, doc["mandateId"], 100)
    assert exc.value.code == "outside_validity"
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.state == "expired"
    events = await world.tzun.mandates.events(doc["mandateId"])
    assert [e.body.event for e in events] == ["issued", "expired"]
    assert events[-1].body.used == 0


async def test_a_caller_chosen_captured_at_is_bounded_like_the_platforms() -> None:
    from tzun_sdk.storage import MemoryAdapter

    tzun = await Tzun.init(storage=MemoryAdapter())
    try:
        human = {"kind": "human", "id": "acct:u-1"}
        ahead = _iso(dt.datetime.now(dt.UTC) + dt.timedelta(minutes=10))
        with pytest.raises(InvalidPayloadError) as future:
            await tzun.capture(ai_output={"x": 1}, action="approve", reason="r", decider=human, captured_at=ahead)
        assert (future.value.code, future.value.field) == ("invalid_captured_at", "capturedAt")
        with pytest.raises(InvalidPayloadError) as unparsable:
            await tzun.capture(ai_output={"x": 1}, action="approve", reason="r", decider=human, captured_at="yesterday")
        assert unparsable.value.code == "invalid_captured_at"
        with pytest.raises(InvalidPayloadError) as bad_id:
            await tzun.capture(ai_output={"x": 1}, action="approve", reason="r", decider=human, evidence_id="not-a-uuid")
        assert bad_id.value.code == "invalid_evidence_id"
        soon = _iso(dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2))
        stored = await tzun.capture(ai_output={"x": 1}, action="approve", reason="r", decider=human, captured_at=soon)
        assert stored.envelope.payload.capturedAt == soon
    finally:
        await tzun.close()


# ── Revocation is rebuilt from the mandate row ───────────────────────────────


def _edited(prepared: dict[str, Any], **ai_output: Any) -> dict[str, Any]:
    """``prepared`` with ``aiOutput`` members replaced and its digest recomputed over the edited record."""
    p = copy.deepcopy(prepared)
    p["aiOutput"].update(ai_output)
    payload = {
        "evidenceId": p["evidenceId"],
        "schemaVersion": "v1.0",
        "aiSystemId": "tzun:mandate",
        "aiOutput": p["aiOutput"],
        "action": "revoke-mandate",
        "reason": p["reason"],
        "capturedAt": p["capturedAt"],
        "sequenceNumber": p["sequenceNumber"],
        "decider": p["decider"],
        "contributions": p["contributions"],
        "links": p["links"],
        "signoffExpectation": p["signoffExpectation"],
    }
    p["digest"] = payload_digest(payload)
    p["challenge"] = webauthn_challenge_for_digest(p["digest"])
    return p


async def test_a_prepared_revocation_edited_to_name_another_mandate_is_refused(world: World) -> None:
    doc_a, doc_b = world.document(), world.document()
    await world.issue(doc_a)
    issued_b = await world.issue(doc_b)
    row_b = await world.tzun.mandates.get(doc_b["mandateId"])
    assert row_b is not None
    prepared = await world.tzun.mandates.prepare_revocation(mandate_id=doc_a["mandateId"], reason="stop", revoker=REVOKER)
    p = _edited(prepared, mandateDigest=row_b.mandateDigest, statementDigest=row_b.statementDigest)
    p["links"] = [
        {
            "rel": "revokes",
            "target": {"digest": issued_b["issuance"].canonicalDigest, "evidenceId": row_b.issuanceEvidenceId, "locator": None},
            "attrs": None,
        }
    ]
    p = _edited(p)
    with pytest.raises(CaptureRefusedError) as exc:
        await world.tzun.mandates.revoke(mandate_id=doc_a["mandateId"], prepared=p, assertion=world.auth.sign(REVOKER, p["challenge"]))
    assert exc.value.code == "invalid_prepared"
    only_output = _edited(prepared, mandateDigest=row_b.mandateDigest, statementDigest=row_b.statementDigest)
    with pytest.raises(CaptureRefusedError) as output:
        await world.tzun.mandates.revoke(
            mandate_id=doc_a["mandateId"], prepared=only_output, assertion=world.auth.sign(REVOKER, only_output["challenge"])
        )
    assert output.value.code == "invalid_prepared"
    with pytest.raises(InvalidMandateError) as other:
        await world.tzun.mandates.revoke(
            mandate_id=doc_b["mandateId"], prepared=prepared, assertion=world.auth.sign(REVOKER, prepared["challenge"])
        )
    assert other.value.code == "invalid_prepared"
    for doc in (doc_a, doc_b):
        row = await world.tzun.mandates.get(doc["mandateId"])
        assert row is not None and row.state == "open"
    assert (await _capture(world, doc_b["mandateId"], 1)).mandate is not None


async def test_a_prepared_revocation_with_a_later_instant_or_an_unattributed_revoker_is_refused(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    prepared = await world.tzun.mandates.prepare_revocation(mandate_id=doc["mandateId"], reason="stop", revoker=REVOKER)
    later = _edited(prepared, claimedRevocationInstant="2099-01-01T00:00:00.000Z")
    with pytest.raises(InvalidMandateError) as instant:
        await world.tzun.mandates.revoke(
            mandate_id=doc["mandateId"], prepared=later, assertion=world.auth.sign(REVOKER, later["challenge"])
        )
    assert instant.value.code == "invalid_revocation_instant"
    committed = copy.deepcopy(prepared)
    committed["decider"] = {**committed["decider"], "id": "cmt:" + "ab" * 32}
    committed = _edited(committed)
    with pytest.raises(InvalidMandateError) as unattributed:
        await world.tzun.mandates.revoke(
            mandate_id=doc["mandateId"], prepared=committed, assertion=world.auth.sign(REVOKER, committed["challenge"])
        )
    assert (unattributed.value.code, unattributed.value.field) == ("invalid_identifier", "revoker")
    with pytest.raises(InvalidMandateError) as reason:
        await world.tzun.mandates.revoke(
            mandate_id=doc["mandateId"],
            prepared=prepared,
            assertion=world.auth.sign(REVOKER, prepared["challenge"]),
            reason="another reason",
        )
    assert reason.value.code == "invalid_prepared"
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.state == "open"
    revoked = await world.tzun.mandates.revoke(
        mandate_id=doc["mandateId"], prepared=prepared, assertion=world.auth.sign(REVOKER, prepared["challenge"]), reason="stop"
    )
    assert (await world.tzun.verify(revoked.evidenceId)).valid is True


async def test_prepare_revocation_refuses_a_revoker_that_is_not_an_opaque_account_id(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    with pytest.raises(InvalidMandateError) as exc:
        await world.tzun.mandates.prepare_revocation(mandate_id=doc["mandateId"], reason="stop", revoker="ops@example.com")
    assert (exc.value.code, exc.value.field) == ("invalid_identifier", "revoker")
    with pytest.raises(InvalidMandateError) as missing:
        await world.tzun.mandates.prepare_revocation(mandate_id="no-such-mandate", reason="stop", revoker=REVOKER)
    assert missing.value.code == "mandate_not_found"


# ── Issuance and confirmation, as the TS SDK names them ──────────────────────


async def test_issue_refuses_a_statement_for_another_policy(world: World) -> None:
    doc = world.document()
    prepared = await world.tzun.mandates.prepare(doc)
    statement = {**prepared["statement"], "policyDigest": "ab" * 32}
    with pytest.raises(InvalidMandateError) as exc:
        await world.tzun.mandates.issue(
            document=doc, statement=statement, assertion=world.auth.sign(PRINCIPAL, prepared["challenge"])
        )
    assert (exc.value.code, exc.value.field) == ("invalid_statement", "statement")


async def test_an_issued_mandate_is_refused_again_before_the_ceremony(world: World) -> None:
    doc = world.document()
    prepared = await world.tzun.mandates.prepare(doc)
    await world.tzun.mandates.issue(
        document=doc, statement=prepared["statement"], assertion=world.auth.sign(PRINCIPAL, prepared["challenge"])
    )
    with pytest.raises(MandateRefusedError) as exc:
        await world.tzun.mandates.issue(
            document=doc, statement=prepared["statement"], assertion=world.auth.sign(REVOKER, "A" * 43)
        )
    assert (exc.value.code, exc.value.field) == ("mandate_already_issued", "document.mandateId")


async def test_a_confirmation_is_recorded_with_its_mandate_and_slot(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    flagged = await world.capture(doc["mandateId"], 1000, fraud=True)
    before = await world.tzun.verify(flagged.evidenceId)
    assert before.signoffExpectationReason == "confirmation_missing"
    assert before.mandate is not None and before.mandate.scope is not None and before.mandate.limits is not None
    assert before.mandate.scope.outcome == "checked-correct" and before.mandate.limits.outcome == "checked-correct"
    raw = await world.tzun._stored_raw(flagged.evidenceId)
    assert raw is not None
    challenge = mandate_confirmation_challenge(raw["integrity"]["canonicalDigest"])
    await world.tzun.mandates.confirm(flagged.evidenceId, world.auth.sign(PRINCIPAL, challenge))
    after = await world.tzun._stored_raw(flagged.evidenceId)
    assert after is not None
    assert after["custodyChain"][-1]["action"] == "mandate_confirmed"
    assert after["custodyChain"][-1]["metadata"] == {"mandateId": doc["mandateId"], "slot": 1}
    with pytest.raises(InvalidMandateError) as missing:
        await world.tzun.mandates.confirm("no-such-record", world.auth.sign(PRINCIPAL, challenge))
    assert missing.value.code == "record_not_found"


# ── Freshness under a mandate ─────────────────────────────────────────────────


async def test_an_agent_mandated_capture_needs_a_freshness_reference_where_a_chain_is_configured() -> None:
    from tzun_sdk.storage import MemoryAdapter

    shared = MemoryAdapter()
    base = await make_world(shared)
    doc = base.document()
    await base.issue(doc)
    await base.tzun.close()
    tzun = await Tzun.init(storage=shared, assertion_verifier=base.verifier, freshness_chain="eip155:11155111")
    try:
        world = World(tzun, base.auth, base.verifier, base.model, base.agent)
        with pytest.raises(InvalidDeciderError) as exc:
            await _capture(world, doc["mandateId"], 10)
        assert (exc.value.code, exc.value.field) == ("freshness_required", "decider.freshness")
        row = await tzun.mandates.get(doc["mandateId"])
        assert row is not None and row.used == 0

        async def fresh(chain: str) -> dict[str, Any]:
            now_ms = int(dt.datetime.now(dt.UTC).timestamp() * 1000)
            return {"chain": chain, "number": 7, "hash": "0x" + "ab" * 32, "timeMs": now_ms}

        shared.read_anchor_freshness = fresh  # type: ignore[attr-defined]
        stored = await _capture(world, doc["mandateId"], 10)
        assert stored.envelope.payload.decider.freshness is not None
    finally:
        await tzun.close()


# ── The store refuses what does not match the row it locked ──────────────────


def _mandate_row(**over: Any) -> dict[str, Any]:
    row = {
        "state": "open",
        "used": 2,
        "max_records": 5,
        "not_before": "2026-01-01T00:00:00.000Z",
        "not_after": "2026-12-31T23:59:59.999Z",
    }
    row.update(over)
    return row


def test_a_claim_at_exactly_not_after_is_inside_the_window() -> None:
    claim = MandateClaimStore(mandateId="m", expectUsed=2, caps=[], now="2026-12-31T23:59:59.999Z")
    check_mandate_claim(claim, _mandate_row(), {})
    late = MandateClaimStore(mandateId="m", expectUsed=2, caps=[], now="2027-01-01T00:00:00.000Z")
    with pytest.raises(MandateRefusedError) as exc:
        check_mandate_claim(late, _mandate_row(), {})
    assert exc.value.code == "outside_validity"


def test_the_store_refuses_a_claim_past_a_cap_and_a_lost_race_on_a_total() -> None:
    totals = {"paid": {"max": 100, "total": 60}}
    over = MandateClaimStore(
        mandateId="m", expectUsed=2, caps=[MandateCapClaim(cap="paid", expectTotal=60, newTotal=101)], now="2026-06-01T00:00:00.000Z"
    )
    with pytest.raises(MandateRefusedError) as exc:
        check_mandate_claim(over, _mandate_row(), totals)
    assert exc.value.code == "cap_exceeded"
    stale = MandateClaimStore(
        mandateId="m", expectUsed=2, caps=[MandateCapClaim(cap="paid", expectTotal=50, newTotal=70)], now="2026-06-01T00:00:00.000Z"
    )
    with pytest.raises(MandateClaimConflictError):
        check_mandate_claim(stale, _mandate_row(), totals)


def test_a_close_racing_a_capture_that_moved_a_total_loses() -> None:
    close = MandateRevokeStore.model_construct(
        mandateId="m", expectState="open", newState="revoked", expectUsed=2, expectTotals={"paid": 50}, event=None
    )
    with pytest.raises(MandateClaimConflictError):
        check_mandate_transition(close, _mandate_row(), {"paid": {"max": 100, "total": 60}})
    check_mandate_transition(close, _mandate_row(), {"paid": {"max": 100, "total": 50}})


async def test_a_decider_opening_that_does_not_open_the_record_is_refused_by_the_store(store: Any) -> None:  # noqa: F811
    from tzun_sdk.models import DeciderOpening, StoreOptions
    from tzun_sdk.storage._records import DeciderOpeningMismatchError

    tzun = await Tzun.init(storage=store)
    try:
        r = await tzun.capture(
            ai_output={"x": 1}, action="approve", reason="r", decider={"kind": "human", "id": "acct:carol", "commit": True}
        )
        raw = await tzun._stored_raw(r.evidenceId)
        assert raw is not None
        forged = copy.deepcopy(raw)
        forged["payload"]["evidenceId"] = "9b2f1d4e-2222-4a1a-8a1a-000000000002"
        forged["payload"]["sequenceNumber"] = 2
        forged["integrity"]["canonicalDigest"] = payload_digest(forged["payload"])
        with pytest.raises(DeciderOpeningMismatchError):
            await store.store(
                forged, None, StoreOptions(deciderOpening=DeciderOpening(salt="00" * 16, id="acct:mallory"))
            )
    finally:
        await tzun.close()


async def test_an_expiry_that_lost_its_race_to_a_capture_is_skipped(world: World) -> None:
    doc = world.document()
    await world.issue(doc)
    stale_row = await world.tzun.mandates.get(doc["mandateId"])
    stale_totals = await world.tzun.mandates.totals(doc["mandateId"])
    assert stale_row is not None
    await world.capture(doc["mandateId"], 5)
    assert await _expire_if_still_due(world.tzun, stale_row, stale_totals) is False
    row = await world.tzun.mandates.get(doc["mandateId"])
    assert row is not None and row.state == "open" and row.used == 1


# ── Writers on several chains of one store share a mandate ───────────────────


@pytest.mark.parametrize("kind", [p for p in STORES if (p if isinstance(p, str) else p.values[0]) != "memory"])
async def test_writers_on_four_chains_claim_contiguous_slots_of_one_mandate(kind: Any, tmp_path: Any) -> None:
    """Only the mandate's compare-and-swap orders claims made on different chains."""
    from tzun_sdk.storage import PostgresAdapter, SqliteAdapter

    first = await open_store(kind, tmp_path)
    a = await make_world(first)

    def adapter() -> Any:
        if isinstance(first, SqliteAdapter):
            return SqliteAdapter(str(tmp_path / "store.db"), mode="async")
        return PostgresAdapter(first._dsn, mode="async")

    doc = a.document(limits={"maxRecords": 40, "cumulative": None})
    await a.issue(doc)
    worlds = [a]
    for i in range(3):
        t = await Tzun.init(
            storage=adapter(), assertion_verifier=a.verifier, chain_id=f"chain-{i}", chain_conflict_max_attempts=200
        )
        worlds.append(World(t, a.auth, a.verifier, a.model, a.agent))

    async def run(w: World, i: int) -> list[int]:
        return [(await w.capture(doc["mandateId"], 1 + i * 100 + j)).mandate.slot for j in range(5)]

    try:
        results = await asyncio.gather(*(run(w, i) for i, w in enumerate(worlds)))
        slots = sorted(s for r in results for s in r)
        assert slots == list(range(1, 21))
        row = await a.tzun.mandates.get(doc["mandateId"])
        assert row is not None and row.used == 20
    finally:
        for w in worlds:
            await w.tzun.close()
