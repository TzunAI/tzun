"""Links, link records, the decision graph, decider openings and the agent catalog (Record §6.3, §6.9, §8).

Every case runs on each local store (memory, SQLite, and Postgres when the
integration gate is on).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from tests._stores import store  # noqa: F401 - the fixture
from tzun_sdk import Tzun, TzunSync
from tzun_sdk.agents import agent_descriptor_digest
from tzun_sdk.decider import decider_commitment
from tzun_sdk.errors import InvalidAgentDescriptorError, InvalidDeciderError, InvalidLinksError
from tzun_sdk.storage import MemoryAdapter

ALICE = {"kind": "human", "id": "acct:alice"}
CAROL = {"kind": "human", "id": "acct:carol"}
BOB = {"kind": "human", "id": "acct:bob"}


def descriptor(name: str = "rules", **over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "v": "tzun-agent/1",
        "derivation": "base",
        "identities": [],
        "instructions": None,
        "keys": [],
        "models": [],
        "name": name,
        "operator": {"organization": "Example Org", "owner": None},
        "parent": None,
        "policy": None,
        "runtime": None,
        "tools": None,
    }
    d.update(over)
    return d


@pytest.fixture
async def tzun(store: Any) -> Any:  # noqa: F811 - the fixture
    t = await Tzun.init(storage=store)
    yield t
    await t.close()


async def digest_of(tzun: Tzun, evidence_id: str) -> str:
    raw = await tzun._stored_raw(evidence_id)
    assert raw is not None
    return str(raw["integrity"]["canonicalDigest"])


async def test_a_same_store_link_is_resolved_written_with_its_root_and_indexed(tzun: Tzun) -> None:
    parent = await tzun.capture(ai_output={"x": 1}, action="approve", reason="intake", decider=ALICE)
    child = await tzun.capture(
        ai_output={"x": 2},
        action="approve",
        reason="decision",
        decider=CAROL,
        links=[{"rel": "derivedFrom", "target": {"evidenceId": parent.evidenceId}}],
    )
    parent_digest = await digest_of(tzun, parent.evidenceId)
    target = {"digest": parent_digest, "evidenceId": parent.evidenceId, "locator": None}
    raw = await tzun._stored_raw(child.evidenceId)
    assert raw is not None
    assert raw["payload"]["links"] == [
        {"rel": "derivedFrom", "target": target, "attrs": None},
        {"rel": "root", "target": target, "attrs": None},
    ]
    of = await tzun.links.of(child.evidenceId)
    assert [(r["rel"], r["held"], r["heldEvidenceId"]) for r in of] == [
        ("derivedFrom", True, parent.evidenceId),
        ("root", True, parent.evidenceId),
    ]
    to = await tzun.links.to(parent_digest)
    assert to["cursor"] is None
    assert [(r["evidenceId"], r["idx"], r["rel"], r["linkRecord"]) for r in to["rows"]] == [
        (child.evidenceId, 0, "derivedFrom", False),
        (child.evidenceId, 1, "root", False),
    ]
    assert [r["rel"] for r in (await tzun.links.to(parent_digest, rels=["root"]))["rows"]] == ["root"]
    result = await tzun.verify(child.evidenceId)
    assert result.valid is True
    assert result.links is not None and result.links.valid is True
    assert [(r.rel, r.targetHeld) for r in result.links.relations] == [("derivedFrom", True), ("root", True)]


async def test_links_to_pages_through_every_linking_record(tzun: Tzun) -> None:
    parent = await tzun.capture(ai_output={"x": 0}, action="approve", reason="intake", decider=ALICE)
    children = []
    for i in range(5):
        r = await tzun.capture(
            ai_output={"x": i + 1},
            action="approve",
            reason="decision",
            decider=CAROL,
            links=[{"rel": "derivedFrom", "target": {"evidenceId": parent.evidenceId}}],
        )
        children.append(r.evidenceId)
    digest = await digest_of(tzun, parent.evidenceId)
    seen: list[str] = []
    cursor = None
    while True:
        page = await tzun.links.to(digest, rels=["derivedFrom"], limit=2, cursor=cursor)
        assert len(page["rows"]) <= 2
        seen.extend(r["evidenceId"] for r in page["rows"])
        cursor = page["cursor"]
        if cursor is None:
            break
    assert sorted(seen) == sorted(children)


async def test_capture_refuses_a_reserved_relation_a_missing_target_and_a_broken_rule(tzun: Tzun) -> None:
    parent = await tzun.capture(ai_output={"x": 1}, action="approve", reason="intake", decider=ALICE)
    cases = [
        ([{"rel": "mandate", "target": {"evidenceId": parent.evidenceId}}], ALICE, "relation_reserved"),
        (
            [{"rel": "derivedFrom", "target": {"evidenceId": "00000000-0000-4000-8000-000000000000"}}],
            ALICE,
            "link_target_not_found",
        ),
        ([{"rel": "reviews", "target": {"evidenceId": parent.evidenceId}}], ALICE, "link_rule_violated"),
    ]
    for links, decider, code in cases:
        with pytest.raises(InvalidLinksError) as exc:
            await tzun.capture(ai_output={"x": 2}, action="approve", reason="r", decider=decider, links=links)
        assert exc.value.code == code
    # A refusal takes no sequence number.
    after = await tzun.capture(ai_output={"x": 3}, action="approve", reason="r", decider=CAROL)
    assert after.sequenceNumber == parent.sequenceNumber + 1


async def test_an_external_target_is_kept_as_given_and_read_as_not_held(tzun: Tzun) -> None:
    target = {"digest": "c" * 64, "evidenceId": "00000000-0000-4000-8000-000000000001", "locator": None}
    r = await tzun.capture(
        ai_output={"x": 1},
        action="approve",
        reason="r",
        decider=ALICE,
        links=[{"rel": "derivedFrom", "target": {**target, "external": True}}],
    )
    raw = await tzun._stored_raw(r.evidenceId)
    assert raw is not None and raw["payload"]["links"] == [{"rel": "derivedFrom", "target": target, "attrs": None}]
    result = await tzun.verify(r.evidenceId)
    assert result.valid is True
    assert result.links is not None and [x.targetHeld for x in result.links.relations] == [False]


async def test_a_link_record_states_a_relation_of_its_subject_after_the_fact(tzun: Tzun) -> None:
    first = await tzun.capture(ai_output={"x": 1}, action="approve", reason="first", decider=ALICE)
    second = await tzun.capture(ai_output={"x": 2}, action="approve", reason="second", decider=CAROL)
    statement = await tzun.links.relate(
        subject={"evidenceId": second.evidenceId},
        relations=[{"rel": "reviews", "target": {"evidenceId": first.evidenceId}}],
        reason="the second decision reviewed the first",
        decider=BOB,
    )
    raw = await tzun._stored_raw(statement.evidenceId)
    assert raw is not None
    payload = raw["payload"]
    assert (payload["aiSystemId"], payload["action"], payload["aiOutput"]) == ("tzun:link", "link", {})
    assert [link["rel"] for link in payload["links"]] == ["reviews", "subject"]
    assert payload["links"][1]["target"]["evidenceId"] == second.evidenceId
    result = await tzun.verify(statement.evidenceId)
    assert result.valid is True and result.links is not None and result.links.valid is True
    first_digest = await digest_of(tzun, first.evidenceId)
    rows = (await tzun.links.to(first_digest))["rows"]
    assert [(r["evidenceId"], r["rel"], r["linkRecord"]) for r in rows] == [(statement.evidenceId, "reviews", True)]


async def test_a_link_record_reads_the_subject_in_the_childs_place(tzun: Tzun) -> None:
    first = await tzun.capture(ai_output={"x": 1}, action="approve", reason="first", decider=ALICE)
    second = await tzun.capture(ai_output={"x": 2}, action="approve", reason="second", decider=ALICE)
    with pytest.raises(InvalidLinksError) as exc:
        await tzun.links.relate(
            subject={"evidenceId": second.evidenceId},
            relations=[{"rel": "reviews", "target": {"evidenceId": first.evidenceId}}],
            reason="r",
            decider=BOB,
        )
    assert exc.value.code == "link_rule_violated"
    with pytest.raises(InvalidLinksError) as none:
        await tzun.links.relate(subject={"evidenceId": second.evidenceId}, relations=[], reason="r", decider=BOB)
    assert none.value.code == "required_link_missing"


async def test_capture_opens_a_committed_decider_for_the_reviews_rule(tzun: Tzun) -> None:
    """The ``reviews`` relation (Record §8.3) at capture: a ``cmt:`` decider is opened as store-level verification opens it."""
    alice_committed = {**ALICE, "commit": True}
    committed = await tzun.capture(ai_output={"x": 1}, action="approve", reason="committed", decider=alice_committed)
    raw = await tzun._stored_raw(committed.evidenceId)
    assert raw is not None and raw["payload"]["decider"]["id"].startswith("cmt:")
    plain = await tzun.capture(ai_output={"x": 2}, action="approve", reason="plain", decider=ALICE)

    def reviews(evidence_id: str) -> list[dict[str, Any]]:
        return [{"rel": "reviews", "target": {"evidenceId": evidence_id}}]

    # The target's commitment, opened from the store; this capture's own, from its opening; both.
    for decider, target in ((ALICE, committed.evidenceId), (alice_committed, plain.evidenceId), (alice_committed, committed.evidenceId)):
        with pytest.raises(InvalidLinksError) as exc:
            await tzun.capture(ai_output={"x": 3}, action="approve", reason="self review", decider=decider, links=reviews(target))
        assert (exc.value.code, exc.value.details.get("rule")) == ("link_rule_violated", "reviews_distinct_decider")
    # A link record whose held subject the same committed person decided.
    subject = await tzun.capture(ai_output={"x": 4}, action="approve", reason="subject", decider=alice_committed)
    with pytest.raises(InvalidLinksError) as relate:
        await tzun.links.relate(subject={"evidenceId": subject.evidenceId}, relations=reviews(plain.evidenceId), reason="r", decider=BOB)
    assert (relate.value.code, relate.value.details.get("rule")) == ("link_rule_violated", "reviews_distinct_decider")
    # Another person reviews the committed decision, committed or not.
    other = await tzun.capture(ai_output={"x": 5}, action="approve", reason="other", decider=BOB, links=reviews(committed.evidenceId))
    result = await tzun.verify(other.evidenceId)
    assert result.links is not None and result.links.valid is True
    await tzun.capture(ai_output={"x": 6}, action="approve", reason="other", decider={**BOB, "commit": True}, links=reviews(committed.evidenceId))


async def test_the_decision_graph_walk_names_who_asserted_each_edge(tzun: Tzun) -> None:
    a = await tzun.capture(ai_output={"x": 1}, action="approve", reason="a", decider=ALICE)
    b = await tzun.capture(
        ai_output={"x": 2},
        action="approve",
        reason="b",
        decider=CAROL,
        links=[{"rel": "derivedFrom", "target": {"evidenceId": a.evidenceId}}],
    )
    statement = await tzun.links.relate(
        subject={"evidenceId": b.evidenceId},
        relations=[{"rel": "reviews", "target": {"evidenceId": a.evidenceId}}],
        reason="review",
        decider=BOB,
    )
    da, db = await digest_of(tzun, a.evidenceId), await digest_of(tzun, b.evidenceId)
    graph = await tzun.decision_graph.walk(b.evidenceId)
    assert graph["root"] == db and graph["rootEvidenceId"] == b.evidenceId
    assert graph["truncated"] is False and graph["truncatedBy"] == []
    assert graph["nodes"] == [db, da]
    assert {(n["digest"], n["evidenceId"], n["held"], n["depth"], n["intact"]) for n in graph["details"].values()} == {
        (db, b.evidenceId, True, 0, True),
        (da, a.evidenceId, True, 1, True),
    }
    assert sorted(
        (e["from"], e["to"], e["rel"], e["assertedBy"], e["statement"], e["decider"]["id"]) for e in graph["edges"]
    ) == sorted(
        [
            (db, da, "derivedFrom", b.evidenceId, False, "acct:carol"),
            (db, da, "root", b.evidenceId, False, "acct:carol"),
            (db, da, "reviews", statement.evidenceId, True, "acct:bob"),
        ]
    )
    only = await tzun.decision_graph.walk(b.evidenceId, rels=["reviews"])
    assert [(e["rel"], e["assertedBy"]) for e in only["edges"]] == [("reviews", statement.evidenceId)]


async def test_the_walk_stops_at_its_depth_and_node_budget(tzun: Tzun) -> None:
    prev = await tzun.capture(ai_output={"x": 0}, action="approve", reason="0", decider=ALICE)
    for i in range(3):
        prev = await tzun.capture(
            ai_output={"x": i + 1},
            action="approve",
            reason=str(i + 1),
            decider=CAROL if i % 2 == 0 else ALICE,
            links=[{"rel": "derivedFrom", "target": {"evidenceId": prev.evidenceId}}],
        )
    full = await tzun.decision_graph.walk(prev.evidenceId)
    assert len(full["nodes"]) == 4 and full["truncated"] is False
    shallow = await tzun.decision_graph.walk(prev.evidenceId, depth=1)
    assert shallow["truncatedBy"] == ["depth"] and len(shallow["nodes"]) < 4
    small = await tzun.decision_graph.walk(prev.evidenceId, max_nodes=2)
    assert small["truncatedBy"] == ["maxNodes"] and len(small["nodes"]) == 2


async def test_a_committed_decider_keeps_its_opening_in_the_store(tzun: Tzun) -> None:
    r = await tzun.capture(
        ai_output={"x": 1}, action="approve", reason="r", decider={"kind": "human", "id": "acct:carol", "commit": True}
    )
    assert r.deciderOpening is not None and r.deciderOpening.id == "acct:carol"
    raw = await tzun._stored_raw(r.evidenceId)
    assert raw is not None
    assert raw["payload"]["decider"]["id"] == decider_commitment("acct:carol", r.deciderOpening.salt)
    opening = await tzun.deciders.opening(r.evidenceId)
    assert opening is not None and (opening.salt, opening.id) == (r.deciderOpening.salt, "acct:carol")
    result = await tzun.verify(r.evidenceId)
    assert result.valid is True
    assert result.decider is not None and result.decider.scheme == "cmt" and result.decider.committed is True
    plain = await tzun.capture(ai_output={"x": 2}, action="approve", reason="r", decider=ALICE)
    assert await tzun.deciders.opening(plain.evidenceId) is None
    with pytest.raises(InvalidDeciderError) as exc:
        await tzun.capture(
            ai_output={"x": 3},
            action="approve",
            reason="r",
            decider={"kind": "human", "id": raw["payload"]["decider"]["id"], "commit": True},
        )
    assert exc.value.code == "invalid_identifier"


async def test_the_agent_catalog_registers_once_per_canonical_bytes(tzun: Tzun) -> None:
    d = descriptor()
    first = await tzun.agents.register(d)
    again = await tzun.agents.register(dict(reversed(list(d.items()))))
    assert first == {"digest": agent_descriptor_digest(d), "alreadyExisted": False}
    assert again == {"digest": first["digest"], "alreadyExisted": True}
    row = await tzun.agents.get(first["digest"])
    assert row is not None and json.loads(row.canonicalBytes) == d
    assert (row.name, row.organization) == ("rules", "Example Org")
    await tzun.agents.register(descriptor("other"))
    page = await tzun.agents.list(name="rules")
    assert [r.digest for r in page["rows"]] == [first["digest"]]
    assert len((await tzun.agents.list(organization="Example Org"))["rows"]) == 2
    assert await tzun.agents.get("sha256:" + "0" * 64) is None
    with pytest.raises(InvalidAgentDescriptorError) as exc:
        await tzun.agents.register(descriptor(v="tzun-agent/2"))
    assert exc.value.code == "invalid_agent_descriptor"


async def test_capture_resolves_agent_references_against_the_catalog(tzun: Tzun) -> None:
    registered = await tzun.agents.register(descriptor())
    r = await tzun.capture(
        ai_output={"x": 1}, action="approve", reason="r", decider={"kind": "agent", "agent": registered["digest"]}
    )
    raw = await tzun._stored_raw(r.evidenceId)
    assert raw is not None and raw["payload"]["decider"]["id"] == f"desc:{registered['digest']}"
    result = await tzun.verify(r.evidenceId)
    assert result.valid is True
    assert result.agents is not None and [(a.field, a.resolved) for a in result.agents] == [("decider", True)]
    with pytest.raises(InvalidAgentDescriptorError) as missing:
        await tzun.capture(
            ai_output={"x": 2}, action="approve", reason="r", decider={"kind": "agent", "agent": "sha256:" + "2" * 64}
        )
    assert (missing.value.code, missing.value.field) == ("agent_not_registered", "decider.agent")
    model = "sha256:" + "6" * 64
    with_model = await tzun.agents.register(descriptor("model-agent", models=[model]))
    with pytest.raises(InvalidAgentDescriptorError) as kind:
        await tzun.capture(
            ai_output={"x": 3},
            action="approve",
            reason="r",
            decider={"kind": "policy-engine", "agent": with_model["digest"]},
        )
    assert kind.value.code == "agent_kind_mismatch"


def test_the_sync_client_relates_walks_and_registers() -> None:
    tzun = TzunSync.init(storage=MemoryAdapter())
    try:
        a = tzun.capture(ai_output={"x": 1}, action="approve", reason="a", decider=ALICE)
        b = tzun.capture(ai_output={"x": 2}, action="approve", reason="b", decider=CAROL)
        statement = tzun.links.relate(
            subject={"evidenceId": b.evidenceId},
            relations=[{"rel": "reviews", "target": {"evidenceId": a.evidenceId}}],
            reason="review",
            decider=BOB,
        )
        graph = tzun.decision_graph.walk(b.evidenceId)
        assert [e["assertedBy"] for e in graph["edges"]] == [statement.evidenceId]
        assert [r["rel"] for r in tzun.links.of(statement.evidenceId)] == ["reviews", "subject"]
        registered = tzun.agents.register(descriptor())
        assert tzun.agents.get(registered["digest"]) is not None
        committed = tzun.capture(
            ai_output={"x": 3}, action="approve", reason="c", decider={"kind": "human", "id": "acct:dan", "commit": True}
        )
        assert tzun.deciders.opening(committed.evidenceId) is not None
        challenge = tzun.prepare_assertion_challenge(ai_output={"x": 4}, action="approve", reason="d", decider=ALICE)
        assert isinstance(challenge["challenge"], str)
    finally:
        tzun.close()
