"""Link targets resolved as the TS link hook resolves them, and the decision-graph walk as the TS walk draws it (Record §8.7, §8.8).

A held target must recompute to its stored digest before a record links to
it; an ``external`` target that this store holds is a same-store target,
found by evidence id or by digest; the walk follows link records' statements
from either end, a page of the index at a time; the scanner reports a held
target that no longer matches a link, and a relation rule a record breaks on
its own. Every store case runs on memory, SQLite, and Postgres when the
integration gate is on.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from tests._stores import store  # noqa: F401 - the fixture
from tzun_sdk import Tzun
from tzun_sdk._capture import payload_digest
from tzun_sdk.decision_graph import DecisionGraphError
from tzun_sdk.errors import InvalidLinksError
from tzun_sdk.monitoring.scanner import ScheduledScanner
from tzun_sdk.monitoring.tamper_detector import TamperDetector
from tzun_sdk.storage import MemoryAdapter, PostgresAdapter, SqliteAdapter

ALICE = {"kind": "human", "id": "acct:alice"}
BOB = {"kind": "human", "id": "acct:bob"}


@pytest.fixture
async def tzun(store: Any) -> Any:  # noqa: F811 - the fixture
    t = await Tzun.init(storage=store)
    yield t
    await t.close()


async def _capture(tzun: Tzun, x: int, **kw: Any) -> Any:
    return await tzun.capture(ai_output={"x": x}, action="approve", reason=f"r{x}", decider=ALICE, **kw)


async def _tamper(tzun: Tzun, evidence_id: str, reason: str) -> None:
    """Edit a stored record's ``reason`` behind the store's back (its stored digest no longer recomputes)."""
    storage = tzun._storage
    if isinstance(storage, MemoryAdapter):
        storage._envelopes[evidence_id]["payload"]["reason"] = reason
        return
    raw = await tzun._stored_raw(evidence_id)
    assert raw is not None
    edited = copy.deepcopy(raw)
    edited["payload"]["reason"] = reason
    if isinstance(storage, SqliteAdapter):
        ex = await storage._exec()
        triggers = await ex.all(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'evidence_envelopes'", ()
        )
        for (name,) in triggers:
            await ex.run(f"DROP TRIGGER {name}", ())
        await ex.run(
            "UPDATE evidence_envelopes SET envelope_json = ? WHERE evidence_id = ?", (json.dumps(edited), evidence_id)
        )
        conn = await storage._ensure_async_conn()
        await conn.commit()
        return
    assert isinstance(storage, PostgresAdapter)
    import asyncpg

    conn = await asyncpg.connect(dsn=storage._dsn)
    try:
        async with conn.transaction():
            await conn.execute("SET LOCAL session_replication_role = 'replica'")
            await conn.execute(
                "UPDATE evidence_envelopes SET envelope_json = $1::jsonb WHERE evidence_id = $2",
                json.dumps(edited),
                evidence_id,
            )
    finally:
        await conn.close()


# ── Capture: the held target ─────────────────────────────────────────────────


async def test_a_record_is_not_linked_to_a_held_record_that_does_not_recompute(tzun: Tzun) -> None:
    a = await _capture(tzun, 1)
    await _tamper(tzun, a.evidenceId, "edited")
    before, _ = await tzun._head_parts()
    with pytest.raises(InvalidLinksError) as exc:
        await _capture(tzun, 2, links=[{"rel": "derivedFrom", "target": {"evidenceId": a.evidenceId}}])
    assert (exc.value.code, exc.value.field) == ("link_target_mismatch", "links[0].target.digest")
    assert (await tzun._head_parts())[0] == before
    # Named as external by its stored digest, the damaged copy is written as given
    # (it cannot block a record that names it) and reported by the reader.
    named = await _capture(
        tzun, 3, links=[{"rel": "derivedFrom", "target": {"digest": a.canonicalDigest, "external": True}}]
    )
    raw = await tzun._stored_raw(named.evidenceId)
    assert raw is not None
    assert raw["payload"]["links"] == [
        {"rel": "derivedFrom", "target": {"digest": a.canonicalDigest, "evidenceId": None, "locator": None}, "attrs": None}
    ]
    result = await tzun.verify(named.evidenceId)
    assert result.valid is True
    assert result.links is not None
    assert [(r.outcome, r.reason, r.targetHeld) for r in result.links.relations] == [
        ("checked-wrong", "link_target_mismatch", True)
    ]


async def test_an_external_target_this_store_holds_is_resolved_by_its_digest(tzun: Tzun) -> None:
    a = await _capture(tzun, 1)
    with pytest.raises(InvalidLinksError) as exc:
        await _capture(
            tzun,
            2,
            links=[
                {
                    "rel": "derivedFrom",
                    "target": {"digest": a.canonicalDigest, "evidenceId": "other-store-id-1", "external": True},
                }
            ],
        )
    assert (exc.value.code, exc.value.field) == ("link_target_mismatch", "links[0].target.evidenceId")
    by_digest = await _capture(
        tzun, 3, links=[{"rel": "derivedFrom", "target": {"digest": a.canonicalDigest, "external": True}}]
    )
    raw = await tzun._stored_raw(by_digest.evidenceId)
    assert raw is not None
    held = {"digest": a.canonicalDigest, "evidenceId": a.evidenceId, "locator": None}
    assert raw["payload"]["links"] == [
        {"rel": "derivedFrom", "target": held, "attrs": None},
        {"rel": "root", "target": held, "attrs": None},
    ]
    assert (await tzun.verify(by_digest.evidenceId)).links.valid is True  # type: ignore[union-attr]


async def test_a_store_without_a_digest_lookup_refuses_a_digest_only_target() -> None:
    class NoDigestLookup(MemoryAdapter):
        retrieve_raw_by_digest = None  # type: ignore[assignment]

    tzun = await Tzun.init(storage=NoDigestLookup())
    try:
        a = await _capture(tzun, 1)
        with pytest.raises(InvalidLinksError) as exc:
            await _capture(tzun, 2, links=[{"rel": "derivedFrom", "target": {"digest": a.canonicalDigest}}])
        assert (exc.value.code, exc.value.field) == ("links_not_supported_by_store", "links[0].target")
    finally:
        await tzun.close()


# ── The reader and the scanner ───────────────────────────────────────────────


async def test_the_scanner_reports_a_held_target_edited_after_a_record_linked_it(tzun: Tzun) -> None:
    a = await _capture(tzun, 1)
    child = await _capture(tzun, 2, links=[{"rel": "derivedFrom", "target": {"evidenceId": a.evidenceId}}])
    await _tamper(tzun, a.evidenceId, "edited")
    result = await tzun.verify(child.evidenceId)
    assert result.valid is True and result.links is not None
    assert [(r.rel, r.outcome, r.reason) for r in result.links.relations] == [
        ("derivedFrom", "checked-wrong", "link_target_mismatch"),
        ("root", "checked-wrong", "link_target_mismatch"),
    ]
    incidents = await ScheduledScanner(tzun).scan_once()
    by_record = {(i.evidenceId, i.eventType, (i.details or {}).get("rule")) for i in incidents}
    assert (a.evidenceId, "digest_mismatch", None) in by_record
    assert (child.evidenceId, "record_rule_violated", "links.target") in by_record


async def test_the_detector_reports_a_relation_rule_a_record_breaks_on_its_own() -> None:
    agent = "sha256:" + "7" * 64
    payload: dict[str, Any] = {
        "evidenceId": "9b2f1d4e-3333-4a1a-8a1a-000000000003",
        "schemaVersion": "v1.0",
        "aiSystemId": "claims",
        "aiOutput": {"x": 1},
        "action": "approve",
        "reason": "r",
        "capturedAt": "2026-10-01T00:00:00.000Z",
        "sequenceNumber": 1,
        "decider": {"kind": "agent", "id": f"desc:{agent}", "agent": agent, "credential": None, "freshness": None},
        "contributions": None,
        "links": [
            {
                "rel": "ratifies",
                "target": {"digest": "c" * 64, "evidenceId": None, "locator": None},
                "attrs": None,
            }
        ],
        "signoffExpectation": None,
    }
    raw = {
        "envelopeVersion": "e1",
        "payload": payload,
        "integrity": {"canonicalDigest": payload_digest(payload), "chainLink": None},
        "nonRepudiation": {},
        "custodyChain": [],
        "attestationStatus": "none",
    }
    incidents = await TamperDetector().detect(raw)
    rows = [(i.eventType, (i.details or {}).get("rule"), (i.details or {}).get("link")) for i in incidents]
    assert ("record_rule_violated", "links", 0) in rows


# ── The decision graph ───────────────────────────────────────────────────────


async def test_the_walk_draws_a_link_records_statement_from_either_end(tzun: Tzun) -> None:
    a = await _capture(tzun, 1)
    subject = "c0" * 32
    statement = await tzun.links.relate(
        subject={"digest": subject, "external": True},
        relations=[{"rel": "appeals", "target": {"evidenceId": a.evidenceId}}],
        reason="the complaint contests the decision",
        decider=BOB,
    )
    from_a = await tzun.decision_graph.walk(a.evidenceId)
    assert [(e["from"], e["to"], e["rel"], e["assertedBy"], e["statement"]) for e in from_a["edges"]] == [
        (subject, a.canonicalDigest, "appeals", statement.evidenceId, True)
    ]
    assert from_a["details"][subject]["held"] is False
    assert from_a["edges"][0]["decider"] == {"kind": "human", "id": "acct:bob"}
    from_statement = await tzun.decision_graph.walk(statement.evidenceId)
    assert sorted((e["from"], e["to"], e["rel"], e["statement"]) for e in from_statement["edges"]) == sorted(
        [
            (subject, a.canonicalDigest, "appeals", True),
            (statement.canonicalDigest, subject, "subject", False),
        ]
    )


async def test_a_flood_of_link_records_costs_one_page_per_node(tzun: Tzun, monkeypatch: pytest.MonkeyPatch) -> None:
    import tzun_sdk.decision_graph as graph

    monkeypatch.setattr(graph, "DECISION_GRAPH_PAGE", 3)
    a = await _capture(tzun, 1)
    b = await _capture(tzun, 2)
    for i in range(7):
        await tzun.links.relate(
            subject={"evidenceId": a.evidenceId},
            relations=[{"rel": "implements", "target": {"evidenceId": b.evidenceId}}],
            reason=f"statement {i}",
            decider=BOB,
        )
    reads: list[str] = []
    original = tzun._stored_raw

    async def counting(evidence_id: str) -> Any:
        reads.append(evidence_id)
        return await original(evidence_id)

    monkeypatch.setattr(tzun, "_stored_raw", counting)
    walk = await tzun.decision_graph.walk(a.evidenceId, max_nodes=5)
    assert walk["truncated"] is True and "page" in walk["truncatedBy"]
    assert walk["nodes"] == [a.canonicalDigest, b.canonicalDigest]
    # The root, then at most one page of statements and one of subjects per node.
    assert len(reads) <= 1 + 2 * 2 * 3
    assert len(walk["edges"]) <= 2 * 3


async def test_the_walk_refuses_options_out_of_range_and_an_unknown_record(tzun: Tzun) -> None:
    a = await _capture(tzun, 1)
    for kwargs, code in (
        ({"depth": -1}, "invalid_depth"),
        ({"depth": 257}, "invalid_depth"),
        ({"max_nodes": 0}, "invalid_max_nodes"),
        ({"max_nodes": 100_001}, "invalid_max_nodes"),
        ({"rels": ["Not A Relation"]}, "invalid_relation"),
        ({"rels": "derivedFrom"}, "invalid_relation"),
    ):
        with pytest.raises(DecisionGraphError) as exc:
            await tzun.decision_graph.walk(a.evidenceId, **kwargs)
        assert exc.value.code == code
    with pytest.raises(DecisionGraphError) as missing:
        await tzun.decision_graph.walk("00000000-0000-4000-8000-000000000000")
    assert missing.value.code == "record_not_found"
