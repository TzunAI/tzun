"""The decision graph: a bounded walk over the links of this store's records and the statements of link records.

The twin of the TS SDK's ``src/sdk/decision-graph.ts``. From a record, the walk follows:

* its own links: an edge from the record to each target, asserted by the
  record itself;
* when the record is a link record, its statements (an edge from its subject
  to each target, asserted by the link record) and its ``subject`` link;
* the statements of link records about it, found through the link index:
  link records that state a relation towards it (an edge from their subject
  to it), and link records whose subject it is (an edge from it to each
  target they name). Such a link record is the asserter of those edges, not a
  node of the walk.

It does not follow a link towards the record from a record that is not a
link record: the records derived from a decision are found with
``tzun.links.to``, a page at a time.

Every edge names the record that asserts it (``assertedBy``) and that
record's decider, and says whether it is a link record's statement, so a
relation a third party stated is never shown as the target's own. The index
is used to find link records only: each one is read, and an edge is drawn
from the link the record actually carries, never from an index row alone. A
node and an asserting record each say whether their payload recomputes to
their stored digest (``intact``, ``assertedByIntact``).

Depth counts the steps of the walk, not edges: a link record found from a
node contributes all of its statements in that step, so every endpoint they
name is one deeper than that node.

Bounds: a depth (default 16; the root is at depth 0), a node budget
(``max_nodes``, default 1,000), a visited set (records can state cycles),
and one page of the index per node and kind (100 rows), so a flood of link
records at one target costs one bounded page, not a scan. A walk that stops
early for any of these reports ``truncated: True`` and names the bounds in
``truncatedBy``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from tzun_sdk._capture import record_intact
from tzun_sdk._record_rules import BARE_DIGEST_RE, is_safe_integer
from tzun_sdk.errors import TzunError
from tzun_sdk.links import LINK_RECORD_AI_SYSTEM_ID, is_relation_name

#: The depth a walk goes to when the caller names none.
DECISION_GRAPH_DEFAULT_DEPTH = 16
#: The deepest walk.
DECISION_GRAPH_MAX_DEPTH = 256
#: The node budget when the caller names none.
DECISION_GRAPH_DEFAULT_MAX_NODES = 1_000
#: The largest node budget.
DECISION_GRAPH_MAX_NODES = 100_000
#: Index rows read per node and kind (statements towards it; link records about it).
DECISION_GRAPH_PAGE = 100
#: The most relations a walk may filter on (the link index's limit).
DECISION_GRAPH_MAX_RELS = 64


class DecisionGraphError(TzunError):
    """A walk the decision graph refuses: ``invalid_evidence_id``, ``record_not_found``,
    ``invalid_depth``, ``invalid_max_nodes`` or ``invalid_relation``. Never echoes the value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _well_formed_link(link: Any) -> bool:
    """A relation name and a 64-hex target digest."""
    return (
        isinstance(link, dict)
        and is_relation_name(link.get("rel"))
        and isinstance(link.get("target"), dict)
        and isinstance(link["target"].get("digest"), str)
        and BARE_DIGEST_RE.fullmatch(link["target"]["digest"]) is not None
    )


def _payload(raw: dict[str, Any]) -> dict[str, Any]:
    payload = raw.get("payload")
    return payload if isinstance(payload, dict) else {}


def _links_of(raw: dict[str, Any]) -> list[Any]:
    links = _payload(raw).get("links")
    return links if isinstance(links, list) else []


def _is_link_record(raw: dict[str, Any]) -> bool:
    return _payload(raw).get("aiSystemId") == LINK_RECORD_AI_SYSTEM_ID


def _subject_link_of(raw: dict[str, Any]) -> dict[str, Any] | None:
    """A link record's first well-formed ``subject`` link, or ``None`` (also for a record that is not a link record)."""
    if not _is_link_record(raw):
        return None
    return next((link for link in _links_of(raw) if _well_formed_link(link) and link["rel"] == "subject"), None)


def _carried_link(raw: dict[str, Any], idx: int, rel: str, digest: str) -> dict[str, Any] | None:
    """The link at ``idx`` of a stored record when it is well formed, has ``rel`` and names ``digest``."""
    links = _links_of(raw)
    link = links[idx] if 0 <= idx < len(links) else None
    if _well_formed_link(link) and link["rel"] == rel and link["target"]["digest"] == digest:  # type: ignore[index]
        return link
    return None


def _decider_of(raw: dict[str, Any]) -> dict[str, str] | None:
    d = _payload(raw).get("decider")
    if isinstance(d, dict) and isinstance(d.get("kind"), str) and isinstance(d.get("id"), str):
        return {"kind": d["kind"], "id": d["id"]}
    return None


def _target_of(link: dict[str, Any]) -> dict[str, Any]:
    evidence_id = link["target"].get("evidenceId")
    return {"digest": link["target"]["digest"], "evidenceId": evidence_id if isinstance(evidence_id, str) else None}


def check_walk_options(
    evidence_id: Any, *, rels: Any, depth: Any, max_nodes: Any
) -> tuple[int, int, set[str] | None]:
    """The walk's options, checked: ``(depth, max_nodes, rels)``; raises :class:`DecisionGraphError`."""
    if not isinstance(evidence_id, str) or not evidence_id:
        raise DecisionGraphError("invalid_evidence_id", "evidenceId must be a non-empty string")
    depth = DECISION_GRAPH_DEFAULT_DEPTH if depth is None else depth
    if not is_safe_integer(depth) or not 0 <= depth <= DECISION_GRAPH_MAX_DEPTH:
        raise DecisionGraphError("invalid_depth", f"depth must be an integer from 0 to {DECISION_GRAPH_MAX_DEPTH}")
    max_nodes = DECISION_GRAPH_DEFAULT_MAX_NODES if max_nodes is None else max_nodes
    if not is_safe_integer(max_nodes) or not 1 <= max_nodes <= DECISION_GRAPH_MAX_NODES:
        raise DecisionGraphError(
            "invalid_max_nodes", f"max_nodes must be an integer from 1 to {DECISION_GRAPH_MAX_NODES}"
        )
    wanted: set[str] | None = None
    if rels is not None:
        if (
            isinstance(rels, (str, bytes))
            or not isinstance(rels, Sequence)
            or len(rels) > DECISION_GRAPH_MAX_RELS
            or not all(is_relation_name(r) for r in rels)
        ):
            raise DecisionGraphError(
                "invalid_relation", f"rels must be a list of at most {DECISION_GRAPH_MAX_RELS} relation names"
            )
        wanted = set(rels)
    return int(depth), int(max_nodes), wanted


async def walk_decision_graph(
    evidence_id: str,
    *,
    by_id: Callable[[str], Awaitable[dict[str, Any] | None]],
    by_digest: Callable[[str], Awaitable[dict[str, Any] | None]],
    links_to: Callable[..., Awaitable[tuple[list[Any], str | None]]],
    rels: Sequence[str] | None = None,
    depth: int | None = None,
    max_nodes: int | None = None,
) -> dict[str, Any]:
    """Walk the decision graph from the record ``evidence_id`` (the TS ``decisionGraphService.walk``).

    ``by_id`` and ``by_digest`` read a stored record's JSON; ``links_to`` is
    the store's ``list_links_to``. Returns ``{root, rootEvidenceId, nodes,
    details, edges, truncated, truncatedBy}``: ``nodes`` the digests in the
    order found (the root first), ``details`` each node (``digest``,
    ``evidenceId``, ``held``, ``depth``, and for a held record
    ``aiSystemId`` and ``intact``), and each edge ``{from, to, rel,
    assertedBy, assertedByDigest, linkIndex, statement, decider,
    assertedByIntact}``.
    """
    max_depth, budget, wanted = check_walk_options(evidence_id, rels=rels, depth=depth, max_nodes=max_nodes)
    root_raw = await by_id(evidence_id)
    if root_raw is None:
        raise DecisionGraphError("record_not_found", "the store holds no record with this evidence id")

    digest_cache: dict[str, dict[str, Any] | None] = {}
    id_cache: dict[str, dict[str, Any] | None] = {}
    intact_cache: dict[str, bool] = {}

    async def record_at(digest: str) -> dict[str, Any] | None:
        if digest not in digest_cache:
            digest_cache[digest] = await by_digest(digest)
        return digest_cache[digest]

    async def record_by_id(identifier: str) -> dict[str, Any] | None:
        if identifier not in id_cache:
            id_cache[identifier] = await by_id(identifier)
        return id_cache[identifier]

    def intact_of(raw: dict[str, Any]) -> bool:
        key = str(_payload(raw).get("evidenceId"))
        if key not in intact_cache:
            intact_cache[key] = record_intact(raw)
        return intact_cache[key]

    root = raw_digest(root_raw)
    digest_cache[root] = root_raw
    nodes: list[str] = []
    details: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_keys: set[str] = set()
    truncated_by: list[str] = []
    queue: list[str] = []

    def stop(bound: str) -> None:
        if bound not in truncated_by:
            truncated_by.append(bound)

    def add_node(digest: str, at_depth: int, node_evidence_id: str | None) -> None:
        if digest in details:
            node = details[digest]
            if node["evidenceId"] is None and node_evidence_id is not None and not node["held"]:
                node["evidenceId"] = node_evidence_id
            return
        nodes.append(digest)
        details[digest] = {"digest": digest, "evidenceId": node_evidence_id, "held": False, "depth": at_depth}
        queue.append(digest)

    def fits(digests: list[str], at_depth: int) -> bool:
        fresh = {d for d in digests if d not in details}
        if not fresh:
            return True
        if at_depth > max_depth:
            stop("depth")
            return False
        if len(nodes) + len(fresh) > budget:
            stop("maxNodes")
            return False
        return True

    def add_edge(
        asserter: dict[str, Any],
        link_index: int,
        source: dict[str, Any],
        target: dict[str, Any],
        rel: str,
        statement: bool,
        at_depth: int,
    ) -> None:
        if wanted is not None and rel not in wanted:
            return
        asserted_by_digest = raw_digest(asserter)
        key = f"{asserted_by_digest}#{link_index}"
        if key in edge_keys:
            return
        # Both endpoints or neither: an edge never leaves a node behind without it.
        if not fits([source["digest"], target["digest"]], at_depth + 1):
            return
        add_node(source["digest"], at_depth + 1, source["evidenceId"])
        add_node(target["digest"], at_depth + 1, target["evidenceId"])
        edge_keys.add(key)
        edges.append(
            {
                "from": source["digest"],
                "to": target["digest"],
                "rel": rel,
                "assertedBy": _payload(asserter).get("evidenceId"),
                "assertedByDigest": asserted_by_digest,
                "linkIndex": link_index,
                "statement": statement,
                "decider": _decider_of(asserter),
                "assertedByIntact": intact_of(asserter),
            }
        )

    def link_record_edges(record: dict[str, Any], at_depth: int, as_node: bool) -> None:
        subject = _subject_link_of(record)
        if subject is None:
            return
        own = {"digest": raw_digest(record), "evidenceId": _payload(record).get("evidenceId")}
        for j, link in enumerate(_links_of(record)):
            if not _well_formed_link(link):
                continue
            if link["rel"] != "subject":
                add_edge(record, j, _target_of(subject), _target_of(link), link["rel"], True, at_depth)
            elif as_node:
                add_edge(record, j, own, _target_of(link), "subject", False, at_depth)

    add_node(root, 0, _payload(root_raw).get("evidenceId"))
    while queue:
        digest = queue.pop(0)
        node = details[digest]
        record = await record_at(digest)
        if record is not None:
            payload = _payload(record)
            node["held"] = True
            node["evidenceId"] = payload.get("evidenceId")
            node["aiSystemId"] = payload.get("aiSystemId")
            node["intact"] = intact_of(record)
            if _is_link_record(record):
                link_record_edges(record, node["depth"], True)
            else:
                own = {"digest": digest, "evidenceId": payload.get("evidenceId")}
                for j, link in enumerate(_links_of(record)):
                    if _well_formed_link(link):
                        add_edge(record, j, own, _target_of(link), link["rel"], False, node["depth"])

        # Link records' statements towards this node, and link records about it.
        towards, towards_cursor = await links_to(
            digest, rels=sorted(wanted) if wanted is not None else None, limit=DECISION_GRAPH_PAGE, statements=True
        )
        about, about_cursor = await links_to(digest, rels=["subject"], limit=DECISION_GRAPH_PAGE)
        if towards_cursor is not None or about_cursor is not None:
            stop("page")
        for row in [*towards, *about]:
            asserter = await record_by_id(row.evidenceId)
            if asserter is None:
                continue
            # Only what the record itself carries: an index row that does not
            # match the record's link (or a record that is not a link record)
            # draws nothing.
            if _carried_link(asserter, row.idx, row.rel, digest) is None or _subject_link_of(asserter) is None:
                continue
            link_record_edges(asserter, node["depth"], False)

    return {
        "root": root,
        "rootEvidenceId": _payload(root_raw).get("evidenceId"),
        "nodes": nodes,
        "details": details,
        "edges": edges,
        "truncated": bool(truncated_by),
        "truncatedBy": truncated_by,
    }


def raw_digest(raw: dict[str, Any]) -> str:
    integrity = raw.get("integrity")
    digest = integrity.get("canonicalDigest") if isinstance(integrity, dict) else None
    return digest if isinstance(digest, str) else ""


__all__ = (
    "DECISION_GRAPH_DEFAULT_DEPTH",
    "DECISION_GRAPH_DEFAULT_MAX_NODES",
    "DECISION_GRAPH_MAX_DEPTH",
    "DECISION_GRAPH_MAX_NODES",
    "DECISION_GRAPH_PAGE",
    "DecisionGraphError",
    "check_walk_options",
    "walk_decision_graph",
)
