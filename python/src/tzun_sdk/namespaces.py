"""The ``agents``, ``links``, ``deciders`` and ``decision_graph`` namespaces of :class:`~tzun_sdk.Tzun`.

* ``tzun.agents``: the agent catalog (Record §6.9): ``register`` (idempotent on
  identical bytes), ``get``, ``list``.
* ``tzun.links``: ``relate`` captures a link record stating relations of a
  subject after the fact (Record §8.6); ``of`` lists a record's links with their
  resolution; ``to`` lists, a page at a time, the same-store records that link
  to a digest (the link index).
* ``tzun.deciders.opening``: the opening of a record's ``cmt:`` decider (Record §6.3).
* ``tzun.decision_graph.walk``: a bounded walk over a record's links and the
  statements of link records (:mod:`tzun_sdk.decision_graph`).

The twins of the TS SDK's ``AgentsApi``, ``LinksApi``, ``tzun.deciders`` and
``DecisionGraphApi``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from tzun_sdk._capture import CaptureRequest
from tzun_sdk._record_rules import deep_plain
from tzun_sdk.agents import agent_descriptor_violation
from tzun_sdk.errors import InvalidAgentDescriptorError, InvalidLinksError
from tzun_sdk.links import LINK_RECORD_ACTION, LINK_RECORD_AI_SYSTEM_ID
from tzun_sdk.models import AgentDescriptorRow, CaptureResult, DeciderOpening

if TYPE_CHECKING:
    from tzun_sdk.core import Tzun

#: The default and largest page of ``links.to`` and ``agents.list``.
DEFAULT_PAGE = 100
MAX_PAGE = 200


class AgentsNamespace:
    """``tzun.agents``: the agent catalog (Record §6.9)."""

    def __init__(self, tzun: Tzun) -> None:
        self._tzun = tzun

    def _storage(self, method: str) -> Any:
        storage = self._tzun._storage
        if not hasattr(storage, method):
            raise InvalidAgentDescriptorError(
                "agent_not_supported_by_store",
                "agents",
                "this store keeps no agent catalog; capture accepts agent references as given",
            )
        return storage

    async def register(self, descriptor: Any) -> dict[str, Any]:
        """Register a ``tzun-agent/1`` descriptor; ``{"digest", "alreadyExisted"}``, idempotent on identical bytes.

        Raises :class:`~tzun_sdk.errors.InvalidAgentDescriptorError`
        (``invalid_agent_descriptor``) for a descriptor outside the grammar or
        the writer limits (16 KiB, 64 elements per set, 256 UTF-16 units per
        string, 8,192 for an attestation). ``name`` and ``organization`` name
        a product and an organisation, never a person.
        """
        self._tzun._require_active()
        d = deep_plain(descriptor)
        reason = agent_descriptor_violation(d)
        if reason is not None:
            raise InvalidAgentDescriptorError("invalid_agent_descriptor", "descriptor", reason)
        digest, existed = await self._storage("put_agent_descriptor").put_agent_descriptor(d)
        return {"digest": digest, "alreadyExisted": existed}

    async def get(self, digest: str) -> AgentDescriptorRow | None:
        """The catalog row (its ``canonicalBytes`` are the bytes that were hashed), or ``None``."""
        self._tzun._require_active()
        row: AgentDescriptorRow | None = await self._storage("get_agent_descriptor").get_agent_descriptor(digest)
        return row

    async def list(
        self,
        *,
        name: str | None = None,
        organization: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """A page of descriptors by lookup column: ``{"rows": [...], "cursor": str | None}`` (``limit`` at most 200)."""
        self._tzun._require_active()
        rows, nxt = await self._storage("list_agent_descriptors").list_agent_descriptors(
            name=name, organization=organization, limit=limit, cursor=cursor
        )
        return {"rows": rows, "cursor": nxt}


class LinksNamespace:
    """``tzun.links``: link records, a record's links, and the records that link to a digest (Record §8)."""

    def __init__(self, tzun: Tzun) -> None:
        self._tzun = tzun

    async def relate(
        self,
        *,
        subject: dict[str, Any],
        relations: Sequence[dict[str, Any]],
        reason: str,
        decider: Any,
    ) -> CaptureResult:
        """Capture a link record (Record §8.6): ``subject`` ``<rel>`` each relation's target, asserted by ``decider``.

        ``subject`` and each relation's ``target`` are link targets (Record §8.7): a
        same-store record by ``evidenceId`` or ``digest``, or one held in
        another store with ``"external": True``. The record's ``aiSystemId``
        is ``tzun:link``, its action ``link``, its ``aiOutput`` ``{}``; it
        carries no ``root``, ``mandate``, ``revokes``, ``closes`` or
        ``fanoutOf`` link, and each relation's rules read the subject in the
        child's place.
        """
        self._tzun._require_active()
        subject_plain = deep_plain(subject)
        relations_plain = deep_plain(list(relations))
        if not isinstance(relations_plain, list) or not relations_plain:
            raise InvalidLinksError(
                "required_link_missing", "relations", "a link record states at least one relation of its subject"
            )
        link_inputs: list[Any] = [{"rel": "subject", "target": subject_plain}]
        for relation in relations_plain:
            if not isinstance(relation, dict):
                raise InvalidLinksError("link_unknown_members", "relations", "each relation is {rel, target, attrs?}")
            link_inputs.append(relation)
        decider_plain = deep_plain(decider)
        if not isinstance(decider_plain, dict):
            raise InvalidLinksError("required_link_missing", "decider", "a link record names its decider")
        request = CaptureRequest(
            ai_output={},
            action=LINK_RECORD_ACTION,
            reason=reason,
            decider=decider_plain,
            ai_system_id=LINK_RECORD_AI_SYSTEM_ID,
            links=link_inputs,
            system_record="link",
            allow_reserved=("subject",),
            link_record=True,
        )
        from tzun_sdk._capture import capture_input_violation

        refusal = capture_input_violation(
            ai_output={},
            action=LINK_RECORD_ACTION,
            reason=reason,
            ai_system_id=None,
            decider=decider_plain,
            contributions=None,
            links=link_inputs,
        )
        if refusal is not None:
            raise refusal
        return await self._tzun._capture_request(request)

    async def of(self, evidence_id: str) -> list[dict[str, Any]]:
        """A record's links with their resolution: ``[{index, rel, target, attrs, held, heldEvidenceId}]``."""
        self._tzun._require_active()
        raw = await self._tzun._stored_raw(evidence_id)
        if raw is None:
            raise InvalidLinksError("link_target_not_found", "evidenceId", f"no record {evidence_id!r} in this store")
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
        links = payload.get("links") if isinstance(payload.get("links"), list) else []
        storage = self._tzun._storage
        out: list[dict[str, Any]] = []
        for index, link in enumerate(links):
            if not isinstance(link, dict):
                continue
            target = link.get("target") if isinstance(link.get("target"), dict) else {}
            held = None
            if hasattr(storage, "retrieve_raw_by_digest") and isinstance(target.get("digest"), str):
                held = await storage.retrieve_raw_by_digest(target["digest"])
            held_payload = held.get("payload") if isinstance(held, dict) and isinstance(held.get("payload"), dict) else None
            out.append(
                {
                    "index": index,
                    "rel": link.get("rel"),
                    "target": target,
                    "attrs": link.get("attrs"),
                    "held": held_payload is not None,
                    "heldEvidenceId": held_payload.get("evidenceId") if held_payload is not None else None,
                }
            )
        return out

    async def to(
        self,
        digest: str,
        *,
        rels: Sequence[str] | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """The same-store records that link to ``digest``, a page at a time (``limit`` at most 200, default 100).

        ``{"rows": [{evidenceId, idx, rel, linkRecord}], "cursor": str | None}``;
        ``linkRecord`` says the row is a link record's statement about its
        subject (or its ``subject`` link), not the linking record's own
        relation. Raises :class:`~tzun_sdk.errors.InvalidLinksError`
        (``links_not_supported_by_store``) on a store with no link index.
        """
        self._tzun._require_active()
        storage = self._tzun._storage
        if not hasattr(storage, "list_links_to"):
            raise InvalidLinksError(
                "links_not_supported_by_store", "links", "this store keeps no link index (the cloud store in 0.8.0)"
            )
        rows, nxt = await storage.list_links_to(digest, rels=rels, limit=limit, cursor=cursor)
        out = []
        for row in rows:
            raw = await self._tzun._stored_raw(row.evidenceId)
            payload = raw.get("payload") if isinstance(raw, dict) and isinstance(raw.get("payload"), dict) else {}
            out.append(
                {
                    "evidenceId": row.evidenceId,
                    "idx": row.idx,
                    "rel": row.rel,
                    "linkRecord": payload.get("aiSystemId") == LINK_RECORD_AI_SYSTEM_ID,
                }
            )
        return {"rows": out, "cursor": nxt}


class DecidersNamespace:
    """``tzun.deciders``: the openings of ``cmt:`` deciders this store keeps (Record §6.3)."""

    def __init__(self, tzun: Tzun) -> None:
        self._tzun = tzun

    async def opening(self, evidence_id: str) -> DeciderOpening | None:
        """The opening ``{salt, id}`` of the record's ``cmt:`` decider, or ``None`` when the store keeps none."""
        self._tzun._require_active()
        reader = getattr(self._tzun._storage, "get_decider_opening", None)
        if reader is None:
            return None
        opening: DeciderOpening | None = await reader(evidence_id)
        return opening


class DecisionGraphNamespace:
    """``tzun.decision_graph``: the bounded walk over a record's links."""

    def __init__(self, tzun: Tzun) -> None:
        self._tzun = tzun

    async def walk(
        self,
        evidence_id: str,
        *,
        rels: Sequence[str] | None = None,
        depth: int | None = None,
        max_nodes: int | None = None,
    ) -> dict[str, Any]:
        """Walk from a record: its links, a link record's statements, and the statements link records make about it.

        Returns ``{root, rootEvidenceId, nodes, details, edges, truncated,
        truncatedBy}`` (:func:`tzun_sdk.decision_graph.walk_decision_graph`):
        ``nodes`` are digests, ``details`` each node, and each edge names the
        record that asserts it (``assertedBy``, its decider, whether it is a
        link record's statement, whether it is intact), so a relation a third
        party stated is never shown as the target's own. ``depth`` (0 to 256,
        default 16), ``max_nodes`` (1 to 100,000, default 1,000) and one page
        of the link index per node and kind bound the walk; ``truncatedBy``
        names the bounds that stopped it. Raises
        :class:`~tzun_sdk.decision_graph.DecisionGraphError` for a refused
        option or an unknown record, and
        :class:`~tzun_sdk.errors.InvalidLinksError`
        (``links_not_supported_by_store``) on a store with no link index.
        """
        from tzun_sdk.decision_graph import check_walk_options, walk_decision_graph

        self._tzun._require_active()
        check_walk_options(evidence_id, rels=rels, depth=depth, max_nodes=max_nodes)
        storage = self._tzun._storage
        if not hasattr(storage, "list_links_to") or not hasattr(storage, "retrieve_raw_by_digest"):
            raise InvalidLinksError(
                "links_not_supported_by_store", "links", "this store keeps no link index (the cloud store in 0.8.0)"
            )
        return await walk_decision_graph(
            evidence_id,
            by_id=self._tzun._stored_raw,
            by_digest=storage.retrieve_raw_by_digest,
            links_to=storage.list_links_to,
            rels=rels,
            depth=depth,
            max_nodes=max_nodes,
        )


__all__ = ("AgentsNamespace", "DecidersNamespace", "DecisionGraphNamespace", "LinksNamespace")
