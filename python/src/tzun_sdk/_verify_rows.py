"""The record-rule rows of ``Tzun.verify()`` (Verification §4.9 to §4.12), over the stored JSON.

The twin of the engine ``verifyEnvelope``'s ``recordRuleFields``,
``mandateRows``, ``resolveAgentReferences`` and ``prefetchLinkTargets``: the
``decider``, ``contributions``, ``links`` and ``mandate`` rows, read from the
record alone and only where its digest holds; with a store, the agent
references resolved against the catalog and the link targets the store holds.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tzun_sdk.agents import agent_descriptor_digest, agent_descriptor_violation, agent_kind_mismatch
from tzun_sdk.contributions import check_contributions
from tzun_sdk.decider import check_decider, identifier_scheme, verify_decider_opening
from tzun_sdk.errors import InvalidAgentDescriptorError
from tzun_sdk.links import HeldLinkTarget, LinkTargetResolver, check_links
from tzun_sdk.mandate.document import mandate_document_violation
from tzun_sdk.mandate.issuance import check_mandate_issuance
from tzun_sdk.mandate.scope import check_mandate_limits, evaluate_mandate_scope
from tzun_sdk.signoff_expectation import signoff_expectation_form


def _mandate_rows(raw: dict[str, Any], expectation: dict[str, Any]) -> dict[str, Any] | None:
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    nr = raw.get("nonRepudiation") if isinstance(raw.get("nonRepudiation"), dict) else {}
    out: dict[str, Any] = {}
    issuance = check_mandate_issuance(raw)
    if issuance is not None:
        out["issuance"] = issuance
    if signoff_expectation_form(payload.get("signoffExpectation")) == "mandate":
        ready = expectation.get("valid") is True or (
            expectation.get("valid") is None and expectation.get("reason") == "confirmation_missing"
        )
        if not ready:
            blocked = {"outcome": "not-checked", "valid": None, "reason": "blocked_by:signoff.expectation"}
            out["scope"] = dict(blocked)
            out["limits"] = dict(blocked)
        else:
            block = nr.get("mandate") if isinstance(nr.get("mandate"), dict) else {}
            document = block.get("document")
            if document is None:
                missing = {"outcome": "not-checked", "valid": None, "reason": "not_in_bundle:mandate_document"}
                out["scope"] = dict(missing)
                out["limits"] = dict(missing)
            elif mandate_document_violation(document, prepare=False) is not None:
                malformed = {"outcome": "checked-wrong", "valid": False, "reason": "malformed_mandate_document"}
                out["scope"] = dict(malformed)
                out["limits"] = dict(malformed)
            else:
                scope = evaluate_mandate_scope(document, payload)
                if not scope["agentInMandate"]:
                    out["scope"] = {
                        "outcome": "checked-wrong",
                        "valid": False,
                        "reason": "agent_not_in_mandate",
                        "failures": scope["failures"],
                    }
                elif scope["verdict"] == "outside":
                    out["scope"] = {
                        "outcome": "checked-wrong",
                        "valid": False,
                        "reason": "outside_mandate_scope",
                        "failures": scope["failures"],
                    }
                elif scope["confirmationEvaded"]:
                    out["scope"] = {"outcome": "checked-wrong", "valid": False, "reason": "confirmation_evaded"}
                elif scope["verdict"] == "undeterminable":
                    out["scope"] = {
                        "outcome": "not-checked",
                        "valid": None,
                        "reason": "scope_undeterminable",
                        "undeterminable": scope["undeterminable"],
                    }
                else:
                    out["scope"] = {"outcome": "checked-correct", "valid": True}
                limits = check_mandate_limits(document, payload)
                row: dict[str, Any] = (
                    {"outcome": "checked-correct", "valid": True}
                    if limits["valid"]
                    else {"outcome": "checked-wrong", "valid": False, "reason": limits["reason"]}
                )
                if "slot" in limits:
                    row["slot"] = limits["slot"]
                if "totals" in limits:
                    row["totals"] = limits["totals"]
                out["limits"] = row
    return out or None


def record_rule_fields(
    raw: dict[str, Any],
    digest_holds: bool,
    expectation: dict[str, Any],
    resolver: LinkTargetResolver | None = None,
) -> dict[str, Any]:
    """The ``decider``, ``contributions``, ``links`` and ``mandate`` rows, as ``VerificationResult`` fields."""
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    nr = raw.get("nonRepudiation") if isinstance(raw.get("nonRepudiation"), dict) else {}
    mandate_material = (
        nr.get("mandate") is not None
        or nr.get("mandateIssuance") is not None
        or payload.get("aiSystemId") == "tzun:mandate"
    )
    if not digest_holds:
        invalid = {"outcome": "not-checked", "valid": None, "reason": "digest_invalid"}
        binding = {
            **invalid,
            "approvals": [],
            "staleApprovals": [],
            "uncoveredReviews": [],
            "proposals": [],
            "decisionBinding": "not-applicable",
        }
        out: dict[str, Any] = {
            "decider": dict(invalid),
            "contributions": {**invalid, "binding": binding},
            "links": {**invalid, "relations": [], "edges": []},
        }
        if mandate_material or signoff_expectation_form(payload.get("signoffExpectation")) == "mandate":
            out["mandate"] = {"reason": "digest_invalid"}
        return out
    out = {
        "decider": check_decider(raw),
        "contributions": check_contributions(payload),
        "links": check_links(payload, resolver=resolver),
    }
    mandate = _mandate_rows(raw, expectation)
    if mandate is not None:
        out["mandate"] = mandate
    return out


def _hash_bytes(canonical_bytes: Any) -> str:
    if not isinstance(canonical_bytes, str):
        return ""
    return "sha256:" + hashlib.sha256(canonical_bytes.encode("utf-8")).hexdigest()


async def resolve_agent_references(raw: dict[str, Any], storage: Any) -> list[dict[str, Any]]:
    """The decider's and every step actor's agent reference against the catalog (Record §6.9)."""
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    refs: list[dict[str, Any]] = []
    decider = payload.get("decider") if isinstance(payload.get("decider"), dict) else None
    if decider is not None and isinstance(decider.get("agent"), str):
        refs.append({"field": "decider", "kind": decider.get("kind"), "reference": decider["agent"]})
    contributions = payload.get("contributions") if isinstance(payload.get("contributions"), dict) else None
    if contributions is not None and isinstance(contributions.get("steps"), list):
        for i, step in enumerate(contributions["steps"]):
            actor = step.get("actor") if isinstance(step, dict) and isinstance(step.get("actor"), dict) else None
            if actor is not None and isinstance(actor.get("agent"), str):
                refs.append({"field": f"contributions.steps[{i}].actor", "kind": actor.get("kind"), "reference": actor["agent"]})
    out: list[dict[str, Any]] = []
    for ref in refs:
        base = {"reference": ref["reference"], "field": ref["field"]}
        if not hasattr(storage, "get_agent_descriptor"):
            out.append({**base, "resolved": False, "reason": "catalog_absent"})
            continue
        try:
            row = await storage.get_agent_descriptor(ref["reference"])
        except InvalidAgentDescriptorError as exc:
            # A store whose catalog methods answer that it keeps none.
            if exc.code != "agent_not_supported_by_store":
                raise
            out.append({**base, "resolved": False, "reason": "catalog_absent"})
            continue
        if row is None:
            out.append({**base, "resolved": False, "reason": "not_registered"})
            continue
        if _hash_bytes(row.canonicalBytes) != ref["reference"]:
            out.append({**base, "resolved": False, "reason": "digest_mismatch"})
            continue
        try:
            parsed = json.loads(row.canonicalBytes)
            descriptor = parsed if agent_descriptor_violation(parsed, limits=False) is None else None
        except ValueError:
            descriptor = None
        if descriptor is None or agent_descriptor_digest(descriptor) != ref["reference"]:
            out.append({**base, "resolved": False, "reason": "malformed_descriptor"})
            continue
        if agent_kind_mismatch(ref["kind"], descriptor):
            out.append({**base, "resolved": False, "reason": "agent_kind_mismatch"})
            continue
        out.append({**base, "resolved": True})
    return out


async def store_link_resolver(raw: dict[str, Any], storage: Any) -> LinkTargetResolver | None:
    """What the store holds for this record's links (Record §8.8): targets by digest and the ``cmt:`` openings.

    ``None`` when the adapter cannot look a record up by digest. Resolution
    never crosses the store. This SDK's stores keep no evidence log, so no
    locator is compared with a position here.
    """
    if not hasattr(storage, "retrieve_raw_by_digest"):
        return None
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    links = payload.get("links") if isinstance(payload.get("links"), list) else []
    held: dict[str, HeldLinkTarget | None] = {}
    openings: dict[str, str | None] = {}

    async def add_opening(record: dict[str, Any]) -> None:
        d = record.get("decider") if isinstance(record.get("decider"), dict) else None
        if d is None or not isinstance(d.get("id"), str) or identifier_scheme(d["id"]) != "cmt" or d["id"] in openings:
            return
        inner: str | None = None
        if hasattr(storage, "get_decider_opening") and isinstance(record.get("evidenceId"), str):
            opening = await storage.get_decider_opening(record["evidenceId"])
            if opening is not None and verify_decider_opening(d["id"], opening):
                inner = opening.id
        openings[d["id"]] = inner

    await add_opening(payload)
    for link in links:
        if not isinstance(link, dict) or not isinstance(link.get("target"), dict):
            continue
        digest = link["target"].get("digest")
        if not isinstance(digest, str) or digest in held:
            continue
        env = await storage.retrieve_raw_by_digest(digest)
        if (
            env is not None
            and isinstance(env.get("payload"), dict)
            and isinstance(env.get("integrity"), dict)
            and isinstance(env["integrity"].get("canonicalDigest"), str)
        ):
            target = HeldLinkTarget(payload=env["payload"], digest=env["integrity"]["canonicalDigest"], origin=None)
            held[digest] = target
            await add_opening(target.payload)
        else:
            held[digest] = None
    return LinkTargetResolver(
        by_digest=lambda digest: held.get(digest),
        open_commitment=lambda identifier: openings.get(identifier),
    )


__all__ = ("record_rule_fields", "resolve_agent_references", "store_link_resolver")
