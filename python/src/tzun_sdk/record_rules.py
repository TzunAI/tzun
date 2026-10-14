"""The one gate over a built payload (Record §2.2): the twin of ``packages/engine/src/record-rules.ts``.

A writer hashes a payload only when :func:`payload_record_rule_violation`
answers ``None``: the members of the format, each member's writer rule, the
decider, the signature expectation and the decider's agreement with it, the
contributions, the links, and the size cap, first failure first.
"""

from __future__ import annotations

from typing import Any

from tzun_sdk._record_rules import plain
from tzun_sdk.payload_rules import (
    CURRENT_SCHEMA_VERSION,
    PAYLOAD_MEMBERS,
    action_violation,
    ai_output_violation,
    ai_system_id_violation,
    capture_time_violation,
    evidence_id_violation,
    moved_field_violation,
    payload_size_violation,
    reason_violation,
    renamed_field_violation,
    sequence_number_violation,
)


def _of(rule: str, v: dict[str, Any]) -> dict[str, Any]:
    return {"rule": rule, "code": v["code"], "field": v["field"], "message": v["message"]}


def payload_record_rule_violation(payload: Any, *, system_record: str | None = None) -> dict[str, Any] | None:
    """Why a built payload is not one a writer may hash, first failure first, or ``None``. Never raises.

    The refusal is ``{rule, code, field, message}`` (``linkRule`` for a
    ``links`` refusal that names a rule); ``rule`` is ``payload``,
    ``decider``, ``signoffExpectation``, ``contributions`` or ``links``.
    """
    from tzun_sdk.contributions import contributions_violation
    from tzun_sdk.decider import (
        decider_agrees_with_expectation,
        decider_violation,
        decider_violation_of,
    )
    from tzun_sdk.links import links_violation
    from tzun_sdk.signoff_expectation import (
        describe_signoff_expectation_violation,
        signoff_expectation_violation,
    )

    payload = plain(payload)
    if not isinstance(payload, dict):
        return {
            "rule": "payload",
            "code": "missing_members",
            "field": "payload",
            "message": "payload must be an object with every member of the format",
        }
    renamed = renamed_field_violation(payload) or moved_field_violation(payload)
    if renamed:
        return _of("payload", renamed)
    if payload.get("schemaVersion") != CURRENT_SCHEMA_VERSION:
        return {
            "rule": "payload",
            "code": "unsupported_schema_version",
            "field": "schemaVersion",
            "message": f"schemaVersion must be {CURRENT_SCHEMA_VERSION}",
        }
    unknown = next((k for k in payload if k not in PAYLOAD_MEMBERS), None)
    if unknown is not None:
        return {
            "rule": "payload",
            "code": "unknown_payload_member",
            "field": unknown,
            "message": f"{unknown} is not a member of the payload",
        }
    missing = next((k for k in PAYLOAD_MEMBERS if k not in payload), None)
    if missing is not None:
        return {
            "rule": "payload",
            "code": "missing_members",
            "field": missing,
            "message": f"{missing} is required: a writer writes every member, null where it does not apply",
        }
    p = payload
    member_issue = (
        evidence_id_violation(p["evidenceId"])
        or capture_time_violation(p["capturedAt"])
        or sequence_number_violation(p["sequenceNumber"])
        or ai_system_id_violation(p["aiSystemId"], system_record=system_record)
        or ai_output_violation(p["aiOutput"])
        or action_violation(p["action"])
        or reason_violation(p["reason"])
    )
    if member_issue:
        return _of("payload", member_issue)
    decider_issue = decider_violation(p["decider"])
    if decider_issue:
        return _of("decider", decider_issue)
    expectation_issue = signoff_expectation_violation(p["signoffExpectation"])
    if expectation_issue is not None:
        return {
            "rule": "signoffExpectation",
            "code": expectation_issue,
            "field": "signoffExpectation",
            "message": describe_signoff_expectation_violation(expectation_issue),
        }
    if decider_agrees_with_expectation(p["decider"].get("kind"), p["signoffExpectation"]) is False:
        return _of("decider", decider_violation_of("kind_contradicts_expectation", "decider.kind"))
    contributions_issue = contributions_violation(
        p["contributions"], {"decider": p["decider"], "action": p["action"], "reason": p["reason"]}
    )
    if contributions_issue:
        return _of("contributions", contributions_issue)
    links_issue = links_violation(p["links"], p)
    if links_issue:
        out = _of("links", links_issue)
        if links_issue.get("rule") is not None:
            out["linkRule"] = links_issue["rule"]
        return out
    size_issue = payload_size_violation(p)
    if size_issue:
        return _of("payload", size_issue)
    return None


__all__ = ("payload_record_rule_violation",)
