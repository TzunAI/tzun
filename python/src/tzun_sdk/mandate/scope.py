"""What a mandate permits, checked against a record (Record §9.9, §9.10).

The scope, the confirmation flag, the single-record limits, and the
consumption of slots and totals over a set of records. The twin of
``packages/engine/src/mandate/scope.ts``.
"""

from __future__ import annotations

from typing import Any

from tzun_sdk._record_rules import (
    is_non_negative_safe_integer,
    is_positive_safe_integer,
    plain,
)
from tzun_sdk.mandate.document import mandate_restriction_holds
from tzun_sdk.mandate.predicate import evaluate_predicate, parse_json_pointer, resolve_pointer


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _includes(values: list[Any], item: Any) -> bool:
    """JavaScript ``Array.prototype.includes`` over JSON values (strings compare by value, ``True`` is not 1)."""
    for v in values:
        if isinstance(v, bool) or isinstance(item, bool):
            if v is item:
                return True
        elif v == item and type(v) is not dict and type(v) is not list:
            return True
    return False


def decider_in_mandate(decider: Any, agents: Any) -> bool:
    """Whether a decider is one of the document's agents: its id, ``desc:`` + its agent, or the same ``cmt``."""
    decider = plain(decider)
    if not isinstance(decider, dict) or not isinstance(agents, list):
        return False
    if isinstance(decider.get("id"), str) and _includes(agents, decider["id"]):
        return True
    return isinstance(decider.get("agent"), str) and _includes(agents, f"desc:{decider['agent']}")


def recorded_models(payload: dict[str, Any]) -> list[Any]:
    """Every model a record names: each non-null contribution step ``aiBom``'s digest, in step order."""
    models: list[Any] = []
    contributions = payload.get("contributions")
    if isinstance(contributions, dict) and isinstance(contributions.get("steps"), list):
        for step in contributions["steps"]:
            if isinstance(step, dict) and isinstance(step.get("aiBom"), dict):
                models.append(step["aiBom"].get("modelDescriptorDigest"))
    return models


def _evaluate_group(group: Any, payload: Any) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"holding": [], "failing": [], "undeterminable": []}
    if not isinstance(group, dict):
        return out
    for name in sorted(group):
        outcome = evaluate_predicate(group[name], payload)
        if outcome == "true":
            out["holding"].append(name)
        elif outcome == "false":
            out["failing"].append(name)
        else:
            out["undeterminable"].append(name)
    return out


def evaluate_mandate_scope(document: Any, payload: Any) -> dict[str, Any]:
    """Whether the record is within the scope of ``document`` (Record §9.9). Never raises.

    Returns ``{verdict, failures, undeterminable, agentInMandate, confirmationEvaded}``.
    """
    failures: list[dict[str, Any]] = []
    undeterminable: list[dict[str, Any]] = []
    d = _obj(plain(document))
    p = _obj(plain(payload))
    scope = _obj(d.get("scope"))
    agent_in_mandate = decider_in_mandate(p.get("decider"), d.get("agents"))
    if not agent_in_mandate:
        failures.append({"constraint": "agents"})

    version = p.get("schemaVersion") if isinstance(p.get("schemaVersion"), str) else ""
    if not mandate_restriction_holds(d, version):
        undeterminable.append({"constraint": "restriction"})

    if isinstance(scope.get("aiSystemIds"), list) and not _includes(scope["aiSystemIds"], p.get("aiSystemId")):
        failures.append({"constraint": "aiSystemIds"})
    if isinstance(scope.get("actions"), list) and not _includes(scope["actions"], p.get("action")):
        failures.append({"constraint": "actions"})
    if isinstance(scope.get("models"), list):
        models = recorded_models(p)
        if len(models) == 0:
            undeterminable.append({"constraint": "models"})
        elif not all(_includes(scope["models"], m) for m in models):
            failures.append({"constraint": "models"})
    predicates = _evaluate_group(scope.get("predicates"), p)
    for name in predicates["failing"]:
        failures.append({"constraint": "predicate", "name": name})
    for name in predicates["undeterminable"]:
        undeterminable.append({"constraint": "predicate", "name": name})

    expectation = _obj(p.get("signoffExpectation"))
    confirm = _evaluate_group(d.get("confirm"), p)
    confirmation_evaded = expectation.get("confirm") is False and len(confirm["holding"]) > 0
    if expectation.get("confirm") is False and len(confirm["holding"]) == 0:
        for name in confirm["undeterminable"]:
            undeterminable.append({"constraint": "confirm", "name": name})

    verdict = "within"
    if failures:
        verdict = "outside"
    elif undeterminable:
        verdict = "undeterminable"
    return {
        "verdict": verdict,
        "failures": failures,
        "undeterminable": undeterminable,
        "agentInMandate": agent_in_mandate,
        "confirmationEvaded": confirmation_evaded,
    }


def evaluate_mandate_confirm(document: Any, payload: Any) -> dict[str, Any]:
    """The confirmation flag a capture under ``document`` writes (Record §9.6, capture under a mandate).

    ``confirm`` is ``True`` when a confirm predicate holds, ``False`` when none
    holds and none is undeterminable, ``None`` (refused) otherwise.
    """
    d = _obj(plain(document))
    group = _evaluate_group(d.get("confirm"), plain(payload))
    if group["holding"]:
        confirm: bool | None = True
    elif group["undeterminable"]:
        confirm = None
    else:
        confirm = False
    return {"confirm": confirm, "holding": group["holding"], "undeterminable": group["undeterminable"]}


def mandate_cap_values(document: Any, payload: Any) -> dict[str, Any]:
    """The value at each cap's path, which must be a non-negative safe integer.

    ``{"values": {...} | None, "invalid": [...]}``; ``values`` is ``None`` for
    a document with no cap.
    """
    d = _obj(plain(document))
    limits = _obj(d.get("limits"))
    cumulative = limits.get("cumulative")
    if not isinstance(cumulative, dict):
        return {"values": None, "invalid": []}
    values: dict[str, Any] = {}
    invalid: list[str] = []
    for cap, definition in cumulative.items():
        tokens = parse_json_pointer(definition.get("path")) if isinstance(definition, dict) else None
        resolved = {"found": False} if tokens is None else resolve_pointer(payload, tokens)
        if resolved["found"] and is_non_negative_safe_integer(resolved["value"]):
            values[cap] = resolved["value"]
        else:
            invalid.append(cap)
    return {"values": values, "invalid": invalid}


def check_mandate_limits(document: Any, payload: Any) -> dict[str, Any]:
    """The single-record limits (Record §9.9). Never raises.

    ``{"valid": bool, "reason"?: ..., "slot"?: ..., "totals"?: ...}``.
    """
    d = _obj(plain(document))
    p = _obj(plain(payload))
    expectation = _obj(p.get("signoffExpectation"))
    limits = _obj(d.get("limits"))
    slot = expectation.get("mandateSeq")
    if not is_positive_safe_integer(slot):
        return {"valid": False, "reason": "mandate_totals_malformed"}
    totals = expectation.get("totals")
    facts = {"slot": slot, "totals": totals if isinstance(totals, dict) else None}
    if is_non_negative_safe_integer(limits.get("maxRecords")) and slot > limits["maxRecords"]:
        return {"valid": False, "reason": "mandate_limit_exceeded", **facts}
    cumulative = limits.get("cumulative") if isinstance(limits.get("cumulative"), dict) else None
    if cumulative is None:
        if totals is None:
            return {"valid": True, **facts}
        return {"valid": False, "reason": "mandate_totals_malformed", **facts}
    if not isinstance(totals, dict):
        return {"valid": False, "reason": "mandate_totals_malformed", **facts}
    caps = sorted(cumulative)
    if caps != sorted(totals):
        return {"valid": False, "reason": "mandate_totals_malformed", **facts}
    cap_values = mandate_cap_values(d, p)
    values, invalid = cap_values["values"], cap_values["invalid"]
    if invalid or values is None:
        return {"valid": False, "reason": "mandate_totals_malformed", **facts}
    for cap in caps:
        total = totals[cap]
        definition = cumulative[cap] if isinstance(cumulative[cap], dict) else {}
        if not is_non_negative_safe_integer(total):
            return {"valid": False, "reason": "mandate_totals_malformed", **facts}
        if (
            total < values[cap]
            or not is_non_negative_safe_integer(definition.get("max"))
            or total > definition["max"]
        ):
            return {"valid": False, "reason": "mandate_limit_exceeded", **facts}
    return {"valid": True, **facts}


def check_mandate_consumption(
    document: Any, envelopes: list[Any], *, last_event: Any = None
) -> dict[str, Any]:
    """Consumption over the records of one mandate (Record §9.10), pure. Never raises."""
    malformed: list[dict[str, Any]] = []
    by_slot: dict[int, list[dict[str, Any]]] = {}
    d = _obj(plain(document))
    limits = _obj(d.get("limits"))
    caps = sorted(limits["cumulative"]) if isinstance(limits.get("cumulative"), dict) else []
    for index, envelope in enumerate(envelopes):
        env = _obj(plain(envelope))
        payload = _obj(env.get("payload"))
        expectation = _obj(payload.get("signoffExpectation"))
        slot = expectation.get("mandateSeq")
        if not is_positive_safe_integer(slot):
            malformed.append({"index": index, "reason": "mandate_seq_malformed"})
            continue
        cap_values = mandate_cap_values(d, payload)
        totals = _obj(expectation.get("totals"))
        if cap_values["invalid"] or not all(is_non_negative_safe_integer(totals.get(c)) for c in caps):
            malformed.append({"index": index, "reason": "mandate_totals_malformed"})
            continue
        record = {"slot": int(slot), "totals": totals, "values": cap_values["values"] or {}}
        by_slot.setdefault(int(slot), []).append(record)

    slots = sorted(by_slot)
    duplicate_slots = [s for s in slots if len(by_slot[s]) > 1]
    gaps: list[dict[str, Any]] = []
    unexplained_steps: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    complete_up_to = 0
    for slot in slots:
        record = by_slot[slot][0]
        previous_slot = previous["slot"] if previous is not None else 0
        if slot == complete_up_to + 1:
            complete_up_to = slot

        def previous_total(cap: str, prev: dict[str, Any] | None = previous) -> Any:
            return prev["totals"][cap] if prev is not None else 0

        if slot > previous_slot + 1:
            unexplained = {
                cap: record["totals"][cap] - previous_total(cap) - record["values"][cap] for cap in caps
            }
            gaps.append({"from": previous_slot + 1, "to": slot - 1, "unexplained": unexplained})
        else:
            for cap in caps:
                expected = previous_total(cap) + record["values"][cap]
                if record["totals"][cap] != expected:
                    unexplained_steps.append(
                        {"slot": slot, "cap": cap, "expected": expected, "actual": record["totals"][cap]}
                    )
        previous = record

    complete: bool | None = None
    beyond_event: list[int] = []
    event = plain(last_event)
    if isinstance(event, dict) and is_non_negative_safe_integer(event.get("used")):
        used = int(event["used"])
        last = None if used == 0 else (by_slot[used][0] if used in by_slot else None)
        event_totals = event.get("totals") if isinstance(event.get("totals"), dict) else None
        totals_match = used == 0 or (
            last is not None
            and all(event_totals is not None and event_totals.get(cap) == last["totals"][cap] for cap in caps)
        )
        beyond_event = [s for s in slots if s > used]
        complete = complete_up_to >= used and totals_match and len(beyond_event) == 0
    return {
        "duplicateSlots": duplicate_slots,
        "gaps": gaps,
        "unexplainedSteps": unexplained_steps,
        "malformed": malformed,
        "completeUpTo": complete_up_to,
        "beyondEvent": beyond_event,
        "complete": complete,
    }


__all__ = (
    "check_mandate_consumption",
    "check_mandate_limits",
    "decider_in_mandate",
    "evaluate_mandate_confirm",
    "evaluate_mandate_scope",
    "mandate_cap_values",
    "recorded_models",
)
