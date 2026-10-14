"""The mandate lifecycle as pure functions (Record §9.6).

What a capture under a mandate claims, the issuance and revocation records
the mandate API captures, and the refusals of revocation, succession and
confirmation. The twin of ``packages/engine/src/mandate/lifecycle.ts``: the
two SDKs claim, issue and refuse alike; the storage and the ceremony
verification are each SDK's own.
"""

from __future__ import annotations

from typing import Any

from tzun_sdk._instant import is_mandate_instant, js_date_parse_ms
from tzun_sdk._record_rules import is_non_negative_safe_integer, is_safe_integer, plain
from tzun_sdk.links import _link_sort_key, links_grammar_violation
from tzun_sdk.mandate.assertion_digest import assertion_digest
from tzun_sdk.mandate.document import mandate_digest
from tzun_sdk.mandate.issuance import (
    MANDATE_AI_SYSTEM_ID,
    MANDATE_ISSUE_ACTION,
    MANDATE_REVOKE_ACTION,
)
from tzun_sdk.mandate.scope import (
    check_mandate_limits,
    decider_in_mandate,
    evaluate_mandate_confirm,
    evaluate_mandate_scope,
    mandate_cap_values,
)
from tzun_sdk.mandate.statement import mandate_statement_digest

_MISSING = object()


def _js_number(value: Any) -> float:
    """JavaScript's ``Number(value)`` over a JSON value (``_MISSING`` for ``undefined``)."""
    if value is _MISSING:
        return float("nan")
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if text == "":
            return 0.0
        try:
            return float(text) if text.lower() not in ("nan", "inf", "-inf", "+inf", "infinity", "-infinity") else (
                float(text) if text in ("Infinity", "-Infinity", "+Infinity") else float("nan")
            )
        except ValueError:
            return float("nan")
    if isinstance(value, list):
        if not value:
            return 0.0
        return _js_number(value[0]) if len(value) == 1 and not isinstance(value[0], (list, dict)) else float("nan")
    return float("nan")


def _js_greater(a: float, b: Any) -> bool:
    """``a > b`` as JavaScript compares a number with a JSON value."""
    right = _js_number(b)
    return right == right and a > right


def _refused(code: str, field: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "code": code, "field": field, "message": message, **extra}


def _links_with_mandate(links: Any, issuance: Any) -> list[Any]:
    """The payload's links with the ``mandate`` link to ``issuance`` added, sorted (kept once if present)."""
    own: list[Any] = [] if links is None else (list(links) if isinstance(links, list) else [links])
    t = plain(issuance) if isinstance(plain(issuance), dict) else {}
    locator = t.get("locator")
    mandate_link = {
        "rel": "mandate",
        "target": {
            "digest": t.get("digest"),
            "evidenceId": t.get("evidenceId"),
            "locator": dict(locator) if isinstance(locator, dict) else None,
        },
        "attrs": None,
    }
    if links_grammar_violation(own if own else None) is not None or links_grammar_violation([mandate_link]) is not None:
        return [*own, mandate_link]
    present = any(link["rel"] == "mandate" and link["target"]["digest"] == t.get("digest") for link in own)
    out = list(own) if present else [*own, mandate_link]
    return sorted(out, key=_link_sort_key)


def plan_mandate_claim(
    *,
    document: Any,
    mandate: dict[str, Any],
    payload: dict[str, Any],
    assertion_digest: str,
    issuance: dict[str, Any],
) -> dict[str, Any]:
    """What a capture under a mandate claims (Record §9.6, capture under a mandate), or why it is refused. Never raises.

    ``mandate`` is ``{state, used, totals}``; ``issuance`` the ``mandate``
    link's target. Returns ``{ok: True, expectation, links, expectUsed, caps,
    confirmHolding}`` or ``{ok: False, code, field, message, ...}``.
    """
    d = plain(document) if isinstance(plain(document), dict) else {}
    links = _links_with_mandate(payload.get("links"), issuance)
    p = {**payload, "links": links}
    decider = p.get("decider") if isinstance(p.get("decider"), dict) else None
    if decider is None or decider.get("kind") != "agent-mandated":
        return _refused(
            "agent_not_in_mandate", "decider.kind", "a decision under a mandate has the decider kind agent-mandated"
        )
    if not decider_in_mandate(decider, d.get("agents")):
        return _refused("agent_not_in_mandate", "decider", "the decider is not one of the mandate's agents")
    if mandate.get("state") != "open":
        return _refused("mandate_not_open", "mandate", "the mandate is not open")
    validity = d.get("validity") if isinstance(d.get("validity"), dict) else {}
    at = js_date_parse_ms(p.get("capturedAt"))
    if at is None:
        return _refused("outside_validity", "capturedAt", "the record's capturedAt is not an instant")
    not_before = js_date_parse_ms(validity.get("notBefore"))
    if not_before is not None and at < not_before:
        return _refused(
            "outside_validity", "capturedAt", "the record's capturedAt is before the mandate's validity window"
        )
    not_after = js_date_parse_ms(validity.get("notAfter"))
    if not_after is not None and at > not_after:
        return _refused(
            "outside_validity",
            "capturedAt",
            "the record's capturedAt is after the mandate's validity window",
            expired=True,
        )
    if p.get("schemaVersion") != d.get("schemaVersion"):
        return _refused(
            "schema_version_mismatch", "schemaVersion", "the record's schema version is not the mandate document's"
        )
    limits = d.get("limits") if isinstance(d.get("limits"), dict) else {}
    cumulative = limits.get("cumulative") if isinstance(limits.get("cumulative"), dict) else None
    used = mandate["used"]
    cap_values = mandate_cap_values(d, p)
    values, invalid = cap_values["values"], cap_values["invalid"]
    caps: list[dict[str, Any]] = []
    totals: dict[str, Any] | None = None
    if cumulative is not None and values is not None:
        totals = {}
        held_totals = mandate.get("totals") or {}
        for cap in sorted(cumulative):
            expect_total = held_totals.get(cap, 0)
            new_total = expect_total + values.get(cap, 0)
            totals[cap] = new_total
            caps.append({"cap": cap, "expectTotal": expect_total, "newTotal": new_total})
    confirm = evaluate_mandate_confirm(d, p)
    expectation = {
        "mandateAssertion": assertion_digest,
        "mandateSeq": used + 1,
        "totals": totals,
        "confirm": confirm["confirm"] if confirm["confirm"] is not None else True,
    }
    scope = evaluate_mandate_scope(d, {**p, "signoffExpectation": expectation})
    if scope["verdict"] == "outside":
        return _refused("outside_scope", "payload", "the record is outside the mandate's scope", findings=scope["failures"])
    if scope["verdict"] == "undeterminable":
        return _refused(
            "scope_undeterminable",
            "payload",
            "the record's scope cannot be determined",
            findings=scope["undeterminable"],
        )
    if confirm["confirm"] is None:
        return _refused(
            "confirm_undeterminable",
            "confirm",
            "no confirm predicate holds and one cannot be evaluated",
            findings=[{"constraint": "confirm", "name": name} for name in confirm["undeterminable"]],
        )
    if invalid:
        return _refused(
            "cap_value_invalid",
            f"limits.cumulative.{invalid[0]}",
            f"the value at the path of cap {invalid[0]} is not a non-negative integer",
        )
    if is_non_negative_safe_integer(limits.get("maxRecords")) and used >= limits["maxRecords"]:
        return _refused("mandate_full", "mandate", "every slot of the mandate is used")
    for c in caps:
        assert cumulative is not None
        cap_def = cumulative[c["cap"]]
        cap_max = cap_def.get("max", _MISSING) if isinstance(cap_def, dict) else _MISSING
        if not is_safe_integer(c["newTotal"]) or _js_greater(c["newTotal"], cap_max):
            return _refused(
                "cap_exceeded",
                f"limits.cumulative.{c['cap']}",
                f"the record would take cap {c['cap']} past its maximum",
            )
    check = check_mandate_limits(d, {**p, "signoffExpectation": expectation})
    if not check["valid"]:
        return _refused("cap_exceeded", "limits", "the planned slot and totals break the mandate limits")
    return {
        "ok": True,
        "expectation": expectation,
        "links": links,
        "expectUsed": used,
        "caps": caps,
        "confirmHolding": confirm["holding"],
    }


def mandate_principal_decider(document: dict[str, Any], freshness: str | None = None) -> dict[str, Any]:
    """The ``decider`` of a mandate's issuance record: the principal, ``acct:<principal.signer>``."""
    document = plain(document)
    return {
        "kind": "human",
        "id": f"acct:{document['principal']['signer']}",
        "agent": None,
        "credential": document["principal"]["credential"],
        "freshness": freshness,
    }


def mandate_issuance_input(
    *,
    document: Any,
    statement: Any,
    assertion: Any,
    reason: str,
    predecessor_issuance: dict[str, Any] | None = None,
    freshness: str | None = None,
) -> dict[str, Any]:
    """The capture input of a mandate's issuance record (Record §9.6). Raises ``ValueError`` on bad material."""
    m_digest = mandate_digest(document)
    s_digest = mandate_statement_digest(statement)
    a_digest = assertion_digest(assertion)
    if m_digest is None or s_digest is None or a_digest is None:
        raise ValueError(
            "An issuance record needs a well-formed document and statement, and an assertion with a digest."
        )
    return {
        "aiSystemId": MANDATE_AI_SYSTEM_ID,
        "aiOutput": {"assertionDigest": a_digest, "mandateDigest": m_digest, "statementDigest": s_digest},
        "action": MANDATE_ISSUE_ACTION,
        "reason": reason,
        "decider": mandate_principal_decider(plain(document), freshness),
        "contributions": None,
        "links": (
            [{"rel": "supersedes", "target": predecessor_issuance, "attrs": None}] if predecessor_issuance else None
        ),
    }


def revocation_instant_violation(claimed_revocation_instant: Any, captured_at: str) -> dict[str, str] | None:
    """Why a revocation's claimed instant is refused (Record §9.6), or ``None``."""
    claimed = js_date_parse_ms(claimed_revocation_instant)
    at = js_date_parse_ms(captured_at)
    if (
        not is_mandate_instant(claimed_revocation_instant)
        or claimed is None
        or (at is not None and claimed > at)
    ):
        return {
            "code": "invalid_revocation_instant",
            "field": "effectiveAt",
            "message": "effectiveAt must be an ISO 8601 UTC instant with milliseconds, no later than the revocation "
            "is captured",
        }
    return None


def mandate_revocation_input(
    *,
    mandate_digest_hex: str,
    statement_digest: str,
    claimed_revocation_instant: str,
    reason: str,
    revoker_user_id: str,
    issuance: dict[str, Any],
    freshness: str | None = None,
) -> dict[str, Any]:
    """The capture input of a revocation record (Record §9.6)."""
    return {
        "aiSystemId": MANDATE_AI_SYSTEM_ID,
        "aiOutput": {
            "claimedRevocationInstant": claimed_revocation_instant,
            "mandateDigest": mandate_digest_hex,
            "reason": reason,
            "statementDigest": statement_digest,
        },
        "action": MANDATE_REVOKE_ACTION,
        "reason": reason,
        "decider": {
            "kind": "human",
            "id": f"acct:{revoker_user_id}",
            "agent": None,
            "credential": None,
            "freshness": freshness,
        },
        "contributions": None,
        "links": [{"rel": "revokes", "target": issuance, "attrs": None}],
    }


def predecessor_principal_violation(document: Any, predecessor: Any) -> dict[str, str] | None:
    """Why a successor's document is refused against its predecessor's (Record §9.6), or ``None``."""
    document, predecessor = plain(document), plain(predecessor)
    if (
        document.get("predecessor") != mandate_digest(predecessor)
        or document["principal"]["signer"] != predecessor["principal"]["signer"]
    ):
        return {
            "code": "predecessor_principal_mismatch",
            "field": "document.predecessor",
            "message": "a successor names its predecessor's digest and the same principal",
        }
    return None


def mandate_confirmation_violation(envelope: Any) -> dict[str, str] | None:
    """Why a confirmation of a stored record is refused (Record §9.6), or ``None``."""
    env = plain(envelope) if isinstance(plain(envelope), dict) else {}
    payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
    expectation = payload.get("signoffExpectation") if isinstance(payload.get("signoffExpectation"), dict) else {}
    if expectation.get("confirm") is not True or "mandateAssertion" not in expectation:
        return {
            "code": "confirmation_not_owed",
            "field": "signoffExpectation.confirm",
            "message": "the record owes no confirmation",
        }
    nr = env.get("nonRepudiation") if isinstance(env.get("nonRepudiation"), dict) else {}
    if nr.get("confirmation") is not None:
        return {
            "code": "already_confirmed",
            "field": "nonRepudiation.confirmation",
            "message": "the record is already confirmed",
        }
    return None


def mandate_expired_at(not_after: str | None, instant: str) -> bool:
    """Whether a mandate whose window ends at ``not_after`` has expired at ``instant``."""
    if not_after is None:
        return False
    end, at = js_date_parse_ms(not_after), js_date_parse_ms(instant)
    return end is not None and at is not None and at > end


__all__ = (
    "mandate_confirmation_violation",
    "mandate_expired_at",
    "mandate_issuance_input",
    "mandate_principal_decider",
    "mandate_revocation_input",
    "plan_mandate_claim",
    "predecessor_principal_violation",
    "revocation_instant_violation",
)
