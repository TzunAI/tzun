"""Mandate issuance records (Record §9.6; the ``mandate.issuance`` row, Verification §4.12) and mandate event bodies.

The twin of ``packages/engine/src/mandate/issuance.ts``.
"""

from __future__ import annotations

from typing import Any

from tzun_sdk._record_rules import (
    canonical_value,
    has_exact_keys,
    is_bare_digest,
    is_non_negative_safe_integer,
    plain,
    sha256_hex,
)
from tzun_sdk.attestation.webauthn import assertion_presents_challenge
from tzun_sdk.mandate.assertion_digest import assertion_digest
from tzun_sdk.mandate.document import (
    MANDATE_MAX_CAPS,
    MANDATE_NAME_RE,
    mandate_digest,
    mandate_document_violation,
)
from tzun_sdk.mandate.statement import mandate_statement_challenge, mandate_statement_digest

#: The ``aiSystemId`` of mandate issuance and revocation records.
MANDATE_AI_SYSTEM_ID = "tzun:mandate"
#: The action of an issuance record.
MANDATE_ISSUE_ACTION = "issue-mandate"
#: The action of a revocation record.
MANDATE_REVOKE_ACTION = "revoke-mandate"
#: The version tag of a mandate event body.
MANDATE_EVENT_VERSION = "tzun-mandate-event/1"

_EVENT_KEYS = ("v", "event", "mandateDigest", "record", "successor", "used", "totals")
_EVENTS = ("issued", "revoked", "superseded", "expired")


def check_mandate_issuance(envelope: Any) -> dict[str, Any] | None:
    """The ``mandate.issuance`` row, or ``None`` when it is not reported. Never raises."""
    env = plain(envelope)
    env = env if isinstance(env, dict) else {}
    payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
    nr = env.get("nonRepudiation") if isinstance(env.get("nonRepudiation"), dict) else {}
    block = nr.get("mandateIssuance")
    has_block = block is not None
    is_issuance = payload.get("aiSystemId") == MANDATE_AI_SYSTEM_ID and payload.get("action") == MANDATE_ISSUE_ACTION
    if not has_block and not is_issuance:
        return None
    if has_block and not is_issuance:
        return {"outcome": "checked-wrong", "valid": False, "reason": "issuance_not_expected"}
    if not has_block:
        return {"outcome": "checked-wrong", "valid": False, "reason": "issuance_material_stripped"}

    def mismatch(link: str) -> dict[str, Any]:
        return {"outcome": "checked-wrong", "valid": False, "reason": "issuance_material_mismatch", "link": link}

    if not isinstance(block, dict):
        return mismatch("statement")
    ai_output = payload.get("aiOutput") if isinstance(payload.get("aiOutput"), dict) else {}
    statement = block.get("statement") if isinstance(block.get("statement"), dict) else None
    document = block.get("document")
    if statement is None or not isinstance(document, dict) or mandate_document_violation(document, prepare=False) is not None:
        return mismatch("document")
    doc_digest = mandate_digest(document)
    if doc_digest is None or doc_digest != statement.get("mandateDigest") or doc_digest != ai_output.get("mandateDigest"):
        return mismatch("document")
    statement_digest = mandate_statement_digest(statement)
    if statement_digest is None or statement_digest != ai_output.get("statementDigest"):
        return mismatch("statement")
    signer = document["principal"]["signer"]
    if statement.get("signer") != signer:
        return mismatch("signer")
    assertion = block.get("assertion")
    if not isinstance(assertion, dict) or not assertion_presents_challenge(
        assertion, mandate_statement_challenge(statement_digest)
    ):
        return mismatch("challenge")
    if assertion_digest(assertion) != ai_output.get("assertionDigest"):
        return mismatch("assertion")
    decider = payload.get("decider") if isinstance(payload.get("decider"), dict) else None
    if decider is None or decider.get("kind") != "human" or decider.get("id") != f"acct:{signer}":
        return mismatch("decider")
    return {"outcome": "checked-correct", "valid": True}


def mandate_event_body_violation(body: Any) -> str | None:
    """Why ``body`` is not a mandate event body ``tzun-mandate-event/1``, or ``None``."""
    body = plain(body)
    if not isinstance(body, dict) or not has_exact_keys(body, _EVENT_KEYS):
        return "an event body has exactly the keys " + ", ".join(_EVENT_KEYS)
    if body["v"] != MANDATE_EVENT_VERSION:
        return f"v must be {MANDATE_EVENT_VERSION}"
    if not isinstance(body["event"], str) or body["event"] not in _EVENTS:
        return "event must be one of " + ", ".join(_EVENTS)
    if not is_bare_digest(body["mandateDigest"]):
        return "mandateDigest must be 64 lowercase hex"
    if not is_bare_digest(body["record"]):
        return "record must be 64 lowercase hex"
    if body["successor"] is not None and not is_bare_digest(body["successor"]):
        return "successor must be null or 64 lowercase hex"
    if body["used"] is not None and not is_non_negative_safe_integer(body["used"]):
        return "used must be null or a non-negative integer"
    totals = body["totals"]
    if totals is not None:
        if not isinstance(totals, dict):
            return "totals must be null or an object of caps"
        if not 1 <= len(totals) <= MANDATE_MAX_CAPS:
            return f"totals holds 1 to {MANDATE_MAX_CAPS} caps"
        if not all(
            MANDATE_NAME_RE.fullmatch(c) is not None and is_non_negative_safe_integer(totals[c]) for c in totals
        ):
            return "each total is a non-negative integer under a cap name"
    return None


def mandate_event_body_digest(body: Any) -> str | None:
    """``hex(SHA-256(C(body)))`` of a well-formed event body, or ``None``."""
    if mandate_event_body_violation(body) is not None:
        return None
    return sha256_hex(canonical_value(plain(body)))


def build_mandate_event_body(
    *,
    event: str,
    mandate_digest: str,
    record: str,
    successor: str | None = None,
    used: int | None = None,
    totals: dict[str, int] | None = None,
) -> dict[str, Any]:
    """A mandate event body, checked. Raises ``ValueError`` when the parts do not make one."""
    body = {
        "v": MANDATE_EVENT_VERSION,
        "event": event,
        "mandateDigest": mandate_digest,
        "record": record,
        "successor": successor,
        "used": used,
        "totals": totals,
    }
    reason = mandate_event_body_violation(body)
    if reason is not None:
        raise ValueError(f"Invalid mandate event body: {reason}")
    if (event == "superseded") != (successor is not None):
        raise ValueError("Invalid mandate event body: successor is set exactly on a superseded event")
    if (event == "issued") != (used is None):
        raise ValueError("Invalid mandate event body: used is null exactly on an issued event")
    return body


__all__ = (
    "MANDATE_AI_SYSTEM_ID",
    "MANDATE_EVENT_VERSION",
    "MANDATE_ISSUE_ACTION",
    "MANDATE_REVOKE_ACTION",
    "build_mandate_event_body",
    "check_mandate_issuance",
    "mandate_event_body_digest",
    "mandate_event_body_violation",
)
