"""The mandate form of the signature expectation (Record §9.1) and its keyless checks (Verification §5 rows 17-24).

``{"mandateAssertion": <64 hex>, "mandateSeq": <safe integer ≥ 1>,
"totals": {<cap>: <safe integer ≥ 0>, …} | null, "confirm": true | false}``

The twin of ``packages/engine/src/mandate/expectation.ts``.
"""

from __future__ import annotations

from typing import Any

from tzun_sdk._record_rules import (
    canonical_value,
    has_exact_keys,
    is_bare_digest,
    is_non_negative_safe_integer,
    is_positive_safe_integer,
    plain,
    utf8_length,
)
from tzun_sdk.attestation.webauthn import assertion_presents_challenge
from tzun_sdk.mandate.assertion_digest import assertion_digest
from tzun_sdk.mandate.document import MANDATE_MAX_CAPS, MANDATE_NAME_RE, mandate_digest
from tzun_sdk.mandate.statement import (
    mandate_confirmation_challenge,
    mandate_statement_challenge,
    mandate_statement_digest,
)

#: The members of the mandate form.
MANDATE_EXPECTATION_KEYS = ("confirm", "mandateAssertion", "mandateSeq", "totals")

#: The most canonical bytes a ``mandate`` or ``mandateIssuance`` block has (a writer limit).
MANDATE_BLOCK_MAX_BYTES = 48 * 1024


def has_mandate_expectation_members(value: dict[str, Any]) -> bool:
    """Whether ``value`` has exactly the members of the mandate form (whatever their values)."""
    return has_exact_keys(value, MANDATE_EXPECTATION_KEYS)


def mandate_expectation_member_violation(value: dict[str, Any]) -> str | None:
    """Why an object with exactly the mandate form's members is not one, or ``None``."""
    if not is_bare_digest(value.get("mandateAssertion")):
        return "invalid_mandate_assertion"
    if not is_positive_safe_integer(value.get("mandateSeq")):
        return "invalid_mandate_seq"
    totals = value.get("totals")
    if totals is not None:
        if not isinstance(totals, dict):
            return "invalid_totals"
        if not 1 <= len(totals) <= MANDATE_MAX_CAPS:
            return "invalid_totals"
        if not all(
            MANDATE_NAME_RE.fullmatch(cap) is not None and is_non_negative_safe_integer(totals[cap])
            for cap in totals
        ):
            return "invalid_totals"
    if not isinstance(value.get("confirm"), bool):
        return "invalid_confirm"
    return None


def mandate_block_violation(block: Any, field: str = "nonRepudiation.mandate") -> dict[str, str] | None:
    """Why a ``mandate`` or ``mandateIssuance`` block is refused at capture (over 48 KiB), or ``None``."""
    try:
        size = utf8_length(canonical_value(plain(block)))
    except Exception:
        size = MANDATE_BLOCK_MAX_BYTES + 1
    if size > MANDATE_BLOCK_MAX_BYTES:
        return {
            "code": "mandate_block_too_large",
            "field": field,
            "message": f"{field}'s canonical bytes exceed {MANDATE_BLOCK_MAX_BYTES}, or it cannot be canonically "
            "serialized",
        }
    return None


def check_mandate_expectation_material(
    expectation: dict[str, Any],
    non_repudiation: dict[str, Any],
    digest: Any,
    is_session_signoff: bool,
) -> dict[str, Any]:
    """The mandate-form rows of the signature-expectation check (Verification §5 rows 17-24). Never raises."""
    if is_session_signoff:
        return {"valid": False, "reason": "session_signoff_not_expected"}
    block = non_repudiation.get("mandate")
    if block is None:
        return {"valid": False, "reason": "mandate_stripped"}
    if not isinstance(block, dict):
        return {"valid": False, "reason": "malformed_mandate_statement"}
    statement_digest = mandate_statement_digest(block.get("statement"))
    if statement_digest is None:
        return {"valid": False, "reason": "malformed_mandate_statement"}
    assertion = block.get("assertion")
    if assertion_digest(assertion) != expectation.get("mandateAssertion"):
        return {"valid": False, "reason": "mandate_assertion_mismatch"}
    if not isinstance(assertion, dict) or not assertion_presents_challenge(
        assertion, mandate_statement_challenge(statement_digest)
    ):
        return {"valid": False, "reason": "mandate_unbound"}
    document = block.get("document")
    if document is not None:
        statement = block["statement"]
        if mandate_digest(document) != statement.get("mandateDigest"):
            return {"valid": False, "reason": "mandate_document_mismatch"}
        principal = document.get("principal") if isinstance(document, dict) else None
        if not isinstance(principal, dict) or principal.get("signer") != statement.get("signer"):
            return {"valid": False, "reason": "mandate_document_mismatch"}
    if expectation.get("confirm") is True:
        confirmation = non_repudiation.get("confirmation")
        confirmed = (
            isinstance(confirmation, dict)
            and isinstance(digest, str)
            and digest != ""
            and assertion_presents_challenge(confirmation, mandate_confirmation_challenge(digest))
        )
        if not confirmed:
            return {"valid": None, "reason": "confirmation_missing"}
    return {"valid": True}


__all__ = (
    "MANDATE_BLOCK_MAX_BYTES",
    "MANDATE_EXPECTATION_KEYS",
    "check_mandate_expectation_material",
    "has_mandate_expectation_members",
    "mandate_block_violation",
    "mandate_expectation_member_violation",
)
