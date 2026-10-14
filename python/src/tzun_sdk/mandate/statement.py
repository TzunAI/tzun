"""The mandate statement ``tzun-signoff-mandate/1`` (Record §9.6) and the confirmation challenge (Record §9.4).

A flat statement in the sign-off value domain with exactly eight keys. It
carries no printed name: ``signer`` is the principal's opaque relying-party
user id. The twin of ``packages/engine/src/mandate/statement.ts``.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from tzun_sdk._record_rules import has_exact_keys, is_bare_digest, plain
from tzun_sdk.decider import ACCT_VALUE_RE, is_freshness_reference

MANDATE_STATEMENT_VERSION = "tzun-signoff-mandate/1"

_STATEMENT_KEYS = ("v", "mode", "mandateDigest", "signer", "signerKind", "meaning", "policyDigest", "notBefore")

#: The domain separator of a confirmation challenge.
_CONFIRM_CHALLENGE_DOMAIN = "tzun-confirm-v1"


def mandate_statement_violation(statement: Any) -> str | None:
    """Why ``statement`` is not a well-formed mandate statement, or ``None``.

    A statement carrying ``signerName`` is malformed.
    """
    s = plain(statement)
    if not isinstance(s, dict):
        return "a mandate statement must be an object"
    if not has_exact_keys(s, _STATEMENT_KEYS):
        return "a mandate statement has exactly the keys " + ", ".join(_STATEMENT_KEYS)
    if s["v"] != MANDATE_STATEMENT_VERSION:
        return f"v must be {MANDATE_STATEMENT_VERSION}"
    if s["mode"] != "mandate":
        return "mode must be mandate"
    if not is_bare_digest(s["mandateDigest"]):
        return "mandateDigest must be 64 lowercase hex"
    if not isinstance(s["signer"], str) or ACCT_VALUE_RE.fullmatch(s["signer"]) is None:
        return "signer must be [A-Za-z0-9._-]{1,128}"
    if s["signerKind"] != "human":
        return "signerKind must be human"
    if s["meaning"] != "responsibility":
        return "meaning must be responsibility"
    if s["policyDigest"] != "none" and not is_bare_digest(s["policyDigest"]):
        return "policyDigest must be 64 lowercase hex or none"
    if s["notBefore"] != "none" and not is_freshness_reference(s["notBefore"]):
        return "notBefore must be a finalized-block reference or none"
    return None


def mandate_statement_digest(statement: Any) -> str | None:
    """The statement digest of a well-formed mandate statement, or ``None``. Never raises."""
    from tzun_sdk.signoff_expectation import signoff_statement_digest

    if mandate_statement_violation(statement) is not None:
        return None
    return signoff_statement_digest(plain(statement))


def mandate_statement_challenge(statement_digest: str) -> str:
    """The challenge a principal's ceremony over the statement presents."""
    from tzun_sdk.signoff_expectation import signoff_statement_challenge

    return signoff_statement_challenge(statement_digest)


def build_mandate_statement(
    *, mandate_digest: str, signer: str, policy_digest: str | None, not_before: str | None
) -> dict[str, str]:
    """The statement ``prepare`` forms. Raises ``ValueError`` when the parts do not make one."""
    statement = {
        "v": MANDATE_STATEMENT_VERSION,
        "mode": "mandate",
        "mandateDigest": mandate_digest,
        "signer": signer,
        "signerKind": "human",
        "meaning": "responsibility",
        "policyDigest": policy_digest if policy_digest is not None else "none",
        "notBefore": not_before if not_before is not None else "none",
    }
    reason = mandate_statement_violation(statement)
    if reason is not None:
        raise ValueError(f"Invalid mandate statement: {reason}")
    return statement


def mandate_confirmation_challenge(digest: str) -> str:
    """``B64URL(SHA-256("tzun-confirm-v1" ‖ digest))``, ``digest`` the record's canonical digest."""
    raw = hashlib.sha256((_CONFIRM_CHALLENGE_DOMAIN + digest).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


__all__ = (
    "MANDATE_STATEMENT_VERSION",
    "build_mandate_statement",
    "mandate_confirmation_challenge",
    "mandate_statement_challenge",
    "mandate_statement_digest",
    "mandate_statement_violation",
)
