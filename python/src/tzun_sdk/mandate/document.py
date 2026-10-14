"""The mandate document ``tzun-mandate/1`` (Record §9.7).

Its grammar, its digest and the restriction applied at signing. The twin of
``packages/engine/src/mandate/document.ts``.

The document grammar: nested objects; arrays that are sets of printable ASCII
strings, already sorted by byte with no duplicate (a reader never re-sorts);
the literals ``true``, ``false`` and ``null``; non-negative safe integers;
printable-ASCII strings; every key required. ``mandateDigest =
hex(SHA-256(C(document)))``, over at most 16 KiB of canonical bytes.
"""

from __future__ import annotations

import re
from typing import Any

from tzun_sdk._generated.canonical import V1_HASHED_FIELDS
from tzun_sdk._instant import is_mandate_instant, js_date_parse_ms
from tzun_sdk._record_rules import (
    PRINTABLE_ASCII_RE,
    canonical_value,
    has_exact_keys,
    is_bare_digest,
    is_non_negative_safe_integer,
    is_prefixed_digest,
    is_strictly_increasing,
    plain,
    sha256_hex,
    utf8_length,
)
from tzun_sdk.decider import ACCT_VALUE_RE, identifier_scheme, is_known_scheme_identifier
from tzun_sdk.mandate.predicate import parse_json_pointer, predicate_violation

#: The version tag of a mandate document.
MANDATE_DOCUMENT_VERSION = "tzun-mandate/1"
#: The most canonical bytes a mandate document has (a grammar maximum).
MANDATE_DOCUMENT_MAX_BYTES = 16 * 1024
#: The most caps in ``limits.cumulative`` (and in an expectation's ``totals``).
MANDATE_MAX_CAPS = 16
#: The most predicates in a document, ``scope.predicates`` and ``confirm`` together.
MANDATE_MAX_PREDICATES = 64
#: A cap or predicate name.
MANDATE_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,64}", re.ASCII)

#: The schema versions this release knows, with their hashed field sets.
SCHEMA_VERSIONS: dict[str, tuple[str, ...]] = {"v1.0": tuple(V1_HASHED_FIELDS)}

_DOCUMENT_KEYS = (
    "v", "mandateId", "principal", "agents", "schemaVersion", "scope", "confirm", "validity", "limits",
    "delegation", "review", "policyDigest", "predecessor", "parent",
)
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.ASCII)
_AGENT_SCHEMES = ("spiffe", "jkt", "desc", "cmt")
#: The members a mandate's scope restricts, which must be hashed in the document's schema version.
_SCOPED_MEMBERS = ("aiSystemId", "action", "contributions")


def _violation(code: str, field: str, message: str) -> dict[str, str]:
    return {"code": code, "field": field, "message": message}


def _printable(value: Any) -> bool:
    return isinstance(value, str) and PRINTABLE_ASCII_RE.fullmatch(value) is not None


def document_grammar_failure(value: Any, path: str = "") -> str | None:
    """The path of the first value outside the document grammar, or ``None``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        return None if _printable(value) else (path or ".")
    if isinstance(value, (int, float)):
        return None if is_non_negative_safe_integer(value) else (path or ".")
    if isinstance(value, list):
        if not all(_printable(v) for v in value):
            return path or "."
        return None if is_strictly_increasing(value) else (path or ".")
    if isinstance(value, dict):
        for k, v in value.items():
            if not _printable(k):
                return f"{path}.{k}"
            failure = document_grammar_failure(v, f"{path}.{k}")
            if failure is not None:
                return failure
        return None
    return path or "."


def mandate_digest(document: Any) -> str | None:
    """``hex(SHA-256(C(document)))``, or ``None`` when it cannot be serialized. Never raises."""
    try:
        return sha256_hex(canonical_value(plain(document)))
    except Exception:
        return None


def document_path_members(document: dict[str, Any]) -> list[str]:
    """The first reference token of every predicate path and cap path of a document."""
    out: list[str] = []

    def add(path: Any) -> None:
        tokens = parse_json_pointer(path)
        if tokens is not None:
            out.append(tokens[0])

    scope = document.get("scope") if isinstance(document.get("scope"), dict) else {}
    for group in (scope.get("predicates"), document.get("confirm")):
        if isinstance(group, dict):
            for p in group.values():
                if isinstance(p, dict):
                    add(p.get("path"))
    limits = document.get("limits") if isinstance(document.get("limits"), dict) else {}
    if isinstance(limits.get("cumulative"), dict):
        for c in limits["cumulative"].values():
            if isinstance(c, dict):
                add(c.get("path"))
    return out


def mandate_restriction_holds(document: dict[str, Any], schema_version: Any) -> bool:
    """Whether the document's paths read only members hashed in ``schema_version`` (Record §9.7)."""
    hashed = SCHEMA_VERSIONS.get(schema_version) if isinstance(schema_version, str) else None
    if hashed is None:
        return False
    if not all(m in hashed for m in _SCOPED_MEMBERS):
        return False
    return all(m in hashed for m in document_path_members(document))


def _check_predicate_group(group: Any, field: str) -> dict[str, str] | None:
    if group is None:
        return None
    if not isinstance(group, dict) or len(group) == 0:
        return _violation("invalid_document", field, f"{field} must be null or an object of named predicates")
    for name, predicate in group.items():
        if MANDATE_NAME_RE.fullmatch(name) is None:
            return _violation("invalid_predicate", f"{field}.{name}", f"{field}: a predicate name is [A-Za-z0-9._-]{{1,64}}")
        reason = predicate_violation(predicate)
        if reason is not None:
            return _violation("invalid_predicate", f"{field}.{name}", f"{field}.{name}: {reason}")
    return None


def _nullable_string_set(value: Any, item: Any) -> bool:
    return value is None or (isinstance(value, list) and all(isinstance(v, str) and item(v) for v in value))


def mandate_document_violation(document: Any, *, prepare: bool = True) -> dict[str, str] | None:
    """Why ``document`` is not a mandate document, first failure first, or ``None``. Never raises.

    With ``prepare`` (the default), also the rules ``prepare`` applies before a
    principal signs: a registered version that passes the restriction,
    ``delegation`` ``{allowed: false, maxDepth: 0}``, ``parent`` ``None``, and
    a validity window that does not end before it begins.
    """
    d = plain(document)
    if not isinstance(d, dict):
        return _violation("invalid_document", "document", "a mandate document must be an object")
    if not has_exact_keys(d, _DOCUMENT_KEYS):
        return _violation(
            "invalid_document", "document", "a mandate document has exactly the keys " + ", ".join(_DOCUMENT_KEYS)
        )
    grammar = document_grammar_failure(d)
    if grammar is not None:
        return _violation(
            "invalid_document",
            f"document{grammar}",
            "a mandate document holds only objects, sorted sets of printable-ASCII strings, booleans, null, "
            "non-negative safe integers and printable-ASCII strings",
        )
    try:
        canonical = canonical_value(d)
    except Exception:
        return _violation("invalid_document", "document", "a mandate document must be canonically serializable")
    if utf8_length(canonical) > MANDATE_DOCUMENT_MAX_BYTES:
        return _violation(
            "document_too_large",
            "document",
            f"a mandate document's canonical bytes are at most {MANDATE_DOCUMENT_MAX_BYTES}",
        )
    if d["v"] != MANDATE_DOCUMENT_VERSION:
        return _violation("invalid_document", "document.v", f"v must be {MANDATE_DOCUMENT_VERSION}")
    if not isinstance(d["mandateId"], str) or _UUID_RE.fullmatch(d["mandateId"]) is None:
        return _violation("invalid_document", "document.mandateId", "mandateId must be a lowercase UUID")
    principal = d["principal"]
    if not isinstance(principal, dict) or not has_exact_keys(principal, ("signer", "credential")):
        return _violation("invalid_principal", "document.principal", "principal has exactly the members signer and credential")
    if not isinstance(principal["signer"], str) or ACCT_VALUE_RE.fullmatch(principal["signer"]) is None:
        return _violation(
            "invalid_principal",
            "document.principal.signer",
            "principal.signer must be an opaque account id [A-Za-z0-9._-]{1,128}, never an email address or a name",
        )
    if principal["credential"] is not None and not is_bare_digest(principal["credential"]):
        return _violation(
            "invalid_principal", "document.principal.credential", "principal.credential must be null or 64 lowercase hex"
        )
    agents = d["agents"]
    if not isinstance(agents, list) or not all(
        isinstance(a, str) and is_known_scheme_identifier(a) and identifier_scheme(a) in _AGENT_SCHEMES
        for a in agents
    ):
        return _violation(
            "invalid_document", "document.agents", "agents must be a set of agent identifiers (spiffe, jkt, desc or cmt)"
        )
    if not isinstance(d["schemaVersion"], str) or d["schemaVersion"] == "":
        return _violation("invalid_document", "document.schemaVersion", "schemaVersion must name a schema version")
    scope = d["scope"]
    if not isinstance(scope, dict) or not has_exact_keys(scope, ("aiSystemIds", "actions", "models", "predicates")):
        return _violation(
            "invalid_document", "document.scope", "scope has exactly the members aiSystemIds, actions, models and predicates"
        )
    if not _nullable_string_set(scope["aiSystemIds"], lambda v: len(v) > 0):
        return _violation("invalid_document", "document.scope.aiSystemIds", "scope.aiSystemIds must be null or a set of strings")
    if not _nullable_string_set(scope["actions"], lambda v: len(v) > 0):
        return _violation("invalid_document", "document.scope.actions", "scope.actions must be null or a set of strings")
    if not _nullable_string_set(scope["models"], is_prefixed_digest):
        return _violation(
            "invalid_document", "document.scope.models", "scope.models must be null or a set of model descriptor digests"
        )
    scope_predicates = _check_predicate_group(scope["predicates"], "document.scope.predicates")
    if scope_predicates:
        return scope_predicates
    confirm = _check_predicate_group(d["confirm"], "document.confirm")
    if confirm:
        return confirm
    predicate_count = (len(scope["predicates"]) if isinstance(scope["predicates"], dict) else 0) + (
        len(d["confirm"]) if isinstance(d["confirm"], dict) else 0
    )
    if predicate_count > MANDATE_MAX_PREDICATES:
        return _violation(
            "invalid_document", "document", f"a mandate document holds at most {MANDATE_MAX_PREDICATES} predicates"
        )
    validity = d["validity"]
    if (
        not isinstance(validity, dict)
        or not has_exact_keys(validity, ("notBefore", "notAfter"))
        or (validity["notBefore"] is not None and not is_mandate_instant(validity["notBefore"]))
        or (validity["notAfter"] is not None and not is_mandate_instant(validity["notAfter"]))
    ):
        return _violation(
            "invalid_document",
            "document.validity",
            "validity has exactly notBefore and notAfter, each null or an ISO 8601 UTC instant with milliseconds",
        )
    limits = d["limits"]
    if not isinstance(limits, dict) or not has_exact_keys(limits, ("maxRecords", "cumulative")):
        return _violation("invalid_document", "document.limits", "limits has exactly the members maxRecords and cumulative")
    if limits["maxRecords"] is not None and not (
        is_non_negative_safe_integer(limits["maxRecords"]) and limits["maxRecords"] >= 1
    ):
        return _violation(
            "invalid_document", "document.limits.maxRecords", "limits.maxRecords must be null or an integer of at least 1"
        )
    cumulative = limits["cumulative"]
    if cumulative is not None:
        if not isinstance(cumulative, dict):
            return _violation(
                "invalid_cap", "document.limits.cumulative", "limits.cumulative must be null or an object of named caps"
            )
        if len(cumulative) == 0:
            return _violation(
                "empty_cumulative", "document.limits.cumulative", "limits.cumulative with no cap must be written null"
            )
        if len(cumulative) > MANDATE_MAX_CAPS:
            return _violation(
                "invalid_cap", "document.limits.cumulative", f"limits.cumulative holds at most {MANDATE_MAX_CAPS} caps"
            )
        for name, cap in cumulative.items():
            field = f"document.limits.cumulative.{name}"
            if MANDATE_NAME_RE.fullmatch(name) is None:
                return _violation("invalid_cap", field, "a cap name is [A-Za-z0-9._-]{1,64}")
            if (
                not isinstance(cap, dict)
                or not has_exact_keys(cap, ("path", "max"))
                or parse_json_pointer(cap["path"]) is None
                or not is_non_negative_safe_integer(cap["max"])
            ):
                return _violation("invalid_cap", field, "a cap has exactly a JSON Pointer path and a non-negative integer max")
    delegation = d["delegation"]
    if (
        not isinstance(delegation, dict)
        or not has_exact_keys(delegation, ("allowed", "maxDepth", "attenuation"))
        or not isinstance(delegation["allowed"], bool)
        or not is_non_negative_safe_integer(delegation["maxDepth"])
        or delegation["attenuation"] != "subset"
    ):
        return _violation(
            "invalid_document",
            "document.delegation",
            "delegation has exactly allowed (boolean), maxDepth (integer) and attenuation (subset)",
        )
    review = d["review"]
    if review is not None and (
        not isinstance(review, dict)
        or not has_exact_keys(review, ("maxAgeMs",))
        or not is_non_negative_safe_integer(review["maxAgeMs"])
    ):
        return _violation("invalid_document", "document.review", "review must be null or have exactly an integer maxAgeMs")
    for key in ("policyDigest", "predecessor", "parent"):
        if d[key] is not None and not is_bare_digest(d[key]):
            return _violation("invalid_document", f"document.{key}", f"{key} must be null or 64 lowercase hex")
    if prepare:
        if d["schemaVersion"] not in SCHEMA_VERSIONS or not mandate_restriction_holds(d, d["schemaVersion"]):
            return _violation(
                "restriction_failed",
                "document.schemaVersion",
                "the document must name a registered schema version (v1.0) that hashes aiSystemId, action and "
                "contributions, and every predicate and cap path must begin with a member that version hashes",
            )
        if delegation["allowed"] is not False or delegation["maxDepth"] != 0:
            return _violation(
                "invalid_document",
                "document.delegation",
                "this version issues no sub-mandates: delegation.allowed is false and maxDepth 0",
            )
        if d["parent"] is not None:
            return _violation("invalid_document", "document.parent", "this version issues no sub-mandates: parent is null")
        not_before, not_after = validity["notBefore"], validity["notAfter"]
        if isinstance(not_before, str) and isinstance(not_after, str):
            nb, na = js_date_parse_ms(not_before), js_date_parse_ms(not_after)
            if nb is not None and na is not None and na < nb:
                return _violation(
                    "invalid_document", "document.validity", "the validity window must not end before it begins"
                )
    return None


__all__ = (
    "MANDATE_DOCUMENT_MAX_BYTES",
    "MANDATE_DOCUMENT_VERSION",
    "MANDATE_MAX_CAPS",
    "MANDATE_MAX_PREDICATES",
    "MANDATE_NAME_RE",
    "SCHEMA_VERSIONS",
    "document_grammar_failure",
    "document_path_members",
    "is_mandate_instant",
    "mandate_digest",
    "mandate_document_violation",
    "mandate_restriction_holds",
)
