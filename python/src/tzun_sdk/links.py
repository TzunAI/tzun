"""The links member (Record §8): a hashed, generic, extensible list of relations to other records.

The twin of ``packages/engine/src/links.ts``: the grammar, the relation
registry with closed attribute profiles, the record-local, list-level and
target rules, the builder, link records, and the reader's ``links``,
``links[<i>]`` and ``links[<i>].edge`` rows.

``links := null | [link x1..256]``, strictly increasing by
``(rel, target.digest)`` bytewise; ``link := {rel, target: {digest,
evidenceId, locator}, attrs}``. A writer refuses an unregistered unprefixed
relation; a reader abstains on any relation it does not know. This version
proves no edge: every ``links[<i>].edge`` row abstains.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize
from tzun_sdk._record_rules import (
    compare_bytes,
    has_exact_keys,
    is_bare_digest,
    is_non_negative_safe_integer,
    is_positive_safe_integer,
    plain,
)
from tzun_sdk.decider import identifier_scheme

#: The most links a record carries (a grammar maximum).
LINKS_MAX = 256
#: The longest ``target.evidenceId``.
LINK_EVIDENCE_ID_MAX_LENGTH = 128
#: The most attributes a link carries (a grammar maximum).
LINK_ATTRS_MAX = 16
#: The longest attribute string value.
LINK_ATTR_STRING_MAX_LENGTH = 256

REGISTERED_RELATION_RE = re.compile(r"[a-z][A-Za-z0-9]{0,31}", re.ASCII)
EXTENSION_RELATION_RE = re.compile(r"x-[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.[a-z][A-Za-z0-9]{0,31}", re.ASCII)
RELATION_NAME_RE = re.compile(
    r"(?:[a-z][A-Za-z0-9]{0,31}|x-[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\.[a-z][A-Za-z0-9]{0,31})", re.ASCII
)

#: The ``aiSystemId`` of a link record (Record §8.6).
LINK_RECORD_AI_SYSTEM_ID = "tzun:link"
#: The ``action`` of a link record.
LINK_RECORD_ACTION = "link"

_MANDATE_AI_SYSTEM_ID = "tzun:mandate"
_MANDATE_ISSUE_ACTION = "issue-mandate"
_MANDATE_REVOKE_ACTION = "revoke-mandate"

_LINK_KEYS = ("rel", "target", "attrs")
_TARGET_KEYS = ("digest", "evidenceId", "locator")
_LOCATOR_KEYS = ("origin", "seq")
_INPUT_KEYS = ("rel", "target", "attrs")
_TARGET_INPUT_KEYS = ("digest", "evidenceId", "locator", "external")
_EVIDENCE_ID_RE = re.compile(r"[\x21-\x7e]{1,128}", re.ASCII)
_ATTR_STRING_RE = re.compile(r"[\x20-\x7e]{0,256}", re.ASCII)


@dataclass(frozen=True)
class LinkRelationProfile:
    """A registered relation: its name, whether it is a lineage relation, its closed attribute profile and its writer."""

    name: str
    lineage: bool
    required_attrs: tuple[str, ...]
    optional_attrs: tuple[str, ...]
    writer: str  # 'caller' | 'reserved' | 'none'


def _profile(name: str, lineage: bool, writer: str, required: tuple[str, ...] = ()) -> LinkRelationProfile:
    return LinkRelationProfile(name, lineage, required, (), writer)


#: The relation registry (Record §8.3). A registered relation's profile and rules never change (Record §8.4).
LINK_RELATIONS: dict[str, LinkRelationProfile] = {
    "derivedFrom": _profile("derivedFrom", True, "caller"),
    "reviews": _profile("reviews", True, "caller"),
    "supersedes": _profile("supersedes", True, "caller"),
    "appeals": _profile("appeals", True, "caller"),
    "ratifies": _profile("ratifies", True, "caller"),
    "implements": _profile("implements", True, "caller"),
    "delegatedBy": _profile("delegatedBy", True, "caller"),
    "closes": _profile("closes", True, "none", ("size", "statement", "treeRoot")),
    "fanoutOf": _profile("fanoutOf", True, "none", ("slot", "statement")),
    "root": _profile("root", False, "caller"),
    "mandate": _profile("mandate", False, "reserved"),
    "revokes": _profile("revokes", False, "reserved"),
    "subject": _profile("subject", False, "reserved"),
}

LINK_RELATION_NAMES: tuple[str, ...] = tuple(LINK_RELATIONS)

_NOT_IN_LINK_RECORD = ("root", "mandate", "revokes", "closes", "fanoutOf")
_AT_MOST_ONE = ("root", "closes", "fanoutOf")


def is_registered_relation(rel: Any) -> bool:
    return isinstance(rel, str) and rel in LINK_RELATIONS


def is_extension_relation(rel: Any) -> bool:
    return isinstance(rel, str) and EXTENSION_RELATION_RE.fullmatch(rel) is not None


def is_relation_name(rel: Any) -> bool:
    return isinstance(rel, str) and RELATION_NAME_RE.fullmatch(rel) is not None


def is_lineage_relation(rel: Any) -> bool:
    return is_registered_relation(rel) and LINK_RELATIONS[rel].lineage


# ── Evidence-log origins (tzun-anchor/1 §4.3) ────────────────────────────

_ORIGIN_TEXT_RE = re.compile(r"[\x21-\x2a\x2c-\x7e]+", re.ASCII)
_NAMESPACE_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", re.ASCII)
_NAMESPACE_MAX_LENGTH = 253
_NAMESPACE_LABEL_MAX_LENGTH = 63
_STORE_ID_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)
_CHAIN_SEGMENT_RE = re.compile(r"(?:[0-9a-f]{2})+", re.ASCII)


def _is_log_namespace(ns: str) -> bool:
    if len(ns) == 0 or len(ns) > _NAMESPACE_MAX_LENGTH:
        return False
    return all(
        len(label) <= _NAMESPACE_LABEL_MAX_LENGTH and _NAMESPACE_LABEL_RE.fullmatch(label) is not None
        for label in ns.split(".")
    )


def _is_chain_segment(segment: str) -> bool:
    if _CHAIN_SEGMENT_RE.fullmatch(segment) is None:
        return False
    try:
        chain_id = bytes.fromhex(segment).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return False
    return "\x00" not in chain_id and chain_id.encode("utf-8").hex() == segment


def is_evidence_log_origin(origin: Any) -> bool:
    """Whether ``origin`` names a log that holds evidence records (tzun-anchor/1 §4.3)."""
    if not isinstance(origin, str) or _ORIGIN_TEXT_RE.fullmatch(origin) is None:
        return False
    segments = origin.split("/")
    if not 3 <= len(segments) <= 4 or any(len(s) == 0 for s in segments):
        return False
    if not _is_log_namespace(segments[0]):
        return False
    if len(segments) == 4:
        return (
            _STORE_ID_RE.fullmatch(segments[1]) is not None
            and segments[2] == "evidence"
            and _is_chain_segment(segments[3])
        )
    return segments[2] not in ("anchors", "evidence")


# ── Grammar ──────────────────────────────────────────────────────────────


def compare_links(a: dict[str, Any], b: dict[str, Any]) -> int:
    """Order links by ``(rel, target.digest)``, each bytewise."""
    return compare_bytes(a["rel"], b["rel"]) or compare_bytes(a["target"]["digest"], b["target"]["digest"])


def _link_sort_key(link: dict[str, Any]) -> tuple[bytes, bytes]:
    return (link["rel"].encode("utf-8", "replace"), link["target"]["digest"].encode("utf-8", "replace"))


_MESSAGES: dict[str, str] = {
    "not_an_array": "links must be null or an array of links",
    "empty_links": "links must be null when there is no link, never []",
    "too_many_links": f"links holds at most {LINKS_MAX} links",
    "not_a_set": "links must be strictly increasing by (rel, target.digest) bytewise, with no repeated pair",
    "link_unknown_members": "a link has exactly the members rel, target and attrs",
    "link_missing_members": "a link has every member (rel, target, attrs), null where it does not apply",
    "invalid_relation": "rel must be [a-z][A-Za-z0-9]{0,31} or an extension x-<org>.<name>",
    "unknown_relation": "rel must be a registered relation (" + ", ".join(LINK_RELATIONS)
    + ") or an extension x-<org>.<name>",
    "relation_reserved": "this relation is written only by the SDK (mandate, revokes and subject)",
    "relation_not_writable": "this relation has no writer in this version (closes and fanoutOf)",
    "invalid_target": "target has exactly the members digest, evidenceId and locator",
    "invalid_target_digest": "target.digest must be 64 lowercase hex characters",
    "invalid_target_evidence_id": "target.evidenceId must be null or 1 to 128 characters of 0x21-0x7E",
    "invalid_locator": "target.locator must be null or exactly an evidence-log origin and a seq of at least 1",
    "invalid_attrs": "attrs must be null or an object of 1 to 16 attributes, each named [a-z][A-Za-z0-9]{0,31} or "
    "x-<org>.<name>, whose value is a string of at most 256 characters 0x20-0x7E, a non-negative safe "
    "integer, or a boolean",
    "too_many_attrs": f"attrs holds at most {LINK_ATTRS_MAX} attributes",
    "attrs_not_allowed": "an attribute outside the relation's profile",
    "missing_attr": "an attribute the relation's profile requires is missing",
    "link_rule_violated": "the relation's rule does not hold",
    "required_link_missing": "the record requires a link it does not carry",
    "link_target_not_found": "the store holds no record the target names; a record of another store is passed "
    "with external: true",
    "link_target_mismatch": "a member of the target disagrees with the record the store holds",
    "root_without_lineage": "a root link stands only beside a lineage link",
}


def _violation(code: str, field: str, *, link: int | None = None, rule: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"code": code, "field": field, "message": f"{field}: {_MESSAGES[code]}"}
    if link is not None:
        out["link"] = link
    if rule is not None:
        out["rule"] = rule
    return out


def _is_attr_name(name: str) -> bool:
    return REGISTERED_RELATION_RE.fullmatch(name) is not None or EXTENSION_RELATION_RE.fullmatch(name) is not None


def _is_attr_value(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, str):
        return _ATTR_STRING_RE.fullmatch(value) is not None
    return is_non_negative_safe_integer(value)


def _locator_well_formed(locator: Any) -> bool:
    return (
        isinstance(locator, dict)
        and has_exact_keys(locator, _LOCATOR_KEYS)
        and is_evidence_log_origin(locator["origin"])
        and is_positive_safe_integer(locator["seq"])
    )


def _link_grammar_violation(link: Any, i: int) -> dict[str, Any] | None:
    f = f"links[{i}]"
    if not isinstance(link, dict):
        return _violation("link_unknown_members", f, link=i)
    if any(k not in _LINK_KEYS for k in link):
        return _violation("link_unknown_members", f, link=i)
    if not has_exact_keys(link, _LINK_KEYS):
        return _violation("link_missing_members", f, link=i)
    if not is_relation_name(link["rel"]):
        return _violation("invalid_relation", f"{f}.rel", link=i)
    target = link["target"]
    if not isinstance(target, dict) or not has_exact_keys(target, _TARGET_KEYS):
        return _violation("invalid_target", f"{f}.target", link=i)
    if not is_bare_digest(target["digest"]):
        return _violation("invalid_target_digest", f"{f}.target.digest", link=i)
    if target["evidenceId"] is not None and not (
        isinstance(target["evidenceId"], str) and _EVIDENCE_ID_RE.fullmatch(target["evidenceId"]) is not None
    ):
        return _violation("invalid_target_evidence_id", f"{f}.target.evidenceId", link=i)
    if target["locator"] is not None and not _locator_well_formed(target["locator"]):
        return _violation("invalid_locator", f"{f}.target.locator", link=i)
    attrs = link["attrs"]
    if attrs is not None:
        if not isinstance(attrs, dict):
            return _violation("invalid_attrs", f"{f}.attrs", link=i)
        if len(attrs) == 0:
            return _violation("invalid_attrs", f"{f}.attrs", link=i)
        if len(attrs) > LINK_ATTRS_MAX:
            return _violation("too_many_attrs", f"{f}.attrs", link=i)
        for name, value in attrs.items():
            if not _is_attr_name(name) or not _is_attr_value(value):
                return _violation("invalid_attrs", f"{f}.attrs", link=i)
    return None


def links_grammar_violation(value: Any) -> dict[str, Any] | None:
    """Why ``value`` breaks the general grammar of ``links`` (Record §8.2), or ``None`` (``None`` meets it)."""
    value = plain(value)
    if value is None:
        return None
    if not isinstance(value, list):
        return _violation("not_an_array", "links")
    if len(value) == 0:
        return _violation("empty_links", "links")
    if len(value) > LINKS_MAX:
        return _violation("too_many_links", "links")
    for i, link in enumerate(value):
        v = _link_grammar_violation(link, i)
        if v:
            return v
    for i in range(1, len(value)):
        if compare_links(value[i - 1], value[i]) >= 0:
            return _violation("not_a_set", "links", link=i)
    return None


def link_attrs_violation(link: dict[str, Any], i: int) -> dict[str, Any] | None:
    """Why a link's attributes break its registered relation's closed profile, or ``None``."""
    if not is_registered_relation(link["rel"]):
        return None
    p = LINK_RELATIONS[link["rel"]]
    f = f"links[{i}].attrs"
    attrs = link["attrs"] if link.get("attrs") is not None else {}
    allowed = p.required_attrs + p.optional_attrs
    if any(n not in allowed for n in attrs):
        return _violation("attrs_not_allowed", f, link=i)
    for name in p.required_attrs:
        if name not in attrs:
            return _violation("missing_attr", f"{f}.{name}", link=i)
        value = attrs[name]
        if name in ("statement", "treeRoot"):
            ok = is_bare_digest(value)
        elif name == "size":
            ok = is_non_negative_safe_integer(value)
        elif name == "slot":
            ok = is_positive_safe_integer(value)
        else:
            ok = True
        if not ok:
            return _violation("invalid_attrs", f"{f}.{name}", link=i)
    return None


# ── Rules ────────────────────────────────────────────────────────────────


def _is_revocation_record(ctx: dict[str, Any]) -> bool:
    return ctx.get("aiSystemId") == _MANDATE_AI_SYSTEM_ID and ctx.get("action") == _MANDATE_REVOKE_ACTION


def _is_issuance_record(payload: dict[str, Any]) -> bool:
    return payload.get("aiSystemId") == _MANDATE_AI_SYSTEM_ID and payload.get("action") == _MANDATE_ISSUE_ACTION


def is_link_record(payload: Any) -> bool:
    """Whether a record is a link record (Record §8.6): its ``aiSystemId`` is ``tzun:link``."""
    payload = plain(payload)
    return isinstance(payload, dict) and payload.get("aiSystemId") == LINK_RECORD_AI_SYSTEM_ID


def _count_of(links: Sequence[dict[str, Any]], rel: str) -> int:
    return sum(1 for link in links if link["rel"] == rel)


def links_list_rule_violation(links: Sequence[dict[str, Any]] | None, ctx: dict[str, Any]) -> dict[str, Any] | None:
    """The list-level rules (Record §8.3) over a well-formed ``links``: ``{rule, missing}`` or ``None``."""
    from tzun_sdk.signoff_expectation import signoff_expectation_form

    lst = list(links) if links is not None else []
    form = signoff_expectation_form(ctx.get("signoffExpectation"))
    if form is not None:
        expected = 1 if form == "mandate" else 0
        n = _count_of(lst, "mandate")
        if n != expected:
            return {"rule": "mandate_link", "missing": n < expected}
    expected = 1 if _is_revocation_record(ctx) else 0
    n = _count_of(lst, "revokes")
    if n != expected:
        return {"rule": "revokes_link", "missing": n < expected}
    link_record = ctx.get("aiSystemId") == LINK_RECORD_AI_SYSTEM_ID
    n = _count_of(lst, "subject")
    if n != (1 if link_record else 0):
        return {"rule": "subject_link", "missing": link_record and n == 0}
    if link_record:
        subject = next(link for link in lst if link["rel"] == "subject")
        others = [link for link in lst if link["rel"] != "subject"]
        if (
            ctx.get("action") != LINK_RECORD_ACTION
            or ctx.get("contributions") is not None
            or len(others) == 0
            or any(link["target"]["digest"] == subject["target"]["digest"] for link in others)
            or any(link["rel"] in _NOT_IN_LINK_RECORD for link in others)
        ):
            return {"rule": "subject_link", "missing": len(others) == 0}
    for rel in _AT_MOST_ONE:
        if _count_of(lst, rel) > 1:
            return {"rule": "at_most_one", "missing": False}
    return None


def _has_unregistered_unprefixed_relation(links: Sequence[dict[str, Any]]) -> bool:
    return any(not is_registered_relation(link["rel"]) and not is_extension_relation(link["rel"]) for link in links)


def link_record_local_rule(links: Sequence[dict[str, Any]], i: int, ctx: dict[str, Any]) -> dict[str, Any]:
    """The record-local rule of link ``i`` (Record §8.3): ``{"result": "ok" | "violated" | "abstain", ...}``."""
    link = links[i]
    if ctx.get("aiSystemId") == LINK_RECORD_AI_SYSTEM_ID:
        return {"result": "ok"}
    if link["rel"] == "ratifies":
        decider = ctx.get("decider") if isinstance(ctx.get("decider"), dict) else None
        if decider is None or decider.get("kind") != "human":
            return {"result": "violated", "rule": "ratifies_decider_human"}
    if link["rel"] == "root":
        lineage = any(j != i and is_lineage_relation(other["rel"]) for j, other in enumerate(links))
        if not lineage:
            if _has_unregistered_unprefixed_relation(links):
                return {"result": "abstain"}
            return {"result": "violated", "rule": "root_without_lineage"}
    return {"result": "ok"}


def _held_digest(payload: dict[str, Any]) -> str | None:
    try:
        return hashlib.sha256(canonical_serialize(payload, list(V1_HASHED_FIELDS)).encode("utf-8")).hexdigest()
    except Exception:
        return None


@dataclass(frozen=True)
class HeldLinkTarget:
    """A record a verifier or writer holds as a link's target: its stored payload, digest and chain origin."""

    payload: dict[str, Any]
    digest: str
    origin: str | None


@dataclass
class LinkTargetResolver:
    """What a store-level verifier holds beside the record (Record §8.8), read synchronously."""

    by_digest: Callable[[str], HeldLinkTarget | None] | None = None
    is_own_origin: Callable[[str], bool] | None = None
    digest_at: Callable[[str, int], str | None] | None = None
    open_commitment: Callable[[str], str | None] | None = None


def link_target_member_mismatch(target: dict[str, Any], held: HeldLinkTarget) -> str | None:
    """Which non-null member of ``target`` disagrees with the held record (Record §8.8), or ``None``."""
    if held.digest != target["digest"] or _held_digest(held.payload) != target["digest"]:
        return "digest"
    if target["evidenceId"] is not None and target["evidenceId"] != held.payload.get("evidenceId"):
        return "evidenceId"
    locator = target["locator"]
    if locator is not None:
        if not _same_json_number(locator["seq"], held.payload.get("sequenceNumber")):
            return "locator"
        if held.origin is not None and locator["origin"] != held.origin:
            return "locator"
    return None


def _same_json_number(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return a == b


def _decider_of(payload: dict[str, Any]) -> dict[str, Any] | None:
    d = payload.get("decider")
    return d if isinstance(d, dict) else None


def _same_decider(
    a: dict[str, Any] | None, b: dict[str, Any] | None, open_commitment: Callable[[str], str | None] | None
) -> bool | None:
    if a is None or b is None:
        return None
    if a.get("kind") == b.get("kind") and a.get("id") == b.get("id"):
        return True

    def id_of(identifier: Any) -> str | None:
        if not isinstance(identifier, str):
            return None
        if identifier_scheme(identifier) != "cmt":
            return identifier
        return open_commitment(identifier) if open_commitment else None

    ia, ib = id_of(a.get("id")), id_of(b.get("id"))
    if ia is None or ib is None:
        return None
    return a.get("kind") == b.get("kind") and ia == ib


def _root_named_by(held: HeldLinkTarget) -> str | None:
    own = held.payload.get("links") if isinstance(held.payload.get("links"), list) else []
    root = next((link for link in own if isinstance(link, dict) and link.get("rel") == "root"), None)
    if root is not None and isinstance(root.get("target"), dict) and isinstance(root["target"].get("digest"), str):
        return root["target"]["digest"]
    if any(isinstance(link, dict) and is_lineage_relation(link.get("rel")) for link in own):
        return None
    return held.digest


def _root_inconsistent(
    link: dict[str, Any],
    target: HeldLinkTarget,
    links: Sequence[dict[str, Any]] | None,
    resolver: LinkTargetResolver | None,
) -> bool:
    own = target.payload.get("links") if isinstance(target.payload.get("links"), list) else []
    if any(isinstance(other, dict) and is_lineage_relation(other.get("rel")) for other in own):
        return True
    if links is None or resolver is None or resolver.by_digest is None:
        return False
    for other in links:
        if not is_lineage_relation(other["rel"]):
            continue
        held = resolver.by_digest(other["target"]["digest"])
        if held is None:
            continue
        named = _root_named_by(held)
        if named is not None and named != link["target"]["digest"]:
            return True
    return False


def check_link_target(
    link: dict[str, Any],
    child: dict[str, Any] | None,
    target: HeldLinkTarget | None,
    *,
    links: Sequence[dict[str, Any]] | None = None,
    resolver: LinkTargetResolver | None = None,
) -> dict[str, Any]:
    """The target rule of ``link`` (Record §8.3) with ``child`` in the child's place."""
    rel = link["rel"]
    if rel in ("delegatedBy", "closes", "fanoutOf"):
        return {"result": "unsupported"}
    if rel in ("derivedFrom", "appeals", "implements", "subject"):
        return {"result": "ok"}
    if rel == "root":
        if target is None:
            return {"result": "ok"}
        return {"result": "ok", "rootInconsistent": _root_inconsistent(link, target, links, resolver)}
    if child is None or target is None:
        return {"result": "not-held"}
    t = target.payload
    if rel == "reviews":
        same = _same_decider(
            _decider_of(child), _decider_of(t), resolver.open_commitment if resolver is not None else None
        )
        if same is None:
            return {"result": "undetermined", "rule": "reviews_distinct_decider"}
        return {"result": "violated", "rule": "reviews_distinct_decider"} if same else {"result": "ok"}
    if rel == "supersedes":
        if child.get("aiSystemId") == t.get("aiSystemId"):
            return {"result": "ok"}
        return {"result": "violated", "rule": "supersedes_same_system"}
    if rel == "ratifies":
        target_decider = _decider_of(t)
        if target_decider is not None and target_decider.get("kind") == "human":
            return {"result": "violated", "rule": "ratifies_target_not_human"}
        return {"result": "ok"}
    if rel == "mandate":
        expectation = child.get("signoffExpectation") if isinstance(child.get("signoffExpectation"), dict) else {}
        out = t.get("aiOutput") if isinstance(t.get("aiOutput"), dict) else {}
        if _is_issuance_record(t) and out.get("assertionDigest") == expectation.get("mandateAssertion"):
            return {"result": "ok"}
        return {"result": "violated", "rule": "mandate_target"}
    if rel == "revokes":
        own = child.get("aiOutput") if isinstance(child.get("aiOutput"), dict) else {}
        out = t.get("aiOutput") if isinstance(t.get("aiOutput"), dict) else {}
        if (
            _is_issuance_record(t)
            and isinstance(own.get("mandateDigest"), str)
            and out.get("mandateDigest") == own.get("mandateDigest")
        ):
            return {"result": "ok"}
        return {"result": "violated", "rule": "revokes_target"}
    return {"result": "ok"}


def check_link_record_link(
    link: dict[str, Any],
    subject: HeldLinkTarget | None,
    target: HeldLinkTarget | None,
    *,
    links: Sequence[dict[str, Any]] | None = None,
    resolver: LinkTargetResolver | None = None,
) -> dict[str, Any]:
    """The rules of a link record's non-``subject`` link, with the held subject in the child's place (Record §8.6)."""
    if link["rel"] == "ratifies":
        if subject is None:
            return {"result": "not-held"}
        subject_decider = _decider_of(subject.payload)
        if subject_decider is None or subject_decider.get("kind") != "human":
            return {"result": "violated", "rule": "ratifies_decider_human"}
    return check_link_target(
        link, None if subject is None else subject.payload, target, links=links, resolver=resolver
    )


# ── Writer ───────────────────────────────────────────────────────────────


def links_violation(value: Any, ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Why ``value`` is not a ``links`` member a 0.8.0 writer may write, or ``None``."""
    value = plain(value)
    ctx = plain(ctx) if isinstance(ctx, dict) else {}
    grammar = links_grammar_violation(value)
    if grammar:
        return grammar
    links: list[dict[str, Any]] | None = value
    if links is not None:
        for i, link in enumerate(links):
            rel = link["rel"]
            if not is_registered_relation(rel) and not is_extension_relation(rel):
                return _violation("unknown_relation", f"links[{i}].rel", link=i)
            if is_registered_relation(rel) and LINK_RELATIONS[rel].writer == "none":
                return _violation("relation_not_writable", f"links[{i}].rel", link=i)
            attrs = link_attrs_violation(link, i)
            if attrs:
                return attrs
        for i in range(len(links)):
            local = link_record_local_rule(links, i, ctx)
            if local["result"] == "violated":
                code = "root_without_lineage" if local["rule"] == "root_without_lineage" else "link_rule_violated"
                return _violation(code, f"links[{i}]", link=i, rule=local["rule"])
            if local["result"] == "abstain":
                return _violation("root_without_lineage", f"links[{i}]", link=i, rule="root_without_lineage")
    lst = links_list_rule_violation(links, ctx)
    if lst:
        code = "required_link_missing" if lst["missing"] else "link_rule_violated"
        return _violation(code, "links", rule=lst["rule"])
    return None


def link_record_violation(payload: Any) -> dict[str, Any] | None:
    """Why a link record (Record §8.6) is refused, or ``None`` when it is one, or is not a link record."""
    payload = plain(payload)
    if not is_link_record(payload):
        return None
    grammar = links_grammar_violation(payload.get("links"))
    if grammar:
        return grammar
    lst = links_list_rule_violation(payload.get("links"), payload)
    if lst and lst["rule"] == "subject_link":
        code = "required_link_missing" if lst["missing"] else "link_rule_violated"
        return _violation(code, "links", rule="subject_link")
    return None


class LinksBuildError(ValueError):
    """Raised by :func:`build_links` for input a writer refuses."""

    def __init__(self, violation: dict[str, Any]) -> None:
        super().__init__(violation["message"])
        self.code: str = violation["code"]
        self.field: str = violation["field"]
        self.link: int | None = violation.get("link")
        self.rule: str | None = violation.get("rule")


def _same_locator(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is b
    return a.get("origin") == b.get("origin") and _same_json_number(a.get("seq"), b.get("seq"))


_UNSET = object()


def build_links(
    inputs: Sequence[Any],
    *,
    held: Sequence[HeldLinkTarget | None] | None = None,
    allow_reserved: Sequence[str] = (),
    link_record: bool = False,
    context: dict[str, Any] | None = None,
    open_commitment: Callable[[str], str | None] | None = None,
) -> list[dict[str, Any]]:
    """Build ``links`` from capture input (Record §8.7). Raises :class:`LinksBuildError`.

    ``held`` has one entry per input, in input order: the same-store record the
    target resolved to, or ``None``. With ``context`` (the record being built),
    the target rule of each held target is applied. ``open_commitment`` names
    the identifier a ``cmt:`` decider commits to, or ``None`` when the writer
    cannot open it; the ``reviews`` rule opens both sides with it, as
    store-level verification does. Without it a ``cmt:`` decider leaves the
    rule undetermined and the link is written.
    """
    inputs = plain(inputs)
    if not isinstance(inputs, list):
        raise LinksBuildError(_violation("not_an_array", "links"))
    if len(inputs) == 0:
        raise LinksBuildError(_violation("empty_links", "links"))
    if len(inputs) > LINKS_MAX:
        raise LinksBuildError(_violation("too_many_links", "links"))
    built: list[tuple[dict[str, Any], HeldLinkTarget | None]] = []
    for i, item in enumerate(inputs):
        item = plain(item)
        f = f"links[{i}]"
        if not isinstance(item, dict) or any(k not in _INPUT_KEYS for k in item):
            raise LinksBuildError(_violation("link_unknown_members", f, link=i))
        rel = item.get("rel")
        if not is_relation_name(rel):
            raise LinksBuildError(_violation("invalid_relation", f"{f}.rel", link=i))
        if not is_registered_relation(rel) and not is_extension_relation(rel):
            raise LinksBuildError(_violation("unknown_relation", f"{f}.rel", link=i))
        if is_registered_relation(rel):
            writer = LINK_RELATIONS[rel].writer
            if writer == "none":
                raise LinksBuildError(_violation("relation_not_writable", f"{f}.rel", link=i))
            if writer == "reserved" and rel not in allow_reserved:
                raise LinksBuildError(_violation("relation_reserved", f"{f}.rel", link=i))
        t = plain(item.get("target"))
        if not isinstance(t, dict) or any(k not in _TARGET_INPUT_KEYS for k in t):
            raise LinksBuildError(_violation("invalid_target", f"{f}.target", link=i))
        h = held[i] if held is not None and i < len(held) else None
        if h is not None:
            t_locator = t.get("locator", _UNSET)
            if t_locator is None:
                filled_locator = None
            elif h.origin is not None and is_positive_safe_integer(h.payload.get("sequenceNumber")):
                filled_locator = {"origin": h.origin, "seq": h.payload["sequenceNumber"]}
            else:
                filled_locator = None
            if "digest" in t and t["digest"] != h.digest:
                raise LinksBuildError(_violation("link_target_mismatch", f"{f}.target.digest", link=i))
            if t.get("evidenceId") is not None and t["evidenceId"] != h.payload.get("evidenceId"):
                raise LinksBuildError(_violation("link_target_mismatch", f"{f}.target.evidenceId", link=i))
            if t_locator is not _UNSET and t_locator is not None and not _same_locator(t_locator, filled_locator):
                raise LinksBuildError(_violation("link_target_mismatch", f"{f}.target.locator", link=i))
            evidence_id = h.payload.get("evidenceId")
            target = {
                "digest": h.digest,
                "evidenceId": evidence_id if isinstance(evidence_id, str) else None,
                "locator": filled_locator,
            }
        else:
            if t.get("external") is not True:
                raise LinksBuildError(_violation("link_target_not_found", f"{f}.target", link=i))
            target = {
                "digest": t.get("digest"),
                "evidenceId": t.get("evidenceId"),
                "locator": t.get("locator"),
            }
        link = {"rel": rel, "target": target, "attrs": item.get("attrs")}
        grammar = _link_grammar_violation(link, i)
        if grammar:
            raise LinksBuildError(grammar)
        attrs = link_attrs_violation(link, i)
        if attrs:
            raise LinksBuildError(attrs)
        built.append((link, h))
    built.sort(key=lambda pair: _link_sort_key(pair[0]))
    for i in range(1, len(built)):
        if compare_links(built[i - 1][0], built[i][0]) == 0:
            raise LinksBuildError(_violation("not_a_set", "links", link=i))
    if not link_record and not any(link["rel"] == "root" for link, _ in built):
        first = next(((link, h) for link, h in built if is_lineage_relation(link["rel"]) and h is not None), None)
        if first is not None:
            first_link, first_held = first
            assert first_held is not None
            own = first_held.payload.get("links") if isinstance(first_held.payload.get("links"), list) else []
            own_root = next(
                (
                    link
                    for link in own
                    if isinstance(link, dict) and link.get("rel") == "root" and isinstance(link.get("target"), dict)
                ),
                None,
            )
            root_target: dict[str, Any] | None = None
            if own_root is not None:
                rt = own_root["target"]
                root_target = {
                    **rt,
                    "locator": None if rt.get("locator") is None else dict(rt["locator"]),
                }
            elif not any(isinstance(link, dict) and is_lineage_relation(link.get("rel")) for link in own):
                root_target = dict(first_link["target"])
            if root_target is not None:
                built.append(({"rel": "root", "target": root_target, "attrs": None}, None))
                built.sort(key=lambda pair: _link_sort_key(pair[0]))
    links = [link for link, _ in built]
    grammar = links_grammar_violation(links)
    if grammar:
        raise LinksBuildError(grammar)
    if context is not None:
        ctx = plain(context)
        is_lr = link_record or is_link_record(ctx)
        subject = next((h for link, h in built if link["rel"] == "subject"), None) if is_lr else None
        resolver = LinkTargetResolver(open_commitment=open_commitment) if open_commitment is not None else None
        for link, h in built:
            if is_lr:
                if link["rel"] == "subject" or subject is None:
                    continue
                result = check_link_record_link(link, subject, h, links=links, resolver=resolver)
            else:
                if h is None:
                    continue
                result = check_link_target(link, ctx, h, links=links, resolver=resolver)
            if result["result"] == "violated":
                index = next(j for j, other in enumerate(links) if other is link)
                raise LinksBuildError(
                    _violation("link_rule_violated", f"links[{index}]", link=index, rule=result["rule"])
                )
    return links


# ── Reader ───────────────────────────────────────────────────────────────


def _row(index: int, rel: str, outcome: str, reason: str | None = None, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "index": index,
        "rel": rel,
        "outcome": outcome,
        "valid": True if outcome == "checked-correct" else False if outcome == "checked-wrong" else None,
    }
    if reason is not None:
        out["reason"] = reason
    out.update(extra)
    return out


def _edge() -> dict[str, str]:
    return {"outcome": "abstain", "reason": "unsupported_link_edge"}


def check_links(payload: Any, *, resolver: LinkTargetResolver | None = None) -> dict[str, Any]:
    """The reader's ``links`` row and the rows under it (Verification §4.11). Never raises."""
    from tzun_sdk.signoff_expectation import signoff_expectation_form

    p = plain(payload)
    p = p if isinstance(p, dict) else {}
    value = p.get("links")
    expectation_malformed = signoff_expectation_form(p.get("signoffExpectation")) is None
    ctx = p
    if value is None:
        lst = links_list_rule_violation(None, ctx)
        if lst:
            return {
                "outcome": "checked-wrong",
                "valid": False,
                "reason": "link_rule_violated",
                "rule": lst["rule"],
                "relations": [],
                "edges": [],
            }
        return {"outcome": "not-checked", "valid": None, "reason": "absent", "relations": [], "edges": []}
    grammar = links_grammar_violation(value)
    links: list[Any] = value if isinstance(value, list) else []
    edges = [_edge() for _ in links]

    def blocked(reason: str) -> list[dict[str, Any]]:
        return [
            _row(i, link["rel"] if isinstance(link, dict) and isinstance(link.get("rel"), str) else "", "not-checked", reason)
            for i, link in enumerate(links)
        ]

    if grammar:
        out: dict[str, Any] = {
            "outcome": "checked-wrong",
            "valid": False,
            "reason": "malformed_links",
            "rule": grammar["code"],
        }
        if grammar.get("link") is not None:
            out["failedLink"] = grammar["link"]
        out["relations"] = blocked("blocked_by:links")
        out["edges"] = edges
        return out
    lst = links_list_rule_violation(links, ctx)
    if lst:
        return {
            "outcome": "checked-wrong",
            "valid": False,
            "reason": "link_rule_violated",
            "rule": lst["rule"],
            "relations": blocked("blocked_by:links"),
            "edges": edges,
        }

    link_record = is_link_record(p)
    subject_link = next((link for link in links if link["rel"] == "subject"), None) if link_record else None

    def by_digest(digest: str) -> HeldLinkTarget | None:
        return resolver.by_digest(digest) if resolver is not None and resolver.by_digest is not None else None

    subject = by_digest(subject_link["target"]["digest"]) if subject_link is not None else None

    def relation_row(i: int, link: dict[str, Any]) -> dict[str, Any]:
        rel = link["rel"]
        if rel == "mandate" and expectation_malformed:
            return _row(i, rel, "not-checked", "blocked_by:signoff.expectation")
        if not is_registered_relation(rel):
            return _row(i, rel, "abstain", "unsupported_link_relation")
        if link_attrs_violation(link, i) is not None:
            return _row(i, rel, "checked-wrong", "link_attrs_invalid")
        local = link_record_local_rule(links, i, ctx)
        if local["result"] == "violated":
            return _row(i, rel, "checked-wrong", "link_rule_violated", rule=local["rule"])
        held = by_digest(link["target"]["digest"])
        if held is not None:
            member = link_target_member_mismatch(link["target"], held)
            if member is not None:
                return _row(i, rel, "checked-wrong", "link_target_mismatch", member=member, targetHeld=True)
        else:
            locator = link["target"]["locator"]
            if (
                locator is not None
                and resolver is not None
                and resolver.is_own_origin is not None
                and resolver.is_own_origin(locator["origin"]) is True
                and resolver.digest_at is not None
                and resolver.digest_at(locator["origin"], locator["seq"]) != link["target"]["digest"]
            ):
                return _row(i, rel, "checked-wrong", "link_target_mismatch", member="locator", targetHeld=False)
        subject_in_place = link_record and rel != "subject"
        if subject_in_place:
            rule = check_link_record_link(link, subject, held, links=links, resolver=resolver)
        else:
            rule = check_link_target(link, p, held, links=links, resolver=resolver)
        if rule["result"] == "violated":
            return _row(i, rel, "checked-wrong", "link_rule_violated", rule=rule["rule"], targetHeld=held is not None)
        if rule["result"] == "unsupported" or local["result"] == "abstain":
            return _row(i, rel, "abstain", "unsupported_link_rule", targetHeld=held is not None)
        if rule["result"] == "undetermined":
            return _row(i, rel, "not-checked", "link_rule_undetermined", rule=rule["rule"], targetHeld=held is not None)
        if rule["result"] == "not-held":
            return _row(
                i,
                rel,
                "not-checked",
                "not_in_bundle:link_target",
                targetHeld=held is not None,
                missing="subject" if subject_in_place and subject is None else "target",
            )
        extra: dict[str, Any] = {"targetHeld": held is not None}
        if rule.get("rootInconsistent") is True:
            extra["rootInconsistent"] = True
        return _row(i, rel, "checked-correct", None, **extra)

    relations = [relation_row(i, link) for i, link in enumerate(links)]
    names: list[str] = []
    for link in links:
        if link["rel"] not in names:
            names.append(link["rel"])
    return {
        "outcome": "checked-correct",
        "valid": True,
        "count": len(links),
        "relationNames": names,
        "extensions": sum(1 for link in links if is_extension_relation(link["rel"])),
        "relations": relations,
        "edges": edges,
    }


def link_target_inputs(links: Any) -> set[str]:
    """The link targets a step's inputs may name (Record §7.5): ``sha256:`` and each target digest, when ``links`` is well formed."""
    links = plain(links)
    if links is None or links_grammar_violation(links) is not None:
        return set()
    return {f"sha256:{link['target']['digest']}" for link in links}


__all__ = (
    "EXTENSION_RELATION_RE",
    "LINKS_MAX",
    "LINK_ATTRS_MAX",
    "LINK_ATTR_STRING_MAX_LENGTH",
    "LINK_EVIDENCE_ID_MAX_LENGTH",
    "LINK_RECORD_ACTION",
    "LINK_RECORD_AI_SYSTEM_ID",
    "LINK_RELATIONS",
    "LINK_RELATION_NAMES",
    "REGISTERED_RELATION_RE",
    "RELATION_NAME_RE",
    "HeldLinkTarget",
    "LinkRelationProfile",
    "LinkTargetResolver",
    "LinksBuildError",
    "build_links",
    "check_link_record_link",
    "check_link_target",
    "check_links",
    "compare_links",
    "is_evidence_log_origin",
    "is_extension_relation",
    "is_lineage_relation",
    "is_link_record",
    "is_registered_relation",
    "is_relation_name",
    "link_attrs_violation",
    "link_record_local_rule",
    "link_record_violation",
    "link_target_inputs",
    "link_target_member_mismatch",
    "links_grammar_violation",
    "links_list_rule_violation",
    "links_violation",
)
