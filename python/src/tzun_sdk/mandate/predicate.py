"""Mandate predicates (Record §9.8): grammar and exact evaluation.

A predicate is ``{path, op, value, quant}`` and evaluates to ``"true"``,
``"false"`` or ``"undeterminable"``. The twin of
``packages/engine/src/mandate/predicate.ts``; TypeScript, Python and Go agree
on every record. Strings are compared by code points; an integer is a JSON
number that is mathematically integral from 0 to 2^53 - 1 (``1.0`` is 1,
``True`` is never 1).
"""

from __future__ import annotations

import re
from typing import Any

from tzun_sdk._record_rules import (
    PRINTABLE_ASCII_RE,
    is_non_negative_safe_integer,
    is_strictly_increasing,
    plain,
)

PREDICATE_OPS: tuple[str, ...] = ("eq", "ne", "lt", "le", "gt", "ge", "in", "notIn", "prefix", "glob")

#: The most elements an ``in``, ``notIn`` or ``glob`` set holds.
PREDICATE_MAX_SET = 64
#: The longest glob pattern, in characters.
GLOB_MAX_PATTERN_LENGTH = 256
#: A string subject longer than this, in code points, is undeterminable.
PREDICATE_MAX_SUBJECT_CODE_POINTS = 4096
#: An array subject longer than this is undeterminable.
PREDICATE_MAX_ARRAY_ELEMENTS = 10000

_PREDICATE_KEYS = ("path", "op", "value", "quant")
_ARRAY_INDEX_RE = re.compile(r"0|[1-9][0-9]*", re.ASCII)
_BAD_TILDE_RE = re.compile(r"~(?![01])")

_MISSING = object()


def _printable(value: Any) -> bool:
    return isinstance(value, str) and PRINTABLE_ASCII_RE.fullmatch(value) is not None


def parse_json_pointer(path: Any) -> list[str] | None:
    """The reference tokens of an RFC 6901 JSON Pointer, unescaped, or ``None``."""
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    out: list[str] = []
    for raw in path[1:].split("/"):
        if _BAD_TILDE_RE.search(raw):
            return None
        out.append(raw.replace("~1", "/").replace("~0", "~"))
    return out


def resolve_pointer(root: Any, tokens: list[str]) -> dict[str, Any]:
    """``{"found": True, "value": ...}`` or ``{"found": False}``.

    On an object a token names an own member; on an array it is ``0`` or
    ``[1-9][0-9]*`` below the length; on anything else it resolves to nothing.
    """
    current = plain(root)
    for token in tokens:
        if isinstance(current, list):
            if _ARRAY_INDEX_RE.fullmatch(token) is None:
                return {"found": False}
            index = int(token)
            if index > 2**53 - 1 or index >= len(current):
                return {"found": False}
            current = current[index]
        elif isinstance(current, dict):
            if token not in current:
                return {"found": False}
            current = current[token]
        else:
            return {"found": False}
    return {"found": True, "value": current}


def _match_segment(pattern: list[str], subject: list[str]) -> bool:
    p = s = 0
    star = -1
    mark = 0
    while s < len(subject):
        if p < len(pattern) and (pattern[p] == "?" or (pattern[p] != "*" and pattern[p] == subject[s])):
            p += 1
            s += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            mark = s
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            s = mark
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        p += 1
    return p == len(pattern)


def glob_match(pattern: str, subject: str) -> bool:
    """Whether ``subject`` matches the glob ``pattern`` (Record §9.8), iteratively, with no recursion."""
    ps: list[list[str] | None] = [None if seg == "**" else list(seg) for seg in pattern.split("/")]
    ss = [list(seg) for seg in subject.split("/")]
    p = s = 0
    star = -1
    mark = 0
    while s < len(ss):
        seg = ps[p] if p < len(ps) else _MISSING
        if seg is not _MISSING and seg is not None and _match_segment(seg, ss[s]):  # type: ignore[arg-type]
            p += 1
            s += 1
        elif seg is None:
            star = p
            mark = s
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            s = mark
        else:
            return False
    while p < len(ps) and ps[p] is None:
        p += 1
    return p == len(ps)


def _is_string_set(value: Any, max_length: int | None = None) -> bool:
    return (
        isinstance(value, list)
        and 1 <= len(value) <= PREDICATE_MAX_SET
        and all(
            _printable(v) and (max_length is None or 1 <= len(v) <= max_length) for v in value
        )
        and is_strictly_increasing(value)
    )


def predicate_violation(predicate: Any) -> str | None:
    """Why ``predicate`` is not a well-formed predicate, or ``None`` (the grammar ``prepare`` applies)."""
    predicate = plain(predicate)
    if not isinstance(predicate, dict):
        return "a predicate must be an object"
    if len(predicate) != len(_PREDICATE_KEYS) or not all(k in predicate for k in _PREDICATE_KEYS):
        return "a predicate must have exactly the members path, op, value and quant"
    path, op, value, quant = (predicate[k] for k in _PREDICATE_KEYS)
    if not _printable(path) or parse_json_pointer(path) is None:
        return "path must be a JSON Pointer of printable ASCII whose ~ appear only as ~0 or ~1"
    if quant not in (None, "all", "any") or isinstance(quant, bool):
        return "quant must be null, all or any"
    if op in ("eq", "ne"):
        ok = _printable(value) if isinstance(value, str) else (
            isinstance(value, bool) or is_non_negative_safe_integer(value)
        )
        return None if ok else f"{op} takes a printable-ASCII string, a non-negative safe integer or a boolean"
    if op in ("lt", "le", "gt", "ge"):
        return None if is_non_negative_safe_integer(value) else f"{op} takes a non-negative safe integer"
    if op in ("in", "notIn"):
        return None if _is_string_set(value) else f"{op} takes a sorted set of 1 to {PREDICATE_MAX_SET} strings"
    if op == "prefix":
        return None if _printable(value) else "prefix takes a printable-ASCII string"
    if op == "glob":
        if _is_string_set(value, GLOB_MAX_PATTERN_LENGTH):
            return None
        return (
            f"glob takes a sorted set of 1 to {PREDICATE_MAX_SET} patterns of 1 to "
            f"{GLOB_MAX_PATTERN_LENGTH} characters"
        )
    return "op must be one of " + ", ".join(PREDICATE_OPS)


def _evaluate_one(op: str, value: Any, subject: Any) -> str:
    if subject is None:
        return "undeterminable"
    if isinstance(subject, str) and len(subject) > PREDICATE_MAX_SUBJECT_CODE_POINTS:
        return "undeterminable"

    def truth(b: bool) -> str:
        return "true" if b else "false"

    if op in ("eq", "ne"):
        if isinstance(subject, bool):
            same = isinstance(value, bool) and subject is value
        elif isinstance(subject, str):
            same = isinstance(value, str) and subject == value
        elif is_non_negative_safe_integer(subject):
            same = is_non_negative_safe_integer(value) and subject == value
        else:
            return "undeterminable"
        return truth(same if op == "eq" else not same)
    if op in ("lt", "le", "gt", "ge"):
        if not is_non_negative_safe_integer(subject) or not is_non_negative_safe_integer(value):
            return "undeterminable"
        if op == "lt":
            return truth(subject < value)
        if op == "le":
            return truth(subject <= value)
        if op == "gt":
            return truth(subject > value)
        return truth(subject >= value)
    if op in ("in", "notIn"):
        if not isinstance(subject, str) or not isinstance(value, list):
            return "undeterminable"
        member = any(isinstance(v, str) and v == subject for v in value)
        return truth(member if op == "in" else not member)
    if op == "prefix":
        if not isinstance(subject, str) or not isinstance(value, str):
            return "undeterminable"
        return truth(subject.startswith(value))
    if op == "glob":
        if not isinstance(subject, str) or not isinstance(value, list):
            return "undeterminable"
        return truth(any(isinstance(p, str) and glob_match(p, subject) for p in value))
    return "undeterminable"


def evaluate_predicate(predicate: Any, payload: Any) -> str:
    """Evaluate ``predicate`` over ``payload`` (Record §9.8). Never raises."""
    predicate = plain(predicate)
    if predicate_violation(predicate) is not None:
        return "undeterminable"
    path, op, value, quant = (predicate[k] for k in _PREDICATE_KEYS)
    tokens = parse_json_pointer(path)
    assert tokens is not None
    resolved = resolve_pointer(payload, tokens)
    if not resolved["found"]:
        return "undeterminable"
    subject = resolved["value"]
    if subject is None:
        return "undeterminable"
    if quant is None:
        if isinstance(subject, list):
            return "undeterminable"
        return _evaluate_one(op, value, subject)
    if not isinstance(subject, list) or len(subject) > PREDICATE_MAX_ARRAY_ELEMENTS:
        return "undeterminable"
    saw_undeterminable = False
    for element in subject:
        outcome = _evaluate_one(op, value, element)
        if quant == "all" and outcome == "false":
            return "false"
        if quant == "any" and outcome == "true":
            return "true"
        if outcome == "undeterminable":
            saw_undeterminable = True
    if saw_undeterminable:
        return "undeterminable"
    return "true" if quant == "all" else "false"


__all__ = (
    "GLOB_MAX_PATTERN_LENGTH",
    "PREDICATE_MAX_ARRAY_ELEMENTS",
    "PREDICATE_MAX_SET",
    "PREDICATE_MAX_SUBJECT_CODE_POINTS",
    "PREDICATE_OPS",
    "evaluate_predicate",
    "glob_match",
    "parse_json_pointer",
    "predicate_violation",
    "resolve_pointer",
)
