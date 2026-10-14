"""Shared predicates for the record rules.

The twin of ``packages/engine/src/record-rules-util.ts``: the decider,
contributions, links, mandate and agent-descriptor rules read the same
definitions, so one value is never judged two ways.

Every pattern is matched over the whole string with ASCII classes:
``re.fullmatch`` with ``re.ASCII`` and ``[0-9]``, never ``re.match(...$)``
(which accepts a trailing newline) or ``\\d`` (which matches non-ASCII digits).

Values are JSON values as ``json.loads`` gives them: ``dict``, ``list``,
``str``, ``int``, ``float``, ``bool`` and ``None``. A JSON number is read the
way JavaScript reads it: ``3.0`` and ``3e0`` are the integer 3, and ``True`` is
never a number.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from pydantic import BaseModel

from tzun_sdk._generated.canonical import canonical_serialize

#: A bare digest, as evidence records and registrations write one: 64 lowercase hex.
BARE_DIGEST_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)

#: A prefixed digest, as content-addressed documents write one.
PREFIXED_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)

#: Printable ASCII, 0x20 to 0x7E, possibly empty.
PRINTABLE_ASCII_RE = re.compile(r"[\x20-\x7e]*", re.ASCII)

#: Printable ASCII other than space, 0x21 to 0x7E, possibly empty.
VISIBLE_ASCII_RE = re.compile(r"[\x21-\x7e]*", re.ASCII)

#: The largest integer a JSON number carries exactly.
MAX_SAFE_INTEGER = 2**53 - 1


def plain(value: Any) -> Any:
    """A model as the JSON value it stands for; anything else as it is.

    ``exclude_unset`` keeps a model's absent optional members absent, as the
    TypeScript object it mirrors would have them.
    """
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_unset=True)
    return value


def deep_plain(value: Any) -> Any:
    """``value`` with every model inside it (at any depth) replaced by its JSON value.

    Dicts and lists are copied; anything else is returned as it is.
    """
    value = plain(value)
    if isinstance(value, dict):
        return {k: deep_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [deep_plain(v) for v in value]
    return value


def json_value(value: Any) -> Any:
    """``value`` as plain JSON values: models (``exclude_unset``) and the types pydantic re-encodes.

    ``bytes`` become their UTF-8 text, ``Decimal``, dates and UUIDs their
    string forms, tuples lists: what ``model_dump(mode="json")`` writes for a
    ``dict[str, Any]``. Call after ``assert_capture_serializable``, which
    refuses what this would silently rewrite (NaN, ±Infinity, undecodable bytes).
    """
    from pydantic_core import to_jsonable_python

    return to_jsonable_python(deep_plain(value))


def is_plain_object(value: Any) -> bool:
    """A JSON object."""
    return isinstance(value, dict)


def has_exact_keys(value: dict[str, Any], expected: tuple[str, ...] | list[str]) -> bool:
    """Whether the object's own keys are exactly ``expected`` (any order)."""
    return len(value) == len(expected) and all(k in value for k in expected)


def is_bare_digest(value: Any) -> bool:
    return isinstance(value, str) and BARE_DIGEST_RE.fullmatch(value) is not None


def is_prefixed_digest(value: Any) -> bool:
    return isinstance(value, str) and PREFIXED_DIGEST_RE.fullmatch(value) is not None


def is_json_number(value: Any) -> bool:
    """A JSON number: an ``int`` or a ``float``, never a ``bool``."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_safe_integer(value: Any) -> bool:
    """JavaScript ``Number.isSafeInteger``: a number, mathematically integral, |n| <= 2^53 - 1."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER
    if isinstance(value, float):
        return value.is_integer() and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER
    return False


def is_non_negative_safe_integer(value: Any) -> bool:
    """A non-negative integer no greater than 2^53 - 1. ``1.0`` and ``1e0`` are the integer 1."""
    return is_safe_integer(value) and value >= 0


def is_positive_safe_integer(value: Any) -> bool:
    """A safe integer of at least 1."""
    return is_safe_integer(value) and value >= 1


def is_finite_number(value: Any) -> bool:
    """JavaScript ``Number.isFinite`` over a JSON value."""
    if not is_json_number(value):
        return False
    if isinstance(value, float):
        return value == value and value not in (float("inf"), float("-inf"))
    return True


def _js_integer_literal(text: str) -> int | float:
    """A JSON integer literal as ``JSON.parse`` reads it: exact while safe, otherwise the nearest double."""
    if len(text.lstrip("-")) <= 15:
        return int(text)
    value = float(text)
    if value.is_integer() and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        return int(text)
    return value


def js_json_loads(text: str | bytes) -> Any:
    """JSON text parsed as ``JSON.parse`` parses it: an integer literal past 2^53 - 1 is the nearest double.

    A stored record a JavaScript writer hashed was hashed over the double its
    parser made of such a literal (``2**60`` is ``1152921504606847000``), so a
    reader recomputing the digest reads the literal the same way. A literal
    past the largest double is ``inf``, which the canonical serializer refuses
    as ``JSON.parse`` + ``canonicalSerialize`` do.
    """
    return json.loads(text, parse_int=_js_integer_literal)


def as_int(value: Any) -> int:
    """A safe integer as a Python ``int`` (``3.0`` is ``3``). Call after :func:`is_safe_integer`."""
    return int(value)


def utf16_length(value: str) -> int:
    """Length in UTF-16 code units, JavaScript's ``String.length``."""
    return sum(2 if ord(c) > 0xFFFF else 1 for c in value)


def has_lone_surrogate(value: str) -> bool:
    """Whether a string holds an unpaired UTF-16 surrogate, which the canonical serializer refuses."""
    chars = value
    i = 0
    n = len(chars)
    while i < n:
        c = ord(chars[i])
        if 0xD800 <= c <= 0xDBFF:
            nxt = ord(chars[i + 1]) if i + 1 < n else -1
            if not 0xDC00 <= nxt <= 0xDFFF:
                return True
            i += 2
            continue
        if 0xDC00 <= c <= 0xDFFF:
            return True
        i += 1
    return False


def _utf8(text: str) -> bytes:
    # A lone surrogate has no UTF-8 encoding; Node writes U+FFFD for it.
    return text.encode("utf-8", errors="replace")


def compare_bytes(a: str, b: str) -> int:
    """Compare two strings by their UTF-8 bytes: negative, zero or positive."""
    ab, bb = _utf8(a), _utf8(b)
    return (ab > bb) - (ab < bb)


def bytes_key(value: str) -> bytes:
    """A sort key that orders strings by their UTF-8 bytes."""
    return _utf8(value)


def is_strictly_increasing(values: list[Any]) -> bool:
    """Whether ``values`` is strictly increasing by bytes: sorted, with no repeated element."""
    return all(compare_bytes(values[i - 1], values[i]) < 0 for i in range(1, len(values)))


def canonical_value(value: Any) -> str:
    """The canonical bytes of a whole value (every key of every object).

    Raises ``CanonicalSerializationError`` for a value the serializer refuses.
    """
    return canonical_serialize(value)  # type: ignore[arg-type]


def sha256_hex(text: str) -> str:
    """Lowercase hex SHA-256 of a string's UTF-8 bytes."""
    return hashlib.sha256(_utf8(text)).hexdigest()


def utf8_length(text: str) -> int:
    """UTF-8 byte length of a string."""
    return len(_utf8(text))


def full(pattern: re.Pattern[str], value: Any) -> bool:
    """Whether ``value`` is a string ``pattern`` matches in full."""
    return isinstance(value, str) and pattern.fullmatch(value) is not None


__all__ = (
    "BARE_DIGEST_RE",
    "MAX_SAFE_INTEGER",
    "PREFIXED_DIGEST_RE",
    "PRINTABLE_ASCII_RE",
    "VISIBLE_ASCII_RE",
    "as_int",
    "bytes_key",
    "canonical_value",
    "compare_bytes",
    "deep_plain",
    "full",
    "has_exact_keys",
    "has_lone_surrogate",
    "is_bare_digest",
    "is_finite_number",
    "is_json_number",
    "is_non_negative_safe_integer",
    "is_plain_object",
    "is_positive_safe_integer",
    "is_prefixed_digest",
    "is_safe_integer",
    "is_strictly_increasing",
    "js_json_loads",
    "json_value",
    "plain",
    "sha256_hex",
    "utf8_length",
    "utf16_length",
)
