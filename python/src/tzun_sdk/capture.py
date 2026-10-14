"""Capture-path utilities.

The core capture logic lives on :class:`Tzun.capture`; this module holds the
free-function shims and helpers used by both the async and sync paths.
"""

from __future__ import annotations

import math
from typing import Any

from tzun_sdk._generated.canonical import MAX_DEPTH
from tzun_sdk.errors import TzunError

#: Types pydantic re-encodes losslessly into JSON strings (``Decimal('0.10')``
#: → ``"0.10"``, ``datetime`` → ISO-8601). They are accepted, unlike a
#: non-finite float: nothing is *lost*, the value is merely re-typed. TS would
#: refuse them outright, which is a known and separately tracked asymmetry —
#: it is not the silent-value-substitution this guard exists to stop.
_RETYPED_BY_PYDANTIC = ("Decimal", "datetime", "date", "time", "UUID")


def assert_capture_serializable(value: Any, path: str = "aiOutput") -> None:
    """Reject inputs that ``model_dump(mode="json")`` would quietly rewrite.

    This has to run BEFORE the payload is dumped, because pydantic v2's
    default ``ser_json_inf_nan='null'`` rewrites NaN and ±Infinity to ``null``
    *before* :func:`canonical_serialize` — whose own non-finite guard is
    therefore unreachable from ``capture()``. The digest is then computed over
    a ``null`` the model never produced, and the record asserts "no value"
    where the caller supplied one.

    The TS engine throws on a non-finite number (packages/engine/src/
    canonical.ts:64-68) and ``Tzun.capture`` turns that into a
    ``serialization_failure`` with ``stored: false``. Python's public
    ``CaptureResult`` has no failure channel, so the equivalent refusal here
    is a raised :class:`~tzun_sdk.errors.TzunError` — the same answer, in the
    idiom this SDK already uses.

    Raises:
        TzunError: on a non-finite float, an undecodable ``bytes`` value, a
            non-string mapping key, or nesting past ``MAX_DEPTH``.
    """
    _walk(value, path, 0)


def _walk(value: Any, path: str, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise TzunError(
            f"Cannot capture: {path} exceeds the maximum nesting depth of "
            f"{MAX_DEPTH} (circular reference?)."
        )
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise TzunError(
                f"Cannot capture: {path} is a non-finite number ({value}). "
                "NaN and Infinity have no canonical JSON form; recording one "
                "would store 'null' under a valid digest, asserting a value "
                "the AI system never produced. Replace it with a finite "
                "number, or with null if the value is genuinely absent."
            )
        return
    if isinstance(value, (bytes, bytearray)):
        try:
            value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TzunError(
                f"Cannot capture: {path} contains bytes that are not valid "
                f"UTF-8 ({exc}). Decode or base64-encode the value before "
                "passing it to capture()."
            ) from exc
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TzunError(
                    f"Cannot capture: {path} has a non-string key "
                    f"{key!r} ({type(key).__name__}). Canonical JSON objects "
                    "are keyed by strings only."
                )
            _walk(item, f"{path}.{key}", depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _walk(item, f"{path}[{i}]", depth + 1)
        return
    # Everything else — Decimal, datetime, and any object pydantic knows how
    # to encode — is left to pydantic, which re-types rather than drops.
    return


__all__ = ("assert_capture_serializable",)
