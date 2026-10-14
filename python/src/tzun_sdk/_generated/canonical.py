# HAND-MAINTAINED Python port of packages/engine/src/canonical.ts. NOT generated.
#
# scripts/codegen-python.ts writes only _generated/models.py and never touches
# this file, so regenerating does not carry a TypeScript change across: a
# change to the TypeScript source must be made here too.
#
# Parity with the TypeScript is enforced by the `cross-sdk` CI job (live
# Node<->Python harness over vectors/v1.0-canonical-vectors.json), not by the
# codegen-drift job.
"""Canonical serializer (Record §3).

This is the load-bearing parity surface: every entry in
``vectors/v1.0-canonical-vectors.json`` SHALL roundtrip byte-identically
through ``canonical_serialize``.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

MAX_DEPTH = 64

# JavaScript Numbers are IEEE-754 doubles, so an integer outside
# [-(2^53-1), 2^53-1] cannot round-trip through the reference implementation.
MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalSerializationError(ValueError):
    """Raised when a value cannot be canonicalized.

    Reasons include: non-finite numbers (NaN / Infinity), non-plain objects,
    lone surrogates in strings, exceeding ``MAX_DEPTH``.
    """


def canonical_serialize(
    fields: dict[str, Any],
    hashed_field_set: list[str] | None = None,
) -> str:
    """Serialize a dict of fields into canonical JSON bytes (as a str).

    When ``hashed_field_set`` is provided, only the named fields are
    included; absent fields are serialized as ``null`` (matching the TS
    reference behavior — fields named in the set but absent from the
    input become ``null`` in canonical bytes).

    When ``hashed_field_set`` is ``None``, every key in ``fields`` is
    serialized; this is the recursive "serialize whole subtree" path used
    by the canonical-vectors corpus.
    """
    if hashed_field_set is None:
        return _serialize_value(fields)
    subset: dict[str, Any] = {}
    for key in hashed_field_set:
        subset[key] = fields.get(key)
    return _serialize_value(subset)


def _serialize_value(value: Any, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        raise CanonicalSerializationError(
            "Canonical serialization error: maximum nesting depth exceeded "
            "(circular reference?)."
        )
    if value is None:
        return "null"
    if isinstance(value, bool):
        # bool MUST be checked before int (bool is a subclass of int).
        return "true" if value else "false"
    if isinstance(value, int):
        # Python ints are arbitrary precision; JavaScript Numbers are doubles.
        # Beyond 2^53-1 the reference implementation cannot represent the value
        # at all — 1725000000000000123 arrives in TS already rounded to
        # 1725000000000000000 — so emitting the exact Python digits would
        # produce canonical bytes the other SDK can never reproduce, and the
        # record would read as tampered wherever it was verified. Refusing is
        # the same choice already made for NaN and Infinity: fail closed rather
        # than write evidence that silently disagrees across languages.
        if value > MAX_SAFE_INTEGER or value < -MAX_SAFE_INTEGER:
            raise CanonicalSerializationError(
                f"Canonical serialization error: integer {value} is outside the "
                f"safe range +/-{MAX_SAFE_INTEGER} (2^53-1). JavaScript cannot "
                "represent it exactly, so the two SDKs would compute different "
                "digests for the same record. Encode large identifiers "
                "(snowflake IDs, nanosecond timestamps) as strings."
            )
        return str(value)
    if isinstance(value, float):
        if not _is_finite(value):
            raise CanonicalSerializationError(
                f"Canonical serialization error: non-finite number ({value}). "
                "Numbers must be finite — NaN and Infinity are not allowed."
            )
        return _js_number_to_string(value)
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, list) or isinstance(value, tuple):
        items = [_serialize_value(item, depth + 1) for item in value]
        return "[" + ",".join(items) + "]"
    if isinstance(value, dict):
        return _serialize_object(value, depth)
    raise CanonicalSerializationError(
        f"Canonical serialization error: unsupported type {type(value).__name__!r}."
    )


def _js_number_to_string(x: float) -> str:
    """ECMA-262 ``Number::toString(x, 10)`` — the reference implementation.

    Neither ``str(int(x))`` nor ``repr(x)`` can stand in for it. ``repr`` gives
    the same shortest round-trip DIGITS as JavaScript, but not the same
    rendering of them, and the two disagree in four places that all appear in
    real data:

    * ``1e-5`` / ``1e-6``: Python ``1e-05`` / ``1e-06``, JS ``0.00001`` /
      ``0.000001`` — JS only switches to exponent notation below 1e-6.
    * ``1e21`` and above: Python ``1000000000000000000000``, JS ``1e+21``.
    * Exponent padding: Python ``1e-07``, JS ``1e-7``.
    * Integer-valued floats with more than 17 significant digits: Python
      ``123456789012345683968`` (the exact binary value), JS
      ``123456789012345680000`` (shortest round-trip, zero-padded).

    The algorithm is the spec's, verbatim: find the smallest k and the s, n with
    10^(k-1) <= s < 10^k and s x 10^(n-k) = x, then pick a rendering by where n
    falls relative to k, 21 and -6. ``repr`` supplies s and n.
    """
    if x == 0:
        # Covers -0.0, which JS renders as "0" (String(-0) === "0").
        return "0"
    if x < 0:
        return "-" + _js_number_to_string(-x)

    _, digits, exp = Decimal(repr(x)).as_tuple()
    ds = list(digits)
    # s must not end in a zero for k to be minimal.
    while len(ds) > 1 and ds[-1] == 0:
        ds.pop()
        exp += 1
    k = len(ds)
    n = int(exp) + k
    s = "".join(str(d) for d in ds)

    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    e = n - 1
    sign = "+" if e >= 0 else "-"
    if k == 1:
        return f"{s}e{sign}{abs(e)}"
    return f"{s[0]}.{s[1:]}e{sign}{abs(e)}"


def _serialize_object(obj: dict[str, Any], depth: int) -> str:
    # Record §3.3: keys sorted lexicographically (Python str sort is Unicode
    # code-point order, which matches JS's `<`/`>` on basic-plane strings;
    # for supplementary-plane code points, Python compares by code point
    # while JS compares by UTF-16 code unit. The two agree on basic-plane
    # text. The TS reference uses `Object.keys(obj).sort()` which is
    # implementation-defined-but-stable code-unit sort.)
    #
    # For full UTF-16-BE byte parity (Record §3.3), encode each key to
    # UTF-16-BE bytes and compare those byte sequences. This matches JS
    # exactly on supplementary-plane code points too.
    keys = sorted(obj.keys(), key=lambda s: s.encode("utf-16-be"))
    pairs = []
    for key in keys:
        val = obj[key]
        serialized_val = _serialize_value(val, depth + 1)
        pairs.append(_serialize_string(key) + ":" + serialized_val)
    return "{" + ",".join(pairs) + "}"


def _serialize_string(s: str) -> str:
    """JSON-escape a string per RFC 8259.

    Non-ASCII characters are NOT escaped (pass through as UTF-8 in output).
    Lone surrogates are rejected.
    """
    result: list[str] = ['"']
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        cp = ord(ch)
        if cp == 0x22:  # "
            result.append('\\"')
        elif cp == 0x5C:  # \
            result.append("\\\\")
        elif cp == 0x08:
            result.append("\\b")
        elif cp == 0x0C:
            result.append("\\f")
        elif cp == 0x0A:
            result.append("\\n")
        elif cp == 0x0D:
            result.append("\\r")
        elif cp == 0x09:
            result.append("\\t")
        elif cp < 0x20:
            result.append(f"\\u{cp:04x}")
        elif 0xD800 <= cp <= 0xDFFF:
            # Lone surrogate. Python strs CAN contain these only if explicitly
            # constructed via chr(); reject for round-tripping safety.
            raise CanonicalSerializationError(
                f"Canonical serialization error: lone surrogate U+{cp:04X} in string."
            )
        else:
            result.append(ch)
        i += 1
    result.append('"')
    return "".join(result)


def _is_finite(value: float) -> bool:
    import math

    return not (math.isnan(value) or math.isinf(value))


# ── Descriptor sub-rule ─────────────────────────────────────


def canonical_serialize_descriptor(descriptor: dict[str, Any]) -> str:
    """Canonicalize a ModelDescriptor with the set-valued-field sub-rule.

    Sorts ``regulatoryMarkings`` by ``(authority, identifier)``,
    ``training.evaluations`` by ``name``, and ``externalIdentifiers`` by
    ``(scheme, value)`` before applying the base serializer. Matches the
    TS ``canonicalSerializeDescriptor`` implementation in
    ``packages/engine/src/canonical.ts``.
    """
    d = dict(descriptor)

    def _key(*parts: Any) -> tuple[bytes, ...]:
        # TS `cmpTuple` compares with `<`/`>`, which is UTF-16 CODE-UNIT order.
        # Python's default str sort is code-POINT order, and the two disagree
        # for supplementary-plane characters (an emoji sorts before U+E000..
        # U+FFFF in JS and after it in Python). The base key sort a few lines
        # down uses utf-16-be for the same reason; without it here, a
        # descriptor whose externalIdentifiers contain an emoji would serialise
        # in a different ORDER in the two SDKs and hash to a different digest.
        return tuple(
            (p if isinstance(p, str) else "").encode("utf-16-be") for p in parts
        )

    if "regulatoryMarkings" in d and isinstance(d["regulatoryMarkings"], list):
        d["regulatoryMarkings"] = sorted(
            d["regulatoryMarkings"],
            key=lambda m: _key(
                m.get("authority", "") if isinstance(m, dict) else "",
                m.get("identifier", "") if isinstance(m, dict) else "",
            ),
        )
    if "externalIdentifiers" in d and isinstance(d["externalIdentifiers"], list):
        d["externalIdentifiers"] = sorted(
            d["externalIdentifiers"],
            key=lambda e: _key(
                e.get("scheme", "") if isinstance(e, dict) else "",
                e.get("value", "") if isinstance(e, dict) else "",
            ),
        )
    if "training" in d and isinstance(d["training"], dict):
        training = dict(d["training"])
        if "evaluations" in training and isinstance(training["evaluations"], list):
            training["evaluations"] = sorted(
                training["evaluations"],
                key=lambda e: _key(e.get("name", "") if isinstance(e, dict) else ""),
            )
        d["training"] = training
    return canonical_serialize(d)


# ── Hashed-field-set (v1.0) ──────────────────────────────────────────

#: v1.0 of the wire format, as revised in 0.8.0, hashes exactly these eleven
#: fields, in byte order (``V1_0_HASHED_FIELDS`` in the engine's
#: schema-registry.ts).
V1_HASHED_FIELDS: tuple[str, ...] = (
    "action",
    "aiOutput",
    "aiSystemId",
    "capturedAt",
    "contributions",
    "decider",
    "evidenceId",
    "links",
    "reason",
    "sequenceNumber",
    "signoffExpectation",
)

#: The v1.0 hashed field set of the 0.7 releases (nine names): a detection
#: constant only, nothing is built or verified under it (``FIELD_SET_0_7`` in
#: the engine's store-schema.ts).
V1_HASHED_FIELDS_0_7: tuple[str, ...] = (
    "aiBom",
    "aiOutput",
    "aiSystemId",
    "capturedAt",
    "evidenceId",
    "humanAction",
    "humanReason",
    "sequenceNumber",
    "signoffExpectation",
)

#: The v1.0 hashed field set before 0.7.0 (eight names): a detection constant
#: only (``FIELD_SET_BEFORE_0_7`` in the engine's store-schema.ts).
V1_HASHED_FIELDS_BEFORE_0_7: tuple[str, ...] = (
    "aiBom",
    "aiOutput",
    "aiSystemId",
    "capturedAt",
    "evidenceId",
    "humanAction",
    "humanReason",
    "sequenceNumber",
)
