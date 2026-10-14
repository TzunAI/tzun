"""Vector-corpus roundtrip (load-bearing parity).

Every entry in ``vectors/v1.0-canonical-vectors.json`` MUST roundtrip
byte-identically through the Python canonicalizer. This test is the
cross-language wire-format parity gate.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

import pytest

from tzun_sdk._generated.canonical import (
    canonical_serialize,
    canonical_serialize_descriptor,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent / "vectors" / "v1.0-canonical-vectors.json"
)


def _load_vectors() -> list[dict[str, Any]]:
    raw = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return raw["vectors"]


def _load_negative_vectors() -> list[dict[str, Any]]:
    raw = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    return raw.get("negativeVectors", [])


VECTORS = _load_vectors()
NEGATIVE_VECTORS = _load_negative_vectors()

# V11 uses the sentinel "UNDEFINED_MARKER" string in JSON to represent
# JavaScript `undefined`. The TS reference canonicalizer maps `undefined`
# → `null`; the Python equivalent is replacing the sentinel with None
# before serialization. We materialize this mapping per-vector during
# preprocessing.
UNDEFINED_MARKER = "UNDEFINED_MARKER"


def _substitute_undefined(obj: Any) -> Any:
    """Replace the UNDEFINED_MARKER sentinel with None recursively."""
    if isinstance(obj, dict):
        return {k: _substitute_undefined(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_undefined(v) for v in obj]
    if obj == UNDEFINED_MARKER:
        return None
    return obj


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["id"])
def test_vector_roundtrip(vector: dict[str, Any]) -> None:
    """Byte-identical canonical output per vector."""
    raw_input = vector["input"]
    expected = vector["canonical"]
    prepared = _substitute_undefined(raw_input)
    kind = vector.get("kind")
    if kind == "descriptor":
        actual = canonical_serialize_descriptor(prepared)
    else:
        # Envelope-v1.0 and the base canonical tests all serialize the
        # supplied dict (without a hashed_fields filter — vectors are
        # already shaped as the hashed subset).
        actual = canonical_serialize(prepared)
    assert actual == expected, (
        f"Vector {vector['id']} diverged.\n"
        f"  Expected: {expected!r}\n"
        f"  Actual:   {actual!r}"
    )


def test_corpus_non_empty() -> None:
    """Sanity: the corpus is present and parameterizes the suite."""
    assert len(VECTORS) > 0, "vectors/v1.0-canonical-vectors.json is empty"


# ---------------------------------------------------------------------------
# Negative corpus — inputs the canonicalizer MUST refuse.
#
# A canonicalizer that returns bytes for any of these is minting a digest for
# a value that has no canonical form. That is exactly how the lone-surrogate
# collision reached the corpus unnoticed: nothing in the vector file was ever
# allowed to fail.
#
# JSON text cannot carry a lone surrogate or NaN, so both arrive as sentinels
# and are materialized here — the same convention the TypeScript harness uses.
# ---------------------------------------------------------------------------

LONE_SURROGATE_MARKER = "LONE_SURROGATE_D800"
NAN_MARKER = "NAN_MARKER"


def _materialize_sentinels(obj: Any) -> Any:
    if isinstance(obj, str):
        if obj == NAN_MARKER:
            return float("nan")
        return obj.replace(LONE_SURROGATE_MARKER, "\ud800")
    if isinstance(obj, dict):
        return {k: _materialize_sentinels(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_materialize_sentinels(v) for v in obj]
    return obj


def test_negative_corpus_is_present() -> None:
    """A silently-empty negative corpus would make every test below vacuous."""
    assert len(NEGATIVE_VECTORS) >= 3


@pytest.mark.parametrize("vector", NEGATIVE_VECTORS, ids=lambda v: v["id"])
def test_negative_vector_is_refused(vector: dict[str, Any]) -> None:
    """Each negative vector must raise, with a message naming the reason."""
    prepared = _materialize_sentinels(vector["input"])
    with pytest.raises(Exception, match=re.compile(vector["expectError"], re.I)):
        canonical_serialize(prepared)
