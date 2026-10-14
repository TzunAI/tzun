"""Cross-SDK canonical parity test.

For each vector in the corpus, computes the canonical bytes in both
TypeScript (via the harness) and Python (in-process), then asserts byte
equality. This is the strict form of cross-language canonical parity
(Record §3).
"""

from __future__ import annotations

import json
import pathlib

import pytest

VECTORS_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "vectors"
    / "v1.0-canonical-vectors.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())["vectors"]


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["id"])
def test_ts_python_byte_parity(vector, ts_invoke) -> None:  # type: ignore[no-untyped-def]
    """TS and Python produce identical bytes (Record §3)."""
    from tzun_sdk._generated.canonical import (
        canonical_serialize,
        canonical_serialize_descriptor,
    )

    UNDEFINED = "UNDEFINED_MARKER"

    def _substitute_undefined(obj):  # type: ignore[no-untyped-def]
        if isinstance(obj, dict):
            return {k: _substitute_undefined(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_substitute_undefined(v) for v in obj]
        if obj == UNDEFINED:
            return None
        return obj

    raw_input = vector["input"]
    prepared = _substitute_undefined(raw_input)
    kind = vector.get("kind")
    if kind == "descriptor":
        py_out = canonical_serialize_descriptor(prepared)
    else:
        py_out = canonical_serialize(prepared)
    action = "canonical-descriptor" if kind == "descriptor" else "canonical"
    ts_result = ts_invoke(
        {
            "action": action,
            "input": prepared,
        }
    )
    ts_out = ts_result["canonical"]
    assert py_out == ts_out, (
        f"Cross-SDK divergence on vector {vector['id']}:\n"
        f"  Python: {py_out!r}\n"
        f"  TS:     {ts_out!r}"
    )
