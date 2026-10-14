"""Python half of vectors/store-generation-vectors.json (Record §4.1).

tests/cross-sdk/ts/store-generation-vectors.test.ts replays the file through
the engine. Every answer in the file is a recomputation, so Python recomputes
all of it with its own serializer and field-set constants: the generation each
stored digest recomputes under (the current set, then 0.7, then before 0.7),
the ``fieldSet`` fact of a mismatch, whether a record predates the signature
expectation, the first-record rule a store open applies, and the later
records a reader reports as tampered.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

import pytest
from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS,
    V1_HASHED_FIELDS_0_7,
    V1_HASHED_FIELDS_BEFORE_0_7,
    canonical_serialize,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "store-generation-vectors.json").read_text(encoding="utf-8"))
SETS = (("0.8", V1_HASHED_FIELDS), ("0.7", V1_HASHED_FIELDS_0_7), ("before-0.7", V1_HASHED_FIELDS_BEFORE_0_7))


def _under(payload: dict[str, Any], fields: Any) -> str:
    return hashlib.sha256(canonical_serialize(payload, list(fields)).encode("utf-8")).hexdigest()


def _generation(envelope: dict[str, Any]) -> str | None:
    for name, fields in SETS:
        if _under(envelope["payload"], fields) == envelope["integrity"]["canonicalDigest"]:
            return name
    return None


def _field_set(envelope: dict[str, Any]) -> str | None:
    for name, fields in SETS[1:]:
        if _under(envelope["payload"], fields) == envelope["integrity"]["canonicalDigest"]:
            return name
    return None


def test_the_field_sets() -> None:
    assert FILE["fieldSets"] == {name: list(fields) for name, fields in SETS}


@pytest.mark.parametrize("item", FILE["records"], ids=lambda c: c["case"])
def test_a_record(item: dict[str, Any]) -> None:
    envelope, expect = item["envelope"], item["expect"]
    assert _generation(envelope) == expect["generation"]
    assert (None if _generation(envelope) == "0.8" else _field_set(envelope)) == expect["fieldSet"]
    predates = "signoffExpectation" not in envelope["payload"] and _under(envelope["payload"], V1_HASHED_FIELDS_BEFORE_0_7) == envelope["integrity"]["canonicalDigest"]
    assert predates is expect["predatesSignoffExpectation"]


@pytest.mark.parametrize("item", FILE["stores"], ids=lambda c: c["case"])
def test_a_store(item: dict[str, Any]) -> None:
    generations = [_generation(e) for e in item["envelopes"]]
    expect = item["expect"]
    assert generations[0] == expect["generation"]
    assert (generations[0] == "0.8") is expect["opens"]
    if expect["opens"]:
        tampered = [{"index": i, "fieldSet": _field_set(e)} for i, e in enumerate(item["envelopes"]) if i > 0 and generations[i] != "0.8"]
        assert tampered == expect["tampered"]
