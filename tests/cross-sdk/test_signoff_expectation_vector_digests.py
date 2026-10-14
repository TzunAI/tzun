"""Python recomputation for vectors/signoff-expectation-vectors.json.

The file is replayed through each SDK's expectation check by
tests/ts/signoff-expectation-vectors.test.ts and
python/tests/verify/test_signoff_expectation_vectors.py. Here, independently of
TypeScript and of the Python check: every record's digest under the v1.0
hashed field set as revised in 0.8.0 (a ``verifications`` record whose digest
is said not to hold does not recompute; every other one does), every sign-off
statement's digest and challenge, and the record captured before 0.7.0
recomputing under the eight names of its time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
from typing import Any

import pytest
from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS,
    V1_HASHED_FIELDS_BEFORE_0_7,
    canonical_serialize,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "signoff-expectation-vectors.json").read_text(encoding="utf-8"))


def _holds(envelope: dict[str, Any], fields: Any = V1_HASHED_FIELDS) -> bool:
    canonical = canonical_serialize(envelope["payload"], list(fields))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest() == envelope["integrity"]["canonicalDigest"]


@pytest.mark.parametrize("item", FILE["checks"], ids=lambda c: c["case"])
def test_every_check_is_an_intact_record(item: dict[str, Any]) -> None:
    assert _holds(item["envelope"])


@pytest.mark.parametrize("item", FILE["verifications"], ids=lambda c: c["case"])
def test_a_verification(item: dict[str, Any]) -> None:
    assert _holds(item["envelope"]) is item["expect"]["verified"]


def test_the_record_captured_before_0_7() -> None:
    first = next(p for p in FILE["predates"] if p["expect"] is True)
    assert _holds(first["envelope"], V1_HASHED_FIELDS_BEFORE_0_7)
    assert not _holds(first["envelope"])


@pytest.mark.parametrize("item", [s for s in FILE["statementDigests"] if s["digest"] is not None], ids=lambda c: c["case"])
def test_a_statement(item: dict[str, Any]) -> None:
    statement = item["statement"]
    canonical = canonical_serialize(statement, list(statement))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert digest == item["digest"]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(b"tzun-signoff-v1" + digest.encode("ascii")).digest()).rstrip(b"=")
    assert challenge.decode("ascii") == item["challenge"]
