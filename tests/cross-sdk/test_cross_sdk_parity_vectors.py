"""Python half of vectors/cross-sdk-parity-vectors.json (Record §2.2).

Each case is a payload as JSON text, parsed here with ``json.loads``, which
reads ``1.0`` and ``1e0`` as floats and ``"3"`` as a string: the canonical
bytes, the digest, and the members outside the twelve names must be the ones
the engine computed from ``JSON.parse`` of the same text
(tests/cross-sdk/ts/cross-sdk-parity-vectors.test.ts). Once the Python SDK
has its writer gate and its rows, they must give the file's answers too.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

import pytest
from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "cross-sdk-parity-vectors.json").read_text(encoding="utf-8"))
PAYLOAD_MEMBERS = {"schemaVersion", *V1_HASHED_FIELDS}


@pytest.mark.parametrize("item", FILE["cases"], ids=lambda c: c["case"])
def test_bytes_and_digest(item: dict[str, Any]) -> None:
    payload = json.loads(item["json"])
    canonical = canonical_serialize(payload, list(V1_HASHED_FIELDS))
    assert canonical == item["canonical"]
    assert item["contains"] in canonical
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == item["digest"]


@pytest.mark.parametrize("item", FILE["cases"], ids=lambda c: c["case"])
def test_members_outside_the_format(item: dict[str, Any]) -> None:
    payload = json.loads(item["json"])
    outside = sorted((k for k in payload if k not in PAYLOAD_MEMBERS), key=lambda k: k.encode("utf-8"))
    assert outside == item["unhashedPayloadMembers"]


@pytest.mark.parametrize("item", FILE["cases"], ids=lambda c: c["case"])
def test_the_python_sdk_writer_gate(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    gate = sdk_rule("record_rules", "payload_record_rule_violation")
    assert projection(gate(json.loads(item["json"])), ("rule", "code")) == item["writer"]
