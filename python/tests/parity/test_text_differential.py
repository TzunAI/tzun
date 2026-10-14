"""The Python reader gives the engine's answer on every text of the differential corpus.

``text-differential.json.gz`` holds the texts of ``text_differential_cases.py``
with the answers the built engine gave after ``JSON.parse``
(``generate_text_differential.cjs``). Each text is read here as this SDK reads
a stored record (``js_json_loads``), and the canonical bytes, the digest, the
writer gate, the expectation and issuance checks and every ``verifyEnvelope``
row must be the engine's.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
from typing import Any

import pytest

from tests.parity import text_differential_cases
from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize
from tzun_sdk._record_rules import js_json_loads
from tzun_sdk._verify_rows import record_rule_fields
from tzun_sdk.mandate import check_mandate_issuance
from tzun_sdk.payload_rules import unhashed_payload_members
from tzun_sdk.record_rules import payload_record_rule_violation
from tzun_sdk.signoff_expectation import check_signoff_expectation

CASES = json.loads(gzip.decompress((pathlib.Path(__file__).parent / "text-differential.json.gz").read_bytes()))
ZERO = "0" * 64


def _canonical(payload: Any) -> dict[str, Any]:
    try:
        return {"ok": canonical_serialize(payload, list(V1_HASHED_FIELDS))}
    except Exception:
        return {"error": True}


def _rows(env: dict[str, Any], holds: bool) -> dict[str, Any]:
    expectation = check_signoff_expectation(env) if holds else {"valid": None, "reason": "digest_invalid"}
    r = record_rule_fields(env, holds, expectation)
    return {
        "holds": holds,
        "signoffExpectationValid": expectation["valid"],
        "signoffExpectationReason": expectation.get("reason"),
        "decider": r["decider"],
        "contributions": r["contributions"],
        "links": r["links"],
        "mandate": r.get("mandate"),
    }


def _python_answer(case: dict[str, Any]) -> dict[str, Any]:
    if case["kind"] == "payload":
        payload = js_json_loads(case["text"])
        canonical = _canonical(payload)
        digest = hashlib.sha256(canonical["ok"].encode("utf-8")).hexdigest() if "ok" in canonical else None
        env = {"payload": payload, "integrity": {"canonicalDigest": digest or ZERO, "chainLink": None}, "nonRepudiation": {}}
        verify = _rows(env, digest is not None)
        verify["unhashedPayloadMembers"] = unhashed_payload_members(payload)
        gate = payload_record_rule_violation(payload, system_record=case["systemRecord"])
        return {
            "canonical": canonical,
            "digest": digest,
            "gate": None if gate is None else {k: gate[k] for k in ("rule", "code", "field") if gate.get(k) is not None},
            "verify": verify,
        }
    env = js_json_loads(case["text"])
    canonical = _canonical(env["payload"])
    digest = hashlib.sha256(canonical["ok"].encode("utf-8")).hexdigest() if "ok" in canonical else ZERO
    return {
        "canonical": canonical,
        "digest": digest,
        "expectation": check_signoff_expectation(env),
        "issuance": check_mandate_issuance(env),
        "verify": _rows(env, "ok" in canonical and digest == env["integrity"]["canonicalDigest"]),
    }


def _norm(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def test_the_fixture_is_the_corpus_text_differential_cases_builds() -> None:
    built = {c["id"]: c for c in text_differential_cases.cases()}
    assert len(CASES) == len(built) > 1000
    stale = [
        c["id"]
        for c in CASES
        if c["id"] not in built or (c["kind"] == "payload" and built[c["id"]]["text"] != c["text"])
    ]
    assert not stale, f"{len(stale)} cases differ from text_differential_cases.py (regenerate): {stale[:10]}"


@pytest.mark.parametrize("kind", ["payload", "envelope"])
def test_python_reads_every_text_as_the_engine_does(kind: str) -> None:
    mismatches: list[str] = []
    for case in (c for c in CASES if c["kind"] == kind):
        got, expected = _norm(_python_answer(case)), _norm(case["ts"])
        for key in expected:
            if got.get(key) != expected[key]:
                mismatches.append(
                    f"{case['id']} {key}\n  engine: {json.dumps(expected[key])[:400]}\n  python: {json.dumps(got.get(key))[:400]}"
                )
    assert not mismatches, f"{len(mismatches)} answers differ:\n" + "\n".join(mismatches[:20])
