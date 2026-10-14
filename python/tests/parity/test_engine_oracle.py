"""The Python record rules give the TypeScript engine's answer on every case of the engine oracle.

``engine-oracle.json.gz`` holds about twelve thousand cases (``oracle_cases.py``)
with the answer the built engine gave each (``generate_engine_oracle.cjs``):
the worked examples W1 to W7 mutated one member at a time through the payload
gate and the member rules and reader rows; the mandate and issuance rows over
W6 and W5 with their material mutated; the mandate document, scope, limits,
confirmation and claim; predicates, JSON pointers and globs; agent
descriptors; assertion digests; freshness references, evidence-log origins,
expectation shapes and instants; and the contributions and links builders.
Each answer, refusals and their messages included, must be the engine's.

The file's arguments went through ``JSON.stringify``, which writes ``3.0`` as
``3``; the Python rules are run on each case's arguments as ``oracle_cases``
builds them, read back from their JSON text the way this SDK reads a stored
record (``js_json_loads``): a float spelling stays a float, and an integer past
2^53 - 1 is the double JavaScript reads. The engine answered the same values.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
from typing import Any

import pytest

from tests.parity import oracle_cases
from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize
from tzun_sdk._instant import js_date_parse_ms
from tzun_sdk._record_rules import js_json_loads
from tzun_sdk._verify_rows import record_rule_fields
from tzun_sdk.agents import agent_descriptor_digest, agent_descriptor_violation
from tzun_sdk.contributions import (
    ContributionsBuildError,
    build_contributions,
    check_contributions,
    contributions_violation,
)
from tzun_sdk.decider import check_decider, decider_violation, parse_freshness_reference
from tzun_sdk.links import (
    HeldLinkTarget,
    LinksBuildError,
    build_links,
    check_links,
    is_evidence_log_origin,
    link_record_violation,
    links_violation,
)
from tzun_sdk.mandate import (
    assertion_digest_result,
    check_mandate_issuance,
    check_mandate_limits,
    evaluate_mandate_confirm,
    evaluate_mandate_scope,
    evaluate_predicate,
    glob_match,
    mandate_cap_values,
    mandate_digest,
    mandate_document_violation,
    mandate_expired_at,
    plan_mandate_claim,
    revocation_instant_violation,
)
from tzun_sdk.payload_rules import (
    earlier_field_set,
    record_field_set_generation,
    unhashed_payload_members,
)
from tzun_sdk.record_rules import payload_record_rule_violation
from tzun_sdk.signoff_expectation import check_signoff_expectation, signoff_expectation_violation

ORACLE = json.loads(gzip.decompress((pathlib.Path(__file__).parent / "engine-oracle.json.gz").read_bytes()))

#: Each case's arguments as Python reads their JSON text, by case id.
NATIVE_ARGS: dict[str, Any] = {c["id"]: js_json_loads(json.dumps(c["args"])) for c in oracle_cases.cases()}

W6_MANDATE_LINK_TARGET = {
    "digest": "fb29b130c25c42d6ac72f1ea4123f0c542d6fefed9cfcaaa6b9a1b5e74af9844",
    "evidenceId": "7a2c0d4e-1111-4a1a-8a1a-000000000001",
    "locator": {"origin": "test.insurer.example/9a8b7c6d5e4f30211203f4e5d6c7b8a9/evidence/636c61696d73", "seq": 1},
}


def _payload_rows(payload: Any, system_record: str | None, env: dict[str, Any]) -> dict[str, Any]:
    p = payload if isinstance(payload, dict) else {}
    return {
        "gate": payload_record_rule_violation(payload, system_record=system_record),
        "decider": decider_violation(p.get("decider")),
        "contributions": contributions_violation(
            p.get("contributions"), {"decider": p.get("decider"), "action": p.get("action"), "reason": p.get("reason")}
        ),
        "links": links_violation(p.get("links"), p),
        "linkRecord": link_record_violation(payload),
        "checkDecider": check_decider(env),
        "checkContributions": check_contributions(payload),
        "checkLinks": check_links(payload),
        "unhashed": unhashed_payload_members(payload),
        "generation": record_field_set_generation(env),
        "earlier": earlier_field_set(payload, env["integrity"]["canonicalDigest"]),
    }


def _envelope_rows(env: dict[str, Any]) -> dict[str, Any]:
    payload = env.get("payload") if isinstance(env.get("payload"), dict) else {}
    stored = env.get("integrity", {}).get("canonicalDigest")
    try:
        digest_holds = (
            hashlib.sha256(canonical_serialize(payload, list(V1_HASHED_FIELDS)).encode("utf-8")).hexdigest() == stored
        )
    except ValueError:
        digest_holds = False
    expectation = check_signoff_expectation(env) if digest_holds else {"valid": None, "reason": "digest_invalid"}
    rows = record_rule_fields(env, digest_holds, expectation)
    return {
        "expectation": check_signoff_expectation(env),
        "issuance": check_mandate_issuance(env),
        "verify": {
            "digest": digest_holds,
            "signoffExpectationValid": expectation["valid"],
            "signoffExpectationReason": expectation.get("reason"),
            "decider": rows["decider"],
            "contributions": rows["contributions"],
            "links": rows["links"],
            "mandate": rows.get("mandate"),
            "unhashedPayloadMembers": unhashed_payload_members(payload),
            "fieldSet": None if digest_holds else earlier_field_set(payload, stored),
        },
    }


def _document_rows(doc: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "prepare": mandate_document_violation(doc),
        "reader": mandate_document_violation(doc, prepare=False),
        "digest": mandate_digest(doc),
        "scope": evaluate_mandate_scope(doc, payload),
        "limits": check_mandate_limits(doc, payload),
        "confirm": evaluate_mandate_confirm(doc, payload),
        "caps": mandate_cap_values(doc, payload),
        "plan": plan_mandate_claim(
            document=doc,
            mandate={"state": "open", "used": 40, "totals": {"paid": 5000000}},
            payload={**payload, "signoffExpectation": None, "links": None},
            assertion_digest="79aafeb32c197be65d3b27c7b1cc469beff89e8650d1a84e02b437ec7937966d",
            issuance=W6_MANDATE_LINK_TARGET,
        ),
    }


def _agent_rows(d: Any) -> dict[str, Any]:
    reader = agent_descriptor_violation(d, limits=False)
    return {
        "violation": agent_descriptor_violation(d),
        "reader": reader,
        "digest": agent_descriptor_digest(d) if reader is None else None,
    }


def _build_contributions(value: Any, ctx: Any) -> dict[str, Any]:
    try:
        return {"ok": build_contributions(value, ctx)}
    except ContributionsBuildError as exc:
        error: dict[str, Any] = {"name": "ContributionsBuildError", "code": exc.code, "field": exc.field}
        if exc.step is not None:
            error["step"] = exc.step
        return {"error": error}


def _held(entry: Any) -> HeldLinkTarget | None:
    if entry is None:
        return None
    return HeldLinkTarget(payload=entry["payload"], digest=entry["digest"], origin=entry["origin"])


def _build_links(inputs: Any, options: dict[str, Any]) -> dict[str, Any]:
    try:
        return {
            "ok": build_links(
                inputs,
                held=[_held(h) for h in options.get("held") or []],
                allow_reserved=options.get("allowReserved") or (),
                link_record=bool(options.get("linkRecord")),
                context=options.get("context"),
            )
        }
    except LinksBuildError as exc:
        error: dict[str, Any] = {"name": "LinksBuildError", "code": exc.code, "field": exc.field}
        if exc.link is not None:
            error["link"] = exc.link
        if exc.rule is not None:
            error["rule"] = exc.rule
        return {"error": error}


RUN = {
    "payloadRows": _payload_rows,
    "envelopeRows": _envelope_rows,
    "documentRows": _document_rows,
    "evaluatePredicate": evaluate_predicate,
    "globMatch": glob_match,
    "agentRows": _agent_rows,
    "assertionDigestResult": assertion_digest_result,
    "parseFreshnessReference": parse_freshness_reference,
    "isEvidenceLogOrigin": is_evidence_log_origin,
    "signoffExpectationViolation": signoff_expectation_violation,
    "revocationInstantViolation": revocation_instant_violation,
    "mandateExpiredAt": mandate_expired_at,
    "buildContributions": _build_contributions,
    "buildLinks": _build_links,
}


def _json(value: Any) -> Any:
    """As JSON reads it: tuples are lists, ``3.0`` equals ``3``."""
    return json.loads(json.dumps(value))


def _floats(value: Any) -> int:
    if isinstance(value, float):
        return 1
    if isinstance(value, dict):
        return sum(_floats(v) for v in value.values())
    if isinstance(value, list):
        return sum(_floats(v) for v in value)
    return 0


def test_the_oracle_covers_every_function() -> None:
    assert len(ORACLE) > 10000
    assert {c["fn"] for c in ORACLE} == set(RUN)


def test_the_oracle_is_the_corpus_oracle_cases_builds() -> None:
    """Every case of the file is a case of ``oracle_cases`` with the same arguments; regenerate the file when not."""
    stale = [c["id"] for c in ORACLE if c["id"] not in NATIVE_ARGS or NATIVE_ARGS[c["id"]] != c["args"]]
    assert not stale, f"{len(stale)} oracle cases differ from oracle_cases.py (regenerate): {stale[:10]}"
    # The float spellings reach the Python rules as floats.
    assert sum(_floats(NATIVE_ARGS[c["id"]]) for c in ORACLE) > 100


@pytest.mark.parametrize("fn", sorted(RUN))
def test_python_gives_the_engines_answer(fn: str) -> None:
    mismatches: list[str] = []
    for case in (c for c in ORACLE if c["fn"] == fn):
        got = _json(RUN[fn](*NATIVE_ARGS.get(case["id"], case["args"])))
        if got != case["expect"]:
            mismatches.append(f"{case['id']}\n  engine: {json.dumps(case['expect'])[:600]}\n  python: {json.dumps(got)[:600]}")
    assert not mismatches, f"{len(mismatches)} cases differ:\n" + "\n".join(mismatches[:20])


def test_instants_are_read_as_date_parse_reads_them() -> None:
    assert js_date_parse_ms("2026-02-30T00:00:00Z") == 1772409600000
    assert js_date_parse_ms("2026-01-01T24:00:00Z") == 1767312000000
    assert js_date_parse_ms("2026-01-01T23:59:60Z") is None
