"""Python half of vectors/contributions-vectors.json (Record §7).

tests/cross-sdk/ts/contributions-vectors.test.ts replays the file through the
engine. Here, independently of TypeScript:

  - every output digest and step digest is recomputed (``sha256:`` and the hex
    SHA-256 of the canonical bytes of the whole value);
  - each built member's step chain, its sorted sets, and the outputs the
    builder fills are recomputed;
  - in the reader's checks, the step chain a ``step_chain_broken`` row names,
    the models a correct row lists, and the digest a ``decided_output_differs``
    row names are recomputed;
  - the generated strict ``Contributions`` model takes every valid member and
    refuses every one whose refusal is a type, member or pattern rule;
  - and, once the Python SDK has ``tzun_sdk.contributions``, its rules give
    every refusal and row the file states.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import pathlib
from typing import Any

import pytest
from pydantic import ValidationError
from tzun_sdk._generated.canonical import _serialize_value

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "contributions-vectors.json").read_text(encoding="utf-8"))
#: Refusals the generated model enforces: a type, a member, an enumeration or a pattern.
MODEL_CODES = {
    "not_an_object",
    "unknown_members",
    "missing_members",
    "invalid_pipeline",
    "step_unknown_members",
    "step_missing_members",
    "invalid_output",
    "invalid_verdict",
    "invalid_step_ai_bom",
}


def _prefixed(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_serialize_value(value).encode("utf-8")).hexdigest()


def _utf8_sorted(values: list[str]) -> bool:
    encoded = [v.encode("utf-8") for v in values]
    return all(a < b for a, b in itertools.pairwise(encoded))


def _broken_at(steps: list[dict[str, Any]]) -> int | None:
    for i, step in enumerate(steps):
        if step["prev"] != (None if i == 0 else _prefixed(steps[i - 1])):
            return i
    return None


@pytest.mark.parametrize("item", FILE["outputDigests"], ids=lambda c: c["label"])
def test_output_digest(item: dict[str, Any]) -> None:
    assert _prefixed(item["value"]) == item["digest"]


@pytest.mark.parametrize("item", FILE["stepDigests"], ids=lambda c: c["label"])
def test_step_digest(item: dict[str, Any]) -> None:
    assert _prefixed(item["step"]) == item["digest"]


@pytest.mark.parametrize("item", [b for b in FILE["builder"] if "built" in b], ids=lambda c: c["case"])
def test_a_built_member(item: dict[str, Any]) -> None:
    built = item["built"]
    context = item["context"]
    assert _broken_at(built["steps"]) is None
    assert _utf8_sorted(built["externals"])
    for i, step in enumerate(built["steps"]):
        assert _utf8_sorted(step["inputs"]), i
        source = item["input"]["steps"][i]
        if "outputOf" in source:
            assert step["output"] == _prefixed(source["outputOf"])
        elif "output" not in source and step["role"].split(":")[0] == "decide":
            assert step["output"] == _prefixed({"action": context["action"], "reason": context["reason"]})
            assert step["reason"] == source.get("reason", context["reason"])
    proposals = [i for i, s in enumerate(built["steps"]) if s["role"].split(":")[0] == "propose" and "output" not in item["input"]["steps"][i]]
    if proposals:
        assert built["steps"][proposals[-1]]["output"] == _prefixed(context["aiOutput"])


@pytest.mark.parametrize("item", FILE["checks"], ids=lambda c: c["case"])
def test_a_reader_check(item: dict[str, Any]) -> None:
    expect = item["expect"]
    contributions = item["payload"]["contributions"]
    if expect.get("reason") == "step_chain_broken":
        assert _broken_at(contributions["steps"]) == expect["failedStep"]
    if expect["outcome"] == "checked-correct":
        steps = contributions["steps"]
        assert _broken_at(steps) is None
        models: list[str] = []
        for step in steps:
            digest = (step["aiBom"] or {}).get("modelDescriptorDigest")
            if digest is not None and digest not in models:
                models.append(digest)
        assert models == expect["models"]
        if expect["binding"].get("reason") == "decided_output_differs":
            assert _prefixed(item["payload"]["aiOutput"]) != expect["binding"]["failedDigest"]


@pytest.mark.parametrize("item", FILE["shapes"], ids=lambda c: c["case"])
def test_the_strict_model_holds_the_writer_rules_it_can(item: dict[str, Any]) -> None:
    from tzun_sdk._generated.models import Contributions

    violation = item["violation"]
    if item["value"] is None:
        return
    if violation is None:
        Contributions.model_validate(item["value"])
    elif violation["code"] in MODEL_CODES:
        with pytest.raises(ValidationError):
            Contributions.model_validate(item["value"])


@pytest.mark.parametrize("item", FILE["shapes"], ids=lambda c: c["case"])
def test_the_python_sdk_refuses_what_the_engine_refuses(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    contributions_violation = sdk_rule("contributions", "contributions_violation")
    got = projection(contributions_violation(item["value"], item["context"]), ("code", "field", "step"))
    assert got == item["violation"]


@pytest.mark.parametrize("item", FILE["checks"], ids=lambda c: c["case"])
def test_the_python_sdk_gives_each_row(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    check_contributions = sdk_rule("contributions", "check_contributions")
    got = check_contributions(item["payload"])
    assert projection(got, ("outcome", "reason", "failedStep")) == projection(item["expect"], ("outcome", "reason", "failedStep"))
    binding = got["binding"] if isinstance(got, dict) else got.binding
    keys = ("outcome", "reason", "approvals", "staleApprovals", "uncoveredReviews", "decisionBinding")
    assert projection(binding, keys) == projection(item["expect"]["binding"], keys)
