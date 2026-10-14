"""Python half of vectors/links-vectors.json (Record §8).

tests/cross-sdk/ts/links-vectors.test.ts replays the file through the engine.
Here, independently of TypeScript:

  - the set rule (strictly increasing by ``(rel, target.digest)``, compared by
    UTF-8 bytes, no repeated pair) is recomputed for every list of well-formed
    links, and agrees with whether the reader called it ``not_a_set``;
  - every held target's digest is recomputed under the v1.0 hashed field set,
    and differs exactly where the reader names ``member: digest``;
  - every list the builder built is a set, and every relation the registry
    names is a registered name;
  - the generated strict ``Link`` model takes every well-formed link and
    refuses every link whose refusal is a type, member or pattern rule;
  - and, once the Python SDK has ``tzun_sdk.links``, its rules give every
    refusal and row the file states.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import pathlib
from typing import Any

import pytest
from pydantic import ValidationError
from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "links-vectors.json").read_text(encoding="utf-8"))
GROUPS = ("shapes", "profiles", "listLevel", "targets")
CASES = [(group, case) for group in GROUPS for case in FILE[group]]
#: Grammar refusals the generated model enforces: a type, a member or a pattern.
MODEL_CODES = {"link_unknown_members", "link_missing_members", "invalid_relation", "invalid_target", "invalid_target_digest", "too_many_attrs"}
WELL_FORMED_KEYS = {"rel", "target", "attrs"}


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_serialize(payload, list(V1_HASHED_FIELDS)).encode("utf-8")).hexdigest()


def _key(link: dict[str, Any]) -> tuple[bytes, bytes]:
    return (link["rel"].encode("utf-8"), link["target"]["digest"].encode("utf-8"))


def _is_set(links: list[dict[str, Any]]) -> bool:
    keys = [_key(link) for link in links]
    return all(a < b for a, b in itertools.pairwise(keys))


def _shaped(links: Any) -> bool:
    return (
        isinstance(links, list)
        and len(links) > 0
        and all(
            isinstance(link, dict)
            and set(link) == WELL_FORMED_KEYS
            and isinstance(link["rel"], str)
            and isinstance(link["target"], dict)
            and isinstance(link["target"].get("digest"), str)
            for link in links
        )
    )


@pytest.mark.parametrize(("group", "item"), CASES, ids=lambda c: c if isinstance(c, str) else c["case"])
def test_the_set_rule(group: str, item: dict[str, Any]) -> None:
    links = item["payload"]["links"]
    if not _shaped(links):
        return
    reader = item["reader"]
    flagged = reader.get("reason") == "malformed_links" and reader.get("rule") == "not_a_set"
    other_grammar = reader.get("reason") == "malformed_links" and not flagged
    if not other_grammar:
        assert _is_set(links) is not flagged


@pytest.mark.parametrize(("group", "item"), [c for c in CASES if "resolver" in c[1]], ids=lambda c: c if isinstance(c, str) else c["case"])
def test_held_targets_recompute(group: str, item: dict[str, Any]) -> None:
    mismatched = {
        row["rel"] + ":" + item["payload"]["links"][row["index"]]["target"]["digest"]
        for row in item["reader"].get("relations", [])
        if row.get("reason") == "link_target_mismatch" and row.get("member") == "digest"
    }
    for held in item["resolver"].get("held", []):
        named = any(m.endswith(held["digest"]) for m in mismatched)
        assert (_digest(held["payload"]) == held["digest"]) is not named


@pytest.mark.parametrize("item", [c for c in FILE["capture"] if "links" in c], ids=lambda c: c["case"])
def test_a_built_list_is_a_set(item: dict[str, Any]) -> None:
    assert _is_set(item["links"])


def test_the_registry() -> None:
    assert FILE["registry"] == sorted(FILE["registry"])
    assert len(FILE["registry"]) == 13
    assert {"derivedFrom", "root", "mandate", "revokes", "subject", "closes", "fanoutOf"} <= set(FILE["registry"])


@pytest.mark.parametrize("item", FILE["shapes"], ids=lambda c: c["case"])
def test_the_strict_model_holds_the_grammar_it_can(item: dict[str, Any]) -> None:
    from tzun_sdk._generated.models import Link

    links = item["payload"]["links"]
    reader = item["reader"]
    if not isinstance(links, list) or not links:
        return
    if reader["outcome"] == "checked-correct" or reader.get("reason") == "link_rule_violated":
        for link in links:
            Link.model_validate(link)
    elif reader.get("reason") == "malformed_links" and reader.get("rule") in MODEL_CODES:
        with pytest.raises(ValidationError):
            Link.model_validate(links[reader["failedLink"]])


@pytest.mark.parametrize(("group", "item"), CASES, ids=lambda c: c if isinstance(c, str) else c["case"])
def test_the_python_sdk_refuses_what_the_engine_refuses(group: str, item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    links_violation = sdk_rule("links", "links_violation")
    got = projection(links_violation(item["payload"]["links"], item["payload"]), ("code", "field", "rule"))
    assert got == item["writer"]


@pytest.mark.parametrize(("group", "item"), [c for c in CASES if "resolver" not in c[1]], ids=lambda c: c if isinstance(c, str) else c["case"])
def test_the_python_sdk_gives_each_row(group: str, item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    check_links = sdk_rule("links", "check_links")
    got = check_links(item["payload"])
    keys = ("outcome", "reason", "rule", "failedLink", "count", "extensions")
    assert projection(got, keys) == projection(item["reader"], keys)
    relations = got["relations"] if isinstance(got, dict) else got.relations
    row_keys = ("index", "rel", "outcome", "reason", "rule", "member", "missing")
    assert [projection(r, row_keys) for r in relations] == [projection(r, row_keys) for r in item["reader"]["relations"]]
