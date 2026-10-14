"""Python half of vectors/agent-descriptor-vectors.json (Record §6.9).

tests/cross-sdk/ts/agent-descriptor-vectors.test.ts replays the file through
the engine. Here, independently of TypeScript:

  - every descriptor's canonical bytes are recomputed with its sets sorted by
    UTF-8 bytes (``sorted()`` on ``str`` orders by code point, which is the
    same order; JavaScript's default sort is not), and its digest;
  - the writer limits are recomputed, lengths in UTF-16 code units
    (``len(s.encode("utf-16-le")) // 2``): a descriptor a writer refuses for
    a limit breaks at least one, and one it accepts breaks none;
  - the generated strict ``AgentDescriptor`` model takes every well-formed
    descriptor;
  - and, once the Python SDK has ``tzun_sdk.agents``, its rules give every
    answer the file states.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Any

import pytest
from tzun_sdk._generated.canonical import _serialize_value

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "agent-descriptor-vectors.json").read_text(encoding="utf-8"))


def _sorted(d: dict[str, Any]) -> dict[str, Any]:
    out = dict(d)
    out["identities"] = sorted(d["identities"])
    out["keys"] = sorted(d["keys"], key=lambda k: k["kid"])
    out["models"] = sorted(d["models"])
    if d["runtime"] is not None:
        out["runtime"] = {**d["runtime"], "measurements": sorted(d["runtime"]["measurements"])}
    return out


def _units(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _materialize(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("LONE_SURROGATE_D800", "\ud800")
    if isinstance(value, list):
        return [_materialize(v) for v in value]
    if isinstance(value, dict):
        return {k: _materialize(v) for k, v in value.items()}
    return value


def _limits_broken(d: dict[str, Any]) -> list[str]:
    broken = []
    runtime = d["runtime"] or {"format": "x", "measurements": []}
    for name, values in (("identities", d["identities"]), ("keys", d["keys"]), ("models", d["models"]), ("measurements", runtime["measurements"])):
        if len(values) > 64:
            broken.append(f"{name}: more than 64")
    strings = [d["name"], d["operator"]["organization"], runtime["format"], *d["identities"], *runtime["measurements"]]
    if any(_units(s) > 256 for s in strings):
        broken.append("a string over 256 UTF-16 code units")
    if any(k["attestation"] is not None and _units(k["attestation"]) > 8192 for k in d["keys"]):
        broken.append("an attestation over 8,192")
    if any(any(0xD800 <= ord(c) <= 0xDFFF for c in s) for s in strings):
        broken.append("a lone surrogate")
    else:
        size = len(_serialize_value(_sorted(d)).encode("utf-8"))
        if size > 16 * 1024:
            broken.append("over 16 KiB")
    return broken


@pytest.mark.parametrize("item", FILE["digests"], ids=lambda c: c["case"])
def test_a_digest(item: dict[str, Any]) -> None:
    from tzun_sdk._generated.models import AgentDescriptor

    canonical = _serialize_value(_sorted(item["descriptor"]))
    assert canonical == item["canonical"]
    assert len(canonical.encode("utf-8")) == item["byteLength"]
    assert "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest() == item["digest"]
    AgentDescriptor.model_validate(item["descriptor"])


def test_the_example_is_the_agent_reference_of_the_worked_examples() -> None:
    assert FILE["digests"][0]["byteLength"] == 729
    assert FILE["digests"][0]["digest"] == "sha256:eed92bfa7577d6f66e26fed38c35ebbec3b663a25fd6cc4c6af7d8c7475a250f"


@pytest.mark.parametrize("item", [v for v in FILE["violations"] if v["grammar"]], ids=lambda c: c["case"])
def test_the_writer_limits(item: dict[str, Any]) -> None:
    broken = _limits_broken(_materialize(item["descriptor"]))
    assert (broken == []) is item["writer"], broken


@pytest.mark.parametrize("item", FILE["violations"], ids=lambda c: c["case"])
def test_the_python_sdk_refuses_what_the_engine_refuses(item: dict[str, Any], sdk_rule) -> None:  # type: ignore[no-untyped-def]
    violation = sdk_rule("agents", "agent_descriptor_violation")
    descriptor = _materialize(item["descriptor"])
    assert (violation(descriptor, limits=False) is None) is item["grammar"]
    assert (violation(descriptor) is None) is item["writer"]


@pytest.mark.parametrize("item", FILE["digests"], ids=lambda c: c["case"])
def test_the_python_sdk_digests_each_descriptor(item: dict[str, Any], sdk_rule) -> None:  # type: ignore[no-untyped-def]
    assert sdk_rule("agents", "agent_descriptor_digest")(item["descriptor"]) == item["digest"]
