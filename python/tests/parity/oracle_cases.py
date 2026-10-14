"""The engine-oracle corpus: the inputs the TypeScript engine and the Python rules must answer alike.

Each case is ``{"id", "fn", "args"}``: ``fn`` names an engine function, and
``args`` are its arguments as JSON. The corpus is built from the worked
examples W1 to W7 (``vectors/v1.0-worked-example-vectors.json``) by mutating
one member at a time: removed, ``null``, the wrong type, a boundary string, a
float spelling of an integer, a trailing newline. ``generate_engine_oracle.cjs``
runs every case through the built engine (``packages/engine/dist``) and
``engine-oracle.json.gz`` holds the cases with the engine's answers;
``test_engine_oracle.py`` holds the Python rules to them.

Regenerate (from the repository root, after ``pnpm --filter @tzun/engine build``)::

    cases="$(mktemp)"
    python3 python/tests/parity/oracle_cases.py > "$cases"
    node python/tests/parity/generate_engine_oracle.cjs "$cases" \\
      | gzip -9n > python/tests/parity/engine-oracle.json.gz
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys
from collections.abc import Iterator
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS = json.loads((ROOT / "vectors" / "v1.0-worked-example-vectors.json").read_text(encoding="utf-8"))

#: Replacement values for a member, by name. ``"<delete>"`` removes the key.
DELETE = "<delete>"
VALUES: dict[str, Any] = {
    "delete": DELETE,
    "null": None,
    "int3": 3,
    "float3": 3.0,
    "true": True,
    "empty": "",
    "space": " ",
    "x": "x",
    "nl": "acct:u-4821\n",
    "list": [],
    "obj": {},
    "hex": "a" * 64,
    "HEX": "A" * 64,
    "pfx": "sha256:" + "b" * 64,
    "big": 2**53,
    "neg": -1,
    "frac": 1.5,
}


def _records() -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in VECTORS["records"]}


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    """Every path into ``value``: objects by key, lists by index."""
    if isinstance(value, dict):
        for key in value:
            yield (*prefix, key)
            yield from _paths(value[key], (*prefix, key))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield (*prefix, i)
            yield from _paths(item, (*prefix, i))


def mutate(value: Any, path: list[Any], replacement: Any) -> Any:
    """A deep copy of ``value`` with the member at ``path`` replaced (or removed for ``DELETE``)."""
    out = copy.deepcopy(value)
    parent = out
    for key in path[:-1]:
        parent = parent[key]
    last = path[-1]
    if replacement == DELETE:
        if isinstance(parent, dict):
            parent.pop(last, None)
        else:
            parent.pop(last)
    else:
        parent[last] = copy.deepcopy(replacement)
    return out


def _system_record(payload: dict[str, Any]) -> str | None:
    return {"tzun:mandate": "mandate", "tzun:link": "link"}.get(payload.get("aiSystemId"))


def _payload_cases() -> Iterator[dict[str, Any]]:
    """Every member of every worked example, mutated, through the payload rules and the reader rows."""
    for rid, record in _records().items():
        payload = record["payload"]
        paths = [p for p in _paths(payload) if p[0] not in ("aiOutput",) or len(p) == 1]
        for path in paths:
            for name, value in VALUES.items():
                mutated = mutate(payload, list(path), value)
                env = {"payload": mutated, "integrity": {"canonicalDigest": record["digest"]}}
                case = f"{rid}:{'.'.join(map(str, path))}={name}"
                yield {"id": case, "fn": "payloadRows", "args": [mutated, _system_record(payload), env]}


def _mandate_block() -> dict[str, Any]:
    return {
        "statement": VECTORS["mandateStatements"][0]["statement"],
        "assertion": VECTORS["mandateAssertions"][0]["assertion"],
        "assertionTimestamp": None,
        "document": VECTORS["mandateDocuments"][0]["document"],
    }


def _envelope_cases() -> Iterator[dict[str, Any]]:
    """The mandate and issuance rows over W6 and W5 with their material, member by member."""
    records = _records()
    w6 = records["W6"]
    w5 = records["W5"]
    block = _mandate_block()
    base6 = {
        "envelopeVersion": "e1",
        "payload": w6["payload"],
        "integrity": {"canonicalDigest": w6["digest"], "chainLink": None},
        "nonRepudiation": {"mandate": block},
        "custodyChain": [],
        "attestationStatus": "none",
    }
    base5 = {
        "envelopeVersion": "e1",
        "payload": w5["payload"],
        "integrity": {"canonicalDigest": w5["digest"], "chainLink": None},
        "nonRepudiation": {"mandateIssuance": block},
        "custodyChain": [],
        "attestationStatus": "none",
    }
    for rid, base in (("W6", base6), ("W5", base5)):
        yield {"id": f"{rid}:env", "fn": "envelopeRows", "args": [base]}
        for path in _paths(base["nonRepudiation"]):
            for name in ("delete", "null", "x", "obj", "int3"):
                env = mutate(base, ["nonRepudiation", *path], VALUES[name])
                yield {"id": f"{rid}:nr.{'.'.join(map(str, path))}={name}", "fn": "envelopeRows", "args": [env]}
        for path in [p for p in _paths(base["payload"]) if p[0] in ("signoffExpectation", "aiOutput", "decider")]:
            for name in ("delete", "null", "x", "int3", "float3"):
                env = mutate(base, ["payload", *path], VALUES[name])
                yield {"id": f"{rid}:p.{'.'.join(map(str, path))}={name}", "fn": "envelopeRows", "args": [env]}
    # A record carrying a mandate block under a non-mandate expectation (row 1a).
    w3 = records["W3"]
    env = {"payload": w3["payload"], "integrity": {"canonicalDigest": w3["digest"]}, "nonRepudiation": {"mandate": block}}
    yield {"id": "W3:row-1a", "fn": "envelopeRows", "args": [env]}


def _document_cases() -> Iterator[dict[str, Any]]:
    document = VECTORS["mandateDocuments"][0]["document"]
    payload = _records()["W6"]["payload"]
    for path in [(), *_paths(document)]:
        # No 2**53 here: the Python canonical serializer refuses an integer past
        # 2**53 - 1 (canonical.py), where JavaScript writes the double it holds,
        # so the digest of such a (malformed) document is not comparable.
        for name in ("delete", "null", "x", "int3", "float3", "true", "list", "obj", "neg") if path else ("none",):
            doc = document if not path else mutate(document, list(path), VALUES[name])
            yield {"id": f"doc:{'.'.join(map(str, path))}={name}", "fn": "documentRows", "args": [doc, payload]}


_PREDICATE_SUBJECTS: list[Any] = [
    None, True, False, 0, 1, 1.0, 2, 3.5, -1, 2**53 - 1, 2**53, "", "a", "approve", "ab/cd", "a/b/c", "x" * 4097,
    [], [1, 2], ["a", "b"], ["approve"], [None], [True], {"k": 1}, "😀", "a😀b",
]
_PREDICATES: list[dict[str, Any]] = [
    {"op": "eq", "value": 1}, {"op": "eq", "value": True}, {"op": "eq", "value": "a"}, {"op": "ne", "value": "a"},
    {"op": "ne", "value": 1}, {"op": "lt", "value": 2}, {"op": "le", "value": 1}, {"op": "gt", "value": 0},
    {"op": "ge", "value": 2**53 - 1}, {"op": "in", "value": ["a", "approve"]}, {"op": "notIn", "value": ["a"]},
    {"op": "prefix", "value": "a"}, {"op": "glob", "value": ["a*"]}, {"op": "glob", "value": ["**/c"]},
    {"op": "glob", "value": ["a/*/c"]}, {"op": "glob", "value": ["?"]}, {"op": "glob", "value": ["a?b"]},
    {"op": "eq", "value": None}, {"op": "lt", "value": 1.5}, {"op": "in", "value": []}, {"op": "in", "value": ["b", "a"]},
    {"op": "bogus", "value": 1}, {"op": "eq", "value": 1.0}, {"op": "glob", "value": ["*" * 300]},
]


def _predicate_cases() -> Iterator[dict[str, Any]]:
    for i, subject in enumerate(_PREDICATE_SUBJECTS):
        for j, pred in enumerate(_PREDICATES):
            for quant in (None, "all", "any", "some"):
                predicate = {"path": "/s", "op": pred["op"], "value": pred["value"], "quant": quant}
                yield {"id": f"pred:{i}:{j}:{quant}", "fn": "evaluatePredicate", "args": [predicate, {"s": subject}]}
    for path in ("/s", "/s/0", "/s/01", "/s/-", "/a~1b", "/a~0b", "/a~2b", "s", "", "/", "/s/1"):
        predicate = {"path": path, "op": "eq", "value": "a", "quant": None}
        payload = {"s": ["a", "b"], "a/b": "a", "a~b": "a", "": "a"}
        yield {"id": f"ptr:{path}", "fn": "evaluatePredicate", "args": [predicate, payload]}
    globs = [("*", "abc"), ("*", "a/b"), ("**", "a/b/c"), ("a/**", "a"), ("a/**/b", "a/b"), ("a/**/b", "a/x/y/b"),
             ("**/b", "b"), ("a*c", "abbc"), ("a*c", "ab/c"), ("?b", "😀b"), ("*a*a*a*a*b", "aaaaaaaaaaaaaaaaaa"),
             ("a?c", "ac"), ("", ""), ("", "a"), ("a/", "a/"), ("**/**", "x")]
    for k, (pattern, subject) in enumerate(globs):
        yield {"id": f"glob:{k}", "fn": "globMatch", "args": [pattern, subject]}


def _agent_cases() -> Iterator[dict[str, Any]]:
    for k, entry in enumerate(VECTORS["agentDescriptors"]):
        descriptor = entry["descriptor"]
        yield {"id": f"agent:{k}", "fn": "agentRows", "args": [descriptor]}
        for path in _paths(descriptor):
            for name in ("delete", "null", "x", "empty", "int3", "list", "pfx", "hex"):
                yield {
                    "id": f"agent:{k}:{'.'.join(map(str, path))}={name}",
                    "fn": "agentRows",
                    "args": [mutate(descriptor, list(path), VALUES[name])],
                }


def _assertion_cases() -> Iterator[dict[str, Any]]:
    for k, entry in enumerate(VECTORS["assertionDigests"] + VECTORS["mandateAssertions"]):
        assertion = entry["assertion"]
        yield {"id": f"assertion:{k}", "fn": "assertionDigestResult", "args": [assertion]}
        for key in assertion:
            for name, value in (("delete", DELETE), ("null", None), ("bad", "@@"), ("pad", assertion[key] + "="),
                                ("std", str(assertion[key]).replace("-", "+").replace("_", "/"))):
                yield {
                    "id": f"assertion:{k}:{key}={name}",
                    "fn": "assertionDigestResult",
                    "args": [mutate(assertion, [key], value)],
                }


def _small_cases() -> Iterator[dict[str, Any]]:
    refs = [
        "eip155:1@9123456:0x" + "8a" * 32, "eip155:01@1:0x" + "8a" * 32, "eip155:1@01:0x" + "8a" * 32,
        "eip155:1@9007199254740992:0x" + "8a" * 32, "eip155:1@9007199254740991:0x" + "8a" * 32,
        "eip155:11155111@1:0x" + "8a" * 32, "eip155:560048@1:0x" + "8a" * 32, "eip155:1@1:0x" + "8A" * 32,
        "cosmos:hub-4@5:0x" + "00" * 32, "eip155:1@1:0x" + "8a" * 32 + "\n", "x@1:0x" + "00" * 32, "",
    ]
    for k, ref in enumerate(refs):
        yield {"id": f"fresh:{k}", "fn": "parseFreshnessReference", "args": [ref]}
    origins = [
        "test.lender.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/6c656e64696e67",
        "log.tzun.ai/dep-1/log-1", "log.tzun.ai/dep-1/anchors", "log.tzun.ai/dep-1/evidence",
        "Test.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/6c", "a/b", "a/b/c/d/e",
        "x.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/00", "x.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/custody/6c",
        "x.example/0f1e2d3c4b5a69788796a5b4c3d2e1f0/evidence/c3", "-a.example/x/y", "a b/c/d", "a+b/c/d",
    ]
    for k, origin in enumerate(origins):
        yield {"id": f"origin:{k}", "fn": "isEvidenceLogOrigin", "args": [origin]}
    hexd = "c" * 64
    expectations = [
        None, {}, "x", {"policyDigest": hexd}, {"policyDigest": hexd, "x": 1}, {"statementDigest": hexd, "sessionSeq": 1},
        {"statementDigest": hexd, "sessionSeq": 1.0}, {"statementDigest": hexd, "sessionSeq": "1"},
        {"mandateAssertion": hexd, "mandateSeq": 1, "totals": None, "confirm": False},
        {"mandateAssertion": hexd, "mandateSeq": 1.0, "totals": {"paid": 3.0}, "confirm": True},
        {"mandateAssertion": hexd, "mandateSeq": 1, "totals": {}, "confirm": False},
        {"mandateAssertion": hexd, "mandateSeq": 1, "totals": {"paid": "3"}, "confirm": False},
        {"mandateAssertion": hexd, "mandateSeq": 1, "totals": None, "confirm": 1},
        {"mandateAssertion": hexd.upper(), "mandateSeq": 1, "totals": None, "confirm": False},
        {"mandateAssertion": hexd, "mandateSeq": 0, "totals": None, "confirm": False},
        {"mandateAssertion": hexd, "mandateSeq": 1, "totals": {"a b": 1}, "confirm": False},
        {"mandateAssertion": hexd, "mandateSeq": 1, "totals": {f"c{i}": 1 for i in range(17)}, "confirm": False},
    ]
    for k, value in enumerate(expectations):
        yield {"id": f"expectation:{k}", "fn": "signoffExpectationViolation", "args": [value]}
    instants = ["2026-10-01T00:00:00.000Z", "2026-02-30T00:00:00.000Z", "2026-10-01T00:00:00Z", "2026-10-01T24:00:00.000Z",
                "0000-01-01T00:00:00.000Z", "2026-13-01T00:00:00.000Z", "2026-10-01T00:00:00.000+00:00"]
    for k, instant in enumerate(instants):
        yield {"id": f"revocation:{k}", "fn": "revocationInstantViolation", "args": [instant, "2026-10-01T00:00:00.000Z"]}
        yield {"id": f"expired:{k}", "fn": "mandateExpiredAt", "args": ["2026-10-01T00:00:00.000Z", instant]}


def _build_cases() -> Iterator[dict[str, Any]]:
    """buildContributions and buildLinks over builder input derived from W2, W3, W6 and W7."""
    records = _records()
    w3 = records["W3"]["payload"]
    steps_in = []
    for step in w3["contributions"]["steps"]:
        steps_in.append({k: v for k, v in step.items() if k not in ("output", "prev")} | (
            {"output": step["output"]} if step["role"].startswith("review") else {}))
    ctx = {"decider": w3["decider"], "action": w3["action"], "reason": w3["reason"], "aiOutput": w3["aiOutput"]}
    base = {"steps": steps_in, "externals": []}
    yield {"id": "buildC:W3", "fn": "buildContributions", "args": [base, ctx]}
    for path in _paths(base):
        for name in ("delete", "null", "x", "list", "obj", "pfx"):
            yield {"id": f"buildC:{'.'.join(map(str, path))}={name}", "fn": "buildContributions",
                   "args": [mutate(base, list(path), VALUES[name]), ctx]}
    w2 = records["W2"]
    held = {"payload": w2["payload"], "digest": w2["digest"], "origin": None}
    link_inputs = [{"rel": "derivedFrom", "target": {"evidenceId": w2["payload"]["evidenceId"]}}]
    ctx_links = {"aiSystemId": w3["aiSystemId"], "action": w3["action"], "decider": w3["decider"],
                 "contributions": None, "aiOutput": w3["aiOutput"], "signoffExpectation": None}
    for rel in ("derivedFrom", "reviews", "supersedes", "appeals", "ratifies", "implements", "delegatedBy", "root",
                "closes", "fanoutOf", "mandate", "revokes", "subject", "x-acme.renewal", "unknownRel", "X"):
        for held_or_not in ("held", "external", "missing"):
            target: dict[str, Any] = {"evidenceId": w2["payload"]["evidenceId"]}
            if held_or_not == "external":
                target = {"digest": w2["digest"], "external": True}
            inputs = [{"rel": rel, "target": target}]
            options = {"held": [held if held_or_not == "held" else None], "context": ctx_links}
            yield {"id": f"buildL:{rel}:{held_or_not}", "fn": "buildLinks", "args": [inputs, options]}
    for path in _paths(link_inputs):
        for name in ("delete", "null", "x", "hex", "obj", "true"):
            yield {"id": f"buildL:mut:{'.'.join(map(str, path))}={name}", "fn": "buildLinks",
                   "args": [mutate(link_inputs, list(path), VALUES[name]), {"held": [held], "context": ctx_links}]}


def cases() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for gen in (_payload_cases, _envelope_cases, _document_cases, _predicate_cases, _agent_cases, _assertion_cases,
                _small_cases, _build_cases):
        out.extend(gen())
    seen: set[str] = set()
    for case in out:
        if case["id"] in seen:
            raise SystemExit(f"duplicate case id {case['id']}")
        seen.add(case["id"])
    return out


if __name__ == "__main__":
    json.dump(cases(), sys.stdout)
