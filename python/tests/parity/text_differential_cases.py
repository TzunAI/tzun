"""The text-level differential corpus: JSON texts each SDK parses with its own parser.

Each case is ``{"id", "kind", "text", "systemRecord"}``. ``kind`` is
``payload`` (a payload of the worked examples W1 to W7) or ``envelope`` (W6
with its mandate block, W5 with its issuance block). The texts respell every
integer (``3.0``, ``3e0``, ``3E+0``, ``3.000``, scientific) or replace it with
a hostile number (2^53 - 1, 2^53, 2^53 + 1, 1e21, 1e400, -0, 0.1, a 30-digit
integer, the smallest and largest doubles), put escapes, a lone surrogate,
an astral pair, NUL, DEL, NBSP, a newline or a tab into the strings, and add
duplicate keys, ``__proto__``, ``constructor`` and ``toString`` keys, and
non-boolean ``confirm`` values. ``JSON.parse`` and this SDK's reader
(``js_json_loads``) each read the text, so a float spelling, a big integer,
an escape or a duplicate key reaches each implementation as its own parser
produces it. ``generate_text_differential.cjs`` records the engine's answers
in ``text-differential.json.gz``; ``test_text_differential.py`` holds the
Python rules to them.

Regenerate (from the repository root, after ``pnpm --filter @tzun/engine build``)::

    cases="$(mktemp)"
    python3 python/tests/parity/text_differential_cases.py > "$cases"
    node python/tests/parity/generate_text_differential.cjs "$cases" \\
      | gzip -9n > python/tests/parity/text-differential.json.gz
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[3]
VECTORS = json.loads((ROOT / "vectors" / "v1.0-worked-example-vectors.json").read_text(encoding="utf-8"))
RECORDS = {r["id"]: r for r in VECTORS["records"]}
BLOCK = {
    "statement": VECTORS["mandateStatements"][0]["statement"],
    "assertion": VECTORS["mandateAssertions"][0]["assertion"],
    "assertionTimestamp": None,
    "document": VECTORS["mandateDocuments"][0]["document"],
}
SYSTEM_RECORDS = {"tzun:mandate": "mandate", "tzun:link": "link"}

#: An integer literal standing alone as a member value or an array element.
NUM_RE = re.compile(r"(?<=[:\[,])(-?\d+)(?=[,\]}])")


def _scientific(n: int) -> str:
    if n == 0:
        return "0e5"
    digits = len(str(abs(n))) - 1
    return f"{n / 10**digits!r}e{digits}"


INT_SPELLINGS = {
    "dot0": lambda n: f"{n}.0",
    "e0": lambda n: f"{n}e0",
    "E+0": lambda n: f"{n}E+0",
    "dot000": lambda n: f"{n}.000",
    "sci": _scientific,
}

HOSTILE_NUMBERS = [
    "9007199254740991",
    "9007199254740992",
    "9007199254740993",
    "1e21",
    "1e400",
    "-0",
    "-0.0",
    "0.1",
    "1.5",
    "-1",
    "1e-7",
    "123456789012345678901234567890",
    "5e-324",
    "1.7976931348623157e308",
]

STRING_EDITS = {
    "esc": lambda v: "".join(f"\\u{ord(c):04x}" for c in v[:3]) + v[3:],
    "lone": lambda v: v + "\\ud800",
    "pair": lambda v: v + "\\ud83d\\ude00",
    "nul": lambda v: v + "\\u0000",
    "del": lambda v: v + "\\u007f",
    "nbsp": lambda v: v + "\\u00a0",
    "nl": lambda v: v + "\\n",
    "tab": lambda v: v + "\\t",
}


def cases() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(kind: str, cid: str, text: str, system: str | None) -> None:
        out.append({"id": cid, "kind": kind, "text": text.replace(",}", "}"), "systemRecord": system})

    for rid, rec in RECORDS.items():
        p = rec["payload"]
        system = SYSTEM_RECORDS.get(p.get("aiSystemId"))
        base = json.dumps(p, separators=(",", ":"), ensure_ascii=False)
        add("payload", f"{rid}:base", base, system)
        for mi, m in enumerate(NUM_RE.finditer(base)):
            n = int(m.group(1))
            for name, spell in INT_SPELLINGS.items():
                add("payload", f"{rid}:num{mi}={name}", base[: m.start()] + spell(n) + base[m.end() :], system)
            for h in HOSTILE_NUMBERS:
                add("payload", f"{rid}:num{mi}={h}", base[: m.start()] + h + base[m.end() :], system)
        for si, m in enumerate(re.finditer(r'"(reason|action|id|role|rel|evidenceId)":"([^"]*)"', base)):
            key, val = m.group(1), m.group(2)
            for name, edit in STRING_EDITS.items():
                add("payload", f"{rid}:str{si}.{key}={name}", base[: m.start(2)] + edit(val) + base[m.end(2) :], system)
        add("payload", f"{rid}:dupaction", base[:-1] + ',"action":"x-dup"}', system)
        add("payload", f"{rid}:proto-top", base[:-1] + ',"__proto__":{"x":1}}', system)
        add("payload", f"{rid}:aiOutput-proto", base.replace('"aiOutput":{', '"aiOutput":{"__proto__":{"evil":1},', 1), system)
        add("payload", f"{rid}:decider-proto", base.replace('"decider":{', '"decider":{"__proto__":null,', 1), system)
        add(
            "payload",
            f"{rid}:aiOutput-constructor",
            base.replace('"aiOutput":{', '"aiOutput":{"constructor":1,"toString":2,', 1),
            system,
        )
        add("payload", f"{rid}:decider-dupkind", base.replace('"decider":{', '"decider":{"kind":"human",', 1), system)
        if p.get("signoffExpectation") and "confirm" in p["signoffExpectation"]:
            for rep in ("1", "0", '"true"', "null"):
                add("payload", f"{rid}:confirm={rep}", base.replace('"confirm":false', f'"confirm":{rep}'), system)

    for rid, key in (("W6", "mandate"), ("W5", "mandateIssuance")):
        rec = RECORDS[rid]
        system = SYSTEM_RECORDS.get(rec["payload"].get("aiSystemId"))
        env = {
            "envelopeVersion": "e1",
            "payload": rec["payload"],
            "integrity": {"canonicalDigest": "__DIGEST__", "chainLink": None},
            "nonRepudiation": {key: BLOCK},
            "custodyChain": [],
            "attestationStatus": "none",
        }
        base = json.dumps(env, separators=(",", ":"), ensure_ascii=False)
        add("envelope", f"{rid}:env:base", base, system)
        for mi, m in enumerate(NUM_RE.finditer(base)):
            n = int(m.group(1))
            for name in ("dot0", "e0"):
                add("envelope", f"{rid}:env:num{mi}={name}", base[: m.start()] + INT_SPELLINGS[name](n) + base[m.end() :], system)
            for h in ("9007199254740993", "1e21", "-0", "1.5", "-1"):
                add("envelope", f"{rid}:env:num{mi}={h}", base[: m.start()] + h + base[m.end() :], system)
        for rep in ("true", "1", '"yes"'):
            add("envelope", f"{rid}:env:confirmvalue={rep}", base.replace('"value":true', f'"value":{rep}'), system)
    return out


if __name__ == "__main__":
    json.dump(cases(), sys.stdout)
