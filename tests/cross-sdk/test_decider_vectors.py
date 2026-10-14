"""Python half of vectors/decider-vectors.json (Record §6).

The TypeScript generator writes every answer from the specification and stops
where the engine disagrees; tests/cross-sdk/ts/decider-vectors.test.ts replays
the file through the engine. Here, independently of TypeScript:

  - commitments, derived salts and openings are recomputed with hashlib and
    hmac;
  - finalized-block references are parsed with ``re.fullmatch`` and
    ``re.ASCII`` (a trailing newline and a non-ASCII digit are the cases a
    Python ``re.match(...$)`` or ``\\d`` would let through);
  - every envelope's digest is recomputed under the v1.0 hashed field set;
  - the generated strict ``Decider`` model takes every valid decider and
    refuses every one whose refusal is a type, member or pattern rule;
  - and the Python SDK's own rules (``tzun_sdk.decider``) give every refusal
    and row the file states.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import pathlib
import re
from typing import Any

import pytest
from pydantic import ValidationError
from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, canonical_serialize

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "decider-vectors.json").read_text(encoding="utf-8"))

FRESHNESS_RE = r"([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32})@(0|[1-9][0-9]{0,15}):(0x[0-9a-f]{64})"
IDENTIFIER_RE = r"[a-z][a-z0-9+.-]{0,15}:[\x21-\x7e]+"
VALUE_RE = {
    "acct": r"[A-Za-z0-9._-]{1,128}",
    "spiffe": r"//[a-z0-9._-]{1,255}(/[A-Za-z0-9._-]+)+",
    "jkt": r"[A-Za-z0-9_-]{43}",
    "desc": r"sha256:[0-9a-f]{64}",
    "cmt": r"[0-9a-f]{64}",
}
#: Refusals the generated model enforces: a type, a member, an enumeration or a pattern.
MODEL_CODES = {
    "not_an_object",
    "unknown_members",
    "missing_members",
    "invalid_kind",
    "invalid_agent_reference",
    "invalid_credential_reference",
    "invalid_freshness_reference",
}


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_serialize(payload, list(V1_HASHED_FIELDS)).encode("utf-8")).hexdigest()


def _parse_freshness(reference: str) -> dict[str, Any] | None:
    m = re.fullmatch(FRESHNESS_RE, reference, re.ASCII)
    if m is None:
        return None
    namespace, ref, block, block_hash = m.groups()
    if namespace == "eip155" and re.fullmatch(r"[1-9][0-9]{0,30}", ref, re.ASCII) is None:
        return None
    if int(block) > 2**53 - 1:
        return None
    return {"chain": f"{namespace}:{ref}", "namespace": namespace, "reference": ref, "blockNumber": int(block), "blockHash": block_hash}


def _known_identifier(identifier: str) -> bool:
    if len(identifier) < 3 or len(identifier) > 1024 or re.fullmatch(IDENTIFIER_RE, identifier, re.ASCII) is None:
        return False
    scheme, value = identifier.split(":", 1)
    if scheme not in VALUE_RE or re.fullmatch(VALUE_RE[scheme], value, re.ASCII) is None:
        return False
    return not (scheme == "spiffe" and any(s in (".", "..") for s in value.split("/")[3:]))


def _commitment(inner_id: str, salt: bytes) -> str:
    return "cmt:" + hashlib.sha256(b"tzun-decider-cmt-v1" + salt + inner_id.encode("utf-8")).hexdigest()


def _opens(identifier: Any, opening: Any) -> bool:
    if not isinstance(identifier, str) or re.fullmatch(r"cmt:[0-9a-f]{64}", identifier, re.ASCII) is None:
        return False
    salt, inner = (opening or {}).get("salt"), (opening or {}).get("id")
    if not isinstance(salt, str) or not isinstance(inner, str) or re.fullmatch(r"[A-Za-z0-9_-]*", salt, re.ASCII) is None:
        return False
    raw = base64.urlsafe_b64decode(salt + "=" * (-len(salt) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != salt or len(raw) != 32:
        return False
    if not _known_identifier(inner) or inner.startswith("cmt:"):
        return False
    return _commitment(inner, raw) == identifier


@pytest.mark.parametrize("item", FILE["commitments"], ids=lambda c: c["case"])
def test_commitment(item: dict[str, Any]) -> None:
    salt = bytes.fromhex(item["saltHex"])
    assert base64.urlsafe_b64encode(salt).rstrip(b"=").decode("ascii") == item["saltBase64url"]
    assert _commitment(item["innerId"], salt) == item["commitment"]


def test_derived_salts() -> None:
    def lp(text: str) -> bytes:
        data = text.encode("utf-8")
        return len(data).to_bytes(4, "big") + data

    for item in FILE["derivedSalts"]:
        mac = hmac.new(bytes.fromhex(item["secretHex"]), digestmod=hashlib.sha256)
        mac.update(b"tzun-cmt-salt-v1" + lp(item["idempotencyKey"]) + lp(item["innerId"]))
        salt = mac.digest()
        assert base64.urlsafe_b64encode(salt).rstrip(b"=").decode("ascii") == item["saltBase64url"]
        assert _commitment(item["innerId"], salt) == item["commitment"]


@pytest.mark.parametrize("item", FILE["openings"], ids=lambda c: c["case"])
def test_opening(item: dict[str, Any]) -> None:
    assert _opens(item["id"], item["opening"]) is item["opens"]


@pytest.mark.parametrize("item", FILE["freshness"], ids=lambda c: c["case"])
def test_freshness_reference(item: dict[str, Any]) -> None:
    assert _parse_freshness(item["reference"]) == item["parsed"]


def test_the_example_commitment_is_the_worked_examples() -> None:
    worked = json.loads((REPO_ROOT / "vectors" / "v1.0-worked-example-vectors.json").read_text(encoding="utf-8"))
    assert FILE["commitments"][0]["commitment"] == worked["deciderCommitments"][0]["commitment"]


def test_every_envelope_digest_recomputes() -> None:
    for item in FILE["rows"]:
        envelope = item["envelope"]
        assert _digest(envelope["payload"]) == envelope["integrity"]["canonicalDigest"], item["case"]


@pytest.mark.parametrize("item", FILE["shapes"], ids=lambda c: c["case"])
def test_the_strict_model_holds_the_writer_rules_it_can(item: dict[str, Any]) -> None:
    from tzun_sdk._generated.models import Decider

    violation = item["violation"]
    if violation is None:
        Decider.model_validate(item["value"])
    elif violation["code"] in MODEL_CODES:
        with pytest.raises(ValidationError):
            Decider.model_validate(item["value"])


@pytest.mark.parametrize("item", FILE["shapes"], ids=lambda c: c["case"])
def test_the_python_sdk_refuses_what_the_engine_refuses(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    decider_violation = sdk_rule("decider", "decider_violation")
    got = projection(decider_violation(item["value"]), ("code", "field"))
    assert got == item["violation"]


@pytest.mark.parametrize("item", FILE["rows"], ids=lambda c: c["case"])
def test_the_python_sdk_gives_each_row(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    check_decider = sdk_rule("decider", "check_decider")
    keys = ("outcome", "reason", "kind", "scheme", "level", "levelUndetermined", "committed", "kindContradiction")
    assert projection(check_decider(item["envelope"]), keys) == {k: v for k, v in item["expect"].items() if k in keys and v is not None}
