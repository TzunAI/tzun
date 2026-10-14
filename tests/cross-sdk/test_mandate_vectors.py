"""Python half of vectors/mandate-vectors.json (Record §9.6 to §9.11).

tests/cross-sdk/ts/mandate-vectors.test.ts replays the file through the
engine. Here, independently of TypeScript:

  - every well-formed document's canonical length and digest, every statement's
    digest and challenge, every event body's digest, and every issuance
    envelope's record digest are recomputed;
  - every assertion digest is recomputed: each member decoded from base64 or
    base64url text, padded or not; an ES256 signature read as DER and
    re-encoded minimal with low S; a signature that is not DER, an algorithm
    outside the two, or a member missing, giving none;
  - the predicates whose number spelling is the point (``1.0``, ``1e0``) are
    read with ``json.loads``, which gives a float, and the float is integral
    exactly where the case evaluates it as the integer;
  - the generated strict models take every well-formed document and
    statement, and refuse a statement that carries ``signerName``;
  - and, once the Python SDK has ``tzun_sdk.mandate``, its rules give every
    answer the file states.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
from typing import Any

import pytest
from pydantic import ValidationError
from tzun_sdk._generated.canonical import V1_HASHED_FIELDS, _serialize_value, canonical_serialize

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "mandate-vectors.json").read_text(encoding="utf-8"))
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _decode(text: Any) -> bytes | None:
    """base64 or base64url text, padded or not, the two alphabets never mixed in one value."""
    if not isinstance(text, str) or text == "":
        return None
    body = text.rstrip("=")
    if len(text) - len(body) > 2:
        return None
    standard = re.fullmatch(r"[A-Za-z0-9+/]*", body, re.ASCII) is not None
    url = re.fullmatch(r"[A-Za-z0-9_-]*", body, re.ASCII) is not None
    if not standard and not url:
        return None
    if len(body) % 4 == 1 or (len(text) != len(body) and len(text) % 4 != 0):
        return None
    return base64.b64decode(body.replace("-", "+").replace("_", "/") + "=" * (-len(body) % 4))


def _length(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4:
        raise ValueError("length")
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def _integer(data: bytes, pos: int) -> tuple[int, int]:
    if data[pos] != 0x02:
        raise ValueError("tag")
    length, pos = _length(data, pos + 1)
    content = data[pos : pos + length]
    if length == 0 or len(content) != length or content[0] & 0x80:
        raise ValueError("integer")
    return int.from_bytes(content, "big"), pos + length


def _der(n: int) -> bytes:
    body = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


def _es256(sig: bytes) -> bytes | None:
    try:
        if sig[0] != 0x30:
            return None
        seq_len, pos = _length(sig, 1)
        if pos + seq_len != len(sig):
            return None
        r, pos = _integer(sig, pos)
        s, pos = _integer(sig, pos)
        if pos != len(sig) or not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
            return None
    except (IndexError, ValueError):
        return None
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    body = _der(r) + _der(s)
    return b"\x30" + bytes([len(body)]) + body


def _assertion_digest(a: Any) -> str | None:
    if not isinstance(a, dict) or a.get("algorithm") not in ("ES256", "Ed25519"):
        return None
    if a.get("authenticatorData") is None or a.get("clientDataJSON") is None:
        return None
    auth, client, sig = _decode(a["authenticatorData"]), _decode(a["clientDataJSON"]), _decode(a.get("signature"))
    if auth is None or client is None or sig is None:
        return None
    if a["algorithm"] == "ES256":
        sig = _es256(sig)
        if sig is None:
            return None
    return hashlib.sha256(b"tzun-assertion-v1" + hashlib.sha256(auth).digest() + hashlib.sha256(client).digest() + hashlib.sha256(sig).digest()).hexdigest()


@pytest.mark.parametrize("item", [d for d in FILE["documents"] if d["violation"] is None], ids=lambda c: c["case"])
def test_a_document_digest(item: dict[str, Any]) -> None:
    from tzun_sdk._generated.models import MandateDocument

    canonical = _serialize_value(item["document"])
    assert len(canonical.encode("utf-8")) == item["byteLength"]
    assert _hex(canonical) == item["digest"]
    MandateDocument.model_validate(item["document"])


def test_w4() -> None:
    assert FILE["documents"][0]["digest"] == "26b1fbef903914e39cb45378b7f10648611c751c1b93624173bcfe7b7b9938da"
    assert FILE["documents"][0]["byteLength"] == 921
    assert FILE["assertionDigests"][0]["digest"] == "79aafeb32c197be65d3b27c7b1cc469beff89e8650d1a84e02b437ec7937966d"


@pytest.mark.parametrize("item", FILE["statements"], ids=lambda c: c["case"])
def test_a_statement(item: dict[str, Any]) -> None:
    from tzun_sdk._generated.models import MandateStatement

    if item["digest"] is None:
        if "signerName" in item["statement"]:
            with pytest.raises(ValidationError):
                MandateStatement.model_validate(item["statement"])
        return
    MandateStatement.model_validate(item["statement"])
    digest = _hex(_serialize_value(item["statement"]))
    assert digest == item["digest"]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(b"tzun-signoff-v1" + digest.encode("ascii")).digest()).rstrip(b"=")
    assert challenge.decode("ascii") == item["challenge"]


@pytest.mark.parametrize("item", FILE["assertionDigests"], ids=lambda c: c["case"])
def test_an_assertion_digest(item: dict[str, Any]) -> None:
    assert _assertion_digest(item["assertion"]) == item["digest"]


@pytest.mark.parametrize("item", FILE["eventBodies"], ids=lambda c: c["case"])
def test_an_event_body(item: dict[str, Any]) -> None:
    assert "leaf" not in item
    if item["digest"] is None:
        return
    assert _hex(_serialize_value(item["body"])) == item["digest"]


def test_issuance_envelopes_recompute() -> None:
    w5 = FILE["issuance"][0]["envelope"]
    assert w5["integrity"]["canonicalDigest"] == "fb29b130c25c42d6ac72f1ea4123f0c542d6fefed9cfcaaa6b9a1b5e74af9844"
    for item in FILE["issuance"]:
        envelope = item["envelope"]
        canonical = canonical_serialize(envelope["payload"], list(V1_HASHED_FIELDS))
        assert _hex(canonical) == envelope["integrity"]["canonicalDigest"], item["case"]


@pytest.mark.parametrize("item", [p for p in FILE["predicates"] if "payloadJson" in p], ids=lambda c: c["case"])
def test_a_number_spelling(item: dict[str, Any]) -> None:
    subject = json.loads(item["payloadJson"])["aiOutput"]["n"]
    integral = float(subject).is_integer() and not isinstance(subject, bool)
    assert integral is (item["outcome"] != "undeterminable")


@pytest.mark.parametrize("item", FILE["documents"], ids=lambda c: c["case"])
def test_the_python_sdk_refuses_each_document(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    violation = sdk_rule("mandate", "mandate_document_violation")
    got = violation(item["document"], prepare=False) if item.get("prepare") is False else violation(item["document"])
    assert projection(got, ("code", "field")) == item["violation"]


@pytest.mark.parametrize("item", FILE["predicates"], ids=lambda c: c["case"])
def test_the_python_sdk_evaluates_each_predicate(item: dict[str, Any], sdk_rule) -> None:  # type: ignore[no-untyped-def]
    evaluate = sdk_rule("mandate", "evaluate_predicate")
    payload = json.loads(item["payloadJson"]) if "payloadJson" in item else item["payload"]
    assert evaluate(item["predicate"], payload) == item["outcome"]


@pytest.mark.parametrize("item", FILE["assertionDigests"], ids=lambda c: c["case"])
def test_the_python_sdk_digests_each_assertion(item: dict[str, Any], sdk_rule) -> None:  # type: ignore[no-untyped-def]
    assert sdk_rule("mandate", "assertion_digest")(item["assertion"]) == item["digest"]


@pytest.mark.parametrize("item", FILE["eventBodies"], ids=lambda c: c["case"])
def test_the_python_sdk_digests_each_event_body(item: dict[str, Any], sdk_rule) -> None:  # type: ignore[no-untyped-def]
    assert sdk_rule("mandate", "mandate_event_body_digest")(item["body"]) == item["digest"]


@pytest.mark.parametrize("item", FILE["scope"], ids=lambda c: c["case"])
def test_the_python_sdk_reads_each_scope(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    got = sdk_rule("mandate", "evaluate_mandate_scope")(item["document"], item["payload"])
    keys = ("verdict", "agentInMandate", "confirmationEvaded")
    assert projection(got, keys) == projection(item["expect"], keys)


@pytest.mark.parametrize("item", FILE["limits"], ids=lambda c: c["case"])
def test_the_python_sdk_checks_each_limit(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    got = sdk_rule("mandate", "check_mandate_limits")(item["document"], item["payload"])
    assert projection(got, ("valid", "reason", "slot")) == projection(item["expect"], ("valid", "reason", "slot"))


@pytest.mark.parametrize("item", FILE["issuance"], ids=lambda c: c["case"])
def test_the_python_sdk_gives_each_issuance_row(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    got = sdk_rule("mandate", "check_mandate_issuance")(item["envelope"])
    assert projection(got, ("outcome", "reason", "link")) == projection(item["expect"], ("outcome", "reason", "link"))


@pytest.mark.parametrize("item", FILE["claims"], ids=lambda c: c["case"])
def test_the_python_sdk_plans_each_claim(item: dict[str, Any], sdk_rule, projection) -> None:  # type: ignore[no-untyped-def]
    plan = sdk_rule("mandate", "plan_mandate_claim")
    issuance = next(link for link in FILE["claims"][0]["expect"]["links"] if link["rel"] == "mandate")["target"]
    got = plan(
        document=item["document"],
        mandate=item["mandate"],
        payload=item["payload"],
        assertion_digest=FILE["assertionDigests"][0]["digest"],
        issuance=issuance,
    )
    keys = ("ok", "code", "field", "expectUsed", "expired")
    assert projection(got, keys) == projection(item["expect"], keys)
