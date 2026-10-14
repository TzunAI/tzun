"""Python recomputation of vectors/v1.0-worked-example-vectors.json.

The TypeScript generator wrote every canonical byte string and digest in the
file, building W1 to W7 with the engine's own builders; this suite recomputes
each one with the Python SDK's canonical serializer and hashlib, independently
of the TypeScript engine, so a value the two languages disagree on fails here.
The TypeScript side is tests/ts/v1.0-worked-example-vectors.test.ts.

What is recomputed here, and how:

  - record digests: ``canonical_serialize`` over the eleven names of the v1.0
    hashed field set, as revised in 0.8.0;
  - output and step digests: ``sha256:`` and the hex SHA-256 of the canonical
    bytes of the whole value, each step's ``prev`` the digest of the step
    before it;
  - agent descriptors: their sets sorted by UTF-8 bytes, then the canonical
    bytes;
  - commitments: SHA-256 of the domain separator, the salt and the inner id;
    a derived salt: HMAC-SHA256 of the store secret over the length-prefixed
    idempotency key and inner id;
  - the mandate document, statement and challenge; W4's Ed25519 assertion,
    whose signature is verified with the RFC 8037 Appendix A public key, and
    its assertion digest; the event bodies and their digests; the
    confirmation challenge;
  - assertion digests: the ES256 signature read as DER (lenient on integer and
    length encodings), re-encoded minimal with low S.

It also holds the generated strict models to the writer's rules on the worked
records: they take each member as stored, and refuse what TypeScript refuses
(a coerced integer, a missing nullable key, a statement carrying signerName).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import pathlib
from typing import Any

import pytest
from pydantic import ValidationError
from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS,
    V1_HASHED_FIELDS_0_7,
    V1_HASHED_FIELDS_BEFORE_0_7,
    _serialize_value,
    canonical_serialize,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
FILE = json.loads((REPO_ROOT / "vectors" / "v1.0-worked-example-vectors.json").read_text(encoding="utf-8"))
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
# RFC 8037 Appendix A: the Ed25519 public key W4's assertion is signed with.
RFC8037_PUBLIC_KEY = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"


def _hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _prefixed(value: Any) -> str:
    return "sha256:" + _hex(_serialize_value(value).encode("utf-8"))


def _b64(text: str) -> bytes:
    body = text.rstrip("=").replace("-", "+").replace("_", "/")
    return base64.b64decode(body + "=" * (-len(body) % 4), validate=True)


def _record(record_id: str) -> dict[str, Any]:
    return next(r for r in FILE["records"] if r["id"] == record_id)


@pytest.mark.parametrize("record", FILE["records"], ids=lambda r: r["id"])
def test_record_digest(record: dict[str, Any]) -> None:
    canonical = canonical_serialize(record["payload"], FILE["hashedFieldSet"])
    assert canonical == record["canonical"]
    assert len(canonical.encode("utf-8")) == record["byteLength"]
    assert _hex(canonical.encode("utf-8")) == record["digest"]


def test_v1_0_field_set_is_eleven_names_in_byte_order() -> None:
    names = FILE["hashedFieldSet"]
    assert len(names) == 11
    assert names == sorted(names)
    assert {"action", "reason", "decider", "contributions", "links"} <= set(names)
    assert not {"humanAction", "humanReason", "aiBom", "lineage"} & set(names)


def test_python_sdk_hashes_the_same_field_set() -> None:
    # The SDK's own constant, which capture and the tamper detector hash with,
    # is the set the vectors were built under.
    assert list(V1_HASHED_FIELDS) == FILE["hashedFieldSet"]
    for record in FILE["records"]:
        assert canonical_serialize(record["payload"], list(V1_HASHED_FIELDS)) == record["canonical"], record["id"]
    # The earlier sets are detection constants: no worked record recomputes under them.
    assert len(V1_HASHED_FIELDS_0_7) == 9 and len(V1_HASHED_FIELDS_BEFORE_0_7) == 8
    assert list(V1_HASHED_FIELDS_BEFORE_0_7) == [f for f in V1_HASHED_FIELDS_0_7 if f != "signoffExpectation"]
    for record in FILE["records"]:
        for earlier in (V1_HASHED_FIELDS_0_7, V1_HASHED_FIELDS_BEFORE_0_7):
            canonical = canonical_serialize(record["payload"], list(earlier))
            assert _hex(canonical.encode("utf-8")) != record["digest"], record["id"]


def test_records_carry_no_member_outside_the_format() -> None:
    members = set(FILE["hashedFieldSet"]) | {"schemaVersion"}
    for record in FILE["records"]:
        assert set(record["payload"]) == members, record["id"]
        assert record["payload"]["schemaVersion"] == "v1.0"


def test_output_and_step_digests() -> None:
    for item in FILE["outputDigests"]:
        assert _prefixed(item["value"]) == item["digest"], item["label"]
    for item in FILE["stepDigests"]:
        assert _prefixed(item["step"]) == item["digest"]
    for record_id in ("W1", "W3"):
        steps = _record(record_id)["payload"]["contributions"]["steps"]
        for i, step in enumerate(steps):
            assert step["prev"] == (None if i == 0 else _prefixed(steps[i - 1]))


def test_w3_decide_step_and_link_targets() -> None:
    w3 = _record("W3")["payload"]
    steps = w3["contributions"]["steps"]
    assert steps[2]["output"] == _prefixed({"action": w3["action"], "reason": w3["reason"]})
    assert steps[0]["output"] == _prefixed(w3["aiOutput"])
    w2 = _record("W2")["digest"]
    assert [link["rel"] for link in w3["links"]] == ["derivedFrom", "root"]
    assert {link["target"]["digest"] for link in w3["links"]} == {w2}
    assert "sha256:" + w2 in steps[0]["inputs"]


def test_agent_descriptors() -> None:
    def utf8(s: str) -> bytes:
        return s.encode("utf-8")

    for item in FILE["agentDescriptors"]:
        d = dict(item["descriptor"])
        d["identities"] = sorted(d["identities"], key=utf8)
        d["keys"] = sorted(d["keys"], key=lambda k: utf8(k["kid"]))
        d["models"] = sorted(d["models"], key=utf8)
        if d["runtime"] is not None:
            d["runtime"] = {**d["runtime"], "measurements": sorted(d["runtime"]["measurements"], key=utf8)}
        canonical = _serialize_value(d)
        assert canonical == item["canonical"], item["label"]
        assert "sha256:" + _hex(canonical.encode("utf-8")) == item["digest"]


def test_decider_commitments_and_a_derived_salt() -> None:
    for item in FILE["deciderCommitments"]:
        salt = bytes.fromhex(item["saltHex"])
        assert _b64(item["saltBase64url"]) == salt
        commitment = hashlib.sha256(b"tzun-decider-cmt-v1" + salt + item["innerId"].encode("utf-8")).hexdigest()
        assert "cmt:" + commitment == item["commitment"]

    def lp(text: str) -> bytes:
        data = text.encode("utf-8")
        return len(data).to_bytes(4, "big") + data

    for item in FILE["derivedSalts"]:
        mac = hmac.new(bytes.fromhex(item["secretHex"]), digestmod=hashlib.sha256)
        mac.update(b"tzun-cmt-salt-v1" + lp(item["idempotencyKey"]) + lp(item["innerId"]))
        salt = mac.digest()
        assert base64.urlsafe_b64encode(salt).rstrip(b"=").decode("ascii") == item["saltBase64url"]
        commitment = hashlib.sha256(b"tzun-decider-cmt-v1" + salt + item["innerId"].encode("utf-8")).hexdigest()
        assert "cmt:" + commitment == item["commitment"]


def test_mandate_document_statement_and_challenge() -> None:
    for item in FILE["mandateDocuments"]:
        canonical = _serialize_value(item["document"])
        assert canonical == item["canonical"]
        assert len(canonical.encode("utf-8")) == item["byteLength"]
        assert _hex(canonical.encode("utf-8")) == item["digest"]
        assert item["document"]["schemaVersion"] == "v1.0"
    for item in FILE["mandateStatements"]:
        assert "signerName" not in item["statement"]
        canonical = _serialize_value(item["statement"])
        assert canonical == item["canonical"]
        digest = _hex(canonical.encode("utf-8"))
        assert digest == item["digest"]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(b"tzun-signoff-v1" + digest.encode("ascii")).digest())
        assert challenge.rstrip(b"=").decode("ascii") == item["challenge"]


def test_w4_assertion_is_a_real_signature_over_the_challenge() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    a = FILE["mandateAssertions"][0]["assertion"]
    auth = _b64(a["authenticatorData"])
    client = _b64(a["clientDataJSON"])
    assert json.loads(client)["challenge"] == FILE["mandateStatements"][0]["challenge"]
    Ed25519PublicKey.from_public_bytes(_b64(RFC8037_PUBLIC_KEY)).verify(_b64(a["signature"]), auth + hashlib.sha256(client).digest())
    digest = hashlib.sha256(
        b"tzun-assertion-v1" + hashlib.sha256(auth).digest() + hashlib.sha256(client).digest() + hashlib.sha256(_b64(a["signature"])).digest()
    ).hexdigest()
    assert digest == FILE["mandateAssertions"][0]["digest"]
    assert _record("W5")["payload"]["aiOutput"]["assertionDigest"] == digest
    assert _record("W6")["payload"]["signoffExpectation"]["mandateAssertion"] == digest


def test_mandate_event_bodies_and_the_confirmation_challenge() -> None:
    for item in FILE["mandateEventBodies"]:
        canonical = _serialize_value(item["body"])
        assert canonical == item["canonical"]
        assert _hex(canonical.encode("utf-8")) == item["digest"]
        assert "leaf" not in item
    assert FILE["mandateEventBodies"][0]["body"]["record"] == _record("W5")["digest"]
    for item in FILE["confirmationChallenges"]:
        challenge = base64.urlsafe_b64encode(hashlib.sha256(b"tzun-confirm-v1" + item["digest"].encode("ascii")).digest())
        assert challenge.rstrip(b"=").decode("ascii") == item["challenge"]


def test_strict_models_take_the_worked_members_and_refuse_what_typescript_refuses() -> None:
    from tzun_sdk._generated.models import (
        Contributions,
        Decider,
        Link,
        MandateDocument,
        MandateStatement,
    )

    w3 = _record("W3")["payload"]
    assert Contributions.model_validate(w3["contributions"]).model_dump(mode="json") == w3["contributions"]
    for link in w3["links"]:
        assert Link.model_validate(link).model_dump(mode="json") == link
    for record in FILE["records"]:
        Decider.model_validate(record["payload"]["decider"])
    assert Contributions.model_validate(_record("W2")["payload"]["contributions"]).steps[0].actor is None
    MandateDocument.model_validate(FILE["mandateDocuments"][0]["document"])
    MandateStatement.model_validate(FILE["mandateStatements"][0]["statement"])

    coerced = copy.deepcopy(w3["contributions"])
    coerced["steps"][0]["aiBom"]["inferenceParameters"]["maxTokens"] = "800"
    with pytest.raises(ValidationError):
        Contributions.model_validate(coerced)

    missing = copy.deepcopy(w3["contributions"])
    del missing["steps"][0]["aiBom"]["inferenceParameters"]["seed"]
    with pytest.raises(ValidationError):
        Contributions.model_validate(missing)

    no_attrs = {"rel": "derivedFrom", "target": w3["links"][0]["target"]}
    with pytest.raises(ValidationError):
        Link.model_validate(no_attrs)
    with pytest.raises(ValidationError):
        Link.model_validate({**w3["links"][0], "attrs": {}})
    with pytest.raises(ValidationError):
        Link.model_validate({**w3["links"][0], "rel": "derived-from"})

    with pytest.raises(ValidationError):
        MandateStatement.model_validate({**FILE["mandateStatements"][0]["statement"], "signerName": "U2Ft"})


def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4:
        raise ValueError("length")
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def _read_integer(data: bytes, pos: int) -> tuple[int, int]:
    if data[pos] != 0x02:
        raise ValueError("tag")
    length, pos = _read_length(data, pos + 1)
    content = data[pos : pos + length]
    if length == 0 or len(content) != length or content[0] & 0x80:
        raise ValueError("integer")
    return int.from_bytes(content, "big"), pos + length


def _minimal_der(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + bytes([len(body)]) + body


def _normalise_es256(sig: bytes) -> bytes | None:
    try:
        if sig[0] != 0x30:
            return None
        seq_len, pos = _read_length(sig, 1)
        if pos + seq_len != len(sig):
            return None
        r, pos = _read_integer(sig, pos)
        s, pos = _read_integer(sig, pos)
        if pos != len(sig) or not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
            return None
    except (IndexError, ValueError):
        return None
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    body = _minimal_der(r) + _minimal_der(s)
    return b"\x30" + bytes([len(body)]) + body


@pytest.mark.parametrize("item", FILE["assertionDigests"], ids=lambda a: a["label"])
def test_assertion_digest(item: dict[str, Any]) -> None:
    a = item["assertion"]
    signature = _b64(a["signature"])
    if a["algorithm"] == "ES256":
        normalised = _normalise_es256(signature)
        if normalised is None:
            assert item["digest"] is None
            return
        signature = normalised
    digest = hashlib.sha256(
        b"tzun-assertion-v1"
        + hashlib.sha256(_b64(a["authenticatorData"])).digest()
        + hashlib.sha256(_b64(a["clientDataJSON"])).digest()
        + hashlib.sha256(signature).digest()
    ).hexdigest()
    assert digest == item["digest"]
