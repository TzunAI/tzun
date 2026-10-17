"""The RFC 3161 client's check at capture: tzun-anchor/1 §10.5 steps 1 to 3.

The backend keeps a token that passes its own checks (status, imprint, nonce) and checks
it against §10.5 steps 1 to 3 over the requested digest, as the TypeScript client does.
One that does not meet them is kept and logged as
``event=attestation_timestamp_nonconformant``. tests/cross-sdk/test_rfc3161_conformance_parity.py
holds the verdicts and the event to the TypeScript SDK's on the same tokens; this file
pins them on tokens the Python tests build or store.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import logging
import pathlib
import re
import secrets
import tracemalloc
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tests.attestation.mock_tsa import build_timestamp_response, mock_tsa_transport
from tzun_sdk.attestation import _rfc3161_steps
from tzun_sdk.attestation._ecmascript import iso_from_millis
from tzun_sdk.attestation._rfc3161_steps import (
    VERIFIER_FAILED,
    UnreadableTrustAnchorError,
    _openssl_rsa_key,
    _rsa_pkcs1_verifies,
    authority_of,
    read_rfc3161_token,
    read_trust_anchors,
    verify_rfc3161_steps,
)
from tzun_sdk.attestation.rfc3161 import (
    RFC3161Backend,
    TimestampConformance,
    extract_tst_info,
    timestamp_conformance,
)
from tzun_sdk.errors import TsaUnavailableError

STORED: dict[str, dict[str, Any]] = json.loads(
    (pathlib.Path(__file__).resolve().parents[3] / "tests" / "ts" / "fixtures" / "tsa-tokens.json").read_text(
        encoding="utf-8"
    )
)
FREETSA = STORED["freetsa"]
URL = "https://private-tsa.example/tsr"


def _flipped(token: str, i: int, mask: int = 0x01) -> str:
    der = bytearray(base64.b64decode(token))
    der[i] ^= mask
    return base64.b64encode(bytes(der)).decode("ascii")


def _patched(token: str, at: int, value: int) -> str:
    der = bytearray(base64.b64decode(token))
    der[at] = value
    return base64.b64encode(bytes(der)).decode("ascii")


# ---- Steps 1 to 3 ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(STORED))
def test_every_stored_authority_token_meets_steps_1_to_3(name: str) -> None:
    t = STORED[name]
    assert verify_rfc3161_steps(t["tokenBase64"], t["digestHex"]).token == "held"
    assert timestamp_conformance(t["tokenBase64"], t["digestHex"]) == TimestampConformance(holds=True)


def test_a_token_over_another_value_is_imprint_mismatch() -> None:
    other = hashlib.sha256(b"another value").hexdigest()
    assert timestamp_conformance(FREETSA["tokenBase64"], other).to_json() == {
        "holds": False,
        "reason": "imprint_mismatch",
        "error": "the imprint is not SHA-256 over the expected value",
    }


def test_the_mock_authority_token_has_no_signer() -> None:
    digest = "ab" * 32
    token = base64.b64encode(build_timestamp_response(digest, b"\x01\x02")).decode("ascii")
    assert timestamp_conformance(token, digest).to_json() == {
        "holds": False,
        "reason": "malformed",
        "error": "SignedData does not carry exactly one SignerInfo",
    }


def test_a_flipped_signature_does_not_verify() -> None:
    der = base64.b64decode(FREETSA["tokenBase64"])
    token = _flipped(FREETSA["tokenBase64"], len(der) - 1)
    assert timestamp_conformance(token, FREETSA["digestHex"]).to_json() == {
        "holds": False,
        "reason": "verification_failed",
        "error": "the signature does not verify under the signer certificate",
    }


@pytest.mark.parametrize(
    ("token", "error"),
    [
        (7, "the token is not a string"),
        ("", "the token is not RFC 4648 base64"),
        (" " + FREETSA["tokenBase64"], "the token is not RFC 4648 base64"),
        (FREETSA["tokenBase64"].replace("+", "-").replace("/", "_"), "the token is not RFC 4648 base64"),
        (FREETSA["tokenBase64"] + "=", "the token is not RFC 4648 base64"),
        (
            base64.b64encode(base64.b64decode(FREETSA["tokenBase64"]) + b"\x05\x00").decode("ascii"),
            "bytes after the element",
        ),
        (
            base64.b64encode(base64.b64decode(FREETSA["tokenBase64"]) + b"\x00").decode("ascii"),
            "truncated length",
        ),
    ],
)
def test_a_token_that_is_not_base64_of_one_der_element_is_malformed(token: object, error: str) -> None:
    verdict = verify_rfc3161_steps(token, FREETSA["digestHex"])
    assert (verdict.token, verdict.error) == ("malformed", error)


def test_a_verifier_fault_is_missing_dependency_not_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_token: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(_rfc3161_steps, "check_signature_and_signer", broken)
    verdict = verify_rfc3161_steps(FREETSA["tokenBase64"], FREETSA["digestHex"])
    assert verdict.token == "missing_dependency"
    assert verdict.error == f"{VERIFIER_FAILED}: boom"


def test_no_input_makes_it_raise() -> None:
    der = base64.b64decode(FREETSA["tokenBase64"])
    for i in range(0, len(der), 7):
        for mask in (0x01, 0x80, 0xFF):
            verdict = verify_rfc3161_steps(_flipped(FREETSA["tokenBase64"], i, mask), FREETSA["digestHex"])
            assert verdict.token in ("held", "malformed", "imprint_mismatch", "verification_failed", "missing_dependency")


# ---- Steps 1 and 3 as tzun-anchor/1 §10.5 now states them ------------------------------------------


class _Node:
    """A DER element to edit and write back: its identifier octets, and its content or, when
    constructed, its elements."""

    def __init__(self, ident: bytes, content: bytes = b"", children: list[_Node] | None = None) -> None:
        self.ident = ident
        self.content = content
        self.children = children

    def der(self) -> bytes:
        body = b"".join(c.der() for c in self.children) if self.children is not None else self.content
        n = len(body)
        if n < 0x80:
            return self.ident + bytes([n]) + body
        size = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return self.ident + bytes([0x80 | len(size)]) + size + body


def _tree(der: bytes) -> _Node:
    """``der``, one definite-length element, as a ``_Node`` tree."""

    def one(pos: int) -> tuple[_Node, int]:
        at = pos + 1
        if der[pos] & 0x1F == 0x1F:
            while der[at] & 0x80:
                at += 1
            at += 1
        ident = der[pos:at]
        length = der[at]
        at += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(der[at : at + n], "big")
            at += n
        if der[pos] & 0x20 == 0:
            return _Node(ident, der[at : at + length]), at + length
        children, p = [], at
        while p < at + length:
            child, p = one(p)
            children.append(child)
        return _Node(ident, children=children), at + length

    node, end = one(0)
    assert end == len(der)
    return node


def _leaf(ident: int | bytes, content: bytes = b"") -> _Node:
    return _Node(bytes([ident]) if isinstance(ident, int) else ident, content)


def _node(ident: int | bytes, *children: _Node) -> _Node:
    return _Node(bytes([ident]) if isinstance(ident, int) else ident, children=list(children))


def _edited(edit: Any, token: str | None = None) -> str:
    """The FreeTSA token (or ``token``) with its SignedData's members edited by ``edit``."""
    resp = _tree(base64.b64decode(token or FREETSA["tokenBase64"]))
    edit(resp.children[1].children[1].children[0].children)  # type: ignore[index]
    return base64.b64encode(resp.der()).decode("ascii")


def _signer_info(signed_data: list[_Node]) -> list[_Node]:
    return signed_data[-1].children[0].children  # type: ignore[index,return-value]


def _with_unsigned_attribute(values: list[_Node]) -> str:
    """The FreeTSA token with an unsigned attribute of ``values`` added, which no signature
    covers: it holds whenever step 1 does."""

    def edit(signed_data: list[_Node]) -> None:
        attribute = _node(0x30, _leaf(0x06, bytes.fromhex("2a0304")), _node(0x31, *values))
        _signer_info(signed_data).append(_node(0xA1, attribute))

    return _edited(edit)


def _with_tst_info(edit_members: Any) -> str:
    """The FreeTSA token with its TSTInfo's members edited: the message-digest attribute no
    longer matches, so a TSTInfo step 1 accepts fails at step 3."""

    def edit(signed_data: list[_Node]) -> None:
        octets = signed_data[2].children[1].children[0]  # type: ignore[index]
        tst_info = _tree(octets.content)
        edit_members(tst_info.children)
        octets.content = tst_info.der()

    return _edited(edit)


def _with_certificate(cert: _Node) -> str:
    """The FreeTSA token with ``cert`` added to its certificates, which no signature covers."""

    def edit(signed_data: list[_Node]) -> None:
        signed_data[3].children.append(cert)  # type: ignore[union-attr]

    return _edited(edit)


def _signer_copy(edit: Any) -> _Node:
    """The FreeTSA signer certificate with serial number 7, its tbsCertificate's members
    edited by ``edit`` (and where its serial number is): a certificate no path names, its
    signature no longer verifying."""
    signer = read_rfc3161_token(FREETSA["tokenBase64"])
    assert not isinstance(signer, _rfc3161_steps.Rfc3161Unreadable)
    cert = _tree(signer.signer.der)
    fields = cert.children[0].children  # type: ignore[index]
    at = 1 if fields[0].ident == b"\xa0" else 0  # type: ignore[index]
    fields[at] = _leaf(0x02, b"\x07")  # type: ignore[index]
    edit(fields, at)
    return cert


def _steps(token: str) -> tuple[str, str | None]:
    verdict = verify_rfc3161_steps(token, FREETSA["digestHex"])
    return verdict.token, verdict.error


def test_an_element_of_certificates_that_is_not_the_certificate_choice_is_malformed() -> None:
    for tag in (0xA0, 0xA1, 0xA2, 0xA3):
        choice = _node(tag, _leaf(0x06, bytes.fromhex("2a0304")), _leaf(0x05))
        assert (tag, _steps(_with_certificate(choice))) == (tag, ("malformed", "certificate is not a SEQUENCE"))


def test_universal_types_29_35_and_36_are_in_the_form_x690_gives_them() -> None:
    assert _steps(_with_unsigned_attribute([_node(0x3D, _leaf(0x02, b"\x01"))]))[0] == "held"
    assert _steps(_with_unsigned_attribute([_leaf(b"\x1f\x23", b"/tzun")]))[0] == "held"
    assert _steps(_with_unsigned_attribute([_leaf(b"\x1f\x24", b"tzun")]))[0] == "held"
    assert _steps(_with_unsigned_attribute([_leaf(0x1D, b"\x00")])) == ("malformed", "primitive form of universal type 29")
    assert _steps(_with_unsigned_attribute([_node(b"\x3f\x23")])) == ("malformed", "constructed form of universal type 35")
    assert _steps(_with_unsigned_attribute([_node(b"\x3f\x24")])) == ("malformed", "constructed form of universal type 36")


def _shape(der: bytes) -> tuple[int, int]:
    """How deep the constructed elements of ``der`` nest (the outermost at depth 1), and how
    many elements it holds, neither looking inside a primitive element."""
    deepest, count = 0, 0

    def walk(node: _Node, depth: int) -> None:
        nonlocal deepest, count
        count += 1
        if node.children is None:
            return
        deepest = max(deepest, depth)
        for child in node.children:
            walk(child, depth + 1)

    walk(_tree(der), 1)
    return deepest, count


def test_the_decoder_bounds_are_64_levels_and_100000_elements_each_encoding_on_its_own() -> None:
    def nested(levels: int) -> _Node:
        inner = _node(0x30)
        for _ in range(levels - 1):
            inner = _node(0x30, inner)
        return inner

    # An attribute's values sit at depth 10: TimeStampResp, ContentInfo, [0], SignedData,
    # signerInfos, SignerInfo, unsignedAttrs [1], Attribute, its SET.
    for depth, verdict in ((64, ("held", None)), (65, ("malformed", "nested too deep"))):
        token = _with_unsigned_attribute([nested(depth - 9)])
        assert _shape(base64.b64decode(token))[0] == depth
        assert _steps(token) == verdict
    base = _shape(base64.b64decode(_with_unsigned_attribute([])))[1]
    for count, verdict in ((100_000, ("held", None)), (100_001, ("malformed", "too many elements"))):
        token = _with_unsigned_attribute([_leaf(0x05) for _ in range(count - base)])
        assert _shape(base64.b64decode(token))[1] == count
        assert _steps(token) == verdict

    # The TSTInfo, in an OCTET STRING, is bounded on its own: a tsa whose otherName holds
    # SEQUENCEs nested down to depth 64 passes step 1, and to 65 does not.
    def tsa_down_to(depth: int) -> Any:
        def edit(members: list[_Node]) -> None:
            inner = _node(0x30)
            for _ in range(depth - 4):
                inner = _node(0x30, inner)
            members[5:] = [_node(0xA0, _node(0xA0, inner))]
            assert _shape(_node(0x30, *members).der())[0] == depth

        return edit

    assert _steps(_with_tst_info(tsa_down_to(64)))[0] == "verification_failed"
    assert _steps(_with_tst_info(tsa_down_to(65))) == ("malformed", "TSTInfo is not DER: nested too deep")


_AFTER_GEN_TIME = (
    "TSTInfo holds members after genTime other than accuracy, ordering, nonce, tsa and extensions, in that order"
)
_ACCURACY = "the accuracy's millis or micros is not an INTEGER from 1 to 999"
_ACCURACY_SHAPE = "accuracy is not seconds, millis and micros, each optional, in that order"


def test_the_tst_info_decodes_whole() -> None:
    def tail(*members: _Node) -> str | None:
        def edit(tst: list[_Node]) -> None:
            tst[5:] = list(members)

        token, error = _steps(_with_tst_info(edit))
        return error if token == "malformed" else "step 1 holds"

    h = bytes.fromhex
    extension = _node(0x30, _leaf(0x06, h("2a0304")), _leaf(0x01, h("ff")), _leaf(0x04, h("0500")))
    name = _node(0x30, _node(0x31, _node(0x30, _leaf(0x06, h("550403")), _leaf(0x0C, b"TSA"))))
    every = [
        _node(0x30, _leaf(0x02, h("0102030405060708ff")), _leaf(0x80, h("03e7")), _leaf(0x81, h("01"))),
        _leaf(0x01, h("00")),
        _leaf(0x02, h("01")),
        _node(0xA0, _node(0xA4, name)),
        _node(0xA1, extension, extension),
    ]
    assert tail(*every) == "step 1 holds"
    assert tail() == "step 1 holds"
    assert [tail(_node(0xA0, _node(0xA0 + n))) for n in (0, 3, 4, 5)] == ["step 1 holds"] * 4
    assert [tail(_node(0xA0, _leaf(0x80 + n, b"\x00"))) for n in (1, 2, 6, 7, 8)] == ["step 1 holds"] * 5
    assert [
        tail(*every, _leaf(0x05)),
        tail(_leaf(0x02, h("01")), _leaf(0x01, h("00"))),
        tail(_node(0x30, _leaf(0x80, h("00")))),
        tail(_node(0x30, _leaf(0x80, h("0001")))),
        tail(_node(0x30, _leaf(0x81, h("03e8")))),
        tail(_node(0x30, _leaf(0x81, h("01")), _leaf(0x80, h("01")))),
        tail(_node(0xA0)),
        tail(_node(0xA0, _node(0xA2, _leaf(0x16, b"tsa.example")))),
        tail(_node(0xA0, _leaf(0x84, b"\x00"))),
        tail(_node(0xA0, _leaf(0x89, b"\x00"))),
        tail(_node(0xA1)),
        tail(_node(0xA1, _node(0x30, _leaf(0x06, h("2a0304"))))),
    ] == [
        _AFTER_GEN_TIME,
        _AFTER_GEN_TIME,
        _ACCURACY,
        _ACCURACY,
        _ACCURACY,
        _ACCURACY_SHAPE,
        "tsa is not one GeneralName",
        "tsa is not one GeneralName",
        "tsa is not one GeneralName",
        "tsa is not one GeneralName",
        "the TSTInfo extensions are not one or more extensions",
        "the TSTInfo extensions are not one or more extensions",
    ]


def test_gen_time_has_the_ranges_of_a_validity_time_and_keeps_its_fraction() -> None:
    def at(text: str) -> tuple[str, str | None]:
        def edit(tst: list[_Node]) -> None:
            tst[4] = _leaf(0x18, text.encode("latin-1"))

        return _steps(_with_tst_info(edit))

    for text in ("00000229120000Z", "20240229120000.5Z", "99991231235959Z", "00500101000000Z"):
        assert (text, at(text)[0]) == (text, "verification_failed")
    for text in (
        "20261301120000Z",
        "20260001120000Z",
        "20260631120000Z",
        "20230229120000Z",
        "01000229120000Z",
        "20260601240000Z",
        "20260601126000Z",
        "20260601120060Z",
    ):
        assert (text, at(text)) == (text, ("malformed", "genTime is not a GeneralizedTime"))


def _validity(not_before: str, not_after: str) -> _Node:
    def time(text: str) -> _Node:
        return _leaf(0x17 if len(text) == 13 else 0x18, text.encode("latin-1"))

    def edit(fields: list[_Node], at: int) -> None:
        fields[at + 3] = _node(0x30, time(not_before), time(not_after))

    return _signer_copy(edit)


def test_a_validity_time_has_no_fraction_any_year_and_the_gregorian_calendar() -> None:
    def read(not_before: str, not_after: str) -> tuple[str, str] | None:
        try:
            cert = _rfc3161_steps._read_certificate(_validity(not_before, not_after).der())
        except _rfc3161_steps._Malformed:
            return None
        return iso_from_millis(cert.not_before), iso_from_millis(cert.not_after)

    assert read("500101000000Z", "491231235959Z") == ("1950-01-01T00:00:00.000Z", "2049-12-31T23:59:59.000Z")
    assert read("00000229000000Z", "99991231235959Z") == ("0000-02-29T00:00:00.000Z", "9999-12-31T23:59:59.000Z")
    assert read("00500101000000Z", "00991231235959Z") == ("0050-01-01T00:00:00.000Z", "0099-12-31T23:59:59.000Z")
    assert read("20000229000000Z", "24000229000000Z") == ("2000-02-29T00:00:00.000Z", "2400-02-29T00:00:00.000Z")
    for not_before, not_after in (
        ("01000229000000Z", "20400101000000Z"),
        ("260101000000Z", "21000229000000Z"),
        ("230229000000Z", "400101000000Z"),
        ("260431000000Z", "400101000000Z"),
        ("20260101000000.5Z", "20400101000000Z"),
        ("260101000000Z", "20400101000000.25Z"),
        ("20261301000000Z", "20400101000000Z"),
        ("260101240000Z", "400101000000Z"),
        ("260101006000Z", "400101000000Z"),
        ("260101000060Z", "400101000000Z"),
    ):
        assert (not_before, not_after, read(not_before, not_after)) == (not_before, not_after, None)
    # In a token, a certificate no step needs: the year 0050 reads, a fraction does not.
    assert _steps(_with_certificate(_validity("00500101000000Z", "20400101000000Z")))[0] == "held"
    assert _steps(_with_certificate(_validity("20260101000000.5Z", "20400101000000Z"))) == (
        "malformed",
        "unreadable validity",
    )


_NOT_X509_AFTER_KEY = (
    "tbsCertificate holds fields after its subjectPublicKeyInfo other than a primitive [1], a primitive [2]"
    " and a constructed [3], in that order"
)


def test_what_follows_the_subject_public_key_info() -> None:
    def after(make: Any) -> _Node:
        def edit(fields: list[_Node], at: int) -> None:
            fields[at + 6 :] = make(fields[at + 6])

        return _signer_copy(edit)

    def uid(tag: int) -> _Node:
        return _leaf(tag, b"\x00\xab")

    def retagged(x: _Node) -> _Node:
        return _Node(b"\xa2", children=x.children)

    held = [
        lambda x: [uid(0x81), uid(0x82), x],
        lambda x: [uid(0x82), x],
        lambda x: [uid(0x81)],
        lambda x: [],
    ]
    assert [_steps(_with_certificate(after(make)))[0] for make in held] == ["held"] * 4
    refused = [
        lambda x: [retagged(x)],
        lambda x: [_node(0xA1, _leaf(0x03, b"\x00\xab")), x],
        lambda x: [_leaf(0x83, x.children[0].der())],
        lambda x: [uid(0x82), uid(0x81), x],
        lambda x: [uid(0x81), uid(0x81), x],
        lambda x: [x, x],
        lambda x: [x, _leaf(0x05)],
        lambda x: [_leaf(0x84, b"\x00"), x],
    ]
    assert [_steps(_with_certificate(after(make))) for make in refused] == [("malformed", _NOT_X509_AFTER_KEY)] * 8
    assert _steps(_with_certificate(after(lambda x: [_node(0xA3, *x.children, _node(0x30))]))) == (
        "malformed",
        "extensions are not one SEQUENCE",
    )
    assert _steps(_with_certificate(after(lambda x: [_node(0xA3)]))) == ("malformed", "extensions are not one SEQUENCE")


def test_a_requirement_of_step_3_it_can_check_decides_before_one_it_cannot() -> None:
    unknown_digest = _node(0x30, _leaf(0x06, bytes.fromhex("60864801650304027f")))  # 2.16.840.1.101.3.4.2.127
    unknown_signature = _node(0x30, _leaf(0x06, bytes.fromhex("2a8648ce3d04037f")))  # 1.2.840.10045.4.3.127

    def signer_info(edit: Any) -> Any:
        return lambda signed_data: edit(_signer_info(signed_data))

    def set_digest(si: list[_Node]) -> None:
        si[2] = unknown_digest

    def set_signature(si: list[_Node]) -> None:
        si[4] = unknown_signature

    def flip_signature(si: list[_Node]) -> None:
        si[5] = _leaf(0x04, si[5].content[:-1] + bytes([si[5].content[-1] ^ 0x01]))

    def flip_cert_hash(si: list[_Node]) -> None:
        # The signingCertificate attribute's first ESSCertID: its certHash, one bit flipped.
        attribute = next(a for a in si[3].children if a.children[0].content == bytes.fromhex("2a864886f70d010910020c"))  # type: ignore[union-attr,index]
        cert_hash = attribute.children[1].children[0].children[0].children[0].children[0]  # type: ignore[index]
        cert_hash.content = cert_hash.content[:-1] + bytes([cert_hash.content[-1] ^ 0x01])

    # FreeTSA signs with ecdsa-with-SHA512, so its signature is checked whatever the
    # SignerInfo's digestAlgorithm names.
    digest_unknown = _edited(signer_info(set_digest))
    assert _steps(digest_unknown) == ("missing_dependency", "digest algorithm 2.16.840.1.101.3.4.2.127 is not supported")
    assert _steps(_edited(signer_info(flip_signature), digest_unknown))[0] == "verification_failed"
    # A signature algorithm it does not implement, and a signer binding that fails.
    signature_unknown = _edited(signer_info(set_signature))
    assert _steps(signature_unknown) == ("missing_dependency", "signature algorithm 1.2.840.10045.4.3.127 is not supported")
    assert _steps(_edited(signer_info(flip_cert_hash), signature_unknown)) == (
        "verification_failed",
        "the signingCertificate certHash names another certificate",
    )
    # A signer key of an algorithm it does not implement: the binding, over the signer as
    # it was, fails first.
    def unknown_key(signed_data: list[_Node]) -> None:
        signer_der = read_rfc3161_token(FREETSA["tokenBase64"]).signer.der  # type: ignore[union-attr]
        for i, cert in enumerate(signed_data[3].children):  # type: ignore[arg-type]
            if cert.der() == signer_der:
                patched = signer_der.replace(bytes.fromhex("06072a8648ce3d0201"), bytes.fromhex("06072a8648ce3d0209"), 1)
                signed_data[3].children[i] = _tree(patched)  # type: ignore[index]

    assert _steps(_edited(unknown_key)) == ("verification_failed", "the signingCertificate certHash names another certificate")


# ---- What Node reads, read as Node reads it --------------------------------------------------------


def _signer_cn_value_tag_at(token: str) -> int:
    """Where the tag of the common name value in the signer certificate's subject is in the token."""
    read = read_rfc3161_token(token)
    assert not isinstance(read, _rfc3161_steps.Rfc3161Unreadable)
    der = base64.b64decode(token)
    subject_at = der.index(read.signer.subject, der.index(read.signer.der))
    return subject_at + read.signer.subject.index(bytes.fromhex("0603550403")) + 5


def test_a_name_value_openssl_does_not_read_makes_the_certificate_unreadable() -> None:
    # OpenSSL reads a Name's value only as a string type: an OCTET STRING there makes the
    # signer certificate no certificate, where step 1's own checks would read it.
    token = _patched(FREETSA["tokenBase64"], _signer_cn_value_tag_at(FREETSA["tokenBase64"]), 0x04)
    verdict = verify_rfc3161_steps(token, FREETSA["digestHex"])
    assert verdict.token == "malformed"
    assert verdict.error is not None and verdict.error.startswith("certificate does not parse: ")


def test_a_name_value_openssl_reads_leaves_the_certificate_readable() -> None:
    # Universal tag 15 is one OpenSSL files as unknown and reads: the certificate reads, and
    # the signingCertificateV2 no longer names it.
    token = _patched(FREETSA["tokenBase64"], _signer_cn_value_tag_at(FREETSA["tokenBase64"]), 0x0F)
    assert timestamp_conformance(token, FREETSA["digestHex"]).to_json() == {
        "holds": False,
        "reason": "verification_failed",
        "error": "the signingCertificate certHash names another certificate",
    }


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def test_an_rsa_key_is_read_as_openssl_reads_one() -> None:
    n = (1 << 2047) | 0x12345
    e = 65537
    n_bytes = n.to_bytes(256, "big")
    e_bytes = e.to_bytes(3, "big")
    integer = lambda b: _der(0x02, b)  # noqa: E731
    sequence = lambda *parts: _der(0x30, b"".join(parts))  # noqa: E731
    # Its INTEGERs unsigned and in any encoding, and what follows the SEQUENCE unread, as
    # Node's createPublicKey reads them.
    assert _openssl_rsa_key(sequence(integer(b"\x00" + n_bytes), integer(e_bytes))) == (n, e)
    assert _openssl_rsa_key(sequence(integer(n_bytes), integer(e_bytes))) == (n, e)
    assert _openssl_rsa_key(sequence(integer(b"\x00\x00" + n_bytes), integer(e_bytes))) == (n, e)
    assert _openssl_rsa_key(sequence(integer(n_bytes), integer(e_bytes)) + b"\x05\x00") == (n, e)
    assert _openssl_rsa_key(b"\x30\x80" + integer(n_bytes) + integer(e_bytes) + b"\x00\x00") == (n, e)
    assert _openssl_rsa_key(sequence(integer(b""), integer(e_bytes))) == (0, e)
    # And refused where Node refuses them.
    assert _openssl_rsa_key(sequence(integer(n_bytes), integer(e_bytes), integer(e_bytes))) is None
    assert _openssl_rsa_key(sequence(_der(0x04, n_bytes), integer(e_bytes))) is None
    assert _openssl_rsa_key(_der(0x31, integer(n_bytes) + integer(e_bytes))) is None
    assert _openssl_rsa_key(sequence(integer(n_bytes))) is None


def test_an_rsa_signature_is_checked_as_pkcs1_v1_5() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    signature = key.sign(b"signed attributes", padding.PKCS1v15(), hashes.SHA256())
    assert _rsa_pkcs1_verifies((numbers.n, numbers.e), "sha256", b"signed attributes", signature)
    assert not _rsa_pkcs1_verifies((numbers.n, numbers.e), "sha256", b"other attributes", signature)
    assert not _rsa_pkcs1_verifies((numbers.n, numbers.e), "sha384", b"signed attributes", signature)
    assert not _rsa_pkcs1_verifies((numbers.n, numbers.e), "sha256", b"signed attributes", signature[1:])
    assert not _rsa_pkcs1_verifies((numbers.n, numbers.e), "sha256", b"signed attributes", b"\x00" + signature)
    # A modulus that is not odd is one OpenSSL does not compute with.
    assert not _rsa_pkcs1_verifies((numbers.n + 1, numbers.e), "sha256", b"signed attributes", signature)


_P256 = "2a8648ce3d030107"
_SECP224K1 = "2b81040020"
#: An uncompressed point on P-256, and one on secp224k1.
_P256_POINT = bytes.fromhex(
    "045f899116779fc4ba3dd8c8dc3cc053e39879aa1a5505999da3f15e6a46cd120a6a5001a935e6ecefa5888ae3c90c06ae"
    "585216f538a6000f0cd008a4aff5039a"
)
_SECP224K1_POINT = bytes.fromhex(
    "04601ecff0b78cf61ed0491001194e55b4ac2b5d180ebdc94926c00cf9fd777c46c0a8f85ce6118ddbf746254d1cda8f"
    "a8eeb6361628f538b3"
)


def _ec_spki(curve: str | bytes, point: bytes) -> bytes:
    """An EC SubjectPublicKeyInfo on the named curve ``curve`` (hex of its OID's content),
    or with ``curve`` as its DER parameters."""
    params = _der(0x06, bytes.fromhex(curve)) if isinstance(curve, str) else curve
    algorithm = _der(0x30, _der(0x06, bytes.fromhex("2a8648ce3d0201")) + params)
    return _der(0x30, algorithm + _der(0x03, b"\x00" + point))


def _read_key(spki: bytes) -> Any:
    el = _rfc3161_steps._parse_der(spki)
    algorithm, key = _rfc3161_steps._elements_of(el.content)
    read = _rfc3161_steps._algorithm_of(algorithm)
    assert read is not None
    return _rfc3161_steps._read_public_key(el, read[0], read[1], key.content)


def test_an_ec_key_is_read_as_node_reads_it() -> None:
    p256 = _read_key(_ec_spki(_P256, _P256_POINT))
    assert p256.type == "ec" and p256.ec_limit is None and p256.key is not None
    # The point at infinity: Node reads it, and no signature verifies under it.
    infinity = _read_key(_ec_spki(_P256, b"\x00"))
    assert (infinity.type, infinity.ec_limit) == ("ec", "infinity")
    assert not _rfc3161_steps._verifies(infinity, "sha256", b"signed", b"\x30\x06\x02\x01\x01\x02\x01\x01")
    # A curve Node's OpenSSL implements and cryptography does not: a point of the curve's
    # length is read, and any other is not.
    assert _read_key(_ec_spki(_SECP224K1, _SECP224K1_POINT)).ec_limit == "unsupported"
    assert _read_key(_ec_spki(_SECP224K1, b"\x03" + _SECP224K1_POINT[1:29])).ec_limit == "unsupported"
    assert _read_key(_ec_spki(_SECP224K1, _P256_POINT)) is None
    assert _read_key(_ec_spki(_SECP224K1, b"\x05" + _SECP224K1_POINT[1:])) is None
    # A named curve Node's OpenSSL does not implement either (an OID assigned to no curve,
    # a GOST parameter set) is read with the key left unread, whatever its point
    # (tzun-anchor/1 §10.5 step 1); a point that is not on P-256 is not a key.
    for curve in ("2b81040063", "2a8648ce3d030163", "2a850302022301"):
        for point in (_P256_POINT, b"\x00", b"\x05"):
            key = _read_key(_ec_spki(curve, point))
            assert (key.type, key.ec_limit) == ("ec", "unimplemented")
    assert _read_key(_ec_spki(_P256, _P256_POINT[:-1] + bytes([_P256_POINT[-1] ^ 1]))) is None


def test_explicit_curve_parameters_are_read() -> None:
    # P-256's parameters, written out: cryptography loads them from 47.0.0, and before it
    # the key is read as one this verifier cannot check a signature under.
    p = 2**256 - 2**224 + 2**192 + 2**96 - 1
    a = (p - 3).to_bytes(32, "big")
    b = bytes.fromhex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
    g = bytes.fromhex(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e"
        "162bce33576b315ececbb6406837bf51f5"
    )
    n = bytes.fromhex("00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    params = _der(
        0x30,
        _der(0x02, b"\x01")
        + _der(0x30, _der(0x06, bytes.fromhex("2a8648ce3d0101")) + _der(0x02, b"\x00" + p.to_bytes(32, "big")))
        + _der(0x30, _der(0x04, a) + _der(0x04, b))
        + _der(0x04, g)
        + _der(0x02, n)
        + _der(0x02, b"\x01"),
    )
    key = _read_key(_ec_spki(params, _P256_POINT))
    assert key.type == "ec"
    assert key.key is not None or key.ec_limit == "unsupported"
    assert _read_key(_ec_spki(params, b"\x00")).ec_limit == "infinity"


def test_the_signer_key_this_verifier_cannot_check_is_missing_dependency() -> None:
    read = read_rfc3161_token(FREETSA["tokenBase64"])
    assert isinstance(read, _rfc3161_steps.Rfc3161Token)

    def signed_by(key: Any) -> Any:
        return _rfc3161_steps.check_signature_and_signer(
            dataclasses.replace(read, signer=dataclasses.replace(read.signer, public_key=key))
        )

    assert signed_by(_rfc3161_steps._PublicKey("ec", ec_limit="unsupported")) == (
        "missing_dependency",
        "the signer certificate's elliptic curve is not supported",
    )
    # A key on a curve Node does not implement either: whatever signature algorithm the
    # token names, as the TypeScript verifier reads a key it left unread.
    assert signed_by(_rfc3161_steps._PublicKey("ec", ec_limit="unimplemented")) == (
        "missing_dependency",
        "the signer certificate's elliptic curve is not supported",
    )
    assert signed_by(_rfc3161_steps._PublicKey("ec", ec_limit="infinity")) == (
        "verification_failed",
        "the signature does not verify under the signer certificate",
    )
    # A key it holds as no type it checks a signature with is a fault of this verifier,
    # which verify_rfc3161_steps reports as one.
    with pytest.raises(_rfc3161_steps._VerifierFault):
        signed_by(_rfc3161_steps._PublicKey("ec"))


def _nested(depth: int) -> bytes:
    """A constructed [UNIVERSAL 8] holding ``depth - 1`` constructed levels, then an OCTET STRING."""
    inner = _der(0x04, b"x")
    for _ in range(depth):
        inner = _der(0x28, inner)
    return inner


def _name(value: bytes) -> Any:
    return _rfc3161_steps._parse_der(
        _der(0x30, _der(0x31, _der(0x30, _der(0x06, bytes.fromhex("550403")) + value)))
    )


def test_a_name_and_parameters_are_collected_as_openssl_collects_them() -> None:
    # A constructed string five levels deep (ASN1_MAX_STRING_NEST), and a Name of at most
    # 1 MiB (X509_NAME_MAX).
    assert _rfc3161_steps._name_holds(_name(_nested(6))) is None
    assert _rfc3161_steps._name_holds(_name(_nested(7))) == "a Name's value nested too deep"
    assert _rfc3161_steps._name_holds(_name(_der(0x0C, b"a" * 1_000_000))) is None
    assert _rfc3161_steps._name_holds(_name(_der(0x0C, b"a" * 1_100_000))) == "a Name longer than X509_NAME_MAX"
    assert _rfc3161_steps._any_holds(_rfc3161_steps._parse_der(_nested(6))) is None
    assert _rfc3161_steps._any_holds(_rfc3161_steps._parse_der(_nested(7))) == "a constructed value nested too deep"


def test_a_token_nested_deep_is_read_without_copying_it() -> None:
    # A hostile authority's response: 16 MiB nested 50 deep. The reader takes each element
    # as a view of the token's bytes, so reading it costs about the token's size, not the
    # token's size at each level.
    blob = _der(0x04, bytes(16 << 20))
    for _ in range(50):
        blob = _der(0xA2, blob)
    der = _der(0x30, _der(0x30, _der(0x02, b"\x00")) + blob)
    token = base64.b64encode(der).decode("ascii")
    tracemalloc.start()
    try:
        verdict = verify_rfc3161_steps(token, "00" * 32)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert verdict == _rfc3161_steps.Rfc3161StepsVerdict("malformed", "TimeStampResp carries no timeStampToken")
    assert peak < 5 * len(der), (peak, len(der))


# ---- The client: the token kept, the event reported ----------------------------------------------

_EVENT = re.compile(
    r"event=attestation_timestamp_nonconformant digest=(?P<digest>\S+) authorityUrl=(?P<authorityUrl>\S+)"
    r" reason=(?P<reason>\S+) error=(?P<error>.*)"
)


def _envelope(digest: str) -> Any:
    return SimpleNamespace(integrity=SimpleNamespace(canonicalDigest=digest))


def _events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    out = []
    for record in caplog.records:
        m = _EVENT.fullmatch(record.getMessage())
        if m is not None:
            assert record.levelno == logging.WARNING
            assert record.name == "tzun_sdk.attestation.rfc3161"
            out.append({**m.groupdict(), "error": json.loads(m["error"])})
    return out


def _answering(token: str) -> Any:
    async def transport(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        return 200, base64.b64decode(token)

    return transport


def _stored_nonce(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    """Draw the request nonce ``token`` echoes, as a real request for it would have."""
    nonce = extract_tst_info(base64.b64decode(token))["nonce"]
    monkeypatch.setattr(secrets, "token_bytes", lambda n: int(nonce, 16).to_bytes(n, "big"))


async def test_a_public_authority_token_is_kept_and_nothing_is_reported(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _stored_nonce(monkeypatch, FREETSA["tokenBase64"])
    caplog.set_level(logging.WARNING, logger="tzun_sdk.attestation.rfc3161")
    blob = await RFC3161Backend(tsa_url=URL, transport=_answering(FREETSA["tokenBase64"])).attest(
        _envelope(FREETSA["digestHex"])
    )
    assert blob is not None and blob.rfc3161Token == FREETSA["tokenBase64"]
    assert _events(caplog) == []


async def test_a_token_whose_signature_does_not_verify_is_kept_and_reported(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    der = base64.b64decode(FREETSA["tokenBase64"])
    token = _flipped(FREETSA["tokenBase64"], len(der) - 1)
    _stored_nonce(monkeypatch, token)
    caplog.set_level(logging.WARNING, logger="tzun_sdk.attestation.rfc3161")
    blob = await RFC3161Backend(tsa_url=URL, transport=_answering(token)).attest(_envelope(FREETSA["digestHex"]))
    assert blob is not None and blob.rfc3161Token == token
    assert _events(caplog) == [
        {
            "digest": FREETSA["digestHex"],
            "authorityUrl": URL,
            "reason": "verification_failed",
            "error": "the signature does not verify under the signer certificate",
        }
    ]


async def test_a_mock_authority_token_is_kept_and_reported(
    envelope_fixture: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="tzun_sdk.attestation.rfc3161")
    blob = await RFC3161Backend(tsa_url=URL, transport=mock_tsa_transport()).attest(envelope_fixture)
    assert blob is not None and blob.rfc3161Token is not None
    assert _events(caplog) == [
        {
            "digest": envelope_fixture.integrity.canonicalDigest,
            "authorityUrl": URL,
            "reason": "malformed",
            "error": "SignedData does not carry exactly one SignerInfo",
        }
    ]


async def test_a_tst_info_in_ber_is_kept_and_reported(
    envelope_fixture: Any, caplog: pytest.LogCaptureFixture
) -> None:
    # A private authority that writes the TSTInfo in a constructed OCTET STRING: the
    # TypeScript client keeps its token and reports it, and so does this one.
    caplog.set_level(logging.WARNING, logger="tzun_sdk.attestation.rfc3161")
    blob = await RFC3161Backend(tsa_url=URL, transport=mock_tsa_transport(ber_tst_info=True)).attest(
        envelope_fixture
    )
    assert blob is not None and blob.rfc3161Metadata is not None
    assert blob.rfc3161Metadata.genTime == "20260102030405Z"
    assert _events(caplog) == [
        {
            "digest": envelope_fixture.integrity.canonicalDigest,
            "authorityUrl": URL,
            "reason": "malformed",
            "error": "constructed form of universal type 4",
        }
    ]


async def test_a_response_in_indefinite_length_is_kept_and_reported(
    envelope_fixture: Any, caplog: pytest.LogCaptureFixture
) -> None:
    # BER the TypeScript client's reader (asn1js) reads: kept, and reported.
    caplog.set_level(logging.WARNING, logger="tzun_sdk.attestation.rfc3161")
    blob = await RFC3161Backend(tsa_url=URL, transport=mock_tsa_transport(indefinite_length=True)).attest(
        envelope_fixture
    )
    assert blob is not None and blob.rfc3161Token is not None
    assert _events(caplog) == [
        {
            "digest": envelope_fixture.integrity.canonicalDigest,
            "authorityUrl": URL,
            "reason": "malformed",
            "error": "indefinite length",
        }
    ]


async def test_a_nested_segment_adds_nothing_to_the_tst_info(
    envelope_fixture: Any, caplog: pytest.LogCaptureFixture
) -> None:
    # asn1js joins a constructed OCTET STRING's own segments: one nested inside adds
    # nothing, so the TSTInfo still reads.
    caplog.set_level(logging.WARNING, logger="tzun_sdk.attestation.rfc3161")
    backend = RFC3161Backend(tsa_url=URL, transport=mock_tsa_transport(ber_nested_segment="octets"))
    blob = await backend.attest(envelope_fixture)
    assert blob is not None and blob.rfc3161Metadata is not None
    assert blob.rfc3161Metadata.genTime == "20260102030405Z"
    assert [e["error"] for e in _events(caplog)] == ["constructed form of universal type 4"]


async def test_a_nested_segment_of_another_type_is_refused(envelope_fixture: Any) -> None:
    backend = RFC3161Backend(tsa_url=URL, transport=mock_tsa_transport(ber_nested_segment="integer"))
    with pytest.raises(TsaUnavailableError, match="not a parseable RFC 3161 TimeStampResp: a constructed string holds another type"):
        await backend.attest(envelope_fixture)


async def test_digest_algorithms_that_are_not_algorithm_identifiers_are_refused(envelope_fixture: Any) -> None:
    # The TypeScript client reads SignedData by its schema and refuses this before any
    # check of §10.5; so does this one.
    backend = RFC3161Backend(tsa_url=URL, transport=mock_tsa_transport(bare_digest_algorithm=True))
    with pytest.raises(TsaUnavailableError, match="digestAlgorithms holds something else"):
        await backend.attest(envelope_fixture)


def test_conformance_as_the_typescript_type_writes_it() -> None:
    assert TimestampConformance(holds=True).to_json() == {"holds": True}
    assert TimestampConformance(holds=False, reason="malformed", error="x").to_json() == {
        "holds": False,
        "reason": "malformed",
        "error": "x",
    }


# ---- The roots the auditor supplies, and the authority ------------------------------

_CERTS = pathlib.Path(__file__).resolve().parents[3] / "src" / "attestation" / "certs"


def _pem(der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def _der_of(pem: str) -> bytes:
    return base64.b64decode("".join(pem.split("-----")[2].split()))


@pytest.mark.parametrize("path", sorted(_CERTS.glob("*.pem")), ids=lambda p: p.stem)
def test_every_root_the_registry_ships_reads(path: pathlib.Path) -> None:
    assert len(read_trust_anchors([path.read_text("utf-8")])) >= 1


def test_a_root_that_cannot_be_read_is_refused_never_dropped() -> None:
    root = (_CERTS / "freetsa-ca.pem").read_text("utf-8")
    der = _der_of(root)
    # FreeTSA's root is RSA: rsaEncryption renamed to an OID no verifier implements.
    rsa = bytes.fromhex("06092a864886f70d010101")
    unknown = der.replace(rsa, bytes.fromhex("06092a864886f70d010163"), 1)
    assert unknown != der
    cases: list[tuple[object, str]] = [
        ("not a list", "the trust anchors are not a list of PEM strings"),
        ([7], "trust anchor 1 is not a PEM string"),
        (["no certificate"], "trust anchor 1 holds no PEM CERTIFICATE block"),
        ([root, "no certificate"], "trust anchor 2 holds no PEM CERTIFICATE block"),
        (["-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"], "trust anchor 1 is not base64"),
        (
            ["-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----"],
            "trust anchor 1 does not read as a certificate: ",
        ),
        (
            [_pem(unknown)],
            "trust anchor 1 has a key this verifier does not implement: its public-key algorithm is not supported",
        ),
        (
            [root + _pem(unknown)],
            "trust anchor 1, certificate 2 has a key this verifier does not implement: its public-key algorithm is not supported",
        ),
    ]
    for pems, message in cases:
        with pytest.raises(UnreadableTrustAnchorError) as refused:
            read_trust_anchors(pems)
        assert str(refused.value).startswith(message), (pems, str(refused.value))
    assert isinstance(UnreadableTrustAnchorError("x"), ValueError)


def test_a_pem_body_is_stripped_of_ascii_white_space_alone() -> None:
    # As the TypeScript verifier strips it: any other character between the base64 lines,
    # Unicode white space included, makes the body not base64.
    lines = (_CERTS / "freetsa-ca.pem").read_text("utf-8").strip().split("\n")

    def joined(separator: str) -> str:
        return lines[0] + "\n" + separator.join(lines[1:-1]) + "\n" + lines[-1]

    for separator in ("\t", "\v", "\f", "\r\n", "  "):
        assert len(read_trust_anchors([joined(separator)])) == 1
    for separator in ("\x1c", "\x1f", "\x85", "\u00a0", "\u2028", "\u3000", "\ufeff"):
        with pytest.raises(UnreadableTrustAnchorError, match=r"^trust anchor 1 is not base64$"):
            read_trust_anchors([joined(separator)])


def test_a_root_whose_key_is_on_a_curve_no_one_implements_is_refused() -> None:
    signer = read_rfc3161_token(FREETSA["tokenBase64"])
    assert isinstance(signer, _rfc3161_steps.Rfc3161Token)
    # FreeTSA's signer certificate with its SubjectPublicKeyInfo replaced by a P-256 point
    # named on the curve OID 1.2.840.10045.3.1.99, assigned to no curve.
    cert = _rfc3161_steps._parse_der(signer.signer.der)
    tbs, *rest = _rfc3161_steps._elements_of(cert.content)
    fields = [bytes(f.raw) for f in _rfc3161_steps._elements_of(tbs.content)]
    at = fields.index(signer.signer.spki)
    fields[at] = _ec_spki("2a8648ce3d030163", _P256_POINT)
    renamed = _der(0x30, _der(0x30, b"".join(fields)) + b"".join(bytes(r.raw) for r in rest))
    with pytest.raises(UnreadableTrustAnchorError, match="its elliptic curve is not supported"):
        read_trust_anchors([_pem(renamed)])


def _cn_name(tag: int, value: bytes) -> bytes:
    atv = _der(0x30, _der(0x06, bytes.fromhex("550403")) + _der(tag, value))
    return _der(0x30, _der(0x31, atv))


@pytest.mark.parametrize(
    ("subject", "authority"),
    [
        (_cn_name(12, "Zürich Ω".encode()), "Zürich Ω"),
        (_cn_name(12, b" Acme, Inc. \\ "), " Acme, Inc. \\ "),
        (_cn_name(30, "Zürich".encode("utf-16-be")), "Zürich"),
        (_cn_name(20, "Zürich".encode("latin-1")), "Zürich"),
        (_cn_name(28, "Z😀".encode("utf-32-be")), "Z😀"),
        (_cn_name(12, b""), ""),
        (_der(0x30, b""), ""),
        (_der(0x30, _der(0x31, _der(0x30, _der(0x06, bytes.fromhex("55040a")) + _der(12, b"Org")))), ""),
        (_cn_name(30, bytes.fromhex("d800005a")), "\ufffdZ"),
    ],
)
def test_the_authority_is_the_first_common_name_as_encoded(subject: bytes, authority: str) -> None:
    signer = read_rfc3161_token(FREETSA["tokenBase64"])
    assert isinstance(signer, _rfc3161_steps.Rfc3161Token)
    assert authority_of(dataclasses.replace(signer.signer, subject=subject)) == authority


def test_the_steps_verdict_carries_the_authority_once_step_1_holds() -> None:
    assert verify_rfc3161_steps(FREETSA["tokenBase64"], FREETSA["digestHex"]).authority == FREETSA["signerCommonName"]
    other = hashlib.sha256(b"another value").hexdigest()
    assert verify_rfc3161_steps(FREETSA["tokenBase64"], other).authority == FREETSA["signerCommonName"]
    assert verify_rfc3161_steps("not a token", other).authority is None
