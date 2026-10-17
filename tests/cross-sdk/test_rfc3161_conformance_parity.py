"""The RFC 3161 client's check at capture in both SDKs: the same tokens, the same finding.

Each SDK's client checks every token it keeps against tzun-anchor/1 §10.5 steps 1 to 3 over
the requested digest (TypeScript ``timestampConformance`` in ``src/attestation/rfc3161.ts``,
Python ``tzun_sdk.attestation.rfc3161.timestamp_conformance``), keeps a token that does not
meet them, and reports it as ``attestation_timestamp_nonconformant`` with its ``digest``,
``authorityUrl``, ``reason`` and ``error``. ``ts-harness/rfc3161-conformance.ts`` runs the
TypeScript side; this file requires the Python side to give the same answer:

- on every stored public authority's token (``tests/ts/fixtures/tsa-tokens.json``);
- on a token from a throwaway authority for each ``TokenFaults`` shape of
  ``tests/ts/rfc3161-fixture.ts``, one rule broken at a time, and the mock authority's
  unsigned token;
- on every byte of the stored FreeTSA token, of the conforming throwaway token and of the
  mock token, flipped;
- on certificates and keys Node reads by OpenSSL's rules and :mod:`cryptography` reads by
  its own: EC curves it does not implement, explicit curve parameters, the point at
  infinity, a Name's nesting and size, RSASSA-PSS and DHX keys;
- on keys on a named curve neither implements (a curve OID assigned to no curve, a GOST
  parameter set): read with the key left unread, ``missing_dependency`` where step 3
  needs the key and not examined where no step does (tzun-anchor/1 §10.5 steps 1 and 5);
- on the ``authority`` fact of a trust check, from the signer subject's Name (§10.5 step
  4), and on the trust roots each SDK refuses as unreadable, in the same words
  (Verification §3.1);
- end to end, through each SDK's client and its report: whether the token is stored, and
  the event; on BER the TypeScript client's reader reads, and on every byte the two
  clients' readers decide on, flipped.

Where the Python verifier cannot do what Node does (a signature under an EC key
:mod:`cryptography` does not load, that key's point against its curve), the answers
differ, and ``test_the_python_verifier_limits_are_what_they_are`` pins both.

An error that carries a library's own message (``certificate does not parse: …`` and the
like) is compared up to the colon: the words after it are OpenSSL's in Node and this
library's in Python. Every other error is compared whole.

Skipped without Node.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import json
import logging
import pathlib
import re
import secrets
import shutil
import subprocess
from collections import Counter
from types import SimpleNamespace
from typing import Any

import pytest

from tzun_sdk.attestation._rfc3161_steps import (
    UnreadableTrustAnchorError,
    authority_of,
    read_rfc3161_token,
    read_trust_anchors,
    verify_rfc3161_steps,
)
from tzun_sdk.attestation._rfc3161_token import pkijs_only_regions
from tzun_sdk.attestation.rfc3161 import RFC3161Backend, extract_tst_info, timestamp_conformance
from tzun_sdk.errors import TsaUnavailableError

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
HARNESS = REPO_ROOT / "tests" / "cross-sdk" / "ts-harness" / "rfc3161-conformance.ts"
STORED = json.loads((REPO_ROOT / "tests" / "ts" / "fixtures" / "tsa-tokens.json").read_text("utf-8"))

DIGEST = hashlib.sha256(b"rfc3161 conformance parity").hexdigest()
NONCE = "1122334455667788"
GEN_TIME = "2026-06-01T12:00:00.500Z"
URL = "https://private-tsa.example/tsr"

#: The start of each error that goes on in a library's own words.
LIBRARY_MESSAGES = (
    "certificate does not parse: ",
    "the certificate's public key does not decode: ",
    "the signature does not verify: ",
    "unreadable: ",
    "the RFC 3161 verifier failed on this token",
)

#: What each token of the corpus is at steps 1 to 3 (its `TokenFaults` in the harness).
EXPECTED = {
    "conforming": None,
    "ber-tst-info": "malformed",
    "non-der-gen-time": "malformed",
    "without-signer-certificate": "malformed",
    "digest-algorithms-bare-oid": "malformed",
    "signer-key-bad": "malformed",
    "signer-key-unknown-algorithm": "missing_dependency",
    "issuer-copy-bad-key": "malformed",
    # The copy's key is of an algorithm no verifier reads: it signs nothing, and step 3 holds.
    "issuer-copy-unknown-key-algorithm": None,
    # A key on a curve assigned to no curve is left unread: step 3 needs the signer's, and
    # no step needs the others' (tzun-anchor/1 §10.5 steps 1 and 5).
    "signer-key-unassigned-curve": "missing_dependency",
    "issuer-copy-unassigned-curve": None,
    "unneeded-certificate-unassigned-curve": None,
    # The intermediate is step 4's, which capture does not check.
    "signer-issuer-intermediate-unassigned-curve": None,
    "content-type-data": "verification_failed",
    "message-digest-other": "verification_failed",
    # A name written in another string type breaks step 4, the path, which capture does not check.
    "signer-issuer-name-utf8": None,
    "signing-certificate-v1": None,
    "signing-certificate-none": "verification_failed",
    "signing-certificate-other": "verification_failed",
    "signer-eku-none": "verification_failed",
    "signer-eku-non-critical": "verification_failed",
    "signer-eku-tls-server": "verification_failed",
    "signer-eku-second-purpose": "verification_failed",
    # A requirement of step 3 the verifier can check decides before one that needs a key or
    # an algorithm it does not implement (tzun-anchor/1 §10.5 step 5).
    "signer-key-unknown-algorithm-eku-none": "verification_failed",
    "signer-key-unassigned-curve-eku-none": "verification_failed",
    "signing-certificate-v2-unknown-hash": "missing_dependency",
    "signing-certificate-v2-unknown-hash-eku-none": "verification_failed",
    "signing-certificate-v2-unknown-hash-other-serial": "verification_failed",
    # The signed attributes out of DER SET OF order, signed as carried.
    "signed-attrs-reversed": None,
    # The TSTInfo decodes whole by RFC 3161 §2.4.2 (§10.5 step 1).
    "tst-info-all": None,
    "tst-info-member-after-extensions": "malformed",
    "tst-info-ordering-after-nonce": "malformed",
    "tst-info-millis-zero": "malformed",
    "tst-info-micros-1000": "malformed",
    "tst-info-tsa-empty": "malformed",
    "tst-info-tsa-dns-name-constructed": "malformed",
    "tst-info-extensions-empty": "malformed",
    "mock-authority": "malformed",
}


def harness(cmd: dict[str, Any]) -> Any:
    """Run one command through the TypeScript harness."""
    if shutil.which("npx") is None:
        pytest.skip("Node not available: the cross-SDK suite needs Node 22+")
    proc = subprocess.run(
        ["npx", "tsx", str(HARNESS)],
        input=json.dumps(cmd),
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=600,
    )
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError(
            f"rfc3161-conformance harness failed (exit {proc.returncode})\nstderr: {proc.stderr}"
        )
    return json.loads(proc.stdout)


def comparable(conformance: dict[str, Any]) -> dict[str, Any]:
    """A conformance as both SDKs must agree on it: an error in a library's own words is
    compared up to the colon."""
    error = conformance.get("error")
    if isinstance(error, str):
        for prefix in LIBRARY_MESSAGES:
            if error.startswith(prefix):
                return {**conformance, "error": prefix}
    return conformance


def python_conformance(token: str, digest: str) -> dict[str, Any]:
    return timestamp_conformance(token, digest).to_json()


def flipped(token: str, i: int, mask: int) -> str:
    der = bytearray(base64.b64decode(token))
    der[i] ^= mask
    return base64.b64encode(bytes(der)).decode("ascii")


@pytest.fixture(scope="module")
def corpus() -> dict[str, str]:
    cases = harness({"action": "corpus", "digest": DIGEST, "nonce": NONCE, "genTime": GEN_TIME})["cases"]
    return {c["name"]: c["token"] for c in cases}


def test_every_stored_authority_token_holds_in_both() -> None:
    cases = [{"token": t["tokenBase64"], "digest": t["digestHex"]} for t in STORED.values()]
    ts = harness({"action": "conformance", "cases": cases})["results"]
    py = [python_conformance(c["token"], c["digest"]) for c in cases]
    assert ts == py == [{"holds": True}] * len(cases)


def test_each_broken_rule_gives_the_same_finding(corpus: dict[str, str]) -> None:
    assert sorted(corpus) == sorted(EXPECTED)
    names = sorted(corpus)
    cases = [{"token": corpus[n], "digest": DIGEST} for n in names]
    # And the conforming token over another value: step 2.
    cases.append({"token": corpus["conforming"], "digest": hashlib.sha256(b"another value").hexdigest()})
    ts = harness({"action": "conformance", "cases": cases})["results"]
    py = [python_conformance(c["token"], c["digest"]) for c in cases]
    for name, t, p in zip([*names, "conforming over another value"], ts, py, strict=True):
        assert (name, comparable(p)) == (name, comparable(t))
    reasons = {n: (None if r["holds"] else r["reason"]) for n, r in zip(names, py, strict=False)}
    assert reasons == EXPECTED
    assert py[-1] == {
        "holds": False,
        "reason": "imprint_mismatch",
        "error": "the imprint is not SHA-256 over the expected value",
    }


@pytest.mark.parametrize("source", ["freetsa", "conforming", "mock-authority"])
def test_every_flipped_byte_gives_the_same_finding(source: str, corpus: dict[str, str]) -> None:
    if source in STORED:
        token, digest = STORED[source]["tokenBase64"], STORED[source]["digestHex"]
    else:
        token, digest = corpus[source], DIGEST
    ts = harness({"action": "flips", "token": token, "digest": digest, "mask": 0x01})["results"]
    size = len(base64.b64decode(token))
    assert len(ts) == size
    seen: Counter[str] = Counter()
    for i, t in enumerate(ts):
        p = python_conformance(flipped(token, i, 0x01), digest)
        assert (i, comparable(p)) == (i, comparable(t))
        seen["held" if p["holds"] else p["reason"]] += 1
    # The flips reach every step, not only step 1.
    if source != "mock-authority":
        assert {"held", "malformed", "verification_failed"} <= set(seen), seen


# ---- End to end: the client, its report ----------------------------------------------------------

_EVENT = re.compile(
    r"event=(?P<event>\S+) digest=(?P<digest>\S+) authorityUrl=(?P<authorityUrl>\S+)"
    r" reason=(?P<reason>\S+)(?: error=(?P<error>.*))?"
)


def nonce_of(token: str) -> str:
    """The 8-byte request nonce ``token`` echoes, as the client draws it."""
    nonce = extract_tst_info(base64.b64decode(token))["nonce"]
    assert nonce is not None
    return int(nonce, 16).to_bytes(8, "big").hex()


def python_capture(
    token: str, digest: str, nonce: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> dict[str, Any]:
    """A capture's attestation through the Python client whose one authority answers with
    ``token``: whether the token is stored, and the events it reports."""
    monkeypatch.setattr(secrets, "token_bytes", lambda n: bytes.fromhex(nonce))

    async def transport(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
        return 200, base64.b64decode(token)

    backend = RFC3161Backend(tsa_url=URL, transport=transport)
    envelope = SimpleNamespace(integrity=SimpleNamespace(canonicalDigest=digest))
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="tzun_sdk.attestation.rfc3161"):
        try:
            blob = asyncio.run(backend.attest(envelope))  # type: ignore[arg-type]
        except TsaUnavailableError:
            blob = None
    events = []
    for record in caplog.records:
        m = _EVENT.fullmatch(record.getMessage())
        if m and m["event"] == "attestation_timestamp_nonconformant":
            event = {k: v for k, v in m.groupdict().items() if k != "error"}
            if m["error"] is not None:
                event["error"] = json.loads(m["error"])
            events.append(event)
    return {"stored": blob is not None and blob.rfc3161Token == token, "events": events}


def test_capture_keeps_the_same_tokens_and_reports_the_same_event(
    corpus: dict[str, str], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    freetsa = STORED["freetsa"]
    signer = read_rfc3161_token(freetsa["tokenBase64"])
    der = base64.b64decode(freetsa["tokenBase64"])
    key_at = der.index(signer.signer.spki) + len(signer.signer.spki) // 2  # type: ignore[union-attr]
    nonce = nonce_of(freetsa["tokenBase64"])
    cases = [
        # A real public authority's token: stored, nothing reported.
        ("freetsa", freetsa["tokenBase64"], freetsa["digestHex"], nonce),
        # Its signature, the last byte of the token, flipped.
        ("freetsa, signature flipped", flipped(freetsa["tokenBase64"], len(der) - 1, 0x01), freetsa["digestHex"], nonce),
        # A byte of the signer certificate's key flipped: the key still reads.
        ("freetsa, signer key flipped", flipped(freetsa["tokenBase64"], key_at, 0x01), freetsa["digestHex"], nonce),
        *((name, corpus[name], DIGEST, NONCE) for name in sorted(corpus)),
    ]
    requests = [{"token": t, "digest": d, "nonce": n} for _, t, d, n in cases]
    ts = harness({"action": "capture", "url": URL, "cases": requests})["results"]
    for (name, token, digest, request_nonce), t in zip(cases, ts, strict=True):
        p = python_capture(token, digest, request_nonce, monkeypatch, caplog)
        assert (name, p["stored"]) == (name, t["stored"])
        assert (name, [comparable(e) for e in p["events"]]) == (name, [comparable(e) for e in t["events"]])
        # Both clients refuse a SignedData whose digestAlgorithms are not
        # AlgorithmIdentifiers, before any check of §10.5; they keep every other token.
        if name == "digest-algorithms-bare-oid":
            assert not p["stored"] and p["events"] == [], name
            continue
        assert p["stored"], name
        conformance = timestamp_conformance(token, digest)
        if conformance.holds:
            assert p["events"] == [], name
        else:
            assert p["events"] == [
                {
                    "event": "attestation_timestamp_nonconformant",
                    "digest": digest,
                    "authorityUrl": URL,
                    "reason": conformance.reason,
                    "error": conformance.error,
                }
            ], name


@pytest.mark.parametrize("source", ["freetsa", "digicert", "mock-authority"])
def test_capture_keeps_the_same_flipped_tokens(
    source: str, corpus: dict[str, str], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Each byte the clients' own readers decide on, flipped: the same tokens kept, and the
    same events. The bytes of the certificates and the signer infos are left out: pkijs
    reads them by its X.509 and CMS schemas, and the Python reader does not
    (``tzun_sdk.attestation._rfc3161_token``), so a token corrupted only there is refused
    by the TypeScript client and kept and reported by the Python one."""
    if source in STORED:
        token, digest = STORED[source]["tokenBase64"], STORED[source]["digestHex"]
        nonce = nonce_of(token)
    else:
        token, digest, nonce = corpus[source], DIGEST, NONCE
    regions = pkijs_only_regions(token)
    offsets = [i for i in range(len(base64.b64decode(token))) if not any(a <= i < b for a, b in regions)]
    tokens = [flipped(token, i, 0x01) for i in offsets]
    requests = [{"token": t, "digest": digest, "nonce": nonce} for t in tokens]
    ts = harness({"action": "capture", "url": URL, "cases": requests})["results"]
    kept: Counter[bool] = Counter()
    for i, flipped_token, t in zip(offsets, tokens, ts, strict=True):
        p = python_capture(flipped_token, digest, nonce, monkeypatch, caplog)
        assert (i, p["stored"]) == (i, t["stored"])
        assert (i, [comparable(e) for e in p["events"]]) == (i, [comparable(e) for e in t["events"]])
        kept[p["stored"]] += 1
    # The flips reach both answers: kept (and reported), and refused.
    assert kept[True] and kept[False], kept


# ---- Certificates and keys Node reads by OpenSSL's rules ------------------------------------------


class _El:
    """A DER element to edit and write back: its identifier octets, and its content or its
    elements; written in the indefinite-length form when ``indefinite``."""

    def __init__(self, ident: bytes, content: bytes = b"", children: list[_El] | None = None) -> None:
        self.ident = ident
        self.content = content
        self.children = children
        self.indefinite = False

    def der(self) -> bytes:
        body = b"".join(c.der() for c in self.children) if self.children is not None else self.content
        if self.indefinite:
            return self.ident + b"\x80" + body + b"\x00\x00"
        if len(body) < 0x80:
            return self.ident + bytes([len(body)]) + body
        n = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        return self.ident + bytes([0x80 | len(n)]) + n + body


def _el(der: bytes) -> _El:
    """``der``, one definite-length element, as an ``_El`` tree."""

    def one(pos: int) -> tuple[_El, int]:
        first = der[pos]
        end_of_tag = pos + 1
        if first & 0x1F == 0x1F:
            while der[end_of_tag] & 0x80:
                end_of_tag += 1
            end_of_tag += 1
        length, at = der[end_of_tag], end_of_tag + 1
        if length & 0x80:
            n = length & 0x7F
            length, at = int.from_bytes(der[at : at + n], "big"), at + n
        content = der[at : at + length]
        if first & 0x20:
            children, p = [], at
            while p < at + length:
                child, p = one(p)
                children.append(child)
            return _El(der[pos:end_of_tag], children=children), at + length
        return _El(der[pos:end_of_tag], content), at + length

    el, end = one(0)
    assert end == len(der)
    return el


def _certificates(resp: _El) -> _El:
    signed_data = resp.children[1].children[1].children[0]  # type: ignore[index]
    return next(c for c in signed_data.children if c.ident == b"\xa0")  # type: ignore[union-attr]


def _tbs(cert: _El) -> tuple[list[_El], int]:
    """A certificate's tbsCertificate fields, and where its serialNumber is."""
    fields = cert.children[0].children  # type: ignore[index]
    return fields, 1 if fields[0].ident == b"\xa0" else 0  # type: ignore[index,return-value]


#: SubjectPublicKeyInfos whose keys Node reads, as OpenSSL reads them.
SPKI = {
    # Named curves cryptography does not implement.
    "secp224k1": "304e301006072a8648ce3d020106052b81040020033a0004601ecff0b78cf61ed0491001194e55b4ac2b5d"
    "180ebdc94926c00cf9fd777c46c0a8f85ce6118ddbf746254d1cda8fa8eeb6361628f538b3",
    "brainpoolP192r1": "304a301406072a8648ce3d020106092b2403030208010103033200046acf7fb0e8c0f89480d6951f328e55"
    "e1a05e462ac65d3e56a9373e78d594d079908f66027e44805903aac9a8a8288b99",
    "p256": "3059301306072a8648ce3d020106082a8648ce3d030107034200045f899116779fc4ba3dd8c8dc3cc053e398"
    "79aa1a5505999da3f15e6a46cd120a6a5001a935e6ecefa5888ae3c90c06ae585216f538a6000f0cd008a4aff5039a",
    # P-256 written with explicit curve parameters, which cryptography loads from 47.0.0.
    "p256-explicit": "3082014b3082010306072a8648ce3d02013081f7020101302c06072a8648ce3d0101022100ffffffff0000"
    "0001000000000000000000000000ffffffffffffffffffffffff305b0420ffffffff0000000100000000000000000000"
    "0000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
    "031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb"
    "33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffff"
    "ff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101034200048d653b8b6770798fcad0c716"
    "47242ed5484c29b5b10df1e0e696e78025f70a42a437ae7b5ecf6297594747044794ec49dd806027816c9a3d5526e857"
    "b3df2b7f",
    # RSASSA-PSS with its parameters absent.
    "rsa-pss": "30820120300b06092a864886f70d01010a0382010f003082010a0282010100ac6d437041fef1bd4921c4b7a2"
    "81286a027f5fe672cd276e7bfc63faa4870a3ddedc338eb0f532a9cfa980645e1675a7ef5065ea8049b4fff8384fb2"
    "53212d12add70b38b174654a32760d9fbf906cf24ffc296cf373fb2a01b4c6355919360b05a793774f9434ef2599b3"
    "2bfbc4b98c0f47bf58ca14b4546f2015265bef684af7888035b96c5b60ffc188c21420b4521ea8f6f0a438b439cb4e"
    "e4cc02e438e495f50e222bdcf3e48dd2a03cbc6020f4e49e57c0dfdd8633a45713a518f785abb72e5bc188e4d916b0"
    "358dd568d3448ad1ac3e25eadeb66858403eb5668131efa8d05cc211baf0b12cc352886f8995fb1fdae997720ab6eb"
    "02a42580fb59540f0203010001",
    # An X9.42 DH key, which Node reads and names no type.
    "dhx": "308201be3082013306072a8648ce3e02013082012602818100fecd7e8841bff7010391be7dbb2df072f93ead26"
    "fc43285c576dbf3a3811b5371407a5832a0ddd7b29efc638a588aeb4fcfc198f0705fefdd75374035703c95cb1e873"
    "3fd51b5269cc54dc4b02d1ce4c059e8138f4a898de19253505e2187c3c3b3df53019b56a709f0699e5b2e96a6886b5"
    "2d24424c23b2983739e2ddbefef9028180713a18ca2c73be79be8681d02af2a7d170d75d50863f30b9c23635b2dae5"
    "b29a6b98d0d8a7030372dc6ab68b8d0b555094fa2ee5bb0b7b2a9d9de6307f8b790780088ff65b5577f1c2cd01bd56"
    "bdf0d2a42084bf2b5fca54f33a62ff4cfdd6d032ef101b3f6c4274b7aa08f74826aa2475fd550e391a67b26aedac96"
    "8ec3b772021d00e84ffddda4d84468c522277d85cfbffb0323a48e755d89ab5b4809bf0381840002818003a173e56e"
    "21a66489bfef8c437f7514122d3e4e33fb2aadf3361376c28d9c46e1dc5e6f9933aa504a776b3fe92fce76da8e1c8a"
    "1ef5bf359764332c64601768e65dc0e0d92b338bbbc9f5630d59cb6a2b9834010e6f9e519485e51c447f228836da67"
    "fa4402dfbb4c4a6e2c048fae3dd28f78302eca7b8484643a2949452f75",
}


def _spki(name: str, *, curve: str | None = None, point: bytes | None = None, params: bytes | None = None) -> _El:
    """``SPKI[name]``, with another named curve (hex of its OID's content), another point
    (a subjectPublicKey's bytes after its unused-bits count), or other parameters (DER)."""
    spki = _el(bytes.fromhex(SPKI[name]))
    algorithm = spki.children[0]  # type: ignore[index]
    if curve is not None:
        algorithm.children[1] = _El(b"\x06", bytes.fromhex(curve))  # type: ignore[index]
    if params is not None:
        algorithm.children = [algorithm.children[0], _el(params)]  # type: ignore[index]
    if point is not None:
        spki.children[1] = _El(b"\x03", b"\x00" + point)  # type: ignore[index]
    return spki


def _nested(depth: int) -> _El:
    """A constructed [UNIVERSAL 8] holding ``depth - 1`` constructed levels, then an OCTET STRING."""
    inner = _El(b"\x04", b"x")
    for _ in range(depth):
        inner = _El(b"\x28", children=[inner])
    return inner


def _name(value: _El) -> _El:
    """A Name of one commonName whose value is ``value``."""
    atv = _El(b"\x30", children=[_El(b"\x06", bytes.fromhex("550403")), value])
    return _El(b"\x30", children=[_El(b"\x31", children=[atv])])


def _freetsa(edit_signer: Any = None, extra: Any = None) -> str:
    """The stored FreeTSA token with its signer certificate edited by ``edit_signer``, or a
    copy of it (another serial number) edited by ``extra`` added to its certificates."""
    token = STORED["freetsa"]["tokenBase64"]
    resp = _el(base64.b64decode(token))
    signer_der = read_rfc3161_token(token).signer.der  # type: ignore[union-attr]
    certificates = _certificates(resp)
    signer = next(c for c in certificates.children if c.der() == signer_der)  # type: ignore[union-attr]
    if edit_signer is not None:
        edit_signer(signer)
    if extra is not None:
        copy = _el(signer_der)
        fields, i = _tbs(copy)
        fields[i] = _El(b"\x02", b"\x07")
        extra(copy)
        certificates.children.append(copy)  # type: ignore[union-attr]
    return base64.b64encode(resp.der()).decode("ascii")


def _with_spki(spki: _El) -> Any:
    def edit(cert: _El) -> None:
        fields, i = _tbs(cert)
        fields[i + 5] = spki

    return edit


def _with_subject(value: _El) -> Any:
    def edit(cert: _El) -> None:
        fields, i = _tbs(cert)
        fields[i + 4] = _name(value)

    return edit


def _with_signature_parameters(value: _El) -> Any:
    def edit(cert: _El) -> None:
        fields, i = _tbs(cert)
        for algorithm in (fields[i + 1], cert.children[1]):  # type: ignore[index]
            algorithm.children = [algorithm.children[0], value]  # type: ignore[index]

    return edit


def _cryptography_loads_explicit_curves() -> bool:
    import cryptography

    return int(cryptography.__version__.split(".")[0]) >= 47


def _node_reads_cases() -> dict[str, tuple[str, dict[str, Any] | None]]:
    """Each case: its token, and the verdict both SDKs give (``None``: steps 1 to 3 hold)."""
    p256_point = bytes(_el(bytes.fromhex(SPKI["p256"])).children[1].content[1:])  # type: ignore[index]
    malformed_key = {"reason": "malformed", "error": "the certificate's public key does not decode: "}
    not_parsed = {"reason": "malformed", "error": "certificate does not parse: "}
    no_signature = {"reason": "verification_failed", "error": "the signature does not verify under the signer certificate"}
    # The signer binding names the signer certificate as it was before the edit, and a
    # requirement of step 3 that fails decides before one that needs a key the verifier
    # does not read (tzun-anchor/1 §10.5 step 5).
    binding_fails = {"reason": "verification_failed", "error": "the signingCertificate certHash names another certificate"}
    return {
        # A certificate the token also carries, whose key Node reads and cryptography does not.
        "extra secp224k1": (_freetsa(extra=_with_spki(_spki("secp224k1"))), None),
        "extra brainpoolP192r1": (_freetsa(extra=_with_spki(_spki("brainpoolP192r1"))), None),
        "extra P-256 with explicit parameters": (_freetsa(extra=_with_spki(_spki("p256-explicit"))), None),
        "extra P-256 point at infinity": (_freetsa(extra=_with_spki(_spki("p256", point=b"\x00"))), None),
        # ... and keys neither reads.
        "extra P-256 point off the curve": (
            _freetsa(extra=_with_spki(_spki("p256", point=p256_point[:-1] + bytes([p256_point[-1] ^ 1])))),
            malformed_key,
        ),
        # A named curve neither implements, the OID assigned to no curve or a GOST parameter
        # set: the certificate is read with its key left unread, and no step needs it.
        "extra curve no one implements": (_freetsa(extra=_with_spki(_spki("p256", curve="2b81040063"))), None),
        "extra curve OID assigned to no curve": (_freetsa(extra=_with_spki(_spki("p256", curve="2a8648ce3d030163"))), None),
        "extra GOST parameter set": (_freetsa(extra=_with_spki(_spki("p256", curve="2a850302022301"))), None),
        # ... and the signer's own, which step 3 needs: read too, so the binding decides.
        "signer curve OID assigned to no curve": (
            _freetsa(edit_signer=_with_spki(_spki("p256", curve="2a8648ce3d030163"))),
            binding_fails,
        ),
        "signer GOST parameter set": (_freetsa(edit_signer=_with_spki(_spki("p256", curve="2a850302022301"))), binding_fails),
        # A P-256 point named as on secp224k1: not of that curve's length.
        "extra secp224k1 point of another curve's length": (
            _freetsa(extra=_with_spki(_spki("p256", curve="2b81040020"))),
            malformed_key,
        ),
        # OpenSSL collects a constructed string five levels deep, and a Name of 1 MiB.
        "extra Name value nested five deep": (_freetsa(extra=_with_subject(_nested(6))), None),
        "extra Name value nested six deep": (_freetsa(extra=_with_subject(_nested(7))), not_parsed),
        "extra signature parameters nested five deep": (_freetsa(extra=_with_signature_parameters(_nested(6))), None),
        "extra signature parameters nested six deep": (
            _freetsa(extra=_with_signature_parameters(_nested(7))),
            not_parsed,
        ),
        "extra Name of 1,000,000 bytes": (_freetsa(extra=_with_subject(_El(b"\x0c", b"a" * 1_000_000))), None),
        "extra Name of 1,100,000 bytes": (_freetsa(extra=_with_subject(_El(b"\x0c", b"a" * 1_100_000))), not_parsed),
        # The signer's own key.
        "signer P-256 point at infinity": (_freetsa(edit_signer=_with_spki(_spki("p256", point=b"\x00"))), no_signature),
        "signer RSASSA-PSS": (
            _freetsa(edit_signer=_with_spki(_spki("rsa-pss"))),
            {"reason": "verification_failed", "error": "a rsa-pss key cannot verify a ec signature"},
        ),
        "signer RSASSA-PSS with NULL parameters": (
            _freetsa(edit_signer=_with_spki(_spki("rsa-pss", params=b"\x05\x00"))),
            binding_fails,
        ),
        "signer X9.42 DH": (
            _freetsa(edit_signer=_with_spki(_spki("dhx"))),
            {"reason": "verification_failed", "error": "a undefined key cannot verify a ec signature"},
        ),
    }


def _verifier_limit_cases() -> dict[str, tuple[str, dict[str, Any] | None, dict[str, Any]]]:
    """Where the SDKs' answers differ, each a limit of the Python verifier (§10.1): the
    token, the TypeScript verdict and the Python one. A signature under an EC key
    cryptography does not load is not checked, and that key's point is not checked
    against its curve. A signer certificate edited after the token was signed fails its
    binding too, so both verdicts are ``verification_failed``: the TypeScript verifier
    finds the signature first, and the Python one, which sets the signature aside, the
    binding (tzun-anchor/1 §10.5 step 5)."""
    secp224k1 = _el(bytes.fromhex(SPKI["secp224k1"]))
    point = bytes(secp224k1.children[1].content[1:])  # type: ignore[index]
    binding_fails = {"reason": "verification_failed", "error": "the signingCertificate certHash names another certificate"}
    no_signature = {"reason": "verification_failed", "error": "the signature does not verify under the signer certificate"}
    cases = {
        "signer secp224k1": (_freetsa(edit_signer=_with_spki(_spki("secp224k1"))), no_signature, binding_fails),
        "extra secp224k1 point off the curve": (
            _freetsa(extra=_with_spki(_spki("secp224k1", point=point[:-1] + bytes([point[-1] ^ 1])))),
            {"reason": "malformed", "error": "the certificate's public key does not decode: "},
            {"holds": True},
        ),
    }
    explicit = _freetsa(edit_signer=_with_spki(_spki("p256-explicit")))
    if not _cryptography_loads_explicit_curves():
        cases["signer P-256 with explicit parameters"] = (explicit, no_signature, binding_fails)
    return cases


def _verdict(expected: dict[str, Any] | None) -> dict[str, Any]:
    return {"holds": True} if expected is None or expected == {"holds": True} else {"holds": False, **expected}


def test_keys_and_certificates_node_reads_by_openssl_rules() -> None:
    cases = _node_reads_cases()
    if _cryptography_loads_explicit_curves():
        cases["signer P-256 with explicit parameters"] = (
            _freetsa(edit_signer=_with_spki(_spki("p256-explicit"))),
            {"reason": "verification_failed", "error": "the signature does not verify under the signer certificate"},
        )
    digest = STORED["freetsa"]["digestHex"]
    names = list(cases)
    ts = harness({"action": "conformance", "cases": [{"token": cases[n][0], "digest": digest} for n in names]})["results"]
    for name, t in zip(names, ts, strict=True):
        p = python_conformance(cases[name][0], digest)
        assert (name, comparable(p)) == (name, comparable(t))
        assert (name, comparable(p)) == (name, _verdict(cases[name][1]))


def test_the_python_verifier_limits_are_what_they_are() -> None:
    cases = _verifier_limit_cases()
    digest = STORED["freetsa"]["digestHex"]
    names = list(cases)
    ts = harness({"action": "conformance", "cases": [{"token": cases[n][0], "digest": digest} for n in names]})["results"]
    for name, t in zip(names, ts, strict=True):
        token, ts_expected, py_expected = cases[name]
        assert (name, comparable(t)) == (name, _verdict(ts_expected))
        assert (name, comparable(python_conformance(token, digest))) == (name, _verdict(py_expected))


# ---- Steps 1 and 3 as tzun-anchor/1 §10.5 states them --------------------------------------------


def _freetsa_signed_data(edit: Any, token: str | None = None) -> str:
    """The stored FreeTSA token (or ``token``) with its SignedData's members edited by ``edit``."""
    resp = _el(base64.b64decode(token or STORED["freetsa"]["tokenBase64"]))
    edit(resp.children[1].children[1].children[0].children)  # type: ignore[index]
    return base64.b64encode(resp.der()).decode("ascii")


def _signer_info_of(signed_data: list[_El]) -> list[_El]:
    return signed_data[-1].children[0].children  # type: ignore[index,return-value]


def _unsigned_attribute(*values: _El) -> str:
    """The FreeTSA token with an unsigned attribute of ``values``, which no signature covers."""

    def edit(signed_data: list[_El]) -> None:
        attribute = _El(b"\x30", children=[_El(b"\x06", bytes.fromhex("2a0304")), _El(b"\x31", children=list(values))])
        _signer_info_of(signed_data).append(_El(b"\xa1", children=[attribute]))

    return _freetsa_signed_data(edit)


def _tst_info_tail(*members: _El, gen_time: str | None = None) -> str:
    """The FreeTSA token with its TSTInfo's members after genTime replaced by ``members`` (and
    its genTime by ``gen_time``): its message-digest attribute no longer matches."""

    def edit(signed_data: list[_El]) -> None:
        octets = signed_data[2].children[1].children[0]  # type: ignore[index]
        tst = _el(octets.content)
        tst.children[5:] = list(members)  # type: ignore[index]
        if gen_time is not None:
            tst.children[4] = _El(b"\x18", gen_time.encode("latin-1"))  # type: ignore[index]
        octets.content = tst.der()

    return _freetsa_signed_data(edit)


def _with_validity(not_before: str, not_after: str) -> Any:
    def time(text: str) -> _El:
        return _El(b"\x17" if len(text) == 13 else b"\x18", text.encode("latin-1"))

    def edit(cert: _El) -> None:
        fields, i = _tbs(cert)
        fields[i + 3] = _El(b"\x30", children=[time(not_before), time(not_after)])

    return edit


def _after_key(make: Any) -> Any:
    def edit(cert: _El) -> None:
        fields, i = _tbs(cert)
        fields[i + 6 :] = make(fields[i + 6])

    return edit


def _revised_rule_cases() -> dict[str, tuple[str, dict[str, Any] | None]]:
    """Each case: its token, and the verdict both SDKs give (``None``: steps 1 to 3 hold)."""
    h = bytes.fromhex
    after_gen_time = {
        "reason": "malformed",
        "error": "TSTInfo holds members after genTime other than accuracy, ordering, nonce, tsa and"
        " extensions, in that order",
    }
    accuracy = {"reason": "malformed", "error": "the accuracy's millis or micros is not an INTEGER from 1 to 999"}
    no_general_name = {"reason": "malformed", "error": "tsa is not one GeneralName"}
    gen_time = {"reason": "malformed", "error": "genTime is not a GeneralizedTime"}
    # A TSTInfo step 1 accepts is no longer the one the message-digest attribute is over.
    digest_fails = {"reason": "verification_failed", "error": "the message-digest attribute is not the digest of the TSTInfo"}
    after_key = {
        "reason": "malformed",
        "error": "tbsCertificate holds fields after its subjectPublicKeyInfo other than a primitive [1],"
        " a primitive [2] and a constructed [3], in that order",
    }

    def nested(levels: int) -> _El:
        inner = _El(b"\x30", children=[])
        for _ in range(levels - 1):
            inner = _El(b"\x30", children=[inner])
        return inner

    def uid(tag: int) -> _El:
        return _El(bytes([tag]), b"\x00\xab")

    def null() -> _El:
        return _El(b"\x05")

    count = _count_elements(base64.b64decode(_unsigned_attribute()))
    extension = _El(b"\x30", children=[_El(b"\x06", h("2a0304")), _El(b"\x01", h("ff")), _El(b"\x04", h("0500"))])

    def set_digest(si: list[_El]) -> None:
        si[2] = _El(b"\x30", children=[_El(b"\x06", h("60864801650304027f"))])

    def set_signature(si: list[_El]) -> None:
        si[4] = _El(b"\x30", children=[_El(b"\x06", h("2a8648ce3d04037f"))])

    def flip_signature(si: list[_El]) -> None:
        si[5] = _El(b"\x04", si[5].content[:-1] + bytes([si[5].content[-1] ^ 0x01]))

    def flip_cert_hash(si: list[_El]) -> None:
        attribute = next(a for a in si[3].children if a.children[0].content == h("2a864886f70d010910020c"))  # type: ignore[union-attr,index]
        cert_hash = attribute.children[1].children[0].children[0].children[0].children[0]  # type: ignore[index]
        cert_hash.content = cert_hash.content[:-1] + bytes([cert_hash.content[-1] ^ 0x01])

    def on_signer_info(*edits: Any) -> str:
        token = None
        for edit in edits:
            token = _freetsa_signed_data(lambda sd, e=edit: e(_signer_info_of(sd)), token)
        assert token is not None
        return token

    cases: dict[str, tuple[str, dict[str, Any] | None]] = {}
    for tag in (0xA0, 0xA1, 0xA2, 0xA3):
        choice = _El(bytes([tag]), children=[_El(b"\x06", h("2a0304")), null()])
        cases[f"certificates element [{tag & 0x1F}]"] = (
            _freetsa_signed_data(lambda sd, c=choice: sd[3].children.append(c)),  # type: ignore[union-attr]
            {"reason": "malformed", "error": "certificate is not a SEQUENCE"},
        )
    cases.update(
        {
            "universal 29 constructed": (_unsigned_attribute(_El(b"\x3d", children=[_El(b"\x02", b"\x01")])), None),
            "universal 35 primitive": (_unsigned_attribute(_El(b"\x1f\x23", b"/tzun")), None),
            "universal 36 primitive": (_unsigned_attribute(_El(b"\x1f\x24", b"tzun")), None),
            "universal 29 primitive": (
                _unsigned_attribute(_El(b"\x1d", b"\x00")),
                {"reason": "malformed", "error": "primitive form of universal type 29"},
            ),
            "universal 35 constructed": (
                _unsigned_attribute(_El(b"\x3f\x23", children=[])),
                {"reason": "malformed", "error": "constructed form of universal type 35"},
            ),
            "universal 36 constructed": (
                _unsigned_attribute(_El(b"\x3f\x24", children=[])),
                {"reason": "malformed", "error": "constructed form of universal type 36"},
            ),
            # An attribute's values sit at depth 10.
            "64 levels deep": (_unsigned_attribute(nested(55)), None),
            "65 levels deep": (_unsigned_attribute(nested(56)), {"reason": "malformed", "error": "nested too deep"}),
            "100,000 elements": (_unsigned_attribute(*(null() for _ in range(100_000 - count))), None),
            "100,001 elements": (
                _unsigned_attribute(*(null() for _ in range(100_001 - count))),
                {"reason": "malformed", "error": "too many elements"},
            ),
            "TSTInfo with every optional member": (
                _tst_info_tail(
                    _El(b"\x30", children=[_El(b"\x02", h("0102030405060708ff")), _El(b"\x80", h("03e7")), _El(b"\x81", h("01"))]),
                    _El(b"\x01", h("00")),
                    _El(b"\x02", h("01")),
                    _El(b"\xa0", children=[_El(b"\xa4", children=[_El(b"\x30", children=[])])]),
                    _El(b"\xa1", children=[extension]),
                ),
                digest_fails,
            ),
            "TSTInfo with nothing after genTime": (_tst_info_tail(), digest_fails),
            "TSTInfo with a member after the last": (_tst_info_tail(_El(b"\xa1", children=[extension]), null()), after_gen_time),
            "TSTInfo with ordering after the nonce": (_tst_info_tail(_El(b"\x02", h("01")), _El(b"\x01", h("ff"))), after_gen_time),
            "TSTInfo accuracy millis 0": (_tst_info_tail(_El(b"\x30", children=[_El(b"\x80", h("00"))])), accuracy),
            "TSTInfo accuracy millis not minimal": (_tst_info_tail(_El(b"\x30", children=[_El(b"\x80", h("0001"))])), accuracy),
            "TSTInfo accuracy micros 1000": (_tst_info_tail(_El(b"\x30", children=[_El(b"\x81", h("03e8"))])), accuracy),
            "TSTInfo accuracy millis -1": (_tst_info_tail(_El(b"\x30", children=[_El(b"\x80", h("ff"))])), accuracy),
            "TSTInfo tsa empty": (_tst_info_tail(_El(b"\xa0", children=[])), no_general_name),
            "TSTInfo tsa two GeneralNames": (
                _tst_info_tail(_El(b"\xa0", children=[_El(b"\x82", b"\x00"), _El(b"\x82", b"\x00")])),
                no_general_name,
            ),
            # Not of the context-specific class, with a tag number from 0 to 8 and the form that
            # alternative has.
            "TSTInfo tsa INTEGER": (_tst_info_tail(_El(b"\xa0", children=[_El(b"\x02", h("01"))])), no_general_name),
            "TSTInfo tsa BOOLEAN": (_tst_info_tail(_El(b"\xa0", children=[_El(b"\x01", h("ff"))])), no_general_name),
            "TSTInfo tsa APPLICATION [2]": (_tst_info_tail(_El(b"\xa0", children=[_El(b"\x42", h("00"))])), no_general_name),
            "TSTInfo tsa PRIVATE [0] constructed": (
                _tst_info_tail(_El(b"\xa0", children=[_El(b"\xe0", children=[])])),
                no_general_name,
            ),
            "TSTInfo tsa dNSName constructed": (
                _tst_info_tail(_El(b"\xa0", children=[_El(b"\xa2", children=[_El(b"\x16", b"tsa.example")])])),
                no_general_name,
            ),
            "TSTInfo tsa [9]": (_tst_info_tail(_El(b"\xa0", children=[_El(b"\x89", b"\x00")])), no_general_name),
            "TSTInfo extensions empty": (
                _tst_info_tail(_El(b"\xa1", children=[])),
                {"reason": "malformed", "error": "the TSTInfo extensions are not one or more extensions"},
            ),
            "genTime 0000-02-29": (_tst_info_tail(gen_time="00000229120000Z"), digest_fails),
            "genTime 0050-01-01 with a fraction": (_tst_info_tail(gen_time="00500101120000.5Z"), digest_fails),
            "genTime 0100-02-29": (_tst_info_tail(gen_time="01000229120000Z"), gen_time),
            "genTime month 13": (_tst_info_tail(gen_time="20261301120000Z"), gen_time),
            "genTime second 60": (_tst_info_tail(gen_time="20260601120060Z"), gen_time),
            # A certificate no step needs, added to the token's certificates.
            "extra validity from 0000-02-29": (_freetsa(extra=_with_validity("00000229000000Z", "99991231235959Z")), None),
            "extra validity from 0050": (_freetsa(extra=_with_validity("00500101000000Z", "00991231235959Z")), None),
            "extra validity UTCTime 50 to 49": (_freetsa(extra=_with_validity("500101000000Z", "491231235959Z")), None),
            "extra validity 0100-02-29": (
                _freetsa(extra=_with_validity("01000229000000Z", "20400101000000Z")),
                {"reason": "malformed", "error": "unreadable validity"},
            ),
            "extra validity with a fraction": (
                _freetsa(extra=_with_validity("20260101000000.5Z", "20400101000000Z")),
                {"reason": "malformed", "error": "unreadable validity"},
            ),
            "extra issuerUniqueID and subjectUniqueID": (_freetsa(extra=_after_key(lambda x: [uid(0x81), uid(0x82), x])), None),
            "extra with no extensions": (_freetsa(extra=_after_key(lambda x: [])), None),
            "extra extensions retagged [2]": (_freetsa(extra=_after_key(lambda x: [_El(b"\xa2", children=x.children)])), after_key),
            "extra issuerUniqueID constructed": (
                _freetsa(extra=_after_key(lambda x: [_El(b"\xa1", children=[_El(b"\x03", b"\x00\xab")]), x])),
                after_key,
            ),
            "extra extensions twice": (_freetsa(extra=_after_key(lambda x: [x, x])), after_key),
            "extra unique identifiers out of order": (_freetsa(extra=_after_key(lambda x: [uid(0x82), uid(0x81), x])), after_key),
            "extra extensions holding two": (
                _freetsa(extra=_after_key(lambda x: [_El(b"\xa3", children=[*(x.children or []), _El(b"\x30", children=[])])])),
                {"reason": "malformed", "error": "extensions are not one SEQUENCE"},
            ),
            # Step 3: FreeTSA signs with ecdsa-with-SHA512, so its signature is checked
            # whatever the SignerInfo's digestAlgorithm names.
            "digestAlgorithm unknown": (
                on_signer_info(set_digest),
                {"reason": "missing_dependency", "error": "digest algorithm 2.16.840.1.101.3.4.2.127 is not supported"},
            ),
            "digestAlgorithm unknown, signature flipped": (
                on_signer_info(set_digest, flip_signature),
                {"reason": "verification_failed", "error": "the signature does not verify under the signer certificate"},
            ),
            "signatureAlgorithm unknown": (
                on_signer_info(set_signature),
                {"reason": "missing_dependency", "error": "signature algorithm 1.2.840.10045.4.3.127 is not supported"},
            ),
            "signatureAlgorithm unknown, certHash flipped": (
                on_signer_info(set_signature, flip_cert_hash),
                {"reason": "verification_failed", "error": "the signingCertificate certHash names another certificate"},
            ),
        }
    )
    return cases


def _count_elements(der: bytes) -> int:
    """How many elements ``der`` holds, not looking inside a primitive element."""

    def count(node: _El) -> int:
        return 1 + sum(count(c) for c in node.children or [])

    return count(_el(der))


def test_steps_1_and_3_as_the_anchor_spec_states_them_give_the_same_finding() -> None:
    cases = _revised_rule_cases()
    digest = STORED["freetsa"]["digestHex"]
    names = list(cases)
    ts = harness({"action": "conformance", "cases": [{"token": cases[n][0], "digest": digest} for n in names]})["results"]
    for name, t in zip(names, ts, strict=True):
        p = python_conformance(cases[name][0], digest)
        assert (name, comparable(p)) == (name, comparable(t))
        assert (name, comparable(p)) == (name, _verdict(cases[name][1]))


# ---- BER the two clients' readers read -------------------------------------------------------------


def _ber_freetsa(edit: Any) -> str:
    resp = _el(base64.b64decode(STORED["freetsa"]["tokenBase64"]))
    edit(resp)
    return base64.b64encode(resp.der()).decode("ascii")


def _indefinite(*path: int) -> Any:
    """Write the element at ``path`` (and each on the way to it) in the indefinite-length form."""

    def edit(resp: _El) -> None:
        el = resp
        el.indefinite = True
        for i in path:
            el = el.children[i]  # type: ignore[index]
            el.indefinite = True

    return edit


def _e_content_segments(nested: _El | None) -> Any:
    """The TSTInfo in a constructed OCTET STRING of two segments, with ``nested`` between them."""

    def edit(resp: _El) -> None:
        encap = resp.children[1].children[1].children[0].children[2]  # type: ignore[index]
        octets = encap.children[1].children[0]  # type: ignore[index]
        half = len(octets.content) // 2
        middle = [nested] if nested is not None else []
        encap.children[1].children[0] = _El(  # type: ignore[index]
            b"\x24",
            children=[_El(b"\x04", octets.content[:half]), *middle, _El(b"\x04", octets.content[half:])],
        )

    return edit


def _status(content: bytes) -> Any:
    def edit(resp: _El) -> None:
        resp.children[0].children[0] = _El(b"\x02", content)  # type: ignore[index]

    return edit


def test_capture_keeps_the_same_ber_tokens(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    freetsa = STORED["freetsa"]
    nonce = nonce_of(freetsa["tokenBase64"])
    cases = {
        # A token the TypeScript client keeps and reports: BER, but read by asn1js.
        "indefinite TimeStampResp": (_ber_freetsa(_indefinite()), True),
        "indefinite PKIStatusInfo": (_ber_freetsa(_indefinite(0)), True),
        "indefinite ContentInfo and SignedData": (_ber_freetsa(_indefinite(1, 1, 0)), True),
        "eContent in two segments": (_ber_freetsa(_e_content_segments(None)), True),
        # A constructed segment inside adds nothing to the TSTInfo (asn1js getValue()).
        "eContent segment nested, holding an OCTET STRING": (
            _ber_freetsa(_e_content_segments(_El(b"\x24", children=[_El(b"\x04", b"\x05\x00")]))),
            True,
        ),
        # A constructed OCTET STRING holds only OCTET STRINGs.
        "eContent segment nested, holding an INTEGER": (
            _ber_freetsa(_e_content_segments(_El(b"\x24", children=[_El(b"\x02", b"\x00")]))),
            False,
        ),
    }
    names = list(cases)
    requests = [{"token": cases[n][0], "digest": freetsa["digestHex"], "nonce": nonce} for n in names]
    ts = harness({"action": "capture", "url": URL, "cases": requests})["results"]
    for name, t in zip(names, ts, strict=True):
        token, kept = cases[name]
        p = python_capture(token, freetsa["digestHex"], nonce, monkeypatch, caplog)
        assert (name, p["stored"]) == (name, t["stored"]) == (name, kept)
        assert (name, [comparable(e) for e in p["events"]]) == (name, [comparable(e) for e in t["events"]])
        assert [e["reason"] for e in p["events"]] == (["malformed"] if kept else []), name


def test_capture_refuses_a_status_that_asn1js_reads_as_granted(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # asn1js reads an INTEGER of four or more bytes as 0, so the TypeScript client keeps
    # a token whose status is rejection written in four bytes. The
    # Python client reads the status whole, and refuses it.
    freetsa = STORED["freetsa"]
    nonce = nonce_of(freetsa["tokenBase64"])
    token = _ber_freetsa(_status(b"\x00\x00\x00\x02"))
    ts = harness(
        {"action": "capture", "url": URL, "cases": [{"token": token, "digest": freetsa["digestHex"], "nonce": nonce}]}
    )["results"]
    assert ts[0]["stored"] is True
    assert python_capture(token, freetsa["digestHex"], nonce, monkeypatch, caplog) == {"stored": False, "events": []}


# ---- The authority fact, and the roots each SDK refuses ------------------------------


def _name_der(rdns: list[list[tuple[str, int, bytes]]]) -> bytes:
    """A Name: RDNs in order, each a list of (type OID, string tag, value bytes), the
    attributes of each RDN in DER order."""

    def tlv(tag: int, body: bytes) -> bytes:
        return _El(bytes([tag]), body).der()

    def oid(dotted: str) -> bytes:
        parts = [int(p) for p in dotted.split(".")]
        body = bytes([parts[0] * 40 + parts[1]])
        for n in parts[2:]:
            chunk = [n & 0x7F]
            n >>= 7
            while n:
                chunk.insert(0, 0x80 | (n & 0x7F))
                n >>= 7
            body += bytes(chunk)
        return tlv(0x06, body)

    rdn_ders = [
        tlv(0x31, b"".join(sorted(tlv(0x30, oid(o) + tlv(tag, value)) for o, tag, value in rdn))) for rdn in rdns
    ]
    return tlv(0x30, b"".join(rdn_ders))


_CN = "2.5.4.3"

#: Each subject: its Name, and the authority both SDKs read from it.
AUTHORITY_CASES: dict[str, tuple[bytes, str]] = {
    "one CN among other RDNs": (
        _name_der([[("2.5.4.6", 19, b"US")], [("2.5.4.10", 12, b"Probe Org")], [(_CN, 12, b"Probe TSA")]]),
        "Probe TSA",
    ),
    "two CN RDNs: the first": (
        _name_der([[("2.5.4.6", 19, b"US")], [(_CN, 12, b"First CN")], [(_CN, 12, b"Second CN")]]),
        "First CN",
    ),
    "a CN in a multi-valued RDN": (_name_der([[("2.5.4.10", 12, b"Probe Org"), (_CN, 12, b"Multi CN")]]), "Multi CN"),
    "specials, kept as encoded": (
        _name_der([[(_CN, 12, b' Acme, Inc. + "TSA" = #1 \\ <x>; ')]]),
        ' Acme, Inc. + "TSA" = #1 \\ <x>; ',
    ),
    "a line feed": (_name_der([[(_CN, 12, b"Line1\nLine2")]]), "Line1\nLine2"),
    "a UTF8String outside ASCII": (
        _name_der([[(_CN, 12, "Zeitstempel Zürich Ω 時 😀".encode())]]),
        "Zeitstempel Zürich Ω 時 😀",
    ),
    "a leading U+FEFF, kept": (_name_der([[(_CN, 12, "\ufeffBOM".encode())]]), "\ufeffBOM"),
    "a BMPString": (_name_der([[(_CN, 30, "Zürich BMP".encode("utf-16-be"))]]), "Zürich BMP"),
    "a BMPString with a surrogate pair": (_name_der([[(_CN, 30, "Z😀".encode("utf-16-be"))]]), "Z😀"),
    "a TeletexString as ISO 8859-1": (_name_der([[(_CN, 20, "Zürich T61".encode("latin-1"))]]), "Zürich T61"),
    "a UniversalString": (_name_der([[(_CN, 28, "Zürich 😀".encode("utf-32-be"))]]), "Zürich 😀"),
    "a PrintableString": (_name_der([[(_CN, 19, b"Printable")]]), "Printable"),
    "an IA5String": (_name_der([[(_CN, 22, b"ia5@example")]]), "ia5@example"),
    "an empty CN": (_name_der([[("2.5.4.10", 12, b"Probe Org")], [(_CN, 12, b"")]]), ""),
    "no CN": (_name_der([[("2.5.4.6", 19, b"US")], [("2.5.4.10", 12, b"Probe Org")]]), ""),
    "no RDN": (_name_der([]), ""),
    # Code units that do not decode are U+FFFD, so the fact is always a string a report can write.
    "a BMPString with a lone surrogate": (_name_der([[(_CN, 30, bytes.fromhex("d800005a"))]]), "\ufffdZ"),
    "a BMPString of odd length": (_name_der([[(_CN, 30, bytes.fromhex("005a00"))]]), "Z\ufffd"),
    "a UniversalString past U+10FFFF": (_name_der([[(_CN, 28, bytes.fromhex("00110000"))]]), "\ufffd"),
    "not a Name": (bytes.fromhex("0400"), ""),
}


def test_the_authority_fact_is_the_same_in_both() -> None:
    names = list(AUTHORITY_CASES)
    ts = harness({"action": "authority", "subjects": [AUTHORITY_CASES[n][0].hex() for n in names]})["results"]
    signer = read_rfc3161_token(STORED["freetsa"]["tokenBase64"]).signer  # type: ignore[union-attr]
    for name, t in zip(names, ts, strict=True):
        subject, expected = AUTHORITY_CASES[name]
        py = authority_of(dataclasses.replace(signer, subject=subject))
        assert (name, py) == (name, t) == (name, expected)


def test_the_steps_verdict_carries_the_same_authority(corpus: dict[str, str]) -> None:
    cases = [{"token": t["tokenBase64"], "digest": t["digestHex"]} for t in STORED.values()]
    cases += [{"token": corpus[n], "digest": DIGEST} for n in sorted(corpus)]
    ts = harness({"action": "steps-authority", "cases": cases})["results"]
    for c, t in zip(cases, ts, strict=True):
        v = verify_rfc3161_steps(c["token"], c["digest"])
        assert {"token": v.token, "authority": v.authority} == t
    # Every stored authority names itself in its signer's first CN.
    for name, t in STORED.items():
        assert verify_rfc3161_steps(t["tokenBase64"], t["digestHex"]).authority == t["signerCommonName"], name


def _pem(der: bytes) -> str:
    body = base64.b64encode(der).decode("ascii")
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def test_the_same_roots_are_refused_with_the_same_words() -> None:
    certs = REPO_ROOT / "src" / "attestation" / "certs"
    freetsa_root = (certs / "freetsa-ca.pem").read_text("utf-8")
    sectigo_root = (certs / "sectigo-public-time-stamping-root-r46.pem").read_text("utf-8")
    signer = read_rfc3161_token(STORED["freetsa"]["tokenBase64"]).signer  # type: ignore[union-attr]
    unassigned = _el(signer.der)
    _with_spki(_spki("p256", curve="2a8648ce3d030163"))(unassigned)
    unknown_algorithm = _el(signer.der)
    _with_spki(_spki("p256"))(unknown_algorithm)
    spki_algorithm = _tbs(unknown_algorithm)[0][_tbs(unknown_algorithm)[1] + 5].children[0].children[0]  # type: ignore[index]
    spki_algorithm.content = bytes.fromhex("2a8648ce3d0209")
    off_curve = _el(signer.der)
    point = bytes(_el(bytes.fromhex(SPKI["p256"])).children[1].content[1:])  # type: ignore[index]
    _with_spki(_spki("p256", point=point[:-1] + bytes([point[-1] ^ 1])))(off_curve)
    cases: dict[str, list[object]] = {
        "a root": [freetsa_root],
        "two roots in one entry, and another": [freetsa_root + sectigo_root, _pem(signer.der)],
        "not a string": [7],
        "no PEM block": ["not a certificate"],
        "a genuine root, then no PEM block": [freetsa_root, "not a certificate"],
        "a block that is not base64": ["-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"],
        "a block that is not a certificate": ["-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----"],
        "a key on a curve assigned to no curve": [_pem(unassigned.der())],
        "a key of an algorithm neither implements": [_pem(unknown_algorithm.der())],
        "a P-256 key off its curve": [_pem(off_curve.der())],
        "the second certificate of an entry unreadable": [freetsa_root + _pem(unassigned.der())],
    }
    # Between the base64 lines of a body, ASCII tab, line feed, vertical tab, form feed,
    # carriage return and space are stripped, and nothing else: in both SDKs, any other
    # character, Unicode white space included, makes the body not base64.
    body_lines = freetsa_root.strip().split("\n")
    for label, separator in {
        "tab": "\t",
        "vertical tab": "\v",
        "form feed": "\f",
        "CR LF": "\r\n",
        "spaces": "  ",
        "U+001C": "\x1c",
        "U+001F": "\x1f",
        "U+0085": "\x85",
        "U+00A0": "\u00a0",
        "U+2028": "\u2028",
        "U+3000": "\u3000",
        "U+FEFF": "\ufeff",
    }.items():
        cases[f"body lines separated by {label}"] = [
            body_lines[0] + "\n" + separator.join(body_lines[1:-1]) + "\n" + body_lines[-1]
        ]
    names = list(cases)
    ts = harness({"action": "trust-anchors", "cases": [cases[n] for n in names]})["results"]

    def python(pems: list[object]) -> dict[str, object]:
        try:
            return {"count": len(read_trust_anchors(pems))}
        except UnreadableTrustAnchorError as exc:
            return {"error": str(exc)}

    def comparable_refusal(result: dict[str, object]) -> dict[str, object]:
        # The words after "does not read as a certificate: " are each reader's own.
        error = result.get("error")
        if isinstance(error, str) and "does not read as a certificate: " in error:
            return {"error": error.split("does not read as a certificate: ")[0] + "does not read as a certificate: "}
        return result

    for name, t in zip(names, ts, strict=True):
        assert (name, comparable_refusal(python(cases[name]))) == (name, comparable_refusal(t))
    assert ts[0] == {"count": 1}
    assert ts[1] == {"count": 3}
    assert ts[7] == {"error": "trust anchor 1 has a key this verifier does not implement: its elliptic curve is not supported"}
    assert ts[8] == {
        "error": "trust anchor 1 has a key this verifier does not implement: its public-key algorithm is not supported"
    }
    assert ts[10] == {
        "error": "trust anchor 1, certificate 2 has a key this verifier does not implement: its elliptic curve is not supported"
    }
    separated = {n: t for n, t in zip(names, ts, strict=True) if n.startswith("body lines separated by ")}
    assert [n for n, t in separated.items() if t == {"count": 1}] == [
        f"body lines separated by {label}" for label in ("tab", "vertical tab", "form feed", "CR LF", "spaces")
    ]
    assert all(t == {"error": "trust anchor 1 is not base64"} for n, t in separated.items() if t != {"count": 1})


def test_a_root_off_a_curve_only_node_implements_is_refused_in_typescript_alone() -> None:
    """The one root the two SDKs read differently, held as it is: an EC key named on SM2, a
    curve Node's OpenSSL implements and :mod:`cryptography` does not, that carries a P-256
    point. TypeScript refuses it as a key that does not decode; Python checks such a key's
    point for its length alone, as §10.5 step 1 does, and reads it."""
    signer = read_rfc3161_token(STORED["freetsa"]["tokenBase64"]).signer  # type: ignore[union-attr]
    sm2 = _el(signer.der)
    _with_spki(_spki("p256", curve="2a811ccf5501822d"))(sm2)
    ts = harness({"action": "trust-anchors", "cases": [[_pem(sm2.der())]]})["results"]
    assert ts[0]["error"].startswith(
        "trust anchor 1 does not read as a certificate: the certificate's public key does not decode: "
    )
    assert len(read_trust_anchors([_pem(sm2.der())])) == 1
