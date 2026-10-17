# HAND-MAINTAINED. NOT generated.
"""An RFC 3161 timestamp token held to tzun-anchor/1 §10.5, steps 1 to 3.

The twin of steps 1 to 3 of the TypeScript verifier (``src/attestation/rfc3161-token.ts``),
which gives the same verdict and the same error on the same token:

1. parse (:func:`read_rfc3161_token`): base64 (RFC 4648 §4) of a DER TimeStampResp whose
   status is granted or grantedWithMods, carrying a CMS SignedData over a DER TSTInfo, with
   exactly one SignerInfo whose certificate the token carries. Every certificate the token
   carries is read whole, its public key included;
2. imprint (:func:`imprint_holds`): SHA-256, and the expected value;
3. signature and signer (:func:`check_signature_and_signer`): the content-type and
   message-digest attributes, the CMS signature, a signingCertificate (ESSCertID) or
   signingCertificateV2 (ESSCertIDv2) that names the signer certificate, and on that
   certificate a critical extendedKeyUsage whose only purpose is id-kp-timeStamping.

:func:`verify_rfc3161_steps` runs them in order and reports the first that does not hold:
``malformed``, ``imprint_mismatch``, ``verification_failed``, or ``missing_dependency`` for an
algorithm this verifier does not implement (Anchor §10.5 step 5). Step 4, the trust path, is not
implemented here.

Where the TypeScript verifier leans on Node, this module does what Node does:

- a certificate must also be one OpenSSL's X.509 reader reads (``d2i_X509``), which is
  stricter than the checks of step 1 in its Names (a SEQUENCE OF SET OF type and value,
  each value a string type OpenSSL reads, its characters valid, a constructed value
  nested at most five deep, the Name at most 1 MiB), its validity (two times), the
  parameters of its AlgorithmIdentifiers, and what follows the subjectPublicKeyInfo
  ([1], [2] and [3], in that order and nothing else);
- an RSA key is read as OpenSSL reads one (its INTEGERs unsigned, with no DER rule on
  them), and an RSA signature is checked as OpenSSL checks one (PKCS #1 v1.5), so a key
  OpenSSL reads and :mod:`cryptography` refuses gives the same answer;
- EC, Ed25519, DSA and X25519 keys, and the EC and Ed25519 signatures, go through
  :mod:`cryptography`, which reads a key by its own rules, not OpenSSL's. Where they
  differ on an EC key, the key is read as Node reads it: a key on a named curve Node's
  OpenSSL implements and :mod:`cryptography` does not (secp224k1, brainpoolP192r1, the
  binary curves, …), or with explicit curve parameters :mod:`cryptography` does not
  load, is read; so is the point at infinity, under which no signature verifies.
- an EC key on a named curve Node's OpenSSL does not implement (a curve OID assigned to
  no curve included, since no verifier can tell the two apart) is not a decoding
  failure: the certificate is read with its key left unread, and a step that needs the
  key is ``missing_dependency`` (tzun-anchor/1 §10.5 steps 1 and 5).

The trust roots are the auditor's input, not the token's: :func:`read_trust_anchors`
reads them and raises :class:`UnreadableTrustAnchorError` for one it cannot read, its key
included (Verification §3.1). :func:`authority_of` is the ``authority`` fact of a trust
check (Anchor §10.5 step 4).

What this verifier cannot do is a verifier limit, never a verdict on the token
(Anchor §10.1):

- a signature under an EC key :mod:`cryptography` does not load is not checked: the
  signer's key on such a curve gives ``missing_dependency``, where Node checks the
  signature (on :mod:`cryptography` before 47.0.0, which loads no explicit curve
  parameters, that includes a P-256 key written with them);
- the point of such a key is checked for its encoding's length, and not against its
  curve; nor are explicit curve parameters checked. OpenSSL refuses a point that is not
  on its curve, and parameters that are not a curve.

An error that carries a library's own message (``certificate does not parse: …``, ``the
certificate's public key does not decode: …``, ``the signature does not verify: …``,
``unreadable: …``, and a verifier failure) has the TypeScript verifier's words before the
colon and this library's after it. Nothing here raises on its input.

The reader takes the token's elements as views of its bytes, never copies, so a token
nested deep costs its own size once, not once per level.
"""

from __future__ import annotations

import base64
import hashlib
import re
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Literal, TypeAlias

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from tzun_sdk.attestation._ecmascript import days_from_civil, js_integral_number_string

_OID_SIGNED_DATA: Final = "1.2.840.113549.1.7.2"
_OID_TST_INFO: Final = "1.2.840.113549.1.9.16.1.4"
_OID_CONTENT_TYPE: Final = "1.2.840.113549.1.9.3"
_OID_MESSAGE_DIGEST: Final = "1.2.840.113549.1.9.4"
_OID_SIGNING_CERTIFICATE: Final = "1.2.840.113549.1.9.16.2.12"
_OID_SIGNING_CERTIFICATE_V2: Final = "1.2.840.113549.1.9.16.2.47"
_OID_SHA256: Final = "2.16.840.1.101.3.4.2.1"
_OID_EXT_KEY_USAGE: Final = "2.5.29.37"
_OID_BASIC_CONSTRAINTS: Final = "2.5.29.19"
_OID_KEY_USAGE: Final = "2.5.29.15"
_OID_SUBJECT_KEY_IDENTIFIER: Final = "2.5.29.14"
_OID_KP_TIME_STAMPING: Final = "1.3.6.1.5.5.7.3.8"
_OID_RSA: Final = "1.2.840.113549.1.1.1"
_OID_RSA_PSS: Final = "1.2.840.113549.1.1.10"
_OID_EC_PUBLIC_KEY: Final = "1.2.840.10045.2.1"

#: Public-key algorithms whose keys this verifier decodes: RSA, EC, Ed25519, and the DSA
#: and X25519 keys a certificate may also carry. A certificate naming one of them whose
#: key does not decode is not a certificate.
_KEY_ALGORITHMS: Final = frozenset(
    {_OID_RSA, _OID_EC_PUBLIC_KEY, "1.3.101.112", "1.2.840.10040.4.1", "1.3.101.110"}
)

#: Each key algorithm by the name Node gives its keys (``KeyObject.asymmetricKeyType``;
#: Node names no type for an X9.42 DH key, and writes that as ``undefined``). A key of an
#: algorithm outside ``_KEY_ALGORITHMS`` is read when it decodes, and a step that needs it
#: finds it is of another type.
_KEY_TYPES: Final = {
    _OID_RSA: "rsa",
    _OID_RSA_PSS: "rsa-pss",
    _OID_EC_PUBLIC_KEY: "ec",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
    "1.2.840.10040.4.1": "dsa",
    "1.3.101.110": "x25519",
    "1.3.101.111": "x448",
    "1.2.840.113549.1.3.1": "dh",
    "1.2.840.10046.2.1": "undefined",
}


def _curves(prefix: str, sizes: dict[int, int]) -> dict[str, int]:
    return {f"{prefix}.{n}": size for n, size in sizes.items()}


#: The named curves Node's OpenSSL reads an EC key on (``crypto.getCurves()`` with an
#: OID), each with the length of its field elements in bytes. A key on one of them that
#: :mod:`cryptography` does not implement is read as OpenSSL reads its point
#: (``ec_GFp_simple_oct2point``) for what can be decided without the curve: ``00``, the
#: point at infinity; ``02`` or ``03`` and x; or ``04``, ``06`` or ``07``, x and y. A key
#: on any other curve is not a key.
_OPENSSL_CURVES: Final[dict[str, int]] = {
    "1.2.156.10197.1.301": 32,  # SM2
    # X9.62 binary
    **_curves("1.2.840.10045.3.0", {
        1: 21, 2: 21, 3: 21, 4: 22, 5: 24, 6: 24, 7: 24, 10: 26, 11: 30, 12: 30, 13: 30, 16: 34,
        17: 38, 18: 45, 19: 46, 20: 54,
    }),
    # X9.62 prime
    **_curves("1.2.840.10045.3.1", {
        1: 24, 2: 24, 3: 24, 4: 30, 5: 30, 6: 30, 7: 32,
    }),
    # brainpool
    **_curves("1.3.36.3.3.2.8.1.1", {
        1: 20, 2: 20, 3: 24, 4: 24, 5: 28, 6: 28, 7: 32, 8: 32, 9: 40, 10: 40, 11: 48, 12: 48,
        13: 64, 14: 64,
    }),
    # SEC 2
    **_curves("1.3.132.0", {
        1: 21, 2: 21, 3: 30, 4: 15, 5: 15, 6: 14, 7: 14, 8: 20, 9: 20, 10: 32, 15: 21, 16: 36,
        17: 36, 22: 17, 23: 17, 24: 25, 25: 25, 26: 30, 27: 30, 28: 16, 29: 16, 30: 20, 31: 24,
        32: 28, 33: 28, 34: 48, 35: 66, 36: 52, 37: 52, 38: 72, 39: 72,
    }),
    # WAP WTLS
    **_curves("2.23.43.1.4", {
        1: 15, 3: 21, 4: 15, 5: 21, 6: 14, 7: 20, 8: 14, 9: 20, 10: 30, 11: 30, 12: 28,
    }),
}

#: Digest algorithms by OID, by their hashlib names (which are Node's).
_DIGESTS: Final = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    _OID_SHA256: "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}

#: Signature algorithms by OID: the key type they need, and the digest they name (``None``
#: for the bare key OIDs, which take the SignerInfo's digestAlgorithm, as CMS allows).
_SIGNATURES: Final[dict[str, tuple[str, str | None]]] = {
    _OID_RSA: ("rsa", None),
    "1.2.840.113549.1.1.5": ("rsa", "sha1"),
    "1.2.840.113549.1.1.14": ("rsa", "sha224"),
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    _OID_EC_PUBLIC_KEY: ("ec", None),
    "1.2.840.10045.4.1": ("ec", "sha1"),
    "1.2.840.10045.4.3.1": ("ec", "sha224"),
    "1.2.840.10045.4.3.2": ("ec", "sha256"),
    "1.2.840.10045.4.3.3": ("ec", "sha384"),
    "1.2.840.10045.4.3.4": ("ec", "sha512"),
    "1.3.101.112": ("ed25519", None),
}

_HASHES: Final[dict[str, Callable[[], hashes.HashAlgorithm]]] = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

#: The DER DigestInfo prefix of each digest, as PKCS #1 v1.5 signs it (RFC 8017 §9.2).
_DIGEST_INFO: Final = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

#: The start of the error a verdict carries when the verifier itself failed.
VERIFIER_FAILED: Final = "the RFC 3161 verifier failed on this token"

# ---- DER ------------------------------------------------------------------------------------


class _Malformed(Exception):
    """A token or certificate that is not what step 1 reads: not DER, or not of its type."""


class _VerifierFault(Exception):
    """A state the checks never reach on any input: a fault of this verifier, reported as
    one (Anchor §10.1), never a verdict on the token."""


class _Absent:
    """An attribute the signed attributes do not carry."""


_ABSENT: Final = _Absent()

#: Bytes as the reader holds them: a view of the token's bytes, not a copy.
_Buf: TypeAlias = bytes | memoryview


@dataclass(frozen=True, slots=True)
class _Der:
    """One DER element: its tag, its bytes with the header, and its content, each a view of
    the bytes it was read from."""

    #: 0 universal, 1 application, 2 context-specific, 3 private.
    cls: int
    constructed: bool
    tag: int
    raw: _Buf
    content: _Buf


_MAX_DEPTH: Final = 64
_MAX_ELEMENTS: Final = 100_000

#: Universal types DER encodes only in the primitive form.
_PRIMITIVE_ONLY: Final = frozenset(
    {1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28}
    | {29, 30, 31, 32, 33, 34}
)
#: Universal types DER encodes only in the constructed form.
_CONSTRUCTED_ONLY: Final = frozenset({8, 11, 16, 17})


def _read_element(buf: _Buf, pos: int, limit: int) -> _Der:
    """The element at ``pos``, which must end at or before ``limit``."""
    start = pos
    if pos >= limit:
        raise _Malformed("truncated element")
    first = buf[pos]
    pos += 1
    cls = first >> 6
    constructed = (first & 0x20) != 0
    tag = first & 0x1F
    if tag == 0x1F:
        tag = 0
        i = 0
        while True:
            if pos >= limit:
                raise _Malformed("truncated tag")
            b = buf[pos]
            pos += 1
            if i == 0 and b == 0x80:
                raise _Malformed("non-minimal tag")
            if tag > 0x00FFFFFF:
                raise _Malformed("tag number too large")
            tag = tag * 128 + (b & 0x7F)
            if b & 0x80 == 0:
                break
            i += 1
        if tag < 31:
            raise _Malformed("non-minimal tag")
    if pos >= limit:
        raise _Malformed("truncated length")
    length = buf[pos]
    pos += 1
    if length == 0x80:
        raise _Malformed("indefinite length")
    if length > 0x80:
        n = length & 0x7F
        if n > 4:
            raise _Malformed("length too long")
        if pos + n > limit:
            raise _Malformed("truncated length")
        if buf[pos] == 0:
            raise _Malformed("non-minimal length")
        length = int.from_bytes(buf[pos : pos + n], "big")
        pos += n
        if length < 0x80:
            raise _Malformed("non-minimal length")
    end = pos + length
    if end > limit:
        raise _Malformed("element runs past its container")
    return _Der(cls, constructed, tag, buf[start:end], buf[pos:end])


def _elements_of(content: _Buf) -> list[_Der]:
    """The elements of ``content``, in order."""
    out: list[_Der] = []
    pos = 0
    while pos < len(content):
        el = _read_element(content, pos, len(content))
        out.append(el)
        pos += len(el.raw)
    return out


_GENERALIZED_TIME_DER: Final = re.compile(r"[0-9]{14}(\.[0-9]*[1-9])?Z")
_UTC_TIME_DER: Final = re.compile(r"[0-9]{12}Z")


def _check_der(content: _Buf, depth: int, count: list[int]) -> None:
    """Whether ``content`` (every element in it, recursively) is DER as X.690 §10 and §11
    define it, for what can be decided without a schema: definite, minimal lengths and
    tags; the primitive form for strings and the other primitive types; minimal INTEGERs;
    BOOLEAN as 00 or FF; a BIT STRING's unused bits zero; and the DER forms of UTCTime and
    GeneralizedTime. A context-specific primitive is not read inside: its type is the
    schema's."""
    if depth > _MAX_DEPTH:
        raise _Malformed("nested too deep")
    pos = 0
    while pos < len(content):
        count[0] += 1
        if count[0] > _MAX_ELEMENTS:
            raise _Malformed("too many elements")
        el = _read_element(content, pos, len(content))
        pos += len(el.raw)
        c = el.content
        if el.cls == 0:
            tag = el.tag
            if tag == 0:
                raise _Malformed("end-of-contents in DER")
            if el.constructed and tag in _PRIMITIVE_ONLY:
                raise _Malformed(f"constructed form of universal type {tag}")
            if not el.constructed and tag in _CONSTRUCTED_ONLY:
                raise _Malformed(f"primitive form of universal type {tag}")
            if tag == 1:
                if len(c) != 1 or (c[0] != 0x00 and c[0] != 0xFF):
                    raise _Malformed("BOOLEAN not 00 or FF")
            elif tag in (2, 10):
                if len(c) == 0:
                    raise _Malformed("empty INTEGER")
                if len(c) > 1 and (
                    (c[0] == 0x00 and c[1] & 0x80 == 0) or (c[0] == 0xFF and c[1] & 0x80 != 0)
                ):
                    raise _Malformed("non-minimal INTEGER")
            elif tag == 3:
                if len(c) == 0 or c[0] > 7 or (len(c) == 1 and c[0] != 0):
                    raise _Malformed("malformed BIT STRING")
                if len(c) > 1 and c[-1] & ((1 << c[0]) - 1) != 0:
                    raise _Malformed("BIT STRING unused bits not zero")
            elif tag == 5:
                if len(c) != 0:
                    raise _Malformed("NULL with content")
            elif tag in (6, 13):
                if len(c) == 0 or c[-1] & 0x80 != 0:
                    raise _Malformed("truncated OBJECT IDENTIFIER")
                for i, b in enumerate(c):
                    if b == 0x80 and (i == 0 or c[i - 1] & 0x80 == 0):
                        raise _Malformed("non-minimal OBJECT IDENTIFIER")
            elif tag == 23:
                if _UTC_TIME_DER.fullmatch(bytes(c).decode("latin-1")) is None:
                    raise _Malformed("UTCTime not in DER form")
            elif tag == 24:
                if _GENERALIZED_TIME_DER.fullmatch(bytes(c).decode("latin-1")) is None:
                    raise _Malformed("GeneralizedTime not in DER form")
        if el.constructed:
            _check_der(c, depth + 1, count)


def _parse_der(data: _Buf) -> _Der:
    """``data`` as exactly one DER element, checked through. The element and every element
    read from it are views of ``data``."""
    view = memoryview(data)
    _check_der(view, 0, [0])
    el = _read_element(view, 0, len(view))
    if len(el.raw) != len(view):
        raise _Malformed("bytes after the element")
    return el


def _is(el: _Der | None, cls: int, tag: int, constructed: bool) -> bool:
    return el is not None and el.cls == cls and el.tag == tag and el.constructed == constructed


def _is_sequence(el: _Der | None) -> bool:
    return _is(el, 0, 16, True)


def _is_set(el: _Der | None) -> bool:
    return _is(el, 0, 17, True)


def _is_integer(el: _Der | None) -> bool:
    return _is(el, 0, 2, False)


def _is_oid(el: _Der | None) -> bool:
    return _is(el, 0, 6, False)


def _is_octets(el: _Der | None) -> bool:
    return _is(el, 0, 4, False)


def _at(items: list[_Der], i: int) -> _Der | None:
    return items[i] if 0 <= i < len(items) else None


def _oid(el: _Der) -> str:
    """The dotted form of an OBJECT IDENTIFIER's content, in the TypeScript verifier's
    arithmetic: each arc an ECMAScript number, so an arc past 2^53 is rounded as it is
    there."""
    parts: list[float] = []
    value = 0.0
    for b in el.content:
        value = value * 128 + (b & 0x7F)
        if b & 0x80 == 0:
            if not parts:
                head = 0 if value < 40 else 1 if value < 80 else 2
                parts.append(head)
                parts.append(value - head * 40)
            else:
                parts.append(value)
            value = 0.0
    return ".".join(js_integral_number_string(p) for p in parts)


def _algorithm_of(el: _Der | None) -> tuple[str, _Der | None] | None:
    """An AlgorithmIdentifier's OID and parameters, or ``None`` when it is not one."""
    if el is None or not _is_sequence(el):
        return None
    items = _elements_of(el.content)
    id_ = _at(items, 0)
    if id_ is None or not _is_oid(id_) or len(items) > 2:
        return None
    return _oid(id_), _at(items, 1)


_UTC_TIME: Final = re.compile(r"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")
_GENERALIZED_TIME: Final = re.compile(
    r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]+))?Z"
)
_DAYS_IN_MONTH: Final = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _time_of(el: _Der | None) -> int | None:
    """A DER UTCTime or GeneralizedTime as milliseconds since the epoch, sub-milliseconds
    truncated; ``None`` when it is neither, or not a date."""
    if el is None or el.cls != 0 or el.constructed:
        return None
    text = bytes(el.content).decode("latin-1")
    if el.tag == 23:
        m = _UTC_TIME.fullmatch(text)
        if m is not None:
            yy = int(m[1])
            fields = [int(g) for g in m.groups()[1:6]]
            return _utc(2000 + yy if yy < 50 else 1900 + yy, fields, "")
    if el.tag == 24:
        m = _GENERALIZED_TIME.fullmatch(text)
        if m is not None:
            fields = [int(g) for g in m.groups()[1:6]]
            return _utc(int(m[1]), fields, m[7] or "")
    return None


def _utc(year: int, fields: list[int], fraction: str) -> int | None:
    month, day, hour, minute, second = fields
    if month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 59:
        return None
    # `Date.UTC` reads a year from 0 to 99 as 1900 to 1999, so the date it makes is not
    # that year's, and the TypeScript verifier refuses it.
    if 0 <= year <= 99:
        return None
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    if day > _DAYS_IN_MONTH[month - 1] + (1 if month == 2 and leap else 0):
        return None
    millis = int((fraction + "000")[:3])
    days = days_from_civil(year, month, day)
    return ((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis


# ---- OpenSSL's reading of a certificate --------------------------------------------------------

#: OpenSSL's ``ASN1_tag2bit`` for the universal tags a Name's value may carry
#: (``B_ASN1_PRINTABLE``): BIT STRING, UTF8String, SEQUENCE, NumericString,
#: PrintableString, T61String, IA5String, UniversalString, BMPString, and the tags
#: OpenSSL files as unknown.
_NAME_VALUE_TAGS: Final = frozenset({3, 7, 8, 9, 11, 12, 13, 14, 15, 16, 18, 19, 20, 22, 28, 29, 30})
#: How deep OpenSSL collects a constructed string (``ASN1_MAX_STRING_NEST``).
_MAX_STRING_NEST: Final = 5
#: The longest Name OpenSSL's reader reads (``X509_NAME_MAX``), its header included.
_X509_NAME_MAX: Final = 1 << 20


def _unicode_valid(value: int) -> bool:
    return value <= 0x10FFFF and not 0xD800 <= value <= 0xDFFF


def _string_holds(el: _Der) -> str | None:
    """What OpenSSL's reader refuses in a universal string's value (``asn1_ex_c2i``), and
    in a Name's value when it converts it to UTF-8 (``x509_name_canon``)."""
    c = el.content
    if el.tag == 30:
        if len(c) % 2:
            return "a BMPString of odd length"
        if any(not _unicode_valid(int.from_bytes(c[i : i + 2], "big")) for i in range(0, len(c), 2)):
            return "a BMPString with a surrogate"
    if el.tag == 28:
        if len(c) % 4:
            return "a UniversalString whose length is not a multiple of four"
        if any(not _unicode_valid(int.from_bytes(c[i : i + 4], "big")) for i in range(0, len(c), 4)):
            return "a UniversalString with a character outside Unicode"
    if el.tag == 12:
        try:
            bytes(c).decode("utf-8")
        except UnicodeDecodeError:
            return "a UTF8String that is not UTF-8"
    return None


def _collect(el: _Der) -> bytearray | None:
    """OpenSSL's ``asn1_collect`` on a constructed string: the content of each primitive
    element it holds, whatever its tag, in order; ``None`` when an element is nested
    deeper than ``ASN1_MAX_STRING_NEST``."""
    collected = bytearray()

    def collect(content: _Buf, depth: int) -> bool:
        for child in _elements_of(content):
            if child.constructed:
                if depth >= _MAX_STRING_NEST or not collect(child.content, depth + 1):
                    return False
            else:
                collected.extend(child.content)
        return True

    return collected if collect(el.content, 0) else None


def _any_holds(el: _Der | None) -> str | None:
    """What OpenSSL's reader refuses in an ANY (an AlgorithmIdentifier's parameters): a
    constructed universal value other than a SEQUENCE or SET is collected as a string,
    and a BMPString or UniversalString must have whole characters."""
    if el is None or el.cls != 0:
        return None
    if el.constructed:
        if el.tag not in (16, 17) and _collect(el) is None:
            return "a constructed value nested too deep"
        return None
    c = el.content
    if el.tag == 30 and len(c) % 2:
        return "a BMPString of odd length"
    if el.tag == 28 and len(c) % 4:
        return "a UniversalString whose length is not a multiple of four"
    return None


def _name_holds(name: _Der) -> str | None:
    """Whether OpenSSL reads ``name`` as an X.509 Name: at most ``X509_NAME_MAX`` bytes, a
    SEQUENCE OF SET OF AttributeTypeAndValue, each value a universal string type it reads,
    collected when constructed (a SEQUENCE is kept as it is), whose characters convert to
    UTF-8."""
    if len(name.raw) > _X509_NAME_MAX:
        return "a Name longer than X509_NAME_MAX"
    for rdn in _elements_of(name.content):
        if not _is_set(rdn):
            return "a Name holds something other than a SET"
        for atv in _elements_of(rdn.content):
            parts = _elements_of(atv.content) if _is_sequence(atv) else []
            if len(parts) != 2 or not _is_oid(parts[0]):
                return "a Name holds something other than a type and a value"
            value = parts[1]
            if value.cls != 0 or value.tag not in _NAME_VALUE_TAGS:
                return "a Name's value is not a string type"
            if value.constructed and value.tag != 16 and _collect(value) is None:
                return "a Name's value nested too deep"
            why = _string_holds(value)
            if why is not None:
                return why
    return None


def _collected_bit_string_holds(el: _Der) -> str | None:
    """OpenSSL's reading of an issuerUniqueID or subjectUniqueID ([1] or [2] IMPLICIT BIT
    STRING): a constructed one is collected, and the result must open with a count of
    unused bits from 0 to 7."""
    data: _Buf | bytearray | None = _collect(el) if el.constructed else el.content
    if data is None:
        return "a unique identifier nested too deep"
    if len(data) == 0 or data[0] > 7:
        return "a unique identifier that is not a BIT STRING"
    return None


def _openssl_reads(
    fields: list[_Der],
    after_spki: int,
    issuer: _Der,
    validity: _Der,
    subject: _Der,
    params: list[_Der | None],
) -> str | None:
    """Why OpenSSL's X.509 reader (``d2i_X509``) refuses a certificate that step 1's
    checks accept, or ``None``: the Names, the validity's two times, what follows the
    subjectPublicKeyInfo, and the parameters of its AlgorithmIdentifiers."""
    for p in params:
        why = _any_holds(p)
        if why is not None:
            return why
    for name in (issuer, subject):
        why = _name_holds(name)
        if why is not None:
            return why
    if len(_elements_of(validity.content)) != 2:
        return "the validity is not two times"
    rest = fields[after_spki:]
    i = 0
    for number in (1, 2):
        el = _at(rest, i)
        if el is not None and el.cls == 2 and el.tag == number:
            why = _collected_bit_string_holds(el)
            if why is not None:
                return why
            i += 1
    el = _at(rest, i)
    if el is not None and el.cls == 2 and el.tag == 3:
        if not el.constructed:
            return "the extensions' [3] tag is not constructed"
        if len(_elements_of(el.content)) != 1:
            return "the extensions' [3] tag holds more than one element"
        i += 1
    if i != len(rest):
        return "tbsCertificate holds fields after its subjectPublicKeyInfo that are not X.509's"
    return None


# ---- Public keys ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PublicKey:
    """A certificate's public key: its type, as Node names it, and the key."""

    type: str
    #: An RSA key's modulus and exponent.
    rsa: tuple[int, int] | None = None
    #: The key as :mod:`cryptography` holds it, for every other type it loads.
    key: object = None
    #: An EC key :mod:`cryptography` does not load: ``"infinity"``, the point at infinity,
    #: which Node reads and under which no signature verifies; ``"unsupported"``, a key Node
    #: reads on a curve, named or explicit, this library does not implement;
    #: ``"unimplemented"``, a key on a named curve Node's OpenSSL does not implement
    #: either, left unread as the TypeScript verifier leaves it.
    ec_limit: Literal["infinity", "unsupported", "unimplemented"] | None = None


def _ber_header(buf: _Buf, pos: int, available: int) -> tuple[int, int, bool, int, int, bool] | None:
    """OpenSSL's ``ASN1_get_object``: ``(class, tag, constructed, start, length,
    indefinite)`` of the element at ``pos``, or ``None`` where OpenSSL refuses it."""
    if available <= 0:
        return None
    first = buf[pos]
    cls = first >> 6
    constructed = (first & 0x20) != 0
    p = pos + 1
    left = available - 1
    if first & 0x1F == 0x1F:
        if left == 0:
            return None
        tag = 0
        while buf[p] & 0x80:
            tag = (tag << 7) | (buf[p] & 0x7F)
            p += 1
            left -= 1
            if left == 0 or tag > (0x7FFFFFFF >> 7):
                return None
        tag = (tag << 7) | (buf[p] & 0x7F)
        p += 1
        left -= 1
        if left == 0:
            return None
    else:
        tag = first & 0x1F
        if left == 0:
            return None
    # asn1_get_length
    left -= 1
    first_len = buf[p]
    p += 1
    indefinite = False
    if first_len == 0x80:
        indefinite = True
        length = 0
    elif first_len & 0x80:
        n = first_len & 0x7F
        if left < n + 1:
            return None
        while n > 0 and buf[p] == 0:
            p += 1
            n -= 1
        if n > 8:
            return None
        length = int.from_bytes(buf[p : p + n], "big")
        p += n
        if length > 0x7FFFFFFFFFFFFFFF:
            return None
    else:
        length = first_len
    if indefinite and not constructed:
        return None
    if not indefinite and length > available - (p - pos):
        return None
    return cls, tag, constructed, p, length, indefinite


def _openssl_rsa_key(bits: _Buf) -> tuple[int, int] | None:
    """An RSAPublicKey as OpenSSL reads one from a subjectPublicKey's bytes: a SEQUENCE,
    of definite or indefinite length, of exactly two INTEGERs read unsigned, whatever
    their encoding; what follows the SEQUENCE is not read."""
    header = _ber_header(bits, 0, len(bits))
    if header is None:
        return None
    cls, tag, constructed, pos, length, indefinite = header
    if cls != 0 or tag != 16 or not constructed:
        return None
    left = len(bits) - pos if indefinite else length
    numbers: list[int] = []
    while len(numbers) < 2:
        if left == 0:
            return None
        if left >= 2 and bits[pos] == 0 and bits[pos + 1] == 0:
            return None
        field = _ber_header(bits, pos, left)
        if field is None:
            return None
        f_cls, f_tag, f_constructed, start, f_length, _ = field
        if f_cls != 0 or f_tag != 2 or f_constructed:
            return None
        numbers.append(int.from_bytes(bits[start : start + f_length], "big"))
        left -= start + f_length - pos
        pos = start + f_length
    if indefinite:
        if left < 2 or bits[pos] != 0 or bits[pos + 1] != 0:
            return None
    elif left != 0:
        return None
    return numbers[0], numbers[1]


def _read_public_key(
    spki: _Der, algorithm: str, params: _Der | None, key_bits: _Buf
) -> _PublicKey | None:
    """The key of a subjectPublicKeyInfo whose AlgorithmIdentifier is ``algorithm`` and
    ``params``, as Node reads it; ``None`` when it does not decode."""
    key_type = _KEY_TYPES.get(algorithm)
    if key_type is None:
        return None
    if algorithm in (_OID_RSA, _OID_RSA_PSS):
        # OpenSSL takes RSA-PSS parameters, when present, only as a SEQUENCE
        # (``ossl_rsa_param_decode``).
        if algorithm == _OID_RSA_PSS and params is not None and not _is_sequence(params):
            return None
        numbers = _openssl_rsa_key(key_bits[1:])
        return None if numbers is None else _PublicKey(key_type, rsa=numbers)
    try:
        # A key cryptography reads and deprecates (a DHX key) is still read.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            key = serialization.load_der_public_key(bytes(spki.raw))
    except (UnsupportedAlgorithm, ValueError) as exc:
        return _ec_key_node_reads(key_type, params, key_bits, exc)
    except Exception:
        return None
    return _PublicKey(key_type, key=key)


def _ec_key_node_reads(
    key_type: str, params: _Der | None, key_bits: _Buf, refusal: Exception
) -> _PublicKey | None:
    """An EC key :mod:`cryptography` refuses and Node reads, or ``None``. On a named curve
    Node's OpenSSL implements: the point at infinity, or, on a curve :mod:`cryptography`
    does not implement, a point of the length the curve's field gives. With explicit
    curve parameters: any point. On a named curve Node's OpenSSL does not implement, any
    point, left unread (``"unimplemented"``)."""
    if key_type != "ec" or params is None:
        return None
    point = bytes(key_bits[1:])
    if _is_oid(params):
        size = _OPENSSL_CURVES.get(_oid(params))
        if size is None:
            return _PublicKey("ec", ec_limit="unimplemented")
        if point == b"\x00":
            return _PublicKey("ec", ec_limit="infinity")
        if isinstance(refusal, UnsupportedAlgorithm) and (
            (len(point) == 1 + size and point[0] in (2, 3))
            or (len(point) == 1 + 2 * size and point[0] in (4, 6, 7))
        ):
            return _PublicKey("ec", ec_limit="unsupported")
        # A point OpenSSL does not read, or one not on a curve cryptography implements.
        return None
    if _is_sequence(params):
        return _PublicKey("ec", ec_limit="infinity" if point == b"\x00" else "unsupported")
    return None


def _rsa_pkcs1_verifies(rsa: tuple[int, int], digest: str, data: bytes, signature: bytes) -> bool:
    """A PKCS #1 v1.5 signature checked as OpenSSL checks one (``ossl_rsa_verify``)."""
    n, e = rsa
    if n.bit_length() > 16384 or n <= e:
        return False
    if n.bit_length() > 3072 and e.bit_length() > 64:
        return False
    size = (n.bit_length() + 7) // 8
    if len(signature) != size or size < 11:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n or n % 2 == 0:
        return False
    encoded = pow(s, e, n).to_bytes(size, "big")
    t = _DIGEST_INFO[digest] + hashlib.new(digest, data).digest()
    padding = size - 3 - len(t)
    if padding < 8:
        return False
    return encoded == b"\x00\x01" + b"\xff" * padding + b"\x00" + t


# ---- Certificates -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rfc3161Certificate:
    """A certificate as the checks read it: its bytes, names, serial, key, validity and
    extensions."""

    der: bytes
    #: The DER of its subject and issuer Names.
    subject: bytes
    issuer: bytes
    #: The DER of its SubjectPublicKeyInfo.
    spki: bytes
    #: Its public key, or ``None`` for a key algorithm this verifier does not read. An EC
    #: key on a named curve Node's OpenSSL does not implement is read with ``ec_limit``
    #: ``"unimplemented"``, and is as unread as ``None``.
    public_key: _PublicKey | None
    #: The content of its serialNumber INTEGER.
    serial: bytes
    not_before: int
    not_after: int
    #: Each extension by OID: whether it is critical, and its extnValue's content.
    extensions: dict[str, tuple[bool, bytes]]


def _is_bool_then_integer(v: _Der) -> bool:
    if not _is_sequence(v):
        return False
    parts = _elements_of(v.content)
    rest = parts[1:] if parts and _is(parts[0], 0, 1, False) else parts
    return len(rest) == 0 or (len(rest) == 1 and _is_integer(rest[0]))


#: The RFC 5280 type of each standard extension a certificate is held to: its extnValue
#: must be one DER element of that type.
_EXTENSION_TYPES: Final[dict[str, Callable[[_Der], bool]]] = {
    _OID_KEY_USAGE: lambda v: _is(v, 0, 3, False),
    _OID_BASIC_CONSTRAINTS: _is_bool_then_integer,
    _OID_EXT_KEY_USAGE: lambda v: _is_sequence(v) and all(_is_oid(p) for p in _elements_of(v.content)),
    _OID_SUBJECT_KEY_IDENTIFIER: _is_octets,
    "2.5.29.35": _is_sequence,  # authorityKeyIdentifier
    "2.5.29.17": _is_sequence,  # subjectAltName
    "2.5.29.30": _is_sequence,  # nameConstraints
    "2.5.29.31": _is_sequence,  # cRLDistributionPoints
    "2.5.29.32": _is_sequence,  # certificatePolicies
    "1.3.6.1.5.5.7.1.1": _is_sequence,  # authorityInfoAccess
}


def _read_certificate(der: _Buf) -> Rfc3161Certificate:
    """Read a DER X.509 certificate, or raise :class:`_Malformed` when it is not one:
    version v1 to v3; the signature AlgorithmIdentifier inside tbsCertificate the same bytes
    as the one outside it (RFC 5280 §4.1.1.2); a subjectPublicKeyInfo whose key, for an
    algorithm in ``_KEY_ALGORITHMS``, has no unused bits and decodes; a readable validity;
    extensions that are not repeated, each standard one of its type; and a certificate
    OpenSSL's reader reads."""
    cert = _parse_der(der)
    if not _is_sequence(cert):
        raise _Malformed("certificate is not a SEQUENCE")
    top = _elements_of(cert.content)
    tbs, outer, signature_value = _at(top, 0), _at(top, 1), _at(top, 2)
    outer_algorithm = _algorithm_of(outer)
    if (
        tbs is None
        or not _is_sequence(tbs)
        or outer is None
        or outer_algorithm is None
        or not _is(signature_value, 0, 3, False)
        or len(top) > 3
    ):
        raise _Malformed("certificate is not a tbsCertificate, a signatureAlgorithm and a signature")
    fields = _elements_of(tbs.content)
    i = 0
    first = _at(fields, 0)
    if first is not None and _is(first, 2, 0, True):
        i += 1
        inner = _elements_of(first.content)
        version = _at(inner, 0)
        if (
            version is None
            or not _is_integer(version)
            or len(inner) > 1
            or len(version.content) != 1
            or version.content[0] > 2
        ):
            raise _Malformed("certificate version is not v1, v2 or v3")
    serial, inner_algorithm, issuer, validity, subject, spki = (
        _at(fields, i),
        _at(fields, i + 1),
        _at(fields, i + 2),
        _at(fields, i + 3),
        _at(fields, i + 4),
        _at(fields, i + 5),
    )
    i += 6
    if (
        serial is None
        or issuer is None
        or validity is None
        or subject is None
        or spki is None
        or not _is_integer(serial)
        or not _is_sequence(issuer)
        or not _is_sequence(validity)
        or not _is_sequence(subject)
        or not _is_sequence(spki)
    ):
        raise _Malformed("tbsCertificate does not have the X.509 fields")
    if inner_algorithm is None or inner_algorithm.raw != outer.raw:
        raise _Malformed("the signature algorithm inside tbsCertificate is not the one outside it")
    spki_items = _elements_of(spki.content)
    spki_algorithm = _algorithm_of(_at(spki_items, 0))
    spki_key = _at(spki_items, 1)
    if spki_algorithm is None or spki_key is None or not _is(spki_key, 0, 3, False) or len(spki_items) > 2:
        raise _Malformed("subjectPublicKeyInfo is not an AlgorithmIdentifier and a BIT STRING")
    if spki_algorithm[0] in _KEY_ALGORITHMS and spki_key.content[0] != 0:
        raise _Malformed("subjectPublicKey has unused bits")
    times = _elements_of(validity.content)
    not_before = _time_of(_at(times, 0))
    not_after = _time_of(_at(times, 1))
    if not_before is None or not_after is None:
        raise _Malformed("unreadable validity")
    extensions: dict[str, tuple[bool, bytes]] = {}
    block = next((f for f in fields[i:] if _is(f, 2, 3, True)), None)
    if block is not None:
        listed = _at(_elements_of(block.content), 0)
        if listed is None or not _is_sequence(listed):
            raise _Malformed("extensions are not a SEQUENCE")
        for ext in _elements_of(listed.content):
            # Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
            parts = _elements_of(ext.content) if _is_sequence(ext) else []
            flagged = _is(_at(parts, 1), 0, 1, False)
            critical = flagged and parts[1].content[0] == 0xFF
            value = _at(parts, 2 if flagged else 1)
            id_el = _at(parts, 0)
            if (
                id_el is None
                or not _is_oid(id_el)
                or value is None
                or not _is_octets(value)
                or len(parts) != (3 if flagged else 2)
            ):
                raise _Malformed("malformed extension")
            ext_id = _oid(id_el)
            if ext_id in extensions:
                raise _Malformed("repeated extension")
            of_type = _EXTENSION_TYPES.get(ext_id)
            if of_type is not None:
                try:
                    inner_value = _parse_der(value.content)
                except Exception as exc:
                    raise _Malformed(f"extension {ext_id} is not DER") from exc
                if not of_type(inner_value):
                    raise _Malformed(f"extension {ext_id} is not of its type")
            extensions[ext_id] = (critical, bytes(value.content))
    unread = _openssl_reads(fields, i, issuer, validity, subject, [outer_algorithm[1], spki_algorithm[1]])
    if unread is not None:
        raise _Malformed(f"certificate does not parse: {unread}")
    public_key = _read_public_key(spki, spki_algorithm[0], spki_algorithm[1], spki_key.content)
    if public_key is None and spki_algorithm[0] in _KEY_ALGORITHMS:
        raise _Malformed("the certificate's public key does not decode: it is not a key of its algorithm")
    return Rfc3161Certificate(
        der=bytes(der),
        subject=bytes(subject.raw),
        issuer=bytes(issuer.raw),
        spki=bytes(spki.raw),
        public_key=public_key,
        serial=bytes(serial.content),
        not_before=not_before,
        not_after=not_after,
        extensions=extensions,
    )


# ---- The auditor's roots, and the authority -------------------------------------------------


class UnreadableTrustAnchorError(ValueError):
    """A trust root or intermediate the auditor supplied that the verifier cannot read: an
    input error, never a verdict on a token (Verification §3.1, §6.6). The verifier
    refuses it rather than drop it and go on, since a dropped root reads as a token that
    chains to no root. The twin of the TypeScript ``UnreadableTrustAnchorError``, with
    the same messages."""


_PEM_CERTIFICATE: Final = re.compile(r"-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----")
#: The whitespace a PEM body may carry between its base64 lines: ASCII tab, line feed,
#: vertical tab, form feed, carriage return and space, as the TypeScript verifier strips.
#: Any other character, Unicode whitespace included, makes the body not base64.
_PEM_WHITESPACE: Final = re.compile(r"[\t\n\x0b\x0c\r ]+")
_BASE64_BODY: Final = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def read_trust_anchors(pems: object) -> list[Rfc3161Certificate]:
    """The certificates of the auditor's PEM inputs, every one of them: each entry must
    hold at least one ``CERTIFICATE`` block, and each block must read as a certificate by
    the rules of Anchor §10.5 step 1 with a key whose algorithm and curve the TypeScript verifier
    implements (a root whose key algorithm or curve it does not implement cannot anchor a
    path it can check). The messages are the TypeScript ``trustAnchorsFromPem``'s.

    One input reads here and not there: an EC key on a named curve Node's OpenSSL
    implements and :mod:`cryptography` does not (SM2, secp224k1, the binary curves, …) is
    checked for the length of its point alone, as step 1 checks it, so a point that is not
    on that curve reads here, where the TypeScript verifier refuses it as a key that does
    not decode.

    :raises UnreadableTrustAnchorError: naming the entry and why.
    """
    if not isinstance(pems, (list, tuple)):
        raise UnreadableTrustAnchorError("the trust anchors are not a list of PEM strings")
    out: list[Rfc3161Certificate] = []
    for i, pem in enumerate(pems):
        which = f"trust anchor {i + 1}"
        if not isinstance(pem, str):
            raise UnreadableTrustAnchorError(f"{which} is not a PEM string")
        blocks = _PEM_CERTIFICATE.findall(pem)
        if not blocks:
            raise UnreadableTrustAnchorError(f"{which} holds no PEM CERTIFICATE block")
        for j, block in enumerate(blocks):
            where = f"{which}, certificate {j + 1}" if len(blocks) > 1 else which
            body = _PEM_WHITESPACE.sub("", block)
            if not _BASE64_BODY.fullmatch(body) or len(body) % 4 != 0:
                raise UnreadableTrustAnchorError(f"{where} is not base64")
            try:
                cert = _read_certificate(base64.b64decode(body))
            except _Malformed as exc:
                raise UnreadableTrustAnchorError(f"{where} does not read as a certificate: {exc}") from None
            key = cert.public_key
            if key is None or key.ec_limit == "unimplemented":
                what = "elliptic curve" if key is not None else "public-key algorithm"
                raise UnreadableTrustAnchorError(
                    f"{where} has a key this verifier does not implement: its {what} is not supported"
                )
            out.append(cert)
    return out


_OID_COMMON_NAME: Final = "2.5.4.3"


def authority_of(cert: Rfc3161Certificate) -> str:
    """The ``authority`` fact of a trust check (tzun-anchor/1 §10.5 step 4, §10.7): from the
    certificate's subject Name alone, the value of its first commonName (2.5.4.3), taking
    the RDNs and the attributes of each RDN in the order they are encoded, as the
    characters its string type holds (a UTF8String as UTF-8, a TeletexString as ISO
    8859-1, a BMPString as UTF-16, a UniversalString as UTF-32, the other string types
    byte for byte), with no escaping, no trimming and no normalization, even when it is
    empty. With no commonName, the empty string. The twin of the TypeScript
    ``authorityOf``."""
    try:
        name = _parse_der(cert.subject)
        if not _is_sequence(name):
            return ""
        for rdn in _elements_of(name.content):
            if not _is_set(rdn):
                continue
            for atv in _elements_of(rdn.content):
                parts = _elements_of(atv.content) if _is_sequence(atv) else []
                type_, value = _at(parts, 0), _at(parts, 1)
                if type_ is not None and value is not None and _is_oid(type_) and _oid(type_) == _OID_COMMON_NAME:
                    return _string_value(value)
    except Exception:
        # A subject that does not parse names no commonName.
        return ""
    return ""


def _string_value(value: _Der) -> str:
    """The characters a Name's string value holds, by its type. A code unit sequence that
    does not decode (a lone UTF-16 surrogate, invalid UTF-8, a UTF-32 value past U+10FFFF)
    is U+FFFD, so the result is always a string a report can write."""
    data = bytes(value.content)
    if value.cls != 0:
        return data.decode("latin-1")
    if value.tag == 12:
        return data.decode("utf-8", errors="replace")
    if value.tag == 30:
        units = [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data) - 1, 2)]
        chars: list[str] = []
        k = 0
        while k < len(units):
            u = units[k]
            if 0xD800 <= u <= 0xDBFF and k + 1 < len(units) and 0xDC00 <= units[k + 1] <= 0xDFFF:
                chars.append(chr(0x10000 + ((u - 0xD800) << 10) + (units[k + 1] - 0xDC00)))
                k += 2
                continue
            chars.append("\ufffd" if 0xD800 <= u <= 0xDFFF else chr(u))
            k += 1
        if len(data) % 2:
            chars.append("\ufffd")
        return "".join(chars)
    if value.tag == 28:
        out: list[str] = []
        for i in range(0, len(data) - 3, 4):
            cp = int.from_bytes(data[i : i + 4], "big")
            out.append("\ufffd" if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF else chr(cp))
        if len(data) % 4:
            out.append("\ufffd")
        return "".join(out)
    return data.decode("latin-1")


# ---- Step 1: the token ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rfc3161Token:
    """A token that step 1 read."""

    imprint_algorithm: str
    #: The imprint algorithm's parameters: ``None`` when absent, or their DER.
    imprint_params: bytes | None
    hashed_message: bytes
    #: The TSTInfo's genTime, in milliseconds since the epoch.
    gen_time: int
    signer: Rfc3161Certificate
    #: Every certificate the token carries, the signer included.
    certificates: tuple[Rfc3161Certificate, ...]
    digest_algorithm: str
    #: The signed attributes' element, ``[0] IMPLICIT``; ``None`` when the SignerInfo has none.
    signed_attrs: _Der | None
    signature_algorithm: str
    signature: bytes
    #: The encapsulated TSTInfo's bytes.
    e_content: bytes


@dataclass(frozen=True, slots=True)
class Rfc3161Unreadable:
    """Why step 1 does not hold."""

    error: str


_BASE64: Final = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def _strict_base64(text: str) -> bytes | None:
    """RFC 4648 §4 base64 with ``=`` padding, and nothing else: no whitespace, no URL-safe
    alphabet, no stray bits."""
    if len(text) == 0 or len(text) % 4 != 0 or _BASE64.fullmatch(text) is None:
        return None
    try:
        data = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    return data if base64.b64encode(data).decode("ascii") == text else None


def read_rfc3161_token(token: object) -> Rfc3161Token | Rfc3161Unreadable:
    """Anchor §10.5 step 1: whether ``token`` is the base64 of a DER TimeStampResp that carries a
    readable timestamp and the certificate its SignerInfo names."""
    if not isinstance(token, str):
        return Rfc3161Unreadable("the token is not a string")
    der = _strict_base64(token)
    if der is None:
        return Rfc3161Unreadable("the token is not RFC 4648 base64")
    try:
        return _read_token(der)
    except _Malformed as exc:
        return Rfc3161Unreadable(str(exc))
    except Exception as exc:
        return Rfc3161Unreadable(f"unreadable: {exc}")


def _read_token(der: bytes) -> Rfc3161Token | Rfc3161Unreadable:
    malformed = Rfc3161Unreadable
    resp = _parse_der(der)
    if not _is_sequence(resp):
        return malformed("TimeStampResp is not a SEQUENCE")
    top = _elements_of(resp.content)
    status_info, content_info = _at(top, 0), _at(top, 1)
    if status_info is None or not _is_sequence(status_info) or len(top) > 2:
        return malformed("TimeStampResp does not have its two members")
    status = _at(_elements_of(status_info.content), 0)
    if status is None or not _is_integer(status):
        return malformed("PKIStatus is not an INTEGER")
    if len(status.content) != 1 or status.content[0] > 1:
        return malformed("PKIStatus is neither granted nor grantedWithMods")
    if content_info is None or not _is_sequence(content_info):
        return malformed("TimeStampResp carries no timeStampToken")

    ci = _elements_of(content_info.content)
    content_type, explicit = _at(ci, 0), _at(ci, 1)
    if (
        content_type is None
        or not _is_oid(content_type)
        or _oid(content_type) != _OID_SIGNED_DATA
        or explicit is None
        or not _is(explicit, 2, 0, True)
    ):
        return malformed("timeStampToken is not a ContentInfo of SignedData")
    signed_data = _at(_elements_of(explicit.content), 0)
    if signed_data is None or not _is_sequence(signed_data):
        return malformed("SignedData is not a SEQUENCE")
    sd = _elements_of(signed_data.content)
    i = 0
    version = _at(sd, i)
    i += 1
    digest_algorithms = _at(sd, i)
    i += 1
    if (
        not _is_integer(version)
        or digest_algorithms is None
        or not _is_set(digest_algorithms)
        or not all(_algorithm_of(a) is not None for a in _elements_of(digest_algorithms.content))
    ):
        return malformed("SignedData does not open with a version and a SET OF AlgorithmIdentifier")
    encap = _at(sd, i)
    i += 1
    certificates_el: _Der | None = None
    if _is(_at(sd, i), 2, 0, True):
        certificates_el = sd[i]
        i += 1
    if _is(_at(sd, i), 2, 1, True):
        i += 1
    signer_infos = _at(sd, i)
    i += 1
    if encap is None or not _is_sequence(encap) or signer_infos is None or not _is_set(signer_infos) or i != len(sd):
        return malformed("SignedData does not have the CMS members")

    ec_items = _elements_of(encap.content)
    e_content_type, e_content_explicit = _at(ec_items, 0), _at(ec_items, 1)
    if e_content_type is None or not _is_oid(e_content_type) or _oid(e_content_type) != _OID_TST_INFO:
        return malformed("eContentType is not id-ct-TSTInfo")
    if e_content_explicit is None or not _is(e_content_explicit, 2, 0, True):
        return malformed("SignedData carries no encapsulated TSTInfo")
    octets = _elements_of(e_content_explicit.content)
    if len(octets) != 1 or not _is_octets(octets[0]):
        return malformed("eContent is not one OCTET STRING")
    e_content = octets[0].content
    tst_info = _read_tst_info(e_content)
    if isinstance(tst_info, str):
        return malformed(tst_info)

    infos = _elements_of(signer_infos.content)
    if len(infos) != 1 or not _is_sequence(infos[0]):
        return malformed("SignedData does not carry exactly one SignerInfo")
    si = _elements_of(infos[0].content)
    j = 0
    if not _is_integer(_at(si, j)):
        return malformed("SignerInfo has no version")
    j += 1
    sid = _at(si, j)
    j += 1
    digest_algorithm = _algorithm_of(_at(si, j))
    j += 1
    signed_attrs: _Der | None = None
    if _is(_at(si, j), 2, 0, True):
        signed_attrs = si[j]
        j += 1
    signature_algorithm = _algorithm_of(_at(si, j))
    j += 1
    signature = _at(si, j)
    j += 1
    unsigned_attrs: _Der | None = None
    if _is(_at(si, j), 2, 1, True):
        unsigned_attrs = si[j]
        j += 1
    if (
        sid is None
        or digest_algorithm is None
        or signature_algorithm is None
        or signature is None
        or not _is_octets(signature)
        or j != len(si)
    ):
        return malformed("SignerInfo does not have the CMS members")
    # Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF AttributeValue }
    for attrs in (signed_attrs, unsigned_attrs):
        for attr in _elements_of(attrs.content) if attrs is not None else []:
            parts = _elements_of(attr.content) if _is_sequence(attr) else []
            if not _is_oid(_at(parts, 0)) or not _is_set(_at(parts, 1)) or len(parts) > 2:
                return malformed("a SignerInfo attribute is not an OBJECT IDENTIFIER and a SET")

    certificates: list[Rfc3161Certificate] = []
    for choice in _elements_of(certificates_el.content) if certificates_el is not None else []:
        # Only the Certificate choice is a certificate; the others are tagged.
        if _is_sequence(choice):
            certificates.append(_read_certificate(choice.raw))
    signer = _find_signer(sid, certificates)
    if signer is None:
        return malformed("the token does not carry the certificate its SignerInfo names")

    algorithm, params, hashed, gen_time = tst_info
    return Rfc3161Token(
        imprint_algorithm=algorithm,
        imprint_params=params,
        hashed_message=hashed,
        gen_time=gen_time,
        signer=signer,
        certificates=tuple(certificates),
        digest_algorithm=digest_algorithm[0],
        signed_attrs=signed_attrs,
        signature_algorithm=signature_algorithm[0],
        signature=bytes(signature.content),
        e_content=bytes(e_content),
    )


def _read_tst_info(data: _Buf) -> tuple[str, bytes | None, bytes, int] | str:
    """The TSTInfo in ``data`` (its imprint's algorithm, parameters and value, and its
    genTime), or why it is not one."""
    try:
        seq = _parse_der(data)
    except Exception as exc:
        return f"TSTInfo is not DER: {exc}"
    if not _is_sequence(seq):
        return "TSTInfo is not a SEQUENCE"
    # TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
    items = _elements_of(seq.content)
    version, policy, imprint, serial, gen_time = (_at(items, k) for k in range(5))
    if (
        not _is_integer(version)
        or not _is_oid(policy)
        or imprint is None
        or not _is_sequence(imprint)
        or not _is_integer(serial)
    ):
        return "TSTInfo does not have its fields"
    parts = _elements_of(imprint.content)
    algorithm = _algorithm_of(_at(parts, 0))
    hashed = _at(parts, 1)
    if algorithm is None or hashed is None or not _is_octets(hashed) or len(parts) > 2:
        return "messageImprint is not an AlgorithmIdentifier and an OCTET STRING"
    at = _time_of(gen_time) if _is(gen_time, 0, 24, False) else None
    if at is None:
        return "genTime is not a GeneralizedTime"
    params = algorithm[1]
    return algorithm[0], None if params is None else bytes(params.raw), bytes(hashed.content), at


def _find_signer(sid: _Der, certificates: list[Rfc3161Certificate]) -> Rfc3161Certificate | None:
    """The certificate ``sid`` names: by issuer and serial number, or by
    subjectKeyIdentifier."""
    if _is_sequence(sid):
        parts = _elements_of(sid.content)
        issuer, serial = _at(parts, 0), _at(parts, 1)
        if issuer is None or serial is None or not _is_sequence(issuer) or not _is_integer(serial):
            return None
        return next(
            (c for c in certificates if c.issuer == issuer.raw and c.serial == serial.content), None
        )
    if _is(sid, 2, 0, False):
        for c in certificates:
            ski = c.extensions.get(_OID_SUBJECT_KEY_IDENTIFIER)
            if ski is None:
                continue
            try:
                key_id = _parse_der(ski[1])
            except Exception:
                continue
            if _is_octets(key_id) and key_id.content == sid.content:
                return c
    return None


# ---- Step 2: the imprint ------------------------------------------------------------------------

_HEX_DIGEST: Final = re.compile(r"[0-9a-fA-F]{64}")


def imprint_holds(token: Rfc3161Token, expected_hex: object) -> bool:
    """Anchor §10.5 step 2: the imprint is SHA-256 (parameters absent or NULL) over
    ``expected_hex``."""
    if token.imprint_algorithm != _OID_SHA256:
        return False
    if token.imprint_params is not None and token.imprint_params != b"\x05\x00":
        return False
    if not isinstance(expected_hex, str) or _HEX_DIGEST.fullmatch(expected_hex) is None:
        return False
    return token.hashed_message == bytes.fromhex(expected_hex)


# ---- Step 3: the signature and the signer ------------------------------------------------------

Rfc3161StepReason = Literal["malformed", "imprint_mismatch", "verification_failed", "missing_dependency"]


def check_signature_and_signer(
    token: Rfc3161Token,
) -> tuple[Literal["verification_failed", "missing_dependency"], str] | None:
    """Anchor §10.5 step 3: the signed attributes carry content-type id-ct-TSTInfo and a
    message-digest of the TSTInfo; the signature over them verifies under the signer
    certificate's key; a signingCertificate or signingCertificateV2 names the signer
    certificate (each one present must); and that certificate has a critical
    extendedKeyUsage whose only purpose is id-kp-timeStamping. ``None`` when it holds, or
    the reason and the error."""

    def failed(error: str) -> tuple[Literal["verification_failed"], str]:
        return "verification_failed", error

    def missing(error: str) -> tuple[Literal["missing_dependency"], str]:
        return "missing_dependency", error

    signer = token.signer
    if token.signed_attrs is None:
        return failed("the SignerInfo has no signed attributes")

    attributes: dict[str, list[list[_Der]]] = {}
    for attr in _elements_of(token.signed_attrs.content):
        parts = _elements_of(attr.content) if _is_sequence(attr) else []
        type_, values = _at(parts, 0), _at(parts, 1)
        if type_ is None or values is None or not _is_oid(type_) or not _is_set(values) or len(parts) > 2:
            return failed("a signed attribute is malformed")
        attributes.setdefault(_oid(type_), []).append(_elements_of(values.content))

    def single(id_: str) -> _Der | _Absent | None:
        """The attribute's one value; ``_ABSENT`` when there is no such attribute, and
        ``None`` when it is repeated or has more than one value."""
        found = attributes.get(id_)
        if found is None:
            return _ABSENT
        return found[0][0] if len(found) == 1 and len(found[0]) == 1 else None

    content_type = single(_OID_CONTENT_TYPE)
    if (
        not isinstance(content_type, _Der)
        or not _is_oid(content_type)
        or _oid(content_type) != _OID_TST_INFO
    ):
        return failed("the content-type attribute is not one id-ct-TSTInfo")
    message_digest = single(_OID_MESSAGE_DIGEST)
    if not isinstance(message_digest, _Der) or not _is_octets(message_digest):
        return failed("the message-digest attribute is not one OCTET STRING")
    digest = _DIGESTS.get(token.digest_algorithm)
    if digest is None:
        return missing(f"digest algorithm {token.digest_algorithm} is not supported")
    if hashlib.new(digest, token.e_content).digest() != message_digest.content:
        return failed("the message-digest attribute is not the digest of the TSTInfo")

    algorithm = _SIGNATURES.get(token.signature_algorithm)
    if algorithm is None:
        return missing(f"signature algorithm {token.signature_algorithm} is not supported")
    key_type, named_digest = algorithm
    key = signer.public_key
    if key is None:
        return missing("the signer certificate's public-key algorithm is not supported")
    if key.ec_limit == "unimplemented":
        return missing("the signer certificate's elliptic curve is not supported")
    if key.type != key_type:
        return failed(f"a {key.type} key cannot verify a {key_type} signature")
    if key.ec_limit == "unsupported":
        return missing("the signer certificate's elliptic curve is not supported")
    # CMS signs the DER of the attributes as a SET OF, not as the [0] IMPLICIT tag they are carried under.
    signed = b"\x31" + bytes(token.signed_attrs.raw[1:])
    try:
        verified = _verifies(key, named_digest or digest, signed, token.signature)
    except _VerifierFault:
        raise
    except Exception as exc:
        return failed(f"the signature does not verify: {exc}")
    if not verified:
        return failed("the signature does not verify under the signer certificate")

    bound = 0
    for id_, v2 in ((_OID_SIGNING_CERTIFICATE, False), (_OID_SIGNING_CERTIFICATE_V2, True)):
        value = single(id_)
        if isinstance(value, _Absent):
            continue
        if not isinstance(value, _Der):
            return failed("a signingCertificate attribute is repeated or has more than one value")
        binding = _binds_signer(value, v2, signer)
        if binding is not True:
            if binding == "missing_dependency":
                return missing("the ESSCertIDv2 hash algorithm is not supported")
            return failed(binding)
        bound += 1
    if bound == 0:
        return failed("no signingCertificate or signingCertificateV2 attribute binds the signer certificate")

    if not _timestamping_only(signer):
        return failed(
            "the signer certificate has no critical extendedKeyUsage whose only purpose is id-kp-timeStamping"
        )
    return None


def _verifies(key: _PublicKey, digest: str, data: bytes, signature: bytes) -> bool:
    """Whether ``signature`` over ``data`` verifies under ``key``: PKCS #1 v1.5 for RSA,
    ECDSA (a DER signature) for EC, and Ed25519. None verifies under the point at
    infinity."""
    if key.type == "rsa" and key.rsa is not None:
        return _rsa_pkcs1_verifies(key.rsa, digest, data, signature)
    if key.type == "ec" and key.ec_limit == "infinity":
        return False
    try:
        if key.type == "ec" and isinstance(key.key, ec.EllipticCurvePublicKey):
            key.key.verify(signature, data, ec.ECDSA(_HASHES[digest]()))
        elif key.type == "ed25519" and isinstance(key.key, ed25519.Ed25519PublicKey):
            key.key.verify(signature, data)
        else:
            raise _VerifierFault(f"a {key.type} key held as {type(key.key).__name__}")
    except InvalidSignature:
        return False
    return True


def _binds_signer(value: _Der, v2: bool, signer: Rfc3161Certificate) -> Literal[True, "missing_dependency"] | str:
    """Whether the first certificate identifier of a SigningCertificate (ESSCertID,
    RFC 2634) or SigningCertificateV2 (ESSCertIDv2, RFC 5816) names ``signer``: its
    certHash over the certificate's DER, and its issuerSerial, when present, naming its
    issuer and serial number. ``True``, ``"missing_dependency"``, or why not."""
    if not _is_sequence(value):
        return "the signingCertificate attribute is not a SEQUENCE"
    certs = _at(_elements_of(value.content), 0)
    if certs is None or not _is_sequence(certs):
        return "the signingCertificate attribute has no certs"
    first = _at(_elements_of(certs.content), 0)
    if first is None or not _is_sequence(first):
        return "the signingCertificate attribute names no certificate"
    parts = _elements_of(first.content)
    i = 0
    digest = "sha256" if v2 else "sha1"
    if v2 and _is_sequence(_at(parts, 0)):
        algorithm = _algorithm_of(_at(parts, i))
        i += 1
        if algorithm is None:
            return "the ESSCertIDv2 hash algorithm is malformed"
        named = _DIGESTS.get(algorithm[0])
        if named is None:
            return "missing_dependency"
        digest = named
    cert_hash = _at(parts, i)
    i += 1
    if cert_hash is None or not _is_octets(cert_hash):
        return "the certificate identifier has no certHash"
    if hashlib.new(digest, signer.der).digest() != cert_hash.content:
        return "the signingCertificate certHash names another certificate"
    issuer_serial = _at(parts, i)
    if issuer_serial is not None:
        pair = _elements_of(issuer_serial.content) if _is_sequence(issuer_serial) else []
        names, serial = _at(pair, 0), _at(pair, 1)
        if names is None or serial is None or not _is_sequence(names) or not _is_integer(serial):
            return "the issuerSerial is malformed"
        directory = next((n for n in _elements_of(names.content) if _is(n, 2, 4, True)), None)
        name = _at(_elements_of(directory.content), 0) if directory is not None else None
        if name is None or not _is_sequence(name):
            return "the issuerSerial names no directoryName"
        if name.raw != signer.issuer or serial.content != signer.serial:
            return "the signingCertificate issuerSerial names another certificate"
    return True


def _timestamping_only(cert: Rfc3161Certificate) -> bool:
    """Whether ``cert`` has a critical extendedKeyUsage whose only purpose is
    id-kp-timeStamping (RFC 3161 §2.3)."""
    eku = cert.extensions.get(_OID_EXT_KEY_USAGE)
    if eku is None or not eku[0]:
        return False
    try:
        seq = _parse_der(eku[1])
        if not _is_sequence(seq):
            return False
        purposes = _elements_of(seq.content)
        return len(purposes) == 1 and _is_oid(purposes[0]) and _oid(purposes[0]) == _OID_KP_TIME_STAMPING
    except Exception:
        return False


# ---- The steps in order --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rfc3161StepsVerdict:
    """Steps 1 to 3: ``held``, or the reason of the first that did not, with its error, and
    once step 1 holds the signer certificate's :func:`authority_of` and the TSTInfo's
    genTime, in milliseconds since the epoch (sub-milliseconds truncated, as the TypeScript
    verifier's ``Date``)."""

    token: Literal["held"] | Rfc3161StepReason
    error: str | None = None
    authority: str | None = None
    gen_time: int | None = None


def verify_rfc3161_steps(token: object, imprint_hex: object) -> Rfc3161StepsVerdict:
    """tzun-anchor/1 §10.5 steps 1 to 3 over ``token``, with ``imprint_hex`` as the value its
    imprint must be, in order: the first step that does not hold decides.

    It does not raise. Should a step fail in a way none of them foresees, the verdict is
    ``missing_dependency`` with an error that says the verifier failed: a verifier fault to
    report, never a verdict on the token (Anchor §10.1).
    """
    try:
        return _steps(token, imprint_hex)
    except Exception as exc:
        return Rfc3161StepsVerdict("missing_dependency", f"{VERIFIER_FAILED}: {exc}")


def _steps(token: object, imprint_hex: object) -> Rfc3161StepsVerdict:
    read = read_rfc3161_token(token)
    if isinstance(read, Rfc3161Unreadable):
        return Rfc3161StepsVerdict("malformed", read.error)
    authority = authority_of(read.signer)
    gen_time = read.gen_time
    if not imprint_holds(read, imprint_hex):
        return Rfc3161StepsVerdict(
            "imprint_mismatch",
            "the imprint is not SHA-256 over the expected value",
            authority,
            gen_time,
        )
    signer = check_signature_and_signer(read)
    if signer is not None:
        return Rfc3161StepsVerdict(signer[0], signer[1], authority, gen_time)
    return Rfc3161StepsVerdict("held", None, authority, gen_time)


__all__ = (
    "VERIFIER_FAILED",
    "Rfc3161Certificate",
    "Rfc3161StepReason",
    "Rfc3161StepsVerdict",
    "Rfc3161Token",
    "Rfc3161Unreadable",
    "UnreadableTrustAnchorError",
    "authority_of",
    "check_signature_and_signer",
    "imprint_holds",
    "read_rfc3161_token",
    "read_trust_anchors",
    "verify_rfc3161_steps",
)
