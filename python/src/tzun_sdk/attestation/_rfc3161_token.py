# HAND-MAINTAINED. NOT generated.
"""Reading an RFC 3161 token as the TypeScript SDK's lenient reader reads it.

The TypeScript SDK's client reads a token it fetched with ``parseTimestampResponse``
and ``extractTSTInfo`` (src/attestation/rfc3161-verify.ts): Node's lenient base64,
asn1js ``fromBER``, pkijs ``ContentInfo`` and ``SignedData``, then the TSTInfo
through asn1js. By them it decides whether a token is one it can check, by which
status (:func:`read_pki_status`), and by which imprint, genTime and nonce
(:func:`read_tst_info`): the Python client's reader. :func:`read_timestamp_token`
reads a token's genTime the same way. This module reads a token as they do, with:

- :func:`~tzun_sdk.attestation._ecmascript.node_base64_decode`, which reads a
  character above U+00FF by the low byte of its UTF-16 code unit, as Node does;
- asn1js's BER reading: its length rules, its type rules (a reserved universal
  tag, a constructed form of a primitive type, an object identifier cut off
  inside a sub-identifier, a BIT STRING with more than 7 unused bits, a
  constructed string of another type, a ``GeneralizedTime`` it cannot read),
  its limits (100 levels, 10,000 elements, 16 MiB), and its offsets: a
  constructed element reads children while its stated length has bytes left,
  the last may run past it, and reading goes on from where that child ended;
- asn1js's reading of the PKIStatus INTEGER, which is 0 for four or more bytes
  whatever they hold, so such a status reads as granted;
- the ContentInfo, SignedData and EncapsulatedContentInfo schemas pkijs
  compares, with their tag classes, numbers and forms;
- asn1js's reading of ``UTCTime`` and ``GeneralizedTime``, as a host whose zone
  is UTC runs it;
- asn1js's decoding of a ``UniversalString`` and a ``BMPString``, which throws on a
  partial character;
- the eContent's bytes as ``eContentBytes`` takes them (asn1js ``getValue()`` for
  an OCTET STRING), and asn1js's values of the imprint's algorithm
  (``valueBlock.toString()``), the imprint's bytes and the nonce
  (``valueHexView``).

What pkijs checks of the certificates and signer infos inside the SignedData
(each certificate against the X.509 schema, each signer info against the CMS
one) is not repeated here. A token corrupted only there is unreadable to the
TypeScript client and readable here: at capture, the TypeScript client refuses
it, and the Python client keeps it and reports it as not meeting tzun-anchor/1
§10.5. ``tests/cross-sdk/test_anchor_verify_parity.py`` holds this reader's
base64 and its ``UTCTime`` and ``GeneralizedTime`` readings to the TypeScript
ones; ``tests/cross-sdk/test_rfc3161_conformance_parity.py`` holds the two
clients to the same tokens kept, BER forms and each byte flipped.

No verifier reads a token this way: the anchor verifiers of both SDKs, like a
bundle's record token, hold an ``rfc3161/1`` token to tzun-anchor/1 §10.5
(:mod:`tzun_sdk.attestation._rfc3161_steps`). Private to
:mod:`tzun_sdk.attestation`.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Final

from tzun_sdk.attestation._ecmascript import (
    JS_ASCII_WHITESPACE,
    civil_from_days,
    date_utc,
    iso_from_millis,
    js_integral_number_string,
    node_base64_decode,
)

_MAX_DEPTH: Final = 100
_MAX_NODES: Final = 10_000
_MAX_CONTENT_LENGTH: Final = 16 * 1024 * 1024

# Universal types asn1js refuses in the constructed form.
_PRIMITIVE_ONLY: Final = frozenset({1, 2, 5, 6, 9, 13, 14, 23, 24, 31, 32, 33, 34})
# Universal types whose value asn1js reads as bytes whatever the constructed bit says.
_BYTES_ALWAYS: Final = frozenset(
    {1, 2, 10, 12, 14, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34}
)
# Universal types whose value block has no bytes of its own (no `valueHexView`).
_NO_BYTES: Final = frozenset({0, 5, 6, 13, 16, 17})


class UnreadableToken(ValueError):
    """The token is not one the TypeScript reader reads."""


@dataclass
class _Element:
    #: Where the element's tag is.
    offset: int
    tag_class: int
    constructed: bool
    number: int
    #: Where the value starts and where the element actually ends. A constructed
    #: element ends after its last child, which may run past its stated length.
    start: int
    end: int
    length: int
    #: The elements asn1js reads inside it; ``None`` when it reads the value as bytes.
    children: list[_Element] | None
    #: Whether its length is the indefinite form.
    indefinite: bool = False

    @property
    def universal(self) -> bool:
        return self.tag_class == 0

    def is_(self, number: int, *, constructed: bool | None = None, tag_class: int = 0) -> bool:
        """Of this class and number, and of this form when ``constructed`` is given."""
        return (
            self.tag_class == tag_class
            and self.number == number
            and (constructed is None or self.constructed == constructed)
        )

    @property
    def is_eoc(self) -> bool:
        return self.universal and self.number == 0


class _Context:
    def __init__(self) -> None:
        self.depth = 0
        self.nodes = 0


def _parse_element(buf: bytes, pos: int, available: int, ctx: _Context) -> _Element:
    """asn1js ``localFromBER``: the element at ``pos``, given ``available`` bytes.

    A declared length is checked against the whole input, not the enclosing
    element: a constructed element reads children while its stated length has
    bytes left, and the last may run past it; the element then ends where its
    last child did.
    """
    if pos < 0 or available < 0 or pos + available > len(buf):
        raise UnreadableToken("end of input reached before message was fully decoded")
    if available == 0:
        raise UnreadableToken("zero buffer length")
    ctx.nodes += 1
    if ctx.nodes > _MAX_NODES:
        raise UnreadableToken("too many elements")

    first = buf[pos]
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    number = first & 0x1F
    cursor = pos + 1
    if number == 0x1F:
        number = 0
        count = 0
        while True:
            if count + 1 >= available:
                raise UnreadableToken("end of input inside a tag")
            b = buf[pos + count + 1]
            count += 1
            number = number * 128 + (b & 0x7F)
            if b & 0x80 == 0:
                break
        cursor = pos + 1 + count
    if tag_class == 0 and constructed and number in _PRIMITIVE_ONLY:
        raise UnreadableToken("constructed encoding used for a primitive type")

    remaining = available - (cursor - pos)
    if remaining <= 0:
        raise UnreadableToken("zero buffer length")
    first_len = buf[cursor]
    if first_len == 0xFF:
        raise UnreadableToken("length block 0xFF is reserved")
    indefinite = first_len == 0x80
    if indefinite:
        length_size = 1
        length = 0
    elif first_len & 0x80:
        count = first_len & 0x7F
        if count > 8:
            raise UnreadableToken("too big a length")
        if count + 1 > remaining:
            raise UnreadableToken("end of input inside a length")
        length = int.from_bytes(buf[cursor + 1 : cursor + 1 + count], "big")
        length_size = count + 1
    else:
        length = first_len
        length_size = 1
    start = cursor + length_size
    remaining -= length_size
    value_length = remaining if indefinite else length
    if value_length > _MAX_CONTENT_LENGTH:
        raise UnreadableToken("content too long")
    if not constructed and indefinite:
        raise UnreadableToken("indefinite length for a primitive encoding")

    if tag_class == 0:
        if number >= 37:
            raise UnreadableToken("a reserved universal tag")
        if number == 15:
            raise UnreadableToken("[UNIVERSAL 15] is reserved")
        if number == 0:
            if constructed and length > 0:
                raise UnreadableToken("[UNIVERSAL 0] is reserved")
            # EndOfContent reads nothing of its value.
            return _Element(pos, tag_class, constructed, number, start, start, length, None)

    reads_children = (tag_class == 0 and number in (16, 17)) or (
        constructed and not (tag_class == 0 and number in _BYTES_ALWAYS)
    )
    if not reads_children:
        if start + value_length > len(buf):
            raise UnreadableToken("end of input reached before message was fully decoded")
        element = _Element(
            pos, tag_class, constructed, number, start, start + value_length, length, None
        )
        _check_primitive(buf, element)
        return element

    if start + value_length > len(buf):
        raise UnreadableToken("end of input reached before message was fully decoded")
    children: list[_Element] = []
    cursor = start
    left = value_length
    ctx.depth += 1
    try:
        while indefinite or left > 0:
            if ctx.depth > _MAX_DEPTH:
                raise UnreadableToken("nesting too deep")
            child = _parse_element(buf, cursor, left, ctx)
            consumed = child.end - cursor
            cursor = child.end
            left -= consumed
            children.append(child)
            if indefinite and child.is_eoc:
                children.pop()
                break
    finally:
        ctx.depth -= 1
    element = _Element(pos, tag_class, constructed, number, start, cursor, length, children, indefinite)
    if tag_class == 0 and number in (3, 4):
        # A constructed OCTET STRING or BIT STRING holds only its own type.
        for child in children:
            if not child.is_(number):
                raise UnreadableToken("a constructed string holds another type")
    return element


def _check_primitive(buf: bytes, element: _Element) -> None:
    """What asn1js refuses in a value it reads as bytes."""
    if not element.universal:
        return
    content = buf[element.start : element.end]
    if element.number in (6, 13) and content and content[-1] & 0x80:
        raise UnreadableToken("an object identifier ends inside a sub-identifier")
    if element.number == 3 and content and content[0] > 7:
        raise UnreadableToken("a BIT STRING with more than 7 unused bits")
    if element.number == 24:
        generalized_time_iso(content.decode("latin-1"))
    # asn1js decodes these strings as it reads them, and throws on a partial character.
    if element.number == 28 and len(content) % 4:
        raise UnreadableToken("a UniversalString whose length is not a multiple of four")
    if element.number == 30 and len(content) % 2:
        raise UnreadableToken("a BMPString of odd length")


def _parse(buf: bytes) -> _Element:
    """asn1js ``fromBER``: the first element of ``buf``; what follows it is ignored."""
    if not buf:
        raise UnreadableToken("empty input")
    return _parse_element(buf, 0, len(buf), _Context())


def _octet_string_bytes(buf: bytes, element: _Element) -> bytes:
    """asn1js ``OctetString.getValue()``: a primitive one's bytes; a constructed one's
    primitive segments, joined, a segment that is itself constructed adding nothing."""
    if element.children is None:
        return buf[element.start : element.end]
    return b"".join(
        buf[child.start : child.end] for child in element.children if child.children is None
    )


def _e_content_bytes(buf: bytes, element: _Element) -> bytes:
    """``eContentBytes`` (src/attestation/rfc3161-verify.ts): a universal OCTET STRING's
    bytes (``getValue()``); for another element asn1js reads elements in, its content as
    asn1js took it (``valueBlock.valueBeforeDecodeView``: its stated length, or all it
    was given in the indefinite form); for any other element, none."""
    if element.is_(4):
        return _octet_string_bytes(buf, element)
    if element.children is None:
        return b""
    return buf[element.start : element.end if element.indefinite else element.start + element.length]


def _children(element: _Element) -> list[_Element]:
    """The elements asn1js reads inside ``element``, or an error where the reader
    would take ``valueBlock.value`` of an element that has none."""
    if element.children is None:
        raise UnreadableToken("not a constructed element")
    return element.children


def _algorithm_identifier(element: _Element) -> bool:
    """pkijs ``AlgorithmIdentifier``: a SEQUENCE whose first element is an OID."""
    kids = element.children
    return element.is_(16, constructed=True) and bool(kids) and kids[0].is_(6, constructed=False)  # type: ignore[index]


def _signed_data_holds(signed: _Element) -> None:
    """pkijs ``SignedData`` as its schema reads it: version INTEGER, a SET of
    AlgorithmIdentifiers, the encapsulated content, [0] certificates and [1] CRLs
    when present, a SET of signer infos; anything after is not read."""
    kids = _children(signed)
    if not signed.is_(16, constructed=True) or len(kids) < 4:
        raise UnreadableToken("not a SignedData")
    if not kids[0].is_(2, constructed=False) or not kids[1].is_(17, constructed=True):
        raise UnreadableToken("not a SignedData")
    if not all(_algorithm_identifier(a) for a in _children(kids[1])):
        raise UnreadableToken("digestAlgorithms holds something else")
    if not kids[2].is_(16, constructed=True):
        raise UnreadableToken("no encapsulated content")
    i = 3
    if i < len(kids) and kids[i].is_(0, constructed=True, tag_class=2):
        i += 1
    if i < len(kids) and kids[i].is_(1, constructed=True, tag_class=2):
        i += 1
    if i >= len(kids) or not kids[i].is_(17, constructed=True):
        raise UnreadableToken("no signer infos")


def _integer(element: _Element) -> bool:
    """Whether asn1js reads ``element`` as an ``Integer``: an INTEGER, or an ENUMERATED,
    whose class extends it."""
    return element.universal and element.number in (2, 10)


def read_pki_status(der: bytes) -> int | None:
    """The PKIStatus of a TimeStampResp where ``parseTimestampResponse`` and
    ``extractPKIStatus`` find it: the first element of the response, a SEQUENCE, and its
    first element, an INTEGER. ``None`` where they find none.

    The value is read whole, as an unsigned number: asn1js reads an INTEGER of four or
    more bytes as 0, which the TypeScript client takes for granted.

    :raises UnreadableToken: when asn1js does not read the response.
    """
    response_el = _parse(der)
    if not response_el.is_(16):
        raise UnreadableToken("the response is not a SEQUENCE")
    response = _children(response_el)
    if not response or not response[0].is_(16):
        return None
    status_info = _children(response[0])
    if not status_info or not _integer(status_info[0]):
        return None
    return int.from_bytes(der[status_info[0].start : status_info[0].end], "big")


def _tst_info(der: bytes) -> tuple[bytes, list[_Element]]:
    """The TSTInfo of a TimeStampResp as ``parseTimestampResponse`` and ``extractTSTInfo``
    reach it: its bytes and the elements asn1js reads in it.

    :raises UnreadableToken: when the TypeScript reader would not reach it.
    """
    response_el = _parse(der)
    if not response_el.is_(16):
        raise UnreadableToken("the response is not a SEQUENCE")
    response = _children(response_el)

    # The status, when it reads as one, must be granted (0) or grantedWithMods (1).
    # asn1js decodes an INTEGER of four or more bytes to 0 ("Too big Integer for
    # decoding, hex only"), so the TypeScript reader reads such a status, whatever
    # its value, as granted. It is read the same way here.
    if response and response[0].is_(16):
        status_info = _children(response[0])
        if status_info and _integer(status_info[0]):
            value = der[status_info[0].start : status_info[0].end]
            status = 0 if len(value) >= 4 else int.from_bytes(value, "big", signed=True)
            if status not in (0, 1):
                raise UnreadableToken(f"non-success status {status}")
    if len(response) < 2 or not response[1].is_(16):
        raise UnreadableToken("no timeStampToken")

    # pkijs ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    content_info = _children(response[1])
    if (
        not response[1].constructed
        or len(content_info) < 2
        or not content_info[0].is_(6, constructed=False)
        or not content_info[1].is_(0, constructed=True, tag_class=2)
        or not _children(content_info[1])
    ):
        raise UnreadableToken("not a ContentInfo")
    signed = _children(content_info[1])[0]
    _signed_data_holds(signed)
    # EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING OPTIONAL }
    encap = _children(_children(signed)[2])
    if not encap or not encap[0].is_(6, constructed=False):
        raise UnreadableToken("not an EncapsulatedContentInfo")
    if (
        len(encap) < 2
        or not encap[1].is_(0, constructed=True, tag_class=2)
        or not _children(encap[1])
    ):
        raise UnreadableToken("no encapsulated TSTInfo")
    tst_der = _e_content_bytes(der, _children(encap[1])[0])

    # TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, ... }
    tst = _children(_parse(tst_der))
    if len(tst) < 5:
        raise UnreadableToken("TSTInfo is too short")
    # The reader takes the algorithm's first element and the imprint's bytes
    # whatever their types, but some types carry no bytes to take.
    imprint = _children(tst[2])
    if len(imprint) < 2 or not _children(imprint[0]):
        raise UnreadableToken("messageImprint is not read")
    hashed = imprint[1]
    if hashed.children is not None and not (hashed.universal and hashed.number in (3, 4)):
        raise UnreadableToken("hashedMessage carries no bytes")
    if hashed.universal and hashed.number in _NO_BYTES:
        raise UnreadableToken("hashedMessage carries no bytes")
    if not (tst[4].is_(24) or tst[4].is_(23)):
        raise UnreadableToken("TSTInfo.genTime is not a time")
    return tst_der, tst


def read_timestamp_token(token: str) -> str | None:
    """The token's ``genTime`` in ISO 8601, or ``None`` when the date is out of range.

    :raises UnreadableToken: when the TypeScript reader would not read the token.
    """
    tst_der, tst = _tst_info(node_base64_decode(token))
    gen_time = tst_der[tst[4].start : tst[4].end].decode("latin-1")
    if tst[4].is_(24):
        return generalized_time_iso(gen_time)
    return utc_time_iso(gen_time)


@dataclass(frozen=True)
class TstInfoFields:
    """What ``extractTSTInfo`` returns of a TimeStampResp: the fields the TypeScript client
    checks a token it fetched by."""

    #: The imprint's hash algorithm as asn1js writes it (``valueBlock.toString()``): the
    #: dotted OBJECT IDENTIFIER, or ``None`` for an element of another type.
    hash_algorithm: str | None
    #: The imprint's bytes (asn1js ``valueHexView``).
    hashed_message: bytes
    #: The text of genTime, a GeneralizedTime or UTCTime.
    gen_time: str
    #: The bytes of the first INTEGER (or ENUMERATED, which asn1js reads as one) after
    #: genTime, the nonce; ``None`` when there is none.
    nonce: bytes | None


def _sid_string(content: bytes, relative: bool) -> str:
    """asn1js ``ObjectIdentifier`` or ``RelativeObjectIdentifier`` ``valueBlock.toString()``:
    each sub-identifier of at most eight bytes as the ECMAScript number pvutils
    ``utilFromBase`` sums, in decimal; a longer one in hex, in braces; the first of an
    OBJECT IDENTIFIER split into its two arcs."""
    out: list[str] = []
    group: list[int] = []
    for b in content:
        group.append(b & 0x7F)
        if b & 0x80:
            continue
        first = not relative and not out
        if len(group) > 8:
            hexed = "{" + bytes(group).hex() + "}"
            out.append(f"2.{{{hexed} - 80}}" if first else hexed)
        else:
            value = float(group[0]) if len(group) == 1 else 0.0
            if len(group) > 1:
                for i, g in enumerate(group):
                    value += g * 2.0 ** (7 * (len(group) - 1 - i))
            if first:
                arc = 0 if value <= 39 else 1 if value <= 79 else 2
                out.append(f"{arc}.{js_integral_number_string(value - 40 * arc)}")
            else:
                out.append(js_integral_number_string(value))
        group = []
    return ".".join(out)


def read_tst_info(der: bytes) -> TstInfoFields:
    """The TSTInfo fields of a TimeStampResp, read as ``parseTimestampResponse`` and
    ``extractTSTInfo`` read them (``src/attestation/rfc3161-verify.ts``): what the
    TypeScript ``RFC3161Client`` checks a token it fetched by, before it keeps it.

    :raises UnreadableToken: when the TypeScript reader would not read the token.
    """
    tst_der, tst = _tst_info(der)
    algorithm = _children(_children(tst[2])[0])[0]
    hash_algorithm = (
        _sid_string(tst_der[algorithm.start : algorithm.end], algorithm.number == 13)
        if algorithm.universal and algorithm.number in (6, 13)
        else None
    )
    hashed = _children(tst[2])[1]
    if hashed.children is not None:
        # A constructed OCTET STRING or BIT STRING: asn1js keeps no bytes of its own.
        hashed_message = b""
    elif hashed.universal and hashed.number == 3:
        hashed_message = tst_der[hashed.start + 1 : hashed.end]
    else:
        hashed_message = tst_der[hashed.start : hashed.end]
    nonce = next((tst_der[e.start : e.end] for e in tst[5:] if _integer(e)), None)
    return TstInfoFields(
        hash_algorithm=hash_algorithm,
        hashed_message=hashed_message,
        gen_time=tst_der[tst[4].start : tst[4].end].decode("latin-1"),
        nonce=nonce,
    )


# ---- asn1js UTCTime and GeneralizedTime -------------------------------------------------------


def utc_time_iso(text: str) -> str | None:
    """A ``UTCTime`` as asn1js dates it: the first ``YYMMDDhhmmssZ`` in the string, the
    year 50-99 in the 1900s and 00-49 in the 2000s; a string with none reads as
    all zeros. Then ``toISOString``; ``None`` for a date out of range."""
    m = re.search(
        r"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z", text, re.IGNORECASE
    )
    if m is None:
        fields: tuple[int, ...] = (0, 0, 0, 0, 0, 0)
    else:
        yy, month, day, hour, minute, second = (int(g) for g in m.groups())
        fields = (1900 + yy if yy >= 50 else 2000 + yy, month, day, hour, minute, second)
    year, month, day, hour, minute, second = fields
    stamp = date_utc(year, month - 1, day, hour, minute, second, 0)
    if stamp != stamp:
        return None
    return iso_from_millis(int(stamp))


def _js_parse_int(text: str) -> int | None:
    """JavaScript ``parseInt(text, 10)``: leading white space, a sign, then digits."""
    m = re.match(rf"[{re.escape(JS_ASCII_WHITESPACE)}]*([+-]?)([0-9]+)", text)
    if m is None:
        return None
    value = int(m.group(2))
    return -value if m.group(1) == "-" else value


def _js_number_fraction(text: str) -> float | None:
    """JavaScript ``Number('0' + text)`` for ``text`` that begins with ``.`` or ``,``."""
    candidate = ("0" + text).strip(JS_ASCII_WHITESPACE)
    if re.fullmatch(r"0\.[0-9]*(?:[eE][+-]?[0-9]+)?", candidate) is None:
        return None
    return float(candidate)


def generalized_time_iso(text: str) -> str | None:
    """A ``GeneralizedTime`` as asn1js dates it, then ``toISOString``; ``None`` for a
    date out of range.

    :raises UnreadableToken: where asn1js refuses the string.
    """
    wrong = UnreadableToken("Wrong input string for conversion")
    is_utc = False
    hour_diff = minute_diff = 0
    if text.endswith("Z"):
        time_string = text[:-1]
        is_utc = True
    else:
        # `new Number(last character)`: a digit or white space reads as a number.
        if text == "" or not (text[-1] in "0123456789" or text[-1] in JS_ASCII_WHITESPACE):
            raise wrong
        time_string = text
    if is_utc:
        if "+" in time_string or "-" in time_string:
            raise wrong
    else:
        multiplier = 1
        position = time_string.find("+")
        if position == -1:
            position = time_string.find("-")
            multiplier = -1
        if position != -1:
            difference = time_string[position + 1 :]
            time_string = time_string[:position]
            if len(difference) not in (2, 4):
                raise wrong
            n = _js_parse_int(difference[0:2])
            if n is None:
                raise wrong
            hour_diff = multiplier * n
            if len(difference) == 4:
                n = _js_parse_int(difference[2:4])
                if n is None:
                    raise wrong
                minute_diff = multiplier * n

    minute = second = millisecond = hour = 0
    fraction_point = time_string.find(".")
    if fraction_point == -1:
        fraction_point = time_string.find(",")
    fraction = 0.0
    if fraction_point != -1:
        parsed = _js_number_fraction(time_string[fraction_point:])
        if parsed is None:
            raise wrong
        fraction = parsed
        date_time_string = time_string[:fraction_point]
    else:
        date_time_string = time_string

    length = len(date_time_string)
    if length == 8:
        groups = 3
        if fraction_point != -1:
            raise wrong
    elif length == 10:
        groups = 4
        if fraction_point != -1:
            result = 60 * fraction
            minute = math.floor(result)
            result = 60 * (result - minute)
            second = math.floor(result)
            result = 1000 * (result - second)
            millisecond = math.floor(result)
    elif length == 12:
        groups = 5
        if fraction_point != -1:
            result = 60 * fraction
            second = math.floor(result)
            result = 1000 * (result - second)
            millisecond = math.floor(result)
    elif length == 14:
        groups = 6
        if fraction_point != -1:
            millisecond = math.floor(1000 * fraction)
    else:
        raise wrong
    if re.fullmatch(r"[0-9]+", date_time_string) is None:
        raise wrong
    widths = (4, 2, 2, 2, 2, 2)[:groups]
    parts: list[int] = []
    at = 0
    for w in widths:
        parts.append(int(date_time_string[at : at + w]))
        at += w
    year, month, day = parts[0], parts[1], parts[2]
    if groups >= 4:
        hour = parts[3] + hour_diff
    if groups >= 5:
        minute = parts[4] + minute_diff
    if groups >= 6:
        second = parts[5]

    fields: tuple[float, ...] = (year, month - 1, day, hour, minute, second, millisecond)
    if not is_utc:
        # asn1js reads a zoned time through a local-time Date and keeps its UTC
        # fields, the month counted from 0 and the day as the weekday, which it
        # then reads back as a month counted from 1 and a day of the month. The
        # TypeScript SDK does this in the host's zone; this is the answer a host
        # on UTC gives.
        local = date_utc(year, month, day, hour, minute, second, millisecond)
        if local != local:
            fields = (math.nan,) * 7
        else:
            days, rem = divmod(int(local), 86_400_000)
            y, m, _ = civil_from_days(days)
            h, rem = divmod(rem, 3_600_000)
            mi, rem = divmod(rem, 60_000)
            s, ms = divmod(rem, 1000)
            fields = (y, m - 2, (days + 4) % 7, h, mi, s, ms)
    stamp = date_utc(*fields)
    if stamp != stamp:
        return None
    return iso_from_millis(int(stamp))


def pkijs_only_regions(token: str) -> list[tuple[int, int]]:
    """The byte ranges of a readable token's certificates and signer infos: where
    pkijs checks more than this module does (see the module docstring)."""
    der = node_base64_decode(token)
    response = _children(_parse(der))
    signed = _children(_children(response[1])[1])[0]
    return [(e.offset, e.end) for e in _children(signed)[3:]]
