"""Mock RFC 3161 Timestamp Authority for the Python tests.

Mirror of the TypeScript `tests/ts/helpers/mock-tsa.ts`. `_do_attest` fails
closed: it parses the TimeStampResp, checks PKIStatus, and requires the returned
messageImprint and nonce to match what was requested. A body that is not a
well-formed TimeStampResp is refused, so the mock has to behave like an actual
TSA.

The token is NOT cryptographically signed (no signerInfos, no certificates).
The client keeps a token whose structure, status, imprint and nonce hold, and
reports one that does not meet tzun-anchor/1 §10.5 as
``attestation_timestamp_nonconformant`` rather than refusing it, so an unsigned
token exercises the client's contract without shipping a private key in the
repo; the client reports it at step 1 (no SignerInfo).
"""

from __future__ import annotations

from typing import Literal

from tzun_sdk.attestation.rfc3161 import _to_positive_der_integer, _wrap_der

SHA256_OID_DER = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
ID_SIGNED_DATA = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
ID_CT_TST_INFO = bytes([0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04])
# 1.3.6.1.4.1.13762.3 — FreeTSA's policy OID, used purely as a filler value.
POLICY_OID = bytes([0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xEB, 0x42, 0x03])


def _read_tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """The ``(tag, content_start, content_end)`` of the DER element at ``pos``."""
    tag = buf[pos]
    length = buf[pos + 1]
    start = pos + 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[start : start + n], "big")
        start += n
    return tag, start, start + length


def _children(buf: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    """The ``(tag, content_start, content_end)`` of each element from ``start`` to ``end``."""
    out: list[tuple[int, int, int]] = []
    pos = start
    while pos < end:
        tag, cstart, cend = _read_tlv(buf, pos)
        out.append((tag, cstart, cend))
        pos = cend
    return out


def parse_timestamp_query(der: bytes) -> tuple[str, bytes | None]:
    """Read ``(digest_hex, nonce_bytes | None)`` back out of a DER TimeStampReq."""
    _, start, end = _read_tlv(der, 0)
    kids = _children(der, start, end)
    # [0] version INTEGER, [1] messageImprint SEQUENCE, [2] nonce INTEGER?, ...
    _, mi_start, mi_end = kids[1]
    mi = _children(der, mi_start, mi_end)
    digest = der[mi[1][1] : mi[1][2]].hex()
    nonce = None
    for tag, cs, ce in kids[2:]:
        if tag == 0x02:
            nonce = der[cs:ce]
            break
    return digest, nonce


def build_timestamp_response(
    digest: str,
    nonce: bytes | None,
    *,
    status: int = 0,
    gen_time: str = "20260102030405Z",
    include_token: bool = True,
    ber_tst_info: bool = False,
    ber_nested_segment: Literal["octets", "integer"] | None = None,
    indefinite_length: bool = False,
    bare_digest_algorithm: bool = False,
) -> bytes:
    """Build a DER TimeStampResp carrying the given imprint / nonce.

    ``ber_tst_info`` carries the TSTInfo in a constructed (BER) OCTET STRING of two
    segments; ``ber_nested_segment`` puts a constructed segment between them, holding
    an OCTET STRING (``"octets"``) or an INTEGER (``"integer"``); ``indefinite_length``
    writes the TimeStampResp in the BER indefinite-length form; ``bare_digest_algorithm``
    puts a bare OBJECT IDENTIFIER in SignedData.digestAlgorithms where an
    AlgorithmIdentifier belongs.
    """
    tst_values = [
        bytes([0x02, 0x01, 0x01]),  # version
        POLICY_OID,
        _wrap_der(  # messageImprint
            0x30,
            _wrap_der(0x30, SHA256_OID_DER + bytes([0x05, 0x00]))
            + _wrap_der(0x04, bytes.fromhex(digest)),
        ),
        bytes([0x02, 0x01, 0x2A]),  # serialNumber
        _wrap_der(0x18, gen_time.encode("ascii")),  # genTime
    ]
    if nonce is not None:
        tst_values.append(_wrap_der(0x02, _to_positive_der_integer(nonce)))
    tst_info = _wrap_der(0x30, b"".join(tst_values))

    if ber_tst_info or ber_nested_segment is not None:
        half = len(tst_info) // 2
        nested = {
            None: b"",
            "octets": _wrap_der(0x24, _wrap_der(0x04, b"\x05\x00")),
            "integer": _wrap_der(0x24, bytes([0x02, 0x01, 0x00])),
        }[ber_nested_segment]
        e_content = _wrap_der(
            0x24, _wrap_der(0x04, tst_info[:half]) + nested + _wrap_der(0x04, tst_info[half:])
        )
    else:
        e_content = _wrap_der(0x04, tst_info)
    encap = _wrap_der(0x30, ID_CT_TST_INFO + _wrap_der(0xA0, e_content))
    digest_algorithm = (
        SHA256_OID_DER if bare_digest_algorithm else _wrap_der(0x30, SHA256_OID_DER + bytes([0x05, 0x00]))
    )
    signed_data = _wrap_der(
        0x30,
        bytes([0x02, 0x01, 0x03])  # version
        + _wrap_der(0x31, digest_algorithm)
        + encap
        + _wrap_der(0x31, b""),  # signerInfos: empty SET
    )
    content_info = _wrap_der(0x30, ID_SIGNED_DATA + _wrap_der(0xA0, signed_data))

    status_info = _wrap_der(0x30, bytes([0x02, 0x01, status]))
    body = status_info + (content_info if include_token else b"")
    if indefinite_length:
        return b"\x30\x80" + body + b"\x00\x00"
    return _wrap_der(0x30, body)


def mock_tsa_transport(**options):
    """An injectable transport that echoes the request's digest and nonce."""

    async def transport(url, body, timeout):
        digest, nonce = parse_timestamp_query(body)
        if options.get("override_digest"):
            digest = options["override_digest"]
        if "override_nonce" in options:
            nonce = options["override_nonce"]
        return 200, build_timestamp_response(
            digest,
            nonce,
            status=options.get("status", 0),
            gen_time=options.get("gen_time", "20260102030405Z"),
            include_token=options.get("include_token", True),
            ber_tst_info=options.get("ber_tst_info", False),
            ber_nested_segment=options.get("ber_nested_segment"),
            indefinite_length=options.get("indefinite_length", False),
            bare_digest_algorithm=options.get("bare_digest_algorithm", False),
        )

    return transport
