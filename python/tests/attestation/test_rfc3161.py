# python/tests/attestation/test_rfc3161.py — the RFC 3161 timestamp backend.
from __future__ import annotations

import base64
import pathlib

import pytest

from tests.attestation.mock_tsa import build_timestamp_response, mock_tsa_transport
from tzun_sdk.attestation.rfc3161 import RFC3161Backend, build_timestamp_query
from tzun_sdk.errors import TsaUnavailableError, TzunError

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
# Golden fixture: DER bytes produced by TS buildTimestampQuery('ab' * 32)
DIGEST = "ab" * 32


def test_der_request_matches_ts_builder_bytes():
    """Python build_timestamp_query byte-matches the TS golden fixture."""
    golden = bytes.fromhex((FIXTURES / "tsq_golden.hex").read_text().strip())
    assert build_timestamp_query(DIGEST) == golden


def test_digest_format_rejected():
    """Invalid digest raises TzunError."""
    with pytest.raises(TzunError, match="Invalid digest"):
        build_timestamp_query("nope")


def _backend(transport):
    return RFC3161Backend(transport=transport)


def _rejected_resp() -> bytes:
    # status 2 = rejection
    return bytes([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02])


async def test_success_stores_base64_token(envelope_fixture):
    """A real granted response stores the base64-encoded token.

    The response is a TimeStampResp whose TSTInfo imprint and nonce match the
    request, which is what the client requires before it stores a token.
    """
    seen: dict[str, bytes] = {}

    async def transport(url, body, timeout):
        seen["query"] = body
        from tests.attestation.mock_tsa import parse_timestamp_query

        digest, nonce = parse_timestamp_query(body)
        return 200, build_timestamp_response(digest, nonce)

    blob = await _backend(transport).attest(envelope_fixture)
    assert blob is not None
    assert base64.b64decode(blob.rfc3161Token)[:1] == b"\x30"
    assert blob.rfc3161Metadata is not None
    assert blob.rfc3161Metadata.genTime == "20260102030405Z"
    assert blob.rfc3161Metadata.status == "granted"
    # A nonce really was sent — without one there is nothing to compare. Its
    # DER INTEGER content octets are minimal: leading 0x00 bytes are dropped
    # and one is put back only when the top bit is set, so eight random bytes
    # encode as anywhere from one to nine octets — seven whenever the first
    # byte drew 0x00 and the second is below 0x80, one draw in 512. So the
    # bound is 1 to 9 octets, not 8 or more; the test below pins the
    # seven-octet case.
    from tests.attestation.mock_tsa import parse_timestamp_query

    _, sent_nonce = parse_timestamp_query(seen["query"])
    assert sent_nonce is not None
    assert 1 <= len(sent_nonce) <= 9
    # Minimal DER: no redundant leading zero octet.
    assert len(sent_nonce) == 1 or sent_nonce[0] != 0x00 or sent_nonce[1] & 0x80


async def test_nonce_with_a_zero_top_byte_is_sent_minimal_and_matched(
    envelope_fixture, monkeypatch
):
    """One 64-bit nonce in 256 starts with 0x00. DER INTEGER content octets are
    minimal, so the request carries seven octets, the TSA echoes seven, and the
    comparison has to agree on the shorter encoding. A fixed nonce pins that
    draw.
    """
    import secrets

    from tests.attestation.mock_tsa import parse_timestamp_query

    forced = bytes.fromhex("0025a05a8ac1fe0a")
    monkeypatch.setattr(secrets, "token_bytes", lambda n: forced[:n])
    seen: dict[str, bytes] = {}

    async def transport(url, body, timeout):
        seen["query"] = body
        digest, nonce = parse_timestamp_query(body)
        return 200, build_timestamp_response(digest, nonce)

    blob = await _backend(transport).attest(envelope_fixture)
    assert blob is not None
    assert blob.rfc3161Metadata is not None
    assert blob.rfc3161Metadata.status == "granted"
    _, sent_nonce = parse_timestamp_query(seen["query"])
    # Seven content octets: DER drops the leading zero, and nothing puts it back.
    assert sent_nonce == forced[1:]


async def test_non_granted_status_fails_attest(envelope_fixture):
    """Rejection PKIStatus raises TsaUnavailableError."""
    async def transport(url, body, timeout):
        return 200, _rejected_resp()

    with pytest.raises(TsaUnavailableError):
        await _backend(transport).attest(envelope_fixture)


# ---------------------------------------------------------------------------
# Fail closed on an HTTP 200 that is not a timestamp
#
# Every downstream timestamp decision is a presence check on rfc3161Token, so
# a stored non-token would satisfy `require: ["timestamp"]` and produce an
# envelope asserting a trusted timestamp it does not have. The client raises
# instead of storing such a body, as the TS client does, so the two SDKs agree
# on this boundary.
# ---------------------------------------------------------------------------


async def test_unparseable_response_is_rejected_not_stored(envelope_fixture):
    """A garbage HTTP-200 body raises instead of being stored as the token."""
    async def transport(url, body, timeout):
        return 200, b"\xff\xfegarbage"

    with pytest.raises(TsaUnavailableError, match="not a parseable"):
        await _backend(transport).attest(envelope_fixture)


async def test_html_error_page_is_rejected(envelope_fixture):
    """The production shape: a captive portal or CDN answering 200 with HTML."""
    async def transport(url, body, timeout):
        return 200, b"<html><head><title>503</title></head><body>maintenance</body></html>"

    with pytest.raises(TsaUnavailableError):
        await _backend(transport).attest(envelope_fixture)


async def test_token_without_a_timestamp_token_is_rejected(envelope_fixture):
    """A well-formed PKIStatusInfo with no timeStampToken is not a timestamp."""
    async def transport(url, body, timeout):
        return 200, bytes([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00])

    with pytest.raises(TsaUnavailableError, match="TSTInfo"):
        await _backend(transport).attest(envelope_fixture)


async def test_token_for_another_digest_is_rejected(envelope_fixture):
    """A structurally perfect token minted for somebody else's digest."""
    transport = mock_tsa_transport(override_digest="cd" * 32)

    with pytest.raises(TsaUnavailableError, match="imprint does not match"):
        await _backend(transport).attest(envelope_fixture)


async def test_token_without_the_nonce_is_rejected(envelope_fixture):
    """RFC 3161 §2.4.2 makes echoing the nonce mandatory; a cache would not."""
    transport = mock_tsa_transport(override_nonce=None)

    with pytest.raises(TsaUnavailableError, match="omitted the nonce"):
        await _backend(transport).attest(envelope_fixture)


async def test_token_with_a_different_nonce_is_rejected(envelope_fixture):
    """A replayed response carries somebody else's nonce."""
    transport = mock_tsa_transport(override_nonce=b"\xde\xad\xbe\xef\xde\xad\xbe\xef")

    with pytest.raises(TsaUnavailableError, match="nonce does not match"):
        await _backend(transport).attest(envelope_fixture)


async def test_a_genuine_token_still_passes(envelope_fixture):
    """Negative control: the guard must not reject a well-formed response."""
    blob = await _backend(mock_tsa_transport()).attest(envelope_fixture)
    assert blob is not None
    assert blob.rfc3161Token is not None
    assert blob.rfc3161Metadata is not None


def test_query_without_a_nonce_is_byte_identical_to_the_golden_fixture():
    """The nonce is OPTIONAL — omitting it must not move the wire format."""
    golden = bytes.fromhex((FIXTURES / "tsq_golden.hex").read_text().strip())
    assert build_timestamp_query(DIGEST) == golden
    assert build_timestamp_query(DIGEST, None) == golden
    assert build_timestamp_query(DIGEST, b"\x01\x02\x03\x04\x05\x06\x07\x08") != golden


async def test_http_error_raises_tzun_error(envelope_fixture):
    """Non-200 HTTP response raises TsaUnavailableError."""
    async def transport(url, body, timeout):
        return 500, b"Internal Server Error"

    with pytest.raises(TsaUnavailableError):
        await _backend(transport).attest(envelope_fixture)


@pytest.mark.skipif(
    not __import__("os").environ.get("RUN_INTEGRATION_TESTS"),
    reason="integration test — set RUN_INTEGRATION_TESTS=true to run",
)
async def test_live_freetsa_grants(envelope_fixture):
    """Live TSA call — only runs when RUN_INTEGRATION_TESTS=true."""
    blob = await RFC3161Backend().attest(envelope_fixture)
    assert blob is not None
    assert blob.rfc3161Token is not None
    assert blob.rfc3161Metadata is None or blob.rfc3161Metadata.status in (
        "granted",
        "grantedWithMods",
    )
