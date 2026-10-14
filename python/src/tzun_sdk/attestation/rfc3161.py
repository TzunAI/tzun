"""RFC 3161 attestation backend.

Real implementation: builds a DER TimeStampReq, POSTs to the TSA,
parses PKIStatus from the response (no RFC 3161 library; the
rfc3161-client extra is not used), and checks each token it keeps
against tzun-anchor/1 §10.5 steps 1 to 3 (:func:`timestamp_conformance`).
A token that does not meet them is kept and logged as
``event=attestation_timestamp_nonconformant``.

Circuit-breaker hysteresis (as the TS client's, 3 failures and 60s):
  CLOSED → (3 consecutive failures) → OPEN
  OPEN  → (60s timeout)              → HALF_OPEN
  HALF_OPEN → (1 success)            → CLOSED
  HALF_OPEN → (1 failure)            → OPEN
Each transition emits a structured INFO log:
  event=rfc3161_circuit_state_change from=<x> to=<y> reason=<z>
"""

from __future__ import annotations

import base64
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from tzun_sdk.attestation._rfc3161_steps import verify_rfc3161_steps
from tzun_sdk.attestation._rfc3161_token import UnreadableToken, read_pki_status, read_tst_info
from tzun_sdk.errors import TsaUnavailableError, TzunError
from tzun_sdk.models import AttestationArtifacts, EvidenceEnvelope, Rfc3161Metadata

LOG = logging.getLogger(__name__)

DEFAULT_TSA_URL = "https://freetsa.org/tsr"
# The TS client's breaker: 3 failures, 60s, then a single probe
# (src/attestation/rfc3161.ts). The TS values are authoritative.
FAILURE_THRESHOLD = 3
HALF_OPEN_AFTER_SECONDS = 60.0

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"

# SHA-256 OID DER encoding: 2.16.840.1.101.3.4.2.1
SHA256_OID_DER = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"

PKI_STATUS = {0: "granted", 1: "grantedWithMods", 2: "rejection", 3: "waiting"}


def _wrap_der(tag: int, content: bytes) -> bytes:
    """Wrap content in a DER TLV (Tag-Length-Value) structure."""
    n = len(content)
    if n < 0x80:
        lb = bytes([n])
    elif n < 0x100:
        lb = bytes([0x81, n])
    elif n < 0x10000:
        lb = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    else:
        raise TzunError(f"DER content too long: {n} bytes")
    return bytes([tag]) + lb + content


def _to_positive_der_integer(raw: bytes) -> bytes:
    """Normalise raw bytes into DER INTEGER content octets.

    Port of TS ``toPositiveInteger``. DER INTEGERs are signed two's complement,
    so a random 64-bit nonce whose top bit is set has to be prefixed with 0x00
    or it encodes as a negative number and the TSA echoes back something that
    does not compare equal.
    """
    i = 0
    while i < len(raw) - 1 and raw[i] == 0x00:
        i += 1
    trimmed = raw[i:]
    if trimmed and (trimmed[0] & 0x80):
        return b"\x00" + trimmed
    return bytes(trimmed)


def build_timestamp_query(digest: str, nonce: bytes | None = None) -> bytes:
    """Build a minimal DER-encoded TimeStampReq (RFC 3161 §2.4.1).

    Byte-for-byte port of TS buildTimestampQuery (rfc3161.ts). The fixture
    digest ``'ab' * 32`` must produce the golden bytes in
    ``python/tests/attestation/fixtures/tsq_golden.hex``.

    WIRE-FORMAT NOTE: with ``nonce=None`` the output is byte-for-byte what this
    function has always produced, so the golden fixture still matches on both
    sides. The nonce is an OPTIONAL field RFC 3161 places between
    messageImprint and certReq, emitted only when the caller supplies one.

    Structure::

        TimeStampReq ::= SEQUENCE {
            version        INTEGER { v1(1) },
            messageImprint MessageImprint,
            nonce          INTEGER OPTIONAL,
            certReq        BOOLEAN DEFAULT FALSE
        }
        MessageImprint ::= SEQUENCE {
            hashAlgorithm  AlgorithmIdentifier,
            hashedMessage  OCTET STRING
        }
    """
    if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise TzunError(
            f'Invalid digest: expected 64-character hex string, got "{digest[:20]}..."'
        )
    alg_id_null = bytes([0x05, 0x00])  # NULL
    alg_id_content = SHA256_OID_DER + alg_id_null
    alg_id_seq = _wrap_der(0x30, alg_id_content)  # AlgorithmIdentifier SEQUENCE

    hashed_message = _wrap_der(0x04, bytes.fromhex(digest))  # OCTET STRING
    message_imprint = _wrap_der(0x30, alg_id_seq + hashed_message)

    version = bytes([0x02, 0x01, 0x01])  # INTEGER v1(1)
    nonce_der = _wrap_der(0x02, _to_positive_der_integer(nonce)) if nonce else b""
    cert_req = bytes([0x01, 0x01, 0xFF])  # BOOLEAN TRUE

    return _wrap_der(0x30, version + message_imprint + nonce_der + cert_req)


class Rfc3161ParseError(TzunError):
    """The bytes a TSA returned are not a usable RFC 3161 TimeStampResp."""


def extract_tst_info(resp: bytes) -> dict[str, Any]:
    """The TSTInfo fields of a TimeStampResp, read as the TS client reads them.

    The TS client decides whether a response it fetched is a token it can check with
    ``parseTimestampResponse`` and ``extractTSTInfo`` (src/attestation/rfc3161-verify.ts):
    asn1js ``fromBER``, pkijs ``ContentInfo`` and ``SignedData``, then the TSTInfo through
    asn1js. :func:`tzun_sdk.attestation._rfc3161_token.read_tst_info` reads it as they do,
    BER included (indefinite lengths, a constructed OCTET STRING), so the two clients keep
    the same tokens and check the same fields. Whether the token is DER, and every other
    rule of tzun-anchor/1 §10.5, is :func:`timestamp_conformance`'s to say.

    Returns ``{"hashAlgorithm", "hashedMessage", "genTime", "nonce"}``:
    ``hashAlgorithm`` is ``"SHA-256"`` or the imprint algorithm's dotted OID,
    ``hashedMessage`` and ``nonce`` are hex (``nonce`` ``None`` when the TSTInfo has
    none), and ``genTime`` is the text of the TSTInfo's genTime. Raises
    :class:`Rfc3161ParseError` on a response the TS client does not read.
    """
    try:
        fields = read_tst_info(resp)
    except (UnreadableToken, IndexError, ValueError) as exc:
        raise Rfc3161ParseError(f"malformed TimeStampResp: {exc}") from exc
    algorithm = fields.hash_algorithm
    return {
        "hashAlgorithm": "SHA-256"
        if algorithm == _OID_SHA256
        else algorithm or "an element that is not an OBJECT IDENTIFIER",
        "hashedMessage": fields.hashed_message.hex(),
        "genTime": fields.gen_time,
        "nonce": None if fields.nonce is None else fields.nonce.hex(),
    }


def nonce_matches(actual: str | None, expected: str | None) -> bool:
    """Compare two DER INTEGER contents as numbers, ignoring leading zeros.

    Port of TS ``nonceMatches``. A TSA is free to re-encode the nonce it echoes
    (dropping or adding the leading 0x00 that keeps a high-bit-set value
    positive), so a raw hex comparison would reject genuine tokens.
    """
    if actual is None or expected is None:
        return False
    strip = lambda h: h.lower().lstrip("0") or "0"  # noqa: E731
    return strip(actual) == strip(expected)


@dataclass(frozen=True)
class TimestampConformance:
    """Whether a token meets tzun-anchor/1 §10.5 steps 1 to 3 over the digest it was
    requested for: the rules every verifier holds a record's token to (a DER TimeStampResp
    carrying its signer certificate, a SHA-256 imprint of the digest, the CMS signature, a
    signingCertificate(V2) naming the signer, and a critical extendedKeyUsage whose only
    purpose is timestamping). ``reason`` is the first step that does not hold, and
    ``error`` says why.

    The twin of the TypeScript ``TimestampConformance``, which :meth:`to_json` writes.
    """

    holds: bool
    reason: Literal["malformed", "imprint_mismatch", "verification_failed", "missing_dependency"] | None = None
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        """``{"holds": True}``, or ``{"holds": False, "reason": ..., "error": ...}``."""
        if self.holds:
            return {"holds": True}
        out: dict[str, Any] = {"holds": False, "reason": self.reason}
        if self.error is not None:
            out["error"] = self.error
        return out


def timestamp_conformance(token: str, digest: str) -> TimestampConformance:
    """Whether ``token`` (base64 of a TimeStampResp) meets tzun-anchor/1 §10.5 steps 1 to 3
    over ``digest``: the answer the TypeScript ``RFC3161Client`` gives as
    ``TimestampResult.conformance`` for the same token and digest. It does not raise."""
    steps = verify_rfc3161_steps(token, digest)
    if steps.token == "held":
        return TimestampConformance(holds=True)
    return TimestampConformance(holds=False, reason=steps.token, error=steps.error)


class RFC3161Backend:
    """RFC 3161 timestamping backend with circuit breaker."""

    def __init__(
        self,
        tsa_url: str = DEFAULT_TSA_URL,
        timeout: float = 10.0,
        transport: Any = None,
    ) -> None:
        self._tsa_url = tsa_url
        self._timeout = timeout
        self._state = CLOSED
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        # Injectable transport for testing; defaults to real httpx POST.
        self._transport = transport or self._httpx_post

    def _transition(self, new_state: str, reason: str) -> None:
        old_state = self._state
        if old_state == new_state:
            return
        self._state = new_state
        LOG.info(
            "event=rfc3161_circuit_state_change from=%s to=%s reason=%s",
            old_state,
            new_state,
            reason,
        )

    def _check_circuit(self) -> None:
        if self._state == OPEN:
            if (
                self._opened_at is not None
                and (time.monotonic() - self._opened_at) >= HALF_OPEN_AFTER_SECONDS
            ):
                self._transition(HALF_OPEN, "half_open_window_elapsed")
            else:
                raise TsaUnavailableError(
                    f"RFC 3161 circuit is OPEN (TSA {self._tsa_url!r} disabled)"
                )

    async def _httpx_post(
        self, url: str, body: bytes, timeout: float
    ) -> tuple[int, bytes]:
        """Real httpx transport — used in production and integration tests."""
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                url,
                content=body,
                headers={"Content-Type": "application/timestamp-query"},
            )
            return resp.status_code, resp.content

    async def attest(
        self, envelope: EvidenceEnvelope
    ) -> AttestationArtifacts | None:
        """Timestamp the envelope's canonical digest via RFC 3161."""
        self._check_circuit()
        try:
            blob, conformance = await self._do_attest(envelope)
        except TsaUnavailableError:
            # Already a TsaUnavailableError — count as failure and re-raise.
            self._consecutive_failures += 1
            if self._consecutive_failures >= FAILURE_THRESHOLD and self._state != OPEN:
                self._opened_at = time.monotonic()
                self._transition(OPEN, "failure_threshold_exceeded")
            elif self._state == HALF_OPEN:
                self._opened_at = time.monotonic()
                self._transition(OPEN, "half_open_test_failed")
            raise
        except Exception as exc:
            self._consecutive_failures += 1
            if self._consecutive_failures >= FAILURE_THRESHOLD and self._state != OPEN:
                self._opened_at = time.monotonic()
                self._transition(OPEN, "failure_threshold_exceeded")
            elif self._state == HALF_OPEN:
                self._opened_at = time.monotonic()
                self._transition(OPEN, "half_open_test_failed")
            raise TsaUnavailableError(
                f"RFC 3161 TSA {self._tsa_url!r} unavailable: {exc}"
            ) from exc
        # Success: close circuit if half-open; reset counter.
        if self._state == HALF_OPEN:
            self._transition(CLOSED, "half_open_test_succeeded")
        self._consecutive_failures = 0
        # A token the backend kept that every verifier will refuse: a private
        # authority that writes BER, omits signingCertificate(V2), or signs
        # without a critical timestamping-only extendedKeyUsage. The record keeps
        # it (the capture is not failed for it), and this says so at the first
        # capture, before a scan or an auditor finds every such record. The
        # event and its fields are the TypeScript SDK's.
        if not conformance.holds:
            fields: list[Any] = [
                envelope.integrity.canonicalDigest,
                self._tsa_url,
                conformance.reason,
            ]
            template = (
                "event=attestation_timestamp_nonconformant digest=%s authorityUrl=%s reason=%s"
            )
            if conformance.error is not None:
                template += " error=%s"
                fields.append(json.dumps(conformance.error))
            LOG.warning(template, *fields)
        return blob

    async def _do_attest(
        self, envelope: EvidenceEnvelope
    ) -> tuple[AttestationArtifacts, TimestampConformance]:
        """Build + send a TimeStampReq, then FAIL CLOSED on the response.

        Every downstream timestamp decision is a presence check on
        ``rfc3161Token``, so keeping whatever bytes came back on an HTTP 200
        would let an HTML maintenance page, a captive-portal login body, or a
        TimeStampResp minted for somebody else's digest pass as a timestamp. A
        token nobody can parse is not evidence of anything.

        Four checks, mirroring the TS client exactly:

        1. the body parses as a TimeStampResp, read as the TS client reads one
           (asn1js BER, :mod:`tzun_sdk.attestation._rfc3161_token`);
        2. PKIStatus is granted or grantedWithMods, and an unreadable status is
           a failure;
        3. TSTInfo is readable and its SHA-256 messageImprint equals the digest
           that was sent, so a replayed or substituted token cannot be kept as
           proof for this record;
        4. the TSA echoed the per-request nonce (RFC 3161 §2.4.2 makes that
           mandatory when the request carried one), so a cached or replayed
           response cannot pass.

        A token that passes them is kept. It is then checked against
        tzun-anchor/1 §10.5 steps 1 to 3 (:func:`timestamp_conformance`: DER,
        the CMS signature, the signer binding and a timestamping-only
        certificate), as the TS client checks it, and the answer is returned
        beside the artifacts for :meth:`attest` to report; it never refuses the
        token. No trust chain is checked here: that would pin one TSA's CA and
        break every other TSA.
        """
        digest = envelope.integrity.canonicalDigest
        nonce = secrets.token_bytes(8)
        query = build_timestamp_query(digest, nonce)
        status_code, resp = await self._transport(self._tsa_url, query, self._timeout)
        if status_code != 200:
            raise TsaUnavailableError(
                f"TSA request failed: HTTP {status_code}"
            )

        try:
            pki = read_pki_status(resp)
        except UnreadableToken as exc:
            raise TsaUnavailableError(
                f"TSA response is not a parseable RFC 3161 TimeStampResp: {exc}"
            ) from exc
        if pki is None:
            raise TsaUnavailableError(
                "TSA response is not a parseable RFC 3161 TimeStampResp "
                "(no readable PKIStatus)"
            )
        if PKI_STATUS.get(pki) not in ("granted", "grantedWithMods"):
            raise TsaUnavailableError(
                f"TSA returned non-success PKIStatus: {PKI_STATUS.get(pki, pki)}"
            )

        try:
            tst_info = extract_tst_info(resp)
        except Rfc3161ParseError as exc:
            raise TsaUnavailableError(
                f"TSA response does not contain a readable TSTInfo: {exc}"
            ) from exc

        algorithm = tst_info["hashAlgorithm"]
        if algorithm != "SHA-256":
            raise TsaUnavailableError(
                f"TSA timestamped with {algorithm}, expected SHA-256"
            )
        imprint = tst_info["hashedMessage"].lower()
        if imprint != digest.lower():
            raise TsaUnavailableError(
                "TSA imprint does not match the requested digest "
                f"(requested {digest.lower()}, token carries "
                f"{imprint})"
            )

        sent_nonce = _to_positive_der_integer(nonce).hex()
        if not nonce_matches(tst_info["nonce"], sent_nonce):
            raise TsaUnavailableError(
                "TSA response omitted the nonce that was sent; cannot prove the "
                "token is not a replay"
                if tst_info["nonce"] is None
                else "TSA response nonce does not match the nonce that was sent "
                "(replayed or cached token)"
            )

        # Metadata stays descriptive, but genTime comes from the parsed
        # TSTInfo, not a byte-scan for the first 0x18 anywhere in the DER.
        metadata = Rfc3161Metadata(
            genTime=tst_info["genTime"],
            tsaName=self._tsa_url,
            status=PKI_STATUS[pki],
        )
        token = base64.b64encode(resp).decode("ascii")
        artifacts = AttestationArtifacts(rfc3161Token=token, rfc3161Metadata=metadata)
        return artifacts, timestamp_conformance(token, digest)


__all__ = (
    "DEFAULT_TSA_URL",
    "RFC3161Backend",
    "Rfc3161ParseError",
    "TimestampConformance",
    "build_timestamp_query",
    "extract_tst_info",
    "nonce_matches",
    "timestamp_conformance",
)
