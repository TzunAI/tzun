"""WebAuthn at-rest verification tests.

``verify_assertion`` takes the relying-party expectations (challenge, origin,
rpId) from its caller, never from the blob it is verifying. If the blob could
supply them, any genuine assertion by the credential would verify against any
evidence record.

The fixtures here mint real ES256 assertions with ``cryptography`` so the
tests exercise py_webauthn's actual signature path rather than a stub.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from tzun_sdk.attestation import WebAuthnBackend
from tzun_sdk.errors import WebAuthnVerificationError

RP_ID = "tzun.example"
ORIGIN = "https://tzun.example"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _cose_es256(public_numbers: ec.EllipticCurvePublicNumbers) -> bytes:
    """COSE_Key encoding of an ES256 public key (what py_webauthn wants).

    Hand-encoded CBOR so the fixture does not lean on a transitive dep:
    a 5-pair map {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}.
    """
    return (
        b"\xa5"
        b"\x01\x02"
        b"\x03\x26"
        b"\x20\x01"
        b"\x21\x58\x20" + public_numbers.x.to_bytes(32, "big") + b"\x22\x58\x20"
        + public_numbers.y.to_bytes(32, "big")
    )


def _mint_assertion(
    key: ec.EllipticCurvePrivateKey,
    *,
    challenge: bytes,
    origin: str = ORIGIN,
    rp_id: str = RP_ID,
    sign_count: int = 7,
) -> dict[str, Any]:
    """Produce a genuine assertion this key really signed."""
    client_data = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": _b64u(challenge),
            "origin": origin,
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    authenticator_data = (
        hashlib.sha256(rp_id.encode()).digest()
        + bytes([0x01 | 0x04])  # UP | UV
        + sign_count.to_bytes(4, "big")
    )
    signature = key.sign(
        authenticator_data + hashlib.sha256(client_data).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    return {
        "id": _b64u(b"cred-id"),
        "rawId": _b64u(b"cred-id"),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64u(client_data),
            "authenticatorData": _b64u(authenticator_data),
            "signature": _b64u(signature),
            "userHandle": None,
        },
        "clientExtensionResults": {},
    }


@pytest.fixture
def credential() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    return key, _cose_es256(key.public_key().public_numbers())


def test_genuine_assertion_verifies_against_its_own_challenge(
    credential: tuple[ec.EllipticCurvePrivateKey, bytes],
) -> None:
    """Sanity floor: the happy path verifies and returns the
    VerifiedAuthentication object (the caller needs ``new_sign_count``)."""
    key, cose = credential
    challenge = hashlib.sha256(b"evidence-record-A").digest()
    result = WebAuthnBackend().verify_assertion(
        _mint_assertion(key, challenge=challenge),
        cose,
        expected_challenge=challenge,
        expected_origin=ORIGIN,
        expected_rp_id=RP_ID,
        current_sign_count=6,
    )
    assert result.new_sign_count == 7


def test_replayed_assertion_from_another_record_is_rejected(
    credential: tuple[ec.EllipticCurvePrivateKey, bytes],
) -> None:
    """The attack: a genuine assertion the reviewer made over record A is
    re-attached to record B. The caller supplies record B's challenge, so the
    assertion does not verify."""
    key, cose = credential
    assertion_for_a = _mint_assertion(
        key, challenge=hashlib.sha256(b"evidence-record-A").digest()
    )
    with pytest.raises(WebAuthnVerificationError):
        WebAuthnBackend().verify_assertion(
            assertion_for_a,
            cose,
            expected_challenge=hashlib.sha256(b"evidence-record-B").digest(),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            current_sign_count=6,
        )


def test_assertion_carrying_its_own_expectations_is_refused(
    credential: tuple[ec.EllipticCurvePrivateKey, bytes],
) -> None:
    """A blob that supplies the expectations it is to be checked against is
    refused, not honoured."""
    key, cose = credential
    challenge_a = hashlib.sha256(b"evidence-record-A").digest()
    smuggling_blob = _mint_assertion(key, challenge=challenge_a)
    smuggling_blob["expected_challenge"] = challenge_a
    smuggling_blob["expected_origin"] = ORIGIN
    smuggling_blob["expected_rp_id"] = RP_ID

    with pytest.raises(WebAuthnVerificationError, match="MUST come from the caller"):
        WebAuthnBackend().verify_assertion(
            smuggling_blob,
            cose,
            expected_challenge=hashlib.sha256(b"evidence-record-B").digest(),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            current_sign_count=6,
        )


def test_wrong_origin_and_rp_id_are_rejected(
    credential: tuple[ec.EllipticCurvePrivateKey, bytes],
) -> None:
    key, cose = credential
    challenge = hashlib.sha256(b"evidence-record-A").digest()
    backend = WebAuthnBackend()
    with pytest.raises(WebAuthnVerificationError):
        backend.verify_assertion(
            _mint_assertion(key, challenge=challenge, origin="https://evil.example"),
            cose,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            current_sign_count=6,
        )
    with pytest.raises(WebAuthnVerificationError):
        backend.verify_assertion(
            _mint_assertion(key, challenge=challenge, rp_id="evil.example"),
            cose,
            expected_challenge=challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            current_sign_count=6,
        )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"expected_challenge": b""}, "expected_challenge is required"),
        ({"expected_rp_id": ""}, "expected_rp_id is required"),
        ({"expected_origin": ""}, "expected_origin is required"),
    ],
)
def test_empty_expectations_are_refused_not_ignored(
    credential: tuple[ec.EllipticCurvePrivateKey, bytes],
    kwargs: dict[str, Any],
    match: str,
) -> None:
    """An empty challenge, rpId or origin raises: an empty expectation must be
    an error, never a skipped check."""
    key, cose = credential
    challenge = hashlib.sha256(b"evidence-record-A").digest()
    call = {
        "expected_challenge": challenge,
        "expected_origin": ORIGIN,
        "expected_rp_id": RP_ID,
        "current_sign_count": 6,
        **kwargs,
    }
    with pytest.raises(WebAuthnVerificationError, match=match):
        WebAuthnBackend().verify_assertion(
            _mint_assertion(key, challenge=challenge), cose, **call
        )


def test_signing_still_refuses() -> None:
    """Python is the relying party, not a signer."""
    from tzun_sdk.errors import TzunError

    with pytest.raises(TzunError, match="require a browser"):
        WebAuthnBackend().sign()
