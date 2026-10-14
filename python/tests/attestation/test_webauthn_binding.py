"""The record-binding half of the WebAuthn artifact, Python side.

Python is a relying-party server: it cannot run a ceremony and holds
no credential store, so it can never report a WebAuthn *signature* as verified.
It can always report whether the assertion is even ABOUT the record carrying
it, because the challenge is a pure function of the canonical digest. That is
the check these tests pin, and it is what stops a replayed assertion from being
indistinguishable from an unattested record.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from tzun_sdk._generated.models import WebauthnAssertion
from tzun_sdk.attestation import assertion_binds_digest, webauthn_challenge_for_digest

DIGEST_A = hashlib.sha256(b"loan-application-4471-APPROVED").hexdigest()
DIGEST_B = hashlib.sha256(b"loan-application-9902-DENIED").hexdigest()


def client_data(challenge: str, *, ceremony: str = "webauthn.get") -> str:
    return base64.b64encode(
        json.dumps(
            {"type": ceremony, "challenge": challenge, "origin": "https://app.example"}
        ).encode()
    ).decode()


def assertion_for(challenge: str, **kwargs: object) -> WebauthnAssertion:
    return WebauthnAssertion(
        signature="sig",
        credentialKeyId="cred-jane",
        algorithm="ES256",
        authenticatorData=base64.b64encode(b"\x01" * 37).decode(),
        clientDataJSON=client_data(challenge, **kwargs),  # type: ignore[arg-type]
    )


def test_an_assertion_bound_to_this_record_binds() -> None:
    assert assertion_binds_digest(assertion_for(webauthn_challenge_for_digest(DIGEST_A)), DIGEST_A)


def test_the_same_assertion_does_not_bind_another_record() -> None:
    """The attack in one line: a genuine assertion stapled onto record B."""
    assertion = assertion_for(webauthn_challenge_for_digest(DIGEST_A))
    assert not assertion_binds_digest(assertion, DIGEST_B)


def test_a_login_nonce_binds_nothing() -> None:
    """Every pre-0.3.16 assertion. Genuine signature, unrelated challenge."""
    assert not assertion_binds_digest(assertion_for("random-login-nonce-not-a-digest"), DIGEST_A)


def test_a_registration_ceremony_replayed_as_an_assertion_does_not_bind() -> None:
    assertion = assertion_for(
        webauthn_challenge_for_digest(DIGEST_A), ceremony="webauthn.create"
    )
    assert not assertion_binds_digest(assertion, DIGEST_A)


def test_an_assertion_with_no_client_data_binds_nothing() -> None:
    """No signed statement of what was signed, so nothing is bound."""
    bare = WebauthnAssertion(signature="x", credentialKeyId="cred-jane", algorithm="ES256")
    assert not assertion_binds_digest(bare, DIGEST_A)


@pytest.mark.parametrize(
    "raw", ["not-base64-!!", base64.b64encode(b"this is not json").decode()]
)
def test_malformed_client_data_binds_nothing_rather_than_raising(raw: str) -> None:
    assert not assertion_binds_digest({"clientDataJSON": raw}, DIGEST_A)


def test_padded_base64_challenge_still_matches() -> None:
    """A challenge that made a round trip through a padded encoder keeps its '='."""
    derived = webauthn_challenge_for_digest(DIGEST_A)
    padded = derived + "=" * (-len(derived) % 4)
    assert padded != derived
    assert assertion_binds_digest(assertion_for(padded), DIGEST_A)


def test_mappings_are_accepted_as_well_as_models() -> None:
    """Envelopes arrive as raw JSON often enough that both shapes must work."""
    challenge = webauthn_challenge_for_digest(DIGEST_A)
    assert assertion_binds_digest({"clientDataJSON": client_data(challenge)}, DIGEST_A)
    assert not assertion_binds_digest({"clientDataJSON": client_data("elsewhere")}, DIGEST_A)
    assert not assertion_binds_digest(None, DIGEST_A)


@pytest.mark.parametrize(
    "origin", ["https://panel.example", "https://panel1.example", "https://panel12.example"]
)
def test_unpadded_base64url_client_data_binds_as_a_browser_returns_it(origin: str) -> None:
    """A browser hands ``clientDataJSON`` back as unpadded base64url.

    Three lengths in four leave a string ``base64.b64decode`` refuses for its
    padding, which read every such assertion as binding nothing while the
    TypeScript verifier, whose decoder accepts it, read it as bound.
    """
    challenge = webauthn_challenge_for_digest(DIGEST_A)
    raw = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": origin}).encode()
    unpadded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert assertion_binds_digest({"clientDataJSON": unpadded}, DIGEST_A)
