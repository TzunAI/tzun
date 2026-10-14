"""Cross-SDK parity for the WebAuthn decision-binding challenge.

The challenge is what makes a WebAuthn assertion evidence about ONE decision
rather than proof that a key once signed something. It is derived — not
random — as ``base64url(SHA-256("tzun-decision-v1" || canonicalDigest))``, and
the derivation is a wire contract between the two SDKs: TypeScript drives the
ceremony (``Tzun.prepareAssertionChallenge`` →
``TzunWebAuthn.startAuthentication(id, {digest})``), Python is a relying-party
server that verifies at rest, and a one-byte divergence would make
every TS-signed assertion fail Python verification in a way that reads exactly
like tampering.

This suite is the pin. Python's verifier deliberately takes the expected
challenge from its caller rather than deriving it, "to avoid a TS↔Python
divergence" — which is only safe once something holds the two derivations
together.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from tzun_sdk.attestation import webauthn_challenge_for_digest

# Real-shaped 64-hex digests plus the edge cases a derivation can get wrong.
DIGESTS = [
    "a" * 64,
    "b" * 64,
    "0" * 64,
    "f" * 64,
    hashlib.sha256(b"loan-application-4471-APPROVED").hexdigest(),
    hashlib.sha256(b"loan-application-9902-DENIED").hexdigest(),
    # Not a digest shape at all: the derivation must still be total and
    # deterministic, because a caller with a different id scheme gets the same
    # guarantee out of it.
    "sha256:deadbeef",
]


def test_python_derivation_is_the_documented_formula() -> None:
    """Pinned independently of the TS side, so a joint drift cannot hide."""
    for digest in DIGESTS:
        raw = hashlib.sha256(("tzun-decision-v1" + digest).encode("utf-8")).digest()
        expected = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        assert webauthn_challenge_for_digest(digest) == expected


def test_challenge_is_unpadded_base64url() -> None:
    """It goes into ``clientDataJSON`` verbatim, where '+' and '/' are wrong."""
    for digest in DIGESTS:
        challenge = webauthn_challenge_for_digest(digest)
        assert "=" not in challenge
        assert "+" not in challenge and "/" not in challenge
        # 32 bytes of SHA-256 → 43 base64url characters once padding is dropped.
        assert len(challenge) == 43


def test_challenge_is_digest_dependent() -> None:
    """A constant would bind every record to the same ceremony, so one assertion
    would read as evidence about every decision."""
    challenges = {webauthn_challenge_for_digest(d) for d in DIGESTS}
    assert len(challenges) == len(DIGESTS)


def test_empty_digest_is_refused_not_silently_bound() -> None:
    with pytest.raises(ValueError, match="canonicalDigest"):
        webauthn_challenge_for_digest("")


def test_ts_and_python_derive_the_same_challenge(ts_invoke) -> None:  # type: ignore[no-untyped-def]
    """Record §9.4: byte-identical across languages, for every digest above."""
    ts = ts_invoke({"action": "webauthn-challenge", "digests": DIGESTS})["challenges"]
    py = [webauthn_challenge_for_digest(d) for d in DIGESTS]

    assert ts == py, (
        "WebAuthn challenge derivation diverged between the SDKs:\n"
        + "\n".join(
            f"  {d}\n    TS: {t}\n    Py: {p}" for d, t, p in zip(DIGESTS, ts, py) if t != p
        )
    )


def test_a_ts_derived_challenge_verifies_through_the_python_backend_expectation(
    ts_invoke,
) -> None:  # type: ignore[no-untyped-def]
    """The bytes Python must hand py_webauthn round-trip from the TS string.

    ``verify_assertion`` takes ``expected_challenge`` as *bytes*, and
    ``clientDataJSON.challenge`` is the unpadded base64url *string*. Getting
    that conversion wrong is the most likely way for two correct derivations to
    still fail to interoperate, so it is pinned here rather than left to a
    docstring.
    """
    digest = hashlib.sha256(b"a decision someone actually made").hexdigest()
    ts_challenge = ts_invoke({"action": "webauthn-challenge", "digests": [digest]})["challenges"][0]

    expected_bytes = base64.urlsafe_b64decode(ts_challenge + "==")
    assert expected_bytes == hashlib.sha256(("tzun-decision-v1" + digest).encode("utf-8")).digest()
    assert base64.urlsafe_b64encode(expected_bytes).decode().rstrip("=") == ts_challenge
