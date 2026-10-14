"""Real WebAuthn assertions for tests: Ed25519 keys minted with ``cryptography``, signed as an authenticator signs.

:class:`Authenticator` holds one credential per user and signs a challenge
(base64url, as the SDK's challenges are); :class:`CredentialStore` is the
relying party's store a :class:`~tzun_sdk.mandates_api.WebAuthnAssertionVerifier`
reads; :class:`FakeVerifier` stands in for one, answering the user the
credential belongs to after checking the challenge the client data present.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

RP_ID = "tzun.example"
ORIGIN = "https://tzun.example"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def cose_ed25519(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """COSE_Key of an Ed25519 key: {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x}."""
    x = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b"\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20" + x


@dataclass
class Credential:
    user_id: str
    key_id: str
    key: ed25519.Ed25519PrivateKey
    sign_count: int = 0


@dataclass
class Authenticator:
    """One credential per user; ``sign`` makes the assertion that user's authenticator makes."""

    credentials: dict[str, Credential] = field(default_factory=dict)

    def enrol(self, user_id: str) -> Credential:
        key = ed25519.Ed25519PrivateKey.generate()
        key_id = b64u(hashlib.sha256(user_id.encode()).digest()[:16])
        credential = Credential(user_id=user_id, key_id=key_id, key=key)
        self.credentials[key_id] = credential
        return credential

    def sign(self, user_id: str, challenge: str, *, uv: bool = True) -> dict[str, Any]:
        credential = next(c for c in self.credentials.values() if c.user_id == user_id)
        credential.sign_count += 1
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": challenge, "origin": ORIGIN, "crossOrigin": False},
            separators=(",", ":"),
        ).encode()
        flags = 0x01 | (0x04 if uv else 0)
        auth = hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + credential.sign_count.to_bytes(4, "big")
        signature = credential.key.sign(auth + hashlib.sha256(client_data).digest())
        return {
            "signature": b64u(signature),
            "credentialKeyId": credential.key_id,
            "algorithm": "Ed25519",
            "authenticatorData": b64u(auth),
            "clientDataJSON": b64u(client_data),
        }

    async def lookup(self, credential_id: str) -> dict[str, Any] | None:
        """The relying party's credential store, as ``WebAuthnAssertionVerifier`` reads it."""
        credential = self.credentials.get(credential_id)
        if credential is None:
            return None
        return {
            "userId": credential.user_id,
            "publicKey": cose_ed25519(credential.key.public_key()),
            "signCount": credential.sign_count - 1,
        }


class FakeVerifier:
    """An ``AssertionVerifier`` that checks only the presented challenge and answers the credential's user."""

    def __init__(self, authenticator: Authenticator) -> None:
        self._authenticator = authenticator
        self.challenges: list[str] = []

    async def user_id_of(self, credential_key_id: str) -> str | None:
        credential = self._authenticator.credentials.get(credential_key_id)
        return credential.user_id if credential else None

    async def verify(self, assertion: dict[str, Any], *, expected_challenge: str) -> str:
        self.challenges.append(expected_challenge)
        client_data = json.loads(_unb64u(assertion["clientDataJSON"]))
        if client_data.get("challenge") != expected_challenge:
            raise ValueError("the client data present another challenge")
        user_id = await self.user_id_of(assertion["credentialKeyId"])
        if user_id is None:
            raise ValueError("unknown credential")
        return user_id
