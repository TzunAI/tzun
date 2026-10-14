"""Sigstore attestation backend.

**This backend is not implemented.** :meth:`SigstoreBackend.sign` and
:meth:`SigstoreBackend.verify` raise :class:`NotImplementedError`.

``verify()`` cannot give an honest answer without parsing a bundle, checking
its signature over ``canonical_bytes`` and consulting the transparency log, and
``sign()`` has nothing honest to return but a real signature. A verifier that
applied only the identity-policy filter would report any dict whose
``"identity"`` key happened to match (an attacker-authored one included) as
Sigstore-verified.

Nothing in the SDK calls either method: :meth:`attest` returns ``None`` so
capture stores no Sigstore artifact, the shared ``AttestationArtifacts`` wire
model has no Sigstore field, and ``Tzun.verify()`` reports
``attestationVerified=None``. The exposure would be an integrator reading the
public API and its docstring and trusting the answer.

Failing closed is the correct state until a real implementation exists:
``sigstore.verify.Verifier`` over a ``sigstore.models.Bundle`` with an identity
policy, and ``sigstore.sign.SigningContext`` with a call-time OIDC ``IdentityToken``
(never cached on the instance). A caller that hits
:class:`NotImplementedError` knows exactly where it stands; a caller that got
``True`` would not.
"""

from __future__ import annotations

import logging
from typing import Any

from tzun_sdk.models import AttestationArtifacts, EvidenceEnvelope

LOG = logging.getLogger(__name__)

_NOT_IMPLEMENTED = (
    "SigstoreBackend is not implemented: sign() and verify() raise "
    "NotImplementedError rather than report evidence as Sigstore-signed or "
    "Sigstore-verified without a real signature check. Use RFC3161Backend for "
    "timestamping, or WebAuthnBackend for at-rest signature verification."
)


class SigstoreBackend:
    """Sigstore signing + verification — **not implemented, fails closed**.

    Constructing the backend is allowed (it is exported from
    ``tzun_sdk.attestation`` and referenced by configuration), and
    :meth:`attest` is a no-op. Both cryptographic
    methods raise :class:`NotImplementedError`.
    """

    def __init__(self, allowed_identities: list[str] | None = None) -> None:
        self._allowed_identities = list(allowed_identities or [])

    async def attest(
        self, envelope: EvidenceEnvelope
    ) -> AttestationArtifacts | None:
        """No-op. Sigstore artifacts have no field in the evidence envelope."""
        return None

    def sign(
        self,
        canonical_bytes: bytes,
        oidc_token: str,
    ) -> dict[str, Any]:
        """Raise :class:`NotImplementedError`.

        A dict describing the inputs and containing no signature would leave
        a caller unable to tell a signed artifact from an unsigned one.
        """
        raise NotImplementedError(_NOT_IMPLEMENTED)

    def verify(
        self,
        signature: dict[str, Any],
        canonical_bytes: bytes,
        *,
        verify_tlog: bool = True,
    ) -> bool:
        """Raise :class:`NotImplementedError`.

        Answering ``True`` for every input that clears the identity-policy
        filter would pass ``verify({}, b"anything")``.
        """
        raise NotImplementedError(_NOT_IMPLEMENTED)


__all__ = ("SigstoreBackend",)
