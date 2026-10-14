"""Attestation backends.

Three backends:

* :class:`RFC3161Backend` — RFC 3161 timestamping, with a circuit
  breaker of the TS client's hysteresis (3 failures opens; 60s
  half-open; one success closes). Each token it keeps is checked against
  tzun-anchor/1 §10.5 steps 1 to 3, and one that does not meet them is
  logged as ``event=attestation_timestamp_nonconformant``.
* :class:`WebAuthnBackend` — at-rest verification only; no signing
  ceremonies in Python (relying-party server context).
* :class:`SigstoreBackend` — **not implemented**. Both
  :meth:`~tzun_sdk.attestation.SigstoreBackend.sign` and
  :meth:`~tzun_sdk.attestation.SigstoreBackend.verify` raise
  :class:`NotImplementedError` rather than return a signature or a verdict
  nobody computed.

All three are wired by :class:`AttestationOrchestrator`, invoked by the
capture path after envelope storage.
"""

from __future__ import annotations

from tzun_sdk.attestation._rfc3161_steps import UnreadableTrustAnchorError
from tzun_sdk.attestation.orchestrator import AttestationOrchestrator
from tzun_sdk.attestation.rfc3161 import RFC3161Backend, TimestampConformance
from tzun_sdk.attestation.sigstore import SigstoreBackend
from tzun_sdk.attestation.webauthn import (
    WebAuthnBackend,
    assertion_binds_digest,
    assertion_provenance,
    webauthn_challenge_for_digest,
)

__all__ = (
    "AttestationOrchestrator",
    "RFC3161Backend",
    "SigstoreBackend",
    "TimestampConformance",
    "UnreadableTrustAnchorError",
    "WebAuthnBackend",
    "assertion_binds_digest",
    "assertion_provenance",
    "webauthn_challenge_for_digest",
)
