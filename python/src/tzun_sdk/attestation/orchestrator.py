"""Attestation orchestrator — iterates configured backends per capture."""

from __future__ import annotations

import logging
from typing import Any

from tzun_sdk.models import AttestationArtifacts, EvidenceEnvelope

LOG = logging.getLogger(__name__)


class AttestationOrchestrator:
    """Collects attestation artifacts from configured backends."""

    def __init__(self, backends: list[Any]) -> None:
        self._backends = list(backends)

    async def attest(self, envelope: EvidenceEnvelope) -> list[AttestationArtifacts]:
        results: list[AttestationArtifacts] = []
        for backend in self._backends:
            try:
                blob = await backend.attest(envelope)
                if blob is not None:
                    results.append(blob)
            except Exception as exc:
                LOG.warning(
                    "attestation_backend_failed backend=%s err=%s",
                    type(backend).__name__,
                    exc,
                )
        return results


__all__ = ("AttestationOrchestrator",)
