"""Shared fixtures for storage adapter tests."""
from __future__ import annotations

import uuid

import pytest

from tzun_sdk.models import (
    AnnotationRecord,
    AttestationArtifacts,
    EvidenceEnvelope,
    EvidencePayload,
    ForkRecord,
    IntegrityBlock,
    RelinkRecord,
    TamperIncident,
)


def _make_envelope(evidence_id: str | None = None, seq: int = 1) -> EvidenceEnvelope:
    eid = evidence_id or str(uuid.uuid4())
    return EvidenceEnvelope(
        envelopeVersion="e1",
        payload=EvidencePayload(
            evidenceId=eid,
            schemaVersion="v1.0",
            aiSystemId="test-sys",
            aiOutput={"r": "x"},
            action="approved",
            decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
            reason="ok",
            capturedAt="2026-01-01T00:00:00.000Z",
            sequenceNumber=seq,
        ),
        integrity=IntegrityBlock(
            canonicalDigest="sha256:" + "ab" * 32,
            chainLink=None,
        ),
    )


@pytest.fixture
def envelope_factory():
    """Return a callable that builds unique EvidenceEnvelopes for each test."""
    _count = [0]

    def _build(seq: int = 1, prev: bool = False) -> EvidenceEnvelope:
        _count[0] += 1
        eid = f"e-{uuid.uuid4().hex[:8]}-{_count[0]}"
        digest = "sha256:" + f"{_count[0]:02x}" * 32
        return EvidenceEnvelope(
            envelopeVersion="e1",
            payload=EvidencePayload(
                evidenceId=eid,
                schemaVersion="v1.0",
                aiSystemId="test-sys",
                aiOutput={"r": "x"},
                action="approved",
                decider={"kind": "human", "id": "acct:test-reviewer", "agent": None, "credential": None, "freshness": None},
                reason="ok",
                capturedAt="2026-01-01T00:00:00.000Z",
                sequenceNumber=seq,
            ),
            integrity=IntegrityBlock(
                canonicalDigest=digest,
                chainLink=None,
            ),
        )

    return _build


@pytest.fixture
def attestation_blob():
    return AttestationArtifacts(
        rfc3161Token="dGVzdA==",
        rfc3161Metadata=None,
    )


@pytest.fixture
def recovery_records():
    ann = AnnotationRecord(
        id="ann-1",
        incidentId="inc-1",
        affectedRecords=["e1"],
        annotatedAt="2026-01-01T00:00:00.000Z",
        annotatedBy="alice",
        notes="test annotation",
        originalDigests={"e1": "sha256:abc"},
    )
    relink = RelinkRecord(
        id="rel-1",
        incidentId="inc-1",
        relinkedAt="2026-01-01T00:00:00.000Z",
        relinkedBy="alice",
        fromSequence=1,
        toSequence=2,
        modifiedLinks=[],
    )
    fork = ForkRecord(
        id="fork-1",
        incidentId="inc-1",
        forkedAt="2026-01-01T00:00:00.000Z",
        forkedBy="alice",
        reason="fork-reason",
        oldChainId="chain-1",
        newChainId="chain-3",
        forkAfterSequence=1,
        sealedOldChainLength=1,
        sealedOldChainHead=1,
    )
    incident = TamperIncident(
        incidentId=f"inc-{uuid.uuid4().hex[:8]}",
        eventType="digest_mismatch",
        evidenceId="e1",
        detectedAt="2026-01-01T00:00:00.000Z",
    )
    return ann, relink, fork, incident
