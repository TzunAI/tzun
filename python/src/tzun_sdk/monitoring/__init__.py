"""Monitoring layer — tamper detection + scheduled scanner."""

from __future__ import annotations

from tzun_sdk.monitoring.tamper_detector import TamperDetector

__all__ = ("MonitoringEventType", "TamperDetector")


#: The monitoring event type union, matching the TS SDK exactly.
MonitoringEventType = (
    "digest_mismatch",
    "chain_break",
    "sequence_gap",
    "descriptor_resolution_failure",
    "descriptor_digest_mismatch",
    "parent_descriptor_resolution_failure",
    "parent_descriptor_digest_mismatch",
    "incident_annotated",
)
