"""Tamper detector.

Recomputes a record's digest over its stored JSON and emits
:class:`TamperIncident` events: ``digest_mismatch`` (with the ``fieldSet``
fact when an earlier v1.0 field set reproduces the stored digest; the fact
explains and never lowers the finding), and, for a record whose digest holds,
``record_rule_violated`` for a record a conforming writer would have refused
(a malformed decider, contributions or links, a relation rule a link
breaks, a link whose held target disagrees with it, a payload member
outside the format). The bytes are as
captured, so these are not tampering: their ``details.severity`` is
``medium``. The process outcomes of ``contributions.binding`` (an unbound
review, a stale approval, a changed output) never raise one: capture accepts
them on purpose.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS,
    CanonicalSerializationError,
    canonical_serialize,
)
from tzun_sdk.models import TamperIncident

if TYPE_CHECKING:
    from tzun_sdk.events import EventBus
    from tzun_sdk.links import LinkTargetResolver


def _utcnow_iso() -> str:
    """Return current UTC time as an ISO-8601 string (ms precision)."""
    return (
        datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )


def _raw(envelope: Any) -> dict[str, Any]:
    if isinstance(envelope, BaseModel):
        loaded = json.loads(envelope.model_dump_json(by_alias=True))
        return loaded if isinstance(loaded, dict) else {}
    return envelope if isinstance(envelope, dict) else {}


def _incident(event_type: str, evidence_id: Any, details: dict[str, Any]) -> TamperIncident:
    return TamperIncident(
        incidentId=str(uuid.uuid4()),
        eventType=event_type,
        evidenceId=evidence_id if isinstance(evidence_id, str) else None,
        # When the tamper was DETECTED, not when the record was captured:
        # capturedAt is attacker-influenced payload data.
        detectedAt=_utcnow_iso(),
        details=details,
    )


class TamperDetector:
    """Runs on a stored record; emits incidents through the event bus."""

    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._bus = event_bus

    async def detect(
        self, envelope: Any, *, resolver: LinkTargetResolver | None = None
    ) -> list[TamperIncident]:
        """Verify a record (its stored JSON, or a model of it); return any incidents found."""
        from tzun_sdk._verify_rows import record_rule_fields
        from tzun_sdk.payload_rules import earlier_field_set, unhashed_payload_members
        from tzun_sdk.signoff_expectation import check_signoff_expectation

        raw = _raw(envelope)
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
        integrity = raw.get("integrity") if isinstance(raw.get("integrity"), dict) else {}
        stored = integrity.get("canonicalDigest")
        evidence_id = payload.get("evidenceId")
        incidents: list[TamperIncident] = []
        try:
            actual = hashlib.sha256(
                canonical_serialize(payload, list(V1_HASHED_FIELDS)).encode("utf-8")
            ).hexdigest()
        except CanonicalSerializationError:
            actual = ""
        if actual != stored:
            details: dict[str, Any] = {"expected": stored, "actual": actual}
            field_set = earlier_field_set(payload, stored)
            if field_set is not None:
                details["fieldSet"] = field_set
            incidents.append(_incident("digest_mismatch", evidence_id, details))
            return incidents
        rows = record_rule_fields(raw, True, check_signoff_expectation(raw), resolver)
        for rule in ("decider", "contributions", "links"):
            row = rows[rule]
            if row.get("outcome") == "checked-wrong":
                incidents.append(
                    _incident(
                        "record_rule_violated",
                        evidence_id,
                        {"rule": rule, "reason": row.get("reason"), "severity": "medium"},
                    )
                )
        for relation in rows["links"].get("relations", []):
            if relation.get("outcome") != "checked-wrong":
                continue
            # A held target that disagrees with the link is ``links.target``;
            # a relation rule the record breaks on its own (a ``ratifies`` by
            # a non-human, a ``root`` without lineage, an attribute profile)
            # is ``links``. A conforming writer refuses both.
            incidents.append(
                _incident(
                    "record_rule_violated",
                    evidence_id,
                    {
                        "rule": "links.target" if relation.get("targetHeld") else "links",
                        "reason": relation.get("reason"),
                        "link": relation.get("index"),
                        "severity": "medium",
                    },
                )
            )
        stray = unhashed_payload_members(payload)
        if stray:
            incidents.append(
                _incident(
                    "record_rule_violated",
                    evidence_id,
                    {"rule": "payload.members", "members": stray, "severity": "medium"},
                )
            )
        return incidents


__all__ = ("TamperDetector",)
