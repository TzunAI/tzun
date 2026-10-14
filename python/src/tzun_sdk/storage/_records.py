"""What every Python adapter stores beside a record, and the rules they share.

Each adapter writes, in the transaction that stores a record:

* the record's stored JSON exactly as the capture hashed it (``raw_envelope``):
  verification recomputes digests over the stored JSON, never over a model's
  re-serialisation (Record §3.1);
* the derived link index ``evidence_links`` (one row per stored link,
  ``subject`` included), which ``Tzun.links.to`` and the decision-graph walk
  read and verification never does;
* a commitment opening (``StoreOptions.deciderOpening``, Record §6.3), after
  checking it opens the record's ``cmt:`` decider;
* a mandate issuance, slot claim or revocation (``mandateIssue``,
  ``mandateClaim``, ``mandateRevoke``, Record §9.6), each a compare-and-swap on the
  mandate row, which the adapter locks before it takes the chain head.

The decisions those writes need, given the rows the adapter read under its
lock, live here so the three adapters refuse the same writes for the same
reasons.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any

from pydantic import BaseModel

from tzun_sdk._instant import js_date_parse_ms
from tzun_sdk.decider import verify_decider_opening
from tzun_sdk.errors import MandateClaimConflictError, MandateRefusedError, TzunError
from tzun_sdk.models import (
    EvidenceEnvelope,
    MandateClaimStore,
    MandateEventRow,
    MandateRevokeStore,
    MandateRow,
    StoreOptions,
)

#: The table names this SDK gives the 0.8.0 extension tables. Prefixed so a
#: database shared with the TypeScript SDK (whose evidence table and mandate
#: tables are its own) never holds two shapes under one name.
MANDATES_TABLE = "tzun_py_mandates"
MANDATE_TOTALS_TABLE = "tzun_py_mandate_totals"
MANDATE_EVENTS_TABLE = "tzun_py_mandate_events"
AGENT_DESCRIPTORS_TABLE = "tzun_py_agent_descriptors"
EVIDENCE_LINKS_TABLE = "tzun_py_evidence_links"


def utcnow_iso() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def raw_envelope(envelope: Any) -> dict[str, Any]:
    """The envelope as the JSON object a store keeps: a ``dict`` as given, a model as its JSON."""
    if isinstance(envelope, BaseModel):
        loaded = json.loads(envelope.model_dump_json(by_alias=True))
        return loaded if isinstance(loaded, dict) else {}
    if isinstance(envelope, dict):
        return envelope
    raise TzunError("store() takes an EvidenceEnvelope or the JSON object of one")


def envelope_json(raw: dict[str, Any]) -> str:
    """The stored text of an envelope: JSON, every non-ASCII character escaped.

    Escaping keeps a lone surrogate (which ``json.loads`` admits and the
    canonical serializer refuses) storable, so the record is kept as it was
    hashed and a verifier reports it rather than the write failing.
    """
    return json.dumps(raw, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def evidence_id_of(raw: dict[str, Any]) -> str:
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    evidence_id = payload.get("evidenceId")
    if not isinstance(evidence_id, str):
        raise TzunError("store(): the envelope has no payload.evidenceId")
    return evidence_id


def sequence_of(raw: dict[str, Any]) -> int:
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    seq = payload.get("sequenceNumber")
    if isinstance(seq, bool) or not isinstance(seq, (int, float)):
        raise TzunError("store(): the envelope has no numeric payload.sequenceNumber")
    return int(seq)


def digest_of(raw: dict[str, Any]) -> str | None:
    integrity = raw.get("integrity") if isinstance(raw.get("integrity"), dict) else {}
    digest = integrity.get("canonicalDigest")
    return digest if isinstance(digest, str) else None


def chain_link_of(raw: dict[str, Any]) -> str | None:
    integrity = raw.get("integrity") if isinstance(raw.get("integrity"), dict) else {}
    link = integrity.get("chainLink")
    return link if isinstance(link, str) else None


def capture_actor_of(raw: dict[str, Any]) -> str:
    """The capture revision's actor: the ``decision_captured`` custody entry's actor, else the SDK.

    A revision row with a blank actor reads as "nobody", a worse statement
    than "the SDK" (``REVISION_ACTOR_SDK``).
    """
    from tzun_sdk.storage._revision_log import REVISION_ACTOR_SDK

    custody = raw.get("custodyChain")
    if isinstance(custody, list) and custody and isinstance(custody[0], dict):
        actor = custody[0].get("actor")
        if isinstance(actor, str) and actor:
            return actor
    return REVISION_ACTOR_SDK


def model_of(raw: Any) -> EvidenceEnvelope:
    """The typed envelope of stored JSON (raises ``ValidationError`` for one that does not fit)."""
    return EvidenceEnvelope.model_validate(raw)


def link_index_rows(raw: dict[str, Any]) -> list[tuple[str, int, str, str, str | None]]:
    """``(evidence_id, idx, rel, target_digest, subject_digest)`` for each stored link of the record.

    ``subject_digest`` is set on a statement of a link record (one of its
    links other than ``subject``): the digest of the subject whose relation it
    states. It is ``None`` on every other row, the link record's own
    ``subject`` row included (the TS index's ``subjectDigest``).
    """
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    links = payload.get("links")
    evidence_id = payload.get("evidenceId")
    if not isinstance(links, list) or not isinstance(evidence_id, str):
        return []
    link_record = payload.get("aiSystemId") == "tzun:link"

    def parts(link: Any) -> tuple[str, str] | None:
        if not isinstance(link, dict) or not isinstance(link.get("target"), dict):
            return None
        rel, digest = link.get("rel"), link["target"].get("digest")
        return (rel, digest) if isinstance(rel, str) and isinstance(digest, str) else None

    subject = next((p for p in (parts(link) for link in links) if p is not None and p[0] == "subject"), None)
    subject_digest = subject[1] if link_record and subject is not None else None
    rows: list[tuple[str, int, str, str, str | None]] = []
    for idx, link in enumerate(links):
        found = parts(link)
        if found is not None:
            rel, digest = found
            rows.append((evidence_id, idx, rel, digest, subject_digest if rel != "subject" else None))
    return rows


class DeciderOpeningMismatchError(TzunError):
    """``StoreOptions.deciderOpening`` does not open the record's ``cmt:`` decider."""

    code = "decider_opening_mismatch"

    def __init__(self, evidence_id: str) -> None:
        super().__init__(
            f"The decider opening stored with record {evidence_id} does not open its decider's commitment."
        )
        self.evidence_id = evidence_id


def opening_of(raw: dict[str, Any], options: StoreOptions | None) -> dict[str, str] | None:
    """The opening a write carries, after checking it opens the record's decider; ``None`` when none."""
    if options is None or options.deciderOpening is None:
        return None
    opening = {"salt": options.deciderOpening.salt, "id": options.deciderOpening.id}
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    decider = payload.get("decider") if isinstance(payload.get("decider"), dict) else {}
    if not verify_decider_opening(decider.get("id"), opening):
        raise DeciderOpeningMismatchError(evidence_id_of(raw))
    return opening


def check_mandate_claim(
    claim: MandateClaimStore,
    mandate: dict[str, Any] | None,
    totals: dict[str, dict[str, int]],
) -> None:
    """Refuse a slot claim against the mandate row and totals read under the mandate lock.

    ``mandate`` holds ``state``, ``used``, ``max_records``, ``not_before`` and
    ``not_after``; ``totals`` maps each cap to ``{"max", "total"}``. A lost
    race (``used`` or a total moved) is :class:`MandateClaimConflictError`; a
    closed, full, over-cap or out-of-window mandate is terminal
    (:class:`MandateRefusedError`).
    """
    mid = claim.mandateId
    if mandate is None:
        raise MandateRefusedError("mandate_not_found", "mandate", f"Mandate {mid} is not in this store.")
    if mandate["state"] != "open":
        raise MandateRefusedError("mandate_not_open", "mandate", f"Mandate {mid} is not open.")
    now = js_date_parse_ms(claim.now)
    not_before = js_date_parse_ms(mandate.get("not_before"))
    not_after = js_date_parse_ms(mandate.get("not_after"))
    if now is None or (not_before is not None and now < not_before) or (not_after is not None and now > not_after):
        raise MandateRefusedError(
            "outside_validity", "capturedAt", f"The record's capturedAt is outside mandate {mid}'s validity window."
        )
    max_records = mandate.get("max_records")
    if max_records is not None and int(mandate["used"]) >= int(max_records):
        raise MandateRefusedError("mandate_full", "mandate", f"Every slot of mandate {mid} is used.")
    if int(mandate["used"]) != int(claim.expectUsed):
        raise MandateClaimConflictError(mid)
    for cap in claim.caps:
        held = totals.get(cap.cap)
        if held is None:
            raise MandateRefusedError("cap_exceeded", f"limits.cumulative.{cap.cap}", f"Mandate {mid} has no cap {cap.cap}.")
        if int(held["total"]) != int(cap.expectTotal):
            raise MandateClaimConflictError(mid)
        if int(cap.newTotal) > int(held["max"]) or int(cap.newTotal) < int(held["total"]):
            raise MandateRefusedError(
                "cap_exceeded", f"limits.cumulative.{cap.cap}", f"The record would take cap {cap.cap} past its maximum."
            )


def check_mandate_transition(
    store: MandateRevokeStore | Any,
    mandate: dict[str, Any] | None,
    totals: dict[str, dict[str, int]],
) -> None:
    """Refuse a revocation, supersession or expiry against the row read under the mandate lock."""
    mid = store.mandateId
    if mandate is None:
        raise MandateRefusedError("mandate_not_found", "mandate", f"Mandate {mid} is not in this store.")
    if mandate["state"] != store.expectState:
        raise MandateRefusedError("mandate_not_open", "mandate", f"Mandate {mid} is not open.")
    if int(mandate["used"]) != int(store.expectUsed):
        raise MandateClaimConflictError(mid)
    expect_totals = store.expectTotals or {}
    held = {cap: int(row["total"]) for cap, row in totals.items()}
    if (store.expectTotals is None and held) or (
        store.expectTotals is not None and held != {k: int(v) for k, v in expect_totals.items()}
    ):
        raise MandateClaimConflictError(mid)


def mandate_row_from(columns: dict[str, Any]) -> MandateRow:
    """A :class:`MandateRow` from a stored row's columns."""
    return MandateRow(
        mandateId=columns["mandate_id"],
        mandateDigest=columns["mandate_digest"],
        documentBytes=columns["document_bytes"],
        statementJson=columns["statement_json"],
        statementDigest=columns["statement_digest"],
        assertionJson=columns["assertion_json"],
        assertionDigest=columns["assertion_digest"],
        assertionTimestamp=columns.get("assertion_timestamp"),
        state=columns["state"],
        used=int(columns["used"]),
        maxRecords=None if columns.get("max_records") is None else int(columns["max_records"]),
        notBefore=columns.get("not_before"),
        notAfter=columns.get("not_after"),
        issuanceEvidenceId=columns["issuance_evidence_id"],
        issuanceDigest=columns["issuance_digest"],
        createdAt=str(columns["created_at"]),
    )


def event_row_from(mandate_id: str, canonical: str, digest: str) -> MandateEventRow:
    return MandateEventRow.model_validate(
        {"mandateId": mandate_id, "body": json.loads(canonical), "canonical": canonical, "digest": digest}
    )


MANDATE_COLUMNS = (
    "mandate_id", "mandate_digest", "document_bytes", "statement_json", "statement_digest", "assertion_json",
    "assertion_digest", "assertion_timestamp", "state", "used", "max_records", "not_before", "not_after",
    "issuance_evidence_id", "issuance_digest", "created_at",
)


def mandate_row_values(row: MandateRow) -> tuple[Any, ...]:
    """The insert values of a mandate row, in :data:`MANDATE_COLUMNS` order."""
    return (
        row.mandateId, row.mandateDigest, row.documentBytes, row.statementJson, row.statementDigest,
        row.assertionJson, row.assertionDigest, row.assertionTimestamp, row.state, row.used, row.maxRecords,
        row.notBefore, row.notAfter, row.issuanceEvidenceId, row.issuanceDigest, row.createdAt,
    )


def opaque_cursor(offset: int) -> str:
    return str(offset)


def offset_of(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        value = int(cursor)
    except (TypeError, ValueError) as exc:
        raise TzunError("cursor must be one a previous page returned") from exc
    if value < 0:
        raise TzunError("cursor must be one a previous page returned")
    return value


def page_limit(limit: int | None, default: int = 100, maximum: int = 200) -> int:
    value = default if limit is None else int(limit)
    if not 1 <= value <= maximum:
        raise TzunError(f"limit must be 1 to {maximum}")
    return value


__all__ = (
    "AGENT_DESCRIPTORS_TABLE",
    "EVIDENCE_LINKS_TABLE",
    "MANDATES_TABLE",
    "MANDATE_COLUMNS",
    "MANDATE_EVENTS_TABLE",
    "MANDATE_TOTALS_TABLE",
    "DeciderOpeningMismatchError",
    "capture_actor_of",
    "chain_link_of",
    "check_mandate_claim",
    "check_mandate_transition",
    "digest_of",
    "envelope_json",
    "event_row_from",
    "evidence_id_of",
    "link_index_rows",
    "mandate_row_from",
    "mandate_row_values",
    "model_of",
    "offset_of",
    "opaque_cursor",
    "opening_of",
    "page_limit",
    "raw_envelope",
    "sequence_of",
    "utcnow_iso",
)
