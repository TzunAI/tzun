"""In-process dict-backed storage adapter.

Suitable for tests, scripts, and the default mode when no persistence is
configured. Data is lost on process exit.

Concurrency: write-coordination via ``asyncio.Lock`` on the descriptor
catalog (deduplication) and the custody-append path; reads are lock-free.

FAITHFUL DOUBLE. This adapter exists so that a test written against it means
something about SQLite and Postgres, so it answers every question the way they
do: reads return detached copies (a SQL adapter parses a fresh model from a
row; handing back the very object held would let a caller rewrite stored
evidence with an attribute assignment),
``list()`` pages at 100 like the SQL adapters, ``head()`` is the highest
sequence number on the chain, and the catalog refuses what the SQL schemas
refuse. ``python/tests/storage/test_conformance.py`` asserts all of it against
every adapter.
"""

from __future__ import annotations

import asyncio
import builtins
import copy
import datetime
import os
import secrets
from collections.abc import Sequence
from typing import Any

from tzun_sdk.agents import agent_descriptor_digest, canonical_serialize_agent_descriptor
from tzun_sdk.errors import DuplicateEvidenceError, MandateRefusedError, TzunError
from tzun_sdk.models import (
    AgentDescriptorRow,
    AnnotationRecord,
    AttestationArtifacts,
    DeciderOpening,
    EvidenceEnvelope,
    EvidenceLinkRow,
    ForkRecord,
    MandateEventRow,
    MandateExpireStore,
    MandateRow,
    ModelDescriptor,
    ModelDescriptorAnnotationRow,
    ModelDescriptorRow,
    RelinkRecord,
    StoreOptions,
    TamperIncident,
)
from tzun_sdk.storage._chain_head_guard import assert_chain_head, head_of
from tzun_sdk.storage._records import (
    capture_actor_of,
    chain_link_of,
    check_mandate_claim,
    check_mandate_transition,
    digest_of,
    evidence_id_of,
    link_index_rows,
    model_of,
    offset_of,
    opaque_cursor,
    opening_of,
    page_limit,
    raw_envelope,
    sequence_of,
)
from tzun_sdk.storage._revision_log import (
    CAPTURE_REVISION_NO,
    EnvelopeRevision,
)


def _utcnow_iso() -> str:
    """Return current UTC time as an ISO-8601 string (ms precision)."""
    return (
        datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )

DEFAULT_CHAIN_ID = "default"

#: The page ``list()`` returns when no ``limit`` is given — identical on every
#: adapter, the memory double included, so the truncation
#: ``StorageAdapter.list`` warns about is reachable from a test.
DEFAULT_LIST_LIMIT = 100


class MemoryAdapter:
    """In-process storage. Data lost on process exit. Concurrency-safe.

    Implements the :class:`StorageAdapter` Protocol declared in
    ``_protocol.py``.
    """

    def __init__(self) -> None:
        # The stored JSON of each record, exactly as captured: verification
        # hashes it, never a model's re-serialisation (Record §3.1).
        self._envelopes: dict[str, dict[str, Any]] = {}
        self._chains: dict[str, list[str]] = {}  # chain_id → [evidence_id, ...]
        self._chain_of: dict[str, str] = {}  # evidence_id → chain_id
        self._descriptors: dict[str, ModelDescriptor] = {}
        self._descriptor_rows: dict[str, ModelDescriptorRow] = {}
        self._descriptor_annotations: dict[str, list[ModelDescriptorAnnotationRow]] = {}
        # Alias store: list of (slug, digest, set_by, set_at) — append-only
        self._aliases: list[tuple[str, str, str, str]] = []
        self._attestations: dict[str, list[AttestationArtifacts]] = {}
        self._annotations: list[AnnotationRecord] = []
        self._relinks: list[RelinkRecord] = []
        self._forks: list[ForkRecord] = []
        self._incidents: list[TamperIncident] = []
        # The append-only revision log: one list per record, in
        # revision order. Nothing on this class removes or rewrites a row —
        # the SQL adapters enforce the same with triggers.
        self._envelope_revisions: dict[str, list[EnvelopeRevision]] = {}
        # commitment openings and the salt secret, the agent
        # catalog, the derived link index, and the mandate tables. Each is
        # written only inside the critical section that stores its record.
        self._openings: dict[str, dict[str, str]] = {}
        self._commitment_secret: bytes | None = None
        self._agent_rows: dict[str, AgentDescriptorRow] = {}
        self._links: list[tuple[str, int, str, str, str | None]] = []
        # The records by stored digest, in store order (the SQL adapters' digest index).
        self._by_digest: dict[str, list[str]] = {}
        self._mandates: dict[str, dict[str, Any]] = {}
        self._mandate_totals: dict[str, dict[str, dict[str, int]]] = {}
        self._mandate_events: dict[str, list[MandateEventRow]] = {}
        self._catalog_lock = asyncio.Lock()
        self._chain_lock = asyncio.Lock()

    async def store(
        self,
        envelope: EvidenceEnvelope | dict[str, Any],
        chain_id: str | None = None,
        options: StoreOptions | None = None,
    ) -> None:
        """Append an envelope; optionally compare-and-swap on the chain head.

        When ``options.expectChainHead`` is supplied this is a conditional
        append: the head is compared and the record appended in one critical
        section with no ``await`` in between, so two overlapping ``capture()``
        calls cannot both observe the same head. A mandate claim, issuance or
        revocation and a commitment opening (``options``) are checked in the
        same section, and written with the record or not at all.
        """
        cid = chain_id or DEFAULT_CHAIN_ID
        raw = copy.deepcopy(raw_envelope(envelope))
        evidence_id = evidence_id_of(raw)
        async with self._chain_lock:
            # Append-only: an id that is already stored is refused before the
            # head is even looked at (same order as the TS adapters).
            if evidence_id in self._envelopes:
                raise DuplicateEvidenceError(evidence_id)
            # ── atomic section: no await between the checks and the append ──
            chain = self._chains.setdefault(cid, [])
            live_head = self._envelopes[chain[-1]] if chain else None
            assert_chain_head(
                options.expectChainHead if options is not None else None,
                head_of(
                    sequence_of(live_head) if live_head is not None else 0,
                    digest_of(live_head) if live_head is not None else None,
                ),
            )
            opening = opening_of(raw, options)
            self._check_mandate_options(options)
            self._envelopes[evidence_id] = raw
            stored_digest = digest_of(raw)
            if stored_digest is not None:
                self._by_digest.setdefault(stored_digest, []).append(evidence_id)
            chain.append(evidence_id)
            self._chain_of[evidence_id] = cid
            # The capture revision, written in the SAME
            # critical section as the record it describes.
            rows = self._envelope_revisions.setdefault(evidence_id, [])
            if not any(r.revisionNo == CAPTURE_REVISION_NO for r in rows):
                rows.append(
                    EnvelopeRevision(
                        evidenceId=evidence_id,
                        revisionNo=CAPTURE_REVISION_NO,
                        canonicalDigest=digest_of(raw) or "",
                        chainLink=chain_link_of(raw),
                        recordedAt=_utcnow_iso(),
                        cause="capture",
                        actor=capture_actor_of(raw),
                    )
                )
            if opening is not None:
                self._openings[evidence_id] = opening
            self._links.extend(link_index_rows(raw))
            self._apply_mandate_options(options)

    def _check_mandate_options(self, options: StoreOptions | None) -> None:
        if options is None:
            return
        if options.mandateClaim is not None:
            claim = options.mandateClaim
            check_mandate_claim(
                claim, self._mandates.get(claim.mandateId), self._mandate_totals.get(claim.mandateId, {})
            )
        if options.mandateIssue is not None:
            mid = options.mandateIssue.record.mandateId
            digest = options.mandateIssue.record.mandateDigest
            if mid in self._mandates or any(m["mandate_digest"] == digest for m in self._mandates.values()):
                raise MandateRefusedError("mandate_already_issued", "document.mandateId", f"Mandate {mid} is already issued.")
        if options.mandateRevoke is not None:
            revoke = options.mandateRevoke
            check_mandate_transition(
                revoke, self._mandates.get(revoke.mandateId), self._mandate_totals.get(revoke.mandateId, {})
            )

    def _apply_mandate_options(self, options: StoreOptions | None) -> None:
        if options is None:
            return
        if options.mandateClaim is not None:
            claim = options.mandateClaim
            self._mandates[claim.mandateId]["used"] += 1
            for cap in claim.caps:
                self._mandate_totals[claim.mandateId][cap.cap]["total"] = int(cap.newTotal)
        if options.mandateIssue is not None:
            issue = options.mandateIssue
            row = issue.record
            self._mandates[row.mandateId] = {
                "mandate_id": row.mandateId,
                "mandate_digest": row.mandateDigest,
                "document_bytes": row.documentBytes,
                "statement_json": row.statementJson,
                "statement_digest": row.statementDigest,
                "assertion_json": row.assertionJson,
                "assertion_digest": row.assertionDigest,
                "assertion_timestamp": row.assertionTimestamp,
                "state": row.state,
                "used": row.used,
                "max_records": row.maxRecords,
                "not_before": row.notBefore,
                "not_after": row.notAfter,
                "issuance_evidence_id": row.issuanceEvidenceId,
                "issuance_digest": row.issuanceDigest,
                "created_at": row.createdAt,
            }
            self._mandate_totals[row.mandateId] = {c.cap: {"max": int(c.max), "total": 0} for c in issue.caps}
            self._mandate_events.setdefault(row.mandateId, []).append(issue.event.model_copy(deep=True))
        if options.mandateRevoke is not None:
            revoke = options.mandateRevoke
            self._mandates[revoke.mandateId]["state"] = revoke.newState
            self._mandate_events.setdefault(revoke.mandateId, []).append(revoke.event.model_copy(deep=True))

    async def retrieve(self, evidence_id: str) -> EvidenceEnvelope | None:
        # A detached model parsed from the stored JSON, as a SQL adapter returns one.
        stored = self._envelopes.get(evidence_id)
        return model_of(copy.deepcopy(stored)) if stored is not None else None

    async def retrieve_raw(self, evidence_id: str) -> dict[str, Any] | None:
        """The record's stored JSON, a detached copy, or ``None``."""
        stored = self._envelopes.get(evidence_id)
        return copy.deepcopy(stored) if stored is not None else None

    async def retrieve_raw_by_digest(self, digest: str) -> dict[str, Any] | None:
        """The stored JSON of the record whose stored canonical digest is ``digest`` (the oldest), or ``None``."""
        for evidence_id in self._by_digest.get(digest, ()):
            stored = self._envelopes.get(evidence_id)
            if stored is not None and digest_of(stored) == digest:
                return copy.deepcopy(stored)
        return None

    async def chain_of(self, evidence_id: str) -> str | None:
        """The chain a record was stored on, or ``None``."""
        return self._chain_of.get(evidence_id)

    async def list(self, **options: Any) -> list[EvidenceEnvelope]:
        """Page of envelopes ordered by ``sequenceNumber``; ``limit`` defaults to 100.

        The default page is the SQL adapters' (``sqlite.py``/``postgres.py``
        both ``options.get("limit", 100)``). Use :meth:`list_by_sequence` for
        anything that must see the whole chain.
        """
        limit = options.get("limit", DEFAULT_LIST_LIMIT)
        offset = options.get("offset", 0)
        items = list(self._envelopes.values())
        items.sort(key=sequence_of)
        page = items[offset : offset + limit] if limit is not None else items[offset:]
        return [model_of(copy.deepcopy(e)) for e in page]

    async def list_by_sequence(
        self,
        from_sequence: int | None = None,
        to_sequence: int | None = None,
        chain_id: str | None = None,
    ) -> builtins.list[EvidenceEnvelope]:
        """Chain-scoped, unpaged sequence-range lookup (mirrors TS listBySequence)."""
        return [model_of(e) for e in await self.list_raw_by_sequence(from_sequence, to_sequence, chain_id)]

    async def list_raw_by_sequence(
        self,
        from_sequence: int | None = None,
        to_sequence: int | None = None,
        chain_id: str | None = None,
    ) -> builtins.list[dict[str, Any]]:
        """:meth:`list_by_sequence` as stored JSON."""
        cid = chain_id or DEFAULT_CHAIN_ID
        lower = 1 if from_sequence is None else from_sequence
        items = [self._envelopes[eid] for eid in self._chains.get(cid, []) if eid in self._envelopes]
        items = [e for e in items if sequence_of(e) >= lower]
        if to_sequence is not None:
            items = [e for e in items if sequence_of(e) <= to_sequence]
        items.sort(key=sequence_of)
        return [copy.deepcopy(e) for e in items]

    async def head(self, chain_id: str | None = None) -> EvidenceEnvelope | None:
        """The record with the highest ``sequenceNumber`` on the chain.

        On an equal sequence number the later insert wins, matching the SQL
        tie-break.
        """
        cid = chain_id or DEFAULT_CHAIN_ID
        chain = self._chains.get(cid, [])
        best: dict[str, Any] | None = None
        for eid in chain:
            candidate = self._envelopes.get(eid)
            if candidate is None:
                continue
            if best is None or sequence_of(candidate) >= sequence_of(best):
                best = candidate
        return model_of(copy.deepcopy(best)) if best is not None else None

    async def head_raw(self, chain_id: str | None = None) -> dict[str, Any] | None:
        """:meth:`head` as stored JSON."""
        cid = chain_id or DEFAULT_CHAIN_ID
        best: dict[str, Any] | None = None
        for eid in self._chains.get(cid, []):
            candidate = self._envelopes.get(eid)
            if candidate is not None and (best is None or sequence_of(candidate) >= sequence_of(best)):
                best = candidate
        return copy.deepcopy(best) if best is not None else None

    async def read_envelope_at_end(self, end: str) -> Any:
        """The store's first (``end="first"``) or newest record by insertion, as stored JSON, or ``None``."""
        if not self._envelopes:
            return None
        key = next(iter(self._envelopes)) if end == "first" else next(reversed(self._envelopes))
        return copy.deepcopy(self._envelopes[key])

    # ── Decider openings (Record §6.3) ───────────────────────────────────

    async def get_decider_opening(self, evidence_id: str) -> DeciderOpening | None:
        opening = self._openings.get(evidence_id)
        return DeciderOpening(salt=opening["salt"], id=opening["id"]) if opening is not None else None

    async def get_decider_commitment_secret(self) -> bytes:
        if self._commitment_secret is None:
            self._commitment_secret = secrets.token_bytes(32)
        return self._commitment_secret

    # ── Agent catalog (Record §6.9) ──────────────────────────────────────

    async def put_agent_descriptor(self, descriptor: Any) -> tuple[str, bool]:
        """Register a descriptor (already checked); idempotent on identical bytes. ``(digest, already_existed)``."""
        digest = agent_descriptor_digest(descriptor)
        async with self._catalog_lock:
            if digest in self._agent_rows:
                return digest, True
            d = descriptor if isinstance(descriptor, dict) else descriptor.model_dump(mode="json")
            self._agent_rows[digest] = AgentDescriptorRow(
                digest=digest,
                canonicalBytes=canonical_serialize_agent_descriptor(d),
                name=d["name"],
                organization=d["operator"]["organization"],
                parent=d["parent"],
                registeredAt=_utcnow_iso(),
            )
        return digest, False

    async def get_agent_descriptor(self, digest: str) -> AgentDescriptorRow | None:
        row = self._agent_rows.get(digest)
        return row.model_copy(deep=True) if row is not None else None

    async def list_agent_descriptors(
        self,
        *,
        name: str | None = None,
        organization: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> tuple[builtins.list[AgentDescriptorRow], str | None]:
        size = page_limit(limit)
        start = offset_of(cursor)
        rows = sorted(self._agent_rows.values(), key=lambda r: (r.registeredAt, r.digest))
        rows = [
            r for r in rows
            if (name is None or r.name == name) and (organization is None or r.organization == organization)
        ]
        page = rows[start : start + size]
        nxt = opaque_cursor(start + size) if start + size < len(rows) else None
        return [r.model_copy(deep=True) for r in page], nxt

    # ── The link index ───────────────────────────────────────────────────

    async def list_links_to(
        self,
        digest: str,
        *,
        rels: Sequence[str] | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        statements: bool = False,
    ) -> tuple[builtins.list[EvidenceLinkRow], str | None]:
        """A page of the rows naming ``digest``; ``statements=True`` keeps only link records' statements."""
        size = page_limit(limit)
        start = offset_of(cursor)
        rows = [
            r
            for r in self._links
            if r[3] == digest
            and (rels is None or r[2] in rels)
            and (not statements or r[4] is not None)
            and r[0] in self._envelopes
        ]
        page = rows[start : start + size]
        nxt = opaque_cursor(start + size) if start + size < len(rows) else None
        return [EvidenceLinkRow(evidenceId=r[0], idx=r[1], rel=r[2], targetDigest=r[3]) for r in page], nxt

    # ── Mandates (Record §9.6) ───────────────────────────────────────────

    async def get_mandate(self, mandate_id: str) -> MandateRow | None:
        from tzun_sdk.storage._records import mandate_row_from

        row = self._mandates.get(mandate_id)
        return mandate_row_from(row) if row is not None else None

    async def get_mandate_by_digest(self, mandate_digest: str) -> MandateRow | None:
        from tzun_sdk.storage._records import mandate_row_from

        for row in self._mandates.values():
            if row["mandate_digest"] == mandate_digest:
                return mandate_row_from(row)
        return None

    async def get_mandate_totals(self, mandate_id: str) -> dict[str, int]:
        return {cap: int(row["total"]) for cap, row in self._mandate_totals.get(mandate_id, {}).items()}

    async def list_mandate_events(self, mandate_id: str) -> builtins.list[MandateEventRow]:
        return [e.model_copy(deep=True) for e in self._mandate_events.get(mandate_id, [])]

    async def list_mandates(self, *, state: str | None = None) -> builtins.list[MandateRow]:
        from tzun_sdk.storage._records import mandate_row_from

        return [mandate_row_from(r) for r in self._mandates.values() if state is None or r["state"] == state]

    async def expire_mandate(self, expiry: MandateExpireStore) -> None:
        async with self._chain_lock:
            check_mandate_transition(
                expiry, self._mandates.get(expiry.mandateId), self._mandate_totals.get(expiry.mandateId, {})
            )
            self._mandates[expiry.mandateId]["state"] = "expired"
            self._mandate_events.setdefault(expiry.mandateId, []).append(expiry.event.model_copy(deep=True))

    async def fill_confirmation(self, evidence_id: str, assertion: dict[str, Any]) -> bool:
        """Fill ``nonRepudiation.confirmation`` once; ``False`` when the record already has one or is absent."""
        async with self._chain_lock:
            stored = self._envelopes.get(evidence_id)
            if stored is None:
                return False
            nr = stored.setdefault("nonRepudiation", {})
            if not isinstance(nr, dict) or nr.get("confirmation") is not None:
                return False
            nr["confirmation"] = copy.deepcopy(assertion)
            return True

    async def append_custody(self, evidence_id: str, entry: dict[str, Any]) -> None:
        """Append a custody entry to a stored record (unhashed, outside the digest)."""
        async with self._chain_lock:
            stored = self._envelopes.get(evidence_id)
            if stored is not None:
                stored.setdefault("custodyChain", []).append(copy.deepcopy(entry))

    async def ensure_tables(self) -> None:
        # No-op for memory.
        return None

    async def close(self) -> None:
        # No-op for memory.
        return None

    async def register_descriptor(self, descriptor: ModelDescriptor) -> str:
        # ALWAYS the canonical descriptor hash, never `descriptor.modelDigest`,
        # which is the WEIGHTS digest — a different value about a different
        # thing. TS `registerModelDescriptor` hashes the canonical descriptor
        # bytes unconditionally (storage/memory.ts). Keying on the weights
        # digest would file the same descriptor under two different keys in the
        # two SDKs, and collide two descriptors that differ only in metadata
        # whenever they share weights.
        digest = _compute_descriptor_digest(descriptor)
        async with self._catalog_lock:
            if digest not in self._descriptors:
                self._descriptors[digest] = descriptor
                from tzun_sdk._generated.canonical import canonical_serialize_descriptor
                canonical_bytes = canonical_serialize_descriptor(
                    descriptor.model_dump(mode="json", exclude_none=False)
                )
                now = _utcnow_iso()
                self._descriptor_rows[digest] = ModelDescriptorRow(
                    modelDescriptorDigest=digest,
                    canonicalBytes=canonical_bytes,
                    descriptor=descriptor,
                    vendor=descriptor.vendor,
                    modelName=descriptor.modelName,
                    modelVersion=descriptor.modelVersion,
                    parentModelDescriptorDigest=descriptor.parentModelDescriptorDigest,
                    source="manual",
                    firstRegisteredAt=now,
                    firstRegisteredBy="sdk",
                )
        return digest

    # ── Catalog primitives ────────────────────────────────────────────────

    async def list_model_descriptors(
        self,
        vendor: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> builtins.list[ModelDescriptorRow]:
        rows = list(self._descriptor_rows.values())
        if vendor is not None:
            rows = [r for r in rows if r.vendor == vendor]
        off = offset or 0
        rows = rows[off:]
        if limit is not None:
            rows = rows[:limit]
        return [r.model_copy(deep=True) for r in rows]

    async def append_model_descriptor_annotation(
        self, row: ModelDescriptorAnnotationRow
    ) -> None:
        # The SQL schemas carry a FOREIGN KEY to model_descriptors and a
        # PRIMARY KEY on annotation_id; an orphan or duplicate annotation is
        # refused there, and so it is here.
        if row.modelDescriptorDigest not in self._descriptor_rows:
            raise TzunError(
                f'Model descriptor annotation references model descriptor '
                f'"{row.modelDescriptorDigest}", which does not exist.'
            )
        for rows in self._descriptor_annotations.values():
            if any(r.annotationId == row.annotationId for r in rows):
                raise TzunError(
                    f'Model descriptor annotation "{row.annotationId}" already exists. '
                    "Storage is append-only."
                )
        self._descriptor_annotations.setdefault(row.modelDescriptorDigest, []).append(
            row.model_copy(deep=True)
        )

    async def list_model_descriptor_annotations(
        self, digest: str
    ) -> builtins.list[ModelDescriptorAnnotationRow]:
        # annotated_at ASC, annotation_id ASC — the SQL adapters' order.
        rows = sorted(
            self._descriptor_annotations.get(digest, []),
            key=lambda r: (r.annotatedAt, r.annotationId),
        )
        return [r.model_copy(deep=True) for r in rows]

    async def set_model_descriptor_alias(
        self, slug: str, digest: str, set_by: str
    ) -> None:
        self._aliases.append((slug, digest, set_by, _utcnow_iso()))

    async def resolve_model_descriptor_alias(self, slug: str) -> str | None:
        # Scan in reverse; return the latest binding for this slug
        for s, digest, _, _ in reversed(self._aliases):
            if s == slug:
                return digest
        return None

    async def get_enriched_model_descriptor(self, digest: str) -> ModelDescriptor | None:
        stored = self._descriptors.get(digest)
        return stored.model_copy(deep=True) if stored is not None else None

    async def get_descriptor(self, digest: str) -> ModelDescriptor | None:
        # A detached copy: the SQL adapters parse a fresh model from
        # canonical_bytes on every read, so a caller assigning to the result
        # changes nothing there, and must change nothing here either.
        stored = self._descriptors.get(digest)
        return stored.model_copy(deep=True) if stored is not None else None

    async def list_envelope_revisions(self, evidence_id: str) -> builtins.list[EnvelopeRevision]:
        """Every revision row for one record, in ``revision_no`` order."""
        return sorted(
            self._envelope_revisions.get(evidence_id, []), key=lambda r: r.revisionNo
        )

    async def get_capture_digests(self, evidence_ids: Sequence[str]) -> dict[str, str]:
        """``evidenceId -> capture digest`` for the ids that have a revision 0.

        An id with no capture revision is ABSENT rather than mapped to
        ``None``: a record this store cannot speak for must not be mistakable
        for one it is vouching for.
        """
        out: dict[str, str] = {}
        for evidence_id in evidence_ids:
            for row in self._envelope_revisions.get(evidence_id, []):
                if row.revisionNo == CAPTURE_REVISION_NO:
                    out[evidence_id] = row.canonicalDigest
                    break
        return out

    async def store_attestation(
        self, evidence_id: str, blob: AttestationArtifacts
    ) -> None:
        self._attestations.setdefault(evidence_id, []).append(blob.model_copy(deep=True))

    async def get_attestations(
        self, evidence_id: str
    ) -> builtins.list[AttestationArtifacts]:
        return [b.model_copy(deep=True) for b in self._attestations.get(evidence_id, [])]

    async def store_annotation(self, record: AnnotationRecord) -> None:
        self._annotations.append(record.model_copy(deep=True))

    async def store_relink(self, record: RelinkRecord) -> None:
        self._relinks.append(record.model_copy(deep=True))

    async def store_fork(self, record: ForkRecord) -> None:
        self._forks.append(record.model_copy(deep=True))

    async def store_incident(self, incident: TamperIncident) -> None:
        # First write wins, as the SQL adapters' INSERT OR IGNORE / ON CONFLICT
        # DO NOTHING: a second store of the same incident adds no second copy.
        if any(i.incidentId == incident.incidentId for i in self._incidents):
            return
        self._incidents.append(incident.model_copy(deep=True))

    async def delete_envelope_for_demo(self, evidence_id: str) -> None:
        # Gated by the TZUN_ENABLE_DEMO_DELETE env var. Production
        # builds reach the error path; demo builds reach the deletion.
        if os.environ.get("TZUN_ENABLE_DEMO_DELETE", "") != "1":
            raise TzunError(
                "delete_envelope_for_demo is demo-only and not enabled in "
                "this build (set TZUN_ENABLE_DEMO_DELETE=1 to enable)."
            )
        async with self._chain_lock:
            self._envelopes.pop(evidence_id, None)
            self._chain_of.pop(evidence_id, None)
            for chain in self._chains.values():
                if evidence_id in chain:
                    chain.remove(evidence_id)


def _compute_descriptor_digest(descriptor: ModelDescriptor) -> str:
    """Compute a sha256 digest of the canonical descriptor bytes.

    The digest format matches the TS reference:
    ``sha256:<64 lowercase hex chars>``.
    """
    import hashlib

    from tzun_sdk._generated.canonical import canonical_serialize_descriptor

    canonical = canonical_serialize_descriptor(
        descriptor.model_dump(mode="json", exclude_none=False)
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


__all__ = ("MemoryAdapter",)
