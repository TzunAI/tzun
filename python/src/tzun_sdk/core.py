"""Tzun (async) + TzunSync (sync) lifecycle.

State machine: ``INITIALIZING`` → ``ACTIVE`` → ``CLOSED``. Operations on
``CLOSED`` raise ``TzunError``. ``close()`` is idempotent and
safe under concurrent invocation.

Admin-token gating uses ``hmac.compare_digest`` for constant-time
comparison.
"""

from __future__ import annotations

import asyncio
import copy
import datetime as _dt
import functools
import hashlib
import hmac
import json
import logging
import threading
import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Self, cast

import anyio

# Submodule, not bound by a bare `import anyio`. CI's clean environment failed
# with AttributeError: module 'anyio' has no attribute 'from_thread' while this
# passed locally, because something else in the local run had already imported it.
import anyio.from_thread

from tzun_sdk import catalog
from tzun_sdk._capture import (
    CaptureRequest,
    attestation_status,
    build_payload,
    capture_input_violation,
    draft_payload,
    payload_digest,
    prepared_identity_violation,
    resolve_members,
    settle_signoff_expectation,
)
from tzun_sdk._generated.canonical import (
    V1_HASHED_FIELDS,
    CanonicalSerializationError,
    canonical_serialize,
)
from tzun_sdk._generated.chain import compute_chain_link
from tzun_sdk._record_rules import deep_plain, json_value
from tzun_sdk._store_schema_guard import refuse_outdated_store, refuse_store_before_setup
from tzun_sdk._verify_rows import record_rule_fields, resolve_agent_references, store_link_resolver
from tzun_sdk.ai_bom.registry import DEFAULT_CACHE_SIZE, DescriptorCache
from tzun_sdk.attestation.webauthn import (
    assertion_binds_digest,
    assertion_provenance,
    refuse_bare_string_allowlist,
)
from tzun_sdk.capture import assert_capture_serializable
from tzun_sdk.custody_hash import CUSTODY_ENTRY_HASH_PREIMAGE, verify_custody_trail
from tzun_sdk.decider import decider_material_violation
from tzun_sdk.errors import (
    AdminTokenRequiredError,
    ChainConflictError,
    InvalidAgentDescriptorError,
    InvalidDeciderError,
    InvalidPayloadError,
    MandateClaimConflictError,
    MandateRefusedError,
    StoreSchemaOutdatedError,
    TzunCaptureError,
    TzunError,
    VerificationError,
    WireFormatMismatch,
)
from tzun_sdk.events import EventBus, TzunEvent, TzunEventCallback
from tzun_sdk.mandate.expectation import mandate_block_violation
from tzun_sdk.models import (
    AnnotationRecord,
    CaptureResult,
    ChainHead,
    EvidenceEnvelope,
    ExportedDescriptorEntryMissing,
    ExportedDescriptorEntryPresent,
    ExportedEvidenceEnvelope,
    ForkRecord,
    MandateClaimStore,
    ModelDescriptor,
    RelinkRecord,
    StoreOptions,
    VerificationResult,
)
from tzun_sdk.payload_rules import (
    captured_at_claim_violation,
    earlier_field_set,
    is_evidence_id,
    unhashed_payload_members,
)
from tzun_sdk.signoff_expectation import check_signoff_expectation

if TYPE_CHECKING:
    from tzun_sdk.mandates_api import MandatesNamespace
    from tzun_sdk.namespaces import (
        AgentsNamespace,
        DecidersNamespace,
        DecisionGraphNamespace,
        LinksNamespace,
    )
    from tzun_sdk.storage._protocol import StorageAdapter

LOG = logging.getLogger(__name__)

#: Default for ``Tzun.init(chain_conflict_max_attempts=...)``. Mirrors
#: ``DEFAULT_CHAIN_CONFLICT_MAX_ATTEMPTS`` in ``src/sdk/index.ts``: each attempt
#: past the first means another writer beat this capture to the head, so the
#: bound is "how many writers can beat us in a row before we stop", not a time.
DEFAULT_CHAIN_CONFLICT_MAX_ATTEMPTS = 10

#: The ``aiSystemId`` a capture that names none writes.
DEFAULT_AI_SYSTEM_ID = "tzun-py-default"

#: Default for ``Tzun.init(freshness_max_age_ms=...)``: a shared finalized
#: block older than this is not written into a decider (Record §6.6).
DEFAULT_FRESHNESS_MAX_AGE_MS = 30 * 60 * 1000

INITIALIZING = "INITIALIZING"
ACTIVE = "ACTIVE"
CLOSED = "CLOSED"


def _log_restamp(receipt: dict[str, Any], evidence_id: str, seq: int, digest: str) -> None:
    """Log a cloud capture the platform stored under another sequence or digest than submitted.

    The platform re-stamps a capture onto its own chain head when the head
    this instance built on had moved. The record is stored under the
    receipt's sequence and digest; the result ``capture()`` returns is the
    record as submitted. A receipt for another record (an idempotent replay)
    is not a re-stamp.
    """
    if receipt.get("evidenceId") not in (None, evidence_id):
        return
    stored_seq, stored_digest = receipt.get("sequence"), receipt.get("canonicalDigest")
    if (stored_seq is None or stored_seq == seq) and (stored_digest is None or stored_digest == digest):
        return
    LOG.warning(
        "capture receipt_restamped evidence_id=%s submitted_seq=%d stored_seq=%s submitted_digest=%s stored_digest=%s",
        evidence_id,
        seq,
        stored_seq,
        digest,
        stored_digest,
    )


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _descriptor_digest(descriptor: Any) -> str | None:
    """The catalog digest a model descriptor's canonical bytes hash to, or ``None`` when it has none."""
    from tzun_sdk.storage.memory import _compute_descriptor_digest

    try:
        return _compute_descriptor_digest(descriptor)
    except Exception:
        return None


def _mandate_id_of(mandate: Any) -> str | None:
    """``capture(mandate=...)``: ``{"mandateId": <id>}`` (or the id itself), or ``None``."""
    mandate = deep_plain(mandate)
    if mandate is None:
        return None
    if isinstance(mandate, str):
        mandate = {"mandateId": mandate}
    if not isinstance(mandate, dict) or set(mandate) != {"mandateId"} or not isinstance(mandate["mandateId"], str):
        raise MandateRefusedError("mandate_not_found", "mandate", 'mandate must be {"mandateId": <the mandate id>}')
    return str(mandate["mandateId"])


def _export_verdict(raw: dict[str, Any], predecessor: dict[str, Any]) -> dict[str, Any]:
    """The export's ``RecordVerdict``, by the TS engine's ``recordVerdict`` rules, over the stored JSON.

    ``predecessor`` is ``{"digest": str | None}`` (``None`` when the store holds
    no record at the previous sequence) or ``{"error": str}``.
    """
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    integrity = raw.get("integrity") if isinstance(raw.get("integrity"), dict) else {}
    stored = integrity.get("canonicalDigest") if isinstance(integrity.get("canonicalDigest"), str) else ""
    digest: dict[str, Any] = {"status": "valid", "stored": stored, "recomputed": ""}
    if payload.get("schemaVersion") != "v1.0":
        digest.update(status="invalid", reason="unknown_schema_version")
    else:
        try:
            canonical = canonical_serialize(payload, list(V1_HASHED_FIELDS))
            digest["recomputed"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if digest["recomputed"] != stored:
                digest.update(status="invalid", reason="digest_mismatch")
        except CanonicalSerializationError:
            digest.update(status="invalid", reason="payload_unserializable")

    # The TS engine's chain-link rule: a link is SHA-256(predecessor ‖ stored
    # digest); a record past genesis must carry one; a record carrying one must
    # have a predecessor.
    chain_link: dict[str, Any]
    if "error" in predecessor:
        chain_link = {
            "status": "unmeasured",
            "reason": "predecessor_unreadable",
            "predecessorDigest": None,
            "detail": predecessor["error"],
        }
    else:
        prev_digest = predecessor["digest"]
        link = integrity.get("chainLink")
        chain_link = {"status": "valid", "predecessorDigest": prev_digest}
        seq = payload.get("sequenceNumber")
        if link is None:
            if prev_digest is not None or (isinstance(seq, (int, float)) and seq > 1):
                chain_link.update(status="invalid", reason="chain_link_missing")
        elif prev_digest is None:
            chain_link.update(status="invalid", reason="predecessor_missing")
        elif compute_chain_link(prev_digest, stored) != link:
            chain_link.update(status="invalid", reason="chain_link_mismatch")

    custody_trail = {"status": "unmeasured", "reason": "no_custody_ledger", "ledger": None}
    invalid = "invalid" in (digest["status"], chain_link["status"])
    # The signature expectation (Record §9) — beside the three, not counted in
    # `status`, and read only when the digest holds (the expectation is
    # authenticated by nothing else, Verification §5), as the TS engine's
    # `recordVerdict` reports it.
    signoff_expectation = (
        check_signoff_expectation(raw)
        if digest["status"] == "valid"
        else {"valid": None, "reason": "digest_invalid"}
    )
    return {
        "status": "invalid" if invalid else "valid",
        "digest": digest,
        "custodyTrail": custody_trail,
        "chainLink": chain_link,
        "signoffExpectation": signoff_expectation,
        "checkedAt": _utcnow_iso(),
    }


class _DescriptorCacheNamespace:
    """Public ``tzun.descriptor_cache`` namespace exposing only invalidate + clear."""

    def __init__(self, inner: DescriptorCache) -> None:
        self._inner = inner

    def invalidate(self, digest: str) -> None:
        self._inner.invalidate(digest)

    def clear(self) -> None:
        self._inner.clear()


class _ModelsNamespace:
    """Public ``tzun.models`` namespace."""

    def __init__(self, tzun: Tzun) -> None:
        self._tzun = tzun

    async def register(self, descriptor: ModelDescriptor) -> str:
        return await self._tzun._storage.register_descriptor(descriptor)

    async def get(self, digest: str) -> ModelDescriptor | None:
        cached = self._tzun.descriptor_cache_obj.get(digest)
        if isinstance(cached, ModelDescriptor):
            return cached
        return await self._tzun._storage.get_descriptor(digest)

    async def list(
        self,
        vendor: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Any]:
        """List model descriptor rows (delegates to the catalog primitive)."""
        return await self._tzun._storage.list_model_descriptors(
            vendor=vendor, limit=limit, offset=offset
        )

    async def annotate(
        self,
        digest: str,
        annotation_type: str,
        value: dict[str, Any],
        *,
        annotated_by: str,
        note: str | None = None,
        signature: str | None = None,
        admin_token: str | None = None,
    ) -> Any:
        """Append an annotation row (delegates to the catalog policy layer).

        ``freeform-note`` requires no admin. Any other type requires a valid
        ``admin_token`` (raises :class:`~tzun_sdk.errors.AdminTokenRequiredError`).
        """
        is_admin = False
        if annotation_type != catalog.FREEFORM_NOTE:
            self._tzun._check_admin_token(admin_token)
            is_admin = True
        return await catalog.annotate_model_descriptor(
            self._tzun._storage, digest, annotation_type, value,
            is_admin=is_admin, annotated_by=annotated_by,
            note=note, signature=signature,
        )

    async def set_alias(
        self,
        slug: str,
        digest: str,
        *,
        set_by: str,
        admin_token: str | None = None,
    ) -> None:
        """Bind a human-readable slug to a descriptor digest (admin-gated)."""
        self._tzun._check_admin_token(admin_token)
        await self._tzun._storage.set_model_descriptor_alias(slug, digest, set_by)

    async def resolve_alias(self, slug: str) -> str | None:
        """Return the digest bound to slug, or None."""
        return await self._tzun._storage.resolve_model_descriptor_alias(slug)

    async def get_annotations(self, digest: str) -> list[Any]:
        """Return all annotation rows for a descriptor digest."""
        return await self._tzun._storage.list_model_descriptor_annotations(digest)

    async def get_lineage(self, digest: str) -> list[Any] | None:
        """Walk the parent-DAG from leaf to root; None if digest not found."""
        return await catalog.walk_lineage(self._tzun._storage, digest)

    async def get_enriched(self, digest: str) -> ModelDescriptor | None:
        """Return the enriched (annotations-applied) descriptor, or None."""
        return await self._tzun._storage.get_enriched_model_descriptor(digest)


class _RecoveryNamespace:
    """Public ``tzun.recovery`` namespace."""

    def __init__(self, tzun: Tzun) -> None:
        self._tzun = tzun

    async def annotate(
        self,
        record: AnnotationRecord,
        *,
        admin_token: str | None = None,
    ) -> None:
        self._tzun._check_admin_token(admin_token)
        await self._tzun._storage.store_annotation(record)

    async def relink(
        self,
        record: RelinkRecord,
        *,
        admin_token: str | None = None,
    ) -> None:
        self._tzun._check_admin_token(admin_token)
        await self._tzun._storage.store_relink(record)

    async def fork(
        self,
        record: ForkRecord,
        *,
        admin_token: str | None = None,
    ) -> None:
        self._tzun._check_admin_token(admin_token)
        await self._tzun._storage.store_fork(record)


class Tzun:
    """Async Tzun client. Use :meth:`Tzun.init` to construct.

    All public methods are async. The sync mirror is :class:`TzunSync`.
    """

    def __init__(
        self,
        *,
        storage: StorageAdapter,
        admin_token: str | None = None,
        descriptor_cache_size: int = DEFAULT_CACHE_SIZE,
        chain_id: str | None = None,
        attestation_backends: list[Any] | None = None,
        chain_conflict_max_attempts: int = DEFAULT_CHAIN_CONFLICT_MAX_ATTEMPTS,
        freshness_chain: str | None = None,
        freshness_max_age_ms: int = DEFAULT_FRESHNESS_MAX_AGE_MS,
        assertion_verifier: Any = None,
        assertion_timestamper: Any = None,
    ) -> None:
        # Validated up front: a bound of 0 would silently turn every contended
        # capture into a raised one, which is the failure it exists to prevent.
        if (
            isinstance(chain_conflict_max_attempts, bool)
            or not isinstance(chain_conflict_max_attempts, int)
            or chain_conflict_max_attempts < 1
        ):
            raise ValueError(
                "chain_conflict_max_attempts must be an integer >= 1 "
                f"(got {chain_conflict_max_attempts!r}). It bounds how many times "
                "capture() rebuilds a record after another writer moved the chain head."
            )
        self._storage = storage
        self._admin_token = admin_token
        self._chain_conflict_max_attempts = chain_conflict_max_attempts
        self._state = INITIALIZING
        self._descriptor_cache = DescriptorCache(capacity=descriptor_cache_size)
        self._events = EventBus()
        self._close_lock = asyncio.Lock()
        self._chain_id = chain_id
        self._attestation_backends = list(attestation_backends or [])
        # Diagnostic only: the chain head's sequence as this instance last saw
        # it. `capture()` takes its sequence from the live head, not from here,
        # so nothing gates on this value; it is kept in step with the store —
        # on success, on a chain conflict, and on any other refused store — so
        # a caller inspecting it sees the store's truth, never a value one
        # step behind it.
        self._sequence_counter = 0
        self._sequence_lock = asyncio.Lock()
        self._descriptor_cache_ns = _DescriptorCacheNamespace(self._descriptor_cache)
        self._models_ns = _ModelsNamespace(self)
        self._recovery_ns = _RecoveryNamespace(self)
        self._contextvar_token: Any | None = None
        if isinstance(freshness_max_age_ms, bool) or not isinstance(freshness_max_age_ms, int) or freshness_max_age_ms <= 0:
            raise ValueError("freshness_max_age_ms must be a positive integer of milliseconds")
        # the chain whose shared finalized block `freshness:
        # "auto"` writes, the assertion verifier (the relying party's
        # credential store) the mandate ceremonies are verified with, and the
        # timestamp authority a mandate's assertion digest is stamped by.
        self._freshness_chain = freshness_chain
        self._freshness_max_age_ms = freshness_max_age_ms
        self._highest_freshness_block = 0
        self._assertion_verifier = assertion_verifier
        self._assertion_timestamper = assertion_timestamper
        from tzun_sdk.mandates_api import MandatesNamespace
        from tzun_sdk.namespaces import (
            AgentsNamespace,
            DecidersNamespace,
            DecisionGraphNamespace,
            LinksNamespace,
        )

        self._agents_ns = AgentsNamespace(self)
        self._links_ns = LinksNamespace(self)
        self._deciders_ns = DecidersNamespace(self)
        self._decision_graph_ns = DecisionGraphNamespace(self)
        self._mandates_ns = MandatesNamespace(self)

    @classmethod
    async def init(
        cls,
        *,
        storage: StorageAdapter,
        admin_token: str | None = None,
        descriptor_cache_size: int = DEFAULT_CACHE_SIZE,
        chain_id: str | None = None,
        attestation_backends: list[Any] | None = None,
        chain_conflict_max_attempts: int = DEFAULT_CHAIN_CONFLICT_MAX_ATTEMPTS,
        freshness_chain: str | None = None,
        freshness_max_age_ms: int = DEFAULT_FRESHNESS_MAX_AGE_MS,
        assertion_verifier: Any = None,
        assertion_timestamper: Any = None,
    ) -> Self:
        """Async classmethod. Opens storage + installs contextvar.

        ``chain_conflict_max_attempts`` bounds how many times :meth:`capture`
        builds a record and tries to append it before raising
        :class:`~tzun_sdk.errors.ChainConflictError` — or, over
        :class:`~tzun_sdk.storage.http.HttpBackendAdapter`, the server's
        ``409 chain_conflict`` as
        :class:`~tzun_sdk.errors.TzunCaptureError` (default 10, must be
        >= 1). Each attempt after the first means another writer — a second
        replica on the same database, a second ``Tzun`` on the same SQLite
        file, a second client on the same cloud chain — appended first, so
        under N concurrent writers the unluckiest
        capture can need up to N attempts; raise it if many replicas capture
        in tight loops. ``1`` disables the retry and raises on the first
        refusal. Mirrors ``TzunConfig.chainConflictMaxAttempts`` in TS.

        ``freshness_chain`` (a CAIP-2 chain id, e.g. ``"eip155:1"``) names the
        anchoring chain whose finalized block an anchoring writer shares in the
        store (Postgres ``anchor_freshness``); a decider's ``freshness: "auto"``
        writes it when it is no older than ``freshness_max_age_ms`` (default
        30 minutes), and ``None`` otherwise. Without it, ``"auto"`` writes
        ``None``. ``assertion_verifier`` verifies the WebAuthn ceremonies of the
        mandate API against the relying party's credential store
        (:class:`~tzun_sdk.mandates_api.AssertionVerifier`), and
        ``assertion_timestamper`` (``async (digest_hex) -> base64 DER token |
        None``) stamps a mandate's assertion digest; both default to none.
        """
        from tzun_sdk.ai_bom.hook import active_tzun

        inst = cls(
            storage=storage,
            admin_token=admin_token,
            descriptor_cache_size=descriptor_cache_size,
            chain_id=chain_id,
            attestation_backends=attestation_backends,
            chain_conflict_max_attempts=chain_conflict_max_attempts,
            freshness_chain=freshness_chain,
            freshness_max_age_ms=freshness_max_age_ms,
            assertion_verifier=assertion_verifier,
            assertion_timestamper=assertion_timestamper,
        )
        # A store an earlier release wrote is refused before anything is
        # captured: its records' digests are over an earlier v1.0 hashed field
        # set (0.7.0 and 0.8.0 revised it in place), and would all read as
        # tampered.
        # SQLite and Postgres are read before ensure_tables(), so a refused
        # store gains nothing; any other local adapter is read once it is set
        # up. The cloud backend's store is the platform's, which checks its
        # own, as the TS SDK's cloud transport leaves it to the platform.
        from tzun_sdk.storage.http import HttpBackendAdapter

        local = not isinstance(inst._storage, HttpBackendAdapter)
        try:
            checked = local and await refuse_store_before_setup(inst._storage)
            await inst._storage.ensure_tables()
            if local and not checked:
                listed = await inst._storage.list(limit=1)
                newest = await inst._storage.head(chain_id)

                async def _head() -> Any:
                    return newest

                await refuse_outdated_store(listed[0] if listed else None, _head)
            head_seq, _ = await inst._head_parts()
        except StoreSchemaOutdatedError:
            try:
                await inst._storage.close()
            except Exception:
                LOG.warning("tzun_init storage_close_failed", exc_info=True)
            raise
        inst._sequence_counter = head_seq
        inst._state = ACTIVE
        inst._contextvar_token = active_tzun.set(inst)
        LOG.info("tzun_init state=ACTIVE chain_id=%s", chain_id)
        return inst

    # ── Lifecycle ────────────────────────────────────────────────

    async def close(self) -> None:
        """Idempotent close."""
        from tzun_sdk.ai_bom.hook import active_tzun

        async with self._close_lock:
            if self._state == CLOSED:
                return
            self._state = CLOSED
            try:
                await self._storage.close()
            except Exception:
                LOG.warning("tzun_close storage_close_failed", exc_info=True)
            if self._contextvar_token is not None:
                try:
                    active_tzun.reset(self._contextvar_token)
                except (ValueError, LookupError):
                    active_tzun.set(None)
                self._contextvar_token = None
            self._descriptor_cache.clear()
            self._events.clear()
            LOG.info("tzun_close state=CLOSED")

    async def aclose(self) -> None:
        """Async-style alias for :meth:`close` matching the asyncio convention."""
        await self.close()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    # ── Capture / verify ─────────────────────────────────────────

    async def capture(
        self,
        *,
        ai_output: dict[str, Any],
        action: str,
        reason: str,
        decider: Any,
        contributions: Any = None,
        links: Any = None,
        ai_system_id: str | None = None,
        evidence_id: str | None = None,
        captured_at: str | None = None,
        signoff_expectation: Any = None,
        mandate: Any = None,
        require_freshness: bool | None = None,
        webauthn_assertion: Any = None,
        prepared: Any = None,
    ) -> CaptureResult:
        """Capture a decision; return a :class:`CaptureResult`.

        ``action`` and ``reason`` are the decision taken and its stated
        reason, whoever took it. ``decider`` says who took it, inside the
        digest: ``{"kind": "human", "id": "acct:<opaque account id>"}``, or an
        agent kind with ``agent`` (its descriptor digest; ``id`` defaults to
        ``desc:<agent>``). ``decider["freshness"]`` defaults to ``"auto"``
        (the store's shared finalized block, when one is configured and
        acceptable, otherwise ``None``); ``decider["commit"] = True`` writes a
        ``cmt:`` commitment in place of the identifier and keeps its opening
        in the store (``CaptureResult.deciderOpening``, ``tzun.deciders.opening``).

        ``contributions`` is the record's only bill of materials: a single
        model is ``single_model(ai_bom)``. ``links`` are relations to other
        records (``derivedFrom``, ``reviews``, ...; ``x-<org>.<name>``): a
        same-store target is resolved and checked; one in another store is
        passed with ``"external": True``.

        ``signoff_expectation`` is ``None`` or ``{"policyDigest": <64 hex>}``;
        the session and mandate forms are refused here (only the capture that
        claimed the slot writes them). ``mandate={"mandateId": ...}``
        captures under that mandate: its slot and running totals are claimed
        in the transaction that stores the record. ``require_freshness``
        refuses a capture with no finalized-block reference.
        ``webauthn_assertion`` is a per-record assertion over
        :meth:`prepare_assertion_challenge`'s challenge, captured with
        ``prepared``.

        Every refusal raises before a sequence number is taken: a
        :class:`~tzun_sdk.errors.CaptureRefusedError` subclass naming the
        member (``code``, ``field``), or
        :class:`~tzun_sdk.errors.InvalidSignoffExpectationError`. The 0.7
        names ``human_action``, ``human_reason``, ``reviewer`` and ``ai_bom``
        are not parameters: passing one raises ``TypeError``.

        Captures on one instance are serialised under one per-instance lock,
        as the TS SDK's ``runCaptureExclusive()``; contention on the chain
        head is between instances, which ``chain_conflict_max_attempts``
        bounds.
        """
        self._require_active()
        # Refuse values that a JSON round trip would silently rewrite (NaN,
        # ±Infinity) before anything is built; the capture then works on
        # plain JSON values, models included, as the TS SDK does.
        assert_capture_serializable(ai_output, "aiOutput")
        if contributions is not None:
            assert_capture_serializable(deep_plain(contributions), "contributions")
        ai_output = json_value(ai_output)
        decider = json_value(decider)
        contributions = json_value(contributions)
        links = json_value(links)
        refusal = capture_input_violation(
            ai_output=ai_output,
            action=action,
            reason=reason,
            ai_system_id=ai_system_id,
            decider=decider,
            contributions=contributions,
            links=links,
        )
        if refusal is not None:
            raise refusal
        mandate_id = _mandate_id_of(mandate)
        if mandate_id is not None and captured_at is not None:
            raise MandateRefusedError(
                "captured_at_with_mandate",
                "capturedAt",
                "a capture under a mandate takes its capturedAt from the SDK's clock: the mandate's validity "
                "window is judged against it",
            )
        if mandate_id is not None and evidence_id is not None:
            raise MandateRefusedError(
                "evidence_id_with_mandate", "evidenceId", "a capture under a mandate takes its evidenceId from the SDK"
            )
        if captured_at is not None:
            claim = captured_at_claim_violation(captured_at)
            if claim is not None:
                raise InvalidPayloadError(
                    "invalid_captured_at",
                    "capturedAt",
                    "capturedAt is more than five minutes in the future"
                    if claim == "future_dated"
                    else "capturedAt must be an ISO-8601 date-time with a zone",
                )
        if evidence_id is not None and not is_evidence_id(evidence_id):
            raise InvalidPayloadError("invalid_evidence_id", "evidenceId", "evidenceId must be a v4 UUID")
        prepared_plain = deep_plain(prepared)
        if prepared_plain is not None:
            identity = prepared_identity_violation(prepared_plain)
            if identity is not None:
                raise identity
        expectation = settle_signoff_expectation(signoff_expectation, mandate=mandate_id is not None)
        if prepared_plain is not None and mandate_id is not None:
            raise MandateRefusedError(
                "prepared_with_mandate", "prepared", "a capture under a mandate is not prepared for a signature"
            )
        if prepared_plain is not None:
            # The expectation inside the digest the ceremony signed, held to
            # the same rules as a caller's: the session and mandate forms are
            # refused.
            prepared_expectation = settle_signoff_expectation(
                prepared_plain.get("signoffExpectation"), mandate=False, field="prepared.signoffExpectation"
            )
            if signoff_expectation is not None and prepared_expectation != expectation:
                raise InvalidDeciderError(
                    "prepared_expectation_differs",
                    "signoffExpectation",
                    "signoff_expectation differs from prepared.signoffExpectation, which is inside the digest the "
                    "ceremony signed; omit it, or prepare the record with this one",
                )
            expectation = prepared_expectation
        request = CaptureRequest(
            ai_output=ai_output,
            action=action,
            reason=reason,
            decider=decider,
            ai_system_id=ai_system_id or DEFAULT_AI_SYSTEM_ID,
            contributions=contributions,
            links=links,
            signoff_expectation=expectation,
            evidence_id=evidence_id,
            captured_at=captured_at,
            mandate_id=mandate_id,
            require_freshness=bool(require_freshness),
            webauthn_assertion=deep_plain(webauthn_assertion),
            prepared=prepared_plain,
        )
        return await self._capture_request(request)

    async def prepare_assertion_challenge(
        self,
        *,
        ai_output: dict[str, Any],
        action: str,
        reason: str,
        decider: Any,
        contributions: Any = None,
        links: Any = None,
        ai_system_id: str | None = None,
        signoff_expectation: Any = None,
    ) -> dict[str, Any]:
        """Build the record the next :meth:`capture` would build, without storing it.

        Returns ``{digest, challenge, evidenceId, capturedAt, sequenceNumber,
        previousDigest, signoffExpectation, decider, contributions, links}``
        (and ``deciderOpening`` under ``commit``): a WebAuthn ceremony signs
        ``challenge``, and ``capture(..., webauthn_assertion=..., prepared=...)``
        stores the record with the members resolved here. If another writer
        appends first, the record would move and its digest change, so the
        capture is refused (``ChainConflictError``) rather than storing an
        assertion about a record that does not exist; the caller re-runs the
        ceremony. The twin of the TS SDK's ``prepareAssertionChallenge``.
        """
        self._require_active()
        assert_capture_serializable(ai_output, "aiOutput")
        ai_output = json_value(ai_output)
        decider = json_value(decider)
        contributions = json_value(contributions)
        links = json_value(links)
        refusal = capture_input_violation(
            ai_output=ai_output,
            action=action,
            reason=reason,
            ai_system_id=ai_system_id,
            decider=decider,
            contributions=contributions,
            links=links,
        )
        if refusal is not None:
            raise refusal
        expectation = settle_signoff_expectation(signoff_expectation, mandate=False)
        request = CaptureRequest(
            ai_output=ai_output,
            action=action,
            reason=reason,
            decider=decider,
            ai_system_id=ai_system_id or DEFAULT_AI_SYSTEM_ID,
            contributions=contributions,
            links=links,
            signoff_expectation=expectation,
        )
        return await self._prepare_request(request)

    async def _prepare_request(self, request: CaptureRequest) -> dict[str, Any]:
        from tzun_sdk.attestation.webauthn import webauthn_challenge_for_digest

        async with self._sequence_lock:
            members = await resolve_members(self, request)
            head_seq, prev_digest = await self._head_parts()
            evidence_id = request.evidence_id or str(uuid.uuid4())
            captured_at = request.captured_at or _utcnow_iso()
            payload = build_payload(
                request,
                members,
                sequence_number=head_seq + 1,
                evidence_id=evidence_id,
                captured_at=captured_at,
                expectation=request.signoff_expectation,
                links=members.links,
            )
            digest = payload_digest(payload)
            prepared: dict[str, Any] = {
                "digest": digest,
                "challenge": webauthn_challenge_for_digest(digest),
                "evidenceId": evidence_id,
                "capturedAt": captured_at,
                "sequenceNumber": head_seq + 1,
                "previousDigest": prev_digest,
                "signoffExpectation": None if request.signoff_expectation is None else dict(request.signoff_expectation),
                "decider": dict(members.decider),
                "contributions": copy.deepcopy(members.contributions),
                "links": copy.deepcopy(members.links),
            }
            if members.opening is not None:
                prepared["deciderOpening"] = dict(members.opening)
            return prepared

    async def _head_parts(self) -> tuple[int, str | None]:
        """The chain head's ``(sequence, digest)`` as the store holds it, read from its stored JSON when it can."""
        reader = getattr(self._storage, "head_raw", None)
        if reader is not None:
            raw = await reader(self._chain_id)
            if raw is None:
                return 0, None
            payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
            integrity = raw.get("integrity") if isinstance(raw.get("integrity"), dict) else {}
            seq = payload.get("sequenceNumber")
            digest = integrity.get("canonicalDigest")
            return (
                int(seq) if isinstance(seq, (int, float)) and not isinstance(seq, bool) else 0,
                digest if isinstance(digest, str) else None,
            )
        live = await self._storage.head(self._chain_id)
        if live is None:
            return 0, None
        return live.payload.sequenceNumber, live.integrity.canonicalDigest

    async def _capture_request(self, request: CaptureRequest) -> CaptureResult:
        """The body of :meth:`capture` for a caller's record and a system record alike.

        Members are resolved once, before any sequence number is taken. Each
        attempt builds the record at the live head (with a mandate's slot
        claimed for it), and the store's compare-and-swap refuses it when the
        head moved or another capture took the slot; the record is then
        rebuilt at the next position, bounded by ``chain_conflict_max_attempts``.
        """
        from tzun_sdk.mandates_api import MandateClaim

        async with self._sequence_lock:
            prepared = request.prepared
            # A prepared capture's members are resolved again from its input
            # and must equal the prepared ones (``invalid_prepared``).
            members = await resolve_members(self, request)
            claim = await MandateClaim.open(self, request.mandate_id) if request.mandate_id is not None else None
            evidence_id = request.evidence_id or (prepared["evidenceId"] if prepared else None) or str(uuid.uuid4())
            captured_at = request.captured_at or (prepared["capturedAt"] if prepared else None) or _utcnow_iso()
            head_seq, prev_digest = await self._head_parts()
            attempt = 0
            while True:
                attempt += 1
                seq = head_seq + 1
                plan: dict[str, Any] | None = None
                if claim is not None:
                    plan = await claim.plan(
                        draft_payload(request, members, sequence_number=seq, evidence_id=evidence_id, captured_at=captured_at)
                    )
                payload = build_payload(
                    request,
                    members,
                    sequence_number=seq,
                    evidence_id=evidence_id,
                    captured_at=captured_at,
                    expectation=plan["expectation"] if plan else request.signoff_expectation,
                    links=plan["links"] if plan else members.links,
                )
                canonical_digest = payload_digest(payload)
                if prepared is not None and canonical_digest != prepared["digest"]:
                    if seq == prepared.get("sequenceNumber") and prev_digest == prepared.get("previousDigest"):
                        # Same position, another record: the prepared object
                        # does not describe what this capture builds.
                        raise InvalidDeciderError(
                            "invalid_prepared",
                            "prepared.digest",
                            "prepared.digest is not the digest of the record this capture builds at the prepared "
                            "position: capture with the input and the prepared object prepare_assertion_challenge() "
                            "returned",
                        )
                    # The ceremony signed the prepared record's digest; this
                    # record moved, so the assertion is about a record that
                    # will never exist. Refused, not retried: the caller
                    # re-runs the ceremony.
                    raise ChainConflictError(
                        ChainHead(sequence=int(prepared["sequenceNumber"]) - 1, digest=prepared.get("previousDigest")),
                        ChainHead(sequence=seq - 1, digest=prev_digest),
                    )
                assertion = request.webauthn_assertion
                material = decider_material_violation(
                    payload["decider"],
                    digest=canonical_digest,
                    assertion=assertion,
                    assertion_user_id=request.assertion_user_id
                    if request.assertion_user_id is not None
                    else await self._assertion_user_id(assertion),
                )
                if material is not None:
                    raise InvalidDeciderError(material["code"], material["field"], material["message"])
                non_repudiation: dict[str, Any] = {}
                if assertion is not None:
                    non_repudiation["webauthnAssertion"] = assertion
                if request.mandate_issuance is not None:
                    non_repudiation["mandateIssuance"] = request.mandate_issuance
                if plan is not None:
                    non_repudiation["mandate"] = plan["block"]
                for key in ("mandate", "mandateIssuance"):
                    if key in non_repudiation:
                        too_large = mandate_block_violation(non_repudiation[key], f"nonRepudiation.{key}")
                        if too_large is not None:
                            raise MandateRefusedError(too_large["code"], too_large["field"], too_large["message"])
                custody = [
                    {
                        "timestamp": captured_at,
                        "actor": payload["decider"]["id"],
                        "action": "decision_captured",
                        "systemId": payload["aiSystemId"],
                    }
                ]
                for entry in (plan or {}).get("custody", []):
                    custody.append(
                        {"timestamp": captured_at, "systemId": payload["aiSystemId"], **entry}
                    )
                envelope: dict[str, Any] = {
                    "envelopeVersion": "e1",
                    "payload": payload,
                    "integrity": {
                        "canonicalDigest": canonical_digest,
                        "chainLink": compute_chain_link(prev_digest, canonical_digest),
                    },
                    "nonRepudiation": non_repudiation,
                    "custodyChain": custody,
                    "attestationStatus": attestation_status(non_repudiation, canonical_digest),
                }
                options: dict[str, Any] = {"expectChainHead": ChainHead(sequence=seq - 1, digest=prev_digest)}
                if plan is not None:
                    options["mandateClaim"] = MandateClaimStore.model_validate(plan["claim"])
                if members.opening is not None:
                    options["deciderOpening"] = members.opening
                if request.store_options is not None:
                    options.update(await request.store_options(envelope))
                try:
                    receipt = await self._storage.store(envelope, self._chain_id, StoreOptions(**options))
                except (ChainConflictError, TzunCaptureError, MandateClaimConflictError) as exc:
                    if isinstance(exc, TzunCaptureError) and exc.code != "chain_conflict":
                        await self._resync_after_refused_store(exc, evidence_id, seq)
                        raise
                    if prepared is not None:
                        await self._resync_after_refused_store(exc, evidence_id, seq)
                        raise
                    if isinstance(exc, ChainConflictError):
                        # Adopt the head we lost to, as the adapter read it
                        # inside its own atomic section, and go around.
                        head_seq = int(exc.actual.sequence)
                        prev_digest = exc.actual.digest
                    else:
                        # The server's compare-and-swap (409 chain_conflict,
                        # no head attached) or a lost mandate slot: read the
                        # live head and rebuild against it.
                        head_seq, prev_digest = await self._head_parts()
                    self._sequence_counter = head_seq
                    if attempt >= self._chain_conflict_max_attempts:
                        LOG.error(
                            "capture chain_conflict_exhausted evidence_id=%s attempts=%d max_attempts=%d "
                            "refused_seq=%d live_head_seq=%d",
                            evidence_id,
                            attempt,
                            self._chain_conflict_max_attempts,
                            seq,
                            head_seq,
                        )
                        raise
                    LOG.warning(
                        "capture chain_conflict_retry evidence_id=%s attempt=%d max_attempts=%d refused_seq=%d "
                        "resynced_to=%d",
                        evidence_id,
                        attempt,
                        self._chain_conflict_max_attempts,
                        seq,
                        head_seq,
                    )
                    continue
                except Exception as exc:
                    # Not a moved head, so not a retry: a duplicate id, a
                    # refused mandate claim, a dropped connection. The record
                    # was not written; the reserved sequence is handed back.
                    await self._resync_after_refused_store(exc, evidence_id, seq)
                    raise
                break
            self._sequence_counter = await self._adopt_stored_head(receipt, seq)
            if isinstance(receipt, dict):
                _log_restamp(receipt, evidence_id, seq, canonical_digest)
        model = EvidenceEnvelope.model_validate(envelope)
        for backend in self._attestation_backends:
            try:
                blob = await backend.attest(model)
                if blob is not None:
                    await self._storage.store_attestation(evidence_id, blob)
            except Exception as exc:
                LOG.warning(
                    "attestation_backend_failed backend=%s err=%s",
                    type(backend).__name__,
                    exc,
                )
        # Emit event. PII (reason, aiOutput, the decider) is NOT
        # included in the payload.
        self._events.dispatch(
            TzunEvent(
                event_type="decision_captured",
                timestamp=_utcnow_iso(),
                payload={
                    "evidenceId": evidence_id,
                    "canonicalDigest": canonical_digest,
                    "sequenceNumber": seq,
                },
            )
        )
        LOG.info("capture event=decision_captured evidence_id=%s seq=%d", evidence_id, seq)
        result = CaptureResult(
            evidenceId=evidence_id,
            canonicalDigest=canonical_digest,
            sequenceNumber=seq,
            envelope=model,
            deciderOpening=members.opening,
            mandate=plan["result"] if plan else None,
        )
        return result

    async def _assertion_user_id(self, assertion: Any) -> str | None:
        """The user the configured assertion verifier registers the assertion's credential to, or ``None``."""
        if not isinstance(assertion, dict) or self._assertion_verifier is None:
            return None
        credential = assertion.get("credentialKeyId")
        if not isinstance(credential, str):
            return None
        lookup = getattr(self._assertion_verifier, "user_id_of", None)
        if lookup is None:
            return None
        try:
            user_id = await lookup(credential)
        except Exception:
            return None
        return user_id if isinstance(user_id, str) else None

    async def _freshness_reference(self) -> str | None:
        """What ``freshness: "auto"`` writes now (Record §6.6): the store's shared finalized block, or ``None``.

        Read only when ``freshness_chain`` is configured and the store shares
        a row (Postgres ``anchor_freshness``, written by an anchoring writer).
        A row for another chain, one older than ``freshness_max_age_ms``, or
        one below the last reference this instance wrote is not used.
        """
        from tzun_sdk.decider import format_freshness_reference

        chain = self._freshness_chain
        reader = getattr(self._storage, "read_anchor_freshness", None)
        if chain is None or reader is None:
            return None
        try:
            row = await reader(chain)
        except Exception:
            LOG.warning("capture freshness_row_unreadable", exc_info=True)
            return None
        if row is None or row.get("chain") != chain:
            return None
        now_ms = int(_dt.datetime.now(_dt.UTC).timestamp() * 1000)
        if int(row["number"]) < self._highest_freshness_block or now_ms - int(row["timeMs"]) > self._freshness_max_age_ms:
            return None
        try:
            reference = format_freshness_reference(chain, int(row["number"]), str(row["hash"]))
        except ValueError:
            return None
        self._highest_freshness_block = int(row["number"])
        return reference

    async def _adopt_stored_head(self, receipt: Any, stored_seq: int) -> int:
        """The chain head's sequence as the STORE reports it after a confirmed
        append — the value ``_sequence_counter`` mirrors.

        A cloud receipt (``HttpBackendAdapter.store()`` returns the server's
        ``{sequence, headDigest, ...}``) is adopted as-is: it is the head the
        server committed and costs no request. Every other adapter returns
        ``None`` and is asked ``head()``. The record IS stored by now, so a
        read-back that fails must not turn a successful capture into a raised
        one: it is logged, and the counter takes the sequence the record was
        submitted at. A store that answers with no head at all also leaves the
        counter at that sequence, without a log line.
        """
        if isinstance(receipt, dict):
            reported = receipt.get("sequence")
            if isinstance(reported, int) and not isinstance(reported, bool):
                return reported
        try:
            live = await self._storage.head(self._chain_id)
        except Exception as exc:  # diagnostic read; the store already succeeded
            LOG.warning(
                "capture stored_head_readback_failed seq=%d err=%s",
                stored_seq,
                exc,
            )
            return stored_seq
        return live.payload.sequenceNumber if live is not None else stored_seq

    async def _resync_after_refused_store(
        self, exc: BaseException, evidence_id: str, seq: int
    ) -> None:
        """Hand a refused capture's sequence back after a store failure that is
        not a chain conflict.

        The record was NOT written, whatever the reason — a
        :class:`~tzun_sdk.errors.DuplicateEvidenceError`, a wrapped driver
        error, a dropped connection. :meth:`capture` takes its next sequence
        from the live head, so the chain itself cannot be wedged by this; what
        CAN go stale is ``_sequence_counter``, the diagnostic mirror of "the
        store's head as this instance last saw it", and the log. The counter is
        resynced from the store (TS ``resyncChainFromStore()`` runs on ANY
        store failure); if the store cannot even answer ``head()`` — the
        connection is gone — it falls back to the head this attempt was built
        against, which is the last value known to be true. The warning names
        the refusal's ``code`` (``evidence_id_conflict``, ...) or, for an
        untyped error, its class, so an operator counting chain conflicts does
        not count these among them.
        """
        try:
            live_head = await self._storage.head(self._chain_id)
            resynced = live_head.payload.sequenceNumber if live_head is not None else 0
        except Exception:
            resynced = seq - 1
        self._sequence_counter = resynced
        LOG.warning(
            "capture store_refused code=%s evidence_id=%s attempted_seq=%d resynced_to=%d",
            getattr(exc, "code", type(exc).__name__),
            evidence_id,
            seq,
            resynced,
        )

    async def _stored_raw(self, evidence_id: str) -> dict[str, Any] | None:
        """A record's stored JSON (the adapter's ``retrieve_raw``), or the JSON of its model."""
        reader = getattr(self._storage, "retrieve_raw", None)
        if reader is not None:
            raw = await reader(evidence_id)
            return raw if isinstance(raw, dict) else None
        envelope = await self._storage.retrieve(evidence_id)
        if envelope is None:
            return None
        loaded = json.loads(envelope.model_dump_json(by_alias=True))
        return loaded if isinstance(loaded, dict) else None

    async def _predecessor_digest(self, sequence_number: int) -> str | None:
        """The stored digest of the record at ``sequence_number`` on this chain, or ``None``."""
        if sequence_number < 1:
            return None
        reader = getattr(self._storage, "list_raw_by_sequence", None)
        if reader is not None:
            rows = await reader(sequence_number, sequence_number, self._chain_id)
            for row in rows:
                integrity = row.get("integrity") if isinstance(row.get("integrity"), dict) else {}
                digest = integrity.get("canonicalDigest")
                if isinstance(digest, str):
                    return digest
            return None
        found = await self._storage.list_by_sequence(sequence_number, sequence_number, self._chain_id)
        return found[0].integrity.canonicalDigest if found else None

    async def verify(
        self,
        evidence_id: str,
        *,
        allowed_origins: Sequence[str] | None = None,
        allowed_top_origins: Sequence[str] | None = None,
        require_device_bound: bool = False,
    ) -> VerificationResult:
        """Verify a record by id.

        The digest is recomputed over the record's stored JSON, never over a
        model's re-serialisation (Record §3.1). Beside ``valid`` (the digest and the
        chain link), the result carries the record-rule rows of the engine's
        ``verifyEnvelope``, read only where the digest holds: ``decider``,
        ``contributions`` (with ``binding``), ``links`` (with the same-store
        targets resolved and checked), ``mandate``, the ``agents`` resolved
        against the catalog, ``unhashedPayloadMembers``, and ``fieldSet`` on a
        digest that recomputes under an earlier v1.0 field set (which explains
        a mismatch and never excuses it).

        ``allowed_origins``, ``allowed_top_origins`` and
        ``require_device_bound`` are the checks ``assertionProvenance`` runs on
        the record's WebAuthn assertion. Either allowlist
        passed as a bare ``str`` or bytes raises ``TypeError``.
        """
        refuse_bare_string_allowlist("allowed_origins", allowed_origins)
        refuse_bare_string_allowlist("allowed_top_origins", allowed_top_origins)
        self._require_active()
        raw = await self._stored_raw(evidence_id)
        if raw is None:
            raise VerificationError(f"Envelope {evidence_id!r} not found")
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
        integrity = raw.get("integrity") if isinstance(raw.get("integrity"), dict) else {}
        non_repudiation = raw.get("nonRepudiation") if isinstance(raw.get("nonRepudiation"), dict) else {}
        stored_digest = integrity.get("canonicalDigest") if isinstance(integrity.get("canonicalDigest"), str) else ""
        # The schemaVersion check.
        if payload.get("schemaVersion") != "v1.0":
            raise WireFormatMismatch(
                f"Envelope schemaVersion={payload.get('schemaVersion')!r}; SDK supports v1.0 only"
            )
        # The digest over the stored JSON. A payload this implementation
        # cannot canonicalize (a lone surrogate, nesting past MAX_DEPTH) is a
        # payload whose stored digest cannot be true of it.
        payload_serializable = True
        try:
            actual_digest = hashlib.sha256(
                canonical_serialize(payload, list(V1_HASHED_FIELDS)).encode("utf-8")
            ).hexdigest()
        except CanonicalSerializationError:
            payload_serializable = False
            actual_digest = ""
        digest_valid = payload_serializable and hmac.compare_digest(actual_digest, stored_digest)
        # Every contribution step's model resolves in the catalog
        # and its descriptor re-hashes to the digest the step names. A step
        # whose model does not is reported, never raised.
        descriptor_resolved = True
        descriptor_reasons: list[str] = []
        contributions = payload.get("contributions") if isinstance(payload.get("contributions"), dict) else None
        steps = contributions.get("steps") if contributions is not None else None
        for step in steps if isinstance(steps, list) else []:
            bom = step.get("aiBom") if isinstance(step, dict) else None
            if not isinstance(bom, dict):
                continue
            digest = bom.get("modelDescriptorDigest")
            resolved = None
            if isinstance(digest, str):
                resolved = self._descriptor_cache.get(digest)
                if resolved is None:
                    resolved = await self._storage.get_descriptor(digest)
            if resolved is None:
                descriptor_resolved = False
                descriptor_reasons.append("descriptor_resolution_failure")
                continue
            if _descriptor_digest(resolved) != digest:
                descriptor_resolved = False
                descriptor_reasons.append("descriptor_digest_mismatch")
                continue
            self._descriptor_cache.put(digest, resolved)
        # The chain link. A record whose hashed sequenceNumber is
        # above 1 must link to its predecessor, so a null link there fails.
        chain_link_valid: bool | None = None
        stored_link = integrity.get("chainLink")
        seq = payload.get("sequenceNumber")
        prev_seq = int(seq) - 1 if isinstance(seq, (int, float)) and not isinstance(seq, bool) else 0
        prev_digest = await self._predecessor_digest(prev_seq)
        if stored_link is not None:
            if prev_digest is not None:
                expected = compute_chain_link(prev_digest, actual_digest)
                chain_link_valid = isinstance(stored_link, str) and hmac.compare_digest(expected or "", stored_link)
            else:
                chain_link_valid = False
        elif prev_seq >= 1:
            chain_link_valid = False
        reasons: list[str] = []
        if not payload_serializable:
            reasons.append("payload_not_serializable")
        if not digest_valid:
            reasons.append("digest_mismatch")
        if chain_link_valid is False:
            reasons.append("chain_link_mismatch")
        for reason in descriptor_reasons:
            if reason not in reasons:
                reasons.append(reason)
        custody_chain = raw.get("custodyChain") if isinstance(raw.get("custodyChain"), list) else []
        custody = verify_custody_trail(
            custody_chain,
            evidence_id=str(payload.get("evidenceId")),
            canonical_digest=stored_digest,
        )
        # The WebAuthn artifact's binding, checkable with no key: the
        # challenge is a pure function of the digest.
        attestation_verified: bool | None = None
        assertion = non_repudiation.get("webauthnAssertion")
        if isinstance(assertion, dict) and not assertion_binds_digest(assertion, stored_digest):
            attestation_verified = False
            reasons.append("assertion_not_bound_to_digest")
        provenance = (
            assertion_provenance(
                assertion,
                allowed_origins=allowed_origins,
                allowed_top_origins=allowed_top_origins,
                require_device_bound=require_device_bound,
            )
            if isinstance(assertion, dict)
            else None
        )
        # The expectation is authenticated only by the digest over it, so it
        # is read only when that digest holds.
        expectation: dict[str, Any] = (
            check_signoff_expectation(raw) if digest_valid else {"valid": None, "reason": "digest_invalid"}
        )
        resolver = await store_link_resolver(raw, self._storage) if digest_valid else None
        rows = record_rule_fields(raw, digest_valid, expectation, resolver)
        field_set = None if digest_valid else earlier_field_set(payload, stored_digest)
        result = VerificationResult(
            valid=digest_valid and descriptor_resolved and (chain_link_valid is not False),
            evidenceId=evidence_id,
            canonicalDigest=actual_digest,
            chainLinkValid=chain_link_valid,
            descriptorResolved=descriptor_resolved,
            attestationVerified=attestation_verified,
            reasons=reasons,
            custodyTrailValid=custody.valid,
            assertionProvenance=provenance,
            signoffExpectationValid=expectation["valid"],
            signoffExpectationReason=expectation.get("reason"),
            fieldSet=field_set,
            unhashedPayloadMembers=unhashed_payload_members(payload),
            decider=rows["decider"],
            contributions=rows["contributions"],
            links=rows["links"],
            mandate=rows.get("mandate"),
            agents=await resolve_agent_references(raw, self._storage),
        )
        self._events.dispatch(
            TzunEvent(
                event_type="verification_completed",
                timestamp=_utcnow_iso(),
                payload={"evidenceId": evidence_id, "valid": result.valid},
            )
        )
        return result

    async def verify_range(
        self, from_n: int, to_n: int
    ) -> list[VerificationResult]:
        """Verify every envelope in the sequence range [from_n, to_n]."""
        self._require_active()
        results: list[VerificationResult] = []
        # Chain-scoped and unpaged: self._storage.list() defaults to limit=100
        # on the SQL adapters, which silently truncated any range past
        # sequence 100.
        reader = getattr(self._storage, "list_raw_by_sequence", None)
        if reader is not None:
            ids = [
                r["payload"]["evidenceId"]
                for r in await reader(from_n, to_n, self._chain_id)
                if isinstance(r.get("payload"), dict) and isinstance(r["payload"].get("evidenceId"), str)
            ]
        else:
            ids = [e.payload.evidenceId for e in await self._storage.list_by_sequence(from_n, to_n, self._chain_id)]
        for evidence_id in ids:
            results.append(await self.verify(evidence_id))
        return results

    async def export_evidence(
        self,
        evidence_id: str,
        *,
        walk_lineage: bool = True,
        exported_by: str = "tzun-sdk",
    ) -> ExportedEvidenceEnvelope:
        """Court-ready bundle: envelope + every step model's descriptor (+ ancestor DAG when
        walk_lineage, the default), the agent descriptors (Record §6.9) the record
        names, the record's predecessor, and the verdict on it. Mirrors TS
        exportEvidence.

        The Python adapters keep no custody ledger, so ``custody.entries`` and
        ``custody.trail`` are ``None``, ``verdict.custodyTrail`` is unmeasured
        (``no_custody_ledger``), and ``custody.offlineTrail`` — the envelope-only
        check — is what there is. A record that fails its checks is exported
        with an invalid verdict, not refused."""
        self._require_active()
        raw = await self._stored_raw(evidence_id)
        if raw is None:
            raise TzunError(
                f'Evidence record "{evidence_id}" not found. '
                "Cannot export a non-existent record."
            )
        envelope = EvidenceEnvelope.model_validate(raw)
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
        resolved_model_descriptors: dict[str, Any] = {}
        queue: list[str] = []
        contributions = payload.get("contributions") if isinstance(payload.get("contributions"), dict) else None
        for step in (contributions or {}).get("steps") or []:
            bom = step.get("aiBom") if isinstance(step, dict) else None
            digest = bom.get("modelDescriptorDigest") if isinstance(bom, dict) else None
            if isinstance(digest, str) and digest not in queue:
                queue.append(digest)
        seen: set[str] = set()
        walk_budget = 16 * max(1, len(queue))
        while queue and len(seen) < walk_budget:
            digest = queue.pop(0)
            if digest in seen:
                continue
            seen.add(digest)
            descriptor = await self._storage.get_descriptor(digest)
            if descriptor is None:
                resolved_model_descriptors[digest] = ExportedDescriptorEntryMissing(
                    canonicalBytes="",
                    enrichedView=None,
                    annotations=[],
                    missing=True,
                )
                continue
            annotations = await self._storage.list_model_descriptor_annotations(digest)
            row = None
            for r in await self._storage.list_model_descriptors():
                if r.modelDescriptorDigest == digest:
                    row = r
                    break
            canonical_bytes = row.canonicalBytes if row is not None else ""
            enriched = await self._storage.get_enriched_model_descriptor(digest)
            resolved_model_descriptors[digest] = ExportedDescriptorEntryPresent(
                canonicalBytes=canonical_bytes,
                enrichedView=enriched or descriptor,
                annotations=annotations,
                missing=False,
            )
            if walk_lineage and descriptor.parentModelDescriptorDigest:
                queue.append(descriptor.parentModelDescriptorDigest)
        resolved_agent_descriptors: dict[str, Any] = {}
        if hasattr(self._storage, "get_agent_descriptor"):
            for ref in await resolve_agent_references(raw, self._storage):
                try:
                    row_a = await self._storage.get_agent_descriptor(ref["reference"])
                except InvalidAgentDescriptorError as exc:
                    # A store whose catalog methods answer that it keeps none.
                    if exc.code != "agent_not_supported_by_store":
                        raise
                    break
                if row_a is not None:
                    resolved_agent_descriptors[ref["reference"]] = row_a.canonicalBytes
        predecessor: dict[str, Any] | None = None
        predecessor_input: dict[str, Any]
        try:
            prev = await self._predecessor_of(envelope)
            if prev is not None:
                predecessor = {
                    "evidenceId": prev.payload.evidenceId,
                    "sequenceNumber": prev.payload.sequenceNumber,
                    "canonicalDigest": prev.integrity.canonicalDigest,
                }
            predecessor_input = {"digest": predecessor["canonicalDigest"] if predecessor else None}
        # Deliberately broad: a neighbour that cannot be read must not refuse the
        # export. The record itself is exportable without its predecessor; the
        # bundle just cannot offer an offline chain-link recomputation, and says
        # so by carrying the error instead of the digest.
        except Exception as exc:
            predecessor_input = {"error": str(exc)}
        nr = raw.get("nonRepudiation") if isinstance(raw.get("nonRepudiation"), dict) else {}
        assertion = nr.get("webauthnAssertion") if isinstance(nr.get("webauthnAssertion"), dict) else None
        bundle: dict[str, Any] = {
            "envelope": envelope,
            "resolvedModelDescriptors": resolved_model_descriptors,
            "exportedAt": _utcnow_iso(),
            "exportedBy": exported_by,
            "verdict": _export_verdict(raw, predecessor_input),
            "chain": {"chainId": self._chain_id, "predecessor": predecessor},
            "custody": {
                "hashPreimage": CUSTODY_ENTRY_HASH_PREIMAGE,
                "entries": None,
                "trail": None,
                "offlineTrail": verify_custody_trail(
                    raw.get("custodyChain") if isinstance(raw.get("custodyChain"), list) else [],
                    evidence_id=str(payload.get("evidenceId")),
                    canonical_digest=str(raw.get("integrity", {}).get("canonicalDigest", "")),
                ),
            },
            "assertionProvenance": assertion_provenance(assertion) if assertion else None,
        }
        if resolved_agent_descriptors and "resolvedAgentDescriptors" in ExportedEvidenceEnvelope.model_fields:
            bundle["resolvedAgentDescriptors"] = resolved_agent_descriptors
        return ExportedEvidenceEnvelope.model_validate(bundle)

    async def _predecessor_of(self, envelope: EvidenceEnvelope) -> EvidenceEnvelope | None:
        """The record at the previous sequence of this instance's chain, or None."""
        prev_seq = envelope.payload.sequenceNumber - 1
        if prev_seq < 1:
            return None
        found = await self._storage.list_by_sequence(prev_seq, prev_seq, self._chain_id)
        return next((e for e in found if e.payload.sequenceNumber == prev_seq), None)

    # ── Namespaces ───────────────────────────────────────────────

    @property
    def models(self) -> _ModelsNamespace:
        return self._models_ns

    @property
    def recovery(self) -> _RecoveryNamespace:
        return self._recovery_ns

    @property
    def agents(self) -> AgentsNamespace:
        """The agent catalog (Record §6.9): ``register``, ``get``, ``list``."""
        return self._agents_ns

    @property
    def links(self) -> LinksNamespace:
        """Links between records (Record §8): ``relate``, ``of``, ``to``."""
        return self._links_ns

    @property
    def deciders(self) -> DecidersNamespace:
        """Decider commitment openings (Record §6.3): ``opening``."""
        return self._deciders_ns

    @property
    def decision_graph(self) -> DecisionGraphNamespace:
        """The bounded walk over a record's links and the link records that name it."""
        return self._decision_graph_ns

    @property
    def mandates(self) -> MandatesNamespace:
        """Mandates (Record §9.6): ``prepare``, ``issue``, ``revoke``, ``confirm``, ``get``, ``events``."""
        return self._mandates_ns

    @property
    def descriptor_cache(self) -> _DescriptorCacheNamespace:
        return self._descriptor_cache_ns

    @property
    def descriptor_cache_obj(self) -> DescriptorCache:
        """Internal accessor for the underlying cache; used by ``hook()``."""
        return self._descriptor_cache

    @property
    def state(self) -> str:
        return self._state

    def on_event(self, cb: TzunEventCallback) -> Any:
        """Register an event callback. Returns an unsubscribe fn."""
        return self._events.subscribe(cb)

    def attach(self, client: Any, *, vendor: str | None = None) -> Any:
        """Wrap a vendor client via :func:`tzun_sdk.attach`."""
        from tzun_sdk.ai_bom.attach import attach as _attach

        return _attach(client, tzun=self, vendor=vendor)

    # ── Helpers ──────────────────────────────────────────────────

    def _require_active(self) -> None:
        if self._state != ACTIVE:
            raise TzunError(f"Tzun instance is {self._state.lower()}")

    def _check_admin_token(self, token: str | None) -> None:
        """Constant-time admin-token check."""
        if self._admin_token is None:
            return
        if token is None or not hmac.compare_digest(self._admin_token, token):
            raise AdminTokenRequiredError(
                "Admin-gated operation requires a matching admin token."
            )


class TzunSync:
    """Sync mirror of :class:`Tzun`.

    Bridges via ``anyio.from_thread.run`` when called from inside a running
    event loop, otherwise ``anyio.run``. Avoids ``asyncio.run`` directly
    because that breaks nested-loop callers.
    """

    def __init__(self, inner: Tzun) -> None:
        self._inner = inner
        # Serialises `capture()` across THREADS. Each sync call drives its own
        # event loop (`anyio.run`), and the inner `Tzun._sequence_lock` is an
        # `asyncio.Lock`: its acquire is a plain check-then-set with no
        # cross-thread guarantee, and a waiter it parks is a future on the
        # waiting thread's loop that the releasing thread cannot wake safely.
        # Without this lock, two threads capturing on one `TzunSync` would
        # either both be inside the critical section (N-way contention on the
        # chain head, see `Tzun.capture`) or one of them would park for good.
        # This lock is the sync wrapper's `runCaptureExclusive`.
        self._lock = threading.Lock()

    @classmethod
    def init(
        cls,
        *,
        storage: StorageAdapter,
        admin_token: str | None = None,
        descriptor_cache_size: int = DEFAULT_CACHE_SIZE,
        chain_id: str | None = None,
        attestation_backends: list[Any] | None = None,
        chain_conflict_max_attempts: int = DEFAULT_CHAIN_CONFLICT_MAX_ATTEMPTS,
        freshness_chain: str | None = None,
        freshness_max_age_ms: int = DEFAULT_FRESHNESS_MAX_AGE_MS,
        assertion_verifier: Any = None,
        assertion_timestamper: Any = None,
    ) -> TzunSync:
        # ``Tzun.init`` is keyword-only and ``anyio.run`` forwards *args
        # only, so the call MUST be wrapped — handing these over
        # positionally raises TypeError before any work happens.
        inner = anyio.run(
            functools.partial(
                Tzun.init,
                storage=storage,
                admin_token=admin_token,
                descriptor_cache_size=descriptor_cache_size,
                chain_id=chain_id,
                attestation_backends=attestation_backends,
                chain_conflict_max_attempts=chain_conflict_max_attempts,
                freshness_chain=freshness_chain,
                freshness_max_age_ms=freshness_max_age_ms,
                assertion_verifier=assertion_verifier,
                assertion_timestamper=assertion_timestamper,
            )
        )
        return cls(inner)

    def capture(self, **kwargs: Any) -> CaptureResult:
        with self._lock:
            return cast("CaptureResult", _run_async(self._inner.capture, **kwargs))

    def prepare_assertion_challenge(self, **kwargs: Any) -> dict[str, Any]:
        return cast("dict[str, Any]", _run_async(self._inner.prepare_assertion_challenge, **kwargs))

    def verify(
        self,
        evidence_id: str,
        *,
        allowed_origins: Sequence[str] | None = None,
        allowed_top_origins: Sequence[str] | None = None,
        require_device_bound: bool = False,
    ) -> VerificationResult:
        return cast(
            "VerificationResult",
            _run_async(
                self._inner.verify,
                evidence_id,
                allowed_origins=allowed_origins,
                allowed_top_origins=allowed_top_origins,
                require_device_bound=require_device_bound,
            ),
        )

    def verify_range(self, from_n: int, to_n: int) -> list[VerificationResult]:
        return cast(
            "list[VerificationResult]",
            _run_async(self._inner.verify_range, from_n, to_n),
        )

    def close(self) -> None:
        _run_async(self._inner.close)

    def on_event(self, cb: TzunEventCallback) -> Any:
        return self._inner.on_event(cb)

    def attach(self, client: Any, *, vendor: str | None = None) -> Any:
        return self._inner.attach(client, vendor=vendor)

    @property
    def models(self) -> _ModelsNamespace:
        return self._inner.models

    @property
    def recovery(self) -> _RecoveryNamespace:
        return self._inner.recovery

    @property
    def descriptor_cache(self) -> _DescriptorCacheNamespace:
        return self._inner.descriptor_cache

    @property
    def agents(self) -> _SyncNamespace:
        """:attr:`Tzun.agents`, each method called synchronously."""
        return _SyncNamespace(self._inner.agents, self._lock, writes=())

    @property
    def links(self) -> _SyncNamespace:
        """:attr:`Tzun.links`; ``relate`` appends a link record under the capture lock."""
        return _SyncNamespace(self._inner.links, self._lock, writes=("relate",))

    @property
    def deciders(self) -> _SyncNamespace:
        """:attr:`Tzun.deciders`, each method called synchronously."""
        return _SyncNamespace(self._inner.deciders, self._lock, writes=())

    @property
    def decision_graph(self) -> _SyncNamespace:
        """:attr:`Tzun.decision_graph`, each method called synchronously."""
        return _SyncNamespace(self._inner.decision_graph, self._lock, writes=())

    @property
    def mandates(self) -> _SyncNamespace:
        """:attr:`Tzun.mandates`; the methods that append a record or move a mandate take the capture lock."""
        return _SyncNamespace(self._inner.mandates, self._lock, writes=("issue", "revoke", "confirm", "expire_due"))


class _SyncNamespace:
    """A namespace of :class:`Tzun` whose coroutine methods :class:`TzunSync` runs to completion.

    The methods named in ``writes`` append to the chain or move a mandate, so
    they hold the same thread lock as :meth:`TzunSync.capture`.
    """

    def __init__(self, inner: Any, lock: threading.Lock, *, writes: Sequence[str]) -> None:
        self._inner = inner
        self._lock = lock
        self._writes = frozenset(writes)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if name.startswith("_") or not asyncio.iscoroutinefunction(attr):
            return attr

        @functools.wraps(attr)
        def call(*args: Any, **kwargs: Any) -> Any:
            if name in self._writes:
                with self._lock:
                    return _run_async(attr, *args, **kwargs)
            return _run_async(attr, *args, **kwargs)

        return call


def _run_async(coro_fn: Any, /, *args: Any, **kwargs: Any) -> Any:
    """Run ``coro_fn(*args, **kwargs)`` from sync context, anyio-bridged.

    Used by :class:`TzunSync` to avoid raw ``asyncio.run``.
    """
    # Neither ``anyio.run`` nor ``anyio.from_thread.run`` forwards keyword
    # arguments, so the call is always bound up front.
    bound = functools.partial(coro_fn, *args, **kwargs)
    try:
        # If there's a running event loop, anyio.from_thread.run bridges.
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop — fresh anyio.run is correct.
        return anyio.run(bound)
    # Inside a running loop — use from_thread (uncommon for TzunSync but
    # supports the "Django sync view from inside ASGI" edge case). This
    # only works from an anyio worker thread or a BlockingPortal; on the
    # loop thread itself anyio raises, which is the correct outcome.
    return anyio.from_thread.run(bound)


__all__ = ("Tzun", "TzunSync")
