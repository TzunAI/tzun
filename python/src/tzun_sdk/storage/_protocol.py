"""Storage adapter Protocol.

PEP 544 ``Protocol`` declaring the async surface every storage adapter
implements. It is a SUBSET of the TypeScript ``StorageAdapter`` interface at
``packages/engine/src/types/storage-interface.ts``, with snake_case
method names: the ~20 methods below out of the TS interface's ~45. Not
declared here, and not implemented by any Python adapter: ``getLastDigest`` /
``getLastSequence``, ``updateAttestation``, chain identity and sealing, the
incident reads and status updates, ``getChainForRecord``, and the recovery
reads. Where a method IS shared it behaves identically across the Python
adapters — ``python/tests/storage/test_conformance.py`` asserts that against
memory, SQLite (both modes) and Postgres (both modes) — but NOT necessarily
identically to its TypeScript namesake; see :meth:`StorageAdapter.list` and
:meth:`StorageAdapter.head`.

The optional ``delete_envelope_for_demo`` method is for demos only;
production adapters refuse to execute it unless ``TZUN_ENABLE_DEMO_DELETE``
is set in the environment at import time.
"""

from __future__ import annotations

import builtins
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from tzun_sdk.models import (
    AnnotationRecord,
    AttestationArtifacts,
    EvidenceEnvelope,
    ForkRecord,
    ModelDescriptor,
    ModelDescriptorAnnotationRow,
    ModelDescriptorRow,
    RelinkRecord,
    StoreOptions,
    TamperIncident,
)
from tzun_sdk.storage._revision_log import EnvelopeRevision


@runtime_checkable
class StorageAdapter(Protocol):
    """Storage adapter surface.

    Every method is async. Implementations may be backed by an in-process
    dict, a SQL database, or a remote HTTP service. The Protocol is the
    single point of contract.
    """

    # ── Envelopes ────────────────────────────────────────────────────
    async def store(
        self,
        envelope: EvidenceEnvelope,
        chain_id: str | None = None,
        options: StoreOptions | None = None,
    ) -> None:
        """Persist a new envelope. Append-only — no updates or deletes.

        ``options.expectChainHead`` makes the write a compare-and-swap: the
        adapter MUST refuse the store — atomically, against the live head,
        inside whatever makes its write atomic — unless the chain head is
        exactly that. :meth:`~tzun_sdk.core.Tzun.capture` always supplies it,
        because a record's sequence number and chain link are hashed into its
        digest and therefore have to be chosen before the write; if the head
        moved in between, the record no longer belongs at that position.

        Omit it for a low-level store that is not a chain append (imports,
        test fixtures, recovery flows) — the adapter then writes
        unconditionally, as it always has.
        ``ChainHead(sequence=0, digest=None)`` means "the chain must still be
        empty".

        Mirrors ``StoreOptions.expectChainHead`` in
        ``packages/engine/src/types/storage-interface.ts``.

        Raises:
            ChainConflictError: if the live head differs from
                ``options.expectChainHead``.
            DuplicateEvidenceError: if a record with this ``evidenceId`` is
                already stored (append-only; checked before the head CAS, so
                a duplicate is never reported as a chain conflict).
                :meth:`~tzun_sdk.core.Tzun.capture` relies on this being
                raised, and not swallowed, to hand the sequence back.
        """

    async def retrieve(self, evidence_id: str) -> EvidenceEnvelope | None:
        """Retrieve an envelope by ``evidenceId``. Returns ``None`` if absent."""

    async def list(self, **options: Any) -> list[EvidenceEnvelope]:
        """A page of envelopes across every chain, ordered by ``sequenceNumber``.

        ``limit`` defaults to **100 on every adapter** and ``offset`` to 0;
        nothing in the return value says whether the page was full. It is
        therefore unsuitable for any integrity check — use
        :meth:`list_by_sequence`, which is chain-scoped and unpaged. (A survey
        of a chain through this call is silently short past 100 records.)

        CROSS-LANGUAGE: this is NOT the same call as TypeScript
        ``StorageAdapter.list()``, which has no default limit, orders by the
        instant of ``capturedAt`` (ties by ``sequenceNumber``, ``evidenceId``)
        and filters by ``aiSystemId`` / ``chainId`` / ``order``. Same name,
        different meaning. Proposed for the wire-format window (not renamed
        here): rename this one ``list_page`` and give it the TS sort key and
        filters, or expose TS's semantics under ``list`` and move today's
        paged sequence view to ``list_by_sequence`` callers. Until then the
        two must not be assumed interchangeable.
        """

    async def list_by_sequence(
        self,
        from_sequence: int | None = None,
        to_sequence: int | None = None,
        chain_id: str | None = None,
    ) -> builtins.list[EvidenceEnvelope]:
        """Return the envelopes of one chain within an inclusive sequence range.

        Mirrors the TypeScript ``StorageAdapter.listBySequence`` (see
        ``packages/engine/src/types/storage-interface.ts``). Unlike
        :meth:`list` this is chain-scoped, unpaged and ordered by
        ``sequenceNumber`` ascending, which is what the chain-link and
        chain-completeness checks require.

        Divergence from TS: TS treats an omitted ``chainId`` as "no chain
        filter"; the Python adapters resolve ``None`` to the default chain,
        exactly as :meth:`store` and :meth:`head` already do.

        :param from_sequence: Inclusive lower bound. Defaults to 1.
        :param to_sequence: Inclusive upper bound. ``None`` means unbounded.
        :param chain_id: Chain to scope to; ``None`` means the default chain.
        """

    async def head(self, chain_id: str | None = None) -> EvidenceEnvelope | None:
        """The record with the highest ``sequenceNumber`` on ``chain_id``, or ``None``.

        ``chain_id`` ``None`` means the default chain. On an equal sequence
        number the later insert wins. Identical on every Python adapter.

        CROSS-LANGUAGE: TypeScript ``head()`` takes no chain, ignores chains
        entirely, and returns the last-inserted record store-wide (rowid /
        insertion order). Same name, different meaning; see :meth:`list`.
        """

    async def ensure_tables(self) -> None:
        """Idempotently create required schema. No-op on Memory."""

    async def close(self) -> None:
        """Release resources (pool connections, HTTP session)."""

    # ── Catalog (descriptors) ────────────────────────────────────────
    async def register_descriptor(self, descriptor: ModelDescriptor) -> str:
        """Register a ModelDescriptor in the catalog; return its digest."""

    async def get_descriptor(self, digest: str) -> ModelDescriptor | None:
        """Fetch a ModelDescriptor by digest, or ``None`` on miss."""

    # ── Attestation ──────────────────────────────────────────────────
    async def store_attestation(
        self, evidence_id: str, blob: AttestationArtifacts
    ) -> None:
        """Attach an attestation artifact to an existing envelope."""

    async def get_attestations(self, evidence_id: str) -> builtins.list[AttestationArtifacts]:
        """Return all attestation artifacts for an envelope."""

    # ── The append-only revision log ──────────────────
    async def list_envelope_revisions(
        self, evidence_id: str
    ) -> builtins.list[EnvelopeRevision]:
        """Every revision row for one record, in ``revision_no`` order."""

    async def get_capture_digests(self, evidence_ids: Sequence[str]) -> dict[str, str]:
        """``evidenceId -> capture digest``, omitting ids with no revision 0.

        Absence means "this store cannot speak for that record" — a record
        captured before the log existed — and must never be read as "clean".
        """

    # ── Recovery ─────────────────────────────────────────────────────
    async def store_annotation(self, record: AnnotationRecord) -> None: ...

    async def store_relink(self, record: RelinkRecord) -> None: ...

    async def store_fork(self, record: ForkRecord) -> None: ...

    # ── Monitoring ───────────────────────────────────────────────────
    async def store_incident(self, incident: TamperIncident) -> None: ...

    # ── Catalog primitives (mirror the catalog methods of TS storage-interface.ts;
    #    policy lives in tzun_sdk.catalog, NEVER here) ──────────────────────────
    async def list_model_descriptors(
        self, vendor: str | None = None, limit: int | None = None, offset: int | None = None
    ) -> builtins.list[ModelDescriptorRow]: ...

    async def list_model_descriptor_annotations(
        self, digest: str
    ) -> builtins.list[ModelDescriptorAnnotationRow]: ...

    async def append_model_descriptor_annotation(
        self, row: ModelDescriptorAnnotationRow
    ) -> None: ...

    async def set_model_descriptor_alias(self, slug: str, digest: str, set_by: str) -> None: ...

    async def resolve_model_descriptor_alias(self, slug: str) -> str | None: ...

    async def get_enriched_model_descriptor(self, digest: str) -> ModelDescriptor | None: ...

    # ── Demo-only ────────────────────────────────────────────────────
    async def delete_envelope_for_demo(self, evidence_id: str) -> None:
        """Delete one envelope. Demo-only; raises in production builds."""
