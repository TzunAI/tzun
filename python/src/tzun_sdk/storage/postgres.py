"""PostgreSQL storage adapter.

Two execution paths:

* Async via ``asyncpg``.
* Sync via ``psycopg`` + ``psycopg_pool``.

Both paths share the ``pg_advisory_lock(2026052501)`` key with the TS
adapter so concurrent init from a mixed-language deployment
serializes correctly.

This module is a thin shell that raises ``MissingExtraError`` if the
``[postgres]`` extra is not installed. The DDL is inline below, NOT in
``schema/migrations/postgres/`` — that directory has never existed —
and it is NOT the TS adapter's schema. The two SDKs create different evidence
tables (``evidence_envelopes`` here, ``envelopes`` there) and only the AI-BOM
catalog tables are genuinely shared. See ``python/MIGRATION.md``.

There is also no database-level append-only enforcement here, unlike the TS
adapter's H15 triggers: these rows can be UPDATEd or DELETEd by any principal
with write access. Tampering is detected by the chain digest, not prevented by
the schema.
"""

from __future__ import annotations

import builtins
import contextlib
import datetime as _dt
import os
import re
import secrets
from collections.abc import AsyncIterator, Sequence
from typing import Any

from tzun_sdk.agents import agent_descriptor_digest, canonical_serialize_agent_descriptor
from tzun_sdk.errors import (
    ChainConflictError,
    DuplicateEvidenceError,
    MandateClaimConflictError,
    MandateRefusedError,
    MissingExtraError,
    TzunError,
)
from tzun_sdk.models import (
    AgentDescriptorRow,
    AnnotationRecord,
    AttestationArtifacts,
    ChainHead,
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
from tzun_sdk.storage._chain_head_guard import (
    CHAIN_APPEND_LOCK_KEY,
    assert_chain_head,
    head_of,
)
from tzun_sdk.storage._extension_ddl import POSTGRES_EXTENSION_DDL
from tzun_sdk.storage._records import (
    MANDATE_COLUMNS,
    DeciderOpeningMismatchError,
    capture_actor_of,
    chain_link_of,
    check_mandate_claim,
    check_mandate_transition,
    digest_of,
    envelope_json,
    event_row_from,
    evidence_id_of,
    link_index_rows,
    mandate_row_from,
    mandate_row_values,
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
    revision_from_row,
)
from tzun_sdk.storage._store_ends import stored_json
from tzun_sdk.storage.memory import _utcnow_iso

ADVISORY_LOCK_KEY = 2026052501


def _require_asyncpg() -> Any:
    try:
        import asyncpg

        return asyncpg
    except ImportError as exc:
        raise MissingExtraError(
            "PostgresAdapter async path requires the 'postgres' extra: "
            "pip install 'tzun-sdk[postgres]'"
        ) from exc


def _require_psycopg() -> tuple[Any, Any]:
    try:
        import psycopg
        from psycopg_pool import ConnectionPool

        return psycopg, ConnectionPool
    except ImportError as exc:
        raise MissingExtraError(
            "PostgresAdapter sync path requires the 'postgres' extra: "
            "pip install 'tzun-sdk[postgres]'"
        ) from exc


def _stored_object(text: Any) -> dict[str, Any]:
    """A stored row's JSON object; a row that is not one reads as an empty record."""
    loaded = stored_json(text) if isinstance(text, str) else text
    return loaded if isinstance(loaded, dict) else {}


def _is_evidence_unique_violation(exc: BaseException) -> bool:
    """True when ``exc`` is the driver's unique-violation on ``evidence_envelopes``.

    asyncpg puts ``sqlstate`` / ``table_name`` / ``constraint_name`` on the
    exception itself; psycopg puts the last two on ``exc.diag``. Both shapes
    are read so the translation does not depend on which driver built the
    adapter.

    Scoped to the PRIMARY KEY, not the table: ``DuplicateEvidenceError`` names
    the evidence id as the cause, and only ``evidence_envelopes_pkey`` says
    that. A 23505 on the same table from any other unique constraint (none
    exists today; a ``UNIQUE (chain_id, sequence_number)`` is the obvious
    future one) is a different fact — a sequence collision, not a reused id —
    and keeps its generic wrapping rather than telling the caller to pick a
    new id. The table name is consulted only when the server omits the
    constraint name, which Postgres does not do for a unique violation but a
    proxy or an older driver might.
    """
    if getattr(exc, "sqlstate", None) != "23505":
        return False
    diag = getattr(exc, "diag", None)
    table = getattr(exc, "table_name", None) or getattr(diag, "table_name", None)
    constraint = getattr(exc, "constraint_name", None) or getattr(
        diag, "constraint_name", None
    )
    if constraint is not None:
        return constraint == "evidence_envelopes_pkey"
    return table == "evidence_envelopes"



#: The 0.8.0 statements, each a literal: bandit's B608 refuses SQL built at run time.
_SQL_MANDATE_BY_ID = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates WHERE mandate_id = $1"
)
_SQL_MANDATE_BY_ID_LOCKED = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates WHERE mandate_id = $1 FOR UPDATE"
)
_SQL_MANDATE_BY_DIGEST = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates WHERE mandate_digest = $1"
)
_SQL_MANDATES = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates ORDER BY created_at"
)
_SQL_MANDATES_IN_STATE = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates WHERE state = $1 ORDER BY created_at"
)
_SQL_INSERT_MANDATE = (
    "INSERT INTO tzun_py_mandates (mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at) "
    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)"
)
_SQL_AGENT_BY_DIGEST = "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors WHERE digest = $1"
_SQL_AGENTS = {
    (False, False): "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors "
    "ORDER BY registered_at, digest LIMIT $1 OFFSET $2",
    (True, False): "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors WHERE name = $1 "
    "ORDER BY registered_at, digest LIMIT $2 OFFSET $3",
    (False, True): "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors WHERE organization = $1 "
    "ORDER BY registered_at, digest LIMIT $2 OFFSET $3",
    (True, True): "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors WHERE name = $1 AND organization = $2 "
    "ORDER BY registered_at, digest LIMIT $3 OFFSET $4",
}
_SQL_LINKS_TO = (
    "SELECT l.evidence_id, l.idx, l.rel, l.target_digest FROM tzun_py_evidence_links l "
    "JOIN evidence_envelopes e ON e.evidence_id = l.evidence_id "
    "WHERE l.target_digest = $1 {statements}ORDER BY e.created_at, e.evidence_id, l.idx LIMIT $2 OFFSET $3"
)
_SQL_LINKS_TO_RELS = (
    "SELECT l.evidence_id, l.idx, l.rel, l.target_digest FROM tzun_py_evidence_links l "
    "JOIN evidence_envelopes e ON e.evidence_id = l.evidence_id "
    "WHERE l.target_digest = $1 AND l.rel = ANY($2::text[]) {statements}"
    "ORDER BY e.created_at, e.evidence_id, l.idx LIMIT $3 OFFSET $4"
)
#: The filter ``statements=True`` adds: the statements of link records only.
_SQL_STATEMENTS_ONLY = "AND l.subject_digest IS NOT NULL "

_PLACEHOLDER = re.compile(r"\$[0-9]+")


class _PgExec:
    """One connection, either driver, behind the same awaitable calls (``$n`` placeholders)."""

    def __init__(self, conn: Any, is_async: bool) -> None:
        self._conn = conn
        self._async = is_async

    def _sync_sql(self, sql: str) -> str:
        return _PLACEHOLDER.sub("%s", sql.replace("%", "%%"))

    async def one(self, sql: str, params: Sequence[Any] = ()) -> Any:
        if self._async:
            return await self._conn.fetchrow(sql, *params)
        return self._conn.execute(self._sync_sql(sql), tuple(params)).fetchone()

    async def all(self, sql: str, params: Sequence[Any] = ()) -> builtins.list[Any]:
        if self._async:
            return builtins.list(await self._conn.fetch(sql, *params))
        return builtins.list(self._conn.execute(self._sync_sql(sql), tuple(params)).fetchall())

    async def run(self, sql: str, params: Sequence[Any] = ()) -> None:
        if self._async:
            await self._conn.execute(sql, *params)
        else:
            self._conn.execute(self._sync_sql(sql), tuple(params))


class PostgresAdapter:
    """Postgres storage adapter.

    Constructor:
        ``PostgresAdapter(dsn: str, pool_size: int = 10, mode: 'async' | 'sync' = 'async')``

    See the TS reference ``src/storage/postgres.ts`` for DDL parity and
    the advisory-lock pattern.
    """

    def __init__(
        self,
        dsn: str,
        pool_size: int = 10,
        mode: str = "async",
    ) -> None:
        if mode not in ("async", "sync"):
            raise TzunError(f"PostgresAdapter: mode must be 'async' or 'sync', got {mode!r}")
        self._dsn = dsn
        self._pool_size = pool_size
        self._mode = mode
        self._async_pool: Any | None = None
        self._sync_pool: Any | None = None
        self._closed = False  # set by close(); every operation checks it first
        if mode == "async":
            self._asyncpg = _require_asyncpg()
        else:
            self._psycopg, self._ConnectionPool = _require_psycopg()

    def _check_not_closed(self) -> None:
        """Raise TzunError if close() has already been called."""
        if self._closed:
            raise TzunError("PostgresAdapter has been closed; create a new instance to reconnect.")

    async def _ensure_async_pool(self) -> Any:
        self._check_not_closed()
        if self._async_pool is None:
            self._async_pool = await self._asyncpg.create_pool(
                dsn=self._dsn,
                min_size=1,
                max_size=self._pool_size,
            )
        return self._async_pool

    def _ensure_sync_pool(self) -> Any:
        self._check_not_closed()
        if self._sync_pool is None:
            self._sync_pool = self._ConnectionPool(
                conninfo=self._dsn,
                min_size=1,
                max_size=self._pool_size,
            )
        return self._sync_pool

    async def ensure_tables(self) -> None:
        # Acquire pg_advisory_lock to serialize concurrent init.
        # Use a direct (non-pool) connection so the advisory lock state doesn't
        # interfere with the pool's connection-reset protocol on release.
        ddl = _POSTGRES_DDL + "\n" + POSTGRES_EXTENSION_DDL
        if self._mode == "async":
            asyncpg = self._asyncpg
            conn = await asyncpg.connect(dsn=self._dsn)
            try:
                await conn.execute(f"SELECT pg_advisory_lock({ADVISORY_LOCK_KEY})")
                try:
                    await conn.execute(ddl)
                finally:
                    await conn.execute(f"SELECT pg_advisory_unlock({ADVISORY_LOCK_KEY})")
            finally:
                await conn.close()
        else:
            pool = self._ensure_sync_pool()
            with pool.connection() as conn:
                conn.execute(f"SELECT pg_advisory_lock({ADVISORY_LOCK_KEY})")
                try:
                    conn.execute(ddl)
                finally:
                    conn.execute(f"SELECT pg_advisory_unlock({ADVISORY_LOCK_KEY})")

    #: Append-only guard, run inside the transaction that holds the
    #: chain-append advisory lock, so no other Tzun writer can insert the id
    #: between this check and the INSERT. A writer that does not take the
    #: lock still cannot get past the primary key; that path is translated
    #: by :func:`_is_evidence_unique_violation` above.
    _SELECT_EXISTING_SQL = "SELECT 1 FROM evidence_envelopes WHERE evidence_id = $1"

    #: Head-of-chain lookup used by the conditional-append compare-and-swap.
    #: Same predicate as :meth:`head`, run inside the transaction that holds
    #: the chain-append advisory lock.
    _HEAD_FOR_CAS_SQL = (
        "SELECT sequence_number, envelope_json::text FROM evidence_envelopes "
        "WHERE chain_id = $1 ORDER BY sequence_number DESC LIMIT 1"
    )

    @staticmethod
    def _head_from_row(row: Any) -> ChainHead:
        if row is None:
            return head_of(0, None)
        return head_of(row[0], digest_of(_stored_object(row[1])))

    @contextlib.asynccontextmanager
    async def _transaction(self) -> AsyncIterator[_PgExec]:
        """One transaction on a pooled connection, either driver."""
        if self._mode == "async":
            pool = await self._ensure_async_pool()
            async with pool.acquire() as conn, conn.transaction():
                yield _PgExec(conn, True)
        else:
            sync_pool = self._ensure_sync_pool()
            with sync_pool.connection() as conn, conn.transaction():
                yield _PgExec(conn, False)

    @contextlib.asynccontextmanager
    async def _connection(self) -> AsyncIterator[_PgExec]:
        """A pooled connection for reads, either driver."""
        if self._mode == "async":
            pool = await self._ensure_async_pool()
            async with pool.acquire() as conn:
                yield _PgExec(conn, True)
        else:
            sync_pool = self._ensure_sync_pool()
            with sync_pool.connection() as conn:
                yield _PgExec(conn, False)

    #: The capture revision, written in the SAME transaction as
    #: the record it describes. ON CONFLICT DO NOTHING because a record that
    #: was deleted and re-stored under the same id keeps the capture revision
    #: it already has — overwriting it would let a rewritten copy redefine
    #: what the record was captured as.
    _INSERT_REVISION_SQL = (
        "INSERT INTO envelope_revisions "
        "(evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7) "
        "ON CONFLICT (evidence_id, revision_no) DO NOTHING"
    )

    _SELECT_REVISIONS_SQL = (
        "SELECT evidence_id, revision_no, canonical_digest, chain_link, recorded_at, "
        "cause, actor FROM envelope_revisions WHERE evidence_id = $1 ORDER BY revision_no ASC"
    )

    _SELECT_CAPTURE_DIGESTS_SQL = (
        "SELECT evidence_id, canonical_digest FROM envelope_revisions "
        "WHERE revision_no = $1 AND evidence_id = ANY($2::text[])"
    )

    @staticmethod
    def _to_psycopg(sql: str) -> str:
        """``$n`` placeholders → ``%s``, for the psycopg (sync) path."""
        out = sql
        for n in range(9, 0, -1):
            out = out.replace(f"${n}", "%s")
        return out

    async def list_envelope_revisions(self, evidence_id: str) -> builtins.list[EnvelopeRevision]:
        """Every revision row for one record, in ``revision_no`` order."""
        if self._mode == "async":
            pool = await self._ensure_async_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch(self._SELECT_REVISIONS_SQL, evidence_id)
            return [revision_from_row(tuple(r)) for r in rows]
        pool = self._ensure_sync_pool()
        with pool.connection() as conn:
            rows = conn.execute(
                self._to_psycopg(self._SELECT_REVISIONS_SQL), (evidence_id,)
            ).fetchall()
        return [revision_from_row(tuple(r)) for r in rows]

    async def get_capture_digests(self, evidence_ids: Sequence[str]) -> dict[str, str]:
        """``evidenceId -> capture digest`` for the ids that have a revision 0.

        ONE round trip for the whole set: ``= ANY($2)`` inside the
        ``revision_no = 0`` slice is an index-only scan of the partial
        covering index, not a probe per record over the network.

        An id with no capture revision is ABSENT rather than mapped to
        ``None``: a record this store cannot speak for must not be mistakable
        for one it is vouching for.
        """
        ids = builtins.list(evidence_ids)
        if not ids:
            return {}
        if self._mode == "async":
            pool = await self._ensure_async_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    self._SELECT_CAPTURE_DIGESTS_SQL, CAPTURE_REVISION_NO, ids
                )
        else:
            sync_pool = self._ensure_sync_pool()
            with sync_pool.connection() as conn:
                rows = conn.execute(
                    self._to_psycopg(self._SELECT_CAPTURE_DIGESTS_SQL),
                    (CAPTURE_REVISION_NO, ids),
                ).fetchall()
        return {r[0]: r[1] for r in rows}

    async def store(
        self,
        envelope: EvidenceEnvelope | dict[str, Any],
        chain_id: str | None = None,
        options: StoreOptions | None = None,
    ) -> None:
        """Append an envelope; optionally compare-and-swap on the chain head.

        The record is stored as the JSON the capture hashed. When
        ``options.expectChainHead`` is supplied this is a conditional append:
        the head is re-read under ``pg_advisory_xact_lock`` and the write
        refused unless it still matches. The lock key is shared with the
        TypeScript adapter (``PostgresStorageAdapter.CHAIN_APPEND_LOCK``) so a
        mixed-language deployment serialises across both SDKs.

        The same transaction refuses an ``evidenceId`` that is already stored
        (:class:`~tzun_sdk.errors.DuplicateEvidenceError`, before the head),
        and writes, or refuses, everything ``options`` carries with the
        record. A mandate claim, issuance or revocation locks the mandate row
        (``SELECT ... FOR UPDATE``) before the chain-append lock, the order
        every mandate path takes, so they cannot deadlock.
        """
        cid = chain_id or "default"
        raw = raw_envelope(envelope)
        evidence_id = evidence_id_of(raw)
        expected = options.expectChainHead if options is not None else None
        revision_args = (
            evidence_id,
            CAPTURE_REVISION_NO,
            digest_of(raw) or "",
            chain_link_of(raw),
            _utcnow_iso(),
            "capture",
            capture_actor_of(raw),
        )
        try:
            async with self._transaction() as ex:
                await self._check_mandate_options(ex, options)
                await ex.run("SELECT pg_advisory_xact_lock($1)", (CHAIN_APPEND_LOCK_KEY,))
                if await ex.one(self._SELECT_EXISTING_SQL, (evidence_id,)):
                    raise DuplicateEvidenceError(evidence_id)
                row = await ex.one(self._HEAD_FOR_CAS_SQL, (cid,))
                assert_chain_head(expected, self._head_from_row(row))
                opening = opening_of(raw, options)
                await ex.run(
                    "INSERT INTO evidence_envelopes (evidence_id, chain_id, sequence_number, envelope_json) "
                    "VALUES ($1, $2, $3, $4::jsonb)",
                    (evidence_id, cid, sequence_of(raw), envelope_json(raw)),
                )
                # The capture revision, in the SAME transaction.
                await ex.run(self._INSERT_REVISION_SQL, revision_args)
                if opening is not None:
                    await ex.run(
                        "INSERT INTO decider_openings (evidence_id, salt, inner_id) VALUES ($1, $2, $3)",
                        (evidence_id, opening["salt"], opening["id"]),
                    )
                for link_row in link_index_rows(raw):
                    await ex.run(
                        "INSERT INTO tzun_py_evidence_links (evidence_id, idx, rel, target_digest, subject_digest) "
                        "VALUES ($1, $2, $3, $4, $5)",
                        link_row,
                    )
                await self._apply_mandate_options(ex, options)
        except (
            ChainConflictError,
            DuplicateEvidenceError,
            MandateClaimConflictError,
            MandateRefusedError,
            DeciderOpeningMismatchError,
        ):
            # A refused append is a contract answer, not a driver fault: its
            # code and facts are what a caller needs to resync and retry.
            raise
        except Exception as exc:
            if _is_evidence_unique_violation(exc):
                raise DuplicateEvidenceError(evidence_id) from exc
            # Wrap driver exceptions; preserve the cause chain.
            raise TzunError(f"PostgresAdapter.store failed: {exc}") from exc

    async def _mandate_state(
        self, ex: _PgExec, mandate_id: str, *, lock: bool
    ) -> tuple[dict[str, Any] | None, dict[str, dict[str, int]]]:
        row = await ex.one(_SQL_MANDATE_BY_ID_LOCKED if lock else _SQL_MANDATE_BY_ID, (mandate_id,))
        mandate = dict(zip(MANDATE_COLUMNS, tuple(row), strict=True)) if row is not None else None
        totals = {
            r[0]: {"max": int(r[1]), "total": int(r[2])}
            for r in await ex.all(
                "SELECT cap, max, total FROM tzun_py_mandate_totals WHERE mandate_id = $1", (mandate_id,)
            )
        }
        return mandate, totals

    async def _check_mandate_options(self, ex: _PgExec, options: StoreOptions | None) -> None:
        if options is None:
            return
        if options.mandateClaim is not None:
            mandate, totals = await self._mandate_state(ex, options.mandateClaim.mandateId, lock=True)
            check_mandate_claim(options.mandateClaim, mandate, totals)
        if options.mandateIssue is not None:
            record = options.mandateIssue.record
            held = await ex.one(
                "SELECT 1 FROM tzun_py_mandates WHERE mandate_id = $1 OR mandate_digest = $2",
                (record.mandateId, record.mandateDigest),
            )
            if held is not None:
                raise MandateRefusedError("mandate_already_issued", "document.mandateId", f"Mandate {record.mandateId} is already issued.")
        if options.mandateRevoke is not None:
            mandate, totals = await self._mandate_state(ex, options.mandateRevoke.mandateId, lock=True)
            check_mandate_transition(options.mandateRevoke, mandate, totals)

    async def _apply_mandate_options(self, ex: _PgExec, options: StoreOptions | None) -> None:
        if options is None:
            return
        if options.mandateClaim is not None:
            claim = options.mandateClaim
            await ex.run("UPDATE tzun_py_mandates SET used = used + 1 WHERE mandate_id = $1", (claim.mandateId,))
            for cap in claim.caps:
                await ex.run(
                    "UPDATE tzun_py_mandate_totals SET total = $1 WHERE mandate_id = $2 AND cap = $3",
                    (int(cap.newTotal), claim.mandateId, cap.cap),
                )
        if options.mandateIssue is not None:
            issue = options.mandateIssue
            await ex.run(_SQL_INSERT_MANDATE, mandate_row_values(issue.record))
            for cap in issue.caps:
                await ex.run(
                    "INSERT INTO tzun_py_mandate_totals (mandate_id, cap, max, total) VALUES ($1, $2, $3, 0)",
                    (issue.record.mandateId, cap.cap, int(cap.max)),
                )
            await self._insert_event(ex, issue.event)
        if options.mandateRevoke is not None:
            revoke = options.mandateRevoke
            await ex.run(
                "UPDATE tzun_py_mandates SET state = $1 WHERE mandate_id = $2", (revoke.newState, revoke.mandateId)
            )
            await self._insert_event(ex, revoke.event)

    @staticmethod
    async def _insert_event(ex: _PgExec, event: MandateEventRow) -> None:
        await ex.run(
            "INSERT INTO tzun_py_mandate_events (mandate_id, canonical, digest, created_at) VALUES ($1, $2, $3, $4)",
            (event.mandateId, event.canonical, event.digest, _utcnow_iso()),
        )

    async def retrieve(self, evidence_id: str) -> EvidenceEnvelope | None:
        raw = await self.retrieve_raw(evidence_id)
        return model_of(raw) if raw is not None else None

    async def retrieve_raw(self, evidence_id: str) -> dict[str, Any] | None:
        """The record's stored JSON, or ``None``."""
        try:
            async with self._connection() as ex:
                row = await ex.one(
                    "SELECT envelope_json::text FROM evidence_envelopes WHERE evidence_id = $1", (evidence_id,)
                )
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.retrieve failed: {exc}") from exc
        return _stored_object(row[0]) if row is not None else None

    async def retrieve_raw_by_digest(self, digest: str) -> dict[str, Any] | None:
        """The stored JSON of the oldest record whose stored canonical digest is ``digest``, or ``None``."""
        async with self._connection() as ex:
            row = await ex.one(
                "SELECT envelope_json::text FROM evidence_envelopes "
                "WHERE (envelope_json->'integrity'->>'canonicalDigest') = $1 "
                "ORDER BY created_at, evidence_id LIMIT 1",
                (digest,),
            )
        return _stored_object(row[0]) if row is not None else None

    async def chain_of(self, evidence_id: str) -> str | None:
        """The chain a record was stored on, or ``None``."""
        async with self._connection() as ex:
            row = await ex.one("SELECT chain_id FROM evidence_envelopes WHERE evidence_id = $1", (evidence_id,))
        return row[0] if row is not None else None

    async def list(self, **options: Any) -> list[EvidenceEnvelope]:
        """Page of envelopes ordered by ``sequence_number``; ``limit`` defaults to 100."""
        limit = options.get("limit", 100)
        offset = options.get("offset", 0)
        try:
            async with self._connection() as ex:
                rows = await ex.all(
                    "SELECT envelope_json::text FROM evidence_envelopes ORDER BY sequence_number LIMIT $1 OFFSET $2",
                    (limit, offset),
                )
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.list failed: {exc}") from exc
        return [model_of(_stored_object(r[0])) for r in rows]

    async def list_by_sequence(
        self,
        from_sequence: int | None = None,
        to_sequence: int | None = None,
        chain_id: str | None = None,
    ) -> builtins.list[EvidenceEnvelope]:
        """Chain-scoped, unpaged sequence-range lookup (mirrors TS listBySequence)."""
        return [model_of(r) for r in await self.list_raw_by_sequence(from_sequence, to_sequence, chain_id)]

    async def list_raw_by_sequence(
        self,
        from_sequence: int | None = None,
        to_sequence: int | None = None,
        chain_id: str | None = None,
    ) -> builtins.list[dict[str, Any]]:
        """:meth:`list_by_sequence` as stored JSON. Unlike :meth:`list`, chain-scoped and unpaged."""
        cid = chain_id or "default"
        lower = 1 if from_sequence is None else from_sequence
        params: builtins.list[Any] = [cid, lower]
        query = "SELECT envelope_json::text FROM evidence_envelopes WHERE chain_id = $1 AND sequence_number >= $2"
        if to_sequence is not None:
            query += " AND sequence_number <= $3"
            params.append(to_sequence)
        query += " ORDER BY sequence_number"
        try:
            async with self._connection() as ex:
                rows = await ex.all(query, params)
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.list_by_sequence failed: {exc}") from exc
        return [_stored_object(r[0]) for r in rows]

    async def read_envelope_at_end(self, end: str) -> Any:
        """The store's first (``end="first"``) or newest record by
        ``created_at`` (it defaults to the insertion time, and a writer with
        INSERT on the table can set it; ties by ``evidence_id``), as its stored
        JSON, or ``None``.

        Only reads, on a connection of its own: a schema with no
        ``evidence_envelopes`` table answers ``None`` and nothing is created.
        ``Tzun.init()`` runs the 0.7.0 store check with it before
        :meth:`ensure_tables`. It reads through
        ``idx_evidence_envelopes_created_at``, which :meth:`ensure_tables`
        creates, so only the first open of a store written before that index
        reads the whole table.
        """
        self._check_not_closed()
        present_sql = "SELECT to_regclass('evidence_envelopes') IS NOT NULL"
        row_sql = (
            (
                "SELECT envelope_json::text FROM evidence_envelopes "
                "ORDER BY created_at ASC, evidence_id ASC LIMIT 1"
            )
            if end == "first"
            else (
                "SELECT envelope_json::text FROM evidence_envelopes "
                "ORDER BY created_at DESC, evidence_id DESC LIMIT 1"
            )
        )
        text: str | None
        if self._mode == "async":
            conn = await self._asyncpg.connect(dsn=self._dsn)
            try:
                if not await conn.fetchval(present_sql):
                    return None
                text = await conn.fetchval(row_sql)
            finally:
                await conn.close()
        else:
            pool = self._ensure_sync_pool()
            with pool.connection() as conn:
                present = conn.execute(present_sql).fetchone()
                if present is None or not present[0]:
                    return None
                row = conn.execute(row_sql).fetchone()
                text = None if row is None else row[0]
        return None if text is None else stored_json(text)

    async def head(self, chain_id: str | None = None) -> EvidenceEnvelope | None:
        """The record with the highest ``sequence_number`` on the chain; later insert wins a tie."""
        raw = await self.head_raw(chain_id)
        return model_of(raw) if raw is not None else None

    async def head_raw(self, chain_id: str | None = None) -> dict[str, Any] | None:
        """:meth:`head` as stored JSON."""
        cid = chain_id or "default"
        try:
            async with self._connection() as ex:
                row = await ex.one(
                    "SELECT envelope_json::text FROM evidence_envelopes "
                    "WHERE chain_id = $1 ORDER BY sequence_number DESC, created_at DESC LIMIT 1",
                    (cid,),
                )
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.head failed: {exc}") from exc
        return _stored_object(row[0]) if row is not None else None

    async def register_descriptor(self, descriptor: ModelDescriptor) -> str:

        from tzun_sdk._generated.canonical import canonical_serialize_descriptor
        from tzun_sdk.storage.memory import _compute_descriptor_digest

        # ALWAYS the canonical descriptor hash, never `descriptor.modelDigest`,
        # which is the WEIGHTS digest — a different value about a different
        # thing. TS `registerModelDescriptor` hashes the canonical descriptor
        # bytes unconditionally (storage/memory.ts). Keyed on the weights
        # digest, the two SDKs would file the same descriptor under two
        # different keys, and two descriptors that differ only in metadata
        # would collide on one key whenever they shared weights.
        digest = _compute_descriptor_digest(descriptor)
        # The column is named canonical_bytes and is read by the TS verifier as
        # the bytes the digest is over, so it holds the canonical serialization.
        # Pydantic's model_dump_json() orders keys by field declaration — a
        # different string that does not hash to `digest`, which a TS
        # descriptor check against a Python-written row in a shared catalog
        # would report as descriptor_digest_mismatch.
        canonical_bytes = canonical_serialize_descriptor(
            descriptor.model_dump(mode="json", exclude_none=False)
        )
        # Mirror the TS model_descriptors schema (column names match the TS adapter).
        query = (
            "INSERT INTO model_descriptors "
            "(model_descriptor_digest, canonical_bytes, vendor, model_name, model_version, "
            "parent_model_descriptor_digest, source, first_registered_at, first_registered_by) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) "
            "ON CONFLICT (model_descriptor_digest) DO NOTHING"
        )
        import datetime as _dt

        params: tuple[Any, ...] = (
            digest,
            canonical_bytes,
            descriptor.vendor or "",
            descriptor.modelName or "",
            descriptor.modelVersion or "",
            descriptor.parentModelDescriptorDigest,
            "manual",
            _dt.datetime.now(_dt.UTC),  # asyncpg requires datetime, not str
            "sdk",
        )
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    await conn.execute(query, *params)
            else:
                pool = self._ensure_sync_pool()
                qs = query
                for i in range(9, 0, -1):
                    qs = qs.replace(f"${i}", "%s")
                with pool.connection() as conn:
                    conn.execute(qs, params)
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.register_descriptor failed: {exc}") from exc
        return digest

    async def get_descriptor(self, digest: str) -> ModelDescriptor | None:
        query = (
            "SELECT canonical_bytes FROM model_descriptors "
            "WHERE model_descriptor_digest = $1"
        )
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    row = await conn.fetchrow(query, digest)
            else:
                pool = self._ensure_sync_pool()
                with pool.connection() as conn:
                    cursor = conn.execute(query.replace("$1", "%s"), (digest,))
                    row = cursor.fetchone()
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.get_descriptor failed: {exc}") from exc
        if row is None:
            return None
        body = row[0] if not isinstance(row, dict) else row["canonical_bytes"]
        return ModelDescriptor.model_validate_json(body)

    async def store_attestation(
        self, evidence_id: str, blob: AttestationArtifacts
    ) -> None:
        body = blob.model_dump_json()
        query = "INSERT INTO attestations (evidence_id, blob_json) VALUES ($1, $2::jsonb)"
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    await conn.execute(query, evidence_id, body)
            else:
                pool = self._ensure_sync_pool()
                with pool.connection() as conn:
                    conn.execute(
                        query.replace("$1", "%s").replace("$2", "%s"),
                        (evidence_id, body),
                    )
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.store_attestation failed: {exc}") from exc

    async def get_attestations(
        self, evidence_id: str
    ) -> builtins.list[AttestationArtifacts]:
        query = (
            "SELECT blob_json::text FROM attestations "
            "WHERE evidence_id = $1 ORDER BY id"
        )
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    rows = await conn.fetch(query, evidence_id)
                    return [
                        AttestationArtifacts.model_validate_json(r[0]) for r in rows
                    ]
            else:
                pool = self._ensure_sync_pool()
                with pool.connection() as conn:
                    cursor = conn.execute(query.replace("$1", "%s"), (evidence_id,))
                    return [
                        AttestationArtifacts.model_validate_json(r[0])
                        for r in cursor.fetchall()
                    ]
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.get_attestations failed: {exc}") from exc

    async def store_annotation(self, record: AnnotationRecord) -> None:
        await self._store_recovery("annotation", record.model_dump_json())

    async def store_relink(self, record: RelinkRecord) -> None:
        await self._store_recovery("relink", record.model_dump_json())

    async def store_fork(self, record: ForkRecord) -> None:
        await self._store_recovery("fork", record.model_dump_json())

    async def _store_recovery(self, kind: str, body: str) -> None:
        query = "INSERT INTO recovery_records (kind, record_json) VALUES ($1, $2::jsonb)"
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    await conn.execute(query, kind, body)
            else:
                pool = self._ensure_sync_pool()
                with pool.connection() as conn:
                    conn.execute(
                        query.replace("$1", "%s").replace("$2", "%s"),
                        (kind, body),
                    )
        except Exception as exc:
            raise TzunError(f"PostgresAdapter._store_recovery failed: {exc}") from exc

    async def store_incident(self, incident: TamperIncident) -> None:
        body = incident.model_dump_json()
        query = (
            "INSERT INTO tzun_py_tamper_incidents "
            "(incident_id, event_type, evidence_id, incident_json, detected_at) "
            "VALUES ($1, $2, $3, $4::jsonb, $5) "
            "ON CONFLICT (incident_id) DO NOTHING"
        )
        # detected_at is TIMESTAMPTZ; asyncpg binds only a datetime to it.
        detected_at = _dt.datetime.fromisoformat(str(incident.detectedAt).replace("Z", "+00:00"))
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    await conn.execute(
                        query,
                        incident.incidentId,
                        incident.eventType,
                        incident.evidenceId,
                        body,
                        detected_at,
                    )
            else:
                pool = self._ensure_sync_pool()
                with pool.connection() as conn:
                    conn.execute(
                        (
                            query.replace("$1", "%s")
                            .replace("$2", "%s")
                            .replace("$3", "%s")
                            .replace("$4", "%s")
                            .replace("$5", "%s")
                        ),
                        (
                            incident.incidentId,
                            incident.eventType,
                            incident.evidenceId,
                            body,
                            detected_at,
                        ),
                    )
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.store_incident failed: {exc}") from exc

    async def delete_envelope_for_demo(self, evidence_id: str) -> None:
        if os.environ.get("TZUN_ENABLE_DEMO_DELETE", "") != "1":
            raise TzunError(
                "delete_envelope_for_demo is demo-only and not enabled in "
                "this build (set TZUN_ENABLE_DEMO_DELETE=1 to enable)."
            )
        query = "DELETE FROM evidence_envelopes WHERE evidence_id = $1"
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    await conn.execute(query, evidence_id)
            else:
                pool = self._ensure_sync_pool()
                with pool.connection() as conn:
                    conn.execute(query.replace("$1", "%s"), (evidence_id,))
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.delete_envelope_for_demo failed: {exc}") from exc

    # ── Catalog primitives ────────────────────────────────────────────────

    async def list_model_descriptors(
        self,
        vendor: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> builtins.list[ModelDescriptorRow]:
        """List model descriptors with optional vendor filter, limit, offset.

        Uses the TS-compatible column schema (model_descriptor_digest, canonical_bytes, …).
        """

        query = (
            "SELECT model_descriptor_digest, canonical_bytes, vendor, model_name, "
            "model_version, parent_model_descriptor_digest, source, "
            "first_registered_at, first_registered_by "
            "FROM model_descriptors"
        )
        params: builtins.list[Any] = []
        if vendor is not None:
            query += " WHERE vendor = $1"
            params.append(vendor)
        query += " ORDER BY first_registered_at"
        if limit is not None:
            idx = len(params) + 1
            query += f" LIMIT ${idx}"
            params.append(limit)
        if offset is not None:
            idx = len(params) + 1
            query += f" OFFSET ${idx}"
            params.append(offset)
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    rows = await conn.fetch(query, *params)
            else:
                pool = self._ensure_sync_pool()
                # Replace placeholders in order (no repeated $n beyond $3 needed in practice).
                qs = query
                for i in range(len(params), 0, -1):
                    qs = qs.replace(f"${i}", "%s")
                with pool.connection() as conn:
                    rows = conn.execute(qs, params).fetchall()
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.list_model_descriptors failed: {exc}") from exc
        result = []
        for row in rows:
            def _col(r: Any, idx: int, name: str) -> Any:
                if hasattr(r, "keys"):
                    return r[name]
                return r[idx]

            digest_val = _col(row, 0, "model_descriptor_digest")
            canonical_val = _col(row, 1, "canonical_bytes")
            vendor_val = _col(row, 2, "vendor")
            name_val = _col(row, 3, "model_name")
            version_val = _col(row, 4, "model_version")
            parent_val = _col(row, 5, "parent_model_descriptor_digest")
            source_val = _col(row, 6, "source")
            reg_at_val = str(_col(row, 7, "first_registered_at"))
            reg_by_val = _col(row, 8, "first_registered_by")

            desc = ModelDescriptor.model_validate_json(canonical_val)
            result.append(ModelDescriptorRow(
                modelDescriptorDigest=digest_val,
                canonicalBytes=canonical_val,
                descriptor=desc,
                vendor=vendor_val,
                modelName=name_val,
                modelVersion=version_val,
                parentModelDescriptorDigest=parent_val,
                source=source_val,
                firstRegisteredAt=reg_at_val,
                firstRegisteredBy=reg_by_val,
            ))
        return result

    async def append_model_descriptor_annotation(
        self, row: ModelDescriptorAnnotationRow
    ) -> None:
        query = (
            "INSERT INTO model_descriptor_annotations "
            "(annotation_id, model_descriptor_digest, annotated_at, annotated_by, "
            "annotation_type, value_json, retracts_annotation_id, signature, note) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        import datetime as _dt

        # asyncpg requires datetime for TIMESTAMPTZ; psycopg accepts both str and datetime.
        annotated_at: Any = row.annotatedAt
        if self._mode == "async":
            try:
                annotated_at = _dt.datetime.fromisoformat(row.annotatedAt.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        params = (
            row.annotationId, row.modelDescriptorDigest, annotated_at,
            row.annotatedBy, row.annotationType, row.valueJson,
            row.retractsAnnotationId, row.signature, row.note,
        )
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    await conn.execute(query, *params)
            else:
                pool = self._ensure_sync_pool()
                qs = query
                for i in range(9, 0, -1):
                    qs = qs.replace(f"${i}", "%s")
                with pool.connection() as conn:
                    conn.execute(qs, params)
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.append_model_descriptor_annotation failed: {exc}") from exc

    async def list_model_descriptor_annotations(
        self, digest: str
    ) -> builtins.list[ModelDescriptorAnnotationRow]:
        query = (
            "SELECT annotation_id, model_descriptor_digest, annotated_at, annotated_by, "
            "annotation_type, value_json, retracts_annotation_id, signature, note "
            "FROM model_descriptor_annotations "
            "WHERE model_descriptor_digest = $1 "
            "ORDER BY annotated_at ASC, annotation_id ASC"
        )
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    rows = await conn.fetch(query, digest)
            else:
                pool = self._ensure_sync_pool()
                with pool.connection() as conn:
                    rows = conn.execute(query.replace("$1", "%s"), (digest,)).fetchall()
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.list_model_descriptor_annotations failed: {exc}") from exc
        def _as_str(v: Any) -> str:
            """Convert a datetime (from asyncpg) or keep str (from psycopg) to ISO 8601."""
            import datetime as _dt

            if isinstance(v, _dt.datetime):
                return v.isoformat().replace("+00:00", "Z")
            return str(v)

        def _col(r: Any, idx: int, name: str) -> Any:
            if hasattr(r, "keys"):
                return r[name]
            return r[idx]

        return [
            ModelDescriptorAnnotationRow(
                annotationId=_col(r, 0, "annotation_id"),
                modelDescriptorDigest=_col(r, 1, "model_descriptor_digest"),
                annotatedAt=_as_str(_col(r, 2, "annotated_at")),
                annotatedBy=_col(r, 3, "annotated_by"),
                annotationType=_col(r, 4, "annotation_type"),
                valueJson=_col(r, 5, "value_json"),
                retractsAnnotationId=_col(r, 6, "retracts_annotation_id"),
                signature=_col(r, 7, "signature"),
                note=_col(r, 8, "note"),
            )
            for r in rows
        ]

    async def set_model_descriptor_alias(
        self, slug: str, digest: str, set_by: str
    ) -> None:
        # Same-instant re-set (PK slug+set_at) = the later write wins — upsert
        # keeps the latest-wins contract instead of raising a unique violation.
        query = (
            "INSERT INTO model_descriptor_aliases "
            "(slug, set_at, model_descriptor_digest, set_by) VALUES ($1, $2, $3, $4) "
            "ON CONFLICT (slug, set_at) DO UPDATE SET "
            "model_descriptor_digest = EXCLUDED.model_descriptor_digest, set_by = EXCLUDED.set_by"
        )
        import datetime as _dt

        set_at: Any = _dt.datetime.now(_dt.UTC) if self._mode == "async" else _utcnow_iso()
        params = (slug, set_at, digest, set_by)
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    await conn.execute(query, *params)
            else:
                pool = self._ensure_sync_pool()
                qs = query
                for i in range(4, 0, -1):
                    qs = qs.replace(f"${i}", "%s")
                with pool.connection() as conn:
                    conn.execute(qs, params)
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.set_model_descriptor_alias failed: {exc}") from exc

    async def resolve_model_descriptor_alias(self, slug: str) -> str | None:
        query = (
            "SELECT model_descriptor_digest FROM model_descriptor_aliases "
            "WHERE slug = $1 ORDER BY set_at DESC LIMIT 1"
        )
        try:
            if self._mode == "async":
                pool = await self._ensure_async_pool()
                async with pool.acquire() as conn:
                    row = await conn.fetchrow(query, slug)
            else:
                pool = self._ensure_sync_pool()
                with pool.connection() as conn:
                    row = conn.execute(query.replace("$1", "%s"), (slug,)).fetchone()
        except Exception as exc:
            raise TzunError(f"PostgresAdapter.resolve_model_descriptor_alias failed: {exc}") from exc
        if row is None:
            return None
        return row[0] if not hasattr(row, "keys") else row["model_descriptor_digest"]

    async def get_enriched_model_descriptor(self, digest: str) -> ModelDescriptor | None:
        return await self.get_descriptor(digest)

    # ── Decider openings (Record §6.3) ───────────────────────────────────

    async def get_decider_opening(self, evidence_id: str) -> DeciderOpening | None:
        async with self._connection() as ex:
            row = await ex.one("SELECT salt, inner_id FROM decider_openings WHERE evidence_id = $1", (evidence_id,))
        return DeciderOpening(salt=row[0], id=row[1]) if row is not None else None

    async def get_decider_commitment_secret(self) -> bytes:
        """The store's commitment-salt secret: 32 random bytes minted on first read, kept for the store's life."""
        async with self._transaction() as ex:
            await ex.run(
                "INSERT INTO decider_commitment_secret (id, secret) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
                (secrets.token_bytes(32).hex(),),
            )
            row = await ex.one("SELECT secret FROM decider_commitment_secret WHERE id = 1")
        return bytes.fromhex(row[0])

    # ── Agent catalog (Record §6.9) ──────────────────────────────────────

    async def put_agent_descriptor(self, descriptor: Any) -> tuple[str, bool]:
        """Register a descriptor (already checked); idempotent on identical bytes. ``(digest, already_existed)``."""
        d = descriptor if isinstance(descriptor, dict) else descriptor.model_dump(mode="json")
        digest = agent_descriptor_digest(d)
        async with self._transaction() as ex:
            row = await ex.one(
                "INSERT INTO tzun_py_agent_descriptors "
                "(digest, canonical_bytes, name, organization, parent, registered_at) "
                "VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (digest) DO NOTHING RETURNING digest",
                (
                    digest,
                    canonical_serialize_agent_descriptor(d),
                    d["name"],
                    d["operator"]["organization"],
                    d["parent"],
                    _utcnow_iso(),
                ),
            )
        return digest, row is None

    @staticmethod
    def _agent_row(r: Any) -> AgentDescriptorRow:
        return AgentDescriptorRow(
            digest=r[0], canonicalBytes=r[1], name=r[2], organization=r[3], parent=r[4], registeredAt=r[5]
        )

    async def get_agent_descriptor(self, digest: str) -> AgentDescriptorRow | None:
        async with self._connection() as ex:
            row = await ex.one(_SQL_AGENT_BY_DIGEST, (digest,))
        return self._agent_row(row) if row is not None else None

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
        params: builtins.list[Any] = [v for v in (name, organization) if v is not None]
        async with self._connection() as ex:
            rows = await ex.all(
                _SQL_AGENTS[(name is not None, organization is not None)], [*params, size + 1, start]
            )
        page = [self._agent_row(r) for r in rows[:size]]
        return page, (opaque_cursor(start + size) if len(rows) > size else None)

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
        only = _SQL_STATEMENTS_ONLY if statements else ""
        async with self._connection() as ex:
            if rels is None:
                rows = await ex.all(_SQL_LINKS_TO.format(statements=only), (digest, size + 1, start))
            else:
                rel_list = builtins.list(rels)
                if not rel_list:
                    return [], None
                rows = await ex.all(_SQL_LINKS_TO_RELS.format(statements=only), (digest, rel_list, size + 1, start))
        page = [EvidenceLinkRow(evidenceId=r[0], idx=int(r[1]), rel=r[2], targetDigest=r[3]) for r in rows[:size]]
        return page, (opaque_cursor(start + size) if len(rows) > size else None)

    # ── Mandates (Record §9.6) ───────────────────────────────────────────

    async def _mandate_where(self, sql: str, value: Any) -> MandateRow | None:
        async with self._connection() as ex:
            row = await ex.one(sql, (value,))
        return mandate_row_from(dict(zip(MANDATE_COLUMNS, tuple(row), strict=True))) if row is not None else None

    async def get_mandate(self, mandate_id: str) -> MandateRow | None:
        return await self._mandate_where(_SQL_MANDATE_BY_ID, mandate_id)

    async def get_mandate_by_digest(self, mandate_digest: str) -> MandateRow | None:
        return await self._mandate_where(_SQL_MANDATE_BY_DIGEST, mandate_digest)

    async def list_mandates(self, *, state: str | None = None) -> builtins.list[MandateRow]:
        async with self._connection() as ex:
            rows = await (ex.all(_SQL_MANDATES_IN_STATE, (state,)) if state else ex.all(_SQL_MANDATES))
        return [mandate_row_from(dict(zip(MANDATE_COLUMNS, tuple(r), strict=True))) for r in rows]

    async def get_mandate_totals(self, mandate_id: str) -> dict[str, int]:
        async with self._connection() as ex:
            rows = await ex.all("SELECT cap, total FROM tzun_py_mandate_totals WHERE mandate_id = $1", (mandate_id,))
        return {r[0]: int(r[1]) for r in rows}

    async def list_mandate_events(self, mandate_id: str) -> builtins.list[MandateEventRow]:
        async with self._connection() as ex:
            rows = await ex.all(
                "SELECT canonical, digest FROM tzun_py_mandate_events WHERE mandate_id = $1 ORDER BY id", (mandate_id,)
            )
        return [event_row_from(mandate_id, r[0], r[1]) for r in rows]

    async def expire_mandate(self, expiry: MandateExpireStore) -> None:
        async with self._transaction() as ex:
            mandate, totals = await self._mandate_state(ex, expiry.mandateId, lock=True)
            check_mandate_transition(expiry, mandate, totals)
            await ex.run("UPDATE tzun_py_mandates SET state = 'expired' WHERE mandate_id = $1", (expiry.mandateId,))
            await self._insert_event(ex, expiry.event)

    async def fill_confirmation(self, evidence_id: str, assertion: dict[str, Any]) -> bool:
        """Fill ``nonRepudiation.confirmation`` once; ``False`` when it is already filled or the record is absent."""
        async with self._transaction() as ex:
            row = await ex.one(
                "SELECT envelope_json::text FROM evidence_envelopes WHERE evidence_id = $1 FOR UPDATE", (evidence_id,)
            )
            raw = _stored_object(row[0]) if row is not None else None
            nr = raw.get("nonRepudiation") if raw is not None else None
            if raw is None or not isinstance(nr, dict) or nr.get("confirmation") is not None:
                return False
            nr["confirmation"] = assertion
            await ex.run(
                "UPDATE evidence_envelopes SET envelope_json = $1::jsonb WHERE evidence_id = $2",
                (envelope_json(raw), evidence_id),
            )
        return True

    async def append_custody(self, evidence_id: str, entry: dict[str, Any]) -> None:
        """Append a custody entry to a stored record (unhashed, outside the digest)."""
        async with self._transaction() as ex:
            row = await ex.one(
                "SELECT envelope_json::text FROM evidence_envelopes WHERE evidence_id = $1 FOR UPDATE", (evidence_id,)
            )
            raw = _stored_object(row[0]) if row is not None else None
            if raw is None:
                return
            custody = raw.setdefault("custodyChain", [])
            if isinstance(custody, builtins.list):
                custody.append(entry)
                await ex.run(
                    "UPDATE evidence_envelopes SET envelope_json = $1::jsonb WHERE evidence_id = $2",
                    (envelope_json(raw), evidence_id),
                )

    async def read_anchor_freshness(self, chain: str) -> dict[str, Any] | None:
        """The finalized block an anchoring writer shared for ``chain`` (``anchor_freshness``), or ``None``.

        The table is the anchoring writer's; this SDK only reads it, and a
        database without it answers ``None``.
        """
        async with self._connection() as ex:
            present = await ex.one("SELECT to_regclass('anchor_freshness') IS NOT NULL")
            if present is None or not present[0]:
                return None
            row = await ex.one(
                "SELECT block_number, block_hash, (EXTRACT(EPOCH FROM block_time) * 1000)::bigint "
                "FROM anchor_freshness WHERE chain = $1",
                (chain,),
            )
        if row is None:
            return None
        return {"chain": chain, "number": int(row[0]), "hash": row[1], "timeMs": int(row[2])}

    async def close(self) -> None:
        # Graceful 5s close, then terminate.
        self._closed = True  # set before pool teardown so operations fail cleanly
        if self._async_pool is not None:
            try:
                import anyio

                with anyio.move_on_after(5):
                    await self._async_pool.close()
            except Exception:
                pass
            # asyncpg uses pool.terminate(); we already called close() above.
            self._async_pool = None
        if self._sync_pool is not None:
            try:
                self._sync_pool.close()
            except Exception:
                pass
            self._sync_pool = None


_POSTGRES_DDL = """
CREATE TABLE IF NOT EXISTS evidence_envelopes (
    evidence_id      TEXT PRIMARY KEY,
    chain_id         TEXT NOT NULL,
    sequence_number  BIGINT NOT NULL,
    envelope_json    JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_envelopes_chain
    ON evidence_envelopes(chain_id, sequence_number);

-- The store's first and newest record by insertion time, in the order
-- read_envelope_at_end() sorts by. Tzun.init() reads the 0.7.0 store check
-- through it on every open, before this DDL runs, so only the first open of a
-- store written before the index sorts the whole table.
CREATE INDEX IF NOT EXISTS idx_evidence_envelopes_created_at
    ON evidence_envelopes(created_at, evidence_id);

-- model_descriptors: column names mirror the TS adapter schema.
CREATE TABLE IF NOT EXISTS model_descriptors (
    model_descriptor_digest         TEXT PRIMARY KEY,
    canonical_bytes                 TEXT NOT NULL,
    vendor                          TEXT NOT NULL,
    model_name                      TEXT NOT NULL,
    model_version                   TEXT NOT NULL,
    parent_model_descriptor_digest  TEXT,
    source                          TEXT NOT NULL,
    first_registered_at             TIMESTAMPTZ NOT NULL,
    first_registered_by             TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_md_vmv
    ON model_descriptors(vendor, model_name, model_version);
CREATE INDEX IF NOT EXISTS idx_md_parent
    ON model_descriptors(parent_model_descriptor_digest);

CREATE TABLE IF NOT EXISTS attestations (
    id              BIGSERIAL PRIMARY KEY,
    evidence_id     TEXT NOT NULL REFERENCES evidence_envelopes(evidence_id),
    blob_json       JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS recovery_records (
    id              BIGSERIAL PRIMARY KEY,
    kind            TEXT NOT NULL,
    record_json     JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NAME IS DELIBERATE. The TS adapter also creates a `tamper_incidents`, with
-- entirely different columns (id / detected_at / severity / type /
-- affected_records / ... ) for the engine's TamperIncident. This table holds
-- the Python-SDK-LOCAL TamperIncident shape (tzun_sdk.models.TamperIncident),
-- which is a different model on purpose. Under one name, in a database both
-- SDKs write to (python/MIGRATION.md), whichever SDK ran ensure_tables second
-- would get a CREATE TABLE IF NOT EXISTS no-op against the other's table, and
-- every store_incident() would then fail on unknown columns. With this table
-- namespaced, the two coexist.
CREATE TABLE IF NOT EXISTS tzun_py_tamper_incidents (
    incident_id     TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    evidence_id     TEXT,
    incident_json   JSONB NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS model_descriptor_annotations (
    annotation_id                TEXT PRIMARY KEY,
    model_descriptor_digest      TEXT NOT NULL REFERENCES model_descriptors(model_descriptor_digest),
    annotated_at                 TIMESTAMPTZ NOT NULL,
    annotated_by                 TEXT NOT NULL,
    annotation_type              TEXT NOT NULL,
    value_json                   TEXT NOT NULL,
    retracts_annotation_id       TEXT,
    signature                    TEXT,
    note                         TEXT
);

CREATE INDEX IF NOT EXISTS idx_mda_digest
    ON model_descriptor_annotations(model_descriptor_digest);
CREATE INDEX IF NOT EXISTS idx_mda_ts
    ON model_descriptor_annotations(annotated_at);

CREATE TABLE IF NOT EXISTS model_descriptor_aliases (
    slug                    TEXT NOT NULL,
    set_at                  TIMESTAMPTZ NOT NULL,
    model_descriptor_digest TEXT NOT NULL,
    set_by                  TEXT NOT NULL,
    PRIMARY KEY (slug, set_at)
);

CREATE INDEX IF NOT EXISTS idx_mda_slug
    ON model_descriptor_aliases(slug);

-- The append-only revision log. One row per legitimate write to
-- a record's integrity block; the Python SDK writes only revision 0, because
-- it has no recovery path that could write any other (see _revision_log.py).
--
-- NAME AND COLUMNS ARE DELIBERATELY SHARED WITH THE TS ADAPTER, unlike
-- tzun_py_tamper_incidents. That table was namespaced because the two SDKs
-- hold DIFFERENT shapes under one name, which is a collision. Here the shapes
-- are identical, so CREATE TABLE IF NOT EXISTS converges instead of colliding
-- and a mixed deployment gets one log rather than two that are each blind to
-- half the evidence. The evidence tables themselves stay disjoint
-- (evidence_envelopes vs envelopes) and evidence ids are UUIDs, so the two
-- record populations coexist in the rows without meeting.
--
-- recorded_at is TEXT, not TIMESTAMPTZ, matching the TS adapter: the value is
-- compared across languages and a driver that hands back a datetime on one
-- side and a string on the other is a divergence waiting to be asserted
-- around.
CREATE TABLE IF NOT EXISTS envelope_revisions (
    evidence_id      TEXT NOT NULL,
    revision_no      INTEGER NOT NULL,
    canonical_digest TEXT NOT NULL,
    chain_link       TEXT,
    recorded_at      TEXT NOT NULL,
    cause            TEXT NOT NULL,
    actor            TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (evidence_id, revision_no)
);

-- The O(1) capture probe: a partial COVERING index, so "what did this record
-- hash to at capture" is answered index-only.
CREATE INDEX IF NOT EXISTS idx_envelope_revisions_capture
    ON envelope_revisions(evidence_id, canonical_digest) WHERE revision_no = 0;

-- Append-only, enforced in the database. This is the ONE Python table with
-- immutability triggers: everywhere else MIGRATION.md records, honestly, that
-- the Python adapters install none. Here they are not optional — the log is
-- the only artefact that remembers what a record hashed to at capture, and a
-- log an insider can DELETE from restores exactly the silence the defence
-- removes. Function and trigger names match the TS adapter's so a shared
-- database converges on one guard instead of two that replace each other, and
-- the function is created as the TS adapter creates it: with its search_path
-- pinned to pg_catalog, pg_temp, so the session that fires it resolves nothing
-- in it.
CREATE OR REPLACE FUNCTION envelope_revisions_block_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'envelope_revisions rows are append-only (% refused)', TG_OP;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;

DROP TRIGGER IF EXISTS envelope_revisions_block_mutation_trigger ON envelope_revisions;
CREATE TRIGGER envelope_revisions_block_mutation_trigger
    BEFORE UPDATE OR DELETE ON envelope_revisions
    FOR EACH ROW EXECUTE FUNCTION envelope_revisions_block_mutation();

DROP TRIGGER IF EXISTS envelope_revisions_block_truncate_trigger ON envelope_revisions;
CREATE TRIGGER envelope_revisions_block_truncate_trigger
    BEFORE TRUNCATE ON envelope_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION envelope_revisions_block_mutation();
""".strip()


__all__ = ("ADVISORY_LOCK_KEY", "PostgresAdapter")
