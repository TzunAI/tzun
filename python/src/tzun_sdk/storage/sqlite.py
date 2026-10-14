"""SQLite storage adapter.

Two execution paths selected at construction:

* Async path via ``aiosqlite`` (requires the ``[sqlite]`` extra).
* Sync path via stdlib ``sqlite3``.

The DDL is inline below. ``schema/migrations/sqlite/0001_init.sql``
is a copy kept for readers, not something either adapter reads at runtime, and
it is NOT a cross-language source of truth: the TS SQLite adapter creates a
different set of tables (``envelopes`` vs ``evidence_envelopes`` here, plus
``chains`` / ``chain_state`` / the recovery ledger, which this adapter does not
have). See ``python/MIGRATION.md``.

Database-level append-only enforcement covers one table, ``envelope_revisions``
(UPDATE, DELETE, an insert over an existing row and a row at a negative rowid
are refused by triggers); the evidence table has none (``python/MIGRATION.md``).
"""

from __future__ import annotations

import builtins
import json
import os
import pathlib
import secrets
import sqlite3
from collections.abc import Sequence
from typing import Any

from tzun_sdk.agents import agent_descriptor_digest, canonical_serialize_agent_descriptor
from tzun_sdk.errors import (
    DuplicateEvidenceError,
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
from tzun_sdk.storage._chain_head_guard import assert_chain_head, head_of
from tzun_sdk.storage._extension_ddl import (
    SQLITE_EXTENSION_DDL,
    SQLITE_LINK_STATEMENTS_INDEX,
    SQLITE_LINK_SUBJECT_BACKFILL,
)
from tzun_sdk.storage._records import (
    MANDATE_COLUMNS,
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
from tzun_sdk.storage.memory import _compute_descriptor_digest, _utcnow_iso

DEFAULT_CHAIN_ID = "default"


def _canonical_bytes_for(descriptor: ModelDescriptor) -> str:
    """The canonical serialization the descriptor digest is computed over.

    Identical to what ``_compute_descriptor_digest`` hashes and to what the
    memory adapter stores, so all three adapters agree byte for byte.
    """
    from tzun_sdk._generated.canonical import canonical_serialize_descriptor

    return canonical_serialize_descriptor(
        descriptor.model_dump(mode="json", exclude_none=False)
    )


def _sqlite_ts_to_iso(value: Any) -> str:
    """Normalise a SQLite ``datetime('now')`` string to ISO-8601 UTC.

    SQLite's default renders ``2026-09-02 10:11:12`` — a space separator and no
    zone — while every other timestamp the SDK emits is ``...T...Z``. A consumer
    parsing the bundle should not have to know which adapter wrote it.
    """
    if value is None:
        return _utcnow_iso()
    text = str(value)
    if "T" in text:
        return text
    return text.replace(" ", "T", 1) + "Z"

# SQL DDL — this constant IS the source of truth; it is what ensure_tables()
# executes. `schema/migrations/sqlite/0001_init.sql` is a committed,
# human-readable copy of exactly these statements, kept in step by
# tests/storage/test_schema_file_matches_ddl.py.
#
# Nothing in this module writes that file. A path five directory levels above
# this module is, for an installed wheel, the interpreter's lib/ directory,
# not the repository.
_DDL = """
CREATE TABLE IF NOT EXISTS evidence_envelopes (
    evidence_id      TEXT PRIMARY KEY,
    chain_id         TEXT NOT NULL,
    sequence_number  INTEGER NOT NULL,
    envelope_json    TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_envelopes_chain
    ON evidence_envelopes(chain_id, sequence_number);

CREATE TABLE IF NOT EXISTS model_descriptors (
    digest          TEXT PRIMARY KEY,
    descriptor_json TEXT NOT NULL,
    -- The bytes the digest is over. `descriptor_json` is pydantic's
    -- model_dump_json(), whose key order is field-declaration order, not
    -- canonical order — it does NOT hash to `digest`. An export bundle that
    -- shipped it as canonicalBytes would be internally inconsistent.
    canonical_bytes TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS attestations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id     TEXT NOT NULL,
    blob_json       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (evidence_id) REFERENCES evidence_envelopes(evidence_id)
);

CREATE TABLE IF NOT EXISTS recovery_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL,
    record_json     TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
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
    incident_json   TEXT NOT NULL,
    detected_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS model_descriptor_annotations (
    annotation_id                TEXT PRIMARY KEY,
    model_descriptor_digest      TEXT NOT NULL,
    annotated_at                 TEXT NOT NULL,
    annotated_by                 TEXT NOT NULL,
    annotation_type              TEXT NOT NULL,
    value_json                   TEXT NOT NULL,
    retracts_annotation_id       TEXT,
    signature                    TEXT,
    note                         TEXT,
    FOREIGN KEY (model_descriptor_digest) REFERENCES model_descriptors(digest)
);

CREATE INDEX IF NOT EXISTS idx_mda_digest
    ON model_descriptor_annotations(model_descriptor_digest);
CREATE INDEX IF NOT EXISTS idx_mda_ts
    ON model_descriptor_annotations(annotated_at);

CREATE TABLE IF NOT EXISTS model_descriptor_aliases (
    slug                    TEXT NOT NULL,
    set_at                  TEXT NOT NULL,
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
CREATE TABLE IF NOT EXISTS envelope_revisions (
    evidence_id      TEXT NOT NULL,
    revision_no      INTEGER NOT NULL,
    canonical_digest TEXT NOT NULL,
    chain_link       TEXT,
    recorded_at      TEXT NOT NULL,
    cause            TEXT NOT NULL,
    actor            TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (evidence_id, revision_no)
);

-- The O(1) capture probe: a partial COVERING index, so "what did this record
-- hash to at capture" is answered index-only.
CREATE INDEX IF NOT EXISTS idx_envelope_revisions_capture
    ON envelope_revisions(evidence_id, canonical_digest) WHERE revision_no = 0;

-- Append-only in the database: UPDATE and DELETE are refused, and so is an
-- insert over an existing row. REPLACE conflict resolution
-- (INSERT OR REPLACE, REPLACE INTO) deletes the row an insert conflicts with
-- and then inserts; that delete fires no DELETE trigger unless
-- recursive_triggers is on, and no UPDATE trigger fires at all, so without
-- the third trigger REPLACE would reseat a record's capture revision. A
-- BEFORE INSERT trigger runs before conflict handling, so an insert naming an
-- (evidence_id, revision_no) or a rowid a row already holds is refused
-- whatever its conflict clause. An insert that names no rowid reads
-- NEW.rowid as -1 there; SQLite never assigns a negative rowid itself, and
-- the fourth trigger refuses one written explicitly (AFTER INSERT, where
-- NEW.rowid is the value written), so no row holds -1 for such an insert to
-- collide with. The TS adapter creates these four triggers on the same
-- table, with the same bodies. SQLite has no privilege model, so anyone who
-- can write the file can drop them: that is a schema change, not a row edit.
CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_update
    BEFORE UPDATE ON envelope_revisions
    BEGIN SELECT RAISE(ABORT, 'envelope_revisions rows are append-only (UPDATE refused)'); END;
CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_delete
    BEFORE DELETE ON envelope_revisions
    BEGIN SELECT RAISE(ABORT, 'envelope_revisions rows are append-only (DELETE refused)'); END;
CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_replace
    BEFORE INSERT ON envelope_revisions
    BEGIN
        SELECT RAISE(ABORT, '[tzun:duplicate_record] envelope_revisions rows are append-only (INSERT over an existing row refused)')
         WHERE EXISTS (SELECT 1 FROM envelope_revisions WHERE evidence_id = NEW.evidence_id AND revision_no = NEW.revision_no)
            OR EXISTS (SELECT 1 FROM envelope_revisions WHERE rowid = NEW.rowid);
    END;
CREATE TRIGGER IF NOT EXISTS envelope_revisions_block_negative_rowid
    AFTER INSERT ON envelope_revisions
    BEGIN
        SELECT RAISE(ABORT, 'envelope_revisions: a rowid cannot be negative')
         WHERE NEW.rowid < 0;
    END;
""".strip()



#: The 0.8.0 statements, each a literal: bandit's B608 refuses SQL built at run time.
_SQL_MANDATE_BY_ID = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates WHERE mandate_id = ?"
)
_SQL_MANDATE_BY_DIGEST = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates WHERE mandate_digest = ?"
)
_SQL_MANDATES = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates ORDER BY created_at"
)
_SQL_MANDATES_IN_STATE = (
    "SELECT mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at "
    "FROM tzun_py_mandates WHERE state = ? ORDER BY created_at"
)
_SQL_INSERT_MANDATE = (
    "INSERT INTO tzun_py_mandates (mandate_id, mandate_digest, document_bytes, statement_json, statement_digest, assertion_json, assertion_digest, assertion_timestamp, state, used, max_records, not_before, not_after, issuance_evidence_id, issuance_digest, created_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_SQL_AGENT_BY_DIGEST = "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors WHERE digest = ?"
_SQL_AGENTS = {
    (False, False): "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors "
    "ORDER BY registered_at, digest LIMIT ? OFFSET ?",
    (True, False): "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors WHERE name = ? "
    "ORDER BY registered_at, digest LIMIT ? OFFSET ?",
    (False, True): "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors WHERE organization = ? "
    "ORDER BY registered_at, digest LIMIT ? OFFSET ?",
    (True, True): "SELECT digest, canonical_bytes, name, organization, parent, registered_at FROM tzun_py_agent_descriptors WHERE name = ? AND organization = ? "
    "ORDER BY registered_at, digest LIMIT ? OFFSET ?",
}
_SQL_LINKS_TO = (
    "SELECT l.evidence_id, l.idx, l.rel, l.target_digest FROM tzun_py_evidence_links l "
    "JOIN evidence_envelopes e ON e.evidence_id = l.evidence_id "
    "WHERE l.target_digest = ? {statements}ORDER BY e.rowid, l.idx LIMIT ? OFFSET ?"
)
_SQL_LINKS_TO_RELS = (
    "SELECT l.evidence_id, l.idx, l.rel, l.target_digest FROM tzun_py_evidence_links l "
    "JOIN evidence_envelopes e ON e.evidence_id = l.evidence_id "
    "WHERE l.target_digest = ? AND l.rel IN (SELECT value FROM json_each(?)) {statements}"
    "ORDER BY e.rowid, l.idx LIMIT ? OFFSET ?"
)
#: The filter ``statements=True`` adds: the statements of link records only.
_SQL_STATEMENTS_ONLY = "AND l.subject_digest IS NOT NULL "


def _require_aiosqlite() -> Any:
    """Import ``aiosqlite`` lazily; raise MissingExtraError if absent."""
    try:
        import aiosqlite

        return aiosqlite
    except ImportError as exc:  # pragma: no cover - exercised by extras test
        raise MissingExtraError(
            "SqliteAdapter async path requires the 'sqlite' extra: "
            "pip install 'tzun-sdk[sqlite]'"
        ) from exc


class _Exec:
    """One connection, either mode, behind the same awaitable calls."""

    def __init__(self, conn: Any, is_async: bool) -> None:
        self._conn = conn
        self._async = is_async

    async def one(self, sql: str, params: Sequence[Any] = ()) -> Any:
        if self._async:
            cursor = await self._conn.execute(sql, tuple(params))
            row = await cursor.fetchone()
            await cursor.close()
            return row
        return self._conn.execute(sql, tuple(params)).fetchone()

    async def all(self, sql: str, params: Sequence[Any] = ()) -> builtins.list[Any]:
        if self._async:
            cursor = await self._conn.execute(sql, tuple(params))
            rows = await cursor.fetchall()
            await cursor.close()
            return builtins.list(rows)
        return builtins.list(self._conn.execute(sql, tuple(params)).fetchall())

    async def run(self, sql: str, params: Sequence[Any] = ()) -> None:
        if self._async:
            await self._conn.execute(sql, tuple(params))
        else:
            self._conn.execute(sql, tuple(params))

    async def begin(self) -> None:
        if self._conn.in_transaction:
            await self.commit()
        await self.run("BEGIN IMMEDIATE")

    async def commit(self) -> None:
        if self._async:
            await self._conn.commit()
        else:
            self._conn.commit()

    async def rollback(self) -> None:
        if self._async:
            await self._conn.rollback()
        else:
            self._conn.rollback()


class SqliteAdapter:
    """SQLite storage adapter.

    Constructor:
        ``SqliteAdapter(database_path: str, mode: 'async' | 'sync' = 'async')``

    The async path uses ``aiosqlite`` (requires the ``[sqlite]`` extra).
    The sync path uses stdlib ``sqlite3`` and is used by ``TzunSync``.
    """

    def __init__(self, database_path: str, mode: str = "async") -> None:
        if mode not in ("async", "sync"):
            raise TzunError(f"SqliteAdapter: mode must be 'async' or 'sync', got {mode!r}")
        self._database_path = database_path
        self._mode = mode
        self._async_conn: Any | None = None
        self._sync_conn: sqlite3.Connection | None = None
        if mode == "async":
            self._aiosqlite = _require_aiosqlite()

    async def _ensure_async_conn(self) -> Any:
        if self._async_conn is None:
            self._async_conn = await self._aiosqlite.connect(self._database_path)
            # SQLite does not enforce FOREIGN KEY constraints unless asked, per
            # connection. Without this the annotations→descriptors key in the
            # DDL is decoration, and an orphan annotation that Postgres refuses
            # is accepted here.
            await self._async_conn.execute("PRAGMA foreign_keys = ON")
        return self._async_conn

    def _ensure_sync_conn(self) -> sqlite3.Connection:
        if self._sync_conn is None:
            self._sync_conn = sqlite3.connect(self._database_path)
            self._sync_conn.execute("PRAGMA foreign_keys = ON")
        return self._sync_conn

    @staticmethod
    def _translate_store_integrity_error(
        exc: sqlite3.IntegrityError, evidence_id: str
    ) -> TzunError:
        """The refusal ``store()`` raises when the INSERT itself is refused.

        The duplicate-id check above the INSERT runs under ``BEGIN IMMEDIATE``
        (SQLite's write lock), so a primary-key violation here is not
        expected; it is translated all the same, and to the SAME class the
        pre-check raises — :class:`~tzun_sdk.errors.DuplicateEvidenceError`,
        as Postgres translates its 23505 — rather than a bare
        ``sqlite3.IntegrityError`` or a generic ``TzunError`` (one condition,
        two classes). Scoped to the primary key: an integrity error from any
        other constraint on the table keeps a generic wrapping instead of
        naming a reused id as the cause.
        """
        if "evidence_envelopes.evidence_id" in str(exc):
            return DuplicateEvidenceError(evidence_id)
        return TzunError(f"SqliteAdapter.store failed: {exc}")

    async def ensure_tables(self) -> None:
        # A link index created before subject_digest has the column added and
        # its link records' statements filled in, once, before the index over
        # the statements is created.
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            await conn.executescript(_schema_script())
            await conn.commit()
            cursor = await conn.execute("PRAGMA table_info(model_descriptors)")
            cols = {r[1] for r in await cursor.fetchall()}
            await cursor.close()
            if "canonical_bytes" not in cols:
                await conn.execute(
                    "ALTER TABLE model_descriptors ADD COLUMN canonical_bytes TEXT"
                )
                await conn.commit()
            cursor = await conn.execute("PRAGMA table_info(tzun_py_evidence_links)")
            link_cols = {r[1] for r in await cursor.fetchall()}
            await cursor.close()
            if "subject_digest" not in link_cols:
                await conn.execute("ALTER TABLE tzun_py_evidence_links ADD COLUMN subject_digest TEXT")
                await conn.execute(SQLITE_LINK_SUBJECT_BACKFILL)
            await conn.executescript(SQLITE_LINK_STATEMENTS_INDEX)
            await conn.commit()
        else:
            conn = self._ensure_sync_conn()
            conn.executescript(_schema_script())
            conn.commit()
            cols = {
                r[1] for r in conn.execute("PRAGMA table_info(model_descriptors)").fetchall()
            }
            if "canonical_bytes" not in cols:
                conn.execute(
                    "ALTER TABLE model_descriptors ADD COLUMN canonical_bytes TEXT"
                )
                conn.commit()
            link_cols = {r[1] for r in conn.execute("PRAGMA table_info(tzun_py_evidence_links)").fetchall()}
            if "subject_digest" not in link_cols:
                conn.execute("ALTER TABLE tzun_py_evidence_links ADD COLUMN subject_digest TEXT")
                conn.execute(SQLITE_LINK_SUBJECT_BACKFILL)
            conn.executescript(SQLITE_LINK_STATEMENTS_INDEX)
            conn.commit()

    #: Append-only guard, run inside the same ``BEGIN IMMEDIATE`` transaction
    #: as the insert. The write lock is already held when this runs, so no
    #: other connection — in this process or another one on the same file —
    #: can insert the id between this check and the INSERT.
    _SELECT_EXISTING_SQL = "SELECT 1 FROM evidence_envelopes WHERE evidence_id = ?"

    #: The capture revision, written in the SAME transaction as
    #: the record it describes, and only where the record has none yet: a
    #: record that was deleted and re-stored under the same id keeps the
    #: capture revision it already has — overwriting it would let a rewritten
    #: copy redefine what the record was captured as. INSERT ... SELECT ...
    #: WHERE NOT EXISTS rather than ON CONFLICT DO NOTHING, because
    #: envelope_revisions_block_replace refuses any insert over an existing
    #: row, a skipping conflict clause included, and a SELECT that yields no
    #: row inserts nothing to refuse. Parameters: the seven column values,
    #: then evidence_id and revision_no again for the existence check.
    _INSERT_REVISION_SQL = (
        "INSERT INTO envelope_revisions "
        "(evidence_id, revision_no, canonical_digest, chain_link, recorded_at, cause, actor) "
        "SELECT ?, ?, ?, ?, ?, ?, ? "
        "WHERE NOT EXISTS (SELECT 1 FROM envelope_revisions WHERE evidence_id = ? AND revision_no = ?)"
    )

    #: Head-of-chain lookup used by the conditional-append compare-and-swap.
    #: Same predicate as :meth:`head`, run inside the write transaction.
    _HEAD_FOR_CAS_SQL = (
        "SELECT sequence_number, envelope_json FROM evidence_envelopes "
        "WHERE chain_id = ? ORDER BY sequence_number DESC LIMIT 1"
    )

    _INSERT_SQL = (
        "INSERT INTO evidence_envelopes "
        "(evidence_id, chain_id, sequence_number, envelope_json) "
        "VALUES (?, ?, ?, ?)"
    )

    @staticmethod
    def _head_from_row(row: Any) -> ChainHead:
        if row is None:
            return head_of(0, None)
        return head_of(row[0], digest_of(stored_json(row[1])) if isinstance(stored_json(row[1]), dict) else None)

    async def _exec(self) -> _Exec:
        if self._mode == "async":
            return _Exec(await self._ensure_async_conn(), True)
        return _Exec(self._ensure_sync_conn(), False)

    async def store(
        self,
        envelope: EvidenceEnvelope | dict[str, Any],
        chain_id: str | None = None,
        options: StoreOptions | None = None,
    ) -> None:
        """Append an envelope; optionally compare-and-swap on the chain head.

        The record is stored as the JSON the capture hashed. When
        ``options.expectChainHead`` is supplied this is a conditional append:
        the head read and the insert both run inside one ``BEGIN IMMEDIATE``
        transaction, so the write lock is taken *before* the head is read and
        no other connection can slip an append in between. The same
        transaction refuses an ``evidenceId`` that is already stored
        (:class:`~tzun_sdk.errors.DuplicateEvidenceError`, before the head),
        and writes, or refuses, everything ``options`` carries with the
        record: a mandate claim, issuance or revocation (each checked against
        the mandate row read under the same lock), a commitment opening, and
        the record's rows of the link index.
        """
        cid = chain_id or DEFAULT_CHAIN_ID
        raw = raw_envelope(envelope)
        evidence_id = evidence_id_of(raw)
        expected = options.expectChainHead if options is not None else None
        params = (evidence_id, cid, sequence_of(raw), envelope_json(raw))
        revision_params = (
            evidence_id,
            CAPTURE_REVISION_NO,
            digest_of(raw) or "",
            chain_link_of(raw),
            _utcnow_iso(),
            "capture",
            capture_actor_of(raw),
            evidence_id,
            CAPTURE_REVISION_NO,
        )
        ex = await self._exec()
        await ex.begin()
        try:
            if await ex.one(self._SELECT_EXISTING_SQL, (evidence_id,)) is not None:
                raise DuplicateEvidenceError(evidence_id)
            await self._check_mandate_options(ex, options)
            row = await ex.one(self._HEAD_FOR_CAS_SQL, (cid,))
            assert_chain_head(expected, self._head_from_row(row))
            opening = opening_of(raw, options)
            try:
                await ex.run(self._INSERT_SQL, params)
            except sqlite3.IntegrityError as exc:
                raise self._translate_store_integrity_error(exc, evidence_id) from exc
            await ex.run(self._INSERT_REVISION_SQL, revision_params)
            if opening is not None:
                await ex.run(
                    "INSERT INTO decider_openings (evidence_id, salt, inner_id, created_at) VALUES (?, ?, ?, ?)",
                    (evidence_id, opening["salt"], opening["id"], _utcnow_iso()),
                )
            for link_row in link_index_rows(raw):
                await ex.run(
                    "INSERT INTO tzun_py_evidence_links (evidence_id, idx, rel, target_digest, subject_digest) "
                    "VALUES (?, ?, ?, ?, ?)",
                    link_row,
                )
            await self._apply_mandate_options(ex, options)
        except BaseException:
            await ex.rollback()
            raise
        await ex.commit()

    async def _mandate_state(self, ex: _Exec, mandate_id: str) -> tuple[dict[str, Any] | None, dict[str, dict[str, int]]]:
        row = await ex.one(_SQL_MANDATE_BY_ID, (mandate_id,))
        mandate = dict(zip(MANDATE_COLUMNS, row, strict=True)) if row is not None else None
        totals = {
            r[0]: {"max": int(r[1]), "total": int(r[2])}
            for r in await ex.all(
                "SELECT cap, max, total FROM tzun_py_mandate_totals WHERE mandate_id = ?", (mandate_id,)
            )
        }
        return mandate, totals

    async def _check_mandate_options(self, ex: _Exec, options: StoreOptions | None) -> None:
        if options is None:
            return
        if options.mandateClaim is not None:
            mandate, totals = await self._mandate_state(ex, options.mandateClaim.mandateId)
            check_mandate_claim(options.mandateClaim, mandate, totals)
        if options.mandateIssue is not None:
            record = options.mandateIssue.record
            held = await ex.one(
                "SELECT 1 FROM tzun_py_mandates WHERE mandate_id = ? OR mandate_digest = ?",
                (record.mandateId, record.mandateDigest),
            )
            if held is not None:
                raise MandateRefusedError("mandate_already_issued", "document.mandateId", f"Mandate {record.mandateId} is already issued.")
        if options.mandateRevoke is not None:
            mandate, totals = await self._mandate_state(ex, options.mandateRevoke.mandateId)
            check_mandate_transition(options.mandateRevoke, mandate, totals)

    async def _apply_mandate_options(self, ex: _Exec, options: StoreOptions | None) -> None:
        if options is None:
            return
        if options.mandateClaim is not None:
            claim = options.mandateClaim
            await ex.run("UPDATE tzun_py_mandates SET used = used + 1 WHERE mandate_id = ?", (claim.mandateId,))
            for cap in claim.caps:
                await ex.run(
                    "UPDATE tzun_py_mandate_totals SET total = ? WHERE mandate_id = ? AND cap = ?",
                    (int(cap.newTotal), claim.mandateId, cap.cap),
                )
        if options.mandateIssue is not None:
            issue = options.mandateIssue
            await ex.run(_SQL_INSERT_MANDATE, mandate_row_values(issue.record))
            for cap in issue.caps:
                await ex.run(
                    "INSERT INTO tzun_py_mandate_totals (mandate_id, cap, max, total) VALUES (?, ?, ?, 0)",
                    (issue.record.mandateId, cap.cap, int(cap.max)),
                )
            await self._insert_event(ex, issue.event)
        if options.mandateRevoke is not None:
            revoke = options.mandateRevoke
            await ex.run(
                "UPDATE tzun_py_mandates SET state = ? WHERE mandate_id = ?", (revoke.newState, revoke.mandateId)
            )
            await self._insert_event(ex, revoke.event)

    @staticmethod
    async def _insert_event(ex: _Exec, event: MandateEventRow) -> None:
        await ex.run(
            "INSERT INTO tzun_py_mandate_events (mandate_id, canonical, digest, created_at) VALUES (?, ?, ?, ?)",
            (event.mandateId, event.canonical, event.digest, _utcnow_iso()),
        )

    async def list_envelope_revisions(self, evidence_id: str) -> list[EnvelopeRevision]:
        """Every revision row for one record, in ``revision_no`` order."""
        sql = (
            "SELECT evidence_id, revision_no, canonical_digest, chain_link, recorded_at, "
            "cause, actor FROM envelope_revisions WHERE evidence_id = ? ORDER BY revision_no ASC"
        )
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            cursor = await conn.execute(sql, (evidence_id,))
            rows = await cursor.fetchall()
            await cursor.close()
        else:
            rows = self._ensure_sync_conn().execute(sql, (evidence_id,)).fetchall()
        return [revision_from_row(r) for r in rows]

    async def get_capture_digests(self, evidence_ids: Sequence[str]) -> dict[str, str]:
        """``evidenceId -> capture digest`` for the ids that have a revision 0.

        An id with no capture revision is ABSENT from the result rather than
        mapped to ``None``: a record this store cannot speak for must not be
        mistakable for one it is vouching for. Records written before the log
        existed are exactly that case.
        """
        out: dict[str, str] = {}
        if not evidence_ids:
            return out
        sql = (
            "SELECT canonical_digest FROM envelope_revisions "
            "WHERE evidence_id = ? AND revision_no = ?"
        )
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            for evidence_id in evidence_ids:
                cursor = await conn.execute(sql, (evidence_id, CAPTURE_REVISION_NO))
                row = await cursor.fetchone()
                await cursor.close()
                if row is not None:
                    out[evidence_id] = row[0]
        else:
            conn_sync = self._ensure_sync_conn()
            for evidence_id in evidence_ids:
                row = conn_sync.execute(sql, (evidence_id, CAPTURE_REVISION_NO)).fetchone()
                if row is not None:
                    out[evidence_id] = row[0]
        return out

    async def retrieve(self, evidence_id: str) -> EvidenceEnvelope | None:
        raw = await self.retrieve_raw(evidence_id)
        return model_of(raw) if raw is not None else None

    async def retrieve_raw(self, evidence_id: str) -> dict[str, Any] | None:
        """The record's stored JSON, or ``None``."""
        ex = await self._exec()
        row = await ex.one("SELECT envelope_json FROM evidence_envelopes WHERE evidence_id = ?", (evidence_id,))
        return _stored_object(row[0]) if row is not None else None

    async def retrieve_raw_by_digest(self, digest: str) -> dict[str, Any] | None:
        """The stored JSON of the oldest record whose stored canonical digest is ``digest``, or ``None``."""
        ex = await self._exec()
        row = await ex.one(
            "SELECT envelope_json FROM evidence_envelopes "
            "WHERE json_extract(envelope_json, '$.integrity.canonicalDigest') = ? ORDER BY rowid LIMIT 1",
            (digest,),
        )
        return _stored_object(row[0]) if row is not None else None

    async def chain_of(self, evidence_id: str) -> str | None:
        """The chain a record was stored on, or ``None``."""
        ex = await self._exec()
        row = await ex.one("SELECT chain_id FROM evidence_envelopes WHERE evidence_id = ?", (evidence_id,))
        return row[0] if row is not None else None

    async def list(self, **options: Any) -> list[EvidenceEnvelope]:
        """Page of envelopes ordered by ``sequence_number``; ``limit`` defaults to 100."""
        limit = options.get("limit", 100)
        offset = options.get("offset", 0)
        ex = await self._exec()
        rows = await ex.all(
            "SELECT envelope_json FROM evidence_envelopes ORDER BY sequence_number LIMIT ? OFFSET ?",
            (limit, offset),
        )
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
        cid = chain_id or DEFAULT_CHAIN_ID
        lower = 1 if from_sequence is None else from_sequence
        params: builtins.list[Any] = [cid, lower]
        query = "SELECT envelope_json FROM evidence_envelopes WHERE chain_id = ? AND sequence_number >= ?"
        if to_sequence is not None:
            query += " AND sequence_number <= ?"
            params.append(to_sequence)
        query += " ORDER BY sequence_number"
        ex = await self._exec()
        return [_stored_object(r[0]) for r in await ex.all(query, params)]

    async def head(self, chain_id: str | None = None) -> EvidenceEnvelope | None:
        """The record with the highest ``sequence_number`` on the chain; later insert wins a tie."""
        raw = await self.head_raw(chain_id)
        return model_of(raw) if raw is not None else None

    async def head_raw(self, chain_id: str | None = None) -> dict[str, Any] | None:
        """:meth:`head` as stored JSON."""
        cid = chain_id or DEFAULT_CHAIN_ID
        ex = await self._exec()
        row = await ex.one(
            "SELECT envelope_json FROM evidence_envelopes "
            "WHERE chain_id = ? ORDER BY sequence_number DESC, rowid DESC LIMIT 1",
            (cid,),
        )
        return _stored_object(row[0]) if row is not None else None

    async def read_envelope_at_end(self, end: str) -> Any:
        """The store's first (``end="first"``) or newest record by ``rowid``,
        as its stored JSON, or ``None``. SQLite assigns a rowid above every
        other when an insert names none; this table has no append-only
        triggers (``python/MIGRATION.md``), so a writer with the file can put
        any row first.

        Only reads, through a read-only connection of its own: a path with no
        file yet, or a file with no ``evidence_envelopes`` table, answers
        ``None`` and nothing is created. ``Tzun.init()`` runs the 0.7.0 store
        check with it before :meth:`ensure_tables`.
        """
        path = self._database_path
        if path in ("", ":memory:") or not os.path.exists(path):
            return None
        row_sql = (
            "SELECT envelope_json FROM evidence_envelopes ORDER BY rowid ASC LIMIT 1"
            if end == "first"
            else "SELECT envelope_json FROM evidence_envelopes ORDER BY rowid DESC LIMIT 1"
        )
        conn = sqlite3.connect(pathlib.Path(path).absolute().as_uri() + "?mode=ro", uri=True)
        try:
            table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'evidence_envelopes'"
            ).fetchone()
            if table is None:
                return None
            row = conn.execute(row_sql).fetchone()
        finally:
            conn.close()
        return None if row is None else stored_json(row[0])

    async def register_descriptor(self, descriptor: ModelDescriptor) -> str:
        # ALWAYS the canonical descriptor hash, never `descriptor.modelDigest`,
        # which is the WEIGHTS digest — a different value about a different
        # thing. TS `registerModelDescriptor` hashes the canonical descriptor
        # bytes unconditionally (storage/memory.ts). Keyed on the weights
        # digest, the two SDKs would file the same descriptor under two
        # different keys, and two descriptors that differ only in metadata
        # would collide on one key whenever they shared weights.
        digest = _compute_descriptor_digest(descriptor)
        body = descriptor.model_dump_json()
        # Store the bytes the digest is actually over, alongside the pydantic
        # JSON that get_descriptor() round-trips. They are not the same string:
        # model_dump_json() emits fields in declaration order, the canonical
        # serializer sorts them, so only the latter hashes back to `digest`.
        canonical_bytes = _canonical_bytes_for(descriptor)
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            await conn.execute(
                "INSERT OR IGNORE INTO model_descriptors "
                "(digest, descriptor_json, canonical_bytes) VALUES (?, ?, ?)",
                (digest, body, canonical_bytes),
            )
            await conn.commit()
        else:
            conn = self._ensure_sync_conn()
            conn.execute(
                "INSERT OR IGNORE INTO model_descriptors "
                "(digest, descriptor_json, canonical_bytes) VALUES (?, ?, ?)",
                (digest, body, canonical_bytes),
            )
            conn.commit()
        return digest

    async def get_descriptor(self, digest: str) -> ModelDescriptor | None:
        query = "SELECT descriptor_json FROM model_descriptors WHERE digest = ?"
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            cursor = await conn.execute(query, (digest,))
            row = await cursor.fetchone()
            await cursor.close()
        else:
            conn = self._ensure_sync_conn()
            row = conn.execute(query, (digest,)).fetchone()
        if row is None:
            return None
        return ModelDescriptor.model_validate_json(row[0])

    async def store_attestation(
        self, evidence_id: str, blob: AttestationArtifacts
    ) -> None:
        body = blob.model_dump_json()
        query = "INSERT INTO attestations (evidence_id, blob_json) VALUES (?, ?)"
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            await conn.execute(query, (evidence_id, body))
            await conn.commit()
        else:
            conn = self._ensure_sync_conn()
            conn.execute(query, (evidence_id, body))
            conn.commit()

    async def get_attestations(
        self, evidence_id: str
    ) -> builtins.list[AttestationArtifacts]:
        query = (
            "SELECT blob_json FROM attestations WHERE evidence_id = ? "
            "ORDER BY id"
        )
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            cursor = await conn.execute(query, (evidence_id,))
            rows = await cursor.fetchall()
            await cursor.close()
        else:
            conn = self._ensure_sync_conn()
            rows = conn.execute(query, (evidence_id,)).fetchall()
        return [AttestationArtifacts.model_validate_json(r[0]) for r in rows]

    async def store_annotation(self, record: AnnotationRecord) -> None:
        await self._store_recovery("annotation", record.model_dump_json())

    async def store_relink(self, record: RelinkRecord) -> None:
        await self._store_recovery("relink", record.model_dump_json())

    async def store_fork(self, record: ForkRecord) -> None:
        await self._store_recovery("fork", record.model_dump_json())

    async def _store_recovery(self, kind: str, body: str) -> None:
        query = "INSERT INTO recovery_records (kind, record_json) VALUES (?, ?)"
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            await conn.execute(query, (kind, body))
            await conn.commit()
        else:
            conn = self._ensure_sync_conn()
            conn.execute(query, (kind, body))
            conn.commit()

    async def store_incident(self, incident: TamperIncident) -> None:
        body = incident.model_dump_json()
        # OR IGNORE, not OR REPLACE. `INSERT OR REPLACE` would silently
        # overwrite a stored incident when the same incident_id came round
        # again, on a table that is append-only. First write wins, matching the
        # Postgres adapter's ON CONFLICT DO NOTHING.
        query = (
            "INSERT OR IGNORE INTO tzun_py_tamper_incidents "
            "(incident_id, event_type, evidence_id, incident_json, detected_at) "
            "VALUES (?, ?, ?, ?, ?)"
        )
        params = (
            incident.incidentId,
            incident.eventType,
            incident.evidenceId,
            body,
            incident.detectedAt,
        )
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            await conn.execute(query, params)
            await conn.commit()
        else:
            conn = self._ensure_sync_conn()
            conn.execute(query, params)
            conn.commit()

    # ── Catalog primitives ────────────────────────────────────────────────

    async def list_model_descriptors(
        self,
        vendor: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> builtins.list[ModelDescriptorRow]:
        """List model descriptors with optional vendor filter, limit, offset."""
        query = (
            "SELECT digest, descriptor_json, canonical_bytes, created_at "
            "FROM model_descriptors"
        )
        params: builtins.list[Any] = []
        if vendor is not None:
            query += " WHERE json_extract(descriptor_json, '$.vendor') = ?"
            params.append(vendor)
        query += " ORDER BY rowid"
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        if offset is not None:
            query += " OFFSET ?"
            params.append(offset)
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            cursor = await conn.execute(query, params)
            rows = await cursor.fetchall()
            await cursor.close()
        else:
            conn = self._ensure_sync_conn()
            rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            desc = ModelDescriptor.model_validate_json(row[1])
            # `canonicalBytes` must be the bytes the digest is over. It used to
            # be row[1] — pydantic's model_dump_json() — which is a different
            # string in a different key order, so sha256(canonicalBytes) never
            # equalled modelDescriptorDigest in an exported bundle. Rows written
            # before the column existed carry NULL; recomputing from the stored
            # descriptor reproduces the same bytes registration hashed.
            canonical_bytes = row[2] if row[2] is not None else _canonical_bytes_for(desc)
            result.append(ModelDescriptorRow(
                modelDescriptorDigest=row[0],
                canonicalBytes=canonical_bytes,
                descriptor=desc,
                vendor=desc.vendor,
                modelName=desc.modelName,
                modelVersion=desc.modelVersion,
                parentModelDescriptorDigest=desc.parentModelDescriptorDigest,
                source="manual",
                # The registration time, not the time of this call. Reporting
                # `now` would make every exported bundle claim the model was
                # first registered at the moment the bundle was produced.
                firstRegisteredAt=_sqlite_ts_to_iso(row[3]),
                firstRegisteredBy="sdk",
            ))
        return result

    async def append_model_descriptor_annotation(
        self, row: ModelDescriptorAnnotationRow
    ) -> None:
        """Insert one annotation row (append-only — no UPDATE/DELETE)."""
        query = (
            "INSERT INTO model_descriptor_annotations "
            "(annotation_id, model_descriptor_digest, annotated_at, annotated_by, "
            "annotation_type, value_json, retracts_annotation_id, signature, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        params = (
            row.annotationId, row.modelDescriptorDigest, row.annotatedAt,
            row.annotatedBy, row.annotationType, row.valueJson,
            row.retractsAnnotationId, row.signature, row.note,
        )
        try:
            if self._mode == "async":
                conn = await self._ensure_async_conn()
                await conn.execute(query, params)
                await conn.commit()
            else:
                conn = self._ensure_sync_conn()
                conn.execute(query, params)
                conn.commit()
        except sqlite3.IntegrityError as exc:
            # PK on annotation_id or FK to model_descriptors. One SDK error on
            # every backend; the driver error is the cause.
            raise TzunError(
                f"append_model_descriptor_annotation refused "
                f'"{row.annotationId}" for descriptor "{row.modelDescriptorDigest}": {exc}'
            ) from exc

    async def list_model_descriptor_annotations(
        self, digest: str
    ) -> builtins.list[ModelDescriptorAnnotationRow]:
        """All annotations for a descriptor, ``annotated_at`` ASC then ``annotation_id`` ASC."""
        query = (
            "SELECT annotation_id, model_descriptor_digest, annotated_at, annotated_by, "
            "annotation_type, value_json, retracts_annotation_id, signature, note "
            "FROM model_descriptor_annotations "
            "WHERE model_descriptor_digest = ? "
            "ORDER BY annotated_at ASC, annotation_id ASC"
        )
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            cursor = await conn.execute(query, (digest,))
            rows = await cursor.fetchall()
            await cursor.close()
        else:
            conn = self._ensure_sync_conn()
            rows = conn.execute(query, (digest,)).fetchall()
        return [
            ModelDescriptorAnnotationRow(
                annotationId=r[0], modelDescriptorDigest=r[1],
                annotatedAt=r[2], annotatedBy=r[3], annotationType=r[4],
                valueJson=r[5], retractsAnnotationId=r[6],
                signature=r[7], note=r[8],
            )
            for r in rows
        ]

    async def set_model_descriptor_alias(
        self, slug: str, digest: str, set_by: str
    ) -> None:
        """Append a slug→digest binding (append-only; latest wins on resolve)."""
        query = (
            "INSERT INTO model_descriptor_aliases "
            "(slug, set_at, model_descriptor_digest, set_by) VALUES (?, ?, ?, ?) "
            # Same-instant re-set (PK slug+set_at) = the later write wins — upsert
            # keeps the latest-wins contract instead of raising IntegrityError.
            "ON CONFLICT(slug, set_at) DO UPDATE SET "
            "model_descriptor_digest=excluded.model_descriptor_digest, set_by=excluded.set_by"
        )
        params = (slug, _utcnow_iso(), digest, set_by)
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            await conn.execute(query, params)
            await conn.commit()
        else:
            conn = self._ensure_sync_conn()
            conn.execute(query, params)
            conn.commit()

    async def resolve_model_descriptor_alias(self, slug: str) -> str | None:
        """Return the digest for the latest binding of slug, or None."""
        query = (
            "SELECT model_descriptor_digest FROM model_descriptor_aliases "
            "WHERE slug = ? ORDER BY set_at DESC LIMIT 1"
        )
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            cursor = await conn.execute(query, (slug,))
            row = await cursor.fetchone()
            await cursor.close()
        else:
            conn = self._ensure_sync_conn()
            row = conn.execute(query, (slug,)).fetchone()
        return row[0] if row else None

    async def get_enriched_model_descriptor(self, digest: str) -> ModelDescriptor | None:
        """Return the descriptor for the given digest, or None."""
        return await self.get_descriptor(digest)

    async def delete_envelope_for_demo(self, evidence_id: str) -> None:
        # Gated by the TZUN_ENABLE_DEMO_DELETE env var.
        if os.environ.get("TZUN_ENABLE_DEMO_DELETE", "") != "1":
            raise TzunError(
                "delete_envelope_for_demo is demo-only and not enabled in "
                "this build (set TZUN_ENABLE_DEMO_DELETE=1 to enable)."
            )
        if self._mode == "async":
            conn = await self._ensure_async_conn()
            await conn.execute(
                "DELETE FROM evidence_envelopes WHERE evidence_id = ?",
                (evidence_id,),
            )
            await conn.commit()
        else:
            conn = self._ensure_sync_conn()
            conn.execute(
                "DELETE FROM evidence_envelopes WHERE evidence_id = ?",
                (evidence_id,),
            )
            conn.commit()

    # ── Decider openings (Record §6.3) ───────────────────────────────────

    async def get_decider_opening(self, evidence_id: str) -> DeciderOpening | None:
        ex = await self._exec()
        row = await ex.one("SELECT salt, inner_id FROM decider_openings WHERE evidence_id = ?", (evidence_id,))
        return DeciderOpening(salt=row[0], id=row[1]) if row is not None else None

    async def get_decider_commitment_secret(self) -> bytes:
        """The store's commitment-salt secret: 32 random bytes minted on first read, kept for the store's life."""
        ex = await self._exec()
        await ex.begin()
        try:
            row = await ex.one("SELECT secret FROM decider_commitment_secret WHERE id = 1")
            if row is None:
                minted = secrets.token_bytes(32).hex()
                await ex.run("INSERT INTO decider_commitment_secret (id, secret) VALUES (1, ?)", (minted,))
                secret = minted
            else:
                secret = row[0]
        except BaseException:
            await ex.rollback()
            raise
        await ex.commit()
        return bytes.fromhex(secret)

    # ── Agent catalog (Record §6.9) ──────────────────────────────────────

    async def put_agent_descriptor(self, descriptor: Any) -> tuple[str, bool]:
        """Register a descriptor (already checked); idempotent on identical bytes. ``(digest, already_existed)``."""
        d = descriptor if isinstance(descriptor, dict) else descriptor.model_dump(mode="json")
        digest = agent_descriptor_digest(d)
        ex = await self._exec()
        await ex.begin()
        try:
            held = await ex.one("SELECT 1 FROM tzun_py_agent_descriptors WHERE digest = ?", (digest,))
            if held is None:
                await ex.run(
                    "INSERT INTO tzun_py_agent_descriptors "
                    "(digest, canonical_bytes, name, organization, parent, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        digest,
                        canonical_serialize_agent_descriptor(d),
                        d["name"],
                        d["operator"]["organization"],
                        d["parent"],
                        _utcnow_iso(),
                    ),
                )
        except BaseException:
            await ex.rollback()
            raise
        await ex.commit()
        return digest, held is not None

    @staticmethod
    def _agent_row(r: Any) -> AgentDescriptorRow:
        return AgentDescriptorRow(
            digest=r[0], canonicalBytes=r[1], name=r[2], organization=r[3], parent=r[4], registeredAt=r[5]
        )

    async def get_agent_descriptor(self, digest: str) -> AgentDescriptorRow | None:
        ex = await self._exec()
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
        ex = await self._exec()
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
        ex = await self._exec()
        if rels is None:
            rows = await ex.all(_SQL_LINKS_TO.format(statements=only), (digest, size + 1, start))
        else:
            rel_list = builtins.list(rels)
            if not rel_list:
                return [], None
            rows = await ex.all(
                _SQL_LINKS_TO_RELS.format(statements=only), (digest, json.dumps(rel_list), size + 1, start)
            )
        page = [EvidenceLinkRow(evidenceId=r[0], idx=int(r[1]), rel=r[2], targetDigest=r[3]) for r in rows[:size]]
        return page, (opaque_cursor(start + size) if len(rows) > size else None)

    # ── Mandates (Record §9.6) ───────────────────────────────────────────

    async def get_mandate(self, mandate_id: str) -> MandateRow | None:
        ex = await self._exec()
        row = await ex.one(_SQL_MANDATE_BY_ID, (mandate_id,))
        return mandate_row_from(dict(zip(MANDATE_COLUMNS, row, strict=True))) if row is not None else None

    async def get_mandate_by_digest(self, mandate_digest: str) -> MandateRow | None:
        ex = await self._exec()
        row = await ex.one(_SQL_MANDATE_BY_DIGEST, (mandate_digest,))
        return mandate_row_from(dict(zip(MANDATE_COLUMNS, row, strict=True))) if row is not None else None

    async def list_mandates(self, *, state: str | None = None) -> builtins.list[MandateRow]:
        ex = await self._exec()
        rows = await (ex.all(_SQL_MANDATES_IN_STATE, (state,)) if state else ex.all(_SQL_MANDATES))
        return [mandate_row_from(dict(zip(MANDATE_COLUMNS, r, strict=True))) for r in rows]

    async def get_mandate_totals(self, mandate_id: str) -> dict[str, int]:
        ex = await self._exec()
        rows = await ex.all("SELECT cap, total FROM tzun_py_mandate_totals WHERE mandate_id = ?", (mandate_id,))
        return {r[0]: int(r[1]) for r in rows}

    async def list_mandate_events(self, mandate_id: str) -> builtins.list[MandateEventRow]:
        ex = await self._exec()
        rows = await ex.all(
            "SELECT canonical, digest FROM tzun_py_mandate_events WHERE mandate_id = ? ORDER BY id", (mandate_id,)
        )
        return [event_row_from(mandate_id, r[0], r[1]) for r in rows]

    async def expire_mandate(self, expiry: MandateExpireStore) -> None:
        ex = await self._exec()
        await ex.begin()
        try:
            mandate, totals = await self._mandate_state(ex, expiry.mandateId)
            check_mandate_transition(expiry, mandate, totals)
            await ex.run("UPDATE tzun_py_mandates SET state = 'expired' WHERE mandate_id = ?", (expiry.mandateId,))
            await self._insert_event(ex, expiry.event)
        except BaseException:
            await ex.rollback()
            raise
        await ex.commit()

    async def fill_confirmation(self, evidence_id: str, assertion: dict[str, Any]) -> bool:
        """Fill ``nonRepudiation.confirmation`` once; ``False`` when it is already filled or the record is absent."""
        ex = await self._exec()
        await ex.begin()
        try:
            row = await ex.one("SELECT envelope_json FROM evidence_envelopes WHERE evidence_id = ?", (evidence_id,))
            raw = _stored_object(row[0]) if row is not None else None
            nr = raw.get("nonRepudiation") if raw is not None else None
            if raw is None or not isinstance(nr, dict) or nr.get("confirmation") is not None:
                await ex.rollback()
                return False
            nr["confirmation"] = assertion
            await ex.run(
                "UPDATE evidence_envelopes SET envelope_json = ? WHERE evidence_id = ?", (envelope_json(raw), evidence_id)
            )
        except BaseException:
            await ex.rollback()
            raise
        await ex.commit()
        return True

    async def append_custody(self, evidence_id: str, entry: dict[str, Any]) -> None:
        """Append a custody entry to a stored record (unhashed, outside the digest)."""
        ex = await self._exec()
        await ex.begin()
        try:
            row = await ex.one("SELECT envelope_json FROM evidence_envelopes WHERE evidence_id = ?", (evidence_id,))
            raw = _stored_object(row[0]) if row is not None else None
            if raw is not None:
                custody = raw.setdefault("custodyChain", [])
                if isinstance(custody, builtins.list):
                    custody.append(entry)
                    await ex.run(
                        "UPDATE evidence_envelopes SET envelope_json = ? WHERE evidence_id = ?",
                        (envelope_json(raw), evidence_id),
                    )
        except BaseException:
            await ex.rollback()
            raise
        await ex.commit()

    async def close(self) -> None:
        if self._async_conn is not None:
            await self._async_conn.close()
            self._async_conn = None
        if self._sync_conn is not None:
            self._sync_conn.close()
            self._sync_conn = None


def _schema_script() -> str:
    """The core and 0.8.0 DDL as one transaction: one commit, not one per statement."""
    return "BEGIN;\n" + _DDL + "\n" + SQLITE_EXTENSION_DDL + "\nCOMMIT;"


def _stored_object(text: Any) -> dict[str, Any]:
    """A stored row's JSON object; a row that is not one reads as an empty record."""
    loaded = stored_json(text) if isinstance(text, str) else text
    return loaded if isinstance(loaded, dict) else {}


__all__ = ("SqliteAdapter",)
