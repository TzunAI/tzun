-- The PYTHON SQLite adapter's DDL, kept here for readers.
--
-- GENERATED-EQUIVALENT, NOT AUTHORITATIVE. The statements below are a verbatim
-- copy of the `_DDL` constant in python/src/tzun_sdk/storage/sqlite.py, which
-- is what ensure_tables() actually executes.
-- python/tests/storage/test_schema_file_matches_ddl.py fails if the two drift.
--
-- This is NOT read at runtime and it is NOT a cross-language source of truth:
-- the TypeScript SQLite adapter creates a different set of tables. See
-- python/MIGRATION.md for the full comparison.

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
