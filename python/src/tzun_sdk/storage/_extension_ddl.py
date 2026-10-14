"""The 0.8.0 tables of the SQLite and Postgres adapters, created after the core DDL.

* ``decider_openings`` and ``decider_commitment_secret`` (Record §6.3): the same names,
  columns and triggers as the TypeScript adapters' (``src/storage/ddl/deciders.ts``),
  so a database both SDKs open converges on one table of one shape. Rows are
  append-only; the secret is written once.
* ``tzun_py_agent_descriptors`` (Record §6.9): the catalog, keyed by digest, the exact
  canonical bytes immutable.
* ``tzun_py_evidence_links``: the derived link index, one row per stored
  link, written in the transaction that stores the record; rebuildable from the
  envelopes, never read by verification. ``subject_digest`` is set on a link
  record's statements (its links other than ``subject``), so the decision
  graph finds the statements towards a record through an index.
* ``idx_evidence_envelopes_digest``: the records by their stored canonical
  digest, for resolving a link's target and reading a record by digest.
* ``tzun_py_mandates``, ``tzun_py_mandate_totals``, ``tzun_py_mandate_events``
  (Record §9.6): the mandate record (digests, document, statement and assertion
  immutable; ``state`` moves only out of ``open``; ``used`` only by +1), the
  running totals (only increasing), and the insert-only event bodies.

The extension tables carry the ``tzun_py_`` prefix: the evidence tables of the
two SDKs are disjoint (``evidence_envelopes`` here, ``envelopes`` there), and a
mandate or a link names records of its own SDK's table.
"""

from __future__ import annotations

#: Run on SQLite after :data:`SQLITE_EXTENSION_DDL` and after a link index
#: created before ``subject_digest`` has had the column added.
SQLITE_LINK_STATEMENTS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_tzun_py_evidence_links_statements
    ON tzun_py_evidence_links(target_digest) WHERE subject_digest IS NOT NULL;
"""

#: Fills in ``subject_digest`` on a SQLite link index created before the column.
SQLITE_LINK_SUBJECT_BACKFILL = """
UPDATE tzun_py_evidence_links
   SET subject_digest = (
       SELECT s.target_digest FROM tzun_py_evidence_links s
        WHERE s.evidence_id = tzun_py_evidence_links.evidence_id AND s.rel = 'subject'
        ORDER BY s.idx LIMIT 1)
 WHERE rel <> 'subject'
   AND evidence_id IN (SELECT evidence_id FROM tzun_py_evidence_links WHERE rel = 'subject');
"""

SQLITE_EXTENSION_DDL = """
CREATE TABLE IF NOT EXISTS decider_openings (
    evidence_id TEXT PRIMARY KEY,
    salt TEXT NOT NULL,
    inner_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS decider_openings_block_update
    BEFORE UPDATE ON decider_openings
    BEGIN SELECT RAISE(ABORT, 'decider_openings rows are append-only (UPDATE refused)'); END;
CREATE TRIGGER IF NOT EXISTS decider_openings_block_delete
    BEFORE DELETE ON decider_openings
    BEGIN SELECT RAISE(ABORT, 'decider_openings rows are append-only (DELETE refused)'); END;
CREATE TABLE IF NOT EXISTS decider_commitment_secret (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS decider_commitment_secret_block_update
    BEFORE UPDATE ON decider_commitment_secret
    BEGIN SELECT RAISE(ABORT, 'decider_commitment_secret is written once (UPDATE refused)'); END;
CREATE TRIGGER IF NOT EXISTS decider_commitment_secret_block_delete
    BEFORE DELETE ON decider_commitment_secret
    BEGIN SELECT RAISE(ABORT, 'decider_commitment_secret is written once (DELETE refused)'); END;

CREATE TABLE IF NOT EXISTS tzun_py_agent_descriptors (
    digest          TEXT PRIMARY KEY,
    canonical_bytes TEXT NOT NULL,
    name            TEXT NOT NULL,
    organization    TEXT NOT NULL,
    parent          TEXT,
    registered_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tzun_py_agent_descriptors_lookup
    ON tzun_py_agent_descriptors(name, organization);
CREATE TRIGGER IF NOT EXISTS tzun_py_agent_descriptors_block_update
    BEFORE UPDATE ON tzun_py_agent_descriptors
    BEGIN SELECT RAISE(ABORT, 'agent descriptors are immutable (UPDATE refused)'); END;
CREATE TRIGGER IF NOT EXISTS tzun_py_agent_descriptors_block_delete
    BEFORE DELETE ON tzun_py_agent_descriptors
    BEGIN SELECT RAISE(ABORT, 'agent descriptors are immutable (DELETE refused)'); END;

CREATE TABLE IF NOT EXISTS tzun_py_evidence_links (
    evidence_id    TEXT NOT NULL,
    idx            INTEGER NOT NULL,
    rel            TEXT NOT NULL,
    target_digest  TEXT NOT NULL,
    subject_digest TEXT,
    PRIMARY KEY (evidence_id, idx)
);
CREATE INDEX IF NOT EXISTS idx_tzun_py_evidence_links_target
    ON tzun_py_evidence_links(target_digest, rel);
CREATE INDEX IF NOT EXISTS idx_evidence_envelopes_digest
    ON evidence_envelopes(json_extract(envelope_json, '$.integrity.canonicalDigest'));

CREATE TABLE IF NOT EXISTS tzun_py_mandates (
    mandate_id           TEXT PRIMARY KEY,
    mandate_digest       TEXT NOT NULL UNIQUE,
    document_bytes       TEXT NOT NULL,
    statement_json       TEXT NOT NULL,
    statement_digest     TEXT NOT NULL,
    assertion_json       TEXT NOT NULL,
    assertion_digest     TEXT NOT NULL,
    assertion_timestamp  TEXT,
    state                TEXT NOT NULL CHECK (state IN ('open', 'revoked', 'superseded', 'expired')),
    used                 INTEGER NOT NULL CHECK (used >= 0),
    max_records          INTEGER,
    not_before           TEXT,
    not_after            TEXT,
    issuance_evidence_id TEXT NOT NULL,
    issuance_digest      TEXT NOT NULL,
    created_at           TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS tzun_py_mandates_guard_update
    BEFORE UPDATE ON tzun_py_mandates
    BEGIN
        SELECT RAISE(ABORT, 'a mandate record''s digests, document, statement and assertion are immutable')
         WHERE NEW.mandate_id IS NOT OLD.mandate_id OR NEW.mandate_digest IS NOT OLD.mandate_digest
            OR NEW.document_bytes IS NOT OLD.document_bytes OR NEW.statement_json IS NOT OLD.statement_json
            OR NEW.statement_digest IS NOT OLD.statement_digest OR NEW.assertion_json IS NOT OLD.assertion_json
            OR NEW.assertion_digest IS NOT OLD.assertion_digest
            OR NEW.assertion_timestamp IS NOT OLD.assertion_timestamp
            OR NEW.max_records IS NOT OLD.max_records OR NEW.not_before IS NOT OLD.not_before
            OR NEW.not_after IS NOT OLD.not_after OR NEW.issuance_evidence_id IS NOT OLD.issuance_evidence_id
            OR NEW.issuance_digest IS NOT OLD.issuance_digest OR NEW.created_at IS NOT OLD.created_at;
        SELECT RAISE(ABORT, 'a mandate''s state moves only out of open')
         WHERE NEW.state IS NOT OLD.state AND OLD.state <> 'open';
        SELECT RAISE(ABORT, 'a mandate''s used count changes only by +1')
         WHERE NEW.used <> OLD.used AND NEW.used <> OLD.used + 1;
    END;
CREATE TRIGGER IF NOT EXISTS tzun_py_mandates_block_delete
    BEFORE DELETE ON tzun_py_mandates
    BEGIN SELECT RAISE(ABORT, 'mandate records are never deleted'); END;

CREATE TABLE IF NOT EXISTS tzun_py_mandate_totals (
    mandate_id TEXT NOT NULL,
    cap        TEXT NOT NULL,
    max        INTEGER NOT NULL,
    total      INTEGER NOT NULL CHECK (total >= 0),
    PRIMARY KEY (mandate_id, cap)
);
CREATE TRIGGER IF NOT EXISTS tzun_py_mandate_totals_guard_update
    BEFORE UPDATE ON tzun_py_mandate_totals
    BEGIN
        SELECT RAISE(ABORT, 'a mandate total only increases')
         WHERE NEW.total < OLD.total OR NEW.max IS NOT OLD.max OR NEW.cap IS NOT OLD.cap
            OR NEW.mandate_id IS NOT OLD.mandate_id;
    END;
CREATE TRIGGER IF NOT EXISTS tzun_py_mandate_totals_block_delete
    BEFORE DELETE ON tzun_py_mandate_totals
    BEGIN SELECT RAISE(ABORT, 'mandate totals are never deleted'); END;

CREATE TABLE IF NOT EXISTS tzun_py_mandate_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mandate_id TEXT NOT NULL,
    canonical  TEXT NOT NULL,
    digest     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tzun_py_mandate_events_mandate
    ON tzun_py_mandate_events(mandate_id, id);
CREATE TRIGGER IF NOT EXISTS tzun_py_mandate_events_block_update
    BEFORE UPDATE ON tzun_py_mandate_events
    BEGIN SELECT RAISE(ABORT, 'mandate events are insert-only (UPDATE refused)'); END;
CREATE TRIGGER IF NOT EXISTS tzun_py_mandate_events_block_delete
    BEFORE DELETE ON tzun_py_mandate_events
    BEGIN SELECT RAISE(ABORT, 'mandate events are insert-only (DELETE refused)'); END;
""".strip()


POSTGRES_EXTENSION_DDL = """
CREATE TABLE IF NOT EXISTS decider_openings (
    evidence_id TEXT PRIMARY KEY,
    salt TEXT NOT NULL,
    inner_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE OR REPLACE FUNCTION decider_openings_block_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION '% rows are append-only (% refused)', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
DROP TRIGGER IF EXISTS decider_openings_block_mutation_trigger ON decider_openings;
CREATE TRIGGER decider_openings_block_mutation_trigger
  BEFORE UPDATE OR DELETE ON decider_openings
  FOR EACH ROW EXECUTE FUNCTION decider_openings_block_mutation();
DROP TRIGGER IF EXISTS decider_openings_block_truncate_trigger ON decider_openings;
CREATE TRIGGER decider_openings_block_truncate_trigger
  BEFORE TRUNCATE ON decider_openings
  FOR EACH STATEMENT EXECUTE FUNCTION decider_openings_block_mutation();
CREATE TABLE IF NOT EXISTS decider_commitment_secret (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret TEXT NOT NULL
);
DROP TRIGGER IF EXISTS decider_commitment_secret_block_mutation_trigger ON decider_commitment_secret;
CREATE TRIGGER decider_commitment_secret_block_mutation_trigger
  BEFORE UPDATE OR DELETE ON decider_commitment_secret
  FOR EACH ROW EXECUTE FUNCTION decider_openings_block_mutation();

CREATE TABLE IF NOT EXISTS tzun_py_agent_descriptors (
    digest          TEXT PRIMARY KEY,
    canonical_bytes TEXT NOT NULL,
    name            TEXT NOT NULL,
    organization    TEXT NOT NULL,
    parent          TEXT,
    registered_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tzun_py_agent_descriptors_lookup
    ON tzun_py_agent_descriptors(name, organization);
CREATE OR REPLACE FUNCTION tzun_py_block_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION '% rows are immutable (% refused)', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
DROP TRIGGER IF EXISTS tzun_py_agent_descriptors_block_mutation ON tzun_py_agent_descriptors;
CREATE TRIGGER tzun_py_agent_descriptors_block_mutation
  BEFORE UPDATE OR DELETE ON tzun_py_agent_descriptors
  FOR EACH ROW EXECUTE FUNCTION tzun_py_block_mutation();

CREATE TABLE IF NOT EXISTS tzun_py_evidence_links (
    evidence_id    TEXT NOT NULL,
    idx            INTEGER NOT NULL,
    rel            TEXT NOT NULL,
    target_digest  TEXT NOT NULL,
    subject_digest TEXT,
    PRIMARY KEY (evidence_id, idx)
);
-- A link index created before subject_digest: the column is added and the
-- statements of the link records already indexed are filled in, once.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'tzun_py_evidence_links'
           AND column_name = 'subject_digest'
    ) THEN
        ALTER TABLE tzun_py_evidence_links ADD COLUMN subject_digest TEXT;
        UPDATE tzun_py_evidence_links l
           SET subject_digest = s.target_digest
          FROM tzun_py_evidence_links s
         WHERE s.evidence_id = l.evidence_id AND s.rel = 'subject' AND l.rel <> 'subject';
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_tzun_py_evidence_links_target
    ON tzun_py_evidence_links(target_digest, rel);
CREATE INDEX IF NOT EXISTS idx_tzun_py_evidence_links_statements
    ON tzun_py_evidence_links(target_digest) WHERE subject_digest IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_evidence_envelopes_digest
    ON evidence_envelopes((envelope_json->'integrity'->>'canonicalDigest'));

CREATE TABLE IF NOT EXISTS tzun_py_mandates (
    mandate_id           TEXT PRIMARY KEY,
    mandate_digest       TEXT NOT NULL UNIQUE,
    document_bytes       TEXT NOT NULL,
    statement_json       TEXT NOT NULL,
    statement_digest     TEXT NOT NULL,
    assertion_json       TEXT NOT NULL,
    assertion_digest     TEXT NOT NULL,
    assertion_timestamp  TEXT,
    state                TEXT NOT NULL CHECK (state IN ('open', 'revoked', 'superseded', 'expired')),
    used                 BIGINT NOT NULL CHECK (used >= 0),
    max_records          BIGINT,
    not_before           TEXT,
    not_after            TEXT,
    issuance_evidence_id TEXT NOT NULL,
    issuance_digest      TEXT NOT NULL,
    created_at           TEXT NOT NULL
);
CREATE OR REPLACE FUNCTION tzun_py_mandates_guard()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'mandate records are never deleted';
  END IF;
  IF NEW.mandate_id IS DISTINCT FROM OLD.mandate_id OR NEW.mandate_digest IS DISTINCT FROM OLD.mandate_digest
     OR NEW.document_bytes IS DISTINCT FROM OLD.document_bytes OR NEW.statement_json IS DISTINCT FROM OLD.statement_json
     OR NEW.statement_digest IS DISTINCT FROM OLD.statement_digest OR NEW.assertion_json IS DISTINCT FROM OLD.assertion_json
     OR NEW.assertion_digest IS DISTINCT FROM OLD.assertion_digest
     OR NEW.assertion_timestamp IS DISTINCT FROM OLD.assertion_timestamp
     OR NEW.max_records IS DISTINCT FROM OLD.max_records OR NEW.not_before IS DISTINCT FROM OLD.not_before
     OR NEW.not_after IS DISTINCT FROM OLD.not_after OR NEW.issuance_evidence_id IS DISTINCT FROM OLD.issuance_evidence_id
     OR NEW.issuance_digest IS DISTINCT FROM OLD.issuance_digest OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'a mandate record''s digests, document, statement and assertion are immutable';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND OLD.state <> 'open' THEN
    RAISE EXCEPTION 'a mandate''s state moves only out of open';
  END IF;
  IF NEW.used <> OLD.used AND NEW.used <> OLD.used + 1 THEN
    RAISE EXCEPTION 'a mandate''s used count changes only by +1';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
DROP TRIGGER IF EXISTS tzun_py_mandates_guard_trigger ON tzun_py_mandates;
CREATE TRIGGER tzun_py_mandates_guard_trigger
  BEFORE UPDATE OR DELETE ON tzun_py_mandates
  FOR EACH ROW EXECUTE FUNCTION tzun_py_mandates_guard();

CREATE TABLE IF NOT EXISTS tzun_py_mandate_totals (
    mandate_id TEXT NOT NULL,
    cap        TEXT NOT NULL,
    max        BIGINT NOT NULL,
    total      BIGINT NOT NULL CHECK (total >= 0),
    PRIMARY KEY (mandate_id, cap)
);
CREATE OR REPLACE FUNCTION tzun_py_mandate_totals_guard()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'mandate totals are never deleted';
  END IF;
  IF NEW.total < OLD.total OR NEW.max IS DISTINCT FROM OLD.max OR NEW.cap IS DISTINCT FROM OLD.cap
     OR NEW.mandate_id IS DISTINCT FROM OLD.mandate_id THEN
    RAISE EXCEPTION 'a mandate total only increases';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp;
DROP TRIGGER IF EXISTS tzun_py_mandate_totals_guard_trigger ON tzun_py_mandate_totals;
CREATE TRIGGER tzun_py_mandate_totals_guard_trigger
  BEFORE UPDATE OR DELETE ON tzun_py_mandate_totals
  FOR EACH ROW EXECUTE FUNCTION tzun_py_mandate_totals_guard();

CREATE TABLE IF NOT EXISTS tzun_py_mandate_events (
    id         BIGSERIAL PRIMARY KEY,
    mandate_id TEXT NOT NULL,
    canonical  TEXT NOT NULL,
    digest     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tzun_py_mandate_events_mandate
    ON tzun_py_mandate_events(mandate_id, id);
DROP TRIGGER IF EXISTS tzun_py_mandate_events_block_mutation ON tzun_py_mandate_events;
CREATE TRIGGER tzun_py_mandate_events_block_mutation
  BEFORE UPDATE OR DELETE ON tzun_py_mandate_events
  FOR EACH ROW EXECUTE FUNCTION tzun_py_block_mutation();
""".strip()


__all__ = (
    "POSTGRES_EXTENSION_DDL",
    "SQLITE_EXTENSION_DDL",
    "SQLITE_LINK_STATEMENTS_INDEX",
    "SQLITE_LINK_SUBJECT_BACKFILL",
)
